//! Global per-PURL linkage-evidence dedup per FR-028a (Q5).
//! N binaries referencing the same soname produce ONE `pkg:generic/<soname>`
//! component with N occurrences merged into the evidence trail (via the
//! `source_path` field on PackageDbEntry — the scan_fs conversion
//! layer promotes that into CycloneDX `evidence.occurrences[]`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mikebom_common::types::purl::Purl;

use crate::scan_fs::package_db::PackageDbEntry;

/// Standard shared-library search paths, relative to rootfs. Used by
/// [`LinkageAggregator::add_with_claim_check`] to resolve a DT_NEEDED
/// soname to a probable on-disk path and skip the linkage emission
/// when that path is already claimed by a package-db reader.
///
/// Covers glibc multiarch (Debian/Ubuntu), classic layouts (RHEL
/// lib64), and common aarch64 variants. Order matches
/// ld.so's default search path precedence loosely — we don't
/// implement full ld.so resolution, just cheap probing.
const STANDARD_LIBRARY_DIRS: &[&str] = &[
    "lib/x86_64-linux-gnu",
    "lib/aarch64-linux-gnu",
    "usr/lib/x86_64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
    "lib64",
    "usr/lib64",
    "lib",
    "usr/lib",
];

/// Check whether `soname` resolves to a path claimed by a package-db
/// reader. Probes the standard library search paths; returns `true`
/// at the first claimed hit.
fn soname_resolves_to_claimed(
    soname: &str,
    rootfs: &Path,
    claimed: &std::collections::HashSet<PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
) -> bool {
    for dir in STANDARD_LIBRARY_DIRS {
        let candidate = rootfs.join(dir).join(soname);
        if crate::scan_fs::binary::is_path_claimed(
            &candidate,
            claimed,
            #[cfg(unix)]
            claimed_inodes,
        ) {
            return true;
        }
    }
    false
}

/// Accumulates linkage evidence across a scan. Each unique soname
/// emits one `PackageDbEntry`; multiple parent binaries referencing
/// the same soname merge their paths into the entry's `source_path`
/// field (semicolon-separated).
pub struct LinkageAggregator {
    by_soname: HashMap<String, LinkageRecord>,
}

struct LinkageRecord {
    purl: Purl,
    parents: Vec<String>,
}

impl LinkageAggregator {
    pub fn new() -> Self {
        Self {
            by_soname: HashMap::new(),
        }
    }

    /// Register a linkage observation. `soname` is the raw DT_NEEDED
    /// string; `parent_path` is the absolute path to the binary that
    /// referenced it; `_parent_bom_ref` reserved for future cross-link.
    pub fn add(&mut self, soname: &str, parent_path: &Path, _parent_bom_ref: &str) {
        let entry = self.by_soname.entry(soname.to_string()).or_insert_with(|| {
            // Sonames are a special case: they're bare `pkg:generic/`
            // identifiers where `/` INSIDE the name (e.g. macOS
            // `@rpath/libssl.48.dylib`) is NOT a structural PURL
            // separator — it's part of the identifier. The canonical
            // `encode_purl_segment` leaves `/` literal (correct for
            // Go module paths, Maven groupIds, etc. where `/` is
            // structural); linkage keeps a stricter local encoder
            // that also encodes `/` and `@` to preserve the soname
            // as a single-segment name.
            let purl_str = format!("pkg:generic/{}", percent_encode_soname(soname));
            // Malformed soname → skip this entire record. Defensive:
            // real DT_NEEDED strings should always yield a valid PURL.
            let purl = match Purl::new(&purl_str) {
                Ok(p) => p,
                Err(_) => Purl::new("pkg:generic/unknown")
                    .expect("bare pkg:generic must parse"),
            };
            LinkageRecord {
                purl,
                parents: Vec::new(),
            }
        });
        let parent_str = parent_path.to_string_lossy().into_owned();
        if !entry.parents.iter().any(|p| p == &parent_str) {
            entry.parents.push(parent_str);
        }
    }

    /// Like [`Self::add`], but first probes standard library search
    /// paths under `rootfs` and skips the linkage emission entirely
    /// when the soname resolves to a path already claimed by a
    /// package-db reader (dpkg/apk/rpm). Fixes conformance bug 6b
    /// where `libc.so.6` (owned by the libc6 deb) was double-emitting
    /// as `pkg:generic/libc.so.6`.
    pub fn add_with_claim_check(
        &mut self,
        soname: &str,
        parent_path: &Path,
        parent_bom_ref: &str,
        rootfs: &Path,
        claimed: &std::collections::HashSet<PathBuf>,
        #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
    ) {
        if soname_resolves_to_claimed(
            soname,
            rootfs,
            claimed,
            #[cfg(unix)]
            claimed_inodes,
        ) {
            tracing::debug!(
                soname = %soname,
                parent = %parent_path.display(),
                "linkage evidence skipped: soname resolves to a claimed path"
            );
            return;
        }
        self.add(soname, parent_path, parent_bom_ref);
    }

    /// Emit one `PackageDbEntry` per unique soname. Entries are sorted
    /// by PURL for deterministic output.
    pub fn into_entries(self) -> Vec<PackageDbEntry> {
        let mut records: Vec<_> = self.by_soname.into_iter().collect();
        records.sort_by(|a, b| a.0.cmp(&b.0));

        records
            .into_iter()
            .map(|(soname, rec)| PackageDbEntry {
                purl: rec.purl,
                name: soname,
                version: String::new(),
                arch: None,
                // Multiple occurrences land in source_path as semicolon-
                // separated list. The scan_fs conversion turns the first
                // entry into evidence.source_file_paths[0]; future work
                // can split into a full occurrences array.
                source_path: rec.parents.join("; "),
                depends: Vec::new(),
                maintainer: None,
                licenses: vec![],
                is_dev: None,
                requirement_range: None,
                source_type: None,
                sbom_tier: Some("analyzed".to_string()),
                buildinfo_status: None,
                evidence_kind: Some("dynamic-linkage".to_string()),
                binary_class: None,
                binary_stripped: None,
                linkage_kind: None,
                detected_go: None,
                confidence: None,
                binary_packed: None,
                raw_version: None,
                parent_purl: None,
                npm_role: None,
                co_owned_by: None,
                hashes: Vec::new(),
            })
            .collect()
    }
}

impl Default for LinkageAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Soname-specific percent-encoder. Stricter than
/// `encode_purl_segment` — also encodes `/`, `@`, `:`, `~` — because
/// sonames flow into `pkg:generic/<soname>` where the name slot is a
/// single segment and `/` must not be interpreted as a PURL
/// namespace/name separator.
fn percent_encode_soname(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn same_soname_across_binaries_dedups_to_one_component() {
        let mut agg = LinkageAggregator::new();
        agg.add("libssl.so.3", Path::new("/bin/app1"), "bom-ref-1");
        agg.add("libssl.so.3", Path::new("/bin/app2"), "bom-ref-2");
        agg.add("libssl.so.3", Path::new("/bin/app3"), "bom-ref-3");
        agg.add("libc.so.6", Path::new("/bin/app1"), "bom-ref-1");

        let entries = agg.into_entries();
        assert_eq!(entries.len(), 2, "two unique sonames → two components");

        let libssl = entries
            .iter()
            .find(|e| e.name == "libssl.so.3")
            .expect("libssl.so.3 component missing");
        assert_eq!(libssl.purl.as_str(), "pkg:generic/libssl.so.3");
        assert_eq!(libssl.evidence_kind.as_deref(), Some("dynamic-linkage"));
        assert_eq!(libssl.sbom_tier.as_deref(), Some("analyzed"));
        // All three parent paths preserved.
        assert!(libssl.source_path.contains("/bin/app1"));
        assert!(libssl.source_path.contains("/bin/app2"));
        assert!(libssl.source_path.contains("/bin/app3"));
    }

    #[test]
    fn duplicate_parent_not_listed_twice() {
        let mut agg = LinkageAggregator::new();
        agg.add("libc.so.6", Path::new("/bin/app"), "r1");
        agg.add("libc.so.6", Path::new("/bin/app"), "r1"); // duplicate
        let entries = agg.into_entries();
        assert_eq!(entries.len(), 1);
        // Single parent in source_path.
        assert_eq!(entries[0].source_path, "/bin/app");
    }

    #[test]
    fn soname_with_special_chars_percent_encoded() {
        let mut agg = LinkageAggregator::new();
        agg.add(
            "@rpath/libssl.48.dylib",
            Path::new("/bin/macho"),
            "r1",
        );
        let entries = agg.into_entries();
        assert_eq!(entries.len(), 1);
        // `@`, `/` percent-encoded
        let purl = entries[0].purl.as_str();
        assert!(purl.starts_with("pkg:generic/%40rpath%2Flibssl.48.dylib"));
    }

    #[test]
    fn add_with_claim_check_skips_claimed_soname() {
        // Simulate: /lib/x86_64-linux-gnu/libc.so.6 is dpkg-owned
        // (path is in claim set). The linkage aggregator must NOT emit
        // pkg:generic/libc.so.6 for a binary that links it.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        let libc_path = rootfs.join("lib/x86_64-linux-gnu/libc.so.6");
        std::fs::create_dir_all(libc_path.parent().unwrap()).unwrap();
        std::fs::write(&libc_path, b"\x7fELF").unwrap();

        let mut claimed = std::collections::HashSet::new();
        claimed.insert(libc_path.clone());
        #[cfg(unix)]
        let claimed_inodes = std::collections::HashSet::new();

        let mut agg = LinkageAggregator::new();
        agg.add_with_claim_check(
            "libc.so.6",
            Path::new("/bin/app"),
            "r1",
            rootfs,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
        );

        let entries = agg.into_entries();
        assert_eq!(entries.len(), 0, "claimed soname must not emit linkage");
    }

    #[test]
    fn add_with_claim_check_emits_unclaimed_soname() {
        // Soname that doesn't resolve to any standard library dir
        // must still emit (no claim → no skip).
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();

        let claimed = std::collections::HashSet::new();
        #[cfg(unix)]
        let claimed_inodes = std::collections::HashSet::new();

        let mut agg = LinkageAggregator::new();
        agg.add_with_claim_check(
            "libmycustom.so.1",
            Path::new("/bin/app"),
            "r1",
            rootfs,
            &claimed,
            #[cfg(unix)]
            &claimed_inodes,
        );

        let entries = agg.into_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "libmycustom.so.1");
    }
}
