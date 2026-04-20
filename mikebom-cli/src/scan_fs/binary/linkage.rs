//! Global per-PURL linkage-evidence dedup per FR-028a (Q5).
//! N binaries referencing the same soname produce ONE `pkg:generic/<soname>`
//! component with N occurrences merged into the evidence trail (via the
//! `source_path` field on PackageDbEntry — the scan_fs conversion
//! layer promotes that into CycloneDX `evidence.occurrences[]`).

use std::collections::HashMap;
use std::path::Path;

use mikebom_common::types::purl::Purl;

use crate::scan_fs::package_db::PackageDbEntry;

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
            let purl_str = format!("pkg:generic/{}", percent_encode(soname));
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
                npm_role: None,
            })
            .collect()
    }
}

impl Default for LinkageAggregator {
    fn default() -> Self {
        Self::new()
    }
}

fn percent_encode(s: &str) -> String {
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
}
