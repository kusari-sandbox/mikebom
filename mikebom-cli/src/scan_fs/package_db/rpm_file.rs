//! Standalone `.rpm` package-file reader. Milestone 004 US1
//! (FR-010..FR-017). Emits one `pkg:rpm/<vendor>/<name>@<epoch>:<version>-<release>?arch=<arch>`
//! component per `.rpm` artefact observed, with licenses + supplier +
//! REQUIRES populated from header tags.
//!
//! Parsing uses the `rpm` crate (pure-Rust, audited Principle-I clean
//! per research R1 + task T002). Defense-in-depth:
//! - Per-file size cap of 200 MB (FR-007).
//! - Magic-byte validation at offset 0 (`\xED\xAB\xEE\xDB`) before
//!   handing to the parser (FR-011).
//! - Fail-graceful on malformed inputs: single WARN + zero components
//!   for that file; the overall scan continues (FR-017).
//!
//! Vendor-slug priority per FR-013 / research R9:
//! 1. Header `Vendor:` tag regex-matched against a 9-entry table.
//! 2. `/etc/os-release::ID` via the milestone-003 `rpm_vendor_from_id`.
//! 3. Hardcoded `"rpm"` fallback.

use std::path::{Path, PathBuf};

use mikebom_common::types::license::SpdxExpression;
use mikebom_common::types::purl::Purl;

use super::{rpm_vendor_from_id, PackageDbEntry};
use crate::scan_fs::os_release;

/// Per-file size cap per FR-007. Real `.rpm` files are typically a few
/// megabytes; anything above 200 MB is defense-in-depth rejected.
const MAX_RPM_FILE_BYTES: u64 = 200 * 1024 * 1024;

/// Lower size bound — RPM lead block alone is 96 bytes; anything below
/// that cannot be a valid RPM regardless of claim.
const MIN_RPM_FILE_BYTES: u64 = 96;

/// RPM v3/v4 lead-block magic at offset 0.
const RPM_LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];

/// Ordered vendor-header → PURL-slug table per research R9. First
/// prefix match wins. Most specific entries come first so `openSUSE`
/// doesn't get shadowed by `SUSE`.
const VENDOR_HEADER_MAP: &[(&str, &str)] = &[
    ("Red Hat", "redhat"),
    ("Fedora Project", "fedora"),
    ("Rocky Enterprise Software Foundation", "rocky"),
    ("Rocky Linux", "rocky"),
    ("Amazon Linux", "amazon"),
    ("Amazon.com", "amazon"),
    ("CentOS", "centos"),
    ("Oracle America", "oracle"),
    ("AlmaLinux OS Foundation", "almalinux"),
    ("openSUSE", "opensuse"),
    ("SUSE", "suse"),
];

/// Which source populated the vendor slug — drives the
/// `mikebom:vendor-source` property (not yet wired at serialization
/// time in this pass; `vendor_source` is recorded on the return
/// channel for future use by T017's property-bag plumbing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorSource {
    Header,
    OsRelease,
    Fallback,
}

impl VendorSource {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            VendorSource::Header => "header",
            VendorSource::OsRelease => "os-release",
            VendorSource::Fallback => "fallback",
        }
    }
}

/// Resolve the PURL vendor segment. Priority: header → os-release → fallback.
///
/// # Examples
/// ```ignore
/// resolve_rpm_vendor_slug(Some("Red Hat, Inc."), None)
///     == ("redhat".to_string(), VendorSource::Header)
/// resolve_rpm_vendor_slug(None, Some("fedora"))
///     == ("fedora".to_string(), VendorSource::OsRelease)
/// resolve_rpm_vendor_slug(None, None)
///     == ("rpm".to_string(), VendorSource::Fallback)
/// ```
pub fn resolve_rpm_vendor_slug(
    header_vendor: Option<&str>,
    os_release_id: Option<&str>,
) -> (String, VendorSource) {
    if let Some(v) = header_vendor.filter(|s| !s.is_empty()) {
        for (pattern, slug) in VENDOR_HEADER_MAP {
            if v.starts_with(pattern) {
                return ((*slug).to_string(), VendorSource::Header);
            }
        }
    }
    if let Some(id) = os_release_id.filter(|s| !s.is_empty()) {
        let slug = rpm_vendor_from_id(id);
        if !slug.is_empty() {
            return (slug, VendorSource::OsRelease);
        }
    }
    ("rpm".to_string(), VendorSource::Fallback)
}

/// Recursively discover `.rpm` files under `rootfs` and parse each
/// valid header, returning one `PackageDbEntry` per successful parse.
/// Missing `.rpm` files → empty vector (not an error; FR-005). Single
/// `.rpm` file passed as `rootfs` → still works (treated as its own
/// scan root with no nested walk needed).
pub fn read(rootfs: &Path, distro_version: Option<&str>) -> Vec<PackageDbEntry> {
    let os_release_id = os_release::read_id_from_rootfs(rootfs);

    let mut out = Vec::new();
    for path in discover_rpm_files(rootfs) {
        if let Some(entry) =
            parse_rpm_file(&path, os_release_id.as_deref(), distro_version)
        {
            out.push(entry);
        }
    }
    out
}

/// Walk a scan root for files ending in `.rpm` (case-insensitive)
/// AND whose first four bytes match the lead-block magic per FR-011.
/// Extension match alone is not sufficient — someone may rename a
/// file — so every candidate passes through the magic probe.
fn discover_rpm_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if root.is_file() {
        // Single-file invocation: only yield if it looks like a `.rpm`.
        if is_rpm_candidate(root) {
            found.push(root.to_path_buf());
        }
        return found;
    }
    if !root.is_dir() {
        return found;
    }
    walk_dir(root, &mut found);
    found
}

fn walk_dir(dir: &Path, acc: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Skip typical build-artefact / version-control directories.
        // Keeps the walk bounded on large checkouts.
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                ".git" | "target" | "node_modules" | ".cargo" | "__pycache__" | ".venv"
            ) {
                continue;
            }
            walk_dir(&path, acc);
        } else if path.is_file() && is_rpm_candidate(&path) {
            acc.push(path);
        }
    }
}

fn is_rpm_candidate(path: &Path) -> bool {
    let ext_matches = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("rpm"))
        .unwrap_or(false);
    if !ext_matches {
        return false;
    }
    // Read just the first 4 bytes to check magic, not the whole file.
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => magic == RPM_LEAD_MAGIC,
        Err(_) => false,
    }
}

/// Parse one `.rpm` file via the `rpm` crate and convert to a
/// `PackageDbEntry`. Returns `None` on any failure — single WARN line
/// in every case per FR-017.
fn parse_rpm_file(
    path: &Path,
    os_release_id: Option<&str>,
    distro_version: Option<&str>,
) -> Option<PackageDbEntry> {
    let size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                reason = "stat-failed",
                "skipping malformed .rpm file"
            );
            return None;
        }
    };
    if size < MIN_RPM_FILE_BYTES {
        tracing::warn!(
            path = %path.display(),
            size = size,
            reason = "truncated-lead",
            "skipping malformed .rpm file"
        );
        return None;
    }
    if size > MAX_RPM_FILE_BYTES {
        tracing::warn!(
            path = %path.display(),
            size = size,
            reason = "size-cap-exceeded",
            "skipping malformed .rpm file"
        );
        return None;
    }

    let pkg = match rpm::Package::open(path) {
        Ok(p) => p,
        Err(e) => {
            let reason = classify_rpm_error(&e);
            tracing::warn!(
                path = %path.display(),
                error = %e,
                reason = reason,
                "skipping malformed .rpm file"
            );
            return None;
        }
    };
    let md = &pkg.metadata;

    let name = md.get_name().ok()?.to_string();
    // Feature 005 US4: distinguish "EPOCH tag present" from "EPOCH tag
    // absent" so the PURL mirrors `rpm -qa`'s behaviour for EPOCH=0.
    // `rpm::PackageMetadata::get_epoch()` returns `Ok(v)` on tag-present
    // and `Err(_)` on tag-absent (no separate "present-but-zero" state
    // at the crate level — we conservatively treat `Ok(0)` as
    // tag-present, matching `rpm -qa`'s `0:…` display).
    let epoch: Option<i64> = md.get_epoch().ok().map(|v| v as i64);
    let version = md.get_version().ok()?.to_string();
    let release = md.get_release().ok()?.to_string();
    let arch = md.get_arch().ok()?.to_string();

    let vendor_header = md
        .get_vendor()
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let packager = md
        .get_packager()
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let license_str = md
        .get_license()
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    // REQUIRES → bare names (tokenised per FR-015). Drop rpmlib(...)
    // and soname-style `(...)` entries — those are not installable
    // packages.
    let requires: Vec<String> = md
        .get_requires()
        .ok()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| {
            let n = d.name.trim();
            if n.is_empty() || n.starts_with("rpmlib(") || n.starts_with('/') {
                None
            } else if n.contains('(') {
                // soname-style e.g. `libc.so.6()(64bit)` — drop, they're
                // not package names.
                None
            } else {
                Some(n.to_string())
            }
        })
        .collect();

    let (vendor_slug, _vendor_source) =
        resolve_rpm_vendor_slug(vendor_header.as_deref(), os_release_id);

    // Build canonical PURL per FR-012. Feature 005 US4 alignment: the
    // EPOCH goes in the `&epoch=N` qualifier, NEVER inline in the
    // version segment. This matches `rpm.rs::assemble_entry` (the
    // rpmdb reader) and PURL-TYPES.rst §rpm. Prior behaviour here
    // emitted `NAME@EPOCH:VERSION-RELEASE` which was a divergence.
    //
    // v7 Phase G: append `&distro=<vendor>-<VERSION_ID>` when the
    // dispatcher passed a VERSION_ID, matching the rpmdb reader's
    // behaviour and ground truth
    // (`pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=aarch64&distro=rocky-9.3`).
    let version_tok = format!("{version}-{release}");
    // Omit epoch=0; treat 0 as semantically "no epoch" (matches the
    // rpmdb reader at rpm.rs::assemble_entry — same canonical-form
    // rationale).
    let epoch_seg = match epoch {
        Some(v) if v != 0 => format!("&epoch={v}"),
        _ => String::new(),
    };
    let distro_seg = match distro_version {
        Some(dv) if !dv.is_empty() => {
            format!("&distro={vendor_slug}-{dv}")
        }
        _ => String::new(),
    };
    // purl-spec § Character encoding: route both name AND version
    // through the canonical `encode_purl_segment` (the deb builder
    // and rpmdb reader both do this). The local `percent_encode_purl_version`
    // here explicitly allowed `+` literal (see `is_purl_version_safe`),
    // producing non-conformant PURLs for any RPM with `+` in its
    // version. Arch qualifier keeps its local stricter encoder — it
    // follows a different rule set per spec.
    let purl_str = format!(
        "pkg:rpm/{}/{}@{}?arch={}{}{}",
        percent_encode_purl_segment(&vendor_slug),
        mikebom_common::types::purl::encode_purl_segment(&name),
        mikebom_common::types::purl::encode_purl_segment(&version_tok),
        percent_encode_purl_qualifier(&arch),
        epoch_seg,
        distro_seg,
    );
    let purl = Purl::new(&purl_str).ok()?;

    let licenses: Vec<SpdxExpression> = license_str
        .as_deref()
        .and_then(|l| SpdxExpression::try_canonical(l).ok())
        .into_iter()
        .collect();

    // `supplier.name` gets the raw header `Vendor:` string (per FR-014
    // — preserved verbatim for CycloneDX `component.supplier.name`).
    // `maintainer` field on PackageDbEntry drives that slot.
    let maintainer = vendor_header.or(packager);

    Some(PackageDbEntry {
        purl,
        name,
        version: version_tok.clone(),
        arch: if arch.is_empty() { None } else { Some(arch) },
        source_path: path.to_string_lossy().into_owned(),
        depends: requires,
        maintainer,
        licenses,
        is_dev: None,
        requirement_range: None,
        source_type: None,
        sbom_tier: Some("source".to_string()),
        shade_relocation: None,
        buildinfo_status: None,
        evidence_kind: Some("rpm-file".to_string()),
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: None,
        confidence: None,
        binary_packed: None,
        // Feature 005 US4: same verbatim `VERSION-RELEASE` preservation
        // as `rpm::assemble_entry`. Drives the `mikebom:raw-version`
        // property at CycloneDX serialisation time.
        raw_version: Some(version_tok),
        parent_purl: None,
        npm_role: None,
        co_owned_by: None,
        hashes: Vec::new(),
    })
}

/// Classify an `rpm::Error` into a short stable reason string for WARN
/// log output. Downstream tests assert on these.
fn classify_rpm_error(e: &rpm::Error) -> &'static str {
    let msg = e.to_string();
    if msg.contains("magic") || msg.contains("Magic") {
        "bad-magic"
    } else if msg.contains("truncated") || msg.contains("EOF") || msg.contains("Unexpected") {
        "truncated-header"
    } else if msg.contains("index") {
        "header-index-over-cap"
    } else {
        "parse-error"
    }
}

/// Minimal percent-encoding for PURL name / namespace segments. Keeps
/// unreserved chars, percent-encodes everything else. Matches the
/// packageurl-python canonical encoding shape.
fn percent_encode_purl_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if is_purl_segment_safe(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_encode_purl_version(s: &str) -> String {
    // Version segment preserves `:` for epoch and `-` for release per
    // packageurl-python canonical form.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if is_purl_version_safe(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_encode_purl_qualifier(s: &str) -> String {
    // Qualifier values are similar to segment but allow `.`, `_`.
    percent_encode_purl_segment(s)
}

fn is_purl_segment_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_purl_version_safe(b: u8) -> bool {
    // Allow `:` and `-` in version segment (epoch + release).
    is_purl_segment_safe(b) || matches!(b, b':' | b'-' | b'+')
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn vendor_header_redhat_family() {
        let (slug, src) = resolve_rpm_vendor_slug(Some("Red Hat, Inc."), None);
        assert_eq!(slug, "redhat");
        assert_eq!(src, VendorSource::Header);
    }

    #[test]
    fn vendor_header_fedora() {
        let (slug, _) = resolve_rpm_vendor_slug(Some("Fedora Project"), None);
        assert_eq!(slug, "fedora");
    }

    #[test]
    fn vendor_header_rocky_foundation() {
        let (slug, _) = resolve_rpm_vendor_slug(
            Some("Rocky Enterprise Software Foundation"),
            None,
        );
        assert_eq!(slug, "rocky");
    }

    #[test]
    fn vendor_header_rocky_linux_branding() {
        let (slug, _) = resolve_rpm_vendor_slug(Some("Rocky Linux"), None);
        assert_eq!(slug, "rocky");
    }

    #[test]
    fn vendor_header_opensuse_not_shadowed_by_suse() {
        let (slug, _) = resolve_rpm_vendor_slug(Some("openSUSE"), None);
        assert_eq!(slug, "opensuse");
    }

    #[test]
    fn vendor_header_suse_matches() {
        let (slug, _) = resolve_rpm_vendor_slug(Some("SUSE LLC"), None);
        assert_eq!(slug, "suse");
    }

    #[test]
    fn vendor_falls_back_to_os_release() {
        let (slug, src) = resolve_rpm_vendor_slug(None, Some("rhel"));
        assert_eq!(slug, "redhat");
        assert_eq!(src, VendorSource::OsRelease);
    }

    #[test]
    fn vendor_falls_back_to_rpm_when_nothing_resolves() {
        let (slug, src) = resolve_rpm_vendor_slug(None, None);
        assert_eq!(slug, "rpm");
        assert_eq!(src, VendorSource::Fallback);
    }

    #[test]
    fn vendor_empty_header_falls_through() {
        let (slug, src) = resolve_rpm_vendor_slug(Some(""), Some("fedora"));
        assert_eq!(slug, "fedora");
        assert_eq!(src, VendorSource::OsRelease);
    }

    #[test]
    fn empty_scan_root_yields_zero_entries() {
        let dir = tempfile::tempdir().unwrap();
        let entries = read(dir.path(), None);
        assert!(entries.is_empty());
    }

    #[test]
    fn non_rpm_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("not-rpm.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("fake.rpm"), b"NOT_RPM_MAGIC").unwrap();
        let entries = read(dir.path(), None);
        assert!(entries.is_empty());
    }

    #[test]
    fn case_insensitive_extension_match() {
        let dir = tempfile::tempdir().unwrap();
        // Wrong magic → still skipped, but the extension casing is
        // accepted (the discovery pass runs; parse fails gracefully).
        std::fs::write(dir.path().join("FOO.RPM"), b"xxxx").unwrap();
        let entries = read(dir.path(), None);
        assert!(entries.is_empty());
    }

    /// End-to-end: build a synthetic `.rpm` file via the `rpm` crate's
    /// `PackageBuilder`, write it to a tempdir, scan the tempdir, and
    /// verify the resulting `PackageDbEntry`.
    #[test]
    fn parses_synthetic_rpm_file() {
        let dir = tempfile::tempdir().unwrap();
        let rpm_path = dir.path().join("synthetic-1.0-1.el9.x86_64.rpm");

        // Build a minimal valid RPM via the crate's builder. No files,
        // no scriptlets — just the header.
        let pkg = rpm::PackageBuilder::new(
            "synthetic",
            "1.0",
            "MIT",
            "x86_64",
            "synthetic test package",
        )
        .release("1.el9")
        .vendor("Red Hat, Inc.")
        .packager("test-builder")
        .description("fixture for milestone 004 US1 parser tests")
        .requires(rpm::Dependency::any("zlib"))
        .requires(rpm::Dependency::any("libc"))
        .requires(rpm::Dependency::any("rpmlib(FileDigests)")) // should be dropped
        .build()
        .unwrap();
        pkg.write_file(&rpm_path).unwrap();

        let entries = read(dir.path(), None);
        assert_eq!(entries.len(), 1, "expected exactly one entry");

        let e = &entries[0];
        assert_eq!(e.name, "synthetic");
        assert_eq!(e.version, "1.0-1.el9");
        assert_eq!(e.arch.as_deref(), Some("x86_64"));
        assert_eq!(e.source_path, rpm_path.to_string_lossy());
        assert_eq!(e.sbom_tier.as_deref(), Some("source"));
        assert_eq!(e.evidence_kind.as_deref(), Some("rpm-file"));
        assert_eq!(e.maintainer.as_deref(), Some("Red Hat, Inc."));

        // Canonical PURL — Red Hat vendor slug, no epoch, qualifier arch.
        assert_eq!(
            e.purl.as_str(),
            "pkg:rpm/redhat/synthetic@1.0-1.el9?arch=x86_64"
        );

        // rpmlib() dependency dropped; zlib + libc kept.
        assert!(e.depends.iter().any(|d| d == "zlib"));
        assert!(e.depends.iter().any(|d| d == "libc"));
        assert!(!e.depends.iter().any(|d| d.starts_with("rpmlib")));

        // License canonicalised via SPDX expression. MIT survives.
        assert!(!e.licenses.is_empty());
    }

    #[test]
    fn epoch_nonzero_surfaces_in_purl() {
        let dir = tempfile::tempdir().unwrap();
        let rpm_path = dir.path().join("epochy.rpm");
        let pkg = rpm::PackageBuilder::new("epochy", "2.0", "MIT", "noarch", "x")
            .release("1")
            .epoch(7)
            .vendor("Fedora Project")
            .build()
            .unwrap();
        pkg.write_file(&rpm_path).unwrap();

        let entries = read(dir.path(), None);
        assert_eq!(entries.len(), 1);
        // Feature 005 US4: epoch moved from inline (`@7:2.0-1`) to the
        // `&epoch=7` qualifier — matches `rpm.rs::assemble_entry` and
        // PURL-TYPES.rst §rpm. Pre-005 expected `@7:2.0-1`; updated.
        assert_eq!(
            entries[0].purl.as_str(),
            "pkg:rpm/fedora/epochy@2.0-1?arch=noarch&epoch=7"
        );
    }

    /// T046 — `raw_version` populated on the artefact path too; holds
    /// the verbatim `VERSION-RELEASE` string (with no inline epoch).
    #[test]
    fn parse_rpm_file_populates_raw_version() {
        let dir = tempfile::tempdir().unwrap();
        let rpm_path = dir.path().join("raw.rpm");
        let pkg = rpm::PackageBuilder::new("raw-pkg", "3.1.4", "MIT", "noarch", "x")
            .release("2.fc40")
            .vendor("Fedora Project")
            .build()
            .unwrap();
        pkg.write_file(&rpm_path).unwrap();
        let entries = read(dir.path(), None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].raw_version.as_deref(), Some("3.1.4-2.fc40"));
    }

    #[test]
    fn malformed_rpm_emits_zero_entries_without_erroring() {
        let dir = tempfile::tempdir().unwrap();
        // Magic matches but body is garbage.
        let mut bytes = RPM_LEAD_MAGIC.to_vec();
        bytes.extend_from_slice(&[0u8; 200]);
        std::fs::write(dir.path().join("bad.rpm"), &bytes).unwrap();
        let entries = read(dir.path(), None);
        assert!(entries.is_empty(), "malformed .rpm must not panic or propagate");
    }

    #[test]
    fn dedup_source_path_not_eq_same_purl() {
        // Two synthetic RPMs with the same identity → two entries
        // (dedup happens at the scan_fs orchestrator level via PURL;
        // the reader returns both and lets upstream dedup decide).
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.rpm", "b.rpm"] {
            let pkg = rpm::PackageBuilder::new("dup", "1.0", "MIT", "noarch", "x")
                .release("1")
                .vendor("Fedora Project")
                .build()
                .unwrap();
            pkg.write_file(dir.path().join(name)).unwrap();
        }
        let entries = read(dir.path(), None);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].purl, entries[1].purl);
    }
}
