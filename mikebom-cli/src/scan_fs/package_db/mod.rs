//! Read installed-package databases from a filesystem root.
//!
//! Two formats supported this round:
//! - **dpkg**: `<root>/var/lib/dpkg/status` (Debian, Ubuntu, derivatives)
//! - **apk**: `<root>/lib/apk/db/installed` (Alpine, Wolfi)
//!
//! The dispatcher tries both and returns whichever parses cleanly. In
//! the rare case a rootfs has *both* (it shouldn't; no real distro
//! does), entries are returned in the order the readers were tried —
//! dpkg first, then apk. The scan pipeline de-duplicates by PURL so
//! that scenario's output is still well-formed.

pub mod apk;
pub mod cargo;
pub mod copyright;
pub mod dpkg;
pub mod file_hashes;
pub mod gem;
pub mod go_binary;
pub mod golang;
pub mod maven;
pub mod npm;
pub mod pip;
pub mod rpm;
pub mod rpm_file;
pub mod rpmdb_bdb;
pub mod rpmdb_sqlite;

use std::path::Path;

use mikebom_common::types::license::SpdxExpression;
use mikebom_common::types::purl::Purl;

/// A parsed row from an OS package database, normalised to the shape
/// the scan pipeline consumes. `source_path` is the db file we read —
/// it goes straight into the resulting `ResolutionEvidence.source_file_paths`.
#[derive(Clone, Debug)]
pub struct PackageDbEntry {
    pub purl: Purl,
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    pub source_path: String,
    /// Raw dependency package names declared by this entry (dpkg's
    /// `Depends:` field, apk's `D:` field). Version constraints and
    /// alternative (`|`) separators are already tokenised into
    /// individual names here; the scan orchestrator looks each name
    /// up against the set of entries found in the same scan and drops
    /// any that don't resolve.
    pub depends: Vec<String>,
    /// Free-form package supplier — for dpkg, the `Maintainer:` field
    /// (e.g. `"Matthias Klose <doko@debian.org>"`). Maps directly to
    /// CycloneDX `component.supplier.name`. `None` when the source db
    /// doesn't carry a supplier (apk's installed db has no equivalent
    /// per-package field).
    pub maintainer: Option<String>,
    /// Dev-vs-prod classification for ecosystems that carry the
    /// distinction (npm `devDependencies`, Poetry `category = "dev"`,
    /// Pipfile `develop:`). `Some(false)` = observed as a prod dep,
    /// `Some(true)` = dev-only, `None` = source doesn't carry the
    /// distinction (dpkg, apk, venv `.dist-info`, `requirements.txt`).
    /// Drives the `mikebom:dev-dependency` property at serialization.
    pub is_dev: Option<bool>,
    /// Original unresolved requirement specification for fallback-tier
    /// entries (`requirements.txt` lines, root `package.json`
    /// dependencies). `None` for authoritative sources.
    /// Drives the `mikebom:requirement-range` property at serialization.
    pub requirement_range: Option<String>,
    /// Source-kind marker for non-registry dependencies: `"local"`
    /// (file:), `"git"` (git+...), `"url"` (http(s)://...). `None`
    /// for normal registry-sourced components. Drives the
    /// `mikebom:source-type` property at serialization.
    pub source_type: Option<String>,
    /// Licenses the source embedded directly on the entry (e.g. pypi's
    /// `dist-info/METADATA::License-Expression:`, npm's
    /// `package.json::license:`). Empty for sources where licenses are
    /// resolved out-of-band (dpkg reads `/usr/share/doc/<pkg>/copyright`
    /// separately in `scan_fs::mod.rs`; apk doesn't carry licenses
    /// inline in the scan yet). When populated, `scan_fs::scan_path`
    /// uses these values instead of calling an out-of-band resolver.
    pub licenses: Vec<SpdxExpression>,
    /// Go-binary BuildInfo extraction status for diagnostic file-level
    /// entries (FR-015, milestone 003 US1). `Some("missing")` means the
    /// magic bytes were absent; `Some("unsupported")` means the format
    /// variant isn't implemented (pre-1.18 pointer-indirection). `None`
    /// for every non-diagnostic entry. Drives the
    /// `mikebom:buildinfo-status` property at serialization.
    pub buildinfo_status: Option<String>,
    /// Traceability-ladder tier per research.md R13 (Milestone 002):
    /// `"deployed"` (installed-package-db entries — dpkg, apk, Python
    /// venv, npm `node_modules/`), `"analyzed"` (artefact files on
    /// disk, identified by filename + hash), `"source"` (lockfile
    /// entries without a corresponding install), `"design"` (unlocked
    /// manifest entries — requirements.txt ranges, root package.json
    /// fallback). `None` during transition to preserve compatibility
    /// with any PackageDbEntry construction site that hasn't been
    /// retrofitted yet. Trace-mode components carry `"build"` but
    /// don't flow through PackageDbEntry.
    pub sbom_tier: Option<String>,
    /// Milestone 004: canonical `mikebom:evidence-kind` value per
    /// `contracts/schema.md`. One of:
    /// - `rpm-file` — `.rpm` artefact reader
    /// - `rpmdb-sqlite` — milestone-003 sqlite rpmdb reader (retrofit Q7)
    /// - `rpmdb-bdb` — legacy BDB rpmdb reader (US4)
    /// - `dynamic-linkage` — ELF DT_NEEDED / Mach-O LC_LOAD_DYLIB / PE IMPORT
    /// - `elf-note-package` — systemd Packaging Metadata Notes
    /// - `embedded-version-string` — curated heuristic scanner
    ///
    /// `None` on readers not yet retrofitted (milestones 001–003 non-rpm
    /// ecosystems). Drives the `mikebom:evidence-kind` property at
    /// serialization; value space is enforced by a `debug_assert!` gate
    /// in `generate/cyclonedx/builder.rs`.
    pub evidence_kind: Option<String>,
    /// Milestone 004 US2 — file-level binary classifier (`"elf"` /
    /// `"macho"` / `"pe"`). Set only on file-level binary components
    /// emitted by the new `scan_fs::binary` reader.
    pub binary_class: Option<String>,
    /// Milestone 004 US2 — true when format-appropriate debug / symbol
    /// / version metadata is absent on a file-level binary component.
    pub binary_stripped: Option<bool>,
    /// Milestone 004 US2 — `"dynamic"` / `"static"` / `"mixed"` on
    /// file-level binary components.
    pub linkage_kind: Option<String>,
    /// Milestone 004 US2 — set to `Some(true)` on a file-level binary
    /// component when the Go BuildInfo extractor also matched on the
    /// same binary (R8 flat cross-link).
    pub detected_go: Option<bool>,
    /// Milestone 004 US2 — `"heuristic"` on components emitted via the
    /// curated embedded-version-string scanner (FR-025).
    pub confidence: Option<String>,
    /// Milestone 004 US2 — `"upx"` when a UPX packer signature was
    /// detected on a file-level binary component. `None` otherwise.
    pub binary_packed: Option<String>,
    /// Feature 005 US4 — the raw `<VERSION>-<RELEASE>` string from the
    /// rpmdb header (or `.rpm` artefact), preserved verbatim before any
    /// PURL encoding. Drives the `mikebom:raw-version` property at
    /// serialization. `None` on non-rpm readers.
    pub raw_version: Option<String>,
    /// Feature 005 US1 — role marker for packages that are part of a
    /// package-manager's own toolchain rather than an application
    /// dependency. Currently set to `Some("internal")` by the npm
    /// reader on packages under the canonical `**/node_modules/npm/node_modules/**`
    /// glob. Drives the `mikebom:npm-role` CycloneDX component property.
    pub npm_role: Option<String>,
}

/// Hard failures a database reader can raise that MUST abort the scan
/// rather than degrade silently. Currently the only case is the npm
/// v1 lockfile refusal — per `contracts/cli-interface.md` the CLI must
/// emit a specific stderr message and exit non-zero rather than produce
/// a partial SBOM.
#[derive(Debug, thiserror::Error)]
pub enum PackageDbError {
    #[error("{0}")]
    Npm(#[from] npm::NpmError),
    #[error("{0}")]
    Cargo(#[from] cargo::CargoError),
}

/// Aggregate output of all package-db readers. Milestone-004 post-ship
/// fix for the binary-walker double-counting issue: when a file is
/// claimed by a package-db reader (dpkg `.list`, apk `R:`, pip `RECORD`),
/// the binary walker must skip its file-level + linkage-evidence
/// emissions for that path to avoid reporting the same file as both
/// `pkg:deb/…/coreutils` AND `pkg:generic/base64?file-sha256=…`.
///
/// `.note.package` + embedded-version-string emissions remain unconditional
/// because those surface signals the package-db can't produce (distro
/// self-identification, statically-linked TLS-library versions).
#[derive(Debug, Default)]
pub struct DbScanResult {
    pub entries: Vec<PackageDbEntry>,
    /// Absolute rootfs-joined paths claimed by at least one package-db
    /// reader. Each claim is inserted in raw form + parent-canonical
    /// form so the walker's path matches against either representation
    /// on usrmerged rootfs.
    pub claimed_paths: std::collections::HashSet<std::path::PathBuf>,
    /// (device, inode) pairs of every claimed file that exists at
    /// claim-insert time. Provides symlink-robust matching that closes
    /// the gap path-based matching leaves for hard links, canonicalize
    /// output-form differences, and multiarch path quirks. If the
    /// walker's binary and a claim share (dev, ino), they're the same
    /// physical file — no path-level reasoning required.
    #[cfg(unix)]
    pub claimed_inodes: std::collections::HashSet<(u64, u64)>,
    /// Feature 005 — non-fatal diagnostics collected during `read_all`.
    /// Surfaced into the SBOM's `metadata.properties` so consumers can
    /// detect degraded output without needing the scanner's log stream.
    pub diagnostics: ScanDiagnostics,
}

/// Non-fatal scan-time diagnostics accumulated during `read_all`. Drives
/// document-level CycloneDX `metadata.properties` entries so SBOM
/// consumers can detect degraded output (missing `/etc/os-release` fields,
/// etc.) without needing access to the scanner's log stream.
///
/// Intentionally open-ended — future scan-time diagnostics (rpmdb WAL
/// warnings, docker extraction failures) can be added without churning
/// cross-module signatures.
#[derive(Default, Debug, Clone)]
pub struct ScanDiagnostics {
    /// Fields from `/etc/os-release` that were absent or empty when the
    /// dpkg/apk/rpm readers tried to read them. Each entry is a string
    /// naming the missing field (e.g. `"ID"`, `"VERSION_ID"`).
    /// Deduplicated; insertion order preserved for determinism.
    pub os_release_missing_fields: Vec<String>,
}

impl ScanDiagnostics {
    /// Record a missing os-release field. No-op if the same field was
    /// already recorded — preserves idempotency for readers that check
    /// the same field multiple times within a single scan.
    pub fn record_missing_os_release_field(&mut self, field: &str) {
        if !self.os_release_missing_fields.iter().any(|f| f == field) {
            self.os_release_missing_fields.push(field.to_string());
        }
    }
}

/// Insert a claimed path into the set in BOTH raw and parent-canonical
/// forms AND (on unix) record the file's (device, inode) tuple.
///
/// The raw path form matches walker paths on plain (non-usrmerge)
/// rootfs. The parent-canonical form handles directory-level symlinks
/// (`/bin → usr/bin`). The (dev, inode) tuple handles final-component
/// symlinks and hard links — any two paths pointing to the same
/// physical file share the same tuple, bypassing path-form quirks
/// entirely.
///
/// Parent canonicalization rather than full-path canonicalization
/// because the file itself might not exist at claim time (some
/// `.list` entries reference files removed post-install), but the
/// parent directory's symlink resolution is stable and cheap.
pub(crate) fn insert_claim_with_canonical(
    claimed: &mut std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &mut std::collections::HashSet<(u64, u64)>,
    abs_path: std::path::PathBuf,
) {
    if let (Some(parent), Some(basename)) = (abs_path.parent(), abs_path.file_name()) {
        if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
            let canonical = canonical_parent.join(basename);
            if canonical != abs_path {
                claimed.insert(canonical);
            }
        }
    }
    // Record (dev, inode) of both the symlink itself AND its resolved
    // target. If dpkg lists the symlink, walker walking the target
    // still matches via target's inode. If dpkg lists the target,
    // walker walking the symlink still matches via symlink's inode
    // (which in Unix semantics IS the target's inode — symlinks don't
    // have their own inode in the directory-entry sense; `metadata`
    // follows symlinks and `symlink_metadata` reveals the symlink
    // itself, which has its own inode on the filesystem).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::symlink_metadata(&abs_path) {
            claimed_inodes.insert((meta.dev(), meta.ino()));
        }
        if let Ok(meta) = std::fs::metadata(&abs_path) {
            claimed_inodes.insert((meta.dev(), meta.ino()));
        }
    }
    claimed.insert(abs_path);
}

/// Try every supported database reader against `rootfs` and return all
/// successful entries. Missing db files are not an error — a rootfs
/// with no apt/apk is just empty output. Only fail-closed errors (npm
/// v1 lockfile per FR-006) propagate as `Err`.
///
/// * `rootfs` — absolute path to a rootfs directory (the output of
///   `docker_image::extract` or a user-supplied `--path`).
/// * `deb_codename` — used to stamp the `distro=` qualifier on deb
///   PURLs when present.
pub fn read_all(
    rootfs: &Path,
    _deb_codename: Option<&str>,
    include_dev: bool,
    include_legacy_rpmdb: bool,
    scan_mode: crate::scan_fs::ScanMode,
) -> Result<DbScanResult, PackageDbError> {
    let mut out = Vec::new();
    let mut claimed: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();
    #[cfg(unix)]
    let mut claimed_inodes: std::collections::HashSet<(u64, u64)> =
        std::collections::HashSet::new();
    let mut diagnostics = ScanDiagnostics::default();

    // Feature 005 US2/US3: read os-release once per scan. `ID`
    // drives the deb/rpm/apk PURL namespace + distro-qualifier prefix
    // (falls back to `debian` when missing, with diagnostic emitted).
    // `VERSION_ID` becomes the version half of the qualifier (omitted
    // when missing). Both are recorded in ScanDiagnostics so the SBOM
    // surfaces whichever were missing in `metadata.properties`.
    //
    // v6 fix (conformance bug 1): use the rootfs-aware reader which
    // tries `/etc/os-release` first and falls back to
    // `/usr/lib/os-release` (per the os-release spec) when the primary
    // is missing. Ubuntu 24.04 ships `/etc/os-release` as a relative
    // symlink to `../usr/lib/os-release`; some layer-reorderings during
    // container-image extraction can leave the symlink dangling, which
    // was causing Ubuntu images to fall back to the `debian` namespace.
    let id_raw = crate::scan_fs::os_release::read_id_from_rootfs(rootfs);
    let distro_version =
        crate::scan_fs::os_release::read_version_id_from_rootfs(rootfs);
    let deb_namespace: String = match &id_raw {
        Some(id) if !id.is_empty() => id.to_ascii_lowercase(),
        _ => {
            diagnostics.record_missing_os_release_field("ID");
            "debian".to_string()
        }
    };
    if distro_version.is_none() {
        diagnostics.record_missing_os_release_field("VERSION_ID");
    }

    match dpkg::read(rootfs, &deb_namespace, distro_version.as_deref()) {
        Ok(entries) => {
            out.extend(entries);
            // Milestone 004 post-ship: collect dpkg-owned file paths
            // (from /var/lib/dpkg/info/*.list) + inodes. Drives the
            // binary walker's skip gate so /usr/bin/base64 et al.
            // don't produce duplicate pkg:generic/ components.
            dpkg::collect_claimed_paths(
                rootfs,
                &mut claimed,
                #[cfg(unix)]
                &mut claimed_inodes,
            );
        }
        Err(e) => tracing::debug!(error = %e, "dpkg db read failed (expected if no dpkg)"),
    }
    match apk::read(rootfs, distro_version.as_deref()) {
        Ok(entries) => {
            out.extend(entries);
            // Milestone 004 post-ship: collect apk-owned file paths.
            apk::collect_claimed_paths(
                rootfs,
                &mut claimed,
                #[cfg(unix)]
                &mut claimed_inodes,
            );
        }
        Err(e) => tracing::debug!(error = %e, "apk db read failed (expected if no apk)"),
    }

    // Python: venv dist-info + lockfiles + requirements.txt per R13 tiers.
    // No fail-closed: an empty Python section is fine if the scan root
    // doesn't contain any Python artefacts.
    out.extend(pip::read(rootfs, include_dev));
    // Collect pip-claimed paths from dist-info RECORD files.
    pip::collect_claimed_paths(
        rootfs,
        &mut claimed,
        #[cfg(unix)]
        &mut claimed_inodes,
    );

    // Node.js: fail-closed only on v1 lockfiles; everything else is
    // soft. The reader dispatches lockfile > node_modules > root
    // package.json internally.
    out.extend(npm::read(rootfs, include_dev, scan_mode)?);

    // Milestone 003 ecosystem readers. Concrete implementations land in
    // the per-story tasks (US1 Go, US2 RPM, US3 Maven, US4 Cargo, US5
    // Gem). The stubs below return empty vectors today so the dispatcher
    // compose-order is settled and future story work only needs to touch
    // the individual reader module — no revisit of `read_all`.
    out.extend(golang::read(rootfs, include_dev));
    out.extend(rpm::read(rootfs, include_dev, distro_version.as_deref()));
    // v5 Phase B: rpm-owned file claim-skip — mirrors the dpkg / apk /
    // pip pattern. Real RHEL / Fedora rpmdbs store file paths inside
    // the header blob (BASENAMES / DIRNAMES / DIRINDEXES tags); the
    // paths get reconstructed via `rpm_header::parse_header_blob` and
    // inserted with `insert_claim_with_canonical`.
    rpm::collect_claimed_paths(
        rootfs,
        &mut claimed,
        #[cfg(unix)]
        &mut claimed_inodes,
    );
    // v9 Phase O: go_binary runs AFTER rpm's claim-path collection so
    // its diagnostic emissions (Unsupported / Missing BuildInfo) can
    // be suppressed for Go toolchain binaries owned by an rpm/deb/apk
    // package. Without the reorder, the claim set would be empty at
    // the time go_binary iterates, and golang-owned `link`/`compile`/
    // `asm` tools (which ship with intentionally unreadable BuildInfo)
    // would leak as `pkg:generic/link` etc.
    out.extend(go_binary::read(
        rootfs,
        include_dev,
        &claimed,
        #[cfg(unix)]
        &claimed_inodes,
    ));
    // Milestone 004 US1: standalone `.rpm` artefact reader (stub until
    // T015–T018 land). No-op today; wiring in place so the dispatcher
    // is settled and future story work only touches rpm_file.rs.
    out.extend(rpm_file::read(rootfs, distro_version.as_deref()));
    // Milestone 004 US4: legacy BDB rpmdb reader (stub until T061–T065
    // land). Gated behind --include-legacy-rpmdb; no-op when flag unset.
    out.extend(rpmdb_bdb::read(rootfs, include_legacy_rpmdb));
    out.extend(maven::read_with_claims(
        rootfs,
        include_dev,
        &claimed,
        #[cfg(unix)]
        &claimed_inodes,
    ));
    // Cargo is fail-closed on v1/v2 lockfiles (FR-040), mirroring the
    // npm v1 refusal pattern.
    out.extend(cargo::read(rootfs, include_dev)?);
    out.extend(gem::read(rootfs, include_dev));

    Ok(DbScanResult {
        entries: out,
        claimed_paths: claimed,
        #[cfg(unix)]
        claimed_inodes,
        diagnostics,
    })
}

/// Map an `/etc/os-release::ID` value to the PURL vendor segment used
/// for `pkg:rpm/<vendor>/...` components, per milestone 003 research R8.
///
/// The mapping covers the nine ID values mikebom commits to supporting
/// in milestone 003:
///
/// | `ID=` | `<vendor>` |
/// |---|---|
/// | `rhel` | `redhat` |
/// | `centos` | `centos` |
/// | `fedora` | `fedora` |
/// | `rocky` | `rocky` |
/// | `almalinux` | `almalinux` |
/// | `amzn` | `amazon` |
/// | `ol` | `oracle` |
/// | `opensuse-leap` / `opensuse-tumbleweed` / `opensuse` | `opensuse` |
/// | `sles` | `suse` |
///
/// Any other value is returned verbatim (preserving whatever the distro
/// wrote in its os-release) so an unmapped distro still produces a
/// deterministic — if unfamiliar — PURL. This is the contract: the
/// scanner never invents a vendor, it just normalises the ones it
/// recognises.
pub fn rpm_vendor_from_id(id: &str) -> String {
    match id {
        "rhel" => "redhat".to_string(),
        "centos" => "centos".to_string(),
        "fedora" => "fedora".to_string(),
        "rocky" => "rocky".to_string(),
        "almalinux" => "almalinux".to_string(),
        "amzn" => "amazon".to_string(),
        "ol" => "oracle".to_string(),
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" => "opensuse".to_string(),
        "sles" => "suse".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn rpm_vendor_maps_rhel_family() {
        assert_eq!(rpm_vendor_from_id("rhel"), "redhat");
        assert_eq!(rpm_vendor_from_id("centos"), "centos");
        assert_eq!(rpm_vendor_from_id("fedora"), "fedora");
        assert_eq!(rpm_vendor_from_id("rocky"), "rocky");
        assert_eq!(rpm_vendor_from_id("almalinux"), "almalinux");
        assert_eq!(rpm_vendor_from_id("ol"), "oracle");
    }

    #[test]
    fn rpm_vendor_maps_amazon_linux() {
        assert_eq!(rpm_vendor_from_id("amzn"), "amazon");
    }

    #[test]
    fn rpm_vendor_maps_suse_family() {
        assert_eq!(rpm_vendor_from_id("opensuse-leap"), "opensuse");
        assert_eq!(rpm_vendor_from_id("opensuse-tumbleweed"), "opensuse");
        assert_eq!(rpm_vendor_from_id("opensuse"), "opensuse");
        assert_eq!(rpm_vendor_from_id("sles"), "suse");
    }

    #[test]
    fn rpm_vendor_unmapped_id_returns_verbatim() {
        // Mageia is RPM-based but not in the committed map; assert the
        // verbatim fallback so the scanner still produces a deterministic
        // PURL rather than silently misattributing the packages.
        assert_eq!(rpm_vendor_from_id("mageia"), "mageia");
        assert_eq!(rpm_vendor_from_id("openmandriva"), "openmandriva");
    }

    #[test]
    fn rpm_vendor_preserves_empty_input() {
        // Defensive: an empty ID shouldn't silently become anything
        // meaningful. Caller is responsible for treating `""` as
        // "ecosystem unknown" at the read-site.
        assert_eq!(rpm_vendor_from_id(""), "");
    }

    /// T035 — when `/etc/os-release` is absent, `read_all` must fall
    /// back to `namespace = "debian"` AND record `"ID"` in
    /// diagnostics. Same test also covers the VERSION_ID-missing
    /// diagnostic since both fields are derived from the same file.
    #[test]
    fn read_all_falls_back_to_debian_namespace_when_id_missing() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        // dpkg status planted, /etc/os-release intentionally absent.
        let dpkg_dir = rootfs.join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg_dir).unwrap();
        std::fs::write(
            dpkg_dir.join("status"),
            "\
Package: curl
Status: install ok installed
Version: 8.0.0
Architecture: arm64
",
        )
        .unwrap();

        let result = read_all(
            rootfs,
            None,
            false,
            false,
            crate::scan_fs::ScanMode::Path,
        )
        .unwrap();

        let deb_entries: Vec<_> = result
            .entries
            .iter()
            .filter(|e| e.purl.as_str().starts_with("pkg:deb/"))
            .collect();
        assert!(!deb_entries.is_empty(), "expected at least one deb entry");
        for e in &deb_entries {
            assert!(
                e.purl.as_str().starts_with("pkg:deb/debian/"),
                "expected debian fallback namespace, got {}",
                e.purl.as_str()
            );
            // No distro qualifier because VERSION_ID is also missing.
            assert!(
                !e.purl.as_str().contains("distro="),
                "expected no distro qualifier when VERSION_ID missing, got {}",
                e.purl.as_str()
            );
        }
        assert!(
            result
                .diagnostics
                .os_release_missing_fields
                .iter()
                .any(|f| f == "ID"),
            "expected diagnostics to record missing ID"
        );
        assert!(
            result
                .diagnostics
                .os_release_missing_fields
                .iter()
                .any(|f| f == "VERSION_ID"),
            "expected diagnostics to record missing VERSION_ID"
        );
    }
}
