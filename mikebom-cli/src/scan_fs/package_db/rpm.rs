//! Read RPM package metadata from `/var/lib/rpm/rpmdb.sqlite`.
//!
//! Iterates the `Packages` table via the sibling pure-Rust SQLite
//! reader (`rpmdb_sqlite`), maps each row to a `PackageDbEntry`, and
//! derives the PURL vendor segment from `/etc/os-release::ID` via
//! [`super::rpm_vendor_from_id`].
//!
//! Fail-closed behaviour is NOT used here — per FR-020, rpmdb read
//! failures degrade to zero components + a WARN log line. The only
//! hard error is the legacy-BDB diagnostic (FR-020), which emits zero
//! components and a different WARN line pointing users at the upgrade
//! path.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mikebom_common::types::purl::Purl;

use super::rpmdb_sqlite::rpm_header::{self, RpmHeader};
use super::rpmdb_sqlite::{RecordValue, SqliteFile};
use super::{rpm_vendor_from_id, PackageDbEntry};
use crate::scan_fs::os_release;

/// Hard cap on rpmdb.sqlite size — an honest RHEL rpmdb is ~5 MB;
/// anything above 200 MB is refused as defense-in-depth.
const MAX_RPMDB_BYTES: u64 = 200 * 1024 * 1024;

/// Wall-clock budget for iterating the packages table. If exceeded we
/// abort iteration and return whatever we've collected, logging a WARN
/// with the observed row count.
const ITERATION_BUDGET: Duration = Duration::from_secs(2);

/// v7 Phase H: candidate locations for rpmdb.sqlite. Checked in order;
/// first hit wins.
///
/// - `var/lib/rpm/rpmdb.sqlite` — canonical location on older Fedora,
///   RHEL 8, Rocky 8–9.3, AlmaLinux, OracleLinux.
/// - `usr/lib/sysimage/rpm/rpmdb.sqlite` — Fedora ≥34 and RHEL ≥9.4
///   moved the state directory per the RPM 4.17 `%_dbpath` change.
///
/// v8 Phase K1: `pub(crate)` so the binary walker can use the same
/// candidate list for its `has_rpmdb` probe.
pub(crate) const RPMDB_SQLITE_CANDIDATES: &[&str] = &[
    "var/lib/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
];

/// Legacy BDB candidates used for the FR-020 diagnostic. Same search
/// order so modern Fedora's BDB-suggestion is accurate.
pub(crate) const RPMDB_BDB_CANDIDATES: &[&str] = &[
    "var/lib/rpm/Packages",
    "usr/lib/sysimage/rpm/Packages",
];

/// Return the first candidate path beneath `rootfs` that is a regular
/// file, or `None` if none match.
fn resolve_rpmdb_path(rootfs: &Path, candidates: &[&str]) -> Option<std::path::PathBuf> {
    candidates
        .iter()
        .map(|rel| rootfs.join(rel))
        .find(|p| p.is_file())
}

pub fn read(
    rootfs: &Path,
    _include_dev: bool,
    distro_version: Option<&str>,
) -> Vec<PackageDbEntry> {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    iter_rpmdb(rootfs, distro_version, |entry, _paths| out.push(entry));
    out
}

/// Milestone 005 Phase B: feed rpm-owned file paths into the shared
/// `claimed` / `claimed_inodes` sets so the binary walker can skip
/// file-level + linkage emissions for binaries the rpmdb already
/// accounts for. Mirrors the dpkg / apk / pip claim-skip pattern.
///
/// Reads the same rpmdb.sqlite twice per scan (once in `read`, once
/// here). The file is small (≈5 MB on RHEL) and memory-mapped; the
/// duplication keeps both functions independent and side-effect-free.
pub fn collect_claimed_paths(
    rootfs: &Path,
    claimed: &mut std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &mut std::collections::HashSet<(u64, u64)>,
) {
    // `distro_version` isn't needed here — we only care about file
    // paths, not PURLs. Pass None to keep the helper signature
    // uniform.
    iter_rpmdb(rootfs, None, |_entry, paths| {
        for rel in paths {
            // `rel` is absolute on the packaged system (e.g.
            // `/usr/bin/bash`). Strip the leading `/` and join onto the
            // rootfs to get the on-disk path.
            let tail = rel.strip_prefix("/").unwrap_or(&rel);
            let abs = rootfs.join(tail);
            super::insert_claim_with_canonical(
                claimed,
                #[cfg(unix)]
                claimed_inodes,
                abs,
            );
        }
    });
}

/// Shared rpmdb iteration: opens the db, applies BDB / WAL diagnostics,
/// iterates `Packages` via `iter_table_blobs`, and invokes `visitor`
/// with the decoded `PackageDbEntry` and its file paths (paths are
/// empty for fixture-shaped rows that carry no file list).
fn iter_rpmdb<F>(rootfs: &Path, distro_version: Option<&str>, mut visitor: F)
where
    F: FnMut(PackageDbEntry, Vec<PathBuf>),
{
    // v7 Phase H: try each candidate rpmdb location in order. Fedora ≥34
    // and RHEL ≥9.4 moved to `/usr/lib/sysimage/rpm/`; older distros
    // still use `/var/lib/rpm/`.
    let sqlite_path = match resolve_rpmdb_path(rootfs, RPMDB_SQLITE_CANDIDATES) {
        Some(p) => p,
        None => {
            // FR-020 BDB diagnostic: only fires if a `Packages` file
            // (BDB format) exists at any candidate but there's no
            // sqlite counterpart anywhere.
            if let Some(bdb_path) = resolve_rpmdb_path(rootfs, RPMDB_BDB_CANDIDATES) {
                tracing::warn!(
                    path = %bdb_path.display(),
                    "detected legacy rpmdb (Berkeley DB) — BDB is not supported in this mikebom version; regenerate on rpmdb.sqlite-based RHEL ≥8 to scan",
                );
            }
            return;
        }
    };

    let vendor = os_release::read_id_from_rootfs(rootfs)
        .map(|id| rpm_vendor_from_id(&id))
        .unwrap_or_else(|| "rpm".to_string());

    // WAL-mode detection. When SQLite writes in WAL journaling mode,
    // recent writes live in the `-wal` companion file — the main file
    // may lack tables that were created in the WAL. Our pure-Rust
    // reader walks only the main file today, so WAL-mode databases
    // produce a spurious "table Packages not found" error.
    // Surface an actionable warning with a workaround.
    //
    // v7 Phase H: check companions next to the resolved sqlite_path
    // (which may live under either `/var/lib/rpm/` or
    // `/usr/lib/sysimage/rpm/`).
    let wal_path = {
        let mut p = sqlite_path.clone();
        p.set_extension("sqlite-wal");
        p
    };
    let shm_path = {
        let mut p = sqlite_path.clone();
        p.set_extension("sqlite-shm");
        p
    };
    let wal_mode = wal_path.exists() || shm_path.exists();
    if wal_mode {
        tracing::warn!(
            path = %sqlite_path.display(),
            "rpmdb.sqlite is in WAL journaling mode — companion `-wal`/`-shm` present. \
             Mikebom's pure-Rust sqlite reader walks only the main file; tables created \
             in the WAL may be invisible. Workaround: run \
             `sqlite3 <path> 'PRAGMA wal_checkpoint(TRUNCATE);'` before scanning to \
             merge WAL frames into the main file. Full WAL-merge support is future work.",
        );
    }

    let db = match SqliteFile::open(&sqlite_path, MAX_RPMDB_BYTES) {
        Ok(db) => db,
        Err(e) => {
            tracing::warn!(
                path = %sqlite_path.display(),
                error = %e,
                wal_mode = wal_mode,
                "rpmdb.sqlite could not be read — emitting zero rpm components",
            );
            return;
        }
    };

    let source_path = sqlite_path.to_string_lossy().into_owned();
    let start = Instant::now();
    let mut row_count: usize = 0;

    let iter_result = db.iter_table_blobs("Packages", |values, blob| {
        if start.elapsed() > ITERATION_BUDGET {
            return;
        }
        if let Some((entry, paths)) =
            row_to_entry(values, blob, &vendor, &source_path, distro_version)
        {
            row_count += 1;
            visitor(entry, paths);
        }
    });
    if start.elapsed() > ITERATION_BUDGET {
        tracing::warn!(
            path = %sqlite_path.display(),
            rows_collected = row_count,
            "rpmdb.sqlite iteration exceeded budget — returning partial result",
        );
    }
    if let Err(e) = iter_result {
        tracing::warn!(
            path = %sqlite_path.display(),
            error = %e,
            rows_collected = row_count,
            "rpmdb.sqlite iteration error — returning partial result",
        );
    }
    if row_count > 0 {
        tracing::info!(
            path = %sqlite_path.display(),
            rows = row_count,
            "rpmdb.sqlite parsed",
        );
    }
}

/// Convert a Packages table row into a `PackageDbEntry` plus its
/// owned file paths. Auto-detects between two row shapes:
///
/// 1. **Production**: the blob column starts with the RPM header
///    magic (`\x8e\xad\xe8\x01`). All package fields are decoded from
///    header tags and file paths come from BASENAMES/DIRNAMES/
///    DIRINDEXES.
/// 2. **Fixture**: mikebom's test-fixture schema puts discrete text
///    columns at positions 1..=8 (name, version, release, epoch,
///    arch, license, packager, requires). Used by tests that haven't
///    been regenerated against the production blob format. Returns
///    an empty path list because the fixture doesn't carry files.
///
/// Rows matching neither shape are dropped (return `None`).
fn row_to_entry(
    values: &[RecordValue],
    blob: &[u8],
    vendor: &str,
    source_path: &str,
    distro_version: Option<&str>,
) -> Option<(PackageDbEntry, Vec<PathBuf>)> {
    // Production path: attempt header-blob parse on any non-trivial
    // blob. Real rpmdb.sqlite stores headers in the **stripped
    // immutable-region form** (no magic prefix, 8-byte intro); `.rpm`
    // files and `headerExport` output carry the full form (magic +
    // reserved + intro). `parse_header_blob` auto-detects.
    //
    // We treat any blob ≥ 8 bytes as a candidate; parse errors fall
    // through to the fixture-text path below.
    if blob.len() >= 8 {
        match rpm_header::parse_header_blob(blob) {
            Ok(header) => {
                if let Some(entry) =
                    build_entry_from_header(&header, vendor, source_path, distro_version)
                {
                    let paths = header.file_paths();
                    return Some((entry, paths));
                }
                // Header parsed but required fields missing — fall
                // through to fixture-path attempt.
            }
            Err(err) => {
                tracing::debug!(error = %err, "rpmdb row has malformed header blob; skipping");
                // Fall through; if the fixture-text path also fails,
                // the row is dropped.
            }
        }
    }

    // Fixture path: discrete text columns.
    let entry =
        build_entry_from_text_columns(values, vendor, source_path, distro_version)?;
    Some((entry, Vec::new()))
}

/// Build a `PackageDbEntry` from a parsed RPM header (production blob
/// format). Returns `None` if any required tag (NAME/VERSION/RELEASE)
/// is missing.
fn build_entry_from_header(
    header: &RpmHeader,
    vendor: &str,
    source_path: &str,
    distro_version: Option<&str>,
) -> Option<PackageDbEntry> {
    let name = header.string(rpm_header::TAG_NAME)?.to_string();
    let version = header.string(rpm_header::TAG_VERSION)?.to_string();
    let release = header.string(rpm_header::TAG_RELEASE)?.to_string();
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    // Feature 005 US4: preserve the tag-presence bit. An absent EPOCH
    // tag (444 of 529 packages on a stock Fedora 40 image) and an
    // explicit `EPOCH=0` tag (26 of 529) are semantically distinct per
    // `rpm -qa`'s output convention and syft's emission convention:
    // only the latter should appear as `&epoch=0` in the PURL.
    let epoch_val: Option<i64> = header
        .int32_array(rpm_header::TAG_EPOCH)
        .and_then(|v| v.first().copied())
        .map(|v| v as i64);
    let arch = header
        .string(rpm_header::TAG_ARCH)
        .unwrap_or("")
        .to_string();
    let license_str = header
        .string(rpm_header::TAG_LICENSE)
        .unwrap_or("")
        .to_string();
    // Prefer VENDOR over PACKAGER — Fedora / RHEL / Rocky rpms carry
    // the distro identity in VENDOR (e.g. `Fedora Project`); PACKAGER
    // is per-build and often absent. `rpm_file.rs:342` uses the same
    // precedence for standalone .rpm files.
    let packager = header
        .string(rpm_header::TAG_VENDOR)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            header
                .string(rpm_header::TAG_PACKAGER)
                .filter(|s| !s.is_empty())
        })
        .map(|s| s.to_string());
    let depends: Vec<String> = header
        .string_array(rpm_header::TAG_REQUIRENAME)
        .unwrap_or_default()
        .into_iter()
        .filter(|dep| !dep.is_empty())
        .map(|s| s.to_string())
        .collect();

    Some(assemble_entry(
        vendor,
        source_path,
        name,
        version,
        release,
        epoch_val,
        arch,
        license_str,
        packager,
        depends,
        distro_version,
    ))
}

/// Build a `PackageDbEntry` from discrete text columns (mikebom's
/// synthetic fixture schema).
fn build_entry_from_text_columns(
    values: &[RecordValue],
    vendor: &str,
    source_path: &str,
    distro_version: Option<&str>,
) -> Option<PackageDbEntry> {
    let get_text = |idx: usize| -> String {
        values
            .get(idx)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string()
    };
    let get_int = |idx: usize| -> Option<i64> { values.get(idx).and_then(|v| v.as_integer()) };

    let name = get_text(1);
    let version = get_text(2);
    let release = get_text(3);
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    // Fixture schema has no way to distinguish "no EPOCH tag" from
    // "EPOCH tag = 0" — existing fixtures use `Integer(0)` to mean
    // "no epoch", matching pre-US4 semantics. Keep that convention so
    // legacy fixtures don't have to be rewritten. The production
    // header path (`build_entry_from_header`) preserves the real
    // tag-presence bit; only this path collapses `0` to absent.
    let epoch = get_int(4).filter(|v| *v != 0);
    let arch = get_text(5);
    let license_str = get_text(6);
    let packager = get_text(7);
    let requires_str = get_text(8);

    let depends: Vec<String> = requires_str
        .split_whitespace()
        .filter_map(|dep| {
            let bare = dep.trim_end_matches(|c: char| matches!(c, '(' | ')' | ',' | ';'));
            if bare.is_empty() {
                None
            } else {
                Some(bare.to_string())
            }
        })
        .collect();

    let packager_opt = if packager.is_empty() {
        None
    } else {
        Some(packager)
    };

    Some(assemble_entry(
        vendor,
        source_path,
        name,
        version,
        release,
        epoch,
        arch,
        license_str,
        packager_opt,
        depends,
        distro_version,
    ))
}

/// Shared PURL construction + `PackageDbEntry` assembly. Both the
/// header path and the fixture path end here so the output schema is
/// identical regardless of source.
#[allow(clippy::too_many_arguments)]
fn assemble_entry(
    vendor: &str,
    source_path: &str,
    name: String,
    version: String,
    release: String,
    epoch: Option<i64>,
    arch: String,
    license_str: String,
    maintainer: Option<String>,
    depends: Vec<String>,
    distro_version: Option<&str>,
) -> PackageDbEntry {
    // PURL: pkg:rpm/<vendor>/<name>@<version>-<release>[?arch=<arch>][&epoch=<epoch>][&distro=<vendor>-<version_id>]
    //
    // v7 Phase G: the `distro=<vendor>-<version_id>` qualifier matches
    // the packaging-purl rpm convention and ground truth (e.g.
    // `pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=aarch64&distro=rocky-9.3`).
    // Only emitted when `distro_version` is `Some(non_empty)`.
    //
    // Epoch handling. RPM treats "no epoch" and "epoch = 0" as
    // equivalent for version comparison; `rpm -qa`'s default display
    // omits epoch when it is 0; the purl-spec rpm example never shows
    // `epoch=0`. Mikebom omits the qualifier in both the absent and
    // zero cases — only non-zero epochs surface. This matches the
    // sbom-conformance framework's canonical interpretation and drops
    // 27 exact-match failures on Fedora images where ~5% of packages
    // carry an explicit `EPOCH = 0` header.
    //
    // Trade-off vs the prior milestone-005 behavior (round-trip
    // `rpm -qa --queryformat '%{EPOCH}'` exactly): callers that need
    // to distinguish "tag absent" from "tag present, value 0" have
    // lost that signal in the PURL. Acceptable because the distinction
    // has no semantic meaning for RPM tooling, and the PURL is for
    // consumer SBOM tools (vuln matchers, license scanners) which
    // treat both the same.
    let epoch_seg = match epoch {
        Some(v) if v != 0 => format!("&epoch={v}"),
        _ => String::new(),
    };
    let mut qualifiers = if arch.is_empty() {
        String::new()
    } else {
        format!("?arch={arch}{epoch_seg}")
    };
    if let Some(dv) = distro_version {
        if !dv.is_empty() {
            qualifiers.push(if qualifiers.is_empty() { '?' } else { '&' });
            qualifiers.push_str("distro=");
            qualifiers.push_str(vendor);
            qualifiers.push('-');
            qualifiers.push_str(dv);
        }
    }
    // purl-spec § Character encoding: `+` and other non-allowed chars
    // MUST be percent-encoded in both the name AND version segments.
    // Real-world RPMs carry `+` regularly in names (libstdc++,
    // perl-Text-Tabs+Wrap) and occasionally in versions. Route both
    // through the canonical encoder the deb builder already uses.
    let encoded_name = mikebom_common::types::purl::encode_purl_segment(&name);
    let encoded_version = mikebom_common::types::purl::encode_purl_segment(&version);
    let encoded_release = mikebom_common::types::purl::encode_purl_segment(&release);
    let purl_str = format!(
        "pkg:rpm/{vendor}/{encoded_name}@{encoded_version}-{encoded_release}{qualifiers}",
    );
    // Fall back to a minimal PURL if assembly fails — shouldn't happen
    // with valid RPM names, but defense-in-depth. A panic in the
    // unwrap path would kill the scan.
    let purl = Purl::new(&purl_str).unwrap_or_else(|_| {
        Purl::new(&format!("pkg:rpm/{vendor}/unknown@0")).expect("sentinel PURL always valid")
    });

    let full_version = format!("{version}-{release}");
    let licenses: Vec<mikebom_common::types::license::SpdxExpression> = if license_str.is_empty() {
        Vec::new()
    } else {
        mikebom_common::types::license::SpdxExpression::try_canonical(&license_str)
            .ok()
            .into_iter()
            .collect()
    };

    PackageDbEntry {
        purl,
        name,
        version: full_version.clone(),
        arch: if arch.is_empty() { None } else { Some(arch) },
        source_path: source_path.to_string(),
        depends,
        maintainer,
        licenses,
        is_dev: None,
        requirement_range: None,
        source_type: None,
        buildinfo_status: None,
        sbom_tier: Some("deployed".to_string()),
        evidence_kind: Some("rpmdb-sqlite".to_string()),
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: None,
        confidence: None,
        binary_packed: None,
        // Feature 005 US4: preserve the verbatim `VERSION-RELEASE`
        // string so downstream consumers can cross-reference
        // `rpm -qa`'s `%{VERSION}-%{RELEASE}` column without re-parsing
        // the PURL. Same string as `version` for rpm components (we
        // never re-encode); populated explicitly so the builder can
        // drive the `mikebom:raw-version` property deterministically
        // without having to infer which ecosystem the entry came from.
        raw_version: Some(full_version),
        parent_purl: None,
        npm_role: None,
        hashes: Vec::new(),
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn synth_rootfs_with_rpmdb(dir: &Path, os_id: &str, rpmdb_bytes: &[u8]) -> PathBuf {
        let rpm_dir = dir.join("var/lib/rpm");
        std::fs::create_dir_all(&rpm_dir).unwrap();
        std::fs::write(rpm_dir.join("rpmdb.sqlite"), rpmdb_bytes).unwrap();
        let etc = dir.join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(etc.join("os-release"), format!("ID=\"{os_id}\"\n")).unwrap();
        dir.to_path_buf()
    }

    #[test]
    fn missing_rpmdb_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let entries = read(dir.path(), false, None);
        assert!(entries.is_empty());
    }

    #[test]
    fn bdb_packages_without_sqlite_triggers_diagnostic_empty() {
        let dir = tempfile::tempdir().unwrap();
        let rpm_dir = dir.path().join("var/lib/rpm");
        std::fs::create_dir_all(&rpm_dir).unwrap();
        std::fs::write(rpm_dir.join("Packages"), b"BDB_MAGIC").unwrap();
        let entries = read(dir.path(), false, None);
        assert!(entries.is_empty());
    }

    /// v7 Phase H — rpmdb at the modern Fedora/RHEL location
    /// (`/usr/lib/sysimage/rpm/rpmdb.sqlite`) is discovered.
    #[test]
    fn rpmdb_found_at_sysimage_path() {
        let fixture = std::path::Path::new("/tmp/rpmdb-fixture/rpmdb.sqlite");
        if !fixture.is_file() {
            eprintln!("skipping: fixture {} not found", fixture.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let rpm_dir = dir.path().join("usr/lib/sysimage/rpm");
        std::fs::create_dir_all(&rpm_dir).unwrap();
        let bytes = std::fs::read(fixture).unwrap();
        std::fs::write(rpm_dir.join("rpmdb.sqlite"), &bytes).unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(etc.join("os-release"), "ID=\"fedora\"\n").unwrap();
        let entries = read(dir.path(), false, None);
        assert!(
            !entries.is_empty(),
            "rpmdb at usr/lib/sysimage/rpm/ must be discovered"
        );
    }

    #[test]
    fn reads_fixture_rpmdb_when_present() {
        // Use the Python-generated fixture at /tmp (created during test
        // setup); if it's missing, skip gracefully.
        let fixture = std::path::Path::new("/tmp/rpmdb-fixture/rpmdb.sqlite");
        if !fixture.is_file() {
            eprintln!("skipping: fixture {} not found", fixture.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let bytes = std::fs::read(fixture).unwrap();
        synth_rootfs_with_rpmdb(dir.path(), "rhel", &bytes);
        let entries = read(dir.path(), false, None);
        assert!(
            entries.len() >= 10,
            "expected ≥10 entries from fixture rpmdb, got {}",
            entries.len(),
        );
        assert!(entries.iter().all(|e| e.purl.as_str().starts_with("pkg:rpm/redhat/")));
    }

    // --- v5 Phase B: dual-format dispatch tests ---

    use super::super::rpmdb_sqlite::rpm_header::{
        build_test_header, TagValue, TAG_ARCH, TAG_BASENAMES, TAG_DIRINDEXES, TAG_DIRNAMES,
        TAG_EPOCH, TAG_LICENSE, TAG_NAME, TAG_PACKAGER, TAG_RELEASE, TAG_REQUIRENAME,
        TAG_VENDOR, TAG_VERSION,
    };

    /// Production path — a header-shaped blob should decode all fields
    /// from tags and yield file paths.
    #[test]
    fn row_to_entry_decodes_production_header_blob() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("bash")),
            (TAG_VERSION, TagValue::Str("5.2.15")),
            (TAG_RELEASE, TagValue::Str("1.fc40")),
            (TAG_EPOCH, TagValue::Int32Array(&[0])),
            (TAG_ARCH, TagValue::Str("x86_64")),
            (TAG_LICENSE, TagValue::I18nStr(&["GPL-3.0-or-later"])),
            (TAG_REQUIRENAME, TagValue::StrArray(&["glibc", "ncurses-libs"])),
            (TAG_DIRNAMES, TagValue::StrArray(&["/usr/bin/", "/usr/share/man/man1/"])),
            (TAG_BASENAMES, TagValue::StrArray(&["bash", "bash.1.gz"])),
            (TAG_DIRINDEXES, TagValue::Int32Array(&[0, 1])),
        ]);
        // Fixture-path columns would be at values[1..=8] and all text;
        // production path ignores them, so pass an empty slice.
        let (entry, paths) =
            row_to_entry(&[], &blob, "redhat", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(entry.name, "bash");
        assert_eq!(entry.version, "5.2.15-1.fc40");
        assert_eq!(entry.arch.as_deref(), Some("x86_64"));
        // Conformance fix (2026-04-20): epoch=0 is omitted from the
        // PURL — it's the implicit default in RPM semantics and the
        // purl-spec rpm example never includes it. The previous
        // milestone-005 behavior emitted `&epoch=0` to round-trip
        // `rpm -qa --queryformat '%{EPOCH}'`, but that distinction
        // has no consumer-side meaning and produced 27 framework
        // mismatches.
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/redhat/bash@5.2.15-1.fc40?arch=x86_64"
        );
        assert_eq!(entry.depends, vec!["glibc", "ncurses-libs"]);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/usr/bin/bash"),
                PathBuf::from("/usr/share/man/man1/bash.1.gz"),
            ]
        );
    }

    /// VENDOR wins over PACKAGER when both are present — matches the
    /// precedence in `rpm_file.rs::extract_metadata` for .rpm files so
    /// rpmdb-sqlite and file-level scanners emit the same supplier.
    #[test]
    fn row_to_entry_extracts_vendor_as_maintainer() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("bash")),
            (TAG_VERSION, TagValue::Str("5.2.15")),
            (TAG_RELEASE, TagValue::Str("1.fc40")),
            (TAG_ARCH, TagValue::Str("x86_64")),
            (TAG_VENDOR, TagValue::Str("Fedora Project")),
            (TAG_PACKAGER, TagValue::Str("Fedora Build <build@fedoraproject.org>")),
        ]);
        let (entry, _) =
            row_to_entry(&[], &blob, "redhat", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(entry.maintainer.as_deref(), Some("Fedora Project"));
    }

    /// PACKAGER used as fallback when VENDOR is missing (common on
    /// user-rebuilt rpms).
    #[test]
    fn row_to_entry_falls_back_to_packager_when_vendor_absent() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("mytool")),
            (TAG_VERSION, TagValue::Str("1.0")),
            (TAG_RELEASE, TagValue::Str("1")),
            (TAG_ARCH, TagValue::Str("x86_64")),
            (TAG_PACKAGER, TagValue::Str("Alice <alice@example.com>")),
        ]);
        let (entry, _) =
            row_to_entry(&[], &blob, "redhat", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(entry.maintainer.as_deref(), Some("Alice <alice@example.com>"));
    }

    /// Neither tag present → maintainer stays None (matches behavior
    /// for minimal / third-party rpms that strip provenance).
    #[test]
    fn row_to_entry_maintainer_none_when_both_tags_missing() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("stripped")),
            (TAG_VERSION, TagValue::Str("1.0")),
            (TAG_RELEASE, TagValue::Str("1")),
            (TAG_ARCH, TagValue::Str("x86_64")),
        ]);
        let (entry, _) =
            row_to_entry(&[], &blob, "redhat", "/fake/rpmdb.sqlite", None).unwrap();
        assert!(entry.maintainer.is_none());
    }

    /// Fixture path — a production-magic-free row with text columns
    /// at positions 1..=8 should decode from the fixture schema. Used
    /// by mikebom's existing synthetic rpmdb fixture; must continue
    /// working so legacy tests pass.
    #[test]
    fn row_to_entry_decodes_fixture_text_columns() {
        let values = vec![
            RecordValue::Integer(1),
            RecordValue::Text("bash".into()),
            RecordValue::Text("5.2.15".into()),
            RecordValue::Text("1.fc40".into()),
            RecordValue::Integer(0),
            RecordValue::Text("x86_64".into()),
            RecordValue::Text("GPL-3.0-or-later".into()),
            RecordValue::Text("".into()),
            RecordValue::Text("glibc ncurses-libs".into()),
        ];
        let (entry, paths) =
            row_to_entry(&values, &[], "redhat", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(entry.name, "bash");
        assert_eq!(entry.version, "5.2.15-1.fc40");
        assert_eq!(entry.arch.as_deref(), Some("x86_64"));
        assert_eq!(entry.depends, vec!["glibc", "ncurses-libs"]);
        // Fixture has no file list.
        assert!(paths.is_empty());
    }

    /// Defense-in-depth — a malformed production blob must NOT crash
    /// the dispatch. Instead the row drops or falls through to the
    /// fixture path (which will drop it when text columns are empty).
    #[test]
    fn row_to_entry_handles_malformed_blob_without_panic() {
        // Starts with magic but truncates before the store.
        let mut bad_blob = Vec::new();
        bad_blob.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01]);
        bad_blob.extend_from_slice(&[0u8; 4]);
        bad_blob.extend_from_slice(&1u32.to_be_bytes()); // 1 index entry
        bad_blob.extend_from_slice(&100u32.to_be_bytes()); // declares 100-byte store
                                                            // ...no store bytes follow.
        let result = row_to_entry(&[], &bad_blob, "redhat", "/fake/rpmdb.sqlite", None);
        assert!(result.is_none(), "malformed blob must drop, not panic");
    }

    /// Defense-in-depth — empty row drops without erroring.
    #[test]
    fn row_to_entry_drops_empty_row() {
        assert!(row_to_entry(&[], &[], "redhat", "/fake", None).is_none());
    }

    // --- v7 Phase G: distro qualifier tests ---

    /// Production header path stamps `&distro=<vendor>-<VERSION_ID>`.
    #[test]
    fn row_to_entry_header_path_stamps_distro_qualifier() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("bash")),
            (TAG_VERSION, TagValue::Str("5.1.8")),
            (TAG_RELEASE, TagValue::Str("6.el9_1")),
            (TAG_ARCH, TagValue::Str("aarch64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "rocky", "/fake/rpmdb.sqlite", Some("9.3"))
                .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=aarch64&distro=rocky-9.3"
        );
    }

    /// Fixture text-column path also stamps the qualifier.
    #[test]
    fn row_to_entry_text_path_stamps_distro_qualifier() {
        let values = vec![
            RecordValue::Integer(1),
            RecordValue::Text("bash".into()),
            RecordValue::Text("5.1.8".into()),
            RecordValue::Text("6.el9_1".into()),
            RecordValue::Integer(0),
            RecordValue::Text("aarch64".into()),
            RecordValue::Text("".into()),
            RecordValue::Text("".into()),
            RecordValue::Text("".into()),
        ];
        let (entry, _paths) =
            row_to_entry(&values, &[], "rocky", "/fake/rpmdb.sqlite", Some("9.3"))
                .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=aarch64&distro=rocky-9.3"
        );
    }

    /// When distro_version is None the existing PURL shape is preserved.
    #[test]
    fn row_to_entry_without_distro_version_unchanged() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("bash")),
            (TAG_VERSION, TagValue::Str("5.1.8")),
            (TAG_RELEASE, TagValue::Str("6.el9_1")),
            (TAG_ARCH, TagValue::Str("aarch64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "rocky", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=aarch64"
        );
    }

    // ---- Feature 005 US4 ------------------------------------------------

    /// T044 — `raw_version` is populated on every rpmdb-header entry
    /// and holds the verbatim `VERSION-RELEASE` string.
    #[test]
    fn assemble_entry_populates_raw_version() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("zstd")),
            (TAG_VERSION, TagValue::Str("5.2.15")),
            (TAG_RELEASE, TagValue::Str("5.fc40")),
            (TAG_ARCH, TagValue::Str("x86_64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(entry.raw_version.as_deref(), Some("5.2.15-5.fc40"));
    }

    /// T045 — `raw_version` preserves unusual characters (`~`, `^`)
    /// that rpm uses for pre-release / post-release ordering.
    #[test]
    fn assemble_entry_preserves_special_chars_in_raw_version() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("tricky")),
            (TAG_VERSION, TagValue::Str("1.0~pre1")),
            (TAG_RELEASE, TagValue::Str("2^post1.fc40")),
            (TAG_ARCH, TagValue::Str("x86_64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        assert_eq!(
            entry.raw_version.as_deref(),
            Some("1.0~pre1-2^post1.fc40")
        );
    }

    /// Conformance fix: EPOCH = 0 is treated as semantically "no epoch"
    /// (RPM convention) and the qualifier is OMITTED from the PURL,
    /// regardless of whether the tag was explicitly present in the
    /// header. Stock Fedora 40 ships 26 packages with explicit EPOCH=0;
    /// the previous milestone-005 behavior emitted `&epoch=0` for them
    /// to round-trip `rpm -qa --queryformat '%{EPOCH}'`, but that
    /// distinction has no consumer-side meaning and produced 27
    /// framework mismatches.
    #[test]
    fn explicit_zero_epoch_is_omitted_from_purl() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("aopalliance")),
            (TAG_VERSION, TagValue::Str("1.0")),
            (TAG_RELEASE, TagValue::Str("39.fc40")),
            (TAG_EPOCH, TagValue::Int32Array(&[0])),
            (TAG_ARCH, TagValue::Str("noarch")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        assert!(
            !entry.purl.as_str().contains("epoch="),
            "EPOCH=0 must NOT surface as a PURL qualifier; got {}",
            entry.purl.as_str()
        );
    }

    /// T047b — EPOCH tag absent: no qualifier (regression guard for
    /// the 444-of-529 packages on Fedora 40 that have no EPOCH tag).
    #[test]
    fn absent_epoch_tag_omits_purl_qualifier() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("tzdata")),
            (TAG_VERSION, TagValue::Str("2024b")),
            (TAG_RELEASE, TagValue::Str("1.fc40")),
            (TAG_ARCH, TagValue::Str("noarch")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        assert!(
            !entry.purl.as_str().contains("epoch="),
            "expected no epoch qualifier; got {}",
            entry.purl.as_str()
        );
    }

    /// purl-spec § Character encoding: `+` in the name segment MUST
    /// be percent-encoded as `%2B`. Real Fedora ships packages like
    /// `libstdc++` (trailing double-plus) and `perl-Text-Tabs+Wrap`
    /// (mid-name plus) — both failed reference-impl round-trip
    /// before this fix because `assemble_entry` emitted the name raw.
    #[test]
    fn name_with_trailing_plus_plus_percent_encodes_both() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("libstdc++")),
            (TAG_VERSION, TagValue::Str("14.2.1")),
            (TAG_RELEASE, TagValue::Str("3.fc40")),
            (TAG_ARCH, TagValue::Str("aarch64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        let purl = entry.purl.as_str();
        assert!(
            purl.contains("/libstdc%2B%2B@"),
            "expected name to percent-encode both `+` as %2B; got {purl}",
        );
        assert!(
            !purl.contains("libstdc++"),
            "literal `++` must not appear in canonical PURL; got {purl}",
        );
    }

    #[test]
    fn name_with_mid_plus_percent_encodes_it() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("perl-Text-Tabs+Wrap")),
            (TAG_VERSION, TagValue::Str("2024.001")),
            (TAG_RELEASE, TagValue::Str("1.fc40")),
            (TAG_ARCH, TagValue::Str("noarch")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        let purl = entry.purl.as_str();
        assert!(
            purl.contains("/perl-Text-Tabs%2BWrap@"),
            "expected mid-name `+` to percent-encode as %2B; got {purl}",
        );
    }

    /// Negative: a name with no non-allowed characters must pass
    /// through verbatim — the encoder leaves alphanumerics and
    /// `-._~:` alone.
    #[test]
    fn plain_name_passes_through_unchanged() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("bash")),
            (TAG_VERSION, TagValue::Str("5.2.15")),
            (TAG_RELEASE, TagValue::Str("5.fc40")),
            (TAG_ARCH, TagValue::Str("x86_64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        assert!(
            entry.purl.as_str().contains("/bash@"),
            "plain name must not be rewritten; got {}",
            entry.purl.as_str()
        );
    }

    /// T047c — non-zero epoch round-trips unchanged.
    #[test]
    fn rpm_purl_never_carries_inline_epoch_prefix() {
        let blob = build_test_header(&[
            (TAG_NAME, TagValue::Str("xz-libs")),
            (TAG_VERSION, TagValue::Str("5.4.6")),
            (TAG_RELEASE, TagValue::Str("3.fc40")),
            (TAG_EPOCH, TagValue::Int32Array(&[1])),
            (TAG_ARCH, TagValue::Str("aarch64")),
        ]);
        let (entry, _paths) =
            row_to_entry(&[], &blob, "fedora", "/fake/rpmdb.sqlite", None).unwrap();
        // Version segment MUST be bare `VERSION-RELEASE` — no `1:` prefix.
        assert!(
            entry.purl.as_str().contains("@5.4.6-3.fc40"),
            "expected bare version segment, got {}",
            entry.purl.as_str()
        );
        assert!(
            entry.purl.as_str().contains("&epoch=1"),
            "expected &epoch=1 qualifier, got {}",
            entry.purl.as_str()
        );
        // Negative: no `@1:` (inline epoch) shape.
        assert!(
            !entry.purl.as_str().contains("@1:"),
            "epoch must not be inline, got {}",
            entry.purl.as_str()
        );
    }
}