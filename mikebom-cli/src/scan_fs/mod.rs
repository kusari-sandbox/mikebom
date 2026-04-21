//! Filesystem-based SBOM generation.
//!
//! Two entry points:
//! - [`walker::walk_and_hash`] — cross-platform directory traversal that
//!   returns a set of artifact files with their SHA-256 hashes. Shared
//!   with trace mode's post-exit scan.
//! - [`scan_path`] — end-to-end orchestrator: walks a root, runs the
//!   path resolver over each captured file, and returns a
//!   `Vec<ResolvedComponent>` ready for the CycloneDX builder. Used by
//!   the standalone `mikebom sbom scan` subcommand.

pub mod binary;
pub mod docker_image;
pub mod os_release;
pub mod package_db;
pub mod walker;

use std::path::Path;

use mikebom_common::resolution::{
    EnrichmentProvenance, Relationship, RelationshipType, ResolutionEvidence,
    ResolutionTechnique, ResolvedComponent,
};

use crate::generate::cpe::synthesize_cpes;
use crate::resolve::deduplicator::deduplicate;
use crate::resolve::path_resolver::resolve_path_with_context;

/// Confidence assigned to components discovered by a filesystem walk.
/// Mirrors the value used by the `resolve_path` branch of
/// `ResolutionPipeline` so the resulting SBOM is directly comparable to a
/// trace-sourced one where the artifact-dir scan fired.
pub const FILE_PATH_CONFIDENCE: f64 = 0.70;

/// How the caller invoked mikebom — image-tarball extraction vs. plain
/// directory. Drives scan-mode-aware scoping decisions like npm-internals
/// inclusion (feature 005 US1): `Image` includes npm's own internal
/// packages because the container IS the target; `Path` excludes them
/// because the target is the application, not the tooling that installed
/// its dependencies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    /// `mikebom sbom scan --path <dir>` — target is an application source tree.
    Path,
    /// `mikebom sbom scan --image <tarball>` — target is a full container filesystem.
    Image,
}

/// Confidence assigned to components read from an OS installed-package
/// database. Higher than `FILE_PATH_CONFIDENCE` because the db is
/// authoritative about what's installed (not a guess from a filename),
/// and lower than instrumentation (0.95) because we didn't observe the
/// install event itself.
pub const PACKAGE_DB_CONFIDENCE: f64 = 0.85;

/// Everything a scan produces, ready to be fed to the CycloneDX builder.
/// The relationships list is populated from installed-package-database
/// Depends fields (dpkg) when available; it's empty for filesystem
/// walks that only find artefact files.
pub struct ScanResult {
    pub components: Vec<ResolvedComponent>,
    pub relationships: Vec<Relationship>,
    /// PURL ecosystem identifiers (e.g. `"deb"`, `"apk"`) whose installed
    /// database was read in full during this scan. Each listed ecosystem
    /// gets its own `aggregate: complete` record in the CycloneDX
    /// `compositions[]` section — consumers then know the dpkg subset is
    /// authoritative even when the surrounding SBOM is
    /// `incomplete_first_party_only`. Empty when no dbs were read (pure
    /// artefact-file scan or `--no-package-db`).
    pub complete_ecosystems: Vec<String>,
    /// Feature 005 SC-009 — `/etc/os-release` fields the package-db
    /// readers tried to read but found absent/empty. Surfaced into the
    /// SBOM's `metadata.properties` as `mikebom:os-release-missing-fields`
    /// when non-empty. Empty vec means clean scan.
    pub os_release_missing_fields: Vec<String>,
}

/// Walk `root`, hash matching artifact files, match each against the path
/// resolver, optionally consult OS package databases, and return
/// components + a real dependency graph. The caller (typically the
/// `sbom scan` subcommand) then feeds this into the CycloneDX builder
/// just like the generate-from-attestation path does.
///
/// * `deb_codename` — optional value for the `distro=` qualifier on deb
///   PURLs. Supplied by the CLI or auto-detected from `/etc/os-release`
///   in the scanned root.
/// * `size_cap` — maximum per-file byte count for hashing.
/// * `read_package_db` — when true, attempt to parse
///   `<root>/var/lib/dpkg/status` and `<root>/lib/apk/db/installed` and
///   merge their entries with the artefact-file results. The CLI
///   defaults this to true; pass `--no-package-db` to disable.
/// * `deep_hash` — when true, deep-hash every file each db-installed
///   package owns (via `<pkg>.list`) with SHA-256 and emit per-file
///   occurrences. When false, fall back to a microsecond-cost hash of
///   the dpkg-provided `.md5sums` file content (no per-file detail).
///   Ignored when `read_package_db` is false.
pub fn scan_path(root: &Path, deb_codename: Option<&str>, size_cap: u64, read_package_db: bool, deep_hash: bool, include_dev: bool, include_legacy_rpmdb: bool, scan_mode: ScanMode) -> Result<ScanResult, ScanError> {
    // Canonicalize the rootfs once at entry so downstream path
    // comparisons use a consistent base. Without this, macOS's
    // `/tmp` → `/private/tmp` symlink (and other host-level symlinks)
    // cause spurious mismatches between walker-emitted paths and
    // package-db claim paths. Milestone 004 post-ship fix.
    let canonical_root: std::path::PathBuf;
    let root = match std::fs::canonicalize(root) {
        Ok(c) => {
            canonical_root = c;
            canonical_root.as_path()
        }
        Err(_) => root,
    };
    // `include_dev` gates inclusion of packages marked dev-only by
    // ecosystems that carry the distinction (npm devDependencies,
    // Poetry `category = "dev"`, Pipfile `develop:`). Threaded through
    // to `package_db::read_all` so per-ecosystem readers can filter at
    // source.
    let artifacts = walker::walk_and_hash(root, None, size_cap);
    let mut components: Vec<ResolvedComponent> = Vec::with_capacity(artifacts.len());

    // Artifact-file walk — confidence 0.70, carries a real SHA-256.
    for artifact in artifacts {
        let path_str = artifact.path.to_string_lossy();
        let Some(purl) = resolve_path_with_context(&path_str, deb_codename) else {
            continue;
        };
        let path_string = path_str.into_owned();
        components.push(ResolvedComponent {
            name: purl.name().to_string(),
            version: purl.version().unwrap_or("").to_string(),
            purl,
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::FilePathPattern,
                confidence: FILE_PATH_CONFIDENCE,
                source_connection_ids: vec![],
                source_file_paths: vec![path_string],
                deps_dev_match: None,
            },
            licenses: vec![],
            concluded_licenses: Vec::new(),
            hashes: vec![artifact.hash],
            supplier: None,
            cpes: vec![],
            advisories: vec![],
            occurrences: vec![],
            // Artefact-file walks identify packages by filename + content
            // hash but can't tell whether the file is installed: tier =
            // "analyzed" per R13. No dev/prod info, no range spec.
            is_dev: None,
            requirement_range: None,
            source_type: None,
            sbom_tier: Some("analyzed".to_string()),
            buildinfo_status: None,
            evidence_kind: None,
            binary_class: None,
            binary_stripped: None,
            linkage_kind: None,
            detected_go: None,
            confidence: None,
            binary_packed: None,
            npm_role: None,
            raw_version: None,
            external_references: Vec::new(),
        });
    }

    // Installed-package-db pass — confidence 0.85, no content hash
    // (the installed files are sprayed across /usr and there's no
    // one-hash-per-package source inside the db itself). Also the
    // source of the dependency graph.
    let mut relationships: Vec<Relationship> = Vec::new();
    let mut complete_ecosystems: Vec<String> = Vec::new();
    // Feature 005 SC-009: scan-time diagnostics (missing os-release
    // fields). Carried from DbScanResult into the ScanResult so the
    // CycloneDX metadata builder can surface them.
    let mut os_release_missing_fields: Vec<String> = Vec::new();
    if read_package_db {
        let scan_result = package_db::read_all(root, deb_codename, include_dev, include_legacy_rpmdb, scan_mode)?;
        os_release_missing_fields = scan_result.diagnostics.os_release_missing_fields.clone();
        let mut db_entries = scan_result.entries;
        let claimed_paths = scan_result.claimed_paths;
        #[cfg(unix)]
        let claimed_inodes = scan_result.claimed_inodes;
        // Milestone 004 US2 + post-ship claim-skip: generic-binary
        // reader consumes path + inode claim sets populated by dpkg
        // `.list`, apk `R:` / `F:`, and pip RECORD. Binaries whose
        // path OR inode match a claim skip file-level + linkage
        // emissions. `.note.package` + embedded-version-string
        // emissions remain unconditional (TLS preservation).
        db_entries.extend(binary::read(
            root,
            &claimed_paths,
            #[cfg(unix)]
            &claimed_inodes,
        ));

        // Record which ecosystems actually had a populated db — each
        // produces its own `aggregate: complete` compositions entry.
        // A pypi entry marks the ecosystem complete when it came from
        // an authoritative source (`sbom_tier` is "deployed" or
        // "source"). Design-tier entries (requirements.txt range specs)
        // do NOT trigger completeness per FR-019 / research R13.
        let mut saw_deb = false;
        let mut saw_apk = false;
        let mut saw_pypi_authoritative = false;
        let mut saw_npm_authoritative = false;
        let mut saw_golang_authoritative = false;
        let mut saw_cargo_authoritative = false;
        let mut saw_gem_authoritative = false;
        let mut saw_maven_authoritative = false;
        let mut saw_rpm_authoritative = false;
        for e in &db_entries {
            if !saw_deb && e.source_path.contains("dpkg/status") {
                saw_deb = true;
            }
            if !saw_apk && e.source_path.contains("apk/db/installed") {
                saw_apk = true;
            }
            if !saw_pypi_authoritative
                && e.purl.ecosystem() == "pypi"
                && matches!(
                    e.sbom_tier.as_deref(),
                    Some("deployed") | Some("source")
                )
            {
                saw_pypi_authoritative = true;
            }
            // npm ecosystem completeness mirrors pypi: only authoritative
            // sources (lockfile = `source`, node_modules = `deployed`)
            // count. `design` tier (root package.json fallback) does NOT
            // trigger completeness — it's unresolved range specs.
            if !saw_npm_authoritative
                && e.purl.ecosystem() == "npm"
                && matches!(
                    e.sbom_tier.as_deref(),
                    Some("deployed") | Some("source")
                )
            {
                saw_npm_authoritative = true;
            }
            // Go ecosystem completeness: either source-tier (go.sum)
            // OR analyzed-tier (binary BuildInfo) counts as
            // authoritative. A scratch/distroless image scan is
            // legitimately "complete" from the binary alone because
            // the binary IS the whole ecosystem there.
            if !saw_golang_authoritative
                && e.purl.ecosystem() == "golang"
                && matches!(
                    e.sbom_tier.as_deref(),
                    Some("analyzed") | Some("source")
                )
            {
                saw_golang_authoritative = true;
            }
            // Cargo ecosystem completeness: Cargo.lock v3/v4 resolves
            // every transitive dep to an exact version + SHA-256, so
            // any source-tier entry marks the ecosystem complete.
            if !saw_cargo_authoritative
                && e.purl.ecosystem() == "cargo"
                && matches!(e.sbom_tier.as_deref(), Some("source"))
            {
                saw_cargo_authoritative = true;
            }
            if !saw_gem_authoritative
                && e.purl.ecosystem() == "gem"
                && matches!(e.sbom_tier.as_deref(), Some("source"))
            {
                saw_gem_authoritative = true;
            }
            // Maven completeness: source-tier pom.xml only. JAR scans
            // are analyzed-tier subsets — not authoritative for the
            // ecosystem. Per T054, a design-tier placeholder
            // dependency does NOT mark the ecosystem complete.
            if !saw_maven_authoritative
                && e.purl.ecosystem() == "maven"
                && matches!(e.sbom_tier.as_deref(), Some("source"))
            {
                saw_maven_authoritative = true;
            }
            // RPM: rpmdb-sourced entries are always deployed-tier and
            // cover the whole installed set, so any rpm entry marks
            // the ecosystem complete.
            if !saw_rpm_authoritative && e.purl.ecosystem() == "rpm" {
                saw_rpm_authoritative = true;
            }
        }
        if saw_deb {
            complete_ecosystems.push("deb".to_string());
        }
        if saw_apk {
            complete_ecosystems.push("apk".to_string());
        }
        if saw_pypi_authoritative {
            complete_ecosystems.push("pypi".to_string());
        }
        if saw_npm_authoritative {
            complete_ecosystems.push("npm".to_string());
        }
        if saw_golang_authoritative {
            complete_ecosystems.push("golang".to_string());
        }
        if saw_cargo_authoritative {
            complete_ecosystems.push("cargo".to_string());
        }
        if saw_gem_authoritative {
            complete_ecosystems.push("gem".to_string());
        }
        if saw_maven_authoritative {
            complete_ecosystems.push("maven".to_string());
        }
        if saw_rpm_authoritative {
            complete_ecosystems.push("rpm".to_string());
        }

        // Index by (ecosystem, canonical-name) for dependency-edge
        // lookup. Keyed per-ecosystem so a `libc6` deb never collides
        // with a hypothetical `libc6` pypi package, and normalised
        // because pypi in particular stores dep tokens in varying
        // case / hyphen-vs-underscore forms (a dist-info `Name:
        // Requests` is referenced as `Requires-Dist: requests` in
        // every other package's metadata).
        let mut name_to_purl: std::collections::HashMap<(String, String), String> =
            std::collections::HashMap::with_capacity(db_entries.len());
        for e in &db_entries {
            let ecosystem = e.purl.ecosystem().to_string();
            name_to_purl.insert(
                (ecosystem, normalize_dep_name(e.purl.ecosystem(), &e.name)),
                e.purl.as_str().to_string(),
            );
        }

        for entry in &db_entries {
            let purl_str = entry.purl.as_str().to_string();
            let ecosystem = entry.purl.ecosystem().to_string();
            // Only dpkg ships a per-package copyright file we can read.
            // apk packages have license info embedded in the install
            // db at varying quality (apk-license extraction is its own
            // follow-up). Detect the dpkg case via the source_path.
            let is_dpkg = entry.source_path.contains("dpkg/status");
            // dpkg licenses live out-of-band in /usr/share/doc/<pkg>/
            // copyright; other sources (e.g. Python dist-info METADATA)
            // embed them directly on the entry.
            let licenses = if is_dpkg {
                package_db::copyright::read_copyright(root, &entry.name)
            } else if !entry.licenses.is_empty() {
                entry.licenses.clone()
            } else {
                Vec::new()
            };
            // Deep hashing reads every file the package owns
            // (`<pkg>.list`) and stream-hashes them with SHA-256, also
            // capturing the dpkg-recorded MD5 per file for cross-ref.
            // The fast path SHA-256s the dpkg `.md5sums` file content
            // as a per-package fingerprint with no per-file occurrences.
            let (occurrences, mut component_hashes) = if is_dpkg {
                if deep_hash {
                    let (occs, root_hash) = package_db::file_hashes::hash_package_files(
                        root,
                        &entry.name,
                        entry.arch.as_deref(),
                    );
                    (occs, root_hash.into_iter().collect::<Vec<_>>())
            } else {
                    let h = package_db::file_hashes::hash_md5sums_only(
                        root,
                        &entry.name,
                        entry.arch.as_deref(),
                    );
                    (Vec::new(), h.into_iter().collect::<Vec<_>>())
                }
            } else {
                (Vec::new(), Vec::new())
            };
            // Thread manifest-provided hashes (npm integrity, cargo
            // checksum) onto the component. `entry.hashes` is
            // populated by the npm / cargo readers; empty for other
            // ecosystems, in which case this is a no-op.
            component_hashes.extend(entry.hashes.iter().cloned());
            // OS-package ecosystems (deb/apk/rpm) read licenses
            // directly from the installed-package metadata or the
            // shipped copyright file — those sources ARE the
            // result of build-time analysis by the distro
            // maintainers. Emit them as both declared AND concluded
            // so sbomqs's `comp_with_licenses` / valid-licenses /
            // deprecated / restrictive checks (which key off
            // concluded) give full credit. Non-OS ecosystems are
            // filled by the CD enrichment pass and stay empty here.
            let os_ecosystem = matches!(entry.purl.ecosystem(), "deb" | "apk" | "rpm");
            let concluded_licenses_for_os = if os_ecosystem && !licenses.is_empty() {
                licenses.clone()
            } else {
                Vec::new()
            };
            components.push(ResolvedComponent {
                name: entry.name.clone(),
                version: entry.version.clone(),
                purl: entry.purl.clone(),
                evidence: ResolutionEvidence {
                    technique: ResolutionTechnique::PackageDatabase,
                    confidence: PACKAGE_DB_CONFIDENCE,
                    source_connection_ids: vec![],
                    source_file_paths: vec![entry.source_path.clone()],
                    deps_dev_match: None,
                },
                licenses,
                concluded_licenses: concluded_licenses_for_os,
                hashes: component_hashes,
                supplier: entry
                    .maintainer
                    .clone()
                    .or_else(|| supplier_from_purl(&entry.purl)),
                cpes: vec![],
                advisories: vec![],
                occurrences,
                // Propagate dev/range/source/tier from PackageDbEntry.
                // dpkg/apk leave is_dev/requirement_range/source_type as
                // None (set in their constructors); sbom_tier = "deployed"
                // because both read installed-package databases.
                is_dev: entry.is_dev,
                requirement_range: entry.requirement_range.clone(),
                source_type: entry.source_type.clone(),
                sbom_tier: entry.sbom_tier.clone(),
                buildinfo_status: entry.buildinfo_status.clone(),
                evidence_kind: entry.evidence_kind.clone(),
                binary_class: entry.binary_class.clone(),
                binary_stripped: entry.binary_stripped,
                linkage_kind: entry.linkage_kind.clone(),
                detected_go: entry.detected_go,
                confidence: entry.confidence.clone(),
                binary_packed: entry.binary_packed.clone(),
                npm_role: entry.npm_role.clone(),
                raw_version: entry.raw_version.clone(),
                external_references: external_refs_from_purl(&entry.purl),
            });

            // Emit a Relationship edge for each dependency that
            // resolved to another entry in this scan. Dangling targets
            // (Depends names we never saw) are silently dropped so the
            // CycloneDX `dependsOn[]` array only references bom-refs
            // that exist in this SBOM.
            for dep_name in &entry.depends {
                let key = (ecosystem.clone(), normalize_dep_name(&ecosystem, dep_name));
                if let Some(to) = name_to_purl.get(&key) {
                    if to != &purl_str {
                        // Skip self-loops (can happen via provides).
                        relationships.push(Relationship {
                            from: purl_str.clone(),
                            to: to.clone(),
                            relationship_type: RelationshipType::DependsOn,
                            provenance: EnrichmentProvenance {
                                source: entry.source_path.clone(),
                                data_type: "package-database-depends".to_string(),
                            },
                        });
                    }
                }
            }
        }
    }

    let mut components = deduplicate(components);
    // Post-dedup CPE synthesis — runs on the merged set so a component
    // that exists in both the filename pass and the dpkg pass gets one
    // set of CPEs (attached to the single winning entry) instead of two.
    for c in components.iter_mut() {
        c.cpes = synthesize_cpes(c);
    }

    Ok(ScanResult {
        components,
        relationships,
        complete_ecosystems,
        os_release_missing_fields,
    })
}

/// Normalise a dependency name to the canonical form used as the
/// `name_to_purl` index key. Each ecosystem has its own rules; keeping
/// both the index side and the lookup side on this function guarantees
/// they stay in sync.
///
/// - **pypi** — case-insensitive, `_` ≡ `-` per PEP 503. Both
///   `Name: Requests` and `Requires-Dist: requests` must hit the same
///   bucket. Mirrors `pip::normalize_pypi_name_for_purl`.
/// - **npm** — lowercase (registry is case-insensitive). Scoped
///   `@scope/name` kept intact; only the case is normalised.
/// - **deb / apk / everything else** — lowercase. Debian and Alpine
///   treat names case-insensitively in practice; the installed db
///   stores them lowercase anyway but we stay tolerant.
fn normalize_dep_name(ecosystem: &str, name: &str) -> String {
    match ecosystem {
        "pypi" => name.replace('_', "-").to_lowercase(),
        _ => name.to_lowercase(),
    }
}

/// Derive a best-effort supplier string from a PURL when the
/// component's source didn't carry explicit maintainer metadata.
/// Drives CycloneDX `component.supplier.name` (sbomqs
/// `comp_with_supplier`).
///
/// - `pkg:golang/<host>/<org>/<repo>` → `<host>/<org>`.
/// - `pkg:maven/<group>/<artifact>` → `<group>`.
/// - `pkg:npm/@<scope>/<name>` → `@<scope>`; unscoped npm → `None`.
/// - Anything else → `None` (let deb/apk maintainer fields or later
///   enrichment fill in).
fn supplier_from_purl(purl: &mikebom_common::types::purl::Purl) -> Option<String> {
    let ecosystem = purl.ecosystem();
    let namespace = purl.namespace()?;
    match ecosystem {
        "golang" => {
            let segments: Vec<&str> = namespace.split('/').collect();
            if segments.len() >= 2 {
                Some(format!("{}/{}", segments[0], segments[1]))
            } else {
                Some(namespace.to_string())
            }
        }
        "maven" => Some(namespace.to_string()),
        "npm" => {
            if namespace.starts_with('@') {
                Some(namespace.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Derive VCS / website external references from a PURL when the
/// module path embeds them. Currently limited to Go modules whose
/// canonical form starts with a known repo host — that's where the
/// signal is unambiguous. npm / cargo / pypi / maven need deps.dev
/// or registry metadata to find the repo URL and are populated
/// elsewhere (out of scope for this pass).
fn external_refs_from_purl(
    purl: &mikebom_common::types::purl::Purl,
) -> Vec<mikebom_common::resolution::ExternalReference> {
    use mikebom_common::resolution::ExternalReference;
    let mut out = Vec::new();
    if purl.ecosystem() != "golang" {
        return out;
    }
    let Some(namespace) = purl.namespace() else {
        return out;
    };
    // `pkg:golang/github.com/sirupsen/logrus@v1.9.3` → namespace
    // `github.com/sirupsen`, name `logrus` → vcs
    // `https://github.com/sirupsen/logrus`. Same shape for gitlab
    // and bitbucket. Anything else (gopkg.in, custom vanity
    // domains) needs deps.dev and skips here.
    let segments: Vec<&str> = namespace.split('/').collect();
    if segments.len() < 2 {
        return out;
    }
    let host = segments[0];
    if !matches!(host, "github.com" | "gitlab.com" | "bitbucket.org") {
        return out;
    }
    let org = segments[1];
    let repo = purl.name();
    out.push(ExternalReference {
        ref_type: "vcs".to_string(),
        url: format!("https://{host}/{org}/{repo}"),
    });
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod supplier_tests {
    use super::supplier_from_purl;
    use mikebom_common::types::purl::Purl;

    #[test]
    fn golang_host_and_org() {
        let p = Purl::new("pkg:golang/github.com/sirupsen/logrus@v1.9.3").unwrap();
        assert_eq!(supplier_from_purl(&p), Some("github.com/sirupsen".to_string()));
    }

    #[test]
    fn maven_group_id() {
        let p = Purl::new("pkg:maven/com.fasterxml.jackson.core/jackson-core@2.17.2").unwrap();
        assert_eq!(
            supplier_from_purl(&p),
            Some("com.fasterxml.jackson.core".to_string()),
        );
    }

    #[test]
    fn npm_scoped_has_supplier() {
        let p = Purl::new("pkg:npm/%40types/node@20.1.0").unwrap();
        assert_eq!(supplier_from_purl(&p), Some("@types".to_string()));
    }

    #[test]
    fn npm_unscoped_has_none() {
        let p = Purl::new("pkg:npm/express@4.22.1").unwrap();
        assert_eq!(supplier_from_purl(&p), None);
    }

    #[test]
    fn cargo_has_none() {
        let p = Purl::new("pkg:cargo/serde@1.0.197").unwrap();
        assert_eq!(supplier_from_purl(&p), None);
    }
}

/// Fail-closed errors from `scan_path`. Only raised when a downstream
/// reader reports a hard failure that must abort the scan rather than
/// degrade silently (e.g. npm v1 lockfile refusal per FR-006). Wraps
/// `PackageDbError` so the CLI can print the specific stderr message
/// documented in `contracts/cli-interface.md`.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{0}")]
    PackageDb(#[from] package_db::PackageDbError),
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn scan_picks_up_cargo_crate_filenames() {
        // A path_resolver::resolve_cargo_path-compatible path resolves to
        // the right PURL even when the surrounding dir is synthetic.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join(".cargo/registry/cache/idx");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join("serde-1.0.197.crate"), b"bytes").unwrap();

        let result = scan_path(dir.path(), None, 1024, false, true, false, false, ScanMode::Path).unwrap();
        assert_eq!(result.components.len(), 1);
        assert!(result.relationships.is_empty());
        let c = &result.components[0];
        assert_eq!(c.name, "serde");
        assert_eq!(c.version, "1.0.197");
        assert_eq!(c.evidence.technique, ResolutionTechnique::FilePathPattern);
        assert!((c.evidence.confidence - 0.70).abs() < 1e-9);
        assert_eq!(c.hashes.len(), 1, "scan-sourced component must carry its file hash");
        assert_eq!(c.evidence.source_file_paths.len(), 1);
    }

    #[test]
    fn scan_picks_up_deb_filenames_with_codename_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("jq_1.6-2.1+deb12u1_arm64.deb"),
            b"deb bytes",
        )
        .unwrap();

        let result = scan_path(dir.path(), Some("bookworm"), 1024, false, true, false, false, ScanMode::Path).unwrap();
        assert_eq!(result.components.len(), 1);
        let purl = result.components[0].purl.as_str();
        assert!(
            purl.contains("distro=bookworm"),
            "codename hint should land as qualifier: {purl}"
        );
    }

    #[test]
    fn scan_ignores_non_artifact_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("README.md"), b"not a package").unwrap();
        std::fs::write(dir.path().join("build.log"), b"also not").unwrap();

        let result = scan_path(dir.path(), None, 1024, false, true, false, false, ScanMode::Path).unwrap();
        assert!(result.components.is_empty());
    }

    #[test]
    fn package_db_entries_appear_with_high_confidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Fake rootfs with a dpkg status file.
        let dpkg = dir.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(dpkg.parent().unwrap()).unwrap();
        std::fs::write(
            &dpkg,
            "\
Package: jq
Status: install ok installed
Version: 1.6-2.1+deb12u1
Architecture: arm64
Depends: libc6, libjq1

Package: libjq1
Status: install ok installed
Version: 1.6-2.1+deb12u1
Architecture: arm64
",
        )
        .unwrap();

        let result = scan_path(dir.path(), Some("bookworm"), 1024, true, true, false, false, ScanMode::Path).unwrap();
        // Both packages resolve from the db.
        assert_eq!(result.components.len(), 2, "{:#?}", result.components);
        assert!(result
            .components
            .iter()
            .all(|c| c.evidence.technique == ResolutionTechnique::PackageDatabase));
        assert!(result
            .components
            .iter()
            .all(|c| (c.evidence.confidence - 0.85).abs() < 1e-9));
    }

    #[test]
    fn package_db_relationships_reference_observed_components_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dpkg = dir.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(dpkg.parent().unwrap()).unwrap();
        // jq depends on libjq1 (installed) AND libc6 (NOT listed as
        // installed in this tiny db). Expect exactly one edge: jq→libjq1.
        std::fs::write(
            &dpkg,
            "\
Package: jq
Status: install ok installed
Version: 1.6
Architecture: arm64
Depends: libc6, libjq1

Package: libjq1
Status: install ok installed
Version: 1.6
Architecture: arm64
",
        )
        .unwrap();

        let result = scan_path(dir.path(), None, 1024, true, true, false, false, ScanMode::Path).unwrap();
        assert_eq!(result.relationships.len(), 1);
        let rel = &result.relationships[0];
        assert!(rel.from.contains("jq@1.6"));
        assert!(rel.to.contains("libjq1@1.6"));
        assert_eq!(rel.relationship_type, RelationshipType::DependsOn);
    }

    #[test]
    fn filename_resolved_and_dpkg_resolved_dedupe_into_one_component() {
        // Real-world case: the .deb artefact sits in apt's cache AND
        // the package is also recorded in dpkg's status file. Both
        // code paths fire and must merge into a single component.
        let dir = tempfile::tempdir().expect("tempdir");

        // Filename side: drop the .deb where the apt cache normally lives.
        let cache = dir.path().join("var/cache/apt/archives");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(
            cache.join("jq_1.6-2.1+deb12u1_arm64.deb"),
            b"fake deb body",
        )
        .unwrap();

        // dpkg side: status file listing jq + libjq1 with a dependency edge.
        let dpkg = dir.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(dpkg.parent().unwrap()).unwrap();
        std::fs::write(
            &dpkg,
            "\
Package: jq
Status: install ok installed
Version: 1.6-2.1+deb12u1
Architecture: arm64
Depends: libjq1

Package: libjq1
Status: install ok installed
Version: 1.6-2.1+deb12u1
Architecture: arm64
",
        )
        .unwrap();

        // Deep hash off so we don't depend on .list/.md5sums fixtures.
        let result = scan_path(dir.path(), Some("bookworm"), 1024, true, false, false, false, ScanMode::Path).unwrap();

        // Exactly two components: jq (merged) + libjq1. NOT three.
        assert_eq!(
            result.components.len(),
            2,
            "filename+dpkg duplicates should merge: {:#?}",
            result.components
        );

        let jq = result
            .components
            .iter()
            .find(|c| c.name == "jq")
            .expect("jq component present");
        let libjq1 = result
            .components
            .iter()
            .find(|c| c.name == "libjq1")
            .expect("libjq1 component present");

        // PackageDatabase technique (0.85) beats FilePathPattern (0.70) —
        // the deduplicator should keep the dpkg entry's identity fields.
        assert_eq!(jq.evidence.technique, ResolutionTechnique::PackageDatabase);
        assert!((jq.evidence.confidence - 0.85).abs() < 1e-9);

        // Hashes from the filename side must be preserved through the merge.
        assert!(
            !jq.hashes.is_empty(),
            "merged jq should retain the .deb file's SHA-256"
        );

        // Source file paths from both sides merged.
        let paths = &jq.evidence.source_file_paths;
        assert!(paths.iter().any(|p| p.ends_with(".deb")), "{paths:?}");
        assert!(
            paths.iter().any(|p| p.ends_with("dpkg/status")),
            "{paths:?}"
        );

        // Dependency edge must still reference libjq1 after the merge.
        let libjq1_purl = libjq1.purl.as_str();
        assert!(
            result
                .relationships
                .iter()
                .any(|r| r.from == jq.purl.as_str() && r.to == libjq1_purl),
            "jq -> libjq1 edge survives dedup: {:#?}",
            result.relationships
        );
    }

    #[test]
    fn filename_with_percent_encoded_plus_merges_with_dpkg_plain_plus() {
        // Regression: apt names the cache file with `%2B` but dpkg
        // stores the version with a literal `+`. If the path_resolver
        // doesn't decode %2B back to +, the two PURL keys diverge and
        // dedup produces two components instead of one. This is the
        // exact shape we observed on a real debian:bookworm-slim-style
        // scan (libjq1, fd-find, jq, libonig5, ripgrep — all with +bN
        // binNMU suffixes).
        let dir = tempfile::tempdir().expect("tempdir");

        let cache = dir.path().join("var/cache/apt/archives");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(
            cache.join("libjq1_1.6-2.1%2Bb1_arm64.deb"),
            b"fake deb body",
        )
        .unwrap();

        let dpkg = dir.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(dpkg.parent().unwrap()).unwrap();
        std::fs::write(
            &dpkg,
            "\
Package: libjq1
Status: install ok installed
Version: 1.6-2.1+b1
Architecture: arm64
Maintainer: Some Maintainer <m@example.org>
",
        )
        .unwrap();

        let result = scan_path(dir.path(), Some("bookworm"), 1024, true, false, false, false, ScanMode::Path).unwrap();

        // One merged component, not two.
        assert_eq!(
            result.components.len(),
            1,
            "%2B filename + plain `+` dpkg must dedup: {:#?}",
            result.components
        );

        let c = &result.components[0];
        assert_eq!(c.name, "libjq1");
        // Human-readable version keeps literal `+` (used in CycloneDX
        // `component.version` and CPE).
        assert_eq!(c.version, "1.6-2.1+b1");
        // dpkg won on confidence.
        assert_eq!(c.evidence.technique, ResolutionTechnique::PackageDatabase);
        // Filename-side SHA-256 survived the merge.
        assert!(!c.hashes.is_empty(), "merged component retains .deb hash");
        // dpkg-side Maintainer propagated.
        assert_eq!(
            c.supplier.as_deref(),
            Some("Some Maintainer <m@example.org>")
        );
        // Canonical PURL encodes `+` as `%2B` per the packageurl-python
        // reference impl. Exactly once, and no stray literal `+` left
        // over from either side of the merge.
        let purl = c.purl.as_str();
        assert!(
            purl.contains("1.6-2.1%2Bb1"),
            "canonical form must carry %2B: {purl}"
        );
        assert!(
            !purl.contains("1.6-2.1+"),
            "no literal + should leak into canonical form: {purl}"
        );
    }

    #[test]
    fn no_package_db_flag_skips_db_read_even_if_db_is_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dpkg = dir.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(dpkg.parent().unwrap()).unwrap();
        std::fs::write(
            &dpkg,
            "\
Package: foo
Status: install ok installed
Version: 1.0
Architecture: amd64
",
        )
        .unwrap();

        let result = scan_path(dir.path(), None, 1024, /*read_package_db=*/ false, true, false, false, ScanMode::Path).unwrap();
        assert!(
            result.components.is_empty(),
            "db should be ignored when flag is off"
        );
    }
}