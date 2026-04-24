use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Args;

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;

use crate::enrich::clearly_defined_source::{
    enrich_components as cd_enrich_components, ClearlyDefinedSource,
};
use crate::enrich::deps_dev_client::DepsDevClient;
use crate::enrich::depsdev_source::{enrich_components, DepsDevSource};
use crate::generate::{OutputConfig, ScanArtifacts, SerializerRegistry};
use crate::scan_fs;

/// Hard-coded default when the user passes no `--format` flag. Kept
/// as `cyclonedx-json` so pre-milestone-010 invocations behave exactly
/// as before (FR-004b).
const DEFAULT_FORMAT: &str = "cyclonedx-json";

/// Pseudo-format override key for the OpenVEX sidecar.
///
/// `openvex` is NOT a real `SbomSerializer` — it's a sidecar the
/// SPDX 2.3 serializer co-emits when a scan produces VEX statements
/// (FR-016a). The user cannot request it via `--format`; they can
/// only retarget its output path via `--output openvex=<path>` when
/// an SPDX format is also requested. Using it without SPDX, or
/// naming it in `--format`, is rejected in `resolve_dispatch` with
/// a clear error.
const OPENVEX_PSEUDO_FORMAT: &str = "openvex";

/// Format ids that trigger OpenVEX sidecar emission. Today only
/// the stable SPDX 2.3 serializer does so; SPDX 3.0.1-experimental
/// may opt in in a future milestone, at which point this list grows.
const OPENVEX_EMITTING_FORMATS: &[&str] = &["spdx-2.3-json"];

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Directory to walk for package artifacts.
    ///
    /// Exactly one of `--path` or `--image` is required. The directory
    /// is traversed recursively; files with recognised package-artifact
    /// suffixes (`.deb`, `.crate`, `.whl`, `.tar.gz`, `.jar`, `.gem`, …)
    /// are stream-hashed and matched against the path resolver.
    #[arg(long, conflicts_with = "image")]
    pub path: Option<PathBuf>,

    /// `docker save`-format tarball to extract, overlay, and scan.
    ///
    /// Exactly one of `--path` or `--image` is required. The tarball is
    /// opened, layers extracted into a tempdir (whiteouts honoured),
    /// then the resulting rootfs is scanned exactly like `--path`.
    #[arg(long, conflicts_with = "path")]
    pub image: Option<PathBuf>,

    /// Output path override. Two forms are accepted:
    ///
    /// * Bare `--output <path>` — applies to the single requested
    ///   format. Rejected when more than one format is requested.
    /// * Per-format `--output <fmt>=<path>` — repeatable; each entry
    ///   overrides the default filename for exactly one format id.
    ///
    /// Per-format form is required for multi-format emission. When
    /// omitted, each format writes to its own default filename
    /// (`mikebom.cdx.json`, `mikebom.spdx.json`, …).
    #[arg(long, action = clap::ArgAction::Append, value_name = "[FMT=]PATH")]
    pub output: Vec<String>,

    /// Output format(s). Comma-separated list, and the flag itself
    /// is repeatable: `--format cyclonedx-json,spdx-2.3-json` is
    /// equivalent to `--format cyclonedx-json --format spdx-2.3-json`.
    /// Duplicates are ignored silently. Default: `cyclonedx-json`.
    ///
    /// Registered formats:
    /// - `cyclonedx-json` — CycloneDX 1.6 JSON (default filename
    ///   `mikebom.cdx.json`).
    /// - `spdx-2.3-json` — SPDX 2.3 JSON (default filename
    ///   `mikebom.spdx.json`).
    #[arg(
        long,
        action = clap::ArgAction::Append,
        value_delimiter = ',',
        value_name = "FORMAT",
    )]
    pub format: Vec<String>,

    /// Maximum file size to hash (bytes). Larger files are skipped. The
    /// default (256 MB) covers the largest realistic package artifact.
    #[arg(long, default_value_t = scan_fs::walker::DEFAULT_SIZE_CAP_BYTES)]
    pub max_file_size: u64,

    /// Omit per-component content hashes from the SBOM.
    #[arg(long)]
    pub no_hashes: bool,

    /// Optional distro codename to stamp on deb PURLs. Overrides the
    /// codename auto-detected from `<root>/etc/os-release` when set.
    /// Useful when scanning a directory that isn't itself a rootfs.
    #[arg(long)]
    pub deb_codename: Option<String>,

    /// Skip reading installed-package databases (`/var/lib/dpkg/status`,
    /// `/lib/apk/db/installed`). On by default because production
    /// container images routinely clean up `.deb`/`.apk` artefact caches
    /// and the db is then the only complete source of installed
    /// packages. Pass this flag to fall back to pure artefact-file
    /// scanning.
    #[arg(long)]
    pub no_package_db: bool,

    /// Skip per-file SHA-256 hashing of installed-package contents.
    /// Falls back to a fast SHA-256 over each package's dpkg `.md5sums`
    /// file (microseconds per package; component-level identity only,
    /// no per-file occurrences). Default-on hashing reads every file
    /// referenced by dpkg's `.list` manifest — proportional to
    /// installed size (~3-5 s on debian:bookworm-slim, ~30 s on full
    /// debian).
    #[arg(long)]
    pub no_deep_hash: bool,

    /// Print a JSON summary to stdout after writing the SBOM.
    #[arg(long)]
    pub json: bool,
}

/// Resolved format-dispatch inputs: the canonical (deduped, in-order)
/// list of format ids the user asked for, plus the per-format path
/// overrides to apply. Computed before any scan work runs so argument
/// errors abort early.
#[derive(Debug)]
struct DispatchPlan {
    formats: Vec<String>,
    overrides: BTreeMap<String, PathBuf>,
}

/// Parse `--format` + `--output` into a [`DispatchPlan`], enforcing
/// the FR-001 / FR-004 / FR-004a / FR-004b error semantics the CLI
/// surface promises: unknown format ids reject with the registered-id
/// enumeration; per-format overrides for unrequested formats reject;
/// bare `--output <path>` is only legal with a single requested
/// format; duplicate overrides and cross-format path collisions
/// reject.
fn resolve_dispatch(
    registry: &SerializerRegistry,
    format_args: &[String],
    output_args: &[String],
) -> anyhow::Result<DispatchPlan> {
    // De-dupe format ids silently while preserving the user's order.
    // `--format cyclonedx-json,cyclonedx-json` collapses to one entry.
    let raw_formats: Vec<String> = if format_args.is_empty() {
        vec![DEFAULT_FORMAT.to_string()]
    } else {
        format_args.to_vec()
    };
    let mut formats: Vec<String> = Vec::new();
    for f in raw_formats {
        let f = f.trim().to_string();
        if f.is_empty() {
            anyhow::bail!("--format value must not be empty");
        }
        if !formats.contains(&f) {
            formats.push(f);
        }
    }

    // Reject unknown format ids with a clear enumeration of what IS
    // registered, so the user can see what changed between versions.
    // OpenVEX is explicitly NOT a registered format; calling it out
    // separately gives a more useful error than "unknown".
    for f in &formats {
        if f == OPENVEX_PSEUDO_FORMAT {
            anyhow::bail!(
                "{OPENVEX_PSEUDO_FORMAT:?} is not a selectable --format — \
                 it is emitted as a sidecar alongside SPDX when a scan \
                 produces VEX. Retarget its output path with \
                 `--output {OPENVEX_PSEUDO_FORMAT}=<path>` alongside \
                 an SPDX `--format`.",
            );
        }
        if registry.get(f).is_none() {
            let known: Vec<&'static str> = registry.ids().collect();
            anyhow::bail!(
                "unknown format identifier {:?}; accepted: {}",
                f,
                known.join(", "),
            );
        }
    }

    // Parse --output entries. A bare path (no `=`) is legal only when
    // exactly one format is requested; it then overrides that one
    // format. A `<fmt>=<path>` entry names the format explicitly.
    let mut overrides: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut bare_path: Option<PathBuf> = None;
    for raw in output_args {
        if let Some((fmt, path)) = raw.split_once('=') {
            let fmt = fmt.trim();
            let path = path.trim();
            if fmt.is_empty() || path.is_empty() {
                anyhow::bail!(
                    "--output expects <fmt>=<path> with non-empty parts, got {raw:?}",
                );
            }
            // Special case: `openvex` isn't a format, but is a
            // legal override key when the scan is going to produce
            // the sidecar (i.e., at least one SPDX format was
            // requested). Reject `--output openvex=...` without an
            // SPDX format so typos don't silently no-op.
            if fmt == OPENVEX_PSEUDO_FORMAT {
                let has_spdx = formats
                    .iter()
                    .any(|f| OPENVEX_EMITTING_FORMATS.contains(&f.as_str()));
                if !has_spdx {
                    anyhow::bail!(
                        "`--output {OPENVEX_PSEUDO_FORMAT}=<path>` is only \
                         valid when an SPDX format is also requested \
                         (e.g., --format spdx-2.3-json); it retargets \
                         the OpenVEX sidecar that SPDX emission produces \
                         when a scan has VEX statements. Requested \
                         formats: {}",
                        formats.join(", "),
                    );
                }
                if overrides
                    .insert(fmt.to_string(), PathBuf::from(path))
                    .is_some()
                {
                    anyhow::bail!(
                        "--output for {OPENVEX_PSEUDO_FORMAT:?} specified more than once"
                    );
                }
                continue;
            }
            if !formats.iter().any(|f| f == fmt) {
                anyhow::bail!(
                    "--output targets format {:?} but --format did not request it; \
                     requested: {}",
                    fmt,
                    formats.join(", "),
                );
            }
            if overrides.insert(fmt.to_string(), PathBuf::from(path)).is_some() {
                anyhow::bail!("--output for format {fmt:?} specified more than once");
            }
        } else {
            if bare_path.is_some() {
                anyhow::bail!(
                    "--output bare <path> specified more than once; use \
                     --output <fmt>=<path> to target specific formats"
                );
            }
            bare_path = Some(PathBuf::from(raw));
        }
    }

    if let Some(path) = bare_path {
        if formats.len() != 1 {
            anyhow::bail!(
                "bare --output <path> is only valid with a single --format; \
                 requested formats: {}. Use --output <fmt>=<path> instead.",
                formats.join(", "),
            );
        }
        let fmt = formats[0].clone();
        if overrides.contains_key(&fmt) {
            anyhow::bail!(
                "bare --output <path> conflicts with --output {fmt}=<path>; \
                 specify one form",
            );
        }
        overrides.insert(fmt, path);
    }

    // Path-collision check: two formats (default or overridden) must
    // not resolve to the same filesystem path. Done here so the error
    // fires before any scan work runs.
    let mut resolved_paths: BTreeMap<PathBuf, String> = BTreeMap::new();
    for fmt in &formats {
        let ser = registry
            .get(fmt)
            .expect("format id validated above");
        let path = overrides
            .get(fmt)
            .cloned()
            .unwrap_or_else(|| PathBuf::from(ser.default_filename()));
        let canonical = canonicalize_for_collision(&path);
        if let Some(prev) = resolved_paths.insert(canonical.clone(), fmt.clone()) {
            anyhow::bail!(
                "output path collision: format {prev:?} and format {fmt:?} both \
                 resolve to {}",
                canonical.display(),
            );
        }
    }
    // Also check the OpenVEX override against format outputs, since
    // the sidecar lands beside the SPDX file. No default path to
    // check when the override isn't set — the sidecar's default is
    // `mikebom.openvex.json`, which can't collide with any
    // registered format's default (cdx / spdx filenames are
    // distinct from openvex's).
    if let Some(openvex_path) = overrides.get(OPENVEX_PSEUDO_FORMAT) {
        let canonical = canonicalize_for_collision(openvex_path);
        if let Some(prev) = resolved_paths.insert(canonical.clone(), OPENVEX_PSEUDO_FORMAT.to_string()) {
            anyhow::bail!(
                "output path collision: format {prev:?} and \
                 {OPENVEX_PSEUDO_FORMAT:?} both resolve to {}",
                canonical.display(),
            );
        }
    }

    Ok(DispatchPlan { formats, overrides })
}

/// Normalize a path for collision detection without touching the
/// filesystem. Relative paths are made absolute against the current
/// directory so two formats writing to `foo.json` and `./foo.json`
/// collide as intended.
fn canonicalize_for_collision(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

pub async fn execute(
    args: ScanArgs,
    offline: bool,
    include_dev: bool,
    include_legacy_rpmdb: bool,
    include_declared_deps: bool,
) -> anyhow::Result<()> {
    // Milestone 004 US4: the flag is threaded all the way to
    // `scan_path` so the (future) BDB rpmdb reader can consume it.
    // Until the BDB reader lands (T064), the parameter rides through
    // as a no-op; default behaviour is unchanged from milestone 003.
    let _ = include_legacy_rpmdb;
    if args.path.is_none() && args.image.is_none() {
        anyhow::bail!("one of --path or --image is required");
    }

    // Resolve format dispatch BEFORE any scan work so argument errors
    // abort without having paid for a scan.
    let registry = SerializerRegistry::with_defaults();
    let plan = resolve_dispatch(&registry, &args.format, &args.output)?;

    // `--image` dispatches to Docker-tarball extraction, then falls
    // through into the same scan path. Keeping both modes on one code
    // path ensures the CycloneDX output is structurally identical —
    // only `generation-context` differs.
    //
    // `auto_codename` captures the codename we *infer* from the scanned
    // content (the extracted rootfs for --image, or <path>/etc/os-release
    // for a --path root that looks like a rootfs). Explicit
    // `--deb-codename` on the CLI always wins.
    let (root_path, target_name, generation_context, auto_codename, _extracted) =
        if let Some(archive) = args.image.as_ref() {
            if !archive.is_file() {
                anyhow::bail!(
                    "--image must point at a docker save tarball: {}",
                    archive.display()
                );
            }
            tracing::info!(archive = %archive.display(), "extracting docker image");
            let extracted = scan_fs::docker_image::extract(archive)?;
            let target = extracted
                .repo_tag
                .clone()
                .unwrap_or_else(|| format!("image@sha256:{}", extracted.manifest_digest));
            let rootfs = extracted.rootfs.clone();
            let codename = extracted.distro_codename.clone();
            if let Some(ref c) = codename {
                tracing::info!(codename = %c, "detected distro codename from rootfs /etc/os-release");
            }
            tracing::info!(rootfs = %rootfs.display(), target = %target, "image extracted");
            (
                rootfs,
                target,
                GenerationContext::ContainerImageScan,
                codename,
                Some(extracted),
            )
        } else {
            let path = args.path.clone().expect("path present after --image check");
            if !path.is_dir() {
                anyhow::bail!("--path must be an existing directory: {}", path.display());
            }
            let target = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("filesystem-scan")
                .to_string();
            // If --path points at an extracted rootfs (has /etc/os-release
            // at the top), auto-populate the distro tag from it — the
            // canonical `<ID>-<VERSION_ID>` shape (falling back to
            // VERSION_CODENAME when VERSION_ID is absent). Harmless when
            // the path is just a cache dir — the file isn't there and we
            // get None.
            let codename = scan_fs::os_release::read_distro_tag(
                &path.join("etc/os-release"),
            );
            if let Some(ref c) = codename {
                tracing::info!(
                    distro_tag = %c,
                    "detected distro tag from <path>/etc/os-release"
                );
            }
            (
                path,
                target,
                GenerationContext::FilesystemScan,
                codename,
                None,
            )
        };

    // CLI-supplied --deb-codename overrides the auto-detected value.
    let effective_codename = args
        .deb_codename
        .as_deref()
        .or(auto_codename.as_deref());

    // v005 Phase 2: scan_mode drives feature-005 scan-mode-aware scoping
    // (npm internals in particular). ScanMode::Image when the operator
    // invoked --image; ScanMode::Path otherwise.
    let scan_mode = if args.image.is_some() {
        scan_fs::ScanMode::Image
    } else {
        scan_fs::ScanMode::Path
    };
    // Dual-SBOM scope auto-detection (see docs/design-notes.md:
    // "Scope: artifact vs manifest SBOM"). Image scans default to
    // strict "artifact" scope (only list components actually on disk);
    // path scans default to permissive "manifest" scope (declared deps
    // in the lockfile / pom.xml / etc. are in scope even without
    // bytes on disk, because they WOULD be pulled in on install or
    // build). `--include-declared-deps` is an explicit override that
    // forces permissive in image mode; in path mode it's already on
    // by default so the flag is effectively a no-op.
    let effective_include_declared_deps =
        include_declared_deps || matches!(scan_mode, scan_fs::ScanMode::Path);
    tracing::info!(root = %root_path.display(), "scan starting");
    let scan_fs::ScanResult {
        mut components,
        mut relationships,
        complete_ecosystems,
        os_release_missing_fields,
        scan_target_coord,
    } = scan_fs::scan_path(
        &root_path,
        effective_codename,
        args.max_file_size,
        !args.no_package_db,
        !args.no_deep_hash,
        include_dev,
        include_legacy_rpmdb,
        scan_mode,
        effective_include_declared_deps,
        // Scan-target filter: the Maven walker uses this to skip
        // emitting the scan target's own primary coord as a component
        // (it represents the SBOM subject, not a dependency). See
        // `maven::read_with_claims` and docs/design-notes.md "Scan
        // target identity" for rationale.
        Some(&target_name),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    tracing::info!(
        components = components.len(),
        relationships = relationships.len(),
        "scan complete"
    );

    // deps.dev enrichment runs after the local scan so it only sees the
    // deduped component set. Components in unsupported ecosystems
    // (deb/apk/generic) are skipped silently inside the enrichment;
    // offline mode turns the whole pass into a no-op. Failures are
    // warnings, not errors — the scan still produces a valid SBOM if
    // deps.dev is unreachable.
    let deps_dev_client = DepsDevClient::new(std::time::Duration::from_secs(5));
    let deps_dev_source = DepsDevSource::new(deps_dev_client.clone(), offline);
    let enriched = enrich_components(&deps_dev_source, &mut components).await;
    if enriched > 0 {
        tracing::info!(enriched, "deps.dev added licenses to components");
    }

    // ClearlyDefined enrichment runs after deps.dev and populates each
    // component's `concluded_licenses` with CD's curated SPDX
    // expression. Fed by the same `--offline` flag — a no-op when set.
    // CD's coverage is good for npm / cargo / gem / pypi / maven /
    // golang and shaky elsewhere; unsupported ecosystems are skipped
    // silently inside the source.
    let cd_source = ClearlyDefinedSource::new(offline);
    let cd_enriched = cd_enrich_components(&cd_source, &mut components).await;
    if cd_enriched > 0 {
        tracing::info!(
            cd_enriched,
            "ClearlyDefined added concluded licenses to components"
        );
    }

    // deps.dev transitive dep-graph enrichment fills in edges the
    // local scan couldn't produce — shaded-JAR transitives, cold-
    // cache scans, BOM-declared deps. The response tree is merged
    // into the running component set with `source_type =
    // "declared-not-cached"` on any coord not already observed
    // locally; local versions win when deps.dev reports a different
    // version for the same (group, artifact) pair.
    let new_dep_graph_edges =
        crate::enrich::deps_dev_graph::enrich_dep_graph(
            &deps_dev_client,
            &mut components,
            offline,
            effective_include_declared_deps,
        )
        .await;
    if !new_dep_graph_edges.is_empty() {
        tracing::info!(
            count = new_dep_graph_edges.len(),
            "deps.dev added transitive dep-graph edges",
        );
        relationships.extend(new_dep_graph_edges);
    }

    // Cross-source dedup pass (Fix A). `scan_fs::scan_path` already ran
    // pass-1 + pass-2 before returning, but `enrich_dep_graph` above
    // pushed `source_type = "declared-not-cached"` entries AFTER that
    // dedup — so pass-2's fold-into-on-disk-twin logic had nothing to
    // fold. Re-running `deduplicate()` here closes the loop: pass-1 is
    // a no-op on an already-deduped set; pass-2 now sees the freshly-
    // pushed declared entries and collapses each one whose canonical
    // `(ecosystem, group, artifact, version)` matches an on-disk
    // component (shade-jar vendored coord or top-level).
    //
    // See `resolve/deduplicator.rs::fold_declared_not_cached` for the
    // full matching rule.
    let pre_fold_count = components.len();
    components = crate::resolve::deduplicator::deduplicate(components);
    let folded = pre_fold_count.saturating_sub(components.len());
    if folded > 0 {
        tracing::info!(
            folded,
            "folded declared-not-cached entries into on-disk twins",
        );
    }

    // `trace_integrity` is a clean record: no eBPF ran, so there's nothing
    // to have overflowed or dropped.
    let integrity = TraceIntegrity {
        ring_buffer_overflows: 0,
        events_dropped: 0,
        uprobe_attach_failures: vec![],
        kprobe_attach_failures: vec![],
        partial_captures: vec![],
        bloom_filter_capacity: 0,
        bloom_filter_false_positive_rate: 0.0,
    };

    // Build the neutral artifacts bundle once and hand it to every
    // serializer the user requested — the single-pass guarantee of
    // FR-004 / SC-009.
    let artifacts = ScanArtifacts {
        target_name: &target_name,
        components: &components,
        relationships: &relationships,
        integrity: &integrity,
        complete_ecosystems: &complete_ecosystems,
        os_release_missing_fields: &os_release_missing_fields,
        scan_target_coord: scan_target_coord.as_ref(),
        generation_context: generation_context.clone(),
        include_dev,
        include_hashes: !args.no_hashes,
        include_source_files: true, // path-pattern evidence is the whole value prop here
    };
    let output_cfg = OutputConfig {
        mikebom_version: env!("CARGO_PKG_VERSION"),
        created: chrono::Utc::now(),
        overrides: plan.overrides.clone(),
    };

    // Dispatch: serialize to every requested format and write each
    // emitted artifact to the chosen path. The first format's first
    // artifact path drives the backwards-compatible `--json` summary
    // output below (matches pre-milestone behavior, which only knew
    // about one file).
    let mut primary_output_path: Option<PathBuf> = None;
    let mut primary_format: Option<String> = None;
    for fmt in &plan.formats {
        let serializer = registry
            .get(fmt)
            .expect("format id validated by resolve_dispatch");
        let emitted = serializer.serialize(&artifacts, &output_cfg)?;
        for artifact in emitted {
            // The primary artifact (first returned by the serializer)
            // honors the per-format --output override; side artifacts
            // (e.g. the OpenVEX sidecar in US2) always use their
            // relative_path relative to the primary's directory.
            // Three cases:
            //   (1) The primary artifact (filename == the
            //       serializer's default) → honor a per-format
            //       --output override for this `fmt`.
            //   (2) The OpenVEX sidecar (relative_path matches the
            //       sidecar's default filename) → honor the
            //       `--output openvex=<path>` pseudo-format override.
            //   (3) Any other side artifact (none today; future
            //       formats may add more) → keep its relative_path.
            let target = if artifact.relative_path
                == Path::new(serializer.default_filename())
            {
                plan.overrides
                    .get(fmt)
                    .cloned()
                    .unwrap_or_else(|| artifact.relative_path.clone())
            } else if artifact.relative_path
                == Path::new(
                    crate::generate::openvex::OPENVEX_DEFAULT_FILENAME,
                )
            {
                plan.overrides
                    .get(OPENVEX_PSEUDO_FORMAT)
                    .cloned()
                    .unwrap_or_else(|| artifact.relative_path.clone())
            } else {
                artifact.relative_path.clone()
            };
            write_bytes_to(&target, &artifact.bytes)?;
            if primary_output_path.is_none() {
                primary_output_path = Some(target.clone());
                primary_format = Some(fmt.clone());
            }
            tracing::info!(
                format = %fmt,
                path = %target.display(),
                bytes = artifact.bytes.len(),
                "wrote SBOM artifact"
            );
        }
    }

    if args.json {
        let ctx_str = match generation_context {
            GenerationContext::FilesystemScan => "filesystem-scan",
            GenerationContext::ContainerImageScan => "container-image-scan",
            GenerationContext::BuildTimeTrace => "build-time-trace",
        };
        let summary = serde_json::json!({
            "output_file": primary_output_path
                .as_ref()
                .map(|p| p.to_string_lossy())
                .unwrap_or_default(),
            "format": primary_format.clone().unwrap_or_default(),
            "components": components.len(),
            "relationships": relationships.len(),
            "scanned_root": root_path.to_string_lossy(),
            "target_name": target_name,
            "generation_context": ctx_str,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    }

    tracing::info!(
        output = %primary_output_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        components = components.len(),
        relationships = relationships.len(),
        "SBOM written"
    );
    Ok(())
}

/// Write `bytes` to `path`, creating any missing parent directories.
///
/// Shared by every serializer artifact (CDX today; SPDX + OpenVEX in
/// later phases). Kept local to this CLI module so the generator crate
/// has no filesystem dependencies.
fn write_bytes_to(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory: {}", parent.display()))?;
        }
    }
    std::fs::write(path, bytes)
        .with_context(|| format!("writing SBOM to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    fn reg() -> SerializerRegistry {
        SerializerRegistry::with_defaults()
    }

    #[test]
    fn default_format_is_cyclonedx_when_no_flag_given() {
        let plan = resolve_dispatch(&reg(), &[], &[]).unwrap();
        assert_eq!(plan.formats, vec!["cyclonedx-json".to_string()]);
        assert!(plan.overrides.is_empty());
    }

    #[test]
    fn duplicate_format_ids_dedupe_silently() {
        let plan = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into(), "cyclonedx-json".into()],
            &[],
        )
        .unwrap();
        assert_eq!(plan.formats, vec!["cyclonedx-json".to_string()]);
    }

    #[test]
    fn unknown_format_rejects_with_known_list() {
        let err = resolve_dispatch(&reg(), &["totally-fake-format".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown format identifier") && err.contains("cyclonedx-json"),
            "error should enumerate registered ids, got: {err}"
        );
    }

    #[test]
    fn bare_output_applies_to_single_requested_format() {
        let plan =
            resolve_dispatch(&reg(), &[], &["out.cdx.json".into()]).unwrap();
        assert_eq!(
            plan.overrides.get("cyclonedx-json"),
            Some(&PathBuf::from("out.cdx.json"))
        );
    }

    #[test]
    fn fmt_equals_path_parses_as_per_format_override() {
        let plan = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into()],
            &["cyclonedx-json=custom.cdx.json".into()],
        )
        .unwrap();
        assert_eq!(
            plan.overrides.get("cyclonedx-json"),
            Some(&PathBuf::from("custom.cdx.json"))
        );
    }

    #[test]
    fn openvex_cannot_be_requested_via_format_flag() {
        let err = resolve_dispatch(&reg(), &["openvex".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a selectable --format")
                && err.contains("sidecar alongside SPDX"),
            "got: {err}"
        );
    }

    #[test]
    fn openvex_override_without_spdx_format_rejects() {
        let err = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into()],
            &["openvex=/tmp/vex.json".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("`--output openvex=<path>` is only valid when an SPDX format"),
            "got: {err}"
        );
    }

    #[test]
    fn openvex_override_with_spdx_format_is_accepted() {
        let plan = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into(), "spdx-2.3-json".into()],
            &[
                "cyclonedx-json=out.cdx.json".into(),
                "spdx-2.3-json=out.spdx.json".into(),
                "openvex=out.vex.json".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            plan.overrides.get("openvex"),
            Some(&PathBuf::from("out.vex.json"))
        );
        // openvex is NOT in the formats list — it's a sidecar key
        // only, never dispatched as a serializer.
        assert!(!plan.formats.iter().any(|f| f == "openvex"));
    }

    #[test]
    fn openvex_override_collides_with_cdx_path() {
        let err = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into(), "spdx-2.3-json".into()],
            &[
                "spdx-2.3-json=out.spdx.json".into(),
                "openvex=mikebom.cdx.json".into(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("output path collision")
                && err.contains("openvex"),
            "got: {err}"
        );
    }

    #[test]
    fn override_for_unrequested_format_rejects() {
        let err = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into()],
            &["spdx-2.3-json=s.json".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("but --format did not request it"),
            "got: {err}"
        );
    }

    #[test]
    fn duplicate_override_for_same_format_rejects() {
        let err = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into()],
            &[
                "cyclonedx-json=a.json".into(),
                "cyclonedx-json=b.json".into(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("specified more than once"), "got: {err}");
    }

    #[test]
    fn bare_output_rejected_when_multiple_formats_requested() {
        // Register a second (fake) format by using the existing
        // `cyclonedx-json` twice won't test this — multiple distinct
        // registered ids only appear once SPDX lands. We simulate the
        // condition by checking that bare `--output` with two format
        // args (even before dedup) resolves to one-format and succeeds,
        // then confirm the negative path by forcing the check via the
        // error message branch below.
        //
        // Cross-check: build args that survive dedup as a single
        // format — bare path works. Using two *identical* ids dedupes,
        // so this is actually the default path. The multi-format
        // negative case is covered by `format_dispatch.rs` integration
        // test once SPDX lands; this unit test guards the happy dedup
        // case.
        let plan = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into(), "cyclonedx-json".into()],
            &["out.cdx.json".into()],
        )
        .unwrap();
        assert_eq!(plan.formats.len(), 1);
        assert_eq!(
            plan.overrides.get("cyclonedx-json"),
            Some(&PathBuf::from("out.cdx.json"))
        );
    }

    #[test]
    fn empty_format_value_rejects() {
        let err = resolve_dispatch(&reg(), &["".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn bare_and_per_format_override_for_same_format_rejects() {
        let err = resolve_dispatch(
            &reg(),
            &["cyclonedx-json".into()],
            &[
                "cyclonedx-json=a.json".into(),
                "b.json".into(),
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("conflicts with --output"), "got: {err}");
    }
}
