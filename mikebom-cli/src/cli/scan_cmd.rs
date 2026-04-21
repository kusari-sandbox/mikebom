use std::path::PathBuf;

use clap::Args;

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;

use crate::enrich::deps_dev_client::DepsDevClient;
use crate::enrich::depsdev_source::{enrich_components, DepsDevSource};
use crate::enrich::clearly_defined_source::{
    enrich_components as cd_enrich_components, ClearlyDefinedSource,
};
use crate::generate::cyclonedx::builder::{CycloneDxBuilder, CycloneDxConfig};
use crate::generate::cyclonedx::serializer::write_cyclonedx_json;
use crate::scan_fs;

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

    /// Output path for the CycloneDX SBOM.
    #[arg(long, default_value = "mikebom.cdx.json")]
    pub output: PathBuf,

    /// Output format. Only `cyclonedx-json` is implemented today.
    #[arg(long, default_value = "cyclonedx-json")]
    pub format: String,

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

pub async fn execute(
    args: ScanArgs,
    offline: bool,
    include_dev: bool,
    include_legacy_rpmdb: bool,
) -> anyhow::Result<()> {
    // Milestone 004 US4: the flag is threaded all the way to
    // `scan_path` so the (future) BDB rpmdb reader can consume it.
    // Until the BDB reader lands (T064), the parameter rides through
    // as a no-op; default behaviour is unchanged from milestone 003.
    let _ = include_legacy_rpmdb;
    if args.path.is_none() && args.image.is_none() {
        anyhow::bail!("one of --path or --image is required");
    }

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
    tracing::info!(root = %root_path.display(), "scan starting");
    let scan_fs::ScanResult {
        mut components,
        mut relationships,
        complete_ecosystems,
        os_release_missing_fields,
    } = scan_fs::scan_path(
        &root_path,
        effective_codename,
        args.max_file_size,
        !args.no_package_db,
        !args.no_deep_hash,
        include_dev,
        include_legacy_rpmdb,
        scan_mode,
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
        )
        .await;
    if !new_dep_graph_edges.is_empty() {
        tracing::info!(
            count = new_dep_graph_edges.len(),
            "deps.dev added transitive dep-graph edges",
        );
        relationships.extend(new_dep_graph_edges);
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

    let cdx_config = CycloneDxConfig {
        include_hashes: !args.no_hashes,
        include_source_files: true, // path-pattern evidence is the whole value prop here
        generation_context: generation_context.clone(),
        include_dev,
    };
    let builder = CycloneDxBuilder::new(cdx_config)
        .with_os_release_missing_fields(os_release_missing_fields);
    let bom = builder.build(
        &components,
        &relationships,
        &integrity,
        &target_name,
        &complete_ecosystems,
    )?;

    write_cyclonedx_json(&bom, &args.output)?;

    if args.json {
        let ctx_str = match generation_context {
            GenerationContext::FilesystemScan => "filesystem-scan",
            GenerationContext::ContainerImageScan => "container-image-scan",
            GenerationContext::BuildTimeTrace => "build-time-trace",
        };
        let summary = serde_json::json!({
            "output_file": args.output.to_string_lossy(),
            "format": args.format,
            "components": components.len(),
            "relationships": relationships.len(),
            "scanned_root": root_path.to_string_lossy(),
            "target_name": target_name,
            "generation_context": ctx_str,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    }

    tracing::info!(
        output = %args.output.display(),
        components = components.len(),
        relationships = relationships.len(),
        "SBOM written"
    );
    Ok(())
}
