use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, ValueEnum};

use waybill_common::attestation::integrity::TraceIntegrity;
use waybill_common::attestation::metadata::GenerationContext;

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

/// Enrichment source identifiers for `--enrich-sources`. Selected via
/// comma-separated list; when provided, only the listed sources run.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub enum EnrichSource {
    /// deps.dev license enrichment (declared + observed licenses).
    DepsDev,
    /// ClearlyDefined concluded-license enrichment.
    ClearlyDefined,
    /// deps.dev transitive dep-graph edge enrichment.
    DepsDevGraph,
}

/// Image source for `--image <ref>` resolution. Selected via
/// `--image-src` (comma-separated, in order of preference).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageSource {
    /// Local docker daemon: shell out to `docker image inspect` to
    /// probe, then `docker save` to materialize a tarball.
    Docker,
    /// Milestone 206 (#440) — local podman image cache. Filesystem-only
    /// (no daemon/REST API). Requires the target image be pre-pulled
    /// via `podman pull` or `podman build`. Rootless preferred;
    /// rootful supported when waybill has read access to
    /// `/var/lib/containers/storage/`. Linux-only per spec Assumption 1.
    Podman,
    /// OCI distribution-spec registry pull (the milestone-031+
    /// `oci_pull` path).
    Remote,
}

/// Milestone 186 (#442) — where waybill should get the SBOM: scan the image
/// bytes or fetch a pre-existing SBOM via the OCI Distribution Spec v1.1
/// Referrers API.
///
/// Applies only to registry-pull scans (`--image <oci-ref>`). Rejected
/// (non-zero exit) against `--image <local-path>` and `--path <dir>` inputs
/// per FR-011.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub enum SbomSourceMode {
    /// Default. Always scan the image bytes; never query the Referrers API.
    /// Preserves pre-m186 behavior byte-identically per FR-015 / SC-004.
    #[default]
    Scan,
    /// Query the Referrers API and REQUIRE that an SBOM referrer be found.
    /// Exit non-zero with an actionable error if absent per FR-009 / SC-003.
    /// Use for compliance workflows requiring upstream-published SBOMs only.
    Referrer,
    /// Query the Referrers API and prefer any matching SBOM referrer; fall
    /// through to scan silently if none available (or if any fetch step
    /// fails) per FR-008 / SC-002.
    Either,
}

/// Milestone 232 (#660) — `--tier=<mode>` output-filter flag. Filters
/// the emitted SBOM's component set by `sbom_tier` per operator
/// choice. See `specs/232-tier-filter-flag/spec.md` for the mode
/// inventory and downstream-consumer rationale.
///
/// Default is `All` (no-op filter). Per FR-002 / SC-003, pre-232
/// invocations that don't set the flag produce byte-identical output.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub enum TierMode {
    /// Default: emit all resolved components regardless of tier.
    /// Byte-identical to pre-232 emission for any given scan input.
    #[default]
    All,
    /// Emit only components tagged `sbom_tier: "source"`. Recommended
    /// for vulnerability-scanner pipelines that want resolved versions
    /// only.
    SourceOnly,
    /// Emit only components tagged `sbom_tier: "design"`. Recommended
    /// for compliance-attribution pipelines that want the developer-
    /// declared graph without resolver-tier probes.
    DesignOnly,
    /// Emit components tagged `sbom_tier: "source"` OR "binary".
    /// Recommended for container-artifact pipelines that want
    /// everything "actually shipped" but not "declared but not
    /// resolved".
    SourceAndBinary,
}

/// Milestone 665 — modes for the `--no-binary-scan=<MODE>` flag.
///
/// Names a subset of binary-content-scanning readers to skip at pilot
/// registration time. v1 recognizes `Go` only; the enum is designed
/// for extension without CLI-surface churn. See `specs/665-no-binary-
/// scan-flag/data-model.md` for the entity contract.
///
/// Future variants (reserved; NOT currently emitted):
/// - `Elf`  — skip m096 ELF `.dep-v0` section reader only.
/// - `Symbols` — skip m099 symbol fingerprinting only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum BinaryScanMode {
    /// **Deprecated as a perf lever** (#781). The go_binary reader
    /// now short-circuits on non-binary files via a magic-byte
    /// prefilter, so the default scan is already fast. `--no-binary-scan=go`
    /// still works as a component filter (suppresses `pkg:golang/*`
    /// components from BuildInfo probing) but emits a WARN log
    /// pointing at `--no-binary-scan=all` for operators who want to
    /// drop the entire binary tier. See specs/665 FR-002 for the
    /// original semantics.
    #[clap(name = "go")]
    Go,
    /// Skip the entire binary-scanning tier — no `go_binary` BuildInfo
    /// probing AND no m104 role classification (which today opens every
    /// file in the tree to check magic bytes even on non-Go projects).
    /// Trades ALL binary-derived provenance (`pkg:golang/*` from
    /// BuildInfo, ELF/Mach-O/PE role tagging, embedded linkage
    /// attribution) for scan speed on large trees. Components emitted
    /// from other tiers (dpkg/apk/rpm/pip/etc.) keep their tier data
    /// unchanged. See issue #775.
    #[clap(name = "all")]
    All,
}

impl BinaryScanMode {
    /// The canonical string used in `waybill:binary-scan-suppressed`
    /// annotation values AND in `--help` output AND in FR-009
    /// error messages. Kept in sync with the `#[clap(name = ...)]`
    /// attributes above — single source of truth per data-model.md V1.
    pub fn as_annotation_value(&self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::All => "all",
        }
    }
}

/// Milestone 188 (#455) — resolve `--helm-chart <path>` input.
///
/// When `<path>` ends in `.tgz`, extract to a tempdir + find the
/// top-level chart directory (contains `Chart.yaml`); return that
/// path. When `<path>` is a directory, return it verbatim.
///
/// Exits non-zero per FR-017 on: non-existent path, tarball extraction
/// failure, tarball with no `Chart.yaml` at extracted top-level. A
/// directory input WITHOUT `Chart.yaml` is NOT an error (matches
/// `--path` semantics — other package-DB readers still run).
fn resolve_helm_chart_input(
    helm_chart_path: &std::path::Path,
    tempdir_holder: &mut Option<tempfile::TempDir>,
) -> anyhow::Result<PathBuf> {
    if !helm_chart_path.exists() {
        anyhow::bail!(
            "--helm-chart path {} not found",
            helm_chart_path.display()
        );
    }
    // Directory input: pass through.
    if helm_chart_path.is_dir() {
        return Ok(helm_chart_path.to_path_buf());
    }
    // Tarball input: must end in `.tgz`.
    let is_tgz = helm_chart_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("tgz"))
        .unwrap_or(false);
    if !is_tgz {
        anyhow::bail!(
            "--helm-chart path {} is not a directory or a .tgz tarball",
            helm_chart_path.display()
        );
    }
    let tempdir = tempfile::Builder::new()
        .prefix("waybill-helm-chart-")
        .tempdir()
        .with_context(|| "creating tempdir for --helm-chart tarball extraction")?;
    let bytes = std::fs::read(helm_chart_path).with_context(|| {
        format!(
            "--helm-chart tarball {} could not be read",
            helm_chart_path.display()
        )
    })?;
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    archive.unpack(tempdir.path()).with_context(|| {
        format!(
            "--helm-chart tarball {} could not be extracted",
            helm_chart_path.display()
        )
    })?;
    // Find the top-level directory containing Chart.yaml. Helm's
    // `helm package` output wraps content in `<chart-name>/`.
    let chart_root = find_helm_chart_root(tempdir.path()).ok_or_else(|| {
        anyhow::anyhow!(
            "--helm-chart tarball {} extracted successfully but no Chart.yaml \
             found at top-level directory (expected <chart-name>/Chart.yaml)",
            helm_chart_path.display()
        )
    })?;
    *tempdir_holder = Some(tempdir);
    Ok(chart_root)
}

fn find_helm_chart_root(extracted: &std::path::Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(extracted).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join("Chart.yaml").is_file() {
            return Some(path);
        }
    }
    None
}

/// Milestone 186 — wire-format string for the `--sbom-source` value used in
/// FR-011 error messages. Matches the `#[clap(rename_all = "kebab-case")]`
/// convention on `SbomSourceMode`.
fn sbom_source_mode_wire_str(mode: SbomSourceMode) -> &'static str {
    match mode {
        SbomSourceMode::Scan => "scan",
        SbomSourceMode::Referrer => "referrer",
        SbomSourceMode::Either => "either",
    }
}

/// Milestone 186 — map a requested `--format` value to the referrer
/// descriptor media type waybill expects to see for byte-identical emission.
/// Returns `None` for `--format` values without a canonical referrer media
/// type mapping (SPDX 3 currently — the ecosystem hasn't converged on a
/// stable media type registration as of m186's landing). Used at emission
/// time to detect format-vs-media-type mismatch and emit the FR-004 WARN log.
///
/// This helper is a local mirror of
/// `scan_fs::oci_pull::referrers::media_type_for_mikebom_format` because that
/// function is `pub(super)`-scoped inside the oci_pull submodule and not
/// reachable from `cli`. Keeping the two in-sync is a static invariant —
/// any new mapping added in one must be added in the other (small enough
/// surface that duplication is cheaper than exposing an entire helper API).
fn referrer_media_type_for_format(fmt: &str) -> Option<&'static str> {
    match fmt {
        "cyclonedx-json" => Some("application/vnd.cyclonedx+json"),
        "spdx-2.3-json" => Some("application/spdx+json"),
        _ => None,
    }
}

/// Milestone 235 — Gradle transitive dependency resolution flags.
///
/// Flattened into `ScanArgs` via `#[command(flatten)]`. Spec:
/// `specs/235-gradle-transitive-ladder/spec.md` FR-001, FR-002, FR-003.
///
/// The 5 flags below all default to the safe/off state so waybill's
/// no-flag behavior is unchanged (`--gradle-resolve` is opt-in; the
/// other 4 have no effect without it).
///
/// Flag values are surfaced to the `gradle::read` reader via env vars
/// (`WAYBILL_GRADLE_*`) so we don't have to plumb through the
/// 75-callsite `scan_path` -> `read_all` signature chain (matches the
/// m102 `WAYBILL_INCLUDE_VENDORED` precedent at
/// `waybill-cli/src/scan_fs/package_db/mod.rs:1315`).
#[derive(Args, Debug, Default)]
pub struct GradleCliFlags {
    /// Opt-in: resolve Gradle transitive dependencies via `./gradlew
    /// :sub:dependencies` subprocess. Requires JDK on `$PATH`.
    /// Default: off (waybill falls back to m106 lockfile reading).
    #[arg(long)]
    pub gradle_resolve: bool,

    /// When `--gradle-resolve` is set, also resolve the buildscript
    /// classpath (Gradle plugins the build itself uses) via
    /// `./gradlew :sub:buildEnvironment`. Doubles subprocess call
    /// count. Default: off. Requires `--gradle-resolve`.
    #[arg(long, requires = "gradle_resolve")]
    pub gradle_resolve_buildscript: bool,

    /// When `--gradle-resolve` is set, use the Gradle daemon (faster
    /// on repeated invocations, but leaves a JVM in the operator's
    /// process list). Default: off (waybill passes `--no-daemon`).
    /// Requires `--gradle-resolve`.
    #[arg(long, requires = "gradle_resolve")]
    pub gradle_daemon: bool,

    /// Per-subprocess timeout in seconds. Applies to each
    /// `./gradlew :sub:dependencies` invocation individually.
    /// Default: 300 (5 minutes).
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    pub gradle_timeout_secs: u64,

    /// Additional Gradle configurations to resolve beyond the default
    /// `runtimeClasspath` + `testRuntimeClasspath` set. Repeatable
    /// (`--gradle-extra-configurations compileClasspath
    /// --gradle-extra-configurations testCompileClasspath`).
    /// Requires `--gradle-resolve`.
    #[arg(long, action = clap::ArgAction::Append)]
    pub gradle_extra_configurations: Vec<String>,
}

impl GradleCliFlags {
    /// Reject shell-metacharacter names to prevent injection via the
    /// `--configuration <name>` argument. Called by `SbomSubcommand::Scan`
    /// before waybill spawns any Gradle subprocess.
    pub fn validate_configuration_names(&self) -> Result<(), String> {
        for name in &self.gradle_extra_configurations {
            if name.chars().any(|c| {
                matches!(c, ' ' | ';' | '`' | '$' | '|' | '&' | '>' | '<' | '\n' | '\r')
            }) {
                return Err(format!(
                    "--gradle-extra-configurations value contains unsafe characters: {:?}",
                    name
                ));
            }
            if name.is_empty() {
                return Err("--gradle-extra-configurations values cannot be empty".to_string());
            }
        }
        Ok(())
    }

    /// Convert to the env vars the `gradle::read` reader consumes.
    /// Matches the m102 `WAYBILL_INCLUDE_VENDORED` env-bridge pattern
    /// (see `scan_cmd.rs:2562`).
    ///
    /// SAFETY: caller must ensure single-threaded execution at this
    /// point in the scan-cmd lifecycle (matches m102 precedent).
    pub fn export_env(&self) {
        // SAFETY: single-threaded at scan-cmd entry.
        unsafe {
            std::env::set_var(
                "WAYBILL_GRADLE_RESOLVE",
                if self.gradle_resolve { "1" } else { "0" },
            );
            std::env::set_var(
                "WAYBILL_GRADLE_RESOLVE_BUILDSCRIPT",
                if self.gradle_resolve_buildscript { "1" } else { "0" },
            );
            std::env::set_var(
                "WAYBILL_GRADLE_DAEMON",
                if self.gradle_daemon { "1" } else { "0" },
            );
            std::env::set_var(
                "WAYBILL_GRADLE_TIMEOUT_SECS",
                self.gradle_timeout_secs.to_string(),
            );
            // Configurations passed as comma-separated (the validator has
            // already rejected shell metacharacters, so comma is safe).
            std::env::set_var(
                "WAYBILL_GRADLE_EXTRA_CONFIGURATIONS",
                self.gradle_extra_configurations.join(","),
            );
        }
    }
}

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

    /// Image source-resolution order for `--image <ref>` (when the
    /// argument is an OCI reference, not a tarball path on disk).
    ///
    /// Comma-separated list; waybill tries each source in order and
    /// stops at the first one that has the image. Default
    /// `docker,remote` matches trivy's `--image-src` and syft's
    /// auto-detection: prefer the local docker daemon's cache, fall
    /// back to a registry pull. Pass `--image-src remote` to force
    /// a fresh registry fetch (skipping any locally-cached copy);
    /// pass `--image-src docker` to fail rather than touch the
    /// network.
    ///
    /// When `--image` resolves to an existing tarball file on disk,
    /// this flag is ignored — the file is loaded directly.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "docker,podman,remote",
        value_name = "SRC[,SRC...]",
    )]
    pub image_src: Vec<ImageSource>,

    /// Override the platform that's resolved from a multi-arch image
    /// index. Only meaningful when `--image` points at a registry
    /// reference (not a pre-extracted tarball) — for tarballs the
    /// platform is fixed by whatever `docker save` already wrote.
    ///
    /// Format: `<os>/<arch>` or `<os>/<arch>/<variant>`. Only `linux`
    /// is supported as the OS — waybill's package-database readers
    /// (dpkg / apk / rpm) are linux-rootfs-shaped, so non-Linux
    /// container images aren't a meaningful scan target.
    ///
    /// Common values: `linux/amd64`, `linux/arm64`, `linux/arm/v7`,
    /// `linux/arm/v6`, `linux/386`, `linux/ppc64le`, `linux/s390x`.
    /// When omitted (default), waybill auto-resolves to
    /// `linux/<host-arch>` matching the machine running the scan.
    ///
    /// Use case: a macOS arm64 dev machine scanning a `linux/amd64`
    /// container image deployed to AWS, or Linux x86_64 CI scanning
    /// an `arm64` image deployed to Graviton.
    #[arg(long, requires = "image", value_name = "linux/ARCH[/VARIANT]")]
    pub image_platform: Option<String>,

    /// Disable the OCI blob cache for registry pulls. Equivalent to
    /// `WAYBILL_OCI_CACHE=0`. When set, every blob (config + layer)
    /// is fetched from the registry on every scan, even if waybill
    /// has already cached the same digest from a previous pull.
    /// Cache files on disk are untouched.
    ///
    /// Use case: CI lanes that want pure one-shot semantics, or
    /// debugging a registry-side regression.
    #[arg(long)]
    pub no_oci_cache: bool,
    /// Cap (in bytes) for the on-disk OCI blob cache. When the cache
    /// exceeds this size, oldest-mtime entries are evicted until the
    /// total drops below the cap. Default: 10 GB. Equivalent env
    /// var: `WAYBILL_OCI_CACHE_SIZE=<bytes>`.
    ///
    /// Cache location is resolved from (in priority order):
    /// `$WAYBILL_OCI_CACHE_DIR`, `$XDG_CACHE_HOME/waybill/oci-layers`,
    /// `$HOME/Library/Caches/waybill/oci-layers` on macOS, otherwise
    /// `$HOME/.cache/waybill/oci-layers`.
    #[arg(long, value_name = "BYTES")]
    pub oci_cache_size: Option<u64>,

    /// Issue #235 — directory containing Docker-format registry
    /// credentials. waybill probes `<DIR>/config.json`,
    /// `<DIR>/.dockerconfigjson` (K8s `kubernetes.io/dockerconfigjson`
    /// secret type), and `<DIR>/.dockercfg` (legacy K8s
    /// `kubernetes.io/dockercfg` secret type) in that order; the
    /// first readable+parseable file wins. The file format is the
    /// standard Docker `config.json` shape (`auths`, `credsStore`,
    /// `credHelpers`), so the existing credential-resolution
    /// precedence applies inside the loaded config.
    ///
    /// Use this when running waybill in a container that mounts a
    /// K8s `imagePullSecrets`-derived volume (typically at
    /// `/var/run/secrets/registry/`). For local/CI use with the
    /// standard Docker keychain, leave this unset — waybill falls
    /// back to `$DOCKER_CONFIG/config.json` or
    /// `$HOME/.docker/config.json`.
    ///
    /// Composes with `WAYBILL_REGISTRY_<HOST>_USERNAME/_PASSWORD`
    /// env vars (per-registry, higher priority than the directory
    /// probe) and `WAYBILL_REGISTRY_USERNAME/_PASSWORD` (generic
    /// fallback, also higher priority than the directory probe).
    /// See `docs/reference/identifiers.md` for the full credential
    /// resolution priority chain.
    #[arg(long = "registry-credentials-dir", value_name = "PATH")]
    pub registry_credentials_dir: Option<std::path::PathBuf>,

    /// `--insecure-registry <HOST[:PORT]>` — repeatable. When set, waybill
    /// pulls from the named host over `http://` instead of `https://`.
    /// Host-only form matches any port; explicit `<host>:<port>` matches
    /// only that port. Match target is the user-facing registry name
    /// typed in `--image` — NOT any resolved endpoint (docker.io does
    /// not auto-expand to registry-1.docker.io).
    ///
    /// Milestone 182 / FR-001. Consumers: Harbor devenv
    /// (`--insecure-registry core:8080`), air-gapped mirrors, local dev
    /// registries.
    ///
    /// **Security**: only enable for registries you trust. Plain-HTTP
    /// exposes credentials + blobs to network observers.
    #[arg(
        long = "insecure-registry",
        value_name = "HOST[:PORT]",
        action = clap::ArgAction::Append
    )]
    pub insecure_registry: Vec<String>,

    /// `--registry-ca-cert <PATH>` — repeatable. Additional CA
    /// certificate(s) to trust for HTTPS registry pulls, on top of the
    /// webpki root set. Each file may be a PEM bundle (multiple
    /// concatenated `-----BEGIN CERTIFICATE-----` blocks); ALL
    /// certificates in each file are added.
    ///
    /// Milestone 182 / FR-002 / FR-006. Consumers: private-CA Harbor
    /// deployments, corporate Nexus / JFrog, self-hosted GHCR mirrors.
    ///
    /// **Failure modes** (fail-fast at scan startup, before any network
    /// call): file not found, empty file, non-PEM content, malformed
    /// PEM. All surface actionable errors naming the offending path.
    #[arg(
        long = "registry-ca-cert",
        value_name = "PATH",
        action = clap::ArgAction::Append
    )]
    pub registry_ca_cert: Vec<std::path::PathBuf>,

    /// `--insecure-tls-skip-verify` — disable TLS certificate chain /
    /// hostname / expiry verification for ALL HTTPS registry pulls in
    /// this scan. Emits a WARN-level structured log at scan start
    /// (Constitution Principle X + FR-007).
    ///
    /// Milestone 182 / FR-003. **Security**: extremely dangerous in
    /// production. Use ONLY for CI/dev against self-signed or
    /// hostname-mismatched certs where fetching the CA is impractical.
    /// For private-CA production registries, prefer
    /// `--registry-ca-cert <path>` instead.
    #[arg(long = "insecure-tls-skip-verify")]
    pub insecure_tls_skip_verify: bool,

    /// Milestone 186 (#442) — where waybill should get the SBOM: scan the
    /// image bytes, or fetch a pre-existing SBOM via the OCI Distribution
    /// Spec v1.1 Referrers API.
    ///
    /// - `scan` (default): Always scan the image bytes. Preserves pre-m186
    ///   behavior byte-identically. No network activity on the Referrers
    ///   endpoint.
    /// - `referrer`: REQUIRE a matching SBOM referrer. Exit non-zero if
    ///   absent. Use for compliance workflows requiring upstream-published
    ///   SBOMs only.
    /// - `either`: Prefer a referrer if available; fall through to scan
    ///   silently if none. Cost-effective for images that publish SBOMs.
    ///
    /// Applies only to registry-pull scans. Rejected when used against
    /// `--image <local-tarball-path>` or `--path` scans.
    #[arg(long = "sbom-source", value_enum, default_value_t = SbomSourceMode::Scan)]
    pub sbom_source: SbomSourceMode,

    /// Milestone 188 (#455) — Helm chart tarball or directory to scan.
    ///
    /// When `<path>` ends in `.tgz`, waybill extracts the tarball to a
    /// tempdir and runs the scan pipeline against the extracted
    /// contents. When it is a directory, behavior is identical to
    /// `--path <path>` — Chart.yaml is auto-detected regardless.
    ///
    /// The `.tgz` MUST contain a `Chart.yaml` at the top-level
    /// extracted directory; otherwise waybill exits non-zero.
    /// Directory inputs without Chart.yaml don't cause an error —
    /// other package-DB readers (npm / cargo / etc.) still run.
    ///
    /// Composes freely with all other package-DB readers per
    /// Clarifications Q1.
    #[arg(long = "helm-chart", value_name = "PATH_OR_TGZ", conflicts_with = "path")]
    pub helm_chart: Option<PathBuf>,

    /// Milestone 188 (#455) — Opt-in Helm template rendering.
    ///
    /// When set, waybill shells out to `helm template <chart-dir>`
    /// before extracting container image references, resolving every
    /// `{{ .Values.image.tag }}` placeholder to a concrete value.
    /// Requires the `helm` binary on `$PATH`.
    ///
    /// On failure (missing binary, non-zero exit, timeout), waybill
    /// emits a WARN log and falls back to the default unrendered
    /// extraction — the scan does NOT abort. The emitted SBOM's
    /// document-scope `waybill:image-extraction-completeness`
    /// annotation surfaces whether extraction was "partial" (fallback)
    /// or "full" (helm succeeded).
    ///
    /// Timeout: 60 seconds by default; override via
    /// `WAYBILL_HELM_RENDER_TIMEOUT_SECS=<n>` env var.
    ///
    /// Default (flag omitted): NO helm binary invocation. Zero
    /// external-tool calls per FR-013.
    #[arg(long = "helm-render", default_value_t = false)]
    pub helm_render: bool,

    /// Output path override. Two forms are accepted:
    ///
    /// * Bare `--output <path>` — applies to the single requested
    ///   format. Rejected when more than one format is requested.
    /// * Per-format `--output <fmt>=<path>` — repeatable; each entry
    ///   overrides the default filename for exactly one format id.
    ///
    /// Per-format form is required for multi-format emission. When
    /// omitted, each format writes to its own default filename
    /// (`waybill.cdx.json`, `waybill.spdx.json`, …).
    #[arg(long, action = clap::ArgAction::Append, value_name = "[FMT=]PATH")]
    pub output: Vec<String>,

    /// Milestone 221 (feature 221-cisa-2026-elements-audit / US2a) —
    /// static-key signing.
    ///
    /// Path to a PEM-encoded ECDSA-P256 (default), Ed25519, or RSA
    /// private key. When set, waybill signs each emitted SBOM with
    /// the referenced key: CDX outputs receive a JSF (JSON Signature
    /// Format) object populated at `metadata.signature`; SPDX 2.3 and
    /// SPDX 3 outputs get a companion DSSE envelope at
    /// `<output>.sig.json`.
    ///
    /// Cloud-KMS (`kms://<uri>`) and PKCS#11 (`pkcs11://<uri>`)
    /// references are out of scope for this feature and deferred to
    /// a follow-up milestone (plan.md §Follow-ups).
    ///
    /// Requires `--output <file>` for every emitted format; combining
    /// with `--output -` (stdout) is rejected at parse time per
    /// FR-008a (signing without a durable output path defeats the
    /// signature's purpose).
    ///
    /// When absent, all emitters produce byte-identical output to
    /// today's goldens per FR-009 (no regression).
    #[arg(long = "sign-key", value_name = "PATH")]
    pub sign_key: Option<PathBuf>,

    /// Milestone 221 US2a — environment variable holding the
    /// passphrase for an encrypted PEM key file. When `--sign-key`
    /// references an encrypted key, this env var MUST be set.
    /// Defaults to `WAYBILL_SIGN_KEY_PASSPHRASE` if omitted.
    /// Never accepts a passphrase directly on the command line
    /// (avoids `ps`-visible leak).
    #[arg(long = "sign-key-passphrase-env", value_name = "NAME")]
    pub sign_key_passphrase_env: Option<String>,

    /// Milestone 222 US2b — Sigstore keyless SBOM signing. When set,
    /// waybill fetches an OIDC token (ambient GitHub Actions or
    /// explicit `SIGSTORE_ID_TOKEN`), submits it to Fulcio for a
    /// short-lived signing cert, signs the emitted SBOM bytes,
    /// uploads the signature to Rekor for transparency-log inclusion,
    /// and embeds the resulting Sigstore Bundle in
    /// `metadata.signature` (CDX) or writes a
    /// `<output>.sig.bundle.json` sidecar (SPDX 2.3 + SPDX 3).
    ///
    /// Mutually exclusive with `--sign-key` (a signed SBOM has ONE
    /// signature envelope). Requires `--output <file>` — combining
    /// with stdout is rejected at parse time per FR-008a.
    ///
    /// Endpoints are overridable via `WAYBILL_FULCIO_URL` and
    /// `WAYBILL_REKOR_URL` env vars (defaults: production Sigstore).
    /// Rekor timeout via `WAYBILL_REKOR_TIMEOUT_SECS` (default 30).
    ///
    /// When absent, all emitters produce byte-identical output to
    /// today's goldens per FR-015 (no regression on the default path).
    #[arg(long = "sign", conflicts_with = "sign_key")]
    pub sign: bool,

    /// Milestone 222 US2b — Fulcio endpoint override for Sigstore
    /// keyless signing. Only relevant with `--sign`; otherwise ignored.
    /// Defaults to production Sigstore (`https://fulcio.sigstore.dev`).
    /// Set to `https://fulcio.sigstage.dev` for staging.
    #[arg(
        long = "fulcio-url",
        env = "WAYBILL_FULCIO_URL",
        default_value = "https://fulcio.sigstore.dev",
        value_name = "URL"
    )]
    pub fulcio_url: String,

    /// Milestone 222 US2b — Rekor transparency-log endpoint override
    /// for Sigstore keyless signing. Only relevant with `--sign`;
    /// otherwise ignored. Defaults to production Sigstore
    /// (`https://rekor.sigstore.dev`). Set to
    /// `https://rekor.sigstage.dev` for staging.
    #[arg(
        long = "rekor-url",
        env = "WAYBILL_REKOR_URL",
        default_value = "https://rekor.sigstore.dev",
        value_name = "URL"
    )]
    pub rekor_url: String,

    /// Milestone 222 US2b — Rekor inclusion-proof timeout in seconds.
    /// Only relevant with `--sign`; otherwise ignored. Default 30s
    /// per FR-007 (Rekor is mandatory + fail-close on timeout).
    /// Bump if Sigstore is under abnormal load; do NOT set to 0
    /// (interpreted as "no timeout" would defeat FR-007's fail-close
    /// requirement).
    #[arg(
        long = "rekor-timeout-secs",
        env = "WAYBILL_REKOR_TIMEOUT_SECS",
        default_value_t = 30,
        value_name = "SECS"
    )]
    pub rekor_timeout_secs: u64,

    /// Milestone 221 US4 (feature 221-cisa-2026-elements-audit /
    /// FR-013) — SBOM document version.
    ///
    /// Positive integer matching CDX 1.6's `metadata.version` schema
    /// (`{"type": "integer", "minimum": 1}`). Wires the value into
    /// all three emitters: CDX `metadata.version` as a native
    /// integer, SPDX 2.3 as a document-scope `Annotation` carrying
    /// `waybill:sbom-version=<N>`, SPDX 3 as the same annotation
    /// shape on the `SpdxDocument` root IRI.
    ///
    /// When unset, CDX emits `metadata.version: 1` (today's default,
    /// byte-identical per FR-009); SPDX outputs do not emit a
    /// `waybill:sbom-version` annotation at all.
    ///
    /// Rejects non-integer values (`2.0`, `v2`, `latest`, empty
    /// string, embedded whitespace) and values < 1 at parse time
    /// per FR-014. CISA 2026 § SBOM Version allows semver at the
    /// author's discretion, but CDX 1.6 schema forbids it in this
    /// slot; the integer-only constraint is the intersection.
    ///
    /// Note: waybill's existing UUID `serialNumber` (CDX) +
    /// content-addressed `documentNamespace` / `@id` (SPDX per
    /// milestone 010) already satisfy CISA's RFC 9562 alternative
    /// pathway for revision identity. `--sbom-version` covers the
    /// monotonic-counter pathway consumers who key on
    /// `metadata.version` expect.
    #[arg(long = "sbom-version", value_name = "N")]
    pub sbom_version: Option<waybill_common::types::SbomVersion>,

    /// Milestone 215/219 — split monorepo SBOM into per-workspace-
    /// member OR per-directory sub-SBOMs.
    ///
    /// Accepts an optional value:
    ///
    /// - `--split` (bare) OR `--split=workspace` → per-main-module
    ///   grouping (m215 default; byte-identity preserved with pre-m219
    ///   behavior).
    /// - `--split=directory` → group all main-modules whose
    ///   canonicalized source dirs match into ONE sub-SBOM per dir.
    ///   Useful for polyglot repos where Cargo + package.json coexist.
    ///
    /// Requires `--output-dir <dir>`; incompatible with `--output`
    /// (a single file cannot hold N sub-SBOMs). On single-package
    /// projects with no workspace boundaries, falls back to one SBOM
    /// with a WARN log (FR-009). See
    /// `docs/reference/split-modes.md` for the mode table + worked
    /// examples.
    #[arg(
        long,
        value_enum,
        num_args = 0..=1,
        default_missing_value = "workspace",
        require_equals = true,
        conflicts_with = "output",
    )]
    pub split: Option<crate::generate::split::SplitMode>,

    /// Milestone 215 — output directory for split-mode sub-SBOMs +
    /// `split-manifest.json`. Required when `--split` is set; ignored
    /// otherwise. Directory is created if missing.
    #[arg(long = "output-dir", value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Output format(s). Comma-separated list, and the flag itself
    /// is repeatable: `--format cyclonedx-json,spdx-2.3-json` is
    /// equivalent to `--format cyclonedx-json --format spdx-2.3-json`.
    /// Duplicates are ignored silently. Default: `cyclonedx-json`.
    ///
    /// Registered formats:
    /// - `cyclonedx-json` — CycloneDX 1.6 JSON (default filename
    ///   `waybill.cdx.json`).
    /// - `spdx-2.3-json` — SPDX 2.3 JSON (default filename
    ///   `waybill.spdx.json`).
    /// - `spdx-3-json` — SPDX 3.0.1 JSON-LD (default filename
    ///   `waybill.spdx3.json`). Full ecosystem coverage; production-
    ///   grade output with native-field + annotation parity vs.
    ///   CycloneDX and SPDX 2.3.
    /// - `spdx-3-json-experimental` [DEPRECATED] — deprecation alias
    ///   for `spdx-3-json`. Byte-identical output; prints a stderr
    ///   deprecation notice. Accepted through milestone 012;
    ///   removed in milestone 013. Set
    ///   `WAYBILL_NO_DEPRECATION_NOTICE=1` to suppress the warning
    ///   in CI logs during a controlled migration.
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

    /// Milestone 144 — per-file size cap for standalone `.rpm` files,
    /// in bytes. Files exceeding the cap are skipped with a structured
    /// WARN log (`reason="size-cap-exceeded"`). Useful for Yocto debug
    /// RPMs (kernel-dbg, gcc-dbg) which can exceed the 512 MiB default.
    /// Default: 536870912 (512 MiB).
    #[arg(long, value_name = "BYTES", value_parser = parse_nonzero_u64)]
    pub max_rpm_bytes: Option<u64>,

    /// Milestone 144 — override the distro identifier for RPM PURL
    /// namespaces. When set, overrides `/etc/os-release` `ID=` AND
    /// per-RPM RPMTAG_VENDOR/RPMTAG_PACKAGER metadata across the
    /// entire scan. Typical Yocto use: `--rpm-distro poky` to encode
    /// the build's DISTRO variable in emitted PURLs. Default:
    /// auto-detect (CLI override > /etc/os-release > per-RPM header
    /// > empty namespace).
    #[arg(long, value_name = "ID", value_parser = parse_non_empty_lowercase_distro_id)]
    pub rpm_distro: Option<String>,

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

    /// Issue #363 — operator assertion that declared licenses have been
    /// reviewed and may be promoted to `licenseConcluded`.
    ///
    /// **By passing this flag, YOU (the operator) ASSERT that you have
    /// reviewed and verified the declared license data for accuracy.**
    /// Per SPDX 2.3 § 7.13 / SPDX 3.0.1 `licenseConcluded` carries the
    /// analyst's reviewed conclusion; without this flag waybill leaves
    /// `licenseConcluded` as `NOASSERTION` (no human verified) even
    /// when `licenseDeclared` is populated — technically correct but
    /// invisible to consumers that key on `concluded` (sbomqs,
    /// Kusari Inspector, syft-comparators).
    ///
    /// When set, every component whose `concluded_licenses` is empty
    /// AND `licenses` is non-empty gets its declared licenses copied to
    /// concluded, plus a per-component
    /// `waybill:license-concluded-source = "operator-asserted"`
    /// annotation recording that the conclusion came from THIS FLAG (a
    /// formal operator assertion), not from external enrichment
    /// (ClearlyDefined / deps.dev). Components that already have a
    /// concluded license (e.g. from ClearlyDefined) are untouched.
    ///
    /// Default OFF — preserves pre-feature byte-identity. Don't pass
    /// this flag in unattended pipelines without an upstream review
    /// step; downstream consumers will treat your `licenseConcluded`
    /// as analyst-verified.
    #[arg(long)]
    pub conclude_licenses: bool,

    /// Skip per-file SHA-256 hashing of installed-package contents.
    /// Falls back to a fast SHA-256 over each package's dpkg `.md5sums`
    /// file (microseconds per package; component-level identity only,
    /// no per-file occurrences). Default-on hashing reads every file
    /// referenced by dpkg's `.list` manifest — proportional to
    /// installed size (~3-5 s on debian:bookworm-slim, ~30 s on full
    /// debian).
    #[arg(long)]
    pub no_deep_hash: bool,

    /// Container-scan perf optimization for `--image` mode. When set,
    /// waybill's docker-image extractor skips writing file contents for
    /// everything OUTSIDE the OS-package metadata allow-list
    /// (`/var/lib/{dpkg,apk,rpm}/`, `/usr/share/doc/*/copyright`,
    /// `/etc/os-release`, `/usr/lib/os-release`). Symlinks and
    /// directories are still preserved for correct path resolution.
    ///
    /// Requires `--no-deep-hash` (deep-hash reads the skipped file
    /// contents, so this flag would corrupt its output). Cuts the
    /// `docker_image::extract` step by ~90% on typical OS-only images
    /// (measured 690ms → ~50ms on debian:12-slim).
    ///
    /// NOT recommended when scanning application containers that ship
    /// source-tier content (Python venvs, node_modules, cargo vendor
    /// trees) inside the image — those readers will miss the component
    /// files when they're not extracted. For OS-image scans only.
    #[arg(long, requires = "no_deep_hash")]
    pub fast_container_extract: bool,

    /// Milestone 133 US1 — emit file-tier components for unattributed
    /// content (custom binaries, vendored libraries with no manifest,
    /// embedded archives) surviving the FR-005 content-shape allowlist.
    ///
    /// Modes:
    /// - `off` (US1.B default — preserves pre-milestone-133 byte-
    ///   identity): no file-tier emission.
    /// - `orphan` (US1.C default — planned flip): emit components only
    ///   for content NOT covered by any package-tier or binary-tier
    ///   component's `evidence.occurrences[]` paths or `hashes[]`
    ///   SHA-256 set (FR-011 hybrid dedupe).
    /// - `full`: emit a component for every regular file surviving the
    ///   FR-005 allowlist, regardless of dedupe coverage. Useful for
    ///   forensic / compliance use cases cataloguing every hash on
    ///   disk.
    /// - `source-tree` (m671): opt-in mode that surfaces source-code
    ///   file extensions (`.py`, `.c`, `.h`, etc. per the FR-002
    ///   21-extension allowlist) as file-tier components. Optional
    ///   restriction subset via `--file-inventory-source-shapes`.
    ///   Docs / configs / build-glue stay hard-excluded. See
    ///   `docs/reference/component-tiers.md` for the full flow.
    ///
    /// Emitted file-tier components carry a `waybill:component-tier =
    /// "file"` annotation and a `waybill:file-paths` JSON-encoded
    /// array of every observed path for the unique content.
    ///
    /// **Default flipped to `orphan` in milestone 133 US1.C per FR-015**
    /// — operators wanting pre-milestone-133 byte-identity on SBOMs
    /// opt out via `--file-inventory=off`. Image-scan SBOMs grow by
    /// roughly 180-440 file-tier components on a typical container
    /// image (the SC-001 acceptable range from the FR-022
    /// projection); orphan-mode scan time grows by ~5-15 seconds on
    /// a debian:bookworm-slim-sized rootfs.
    #[arg(long, value_name = "MODE", default_value = "orphan")]
    pub file_inventory: String,

    /// Maximum file size (bytes) considered for file-tier emission.
    /// Files larger than this are skipped; the document-level
    /// `waybill:file-inventory-skipped-oversize` annotation reports
    /// the skip count. Default 100 MB per FR-010.
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    pub file_inventory_size_limit: u64,

    /// Milestone 671 — comma-separated subset of the FR-002 source-
    /// shape allowlist that gets surfaced under
    /// `--file-inventory=source-tree`. Accepted extensions
    /// (case-insensitive, leading dot optional):
    /// `py, pyi, c, cc, cpp, cxx, h, hh, hpp, rs, go, java, kt, js, ts,
    /// rb, php, cs, swift, m, mm`.
    ///
    /// Unknown extensions fail loudly at CLI-parse time per FR-009
    /// (`SourceShapeParseError::UnknownExtension`); adding new
    /// extensions requires a follow-up milestone (curation review,
    /// not operator-time override).
    ///
    /// **Cross-arg constraint**: this flag is only meaningful under
    /// `--file-inventory=source-tree`. Combining it with any other
    /// mode value fails at parse time with a clear diagnostic (see
    /// `specs/671-file-tier-cpython/contracts/source_shape_restriction.md`).
    #[arg(long, value_name = "SHAPES", value_parser = parse_source_shape_restriction_arg)]
    pub file_inventory_source_shapes: Option<scan_fs::file_tier::source_shape::SourceShapeSet>,

    /// Print a JSON summary to stdout after writing the SBOM.
    #[arg(long)]
    pub json: bool,

    /// Skip ClearlyDefined enrichment (concluded licenses). Keeps
    /// deps.dev license + dep-graph enrichment active. Use this when
    /// ClearlyDefined is slow or unreachable but you still want
    /// deps.dev data. Has no effect when `--offline` is set (all
    /// enrichment is already disabled).
    #[arg(long)]
    pub no_clearly_defined: bool,

    /// Milestone 207 (#596): AGGREGATE disable — skip BOTH the
    /// deps.dev license enrichment AND the deps.dev transitive
    /// dep-graph enrichment. Combines `--no-deps-dev-license` and
    /// `--no-deps-dev-graph` semantics per operator expectation.
    ///
    /// Pre-m207 this flag disabled only the license path (keeping
    /// the dep-graph active). Scripts that relied on that behavior
    /// can migrate by renaming to `--no-deps-dev-license`.
    ///
    /// Composition: `--no-deps-dev` (aggregate) OR
    /// `--no-deps-dev-license` (license only) OR
    /// `--no-deps-dev-graph` (graph only). Fine-grained flags allow
    /// surgical control. `--enrich-sources <list>` (allowlist mode)
    /// overrides all `--no-*` flags. `--offline` suppresses all
    /// enrichment paths regardless of `--no-*` flags.
    #[arg(long)]
    pub no_deps_dev: bool,

    /// Milestone 207 (#596) — skip deps.dev LICENSE enrichment
    /// only. Keeps the deps.dev transitive dep-graph enrichment
    /// active. This is the pre-m207 semantic of `--no-deps-dev`;
    /// scripts that relied on that behavior can migrate by
    /// renaming `--no-deps-dev` → `--no-deps-dev-license`.
    ///
    /// Has no effect when `--offline` is set (offline suppresses
    /// all enrichment paths). Overridden by `--enrich-sources`
    /// allowlist mode when the operator supplies that flag.
    #[arg(long)]
    pub no_deps_dev_license: bool,

    /// Milestone 102 (FR-016/FR-017): include vendored C/C++
    /// dependencies declared via CMake `add_subdirectory(third_party/...)`
    /// or `add_subdirectory(vendor/...)`. Default OFF — these are
    /// frequently false positives (CMake's `add_subdirectory` is also
    /// used for first-party `src/` and `tests/` sub-modules) so we
    /// require explicit opt-in. When enabled, version is backfilled
    /// from a co-located `version.txt` or `.version` file when present;
    /// otherwise the PURL has no version segment. Also accepts
    /// `WAYBILL_INCLUDE_VENDORED=1` env var which is read directly by
    /// the milestone-102 C/C++ readers in `read_all` (no clap-level
    /// env binding here, so the env var accepts "1"/"true"/etc. without
    /// clap's bool-env strictness).
    #[arg(long)]
    pub include_vendored: bool,

    /// Extend the CMake reader's recursive descent to `third_party/`.
    /// By default (unset) `third_party/` is walked at depth-1 only
    /// (matching milestone-102 behavior); recursive descent applies
    /// only to `cmake/` and `Modules/`. Setting this flag treats
    /// `third_party/` the same way. Useful when the parent project
    /// has vendored a large dep tree (LLVM, Chromium, WebRTC, etc.)
    /// whose transitive `find_package` declarations should surface
    /// in the SBOM.
    ///
    /// Also accepts `WAYBILL_CMAKE_THIRD_PARTY_RECURSIVE=1` env var,
    /// read directly by the milestone-156 cmake reader (mirrors the
    /// `WAYBILL_INCLUDE_VENDORED` env-var propagation pattern).
    #[arg(long)]
    pub cmake_third_party_recursive: bool,

    /// Milestone 235 — Gradle transitive dependency resolution flags.
    /// See `GradleCliFlags` docstring for individual flag semantics.
    #[command(flatten)]
    pub gradle: GradleCliFlags,

    /// Skip the deps.dev transitive dep-graph enrichment step ONLY.
    /// Keeps deps.dev license enrichment and ClearlyDefined active.
    ///
    /// Companion to `--no-deps-dev-license` (m207 #596) which does
    /// the reverse (skip license, keep graph). Use `--no-deps-dev`
    /// for the aggregate "skip both" semantic.
    ///
    /// Has no effect when `--offline` is set.
    #[arg(long)]
    pub no_deps_dev_graph: bool,

    /// Comma-separated list of enrichment sources to enable. When
    /// provided, ONLY the listed sources run (overrides all
    /// `--no-clearly-defined` / `--no-deps-dev` / `--no-deps-dev-graph`
    /// flags). Has no effect when `--offline` is set — offline
    /// disables all network calls.
    ///
    /// Example: `--enrich-sources deps-dev,clearly-defined` enables
    /// license enrichment from both sources but skips dep-graph edges.
    #[arg(long, value_delimiter = ',', value_name = "SOURCE[,SOURCE...]")]
    pub enrich_sources: Vec<EnrichSource>,

    /// Path to a source-tier SBOM document (CDX 1.6 / SPDX 2.3 / SPDX 3
    /// JSON) that emitted components will be bound to per milestone 072
    /// (FR-011). When set, waybill emits a `waybill:source-document-binding`
    /// annotation on each first-party component whose PURL appears in
    /// the source SBOM, plus a document-level cross-document reference
    /// (CDX `externalReferences[type:bom]`, SPDX `externalDocumentRefs` +
    /// `BUILT_FROM` relationship).
    ///
    /// FR-011 transparency: when the file cannot be loaded or parsed,
    /// the scan exits non-zero rather than silently emitting components
    /// without binding. Components whose PURL has no source-tier
    /// counterpart get an explicit
    /// `binding: unknown { reason: "source-not-found-in-bind-target" }`
    /// marker per FR-003.
    ///
    /// Use `waybill sbom verify-binding --image-sbom <out> --source-sbom <path>`
    /// to verify the binding after emission.
    #[arg(long, value_name = "PATH")]
    pub bind_to_source: Option<PathBuf>,

    /// Milestone 111 (issue #225 Option A) — declare that the binary-
    /// tier PURL on the left should be treated as the source-tier PURL
    /// on the right when computing milestone-072 cross-tier binding.
    /// Format: `LHS_PURL=RHS_PURL`. Repeatable. Both PURLs are
    /// canonicalized; match against scan-output components is strict
    /// canonical-equality on the LHS side.
    ///
    /// Use when an operator's flagship binary inside an image lands as
    /// `pkg:generic/<name>` (no version) but the corresponding source-
    /// tier component carries the ecosystem-specific PURL like
    /// `pkg:cargo/<name>@<ver>` — without an alias, binding strength
    /// stays `unknown { reason: "source-not-found-in-bind-target" }`.
    ///
    /// Requires `--bind-to-source` to have effect. Supplied otherwise,
    /// waybill emits a warning and the alias is discarded (the scan
    /// proceeds; no alias is recorded in the emitted SBOM).
    ///
    /// Also settable via `WAYBILL_PKG_ALIAS` (comma-separated entries
    /// matching the per-flag syntax) for CI ergonomics.
    #[arg(
        long = "pkg-alias",
        value_name = "LHS=RHS",
        value_parser = waybill::binding::alias::parse_pkg_alias,
        action = clap::ArgAction::Append,
    )]
    pub pkg_alias: Vec<waybill::binding::alias::PurlAlias>,

    /// Attach a `repo:` identifier — source repository identity
    /// (URL or git-style ssh URL). Manual override; if both this
    /// flag and the auto-detected `repo:` identifier (from `.git/`
    /// origin remote) produce a value, manual wins per FR-006.
    /// On the same scan, pass `--git-ref <revision>` to upgrade
    /// to a `git:<repo-url>#<revision>` identifier (the `git:`
    /// identifier supersedes — no separate `repo:` is also emitted).
    #[arg(long = "repo", value_name = "URL")]
    pub repo: Option<String>,

    /// Pair with `--repo <url>` to emit a `git:<repo>#<revision>`
    /// identifier (commit/branch/tag-anchored). Cannot be supplied
    /// without `--repo`. When set, supersedes the bare `repo:`
    /// identifier — only the `git:` identifier is emitted.
    #[arg(long = "git-ref", value_name = "REVISION", requires = "repo")]
    pub git_ref: Option<String>,

    /// Attach an `image:` identifier — image identity in the form
    /// `[registry/]name[:tag][@sha256:digest]`. Manual override:
    /// if `--image <PATH>` (the scan input) is also set and
    /// auto-detection produced an `image:` identifier, the manual
    /// value wins per FR-006. Named `--image-id` to avoid colliding
    /// with the `--image <PATH>` scan-input flag.
    #[arg(long = "image-id", value_name = "REF")]
    pub image_id: Option<String>,

    /// Attach an `attestation:` identifier — in-toto attestation
    /// IRI. Manual only; no auto-detection equivalent.
    #[arg(long = "attestation", value_name = "IRI")]
    pub attestation: Option<String>,

    /// Attach a user-defined identifier in `<scheme>=<value>` form.
    /// Repeatable. The `<scheme>` MUST match regex
    /// `^[a-z][a-z0-9_-]*$` (FR-004) and MUST NOT collide with a
    /// built-in scheme (`repo`, `git`, `image`, `attestation`) —
    /// use the dedicated `--repo` / `--git-ref` / `--image-id` /
    /// `--attestation` flags for those. The `<value>` is the
    /// remainder after the first `=`; values may contain `=`
    /// characters.
    ///
    /// User-defined identifiers ride the `waybill:identifiers`
    /// document-level annotation per Constitution Principle V's
    /// documented-exception path; SPDX 3 carries them natively in
    /// `Element.externalIdentifier[]`.
    ///
    /// Worked example: `--id acme_corp_id=svc-alpha-123 --id
    /// internal_ticket=PROJ-456`.
    ///
    /// See `docs/reference/identifiers.md` for the full per-format
    /// carrier table and decode recipes.
    #[arg(
        long = "id",
        action = clap::ArgAction::Append,
        value_name = "SCHEME=VALUE",
        value_parser = parse_user_defined_id_flag,
    )]
    pub id: Vec<waybill::binding::identifiers::Identifier>,

    /// Preserve userinfo (e.g., `USER:TOKEN@host`) in auto-detected git
    /// remote URLs when constructing `repo:` and `git:` identifiers.
    /// By default, waybill strips userinfo to prevent accidental
    /// credential disclosure in published SBOMs. Use this flag only
    /// when the credentials are deliberately non-sensitive (e.g., a
    /// public read-only deploy token, internal-network-only
    /// credentials). Manual `--repo` / `--git-ref` / `--id` flag
    /// values are emitted verbatim regardless of this flag.
    #[arg(long)]
    pub keep_credentials_in_identifiers: bool,

    /// Attach a `subject:` identifier declaring "this SBOM describes
    /// the artifact with the given content hash." Format:
    /// `sha256:<64-lowercase-hex>` or `sha512:<128-lowercase-hex>`.
    /// Repeatable for multi-subject SBOMs. On build-tier scans
    /// (`waybill trace run`), subject identifiers are auto-detected
    /// from the in-toto attestation envelope's subject set; manual
    /// flags augment auto-detected entries (deduplicated by exact
    /// match per milestone 073). On source-tier and image-tier
    /// scans, no auto-detect runs; manual flags are the only source
    /// of `subject:` identifiers.
    #[arg(
        long = "subject-hash",
        action = clap::ArgAction::Append,
        value_name = "ALGO:HEX",
    )]
    pub subject_hash: Vec<String>,

    /// Attach a user-defined identifier to a specific component in the
    /// emitted SBOM. The PURL must byte-equal a component's `purl`
    /// field in the emitted output; the SCHEME must be a non-built-in
    /// scheme name (built-in schemes `repo`, `git`, `image`,
    /// `attestation`, `subject` are reserved for document-level use).
    /// Examples:
    ///
    /// `--component-id "pkg:cargo/serde@1.0.0=kusari-id:asset-shared-lib-v2"`
    ///
    /// `--component-id "pkg:cargo/myapp@0.5.1=acme-asset:myapp-prod-001"`
    ///
    /// Repeatable. If a selector PURL matches multiple components
    /// (same PURL across different bom-ref values), the identifier is
    /// attached to ALL matching components. If a selector matches
    /// zero components, the scan logs a warning and continues.
    #[arg(
        long = "component-id",
        action = clap::ArgAction::Append,
        value_name = "PURL=SCHEME:VALUE",
        value_parser = waybill::binding::identifiers::component_id::parse_component_id_flag,
    )]
    pub component_id:
        Vec<waybill::binding::identifiers::component_id::ComponentIdentifierFlag>,

    /// Override the auto-derived `metadata.component.name` of the
    /// emitted SBOM. Useful when scanning an arbitrary directory whose
    /// basename doesn't reflect the operator-meaningful project
    /// identity. Accepts any non-empty UTF-8 except whitespace, control
    /// characters, `?`, and `#`. URL-encoded automatically when emitted
    /// into the PURL `name` segment.
    ///
    /// When this flag is set on a manifest-driven scan (Cargo, npm,
    /// pip, gem, Maven, Go), the manifest-derived main-module
    /// component is dropped entirely from the emitted SBOM (clean
    /// replacement). To preserve the manifest-derived identity as a
    /// regular library entry alongside the override, track GitHub
    /// issue #151.
    #[arg(
        long = "root-name",
        value_name = "NAME",
        value_parser = validate_root_name,
    )]
    pub root_name: Option<String>,

    /// Override the auto-derived `metadata.component.version`. Same
    /// validation rules as `--root-name`. Independent — can be set
    /// without `--root-name` and vice versa. When unset, falls through
    /// to the auto-derived version (typically `0.0.0` for arbitrary
    /// directories or the manifest-derived version for project scans).
    #[arg(
        long = "root-version",
        value_name = "VERSION",
        value_parser = validate_root_version,
    )]
    pub root_version: Option<String>,

    /// Override the type segment of the root component's PURL.
    /// Defaults to `generic` when `--root-name` is set; this flag
    /// replaces that default so the BOM subject's PURL carries an
    /// operator-supplied ecosystem type. Example: `--root-purl-type
    /// golang --root-name github.com/example/svc` produces
    /// `pkg:golang/github.com/example/svc@<version>`.
    ///
    /// Validated at parse time against the purl-spec type charset
    /// (`^[a-z][a-z0-9.+-]*$`). REQUIRES `--root-name`. Mutually
    /// exclusive with `--no-root-purl`.
    ///
    /// Applied identically across all three output formats: CDX
    /// `metadata.component.purl`, SPDX 2.3 root Package
    /// `externalRefs[purl]`, SPDX 3 root `software_packageUrl` +
    /// `externalIdentifier[packageUrl]`.
    #[arg(
        long = "root-purl-type",
        value_name = "TYPE",
        value_parser = validate_root_purl_type,
        requires = "root_name",
        conflicts_with = "no_root_purl",
    )]
    pub root_purl_type: Option<String>,

    /// Omit the root component's PURL entirely from the emitted SBOM.
    /// CDX: `metadata.component.purl` field absent. SPDX 2.3: no
    /// `purl` entry in the root Package's `externalRefs[]`. SPDX 3:
    /// no `software_packageUrl` AND no `externalIdentifier[]` entry
    /// with `externalIdentifierType: "packageUrl"`.
    ///
    /// Useful when downstream consumers key software identity on
    /// `(type, name)` and a target record was originally produced by
    /// a tool that emitted no root PURL — reproducing that empty-type
    /// identity requires omitting the PURL here.
    ///
    /// REQUIRES `--root-name` (an explicit name is the only identity
    /// signal once the PURL is dropped). Mutually exclusive with
    /// `--root-purl-type`.
    #[arg(
        long = "no-root-purl",
        requires = "root_name",
        conflicts_with = "root_purl_type",
        conflicts_with = "root_purl",
    )]
    pub no_root_purl: bool,

    /// Issue #359 — operator-supplied full PURL string for the root
    /// component. When set, waybill emits this PURL verbatim in every
    /// format (CDX `metadata.component.purl`, SPDX 2.3 root Package
    /// `externalRefs[purl]`, SPDX 3 root `software_packageUrl` +
    /// `externalIdentifier[packageUrl]`). The BOM-subject `name` +
    /// `version` are derived from the PURL itself (`packageurl`-crate
    /// parser).
    ///
    /// Useful when downstream consumers expect a specific
    /// canonical PURL and the operator wants to express it directly
    /// — including PURL features the discrete flags don't reach
    /// (qualifiers like `?arch=amd64`, subpaths like `#cmd/worker`,
    /// custom namespace splits like `pkg:golang/github.com/example/svc`).
    ///
    /// Validated at parse time via `Purl::new`; non-spec input fails
    /// fast with a clap-style error. Mutually exclusive with every
    /// other `--root-*` flag (use one or the other, not both).
    ///
    /// Example: `--root-purl pkg:golang/github.com/example/svc@v1.2.3?arch=amd64`
    /// → `metadata.component.purl = "pkg:golang/github.com/example/svc@v1.2.3?arch=amd64"`,
    ///   name=`github.com/example/svc`, version=`v1.2.3`.
    #[arg(
        long = "root-purl",
        value_name = "PURL",
        value_parser = validate_root_purl,
        conflicts_with = "root_name",
        conflicts_with = "root_version",
        conflicts_with = "root_purl_type",
        conflicts_with = "no_root_purl",
    )]
    pub root_purl: Option<String>,

    /// Milestone 149 (issue #151): when set together with `--root-name`
    /// / `--root-version` / `--root-purl`, preserve the manifest-derived
    /// main-module identity as a `library`-typed entry in
    /// `components[]` rather than dropping it per the milestone-077
    /// clean-replacement default. The demoted entry carries a
    /// `waybill:demoted-from-main-module = "true"` annotation per
    /// Constitution Principle V parity-bridging (none of CDX 1.6
    /// `component.type`, SPDX 2.3 `primaryPackagePurpose`, or SPDX 3
    /// `software_softwarePurpose` expresses demote-provenance). No-op
    /// without an active root-override flag (silent + INFO log per
    /// spec FR-006 / Edge Case 1) and no-op on multi-main-module scans
    /// (silent + INFO log per FR-013 / Edge Case 4).
    #[arg(long, default_value = "false")]
    pub preserve_manifest_main_module: bool,

    // ────────────────────────────────────────────────────────────
    // Milestone 080 — user-provided SBOM metadata. See
    // `specs/080-user-sbom-metadata/` for the full design.
    // ────────────────────────────────────────────────────────────

    /// Attach a creator entry to the emitted SBOM. Repeatable. Form:
    /// `<Type>: <Name>` where `<Type>` is one of `Tool`, `Organization`,
    /// `Person` (case-sensitive). Each entry lands at the standards-
    /// native creator/tools field of every emitted format: CDX 1.6
    /// `metadata.tools.components[]` / `metadata.manufacturer` /
    /// `metadata.authors[]` (per Type), SPDX 2.3
    /// `creationInfo.creators[]` (verbatim), SPDX 3 new `Tool` /
    /// `Organization` / `Person` element in `@graph`. waybill's own
    /// auto-populated tool/organization entries are preserved alongside.
    #[arg(
        long = "creator",
        action = clap::ArgAction::Append,
        value_name = "TYPE: NAME",
    )]
    pub creator: Vec<String>,

    /// Attach a document-level annotator. Repeatable. MUST be paired
    /// 1:1 with `--annotation-comment` — each `--annotator` MUST be
    /// immediately followed by exactly one `--annotation-comment` per
    /// the milestone-080 Q1 clarification. Form: same `<Type>: <Name>`
    /// shape as `--creator`.
    #[arg(
        long = "annotator",
        action = clap::ArgAction::Append,
        value_name = "TYPE: NAME",
    )]
    pub annotator: Vec<String>,

    /// Free-text comment that pairs positionally with the preceding
    /// `--annotator` flag. Repeatable. Counts MUST match `--annotator`
    /// exactly.
    #[arg(
        long = "annotation-comment",
        action = clap::ArgAction::Append,
        value_name = "TEXT",
    )]
    pub annotation_comment: Vec<String>,

    /// Free-text comment about the SBOM document as a whole. Single-
    /// valued. Lands at SPDX 2.3 `creationInfo.comment`, SPDX 3
    /// `Annotation` element of type `OTHER`, CDX 1.6 `bom.annotations[]`
    /// (per the milestone-080 native-fields audit; no `waybill:`
    /// parity bridge introduced).
    #[arg(long = "metadata-comment", value_name = "TEXT")]
    pub metadata_comment: Option<String>,

    /// Operator-supplied override for the document/Sbom-level name
    /// field. SPDX 2.3 document `name`, SPDX 3 `software_Sbom.name`,
    /// CDX 1.6 `metadata.component.name`. **Note**: when both
    /// `--scan-target-name` and milestone-077's `--root-name` are set
    /// on a CDX emission, `--root-name` takes precedence on
    /// `metadata.component.name` (a stderr warning is emitted). On
    /// SPDX 2.3 / SPDX 3 the two flags target different fields and
    /// both are honored independently.
    #[arg(long = "scan-target-name", value_name = "NAME")]
    pub scan_target_name: Option<String>,

    /// Path to a JSON sidecar file containing user-supplied metadata.
    /// Schema: `{creators?: [string], annotators?: [{type_name, comment}],
    /// metadata_comment?: string, scan_target_name?: string}` with
    /// `deny_unknown_fields`. Array fields merge additively with their
    /// flag counterparts (file values come first); single-valued
    /// fields fail with a conflict error if specified in both.
    #[arg(long = "metadata-file", value_name = "PATH")]
    pub metadata_file: Option<PathBuf>,

    // ────────────────────────────────────────────────────────────
    // Milestone 081 — operator-asserted CISA SBOM Type override.
    // See `specs/081-sbom-type-clarity/` for the full design.
    // ────────────────────────────────────────────────────────────

    /// Override the auto-detected SBOM type with an operator-asserted
    /// CISA SBOM Type. Valid values: design, source, build, analyzed,
    /// deployed, runtime. Document-level only — per-component
    /// `waybill:sbom-tier` annotations preserve auto-detected values.
    /// When set, CDX `metadata.lifecycles[]`, SPDX 2.3
    /// `creationInfo.comment` "Observed lifecycle phases", and SPDX 3
    /// `software_Sbom.software_sbomType[]` all collapse to a single-
    /// element output reflecting the asserted type via the
    /// equivalence table in `docs/reference/sbom-types.md`.
    #[arg(
        long = "sbom-type",
        value_name = "TYPE",
        value_parser = parse_sbom_type_flag,
    )]
    pub sbom_type:
        Option<crate::generate::lifecycle_phases::SbomType>,

    // ────────────────────────────────────────────────────────────
    // Issue #228 — SPDX 2.3 relationship-vocabulary compatibility.
    // ────────────────────────────────────────────────────────────

    /// Selects the SPDX 2.3 relationship-type vocabulary the emitter
    /// uses for scoped dependency edges (dev / build / test). Both
    /// modes are spec-conformant, but they are NOT equivalent: the
    /// SPDX 2.3 spec defines the typed scoped variants for exactly
    /// the purpose of expressing dev/build/test scope on a
    /// dependency edge, and Constitution Principle X (Transparency)
    /// requires waybill to default to the spec-native mechanism that
    /// carries the most consumer-actionable signal. Operators who
    /// pick `basic` accept information loss in exchange for
    /// compatibility — choose deliberately.
    ///
    /// Default `full` emits the spec-native typed reversed-direction
    /// variants (`DEV_DEPENDENCY_OF` / `BUILD_DEPENDENCY_OF` /
    /// `TEST_DEPENDENCY_OF`) — the SPDX 2.3 spec's purpose-built
    /// field for the dev/build/test distinction. `basic` emits every
    /// dep as natural-direction `DEPENDS_ON` regardless of scope,
    /// for downstream consumers that don't implement the typed
    /// variants (Trivy, Syft, and tooling built on top of them).
    ///
    /// In BOTH modes the `waybill:lifecycle-scope` annotation is set
    /// on the target Package for non-runtime deps, so the scope
    /// distinction is recoverable from the document regardless of
    /// which mode is in effect. Only affects the `spdx-2.3-json`
    /// format; CDX and SPDX 3 emission are unaffected. See
    /// `docs/reference/sbom-format-mapping.md` C42 for the
    /// cross-format mapping.
    #[arg(
        long = "spdx2-relationship-compat",
        value_name = "PROFILE",
        value_parser = parse_spdx2_relationship_compat_flag,
        default_value = "full",
    )]
    pub spdx2_relationship_compat: crate::generate::Spdx2RelationshipCompat,

    /// Milestone 108 — opt into the external symbol-fingerprint
    /// corpus. Defaults to false: waybill uses the in-source bundled
    /// 7-library corpus exactly as it did pre-108 (SC-003 byte-identity
    /// guarantee). When set, waybill loads fingerprint records from
    /// the operator's per-host cache at the build-time-pinned SHA;
    /// cache-miss triggers a one-shot fetch from
    /// `kusari-sandbox/waybill-fingerprints` (skipped under `--offline`,
    /// falls back to bundled defaults on failure). Components
    /// identified via the symbol-fingerprint path then carry a
    /// `waybill:fingerprint-corpus-sha` annotation (12-hex SHA or
    /// the `bundled` sentinel) per FR-005.
    ///
    /// Also enabled via `WAYBILL_FINGERPRINTS_CORPUS=1`.
    #[arg(long, env = "WAYBILL_FINGERPRINTS_CORPUS")]
    pub fingerprints_corpus: bool,

    /// Milestone 110 Phase 5-Slim (FR-006) — declare additional
    /// fingerprint-corpus sources. Repeatable. Each value is a URL
    /// pointing to a corpus tarball; the optional `=ENV_VAR` suffix
    /// for per-source bearer-token auth is parsed but currently
    /// warned-and-stripped (FR-007 is deferred to a follow-on slice).
    ///
    /// Requires `--fingerprints-corpus`. Sources from this flag are
    /// UNION'd with `WAYBILL_FINGERPRINTS_SOURCES` and the implicit
    /// milestone-108 default (unless `--fingerprints-source-no-default`
    /// is set).
    ///
    /// Also settable via `WAYBILL_FINGERPRINTS_SOURCES` (comma-
    /// separated).
    #[arg(
        long = "fingerprints-source",
        value_name = "URL",
        action = clap::ArgAction::Append,
    )]
    pub fingerprints_source: Vec<String>,

    /// Milestone 110 Phase 5-Slim (FR-006) — suppress the implicit
    /// milestone-108 default fingerprint corpus. Use this for air-
    /// gapped runs that must NOT attempt the public-corpus fetch, or
    /// when the operator's own mirror is the only desired source.
    ///
    /// Also settable via `WAYBILL_FINGERPRINTS_NO_DEFAULT=1`.
    #[arg(
        long = "fingerprints-source-no-default",
        env = "WAYBILL_FINGERPRINTS_NO_DEFAULT",
    )]
    pub fingerprints_source_no_default: bool,

    /// Milestone 108 (US5) — override the build-time-embedded corpus
    /// SHA with a runtime-specified one. Format: 40-char lowercase hex.
    /// Requires `--fingerprints-corpus` (or
    /// `WAYBILL_FINGERPRINTS_CORPUS=1`); when the override is supplied
    /// without the opt-in, waybill emits a warning and ignores the
    /// override (the bundled fallback path is used). Use this to test
    /// newer corpora before they're embedded in a waybill release, or
    /// to pin a specific corpus version for reproducibility across
    /// machines whose embedded SHAs differ.
    ///
    /// Also settable via `WAYBILL_FINGERPRINTS_REV=<SHA>`.
    #[arg(
        long = "fingerprints-rev",
        env = "WAYBILL_FINGERPRINTS_REV",
        value_name = "SHA",
        value_parser = parse_fingerprints_rev_flag,
    )]
    pub fingerprints_rev: Option<String>,

    /// Milestone 173: opt-in Go cache-warming mode. `off` (default)
    /// preserves the milestone-172 `waybill:go-transitive-fallback-count`
    /// annotation as an actionable signal — a non-zero count tells
    /// operators their env is degraded. `per-workspace` invokes `go mod
    /// download` in every discovered Go workspace before the transitive
    /// resolver runs, so step 1 (`go mod graph`) finds every module
    /// locally and produces true parent-child topology instead of
    /// falling through to step 5's go.sum flat fallback.
    ///
    /// No-op when `--offline` is set (the effective mode becomes
    /// `offline-inhibited` and is surfaced via the
    /// `waybill:go-cache-warming-mode` doc-scope annotation).
    ///
    /// Concurrency is controlled by `--warm-go-cache-concurrency`
    /// (default 4). No-op on non-Go scans.
    #[arg(
        long,
        value_enum,
        default_value = "off",
        require_equals = true,
        num_args = 1,
        value_name = "MODE"
    )]
    pub warm_go_cache: WarmGoCacheMode,

    /// Milestone 173: maximum concurrent `go mod download` invocations
    /// during cache warming. Default: 4. Set to 1 for sequential
    /// warming (CI shared-runner friendly). Set to 0 for auto
    /// (`min(logical_cpus, 8)`). Values above 32 are clamped to 32
    /// with a warn-level log (defense against typos flooding
    /// `$GOPROXY`).
    ///
    /// No-op when `--warm-go-cache=off` or in offline mode.
    ///
    /// Rationale: matches m055/m091's `fetch_concurrency = 16`
    /// posture; monorepos are the motivating use case and sequential
    /// warming defeats the ergonomics purpose.
    #[arg(long, default_value_t = 4, value_name = "N")]
    pub warm_go_cache_concurrency: u32,

    /// Milestone 210: bypass the FR-016 trace-noise denylist that
    /// normally filters system paths (`/etc`, `/proc`), user caches
    /// (`~/.cache`), ephemeral paths (`/tmp`), and secret-adjacent
    /// paths (`/var/run/secrets`, `~/.ssh`, `~/.aws`, `*.key`,
    /// `*_rsa` etc.) from the emitted `waybill:source-read-set`
    /// annotation.
    ///
    /// When set, EVERY observed read on a compiler-invocation
    /// descendant lands in the read-set — including any secret
    /// paths the compiler touched. Intended for auditing use cases
    /// where the operator explicitly wants full visibility. NOT
    /// recommended for SBOMs shared beyond the operator's own
    /// audit trail.
    ///
    /// No-op when the compiler-pipeline trace didn't run (default
    /// features / non-Linux host / no `--features ebpf-tracing`).
    #[arg(long)]
    pub include_system_reads: bool,

    /// Milestone 218 (waybill#633): EXPERIMENTAL opt-in cross-
    /// ecosystem dep-name edge resolution.
    ///
    /// When enabled, the graph-dep-name resolver at
    /// `scan_fs/mod.rs:794` bridges `pkg:generic/` main-module
    /// `depends[]` names to matching components across every
    /// ecosystem present in the resolver index (not just the
    /// source ecosystem). This restores outgoing DEPENDS_ON edges
    /// on m216 Gemfile-only Ruby-app main-modules (and, by
    /// generalization, any future m216-alike reader producing
    /// `pkg:generic/` main-modules for pip apps, npm CLI tools,
    /// cargo binary-only crates, etc.).
    ///
    /// Emits three new annotations:
    /// - `waybill:cross-ecosystem-inference` (per-edge) on every
    ///   crossed edge.
    /// - `waybill:cross-ecosystem-inference-ambiguous` (per-edge)
    ///   on ambiguous multi-ecosystem matches per FR-003.
    /// - `waybill:cross-ecosystem-inference-unresolved` (doc-scope)
    ///   listing bare dep names that matched no component in any
    ///   ecosystem.
    ///
    /// Default: OFF. Preserves current post-m216 output byte-
    /// identically. The "experimental" prefix signals that
    /// annotation shapes MAY evolve before flag graduation.
    ///
    /// See `docs/reference/cross-ecosystem-edges.md` for the
    /// consumer-facing interpretation guide.
    ///
    /// The env-var equivalent
    /// `WAYBILL_EXPERIMENTAL_CROSS_ECOSYSTEM_EDGES=1` is read
    /// directly by `scan_fs::scan_path` (bypasses clap) so operators
    /// can enable via env alone in CI without CLI-arg mutation.
    #[arg(
        long = "experimental-cross-ecosystem-edges",
        action = clap::ArgAction::SetTrue,
    )]
    pub experimental_cross_ecosystem_edges: bool,

    /// Milestone 220 — cap main-module discovery scope.
    ///
    /// Accepts:
    /// - `all` (default; current behavior) — every reader discovers
    ///   main-modules wherever they find qualifying manifests. SC-005
    ///   byte-identity contract: `--project-discovery=all` (or the
    ///   flag omitted entirely) produces byte-identical output to
    ///   alpha.68 on every existing test fixture.
    /// - `root-only` — discover only root-level main-modules + their
    ///   ecosystem-native workspace-declared members (via the existing
    ///   `waybill:workspace-member` annotation). Independent nested
    ///   projects are dropped from the SBOM entirely.
    /// - `strict` — discover only the root-level manifest itself.
    ///   Workspace-member declarations are ignored.
    ///
    /// See `docs/reference/project-discovery.md` for the full mode
    /// table + interaction matrix vs `--split[=<mode>]`.
    ///
    /// The env-var equivalent `WAYBILL_PROJECT_DISCOVERY=<mode>` is
    /// bridged from this flag when set to a non-default value (compat
    /// shim for env-only invocations in CI scripts that can't easily
    /// mutate CLI args).
    #[arg(
        long = "project-discovery",
        value_enum,
        default_value = "all",
        require_equals = true,
    )]
    pub project_discovery:
        crate::generate::project_discovery::ProjectDiscoveryMode,

    /// Milestone 232 (#660) — filter the emitted SBOM's component set
    /// by `sbom_tier`. Default `all` preserves pre-232 behavior byte-
    /// for-byte (FR-002 / SC-003 guarantee). See
    /// `docs/reference/component-tiers.md` for the tier taxonomy.
    ///
    /// Modes:
    /// - `all` (default) — emit every resolved component.
    /// - `source-only` — emit only `sbom_tier: "source"` components.
    ///   Recommended for vulnerability-scanner pipelines.
    /// - `design-only` — emit only `sbom_tier: "design"` components.
    ///   Recommended for compliance-attribution pipelines.
    /// - `source-and-binary` — emit `source` OR `binary` components
    ///   (drops `design`, `analyzed`, `file`). Recommended for
    ///   container-artifact pipelines.
    ///
    /// Composes cleanly with every other flag; no mutual exclusions.
    /// Degenerate combinations (filter drops main-module referenced
    /// by `--sign-key`, etc.) produce a WARN log and continue —
    /// never a hard error.
    #[arg(long, value_enum, default_value_t = TierMode::All)]
    pub tier: TierMode,

    /// Skip binary-scanning reader(s). Accepted values: `go`, `all`.
    ///
    /// `go` — skip the `go_binary` reader (no `pkg:golang/*` from
    /// BuildInfo). **Deprecated as a perf lever** (#781): the default
    /// path is now fast on non-Go trees. Keep for component filtering.
    ///
    /// `all` — skip the entire binary-scanning tier. Drops all
    /// binary-tier provenance (Go BuildInfo, role classification,
    /// linkage, fingerprints) for maximum scan speed.
    ///
    /// When set, waybill emits a document-scope
    /// `waybill:binary-scan-suppressed=<mode>` annotation in every
    /// output format so downstream consumers can detect the
    /// suppression. Default (unset) is byte-identical to pre-m665
    /// behavior — FR-003.
    ///
    /// The env-var `WAYBILL_NO_BINARY_SCAN=<mode>` provides the
    /// same value; CLI flag wins when both are set.
    #[arg(
        long = "no-binary-scan",
        value_enum,
        value_name = "MODE",
        env = "WAYBILL_NO_BINARY_SCAN",
        long_help = "\
Skip binary-scanning reader(s). Two modes; each is a filter, not just a perf lever.

MODES:
  `go`  — DEPRECATED as a perf lever (#781): the default path is now fast on non-Go trees \
via a magic-byte prefilter. Still works as a component filter — skips the go_binary reader, so no \
`pkg:golang/*` components from statically-linked Go binaries. Components claimed via OS-package \
readers (dpkg / apk / rpm / pip RECORD) keep their attribution. Emits a WARN log pointing at `all`.

  `all` — Skip the ENTIRE binary-scanning tier. No go_binary BuildInfo probing, no m104 role \
classification, no linkage extraction, no m099 symbol fingerprinting. Drops all binary-tier components. \
Components emitted from other tiers (dpkg/apk/rpm/pip/npm/cargo/etc.) keep their tier data unchanged. \
See issue #775.

WHEN TO USE:
  * `=all`: Scanning a large repo where you don't need any binary-tier provenance and want the max speed win.
  * `=go`: You want to suppress `pkg:golang/*` components in your SBOM (e.g., a compliance regime that \
    can't reason about statically-linked binaries) but keep other binary-tier data.

WHEN NOT TO USE:
  * `=go` for perf: unnecessary post-#781. Just run without the flag.
  * `=all` if you need statically-linked Go module attribution or role/linkage metadata for binaries \
    outside OS-package coverage.

PERF (macOS APFS, warm cache, post-#781):
  * mongo (55k files, C++): default ~4s; `=all` ~2.5s
  * Pre-#781 defaults were ~13.5s on the same tree.

When set, waybill emits a document-scope `waybill:binary-scan-suppressed=<mode>` annotation in every \
output format so downstream consumers can detect the suppression. Default (unset) is byte-identical \
to pre-m665 behavior.

The env-var `WAYBILL_NO_BINARY_SCAN=<mode>` provides the same value; the CLI flag wins when both are set.\
",
    )]
    pub no_binary_scan: Option<BinaryScanMode>,
}

/// Milestone 173: CLI-side cache-warming mode. Two variants;
/// `OfflineInhibited` is internal to the pipeline and NOT
/// exposed at the CLI parse layer (set at the pipeline entry when
/// `--offline` overrides the operator's choice).
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum WarmGoCacheMode {
    /// No warming performed.
    Off,
    /// One `go mod download` invocation per discovered Go workspace.
    PerWorkspace,
}

impl From<WarmGoCacheMode>
    for crate::scan_fs::package_db::golang::CacheWarmingMode
{
    fn from(cli: WarmGoCacheMode) -> Self {
        match cli {
            WarmGoCacheMode::Off => Self::Off,
            WarmGoCacheMode::PerWorkspace => Self::PerWorkspace,
        }
    }
}

/// Clap value parser for `--fingerprints-rev`. Validates the value is
/// 40-char lowercase hex; returns the string verbatim on success so
/// downstream `LoadOptions` plumbing can parse it via
/// `CorpusSha::from_hex` without re-validating.
pub(crate) fn parse_fingerprints_rev_flag(value: &str) -> Result<String, String> {
    if value.len() != 40 {
        return Err(format!(
            "--fingerprints-rev must be 40-char lowercase hex; got {} chars",
            value.len()
        ));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err(
            "--fingerprints-rev must be 40-char lowercase hex; \
             rejected uppercase / non-hex characters"
                .to_string(),
        );
    }
    Ok(value.to_string())
}

/// Clap value_parser for `--spdx2-relationship-compat`. Accepts
/// `full` (default, full SPDX 2.3 relationship vocabulary) and
/// `basic` (issue #228 — only the basic vocabulary
/// `DEPENDS_ON`/`CONTAINS`/`DESCRIBES`, scoped deps collapse to
/// `DEPENDS_ON`).
pub(crate) fn parse_spdx2_relationship_compat_flag(
    value: &str,
) -> Result<crate::generate::Spdx2RelationshipCompat, String> {
    match value {
        "full" => Ok(crate::generate::Spdx2RelationshipCompat::Full),
        "basic" => Ok(crate::generate::Spdx2RelationshipCompat::Basic),
        other => Err(format!(
            "invalid --spdx2-relationship-compat '{other}'; valid values: full, basic"
        )),
    }
}

/// Clap value_parser for `--sbom-type`. Wraps
/// `SbomType::parse_str` so the error type implements `Into<String>`
/// (clap's required error shape).
pub(crate) fn parse_sbom_type_flag(
    value: &str,
) -> Result<crate::generate::lifecycle_phases::SbomType, String> {
    crate::generate::lifecycle_phases::SbomType::parse_str(value)
        .map_err(|e| e.to_string())
}

/// Milestone 077 — validate `--root-name` / `--root-version` values
/// at CLI parse time. Per FR-006 + Q1 clarification: rejects empty
/// strings, ASCII whitespace, control characters (`\x00`–`\x1F`,
/// `\x7F`), `?`, and `#`. Accepts any other UTF-8.
///
/// The error messages identify the offending character + position so
/// operators understand which character violated which rule (operators
/// with weird-but-legal names like `@acme/widget-svc` need to know it's
/// the `@` or `/` that's allowed, vs `?`/`#` which are rejected).
///
/// Returns the validated string verbatim on success — the caller stores
/// it in `RootComponentOverride.name` / `.version` for downstream
/// per-format emission. The PURL emitter applies its own RFC 3986
/// percent-encoding via `percent_encode_purl_name` at emission time.
pub(crate) fn validate_root_field(
    value: &str,
    flag_name: &str,
) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{flag_name} must not be empty"));
    }
    for (i, c) in value.chars().enumerate() {
        if c.is_whitespace() {
            return Err(format!(
                "{flag_name} contains whitespace at position {i} \
                 (character: {c:?}); whitespace is not allowed"
            ));
        }
        if c.is_control() {
            return Err(format!(
                "{flag_name} contains a control character at position {i} \
                 (codepoint: U+{:04X}); control characters are not allowed",
                c as u32
            ));
        }
        if c == '?' || c == '#' {
            return Err(format!(
                "{flag_name} contains URL-syntax-breaking character '{c}' \
                 at position {i}; '?' and '#' are not allowed"
            ));
        }
    }
    Ok(value.to_string())
}

/// Clap value_parser for `--root-name`. Wraps `validate_root_field`
/// with the canonical flag-name string so error messages identify the
/// flag.
pub(crate) fn validate_root_name(value: &str) -> Result<String, String> {
    validate_root_field(value, "--root-name")
}

/// Clap value_parser for `--root-version`. Wraps `validate_root_field`
/// with the canonical flag-name string.
pub(crate) fn validate_root_version(value: &str) -> Result<String, String> {
    validate_root_field(value, "--root-version")
}

/// Clap value_parser for `--root-purl-type`. Enforces the purl-spec
/// type-token charset (`^[a-z][a-z0-9.+-]*$`). The `packageurl` crate
/// would reject non-conforming tokens at PURL construction time
/// downstream, but pre-validating at parse time gives the operator a
/// fast, flag-named error instead of an opaque "PURL construction
/// failed" message during emission.
pub(crate) fn validate_root_purl_type(value: &str) -> Result<String, String> {
    use std::sync::LazyLock;
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^[a-z][a-z0-9.+-]*$")
            .expect("root-purl-type regex compiles")
    });
    if RE.is_match(value) {
        Ok(value.to_string())
    } else {
        Err(format!(
            "--root-purl-type `{value}` is not a valid purl-spec type token \
             (expected lowercase ASCII alphanumeric + `.+-`, starting with a letter)"
        ))
    }
}

/// Issue #359 — `--root-purl <PURL>` validator. Defers to
/// `waybill_common::types::purl::Purl::new` (which delegates to the
/// `packageurl` crate's spec-correct parser) so the operator gets the
/// same error class clap surfaces for every other PURL-shaped input.
/// Returns the canonicalized form on success so emission uses the same
/// representation `Purl::new` would produce internally.
pub(crate) fn validate_root_purl(value: &str) -> Result<String, String> {
    waybill_common::types::purl::Purl::new(value)
        .map(|p| p.as_str().to_string())
        .map_err(|e| format!("--root-purl `{value}` is not a valid PURL: {e}"))
}

/// Parse a `--id <scheme>=<value>` flag for a user-defined identifier.
///
/// Errors at clap parse time on:
/// - missing `=` separator
/// - empty scheme or value
/// - scheme failing the FR-004 regex (`InvalidSchemeName`)
/// - scheme matching one of the built-in schemes (`repo`, `git`,
///   `image`, `attestation`) — operator is directed to the
///   dedicated `--repo` / `--git-ref` / `--image-id` /
///   `--attestation` flag instead.
///
/// Built-in schemes are EXPLICITLY rejected here so users get a
/// clear error pointing at the right flag instead of a
/// soft-fail-to-opaque downgrade. The `--id` flag is for
/// user-defined namespaces only.
/// Milestone 144 T005: `--rpm-distro <ID>` value parser. Rejects empty
/// strings at clap parse time (FR-003). Lowercases the input so the
/// resulting PURL namespace is canonical per purl-spec §lower-case-rules.
fn parse_non_empty_lowercase_distro_id(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("must be non-empty".to_string());
    }
    Ok(s.to_lowercase())
}

/// Milestone 144 T005: `--max-rpm-bytes <N>` value parser. Rejects
/// zero AND non-numeric input at clap parse time (FR-005). Operators
/// wanting "no cap" should pass a very large number; absence of the
/// flag uses the 512 MiB default.
fn parse_nonzero_u64(s: &str) -> Result<u64, String> {
    let v: u64 = s
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    if v == 0 {
        return Err("must be > 0".to_string());
    }
    Ok(v)
}

/// Milestone 671 T009: `--file-inventory-source-shapes` value parser.
/// Thin wrapper over `source_shape::parse_restriction` that stringifies
/// the `SourceShapeParseError` for `clap`'s `Result<_, String>`
/// contract. Diagnostic messages remain byte-identical to the
/// contract in `contracts/source_shape_restriction.md`.
fn parse_source_shape_restriction_arg(
    raw: &str,
) -> Result<scan_fs::file_tier::source_shape::SourceShapeSet, String> {
    scan_fs::file_tier::source_shape::parse_restriction(raw).map_err(|e| e.to_string())
}

fn parse_user_defined_id_flag(
    raw: &str,
) -> Result<waybill::binding::identifiers::Identifier, String> {
    use waybill::binding::identifiers::{
        BuiltinScheme, Identifier, IdentifierError, IdentifierKind, IdentifierValue, SchemeName,
    };
    let Some(idx) = raw.find('=') else {
        return Err(format!(
            "--id value missing `=` separator: {raw:?} \
             (expected form: --id <scheme>=<value>)"
        ));
    };
    let scheme_str = &raw[..idx];
    let value_str = &raw[idx + 1..];
    let scheme = SchemeName::new(scheme_str.to_string())
        .map_err(|e: IdentifierError| e.to_string())?;
    if let Some(b) = BuiltinScheme::from_scheme_name(&scheme) {
        return Err(format!(
            "--id rejects the built-in scheme `{}` — use the dedicated \
             flag instead (--repo / --git-ref / --image-id / --attestation). \
             --id is for user-defined schemes only.",
            b.as_str()
        ));
    }
    let value =
        IdentifierValue::new(value_str.to_string()).map_err(|e: IdentifierError| e.to_string())?;
    Ok(Identifier::from_parts_with_label(
        scheme,
        value,
        IdentifierKind::UserDefined,
        None,
    ))
}

/// Translate the dedicated built-in flags into the `Identifier`
/// list. Returns the manual identifiers in the supply order
/// `[repo-or-git, image, attestation, ...user-defined]`. The
/// `repo`/`git-ref` pair collapses into a single `git:` identifier
/// when `--git-ref` is set; otherwise emits a `repo:` identifier.
///
/// Each identifier is constructed via `Identifier::parse` (so the
/// FR-004 scheme validation + soft-fail value validation paths run
/// uniformly). Validation failure soft-fails to opaque
/// `IdentifierKind::UserDefined` per VR-005 — same behavior as the
/// old single-flag path.
fn assemble_manual_identifiers(args: &ScanArgs) -> Vec<waybill::binding::identifiers::Identifier> {
    let mut out: Vec<waybill::binding::identifiers::Identifier> = Vec::new();
    // (1) repo / git-ref: when --git-ref is set, emit only the git:
    // form; otherwise emit a bare repo: form.
    if let Some(repo_url) = args.repo.as_deref() {
        let raw = if let Some(rev) = args.git_ref.as_deref() {
            format!("git:{repo_url}#{rev}")
        } else {
            format!("repo:{repo_url}")
        };
        match waybill::binding::identifiers::Identifier::parse(&raw) {
            Ok(id) => out.push(id),
            Err(e) => tracing::warn!(
                error = %e,
                raw = %raw,
                "failed to parse manual --repo/--git-ref identifier; skipping"
            ),
        }
    }
    if let Some(image) = args.image_id.as_deref() {
        let raw = format!("image:{image}");
        match waybill::binding::identifiers::Identifier::parse(&raw) {
            Ok(id) => out.push(id),
            Err(e) => tracing::warn!(
                error = %e,
                raw = %raw,
                "failed to parse manual --image-id identifier; skipping"
            ),
        }
    }
    if let Some(att) = args.attestation.as_deref() {
        let raw = format!("attestation:{att}");
        match waybill::binding::identifiers::Identifier::parse(&raw) {
            Ok(id) => out.push(id),
            Err(e) => tracing::warn!(
                error = %e,
                raw = %raw,
                "failed to parse manual --attestation identifier; skipping"
            ),
        }
    }
    // Milestone 076 — manual --subject-hash flags. Format: `algo:hex`.
    // Wrap each value into a full `subject:<algo>:<hex>` shape and
    // route through `Identifier::parse` so the soft-fail path
    // (downgrade to UserDefined per FR-005) handles malformed input
    // identically to other built-ins.
    for sh in &args.subject_hash {
        let raw = format!("subject:{sh}");
        match waybill::binding::identifiers::Identifier::parse(&raw) {
            Ok(id) => out.push(id),
            Err(e) => tracing::warn!(
                error = %e,
                raw = %raw,
                "failed to parse manual --subject-hash identifier; skipping"
            ),
        }
    }
    // (2) user-defined --id flags in supply order.
    for id in &args.id {
        out.push(id.clone());
    }
    out
}

/// Synthesize an `image:` identifier from the user-supplied `--image`
/// reference and the extracted-image state. Per the Q3 clarification,
/// the canonical shape is `image:<registry>/<name>:<tag>@sha256:<digest>`
/// with documented omissions when components are missing.
///
/// This helper attempts:
/// 1. If the user passed `--image <ref>` and `<ref>` is NOT a tarball
///    file (i.e., an OCI ref like `docker.io/foo/bar:v1`), parse it
///    and combine with the extracted manifest_digest to synthesize the
///    full form.
/// 2. If the user passed a tarball file, use the extracted `repo_tag`
///    (typically `name:tag`) plus `manifest_digest`. The registry
///    portion is omitted when not present in `repo_tag`.
/// 3. If neither yields a usable shape, emit just the digest:
///    `image:@sha256:<manifest_digest>` (rare — defensive fallback).
///
/// Returns `None` when neither field is populated — the scan still
/// emits without the auto-detected `image:` identifier.
fn image_auto_identifier(
    extracted: Option<&scan_fs::docker_image::ExtractedImage>,
    image_arg: Option<&Path>,
) -> Option<waybill::binding::identifiers::Identifier> {
    let extracted = extracted?;
    // Prefer the user-supplied reference when it's an OCI ref (not a
    // tarball file). Even when a registry pull resolved the reference,
    // the user-supplied form carries the human-readable
    // `<registry>/<name>:<tag>` pieces we want in the identifier.
    let arg_str: Option<&str> = match image_arg {
        Some(p) => {
            if p.is_file() {
                None
            } else {
                p.to_str()
            }
        }
        None => None,
    };
    let (registry, name, tag) = if let Some(s) = arg_str {
        parse_image_ref_components(s)
    } else if let Some(rt) = extracted.repo_tag.as_deref() {
        // Tarball path: rely on the extracted RepoTags entry.
        parse_image_ref_components(rt)
    } else {
        (None, String::new(), None)
    };
    // The manifest digest is the SHA-256 of the docker-save manifest.json.
    // It's a stable identifier for THIS specific image artifact even if
    // it differs from the upstream registry's content digest. Operators
    // who need the registry-side digest can pass `--image-id
    // <ref>@sha256:<their-digest>` manually; auto-detection's job
    // is to emit a maximally-informative identifier from what waybill
    // can observe.
    let digest = if extracted.manifest_digest.is_empty() {
        None
    } else {
        Some(extracted.manifest_digest.as_str())
    };
    if name.is_empty() && digest.is_none() {
        return None;
    }
    waybill::binding::identifiers::auto_detect::image_reference_to_identifier(
        registry.as_deref(),
        if name.is_empty() {
            // Fall back to a name pulled from `target_name` (which the
            // scan has access to elsewhere) — but the safest defensive
            // choice when we can't extract a name is to skip emission.
            return None;
        } else {
            &name
        },
        tag.as_deref(),
        digest,
    )
}

/// Parse an OCI-ish image reference into `(registry, name, tag)`.
///
/// Heuristic: if the first `/`-separated segment contains a `.` or `:`,
/// or is the literal `localhost`, it's a registry; otherwise the whole
/// thing is the name. The tag is the LAST `:`-separated piece IF that
/// piece contains no `/`. Digest portions (`@sha256:...`) are stripped
/// before parsing — the digest is extracted from the docker-save
/// manifest, not the user-supplied reference.
fn parse_image_ref_components(raw: &str) -> (Option<String>, String, Option<String>) {
    // Strip any trailing `@sha256:...` portion — digest is sourced
    // from the extracted-image state, not the reference string.
    let raw = match raw.find("@sha256:") {
        Some(i) => &raw[..i],
        None => raw,
    };
    if raw.is_empty() {
        return (None, String::new(), None);
    }
    // Identify potential registry prefix.
    let (registry, rest) = match raw.split_once('/') {
        Some((first, rest)) => {
            let looks_like_registry =
                first.contains('.') || first.contains(':') || first == "localhost";
            if looks_like_registry {
                (Some(first.to_string()), rest)
            } else {
                (None, raw)
            }
        }
        None => (None, raw),
    };
    // Now split off the tag — last `:` whose right-hand-side has no `/`.
    let (name, tag) = if let Some(colon_idx) = rest.rfind(':') {
        let after = &rest[colon_idx + 1..];
        if after.contains('/') || after.is_empty() {
            (rest.to_string(), None)
        } else {
            (rest[..colon_idx].to_string(), Some(after.to_string()))
        }
    } else {
        (rest.to_string(), None)
    };
    (registry, name, tag)
}

// Milestone 074 (T005): the previous in-file `resolve_identifiers`
// was tier-agnostic at the type level (`Option<Identifier>` in,
// `Vec<Identifier>` out) but its single-auto-detected signature
// could not represent the build-tier case where two auto-detected
// entries (`repo:` + `git:`) flow into resolution. The function was
// promoted to `waybill::binding::identifiers::resolve_identifiers`
// with a `Vec<Identifier>`-based signature, applying the same
// override semantics per-scheme. Source-tier and image-tier callers
// still pass at most one auto-detected entry; build-tier passes up
// to two.

/// Resolved enrichment-source enablement. Computed from the CLI flags
/// before any scan work so the decision is testable as a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EnrichConfig {
    deps_dev: bool,
    clearly_defined: bool,
    deps_dev_graph: bool,
}

/// Resolve which enrichment sources are enabled from CLI flags.
///
/// Rules:
/// - `--enrich-sources` (when non-empty) is an explicit allowlist that
///   overrides all `--no-*` flags.
/// - When `--enrich-sources` is empty, individual `--no-*` flags apply.
/// - `offline` is NOT checked here — callers gate on it separately so
///   the inner enrichment functions' own offline short-circuit handles
///   the no-op path and logs correctly.
fn resolve_enrich_sources(args: &ScanArgs) -> EnrichConfig {
    if !args.enrich_sources.is_empty() {
        EnrichConfig {
            deps_dev: args.enrich_sources.contains(&EnrichSource::DepsDev),
            clearly_defined: args.enrich_sources.contains(&EnrichSource::ClearlyDefined),
            deps_dev_graph: args.enrich_sources.contains(&EnrichSource::DepsDevGraph),
        }
    } else {
        // Milestone 207 (#596): `--no-deps-dev` is now an aggregate
        // disable — suppresses BOTH the deps.dev license path AND
        // the deps.dev transitive dep-graph path. Pre-m207 it
        // suppressed only the license path. Fine-grained control
        // preserved via `--no-deps-dev-license` (license only) and
        // `--no-deps-dev-graph` (graph only).
        EnrichConfig {
            deps_dev: !args.no_deps_dev && !args.no_deps_dev_license,
            clearly_defined: !args.no_clearly_defined,
            deps_dev_graph: !args.no_deps_dev && !args.no_deps_dev_graph,
        }
    }
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
    //
    // The milestone-010 typo-guard for `spdx-3-json` was removed —
    // that identifier is now first-class (milestone 011 US1).
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
            let known = format_help_list(registry);
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
    // `waybill.openvex.json`, which can't collide with any
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

/// The SPDX 3 deprecation-alias format id (milestone 011 US3).
/// Kept as a named constant so the notice-emission path in
/// `execute()` and the help-list labeling in [`format_help_list`]
/// reference the same string.
const SPDX_3_DEPRECATED_ALIAS: &str = "spdx-3-json-experimental";

/// Environment override to suppress the
/// `spdx-3-json-experimental` deprecation notice. Set to any
/// non-empty value to silence the stderr warning during a
/// controlled migration; document bytes are unaffected either way.
const NO_DEPRECATION_NOTICE_ENV: &str = "WAYBILL_NO_DEPRECATION_NOTICE";

/// Format the registered-id list for user-facing text. Appends
/// ` [EXPERIMENTAL]` to any serializer where
/// [`SbomSerializer::experimental`] is true (Constitution Principle
/// V), and ` [DEPRECATED]` to the
/// `spdx-3-json-experimental` alias (milestone 011 US3 / research.md
/// §R2). Used by the unknown-format error path — surfaces the
/// status at the exact moment a user encounters the set of
/// accepted format identifiers.
fn format_help_list(registry: &SerializerRegistry) -> Vec<String> {
    registry
        .ids()
        .map(|id| {
            let ser = registry.get(id).expect("id from registry.ids()");
            if id == SPDX_3_DEPRECATED_ALIAS {
                format!("{id} [DEPRECATED]")
            } else if ser.experimental() {
                format!("{id} [EXPERIMENTAL]")
            } else {
                id.to_string()
            }
        })
        .collect()
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

/// Resolve an `--image <ref>` OCI reference to a `docker save`-format
/// tarball on disk by trying each source in `args.image_src` in order.
/// First hit wins. The `tempdir` slot is populated with the holder
/// dir so the caller's tarball path stays valid through extraction.
///
/// The OCI-ref parse check from milestone 031 still runs (rejects
/// arguments that are neither tarballs nor parseable refs) so the
/// error message remains the same as before.
async fn resolve_image_ref(
    arg_str: &str,
    args: &ScanArgs,
    tempdir: &mut Option<tempfile::TempDir>,
    selected_source: &mut Option<ImageSource>,
) -> anyhow::Result<PathBuf> {
    #[cfg(feature = "oci-registry")]
    {
        let archive_path = std::path::Path::new(arg_str);
        let kind = scan_fs::oci_pull::detect_image_arg_kind(archive_path);
        if kind != scan_fs::oci_pull::ImageArgKind::OciRef {
            anyhow::bail!(
                "--image argument is neither an existing tarball file nor a parseable OCI image reference: {arg_str}"
            );
        }
    }

    let mut tried: Vec<&'static str> = Vec::new();
    for src in &args.image_src {
        match src {
            ImageSource::Docker => {
                tried.push("docker");
                // `--image-platform` asks for a specific arch/variant
                // pulled from a multi-arch index; the local docker
                // daemon only has whatever it was told to cache. Skip
                // the docker source when a platform is requested.
                if args.image_platform.is_some() {
                    tracing::info!(
                        image_ref = arg_str,
                        "--image-platform set; skipping local docker source (only registry pulls honor platform)"
                    );
                    continue;
                }
                match scan_fs::docker_daemon::inspect(arg_str) {
                    scan_fs::docker_daemon::InspectOutcome::Present => {
                        tracing::info!(
                            image_ref = arg_str,
                            "found image in local docker daemon; exporting via `docker save`"
                        );
                        let td = tempfile::tempdir()
                            .context("creating tempdir for docker-save tarball")?;
                        let tarball = td.path().join("image.tar");
                        scan_fs::docker_daemon::save(arg_str, &tarball)?;
                        *tempdir = Some(td);
                        *selected_source = Some(ImageSource::Docker);
                        return Ok(tarball);
                    }
                    scan_fs::docker_daemon::InspectOutcome::Absent => {
                        tracing::info!(
                            image_ref = arg_str,
                            "image not present in local docker daemon"
                        );
                    }
                    scan_fs::docker_daemon::InspectOutcome::DockerUnavailable => {
                        tracing::info!(
                            image_ref = arg_str,
                            "local docker daemon not available; trying next source"
                        );
                    }
                }
            }
            ImageSource::Podman => {
                tried.push("podman");
                // Milestone 206 (#440) — filesystem-only read of
                // c/storage overlay layout (FR-009: no daemon/REST
                // API). On any PodmanSourceError, WARN + continue
                // to the next --image-src entry per FR-007.
                if args.image_platform.is_some() {
                    tracing::info!(
                        image_ref = arg_str,
                        "--image-platform set; skipping local podman source (only registry pulls honor platform)"
                    );
                    continue;
                }
                let td = tempfile::tempdir()
                    .context("creating tempdir for podman-source tarball")?;
                let tarball = td.path().join("image.tar");
                match scan_fs::podman_source::resolve_and_pack(arg_str, &tarball) {
                    Ok(()) => {
                        tracing::info!(
                            image_ref = arg_str,
                            "found image in local podman storage; packed docker-save tarball"
                        );
                        *tempdir = Some(td);
                        *selected_source = Some(ImageSource::Podman);
                        return Ok(tarball);
                    }
                    Err(e) => {
                        tracing::info!(
                            image_ref = arg_str,
                            error = %e,
                            "podman source failed; trying next --image-src entry"
                        );
                    }
                }
            }
            ImageSource::Remote => {
                tried.push("remote");
                #[cfg(feature = "oci-registry")]
                {
                    tracing::info!(image_ref = arg_str, "pulling image from registry");
                    let cache_disabled = args.no_oci_cache
                        || std::env::var("WAYBILL_OCI_CACHE").as_deref() == Ok("0");
                    let cache_size_cap = if cache_disabled {
                        None
                    } else {
                        let env_size = std::env::var("WAYBILL_OCI_CACHE_SIZE")
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok());
                        Some(
                            args.oci_cache_size
                                .or(env_size)
                                .unwrap_or(10 * 1024 * 1024 * 1024),
                        )
                    };
                    // Milestone 182 — build the TLS/transport config
                    // once up-front. Fails fast (before any network) on
                    // malformed --insecure-registry values or bad CA
                    // paths per FR-014.
                    let tls_config = scan_fs::oci_pull::RegistryTlsConfig::from_args(
                        &args.insecure_registry,
                        &args.registry_ca_cert,
                        args.insecure_tls_skip_verify,
                    )?;
                    let td = scan_fs::oci_pull::pull_to_tarball(
                        arg_str,
                        args.image_platform.as_deref(),
                        cache_size_cap,
                        args.registry_credentials_dir.as_deref(),
                        &tls_config,
                    )
                    .await?;
                    let tarball = td.path().join("image.tar");
                    *tempdir = Some(td);
                    *selected_source = Some(ImageSource::Remote);
                    return Ok(tarball);
                }
                #[cfg(not(feature = "oci-registry"))]
                {
                    anyhow::bail!(
                        "--image-src includes `remote`, but this build of \
                         waybill was compiled with `--no-default-features` \
                         (the `oci-registry` Cargo feature is OFF), so OCI \
                         image references like `alpine:3.19` cannot be \
                         pulled from a registry. Either:\n\
                         (a) reinstall with the default feature set: \
                         `cargo install waybill`, or\n\
                         (b) pre-extract the image with \
                         `docker save <ref> -o image.tar` and pass \
                         `--image image.tar`, or\n\
                         (c) pass `--image-src docker` and ensure the \
                         image is in the local docker daemon."
                    );
                }
            }
        }
    }

    anyhow::bail!(
        "image `{arg_str}` not found in any of the configured `--image-src` sources: [{}]. \
         Pull or build it first, or change `--image-src`.",
        tried.join(", ")
    )
}

/// Milestone 232 (#660) — `--tier` filter's `sbom_tier` predicate.
/// Returns `true` when the given component's tier value should be
/// retained under the requested mode. See
/// `specs/232-tier-filter-flag/data-model.md § New helper`.
fn tier_matches(tier: Option<&str>, mode: TierMode) -> bool {
    match mode {
        TierMode::All => true,
        TierMode::SourceOnly => tier == Some("source"),
        TierMode::DesignOnly => tier == Some("design"),
        TierMode::SourceAndBinary => tier == Some("source") || tier == Some("binary"),
    }
}

/// Milestone 232 (#660) — apply the `--tier=<mode>` filter over the
/// resolved-component set. Early-returns on `TierMode::All` (no-op
/// filter; preserves FR-002 / SC-003 byte-parity). For non-default
/// modes: drops components not matching the mode's predicate, then
/// drops any dependency edge whose source OR target references a
/// dropped component (FR-006). Emits an INFO log with the drop count.
/// Emits an additional WARN log when the post-filter component set
/// is empty (FR-008 observability).
///
/// See `specs/232-tier-filter-flag/data-model.md § New helper`.
fn apply_tier_filter(
    components: &mut Vec<waybill_common::resolution::ResolvedComponent>,
    relationships: &mut Vec<waybill_common::resolution::Relationship>,
    mode: TierMode,
) {
    if mode == TierMode::All {
        return;
    }
    let pre_filter_count = components.len();
    let dropped_purls: std::collections::HashSet<String> = components
        .iter()
        .filter(|c| !tier_matches(c.sbom_tier.as_deref(), mode))
        .map(|c| c.purl.as_str().to_string())
        .collect();
    components.retain(|c| !dropped_purls.contains(c.purl.as_str()));
    relationships.retain(|r| {
        !dropped_purls.contains(&r.from) && !dropped_purls.contains(&r.to)
    });
    let dropped = pre_filter_count.saturating_sub(components.len());
    tracing::info!(
        dropped,
        mode = ?mode,
        "applied --tier filter",
    );
    if components.is_empty() {
        tracing::warn!(
            mode = ?mode,
            "tier filter dropped all components; emitting empty SBOM",
        );
    }
}

pub async fn execute(
    mut args: ScanArgs,
    offline: bool,
    exclude_scope: Vec<waybill_common::resolution::LifecycleScope>,
    include_legacy_rpmdb: bool,
    include_declared_deps: bool,
    exclude_set: crate::scan_fs::package_db::exclude_path::ExclusionSet,
    supplement_cdx: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    // Milestone 102 FR-016: propagate the `--include-vendored` flag to
    // the env var that the C/C++ readers read directly. This avoids
    // plumbing through `scan_path`'s 75-callsite chain. The clap derive
    // already populates `args.include_vendored` from either the CLI
    // flag or `WAYBILL_INCLUDE_VENDORED=1` env (whichever was set first);
    // we re-export to the env so `read_all`-internal readers see the
    // unified signal regardless of which input set it.
    // SAFETY: single-threaded at this point in the scan-cmd lifecycle.
    if args.include_vendored {
        // SAFETY: see comment above — single-threaded.
        unsafe {
            std::env::set_var("WAYBILL_INCLUDE_VENDORED", "1");
        }
    }

    // Milestone 235 — validate + propagate Gradle ladder flags.
    // Validation rejects shell metacharacters in
    // `--gradle-extra-configurations` values before any subprocess spawn.
    args.gradle
        .validate_configuration_names()
        .map_err(anyhow::Error::msg)?;
    args.gradle.export_env();

    // Milestone 188 (#455) — propagate `--helm-render` to the env var
    // that the helm reader consumes. Same zero-plumbing pattern as
    // WAYBILL_INCLUDE_VENDORED. Absent env var → HelmRenderMode::Off.
    // SAFETY: single-threaded at this point in the scan-cmd lifecycle.
    if args.helm_render {
        // SAFETY: see comment above — single-threaded.
        unsafe {
            std::env::set_var("WAYBILL_HELM_RENDER", "1");
        }
    }

    // Milestone 156: propagate `--cmake-third-party-recursive` to the
    // env var that the cmake reader reads directly. Same pattern as
    // WAYBILL_INCLUDE_VENDORED above — zero-plumbing propagation
    // avoiding the 75-callsite scan_path -> read_all chain.
    // SAFETY: single-threaded at this point in the scan-cmd lifecycle.
    if args.cmake_third_party_recursive {
        // SAFETY: see comment above — single-threaded.
        unsafe {
            std::env::set_var("WAYBILL_CMAKE_THIRD_PARTY_RECURSIVE", "1");
        }
    }

    // Milestone 108 FR-002: propagate the `--fingerprints-corpus`
    // opt-in to the env var that the binary-scan loop's fingerprint
    // matcher reads directly. Same pattern as WAYBILL_INCLUDE_VENDORED
    // above. Clap's `env = "WAYBILL_FINGERPRINTS_CORPUS"` derive picks
    // up the env-set form; this re-export handles the
    // operator-passed-the-flag-but-not-the-env form. The matcher then
    // calls `LoadOptions::from_env()` (which also reads `WAYBILL_OFFLINE`,
    // already set by main.rs).
    if args.fingerprints_corpus {
        // SAFETY: see comment above — single-threaded.
        unsafe {
            std::env::set_var("WAYBILL_FINGERPRINTS_CORPUS", "1");
        }
    }

    // Milestone 110 Phase 5-Slim (FR-006): re-export the multi-source
    // declarations to the env vars that the fingerprints subsystem's
    // `Sources::from_env()` reads. Same pattern as the `--fingerprints-
    // corpus` and `--fingerprints-rev` re-exports above. When the
    // operator passed `--fingerprints-source` but not `--fingerprints-
    // corpus`, the sources are still propagated; the corpus opt-in
    // gate downstream will short-circuit before any fetch happens, so
    // the env vars are inert.
    if !args.fingerprints_source.is_empty() {
        // SAFETY: env-mutation pattern matches WAYBILL_FINGERPRINTS_CORPUS
        // above; called single-threaded before any scan thread spawns.
        unsafe {
            std::env::set_var(
                "WAYBILL_FINGERPRINTS_SOURCES",
                args.fingerprints_source.join(","),
            );
        }
        if !args.fingerprints_corpus {
            tracing::warn!(
                count = args.fingerprints_source.len(),
                "--fingerprints-source declared without --fingerprints-corpus; \
                 the sources are parsed but no corpus loading will occur. \
                 Add --fingerprints-corpus (or WAYBILL_FINGERPRINTS_CORPUS=1) to enable.",
            );
        }
    }
    if args.fingerprints_source_no_default {
        // SAFETY: see comment above.
        unsafe {
            std::env::set_var("WAYBILL_FINGERPRINTS_NO_DEFAULT", "1");
        }
    }

    // Milestone 218 (waybill#633): bridge the FR-000
    // `--experimental-cross-ecosystem-edges` CLI flag to the env-var
    // read by `scan_fs::scan_path`'s resolver. Same env-var-bridge
    // pattern as WAYBILL_INCLUDE_VENDORED / WAYBILL_DEEP_HASH. Only
    // SET when the CLI arg is true; NEVER unset — otherwise an
    // env-var-only invocation (`WAYBILL_EXPERIMENTAL_...=1 waybill
    // ...`, without the CLI flag) would be silently disabled.
    if args.experimental_cross_ecosystem_edges {
        // SAFETY: see comment above.
        unsafe {
            std::env::set_var("WAYBILL_EXPERIMENTAL_CROSS_ECOSYSTEM_EDGES", "1");
        }
    }

    // Milestone 220: bridge --project-discovery=<mode> to the env
    // var so env-only invocations (CI scripts that can't easily
    // mutate CLI args) also work. Same set-only-never-unset pattern
    // as the m218 cross-ecosystem-edges bridge above — otherwise an
    // env-var-only invocation (`WAYBILL_PROJECT_DISCOVERY=root-only
    // waybill ...`, without the CLI flag) would be silently disabled.
    if args.project_discovery
        != crate::generate::project_discovery::ProjectDiscoveryMode::All
    {
        // SAFETY: see comment above.
        unsafe {
            std::env::set_var(
                "WAYBILL_PROJECT_DISCOVERY",
                args.project_discovery.to_string(),
            );
        }
    }

    // Milestone 108 US5: re-export `--fingerprints-rev` to the env so
    // the matcher's `LoadOptions::from_env()` sees the runtime
    // override (and ignores it if the operator didn't also pass the
    // opt-in flag — implicit-dependency warn handled inline below).
    if let Some(ref rev) = args.fingerprints_rev {
        if !args.fingerprints_corpus {
            tracing::warn!(
                rev = %rev,
                "--fingerprints-rev provided without --fingerprints-corpus; ignoring (bundled fallback will be used)",
            );
        } else {
            // SAFETY: see comment above — single-threaded.
            unsafe {
                std::env::set_var("WAYBILL_FINGERPRINTS_REV", rev);
            }
        }
    }

    // Milestone 173: propagate `--warm-go-cache` + `--warm-go-cache-
    // concurrency` to the Go reader via env vars (same convention as
    // WAYBILL_INCLUDE_VENDORED / WAYBILL_DEEP_HASH). The reader
    // consults these before invoking `warm_workspaces()`.
    //
    // Effective-mode reconciliation with `--offline` (FR-003): when
    // both `--offline` AND `--warm-go-cache=per-workspace` are set,
    // upgrade to `OfflineInhibited` and emit a warn-level log naming
    // the conflict. The mode is still surfaced via the
    // `waybill:go-cache-warming-mode` doc-scope annotation so the
    // operator's request is auditable.
    let effective_warm_mode: crate::scan_fs::package_db::golang::CacheWarmingMode = {
        use crate::scan_fs::package_db::golang::CacheWarmingMode;
        let cli_mode: CacheWarmingMode = args.warm_go_cache.into();
        if offline && matches!(cli_mode, CacheWarmingMode::PerWorkspace) {
            tracing::warn!(
                "--warm-go-cache=per-workspace ignored under --offline; effective mode = offline-inhibited (per FR-003)"
            );
            CacheWarmingMode::OfflineInhibited
        } else {
            cli_mode
        }
    };
    // SAFETY: single-threaded at this point in the scan-cmd lifecycle.
    unsafe {
        std::env::set_var(
            "WAYBILL_WARM_GO_CACHE_MODE",
            effective_warm_mode.as_wire_str(),
        );
        std::env::set_var(
            "WAYBILL_WARM_GO_CACHE_CONCURRENCY",
            args.warm_go_cache_concurrency.to_string(),
        );
    }

    // Milestone 052/part-3: the default is to include all lifecycle
    // scopes natively tagged. Readers receive `include_dev = true`
    // unconditionally (inlined as `true` at the two callsites
    // below); the centralized `exclude_scope` filter applied post-
    // resolution drops components per the user's opt-out. The
    // deprecated `--include-dev` CLI shim was removed in issue
    // #101 — see CHANGELOG `[Unreleased]` BREAKING. Per-reader
    // drop gates that still consume the parameter are dead code,
    // slated for removal in a follow-on refactor.
    // Milestone 004 US4: the flag is threaded all the way to
    // `scan_path` so the (future) BDB rpmdb reader can consume it.
    // Until the BDB reader lands (T064), the parameter rides through
    // as a no-op; default behaviour is unchanged from milestone 003.
    let _ = include_legacy_rpmdb;

    // Milestone 188 (#455) — `--helm-chart <path>` input resolution.
    // When `<path>` ends in `.tgz`, extract to a tempdir + descend into
    // the top-level chart directory. When `<path>` is a directory,
    // treat identically to `--path`. Held tempdir kept alive through
    // the whole scan.
    let mut _helm_chart_tempdir: Option<tempfile::TempDir> = None;
    if let Some(helm_chart_path) = args.helm_chart.clone() {
        let scan_path = resolve_helm_chart_input(&helm_chart_path, &mut _helm_chart_tempdir)?;
        args.path = Some(scan_path);
    }

    if args.path.is_none() && args.image.is_none() {
        anyhow::bail!("one of --path, --image, or --helm-chart is required");
    }

    // Milestone 215 — `--split` requires `--output-dir`. `clap`
    // already rejects `--split` + `--output`; here we enforce the
    // positive requirement so operators get a friendly diagnostic
    // pointing at the fix rather than a silent no-op.
    if args.split.is_some() && args.output_dir.is_none() {
        anyhow::bail!(
            "`--split` requires `--output-dir <dir>` — a single file cannot \
             hold N sub-SBOMs. Example:\n  \
             waybill sbom scan --path . --split --output-dir ./sboms/",
        );
    }

    // Milestone 221 US2a (feature 221-cisa-2026-elements-audit / FR-008a)
    // + milestone 222 US2b (feature 222-sigstore-keyless-signing / FR-008a):
    // `--sign-key` or `--sign` requires a durable `--output <file>`.
    // Combining with any `--output -` or `--output <fmt>=-` (stdout) is
    // rejected at parse time because signing without a persisted path
    // defeats the signature's purpose (nothing to hand a verifier) and
    // multiplexing signature bytes into stdout has no standard framing.
    if args.sign_key.is_some() || args.sign {
        if let Some(offender) = args.output.iter().find(|s| is_stdout_output(s)) {
            let which = if args.sign { "--sign" } else { "--sign-key" };
            anyhow::bail!(
                "{which} requires --output <file>; signing does not support \
                 stdout output because verifiers cannot access uncaptured \
                 signature bytes.\n  offending flag: --output {offender}\n  \
                 suggested fix: --output {}", suggest_non_stdout_path(offender),
            );
        }
    }

    // Resolve format dispatch BEFORE any scan work so argument errors
    // abort without having paid for a scan.
    let registry = SerializerRegistry::with_defaults();
    let plan = resolve_dispatch(&registry, &args.format, &args.output)?;

    // Milestone 777 US3 (FR-014 / FR-015 / FR-016) — the Sigstore
    // keyless path cannot currently produce a CycloneDX signature that
    // conforms to the CycloneDX 1.6 schema: it embeds a whole Sigstore
    // bundle as the signature value, where JSON Signature Format
    // expresses certificate and transparency-log material through
    // dedicated properties. Rather than emit a document that is invalid
    // while advertising itself as signed, refuse.
    //
    // Sited here, after dispatch resolution and before any scan work,
    // for two reasons: the resolved plan accounts for the default
    // format (omitting `--format` still requests CycloneDX), and
    // failing pre-scan means no partial output can exist even when
    // several formats were requested in one invocation (FR-015). The
    // m221 fail-close cleanup tracker downstream remains as defence in
    // depth rather than the mechanism relied upon.
    //
    // Scoped to CycloneDX only: SPDX signing is a detached sidecar with
    // no in-document signature slot and is unaffected (FR-016).
    if args.sign && plan.formats.iter().any(|f| f == DEFAULT_FORMAT) {
        anyhow::bail!(
            "--sign (Sigstore keyless) cannot currently produce a conformant \
             CycloneDX signature, so waybill will not emit one.\n  \
             The keyless path embeds a Sigstore bundle where the CycloneDX \
             signature format expects JSON Signature Format fields; the \
             resulting document does not validate against the CycloneDX 1.6 \
             schema and is reported as unsigned by conforming consumers.\n  \
             conformant alternative: --sign-key <PATH> (static ECDSA P-256 key)\n  \
             or request a non-CycloneDX format, e.g. --format spdx-2.3-json, \
             where keyless signing emits a detached sidecar and is unaffected.",
        );
    }

    // Milestone 186 (#442) — OCI Referrers API SBOM discovery.
    //
    // FR-011 input-type guard: the `--sbom-source` flag applies ONLY to
    // registry-pull scans. Reject with an actionable error when combined
    // with `--path` (filesystem scan) or a local tarball path.
    if matches!(
        args.sbom_source,
        SbomSourceMode::Referrer | SbomSourceMode::Either
    ) {
        if args.path.is_some() {
            anyhow::bail!(
                "--sbom-source {mode} is only valid for registry-pull scans (--image <oci-ref>). \
                 Use --sbom-source scan (or omit) to scan a local tarball or filesystem path.",
                mode = sbom_source_mode_wire_str(args.sbom_source),
            );
        }
        if let Some(archive) = args.image.as_ref() {
            if archive.is_file() {
                anyhow::bail!(
                    "--sbom-source {mode} is only valid for registry-pull scans (--image <oci-ref>). \
                     Use --sbom-source scan (or omit) to scan a local tarball or filesystem path.",
                    mode = sbom_source_mode_wire_str(args.sbom_source),
                );
            }
        }
    }

    // FR-002 / US1 / US2 dispatch — attempt the Referrers-API path when the
    // operator opted in via `--sbom-source referrer|either` AND the input is
    // a registry OCI reference. On success, write the referrer bytes verbatim
    // to the resolved output path + emit the FR-007 audit-log line + exit.
    // On fall-through under `Either`, continue to the existing scan pipeline.
    // On fall-through under `Referrer`, bail with an actionable error.
    if matches!(
        args.sbom_source,
        SbomSourceMode::Referrer | SbomSourceMode::Either
    ) {
        #[cfg(feature = "oci-registry")]
        {
            if let Some(image_arg) = args.image.as_ref() {
                let arg_str = image_arg.to_str().context(
                    "--image argument is not valid UTF-8 — required for --sbom-source referrer|either OCI ref parsing",
                )?;
                // Skip if the arg happens to be a local file — the FR-011
                // guard above already rejects this, but a defensive re-check
                // preserves the invariant if the guard is refactored.
                let archive_path = std::path::Path::new(arg_str);
                if !archive_path.is_file() {
                    let tls_config = scan_fs::oci_pull::RegistryTlsConfig::from_args(
                        &args.insecure_registry,
                        &args.registry_ca_cert,
                        args.insecure_tls_skip_verify,
                    )?;
                    let max_bytes = scan_fs::oci_pull::resolve_referrer_max_bytes();
                    let requested: Vec<&str> =
                        plan.formats.iter().map(|s| s.as_str()).collect();
                    let outcome = scan_fs::oci_pull::try_fetch_referrer_sbom(
                        arg_str,
                        args.image_platform.as_deref(),
                        args.registry_credentials_dir.as_deref(),
                        &tls_config,
                        &requested,
                        max_bytes,
                    )
                    .await;
                    match (outcome, args.sbom_source) {
                        (Ok(Some(sbom)), _) => {
                            // Resolved output path for the FIRST requested format.
                            let first_fmt = plan.formats.first().ok_or_else(|| {
                                anyhow::anyhow!("no --format resolved for SBOM referrer emission")
                            })?;
                            let output_path = plan
                                .overrides
                                .get(first_fmt)
                                .cloned()
                                .unwrap_or_else(|| {
                                    let default_name = registry
                                        .get(first_fmt)
                                        .map(|s| s.default_filename())
                                        .unwrap_or("waybill.sbom");
                                    std::path::PathBuf::from(default_name)
                                });
                            std::fs::write(&output_path, &sbom.bytes).with_context(|| {
                                format!(
                                    "writing SBOM referrer bytes to {}",
                                    output_path.display()
                                )
                            })?;
                            // FR-007 / SC-005 audit log — operators consuming
                            // waybill logs identify referrer-sourced emissions
                            // from log content alone. Keys named to match the
                            // strings asserted by the m186 integration tests.
                            tracing::info!(
                                image = %arg_str,
                                sbom_source = "referrer",
                                descriptor_digest = %sbom.descriptor_digest,
                                media_type = %sbom.media_type,
                                output_path = %output_path.display(),
                                bytes = sbom.bytes.len(),
                                "emitted SBOM from OCI Referrers API"
                            );
                            // Format-mismatch WARN: the operator requested a
                            // specific `--format` but the referrer we picked
                            // is a different media type (per FR-004 edge case).
                            if let Some(expected_mt) =
                                referrer_media_type_for_format(first_fmt)
                            {
                                if expected_mt != sbom.media_type {
                                    tracing::warn!(
                                        image = %arg_str,
                                        requested_format = %first_fmt,
                                        got_media_type = %sbom.media_type,
                                        "SBOM referrer emitted with media type differing from --format request (byte-identity preserved; consider --sbom-source scan or --sbom-source either for transcoded output — deferred to a follow-up milestone)"
                                    );
                                }
                            }
                            return Ok(());
                        }
                        (Ok(None), SbomSourceMode::Referrer) => {
                            anyhow::bail!(
                                "no matching SBOM referrer found for {arg_str} on registry \
                                 (or registry does not support the OCI Referrers API HTTP 404). \
                                 Use --sbom-source scan or --sbom-source either to scan the image bytes instead."
                            );
                        }
                        (Err(e), SbomSourceMode::Referrer) => {
                            return Err(e).with_context(|| {
                                format!("SBOM referrer fetch failed for {arg_str} under --sbom-source referrer")
                            });
                        }
                        (Ok(None), SbomSourceMode::Either) => {
                            tracing::info!(
                                image = %arg_str,
                                "no matching SBOM referrer found; falling through to scan"
                            );
                            // fall through to scan pipeline
                        }
                        (Err(e), SbomSourceMode::Either) => {
                            tracing::warn!(
                                image = %arg_str,
                                error = %e,
                                "SBOM referrer fetch failed under --sbom-source either; falling through to scan"
                            );
                            // fall through to scan pipeline
                        }
                        (_, SbomSourceMode::Scan) => {
                            // unreachable — outer `matches!` gate excludes Scan
                            unreachable!("SbomSourceMode::Scan handled by outer match")
                        }
                    }
                }
            }
        }
        #[cfg(not(feature = "oci-registry"))]
        {
            anyhow::bail!(
                "--sbom-source referrer|either requires the `oci-registry` Cargo feature (on by default). \
                 This build was compiled with --no-default-features. Rebuild with the default feature set."
            );
        }
    }

    // FR-002 / research.md §R2: when the deprecated SPDX 3 alias is
    // in the resolved format list, print a two-line stderr notice
    // (deprecation directive + shape-change advisory) exactly once
    // per invocation. Suppress with
    // `WAYBILL_NO_DEPRECATION_NOTICE=<anything>` so CI logs of
    // pipelines on a controlled migration don't drown in repeats.
    // Bytes emitted are unaffected by this flag.
    if plan.formats.iter().any(|f| f == SPDX_3_DEPRECATED_ALIAS)
        && std::env::var_os(NO_DEPRECATION_NOTICE_ENV).is_none()
    {
        eprintln!(
            "warning: --format {SPDX_3_DEPRECATED_ALIAS} is deprecated; use --format spdx-3-json instead."
        );
        eprintln!(
            "note: in this release the alias produces full-coverage SPDX 3 output across all 9 ecosystems — pre-011 releases of this alias emitted an npm-only stub. If your pipeline asserted byte-equality against the milestone-010 stub shape, those assertions will need updating."
        );
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
    // Hold any OCI-pull tempdir alive through the `extract` call.
    // Dropped immediately after `extract` finishes — the tarball
    // bytes have been read by then and the rootfs lives in its
    // own tempdir.
    // OCI-pull tempdir holder; same lifetime as the docker-save
    // tempdir below — both keep the on-disk tarball alive through the
    // `extract` call further down. Held in an `Option` so the
    // docker-save and remote-pull branches can both populate it
    // without conflict.
    let mut _image_tempdir: Option<tempfile::TempDir> = None;
    // Milestone 206 (#440) — track which --image-src won the
    // dispatch, so the C124 `waybill:image-source` annotation
    // can be emitted (conditional per FR-005 byte-identity).
    let mut selected_image_source: Option<ImageSource> = None;

    let (root_path, target_name, generation_context, auto_codename, _extracted) =
        if let Some(archive) = args.image.as_ref() {
            // `--image` accepts either an on-disk tarball OR an OCI
            // image reference. Tarballs are loaded directly. References
            // are resolved through one or more sources (`--image-src`)
            // — local docker daemon first by default, then registry
            // pull (milestone 044 commit 1).
            let archive_path: std::path::PathBuf = if archive.is_file() {
                // `--image-platform` is registry-pull-only; for a
                // pre-extracted tarball the platform is fixed by
                // whatever `docker save` already wrote, so the flag
                // is meaningless. Reject upfront so users don't get
                // a silent ignore.
                if args.image_platform.is_some() {
                    anyhow::bail!(
                        "--image-platform only applies to registry image references, \
                         not pre-extracted tarballs (--image {} resolved to an existing file).",
                        archive.display()
                    );
                }
                archive.clone()
            } else {
                let arg_str = archive.to_str().context(
                    "--image argument is not valid UTF-8 — required for OCI ref parsing",
                )?;
                resolve_image_ref(arg_str, &args, &mut _image_tempdir, &mut selected_image_source)
                    .await?
            };
            tracing::info!(archive = %archive_path.display(), "extracting docker image");
            let extract_mode = if args.fast_container_extract {
                // Clap `requires = "no_deep_hash"` guarantees pairing.
                scan_fs::docker_image::ExtractMode::OsPackageMetadataOnly
            } else {
                scan_fs::docker_image::ExtractMode::Full
            };
            let extracted = scan_fs::docker_image::extract(&archive_path, extract_mode)?;
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
    // Milestone 665 T010 (contract C3): FR-009 diagnostic. Emit an
    // INFO log when the operator opted out of binary-content probing
    // via `--no-binary-scan=<mode>` (CLI or env), naming the affected
    // reader(s) so the choice is visible in scan logs without an
    // SBOM diff.
    if let Some(mode) = args.no_binary_scan {
        let (mode_str, affected) = match mode {
            BinaryScanMode::Go => (
                mode.as_annotation_value(),
                "go_binary reader (statically-linked Go BuildInfo probing)",
            ),
            BinaryScanMode::All => (
                mode.as_annotation_value(),
                "entire binary-scanning tier (go_binary reader + m104 role \
                 classification + linkage extraction + m099 symbol fingerprinting)",
            ),
        };
        tracing::info!(
            mode = mode_str,
            "--no-binary-scan={} — skipping {}",
            mode_str,
            affected,
        );
        // Issue #781 — `=go` is deprecated as a perf lever. The
        // go_binary reader now short-circuits on non-binaries via
        // a magic-byte prefilter, so the default path is already
        // fast on source-heavy trees. The flag still works as a
        // component filter for operators who don't want
        // `pkg:golang/*` in their SBOM, but that's a component-scope
        // concern; nudge them toward `=all` if they wanted the perf.
        if matches!(mode, BinaryScanMode::Go) {
            tracing::warn!(
                "--no-binary-scan=go is deprecated as a perf lever \
                 (#781 makes the default path fast on non-Go trees). \
                 The flag still works as a Go-component filter; use \
                 --no-binary-scan=all if your goal is to skip the \
                 entire binary-scanning tier.",
            );
        }
    }
    let scan_fs::ScanResult {
        mut components,
        mut relationships,
        complete_ecosystems,
        os_release_missing_fields,
        go_transitive_coverage,
        go_transitive_fallback_count,
        go_cache_warming,
        go_workspace_mode,
        go_toolchains_detected,
        cross_ecosystem_edges_report,
        helm_extraction_mode,
        gradle_scan_summary,
        scan_target_coord,
        divergence_records,
        no_binary_scan_mode,
    } = scan_fs::scan_path(

        &root_path,
        effective_codename,
        args.max_file_size,
        !args.no_package_db,
        !args.no_deep_hash,
        true, // include_dev — see comment above the scan_path call site
        include_legacy_rpmdb,
        scan_mode,
        effective_include_declared_deps,
        // Scan-target filter: the Maven walker uses this to skip
        // emitting the scan target's own primary coord as a component
        // (it represents the SBOM subject, not a dependency). See
        // `maven::read_with_claims` and docs/design-notes.md "Scan
        // target identity" for rationale.
        Some(&target_name),
        // Milestone 144: pass `--max-rpm-bytes` + `--rpm-distro` through
        // to the rpm-file reader. `scan_path` sets the corresponding
        // env vars before calling `package_db::read_all`, which builds
        // the per-scan `RpmReaderConfig` from them.
        args.max_rpm_bytes,
        args.rpm_distro.as_deref(),
        &exclude_set,
        args.no_binary_scan,
    )
    .with_context(|| format!("scan failed for {}", root_path.display()))?;

    // Milestone 113 FR-014 / Constitution Principle X: when any
    // exclusion entry is active, install its snapshot via the
    // exclude_path thread-local so the CDX/SPDX 2.3/SPDX 3 metadata
    // emitters can pick it up and emit `waybill:exclude-path` at
    // envelope level. The guard MUST outlive every emitter call
    // below so successive in-process scans (e.g. integration tests)
    // never leak state.
    let _exclude_path_guard = if !exclude_set.is_empty() {
        Some(crate::scan_fs::package_db::exclude_path::install_annotation(
            exclude_set.as_normalized_strings(),
        ))
    } else {
        None
    };
    // Milestone 118 (#343 / FR-010) — when --exclude-path had ≥1 entry
    // in effect, surface the per-scan summary so operators can see how
    // many entries applied and how many directories were suppressed
    // without paging through WAYBILL_LOG=debug output. Per-walker debug
    // events emit centrally from `safe_walk` since milestone 114.
    // When the set is empty, preserve the pre-118 two-field shape
    // byte-identically (FR-010 emission gating).
    if !exclude_set.is_empty() {
        tracing::info!(
            components = components.len(),
            relationships = relationships.len(),
            excluded_entries = exclude_set.entries().len(),
            excluded_literals = exclude_set.count_literals(),
            excluded_patterns = exclude_set.count_patterns(),
            suppressed_dirs = exclude_set
                .suppressed_dirs
                .load(std::sync::atomic::Ordering::Relaxed),
            "scan complete"
        );
    } else {
        tracing::info!(
            components = components.len(),
            relationships = relationships.len(),
            "scan complete"
        );
    }

    // Milestone 127 FR-007 — surface a warning when the root-selection
    // heuristic fell through past at least one detected main-module.
    // The warning names the picked subject AND the loser main-modules'
    // PURLs so operators can pass `--root-name`/`--root-purl-type`
    // for deterministic control. Gated on `losers.is_empty() == false`
    // (matches the FR-006 annotation emission gate).
    {
        let root_override_tmp = crate::generate::RootComponentOverride {
            name: args.root_name.clone(),
            version: args.root_version.clone(),
            purl_type: args.root_purl_type.clone(),
            omit_purl: args.no_root_purl,
            // Issue #359 — the early root-selection helper above runs
            // before the full RootComponentOverride is constructed.
            // Pass the same #359 fields so the selector treats
            // --root-purl identically to the final override.
            full_purl: args.root_purl.clone(),
            full_purl_name: None,
            full_purl_version: None,
        };
        let selection = crate::generate::root_selector::select_root(
            &components,
            &root_override_tmp,
            scan_target_coord.as_ref(),
            &target_name,
            "0.0.0",
        );
        if let Some(h) = selection.heuristic {
            if !selection.losers.is_empty() {
                let loser_strs: Vec<String> = selection
                    .losers
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect();
                let selected_str = match &selection.subject {
                    crate::generate::root_selector::ResolvedRootSubject::MainModule(idx) => {
                        components
                            .get(*idx)
                            .map(|c| c.purl.as_str().to_string())
                            .unwrap_or_default()
                    }
                    crate::generate::root_selector::ResolvedRootSubject::MavenCoord => {
                        scan_target_coord
                            .as_ref()
                            .map(|c| {
                                format!(
                                    "pkg:maven/{}/{}@{}",
                                    c.group, c.artifact, c.version
                                )
                            })
                            .unwrap_or_default()
                    }
                    crate::generate::root_selector::ResolvedRootSubject::SyntheticPlaceholder {
                        name,
                        version,
                    } => format!("pkg:generic/{name}@{version}"),
                    crate::generate::root_selector::ResolvedRootSubject::OperatorOverride => {
                        String::new()
                    }
                };
                tracing::warn!(
                    selected = %selected_str,
                    losers = ?loser_strs,
                    heuristic = h.name(),
                    confidence = h.confidence(),
                    hint = "pass --root-name and --root-purl-type to override",
                    "root-component selected via heuristic; operator override recommended for deterministic identity"
                );
            }
        }
    }

    // Enrichment source control: resolve which sources are enabled.
    // `--offline` is handled by each enrichment source's internal
    // short-circuit (they log "offline, skipping" themselves), so we
    // don't need to gate here — but we avoid emitting misleading
    // "skipped (disabled by flags)" messages when the operative cause
    // is offline mode.
    let enrich_cfg = resolve_enrich_sources(&args);

    // Milestone 207 (#596): FR-006 migration signal. When the
    // operator uses the aggregate `--no-deps-dev` flag WITHOUT any
    // fine-grained escape hatch, emit a one-shot INFO log line
    // explaining the m207 semantic change + linking to the escape
    // hatch. Fine-grained-aware operators (who also set
    // `--no-deps-dev-license` or `--no-deps-dev-graph`) are NOT
    // spammed — they already know what they're doing.
    if args.no_deps_dev && !args.no_deps_dev_license && !args.no_deps_dev_graph {
        tracing::info!(
            "--no-deps-dev now disables ALL deps.dev enrichment paths \
             (m207 aggregate semantic per #596). For the pre-m207 \"license \
             only\" behavior, use --no-deps-dev-license instead."
        );
    }

    // deps.dev enrichment runs after the local scan so it only sees the
    // deduped component set. Components in unsupported ecosystems
    // (deb/apk/generic) are skipped silently inside the enrichment;
    // offline mode turns the whole pass into a no-op. Failures are
    // warnings, not errors — the scan still produces a valid SBOM if
    // deps.dev is unreachable.
    let deps_dev_client = DepsDevClient::new(std::time::Duration::from_secs(5));
    // Milestone 776: `enrich_components` now also maps the deps.dev
    // `links[]` array onto component externalReferences and reports the
    // links it skipped. The skip counts are carried to the FR-014a
    // summary emitted after the component set stops changing — they
    // cannot be recovered later because skips never reach the document.
    let mut m776_skips = crate::enrich::depsdev_source::LinkMappingSkips::default();
    if enrich_cfg.deps_dev {
        let deps_dev_source = DepsDevSource::new(deps_dev_client.clone(), offline);
        let (enriched, skips) = enrich_components(&deps_dev_source, &mut components).await;
        m776_skips = skips;
        if enriched > 0 {
            tracing::info!(enriched, "deps.dev added licenses to components");
        }
    } else if !offline {
        tracing::info!("deps.dev license enrichment skipped (disabled by flags)");
    }

    // ClearlyDefined enrichment runs after deps.dev and populates each
    // component's `concluded_licenses` with CD's curated SPDX
    // expression. Fed by the same `--offline` flag — a no-op when set.
    // CD's coverage is good for npm / cargo / gem / pypi / maven /
    // golang and shaky elsewhere; unsupported ecosystems are skipped
    // silently inside the source.
    if enrich_cfg.clearly_defined {
        let cd_source = ClearlyDefinedSource::new(offline);
        let cd_enriched = cd_enrich_components(&cd_source, &mut components).await;
        if cd_enriched > 0 {
            tracing::info!(
                cd_enriched,
                "ClearlyDefined added concluded licenses to components"
            );
        }
    } else if !offline {
        tracing::info!("ClearlyDefined enrichment skipped (disabled by flags)");
    }

    // deps.dev transitive dep-graph enrichment fills in edges the
    // local scan couldn't produce — shaded-JAR transitives, cold-
    // cache scans, BOM-declared deps. The response tree is merged
    // into the running component set with `source_type =
    // "declared-not-cached"` on any coord not already observed
    // locally; local versions win when deps.dev reports a different
    // version for the same (group, artifact) pair.
    if enrich_cfg.deps_dev_graph {
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
    } else if !offline {
        tracing::info!("deps.dev dep-graph enrichment skipped (disabled by flags)");
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

    // Milestone 191 (#560): second-pass reconciliation, mirroring the
    // scan_fs/mod.rs:807 site. Post-dedup + post-enrichment: any design-
    // tier components that survived the deduplicate() fold pass are now
    // matched against source-tier siblings. Rewrites Relationship edges.
    components = crate::resolve::reconciler::reconcile_design_source_tiers(
        components,
        &mut relationships,
    );

    // Milestone 052/part-3: apply the `--exclude-scope` opt-out
    // filter as the final step before serialization. Drops
    // components whose lifecycle_scope matches any element in the
    // user's exclude list, plus any dependency edges referencing
    // dropped components. `Runtime` is never excluded (clap rejects
    // it at parse time via the ExcludeScopeArg enum). Default
    // behavior (empty exclude_scope vec) is no-op: emit all scopes.
    if !exclude_scope.is_empty() {
        let exclude_set: std::collections::HashSet<waybill_common::resolution::LifecycleScope> =
            exclude_scope.iter().copied().collect();
        let pre_filter_count = components.len();
        let dropped_purls: std::collections::HashSet<String> = components
            .iter()
            .filter(|c| {
                c.lifecycle_scope
                    .is_some_and(|s| exclude_set.contains(&s))
            })
            .map(|c| c.purl.as_str().to_string())
            .collect();
        components.retain(|c| !dropped_purls.contains(c.purl.as_str()));
        relationships.retain(|r| {
            !dropped_purls.contains(&r.from) && !dropped_purls.contains(&r.to)
        });
        let dropped = pre_filter_count.saturating_sub(components.len());
        if dropped > 0 {
            tracing::info!(
                dropped,
                exclude_scope = ?exclude_scope,
                "applied --exclude-scope filter",
            );
        }
    }

    // Milestone 232 (#660): `--tier=<mode>` output-filter flag.
    // Runs AFTER --exclude-scope and BEFORE format-builder dispatch
    // (SC-004: format builders' internal graph-completeness passes
    // must observe the filtered slice). Sibling to the --exclude-scope
    // filter above; same retain-on-predicate + drop-dangling-edges
    // shape. See `specs/232-tier-filter-flag/data-model.md § New
    // helper` for the FR-003/FR-004/FR-005/FR-006/FR-008 contract.
    apply_tier_filter(&mut components, &mut relationships, args.tier);

    // Milestone 111 (issue #225 Option A): assemble the operator's
    // `--pkg-alias` declarations into a deterministic AliasMap. CLI-
    // supplied flags are concatenated with `WAYBILL_PKG_ALIAS` env-var
    // entries; conflicts (same LHS, different RHS) abort the scan.
    let pkg_alias_map = build_pkg_alias_map(&args)?;

    // FR-010: warn when `--pkg-alias` was supplied without
    // `--bind-to-source`. The alias has no effect (binding is the only
    // consumer); the warning makes the no-op explicit so operators
    // don't silently miss the intended binding rewrite.
    if !pkg_alias_map.is_empty() && args.bind_to_source.is_none() {
        tracing::warn!(
            count = pkg_alias_map.len(),
            "--pkg-alias declared but --bind-to-source was not supplied; \
             the aliases have no effect on this scan and will not appear \
             in the emitted SBOM. Add --bind-to-source <SOURCE_SBOM> to \
             enable cross-tier binding (milestone 072)."
        );
    }

    // Milestone 072 / T027: when `--bind-to-source <path>` is supplied,
    // resolve the source-tier SBOM and attach per-component
    // `waybill:source-document-binding` annotations to image-tier
    // components whose PURL has a counterpart in the source SBOM.
    // Per FR-011, failure to load the source SBOM aborts the scan.
    let bind_source_ctx: Option<waybill::binding::SourceSbomContext> = if let Some(
        ref source_sbom_path,
    ) = args.bind_to_source
    {
        let ctx = waybill::binding::SourceSbomContext::load(source_sbom_path).with_context(
            || {
                format!(
                    "failed to load --bind-to-source SBOM at {}",
                    source_sbom_path.display()
                )
            },
        )?;
        tracing::info!(
            source_sbom = %source_sbom_path.display(),
            source_purls = ctx.source_purls.len(),
            sha256 = %ctx.source_doc_id.sha256,
            "loaded --bind-to-source SBOM"
        );
        // Per the contract: only emit on non-source-tier SBOMs
        // (i.e., this scan must be `build` or `deployed`). For
        // `--image` scans the tier is `deployed`; for `--path` it's
        // typically `source` and we should NOT emit.
        let is_image_scan = args.image.is_some();
        if is_image_scan {
            let consumed = attach_bindings_to_components(
                &mut components,
                &ctx,
                &pkg_alias_map,
            );
            log_unused_pkg_aliases(&pkg_alias_map, &consumed);
        } else {
            tracing::warn!(
                "--bind-to-source supplied with --path; binding annotations only \
                 emit on image-tier (--image) scans per milestone 072. \
                 Source-tier components stay unmodified."
            );
        }
        Some(ctx)
    } else {
        None
    };

    // `trace_integrity` is a clean record: no eBPF ran, so there's nothing
    // to have overflowed or dropped. Milestone 212 audit (T007a): this
    // site is SCAN-MODE — no eBPF programs are loaded here, so
    // `ring_buffer_overflows: 0` is factually correct + FR-004 compliant.
    // Real-trace attestations flow through `waybill-cli/src/cli/scan.rs`
    // where the value comes from `counters::read_ring_buffer_drops`.
    let integrity = TraceIntegrity {
        ring_buffer_overflows: 0,
        events_dropped: 0,
        uprobe_attach_failures: vec![],
        kprobe_attach_failures: vec![],
        partial_captures: vec![],
        bloom_filter_capacity: 0,
        bloom_filter_false_positive_rate: 0.0,
        filter_categories_applied: vec![],
    };

    // Milestone 073: resolve identifiers — auto-detected
    // `repo:` (from git origin remote, 3-step fallback) on `--path`
    // scans, auto-detected `image:<registry>/<name>:<tag>@sha256:<digest>`
    // on `--image` scans, plus any manual flags
    // (`--repo` / `--git-ref` / `--image-id` / `--attestation` / `--id`).
    // Manual entries dedup against auto-detected by `(scheme, value)`
    // — manual wins, inheriting the auto-detected entry's position.
    // Order: auto-detected first, then manual in supply order
    // (per FR-009 / VR-008 / data-model.md).
    let auto_detected_id: Option<waybill::binding::identifiers::Identifier> =
        if args.image.is_some() {
            // Image-tier auto-detection — synthesize the canonical
            // `image:` form from the resolved-image fields.
            image_auto_identifier(_extracted.as_ref(), args.image.as_deref())
        } else {
            // Source-tier auto-detection — git-remote 3-step fallback.
            // Milestone 075 — `keep_credentials` boolean controls
            // userinfo sanitization (default: strip for security).
            waybill::binding::identifiers::auto_detect::auto_detect_repo_identifier(
                &root_path,
                args.keep_credentials_in_identifiers,
            )
        };
    let manual_identifiers = assemble_manual_identifiers(&args);
    let identifiers = waybill::binding::identifiers::resolve_identifiers(
        auto_detected_id.into_iter().collect(),
        &manual_identifiers,
    );

    // Milestone 080 — assemble user-supplied SBOM metadata from
    // `--creator` / `--annotator` / `--annotation-comment` /
    // `--metadata-comment` / `--scan-target-name` / `--metadata-file`
    // flags. Per research §3, do the early UX-friendly strict-
    // interleaving check on the raw argv BEFORE the flat clap
    // collection is consumed by `merge_file_and_flags`, so the
    // operator gets a crisp pairing-mistake diagnostic rather than a
    // count-mismatch one.
    let argv: Vec<String> = std::env::args().collect();
    if let Err(diag) =
        waybill::binding::user_metadata::validate_annotator_pair_interleaving(&argv)
    {
        anyhow::bail!(diag);
    }
    let metadata_file = match args.metadata_file.as_deref() {
        Some(p) => Some(
            waybill::binding::user_metadata::load_metadata_file(p)
                .map_err(|e| anyhow::anyhow!(e))?,
        ),
        None => None,
    };
    let user_metadata = waybill::binding::user_metadata::merge_file_and_flags(
        metadata_file,
        args.creator.clone(),
        args.annotator.clone(),
        args.annotation_comment.clone(),
        args.metadata_comment.clone(),
        args.scan_target_name.clone(),
        scan_created_timestamp(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    // Stderr warning on the multi-Organization edge case for CDX
    // (research §1: CDX `metadata.manufacturer` is single-valued; 2nd+
    // Organization creators route to bom.annotations[]).
    let org_count = user_metadata
        .creators
        .iter()
        .filter(|c| {
            matches!(
                c.kind,
                waybill::binding::user_metadata::CreatorKind::Organization
            )
        })
        .count();
    if org_count > 1 {
        eprintln!(
            "warning: {} `--creator \"Organization: ...\"` entries supplied; \
             CDX 1.6 permits exactly one `metadata.manufacturer` so the \
             first Organization creator populates that slot and the rest \
             are routed to `bom.annotations[]`.",
            org_count
        );
    }
    if user_metadata.scan_target_name.is_some() && args.root_name.is_some() {
        eprintln!(
            "warning: --root-name overrides --scan-target-name for CDX \
             metadata.component.name; SPDX 2.3 / SPDX 3 honor both \
             independently."
        );
    }

    // Milestone 119 (#326) — `--supplement-cdx <PATH>` opt-in: parse
    // the operator-supplied supplement BEFORE the artifact bundle is
    // constructed; merge it into the scanner-discovered stream so
    // every format builder sees the same combined view; install the
    // merge outcome's provenance + services list on the supplement
    // module's thread-local so per-format metadata emitters can pick
    // them up without churning every ScanArtifacts call site.
    //
    // Parse / I/O / schema-validation failures here exit non-zero
    // BEFORE any emitter runs per FR-002 / SC-005. When the flag is
    // absent the merge is skipped entirely, preserving byte-identity
    // with pre-119 waybill output per FR-013 / SC-006.
    let _supplement_guard = if let Some(path) = supplement_cdx.as_ref() {
        let supp = crate::supplement::load(path).with_context(|| {
            format!(
                "loading supplement file `{}` (see --supplement-cdx)",
                path.display()
            )
        })?;
        let outcome =
            crate::supplement::merge(components, relationships, supp).with_context(
                || {
                    format!(
                        "merging supplement file `{}` into scanner output",
                        path.display()
                    )
                },
            )?;
        components = outcome.components;
        relationships = outcome.dependencies;
        Some(crate::supplement::install(
            outcome.supplement_provenance,
            outcome.services,
        ))
    } else {
        None
    };

    // Milestone 133 US2.2 (FR-013): stamp `waybill:layer-digest` on every
    // component whose `evidence.source_file_paths[0]` matches a path the
    // OCI layer extractor recorded. No-op for non-image scans (path map
    // is `None`). Must run AFTER component resolution + all annotations
    // + path normalization (PR US2.1) so the lookup-keys agree with the
    // layer-map keys (both rootfs-relative, no leading `/`).
    scan_fs::tag_components_with_layer_digest(
        &mut components,
        _extracted.as_ref().map(|e| &e.layer_path_map),
    );

    // Milestone 176 (US1 / FR-001): stamp per-component
    // `waybill:workspace-member` annotation on every component whose
    // evidence.source_file_paths yields a derivable workspace root.
    // Uses the canonicalized scan root so `path+file://<abs>` URI-form
    // source paths (pip/cargo/npm main-modules) can have their scan-
    // root prefix stripped to yield root-relative workspace paths.
    // File-tier components (m133) and any other component with no
    // derivable workspace omit the annotation per FR-002 / Q1. Runs
    // AFTER `tag_components_with_layer_digest` so both tag passes see
    // the same components slice.
    {
        let canonical_root = std::fs::canonicalize(&root_path)
            .unwrap_or_else(|_| root_path.clone());
        scan_fs::tag_components_with_workspace_member(&mut components, &canonical_root);
    }

    // Milestone 220: post-discovery scope filter. Runs AFTER
    // `tag_components_with_workspace_member` so the FR-004 belt-and-
    // suspenders annotation follow-up sees the workspace-member
    // signal populated. Under `All` mode this is a zero-op (returns
    // the slices verbatim; SC-005 byte-identity gate). Under
    // `RootOnly`/`Strict` the filter drops out-of-scope main-modules
    // + their unreachable transitive components. FR-008 empty-root
    // fallback: when the filter reports zero in-scope roots under
    // non-default mode, we WARN + reuse the pre-filter slices (i.e.,
    // treat as `All` for that scan) so the existing synthetic-
    // `pkg:generic/` root path fires cleanly; C140 is NOT emitted on
    // the fallback branch (`project_discovery_mode_for_artifacts`
    // stays `None`).
    let project_discovery_mode_for_artifacts:
        Option<crate::generate::project_discovery::ProjectDiscoveryMode> = {
        let mode = args.project_discovery;
        if mode == crate::generate::project_discovery::ProjectDiscoveryMode::All {
            None
        } else {
            let canonical_root = std::fs::canonicalize(&root_path)
                .unwrap_or_else(|_| root_path.clone());
            // Filter takes owned Vecs; swap out with placeholder,
            // run, then either commit or roll back on empty-root
            // fallback.
            let comps_owned = std::mem::take(&mut components);
            let rels_owned = std::mem::take(&mut relationships);
            let (out_c, out_r, report) =
                crate::generate::project_discovery::filter::apply_scope_filter(
                    comps_owned,
                    rels_owned,
                    mode,
                    &canonical_root,
                );
            if report.root_main_modules == 0 {
                // FR-008 fallback — zero root-level manifests found.
                // Re-run the filter with `All` to get the unfiltered
                // slices back (zero-op fast-path).
                tracing::warn!(
                    mode = %mode,
                    "scan: project-discovery=<mode> found zero root-level manifests; falling back to full-scope emission",
                );
                let (fc, fr, _) =
                    crate::generate::project_discovery::filter::apply_scope_filter(
                        out_c,
                        out_r,
                        crate::generate::project_discovery::ProjectDiscoveryMode::All,
                        &canonical_root,
                    );
                components = fc;
                relationships = fr;
                None
            } else {
                tracing::info!(
                    mode = %report.mode,
                    root_main_modules = report.root_main_modules,
                    workspace_members_followed = report.workspace_members_followed,
                    nested_projects_ignored = report.nested_projects_ignored,
                    "scan: project-discovery mode complete",
                );
                components = out_c;
                relationships = out_r;
                Some(mode)
            }
        }
    };

    // Issue #363 — operator-asserted license-concluded promotion. Runs
    // AFTER every external enricher (ClearlyDefined, deps.dev) so the
    // empty-concluded check correctly identifies components those
    // enrichers couldn't fill. Pre-existing concluded values from
    // enrichment ARE preserved (the apply fn skips populated entries).
    if args.conclude_licenses {
        let promoted = scan_fs::apply_operator_asserted_conclusions(&mut components);
        tracing::info!(
            promoted_components = promoted,
            "operator-asserted license-concluded promotion (per --conclude-licenses): \
             you assert the declared licenses have been reviewed."
        );
    }

    // Milestone 776 (FR-014a + FR-014b + SC-009a): source-provenance
    // reference summary.
    //
    // Emitted HERE, after every pass that can add or drop components,
    // rather than adjacent to the enrichment call. Between enrichment
    // and this point the component set is still mutated by
    // `deduplicate()`, `reconcile_design_source_tiers()`, a retain
    // drop pass, the supplement install, the layer-digest and
    // workspace-member tag passes, and the m220 scope filter — any of
    // which can remove a component carrying references. Counting
    // earlier would OVERCOUNT relative to the emitted document, which
    // SC-009a forbids. See specs/776-component-source-refs/research.md R9.
    //
    // Per-kind counts are derived by counting the final component set
    // directly, so the reported numbers cannot drift from the document
    // they describe. The skip counts come from enrichment because
    // skipped links never reach the document and cannot be recovered
    // by counting components.
    {
        let mut by_kind: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for c in components.iter() {
            for r in &c.external_references {
                *by_kind.entry(r.ref_type.as_str()).or_insert(0) += 1;
            }
        }
        let total: usize = by_kind.values().sum();
        let by_kind_str = by_kind
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::info!(
            total_references = total,
            by_kind = %by_kind_str,
            skipped_unmapped_label = m776_skips.unmapped_label,
            skipped_malformed_url = m776_skips.malformed_url,
            "source-provenance references emitted"
        );
    }

    // Milestone 133 US1.B (FR-002 + FR-015): file-tier emission for
    // unattributed content (custom binaries, vendored libraries with
    // no manifest, embedded archives). Runs AFTER every package /
    // binary / enrichment step so the FR-011 hybrid dedupe sees the
    // full claim set. Default `off` in US1.B — preserves pre-
    // milestone-133 byte-identity. US1.C flips the default to
    // `orphan`. `full` mode forwards an empty `DedupeIndex` so every
    // surviving content-shape match emits regardless of coverage.
    let file_inventory_mode = scan_fs::file_tier::FileInventoryMode::parse(&args.file_inventory)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--file-inventory expects one of: off, orphan, full, source-tree (got: {:?})",
                args.file_inventory
            )
        })?;
    // Milestone 671 T009: cross-arg validation + composition. The
    // companion flag `--file-inventory-source-shapes` is ONLY
    // meaningful under `--file-inventory=source-tree` (FR-001). When
    // both are present, combine into a single
    // `FileInventoryMode::SourceTree { restriction: Some(set) }`; if
    // the companion flag is present under any other mode, fail loudly.
    let file_inventory_mode = match (
        file_inventory_mode,
        args.file_inventory_source_shapes.take(),
    ) {
        (scan_fs::file_tier::FileInventoryMode::SourceTree { .. }, Some(set)) => {
            scan_fs::file_tier::FileInventoryMode::SourceTree {
                restriction: Some(set),
            }
        }
        (scan_fs::file_tier::FileInventoryMode::SourceTree { .. }, None) => {
            scan_fs::file_tier::FileInventoryMode::SourceTree { restriction: None }
        }
        (_, Some(_)) => {
            return Err(anyhow::anyhow!(
                "--file-inventory-source-shapes is only meaningful when \
                 --file-inventory=source-tree (got: --file-inventory={:?}). \
                 See specs/671-file-tier-cpython/contracts/source_shape_restriction.md.",
                args.file_inventory
            ));
        }
        (other, None) => other,
    };
    // Milestone 133 US3: hoist `WalkerStats` so the per-format
    // document-level annotation emission paths can read the
    // diagnostic counters via `ScanArtifacts::file_inventory_stats`.
    let mut file_inventory_stats: Option<scan_fs::file_tier::walker::WalkerStats> = None;
    if file_inventory_mode != scan_fs::file_tier::FileInventoryMode::Off {
        // Milestone 133 US1.C: if the operator excluded the scan root
        // itself via `--exclude-path=<abs-root>`, every package-DB
        // reader emits zero components — the file-tier walker MUST
        // honor the same contract. Pre-strip the leading `/` so the
        // absolute root matches the leading-`/`-stripped literal in
        // the exclusion set.
        let root_excluded = {
            let canon =
                std::fs::canonicalize(&root_path).unwrap_or_else(|_| root_path.clone());
            let s = canon.to_string_lossy().into_owned();
            let stripped = s.trim_start_matches('/');
            !exclude_set.is_empty() && exclude_set.matches(stripped)
        };
        if root_excluded {
            tracing::info!(
                scan_root = %root_path.display(),
                "file-tier walker skipped: scan root is on --exclude-path"
            );
        } else {
        let exclusion_globs = scan_fs::file_tier::content_shape::build_orphan_exclusion_globs();
        let dedupe_index = match file_inventory_mode {
            scan_fs::file_tier::FileInventoryMode::Full => {
                // Full mode bypasses dedupe — caller wants every
                // content-shape-passing file regardless of coverage.
                scan_fs::file_tier::dedupe::DedupeIndex::default()
            }
            _ => scan_fs::file_tier::dedupe::DedupeIndex::build(&components),
        };
        // Milestone 671 T008: derive the source-tree-restriction
        // parameter from the effective mode. `SourceTree { restriction }`
        // → `Some(restriction.as_ref())`; every other mode → `None`
        // (default classifier behavior preserved).
        let source_tree_restriction: Option<
            Option<&scan_fs::file_tier::source_shape::SourceShapeSet>,
        > = match &file_inventory_mode {
            scan_fs::file_tier::FileInventoryMode::SourceTree { restriction } => {
                Some(restriction.as_ref())
            }
            _ => None,
        };
        let walker_cfg = scan_fs::file_tier::walker::WalkerConfig {
            size_limit_bytes: args.file_inventory_size_limit,
            exclusion_globs: &exclusion_globs,
            dedupe_index: &dedupe_index,
            exclude_set: &exclude_set,
            source_tree_restriction,
        };
        let (entries, stats) =
            scan_fs::file_tier::walker::walk_file_tier(&root_path, &walker_cfg);
        tracing::info!(
            file_tier_components = entries.len(),
            mode = ?file_inventory_mode,
            shape_skipped = stats.shape_skipped,
            dedupe_skipped = stats.dedupe_skipped,
            oversize_skipped = stats.oversize_skipped,
            special_skipped = stats.special_skipped,
            unreadable_skipped = stats.unreadable_skipped,
            "file-tier walker complete"
        );
        components.extend(entries.into_iter().map(|e| e.into_resolved_component()));
        file_inventory_stats = Some(stats);
        } // end `else` branch for !root_excluded
    }

    // Milestone 134 — aggregate divergent-PURL collision records
    // into a `CollisionsSummary` when at least one was detected.
    // `None` when empty so the document-scope annotation is
    // omitted entirely (FR-009).
    let collisions_summary: Option<waybill_common::divergence::CollisionsSummary> =
        if divergence_records.is_empty() {
            None
        } else {
            Some(waybill_common::divergence::CollisionsSummary::from_records(
                divergence_records.clone(),
            ))
        };

    // Milestone 167 (T011) — emit-time `waybill:orphan-reason`
    // classifier. Stamps per-component annotations on BFS-unreachable
    // Go/npm components per the extended C45 vocabulary + fires the
    // FR-008 grep-friendly log with per-code counters. Runs AFTER
    // every component-producing pass (package DBs, enrichment,
    // dedupe, supplement merge, file-tier walker) and BEFORE the
    // ScanArtifacts bundle is built so the mutation lands on the
    // shared `components` Vec every emitter (CDX / SPDX 2.3 / SPDX 3)
    // reads. The `waybill:orphan-reason` annotation flows through
    // the format emitters unchanged via the existing per-format
    // `extra_annotations` serialization (parity-catalog C45).
    //
    // Runs with a `RootComponentOverride::default()` placeholder for
    // classification purposes only: BFS-reachability of components
    // is over PURL keys, and override-active vs override-inactive
    // classification produces identical orphan sets because the
    // override only affects which main-module entries are dropped
    // from the emitted `components[]` (a per-format concern). The
    // actual `ScanArtifacts::root_override` below is built from the
    // operator's `--root-*` flags and is unaffected by this call.
    let _m167_orphan_reason_counts =
        crate::generate::orphan_reason::classify_orphans_pre_emit(
            &mut components,
            &relationships,
            &crate::generate::RootComponentOverride::default(),
            scan_target_coord.as_ref(),
            &target_name,
        );

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
        include_dev: true,
        include_hashes: !args.no_hashes,
        include_source_files: true, // path-pattern evidence is the whole value prop here
        // Milestone 221 US4 (feature 221-cisa-2026-elements-audit /
        // FR-013) — operator-supplied SBOM document version.
        // `None` when `--sbom-version` is unset (byte-identity path
        // per FR-009).
        sbom_version: args.sbom_version,
        scope_mode: if effective_include_declared_deps {
            crate::generate::ScopeMode::Manifest
        } else {
            crate::generate::ScopeMode::Artifact
        },
        // Milestone 160 (T034/T035): doc-scope Go-transitive coverage
        // signal for the C110/C111 annotations. Distinct from
        // graph-completeness per research.md R1.
        go_transitive_coverage: go_transitive_coverage.as_ref(),
        // Milestone 172: doc-scope Go step-5 fallback counter for the
        // C117 annotation. Sibling of coverage; Go-gated per FR-002.
        go_transitive_fallback_count,
        // Milestone 173: doc-scope Go cache-warming outcome for the
        // C118 (mode) + C119 (failed) annotations. Sibling of
        // coverage; Go-gated per FR-011.
        go_cache_warming: go_cache_warming.as_ref(),
        // Milestone 161 (T014): doc-scope Go-workspace-mode signal
        // for the C112 annotation.
        go_workspace_mode: go_workspace_mode.as_ref(),
        // Milestone 217 (waybill#631): doc-scope Go-toolchain-detected
        // signal for the C136 `waybill:go-toolchain-detected`
        // annotation. `None` when no Go toolchain was observed in the
        // scanned rootfs (byte-identity for non-Go and Go-project-only
        // scans; annotation absent).
        go_toolchains_detected: go_toolchains_detected.as_deref(),
        cross_ecosystem_edges_report: cross_ecosystem_edges_report.as_ref(),
        // Milestone 204 (#554): doc-scope helm image-extraction-mode
        // signal for the C123 annotation.
        helm_extraction_mode: helm_extraction_mode.as_ref(),
        gradle_scan_summary: gradle_scan_summary.as_ref(),
        // Milestone 665: propagate the operator's `--no-binary-scan=<MODE>`
        // choice so every emitter can attach the doc-scope
        // `waybill:binary-scan-suppressed=<mode>` annotation. `None` on
        // the default (unset) path preserves byte-identity per FR-003.
        no_binary_scan_mode,
        // Milestone 206 (#440): doc-scope image-source signal for
        // the C124 annotation. Conditional emission (podman-only)
        // preserves FR-005 byte-identity for docker/remote scans.
        image_source: selected_image_source.as_ref(),
        // Milestone 072 / T010-T014: when --bind-to-source was set
        // AND the scan target is image-tier, expose the source-doc
        // identifier so each format's metadata builder can emit the
        // standards-native cross-document reference.
        source_document_binding: bind_source_ctx
            .as_ref()
            .filter(|_| args.image.is_some())
            .map(|ctx| &ctx.source_doc_id),
        // Milestone 073: identifiers — populated by T013's
        // resolution pipeline before this struct is constructed.
        identifiers: &identifiers,
        // Milestone 076: per-component user-defined identifiers from
        // `--component-id <PURL>=<scheme>:<value>` flags. Threaded to
        // per-format emitters which match against `components[].purl`.
        component_identifiers: &args.component_id,
        file_inventory_stats: file_inventory_stats.as_ref(),
        // Milestone 133 US4 (Constitution Strict Boundary §5): the
        // mode label rides as `None` when the walker didn't run
        // (`off`), `Some("orphan")` for the default mode (silent
        // passthrough — no doc-level marker), and `Some("full")`
        // for the explicit override that triggers the marker.
        file_inventory_mode: match file_inventory_mode {
            scan_fs::file_tier::FileInventoryMode::Off => None,
            scan_fs::file_tier::FileInventoryMode::Orphan => Some("orphan"),
            scan_fs::file_tier::FileInventoryMode::Full => Some("full"),
            // Milestone 671 T005 placeholder: `source-tree` is a new
            // opt-in mode. Emits the same doc-level marker as `full`
            // in terms of triggering non-orphan-mode metadata; the
            // finer-grained C156 annotation carries mode+restriction
            // and is emitted separately by T010.
            scan_fs::file_tier::FileInventoryMode::SourceTree { .. } => Some("source-tree"),
        },
        // Milestone 671 T010 — projects the parsed `--file-inventory-
        // source-shapes` restriction (if any) into a sorted-lex list
        // consumed by the C156 doc-scope emission. `None` on every
        // non-source-tree path so pre-671 SBOMs remain byte-identical
        // (SC-005). Also `None` under source-tree without a companion
        // restriction — the emitter treats that as
        // `"restriction": null`.
        file_inventory_source_shapes: match &file_inventory_mode {
            scan_fs::file_tier::FileInventoryMode::SourceTree {
                restriction: Some(set),
            } => {
                // `BTreeSet<SourceShape>` iterates in enum-discriminant
                // order (grouped by language family, NOT lex). C156
                // wants a strictly lex-sorted `Array<String>` per
                // data-model.md §"C156 Constraints"; sort explicitly
                // after `as_str()` conversion.
                let mut v: Vec<String> = set
                    .iter()
                    .map(|s| s.as_str().to_string())
                    .collect();
                v.sort();
                Some(v)
            }
            _ => None,
        },
        // Milestone 077 + issue #359: operator-supplied overrides for
        // the root component's name + version + PURL. Constructed
        // from the `--root-name` / `--root-version` / `--root-purl-type`
        // / `--no-root-purl` flags (milestone 077) plus the full-PURL
        // shortcut `--root-purl` (#359). The discrete flags +
        // `--root-purl` are clap-`conflicts_with` mutually exclusive so
        // only one branch is populated at any time.
        root_override: {
            let (full_purl, full_name, full_version) = match args.root_purl.as_deref() {
                Some(raw) => {
                    let parsed = waybill_common::types::purl::Purl::new(raw).expect(
                        "--root-purl already validated at clap parse time via validate_root_purl",
                    );
                    let name = match parsed.namespace() {
                        Some(ns) => format!("{ns}/{}", parsed.name()),
                        None => parsed.name().to_string(),
                    };
                    let version = parsed.version().unwrap_or("").to_string();
                    (Some(parsed.as_str().to_string()), Some(name), Some(version))
                }
                None => (None, None, None),
            };
            crate::generate::RootComponentOverride {
                name: args.root_name.clone(),
                version: args.root_version.clone(),
                purl_type: args.root_purl_type.clone(),
                omit_purl: args.no_root_purl,
                full_purl,
                full_purl_name: full_name,
                full_purl_version: full_version,
            }
        },
        // Milestone 149 (issue #151): opt-in flag to preserve the
        // manifest-derived main-module as a library entry when the
        // root-override flags above fire. Default OFF preserves
        // milestone-077 clean-replacement byte-identity (SC-002).
        preserve_manifest_main_module: args.preserve_manifest_main_module,
        // Milestone 080: user-provided SBOM metadata aggregated from
        // the new flags (--creator / --annotator / --annotation-comment
        // / --metadata-comment / --scan-target-name / --metadata-file).
        user_metadata: user_metadata.clone(),
        // Milestone 081: operator-asserted CISA SBOM Type from the
        // new --sbom-type flag. When set, all three formats'
        // document-level lifecycle aggregations collapse to a
        // single-element output reflecting the asserted type;
        // per-component `waybill:sbom-tier` annotations preserve
        // auto-detected values.
        sbom_type_override: args.sbom_type,
        // Issue #228: relationship-vocabulary compat flag (default
        // `full` preserves the milestone-052/part-2 typed
        // reversed-direction emission).
        spdx2_relationship_compat: args.spdx2_relationship_compat,
        // Milestone 134 — document-scope collisions summary built
        // from `divergence_records`. `None` when no divergence
        // detected (FR-009: no annotation emitted on clean scans).
        collisions_summary: collisions_summary.as_ref(),
        // Milestone 210 — scan-mode never populates the compiler-
        // pipeline field; that data comes from `waybill trace`
        // (eBPF-observed) and reaches the SBOM emitter via the
        // `sbom generate --attestation` code path. Preserving `None`
        // here per m208 defensive-default pattern.
        compiler_pipeline: None,
        // Milestone 220: document-scope project-discovery mode when
        // the scan ran under a non-default `--project-discovery` value.
        // `None` under default `All` mode OR under the FR-008 empty-
        // root fallback branch (SC-005 byte-identity gate).
        project_discovery_mode: project_discovery_mode_for_artifacts,
    };
    let output_cfg = OutputConfig {
        mikebom_version: crate::version::VERSION,
        created: scan_created_timestamp(),
        overrides: plan.overrides.clone(),
    };

    // Milestone 215 — `--split` fan-out. When set and at least one
    // workspace boundary is detected, emit one SBOM per subproject +
    // a `split-manifest.json` into `--output-dir`, then early-return.
    // Zero-boundary fallback (FR-009): `emit_split` returns
    // `Ok(false)` and we fall through to the pre-feature single-SBOM
    // emit below (WARN log already emitted).
    if let Some(mode) = args.split {
        let output_dir = args.output_dir.as_ref().expect(
            "--output-dir required when --split; validated at CLI parse",
        );
        let split_handled = crate::generate::split::emit_split(
            &artifacts,
            &plan.formats,
            &registry,
            output_dir,
            output_cfg.created,
            output_cfg.mikebom_version,
            &root_path,
            mode,
        )?;
        if split_handled {
            if args.json {
                let ctx_str = match generation_context {
                    GenerationContext::FilesystemScan => "filesystem-scan",
                    GenerationContext::ContainerImageScan => "container-image-scan",
                    GenerationContext::BuildTimeTrace => "build-time-trace",
                };
                let summary = serde_json::json!({
                    "split_output_dir": output_dir.to_string_lossy(),
                    "split_manifest": output_dir.join("split-manifest.json").to_string_lossy(),
                    "components": components.len(),
                    "relationships": relationships.len(),
                    "scanned_root": root_path.to_string_lossy(),
                    "target_name": target_name,
                    "generation_context": ctx_str,
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
            return Ok(());
        }
        // else: zero-boundary fallback — fall through to normal emit.
    }

    // Milestone 221 US2a + milestone 222 US2b — construct the signing
    // mode from CLI args. Kept out of `OutputConfig` because signing is
    // a post-serialize concern that doesn't affect the emit code path;
    // passing it separately preserves the OutputConfig contract from
    // m011+. `--sign` and `--sign-key` are mutually exclusive (enforced
    // by clap `conflicts_with = "sign_key"` on the `--sign` flag), so
    // the two branches cannot both fire.
    let signing_mode = if args.sign {
        crate::sbom::signer::SigningMode::Keyless {
            fulcio_url: args.fulcio_url.clone(),
            rekor_url: args.rekor_url.clone(),
            rekor_timeout: std::time::Duration::from_secs(args.rekor_timeout_secs),
        }
    } else {
        match &args.sign_key {
            Some(path) => crate::sbom::signer::SigningMode::StaticKey {
                key_ref: path.clone(),
                passphrase_env: args
                    .sign_key_passphrase_env
                    .clone()
                    .unwrap_or_else(|| "WAYBILL_SIGN_KEY_PASSPHRASE".to_string()),
            },
            None => crate::sbom::signer::SigningMode::Unsigned,
        }
    };

    // Milestone 221 US2a (FR-009a): fail-close cleanup tracker. Every
    // file we write goes into this list; on any signing failure we
    // unlink each one before propagating the error, so consumers never
    // see a partial `--output <path>` file.
    let mut written_files: Vec<PathBuf> = Vec::new();

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
            // Milestone 221 US2a — inject the signing hook at the
            // write boundary. Three cases:
            //   (a) Unsigned mode: write bytes as-emitted (FR-009
            //       byte-identity guarantee).
            //   (b) CDX + signing enabled: parse → in-place JSF sign
            //       → re-serialize → write signed bytes.
            //   (c) SPDX (2.3 or 3) + signing enabled: write primary
            //       verbatim, then emit companion DSSE sidecar at
            //       `<target>.sig.json`.
            let final_bytes = if signing_mode.is_enabled()
                && fmt == "cyclonedx-json"
                && artifact.relative_path == Path::new(serializer.default_filename())
            {
                match sign_cdx_bytes_for_write(&artifact.bytes, &signing_mode) {
                    Ok(signed) => signed,
                    Err(e) => {
                        cleanup_written_files(&written_files);
                        return Err(anyhow::anyhow!(
                            "signing failed for {} (target: {}): {e}",
                            fmt,
                            target.display(),
                        ));
                    }
                }
            } else {
                artifact.bytes.clone()
            };
            write_bytes_to(&target, &final_bytes)?;
            written_files.push(target.clone());
            if primary_output_path.is_none() {
                primary_output_path = Some(target.clone());
                primary_format = Some(fmt.clone());
            }
            tracing::info!(
                format = %fmt,
                path = %target.display(),
                bytes = final_bytes.len(),
                "wrote SBOM artifact"
            );

            // Milestone 221 US2a + m222 US2b — SPDX sidecar. Only
            // for primary SPDX artifacts (not OpenVEX side-artifacts).
            // Static-key path emits `.sig.json` (DSSE); Sigstore
            // keyless path emits `.sig.bundle.json` per FR-004.
            if signing_mode.is_enabled()
                && (fmt == "spdx-2.3-json" || fmt == "spdx-3-json")
                && artifact.relative_path == Path::new(serializer.default_filename())
            {
                match crate::sbom::signer::sign_spdx_bytes_to_sidecar(
                    &final_bytes,
                    &signing_mode,
                ) {
                    Ok(Some(sidecar_payload)) => {
                        let sidecar = target
                            .with_extension(sidecar_extension_for(&target, &sidecar_payload));
                        let kind = sidecar_payload.kind_label();
                        let json = sidecar_payload.to_json_bytes().map_err(|e| {
                            anyhow::anyhow!("cannot serialize {kind} sidecar: {e}")
                        })?;
                        write_bytes_to(&sidecar, &json)?;
                        written_files.push(sidecar.clone());
                        tracing::info!(
                            format = %fmt,
                            sidecar = %sidecar.display(),
                            bytes = json.len(),
                            kind = %kind,
                            "wrote SBOM signature sidecar"
                        );
                    }
                    Ok(None) => {
                        // Unreachable — is_enabled() gate already checked.
                        unreachable!("Unsigned mode short-circuited above");
                    }
                    Err(e) => {
                        cleanup_written_files(&written_files);
                        return Err(anyhow::anyhow!(
                            "signing failed for {} sidecar: {e}",
                            fmt,
                        ));
                    }
                }
            }
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

    // Milestone 173 — FR-004 advisory log. Emitted at INFO level
    // exactly once when ALL FOUR predicates hold:
    //   1. Scan produced ≥1 Go component (FR-009 gate).
    //   2. `--offline` is NOT set.
    //   3. `--warm-go-cache` was NOT explicitly set (took default `off`).
    //   4. The C117 `waybill:go-transitive-fallback-count` value is > 0.
    // Suppressed otherwise. The literal string here MUST match
    // contracts/cli-surface.md verbatim so consumers can grep with a
    // stable substring.
    let advisory_ctx = AdvisoryContext {
        fallback_count: go_transitive_fallback_count,
        warm_flag_was_default: !std::env::args()
            .any(|a| a.starts_with("--warm-go-cache=")),
        offline,
        scan_has_go_components: components
            .iter()
            .any(|c| c.purl.as_str().starts_with("pkg:golang/")),
    };
    if advisory_ctx.should_advise() {
        tracing::info!(
            "waybill:go-transitive-fallback-count > 0 detected. Prime the cache with --warm-go-cache=per-workspace or 'go mod download' per workspace before scanning."
        );
    }

    // Milestone 176 — FR-004 advisory log. Emitted at INFO level
    // exactly once when TWO predicates hold:
    //   1. The scan detected N > 1 workspaces (union of every
    //      component's `waybill:workspace-member` annotation).
    //   2. The scan produced ≥1 component (else there's nothing to
    //      slice per-workspace and no useful advice to give).
    // Suppressed otherwise (single-project + bare-directory scans stay
    // quiet per FR-005). NOT gated on --offline: the remediation
    // (jq per-workspace slicing) is entirely consumer-side and
    // requires no network (per FR-006). The stable grep substring
    // `"monorepo shape detected: "` is load-bearing — dashboards
    // grep-detect monorepo scans via this token.
    {
        use std::collections::BTreeSet;
        let mut workspaces: BTreeSet<String> = BTreeSet::new();
        for c in &components {
            if let Some(v) = c.extra_annotations.get("waybill:workspace-member") {
                if let Some(s) = v.as_str() {
                    if let Ok(paths) = serde_json::from_str::<Vec<String>>(s) {
                        for p in paths {
                            workspaces.insert(p);
                        }
                    }
                }
            }
        }
        if workspaces.len() > 1 && !components.is_empty() {
            let list = workspaces.iter().cloned().collect::<Vec<_>>().join(", ");
            tracing::info!(
                "monorepo shape detected: {} workspaces ({}). Downstream consumers can filter per-workspace via `waybill:workspace-member`; see docs/reference/monorepos.md for jq recipes.",
                workspaces.len(),
                list,
            );
        }
    }

    // Milestone 175 — FR-002 advisory log. Emitted at INFO level exactly
    // once when THREE predicates hold:
    //   1. At least one component has `sbom_tier = "design"` (constraint-
    //      only manifest — pip `requirements.txt` alone, Ruby `Gemfile`
    //      without `Gemfile.lock`, npm root `package.json` without
    //      `package-lock.json`, etc.).
    //   2. The scan produced ≥1 component (empty scans stay quiet).
    //   3. The `WAYBILL_NO_DESIGN_TIER_ADVISORY` env var is unset (or
    //      set to a value other than "1" / "true"). Env-var precedent:
    //      milestone-110 `WAYBILL_NO_DEPRECATION_NOTICE=1`.
    // NOT gated on --offline: the remediation (generate a lockfile,
    // install into a venv) works fully offline (FR-002 explicit).
    // Stable grep substring: "design-tier components detected: " —
    // dashboards grep-detect design-tier scans via this token.
    {
        let design_tier_count = components
            .iter()
            .filter(|c| c.sbom_tier.as_deref() == Some("design"))
            .count();
        let suppress = std::env::var("WAYBILL_NO_DESIGN_TIER_ADVISORY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if design_tier_count > 0 && !components.is_empty() && !suppress {
            tracing::info!(
                "design-tier components detected: {design_tier_count} components lack \
                 resolved versions. Remediation: generate a lockfile (uv lock / poetry \
                 lock / pip-compile / npm install / bundle lock / cargo generate-lockfile) \
                 OR install into a venv and re-scan. See \
                 docs/reference/reading-a-waybill-sbom.md#design-tier-components for jq \
                 recipes and per-ecosystem guidance."
            );
        }
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

/// Milestone 173 — FR-004 advisory-log predicate. Fires the "prime
/// the cache" hint exactly once per scan when the operator's env is
/// degraded AND they haven't explicitly opted in or out of warming.
///
/// The four-input contract is codified in data-model.md Entity 8:
/// suppression on any single false gate — non-Go scan (FR-009),
/// offline mode (FR-004 offline exception), explicit flag (operator
/// took a stance), or clean fallback count (nothing to advise about).
#[derive(Debug)]
struct AdvisoryContext {
    fallback_count: Option<usize>,
    warm_flag_was_default: bool,
    offline: bool,
    scan_has_go_components: bool,
}

impl AdvisoryContext {
    fn should_advise(&self) -> bool {
        self.scan_has_go_components
            && !self.offline
            && self.warm_flag_was_default
            && self.fallback_count.map(|n| n > 0).unwrap_or(false)
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod advisory_tests {
    use super::AdvisoryContext;

    fn ctx(
        fallback: Option<usize>,
        default: bool,
        offline: bool,
        has_go: bool,
    ) -> AdvisoryContext {
        AdvisoryContext {
            fallback_count: fallback,
            warm_flag_was_default: default,
            offline,
            scan_has_go_components: has_go,
        }
    }

    #[test]
    fn advises_when_all_four_predicates_hold() {
        assert!(ctx(Some(3), true, false, true).should_advise());
    }

    #[test]
    fn suppressed_when_offline() {
        assert!(!ctx(Some(3), true, true, true).should_advise());
    }

    #[test]
    fn suppressed_when_flag_explicit() {
        assert!(!ctx(Some(3), false, false, true).should_advise());
    }

    #[test]
    fn suppressed_on_zero_fallback() {
        assert!(!ctx(Some(0), true, false, true).should_advise());
    }

    #[test]
    fn suppressed_when_fallback_none() {
        assert!(!ctx(None, true, false, true).should_advise());
    }

    #[test]
    fn suppressed_on_non_go_scan() {
        assert!(!ctx(Some(3), true, false, false).should_advise());
    }
}

/// Write `bytes` to `path`, creating any missing parent directories.
///
/// Shared by every serializer artifact (CDX today; SPDX + OpenVEX in
/// Resolve the `created` timestamp for the SBOM output config.
///
/// Defaults to `chrono::Utc::now()`. **Test-only override**: when the
/// `WAYBILL_FIXED_TIMESTAMP` env var is set to an RFC 3339 string,
/// that value is used instead — required for tests that compare raw
/// SBOM bytes across two `waybill sbom scan` subprocesses (e.g.
/// `format_dispatch::spdx_3_alias_bytes_are_byte_identical_to_stable_identifier`).
/// Without the override, the two subprocesses' independent
/// `Utc::now()` calls can cross a second boundary on slow runners
/// and produce non-byte-identical output, surfacing as a CI flake
/// even on docs-only PRs.
///
/// Production scans MUST NOT set this env var. An unparseable value
/// is treated as "unset" — silently fall back to `Utc::now()` rather
/// than panic, since this is a defensive belt-and-braces helper, not
/// a hard contract.
fn scan_created_timestamp() -> chrono::DateTime<chrono::Utc> {
    if let Ok(s) = std::env::var("WAYBILL_FIXED_TIMESTAMP") {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&s) {
            return parsed.with_timezone(&chrono::Utc);
        }
    }
    chrono::Utc::now()
}

/// Milestone 072 / T027 helper: walk the resolved component set and
/// attach a `waybill:source-document-binding` annotation to each
/// component whose PURL appears in the source-tier SBOM.
///
/// Components matching by PURL get the source-tier's binding metadata
/// (provenance-preserved). Components whose PURL has no source-tier
/// counterpart get an explicit
/// `binding: unknown { reason: "source-not-found-in-bind-target" }`
/// per FR-003.
///
/// The annotation rides through `extra_annotations` (the milestone-023
/// generic per-component bag). Existing CDX `properties[]`,
/// SPDX 2.3 `Package.annotations[]` envelope, and SPDX 3
/// `Annotation.statement` envelope serializers all consume that bag
/// transparently — no per-format emission code change needed for
/// per-component binding annotations.
/// Milestone 111: assemble the operator's `--pkg-alias` declarations
/// and `WAYBILL_PKG_ALIAS` env-var entries into a single deterministic
/// `AliasMap`. Conflicts (same LHS, different RHS) abort the scan with
/// an actionable error per FR-008.
///
/// Env-var format: comma-separated `LHS=RHS` entries; whitespace
/// trimmed; empty entries silently skipped.
fn build_pkg_alias_map(
    args: &ScanArgs,
) -> anyhow::Result<waybill::binding::alias::AliasMap> {
    use waybill::binding::alias::{parse_pkg_alias, AliasMap};

    let mut map = AliasMap::new();

    // CLI flags first (insertion order = flag order).
    for alias in &args.pkg_alias {
        map.insert(alias.clone())
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    // Then env-var entries.
    if let Ok(raw) = std::env::var("WAYBILL_PKG_ALIAS") {
        for entry in raw.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let alias = parse_pkg_alias(trimmed)
                .map_err(|e| anyhow::anyhow!("WAYBILL_PKG_ALIAS entry: {}", e))?;
            map.insert(alias)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
        }
    }

    Ok(map)
}

/// FR-011: emit an info-level log for any alias whose LHS PURL did
/// not match a component during the binding pass. Operator typos in
/// the LHS are common; surfacing them as info-level diagnostics gives
/// the operator a clear signal without escalating to warn.
fn log_unused_pkg_aliases(
    alias_map: &waybill::binding::alias::AliasMap,
    consumed: &std::collections::HashSet<String>,
) {
    for alias in alias_map.iter() {
        let lhs = alias.lhs().as_str();
        if !consumed.contains(lhs) {
            tracing::info!(
                lhs = %lhs,
                rhs = %alias.rhs().as_str(),
                "--pkg-alias LHS did not match any scan-output component; \
                 no alias applied for this entry. (Verify the LHS PURL \
                 matches what the scan emits for the intended component.)"
            );
        }
    }
}

fn attach_bindings_to_components(
    components: &mut [waybill_common::resolution::ResolvedComponent],
    ctx: &waybill::binding::SourceSbomContext,
    alias_map: &waybill::binding::alias::AliasMap,
) -> std::collections::HashSet<String> {
    use waybill::binding::BindingStrength;
    use waybill_common::types::purl::Purl;

    // Track which alias LHSes were consumed during this pass so the
    // FR-011 unused-alias info log can surface declared-but-unmatched
    // entries to the operator.
    let mut consumed_aliases: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for c in components.iter_mut() {
        let component_purl_str = c.purl.as_str().to_string();

        // Determine whether an alias applies to this component. Match
        // is strict canonical-PURL equality per spec FR-001 + research
        // §3 (Q1 clarification).
        let alias_pair: Option<(Purl, Purl)> = Purl::new(&component_purl_str)
            .ok()
            .and_then(|component_purl| {
                alias_map
                    .get(&component_purl)
                    .map(|rhs| (component_purl, rhs.clone()))
            });

        // Choose which PURL to look up in the source SBOM: when an
        // alias applies, we look up the RHS; otherwise the component's
        // own PURL.
        let lookup_purl_str = match &alias_pair {
            Some((_, rhs)) => rhs.as_str().to_string(),
            None => component_purl_str.clone(),
        };

        let mut binding = ctx.binding_for_purl(&lookup_purl_str);

        // FR-005 + FR-013: stamp alias_from / alias_to onto the
        // envelope regardless of strength outcome so the operator
        // can see the alias was applied even when the RHS is
        // missing from the source SBOM.
        if let Some((lhs, rhs)) = alias_pair {
            // FR-007: when an alias was applied AND the RHS was not
            // found in the bind-source, rewrite the failure reason
            // from `source-not-found-in-bind-target` to the alias-
            // specific reason so operators can debug their alias
            // declaration separately from a missing-source-document
            // state.
            if binding.strength == BindingStrength::Unknown
                && binding.reason.as_deref() == Some("source-not-found-in-bind-target")
            {
                binding.reason = Some("alias-target-not-found-in-bind-target".to_string());
            }
            consumed_aliases.insert(lhs.as_str().to_string());
            binding.alias_from = Some(lhs);
            binding.alias_to = Some(rhs);
            // Milestone 116 — operator-supplied alias overrides any
            // automatic alias that binding_for_purl may have stamped
            // (this preserves the FR-004 operator-precedence rule even
            // in the edge case where the operator's RHS itself triggers
            // the pkg:generic/<name> auto-alias path).
            binding.alias_source = Some(waybill::binding::AliasSource::OperatorSupplied);
        }

        // Serialize via the canonical serde shape so emission is
        // byte-stable across reruns. The CDX side will JSON-encode
        // this Value to a string at emission time (the milestone-023
        // bag does that automatically); the SPDX side wraps it in
        // the MikebomAnnotationCommentV1 envelope.
        if let Ok(value) = waybill::binding::serialize_to_envelope_value(&binding) {
            c.extra_annotations.insert(
                waybill::binding::BINDING_PROPERTY_NAME.to_string(),
                value,
            );
        }
    }
    consumed_aliases
}

/// later phases). Kept local to this CLI module so the generator crate
/// has no filesystem dependencies.
/// Milestone 221 US2a (FR-008a support): true when an `--output`
/// argument value targets stdout — either bare `-` or `<fmt>=-`.
fn is_stdout_output(value: &str) -> bool {
    let raw = value.trim();
    if raw == "-" {
        return true;
    }
    // Per-format form `<fmt>=<path>`; look at the path portion.
    if let Some((_fmt, path)) = raw.split_once('=') {
        return path.trim() == "-";
    }
    false
}

/// Milestone 221 US2a: produce a suggested replacement path when the
/// operator combined `--sign-key` with stdout output. Preserves the
/// `<fmt>=` prefix when present so the diagnostic reads naturally.
fn suggest_non_stdout_path(offender: &str) -> String {
    if let Some((fmt, _)) = offender.split_once('=') {
        format!("{fmt}=signed.{fmt}.json")
    } else {
        "signed.cdx.json".to_string()
    }
}

/// Milestone 221 US2a — parse CDX bytes, sign the doc in-place per
/// FR-007b (JSF into `metadata.signature`), and re-serialize.
///
/// Returns the signed bytes ready to write to disk. Any error
/// bubbles up as `SbomSigningError`; the CLI layer maps that to a
/// fail-close exit per FR-009a.
fn sign_cdx_bytes_for_write(
    bytes: &[u8],
    mode: &crate::sbom::signer::SigningMode,
) -> Result<Vec<u8>, crate::sbom::signer::SbomSigningError> {
    let mut doc: serde_json::Value = serde_json::from_slice(bytes)?;
    crate::sbom::signer::sign_cdx_document_in_place(&mut doc, mode)?;
    // Re-serialize with pretty indentation to match the pre-signing
    // CDX writer's shape. The signer canonicalizes via JCS internally
    // for the signature bytes, so the on-disk pretty formatting is
    // decoupled from what actually got signed.
    Ok(serde_json::to_vec_pretty(&doc)?)
}

/// Milestone 221 US2a (FR-009a) — best-effort unlink of every file
/// waybill wrote during this scan. Called on signing failure so
/// consumers never see a partial `--output <path>` file. Errors on
/// individual unlinks are logged at WARN but do not mask the
/// primary signing error.
fn cleanup_written_files(files: &[PathBuf]) {
    for path in files {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "could not clean up partial output on signing failure"
                );
            }
        }
    }
}

/// Milestone 221 US2a + m222 US2b — variant-aware sidecar extension.
/// Delegates to
/// the `Sidecar::sidecar_suffix()` method so DSSE gets `.sig.json` and
/// Sigstore Bundle gets `.sig.bundle.json` per FR-004.
fn sidecar_extension_for(
    target: &Path,
    sidecar: &crate::sbom::signer::Sidecar,
) -> std::ffi::OsString {
    let suffix = sidecar.sidecar_suffix(); // includes leading '.'
    let mut ext = std::ffi::OsString::new();
    if let Some(existing) = target.extension() {
        ext.push(existing);
        ext.push(suffix);
    } else {
        // Strip the leading '.' for the no-extension case (matches
        // sidecar_extension's shape).
        ext.push(&suffix[1..]);
    }
    ext
}

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

    // ----- Milestone 221 US2a (FR-008a) — stdout+signing rejection helpers -----

    #[test]
    fn is_stdout_output_detects_bare_dash_m221() {
        assert!(is_stdout_output("-"));
        assert!(is_stdout_output(" - "));
    }

    #[test]
    fn is_stdout_output_detects_fmt_dash_m221() {
        assert!(is_stdout_output("cyclonedx-json=-"));
        assert!(is_stdout_output("spdx-2.3-json=-"));
        assert!(is_stdout_output("spdx-3-json= -"));
    }

    #[test]
    fn is_stdout_output_ignores_normal_paths_m221() {
        assert!(!is_stdout_output("/tmp/scan.cdx.json"));
        assert!(!is_stdout_output("cyclonedx-json=/tmp/scan.cdx.json"));
        assert!(!is_stdout_output("./scan.spdx.json"));
        assert!(!is_stdout_output("waybill.cdx.json"));
        // Filename that happens to contain '-' but isn't stdout.
        assert!(!is_stdout_output("signed-scan.cdx.json"));
        assert!(!is_stdout_output("cyclonedx-json=signed-scan.cdx.json"));
    }

    #[test]
    fn suggest_non_stdout_path_preserves_fmt_prefix_m221() {
        assert_eq!(suggest_non_stdout_path("-"), "signed.cdx.json");
        assert_eq!(
            suggest_non_stdout_path("cyclonedx-json=-"),
            "cyclonedx-json=signed.cyclonedx-json.json"
        );
    }

    // ----- Milestone 222 US2b (feature 222-sigstore-keyless-signing) — CLI parsing -----

    #[test]
    fn sign_flag_defaults_off_m222() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from(["scan", "--path", "."])
            .expect("baseline parse");
        assert!(!parsed.inner.sign, "sign defaults off");
        assert_eq!(parsed.inner.fulcio_url, "https://fulcio.sigstore.dev");
        assert_eq!(parsed.inner.rekor_url, "https://rekor.sigstore.dev");
        assert_eq!(parsed.inner.rekor_timeout_secs, 30);
    }

    #[test]
    fn sign_flag_accepts_bare_toggle_m222() {
        let parsed =
            <ScanArgsForTest as clap::Parser>::try_parse_from(["scan", "--path", ".", "--sign"])
                .expect("bare --sign parses");
        assert!(parsed.inner.sign);
    }

    #[test]
    fn sign_and_sign_key_are_mutually_exclusive_m222() {
        let err = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--sign",
            "--sign-key",
            "/tmp/x.pem",
        ])
        .expect_err("--sign + --sign-key must be rejected by clap");
        let rendered = err.to_string();
        assert!(
            rendered.contains("cannot be used with") || rendered.contains("conflicts_with")
                || rendered.contains("--sign-key"),
            "clap conflict-message expected, got: {rendered}"
        );
    }

    #[test]
    fn sign_endpoint_overrides_via_flags_m222() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--sign",
            "--fulcio-url",
            "https://fulcio.sigstage.dev",
            "--rekor-url",
            "https://rekor.sigstage.dev",
            "--rekor-timeout-secs",
            "60",
        ])
        .expect("staging-endpoint override parses");
        assert!(parsed.inner.sign);
        assert_eq!(parsed.inner.fulcio_url, "https://fulcio.sigstage.dev");
        assert_eq!(parsed.inner.rekor_url, "https://rekor.sigstage.dev");
        assert_eq!(parsed.inner.rekor_timeout_secs, 60);
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
                "openvex=waybill.cdx.json".into(),
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

    /// Wrapper Parser for clap-parsing tests — `ScanArgs` derives
    /// `Args`, not `Parser`, so we flatten it into a top-level Parser.
    #[derive(clap::Parser, Debug)]
    struct ScanArgsForTest {
        #[command(flatten)]
        inner: ScanArgs,
    }

    #[test]
    fn image_src_defaults_to_docker_podman_remote_m206() {
        // Milestone 206 (#440): default order bumped from
        // `[Docker, Remote]` to `[Docker, Podman, Remote]` per FR-006.
        // Docker-first preserves backward compat; Podman inserted
        // before Remote so local podman wins over network fetches.
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan", "--path", ".",
        ])
        .unwrap();
        assert_eq!(
            parsed.inner.image_src,
            vec![ImageSource::Docker, ImageSource::Podman, ImageSource::Remote]
        );
    }

    #[test]
    fn image_src_accepts_comma_separated_list() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--image-src",
            "remote,docker",
        ])
        .unwrap();
        assert_eq!(
            parsed.inner.image_src,
            vec![ImageSource::Remote, ImageSource::Docker]
        );
    }

    #[test]
    fn image_src_accepts_single_value() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--image-src",
            "remote",
        ])
        .unwrap();
        assert_eq!(parsed.inner.image_src, vec![ImageSource::Remote]);
    }

    #[test]
    fn image_src_accepts_podman_value_m206() {
        // Milestone 206 (#440): `podman` is now a valid --image-src value.
        // Pre-m206 this was rejected as unknown.
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--image-src",
            "podman",
        ])
        .unwrap();
        assert_eq!(parsed.inner.image_src, vec![ImageSource::Podman]);
    }

    #[test]
    fn image_src_rejects_unknown_value() {
        let err = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--image-src",
            "definitely-not-a-source",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.to_lowercase().contains("invalid value")
                || err.to_lowercase().contains("possible values"),
            "expected clap to reject unknown image-src value, got: {err}"
        );
    }

    // ── Milestone 182 — TLS/transport flag parse tests ────────────

    #[test]
    fn insecure_registry_flag_repeatable_parses() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--insecure-registry",
            "core:8080",
            "--insecure-registry",
            "dev-registry",
        ])
        .unwrap();
        assert_eq!(
            parsed.inner.insecure_registry,
            vec!["core:8080".to_string(), "dev-registry".to_string()]
        );
    }

    #[test]
    fn registry_ca_cert_flag_repeatable_parses() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--registry-ca-cert",
            "/etc/ssl/ca1.pem",
            "--registry-ca-cert",
            "/etc/ssl/ca2.pem",
        ])
        .unwrap();
        assert_eq!(
            parsed.inner.registry_ca_cert,
            vec![
                std::path::PathBuf::from("/etc/ssl/ca1.pem"),
                std::path::PathBuf::from("/etc/ssl/ca2.pem"),
            ]
        );
    }

    #[test]
    fn insecure_tls_skip_verify_bool_defaults_false() {
        let default = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan", "--path", ".",
        ])
        .unwrap();
        assert!(!default.inner.insecure_tls_skip_verify);
        let with_flag = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--insecure-tls-skip-verify",
        ])
        .unwrap();
        assert!(with_flag.inner.insecure_tls_skip_verify);
    }

    #[test]
    fn all_three_flags_combined_parse_ok() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--insecure-registry",
            "core:8080",
            "--registry-ca-cert",
            "/etc/ssl/ca.pem",
            "--insecure-tls-skip-verify",
        ])
        .unwrap();
        assert_eq!(parsed.inner.insecure_registry, vec!["core:8080".to_string()]);
        assert_eq!(
            parsed.inner.registry_ca_cert,
            vec![std::path::PathBuf::from("/etc/ssl/ca.pem")]
        );
        assert!(parsed.inner.insecure_tls_skip_verify);
    }

    // ── Enrichment-control flag tests ─────────────────────────────

    #[test]
    fn no_clearly_defined_flag_parses() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan", "--path", ".", "--no-clearly-defined",
        ])
        .unwrap();
        assert!(parsed.inner.no_clearly_defined);
        assert!(!parsed.inner.no_deps_dev);
        assert!(!parsed.inner.no_deps_dev_graph);
        // Milestone 207 (#596): new `--no-deps-dev-license` flag
        // defaults to OFF (enrichment on).
        assert!(!parsed.inner.no_deps_dev_license);
    }

    #[test]
    fn no_deps_dev_flag_parses() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan", "--path", ".", "--no-deps-dev",
        ])
        .unwrap();
        assert!(parsed.inner.no_deps_dev);
        assert!(!parsed.inner.no_clearly_defined);
        assert!(!parsed.inner.no_deps_dev_graph);
    }

    #[test]
    fn no_deps_dev_graph_flag_parses() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan", "--path", ".", "--no-deps-dev-graph",
        ])
        .unwrap();
        assert!(!parsed.inner.no_clearly_defined);
        assert!(parsed.inner.no_deps_dev_graph);
    }

    #[test]
    fn all_no_flags_combine() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--no-clearly-defined",
            "--no-deps-dev",
            "--no-deps-dev-graph",
        ])
        .unwrap();
        assert!(parsed.inner.no_clearly_defined);
        assert!(parsed.inner.no_deps_dev);
        assert!(parsed.inner.no_deps_dev_graph);
    }

    #[test]
    fn enrich_sources_parses_comma_separated() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--enrich-sources",
            "deps-dev,clearly-defined",
        ])
        .unwrap();
        assert_eq!(
            parsed.inner.enrich_sources,
            vec![EnrichSource::DepsDev, EnrichSource::ClearlyDefined]
        );
    }

    #[test]
    fn enrich_sources_single_value() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--enrich-sources",
            "deps-dev-graph",
        ])
        .unwrap();
        assert_eq!(
            parsed.inner.enrich_sources,
            vec![EnrichSource::DepsDevGraph]
        );
    }

    #[test]
    fn enrich_sources_rejects_unknown_value() {
        let err = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--enrich-sources",
            "clear-defined",
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.to_lowercase().contains("invalid value")
                || err.to_lowercase().contains("possible values"),
            "expected clap to reject unknown enrich-sources value, got: {err}"
        );
    }

    #[test]
    fn enrich_sources_defaults_to_empty() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan", "--path", ".",
        ])
        .unwrap();
        assert!(parsed.inner.enrich_sources.is_empty());
    }

    // ── resolve_enrich_sources logic tests ────────────────────────

    /// Helper: build a minimal ScanArgs with only the enrichment
    /// fields set, rest defaulted.
    fn enrich_args(
        no_deps_dev: bool,
        no_clearly_defined: bool,
        no_deps_dev_graph: bool,
        no_deps_dev_license: bool,
        enrich_sources: Vec<EnrichSource>,
    ) -> ScanArgs {
        ScanArgs {
            path: Some(PathBuf::from(".")),
            image: None,
            image_src: vec![],
            image_platform: None,
            no_oci_cache: false,
            oci_cache_size: None,
            registry_credentials_dir: None,
            // Milestone 182 — test helper defaults preserve pre-m182
            // behavior (no insecure registries, no additional CAs,
            // full TLS verification). Byte-identity SC-004.
            insecure_registry: vec![],
            registry_ca_cert: vec![],
            insecure_tls_skip_verify: false,
            // Milestone 186 — test helper defaults preserve pre-m186
            // behavior (no Referrers-API query; byte-identity SC-004).
            sbom_source: SbomSourceMode::Scan,
            // Milestone 188 — test helper defaults preserve pre-m188
            // behavior (no Helm chart processing; byte-identity per
            // FR-016 / SC-005).
            helm_chart: None,
            helm_render: false,
            // Milestone 221 US2a — test helper defaults preserve pre-m221
            // behavior (no signing; byte-identity guaranteed per FR-009).
            sign_key: None,
            sign_key_passphrase_env: None,
            // Milestone 222 US2b — test helper defaults preserve pre-m222
            // behavior (no keyless signing; byte-identity guaranteed per
            // FR-015). Fulcio + Rekor URL defaults match the CLI's own
            // defaults so any test that flips `sign = true` gets the
            // same endpoint resolution the real CLI would.
            sign: false,
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            rekor_timeout_secs: 30,
            // Milestone 221 US4 — no --sbom-version by default; CDX
            // metadata.version stays at the pre-m221 hardcoded 1 and
            // SPDX outputs emit no waybill:sbom-version annotation.
            sbom_version: None,
            split: None,
            output_dir: None,
            output: vec![],
            format: vec![],
            max_file_size: 256 * 1024 * 1024,
            // Milestone 144 — test helper preserves default-cap behavior
            // (RpmReaderConfig::default() at 512 MiB) and no distro
            // override; equivalent to operator omitting both flags.
            max_rpm_bytes: None,
            rpm_distro: None,
            no_hashes: false,
            deb_codename: None,
            no_package_db: false,
            no_deep_hash: false,
            fast_container_extract: false,
            conclude_licenses: false,
            // Test helper preserves byte-identity on enrichment-
            // focused unit tests by keeping file-tier emission off.
            // Production default in `scan_cmd.rs` is `orphan` per
            // milestone 133 US1.C.
            file_inventory: "off".to_string(),
            file_inventory_size_limit: 100 * 1024 * 1024,
            // Milestone 671 T009 — test helper default: no source-shape
            // restriction. `None` on the `Option<SourceShapeSet>` field.
            file_inventory_source_shapes: None,
            json: false,
            no_clearly_defined,
            no_deps_dev,
            no_deps_dev_graph,
            no_deps_dev_license,
            enrich_sources,
            bind_to_source: None,
            repo: None,
            git_ref: None,
            image_id: None,
            attestation: None,
            id: vec![],
            keep_credentials_in_identifiers: false,
            subject_hash: vec![],
            component_id: vec![],
            root_name: None,
            root_version: None,
            root_purl_type: None,
            no_root_purl: false,
            root_purl: None,
            preserve_manifest_main_module: false,
            // Milestone 080 — defaults for new fields keep the test
            // helper's "minimal flags" contract intact.
            creator: vec![],
            annotator: vec![],
            annotation_comment: vec![],
            metadata_comment: None,
            scan_target_name: None,
            metadata_file: None,
            // Milestone 081 — default the new operator-assert flag to
            // None so the helper's "minimal flags" contract holds.
            sbom_type: None,
            spdx2_relationship_compat: crate::generate::Spdx2RelationshipCompat::Full,
            // Milestone 102 — default vendored-deps emission OFF.
            include_vendored: false,
            // Milestone 156 — default third_party/ recursive-walk OFF.
            cmake_third_party_recursive: false,
            // Milestone 235 — default Gradle ladder opt-out (subprocess off,
            // no daemon, no buildscript, 300s timeout, no extra configs).
            gradle: GradleCliFlags::default(),
            // Milestone 108 — default external fingerprint-corpus opt-in OFF.
            fingerprints_corpus: false,
            // Milestone 110 Phase 5-Slim — defaults for new multi-
            // source flags keep the test helper's "minimal flags"
            // contract intact.
            fingerprints_source: vec![],
            fingerprints_source_no_default: false,
            // Milestone 111 — default no operator-supplied PURL aliases.
            pkg_alias: vec![],
            // Milestone 108 US5 — default runtime SHA override unset.
            fingerprints_rev: None,
            // Milestone 173 — test helper defaults match CLI defaults.
            warm_go_cache: WarmGoCacheMode::Off,
            warm_go_cache_concurrency: 4,
            // Milestone 210 — trace-noise filter escape hatch off
            // by default. Individual tests flip on when auditing
            // secret paths in fixtures.
            include_system_reads: false,
            // Milestone 218 — opt-in cross-ecosystem edges off by
            // default (matches CLI default; preserves SC-009).
            experimental_cross_ecosystem_edges: false,
            // Milestone 220 — default project-discovery mode = All
            // (matches CLI default; preserves SC-005 byte-identity).
            project_discovery: crate::generate::project_discovery::ProjectDiscoveryMode::All,
            tier: TierMode::All,
            // Milestone 665 — test helper defaults preserve pre-665
            // behavior (no binary-scan suppression; byte-identity
            // per FR-003).
            no_binary_scan: None,
        }
    }

    #[test]
    fn resolve_defaults_all_enabled() {
        let args = enrich_args(false, false, false, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert_eq!(cfg, EnrichConfig {
            deps_dev: true,
            clearly_defined: true,
            deps_dev_graph: true,
        });
    }

    #[test]
    fn resolve_no_clearly_defined_disables_cd() {
        let args = enrich_args(false, true, false, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert!(cfg.deps_dev);
        assert!(!cfg.clearly_defined);
        assert!(cfg.deps_dev_graph);
    }

    #[test]
    fn resolve_enrich_no_deps_dev_disables_both_paths_m207() {
        // Milestone 207 (#596) US1 acceptance — `--no-deps-dev` is
        // now an aggregate disable: BOTH the license AND dep-graph
        // paths turn off. Pre-m207 this test asserted deps_dev_graph
        // stayed true.
        let args = enrich_args(true, false, false, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert_eq!(
            cfg,
            EnrichConfig {
                deps_dev: false,
                clearly_defined: true,
                deps_dev_graph: false,
            }
        );
    }

    #[test]
    fn resolve_enrich_no_deps_dev_license_disables_license_only_m207() {
        // Milestone 207 (#596) US2 acceptance — new fine-grained
        // flag `--no-deps-dev-license` restores the pre-m207
        // `--no-deps-dev` semantic (license only).
        let args = enrich_args(false, false, false, true, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert_eq!(
            cfg,
            EnrichConfig {
                deps_dev: false,
                clearly_defined: true,
                deps_dev_graph: true,
            }
        );
    }

    #[test]
    fn resolve_enrich_no_deps_dev_wins_over_no_deps_dev_graph_m207() {
        // Composition sanity — `--no-deps-dev` combined with
        // `--no-deps-dev-graph` produces the same aggregate result.
        let args = enrich_args(true, false, true, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert_eq!(
            cfg,
            EnrichConfig {
                deps_dev: false,
                clearly_defined: true,
                deps_dev_graph: false,
            }
        );
    }

    #[test]
    fn resolve_enrich_no_deps_dev_license_and_graph_equals_aggregate_m207() {
        // Composition sanity — setting both fine-grained flags is
        // equivalent to setting the aggregate `--no-deps-dev`.
        let args = enrich_args(false, false, true, true, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert_eq!(
            cfg,
            EnrichConfig {
                deps_dev: false,
                clearly_defined: true,
                deps_dev_graph: false,
            }
        );
    }

    #[test]
    fn resolve_enrich_sources_allowlist_overrides_no_deps_dev_m207() {
        // FR-004 regression guard — allowlist mode ignores every
        // `--no-*` flag, including the aggregate `--no-deps-dev`.
        let args = enrich_args(
            true, false, false, false,
            vec![EnrichSource::DepsDev],
        );
        let cfg = resolve_enrich_sources(&args);
        assert!(cfg.deps_dev, "allowlist wins per FR-004");
    }

    #[test]
    fn resolve_enrich_no_clearly_defined_unaffected_by_no_deps_dev_m207() {
        // Regression guard — `--no-deps-dev` doesn't affect the
        // ClearlyDefined path.
        let args = enrich_args(true, false, false, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert!(cfg.clearly_defined);
    }

    #[test]
    fn no_deps_dev_help_mentions_enrich_sources_m207() {
        // FR-008 — operators reading `waybill sbom scan --help`
        // see the composition hint next to the flag they're setting.
        // `ScanArgsForTest` flattens `ScanArgs` at the top level (no
        // subcommand nesting), so args are directly discoverable via
        // `get_arguments`.
        let cmd = <ScanArgsForTest as clap::CommandFactory>::command();
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_id().as_str() == "no_deps_dev")
            .expect("--no-deps-dev arg present");
        // long_help includes the multi-line doc-comment; short help
        // is just the first line. Combine both to search.
        let help_text = format!(
            "{}\n{}",
            arg.get_help().map(|s| s.to_string()).unwrap_or_default(),
            arg.get_long_help().map(|s| s.to_string()).unwrap_or_default(),
        );
        assert!(
            help_text.contains("enrich-sources"),
            "FR-008: --no-deps-dev help text must mention `--enrich-sources`. Got:\n{help_text}"
        );
    }

    #[test]
    fn resolve_no_deps_dev_graph_disables_graph() {
        let args = enrich_args(false, false, true, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert!(cfg.deps_dev);
        assert!(cfg.clearly_defined);
        assert!(!cfg.deps_dev_graph);
    }

    #[test]
    fn resolve_all_no_flags_disables_everything() {
        let args = enrich_args(true, true, true, false, vec![]);
        let cfg = resolve_enrich_sources(&args);
        assert_eq!(cfg, EnrichConfig {
            deps_dev: false,
            clearly_defined: false,
            deps_dev_graph: false,
        });
    }

    #[test]
    fn resolve_allowlist_overrides_no_flags() {
        // --enrich-sources clearly-defined --no-clearly-defined
        // → allowlist wins: CD enabled
        let args = enrich_args(
            false,
            true,  // --no-clearly-defined
            true,  // --no-deps-dev-graph
            false, // --no-deps-dev-license (m207)
            vec![EnrichSource::ClearlyDefined],
        );
        let cfg = resolve_enrich_sources(&args);
        assert!(!cfg.deps_dev);         // not in allowlist
        assert!(cfg.clearly_defined);   // in allowlist, overrides --no flag
        assert!(!cfg.deps_dev_graph);   // not in allowlist
    }

    #[test]
    fn resolve_allowlist_subset_only_enables_listed() {
        let args = enrich_args(
            false, false, false, false,
            vec![EnrichSource::DepsDev, EnrichSource::DepsDevGraph],
        );
        let cfg = resolve_enrich_sources(&args);
        assert!(cfg.deps_dev);
        assert!(!cfg.clearly_defined); // not in allowlist
        assert!(cfg.deps_dev_graph);
    }

    // ----------------------------------------------------------------
    // Milestone 073 — identifier resolution pipeline
    // (T013 unit-test coverage). FR-006 + FR-009 override-position
    // rule.
    // ----------------------------------------------------------------

    use waybill::binding::identifiers::Identifier;

    fn make_id(raw: &str, label: Option<&str>) -> Identifier {
        let mut id = Identifier::parse(raw).unwrap();
        id.source_label = label.map(|s| s.to_string());
        id
    }

    // Milestone 074 (T005): resolve_identifiers moved to
    // `waybill::binding::identifiers::resolve_identifiers` with a
    // `Vec<Identifier>`-based auto-detected param. Tests pass through
    // an alias so the existing assertions read the same.
    use waybill::binding::identifiers::resolve_identifiers;

    #[test]
    fn resolve_auto_detected_only_emits_one_entry() {
        let auto = make_id("repo:git@github.com:foo/bar.git", Some("auto"));
        let out = resolve_identifiers(vec![auto.clone()], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_wire(), auto.as_wire());
    }

    #[test]
    fn resolve_manual_only_emits_in_supply_order() {
        let m1 = make_id("repo:git@example.com:a.git", None);
        let m2 = make_id("acme_corp_id:abc123", None);
        let out = resolve_identifiers(vec![], &[m1.clone(), m2.clone()]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_wire(), m1.as_wire());
        assert_eq!(out[1].as_wire(), m2.as_wire());
    }

    #[test]
    fn resolve_manual_inherits_auto_detected_position_on_dedup() {
        // (c) — manual entry with same (scheme, value) as auto-detected
        // inherits the auto-detected entry's position (front of list).
        let auto = make_id("repo:git@github.com:foo/bar.git", Some("auto-label"));
        let manual_dup = make_id("repo:git@github.com:foo/bar.git", None);
        let manual_other = make_id("acme_corp_id:abc", None);
        let out = resolve_identifiers(
            vec![auto.clone()],
            &[manual_dup.clone(), manual_other.clone()],
        );
        assert_eq!(out.len(), 2);
        // Position 0: manual entry inherits auto-detected slot.
        assert_eq!(out[0].as_wire(), manual_dup.as_wire());
        // The replacement carries the manual entry's source_label
        // (None), not the auto-detected label.
        assert_eq!(out[0].source_label, None);
        // Position 1: the other manual entry follows in supply order.
        assert_eq!(out[1].as_wire(), manual_other.as_wire());
    }

    #[test]
    fn resolve_manual_different_value_drops_auto_detected() {
        // (d) — true override: same scheme, different value. The
        // auto-detected entry is dropped, manual follows in supply
        // order (NOT promoted to front).
        let auto = make_id("repo:git@github.com:o/foo.git", Some("auto"));
        let manual_override = make_id("repo:git@github.com:m/foo.git", None);
        let manual_other = make_id("acme_corp_id:abc", None);
        // Supply order: other first, then override. Override should
        // append after `other` (no front-of-list migration).
        let out = resolve_identifiers(
            vec![auto.clone()],
            &[manual_other.clone(), manual_override.clone()],
        );
        assert_eq!(out.len(), 2);
        // After auto-detected dropped, the supply order applies:
        // [other, override].
        assert_eq!(out[0].as_wire(), manual_other.as_wire());
        assert_eq!(out[1].as_wire(), manual_override.as_wire());
    }

    #[test]
    fn resolve_two_manual_with_same_scheme_value_first_wins() {
        // (e) — manual-vs-manual collision on (scheme, value):
        // first-supplied wins.
        let m1 = make_id("acme_corp_id:abc123", None);
        let m2 = make_id("acme_corp_id:abc123", None);
        let out = resolve_identifiers(vec![], &[m1.clone(), m2.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_wire(), m1.as_wire());
    }

    // Milestone 074: build-tier multi-auto-detected-entry coverage.
    #[test]
    fn resolve_multi_auto_detected_per_scheme_override_only_target_scheme() {
        // Build-tier scenario: auto-detected [repo:, git:].
        // Manual --repo with a different value should drop only the
        // auto-detected `repo:`, leaving the auto-detected `git:`
        // intact.
        let auto_repo = make_id("repo:git@github.com:o/foo.git", Some("auto-build-tier"));
        let auto_git = make_id(
            "git:git@github.com:o/foo.git#0123456789abcdef0123456789abcdef01234567",
            Some("auto-build-tier"),
        );
        let manual_override_repo = make_id("repo:git@github.com:m/foo.git", None);
        let out = resolve_identifiers(
            vec![auto_repo.clone(), auto_git.clone()],
            std::slice::from_ref(&manual_override_repo),
        );
        // Expected: auto-detected `git:` stays at position 0,
        // manual `repo:` appended at position 1 (supply-order).
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_wire(), auto_git.as_wire());
        assert_eq!(out[1].as_wire(), manual_override_repo.as_wire());
    }

    #[test]
    fn resolve_multi_auto_detected_exact_dedup_per_entry() {
        let auto_repo = make_id("repo:git@github.com:o/foo.git", Some("auto"));
        let auto_git = make_id(
            "git:git@github.com:o/foo.git#0123456789abcdef0123456789abcdef01234567",
            Some("auto"),
        );
        // Manual --repo matching the auto-detected one: dedup in place.
        let manual_dup_repo = make_id("repo:git@github.com:o/foo.git", None);
        let out = resolve_identifiers(
            vec![auto_repo.clone(), auto_git.clone()],
            std::slice::from_ref(&manual_dup_repo),
        );
        assert_eq!(out.len(), 2);
        // Repo at index 0 has been replaced by manual (label is None).
        assert_eq!(out[0].as_wire(), manual_dup_repo.as_wire());
        assert_eq!(out[0].source_label, None);
        // Git remains at index 1, with its auto-detected label.
        assert_eq!(out[1].as_wire(), auto_git.as_wire());
        assert_eq!(out[1].source_label.as_deref(), Some("auto"));
    }

    // ----------------------------------------------------------------
    // parse_user_defined_id_flag — `--id` value parsing
    // ----------------------------------------------------------------

    #[test]
    fn parse_user_defined_id_flag_accepts_user_defined_scheme() {
        let id = parse_user_defined_id_flag("acme_corp_id=abc123").unwrap();
        assert_eq!(id.scheme.as_str(), "acme_corp_id");
        assert_eq!(id.value.as_str(), "abc123");
        assert!(matches!(
            id.kind,
            waybill::binding::identifiers::IdentifierKind::UserDefined
        ));
    }

    #[test]
    fn parse_user_defined_id_flag_value_can_contain_equals() {
        // Split-on-first-`=` rule: trailing `=`s belong to the value.
        let id = parse_user_defined_id_flag("acme_corp_id=key=val=foo").unwrap();
        assert_eq!(id.scheme.as_str(), "acme_corp_id");
        assert_eq!(id.value.as_str(), "key=val=foo");
    }

    #[test]
    fn parse_user_defined_id_flag_rejects_missing_separator() {
        let err = parse_user_defined_id_flag("acme_corp_id_no_eq").unwrap_err();
        assert!(
            err.contains("missing `=` separator"),
            "expected missing-separator error; got {err}"
        );
    }

    #[test]
    fn parse_user_defined_id_flag_rejects_empty_value() {
        let err = parse_user_defined_id_flag("acme_corp_id=").unwrap_err();
        assert!(
            err.contains("identifier value is empty"),
            "expected EmptyValue error; got {err}"
        );
    }

    #[test]
    fn parse_user_defined_id_flag_rejects_invalid_scheme() {
        let err = parse_user_defined_id_flag("ACME_CORP_ID=abc").unwrap_err();
        assert!(
            err.contains("fails regex"),
            "expected InvalidSchemeName error; got {err}"
        );
    }

    #[test]
    fn parse_user_defined_id_flag_rejects_each_built_in_scheme() {
        // Per the user-instruction: --id <built-in>=<value> MUST
        // produce a clap parse error pointing at the dedicated flag.
        for built_in in ["repo", "git", "image", "attestation"] {
            let raw = format!("{built_in}=anything");
            let err = parse_user_defined_id_flag(&raw).unwrap_err();
            assert!(
                err.contains("--id rejects the built-in scheme")
                    && err.contains(built_in)
                    && err.contains("--repo")
                    && err.contains("--image-id"),
                "expected built-in-rejection error pointing at the dedicated flag; got {err}"
            );
        }
    }

    // ----------------------------------------------------------------
    // assemble_manual_identifiers — translate dedicated flags into Vec
    // ----------------------------------------------------------------

    #[test]
    fn assemble_manual_identifiers_repo_only_emits_repo_scheme() {
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.repo = Some("git@github.com:foo/bar.git".to_string());
        let ids = assemble_manual_identifiers(&args);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_wire(), "repo:git@github.com:foo/bar.git");
    }

    #[test]
    fn assemble_manual_identifiers_repo_plus_git_ref_emits_git_only() {
        // --repo + --git-ref → ONE git: identifier (supersedes repo:),
        // not two entries.
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.repo = Some("https://github.com/foo/bar".to_string());
        args.git_ref = Some("abc1234567890".to_string());
        let ids = assemble_manual_identifiers(&args);
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids[0].as_wire(),
            "git:https://github.com/foo/bar#abc1234567890"
        );
    }

    #[test]
    fn assemble_manual_identifiers_image_attestation_id_in_supply_order() {
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.image_id = Some("docker.io/foo/bar:v1".to_string());
        args.attestation = Some("https://example.org/att/1".to_string());
        args.id = vec![
            parse_user_defined_id_flag("acme_corp_id=svc-alpha").unwrap(),
            parse_user_defined_id_flag("internal_ticket=PROJ-456").unwrap(),
        ];
        let ids = assemble_manual_identifiers(&args);
        assert_eq!(ids.len(), 4);
        assert_eq!(ids[0].scheme.as_str(), "image");
        assert_eq!(ids[1].scheme.as_str(), "attestation");
        assert_eq!(ids[2].scheme.as_str(), "acme_corp_id");
        assert_eq!(ids[3].scheme.as_str(), "internal_ticket");
    }

    // ----------------------------------------------------------------
    // parse_image_ref_components — image-tier auto-detection helper
    // ----------------------------------------------------------------

    #[test]
    fn parse_image_ref_full_form() {
        let (registry, name, tag) =
            parse_image_ref_components("docker.io/acme/foo:v1");
        assert_eq!(registry.as_deref(), Some("docker.io"));
        assert_eq!(name, "acme/foo");
        assert_eq!(tag.as_deref(), Some("v1"));
    }

    #[test]
    fn parse_image_ref_no_registry() {
        let (registry, name, tag) = parse_image_ref_components("acme/foo:v1");
        assert_eq!(registry, None);
        assert_eq!(name, "acme/foo");
        assert_eq!(tag.as_deref(), Some("v1"));
    }

    #[test]
    fn parse_image_ref_no_tag() {
        let (registry, name, tag) = parse_image_ref_components("docker.io/acme/foo");
        assert_eq!(registry.as_deref(), Some("docker.io"));
        assert_eq!(name, "acme/foo");
        assert_eq!(tag, None);
    }

    #[test]
    fn parse_image_ref_localhost_registry() {
        let (registry, name, tag) =
            parse_image_ref_components("localhost:5000/foo:v1");
        assert_eq!(registry.as_deref(), Some("localhost:5000"));
        assert_eq!(name, "foo");
        assert_eq!(tag.as_deref(), Some("v1"));
    }

    #[test]
    fn parse_image_ref_strips_trailing_digest() {
        let (registry, name, tag) = parse_image_ref_components(
            "docker.io/acme/foo:v1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert_eq!(registry.as_deref(), Some("docker.io"));
        assert_eq!(name, "acme/foo");
        assert_eq!(tag.as_deref(), Some("v1"));
    }

    // ---------- Milestone 077 — validate_root_field ----------

    #[test]
    fn validate_root_field_accepts_simple_name() {
        let r = validate_root_field("widget-svc", "--root-name");
        assert_eq!(r.as_deref().ok(), Some("widget-svc"));
    }

    #[test]
    fn validate_root_field_accepts_npm_scoped_name() {
        // Per Q1 clarification: `@` and `/` are PURL-reserved but NOT
        // rejected at parse — they're URL-encoded at PURL emission.
        let r = validate_root_field("@acme/widget-svc", "--root-name");
        assert_eq!(r.as_deref().ok(), Some("@acme/widget-svc"));
    }

    #[test]
    fn validate_root_field_accepts_version_with_dots() {
        let r = validate_root_field("1.2.3", "--root-version");
        assert_eq!(r.as_deref().ok(), Some("1.2.3"));
    }

    #[test]
    fn validate_root_field_rejects_empty() {
        let r = validate_root_field("", "--root-name");
        let err = r.unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
        assert!(err.contains("--root-name"), "got: {err}");
    }

    #[test]
    fn validate_root_field_rejects_whitespace() {
        let r = validate_root_field("my widget svc", "--root-name");
        let err = r.unwrap_err();
        assert!(err.contains("whitespace"), "got: {err}");
        assert!(err.contains("position 2"), "got: {err}");
    }

    #[test]
    fn validate_root_field_rejects_control_char() {
        let r = validate_root_field("foo\x01bar", "--root-name");
        let err = r.unwrap_err();
        assert!(err.contains("control character"), "got: {err}");
        assert!(err.contains("U+0001"), "got: {err}");
    }

    #[test]
    fn validate_root_field_rejects_question_mark() {
        let r = validate_root_field("foo?bar", "--root-name");
        let err = r.unwrap_err();
        assert!(err.contains("URL-syntax-breaking"), "got: {err}");
        assert!(err.contains("'?'"), "got: {err}");
        assert!(err.contains("position 3"), "got: {err}");
    }

    #[test]
    fn validate_root_field_rejects_hash() {
        let r = validate_root_field("foo#bar", "--root-name");
        let err = r.unwrap_err();
        assert!(err.contains("URL-syntax-breaking"), "got: {err}");
        assert!(err.contains("'#'"), "got: {err}");
    }

    // ──────────────────────────────────────────────────────────────
    // Milestone 111 — pkg-alias wiring tests.
    //
    // Cover the algorithmic surface: build_pkg_alias_map (CLI + env
    // composition + conflict detection) and attach_bindings_to_components
    // (alias-rewrite behavior, FR-007 reason rewrite, FR-013 envelope
    // population, FR-011 unused-alias tracking, SC-004 byte-identity
    // for no-alias path). End-to-end CLI integration via a real
    // --image fixture is deferred to a follow-on PR.
    // ──────────────────────────────────────────────────────────────

    use waybill::binding::alias::{AliasMap, PurlAlias};
    use waybill::binding::{
        BindingStrength, SourceDocumentBinding, SourceDocumentId, SourceSbomContext,
    };
    use waybill_common::resolution::ResolvedComponent;
    use waybill_common::types::purl::Purl;

    /// Shared env-mutation lock for env-var-touching tests below.
    /// Same pattern as milestone 110's `fingerprints::test_env_lock`.
    fn pkg_alias_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn make_alias(lhs: &str, rhs: &str) -> PurlAlias {
        PurlAlias::try_new(lhs, rhs).unwrap()
    }

    fn make_component(purl_str: &str) -> ResolvedComponent {
        use waybill_common::resolution::{ResolutionEvidence, ResolutionTechnique};
        let purl = Purl::new(purl_str).unwrap();
        ResolvedComponent {
            build_inclusion: None,
            name: purl.name().to_string(),
            version: purl.version().unwrap_or("0.0.0").to_string(),
            purl,
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::UrlPattern,
                confidence: 0.95,
                source_connection_ids: vec![],
                source_file_paths: vec![],
                deps_dev_match: None,
            },
            licenses: vec![],
            concluded_licenses: vec![],
            hashes: vec![],
            supplier: None,
            cpes: vec![],
            advisories: vec![],
            occurrences: vec![],
            lifecycle_scope: None,
            requirement_ranges: Vec::new(),
            source_type: None,
            sbom_tier: None,
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
            parent_purl: None,
            co_owned_by: None,
            shade_relocation: None,
            external_references: vec![],
            extra_annotations: Default::default(),
            binary_role: None,
        }
    }

    fn make_source_ctx(
        purls: &[(&str, Option<SourceDocumentBinding>)],
    ) -> SourceSbomContext {
        let mut source_purls = std::collections::BTreeSet::new();
        let mut source_bindings_by_purl = std::collections::BTreeMap::new();
        for (purl, binding) in purls {
            source_purls.insert((*purl).to_string());
            if let Some(b) = binding {
                source_bindings_by_purl.insert((*purl).to_string(), b.clone());
            }
        }
        SourceSbomContext {
            source_doc_id: SourceDocumentId {
                sha256: "1".repeat(64),
                iri: None,
            },
            source_purls,
            source_bindings_by_purl,
            binary_name_to_purl: std::collections::HashMap::new(),
        }
    }

    fn fixture_verified_source_binding() -> SourceDocumentBinding {
        SourceDocumentBinding {
            source_doc_id: SourceDocumentId {
                sha256: "1".repeat(64),
                iri: None,
            },
            hash: Some(
                waybill::binding::BindingHash::from_hex("a".repeat(64)).unwrap(),
            ),
            strength: BindingStrength::Verified,
            reason: None,
            algo: "v1".to_string(),
            alias_from: None,
            alias_to: None,
            alias_source: None,
        }
    }

    // ── build_pkg_alias_map ───────────────────────────────────────

    #[test]
    fn build_pkg_alias_map_empty_when_no_input() {
        let _g = pkg_alias_env_lock();
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.pkg_alias = vec![];
        unsafe {
            std::env::remove_var("WAYBILL_PKG_ALIAS");
        }
        let map = build_pkg_alias_map(&args).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn build_pkg_alias_map_collects_cli_flags() {
        let _g = pkg_alias_env_lock();
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.pkg_alias =
            vec![make_alias("pkg:generic/baz", "pkg:cargo/baz@1.0.0")];
        unsafe {
            std::env::remove_var("WAYBILL_PKG_ALIAS");
        }
        let map = build_pkg_alias_map(&args).unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn build_pkg_alias_map_unions_cli_and_env_var_entries() {
        let _g = pkg_alias_env_lock();
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.pkg_alias =
            vec![make_alias("pkg:generic/baz", "pkg:cargo/baz@1.0.0")];
        unsafe {
            std::env::set_var(
                "WAYBILL_PKG_ALIAS",
                "pkg:generic/qux=pkg:npm/qux@2.0.0",
            );
        }
        let map = build_pkg_alias_map(&args).unwrap();
        unsafe {
            std::env::remove_var("WAYBILL_PKG_ALIAS");
        }
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn build_pkg_alias_map_skips_blank_env_entries() {
        let _g = pkg_alias_env_lock();
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.pkg_alias = vec![];
        unsafe {
            std::env::set_var(
                "WAYBILL_PKG_ALIAS",
                ",,pkg:generic/baz=pkg:cargo/baz@1.0.0,,",
            );
        }
        let map = build_pkg_alias_map(&args).unwrap();
        unsafe {
            std::env::remove_var("WAYBILL_PKG_ALIAS");
        }
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn build_pkg_alias_map_rejects_conflicting_lhs_across_cli_and_env() {
        let _g = pkg_alias_env_lock();
        let mut args = enrich_args(false, false, false, false, vec![]);
        args.pkg_alias =
            vec![make_alias("pkg:generic/baz", "pkg:cargo/baz@1.0.0")];
        unsafe {
            std::env::set_var(
                "WAYBILL_PKG_ALIAS",
                "pkg:generic/baz=pkg:cargo/baz@1.1.0",
            );
        }
        let result = build_pkg_alias_map(&args);
        unsafe {
            std::env::remove_var("WAYBILL_PKG_ALIAS");
        }
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("declared twice with conflicting RHS"),
            "expected conflict-named error; got: {msg}"
        );
    }

    // ── attach_bindings_to_components: alias-rewrite ──────────────

    #[test]
    fn attach_bindings_empty_alias_map_preserves_pre_feature_behavior() {
        // SC-004 byte-identity prerequisite: with no aliases, the
        // function MUST behave exactly as before — components with
        // PURL in source get the source binding; components without
        // get Unknown { reason: "source-not-found-in-bind-target" }.
        let mut components = vec![make_component("pkg:cargo/baz@1.0.0")];
        let ctx = make_source_ctx(&[(
            "pkg:cargo/baz@1.0.0",
            Some(fixture_verified_source_binding()),
        )]);
        let alias_map = AliasMap::new();

        let consumed =
            attach_bindings_to_components(&mut components, &ctx, &alias_map);

        assert!(consumed.is_empty());
        let envelope = components[0]
            .extra_annotations
            .get(waybill::binding::BINDING_PROPERTY_NAME)
            .expect("envelope present");
        let binding: SourceDocumentBinding =
            serde_json::from_value(envelope.clone()).unwrap();
        assert_eq!(binding.strength, BindingStrength::Verified);
        assert!(binding.alias_from.is_none());
        assert!(binding.alias_to.is_none());
    }

    #[test]
    fn attach_bindings_with_alias_rewrites_lookup_and_stamps_envelope() {
        // The US1 motivating case: image-tier emits pkg:generic/baz,
        // source-tier carries pkg:cargo/baz@1.0.0. Alias declares the
        // synonym → binding.strength becomes Verified AND
        // alias_from/alias_to are populated.
        let mut components = vec![make_component("pkg:generic/baz")];
        let ctx = make_source_ctx(&[(
            "pkg:cargo/baz@1.0.0",
            Some(fixture_verified_source_binding()),
        )]);
        let mut alias_map = AliasMap::new();
        alias_map
            .insert(make_alias("pkg:generic/baz", "pkg:cargo/baz@1.0.0"))
            .unwrap();

        let consumed =
            attach_bindings_to_components(&mut components, &ctx, &alias_map);

        assert_eq!(consumed.len(), 1);
        assert!(consumed.contains("pkg:generic/baz"));

        let envelope = components[0]
            .extra_annotations
            .get(waybill::binding::BINDING_PROPERTY_NAME)
            .expect("envelope present");
        let binding: SourceDocumentBinding =
            serde_json::from_value(envelope.clone()).unwrap();
        assert_eq!(
            binding.strength,
            BindingStrength::Verified,
            "alias-rewritten lookup should bind to source's verified entry"
        );
        assert_eq!(
            binding.alias_from.as_ref().unwrap().as_str(),
            "pkg:generic/baz"
        );
        assert_eq!(
            binding.alias_to.as_ref().unwrap().as_str(),
            "pkg:cargo/baz@1.0.0"
        );
    }

    #[test]
    fn attach_bindings_rewrites_reason_when_alias_target_missing() {
        // FR-007: when an alias was applied but the RHS PURL is NOT
        // in the bind-source SBOM, the reason rewrites from
        // `source-not-found-in-bind-target` to
        // `alias-target-not-found-in-bind-target` so operators can
        // distinguish the alias-misconfiguration case from the
        // missing-source-document case.
        let mut components = vec![make_component("pkg:generic/baz")];
        // Source SBOM is empty — neither LHS nor RHS exists in it.
        let ctx = make_source_ctx(&[]);
        let mut alias_map = AliasMap::new();
        alias_map
            .insert(make_alias("pkg:generic/baz", "pkg:cargo/baz@1.0.0"))
            .unwrap();

        attach_bindings_to_components(&mut components, &ctx, &alias_map);

        let envelope = components[0]
            .extra_annotations
            .get(waybill::binding::BINDING_PROPERTY_NAME)
            .expect("envelope present");
        let binding: SourceDocumentBinding =
            serde_json::from_value(envelope.clone()).unwrap();
        assert_eq!(binding.strength, BindingStrength::Unknown);
        assert_eq!(
            binding.reason.as_deref(),
            Some("alias-target-not-found-in-bind-target")
        );
        // alias_from/alias_to MUST still be populated so consumers can
        // see the alias was attempted even though it didn't resolve.
        assert!(binding.alias_from.is_some());
        assert!(binding.alias_to.is_some());
    }

    #[test]
    fn attach_bindings_unused_lhs_not_in_consumed_set() {
        // FR-011: when an alias's LHS does not match any scan-output
        // component, the LHS is NOT marked as consumed (the caller
        // logs it as an info-level unused-alias diagnostic).
        let mut components = vec![make_component("pkg:cargo/other@1.0.0")];
        let ctx = make_source_ctx(&[("pkg:cargo/other@1.0.0", None)]);
        let mut alias_map = AliasMap::new();
        alias_map
            .insert(make_alias("pkg:generic/baz", "pkg:cargo/baz@1.0.0"))
            .unwrap();

        let consumed =
            attach_bindings_to_components(&mut components, &ctx, &alias_map);

        assert!(consumed.is_empty(), "no alias LHS matched any component");
    }

    #[test]
    fn attach_bindings_supports_same_rhs_multiple_lhs_distinct_components() {
        // U1 non-collapse invariant per /speckit-analyze: two distinct
        // LHS aliases targeting the same RHS keep their components
        // distinct in the output; both bind to the same source-tier
        // counterpart with strength=Verified.
        let mut components = vec![
            make_component("pkg:generic/baz-cli"),
            make_component("pkg:generic/baz-daemon"),
        ];
        let ctx = make_source_ctx(&[(
            "pkg:cargo/baz@1.0.0",
            Some(fixture_verified_source_binding()),
        )]);
        let mut alias_map = AliasMap::new();
        alias_map
            .insert(make_alias("pkg:generic/baz-cli", "pkg:cargo/baz@1.0.0"))
            .unwrap();
        alias_map
            .insert(make_alias(
                "pkg:generic/baz-daemon",
                "pkg:cargo/baz@1.0.0",
            ))
            .unwrap();

        let consumed =
            attach_bindings_to_components(&mut components, &ctx, &alias_map);

        assert_eq!(
            consumed.len(),
            2,
            "both LHSes should be consumed independently"
        );
        for c in &components {
            let envelope = c
                .extra_annotations
                .get(waybill::binding::BINDING_PROPERTY_NAME)
                .expect("envelope present on both");
            let binding: SourceDocumentBinding =
                serde_json::from_value(envelope.clone()).unwrap();
            assert_eq!(binding.strength, BindingStrength::Verified);
            assert_eq!(
                binding.alias_to.as_ref().unwrap().as_str(),
                "pkg:cargo/baz@1.0.0"
            );
        }
        // Critical: component identities (their own purl) MUST NOT
        // collapse — two distinct components must still be present.
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].purl.as_str(), "pkg:generic/baz-cli");
        assert_eq!(components[1].purl.as_str(), "pkg:generic/baz-daemon");
    }

    // ----- Milestone 144: clap-parser tests for --max-rpm-bytes
    // and --rpm-distro (T025-T027 + T032-T034). -----

    /// T025 (FR-005): valid unsigned integer is accepted; `parsed.inner.max_rpm_bytes`
    /// carries the operator-supplied value.
    #[test]
    fn max_rpm_bytes_accepts_valid_unsigned() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--max-rpm-bytes",
            "1073741824",
        ])
        .unwrap();
        assert_eq!(parsed.inner.max_rpm_bytes, Some(1073741824));
    }

    /// T026 (FR-005 + US3-3): zero is rejected at clap parse time with
    /// the "must be > 0" error message.
    #[test]
    fn max_rpm_bytes_rejects_zero() {
        let err = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--max-rpm-bytes",
            "0",
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be > 0"), "got: {err}");
    }

    /// T027 (FR-005): non-numeric input is rejected at clap parse time.
    #[test]
    fn max_rpm_bytes_rejects_non_numeric() {
        let err = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--max-rpm-bytes",
            "abc",
        ])
        .unwrap_err();
        // Error message will mention parsing failure; exact wording is
        // clap-version-dependent, so just assert it failed at parse time.
        let s = err.to_string();
        assert!(!s.is_empty(), "expected a parse error");
    }

    /// T032 (FR-003): a lowercase slug is accepted unchanged.
    #[test]
    fn rpm_distro_accepts_lowercase_slug() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--rpm-distro",
            "poky",
        ])
        .unwrap();
        assert_eq!(parsed.inner.rpm_distro.as_deref(), Some("poky"));
    }

    /// T033 (FR-003 + US4-3): empty string is rejected at clap parse time
    /// with the "must be non-empty" error message.
    #[test]
    fn rpm_distro_rejects_empty_string() {
        let err = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--rpm-distro",
            "",
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be non-empty"), "got: {err}");
    }

    /// T034 (FR-003 + assumption 2): mixed-case input is lowercased by
    /// the `value_parser` closure so the resulting PURL namespace is
    /// canonical per purl-spec §lower-case-rules.
    #[test]
    fn rpm_distro_lowercases_input() {
        let parsed = <ScanArgsForTest as clap::Parser>::try_parse_from([
            "scan",
            "--path",
            ".",
            "--rpm-distro",
            "Poky",
        ])
        .unwrap();
        assert_eq!(parsed.inner.rpm_distro.as_deref(), Some("poky"));
    }

    // =========================================================
    // Milestone 232 — --tier=<mode> output-filter flag
    // =========================================================

    fn mk_tier_component(purl_str: &str, tier: &str) -> ResolvedComponent {
        let mut c = make_component(purl_str);
        c.sbom_tier = Some(tier.to_string());
        c
    }

    fn mk_edge(from: &str, to: &str) -> waybill_common::resolution::Relationship {
        use waybill_common::resolution::{
            EnrichmentProvenance, Relationship, RelationshipType,
        };
        Relationship {
            from: from.to_string(),
            to: to.to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "dependency".to_string(),
            },
        }
    }

    #[test]
    fn apply_tier_filter_source_only_drops_design() {
        let mut components = vec![
            mk_tier_component("pkg:cargo/src1@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src2@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src3@1.0.0", "source"),
            mk_tier_component("pkg:cargo/dsn1@1.0.0", "design"),
            mk_tier_component("pkg:cargo/dsn2@1.0.0", "design"),
            mk_tier_component("pkg:cargo/bin1@1.0.0", "binary"),
        ];
        let mut edges: Vec<waybill_common::resolution::Relationship> = vec![];
        apply_tier_filter(&mut components, &mut edges, TierMode::SourceOnly);
        assert_eq!(components.len(), 3);
        assert!(components.iter().all(|c| c.sbom_tier.as_deref() == Some("source")));
    }

    #[test]
    fn apply_tier_filter_drops_dangling_edges() {
        let mut components = vec![
            mk_tier_component("pkg:cargo/src1@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src2@1.0.0", "source"),
            mk_tier_component("pkg:cargo/dsn1@1.0.0", "design"),
            mk_tier_component("pkg:cargo/dsn2@1.0.0", "design"),
        ];
        let mut edges = vec![
            mk_edge("pkg:cargo/src1@1.0.0", "pkg:cargo/src2@1.0.0"),
            mk_edge("pkg:cargo/src1@1.0.0", "pkg:cargo/dsn1@1.0.0"),
            mk_edge("pkg:cargo/dsn1@1.0.0", "pkg:cargo/src2@1.0.0"),
            mk_edge("pkg:cargo/dsn1@1.0.0", "pkg:cargo/dsn2@1.0.0"),
        ];
        apply_tier_filter(&mut components, &mut edges, TierMode::SourceOnly);
        assert_eq!(edges.len(), 1, "only src→src survives; got {:?}", edges);
        assert_eq!(edges[0].from, "pkg:cargo/src1@1.0.0");
        assert_eq!(edges[0].to, "pkg:cargo/src2@1.0.0");
    }

    #[test]
    fn apply_tier_filter_design_only_keeps_only_design() {
        let mut components = vec![
            mk_tier_component("pkg:cargo/src1@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src2@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src3@1.0.0", "source"),
            mk_tier_component("pkg:cargo/dsn1@1.0.0", "design"),
            mk_tier_component("pkg:cargo/dsn2@1.0.0", "design"),
            mk_tier_component("pkg:cargo/bin1@1.0.0", "binary"),
        ];
        let mut edges: Vec<waybill_common::resolution::Relationship> = vec![];
        apply_tier_filter(&mut components, &mut edges, TierMode::DesignOnly);
        assert_eq!(components.len(), 2);
        assert!(components.iter().all(|c| c.sbom_tier.as_deref() == Some("design")));
    }

    #[test]
    fn apply_tier_filter_source_and_binary_keeps_both() {
        let mut components = vec![
            mk_tier_component("pkg:cargo/src1@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src2@1.0.0", "source"),
            mk_tier_component("pkg:cargo/src3@1.0.0", "source"),
            mk_tier_component("pkg:cargo/dsn1@1.0.0", "design"),
            mk_tier_component("pkg:cargo/dsn2@1.0.0", "design"),
            mk_tier_component("pkg:cargo/bin1@1.0.0", "binary"),
        ];
        let mut edges: Vec<waybill_common::resolution::Relationship> = vec![];
        apply_tier_filter(&mut components, &mut edges, TierMode::SourceAndBinary);
        assert_eq!(components.len(), 4, "3 source + 1 binary survive");
        assert!(components
            .iter()
            .all(|c| matches!(c.sbom_tier.as_deref(), Some("source") | Some("binary"))));
    }

    #[test]
    fn apply_tier_filter_all_is_noop() {
        let mut components = vec![
            mk_tier_component("pkg:cargo/src1@1.0.0", "source"),
            mk_tier_component("pkg:cargo/dsn1@1.0.0", "design"),
        ];
        let mut edges = vec![mk_edge(
            "pkg:cargo/src1@1.0.0",
            "pkg:cargo/dsn1@1.0.0",
        )];
        apply_tier_filter(&mut components, &mut edges, TierMode::All);
        assert_eq!(components.len(), 2, "All mode is a no-op filter");
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn apply_tier_filter_empty_result() {
        // FR-008 unit-level check — an all-design fixture with
        // TierMode::SourceOnly leaves both components and edges empty.
        // The WARN log emission is asserted at integration-test tier
        // via T017b.
        let mut components = vec![
            mk_tier_component("pkg:cargo/dsn1@1.0.0", "design"),
            mk_tier_component("pkg:cargo/dsn2@1.0.0", "design"),
        ];
        let mut edges: Vec<waybill_common::resolution::Relationship> =
            vec![mk_edge("pkg:cargo/dsn1@1.0.0", "pkg:cargo/dsn2@1.0.0")];
        apply_tier_filter(&mut components, &mut edges, TierMode::SourceOnly);
        assert!(components.is_empty());
        assert!(edges.is_empty());
    }

    #[test]
    fn apply_tier_filter_analyzed_and_file_dropped_under_source_only() {
        // FR-010 strict-literal-match — analyzed and file tiers do NOT
        // survive source-only per Clarifications §1.
        let mut components = vec![
            mk_tier_component("pkg:cargo/src1@1.0.0", "source"),
            mk_tier_component("pkg:cargo/ana1@1.0.0", "analyzed"),
            mk_tier_component("pkg:generic/file1@0.0.0", "file"),
        ];
        let mut edges: Vec<waybill_common::resolution::Relationship> = vec![];
        apply_tier_filter(&mut components, &mut edges, TierMode::SourceOnly);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].sbom_tier.as_deref(), Some("source"));
    }
}
