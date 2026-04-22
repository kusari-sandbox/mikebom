use std::path::PathBuf;

use clap::Args;

use super::generate::{GenerateArgs, SbomScope};
use super::scan::ScanArgs;

#[derive(Args)]
pub struct RunArgs {
    /// SBOM output format
    #[arg(long, default_value = "cyclonedx-json")]
    pub format: String,

    /// SBOM output path
    #[arg(long, default_value = "mikebom.cdx.json")]
    pub sbom_output: PathBuf,

    /// Attestation output path
    #[arg(long, default_value = "mikebom.attestation.json")]
    pub attestation_output: PathBuf,

    /// Skip enrichment step
    #[arg(long)]
    pub no_enrich: bool,

    /// Also include observed source files (not just packages)
    #[arg(long)]
    pub include_source_files: bool,

    /// Omit per-component hashes from SBOM
    #[arg(long)]
    pub no_hashes: bool,

    /// Follow forked children of the traced command
    #[arg(long)]
    pub trace_children: bool,

    /// Override libssl.so path for uprobe attachment
    #[arg(long)]
    pub libssl_path: Option<PathBuf>,

    /// Ring buffer size in bytes (must be power of two)
    #[arg(long, default_value = "8388608")]
    pub ring_buffer_size: u32,

    /// Trace timeout in seconds (0 = no timeout)
    #[arg(long, default_value = "0")]
    pub timeout: u64,

    /// Skip online PURL existence validation
    #[arg(long)]
    pub skip_purl_validation: bool,

    /// Path to a lockfile for dependency relationship enrichment
    #[arg(long)]
    pub lockfile: Option<PathBuf>,

    /// Output combined summary as JSON to stdout
    #[arg(long)]
    pub json: bool,

    /// Directories to scan for artifact files after the traced command
    /// exits. Forwarded verbatim to `mikebom trace capture`. See the
    /// `--artifact-dir` flag there for details.
    #[arg(long, value_delimiter = ',')]
    pub artifact_dir: Vec<PathBuf>,

    /// Auto-detect artifact directories from the traced command. See
    /// `mikebom trace capture --help` for the supported tool list.
    #[arg(long)]
    pub auto_dirs: bool,

    // ─────────────────────────────────────────────────────────────
    // Feature 006 — DSSE signing flags forwarded to the scan phase.
    // ─────────────────────────────────────────────────────────────
    /// Path to a PEM-encoded private key for local-key DSSE signing.
    #[arg(long, conflicts_with = "keyless")]
    pub signing_key: Option<PathBuf>,

    /// Env var name holding the passphrase for an encrypted
    /// `--signing-key`.
    #[arg(long, value_name = "NAME")]
    pub signing_key_passphrase_env: Option<String>,

    /// Keyless signing via OIDC → Fulcio → Rekor.
    #[arg(long)]
    pub keyless: bool,

    /// Override Fulcio URL.
    #[arg(long, default_value = "https://fulcio.sigstore.dev")]
    pub fulcio_url: String,

    /// Override Rekor URL.
    #[arg(long, default_value = "https://rekor.sigstore.dev")]
    pub rekor_url: String,

    /// Skip Rekor upload + inclusion-proof embedding (keyless mode).
    #[arg(long)]
    pub no_transparency_log: bool,

    /// Fail if no signing identity was configured.
    #[arg(long)]
    pub require_signing: bool,

    /// Explicit subject artifact path (feature 006 US3). Repeatable.
    /// When set, auto-detection is suppressed.
    #[arg(long = "subject", value_name = "PATH")]
    pub subject: Vec<PathBuf>,

    /// Attestation output format (feature 006). Default `witness-v0.1`
    /// — compatible with `sbomit generate` and go-witness verifiers.
    #[arg(long = "attestation-format", value_name = "FORMAT", default_value = "witness-v0.1")]
    pub attestation_format: String,

    /// Build command to trace
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

pub async fn execute(args: RunArgs) -> anyhow::Result<()> {
    // Phase 1: capture the trace → attestation.
    let scan_args = ScanArgs {
        target_pid: None,
        output: args.attestation_output.clone(),
        trace_children: args.trace_children,
        libssl_path: args.libssl_path.clone(),
        go_binary: None,
        ring_buffer_size: args.ring_buffer_size,
        timeout: args.timeout,
        json: false,
        artifact_dir: args.artifact_dir.clone(),
        auto_dirs: args.auto_dirs,
        // Feature 006 — forward signing flags verbatim.
        signing_key: args.signing_key.clone(),
        signing_key_passphrase_env: args.signing_key_passphrase_env.clone(),
        keyless: args.keyless,
        fulcio_url: args.fulcio_url.clone(),
        rekor_url: args.rekor_url.clone(),
        no_transparency_log: args.no_transparency_log,
        require_signing: args.require_signing,
        subject: args.subject.clone(),
        attestation_format: args.attestation_format.clone(),
        command: args.command.clone(),
    };
    super::scan::execute(scan_args).await?;

    // Phase 2: derive the SBOM from the attestation.
    let generate_args = GenerateArgs {
        attestation_file: args.attestation_output.clone(),
        format: args.format.clone(),
        output: args.sbom_output.clone(),
        scope: if args.include_source_files {
            SbomScope::Source
        } else {
            SbomScope::Packages
        },
        no_hashes: args.no_hashes,
        enrich: !args.no_enrich,
        lockfile: args.lockfile.clone(),
        deps_dev_timeout: 5000,
        skip_purl_validation: args.skip_purl_validation,
        vex_overrides: None,
        json: false,
    };
    // Trace's one-shot `run` wrapper doesn't thread the global --offline
    // flag through (yet). Default to online — the enrichment doesn't
    // block success when deps.dev is unreachable, so offline users get
    // the same SBOM minus the license/CPE upgrades.
    super::generate::execute(generate_args, false).await?;

    if args.json {
        let summary = serde_json::json!({
            "attestation_file": args.attestation_output.to_string_lossy(),
            "sbom_file": args.sbom_output.to_string_lossy(),
            "format": args.format,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    }

    tracing::info!(
        attestation = %args.attestation_output.display(),
        sbom = %args.sbom_output.display(),
        "trace run complete"
    );
    Ok(())
}
