//! `mikebom sbom enrich` — feature 006 US5.

use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct EnrichArgs {
    /// Path to CycloneDX SBOM file to enrich in place.
    pub sbom_file: PathBuf,

    /// Output path. Defaults to overwriting `sbom_file`.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// RFC 6902 JSON Patch file. Repeatable: patches are applied in
    /// order (later ops see earlier ones).
    #[arg(long = "patch", value_name = "PATH")]
    pub patch: Vec<PathBuf>,

    /// Recorded author of the enrichment. Defaults to "unknown" with
    /// a warning.
    #[arg(long)]
    pub author: Option<String>,

    /// Optional path to the attestation this SBOM was derived from.
    /// Its SHA-256 gets embedded so verifiers can walk back.
    #[arg(long = "base-attestation", value_name = "PATH")]
    pub base_attestation: Option<PathBuf>,

    // ─ Legacy no-op flags preserved on the stub signature ─
    #[arg(long)]
    pub skip_vex: bool,
    #[arg(long)]
    pub skip_licenses: bool,
    #[arg(long)]
    pub skip_supplier: bool,
    #[arg(long)]
    pub vex_overrides: Option<PathBuf>,
    #[arg(long, default_value = "5000")]
    pub deps_dev_timeout: u64,
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: EnrichArgs, _offline: bool) -> anyhow::Result<()> {
    if args.patch.is_empty() {
        anyhow::bail!("at least one --patch <PATH> is required for enrichment");
    }

    let author = match &args.author {
        Some(a) => a.clone(),
        None => {
            tracing::warn!(
                "enrichment author not specified — downstream traceability degraded"
            );
            "unknown".to_string()
        }
    };

    let base_sha = match &args.base_attestation {
        Some(p) => Some(crate::sbom::mutator::attestation_sha256(p).map_err(|e| {
            anyhow::anyhow!("cannot hash base attestation {}: {e}", p.display())
        })?),
        None => None,
    };

    let sbom_text = std::fs::read_to_string(&args.sbom_file).map_err(|e| {
        anyhow::anyhow!("cannot read SBOM {}: {e}", args.sbom_file.display())
    })?;
    let sbom: serde_json::Value = serde_json::from_str(&sbom_text)
        .map_err(|e| anyhow::anyhow!("SBOM JSON parse failed: {e}"))?;

    // Load each patch file into an owned Value; keep vectors parallel
    // so EnrichmentPatch can borrow from them.
    let mut patch_values: Vec<serde_json::Value> = Vec::with_capacity(args.patch.len());
    for p in &args.patch {
        let txt = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("cannot read patch {}: {e}", p.display()))?;
        let v: serde_json::Value = serde_json::from_str(&txt)
            .map_err(|e| anyhow::anyhow!("patch JSON parse failed for {}: {e}", p.display()))?;
        patch_values.push(v);
    }

    let now = chrono::Utc::now();
    let patches: Vec<crate::sbom::mutator::EnrichmentPatch<'_>> = patch_values
        .iter()
        .map(|ops| crate::sbom::mutator::EnrichmentPatch {
            operations: ops,
            author: &author,
            timestamp: now,
            base_attestation_sha256: base_sha.clone(),
        })
        .collect();

    let enriched = crate::sbom::mutator::enrich(&sbom, &patches)
        .map_err(|e| anyhow::anyhow!("enrichment failed: {e}"))?;

    let out_path = args.output.as_ref().unwrap_or(&args.sbom_file);
    std::fs::write(out_path, serde_json::to_string_pretty(&enriched)?)?;
    tracing::info!(
        "Enriched SBOM written to {} ({} patch(es) applied)",
        out_path.display(),
        patches.len()
    );
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "sbom_file": out_path.to_string_lossy(),
                "patches_applied": patches.len(),
                "author": author,
            }))?
        );
    }
    Ok(())
}
