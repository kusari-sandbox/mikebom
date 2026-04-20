use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct EnrichArgs {
    /// Path to CycloneDX or SPDX SBOM file
    pub sbom_file: PathBuf,

    /// Output path
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Skip VEX enrichment
    #[arg(long)]
    pub skip_vex: bool,

    /// Skip license enrichment
    #[arg(long)]
    pub skip_licenses: bool,

    /// Skip supplier metadata enrichment
    #[arg(long)]
    pub skip_supplier: bool,

    /// VEX override file for manual triage states
    #[arg(long)]
    pub vex_overrides: Option<PathBuf>,

    /// Timeout per deps.dev API call in milliseconds
    #[arg(long, default_value = "5000")]
    pub deps_dev_timeout: u64,

    /// Output enrichment summary as JSON to stdout
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(_args: EnrichArgs, _offline: bool) -> anyhow::Result<()> {
    anyhow::bail!("enrich command not yet implemented — see Phase 6 (US4)")
}
