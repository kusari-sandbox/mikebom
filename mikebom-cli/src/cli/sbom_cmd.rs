use clap::{Args, Subcommand};

use super::compare::CompareArgs;
use super::enrich::EnrichArgs;
use super::generate::GenerateArgs;
use super::scan_cmd::ScanArgs;
use super::validate::ValidateArgs;

#[derive(Args)]
pub struct SbomCommand {
    #[command(subcommand)]
    pub command: SbomSubcommand,
}

#[derive(Subcommand)]
pub enum SbomSubcommand {
    /// Generate an SBOM from an attestation file
    Generate(GenerateArgs),
    /// Add license, VEX, and supplier data to an existing SBOM
    Enrich(EnrichArgs),
    /// Validate an SBOM file for conformance
    Validate(ValidateArgs),
    /// Compare mikebom's SBOM against syft/trivy + ground truth
    Compare(CompareArgs),
    /// Walk a directory (or an extracted container image) and produce
    /// an SBOM from the package artifacts on disk. No eBPF required —
    /// runs anywhere Rust runs.
    Scan(ScanArgs),
}

pub async fn execute(
    cmd: SbomCommand,
    offline: bool,
    include_dev: bool,
    include_legacy_rpmdb: bool,
) -> anyhow::Result<()> {
    match cmd.command {
        SbomSubcommand::Generate(args) => super::generate::execute(args, offline).await,
        SbomSubcommand::Enrich(args) => super::enrich::execute(args, offline).await,
        SbomSubcommand::Validate(args) => super::validate::execute(args).await,
        SbomSubcommand::Compare(args) => super::compare::execute(args).await,
        SbomSubcommand::Scan(args) => {
            super::scan_cmd::execute(args, offline, include_dev, include_legacy_rpmdb).await
        }
    }
}
