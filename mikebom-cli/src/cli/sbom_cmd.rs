use clap::{Args, Subcommand};

use std::process::ExitCode;

use super::enrich::EnrichArgs;
use super::generate::GenerateArgs;
use super::parity_cmd::ParityCheckArgs;
use super::scan_cmd::ScanArgs;
use super::verify::VerifyArgs;

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
    /// Verify a signed attestation (DSSE envelope) against a key /
    /// identity / layout
    Verify(VerifyArgs),
    /// Walk a directory (or an extracted container image) and produce
    /// an SBOM from the package artifacts on disk. No eBPF required —
    /// runs anywhere Rust runs.
    Scan(ScanArgs),
    /// Run a per-datum × per-format coverage check against three
    /// already-emitted format outputs and report any parity gaps.
    /// Drives the milestone-013 user-facing diagnostic.
    ParityCheck(ParityCheckArgs),
}

pub async fn execute(
    cmd: SbomCommand,
    offline: bool,
    include_dev: bool,
    include_legacy_rpmdb: bool,
    include_declared_deps: bool,
) -> anyhow::Result<ExitCode> {
    match cmd.command {
        SbomSubcommand::Generate(args) => {
            super::generate::execute(args, offline).await?;
            Ok(ExitCode::from(0))
        }
        SbomSubcommand::Enrich(args) => {
            super::enrich::execute(args, offline).await?;
            Ok(ExitCode::from(0))
        }
        SbomSubcommand::Verify(args) => super::verify::execute(args).await,
        SbomSubcommand::Scan(args) => {
            super::scan_cmd::execute(
                args,
                offline,
                include_dev,
                include_legacy_rpmdb,
                include_declared_deps,
            )
            .await?;
            Ok(ExitCode::from(0))
        }
        SbomSubcommand::ParityCheck(args) => super::parity_cmd::execute(args).await,
    }
}
