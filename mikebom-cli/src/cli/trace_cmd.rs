use clap::{Args, Subcommand};

use super::run::RunArgs;
use super::scan::ScanArgs;

#[derive(Args)]
pub struct TraceCommand {
    #[command(subcommand)]
    pub command: TraceSubcommand,
}

#[derive(Subcommand)]
pub enum TraceSubcommand {
    /// Capture a build trace via eBPF and produce an in-toto attestation
    Capture(ScanArgs),
    /// Capture a trace and generate an SBOM in one step
    Run(RunArgs),
}

pub async fn execute(cmd: TraceCommand) -> anyhow::Result<()> {
    match cmd.command {
        TraceSubcommand::Capture(args) => super::scan::execute(args).await,
        TraceSubcommand::Run(args) => super::run::execute(args).await,
    }
}
