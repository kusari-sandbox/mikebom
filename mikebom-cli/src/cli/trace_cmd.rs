use clap::{Args, Subcommand};

use super::run::RunArgs;
use super::scan::ScanArgs;

/// [EXPERIMENTAL] eBPF-based build-time tracing.
///
/// Captures process syscalls, network connections, and file operations
/// while a build command runs, and binds the resulting attestation to
/// the specific built artifacts. Linux-only, requires CAP_BPF +
/// CAP_PERFMON, and adds ~2-3× wall-clock overhead on syscall-heavy
/// builds.
///
/// This subtree is marked experimental because:
/// - Coverage varies by syscall path (openat2 / io_uring gaps).
/// - Overhead is workload-dependent and can be significant.
/// - The witness-v0.1 attestation format is stable, but the full
///   Fulcio/Rekor keyless flow is still scaffold-level.
///
/// For most SBOM use cases (polyglot source trees, container images,
/// package caches), prefer the stable `mikebom sbom scan` pipeline
/// which produces richer output with no privilege requirements.
#[derive(Args)]
pub struct TraceCommand {
    #[command(subcommand)]
    pub command: TraceSubcommand,
}

#[derive(Subcommand)]
pub enum TraceSubcommand {
    /// [EXPERIMENTAL, Linux-only] Capture a build trace via eBPF and produce an in-toto attestation
    Capture(ScanArgs),
    /// [EXPERIMENTAL, Linux-only] Capture a trace and generate an SBOM in one step
    Run(RunArgs),
}

pub async fn execute(cmd: TraceCommand) -> anyhow::Result<()> {
    match cmd.command {
        TraceSubcommand::Capture(args) => super::scan::execute(args).await,
        TraceSubcommand::Run(args) => super::run::execute(args).await,
    }
}
