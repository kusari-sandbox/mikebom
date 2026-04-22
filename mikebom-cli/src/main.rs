// Milestone 003 T012: production code MUST NOT use `.unwrap()` — see
// `.specify/memory/constitution.md` Principle IV and
// `specs/003-multi-ecosystem-expansion/research.md` R10. Test modules
// opt back in via `#[cfg_attr(test, allow(clippy::unwrap_used))]` on
// their `#[cfg(test)] mod tests` block; see existing examples in
// `scan_fs/package_db/npm.rs` and friends.
#![deny(clippy::unwrap_used)]

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod attestation;
mod cli;
mod config;
mod enrich;
mod error;
mod generate;
mod resolve;
mod scan_fs;
mod trace;

#[derive(Parser)]
#[command(name = "mikebom", version, about = "eBPF-based SBOM generator")]
struct Cli {
    /// Disable all outbound network calls (deps.dev license/CPE lookups,
    /// deps.dev hash queries). When set, enrichment falls back to what
    /// can be derived from the local filesystem and package databases
    /// alone. Useful for air-gapped scanners, reproducible-build
    /// environments, and CI runs that can't reach the internet.
    #[arg(long, global = true)]
    offline: bool,

    /// Include development / test / optional dependencies in the SBOM.
    /// Off by default: the scanner emits only production components.
    /// Affects ecosystems that carry a dev/prod distinction (npm,
    /// Poetry, Pipfile). Venv dist-info scans and requirements.txt
    /// scans are unaffected — they do not carry a dev/prod marker.
    /// Components included via this flag carry a `mikebom:dev-dependency
    /// = true` property so downstream consumers can filter them back
    /// out after the fact.
    #[arg(long, global = true)]
    include_dev: bool,

    /// Enable reading of legacy Berkeley-DB rpmdb (`/var/lib/rpm/Packages`)
    /// on pre-RHEL-8 / CentOS-7 / Amazon-Linux-2 images. Off by default;
    /// preserves milestone-003 behaviour (diagnostic log, zero components)
    /// so existing scans don't silently change output. Canonical
    /// invocation: `mikebom sbom scan --include-legacy-rpmdb …`. Also
    /// enabled via `MIKEBOM_INCLUDE_LEGACY_RPMDB=1`. Milestone 004 US4.
    #[arg(long, global = true, env = "MIKEBOM_INCLUDE_LEGACY_RPMDB")]
    include_legacy_rpmdb: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// eBPF build-process tracing
    Trace(cli::trace_cmd::TraceCommand),
    /// SBOM generation, enrichment, and validation
    Sbom(cli::sbom_cmd::SbomCommand),
    /// Attestation management
    Attestation(cli::attestation_cmd::AttestationCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    // Default: INFO + WARN visible at stderr; users override via RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Trace(cmd) => {
            cli::trace_cmd::execute(cmd).await?;
            Ok(std::process::ExitCode::from(0))
        }
        Commands::Sbom(cmd) => {
            cli::sbom_cmd::execute(cmd, cli.offline, cli.include_dev, cli.include_legacy_rpmdb)
                .await
        }
        Commands::Attestation(cmd) => {
            cli::attestation_cmd::execute(cmd).await?;
            Ok(std::process::ExitCode::from(0))
        }
    }
}
