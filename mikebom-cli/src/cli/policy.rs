//! `mikebom policy` subcommands — feature 006 US4.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct PolicyCommand {
    #[command(subcommand)]
    pub command: PolicySubcommand,
}

#[derive(Subcommand)]
pub enum PolicySubcommand {
    /// Generate a starter in-toto layout for the given functionary key
    Init(PolicyInitArgs),
}

#[derive(Args, Debug)]
pub struct PolicyInitArgs {
    /// Where to write the layout.
    #[arg(long, default_value = "layout.json")]
    pub output: PathBuf,

    /// PEM-encoded public key of the expected signer.
    #[arg(long = "functionary-key", value_name = "PATH")]
    pub functionary_key: PathBuf,

    /// Name of the single step the layout expects.
    #[arg(long, default_value = "build-trace-capture")]
    pub step_name: String,

    /// How long the layout is valid. Default 1y. Accepts `1y`, `6m`,
    /// `18mo`, `2y`, `30d`, `52w`.
    #[arg(long, default_value = "1y")]
    pub expires: String,

    /// Optional human-readable description embedded in the layout.
    #[arg(long)]
    pub readme: Option<String>,
}

pub async fn execute(cmd: PolicyCommand) -> anyhow::Result<()> {
    match cmd.command {
        PolicySubcommand::Init(args) => execute_init(args).await,
    }
}

async fn execute_init(args: PolicyInitArgs) -> anyhow::Result<()> {
    let pem = std::fs::read_to_string(&args.functionary_key).map_err(|e| {
        anyhow::anyhow!(
            "cannot read functionary key {}: {e}",
            args.functionary_key.display()
        )
    })?;

    let duration = crate::policy::layout::parse_expires_duration(&args.expires)
        .map_err(|e| anyhow::anyhow!("invalid --expires {:?}: {e}", args.expires))?;
    let expires_at = chrono::Utc::now() + duration;

    let layout = crate::policy::layout::generate_starter_layout(
        &pem,
        &args.step_name,
        expires_at,
        args.readme.clone(),
    )
    .map_err(|e| anyhow::anyhow!("layout generation failed: {e}"))?;

    let json = serde_json::to_string_pretty(&layout)?;
    std::fs::write(&args.output, json)?;
    tracing::info!(
        "Layout written to {} (expires {})",
        args.output.display(),
        expires_at.to_rfc3339()
    );
    Ok(())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        cmd: PolicySubcommand,
    }

    #[test]
    fn init_args_clap_shape_is_valid() {
        // Wraps PolicySubcommand in a Parser so we can call ::command()
        // on it (PolicyCommand is #[derive(Args)], not Parser).
        let _ = TestCli::command().debug_assert();
    }
}
