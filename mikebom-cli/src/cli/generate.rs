use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::attestation::serializer;
use crate::enrich::lockfile_source::LockfileSource;
use crate::enrich::pipeline::EnrichmentPipeline;
use crate::generate::cyclonedx::builder::{CycloneDxBuilder, CycloneDxConfig};
use crate::generate::cyclonedx::serializer::write_cyclonedx_json;
use crate::resolve::pipeline::{ResolutionConfig, ResolutionPipeline};

/// What to include in the SBOM component list.
#[derive(Clone, Debug, Default, ValueEnum)]
pub enum SbomScope {
    /// Only resolved packages with PURLs (default)
    #[default]
    Packages,
    /// Packages plus source files observed during the build, with hashes
    Source,
}

#[derive(Args)]
pub struct GenerateArgs {
    /// Path to attestation JSON file
    pub attestation_file: PathBuf,

    /// Output format
    #[arg(long, default_value = "cyclonedx-json")]
    pub format: String,

    /// SBOM output path
    #[arg(long, default_value = "mikebom.cdx.json")]
    pub output: PathBuf,

    /// What to include: packages (default) or source (packages + source files)
    #[arg(long, value_enum, default_value = "packages")]
    pub scope: SbomScope,

    /// Omit per-component hashes from output
    #[arg(long)]
    pub no_hashes: bool,

    /// Also run enrichment (license, VEX, supplier)
    #[arg(long)]
    pub enrich: bool,

    /// Path to a lockfile for dependency relationship enrichment
    #[arg(long)]
    pub lockfile: Option<PathBuf>,

    /// Timeout per deps.dev API call in milliseconds
    #[arg(long, default_value = "5000")]
    pub deps_dev_timeout: u64,

    /// Skip online PURL existence validation
    #[arg(long)]
    pub skip_purl_validation: bool,

    /// VEX override file for manual triage states
    #[arg(long)]
    pub vex_overrides: Option<PathBuf>,

    /// Output generation summary as JSON to stdout
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: GenerateArgs, offline: bool) -> anyhow::Result<()> {
    let _ = offline; // TODO: gate deps.dev enrichment when wired into generate flow.
    tracing::info!(
        attestation = %args.attestation_file.display(),
        "Loading attestation"
    );

    // Load the attestation
    let statement = serializer::read_attestation(&args.attestation_file)?;

    // Resolve components from attestation data
    let resolve_config = ResolutionConfig {
        deps_dev_timeout: std::time::Duration::from_millis(args.deps_dev_timeout),
        skip_online_validation: args.skip_purl_validation,
    };
    let pipeline = ResolutionPipeline::new(resolve_config);
    let mut components = pipeline.resolve(&statement).await?;

    tracing::info!(count = components.len(), "Components resolved");

    if components.is_empty() {
        anyhow::bail!("resolution produced zero components from attestation");
    }

    // Run enrichment sources
    let mut enrichment = EnrichmentPipeline::new();

    // Add lockfile source if specified
    if let Some(ref lockfile_path) = args.lockfile {
        if let Some(lockfile_type) = LockfileSource::detect(lockfile_path) {
            tracing::info!(
                path = %lockfile_path.display(),
                kind = ?lockfile_type,
                "Adding lockfile enrichment source"
            );
            let source = LockfileSource::new(lockfile_path.clone(), lockfile_type);
            enrichment.add_source(Box::new(source));
        } else {
            tracing::warn!(
                path = %lockfile_path.display(),
                "Unrecognized lockfile format, skipping relationship enrichment"
            );
        }
    }

    let relationships = enrichment.enrich(&mut components)?;
    tracing::info!(
        relationships = relationships.len(),
        "Enrichment complete"
    );

    // Determine target name from attestation subject
    let target_name = statement
        .subject
        .first()
        .map(|s| s.name.as_str())
        .unwrap_or("unknown");

    // Build CycloneDX SBOM. generate is only invoked from a trace-sourced
    // attestation, so the context is always a build-time trace here; the
    // scan subcommand carries its own context through its own orchestrator.
    let cdx_config = CycloneDxConfig {
        include_hashes: !args.no_hashes,
        include_source_files: matches!(args.scope, SbomScope::Source),
        generation_context: mikebom_common::attestation::metadata::GenerationContext::BuildTimeTrace,
        // Trace-mode doesn't distinguish dev/prod at capture time.
        include_dev: false,
    };
    let builder = CycloneDxBuilder::new(cdx_config);
    let bom = builder.build(
        &components,
        &relationships,
        &statement.predicate.trace_integrity,
        target_name,
        // Trace-sourced SBOMs never read installed-package databases; no
        // ecosystem can claim `aggregate: complete` here.
        &[],
        // Trace-sourced SBOMs don't walk JARs, so no Maven scan-target
        // coord is available. `metadata.component` stays on the
        // generic `pkg:generic/<target>@0.0.0` placeholder.
        None,
    )?;

    // Write output
    write_cyclonedx_json(&bom, &args.output)?;

    let component_count = components.len();
    tracing::info!(
        output = %args.output.display(),
        components = component_count,
        relationships = relationships.len(),
        "SBOM generated"
    );

    if args.json {
        let summary = serde_json::json!({
            "output_file": args.output.to_string_lossy(),
            "format": args.format,
            "components": component_count,
            "relationships": relationships.len(),
            "scope": format!("{:?}", args.scope),
            "hashes_included": !args.no_hashes,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    }

    Ok(())
}
