//! `mikebom sbom verify` — feature 006 US1.
//!
//! Validate a signed DSSE-wrapped attestation. Exit code contract per
//! `specs/006-sbomit-suite/contracts/cli.md`:
//! - `0`: Pass
//! - `1`: signature / identity / subject-digest / transparency-log fail
//! - `2`: envelope malformed / not-signed / cert-chain invalid / cert-expired
//! - `3`: layout violation

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

use crate::attestation::verifier::{verify_attestation, VerificationReport, VerifyOptions};

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to a signed (.json / .dsse) attestation file.
    pub attestation: PathBuf,

    /// Verify against an in-toto layout. When omitted, only envelope-
    /// level checks run.
    #[arg(long)]
    pub layout: Option<PathBuf>,

    /// PEM-encoded public key expected to have signed the attestation.
    /// Mutually exclusive with `--identity`.
    #[arg(long, conflicts_with = "identity")]
    pub public_key: Option<PathBuf>,

    /// Expected signer identity (email, URL, or glob) for keyless-
    /// signed attestations.
    #[arg(long)]
    pub identity: Option<String>,

    /// Verify the on-disk SHA-256 of PATH matches one of the
    /// attestation's subjects. Repeatable.
    #[arg(long = "expected-subject", value_name = "PATH")]
    pub expected_subject: Vec<PathBuf>,

    /// Don't require a Rekor inclusion proof in the envelope.
    #[arg(long)]
    pub no_transparency_log: bool,

    /// Override the Fulcio URL (for private sigstore instances).
    #[arg(long, default_value = "https://fulcio.sigstore.dev")]
    pub fulcio_url: String,

    /// Override the Rekor URL.
    #[arg(long, default_value = "https://rekor.sigstore.dev")]
    pub rekor_url: String,

    /// Emit a structured verification report to stdout.
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: VerifyArgs) -> anyhow::Result<ExitCode> {
    let raw = std::fs::read_to_string(&args.attestation).map_err(|e| {
        anyhow::anyhow!(
            "cannot read attestation file {}: {e}",
            args.attestation.display()
        )
    })?;

    let public_key_pem = match &args.public_key {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| {
            anyhow::anyhow!("cannot read public key file {}: {e}", p.display())
        })?),
        None => None,
    };

    let layout = match &args.layout {
        Some(p) => {
            let s = std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("cannot read layout file {}: {e}", p.display())
            })?;
            let parsed: crate::policy::layout::Layout = serde_json::from_str(&s)
                .map_err(|e| anyhow::anyhow!("layout parse failed: {e}"))?;
            Some(parsed)
        }
        None => None,
    };

    let opts = VerifyOptions {
        public_key_pem,
        identity_pattern: args.identity.clone(),
        expected_subjects: args.expected_subject.clone(),
        skip_transparency_log: args.no_transparency_log,
        layout,
    };

    let report = verify_attestation(&raw, &opts);
    emit_report(&report, args.json)?;
    Ok(exit_code_for(&report))
}

fn emit_report(report: &VerificationReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    match report {
        VerificationReport::Pass {
            signer,
            subject_digest,
            transparency_log_verified,
            layout_satisfied,
        } => {
            println!("PASS — verified with {} {}", signer.kind, signer.label);
            if let Some(digest) = subject_digest {
                println!("  subject digest: {digest}");
            }
            if *transparency_log_verified {
                println!("  transparency log: Rekor inclusion proof verified");
            }
            if let Some(true) = layout_satisfied {
                println!("  layout: satisfied");
            }
        }
        VerificationReport::Fail {
            mode,
            detail,
            partial_identity,
        } => {
            println!("FAIL — {mode:?}");
            println!("  detail: {detail}");
            if let Some(id) = partial_identity {
                println!("  partial_identity: {} {}", id.kind, id.label);
            }
        }
    }
    Ok(())
}

fn exit_code_for(report: &VerificationReport) -> ExitCode {
    match report {
        VerificationReport::Pass { .. } => ExitCode::from(0),
        VerificationReport::Fail { mode, .. } => ExitCode::from(mode.exit_code() as u8),
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use crate::attestation::verifier::FailureMode;

    #[test]
    fn exit_code_groupings_match_contract() {
        // Exit codes 1 = crypto, 2 = envelope, 3 = layout.
        assert_eq!(FailureMode::SignatureInvalid.exit_code(), 1);
        assert_eq!(FailureMode::IdentityMismatch.exit_code(), 1);
        assert_eq!(FailureMode::SubjectDigestMismatch.exit_code(), 1);
        assert_eq!(FailureMode::TransparencyLogMissing.exit_code(), 1);
        assert_eq!(FailureMode::MalformedEnvelope.exit_code(), 2);
        assert_eq!(FailureMode::NotSigned.exit_code(), 2);
        assert_eq!(FailureMode::CertificateExpired.exit_code(), 2);
        assert_eq!(FailureMode::TrustRootInvalid.exit_code(), 2);
        assert_eq!(FailureMode::LayoutViolation.exit_code(), 3);
    }

    #[test]
    fn pass_report_exits_zero() {
        let report = VerificationReport::Pass {
            signer: crate::attestation::verifier::SignerIdentityInfo {
                kind: "public_key".to_string(),
                label: "sha256:abc".to_string(),
            },
            subject_digest: None,
            transparency_log_verified: false,
            layout_satisfied: None,
        };
        let code = exit_code_for(&report);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(0)));
    }
}
