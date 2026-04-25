// Tool-name / tool-version / in-toto type URIs are referenced from
// `attestation/builder.rs`, which is gated behind `cfg(target_os =
// "linux")` because the attestation flow runs only inside the Linux-
// only `cli/scan.rs::execute_scan` trace path. On macOS the constants
// have no callers and clippy flags them dead. The
// `cfg_attr(not(linux), allow(dead_code))` suppresses the warning
// without splitting the constants behind their own platform gate
// (they're stable URIs, not platform-conditional in nature).
#![allow(dead_code)]

use std::time::Duration;

/// Default output path for attestation files.
pub const DEFAULT_ATTESTATION_OUTPUT: &str = "mikebom.attestation.json";

/// Default output path for CycloneDX SBOM files.
pub const DEFAULT_CDX_OUTPUT: &str = "mikebom.cdx.json";

/// Default ring buffer size (8 MB).
pub const DEFAULT_RING_BUFFER_SIZE: u32 = 8 * 1024 * 1024;

/// Default timeout per deps.dev API call.
pub const DEFAULT_DEPS_DEV_TIMEOUT: Duration = Duration::from_millis(5000);

/// Tool name used in SBOM metadata and CISA 2025 fields.
pub const TOOL_NAME: &str = "mikebom";

/// Tool version from Cargo.toml.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// In-toto statement type URI.
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// mikebom build-trace predicate type URI.
pub const PREDICATE_TYPE: &str = "https://mikebom.dev/attestation/build-trace/v1";
