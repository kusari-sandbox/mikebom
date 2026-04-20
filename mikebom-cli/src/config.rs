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

/// Supported SBOM output formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    CycloneDxJson,
    CycloneDxXml,
    SpdxJson,
}

impl OutputFormat {
    pub fn from_str_arg(s: &str) -> Result<Self, String> {
        match s {
            "cyclonedx-json" => Ok(Self::CycloneDxJson),
            "cyclonedx-xml" => Ok(Self::CycloneDxXml),
            "spdx-json" => Ok(Self::SpdxJson),
            other => Err(format!(
                "unsupported format '{other}': expected cyclonedx-json, cyclonedx-xml, or spdx-json"
            )),
        }
    }

    pub fn default_extension(&self) -> &str {
        match self {
            Self::CycloneDxJson => ".cdx.json",
            Self::CycloneDxXml => ".cdx.xml",
            Self::SpdxJson => ".spdx.json",
        }
    }
}
