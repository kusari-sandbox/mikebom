/// Application error types for mikebom CLI.
///
/// Uses `thiserror` for library-level errors with structured variants.
/// Maps to the exit codes defined in contracts/cli-interface.md.
#[derive(Debug, thiserror::Error)]
pub enum MikebomError {
    // === Scan errors (exit codes 1-5) ===
    #[error("eBPF probe attachment failed: {0}")]
    ProbeAttachFailed(String),

    #[error("no dependency activity observed during trace")]
    NoDependencyActivity,

    #[error("ring buffer overflow: {events_lost} events lost")]
    RingBufferOverflow { events_lost: u64 },

    #[error("target process not found or inaccessible: pid {pid}")]
    TargetProcessNotFound { pid: u32 },

    #[error("insufficient privileges: requires root or CAP_BPF")]
    InsufficientPrivileges,

    // === Generate errors ===
    #[error("attestation file invalid or unreadable: {0}")]
    InvalidAttestation(String),

    #[error("resolution produced zero components")]
    NoComponentsResolved,

    #[error("generated SBOM fails schema validation: {0}")]
    SchemaValidationFailed(String),

    // === Enrichment errors ===
    #[error("SBOM file invalid or unreadable: {0}")]
    InvalidSbom(String),

    // === Validation errors ===
    #[error("validation errors found: {count} issues")]
    ValidationFailed { count: usize },

    #[error("file unreadable or format unrecognized: {0}")]
    UnrecognizedFormat(String),

    // === Resolution/API errors ===
    #[error("PURL validation failed: {0}")]
    PurlValidation(String),

    #[error("deps.dev API error: {0}")]
    DepsDevApi(String),

    // === General errors ===
    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl MikebomError {
    /// Map error to CLI exit code per contracts/cli-interface.md.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::ProbeAttachFailed(_) => 1,
            Self::NoDependencyActivity => 2,
            Self::RingBufferOverflow { .. } => 3,
            Self::TargetProcessNotFound { .. } => 4,
            Self::InsufficientPrivileges => 5,
            Self::InvalidAttestation(_) => 1,
            Self::NoComponentsResolved => 2,
            Self::SchemaValidationFailed(_) => 3,
            Self::InvalidSbom(_) => 1,
            Self::ValidationFailed { .. } => 1,
            Self::UnrecognizedFormat(_) => 2,
            Self::PurlValidation(_) | Self::DepsDevApi(_) => 1,
            Self::Config(_) | Self::Io(_) | Self::Json(_) => 1,
        }
    }
}
