//! OpenVEX 0.2.0 document + statement structs (milestone 010, T035 / T036).
//!
//! Data-model mirrors `https://openvex.dev/ns/v0.2.0` — each
//! statement names one vulnerability, the product(s) it affects,
//! its status (`not_affected` / `affected` / `fixed` /
//! `under_investigation`), and an optional justification.
//!
//! Emitted as a JSON sidecar alongside the SPDX 2.3 file when a
//! scan produces VEX statements (FR-016a). Not emitted when the
//! scan has zero advisories. The SPDX document cross-references
//! the sidecar via `externalDocumentRefs` with a SHA-256 of the
//! sidecar bytes.

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenVexDocument {
    /// OpenVEX 0.2.0 context URI. Const-valued by design so a
    /// consumer can identify the schema version with no parsing.
    #[serde(rename = "@context")]
    pub context: &'static str,
    /// Deterministic document id — same fingerprint scheme as the
    /// SPDX `documentNamespace` so re-runs of the same scan produce
    /// the same `@id`.
    #[serde(rename = "@id")]
    pub id: String,
    /// `"mikebom-<version>"` — matches the first creator entry in
    /// the companion SPDX document's `creationInfo.creators`.
    pub author: String,
    /// RFC 3339 UTC timestamp — sourced from `OutputConfig.created`.
    pub timestamp: String,
    /// Per-document revision version. Always 1 today; bumps on
    /// re-publish with revised VEX analyses.
    pub version: u64,
    /// Optional tool identifier. OpenVEX separates `author` (who
    /// authored the statements) from `tooling` (what produced the
    /// document) — for mikebom they are the same string today.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooling: Option<String>,
    /// One entry per (vulnerability, product-set) tuple. Empty is
    /// a legal OpenVEX document but we never emit one — when the
    /// statements list would be empty, the entire sidecar is
    /// skipped (no file written) per FR-016a.
    pub statements: Vec<OpenVexStatement>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenVexStatement {
    pub vulnerability: OpenVexVulnerability,
    /// Affected products. Each product's `@id` is the component
    /// PURL — the CVE ↔ component binding consumers care about.
    pub products: Vec<OpenVexProduct>,
    pub status: OpenVexStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<OpenVexJustification>,
    #[serde(rename = "impact_statement", skip_serializing_if = "Option::is_none")]
    pub impact_statement: Option<String>,
    #[serde(rename = "action_statement", skip_serializing_if = "Option::is_none")]
    pub action_statement: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenVexVulnerability {
    /// Canonical identifier (e.g. `"CVE-2024-1234"`). Copied
    /// verbatim from `AdvisoryRef.id`.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenVexProduct {
    /// Component identifier — mikebom emits the PURL string here,
    /// so the VEX statement binds to the same identity SPDX's
    /// `externalRefs[PACKAGE-MANAGER/purl]` carries.
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVexStatus {
    #[allow(dead_code)]
    NotAffected,
    #[allow(dead_code)]
    Affected,
    #[allow(dead_code)]
    Fixed,
    /// Default for advisories mikebom has discovered but not
    /// analyzed. The VEX-enrichment milestone that wires
    /// `AdvisoryRef → OpenVexStatus` with real analysis will pick
    /// among the four variants.
    UnderInvestigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum OpenVexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

pub const OPENVEX_CONTEXT_V0_2_0: &str = "https://openvex.dev/ns/v0.2.0";
