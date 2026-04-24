# Phase 1 Data Model — SPDX Output Support

**Feature**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md) | **Research**: [research.md](./research.md)

This document defines the internal types introduced by milestone 010. The pre-existing format-neutral types in `mikebom_common::resolution` are referenced but **not redefined**: the SPDX serializers consume them unchanged, per FR-017 (no SPDX-specific structs leak into scan/resolution code).

## 1. Reused (existing) types — boundaries only

These already exist in the workspace; they are listed here for reference so the SPDX serializer's input contract is unambiguous.

| Type | Crate / module | Purpose in this milestone |
|------|----------------|---------------------------|
| `ResolvedComponent` | `mikebom_common::resolution` | Format-neutral component (PURL, name, version, supplier, hashes, declared+concluded licenses, evidence, properties, externalRefs). Input to **both** the CDX and SPDX serializers. |
| `Relationship` | `mikebom_common::resolution` | Format-neutral edge (source bom-ref, target bom-ref, kind: `DependsOn`/`DevDependencyOf`/`Contains`/`Describes`). |
| `ScanResult { components: Vec<ResolvedComponent>, relationships: Vec<Relationship>, vulnerabilities: Vec<Vulnerability>, generation_context: GenerationContext }` | `mikebom_common::resolution` | The whole scan output. The serializer registry receives this once per invocation and dispatches to one or more format serializers. |
| `Vulnerability` | `mikebom_common::resolution` | Format-neutral VEX statement (id, affected component bom-refs, status, justification). Input to the OpenVEX sidecar serializer. |
| `spdx::Expression` | `spdx` crate (Embark Studios) | License expression validation + canonicalization. Used to normalize `licenseDeclared`/`licenseConcluded` before emission. |

**No changes to any of the above.** FR-022 / SC-006 require existing CDX output to remain byte-identical, which forbids modifying `ResolvedComponent` or `Relationship` in any way that would change CDX serialization output.

---

## 2. New types — SerializerRegistry

Lives in `mikebom-cli/src/generate/mod.rs`. Provides the format-dispatch layer required by FR-019.

```rust
pub trait SbomSerializer: Send + Sync {
    /// Stable identifier matching the CLI --format value (e.g., "cyclonedx-json").
    fn id(&self) -> &'static str;

    /// Default output filename when no per-format --output override is set.
    fn default_filename(&self) -> &'static str;

    /// Whether this serializer is labeled experimental (FR-019b). Experimental
    /// formats must surface the label in --help and in produced output's
    /// creator/tool comment.
    fn experimental(&self) -> bool { false }

    /// Serialize a scan result into one or more output artifacts.
    ///
    /// Returns: a Vec of (suggested_relative_path, bytes). Multiple artifacts
    /// allow a single serializer to emit a primary file plus side artifacts
    /// (e.g., the SPDX serializer can also emit the OpenVEX sidecar when VEX
    /// is present, with the cross-reference baked into the primary doc).
    fn serialize(&self, scan: &ScanResult, cfg: &OutputConfig)
        -> anyhow::Result<Vec<EmittedArtifact>>;
}

pub struct EmittedArtifact {
    pub relative_path: PathBuf,   // e.g. "mikebom.spdx.json", "mikebom.openvex.json"
    pub bytes: Vec<u8>,
}

pub struct OutputConfig {
    pub mikebom_version: &'static str,
    pub created: chrono::DateTime<chrono::Utc>, // single timestamp shared across all formats in a single invocation
    pub overrides: HashMap<String /* format id */, PathBuf>,
}

pub struct SerializerRegistry { /* internal: BTreeMap<&'static str, Arc<dyn SbomSerializer>> */ }

impl SerializerRegistry {
    pub fn with_defaults() -> Self;          // registers cyclonedx-json + spdx-2.3-json + spdx-3-json-experimental
    pub fn ids(&self) -> impl Iterator<Item = &'static str>;
    pub fn get(&self, id: &str) -> Option<Arc<dyn SbomSerializer>>;
}
```

**Validation rules**:
- `OutputConfig.created` is shared across all serializers in a single invocation, so when both CDX and SPDX are emitted from one scan their respective `metadata.timestamp` / `creationInfo.created` fields are identical.
- `SerializerRegistry::with_defaults()` is the *only* place where built-in serializers are wired. Adding a future format (e.g., full SPDX 3 emitter) is a one-line registration here plus a new module — no edits to scan/resolution/CDX/SPDX-2.3/OpenVEX code (FR-019).

---

## 3. New types — SPDX 2.3 serializer

Lives in `mikebom-cli/src/generate/spdx/`. Hand-written `serde`-derived structs per R1.

### 3.1 SPDXID newtype

```rust
/// SPDX identifier per spec §3.2 (alphanumerics, hyphens, dots; "SPDXRef-" prefix).
/// Constructed only via SpdxId::for_purl or SpdxId::document().
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct SpdxId(String);

impl SpdxId {
    /// Per R7: SPDXRef-Package-<base32(SHA-256(canonical_purl))[..16]>.
    pub fn for_purl(purl: &Purl) -> Self;

    /// SPDX-spec-required document identifier.
    pub const fn document() -> Self; // returns SpdxId("SPDXRef-DOCUMENT".into())

    pub fn as_str(&self) -> &str;
}
```

**Constraints**: No public constructor accepts a raw `String`. This honors Constitution Principle IV (Type-Driven Correctness): `SpdxId` cannot be confused with any other string-typed value.

### 3.2 Document namespace newtype

```rust
/// Per R8: https://mikebom.kusari.dev/spdx/<base32(SHA-256(canonical_scan_inputs))[..32]>.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct SpdxDocumentNamespace(url::Url);

impl SpdxDocumentNamespace {
    pub fn derive(scan: &ScanResult) -> Self;
}
```

### 3.3 SPDX 2.3 envelope types

```rust
#[derive(serde::Serialize)]
pub struct SpdxDocument {
    #[serde(rename = "spdxVersion")] pub spdx_version: &'static str,    // "SPDX-2.3"
    #[serde(rename = "dataLicense")] pub data_license: &'static str,    // "CC0-1.0"
    #[serde(rename = "SPDXID")] pub spdx_id: SpdxId,                    // SPDXRef-DOCUMENT
    pub name: String,                                                    // scan target description
    #[serde(rename = "documentNamespace")] pub namespace: SpdxDocumentNamespace,
    #[serde(rename = "creationInfo")] pub creation_info: CreationInfo,
    pub packages: Vec<SpdxPackage>,
    pub relationships: Vec<SpdxRelationship>,
    #[serde(skip_serializing_if = "Vec::is_empty")] pub annotations: Vec<SpdxAnnotation>,
    #[serde(skip_serializing_if = "Vec::is_empty",
            rename = "externalDocumentRefs")] pub external_document_refs: Vec<SpdxExternalDocumentRef>,
    #[serde(rename = "documentDescribes")] pub document_describes: Vec<SpdxId>,
}

#[derive(serde::Serialize)]
pub struct CreationInfo {
    pub created: String,                                                 // RFC 3339, from OutputConfig.created
    pub creators: Vec<String>,                                           // ["Tool: mikebom-<version>"]
    #[serde(skip_serializing_if = "Option::is_none",
            rename = "licenseListVersion")] pub license_list_version: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SpdxPackage {
    #[serde(rename = "SPDXID")] pub spdx_id: SpdxId,
    pub name: String,
    #[serde(rename = "versionInfo")] pub version_info: String,
    #[serde(rename = "downloadLocation")] pub download_location: String,  // "NOASSERTION" when unknown
    #[serde(skip_serializing_if = "Option::is_none")] pub supplier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub originator: Option<String>,
    #[serde(rename = "filesAnalyzed")] pub files_analyzed: bool,          // false for package-level scan
    #[serde(skip_serializing_if = "Vec::is_empty")] pub checksums: Vec<SpdxChecksum>,
    #[serde(rename = "licenseDeclared")] pub license_declared: SpdxLicenseField,
    #[serde(rename = "licenseConcluded")] pub license_concluded: SpdxLicenseField,
    #[serde(skip_serializing_if = "Option::is_none",
            rename = "copyrightText")] pub copyright_text: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty",
            rename = "externalRefs")] pub external_refs: Vec<SpdxExternalRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")] pub annotations: Vec<SpdxAnnotation>,
}

#[derive(serde::Serialize)]
pub struct SpdxChecksum {
    pub algorithm: SpdxChecksumAlgorithm,    // enum: SHA1, SHA256, SHA512, MD5, ...
    #[serde(rename = "checksumValue")] pub value: String,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum SpdxLicenseField {
    /// Canonical SPDX expression as accepted by spdx::Expression::canonicalize.
    Expression(String),
    /// Sentinel: spec literal "NOASSERTION" when no value is known.
    NoAssertion,
    /// Sentinel: spec literal "NONE" when source explicitly states no license.
    None,
}
// Custom Serialize impl emits the bare strings "NOASSERTION" / "NONE" for the sentinels.

#[derive(serde::Serialize)]
pub struct SpdxExternalRef {
    #[serde(rename = "referenceCategory")] pub category: SpdxExternalRefCategory,
    #[serde(rename = "referenceType")] pub ref_type: String,        // "purl", "cpe23Type", etc.
    #[serde(rename = "referenceLocator")] pub locator: String,      // the PURL string, the CPE string, ...
}

#[derive(serde::Serialize)]
pub struct SpdxRelationship {
    #[serde(rename = "spdxElementId")] pub source: SpdxId,
    #[serde(rename = "relatedSpdxElement")] pub target: SpdxId,
    #[serde(rename = "relationshipType")] pub kind: SpdxRelationshipType,
    #[serde(skip_serializing_if = "Option::is_none")] pub comment: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SpdxAnnotation {
    pub annotator: String,                                          // "Tool: mikebom-<version>"
    #[serde(rename = "annotationDate")] pub date: String,           // mirrors CreationInfo.created
    #[serde(rename = "annotationType")] pub kind: SpdxAnnotationType, // OTHER, REVIEW
    pub comment: String,                                            // JSON string per §4 below
}

#[derive(serde::Serialize)]
pub struct SpdxExternalDocumentRef {
    #[serde(rename = "externalDocumentId")] pub id: String,         // e.g., "DocumentRef-OpenVEX"
    #[serde(rename = "spdxDocument")] pub spdx_document: String,    // relative path to the sidecar
    pub checksum: SpdxChecksum,                                     // SHA-256 of the sidecar bytes
}
```

### 3.4 Enums

```rust
#[derive(serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SpdxChecksumAlgorithm { Sha1, Sha256, Sha512, Md5, /* SHA224, SHA384, BLAKE2B_256/384/512 if needed */ }

#[derive(serde::Serialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum SpdxExternalRefCategory { PackageManager, Security, PersistentId, Other }

#[derive(serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpdxRelationshipType {
    Describes, DependsOn, DevDependencyOf, Contains, ContainedBy,
    /* additional types added on demand */
}

#[derive(serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SpdxAnnotationType { Other, Review }
```

**Mapping rules** (the `Relationship.kind → SpdxRelationshipType` table):

| Internal `Relationship.kind` | SPDX 2.3 `relationshipType` | Notes |
|------------------------------|-----------------------------|-------|
| `DependsOn`                  | `DEPENDS_ON`                | Default for runtime edges. |
| `DevDependencyOf`            | `DEV_DEPENDENCY_OF`         | Used when `mikebom:dev-dependency` was set on CDX. |
| `Contains`                   | `CONTAINS`                  | Shade-jar parents → children, image → layer components. |
| `Describes`                  | `DESCRIBES`                 | Document → root component. |

---

## 4. New types — mikebom annotation comment envelope

The JSON payload inside `SpdxAnnotation.comment` (per R9, FR-016).

```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MikebomAnnotationCommentV1 {
    /// Versioned schema identifier. Always "mikebom-annotation/v1" for now.
    pub schema: &'static str,

    /// The originating mikebom field name as used in CycloneDX (e.g., "mikebom:evidence-kind",
    /// "evidence.identity", "compositions"). Provides the cross-format key for consumers.
    pub field: String,

    /// The field value, JSON-typed. Free-form to accommodate every preserved field.
    pub value: serde_json::Value,
}
```

Schema is also published as `contracts/mikebom-annotation.schema.json` so third-party SPDX consumers can validate parsed annotations.

---

## 5. New types — SPDX 3.0.1 stub serializer

Lives in `mikebom-cli/src/generate/spdx/v3_stub.rs`. Per R2, this is hand-written JSON-LD against the published 3.0.1 schema, scoped to one ecosystem (npm, per R3) and a small set of element types. No public Rust types are introduced beyond the entry point:

```rust
/// Emit a minimal-but-valid SPDX 3.0.1 JSON-LD document.
/// Returns serde_json::Value to be serialized by the registry layer.
pub fn serialize_v3_stub(scan: &ScanResult, cfg: &OutputConfig) -> anyhow::Result<serde_json::Value>;
```

Internally builds a `serde_json::json!` tree with:
- `@context: "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"`
- `@graph` array containing:
  - `CreationInfo` element
  - `SpdxDocument` element (referencing `CreationInfo` + `rootElement`)
  - One `Package` element per npm component (PURL → `purl` field; checksums → `verifiedUsing` element with `Hash` algorithm)
  - `Relationship` elements for the npm dependency graph

The stub deliberately does not introduce dedicated Rust structs — the JSON is built with `serde_json::json!` macros to keep the surface narrow and the rewrite cost low when SPDX 3.1 (or an actual production SPDX 3 emitter) replaces it.

---

## 6. New types — OpenVEX 0.2.0 sidecar

Lives in `mikebom-cli/src/generate/openvex/`. Hand-written per R4.

```rust
#[derive(serde::Serialize)]
pub struct OpenVexDocument {
    #[serde(rename = "@context")] pub context: &'static str,    // "https://openvex.dev/ns/v0.2.0"
    #[serde(rename = "@id")] pub id: String,                    // deterministic per scan, like SpdxDocumentNamespace
    pub author: String,                                          // "mikebom-<version>"
    pub timestamp: String,                                       // RFC 3339, mirrors OutputConfig.created
    pub version: u64,                                            // 1 (per-document version, monotonically increases on republish)
    #[serde(skip_serializing_if = "Option::is_none")] pub tooling: Option<String>,
    pub statements: Vec<OpenVexStatement>,
}

#[derive(serde::Serialize)]
pub struct OpenVexStatement {
    pub vulnerability: OpenVexVulnerability,
    pub products: Vec<OpenVexProduct>,                           // each carries the affected PURL
    pub status: OpenVexStatus,                                   // not_affected | affected | fixed | under_investigation
    #[serde(skip_serializing_if = "Option::is_none")] pub justification: Option<OpenVexJustification>,
    #[serde(skip_serializing_if = "Option::is_none",
            rename = "impact_statement")] pub impact_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none",
            rename = "action_statement")] pub action_statement: Option<String>,
}

#[derive(serde::Serialize)]
pub struct OpenVexVulnerability {
    pub name: String,                                            // CVE-id or vendor-id
    #[serde(skip_serializing_if = "Option::is_none")] pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")] pub aliases: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct OpenVexProduct {
    #[serde(rename = "@id")] pub id: String,                     // the affected component PURL
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVexStatus { NotAffected, Affected, Fixed, UnderInvestigation }

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenVexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}
```

**Cross-reference rule (FR-016a)**: When the SPDX serializer emits an OpenVEX sidecar, it adds an `externalDocumentRefs` entry to the SPDX document with `externalDocumentId: "DocumentRef-OpenVEX"`, `spdxDocument: "<relative-path-to-sidecar>"`, and `checksum: SHA256 of the sidecar bytes`. (If the SPDX schema rejects `externalDocumentRefs` for non-SPDX targets in some validators, fall back to a document-level `SpdxAnnotation` with a `field: "openvex.sidecar"` envelope — to be confirmed during implementation against the vendored schema.)

---

## 7. Lifecycle / state transitions

This milestone introduces no state machines. SPDX/OpenVEX serialization is a pure function of `ScanResult` + `OutputConfig`. There are no entities with lifecycles, no reads, no writes outside of the `EmittedArtifact` byte buffers handed back to the registry.

---

## 8. Determinism contract (cross-cutting)

Every serializer returned by the registry MUST satisfy:

1. **Pure function of inputs**: `serialize(scan, cfg)` MUST produce identical bytes for identical `(scan, cfg)`. No reads from clocks, no random number generation, no environment lookups beyond what `cfg` carries.
2. **Stable iteration**: Iterating over `scan.components`, `scan.relationships`, `scan.vulnerabilities` MUST be in a deterministic order. Use `BTreeMap`/sorted `Vec`s; the input pipeline already guarantees stable ordering since milestone 002.
3. **Stable map serialization**: All `serde_json::Value` maps emitted MUST be `Map`s (preserves insertion order under `serde_json`'s default `preserve_order` feature when enabled in the workspace) OR `BTreeMap`s. Avoid `HashMap` anywhere in the serialization path.
4. **Single timestamp source**: `OutputConfig.created` is the only timestamp used across all formats in one invocation; serializers MUST NOT call `Utc::now()` directly.

This contract makes FR-020 / SC-007 testable as a one-liner: run the same scan twice, assert byte-equal output (with `documentNamespace` and `created` allowed to differ across separate invocations only because `created` itself is allowed to differ when separate invocations happen at different wall-clock moments — within a single invocation it is constant).
