//! SPDX 2.3 `annotations[]` envelope for mikebom-specific data
//! preserved losslessly via `MikebomAnnotationCommentV1` (milestone
//! 010, T033 / T034).
//!
//! SPDX 2.3 has no native home for mikebom's cross-cutting
//! properties — `mikebom:*` component properties, CycloneDX
//! `evidence.identity` / `evidence.occurrences`, and `compositions`.
//! Per spec.md Clarification Q2 + FR-016, these land in SPDX
//! `annotations[]` entries whose `comment` field carries a JSON-
//! encoded envelope. Consumers that ignore annotations see a clean
//! SPDX document; consumers that parse them recover full mikebom
//! fidelity. The per-field placement contract is
//! `contracts/sbom-format-mapping.md` Sections C / D / E.
//!
//! The envelope's JSON schema is
//! `contracts/mikebom-annotation.schema.json` — the
//! `annotation_envelope_schema_matches_json_file` unit test in this
//! module is a structural canary that catches drift between the
//! Rust type and the committed schema.

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::{ResolutionTechnique, ResolvedComponent};

use super::document::{SpdxAnnotation, SpdxAnnotationType};
use crate::generate::ScanArtifacts;

/// Versioned envelope identifier. Bumping this constant requires a
/// coordinated update to `contracts/mikebom-annotation.schema.json`
/// (which pins `schema` to the exact same string via `const`).
pub const ENVELOPE_SCHEMA_V1: &str = "mikebom-annotation/v1";

/// The JSON payload mikebom places inside `SpdxAnnotation.comment`.
///
/// `field` is the originating mikebom identifier as it appears in
/// CycloneDX — e.g. `"mikebom:evidence-kind"`, `"evidence.identity"`,
/// `"compositions"`. The exact set of legal identifiers is
/// enumerated in the data-placement map.
///
/// `value` is free-form JSON: mirrors whatever shape the same field
/// carries in CycloneDX. Consumers should treat it as opaque unless
/// they know the field's schema.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MikebomAnnotationCommentV1 {
    pub schema: String,
    pub field: String,
    pub value: serde_json::Value,
}

impl MikebomAnnotationCommentV1 {
    /// Construct a v1 envelope with the fixed `schema` constant.
    pub fn new(field: impl Into<String>, value: serde_json::Value) -> Self {
        Self {
            schema: ENVELOPE_SCHEMA_V1.to_string(),
            field: field.into(),
            value,
        }
    }

    /// Serialize the envelope to a compact JSON string suitable for
    /// placing inside `SpdxAnnotation.comment`. "Compact" (not
    /// pretty-printed) because the comment is already nested inside
    /// a pretty-printed SPDX document; two layers of indentation
    /// make the output harder to read, not easier.
    pub fn to_comment_string(&self) -> String {
        serde_json::to_string(self)
            .expect("MikebomAnnotationCommentV1 serializes infallibly (no Map<K,V>)")
    }
}

/// Build an `SpdxAnnotation` whose `comment` is a mikebom-namespaced
/// v1 envelope. `annotator` and `date` are passed through — callers
/// typically use `"Tool: mikebom-<version>"` (matching
/// `CreationInfo.creators`) and the shared
/// `OutputConfig.created` stamp respectively, so annotation
/// timestamps stay consistent with the document's creation info.
pub fn build_annotation(
    annotator: &str,
    date: &str,
    field: &str,
    value: serde_json::Value,
) -> SpdxAnnotation {
    let envelope = MikebomAnnotationCommentV1::new(field, value);
    SpdxAnnotation {
        annotator: annotator.to_string(),
        date: date.to_string(),
        kind: SpdxAnnotationType::Other,
        comment: envelope.to_comment_string(),
    }
}

/// Build every per-component annotation mikebom's SPDX 2.3 output
/// emits for `c`. Follows `contracts/sbom-format-mapping.md`
/// Sections C (rows C1–C20) and D (D1 identity, D2 occurrences).
///
/// Entry-emission rules mirror the CycloneDX emission in
/// `generate/cyclonedx/builder.rs` + `evidence.rs` — if a field is
/// emitted in CDX for a given `ResolvedComponent`, its SPDX
/// annotation twin is emitted here too (that's the FR-015 / FR-016
/// fidelity guarantee). Absent fields stay absent.
pub fn annotate_component(
    annotator: &str,
    date: &str,
    c: &ResolvedComponent,
    include_dev: bool,
    include_source_files: bool,
) -> Vec<SpdxAnnotation> {
    use serde_json::json;
    let mut out: Vec<SpdxAnnotation> = Vec::new();
    let push = |out: &mut Vec<SpdxAnnotation>, field: &str, value: serde_json::Value| {
        out.push(build_annotation(annotator, date, field, value));
    };

    // C1 source-type
    if let Some(ref v) = c.source_type {
        push(&mut out, "mikebom:source-type", json!(v));
    }
    // C2 source-connection-ids (from evidence)
    if !c.evidence.source_connection_ids.is_empty() {
        // Match CDX shape: comma-joined; consumers that want the
        // list back can split on commas. Losslessly trivial.
        push(
            &mut out,
            "mikebom:source-connection-ids",
            json!(c.evidence.source_connection_ids.join(",")),
        );
    }
    // C3 deps-dev-match (from evidence)
    if let Some(ref m) = c.evidence.deps_dev_match {
        push(
            &mut out,
            "mikebom:deps-dev-match",
            json!(format!("{}:{}@{}", m.system, m.name, m.version)),
        );
    }
    // C4 evidence-kind
    if let Some(ref v) = c.evidence_kind {
        push(&mut out, "mikebom:evidence-kind", json!(v));
    }
    // C5 sbom-tier
    if let Some(ref v) = c.sbom_tier {
        push(&mut out, "mikebom:sbom-tier", json!(v));
    }
    // C6 dev-dependency — same gate as CDX: only when include_dev
    // AND the component is dev-flagged. (Relationship direction is
    // also handled by B2's DEV_DEPENDENCY_OF edge in relationships.rs.)
    if include_dev && c.is_dev == Some(true) {
        push(&mut out, "mikebom:dev-dependency", json!("true"));
    }
    // C7 co-owned-by
    if let Some(ref v) = c.co_owned_by {
        push(&mut out, "mikebom:co-owned-by", json!(v));
    }
    // C8 shade-relocation
    if c.shade_relocation == Some(true) {
        push(&mut out, "mikebom:shade-relocation", json!("true"));
    }
    // C9 npm-role
    if let Some(ref v) = c.npm_role {
        push(&mut out, "mikebom:npm-role", json!(v));
    }
    // C10 binary-class
    if let Some(ref v) = c.binary_class {
        push(&mut out, "mikebom:binary-class", json!(v));
    }
    // C11 binary-stripped
    if let Some(v) = c.binary_stripped {
        push(
            &mut out,
            "mikebom:binary-stripped",
            json!(if v { "true" } else { "false" }),
        );
    }
    // C12 linkage-kind
    if let Some(ref v) = c.linkage_kind {
        push(&mut out, "mikebom:linkage-kind", json!(v));
    }
    // C13 buildinfo-status
    if let Some(ref v) = c.buildinfo_status {
        push(&mut out, "mikebom:buildinfo-status", json!(v));
    }
    // C14 detected-go
    if c.detected_go == Some(true) {
        push(&mut out, "mikebom:detected-go", json!("true"));
    }
    // C15 binary-packed
    if let Some(ref v) = c.binary_packed {
        push(&mut out, "mikebom:binary-packed", json!(v));
    }
    // C16 confidence
    if let Some(ref v) = c.confidence {
        push(&mut out, "mikebom:confidence", json!(v));
    }
    // C17 raw-version
    if let Some(ref v) = c.raw_version {
        push(&mut out, "mikebom:raw-version", json!(v));
    }
    // C18 source-files — same gate as CDX (only when
    // include_source_files AND non-empty). SPDX value is the array
    // (CDX uses a comma-joined string; here we keep JSON fidelity).
    if include_source_files && !c.evidence.source_file_paths.is_empty() {
        push(
            &mut out,
            "mikebom:source-files",
            json!(c.evidence.source_file_paths),
        );
    }
    // C19 cpe-candidates — only when MORE than one candidate was
    // synthesized. The first (primary) candidate goes into the
    // native `externalRefs[SECURITY/cpe23Type]` per A12 (handled in
    // packages.rs); the full candidate set lives here.
    if c.cpes.len() > 1 {
        push(&mut out, "mikebom:cpe-candidates", json!(c.cpes));
    }
    // C20 requirement-range
    if let Some(ref v) = c.requirement_range {
        push(&mut out, "mikebom:requirement-range", json!(v));
    }

    // D1 evidence.identity — technique + confidence. Emit
    // unconditionally because every ResolvedComponent has a
    // technique; `confidence` defaults to 0.0 if absent, which is
    // information too (and CDX emits this too).
    let technique = match c.evidence.technique {
        ResolutionTechnique::UrlPattern => "url-pattern",
        ResolutionTechnique::HashMatch => "hash-match",
        ResolutionTechnique::PackageDatabase => "package-database",
        ResolutionTechnique::FilePathPattern => "file-path-pattern",
        ResolutionTechnique::HostnameHeuristic => "hostname-heuristic",
    };
    push(
        &mut out,
        "evidence.identity",
        json!({
            "technique": technique,
            "confidence": c.evidence.confidence,
        }),
    );

    // D2 evidence.occurrences — only when non-empty (deep-hashed
    // db-sourced components).
    if !c.occurrences.is_empty() {
        let items: Vec<serde_json::Value> = c
            .occurrences
            .iter()
            .map(|o| {
                let mut obj = serde_json::Map::new();
                obj.insert("location".into(), json!(o.location));
                obj.insert("sha256".into(), json!(o.sha256));
                if let Some(ref md5) = o.md5_legacy {
                    obj.insert("md5".into(), json!(md5));
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        push(&mut out, "evidence.occurrences", json!(items));
    }

    out
}

/// Build every document-level annotation mikebom's SPDX 2.3 output
/// emits. Follows Sections C21–C23 (document-level mikebom metadata)
/// and E1 (compositions). Always emits at least the
/// `generation-context` annotation plus four `trace-integrity-*`
/// scalars — those are constitution-mandated transparency signals
/// (Principles V and X) and CDX emits them unconditionally.
pub fn annotate_document(
    annotator: &str,
    date: &str,
    artifacts: &ScanArtifacts<'_>,
) -> Vec<SpdxAnnotation> {
    use serde_json::json;
    let mut out: Vec<SpdxAnnotation> = Vec::new();
    let push = |out: &mut Vec<SpdxAnnotation>, field: &str, value: serde_json::Value| {
        out.push(build_annotation(annotator, date, field, value));
    };

    // C21 generation-context
    let gc = match artifacts.generation_context {
        GenerationContext::FilesystemScan => "filesystem-scan",
        GenerationContext::ContainerImageScan => "container-image-scan",
        GenerationContext::BuildTimeTrace => "build-time-trace",
    };
    push(&mut out, "mikebom:generation-context", json!(gc));

    // C22 os-release-missing-fields — CDX emits as
    // comma-joined-with-trailing-empty shape when empty; our JSON
    // value keeps the list-of-strings shape, skipped entirely when
    // empty (skip_serializing_if-style).
    if !artifacts.os_release_missing_fields.is_empty() {
        push(
            &mut out,
            "mikebom:os-release-missing-fields",
            json!(artifacts.os_release_missing_fields),
        );
    }

    // C23 trace-integrity-* — four scalars, emitted unconditionally
    // so consumers can distinguish "no trace ran" (0/0/[]/[]) from
    // "we didn't record it". Matches CDX's metadata-level shape.
    push_trace_integrity(&mut out, annotator, date, artifacts.integrity);

    // E1 compositions — emit when any complete-ecosystem claim is
    // present. The annotation's value is the `complete_ecosystems`
    // list (simpler than duplicating the full CDX `compositions[]`
    // shape; consumers can reconstruct the aggregate claim from
    // membership).
    if !artifacts.complete_ecosystems.is_empty() {
        push(
            &mut out,
            "compositions",
            json!({
                "complete_ecosystems": artifacts.complete_ecosystems,
            }),
        );
    }

    out
}

fn push_trace_integrity(
    out: &mut Vec<SpdxAnnotation>,
    annotator: &str,
    date: &str,
    integrity: &TraceIntegrity,
) {
    use serde_json::json;
    out.push(build_annotation(
        annotator,
        date,
        "mikebom:trace-integrity-ring-buffer-overflows",
        json!(integrity.ring_buffer_overflows),
    ));
    out.push(build_annotation(
        annotator,
        date,
        "mikebom:trace-integrity-events-dropped",
        json!(integrity.events_dropped),
    ));
    out.push(build_annotation(
        annotator,
        date,
        "mikebom:trace-integrity-uprobe-attach-failures",
        json!(integrity.uprobe_attach_failures),
    ));
    out.push(build_annotation(
        annotator,
        date,
        "mikebom:trace-integrity-kprobe-attach-failures",
        json!(integrity.kprobe_attach_failures),
    ));
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn envelope_serializes_schema_field_value_in_that_order() {
        let env = MikebomAnnotationCommentV1::new(
            "mikebom:sbom-tier",
            serde_json::Value::String("deployed".to_string()),
        );
        let json = env.to_comment_string();
        // Field order mirrors the committed JSON schema's `required`
        // array + property declaration order; swap detection is part
        // of the drift guard below, but we also check the basic
        // shape here.
        assert!(json.starts_with("{\"schema\":\"mikebom-annotation/v1\""));
        assert!(json.contains("\"field\":\"mikebom:sbom-tier\""));
        assert!(json.contains("\"value\":\"deployed\""));
    }

    #[test]
    fn build_annotation_wraps_envelope_as_spdx_comment() {
        let a = build_annotation(
            "Tool: mikebom-0.1.0",
            "2026-04-24T10:00:00Z",
            "mikebom:evidence-kind",
            serde_json::json!("instrumentation"),
        );
        assert_eq!(a.annotator, "Tool: mikebom-0.1.0");
        assert_eq!(a.date, "2026-04-24T10:00:00Z");
        assert!(matches!(a.kind, SpdxAnnotationType::Other));
        // The comment parses back to a v1 envelope with matching field.
        let parsed: MikebomAnnotationCommentV1 =
            serde_json::from_str(&a.comment).unwrap();
        assert_eq!(parsed.schema, ENVELOPE_SCHEMA_V1);
        assert_eq!(parsed.field, "mikebom:evidence-kind");
        assert_eq!(parsed.value, serde_json::json!("instrumentation"));
    }

    #[test]
    fn value_can_be_any_json_type() {
        // string
        assert_eq!(
            MikebomAnnotationCommentV1::new("f", serde_json::json!("x"))
                .value
                .as_str(),
            Some("x")
        );
        // number
        assert_eq!(
            MikebomAnnotationCommentV1::new("f", serde_json::json!(0.92))
                .value
                .as_f64(),
            Some(0.92)
        );
        // array
        let arr = MikebomAnnotationCommentV1::new(
            "f",
            serde_json::json!(["a", "b"]),
        );
        assert_eq!(arr.value.as_array().map(|v| v.len()), Some(2));
        // object
        let obj = MikebomAnnotationCommentV1::new(
            "f",
            serde_json::json!({"technique": "hash-comparison", "confidence": 1.0}),
        );
        assert!(obj.value.as_object().is_some());
    }

    /// Structural drift guard: the Rust envelope and the committed
    /// JSON schema at `contracts/mikebom-annotation.schema.json`
    /// MUST stay in sync on the three things a consumer writes code
    /// against: the fixed `schema` constant, the set of required
    /// fields, and the `additionalProperties: false` constraint.
    #[test]
    fn envelope_matches_committed_json_schema() {
        let schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join(
                "specs/010-spdx-output-support/contracts/\
                 mikebom-annotation.schema.json",
            );
        let raw = std::fs::read_to_string(&schema_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", schema_path.display()));
        let schema: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let schema_const = schema["properties"]["schema"]["const"]
            .as_str()
            .expect("schema.properties.schema.const is a string");
        assert_eq!(
            schema_const, ENVELOPE_SCHEMA_V1,
            "Rust envelope constant drifted from committed JSON schema"
        );

        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("required array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let mut expected = vec!["schema", "field", "value"];
        expected.sort();
        let mut got = required.clone();
        got.sort();
        assert_eq!(got, expected, "required-fields set drift");

        assert_eq!(
            schema["additionalProperties"].as_bool(),
            Some(false),
            "schema must forbid additional properties so consumers can \
             duck-type on the three known fields"
        );
    }
}
