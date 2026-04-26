//! SPDX 3.0.1 `Annotation` element builder (milestone 011 US2).
//!
//! Per `data-model.md` Element Catalog §`Annotation`: any mikebom
//! signal whose typed semantics don't match a native SPDX 3
//! property exactly (Q2 strict-match rule, FR-011) lands here.
//! One `Annotation` per `(subject, field, value)` tuple.
//!
//! The `statement` property carries the JSON-encoded
//! `MikebomAnnotationCommentV1` envelope reused verbatim from
//! milestone 010 (`super::annotations::MikebomAnnotationCommentV1`).
//! Reusing the envelope across format versions means downstream
//! consumers parse one shape whether they're reading SPDX 2.3
//! `annotations[].comment` or SPDX 3 `Annotation.statement`.
//!
//! Field set mirrors `super::annotations::annotate_component` and
//! `annotate_document` verbatim — if SPDX 2.3 emits a
//! `mikebom:<foo>` annotation for a given component, SPDX 3 emits
//! the same field with the same value (the annotation-fidelity
//! contract, FR-018 / SC-005). The only difference is wrapper
//! shape: SPDX 2.3 uses `SpdxAnnotation { annotator, date, type,
//! comment }`; SPDX 3 uses `{type: "Annotation", spdxId, subject,
//! annotationType: "other", statement}`.

use data_encoding::BASE32_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::{ResolutionTechnique, ResolvedComponent};

use super::annotations::MikebomAnnotationCommentV1;
use crate::generate::ScanArtifacts;

/// Build the `Annotation` elements for component-level mikebom
/// signals (Section C rows C1–C20 + D1/D2 of the format-mapping
/// doc that stay annotation-bound under the Q2 strict-match rule).
pub fn build_component_annotations(
    components: &[ResolvedComponent],
    package_iri_by_purl: &std::collections::BTreeMap<String, String>,
    doc_iri: &str,
    creation_info_id: &str,
    include_dev: bool,
    include_source_files: bool,
) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for c in components {
        let Some(pkg_iri) = package_iri_by_purl.get(c.purl.as_str()) else {
            continue;
        };
        push_component_fields(
            &mut out,
            pkg_iri,
            doc_iri,
            creation_info_id,
            c,
            include_dev,
            include_source_files,
        );
    }
    sort_by_spdx_id(&mut out);
    out
}

/// Build the `Annotation` elements for document-level mikebom
/// signals (rows C21–C23 + E1) — generation-context, os-release-
/// missing-fields, trace-integrity-*, compositions.
pub fn build_document_annotations(
    scan: &ScanArtifacts<'_>,
    doc_iri: &str,
    creation_info_id: &str,
) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    push_document_fields(&mut out, doc_iri, creation_info_id, scan);
    sort_by_spdx_id(&mut out);
    out
}

/// Build a single SPDX 3 `Annotation` element wrapping the shared
/// `MikebomAnnotationCommentV1` envelope.
fn build_annotation(
    subject_iri: &str,
    doc_iri: &str,
    creation_info_id: &str,
    field: &str,
    value: serde_json::Value,
) -> Value {
    let envelope = MikebomAnnotationCommentV1::new(field, value);
    let statement = envelope.to_comment_string();
    // ID derivation MUST NOT include `statement` — that string carries
    // workspace-relative source-file paths for `mikebom:source-files`,
    // and including host-specific bytes here breaks cross-host
    // byte-identity (milestone 017 T013b: same scan on macOS dev vs
    // Linux CI produced different `anno-*` hashes, displacing every
    // annotation in the spdxId-sorted `@graph[]` array). `subject|field`
    // is already unique per annotation: `push_*_fields` emits one
    // annotation per (component, field) pair, with no duplicate field
    // names per subject.
    let anno_iri = format!(
        "{doc_iri}/anno-{}",
        hash_prefix(format!("{subject_iri}|{field}").as_bytes(), 16)
    );
    json!({
        "type": "Annotation",
        "spdxId": anno_iri,
        "creationInfo": creation_info_id,
        "subject": subject_iri,
        "annotationType": "other",
        "statement": statement,
    })
}

/// Mirror of `annotations::annotate_component` — same 20 rows,
/// same emission gates, same envelope shape. Keep in lockstep.
#[allow(clippy::too_many_arguments)]
fn push_component_fields(
    out: &mut Vec<Value>,
    subject_iri: &str,
    doc_iri: &str,
    creation_info_id: &str,
    c: &ResolvedComponent,
    include_dev: bool,
    include_source_files: bool,
) {
    let push = |out: &mut Vec<Value>, field: &str, value: serde_json::Value| {
        out.push(build_annotation(
            subject_iri,
            doc_iri,
            creation_info_id,
            field,
            value,
        ));
    };

    // C1 source-type
    if let Some(ref v) = c.source_type {
        push(out, "mikebom:source-type", json!(v));
    }
    // C2 source-connection-ids
    if !c.evidence.source_connection_ids.is_empty() {
        push(
            out,
            "mikebom:source-connection-ids",
            json!(c.evidence.source_connection_ids.join(",")),
        );
    }
    // C3 deps-dev-match
    if let Some(ref m) = c.evidence.deps_dev_match {
        push(
            out,
            "mikebom:deps-dev-match",
            json!(format!("{}:{}@{}", m.system, m.name, m.version)),
        );
    }
    // C4 evidence-kind
    if let Some(ref v) = c.evidence_kind {
        push(out, "mikebom:evidence-kind", json!(v));
    }
    // C5 sbom-tier
    if let Some(ref v) = c.sbom_tier {
        push(out, "mikebom:sbom-tier", json!(v));
    }
    // C6 dev-dependency — same gate as CDX / SPDX 2.3 path.
    if include_dev && c.is_dev == Some(true) {
        push(out, "mikebom:dev-dependency", json!("true"));
    }
    // C7 co-owned-by
    if let Some(ref v) = c.co_owned_by {
        push(out, "mikebom:co-owned-by", json!(v));
    }
    // C8 shade-relocation
    if c.shade_relocation == Some(true) {
        push(out, "mikebom:shade-relocation", json!("true"));
    }
    // C9 npm-role
    if let Some(ref v) = c.npm_role {
        push(out, "mikebom:npm-role", json!(v));
    }
    // C10 binary-class
    if let Some(ref v) = c.binary_class {
        push(out, "mikebom:binary-class", json!(v));
    }
    // C11 binary-stripped
    if let Some(v) = c.binary_stripped {
        push(
            out,
            "mikebom:binary-stripped",
            json!(if v { "true" } else { "false" }),
        );
    }
    // C12 linkage-kind
    if let Some(ref v) = c.linkage_kind {
        push(out, "mikebom:linkage-kind", json!(v));
    }
    // C13 buildinfo-status
    if let Some(ref v) = c.buildinfo_status {
        push(out, "mikebom:buildinfo-status", json!(v));
    }
    // C14 detected-go
    if c.detected_go == Some(true) {
        push(out, "mikebom:detected-go", json!("true"));
    }
    // C15 binary-packed
    if let Some(ref v) = c.binary_packed {
        push(out, "mikebom:binary-packed", json!(v));
    }
    // C16 confidence
    if let Some(ref v) = c.confidence {
        push(out, "mikebom:confidence", json!(v));
    }
    // C17 raw-version
    if let Some(ref v) = c.raw_version {
        push(out, "mikebom:raw-version", json!(v));
    }
    // C18 source-files
    if include_source_files && !c.evidence.source_file_paths.is_empty() {
        push(
            out,
            "mikebom:source-files",
            json!(c.evidence.source_file_paths),
        );
    }
    // C19 cpe-candidates — emits full candidate list when more
    // than one candidate exists. Matches SPDX 2.3 shape. The
    // native ExternalIdentifier[cpe23] entries (T012) cover the
    // fully-resolved candidates separately; this annotation
    // carries the whole candidate set for lossless recovery.
    if c.cpes.len() > 1 {
        push(out, "mikebom:cpe-candidates", json!(c.cpes));
    }
    // C20 requirement-range
    if let Some(ref v) = c.requirement_range {
        push(out, "mikebom:requirement-range", json!(v));
    }

    // D1 evidence.identity — unconditional.
    let technique = match c.evidence.technique {
        ResolutionTechnique::UrlPattern => "url-pattern",
        ResolutionTechnique::HashMatch => "hash-match",
        ResolutionTechnique::PackageDatabase => "package-database",
        ResolutionTechnique::FilePathPattern => "file-path-pattern",
        ResolutionTechnique::HostnameHeuristic => "hostname-heuristic",
    };
    push(
        out,
        "evidence.identity",
        json!({
            "technique": technique,
            "confidence": c.evidence.confidence,
        }),
    );

    // D2 evidence.occurrences
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
        push(out, "evidence.occurrences", json!(items));
    }

    // Milestone 023: generic per-component annotation bag. Each
    // entry surfaces as a SPDX 3 graph-element Annotation. BTreeMap
    // iteration order is sorted by key — deterministic across runs.
    for (key, value) in &c.extra_annotations {
        push(out, key, value.clone());
    }
}

/// Mirror of `annotations::annotate_document` — C21–C23 + E1.
fn push_document_fields(
    out: &mut Vec<Value>,
    doc_iri: &str,
    creation_info_id: &str,
    scan: &ScanArtifacts<'_>,
) {
    let push = |out: &mut Vec<Value>, field: &str, value: serde_json::Value| {
        out.push(build_annotation(
            doc_iri,
            doc_iri,
            creation_info_id,
            field,
            value,
        ));
    };

    // C21 generation-context
    let gc = match scan.generation_context {
        GenerationContext::FilesystemScan => "filesystem-scan",
        GenerationContext::ContainerImageScan => "container-image-scan",
        GenerationContext::BuildTimeTrace => "build-time-trace",
    };
    push(out, "mikebom:generation-context", json!(gc));

    // C22 os-release-missing-fields
    if !scan.os_release_missing_fields.is_empty() {
        push(
            out,
            "mikebom:os-release-missing-fields",
            json!(scan.os_release_missing_fields),
        );
    }

    // C23 trace-integrity-* — four unconditional scalars.
    push(
        out,
        "mikebom:trace-integrity-ring-buffer-overflows",
        json!(scan.integrity.ring_buffer_overflows),
    );
    push(
        out,
        "mikebom:trace-integrity-events-dropped",
        json!(scan.integrity.events_dropped),
    );
    push(
        out,
        "mikebom:trace-integrity-uprobe-attach-failures",
        json!(scan.integrity.uprobe_attach_failures),
    );
    push(
        out,
        "mikebom:trace-integrity-kprobe-attach-failures",
        json!(scan.integrity.kprobe_attach_failures),
    );

    // E1 compositions
    if !scan.complete_ecosystems.is_empty() {
        push(
            out,
            "compositions",
            json!({
                "complete_ecosystems": scan.complete_ecosystems,
            }),
        );
    }
}

fn sort_by_spdx_id(values: &mut [Value]) {
    values.sort_by(|a, b| {
        let key = |v: &Value| v["spdxId"].as_str().unwrap_or("").to_string();
        key(a).cmp(&key(b))
    });
}

fn hash_prefix(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    let encoded = BASE32_NOPAD.encode(&digest);
    encoded[..chars].to_string()
}
