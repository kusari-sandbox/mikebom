//! SPDX 3.0.1 `Annotation` element builder (milestone 011).
//!
//! Per `data-model.md` Element Catalog §`Annotation`: any mikebom
//! signal whose typed semantics don't match a native SPDX 3
//! property exactly (Q2 strict-match rule, FR-011) lands here.
//! One `Annotation` per `(subject, field, value)` tuple.
//!
//! The `statement` property carries the JSON-encoded
//! `MikebomAnnotationCommentV1` envelope reused verbatim from
//! milestone 010 (`crate::generate::spdx::annotations::
//! MikebomAnnotationCommentV1`). Reusing the envelope across
//! format versions means downstream consumers parse one shape
//! whether they're reading SPDX 2.3 `annotations[].comment` or
//! SPDX 3 `Annotation.statement`.

use std::collections::BTreeMap;

use serde_json::Value;

use mikebom_common::resolution::ResolvedComponent;

/// Build the `Annotation` elements for component-level mikebom
/// signals (Section C rows C1–C20 of the format-mapping doc that
/// stay annotation-bound under the Q2 strict-match rule).
///
/// Phase-4 placeholder — implemented during US2.
pub fn build_component_annotations(
    _components: &[ResolvedComponent],
    _package_iri_by_purl: &BTreeMap<String, String>,
    _doc_iri: &str,
    _creation_info_id: &str,
) -> Vec<Value> {
    Vec::new()
}

/// Build the `Annotation` elements for document-level mikebom
/// signals (rows C21–C23 + E1) — generation-context, trace-
/// integrity, os-release-missing-fields, compositions.
///
/// Phase-4 placeholder.
pub fn build_document_annotations(
    _scan: &crate::generate::ScanArtifacts<'_>,
    _doc_iri: &str,
    _creation_info_id: &str,
) -> Vec<Value> {
    Vec::new()
}
