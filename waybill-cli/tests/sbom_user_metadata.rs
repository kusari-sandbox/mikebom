//! Milestone 080 — user-provided SBOM metadata integration tests.
//!
//! Drives `waybill sbom scan` with the milestone-080 flag set
//! (`--creator`, `--annotator`, `--annotation-comment`,
//! `--metadata-comment`, `--scan-target-name`, `--metadata-file`)
//! against synthetic source-tier fixtures, then asserts that each
//! supplied value lands at the format-native location in CDX 1.6,
//! SPDX 2.3, and SPDX 3 emissions.
//!
//! Test matrix (per `specs/080-user-sbom-metadata/contracts/user-sbom-metadata.md`):
//!
//! - **US1**: `creator_lands_in_all_three_formats`,
//!   `multi_creator_appends_additively`,
//!   `creator_type_routing_per_format`.
//! - **US2**: `metadata_comment_lands_in_all_three`,
//!   `annotator_pair_emits_annotation`,
//!   `multi_annotator_positional_pairing`,
//!   `annotator_without_comment_fails`.
//! - **US3**: `scan_target_name_overrides_default`,
//!   `scan_target_name_root_name_precedence`.
//! - **US4**: `metadata_file_loads_correctly`,
//!   `metadata_file_unknown_field_fails`,
//!   `metadata_file_malformed_json_fails`,
//!   `file_and_flags_merge_arrays`,
//!   `file_and_flag_conflict_on_singular_fails`.
//! - **Polish (T016)**: `determinism_byte_identical_across_runs`,
//!   `spdx3_conformance_with_full_metadata`,
//!   `cdx_native_annotations_emit_correctly`,
//!   `schema_validation_passes_with_full_metadata_per_format`.
//!
//! The harness mirrors `identifiers_subject_and_component.rs`
//! (milestone 076): synthesize a tiny Cargo fixture in a tempdir, run
//! the binary with the flag set under test, parse the emitted JSON.
//! `apply_fake_home_env` keeps cargo / go / maven probes hermetic.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

mod common;
use common::bin;
use common::normalize::{
    apply_fake_home_env, normalize_cdx_for_golden, normalize_spdx23_for_golden,
    normalize_spdx3_for_golden,
};
use common::workspace_root;
use common::fixture_path;

// ---------------------------------------------------------------------
// Common harness
// ---------------------------------------------------------------------

/// Path to the existing minimal cargo fixture used by the rest of the
/// integration suite. Source-tier scans of this fixture exercise every
/// emission code path waybill 080 touched.
fn fixture_root() -> PathBuf {
    fixture_path("cargo/lockfile-v3")
}

/// Run `waybill sbom scan` against `fixture` with `extra_args`,
/// emitting `out_format` to a tempdir; returns the parsed JSON +
/// captured stderr.
///
/// `out_format` is one of `cyclonedx-json`, `spdx-2.3-json`,
/// `spdx-3-json`.
fn run_scan(
    fake_home: &Path,
    fixture: &Path,
    extra_args: &[&str],
    out_format: &str,
    out_filename: &str,
) -> (serde_json::Value, String) {
    let out_dir = tempfile::tempdir().expect("output tempdir");
    let out_path = out_dir.path().join(out_filename);
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture)
        .arg("--format")
        .arg(out_format)
        .arg("--output")
        .arg(format!("{out_format}={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash");
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("scan runs");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "scan failed: stderr={stderr}\nstdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let bytes = std::fs::read(&out_path).expect("read produced sbom");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("produced sbom is valid JSON");
    drop(out_dir);
    (parsed, stderr)
}

/// Run `waybill sbom scan` and return the raw output bytes alongside
/// the parsed JSON — used by the determinism test which needs the
/// on-disk shape for normalization-stable byte compare.
fn run_scan_raw(
    fake_home: &Path,
    fixture: &Path,
    extra_args: &[&str],
    out_format: &str,
    out_filename: &str,
) -> String {
    let out_dir = tempfile::tempdir().expect("output tempdir");
    let out_path = out_dir.path().join(out_filename);
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture)
        .arg("--format")
        .arg(out_format)
        .arg("--output")
        .arg(format!("{out_format}={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash");
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("scan runs");
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read_to_string(&out_path).expect("read produced sbom")
}

/// Walk a CDX `bom.annotations[]` and collect every `text` whose
/// annotator matches the supplied (kind, name) tuple. `kind` is one of
/// `"organization"`, `"individual"`, `"component"` (CDX `oneOf` keys).
fn cdx_annotation_texts<'a>(
    bom: &'a serde_json::Value,
    annotator_kind: &str,
    annotator_name: &str,
) -> Vec<&'a str> {
    let Some(arr) = bom.get("annotations").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter(|a| {
            a.get("annotator")
                .and_then(|v| v.get(annotator_kind))
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                == Some(annotator_name)
        })
        .filter_map(|a| a.get("text").and_then(|v| v.as_str()))
        .collect()
}

// ---------------------------------------------------------------------
// US1 — `--creator`
// ---------------------------------------------------------------------

#[test]
fn creator_lands_in_all_three_formats() {
    // US1 §1, SC-001 / FR-001: `--creator "Tool: my-pipeline"` lands at
    // the format-native creator/tools field of every emitted format.
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &["--creator", "Tool: my-pipeline"];

    // CDX 1.6: metadata.tools.components[] gains a new application entry.
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let tools_components = cdx["metadata"]["tools"]["components"]
        .as_array()
        .expect("metadata.tools.components[]");
    let names: Vec<&str> = tools_components
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        names.contains(&"my-pipeline"),
        "CDX metadata.tools.components missing user creator; got {names:?}"
    );
    assert!(
        names.contains(&"waybill"),
        "CDX metadata.tools.components dropped the auto-populated waybill entry; got {names:?}"
    );

    // SPDX 2.3: creationInfo.creators[] contains the verbatim line.
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let creators = spdx["creationInfo"]["creators"]
        .as_array()
        .expect("creationInfo.creators[]");
    let creator_strs: Vec<&str> =
        creators.iter().filter_map(|c| c.as_str()).collect();
    assert!(
        creator_strs.contains(&"Tool: my-pipeline"),
        "SPDX 2.3 creationInfo.creators missing user creator; got {creator_strs:?}"
    );

    // SPDX 3: a new Tool element exists in @graph and CreationInfo
    // .createdUsing references it.
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().expect("@graph");
    let tool_iris: Vec<&str> = graph
        .iter()
        .filter(|e| e["type"].as_str() == Some("Tool"))
        .filter(|e| e["name"].as_str() == Some("my-pipeline"))
        .filter_map(|e| e["spdxId"].as_str())
        .collect();
    assert_eq!(
        tool_iris.len(),
        1,
        "SPDX 3 expected one user Tool element named my-pipeline; got {tool_iris:?}"
    );
    let user_tool_iri = tool_iris[0];
    let creation_info = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("CreationInfo"))
        .expect("CreationInfo element");
    let created_using: Vec<&str> = creation_info["createdUsing"]
        .as_array()
        .expect("createdUsing[]")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        created_using.contains(&user_tool_iri),
        "SPDX 3 CreationInfo.createdUsing missing user Tool IRI {user_tool_iri}; got {created_using:?}"
    );
}

#[test]
fn multi_creator_appends_additively() {
    // US1 §2 / FR-001 + FR-007: two `--creator` flags both visible
    // alongside the auto-populated waybill entry.
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--creator",
        "Tool: pipeline-a",
        "--creator",
        "Tool: pipeline-b",
    ];

    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let names: Vec<&str> = cdx["metadata"]["tools"]["components"]
        .as_array()
        .expect("tools.components[]")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        names.contains(&"waybill") && names.contains(&"pipeline-a") && names.contains(&"pipeline-b"),
        "CDX missing one or more expected creators; got {names:?}"
    );
    let pos_a = names.iter().position(|n| *n == "pipeline-a").unwrap();
    let pos_b = names.iter().position(|n| *n == "pipeline-b").unwrap();
    assert!(
        pos_a < pos_b,
        "CDX user-creator insertion order not preserved: {names:?}"
    );

    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let creator_strs: Vec<String> = spdx["creationInfo"]["creators"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.as_str().map(String::from))
        .collect();
    assert!(creator_strs.iter().any(|s| s == "Tool: pipeline-a"));
    assert!(creator_strs.iter().any(|s| s == "Tool: pipeline-b"));
    // waybill auto-tool entry preserved.
    assert!(
        creator_strs.iter().any(|s| s.starts_with("Tool: waybill-")),
        "SPDX 2.3 dropped the auto waybill Tool entry: {creator_strs:?}"
    );
}

#[test]
fn creator_type_routing_per_format() {
    // US1 §3 + edge cases / FR-001 routing matrix: one of each
    // Tool / Organization / Person → routes correctly per research §2.
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--creator",
        "Tool: my-pipeline",
        "--creator",
        "Organization: ACME Corp",
        "--creator",
        "Person: Alice",
    ];

    // ----- CDX 1.6 -----
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    // Tool → metadata.tools.components[].
    let tool_names: Vec<&str> = cdx["metadata"]["tools"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        tool_names.contains(&"my-pipeline"),
        "CDX Tool routing failed; got {tool_names:?}"
    );
    // Organization (1st) → metadata.manufacturer.
    assert_eq!(
        cdx["metadata"]["manufacturer"]["name"].as_str(),
        Some("ACME Corp"),
        "CDX Organization routing failed; expected metadata.manufacturer.name=ACME Corp"
    );
    // Person → metadata.authors[].
    let author_names: Vec<&str> = cdx["metadata"]["authors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert!(
        author_names.contains(&"Alice"),
        "CDX Person routing failed; got authors={author_names:?}"
    );

    // ----- SPDX 2.3 -----
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    // All three types → creationInfo.creators[] verbatim.
    let creator_strs: Vec<String> = spdx["creationInfo"]["creators"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.as_str().map(String::from))
        .collect();
    assert!(
        creator_strs.iter().any(|s| s == "Tool: my-pipeline"),
        "SPDX 2.3 missing Tool creator; got {creator_strs:?}"
    );
    assert!(
        creator_strs.iter().any(|s| s == "Organization: ACME Corp"),
        "SPDX 2.3 missing Organization creator; got {creator_strs:?}"
    );
    assert!(
        creator_strs.iter().any(|s| s == "Person: Alice"),
        "SPDX 2.3 missing Person creator; got {creator_strs:?}"
    );

    // ----- SPDX 3 -----
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().unwrap();
    // Tool → new Tool element + reference from CreationInfo.createdUsing.
    let tool_iri = graph
        .iter()
        .find(|e| {
            e["type"].as_str() == Some("Tool")
                && e["name"].as_str() == Some("my-pipeline")
        })
        .and_then(|e| e["spdxId"].as_str())
        .expect("SPDX 3 user Tool element missing");
    // Organization → new Organization + reference from createdBy.
    let org_iri = graph
        .iter()
        .find(|e| {
            e["type"].as_str() == Some("Organization")
                && e["name"].as_str() == Some("ACME Corp")
        })
        .and_then(|e| e["spdxId"].as_str())
        .expect("SPDX 3 user Organization element missing");
    // Person → new Person + reference from createdBy.
    let person_iri = graph
        .iter()
        .find(|e| {
            e["type"].as_str() == Some("Person")
                && e["name"].as_str() == Some("Alice")
        })
        .and_then(|e| e["spdxId"].as_str())
        .expect("SPDX 3 user Person element missing");
    let creation_info = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("CreationInfo"))
        .unwrap();
    let created_using: Vec<&str> = creation_info["createdUsing"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let created_by: Vec<&str> = creation_info["createdBy"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        created_using.contains(&tool_iri),
        "SPDX 3 createdUsing missing Tool {tool_iri}: {created_using:?}"
    );
    assert!(
        created_by.contains(&org_iri),
        "SPDX 3 createdBy missing Organization {org_iri}: {created_by:?}"
    );
    assert!(
        created_by.contains(&person_iri),
        "SPDX 3 createdBy missing Person {person_iri}: {created_by:?}"
    );

    // Edge case (VR-080-001): non-canonical type prefixes like `Bot:` /
    // `Service:` MUST be rejected at clap parse time so they never
    // silently route to a default kind. This locks the
    // canonical-set-of-three property at the integration boundary —
    // catches regressions that loosen `parse_creator_str` to accept
    // arbitrary prefixes.
    let fake_home2 = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("out.cdx.json");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home2.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--creator")
        .arg("Bot: rogue");
    let bot_out = cmd.output().expect("scan runs");
    assert!(
        !bot_out.status.success(),
        "scan should reject `--creator 'Bot: ...'` at parse time per VR-080-001 \
         (canonical type prefixes are Tool/Organization/Person only); \
         got success — production-side parse_creator_str regressed?"
    );
    let bot_stderr = String::from_utf8_lossy(&bot_out.stderr).to_string();
    assert!(
        bot_stderr.contains("Bot")
            || bot_stderr.contains("invalid type")
            || bot_stderr.contains("Tool, Organization, Person"),
        "expected rejection diagnostic naming `Bot` / valid types; got stderr={bot_stderr}"
    );
}

// ---------------------------------------------------------------------
// US2 — `--metadata-comment` + `--annotator` / `--annotation-comment`
// ---------------------------------------------------------------------

#[test]
fn metadata_comment_lands_in_all_three() {
    // US2 §1-3, SC-002 / FR-002.
    let fake_home = tempfile::tempdir().unwrap();
    let comment = "Release v1.0.0";
    let extra = &["--metadata-comment", comment];

    // SPDX 2.3: creationInfo.comment carries the operator-supplied
    // value (the pre-080 scope hint is appended below it).
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let ci_comment = spdx["creationInfo"]["comment"]
        .as_str()
        .expect("creationInfo.comment");
    assert!(
        ci_comment.starts_with(comment),
        "SPDX 2.3 creationInfo.comment doesn't lead with user comment; got {ci_comment:?}"
    );

    // CDX: bom.annotations[] entry annotator.organization.name = waybill contributors,
    // text == comment.
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let texts = cdx_annotation_texts(&cdx, "organization", "waybill contributors");
    assert!(
        texts.contains(&comment),
        "CDX bom.annotations missing metadata-comment; got texts={texts:?}"
    );

    // SPDX 3: an Annotation element with subject=<doc-iri>,
    // annotationType=other, statement=comment.
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().unwrap();
    let doc_iri = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("SpdxDocument"))
        .and_then(|e| e["spdxId"].as_str())
        .expect("SpdxDocument spdxId");
    let found = graph.iter().any(|e| {
        e["type"].as_str() == Some("Annotation")
            && e["subject"].as_str() == Some(doc_iri)
            && e["annotationType"].as_str() == Some("other")
            && e["statement"].as_str() == Some(comment)
    });
    assert!(
        found,
        "SPDX 3 missing metadata-comment Annotation; doc_iri={doc_iri}"
    );
}

#[test]
fn annotator_pair_emits_annotation() {
    // US2 §4, SC-003 / FR-003.
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--annotator",
        "Tool: reviewer",
        "--annotation-comment",
        "Approved",
    ];

    // CDX: annotation with annotator.component.name (Tool routing).
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let texts = cdx_annotation_texts(&cdx, "component", "reviewer");
    assert!(
        texts.contains(&"Approved"),
        "CDX bom.annotations missing Tool reviewer comment; got texts={texts:?}"
    );

    // SPDX 2.3: annotations[] entry with annotator + comment.
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let anns = spdx["annotations"].as_array().expect("annotations[]");
    let found = anns.iter().any(|a| {
        a["annotator"].as_str() == Some("Tool: reviewer")
            && a["annotationType"].as_str() == Some("OTHER")
            && a["comment"].as_str() == Some("Approved")
    });
    assert!(
        found,
        "SPDX 2.3 annotations missing Tool reviewer entry; got {anns:?}"
    );

    // SPDX 3: Annotation element pointing at the SpdxDocument with the
    // user comment as `statement`.
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().unwrap();
    let doc_iri = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("SpdxDocument"))
        .and_then(|e| e["spdxId"].as_str())
        .expect("SpdxDocument spdxId");
    let found = graph.iter().any(|e| {
        e["type"].as_str() == Some("Annotation")
            && e["subject"].as_str() == Some(doc_iri)
            && e["statement"].as_str() == Some("Approved")
    });
    assert!(
        found,
        "SPDX 3 missing Annotation element with statement=Approved"
    );
}

#[test]
fn multi_annotator_positional_pairing() {
    // Q1 clarification: --annotator A --annotation-comment X
    // --annotator B --annotation-comment Y → two separate annotations,
    // each pairing positionally.
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--annotator",
        "Tool: A",
        "--annotation-comment",
        "X",
        "--annotator",
        "Tool: B",
        "--annotation-comment",
        "Y",
    ];

    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let anns = spdx["annotations"].as_array().expect("annotations[]");
    let pair_a = anns.iter().any(|a| {
        a["annotator"].as_str() == Some("Tool: A") && a["comment"].as_str() == Some("X")
    });
    let pair_b = anns.iter().any(|a| {
        a["annotator"].as_str() == Some("Tool: B") && a["comment"].as_str() == Some("Y")
    });
    assert!(pair_a, "missing pair A→X in SPDX 2.3 annotations: {anns:?}");
    assert!(pair_b, "missing pair B→Y in SPDX 2.3 annotations: {anns:?}");

    // Verify CDX side too — both Tool annotations land with their
    // respective comments.
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let a_texts = cdx_annotation_texts(&cdx, "component", "A");
    let b_texts = cdx_annotation_texts(&cdx, "component", "B");
    assert!(a_texts.contains(&"X"), "CDX missing A→X: {a_texts:?}");
    assert!(b_texts.contains(&"Y"), "CDX missing B→Y: {b_texts:?}");
}

#[test]
fn annotator_without_comment_fails() {
    // US2 §5 / FR-003: --annotator alone fails parsing with the
    // AnnotatorPairCountMismatch error message (or strict-interleaving
    // diagnostic — both surface "annotation-comment" / "annotator").
    let fake_home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("out.cdx.json");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--annotator")
        .arg("Tool: A");
    let out = cmd.output().expect("scan runs");
    assert!(
        !out.status.success(),
        "scan should fail without paired --annotation-comment; got success"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("annotation-comment") || stderr.contains("annotator"),
        "expected pairing-mismatch diagnostic mentioning annotator/annotation-comment; got stderr={stderr}"
    );

    // Also check the intra-clap-collection mismatch path:
    // `--annotator A --annotation-comment X --annotator B` should fail
    // with the strict-interleaving diagnostic (B has no following
    // --annotation-comment).
    let mut cmd2 = Command::new(bin());
    apply_fake_home_env(&mut cmd2, fake_home.path());
    let out_dir2 = tempfile::tempdir().unwrap();
    let out_path2 = out_dir2.path().join("out.cdx.json");
    cmd2.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", out_path2.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--annotator")
        .arg("Tool: A")
        .arg("--annotation-comment")
        .arg("X")
        .arg("--annotator")
        .arg("Tool: B");
    let out2 = cmd2.output().expect("scan runs");
    assert!(
        !out2.status.success(),
        "scan should fail with dangling 2nd --annotator"
    );
}

// ---------------------------------------------------------------------
// US3 — `--scan-target-name`
// ---------------------------------------------------------------------

#[test]
fn scan_target_name_overrides_default() {
    // US3 §1-3, SC-004 / FR-004: --scan-target-name "foo" sets the
    // document/Sbom-level name in all three formats. Use the bare
    // cargo lockfile fixture (no main-module promotion) so the CDX
    // metadata.component.name slot is the auto-derived directory
    // name; --scan-target-name should override it.
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &["--scan-target-name", "foo"];

    // CDX: metadata.component.name = "foo".
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    assert_eq!(
        cdx["metadata"]["component"]["name"].as_str(),
        Some("foo"),
        "CDX metadata.component.name should be 'foo'"
    );

    // SPDX 2.3: top-level document `name` = "foo".
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    assert_eq!(
        spdx["name"].as_str(),
        Some("foo"),
        "SPDX 2.3 document-level name should be 'foo'"
    );

    // SPDX 3: SpdxDocument.name = "foo".
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().unwrap();
    let sbom_name = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("SpdxDocument"))
        .and_then(|e| e["name"].as_str())
        .expect("SpdxDocument.name");
    assert_eq!(sbom_name, "foo", "SPDX 3 SpdxDocument.name should be 'foo'");
}

#[test]
fn scan_target_name_root_name_precedence() {
    // US3 + research §5: --scan-target-name "S" --root-name "R" →
    //   - CDX metadata.component.name == "R" (root wins; stderr warn).
    //   - SPDX 2.3 document-level name == "S" AND root Package name == "R".
    //   - SPDX 3 SpdxDocument.name == "S" AND root software_Package.name == "R".
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--scan-target-name",
        "scan-target-S",
        "--root-name",
        "root-R",
        "--root-version",
        "9.9.9",
    ];

    // CDX: --root-name wins, stderr warning.
    let (cdx, stderr) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    assert_eq!(
        cdx["metadata"]["component"]["name"].as_str(),
        Some("root-R"),
        "CDX metadata.component.name: --root-name takes precedence"
    );
    assert!(
        stderr.contains("--root-name overrides --scan-target-name")
            || stderr.contains("root-name"),
        "expected stderr warning about precedence; got stderr={stderr}"
    );

    // SPDX 2.3: document name = scan-target-S; root Package name = root-R.
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    assert_eq!(
        spdx["name"].as_str(),
        Some("scan-target-S"),
        "SPDX 2.3 document-level name should equal --scan-target-name"
    );
    let pkgs = spdx["packages"].as_array().expect("packages[]");
    let pkg_names: Vec<&str> =
        pkgs.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(
        pkg_names.contains(&"root-R"),
        "SPDX 2.3 root Package name should equal --root-name; got {pkg_names:?}"
    );

    // SPDX 3: SpdxDocument.name = scan-target-S; root software_Package
    // name = root-R.
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().unwrap();
    let sbom_name = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("SpdxDocument"))
        .and_then(|e| e["name"].as_str())
        .expect("SpdxDocument.name");
    assert_eq!(
        sbom_name, "scan-target-S",
        "SPDX 3 SpdxDocument.name should equal --scan-target-name"
    );
    let pkg_names: Vec<&str> = graph
        .iter()
        .filter(|e| e["type"].as_str() == Some("software_Package"))
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert!(
        pkg_names.contains(&"root-R"),
        "SPDX 3 root software_Package name should equal --root-name; got {pkg_names:?}"
    );
}

// ---------------------------------------------------------------------
// US4 — `--metadata-file`
// ---------------------------------------------------------------------

fn write_metadata_file(content: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::Builder::new()
        .prefix("waybill-080-meta-")
        .suffix(".json")
        .tempfile()
        .unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn metadata_file_loads_correctly() {
    // US4 §1, SC-005 / FR-005: emit SBOM via --metadata-file containing
    // all four field types; assert each lands at the correct
    // format-native location.
    let fake_home = tempfile::tempdir().unwrap();
    let f = write_metadata_file(
        r#"{
  "creators": ["Tool: file-T"],
  "annotators": [{"type_name": "Tool: file-A", "comment": "from file"}],
  "metadata_comment": "doc comment from file",
  "scan_target_name": "file-target"
}"#,
    );
    let path_str = f.path().to_string_lossy().to_string();
    let extra = &["--metadata-file", path_str.as_str()];

    // CDX: tools.components has file-T; annotation with text="from file" and
    // an annotation with text="doc comment from file"; component.name = file-target.
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let tool_names: Vec<&str> = cdx["metadata"]["tools"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(tool_names.contains(&"file-T"), "got {tool_names:?}");
    let from_file = cdx_annotation_texts(&cdx, "component", "file-A");
    assert!(from_file.contains(&"from file"), "got {from_file:?}");
    let doc_from_file = cdx_annotation_texts(&cdx, "organization", "waybill contributors");
    assert!(
        doc_from_file.contains(&"doc comment from file"),
        "expected doc comment from file in CDX bom.annotations[]; got {doc_from_file:?}"
    );
    assert_eq!(
        cdx["metadata"]["component"]["name"].as_str(),
        Some("file-target")
    );

    // SPDX 2.3: creators contains "Tool: file-T"; annotations[] has
    // file-A pair; creationInfo.comment starts with the doc comment;
    // top-level name = file-target.
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let creator_strs: Vec<String> = spdx["creationInfo"]["creators"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.as_str().map(String::from))
        .collect();
    assert!(creator_strs.iter().any(|s| s == "Tool: file-T"));
    let anns = spdx["annotations"].as_array().expect("annotations[]");
    let pair_found = anns.iter().any(|a| {
        a["annotator"].as_str() == Some("Tool: file-A")
            && a["comment"].as_str() == Some("from file")
    });
    assert!(pair_found, "SPDX 2.3 missing file-A pair");
    let ci_comment = spdx["creationInfo"]["comment"].as_str().unwrap_or("");
    assert!(ci_comment.starts_with("doc comment from file"));
    assert_eq!(spdx["name"].as_str(), Some("file-target"));

    // SPDX 3: a Tool element named file-T present; an Annotation
    // element with statement="from file" exists; SpdxDocument.name = file-target.
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let graph = spdx3["@graph"].as_array().unwrap();
    let has_tool = graph.iter().any(|e| {
        e["type"].as_str() == Some("Tool") && e["name"].as_str() == Some("file-T")
    });
    assert!(has_tool, "SPDX 3 missing Tool file-T");
    let has_ann = graph.iter().any(|e| {
        e["type"].as_str() == Some("Annotation")
            && e["statement"].as_str() == Some("from file")
    });
    assert!(has_ann, "SPDX 3 missing Annotation 'from file'");
    let sbom_name = graph
        .iter()
        .find(|e| e["type"].as_str() == Some("SpdxDocument"))
        .and_then(|e| e["name"].as_str());
    assert_eq!(sbom_name, Some("file-target"));
}

#[test]
fn metadata_file_unknown_field_fails() {
    // US4 §3 / VR-080-004: file with unknown top-level field
    // (`creator` typo) → fails with parse error naming the field.
    let fake_home = tempfile::tempdir().unwrap();
    let f = write_metadata_file(r#"{"creator": ["Tool: T1"]}"#);
    let path_str = f.path().to_string_lossy().to_string();
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("out.cdx.json");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--metadata-file")
        .arg(&path_str);
    let out = cmd.output().expect("scan runs");
    assert!(
        !out.status.success(),
        "scan should fail on unknown metadata-file field"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("creator"),
        "stderr should name offending field 'creator'; got stderr={stderr}"
    );
}

#[test]
fn metadata_file_malformed_json_fails() {
    // US4 §4 / FR-005: malformed JSON → parse error with line+column.
    let fake_home = tempfile::tempdir().unwrap();
    let f = write_metadata_file(r#"{"creators": ["#); // truncated
    let path_str = f.path().to_string_lossy().to_string();
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("out.cdx.json");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--metadata-file")
        .arg(&path_str);
    let out = cmd.output().expect("scan runs");
    assert!(
        !out.status.success(),
        "scan should fail on malformed JSON metadata-file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("line") || lower.contains("column") || lower.contains("eof"),
        "expected JSON parse error to carry positional info; got stderr={stderr}"
    );
}

#[test]
fn file_and_flags_merge_arrays() {
    // US4 §2 / FR-006: file `creators: ["Tool: A"]` + flag
    // `--creator "Tool: B"` → SBOM contains BOTH A and B, in that order
    // (file first per research §6).
    let fake_home = tempfile::tempdir().unwrap();
    let f = write_metadata_file(
        r#"{"creators": ["Tool: file-creator-A"]}"#,
    );
    let path_str = f.path().to_string_lossy().to_string();
    let extra = &[
        "--metadata-file",
        path_str.as_str(),
        "--creator",
        "Tool: flag-creator-B",
    ];

    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let names: Vec<&str> = cdx["metadata"]["tools"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    let pos_a = names.iter().position(|n| *n == "file-creator-A");
    let pos_b = names.iter().position(|n| *n == "flag-creator-B");
    assert!(pos_a.is_some(), "missing file creator A: {names:?}");
    assert!(pos_b.is_some(), "missing flag creator B: {names:?}");
    assert!(
        pos_a.unwrap() < pos_b.unwrap(),
        "file creator A must precede flag creator B: {names:?}"
    );
}

#[test]
fn file_and_flag_conflict_on_singular_fails() {
    // FR-006 / VR-080-005: file metadata_comment + flag
    // --metadata-comment → conflict error naming both sources.
    let fake_home = tempfile::tempdir().unwrap();
    let f = write_metadata_file(r#"{"metadata_comment": "from-file"}"#);
    let path_str = f.path().to_string_lossy().to_string();
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("out.cdx.json");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--metadata-file")
        .arg(&path_str)
        .arg("--metadata-comment")
        .arg("from-flag");
    let out = cmd.output().expect("scan runs");
    assert!(
        !out.status.success(),
        "scan should fail when file + flag both supply metadata_comment"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("metadata_comment")
            && (stderr.contains("from-file") || stderr.contains("from-flag")),
        "expected conflict error naming both sources; got stderr={stderr}"
    );
}

// ---------------------------------------------------------------------
// T016 — Polish & cross-cutting concerns
// ---------------------------------------------------------------------

#[test]
fn determinism_byte_identical_across_runs() {
    // FR-009 + SC-009: same flag inputs + same scan inputs across two
    // re-runs → byte-identical SBOMs (after normalizing volatile fields
    // like serialNumber + workspace paths + timestamps).
    let workspace = workspace_root();
    let extra: &[&str] = &[
        "--creator",
        "Tool: pipeline-X",
        "--metadata-comment",
        "release v1.0.0",
        "--annotator",
        "Person: reviewer",
        "--annotation-comment",
        "looks good",
        "--scan-target-name",
        "myproj",
    ];

    for (fmt, fname) in &[
        ("cyclonedx-json", "out.cdx.json"),
        ("spdx-2.3-json", "out.spdx.json"),
        ("spdx-3-json", "out.spdx3.json"),
    ] {
        let home_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();
        let raw_a = run_scan_raw(home_a.path(), &fixture_root(), extra, fmt, fname);
        let raw_b = run_scan_raw(home_b.path(), &fixture_root(), extra, fmt, fname);
        let norm_a = match *fmt {
            "cyclonedx-json" => normalize_cdx_for_golden(&raw_a, &workspace),
            "spdx-2.3-json" => normalize_spdx23_for_golden(&raw_a, &workspace),
            "spdx-3-json" => normalize_spdx3_for_golden(&raw_a, &workspace),
            _ => unreachable!(),
        };
        let norm_b = match *fmt {
            "cyclonedx-json" => normalize_cdx_for_golden(&raw_b, &workspace),
            "spdx-2.3-json" => normalize_spdx23_for_golden(&raw_b, &workspace),
            "spdx-3-json" => normalize_spdx3_for_golden(&raw_b, &workspace),
            _ => unreachable!(),
        };
        assert_eq!(
            norm_a, norm_b,
            "format {fmt}: re-emission with full milestone-080 metadata must be byte-identical (after normalize)"
        );
    }
}

/// Pinned validator binary path — same one used by spdx3_conformance.rs.
fn validator_path() -> PathBuf {
    workspace_root().join(".venv/spdx3-validate/bin/spdx3-validate")
}

/// Mirror of `spdx3_conformance::run_validator` — minimal copy because
/// integration-test crates can't share helpers across `tests/*.rs`
/// files.
enum ValidationResult {
    Pass,
    Fail { combined_output: String },
    Skipped,
}

fn run_spdx3_validator(fixture_path: &Path) -> ValidationResult {
    let bin_path = validator_path();
    if !bin_path.exists() {
        let require =
            std::env::var("WAYBILL_REQUIRE_SPDX3_VALIDATOR").ok().as_deref() == Some("1");
        if require {
            return ValidationResult::Fail {
                combined_output: format!(
                    "spdx3-validate not found at {} and WAYBILL_REQUIRE_SPDX3_VALIDATOR=1 is set; \
                     run scripts/install-spdx3-validate.sh on this host before re-running CI.",
                    bin_path.display()
                ),
            };
        }
        eprintln!(
            "[sbom_user_metadata] WARN: spdx3-validate not found at {}; \
             run scripts/install-spdx3-validate.sh and re-run cargo test \
             to enable conformance gating. Skipping check (local-dev mode).",
            bin_path.display()
        );
        return ValidationResult::Skipped;
    }
    let output = Command::new(&bin_path)
        .arg("--quiet")
        .arg("-j")
        .arg(fixture_path)
        .output()
        .expect("validator command should be invocable when binary exists");
    let mut combined = Vec::new();
    combined.extend_from_slice(&output.stdout);
    combined.extend_from_slice(&output.stderr);
    let combined_text = String::from_utf8_lossy(&combined).into_owned();
    let has_violation_marker = combined_text.contains("Violation of type");
    if output.status.success() && !has_violation_marker {
        ValidationResult::Pass
    } else {
        ValidationResult::Fail {
            combined_output: combined_text,
        }
    }
}

#[test]
fn spdx3_conformance_with_full_metadata() {
    // SC-008 / FR-010 + milestone-078 SHACL gate: emit SPDX 3 SBOM with
    // all five flag families populated; shell out to the milestone-078
    // validator; assert zero violations including the new Annotation +
    // Tool/Organization/Person elements.
    let fake_home = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let out_path = out_dir.path().join("out.spdx3.json");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture_root())
        .arg("--format")
        .arg("spdx-3-json")
        .arg("--output")
        .arg(format!("spdx-3-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .arg("--creator")
        .arg("Tool: ci-pipeline")
        .arg("--creator")
        .arg("Organization: ACME Corp")
        .arg("--creator")
        .arg("Person: Alice")
        .arg("--annotator")
        .arg("Tool: reviewer")
        .arg("--annotation-comment")
        .arg("approved")
        .arg("--metadata-comment")
        .arg("Release v1.0.0")
        .arg("--scan-target-name")
        .arg("myproj");
    let out = cmd.output().expect("scan runs");
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    match run_spdx3_validator(&out_path) {
        ValidationResult::Pass => {}
        ValidationResult::Skipped => {
            eprintln!(
                "[sbom_user_metadata] spdx3_conformance_with_full_metadata: skipping conformance assertion (validator absent, local-dev mode)"
            );
        }
        ValidationResult::Fail { combined_output } => {
            panic!(
                "spdx3-validate reported violations for SBOM with full milestone-080 metadata:\n{combined_output}"
            );
        }
    }
}

#[test]
fn cdx_native_annotations_emit_correctly() {
    // Q2 audit confirmation: with milestone-080 flags exercised, the
    // CDX SBOM does NOT introduce any `waybill:invocation-comment`,
    // `waybill:annotation`, or `waybill:user-metadata` properties — the
    // values ride bom.annotations[] / metadata.* native slots per the
    // Phase 0 §1 audit (FR-008; parity-bridge fallback NOT triggered).
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--creator",
        "Tool: ci",
        "--creator",
        "Organization: ACME",
        "--creator",
        "Person: Alice",
        "--metadata-comment",
        "Release v1.0.0",
        "--annotator",
        "Tool: reviewer",
        "--annotation-comment",
        "approved",
        "--scan-target-name",
        "myproj",
    ];
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );

    // Walk all property arrays and assert no milestone-080-specific
    // waybill:* annotation namespaces appear. (Pre-existing
    // waybill:* properties from earlier milestones — generation-context,
    // sbom-tier, etc. — are EXPECTED to be present; we only assert the
    // milestone-080 namespaces don't fall back.)
    let forbidden_names = [
        "waybill:invocation-comment",
        "waybill:annotation",
        "waybill:annotator",
        "waybill:metadata-comment",
        "waybill:scan-target-name",
        "waybill:creator",
        "waybill:user-metadata",
    ];
    fn collect_property_names(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    if k == "properties" {
                        if let Some(arr) = v.as_array() {
                            for p in arr {
                                if let Some(name) = p.get("name").and_then(|n| n.as_str())
                                {
                                    out.push(name.to_string());
                                }
                            }
                        }
                    }
                    collect_property_names(v, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    collect_property_names(v, out);
                }
            }
            _ => {}
        }
    }
    let mut names = Vec::new();
    collect_property_names(&cdx, &mut names);
    for forbidden in &forbidden_names {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "CDX should not emit forbidden milestone-080 fallback property {forbidden:?}; \
             native bom.annotations[] / metadata.* slots are the audit-confirmed home. \
             property names = {names:?}"
        );
    }

    // And confirm the actual native landings are present:
    // (a) bom.annotations[] non-empty
    let bom_anns = cdx["annotations"].as_array();
    assert!(
        bom_anns.is_some() && !bom_anns.unwrap().is_empty(),
        "expected non-empty bom.annotations[] when --metadata-comment + --annotator supplied"
    );
    // (b) metadata.manufacturer set from Organization creator
    assert_eq!(
        cdx["metadata"]["manufacturer"]["name"].as_str(),
        Some("ACME")
    );
    // (c) metadata.authors[] gained the Person creator
    let authors: Vec<&str> = cdx["metadata"]["authors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert!(authors.contains(&"Alice"), "got authors={authors:?}");
}

// ---------------------------------------------------------------------
// Schema validation — milestone-080 outputs must validate against
// each format's official JSON schema.
// ---------------------------------------------------------------------

fn spdx23_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-2.3.json")
}

fn spdx3_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-3.0.1.json")
}

fn spdx23_validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(spdx23_schema_path())
            .expect("read SPDX 2.3 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse SPDX 2.3 schema");
        jsonschema::validator_for(&schema).expect("compile SPDX 2.3 schema")
    })
}

fn spdx3_validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(spdx3_schema_path())
            .expect("read SPDX 3 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse SPDX 3 schema");
        jsonschema::validator_for(&schema).expect("compile SPDX 3 schema")
    })
}

#[test]
fn schema_validation_passes_with_full_metadata_per_format() {
    // FR-010 + SC-007: emit fresh CDX 1.6 + SPDX 2.3 + SPDX 3 SBOMs
    // with all five milestone-080 flag families populated; validate
    // each against its official JSON schema. The comparison rule
    // mirrors `spdx_schema_validation`: validation categories must be a
    // subset of the SPDX-reference baseline, OR empty for CDX 1.6
    // (CDX has no reference example baseline).
    let fake_home = tempfile::tempdir().unwrap();
    let extra = &[
        "--creator",
        "Tool: ci-pipeline",
        "--creator",
        "Organization: ACME Corp",
        "--creator",
        "Person: Alice",
        "--annotator",
        "Tool: reviewer",
        "--annotation-comment",
        "approved",
        "--metadata-comment",
        "Release v1.0.0",
        "--scan-target-name",
        "myproj",
    ];

    // CDX 1.6 — empty validator-error set (no reference baseline).
    let (cdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "cyclonedx-json",
        "out.cdx.json",
    );
    let cdx_errors: Vec<String> = common::cdx_schema::cdx_validator()
        .iter_errors(&cdx)
        .map(|e| format!("{}: {}", e.instance_path(), e))
        .collect();
    assert!(
        cdx_errors.is_empty(),
        "CDX 1.6 validation errors:\n{}",
        cdx_errors.join("\n")
    );

    // SPDX 2.3 — capture validator categories. Empty is best; if the
    // baseline reference example produces some, those are tolerated.
    let (spdx, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let spdx_errors: Vec<String> = spdx23_validator()
        .iter_errors(&spdx)
        .map(|e| format!("{}: {}", e.instance_path(), e))
        .collect();
    // The pre-080 spdx_schema_validation tests already gate that the
    // baseline isn't empty for SPDX 2.3; we're stricter here and
    // require zero errors on this fixture to detect any new milestone-
    // 080 introduction.
    assert!(
        spdx_errors.is_empty(),
        "SPDX 2.3 validation errors:\n{}",
        spdx_errors.join("\n")
    );

    // SPDX 3 — same standard.
    let (spdx3, _) = run_scan(
        fake_home.path(),
        &fixture_root(),
        extra,
        "spdx-3-json",
        "out.spdx3.json",
    );
    let spdx3_errors: Vec<String> = spdx3_validator()
        .iter_errors(&spdx3)
        .map(|e| format!("{}: {}", e.instance_path(), e))
        .collect();
    assert!(
        spdx3_errors.is_empty(),
        "SPDX 3 validation errors:\n{}",
        spdx3_errors.join("\n")
    );
}
