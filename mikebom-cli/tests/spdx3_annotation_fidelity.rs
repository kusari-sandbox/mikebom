//! Annotation-fidelity guard SPDX 2.3 ↔ SPDX 3 (milestone 011 T018).
//!
//! FR-018 / SC-005: every `mikebom:*` signal reachable in the
//! SPDX 2.3 output for a given fixture MUST be reachable (by
//! field name and value) in the SPDX 3 output for the same
//! fixture — whether via a native SPDX 3 field or an Annotation
//! element.
//!
//! Strategy: for each ecosystem, run one dual-format scan
//! (`--format spdx-2.3-json,spdx-3-json`) and build the set of
//! `(subject_kind, field, value_json)` tuples reachable from
//! each output. The envelope shape is byte-identical across the
//! two formats (`MikebomAnnotationCommentV1` — `{schema, field,
//! value}`) so decoding is a single `serde_json::from_str` call
//! per place the envelope lives.
//!
//! `subject_kind` distinguishes document-level from per-package
//! entries. For per-package entries the subject is keyed by the
//! component's PURL (via SPDX 2.3's `externalRefs[purl]` /
//! SPDX 3's `software_packageUrl`) so the two formats' subject
//! anchors align.
//!
//! One test per ecosystem so a failure names the offender.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;


mod common;
use common::{workspace_root, EcosystemCase, CASES};

struct Scan {
    spdx23: serde_json::Value,
    spdx3: serde_json::Value,
}

fn dual_scan(case: &EcosystemCase) -> Scan {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let spdx23_path = tmp.path().join("out.spdx.json");
    let spdx3_path = tmp.path().join("out.spdx3.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    cmd.env("HOME", fake_home.path())
        .env("M2_REPO", fake_home.path().join("no-m2-repo"))
        .env("MAVEN_HOME", fake_home.path().join("no-maven-home"))
        .env("GOPATH", fake_home.path().join("no-gopath"))
        .env("GOMODCACHE", fake_home.path().join("no-gomodcache"))
        .env("CARGO_HOME", fake_home.path().join("no-cargo-home"))
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fixture)
        .arg("--format")
        .arg("spdx-2.3-json,spdx-3-json")
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx23_path.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-3-json={}", spdx3_path.to_string_lossy()))
        .arg("--no-deep-hash");
    if let Some(code) = case.deb_codename {
        cmd.arg("--deb-codename").arg(code);
    }
    let out = cmd.output().expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed for {}: stderr={}",
        case.label,
        String::from_utf8_lossy(&out.stderr)
    );
    Scan {
        spdx23: serde_json::from_str(&std::fs::read_to_string(&spdx23_path).unwrap())
            .expect("SPDX 2.3 output is valid JSON"),
        spdx3: serde_json::from_str(&std::fs::read_to_string(&spdx3_path).unwrap())
            .expect("SPDX 3 output is valid JSON"),
    }
}

/// One mikebom envelope reachable in an SBOM document. `subject`
/// is the PURL of the owning Package, or the literal string
/// `"<document>"` for document-level annotations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct MikebomEntry {
    subject: String,
    field: String,
    value: String,
}

fn parse_envelope(s: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    let schema = v.get("schema").and_then(|x| x.as_str())?;
    if schema != "mikebom-annotation/v1" {
        return None;
    }
    let field = v.get("field").and_then(|x| x.as_str())?.to_string();
    let value = serde_json::to_string(v.get("value")?).ok()?;
    Some((field, value))
}

/// Collect every mikebom envelope from an SPDX 2.3 document.
/// Document-level entries: `annotations[].comment`.
/// Package-level entries: `packages[].annotations[].comment`
/// subject-keyed by the Package's PURL (via
/// `externalRefs[purl].referenceLocator`).
fn collect_spdx23(doc: &serde_json::Value) -> BTreeSet<MikebomEntry> {
    let mut out = BTreeSet::new();

    // Document-level.
    if let Some(arr) = doc.get("annotations").and_then(|v| v.as_array()) {
        for anno in arr {
            let Some(comment) = anno.get("comment").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some((field, value)) = parse_envelope(comment) {
                out.insert(MikebomEntry {
                    subject: "<document>".to_string(),
                    field,
                    value,
                });
            }
        }
    }

    // Package-level.
    if let Some(pkgs) = doc.get("packages").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            let purl = package_purl_spdx23(pkg).unwrap_or_else(|| {
                // Fallback: keyed by SPDXID when no PURL externalRef
                // is present. Should never happen on Section A-
                // compliant output, but be defensive.
                pkg.get("SPDXID")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>")
                    .to_string()
            });
            let Some(annos) = pkg.get("annotations").and_then(|v| v.as_array()) else {
                continue;
            };
            for anno in annos {
                let Some(comment) = anno.get("comment").and_then(|v| v.as_str()) else {
                    continue;
                };
                if let Some((field, value)) = parse_envelope(comment) {
                    out.insert(MikebomEntry {
                        subject: purl.clone(),
                        field,
                        value,
                    });
                }
            }
        }
    }

    out
}

fn package_purl_spdx23(pkg: &serde_json::Value) -> Option<String> {
    let refs = pkg.get("externalRefs")?.as_array()?;
    for r in refs {
        if r.get("referenceType").and_then(|v| v.as_str()) == Some("purl") {
            return r
                .get("referenceLocator")
                .and_then(|v| v.as_str())
                .map(String::from);
        }
    }
    None
}

/// Collect every mikebom envelope from an SPDX 3 document.
/// Subject is the Package's `software_packageUrl` for package-
/// level subjects, or the literal `"<document>"` when the subject
/// is the SpdxDocument element.
fn collect_spdx3(doc: &serde_json::Value) -> BTreeSet<MikebomEntry> {
    let mut out = BTreeSet::new();
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return out;
    };

    // Build spdxId → PURL map for Packages, plus the document's
    // own spdxId so we can map SpdxDocument subject → "<document>".
    let mut purl_by_iri: BTreeMap<String, String> = BTreeMap::new();
    let mut document_iri: Option<String> = None;
    for el in graph {
        match el.get("type").and_then(|v| v.as_str()) {
            Some("software_Package") => {
                if let (Some(id), Some(purl)) = (
                    el.get("spdxId").and_then(|v| v.as_str()),
                    el.get("software_packageUrl").and_then(|v| v.as_str()),
                ) {
                    purl_by_iri.insert(id.to_string(), purl.to_string());
                }
            }
            Some("SpdxDocument") => {
                if let Some(id) = el.get("spdxId").and_then(|v| v.as_str()) {
                    document_iri = Some(id.to_string());
                }
            }
            _ => {}
        }
    }

    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("Annotation") {
            continue;
        }
        let Some(subject_iri) = el.get("subject").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(statement) = el.get("statement").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((field, value)) = parse_envelope(statement) else {
            continue;
        };
        let subject = if Some(subject_iri) == document_iri.as_deref() {
            "<document>".to_string()
        } else if let Some(purl) = purl_by_iri.get(subject_iri) {
            purl.clone()
        } else {
            subject_iri.to_string()
        };
        out.insert(MikebomEntry {
            subject,
            field,
            value,
        });
    }

    out
}

fn assert_fidelity(case: &EcosystemCase) {
    let s = dual_scan(case);
    let spdx23 = collect_spdx23(&s.spdx23);
    let spdx3 = collect_spdx3(&s.spdx3);

    if spdx23 == spdx3 {
        return;
    }
    let only_in_23: Vec<&MikebomEntry> = spdx23.difference(&spdx3).collect();
    let only_in_3: Vec<&MikebomEntry> = spdx3.difference(&spdx23).collect();
    panic!(
        "{}: mikebom annotation fidelity drift between SPDX 2.3 and SPDX 3:\n\
         only in SPDX 2.3 ({} entries):\n{}\nonly in SPDX 3 ({} entries):\n{}",
        case.label,
        only_in_23.len(),
        only_in_23
            .iter()
            .map(|e| format!("  subject={} field={} value={}", e.subject, e.field, e.value))
            .collect::<Vec<_>>()
            .join("\n"),
        only_in_3.len(),
        only_in_3
            .iter()
            .map(|e| format!("  subject={} field={} value={}", e.subject, e.field, e.value))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test] fn fidelity_apk()    { assert_fidelity(&CASES[0]); }
#[test] fn fidelity_cargo()  { assert_fidelity(&CASES[1]); }
#[test] fn fidelity_deb()    { assert_fidelity(&CASES[2]); }
#[test] fn fidelity_gem()    { assert_fidelity(&CASES[3]); }
#[test] fn fidelity_golang() { assert_fidelity(&CASES[4]); }
#[test] fn fidelity_maven()  { assert_fidelity(&CASES[5]); }
#[test] fn fidelity_npm()    { assert_fidelity(&CASES[6]); }
#[test] fn fidelity_pip()    { assert_fidelity(&CASES[7]); }
#[test] fn fidelity_rpm()    { assert_fidelity(&CASES[8]); }
