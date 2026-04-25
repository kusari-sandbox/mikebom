//! Bidirectional catalog ↔ emitter auto-discovery (milestone 013
//! T012, US2).
//!
//! Per spec clarification Q2: both directions are checked. The
//! catalog at `docs/reference/sbom-format-mapping.md` is the
//! source of truth; the CycloneDX emitter is its executable
//! interpretation. A regression in either direction MUST trip
//! the pre-PR gate.
//!
//! - **Forward** — every distinct CDX property/path emitted
//!   anywhere in the 9 ecosystem fixtures has a matching catalog
//!   row whose CDX-column extraction equals that name.
//! - **Reverse** — every universal-parity catalog row's CDX
//!   property name appears in at least one of the 9 cached CDX
//!   outputs (catches catalog rows that reference deleted /
//!   unimplemented emitter paths).
//!
//! Triple-format scans are cached across both tests via
//! `OnceLock` so each ecosystem fixture is scanned once per
//! test run, not 18 times.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use mikebom::parity::catalog::{
    extract_cdx_property_names_from_catalog_row, parse_mapping_doc, CatalogRow,
};


mod common;
use common::{EcosystemCase, CASES};
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn mapping_doc_path() -> PathBuf {
    workspace_root().join("docs/reference/sbom-format-mapping.md")
}fn scan_one_cdx(case: &EcosystemCase) -> serde_json::Value {
    let fixture = workspace_root()
        .join("tests/fixtures")
        .join(case.fixture_subpath);
    assert!(
        fixture.exists(),
        "fixture missing for {}: {}",
        case.label,
        fixture.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let cdx_path = tmp.path().join("out.cdx.json");
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
        .arg("cyclonedx-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx_path.to_string_lossy()))
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
    let s = std::fs::read_to_string(&cdx_path).expect("cdx output exists");
    serde_json::from_str(&s).expect("cdx output is valid JSON")
}

fn cached_cdx_scans() -> &'static Vec<(&'static str, serde_json::Value)> {
    static CACHE: OnceLock<Vec<(&'static str, serde_json::Value)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        CASES
            .iter()
            .map(|c| (c.label, scan_one_cdx(c)))
            .collect()
    })
}

/// Walk a CDX document to collect every emitted name that the
/// catalog might reference: top-level document keys, metadata-
/// level keys, every per-component field key (incl. nested), and
/// every property `name` (under metadata.properties[] +
/// components[].properties[]).
///
/// The universe is *deliberately broad*: it's the set of
/// identifier strings that `extract_cdx_property_name_from_catalog_row`
/// might return for any catalog row, so the bidirectional check
/// can compare apples to apples.
fn emitted_cdx_names(doc: &serde_json::Value) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();

    if let Some(obj) = doc.as_object() {
        for k in obj.keys() {
            names.insert(k.clone());
        }
    }
    if let Some(meta) = doc.get("metadata").and_then(|v| v.as_object()) {
        for k in meta.keys() {
            names.insert(k.clone());
        }
    }
    if let Some(meta_props) = doc
        .get("metadata")
        .and_then(|m| m.get("properties"))
        .and_then(|v| v.as_array())
    {
        for p in meta_props {
            if let Some(n) = p.get("name").and_then(|v| v.as_str()) {
                names.insert(n.to_string());
            }
        }
    }

    fn walk_components(node: &serde_json::Value, names: &mut BTreeSet<String>) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                if let Some(obj) = c.as_object() {
                    for k in obj.keys() {
                        names.insert(k.clone());
                    }
                }
                if let Some(props) = c.get("properties").and_then(|v| v.as_array()) {
                    for p in props {
                        if let Some(n) = p.get("name").and_then(|v| v.as_str()) {
                            names.insert(n.to_string());
                        }
                    }
                }
                walk_components(c, names);
            }
        }
    }
    walk_components(doc, &mut names);

    names
}

/// Names that appear as top-level CDX document / metadata keys
/// for envelope shaping (per G1–G4 catalog rows + format-spec
/// scaffolding) or are CycloneDX-internal mechanism keys
/// (`bom-ref` cross-references, `type` taxonomy enum, `lifecycles`
/// metadata). The forward check skips them — the test is about
/// catching *unexpected new mikebom emitter shapes*, not format-
/// spec scaffolding that's owned by the CycloneDX schema.
fn is_envelope_or_format_scaffolding(name: &str) -> bool {
    matches!(
        name,
        "bomFormat"
            | "specVersion"
            | "version"
            | "serialNumber"
            | "metadata"
            | "components"
            | "$schema"
            | "timestamp"
            | "tools"
            | "component"
            | "bom-ref"
            | "lifecycles"
            | "type"
            | "properties"
    )
}

fn collect_catalog_cdx_property_names(rows: &[CatalogRow]) -> BTreeSet<String> {
    rows.iter()
        .flat_map(extract_cdx_property_names_from_catalog_row)
        .collect()
}

#[test]
fn forward_every_emitted_property_has_a_catalog_row() {
    let rows = parse_mapping_doc(&mapping_doc_path());
    let catalog_names = collect_catalog_cdx_property_names(&rows);

    let scans = cached_cdx_scans();
    let mut missing: Vec<(String, String)> = Vec::new();
    for (label, doc) in scans {
        let names = emitted_cdx_names(doc);
        for name in names {
            if catalog_names.contains(&name) {
                continue;
            }
            // C23 is written as `mikebom:trace-integrity-*` in
            // the catalog (one row covers all four trace-integrity
            // sub-keys per the row's narrative); the helper
            // returns the prefix `mikebom:trace-integrity-`. The
            // emitted form is `mikebom:trace-integrity-events-
            // dropped`, etc. Honor the prefix expansion.
            let any_prefix_match = catalog_names
                .iter()
                .any(|cn| !cn.is_empty() && name.starts_with(cn) && name.len() > cn.len());
            if any_prefix_match {
                continue;
            }
            if is_envelope_or_format_scaffolding(&name) {
                continue;
            }
            missing.push(((*label).to_string(), name));
        }
    }
    if !missing.is_empty() {
        let mut report = String::from(
            "Found CDX-emitted names with no matching catalog row in `docs/reference/sbom-format-mapping.md`:\n",
        );
        for (label, name) in &missing {
            report.push_str(&format!("  - {label}: {name}\n"));
        }
        report.push_str(
            "\nFix: add a row to the mapping doc whose CycloneDX column references the name above.\n",
        );
        panic!("{report}");
    }
}

#[test]
fn reverse_every_universal_parity_row_has_at_least_one_emitted_value() {
    let rows = parse_mapping_doc(&mapping_doc_path());
    let scans = cached_cdx_scans();

    let mut all_emitted: BTreeSet<String> = BTreeSet::new();
    for (_label, doc) in scans {
        all_emitted.extend(emitted_cdx_names(doc));
    }

    let mut orphans: Vec<(String, String, Vec<String>)> = Vec::new();
    for row in &rows {
        if !row.classification().is_universal_parity() {
            continue;
        }
        // Section H is documentation-only (structural/meta); H1
        // describes nested-vs-flat representation strategy, not a
        // datum. Skip per the milestone-013 task spec ("H1 ...
        // skipped by the parity test ... since it's
        // documentation-only").
        if row.section == 'H' {
            continue;
        }
        // `mikebom:*` annotation rows are conditionally emitted
        // (only when the underlying signal is present — e.g.,
        // dev-dependency requires a dev edge in the manifest;
        // shade-relocation requires a shaded JAR). The fixed
        // 9-ecosystem fixture set deliberately doesn't exercise
        // every conditional path. Skip mikebom:*-rows for the
        // reverse check; the holistic_parity test (US1) already
        // enforces cross-format consistency for these rows when
        // they ARE emitted, and the forward check (test (a) above)
        // catches new annotations added without a catalog row.
        if row.label.contains("mikebom:") {
            continue;
        }
        let candidates = extract_cdx_property_names_from_catalog_row(row);
        if candidates.is_empty() {
            continue;
        }
        // Reverse passes if ANY candidate name appears in some
        // fixture's emitted set, OR if any catalog candidate is
        // a prefix of an emitted name (handles C23's `mikebom:
        // trace-integrity-` → `mikebom:trace-integrity-events-
        // dropped`).
        let any_match = candidates.iter().any(|c| {
            all_emitted.contains(c)
                || all_emitted
                    .iter()
                    .any(|e| !c.is_empty() && e.starts_with(c) && e.len() > c.len())
        });
        if any_match {
            continue;
        }
        orphans.push((row.id.clone(), row.label.clone(), candidates));
    }

    if !orphans.is_empty() {
        let mut report = String::from(
            "Found universal-parity catalog rows whose CDX property name was not emitted by any of the 9 ecosystem fixtures:\n",
        );
        for (id, label, names) in &orphans {
            report.push_str(&format!("  - {id} {label}: candidates={names:?}\n"));
        }
        report.push_str(
            "\nFix: either remove the orphan row from the mapping doc, fix the emitter to emit it, or add a fixture that exercises the path.\n",
        );
        panic!("{report}");
    }
}
