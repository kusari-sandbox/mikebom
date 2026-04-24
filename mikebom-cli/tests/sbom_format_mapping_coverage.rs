//! Data-placement-map coverage check (milestone 010 T032).
//!
//! SC-004: the committed CDX↔SPDX map at
//! `specs/010-spdx-output-support/contracts/sbom-format-mapping.md`
//! (canonical home `docs/reference/sbom-format-mapping.md` after
//! Phase 4 T039 moves it) covers 100 % of the data elements mikebom
//! emits in CycloneDX today — with a non-empty entry in each of the
//! three format columns (CycloneDX, SPDX 2.3, SPDX 3.0.1).
//!
//! Implementation:
//!   (1) Walk the 9 pinned CDX goldens under
//!       `mikebom-cli/tests/fixtures/golden/cyclonedx/`, collecting
//!       every `mikebom:*` property name (components and metadata),
//!       every mikebom-significant top-level doc key, and every
//!       mikebom-significant per-component key.
//!   (2) Parse the markdown map into a list of `(cdx_column,
//!       spdx23_column, spdx3_column)` triples.
//!   (3) For each collected item, assert at least one triple's
//!       `cdx_column` names it.
//!   (4) For each triple, assert the SPDX 2.3 and SPDX 3.0.1 columns
//!       are non-empty and don't carry a TODO/TBD/`?` sentinel.
//!
//! A failure here means either a new `mikebom:*` property was added
//! without a map row (add the row) OR the map file is malformed
//! (fix the table). Neither case requires touching this test.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/cyclonedx")
}

fn map_path() -> PathBuf {
    // Phase-4 T039 will move this to docs/reference/sbom-format-mapping.md;
    // this test's path then updates in lockstep with T039.
    workspace_root().join("specs/010-spdx-output-support/contracts/sbom-format-mapping.md")
}

/// Every item we expect to find named in the map's CDX column.
///
/// Two flavors:
///   - `Property(name)` — a `mikebom:*` property name, expected to
///     appear as `name="<property>"` somewhere in a map row's CDX
///     column.
///   - `Path(path)` — a structural CDX path fragment, expected to
///     appear verbatim as a substring in a map row's CDX column.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Expected {
    Property(String),
    Path(String),
}

/// Walk every pinned CDX golden and collect the `Expected` items
/// mikebom actually emits today. This is the ground truth the map
/// has to cover.
fn collect_expected() -> BTreeSet<Expected> {
    let mut out: BTreeSet<Expected> = BTreeSet::new();

    // Structural paths the scanner emits unconditionally. These are
    // the "mikebom-significant" envelope + component keys enumerated
    // in the spec's map Sections A + B + E; they must have rows.
    for p in [
        "/components/{i}/purl",
        "/components/{i}/name",
        "/components/{i}/version",
        "/components/{i}/supplier",
        "/components/{i}/hashes",
        "/components/{i}/licenses",
        "/components/{i}/externalReferences",
        "/components/{i}/evidence",
        "/components/{i}/components",
        "/compositions",
        "/dependencies",
        "/metadata/component",
    ] {
        out.insert(Expected::Path(p.to_string()));
    }

    // Dynamic paths observed in the goldens. Specifically every
    // `mikebom:*` property that actually gets emitted somewhere —
    // this is what catches "new property added without a map row."
    let entries = std::fs::read_dir(goldens_dir()).expect("read goldens dir");
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("read golden");
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("golden is valid JSON");

        collect_component_properties(&doc, &mut out);
        collect_metadata_properties(&doc, &mut out);
        // If a future fixture ever has a non-empty vulnerabilities
        // array, record the presence so the map gets reminded to
        // keep the VEX row (which points at the OpenVEX sidecar).
        if doc
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty())
        {
            out.insert(Expected::Path("/vulnerabilities".to_string()));
        }
    }

    out
}

fn collect_component_properties(
    doc: &serde_json::Value,
    out: &mut BTreeSet<Expected>,
) {
    fn walk(node: &serde_json::Value, out: &mut BTreeSet<Expected>) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                if let Some(props) =
                    c.get("properties").and_then(|v| v.as_array())
                {
                    for p in props {
                        if let Some(name) =
                            p.get("name").and_then(|v| v.as_str())
                        {
                            if name.starts_with("mikebom:") {
                                out.insert(Expected::Property(name.to_string()));
                            }
                        }
                    }
                }
                // Also the `cpe` native field is itself
                // map-worthy — it gets a SECURITY/cpe23Type
                // externalRef in SPDX, not an annotation. Record
                // its presence so the map stays honest.
                if c.get("cpe").is_some() {
                    out.insert(Expected::Path(
                        "/components/{i}/cpe".to_string(),
                    ));
                }
                walk(c, out);
            }
        }
    }
    walk(doc, out);
}

fn collect_metadata_properties(
    doc: &serde_json::Value,
    out: &mut BTreeSet<Expected>,
) {
    let Some(props) = doc
        .get("metadata")
        .and_then(|m| m.get("properties"))
        .and_then(|v| v.as_array())
    else {
        return;
    };
    for p in props {
        if let Some(name) = p.get("name").and_then(|v| v.as_str()) {
            if name.starts_with("mikebom:") {
                out.insert(Expected::Property(name.to_string()));
            }
        }
    }
}

/// One parsed row from the markdown map. The "description" column is
/// kept alongside the three format columns because rows C5–C22 use a
/// compressed form where `cdx_column` is just the literal `"property"`
/// and the real property name lives in `description` — the matcher
/// has to search both.
#[derive(Debug)]
struct MapRow {
    row_id: String,
    description: String,
    cdx_column: String,
    spdx23_column: String,
    spdx3_column: String,
}

/// Sentinel tokens that mean "this cell has not been decided yet" —
/// anything else (including `omitted — <reason>` and
/// `defer — <reason>`) counts as a deliberate decision.
const INCOMPLETE_TOKENS: &[&str] = &["?", "TODO", "TBD", "N/A", "n/a"];

fn is_incomplete(cell: &str) -> bool {
    let t = cell.trim().trim_matches('`');
    if t.is_empty() {
        return true;
    }
    INCOMPLETE_TOKENS.iter().any(|tok| t.eq_ignore_ascii_case(tok))
}

/// Parse the map file into a Vec of data rows. Rules:
///   - Only lines starting with `| ` and containing `|` at least 6
///     times are considered candidate rows.
///   - The header row (`# | mikebom data | CycloneDX 1.6 location | …`)
///     is skipped.
///   - Separator rows (`|---|---|…`) are skipped.
///   - Rows whose first cell is not a recognizable row-id (letter +
///     digits, e.g. `A1`, `C23`, `E1`) are skipped so prose tables in
///     the same file do not confuse the parser.
fn parse_map() -> Vec<MapRow> {
    let raw = std::fs::read_to_string(map_path())
        .unwrap_or_else(|e| panic!("read map at {}: {e}", map_path().display()));
    let mut rows = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end();
        if !line.starts_with('|') {
            continue;
        }
        // A data row has at least 6 pipes (7 cells: leading empty,
        // row-id, description, cdx, spdx23, spdx3, justification).
        let cells: Vec<&str> = line.split('|').collect();
        if cells.len() < 7 {
            continue;
        }
        // Skip separator rows (all cells are dashes).
        if cells.iter().all(|c| {
            let t = c.trim();
            t.is_empty() || t.chars().all(|c| c == '-' || c == ':')
        }) {
            continue;
        }
        // The first cell is an artifact of leading `|`; real data
        // starts at index 1.
        let row_id = cells.get(1).map(|s| s.trim()).unwrap_or("");
        if !is_row_id(row_id) {
            continue;
        }
        let description =
            cells.get(2).map(|s| s.trim().to_string()).unwrap_or_default();
        let cdx = cells.get(3).map(|s| s.trim().to_string()).unwrap_or_default();
        let spdx23 = cells.get(4).map(|s| s.trim().to_string()).unwrap_or_default();
        let spdx3 = cells.get(5).map(|s| s.trim().to_string()).unwrap_or_default();
        rows.push(MapRow {
            row_id: row_id.to_string(),
            description,
            cdx_column: cdx,
            spdx23_column: spdx23,
            spdx3_column: spdx3,
        });
    }
    rows
}

/// Row ids in the map follow `[A-EG][0-9]+` — `A1`..`A11`, `B1`..`B4`,
/// `C1`..`C23`, `D1`..`D2`, `E1`. Keep the predicate lenient so future
/// sections (F, G, …) flow through without a code change.
fn is_row_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    let rest = &s[1..];
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

/// Does a map row "name" this expected item?
///
/// For `Property(name)`, we accept a match in either the description
/// column or the CDX-location column — rows C5–C22 compress the CDX
/// column to just `property` and the name itself lives in
/// description, so a strict "CDX column only" match would false-fail.
/// Row C23 uses a wildcard form (`mikebom:trace-integrity-*`) to
/// cover a family of subkeys — we treat a trailing `*` as a glob
/// that matches any suffix.
/// For `Path(path)`, we search only the CDX column; description is
/// prose, which would match too eagerly (e.g. "PURL" in prose vs.
/// `/components/{i}/purl` in the path column).
fn row_names(row: &MapRow, exp: &Expected) -> bool {
    match exp {
        Expected::Property(name) => {
            cell_names_property(&row.description, name)
                || cell_names_property(&row.cdx_column, name)
        }
        Expected::Path(path) => row.cdx_column.contains(path.as_str()),
    }
}

/// Does `cell` contain a token that names `name`, either literally or
/// as a `<prefix>-*` / `<prefix>*` wildcard?
fn cell_names_property(cell: &str, name: &str) -> bool {
    if cell.contains(name) {
        return true;
    }
    // Wildcard form: a token like `mikebom:trace-integrity-*` matches
    // every `mikebom:trace-integrity-<suffix>`. Scan the cell for
    // `<prefix>*` tokens and test prefix-match. A token can be
    // backticked so strip backticks too.
    for tok in cell.split([' ', ',', '`', '(', ')']) {
        let tok = tok.trim_matches(|c: char| c == '`' || c.is_ascii_punctuation() && c != '-' && c != '_' && c != ':' && c != '*');
        if let Some(prefix) = tok.strip_suffix('*') {
            let prefix = prefix.trim_end_matches('-');
            if !prefix.is_empty() && name.starts_with(prefix) && name.len() > prefix.len() {
                return true;
            }
        }
    }
    false
}

#[test]
fn every_mikebom_emitted_field_has_a_map_row() {
    let expected = collect_expected();
    let rows = parse_map();
    assert!(
        rows.len() >= 20,
        "suspiciously few map rows parsed ({}); check parse_map logic",
        rows.len()
    );

    let mut missing: Vec<Expected> = Vec::new();
    for exp in &expected {
        if !rows.iter().any(|r| row_names(r, exp)) {
            missing.push(exp.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "mikebom emits the following CDX data with NO row in \
         `contracts/sbom-format-mapping.md`:\n  {}\n\nEither add rows \
         to the map or remove the emission. The map is the source of \
         truth for cross-format data placement.",
        missing
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn every_map_row_has_non_empty_spdx_23_and_spdx_3_columns() {
    let rows = parse_map();
    let mut incomplete: Vec<String> = Vec::new();
    for r in &rows {
        if is_incomplete(&r.spdx23_column) {
            incomplete.push(format!(
                "row {}: SPDX 2.3 column is incomplete ({:?})",
                r.row_id, r.spdx23_column
            ));
        }
        if is_incomplete(&r.spdx3_column) {
            incomplete.push(format!(
                "row {}: SPDX 3.0.1 column is incomplete ({:?})",
                r.row_id, r.spdx3_column
            ));
        }
    }
    assert!(
        incomplete.is_empty(),
        "map rows with TODO/TBD/?/empty cells — these are drift \
         markers and block merges:\n  {}",
        incomplete.join("\n  ")
    );
}

#[test]
fn parse_map_finds_every_known_row_id() {
    // Spot-check the parser picks up rows from each section the
    // spec declares. If any named-and-expected row is missing, the
    // parser is broken — every test above silently under-checks.
    let rows = parse_map();
    let ids: std::collections::HashSet<&str> =
        rows.iter().map(|r| r.row_id.as_str()).collect();
    for expected_id in ["A1", "A7", "B1", "B4", "C1", "C21", "D1", "E1"] {
        assert!(
            ids.contains(expected_id),
            "map-parser did not find row {expected_id} — every coverage \
             assertion above silently under-checks. Rows found: {ids:?}"
        );
    }
}
