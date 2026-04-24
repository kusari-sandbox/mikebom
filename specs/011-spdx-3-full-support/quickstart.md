# Quickstart: Full SPDX 3.x Output Support (Milestone 011)

**Branch**: `011-spdx-3-full-support` | **Date**: 2026-04-24

This is the dev-loop a contributor uses to add or change a SPDX 3 row, write a test, or verify the emitter against a fixture.

## Smoke-test the emitter against a fixture

Build a release binary and run it against any of the nine pinned ecosystem fixtures:

```bash
cargo build --release -p mikebom

./target/release/mikebom --offline sbom scan \
  --path mikebom-cli/tests/fixtures/npm/node-modules-walk \
  --format spdx-3-json \
  --output spdx-3-json=/tmp/out.spdx3.json

# Inspect:
jq '.["@graph"] | map(.type) | group_by(.) | map({type: .[0], count: length})' /tmp/out.spdx3.json
```

To see the dual-emit shape (CDX + SPDX 3 in one invocation, exercising the FR-004 single-pass guarantee + the SC-007 amortization):

```bash
./target/release/mikebom --offline sbom scan \
  --path mikebom-cli/tests/fixtures/npm/node-modules-walk \
  --format cyclonedx-json,spdx-2.3-json,spdx-3-json \
  --output cyclonedx-json=/tmp/out.cdx.json \
  --output spdx-2.3-json=/tmp/out.spdx.json \
  --output spdx-3-json=/tmp/out.spdx3.json
```

## Add or change an SPDX 3 row

1. **Decide native vs. Annotation** for the field per the strict-match rule (clarification Q2). When in doubt, Annotation wins — borderline rows are documented in `docs/reference/sbom-format-mapping.md` and `specs/011-spdx-3-full-support/research.md` §R5.
2. **Edit the relevant `v3_*.rs` file**: `v3_packages.rs` for Package-level properties, `v3_relationships.rs` for typed edges, `v3_licenses.rs` for license elements, `v3_agents.rs` for supplier/originator, `v3_external_ids.rs` for PURL/CPE entries, `v3_annotations.rs` for fallback Annotations.
3. **Update the row in `docs/reference/sbom-format-mapping.md`** — replace any `defer until SPDX 3 …` cell with the concrete native binding or the `Annotation <field>` notation.
4. **Run the schema-validation gate** to confirm the output still validates against the bundled SPDX 3.0.1 schema:
   ```bash
   cargo +stable test -p mikebom --test spdx3_schema_validation
   ```
5. **Run the parity gates**:
   ```bash
   cargo +stable test -p mikebom --test spdx3_cdx_parity
   cargo +stable test -p mikebom --test spdx3_annotation_fidelity
   cargo +stable test -p mikebom --test sbom_format_mapping_coverage
   ```
6. **Run the determinism gate** to confirm two runs produce byte-identical output after timestamp/IRI normalization:
   ```bash
   cargo +stable test -p mikebom --test spdx3_determinism
   ```

## Pre-PR verification (MANDATORY)

Same gate as every prior milestone (constitution Development Workflow §Pre-PR Verification):

```bash
cargo +stable clippy --workspace --all-targets
cargo +stable test --workspace
```

Both must pass clean before opening a PR. `cargo test -p mikebom` alone is **not sufficient** — it skips clippy and skips the cross-crate `--all-targets` enforcement of `clippy::unwrap_used`.

## CI-only gates that don't run by default locally

| Gate | When it runs | How to run locally |
|------|--------------|--------------------|
| sbomqs cross-format scoring (SC-001) | CI provisions sbomqs via `go install`; test exits cleanly skipped on local without it | `go install github.com/interlynk-io/sbomqs/v2@v2.0.6 && cargo +stable test -p mikebom --test sbomqs_parity` |
| Triple-format wall-clock perf (SC-007) | Always runs; built-in fixture inflated to ≥1s per scan | `cargo +stable test -p mikebom --test triple_format_perf -- --nocapture` |

## Schema bundle update procedure (if SPDX publishes a 3.0.x dot release)

1. Replace `mikebom-cli/tests/fixtures/spdx3-3.0.1.schema.json` with the new schema bytes. Keep the filename the same — bumping the file path means hunting down every test that references it.
2. Update the comment header at the top of the file to record the new source URL and revision.
3. Run `cargo +stable test -p mikebom --test spdx3_schema_validation` and fix any newly-flagged validation issues in the emitter.
4. If wire-incompatible (3.1+), open a follow-up milestone — milestone 011's spec scopes target version to "the highest published 3.x revision at implementation time," but a wire-incompatible bump is a separate planning conversation.

## Where to look first

- **Format dispatch**: `mikebom-cli/src/generate/mod.rs` — `SbomSerializer` trait + `SerializerRegistry::with_defaults()` registration of `Spdx3JsonSerializer`.
- **CLI surface**: `mikebom-cli/src/cli/scan_cmd.rs` — `--format` parsing, `--output <fmt>=<path>` overrides, deprecation-notice emission for the alias identifier.
- **Element synthesis**: `mikebom-cli/src/generate/spdx/v3_*.rs` — flat-sibling pattern, one file per element category.
- **Mapping doc**: `docs/reference/sbom-format-mapping.md` — the contract the emitter must honor row-by-row.
- **Tests**: `mikebom-cli/tests/spdx3_*.rs` — one file per guarantee category (schema, parity, determinism, annotation fidelity, CLI labeling, US3 acceptance).
