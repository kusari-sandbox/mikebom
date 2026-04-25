# Quickstart: Holistic Cross-Format Output Parity (Milestone 013)

**Branch**: `013-format-parity-enforcement` | **Date**: 2026-04-25

## Run the new tests

```bash
# US1 — Holistic parity (10 per-ecosystem tests + 1 container-image test)
cargo +stable test -p mikebom --test holistic_parity

# US2 — Auto-discovery (emitter → catalog) + reverse check (catalog → emitter)
cargo +stable test -p mikebom --test mapping_doc_bidirectional

# US3 — CLI subcommand end-to-end test
cargo +stable test -p mikebom --test parity_cmd
```

All existing per-slice parity tests still run as part of `cargo test --workspace` and remain narrow regression guards.

## Try the new CLI subcommand (US3)

After building the release binary:

```bash
# Produce all three format outputs against a fixture
rm -rf /tmp/m13-home /tmp/m13-out && mkdir -p /tmp/m13-home /tmp/m13-out
HOME=/tmp/m13-home M2_REPO=/tmp/no MAVEN_HOME=/tmp/no \
  GOPATH=/tmp/no GOMODCACHE=/tmp/no CARGO_HOME=/tmp/no \
  ./target/release/mikebom --offline sbom scan \
    --path tests/fixtures/npm/node-modules-walk \
    --format cyclonedx-json,spdx-2.3-json,spdx-3-json \
    --output cyclonedx-json=/tmp/m13-out/mikebom.cdx.json \
    --output spdx-2.3-json=/tmp/m13-out/mikebom.spdx.json \
    --output spdx-3-json=/tmp/m13-out/mikebom.spdx3.json \
    --no-deep-hash

# Inspect per-datum × per-format coverage
./target/release/mikebom sbom parity-check --scan-dir /tmp/m13-out
```

Example output (shape — exact table will reflect the npm fixture's actual datums):

```
Cross-format coverage report for /tmp/m13-out

Section A — Core identity (universal parity)
  A1  PURL                                   [CDX ✓ (2)]  [SPDX 2.3 ✓ (2)]  [SPDX 3 ✓ (2)]
  A2  name                                   [CDX ✓ (2)]  [SPDX 2.3 ✓ (2)]  [SPDX 3 ✓ (2)]
  A3  version                                [CDX ✓ (2)]  [SPDX 2.3 ✓ (2)]  [SPDX 3 ✓ (2)]
  A6  hashes                                 [CDX · (0)]  [SPDX 2.3 · (0)]  [SPDX 3 · (0)]   (no-hashes fixture)
  A7  license — declared                     [CDX ✓ (2)]  [SPDX 2.3 ✓ (2)]  [SPDX 3 ✓ (2)]
  A9  external reference — homepage          [CDX ✓ (1)]  [SPDX 2.3 ✓ (1)]  [SPDX 3 ✓ (1)]
  A12 CPE                                    [CDX ✓ (2)]  [SPDX 2.3 ✓ (2)]  [SPDX 3 ✓ (3)]   (directional ⊆)

Section B — Graph structure
  B1  dependency edge (runtime)              [CDX ✓ (1)]  [SPDX 2.3 ✓ (1)]  [SPDX 3 ✓ (1)]
  …

Section C — mikebom-specific (via annotations)
  C1  mikebom:source-type                    [CDX ✓ (2)]  [SPDX 2.3 ✓ (2)]  [SPDX 3 ✓ (2)]
  …

Section F — VEX
  F1  vulnerabilities                        [CDX · (0)]  [SPDX 2.3 · (0)]  [SPDX 3 · (0)]   (no-advisory fixture)

Summary
  Universal-parity rows:  28 / 28  ✓
  Format-restricted rows:  3  (A4, A5 documented omissions)
  Parity gaps:             0
```

Exit codes: `0` = no gaps, `1` = at least one gap, `2` = input error.

## Add a new catalog row (dev-loop)

When adding a new signal to mikebom that should appear in all three formats:

1. **Add the emitter path(s)**: edit `src/generate/cyclonedx/`, `src/generate/spdx/packages.rs`, `src/generate/spdx/v3_packages.rs` (or whichever element the signal lives on).
2. **Add a row to `docs/reference/sbom-format-mapping.md`** in the appropriate section. Name the CycloneDX / SPDX 2.3 / SPDX 3 locations; use `omitted — <reason>` if a format doesn't carry the signal.
3. **Add a `ParityExtractor` entry** in `mikebom-cli/tests/common/parity_extractors.rs` — three closures, one per format, each returning a `BTreeSet<String>` of observable values.
4. Run `cargo +stable test -p mikebom --test holistic_parity --test mapping_doc_bidirectional` — both must pass before opening a PR.

If you skip step 2 or step 3, the parity tests fail loudly at the pre-PR gate with a clear message pointing at the missing entry.

## Pre-PR gate (MANDATORY)

Per constitution Development Workflow §Pre-PR Verification:

```bash
cargo +stable clippy --workspace --all-targets   # zero errors
cargo +stable test --workspace                    # every suite "ok. N passed; 0 failed"
```

Both must pass clean before opening a PR. Cite the per-suite pass counts in the PR description per `feedback_prepr_gate_full_output.md`.

## Where to look first

- **Catalog parser**: `mikebom-cli/src/parity/catalog.rs` — 3 regexes, 1 classifier, 1 parser function. Imported via `mikebom::parity::catalog::*`.
- **Extractor table**: `mikebom-cli/src/parity/extractors.rs` — one entry per catalog row; this is where "how to check this datum in each format" lives. Imported via `mikebom::parity::extractors::*`.
- **Library-crate root**: `mikebom-cli/src/lib.rs` — minimal `pub mod parity;` so both the binary AND integration tests can import the parser + extractor table.
- **Holistic parity test**: `mikebom-cli/tests/holistic_parity.rs` — one `#[test]` per ecosystem + 1 for the container-image fixture.
- **Auto-discovery + reverse check**: `mikebom-cli/tests/mapping_doc_bidirectional.rs` — forward (emitter → catalog) + reverse (catalog → emitter).
- **CLI subcommand**: `mikebom-cli/src/cli/parity_cmd.rs` — reads scan-dir, invokes extractors, renders table.
- **Canonical datum catalog**: `docs/reference/sbom-format-mapping.md` — this IS the spec of the mikebom emitter's data surface.
