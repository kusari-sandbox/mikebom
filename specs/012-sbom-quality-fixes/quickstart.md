# Quickstart: Cross-format SBOM-Quality Fixes (Milestone 012)

**Branch**: `012-sbom-quality-fixes` | **Date**: 2026-04-25

## Smoke-test the three fixes against a fixture

Build a release binary and run it against the npm fixture (small, deterministic, exercises license + CPE in three formats simultaneously):

```bash
cargo build --release -p mikebom

mkdir -p /tmp/quickstart-home
HOME=/tmp/quickstart-home M2_REPO=/tmp/no MAVEN_HOME=/tmp/no \
  GOPATH=/tmp/no GOMODCACHE=/tmp/no CARGO_HOME=/tmp/no \
  ./target/release/mikebom --offline sbom scan \
    --path tests/fixtures/npm/node-modules-walk \
    --format cyclonedx-json,spdx-2.3-json,spdx-3-json \
    --output cyclonedx-json=/tmp/out.cdx.json \
    --output spdx-2.3-json=/tmp/out.spdx.json \
    --output spdx-3-json=/tmp/out.spdx3.json \
    --no-deep-hash
```

### Inspect each fix

**US1 — SPDX 3 CPE coverage**:

```bash
# Count CPE strings in CDX vs SPDX 3 (should agree ± 1 for synthetic root)
jq '[.components[].cpe // empty] | length' /tmp/out.cdx.json
jq '[."@graph"[] | select(.type == "software_Package")
     | (.externalIdentifier // [])[] | select(.externalIdentifierType == "cpe23")
     | .identifier] | length' /tmp/out.spdx3.json
```

**US2 — component-count parity**:

```bash
# CDX flattened (top-level + nested) vs SPDX 2.3 packages (minus synthetic root)
jq '[.. | objects | select(.type == "library") | .purl] | length' /tmp/out.cdx.json
jq '[.packages[] | select(.SPDXID | startswith("SPDXRef-DocumentRoot-") | not)
     | .name] | length' /tmp/out.spdx.json
```

The two numbers should agree.

**US3 — SPDX 2.3 LicenseRef preservation**:

```bash
# Count Packages with non-NOASSERTION licenseDeclared
jq '[.packages[] | select(.licenseDeclared != "NOASSERTION") | .licenseDeclared]
    | length' /tmp/out.spdx.json

# Inspect the document-level hasExtractedLicensingInfos array
jq '.hasExtractedLicensingInfos // []' /tmp/out.spdx.json

# Show one Package with a LicenseRef-* declaration (post-US3 only)
jq '.packages[] | select(.licenseDeclared | startswith("LicenseRef-"))
     | {name, licenseDeclared}' /tmp/out.spdx.json | head -20
```

## Per-story acceptance tests

Each user story has an independent acceptance-test file. Run any of them in isolation while developing:

```bash
# US1 — CPE coverage
cargo +stable test -p mikebom --test cpe_v3_acceptance

# US2 — component-count parity (bidirectional)
cargo +stable test -p mikebom --test component_count_parity

# US3 — LicenseRef + hasExtractedLicensingInfos
cargo +stable test -p mikebom --test spdx_license_ref_extracted
```

The existing milestone-010/011 parity tests gain assertions but no new tests; they're already wired in:

```bash
# Tightened bidirectional component-set parity (US2 modifications)
cargo +stable test -p mikebom --test spdx_cdx_parity
cargo +stable test -p mikebom --test spdx3_cdx_parity
```

## Pre-PR verification (MANDATORY)

Per constitution Development Workflow §Pre-PR Verification:

```bash
cargo +stable clippy --workspace --all-targets   # zero errors
cargo +stable test --workspace                    # every suite reports `ok. N passed; 0 failed`
```

Both must pass clean before opening a PR. Per `feedback_prepr_gate_full_output.md`, cite the per-suite `passed; 0 failed` lines in the PR description rather than a grep summary.

## Where to look first

- **CPE filter**: `mikebom-cli/src/generate/spdx/v3_external_ids.rs::is_fully_resolved_cpe23` — the one-line fix.
- **License-Ref derivation**: `mikebom-cli/src/generate/spdx/ids.rs::SpdxId::for_license_ref` (new constructor); `packages.rs::reduce_license_vec` (rewritten body).
- **`hasExtractedLicensingInfos[]` wiring**: `spdx/document.rs::SpdxDocument` (new field), `spdx/document.rs::build_document` (collect dedup'd entries from `build_packages`).
- **Component-count parity tests**: `mikebom-cli/tests/component_count_parity.rs` (new); modifications to `tests/spdx_cdx_parity.rs` add the SPDX→CDX reverse walk.
- **Format-mapping doc**: `docs/reference/sbom-format-mapping.md` Section A rows A7/A8 + a new structural-difference note.

## Updating the format-mapping doc

When implementing US3, update Section A row A7 (declared license) to mention the SPDX 2.3 LicenseRef path explicitly:

> | A7 | license — declared | … | `/packages/{i}/licenseDeclared` (canonical SPDX expression, `"LicenseRef-<hash>"` for non-canonicalizable expressions, `"NOASSERTION"`, or `"NONE"`); when `LicenseRef-<hash>` is used, a matching entry appears in document-level `hasExtractedLicensingInfos[]` (per SPDX 2.3 §10.1) carrying the raw expression as `extractedText` | … | … |

For US2's structural-difference note, add a new short Section H entry to the doc explaining the CDX-nesting vs. SPDX-flattening difference and pointing readers at the bidirectional parity test as the locked invariant.
