# Research: SPDX Byte-Identity Goldens + Cross-Host Determinism Parity

**Phase 0 output for** `/specs/017-spdx-byte-identity-goldens/spec.md`

This document resolves the open technical questions from `plan.md`. Each section follows: **Decision** / **Rationale** / **Alternatives considered**.

---

## R1. Normalize on parsed `serde_json::Value` or on raw string?

**Context**: `cdx_regression.rs:143-183` operates on the raw scan output (`fn normalize(raw: &str) -> String`). It does workspace-path replacement on the string (line 152: `raw.replace(ws_str.as_str(), WORKSPACE_PLACEHOLDER)`), then re-parses the result for surgical UUID/timestamp/hash field edits, then serializes again. The string-replace step is critical because workspace paths can leak into many JSON locations (`comment` strings, `mikebom:source-files`, `evidence.occurrences[].location`, encoded annotation envelopes) that are tedious to enumerate field-by-field.

**Decision**: Same hybrid strategy for SPDX. Workspace-path replacement runs on the raw string (catches every leak vector); UUID/timestamp masking runs on the parsed JSON (surgical, format-aware). The new helper module exposes both phases so a future format that needs only one can compose them as needed.

**Rationale**:

- String-replace for workspace paths is the only way to catch all leak vectors without enumerating them. Future emitter additions (a new annotation field, a new comment vector) get coverage automatically.
- Parsed-JSON normalization for UUID/timestamp/hash fields gives precise control — the masker knows that SPDX 2.3's `creationInfo.created` is always a top-level field and SPDX 3's `CreationInfo.created` always lives in `@graph[]` elements.
- Hybrid is what the existing CDX code already does; the new helper formalizes the convention rather than inventing a different one.

**Alternatives considered**:

- **Pure string-replace** (regex over the raw output for every masked field). Rejected — UUID/timestamp regexes are fragile (false positives on similarly-shaped strings inside content-derived hashes); pretty-printed-vs-compact format differences would require multiple regexes; sorting-vs-unsorted-array shape differences are unrepresentable in a regex.
- **Pure JSON-walk** (parse the document, recursively walk every string value applying both substitutions). Rejected — workspace paths leak into JSON-encoded annotation envelopes which are themselves strings of JSON; recursive walking misses the inner content unless we double-decode at every step. The string-replace pass catches them automatically.

**Helper module shape** (per FR-006):

```rust
// tests/common/normalize.rs
pub fn normalize_cdx_for_golden(raw: &str, workspace: &Path) -> String { ... }
pub fn normalize_spdx23_for_golden(doc: serde_json::Value, workspace: &Path) -> serde_json::Value { ... }
pub fn normalize_spdx3_for_golden(doc: serde_json::Value, workspace: &Path) -> serde_json::Value { ... }
pub fn apply_fake_home_env(cmd: &mut std::process::Command, fake_home: &Path) { ... }
```

The CDX function returns `String` to match the existing `cdx_regression.rs` shape (its golden is a string compared byte-for-byte). The SPDX functions return `serde_json::Value` so tests can either compare structurally (`assert_eq!(a, b)` on `Value`) or stringify deterministically (`serde_json::to_string_pretty(&v).unwrap()`). The maintainer-facing convention is *stringified*-pretty for the on-disk golden so `git diff` is human-readable.

---

## R2. Format-scoped vs. test-scoped regen env var?

**Context**: `cdx_regression.rs:12` uses `MIKEBOM_UPDATE_CDX_GOLDENS=1` — one env var, format-scoped. A maintainer regenerates exactly the CDX goldens by setting it and running `cargo test -p mikebom --test cdx_regression`. Alternatives include a single shared `MIKEBOM_UPDATE_GOLDENS=cdx,spdx-2.3,spdx-3` (multi-value) or a more general `MIKEBOM_UPDATE_GOLDENS=1` (regen anything that has goldens).

**Decision**: Continue the format-scoped pattern: `MIKEBOM_UPDATE_SPDX_GOLDENS=1` for SPDX 2.3 + `MIKEBOM_UPDATE_SPDX3_GOLDENS=1` for SPDX 3. Three env vars total — one per current format.

**Rationale**:

- Matches the existing CDX pattern; minimum cognitive load for contributors who already know how `MIKEBOM_UPDATE_CDX_GOLDENS=1` works.
- Format-scoped reduces blast radius. A maintainer fixing an SPDX 3 emitter bug regenerates only SPDX 3 goldens; the CDX and SPDX 2.3 goldens stay pinned, so a sneaky behavior leak in CDX caused by the SPDX 3 fix gets caught.
- A shared `MIKEBOM_UPDATE_GOLDENS=1` is footgun-shaped — easy to invoke from a half-fixed branch and overwrite multiple formats' goldens accidentally.
- Adding a future format (CDX 1.7, SPDX 3.1) costs one new env var name; cheap.

**Alternatives considered**:

- **Multi-value `MIKEBOM_UPDATE_GOLDENS=cdx,spdx-2.3`**. Rejected — string parsing in test code, error-prone, no compile-time check that a typo in the value matches a format the test recognizes.
- **Single `MIKEBOM_UPDATE_GOLDENS=1` for all**. Rejected per blast-radius argument above.
- **Per-test-file env var (`MIKEBOM_UPDATE_GOLDENS_SPDX_REGRESSION=1`)**. Rejected — no benefit over format-scoping; ties the env-var name to a test-file path that could later be renamed.

---

## R3. Where does workspace path leak in SPDX 2.3 / SPDX 3 today?

**Context**: For CDX, the leak vectors documented in `cdx_regression.rs:30-35` are `mikebom:source-files`, `evidence.source_file_paths`, `evidence.occurrences[].location`. SPDX is shaped differently — it has no direct `evidence` field; equivalent metadata is encoded in `MikebomAnnotationCommentV1`-envelope annotations on Packages and at document level.

**Decision**: Do an empirical sweep before pinning the goldens. The implementation flow:

1. Run `cargo test -p mikebom --test spdx_regression` with `MIKEBOM_UPDATE_SPDX_GOLDENS=1` from the maintainer's macOS dev box. The just-written goldens contain whatever paths leaked.
2. Run `rg '/Users/[^"]*' mikebom-cli/tests/fixtures/golden/spdx-2.3/` to enumerate every leak vector in the freshly-written goldens.
3. Add each discovered path-substring pattern to the workspace-path-replacement step in `normalize_spdx23_for_golden` (string-replace on the raw output before parsing).
4. Re-run regen. Re-run rg. Repeat until the rg output is empty.
5. Repeat for SPDX 3 (`rg '/Users/[^"]*' mikebom-cli/tests/fixtures/golden/spdx-3/`).
6. Cross-host verify: a Linux CI run on the goldens MUST produce byte-identical output. If macOS-pinned goldens fail on Linux, an additional leak vector exists; iterate.

The empirical sweep is bounded by the leak surface area, which is small: SPDX writes are concentrated in `mikebom-cli/src/generate/spdx/` (2.3) and `mikebom-cli/src/generate/spdx_3/` (3). A reading of those modules' `write_*` and `*_to_*` functions enumerates the candidate fields ahead of time; the empirical step is the verification.

**Rationale**:

- Pre-enumerating fields by reading source code is brittle; relying on grep over the freshly-regenerated golden is exhaustive by construction.
- The CDX case settled into 3 fields after exactly this iteration; SPDX is unlikely to be much larger because the underlying scan-pipeline data is the same.
- A small fixture set (9 ecosystems × 2 formats = 18 goldens) makes the iteration cheap.

**Alternatives considered**:

- **Source-code enumeration only** (read `generate/spdx/**.rs`, list every field that could carry a path, mask each by name). Rejected — fragile against future emitter changes; misses JSON-encoded annotation payloads where the path is inside a string-of-JSON.
- **Whole-document path scrub by regex (`/Users/[^/]+/Projects/mikebom/`)**. Rejected — too narrow (CI emits `/home/runner/work/mikebom/mikebom/`); broadening to `/(?:Users|home)/[^/"]+/(?:Projects|work)/.../mikebom/.../` is still host-specific. The string-replace approach using the actual `workspace_root()` value is robust because it knows the exact prefix to strip.

---

## R4. Shared trait between cdx/spdx/spdx3 regression files vs. format-specific files?

**Context**: The three regression test files have substantially the same structure: iterate `common::CASES`, for each ecosystem run a scan, normalize, compare against golden (or write golden on regen). A trait `RegressionFormat` could capture the shape; each file would be ~10 lines parameterizing the trait.

**Decision**: Keep three format-specific test files. Share via the helper module (FR-006), not via a trait.

**Rationale**:

- Test failures are easier to read when each `#[test]` is named with the format (`apk_byte_identity` in `spdx_regression.rs` vs. `apk_byte_identity_spdx_2_3` if a single file generated all three formats).
- Format-specific files give one obvious place to add format-specific edge cases (a future `--deb-codename` requirement, a SPDX-3-only graph-node check) without contorting a generic trait.
- The 80% common code (test loop + golden read/write/diff machinery) goes into helper functions in `tests/common/normalize.rs`; the 20% format-specific (which command-line `--format` flag, which path under `golden/`) stays in the per-format file. Net duplication is small.

**Alternatives considered**:

- **Single `regression.rs` test file with parameterized formats**. Rejected — `cdx_regression.rs` is already milestone-010-pinned at its own path (`cdx_regression`, not `regression::cdx`); migrating would break the test-runner naming the maintainer is used to. Cost is also higher than the upside.
- **Shared `RegressionFormat` trait**. Rejected per the readability + format-specific-edge-case argument above.

---

## R5. Should `cdx_regression.rs` migrate to the helper in this PR or a follow-up?

**Context**: FR-007 mandates the migration in this PR with byte-identical CDX goldens. Splitting it to a follow-up has the appeal of smaller PR scope; bundling it has the appeal of forcing the helper to be CDX-compatible from day one.

**Decision**: Bundle the migration in this PR. Helper is built CDX-first, then SPDX 2.3 + SPDX 3 are added on top.

**Rationale**:

- Building the helper "CDX first, then SPDX" surfaces incompatibilities early. If the helper's `normalize_cdx_for_golden` produces a different golden than the inline `normalize()` does, that's signal — either the helper is wrong or the inline code had an undocumented quirk we should discover before pinning SPDX goldens that depend on the same helper machinery.
- Shipping the helper without proving it works for CDX leaves a half-finished piece of infrastructure: the next contributor pinning a new format's goldens has no precedent.
- The migration is mechanical (move ~40 lines from `cdx_regression.rs` to `tests/common/normalize.rs`, swap calls). PR-size concern is managed via commit chunking, not per-PR splitting.

**Alternatives considered**:

- **CDX migration in a follow-up PR**. Rejected — the helper would be SPDX-only initially; first contributor to extend CDX would have to design the helper's CDX face under pressure. Better to bake it in now.

---

## R6. Goldens for the `holistic_parity` synthetic-image fixture?

**Context**: `holistic_parity.rs` includes a 10th case beyond the 9 ecosystems — a synthetic container-image fixture built by `dual_format_perf::build_benchmark_fixture`. The fixture is built fresh per test run (the inner-layer tar's hash depends on the fixture-build-time deterministic ordering).

**Decision**: Excluded from goldens this milestone. (Per spec clarification.)

**Rationale**:

- Pinning a golden requires masking the synthetic-image SHA-256 (which feeds into the SBOM's `Package.checksums` and `Package.verifiedUsing`). That's solvable but adds complexity.
- The 9-ecosystem coverage already catches every cross-format / cross-host regression that matters. A synthetic-image golden adds redundancy, not new coverage.
- If a future milestone introduces a real container-image scenario worth pinning (e.g., a fixed `debian:12-slim.tar` checked in), goldens for that would be additive — same pattern, no schema change required.

**Alternatives considered**:

- **Pin a synthetic-image golden with an SHA-stripped normalizer**. Rejected per the redundancy argument; revisit if a future regression escapes the per-ecosystem goldens but would have been caught by the synthetic image.

---

## R7. Test-naming convention for the new files

**Context**: `cdx_regression.rs` names its tests `<ecosystem>_byte_identity` (per the file's existing pattern, verifiable by `grep '^fn ' mikebom-cli/tests/cdx_regression.rs`). New files should match.

**Decision**:

- `spdx_regression.rs`: 9 tests named `<ecosystem>_byte_identity` (e.g., `apk_byte_identity`, `cargo_byte_identity`, ..., `rpm_byte_identity`).
- `spdx3_regression.rs`: 9 tests named `<ecosystem>_byte_identity` — same names. Cargo runs them in different test binaries so the names collide harmlessly; the CI logs disambiguate via the test-target line ("Running tests/spdx_regression.rs" vs "Running tests/spdx3_regression.rs").

**Rationale**:

- Mirrors the existing CDX convention so a contributor's mental model stays consistent across all three files.
- Test-target distinction in cargo's output makes the format unambiguous in failure messages.

**Alternatives considered**:

- **Format-suffixed names** (`apk_byte_identity_spdx_2_3`). Rejected — verbose; adds zero information beyond the test target line; the name should describe *what's tested*, not *which file it's in*.
