# Contract: `MIKEBOM_UPDATE_*_GOLDENS=1` Regeneration

**Phase 1 contract for** `/specs/017-spdx-byte-identity-goldens/spec.md`

This document is the formal contract for the env-var-driven golden-regeneration mechanism. It applies to all three formats: CDX (existing, milestone 010), SPDX 2.3 (new, this milestone), SPDX 3 (new, this milestone).

## Naming

| Env var | Test target | Golden directory |
|---|---|---|
| `MIKEBOM_UPDATE_CDX_GOLDENS=1`  | `cargo test -p mikebom --test cdx_regression`  | `mikebom-cli/tests/fixtures/golden/cyclonedx/` |
| `MIKEBOM_UPDATE_SPDX_GOLDENS=1` | `cargo test -p mikebom --test spdx_regression` | `mikebom-cli/tests/fixtures/golden/spdx-2.3/`  |
| `MIKEBOM_UPDATE_SPDX3_GOLDENS=1` | `cargo test -p mikebom --test spdx3_regression` | `mikebom-cli/tests/fixtures/golden/spdx-3/`    |

Future formats (e.g., a hypothetical CDX 1.7 emitter) extend the pattern with one new env var per format.

## Behavior

When the env var is **unset** (the default, including all CI runs):

1. The test reads the committed golden file from disk.
2. The test runs the scan, normalizes the output, compares byte-for-byte against the golden.
3. Mismatch → test fails with a clear diff naming both files.

When the env var is set to `1`:

1. The test runs the scan, normalizes the output.
2. The normalized output is **written** to the golden file (creating the file if it doesn't exist; overwriting it if it does).
3. The test passes unconditionally for that ecosystem.

## Caller responsibilities

When a contributor invokes regen, they MUST:

1. Run with a clean working tree (no other unrelated edits in the goldens directory).
2. Run only the test target whose env var they set — do not regen multiple formats in a single command.
3. Inspect the resulting `git diff mikebom-cli/tests/fixtures/golden/<format>/`. The diff MUST be expected — every changed line should correspond to a deliberate emitter change in the same PR.
4. Add a "Goldens regenerated" section to the PR description (see `data-model.md` for the format) explaining *why* each ecosystem's golden changed.
5. Cross-host verify: regen on one OS (typically macOS dev), push, and observe both CI legs (Linux + macOS) pass. If the macOS-regenerated goldens fail on Linux, a leak vector was missed; iterate the workspace-path-replacement step.

## Non-goals

The regen mechanism is **not** a "make CI green" tool. Specifically:

- A maintainer MUST NOT regen goldens to "fix" a failing CI run unless they have first verified the underlying emitter change is correct.
- A maintainer MUST NOT regen goldens to suppress test flakiness — flakiness signals a real determinism bug.
- CI MUST NOT set the env var. There's no path in CI workflows to set it; this is enforced socially, not technically.

## Failure modes

| Symptom | Likely cause | Remedy |
|---|---|---|
| Regen produces a non-empty diff after the PR's emitter change is "complete" | The emitter has additional drift (e.g., a `HashMap` iteration order in the serializer). | Find and fix the non-determinism source in `mikebom-cli/src/generate/<format>/`; regen again; expect zero diff. |
| Regen on macOS produces goldens that fail on Linux CI | A workspace-path or host-specific value leaked through a vector the normalizer doesn't know about. | Check the CI log's failing-diff hunks for `/home/runner/...` strings; add the prefix to `normalize_<format>_for_golden`'s string-replace pass. |
| Goldens grow significantly in size between PRs | Either the fixture grew or a new field was added on every component. | Document the cause in the PR description; if it's intentional, ship; if not, investigate. |
| Regen passes locally but the resulting goldens fail when the PR's CI runs them | The maintainer regenerated with a stale binary (didn't rebuild after a code change). | Run `cargo build` first; regen again. |

## Constitution alignment

This contract supports Constitution Principle V (Specification Compliance): the goldens are the executable spec for emitter behavior. A regen that's not justified by an emitter change in the same PR is a contract violation that the review process MUST catch.

This contract supports Constitution Principle VII (Test Isolation): the goldens are normalized, host-portable, and produced under the fake-HOME isolation discipline. They cannot encode host-specific scanner behavior.
