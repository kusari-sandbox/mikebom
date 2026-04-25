# Data Model: Address the 192 Deferred Clippy Warnings

**Phase 1 output for** `/specs/016-remaining-clippy-cleanup/spec.md`

## Scope

This feature has minimal "data" — it's a cleanup pass with one human-facing artifact (the per-item triage decision log) and one machine-facing artifact (the CI workflow file). Both are described here for completeness; the CI workflow is also captured as the formal contract in `contracts/ci-clippy-gate.md`.

---

## TriageDecision (in-PR record, no runtime persistence)

A single record describing how one clippy warning was resolved. Lives only in the PR description (rendered as a markdown summary table) — there is no on-disk schema.

### Fields

| Field            | Type                                              | Notes                                                                                                                                |
|------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `file`           | string (relative path from repo root)             | e.g., `mikebom-cli/src/trace/aggregator.rs`                                                                                          |
| `line`           | u32                                               | Source line of the flagged item                                                                                                     |
| `kind`           | enum { `function`, `struct`, `field`, `variant`, `assoc_item`, `doc_list_block` } | Maps to clippy's warning vocabulary                                                                                                 |
| `name`           | string                                            | Item identifier (e.g., `EventAggregator::finalize`, `OidcProvider::Keyless`); for `doc_list_block` the comment range (`L156-L165`)   |
| `lint`           | enum { `dead_code`, `doc_lazy_continuation`, `field_reassign_with_default`, `…` } | Clippy lint name                                                                                                                    |
| `resolution`     | enum { `removed`, `gated`, `annotated`, `restructured` } | `removed` and `gated`/`annotated` apply to dead-code items; `restructured` applies to doc-list blocks (blank-line break or sub-bullet reformat). |
| `rationale`      | string (1 sentence)                               | Required for `annotated`/`restructured`; optional for `removed`/`gated`. Captures the planned-consumer reason for `annotated`.       |

### Aggregation in PR description

The PR description MUST include a per-category summary suitable for a 15-minute review (per SC-005):

```markdown
## Triage summary

| Resolution     | Count | Notes                                                                                              |
|----------------|------:|----------------------------------------------------------------------------------------------------|
| Removed        | XX    | Genuinely orphaned (e.g., `enrich/license_resolver::resolve_licenses` — no caller after #17 refactor) |
| Gated (Tier A) | XX    | `#[cfg(target_os = "linux")]` — items only used in Linux call paths                                  |
| Gated (Tier B) | XX    | `#[cfg_attr(not(target_os = "linux"), allow(dead_code))]` — items used cross-platform                |
| Annotated      | XX    | `#[allow(dead_code)]` + planned-consumer comment (future-feature scaffolding)                       |
| Restructured   | XX    | Doc comments rewritten to fix `doc_lazy_continuation`                                                |
| **Total**      | **192** | Down to 0 warnings on macOS + Linux                                                                  |
```

Plus a list of any 5+ item clusters worth calling out by name (e.g., "All 13 `attestation/witness_builder.rs` items annotated with `#[allow(dead_code)]` — planned consumer is the upcoming witness-collection emit path under `cli/scan.rs::execute_scan` Linux block").

### Validation rules

- Every flagged warning in the baseline (`/tmp/clippy-before.txt` from the implementation snapshot) MUST have exactly one `TriageDecision`.
- `restructured` is mutually exclusive with the dead-code resolutions; doc-list and dead-code categories never overlap.
- `removed` items MUST NOT have any `grep -rn "<name>"` callers in the post-cleanup tree.

### Lifecycle

- Created during implementation as the human implements the per-item triage.
- Aggregated into the PR description on PR-open.
- Discarded after merge — the git history (per-commit messages or the merge commit) carries enough trace.
- No persistence beyond the PR.

---

## ClippyGateConfig (CI workflow, single source of truth)

The minimum-spec configuration of the new CI gate. Authoritative copy lives in `.github/workflows/ci.yml`; the contract in `contracts/ci-clippy-gate.md` is the human-readable specification.

### Fields

| Field                | Type / value                                                     | Notes                                                                                                                |
|----------------------|------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `runs-on`            | string                                                           | One of `ubuntu-latest`, `macos-latest`. Two job instances total.                                                     |
| `clippy-cmd`         | `cargo +stable clippy --workspace --all-targets -- -D warnings`  | Identical on both jobs.                                                                                              |
| `test-cmd`           | `cargo +stable test --workspace`                                 | Identical on both jobs.                                                                                              |
| `pre-clippy-steps`   | list of GH-Actions steps                                         | macOS skips: eBPF build, bpf-linker install, sbomqs install, nightly toolchain. Linux keeps all today.               |
| `passing condition`  | clippy exit 0 AND test report `0 failed`                         | Either failure fails CI for that OS.                                                                                 |

### Validation rules

- Both jobs MUST run on every `pull_request` and on push-to-`main`.
- Neither job is allowed to be marked `continue-on-error: true` — both must hard-fail CI.
- The `clippy-cmd` MUST be byte-identical between the two jobs (no per-OS lint exemptions).

### Lifecycle

- Created in this feature.
- Modified going forward only when (a) toolchain bumps require new clippy lint exclusions, OR (b) GitHub Actions runner names change.
- Constitution-anchored: the pre-PR table at `.specify/memory/constitution.md:357-360` is the canonical reference for the *intent*; this YAML is the *implementation*.

---

## Out of scope (not modeled)

- Historical context for each removed item ("why was this written?"). The triage is forward-looking.
- A persistent baseline-warning-count file. Per R1, the `-D warnings` flag obviates this.
- Per-warning-category telemetry beyond the PR-description summary table.
