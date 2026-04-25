# Research: Address the 192 Deferred Clippy Warnings

**Phase 0 output for** `/specs/016-remaining-clippy-cleanup/spec.md`

This document resolves the open technical questions from `plan.md`. Each section follows: **Decision** / **Rationale** / **Alternatives considered**.

---

## R1. How to deny warnings without contradicting the existing CI rationale?

**Context**: The current CI workflow at `.github/workflows/ci.yml` has an explicit comment justifying *not* using `-D warnings`:

> No `-D warnings`: the repo's load-bearing lint is `#![deny(clippy::unwrap_used)]` at the mikebom-cli crate root (Constitution Principle IV). That still errors through clippy regardless of -D warnings. Other clippy categories remain warnings — visible in the log, not blocking — so CI doesn't become a constant stream of cosmetic-lint bikeshedding.

That comment captures a real concern: a careless `-D warnings` flip will trip on every cosmetic clippy lint introduced by future toolchain bumps, causing PR-level friction unrelated to actual code quality.

**Decision**: Use `cargo +stable clippy --workspace --all-targets -- -D warnings` AFTER the cleanup, on both Linux and macOS jobs. Update the existing CI comment to reflect the new policy and its load-bearing rationale (FR-006 + the post-016 zero-baseline).

**Rationale**:

- The original concern was about the cost of cleaning a *steady stream* of cosmetic lints. After this feature ships, the legacy backlog is cleared (zero warnings baseline). Future toolchain bumps that introduce new lint categories will fail CI loudly — the contributor either fixes the new category in the same PR (small per-PR cost) or adds a per-occurrence `#[allow(...)]` with justification. Either is cheaper than the audit value of guaranteed-clean clippy.
- Spec FR-006 explicitly says "any new clippy warning (any class)" — a category-specific deny list (e.g., `-D dead_code -D clippy::doc_lazy_continuation`) would technically violate it.
- The maintainer chose option A in the clarification (full CI gate on both OSes), implicitly accepting the toolchain-bump cost.

**Alternatives considered**:

- **Category-specific deny list** (`-D dead_code -D clippy::doc_lazy_continuation`). Rejected — narrower than FR-006 requires; misses regressions in other categories like `unused_imports` that future PRs could introduce.
- **Baseline-diff tool** (e.g., a script that diffs current warning count against a stored baseline file in the repo). Rejected — adds infrastructure complexity (a baseline-update workflow, a diffing script) for a problem that `-D warnings` solves directly. Also creates a worse failure mode: a contributor could "fix" a CI failure by updating the baseline file, defeating the gate.
- **Crate-root `#![deny(warnings)]`** instead of CI flag. Rejected — affects local `cargo build` (not just `clippy`), making local development noisy when warnings appear during refactor mid-work. The CI flag scopes the deny to the verification step.

---

## R2. How to cfg-gate platform-conditional dead code without cascade?

**Context**: ~80% of the dead-code warnings are on items that exist unconditionally in source but are only ever *called* from inside `#[cfg(target_os = "linux")]` blocks. On macOS the call graph is empty, so the compiler reports the items as dead. Naively adding `#[cfg(target_os = "linux")]` to one item often breaks the cross-platform compilation if any non-gated code touches it.

**Decision**: Three-tier strategy applied per item.

| Tier | When                                                                                       | Treatment                                                                                                        |
|------|--------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| A    | Item is referenced *only* from `#[cfg(target_os = "linux")]` scopes (compile-verifies on macOS after gating). | Add `#[cfg(target_os = "linux")]` to the item definition itself. Compiler enforces "only used on Linux."         |
| B    | Item is referenced from both gated and ungated code, or removing it breaks ungated compilation. | Add `#[cfg_attr(not(target_os = "linux"), allow(dead_code))]` to silence the macOS warning while preserving cross-platform availability. |
| C    | Item has zero callers anywhere (genuinely orphaned scaffolding from a removed milestone). | Delete the item.                                                                                                 |

**Triage rule**: Prefer Tier A when feasible (compiler-enforced semantics > attribute-suppression). Fall back to Tier B only when the call graph crosses platform boundaries. Use Tier C only after `grep -rn "<item_name>" mikebom-cli/ mikebom-common/ mikebom-ebpf/` confirms zero callers across all crates.

**Tier B subtype — non-platform `#[allow(dead_code)]` for future-feature scaffolding**: Some items are not platform-conditional but exist as deliberate prep for a planned future milestone. These get plain `#[allow(dead_code)]` (without the `cfg_attr`). Per spec FR-003, this is only acceptable when the annotation comment cites a *concrete* planned consumer — a milestone identifier (`milestone-018`), spec ID (`specs/017-...`), issue/PR reference, or named-future-function whose addition is committed to the roadmap. **Bare `#[allow(dead_code)]` without a concrete consumer reference is NOT acceptable; default to Tier C delete.** Vague rationale ("future use", "may need this later") does not qualify — it's drift waiting to happen, and the next milestone-016-equivalent cleanup will just delete it anyway.

**Rationale**:

- Tier A makes the platform-conditional intent visible in source: future readers can't accidentally call a Linux-only helper from macOS code without a compile error.
- Tier B's `cfg_attr` is the minimum-impact escape hatch — no source-level platform branching, just a one-line attribute.
- Tier C fixes drift: zero-caller items are signals that a previous milestone removed the consumer but left the producer behind.

**Alternatives considered**:

- **Always Tier A** (push every dead item behind `#[cfg(target_os = "linux")]`). Rejected — cascades when an item is reachable from both platforms via a generic helper. Forces synthetic platform branches in callers that didn't need them.
- **Always Tier B** (`#[allow(dead_code)]` everywhere). Rejected — silences the lint without expressing platform intent; future readers can't tell which items are platform-conditional vs. genuinely-future-feature scaffolding.
- **Move Linux-only items to a `mod linux_only;` submodule gated as a whole**. Rejected as a blanket strategy — invasive refactor across `attestation/`, `trace/`, `cli/` that adds churn beyond the cleanup scope. May be appropriate as a follow-up for the largest cluster (`trace/*`), but not part of this feature.

---

## R3. macOS GitHub Actions runner — minimal setup

**Decision**: Add a second job `lint-and-test-macos` to `.github/workflows/ci.yml`, using `runs-on: macos-latest` (Apple Silicon by default in 2026). Steps:

1. Checkout (`actions/checkout@v6`).
2. Install stable Rust + clippy (`dtolnay/rust-toolchain@stable` with `components: clippy`).
3. Cache cargo + build artifacts (`Swatinem/rust-cache@v2`).
4. Run `cargo +stable clippy --workspace --all-targets -- -D warnings`.
5. Run `cargo +stable test --workspace`.

Skip:

- eBPF build step (`cargo run --package xtask -- ebpf`) — requires nightly + `bpf-linker` + `clang` + Linux kernel headers; `mikebom-ebpf` is `no_std` Linux-only and Cargo's target metadata excludes it from non-Linux builds.
- `sbomqs` install — only consumed by Linux-only `sbomqs_parity` tests.
- nightly toolchain install — same reason; nightly is solely for the eBPF target.
- `bpf-linker` install — same reason.

**Rationale**: macOS exists in this matrix to enforce the "zero warnings on the maintainer's dev environment" success criterion (SC-001). It runs the user-space Rust paths that the maintainer iterates on locally; the eBPF build is fundamentally Linux-only and wouldn't add coverage. Apple Silicon (`macos-latest`) matches the maintainer's actual hardware.

**Alternatives considered**:

- **Workflow-level matrix `strategy.matrix.os: [ubuntu-latest, macos-latest]`** with a single shared job. Rejected for v1 — the Linux job has eBPF/sbomqs steps that the macOS job must skip; expressing this via `if: matrix.os == 'ubuntu-latest'` filters on every step adds more lines than just having two jobs. Implementation MAY refactor to matrix later if the duplication grows; not blocking.
- **macos-13 (Intel)**. Rejected — Apple Silicon is the maintainer's machine; testing on Intel adds runtime cost without coverage value.
- **Run only clippy on macOS, skip tests**. Rejected — the spec's SC-004 (no test regressions) requires cross-platform test verification. Running tests on macOS catches Apple-Silicon-only regressions that Linux can't see.

---

## R4. How to handle `mikebom-ebpf` on macOS?

**Decision**: Trust Cargo's existing target-metadata exclusion. The `mikebom-ebpf` crate is configured to build only on Linux via its `Cargo.toml` (`[target.'cfg(target_os = "linux")']` dependencies and the `aya-ebpf` toolchain). On macOS, `cargo build --workspace` already skips it cleanly. Verify in implementation by running `cargo +stable build --workspace` on the macOS dev machine before the CI job exists; if it fails, add `--exclude mikebom-ebpf` to the macOS clippy + test commands.

**Rationale**: The existing build already works on the maintainer's macOS dev machine without `--exclude mikebom-ebpf`. No new exclusion logic needed unless verification proves otherwise.

**Alternatives considered**: `--exclude mikebom-ebpf` defensively. Rejected — adds noise to the workflow file when the existing config already handles it. Add only if verification fails.

---

## R5. Counting warnings for triage progress

**Decision**: Use `cargo +stable clippy --workspace --all-targets 2>/tmp/clippy.txt && grep -c '^warning:' /tmp/clippy.txt`. Track in PR description as a single number (current → after each commit → final 0).

**Rationale**: Trivial, no tooling. Same pattern used in PR #33's description. Adds zero infrastructure cost.

**Alternatives considered**: A categorized breakdown via `grep '^warning:' /tmp/clippy.txt | sort | uniq -c | sort -rn` for richer progress reports. Optional — useful in implementation, not required as standing infrastructure.

---

## R6. Constitution doc update — minor or patch bump?

**Context**: The pre-PR table at `.specify/memory/constitution.md:357-360` says clippy must report "Zero errors" — silent on warnings. After this feature, the gate flips to "Zero errors AND zero warnings."

**Decision**: PATCH bump 1.3.0 → 1.3.1. Update the table line:

```
| 1 | `cargo +stable clippy --workspace --all-targets` | Zero errors |
```

→

```
| 1 | `cargo +stable clippy --workspace --all-targets -- -D warnings` | Zero errors and zero warnings |
```

Add a SYNC IMPACT REPORT entry at the top of the file:

```
1.3.0 → 1.3.1: PATCH — pre-PR table line 359 updated to reflect the
post-milestone-016 zero-warnings baseline. The `-D warnings` flag is
added to the clippy invocation; the passing condition is amended from
"Zero errors" to "Zero errors and zero warnings." Templates: ✅ no update
needed.
```

**Rationale**: PATCH per the constitution's own amendment procedure — this is a "non-semantic refinement" of the table to keep it descriptive of the actual CI gate. The principles themselves (I–XII) are unchanged. MINOR would be appropriate only if a *new* principle were added or guidance materially expanded; this is a documentation sync.

**Alternatives considered**: MINOR bump. Rejected — no principle change; the existing language ("Pre-PR Verification") is unchanged in spirit.

---

## Summary

All open technical questions resolved. No NEEDS CLARIFICATION markers remain. Ready for Phase 1 (data-model, contracts, quickstart).

| Area                                | Decision (one-line)                                                                                                                                                  |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Lint-deny mechanism                 | `cargo clippy ... -- -D warnings` on both jobs; update CI comment.                                                                                                   |
| Platform-conditional dead-code      | Three-tier triage: Tier A `#[cfg(target_os = "linux")]`, Tier B `#[cfg_attr(not(target_os = "linux"), allow(dead_code))]`, Tier C delete.                            |
| macOS CI shape                      | Second job `lint-and-test-macos` on `macos-latest`; skip eBPF/sbomqs/nightly steps.                                                                                  |
| `mikebom-ebpf` on macOS             | Trust existing target-metadata exclusion; add `--exclude mikebom-ebpf` only if verification fails.                                                                   |
| Progress tracking                   | `grep -c '^warning:'` against the clippy log; cite in PR description.                                                                                                |
| Constitution update                 | PATCH 1.3.0 → 1.3.1; pre-PR table reflects `-D warnings` and "zero errors and zero warnings" passing condition.                                                      |
