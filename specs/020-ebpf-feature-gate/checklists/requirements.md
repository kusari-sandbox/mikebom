# Spec Quality Checklist: ebpf-tracing Feature Gate

**Checklist for** `/specs/020-ebpf-feature-gate/spec.md`

## Coverage

- [X] Background section explains *why* the gate is needed (carries the Tier 6 finding from PR #38's roadmap + concrete CI-cost numbers).
- [X] User story has a P-priority and a "why this priority" justification.
- [X] Independent Test is concrete (specific commands + expected output).
- [X] Acceptance scenarios use Given/When/Then framing (5 scenarios).
- [X] Edge Cases section names ≥ 5 corner cases (discoverability, cross-feature regressions, xtask invocation, mikebom-ebpf crate, test wiring).
- [X] Functional Requirements are numbered (FR-001 through FR-010), each independently verifiable.
- [X] Key Entities section explicitly notes there's no new data — build-system + module-gating refactor only.
- [X] Success Criteria are measurable (SC-001 through SC-006), each with a verification mechanism.
- [X] Clarifications section captures four scope decisions (default features, feature name, subcommand visibility, xtask scope).
- [X] Out of Scope section names every adjacent concern (mikebom-ebpf split, new trace features, UX rewrite, aya replacement, loader-path change, macOS DYLD/EndpointSecurity, non-eBPF Linux gates).

## Independence

- [X] The single user story is self-contained — no dependencies on other in-flight work.
- [X] Each per-commit deliverable (4 commits) is independently verifiable (per FR-008 each commit's `./scripts/pre-pr.sh` passes).

## Concreteness

- [X] FRs cite specific file paths (`mikebom-cli/Cargo.toml`, `.github/workflows/ci.yml`, `scripts/pre-pr.sh`, `mikebom-cli/src/trace/*`, `mikebom-cli/src/cli/scan.rs`).
- [X] FR-007 quantifies the dependency-tree assertion (`cargo tree -p mikebom -e normal`).
- [X] FR-005 names the verification env var verbatim (`MIKEBOM_PREPR_EBPF=1`).
- [X] FR-003 names the exact runtime-guard error string (the integration test in FR-010 asserts on this).
- [X] Success Criteria reference the existing pre-PR gate + the existing 27-golden byte-identity surface.

## Internal consistency

- [X] FR-001 (umbrella feature shape) aligns with research.md R2 (mikebom-common/aya-user resolution) + data-model.md "feature declaration".
- [X] FR-003 (runtime guard error) aligns with research.md R5 (Option A — twin execute fns) + data-model.md "runtime guard".
- [X] FR-006 (subcommand discoverability) aligns with the rejection of clap-level cfg gating in research.md R5 / contracts/feature-flag.md "What this contract forbids".
- [X] FR-008 (per-commit pre-PR clean) aligns with quickstart.md commit chunking.
- [X] research.md R3 (atomic Cargo.toml + cfg-gates commit) aligns with tasks.md Phase 2 (single commit, not two).

## Lessons from milestones 016, 018, 019

- [X] research.md R3 captures why Cargo.toml + cfg gates ship together — splitting them produces an intermediate state that doesn't compile (analogous to lesson from 018: never half-move a Rust module).
- [X] FR-008 enforces the per-commit verification convention that protected milestones 018 (pip + npm splits) and 019 (binary split).
- [X] quickstart.md "Common pitfalls" enumerates the failure modes (don't drop target predicate, don't gate `LoaderConfig`, don't gate `mod tests` indiscriminately).
- [X] research.md R4 verified that `ScanArgs` clap struct is feature-independent — the lesson from 019's `is_path_claimed` decision: keep cross-cutting plumbing un-gated, only gate the feature-specific implementation.

## Pre-implementation

- [X] [PHASE-1] T001 R2 resolved (mikebom-common aya-user inventory — confirmed `aya-user = ["dep:aya"]` so the umbrella also activates `mikebom-common/aya-user`).
- [X] [PHASE-1] T002 baseline snapshot captured (1216 unique tests).
- [X] [PHASE-2] Commit 1 landed (`9aaf5ea`); cross-target dep-tree confirms default Linux build has no aya/aya-log direct deps.
- [X] [PHASE-3] Commit 2 landed (`82d80d0`); `cargo +stable test -p mikebom --test feature_gate` passes (default), 0-tests under `--features ebpf-tracing`.
- [X] [PHASE-4] Commit 3 landed (`9fc0a7a`); pre-pr.sh clean.
- [X] [PHASE-5] Commit 4 landed (`7a5f4d3`); CLAUDE.md updated with "Feature flags" section.
- [X] [POLISH] SC-001 default-toolchain-only build passes (CI default lane is the proof).
- [ ] [POLISH] SC-002 `lint-and-test` Linux ≤ 2m. **PR #45 first-run came in at 3m42s due to Cargo.lock churn invalidating `Swatinem/rust-cache@v2` key (clippy +43s, tests +51s — both compiled cold).** This checklist item reopens to a steady-state-PR data point: a follow-up PR that does NOT change Cargo.lock should restore the warm cache and confirm whether the default lane lands ≤ 2m. Until that data point exists, SC-002 is unverified, not failed.
- [X] [POLISH] SC-003 `lint-and-test-ebpf` green on PR #45 (5m10s; matches pre-020 default-lane workload).
- [X] [POLISH] SC-005 dep-tree assertion holds (cross-target verification on PR #45).
- [X] [POLISH] SC-006 27-golden regen produces zero diff.

## Post-merge (per spec SC-006 spirit)

- [ ] [QUALITATIVE] Next time a non-Cargo.lock-touching PR opens, capture Linux CI runtime. If ≤ 2m, SC-002 verified and milestone delivered. If 3m+, the Cargo.lock-invalidation theory is wrong and a deeper investigation (or revert) follows.
