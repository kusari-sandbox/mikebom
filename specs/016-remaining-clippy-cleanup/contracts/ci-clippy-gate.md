# Contract: CI Clippy Gate (post-milestone-016)

**Phase 1 contract for** `/specs/016-remaining-clippy-cleanup/spec.md`

This document is the human-readable specification of the CI-level clippy gate established by milestone 016. The implementation lives in `.github/workflows/ci.yml`; the constitutional anchor is `.specify/memory/constitution.md` (pre-PR table at line 357-360, post-bump 1.3.1).

## Contract surface

The gate is a **GitHub Actions workflow** triggered on `pull_request` and on `push` to `main`. Two parallel jobs (Linux + macOS) each run a clippy invocation and the workspace test suite. Both jobs MUST pass for the workflow to succeed.

## Inputs

| Input                          | Source                                                                 |
|--------------------------------|------------------------------------------------------------------------|
| Source tree                    | `${{ github.event.pull_request.head.sha }}` (PR) or `refs/heads/main` (push) |
| Rust toolchain                 | `dtolnay/rust-toolchain@stable` (with `clippy` component) on both jobs |
| Cargo + build cache            | `Swatinem/rust-cache@v2`                                               |
| Linux-only build inputs        | `clang`, `llvm`, `libelf-dev`, `pkg-config`, `libssl-dev`, `bpf-linker`, `sbomqs` |
| macOS-only build inputs        | (none beyond stable Rust + clippy)                                     |

## Outputs

| Output                                                  | Channel                                                                  |
|---------------------------------------------------------|--------------------------------------------------------------------------|
| Pass/fail status per job                                | GitHub Actions UI; required-status-checks contract                       |
| Full clippy + test logs                                 | Actions log retention                                                    |
| Failure annotation pointing at the offending file:line  | GitHub PR file-diff inline annotations (when clippy emits machine-readable output) |

## Behavioral guarantees

### G1. Zero warnings on either OS fails the workflow

`cargo +stable clippy --workspace --all-targets -- -D warnings` MUST exit non-zero on either Linux or macOS if any clippy warning is emitted. The `-D warnings` flag promotes warnings to errors at the clippy invocation level, not at the crate-root level.

### G2. Test failures on either OS fail the workflow

`cargo +stable test --workspace` MUST report `ok. N passed; 0 failed` for every test target on every platform's job. A failure on either platform fails the overall workflow.

### G3. The two jobs MUST be lint-identical

The `clippy-cmd` byte-string is identical on both jobs — no per-OS lint exemptions, no `--exclude` flags differing across platforms (with the one allowed exception that R4 in research.md flags: `--exclude mikebom-ebpf` MAY be added to the macOS commands ONLY if the existing target-metadata exclusion turns out not to skip it cleanly; verified in implementation).

### G4. Linux-only build artifacts MUST NOT be required on macOS

The macOS job MUST NOT install or invoke: `bpf-linker`, `clang`/`llvm`, `libelf-dev`, the nightly Rust toolchain, the eBPF xtask (`cargo run --package xtask -- ebpf`), `sbomqs`, or any other Linux-only tool. The user-space Rust paths (`mikebom-cli`, `mikebom-common`) build and test cleanly on macOS without these.

### G5. Failure messages MUST name the offending file:line

When the gate fails due to a new warning, the contributor MUST be able to read the GitHub Actions log and locate the file/line/lint name without re-running clippy locally. (Standard `cargo clippy` output already provides this; the contract is just to NOT swallow stderr.)

### G6. The workflow MUST run on every PR

`pull_request:` event with no `paths:` filter — every PR (regardless of which files change) runs the gate. Push-to-main runs the gate too, so a faulty merge can't slip past.

## Non-guarantees (out of contract)

- The gate does NOT promise to catch warnings introduced by future toolchain bumps without code changes. A new clippy lint category landing in a stable Rust release MAY surface warnings that this gate then fails on; resolving requires either fixing the new category in a follow-up PR or adding `#[allow(...)]` justification.
- The gate does NOT verify warnings outside `-- -D warnings` — e.g., it does not enforce custom rustdoc lints, `cargo doc` warnings, or non-clippy lints (the underlying `rustc` `unused_*` family is included via clippy's pass-through, but exotic lints are not).
- The gate does NOT enforce style beyond what clippy enforces (no `rustfmt` check today; that's existing convention, untouched by this contract).

## Verification

The acceptance test for this contract is SC-003: a deliberately-warning-introducing PR MUST fail the gate. The verification recipe is in `quickstart.md`:

```bash
# On a throwaway branch:
echo "pub fn deliberate_dead_code() {}" >> mikebom-cli/src/lib.rs
git commit -am "test: deliberate dead-code probe (will close)"
git push -u origin <branch>
# Open PR; confirm both Linux + macOS jobs fail with `dead_code` warnings;
# close PR without merging; delete branch.
```

## Versioning

This contract is anchored to constitution v1.3.1 (post-feature-016 bump). Any future change to the clippy gate's surface — adding a new excluded crate, switching to a category-specific deny list, dropping the macOS job — MUST be reflected here AND in the constitution's pre-PR table simultaneously.
