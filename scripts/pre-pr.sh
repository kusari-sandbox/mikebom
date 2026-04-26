#!/usr/bin/env bash
# Pre-PR verification gate. Runs the two checks that CI runs in
# .github/workflows/ci.yml — clippy with --all-targets (so the
# `clippy::unwrap_used` deny on the cli crate root applies inside
# `#[cfg(test)]` modules too) and the workspace test suite.
#
# Per CLAUDE.md: BOTH must pass locally before any PR. A passing
# `cargo test -p mikebom` alone is insufficient — clippy is not run,
# and `--all-targets` enforces lints on tests.
#
# Usage:
#   ./scripts/pre-pr.sh
#       Default lane — matches the `lint-and-test` CI job. Stable
#       toolchain only, no eBPF, no nightly required.
#
#   MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh
#       Opt-in eBPF lane — matches the `lint-and-test-ebpf` CI job.
#       Adds `--features ebpf-tracing` to both clippy and test.
#       Linux only (the optional aya/aya-log/libc deps are also
#       target-gated). Requires `cargo run -p xtask -- ebpf` to have
#       been run at least once if any test reaches into the kernel
#       artifact path. See specs/020-ebpf-feature-gate/.
#
# Exits non-zero on the first failing step.

set -euo pipefail

if [[ "${MIKEBOM_PREPR_EBPF:-0}" == "1" ]]; then
    printf '>>> running pre-PR checks with --features ebpf-tracing (eBPF lane)\n'
    feature_args=(--features ebpf-tracing)
else
    feature_args=()
fi

steps=(
    "cargo +stable clippy --workspace --all-targets ${feature_args[*]} -- -D warnings"
    "cargo +stable test --workspace ${feature_args[*]}"
)

for cmd in "${steps[@]}"; do
    printf '\n>>> %s\n' "$cmd"
    eval "$cmd"
done

printf '\n>>> all pre-PR checks passed.\n'
