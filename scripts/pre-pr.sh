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
# Usage: ./scripts/pre-pr.sh
# Exits non-zero on the first failing step.

set -euo pipefail

steps=(
    "cargo +stable clippy --workspace --all-targets"
    "cargo +stable test --workspace"
)

for cmd in "${steps[@]}"; do
    printf '\n>>> %s\n' "$cmd"
    eval "$cmd"
done

printf '\n>>> all pre-PR checks passed.\n'
