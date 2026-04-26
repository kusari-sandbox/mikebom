---
description: "Data model — milestone 020 ebpf-tracing feature gate (cfg-gate inventory)"
status: data-model
milestone: 020
---

# Data Model: ebpf-tracing Feature Gate

This is a build-system + module-gating refactor — no runtime data model changes. The "data model" here is the inventory of cfg gates that need expansion and the shape of the new `[features]` block.

## `[features]` block (target shape)

```toml
[features]
default = []

# Enable user-space eBPF tracing (Linux + nightly + bpf-linker required).
# Activates the `mikebom trace` subcommand and pulls in aya/aya-log/libc.
# Build the kernel-side object first: `cargo run -p xtask -- ebpf`.
# See specs/020-ebpf-feature-gate/spec.md for the full surface contract.
ebpf-tracing = ["dep:aya", "dep:aya-log", "dep:libc"]
```

## Optional-dep transformation

```toml
# Before:
[target.'cfg(target_os = "linux")'.dependencies]
aya = "0.13"
aya-log = "0.2"
libc = "0.2"

# After:
[target.'cfg(target_os = "linux")'.dependencies]
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }
libc = { version = "0.2", optional = true }
```

Note: the `target` predicate stays. Combined with `optional = true`, the deps are pulled in only when **both** the target is Linux **and** the feature is on.

## cfg-gate inventory (10 expansions)

| File | Line | Before | After |
|---|---|---|---|
| `mikebom-cli/src/trace/loader.rs` | 16 | `#[cfg(target_os = "linux")]` | `#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]` |
| `mikebom-cli/src/trace/loader.rs` | 179 | `#[cfg(target_os = "linux")]` | same as above |
| `mikebom-cli/src/trace/loader.rs` | 184 | `#[cfg(not(target_os = "linux"))]` | `#[cfg(not(all(target_os = "linux", feature = "ebpf-tracing")))]` |
| `mikebom-cli/src/trace/loader.rs` | 187 | `#[cfg(not(target_os = "linux"))]` | same as line 184 |
| `mikebom-cli/src/trace/processor.rs` | 68 | `#[cfg(target_os = "linux")]` | `#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]` |
| `mikebom-cli/src/trace/pid_tracker.rs` | 92 | same | same |
| `mikebom-cli/src/cli/scan.rs` | 104 | same | same |
| `mikebom-cli/src/cli/scan.rs` | 158 | same | same |
| `mikebom-cli/src/cli/scan.rs` | 169 | same | same |
| `mikebom-cli/src/cli/scan.rs` | 544 | same | same |
| `mikebom-cli/src/cli/scan.rs` | 577 | same | same |
| `mikebom-cli/src/cli/scan.rs` | 612 | same | same |

12 lines actually (10 positive gates + 2 negative gates in `loader.rs`). The negative gates may consolidate into one if the two `cfg(not(target_os = "linux"))` blocks are adjacent — verified at implementation time.

## Out-of-scope cfg gates

These stay platform-only (NOT feature-gated), per spec FR-002:

| File | Line | Reason |
|---|---|---|
| `mikebom-cli/src/scan_fs/os_release.rs` | 134 | `/etc/os-release` reading; host detection independent of trace |
| `mikebom-cli/src/attestation/builder.rs` | 109 | `/proc/version` reading; kernel-version detection for attestations |
| `mikebom-cli/src/trace/aggregator.rs` | 6 | comment-only reference, not a real gate |

## Runtime guard (FR-003)

`mikebom-cli/src/cli/scan.rs::execute` gets a feature-off twin:

```rust
#[cfg(not(all(target_os = "linux", feature = "ebpf-tracing")))]
pub async fn execute(_args: ScanArgs) -> anyhow::Result<()> {
    anyhow::bail!(
        "this build was compiled without eBPF support; \
         rebuild with --features ebpf-tracing on a Linux host \
         to enable trace capture"
    )
}
```

Exact error string is part of the contract — the integration test in `tests/feature_gate.rs` asserts on it.

## CI matrix (target shape)

| Job | Runner | Toolchain | Features | Cost |
|---|---|---|---|---|
| `lint-and-test` | ubuntu-latest | stable | default (empty) | ~1m45s (target) |
| `lint-and-test-macos` | macos-latest | stable | default (empty) | ~1m20s (unchanged) |
| `lint-and-test-ebpf` | ubuntu-latest | stable + nightly | `ebpf-tracing` | ~2m30s (matches pre-020 baseline) |

All three run in parallel. PR is green when all three pass.

## Public surface impact

No public-API change. The only user-visible difference is:

1. `cargo build` from a default checkout requires only stable.
2. `mikebom trace capture --help` from a default build prints the help, but `mikebom trace capture --target-pid X` exits non-zero with the FR-003 message.
3. `mikebom --version` is unchanged.
4. `mikebom sbom scan / verify`, `mikebom attestation generate / verify`, `mikebom policy *` — all unchanged.
