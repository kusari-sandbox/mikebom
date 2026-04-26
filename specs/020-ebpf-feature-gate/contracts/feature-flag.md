# Contract: `ebpf-tracing` Feature Flag

**Phase 1 contract for** `/specs/020-ebpf-feature-gate/spec.md`

This document is the formal contract for the `ebpf-tracing` Cargo feature introduced by milestone 020. Anyone touching the `mikebom-cli` crate's feature surface AFTER this milestone ships should preserve these boundaries.

## Feature declaration

```toml
[features]
default = []
ebpf-tracing = ["dep:aya", "dep:aya-log", "dep:libc"]
```

**Default features**: empty list. Default builds drop nightly toolchain, bpf-linker, and the user-space aya stack.

**`ebpf-tracing` activates**:
- Direct dep `aya` (0.13.x)
- Direct dep `aya-log` (0.2.x)
- Direct dep `libc` (0.2.x)
- Compilation of `mikebom-cli/src/trace/*` (kernel-event aggregator, ring-buffer processor, eBPF loader)
- Compilation of the `mikebom trace` capture pipeline in `mikebom-cli/src/cli/scan.rs`

**`ebpf-tracing` does NOT activate**:
- The `mikebom-ebpf` kernel-side crate (always built via `cargo run -p xtask -- ebpf`, separate target triple, separate toolchain).
- Any non-trace code path. SBOM scanning, attestation generation, policy execution, etc. are unconditionally compiled.

## Compatibility matrix

| Platform | Feature | aya in dep graph | `mikebom trace` | nightly required |
|---|---|---|---|---|
| Linux | off (default) | ✗ | runtime error (FR-003) | ✗ |
| Linux | on | ✓ | functional | ✗ for stable build; ✓ for kernel-side `xtask ebpf` |
| macOS | off (default) | ✗ | runtime error (FR-003) | ✗ |
| macOS | on | ✗ (target gate skips) | runtime error (FR-003) | n/a |
| Other Unix | off | ✗ | runtime error | ✗ |
| Other Unix | on | ✗ | runtime error | n/a |

The `target.'cfg(target_os = "linux")'` gate on the deps means even `--features ebpf-tracing` on macOS does NOT pull in aya. The combined `cfg(all(target_os = "linux", feature = "ebpf-tracing"))` on the trace modules ensures the modules compile only when both conditions hold; the runtime guard catches every other case.

## Public CLI surface

`mikebom trace --help` is **discoverable in all builds**. The subcommand parses normally; only execution returns the FR-003 error when the feature is off.

```
$ mikebom trace capture --target-pid 1234
Error: this build was compiled without eBPF support; rebuild with --features ebpf-tracing on a Linux host to enable trace capture
$ echo $?
1
```

This exact error string is part of the contract — `tests/feature_gate.rs` asserts on it (FR-010).

## What this contract forbids

- **Adding `ebpf-tracing` to `default`**. Defeats the milestone's purpose.
- **Renaming the feature**. Downstream tooling, contributor docs, and CI all reference `ebpf-tracing` by name.
- **Adding non-eBPF deps to the feature umbrella**. `ebpf-tracing` activates only the eBPF-specific stack. Cross-cutting deps stay unconditional.
- **Removing the `target.'cfg(target_os = "linux")'` constraint** from the optional deps. macOS contributors who happen to invoke `cargo build --features ebpf-tracing` get a clean no-op (deps skipped) rather than a build failure.
- **Replacing the runtime guard with a clap-level `Commands::Trace` cfg-gate**. The runtime guard preserves discoverability per FR-006.

## Anti-patterns to avoid

- **Splitting the umbrella into `aya`-only and `libc`-only sub-features**. They're co-required; splitting is YAGNI.
- **Introducing a `default-ebpf` feature for "Linux opt-in by default"**. Cargo doesn't have target-conditional defaults. Workspace contributors and CI authors set `--features ebpf-tracing` explicitly when they want it.
- **Adding `mikebom-common/aya-user` to the feature umbrella without R2 confirmation**. May or may not be needed depending on what `aya-user` actually does in mikebom-common — verified at task T001.
- **Re-using the feature for unrelated trace-like work** (e.g., a future "logging-trace" or "sentry-trace"). If we ship those, give them their own feature names. `ebpf-tracing` means kernel-side instrumentation, full stop.
