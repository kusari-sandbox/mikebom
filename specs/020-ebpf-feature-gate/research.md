---
description: "Research notes — milestone 020 ebpf-tracing feature gate"
status: research
milestone: 020
---

# Research: ebpf-tracing Feature Gate

Pre-implementation investigation. Each finding (R1-R5) supports one or more functional requirements in `spec.md`.

## R1: Why a Cargo feature, not just `cfg(target_os = "linux")` exclusion?

**Question**: macOS already excludes aya/aya-log/libc via the target gate. Why introduce a feature flag at all? Why not "just" make Linux contributors install nightly + bpf-linker?

**Finding**: The contributor-experience cost on Linux is real and load-bearing for CI:

- `cargo +nightly install bpf-linker --locked` runs on every Linux CI invocation (`.github/workflows/ci.yml:67-71`). The conditional `if ! command -v bpf-linker` skips reinstall when cached, but the cache miss on a clean runner is ~30s.
- `cargo run --package xtask -- ebpf` (`.github/workflows/ci.yml:74`) takes ~30-60s.
- The nightly toolchain installation step runs unconditionally (`.github/workflows/ci.yml:51-54`).

Combined: ~60-90s per Linux PR for a code path that has not been touched in production work since `b0f31c1` (bootstrap). PRs that touch only `scan_fs/`, `package_db/`, `generate/`, `attestation/`, etc. — i.e., 100% of recent merge traffic — pay this cost for zero gain.

A feature flag lets us:
1. Drop nightly + bpf-linker from the default Linux CI lane.
2. Move that cost into a dedicated `lint-and-test-ebpf` lane that only validates the trace path.
3. Give local Linux dev the same experience as macOS: stable-only, fast.

**Decision**: Feature flag, default off. Constraint per FR-001.

## R2: Does `mikebom-common`'s `aya-user` feature transitively require `aya`?

**Question**: `mikebom-cli/Cargo.toml:24` reads:

```toml
mikebom-common = { path = "../mikebom-common", features = ["std", "aya-user"] }
```

If `aya-user` itself requires `aya`, the `ebpf-tracing` feature gate must also include the `mikebom-common/aya-user` activation, otherwise toggling `ebpf-tracing` off won't actually drop aya from the dep graph (it'd still come in via the always-on common-crate feature).

**Finding**: To be confirmed during T001 of tasks.md by reading `mikebom-common/Cargo.toml`. Two outcomes:

- **If `aya-user` requires `aya` directly**: change the line to `features = ["std"], default-features = false`, and the `ebpf-tracing` feature does `mikebom-common = { ... features = ["aya-user"] }` via a `dep:` activation. (Requires `optional = true` on the mikebom-common dep, OR a feature-only re-export.)
- **If `aya-user` is just a marker / re-exports types defined in mikebom-common itself**: leave the line alone; the umbrella feature only needs to activate the three direct deps.

**Decision**: Defer to T001. Spec FR-001 names the three direct deps as the umbrella's contents; if R2's confirmation reveals `aya-user` is also load-bearing, FR-001 is amended in a follow-up edit before any code lands.

## R3: Atomic commit ordering — can the Cargo.toml change ship without the cfg-gate change?

**Question**: Plan.md commits 1 and 2 are separate. Is commit 1 (`Cargo.toml`: aya → optional) safe to land alone?

**Finding**: No. Once `aya` is `optional = true` and `default = []`, the `use aya::*` lines in `trace/loader.rs:21-22`, `trace/processor.rs:74`, `cli/scan.rs:173`, etc. fail to resolve unless wrapped in `cfg(feature = "ebpf-tracing")`. The compiler error chain on Linux without the feature would be:

```
error[E0432]: unresolved import `aya`
  --> mikebom-cli/src/trace/loader.rs:21:9
```

**Decision**: Combine commits 1 and 2 into a single atomic commit titled `020/cargo-feature+cfg-gates`. This violates plan.md's per-commit-clean discipline only on the *intermediate* state; the combined commit is itself clean. The lesson from milestones 018 + 019 is "atomic per cohort" — Cargo.toml + cfg gates are the same cohort here.

Plan.md updated to four commits:

1. `020/feature-gate`: Cargo.toml + 10 cfg gates + non-Linux fallback unification.
2. `020/runtime-guard`: trace dispatcher arm + `tests/feature_gate.rs`.
3. `020/ci-split`: `.github/workflows/ci.yml` restructure + `scripts/pre-pr.sh` opt-in.
4. `020/docs`: `CLAUDE.md` paragraph.

## R4: Does the `mikebom trace` clap parser depend on feature-gated types?

**Question**: If `ScanArgs` (in `cli/scan.rs`) holds a field of a feature-gated type, clap parsing breaks even when the user just runs `mikebom trace --help`.

**Finding**: Inspecting `mikebom-cli/src/cli/scan.rs:30-97`:

```rust
pub struct ScanArgs {
    pub target_pid: Option<u32>,
    pub libssl_path: Option<PathBuf>,
    pub ring_buffer_size: u32,
    pub trace_children: bool,
    pub ebpf_object: Option<PathBuf>,
    pub attestation_format: String,
    pub signing_key: Option<PathBuf>,
    pub signing_key_passphrase_env: Option<String>,
    pub keyless: bool,
    pub fulcio_url: String,
    pub rekor_url: String,
    pub no_transparency_log: bool,
    pub require_signing: bool,
    #[arg(last = true)]
    pub command: Vec<String>,
}
```

All fields are `std`-typed. No aya types in the struct. Safe to keep the struct + clap derive un-gated.

`build_signing_identity` (line 104) IS gated, but it's an `impl` method, not part of clap parsing. Its gate expansion to `feature = "ebpf-tracing"` is part of the mechanical sweep — but: this method also handles non-trace signing logic (Fulcio keyless), so gating it removes signing identity construction from default builds.

**Decision**: `build_signing_identity` is invoked only from `execute_scan` (the trace path), so feature-gating it is safe. The `sbom verify` path uses a different signing-verify code path entirely. Confirmed by grep: `build_signing_identity` is referenced only in `cli/scan.rs:execute_scan`.

## R5: How does the runtime guard get added without breaking the cfg structure?

**Question**: When the feature is off, `execute_scan` doesn't compile (it uses aya types). How does the dispatcher in `main.rs` route `Commands::Trace` to the FR-003 error message?

**Finding**: Two clean options:

**Option A**: Two `execute` functions in `cli/scan.rs`, distinguished by cfg:

```rust
#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]
pub async fn execute(args: ScanArgs) -> anyhow::Result<()> { /* existing impl */ }

#[cfg(not(all(target_os = "linux", feature = "ebpf-tracing")))]
pub async fn execute(_args: ScanArgs) -> anyhow::Result<()> {
    anyhow::bail!(
        "this build was compiled without eBPF support; \
         rebuild with --features ebpf-tracing on a Linux host \
         to enable trace capture"
    )
}
```

Dispatcher calls `cli::scan::execute(args).await` unconditionally. The cfg picks the right body.

**Option B**: Gate the `Commands::Trace` variant itself, and feature-off builds emit "unknown subcommand". Worse UX (FR-006 violated).

**Decision**: Option A. The existing `trace/loader.rs:184-190` non-Linux fallback already uses this pattern; we're extending it one level up to the CLI dispatcher.

## R6: Should `xtask ebpf` warn when invoked with feature off?

**Question**: A contributor runs `cargo run -p xtask -- ebpf` with default features. Does it succeed (build the kernel artifact) or fail (warn about feature mismatch)?

**Finding**: `xtask` is a build helper. It doesn't depend on `mikebom-cli` features at all — it just shells out to nightly cargo against `mikebom-ebpf/`. The kernel-side artifact is independent of the user-space feature flag.

**Decision**: No xtask change. A contributor who wants to test the trace path locally runs `cargo run -p xtask -- ebpf` then `cargo +stable test --workspace --features ebpf-tracing`. Two-step, but each step is honest about its job.
