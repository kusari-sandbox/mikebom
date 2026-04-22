# mikebom

An SBOM generator that reads source trees, package caches, and container images
with lockfile-aware dep-graph extraction, produces CycloneDX 1.6 output with
SHA-256 hashes + evidence + real dependency relationships, and — on Linux —
optionally captures build-time provenance via eBPF.

> **Status: early, pre-1.0.**
> - **Stable**: `mikebom sbom scan` (filesystem, container image, package cache) +
>   `sbom verify` (signed DSSE envelopes) + `policy init` (in-toto layouts) +
>   `sbom enrich` (RFC 6902 JSON Patch). Cross-platform, no special privileges.
> - **Experimental, Linux-only**: `mikebom trace capture` / `trace run` —
>   eBPF-based build-time capture. Produces attestations bound to the actual
>   build event (not just a post-hoc scan) but requires CAP_BPF + CAP_PERFMON
>   and adds ~2-3× wall-clock overhead on syscall-heavy builds.
>
> See [`docs/user-guide/cli-reference.md`](docs/user-guide/cli-reference.md)
> for per-command status.

## Why

`mikebom sbom scan` reads lockfiles + package manifests + per-module metadata to
build a proper CycloneDX with:

- **SHA-256 content hashes** on every component (vs. trivy/syft: typically 0 on
  filesystem scans)
- **Real dep-graph edges** — not a flat fan-out. On a kyverno source-tree scan,
  mikebom emits 6,395 real `dependsOn` edges across 304 modules (fanout ≈ 21);
  trivy emits 489 flat edges. Per-module `go.mod` files from the module cache
  drive the Go graph; `Cargo.lock` drives the Rust graph; etc.
- **CycloneDX evidence blocks** pointing back to the specific file path and
  parser technique that identified each component, with confidence scoring
- **Strict PURL encoding** that round-trips through the `packageurl-python`
  reference implementation (including `+` → `%2B` encoding across every
  ecosystem)

On top of scan-mode, mikebom adds:
- **Signed DSSE envelope attestations** via sigstore (local-key or keyless
  OIDC → Fulcio → Rekor)
- **In-toto layout verification** for build-policy enforcement
- **Witness-collection v0.1 output** compatible with `sbomit generate` and any
  go-witness-aware verifier

Existing SBOM tools either infer what's installed (syft, trivy) or capture the
build event (witness). mikebom does both, with the scan-mode pipeline producing
significantly richer CycloneDX output than either peer even without the trace.

See [`EVALUATION.md`](EVALUATION.md) for head-to-head results vs. syft and
trivy on Debian, Rust, and Go fixtures.

## Install

From source (stable Rust, any platform for scan mode):

```bash
cargo build --release
# binary lands at ./target/release/mikebom
```

Trace subcommands require Linux kernel ≥ 5.8 + CAP_BPF + CAP_PERFMON. On macOS,
run tracing inside the `mikebom-dev` container (see
[`Dockerfile.dev`](Dockerfile.dev)) or a Lima VM
([`lima.yaml`](lima.yaml)). Scan subcommands run natively on any OS.

## Stable recipes

**1. Scan a source tree.** Any host. No privilege. Lockfile-driven dep graph.

```bash
mikebom sbom scan --path ./my-project --output project.cdx.json
```

**2. Scan a container image tarball.**

```bash
docker save alpine:3.19 -o alpine.tar
mikebom sbom scan --image alpine.tar --output alpine.cdx.json
```

**3. Scan a filesystem directory or package cache.**

```bash
mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json
```

**4. Verify a signed DSSE attestation.**

```bash
mikebom sbom verify some.dsse.json --public-key signer.pub
# → PASS — verified with public_key sha256:…
```

**5. Generate a starter in-toto layout bound to a functionary key.**

```bash
mikebom policy init --functionary-key signer.pub --output layout.json
mikebom sbom verify some.dsse.json --layout layout.json
```

**6. Enrich an SBOM with an RFC 6902 JSON Patch.**

```bash
mikebom sbom enrich project.cdx.json --patch add-supplier.json --author you@example.com
```

## Experimental: build-time trace (Linux only)

> **Status:** experimental. Requires CAP_BPF + CAP_PERFMON. Adds ~2-3×
> wall-clock overhead on syscall-heavy builds. Coverage varies by syscall path
> (gaps on `openat2` / `io_uring`). For most SBOM use cases, prefer the scan
> recipes above — they produce richer output with no privilege requirements.
> The trace-mode pipeline exists for workflows where the SBOM needs to be
> provably bound to a specific build event (attestation-first provenance).

```bash
# Trace a cargo build and produce an SBOM + signed attestation in one pass
mikebom trace run \
  --signing-key ./signing.key \
  --sbom-output ripgrep.cdx.json \
  --attestation-output ripgrep.attestation.dsse.json \
  -- cargo install ripgrep

# Then verify from anywhere (scan-mode command, works on macOS):
mikebom sbom verify ripgrep.attestation.dsse.json --public-key ./signing.pub
```

See [`docs/architecture/signing.md`](docs/architecture/signing.md),
[`docs/architecture/attestations.md`](docs/architecture/attestations.md), and
[`specs/006-sbomit-suite/quickstart.md`](specs/006-sbomit-suite/quickstart.md)
for keyless (Fulcio/Rekor) flows, policy layouts, and the witness-v0.1
attestation format (compatible with `sbomit generate`).

## Documentation

- **[User guide](docs/user-guide/)** — installation, quickstart, CLI reference, configuration
- **[Architecture](docs/architecture/)** — the four-stage pipeline (scan → resolve → enrich → generate), PURL & CPE emission rules, license resolution, in-toto attestation schema
- **[Ecosystems](docs/ecosystems.md)** — per-ecosystem coverage matrix (apk / cargo / deb / gem / golang / maven / npm / pip / rpm)
- **[Design notes](docs/design-notes.md)** — living architectural changelog
- **[Specs](specs/)** — per-milestone planning specs (001 build-trace → 005 PURL & scope alignment)
- **[Demos](demos/)** — Debian and Rust build-trace demos that run inside `mikebom-dev`
- **[Evaluation](EVALUATION.md)** — accuracy benchmarks vs. syft / trivy / scalibr

## Workspace layout

```
mikebom-cli/      User-space CLI: scan, resolve, enrich, generate
mikebom-common/   Shared types: PURL, attestation schema, resolution types
mikebom-ebpf/     Kernel-side eBPF probes (uprobe on libssl, kprobe on file ops)
xtask/            Workspace build/dev tooling
demos/            End-to-end demo scripts (Debian + Rust)
docs/             User guide, architecture, ecosystems, design notes
specs/            Per-milestone planning specs
```

## License

See workspace `Cargo.toml`.
