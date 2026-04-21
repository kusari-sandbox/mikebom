# mikebom

An attestation-first SBOM generator. mikebom captures what a build actually does
(via eBPF on Linux) or what a filesystem actually contains (anywhere), emits an
in-toto attestation as the primary artifact, and derives a CycloneDX 1.6 SBOM
from that attestation.

> **Status: early, pre-1.0.** Core build-trace, filesystem scan, image scan, and
> the SBOM comparison harness work today on Linux (eBPF) and any host (scan
> modes). See [`docs/user-guide/cli-reference.md`](docs/user-guide/cli-reference.md)
> for per-command status, including a few subcommands still marked **Planned**.

## Why

Existing SBOM tools infer what's installed after the fact. mikebom observes the
install — every TLS download, every file write — so the resulting SBOM carries
real provenance: SHA-256s that byte-match the files on disk, CycloneDX evidence
blocks pointing back to the specific TLS session that fetched each component,
PURLs that round-trip through the `packageurl-python` reference implementation.

See [`EVALUATION.md`](EVALUATION.md) for head-to-head results vs. syft and
trivy: mikebom hits 100% recall / 100% precision / 100% evidence coverage on
Debian and Rust ground-truth fixtures where syft and trivy report zero
components.

## Install

From source (stable Rust, any platform for scan mode):

```bash
cargo build --release
# binary lands at ./target/release/mikebom
```

Linux kernel ≥ 5.8 is required for `trace` subcommands. On macOS, run tracing
inside the `mikebom-dev` container (see [`Dockerfile.dev`](Dockerfile.dev)) or
a Lima VM ([`lima.yaml`](lima.yaml)).

## Three tastes

**1. Trace a build and produce an SBOM.** Linux only; needs eBPF privilege.

```bash
mikebom trace run --sbom-output ripgrep.cdx.json -- cargo install ripgrep
# → mikebom.attestation.json  (in-toto build-trace statement)
# → ripgrep.cdx.json           (CycloneDX 1.6 JSON derived from the attestation)
```

**2. Scan an extracted container image.** Any host. No privilege. No eBPF.

```bash
docker save alpine:3.19 -o alpine.tar
mikebom sbom scan --image alpine.tar --output alpine.cdx.json
```

**3. Scan a filesystem directory.** Caches, package directories, rootfs trees.

```bash
mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json
```

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
