# mikebom

An SBOM generator that reads source trees, package caches, and container
images with lockfile-aware dep-graph extraction, emits **CycloneDX 1.6
JSON** with SHA-256 hashes + evidence + real dependency relationships,
and — on Linux — optionally captures build-time provenance via eBPF.

> **Status: 0.1.0-alpha.3, pre-1.0. Source-only; no crates.io release
> yet.**
>
> - **Stable** — `mikebom sbom scan` (filesystem, container image,
>   package cache) and the rest of the `sbom` surface (`generate`,
>   `enrich`, `verify`, `compare`) plus `policy init` and
>   `attestation validate`. Cross-platform, no special privileges.
> - **Experimental, Linux-only** — `mikebom trace capture` /
>   `trace run`. eBPF-based build-time capture that produces
>   attestations bound to the actual build event. Requires CAP_BPF +
>   CAP_PERFMON and adds ~2–3× wall-clock overhead on syscall-heavy
>   builds.
>
> See [`docs/user-guide/cli-reference.md`](docs/user-guide/cli-reference.md)
> for the per-command stability table and
> [`CHANGELOG.md`](CHANGELOG.md) for what shipped when.

## Why

Scan-mode reads lockfiles + package manifests + per-module metadata to
build a proper CycloneDX with:

- **SHA-256 content hashes** on every component, from the bytes on
  disk.
- **Real dep-graph edges**, not a flat fan-out. Per-module `go.mod`
  from the module cache drives the Go graph; `Cargo.lock` drives the
  Rust graph; for Maven there's a full layered strategy
  ([design notes](docs/design-notes.md)) that resolves through
  `~/.m2/` caches, parent POMs, BOM imports, and — when needed —
  deps.dev.
- **CycloneDX evidence blocks** pointing back to the specific file
  path and parser technique that identified each component, with
  confidence scoring.
- **Strict PURL encoding** that round-trips through the
  `packageurl-python` reference implementation (including
  `+` → `%2B` encoding across every ecosystem; `epoch=0` omission
  on RPM; lexicographic qualifier sort).

On top of scan-mode, mikebom adds:

- **Signed DSSE envelope attestations** via sigstore (local-key or
  keyless OIDC → Fulcio → Rekor).
- **In-toto layout verification** for build-policy enforcement.
- **Witness-collection v0.1** output compatible with `sbomit generate`
  and any go-witness-aware verifier.

## Install

Source-only today. Pre-built binaries and crates.io publication are
tracked but not yet shipped.

```bash
git clone https://github.com/mlieberman85/mikebom.git
cd mikebom
cargo build --release
# binary: ./target/release/mikebom
```

**Rust toolchain.** Scan, generate, enrich, verify, compare, policy,
and attestation subcommands build under the **stable** toolchain (CI
runs `cargo +stable`). Trace subcommands additionally need nightly for
the eBPF target — see
[`docs/user-guide/installation.md`](docs/user-guide/installation.md).

**Platform support.**

| Platform          | `sbom *` / `policy` / `attestation` | `trace capture`/`run`       |
|-------------------|-------------------------------------|-----------------------------|
| Linux x86_64      | ✅ supported                         | ✅ kernel ≥ 5.8, CAP_BPF    |
| Linux aarch64     | ✅ supported                         | ✅ kernel ≥ 5.8, CAP_BPF    |
| macOS (Apple/Intel)| ✅ supported                        | ❌ use Lima/Docker (below)  |
| Windows           | 🟡 untested                          | ❌                          |

On macOS, run tracing inside the `mikebom-dev` container
([`Dockerfile.dev`](Dockerfile.dev)) or a Lima VM
([`lima.yaml`](lima.yaml)). Everything else runs natively.

## Supported ecosystems

Nine production ecosystem readers plus a generic binary scanner.
[`docs/ecosystems.md`](docs/ecosystems.md) holds the full matrix;
summary below.

| Ecosystem         | OS package DB                       | Lockfile / manifest                                                         | Dep-graph                          |
|-------------------|-------------------------------------|-----------------------------------------------------------------------------|------------------------------------|
| **deb**           | `/var/lib/dpkg/status`              | —                                                                           | Full (via `Depends:`)              |
| **apk**           | `/lib/apk/db/installed`             | —                                                                           | Direct only (apk encodes no transitive) |
| **rpm**           | `/var/lib/rpm/rpmdb.sqlite` + `.rpm`| —                                                                           | Full (via `REQUIRES`). BDB opt-in via `--include-legacy-rpmdb`. |
| **cargo**         | —                                   | `Cargo.lock` v3/v4                                                          | Full                                |
| **gem**           | —                                   | `Gemfile.lock` (indent-6 edges), `specifications/*.gemspec`                 | Full                                |
| **golang (src)**  | —                                   | `go.mod` + `go.sum` + `$GOMODCACHE/`                                        | Full when cache warm                |
| **golang (bin)**  | —                                   | `runtime/debug.BuildInfo` (Go 1.18+ ELF/Mach-O/PE)                          | Modules only (BuildInfo has no edges) |
| **maven**         | Fedora sidecar POMs                 | `pom.xml`, embedded `META-INF/maven/`, `~/.m2/`, deps.dev fallback          | Full, 5-layer resolver              |
| **npm**           | —                                   | `package-lock.json` v2/v3, `pnpm-lock.yaml`, `node_modules/`                | Full. v1 locks refused.             |
| **pip**           | venv `dist-info/METADATA`           | `poetry.lock`, `Pipfile.lock`, `requirements.txt`                           | Flat venv; tree in locks            |
| *generic binary*  | —                                   | ELF / Mach-O / PE headers (`DT_NEEDED`, `LC_LOAD_DYLIB`, PE IMPORT)         | Linkage only                        |

Maven fat-jars built with the shade-plugin are emitted as nested
`components[].components[]` with a `mikebom:shade-relocation = true`
property, gated on bytecode-presence verification so
declared-but-not-relocated ancestors do not inflate the SBOM. See
[`specs/009-maven-shade-deps/spec.md`](specs/009-maven-shade-deps/spec.md).

## Quickstart

Produce a CycloneDX 1.6 SBOM from any source tree:

```bash
./target/release/mikebom sbom scan \
  --path ./my-project \
  --output project.cdx.json

jq '.components | length, .dependencies | length' project.cdx.json
```

## Stable recipes

**1. Scan a source tree.** Any host, no privileges. Lockfile-driven
dep graph. `--path` defaults to *manifest scope*
(`--include-declared-deps` is auto-on).

```bash
mikebom sbom scan --path ./my-project --output project.cdx.json
```

**2. Scan a container-image tarball.** Defaults to *artifact scope*
(on-disk presence required). Pass `--include-declared-deps` for the
manifest view.

```bash
docker save alpine:3.19 -o alpine.tar
mikebom sbom scan --image alpine.tar --output alpine.cdx.json
```

**3. Scan a package cache.** Treats cached bytes as present-on-disk;
useful for CI cache audits.

```bash
mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json
```

**4. Scan a Maven fat-jar and see shaded ancestors.** With feature
009 the SBOM emits one nested component per shade-relocated ancestor
whose bytecode is actually in the JAR.

```bash
mikebom sbom scan --path ./target/ --output app.cdx.json

jq '
  .components[]
  | select(.purl | test("pkg:maven/"))
  | .components // []
  | map(select(.properties // [] | any(.name == "mikebom:shade-relocation" and .value == "true")))
  | map({purl, bom_ref: ."bom-ref"})
' app.cdx.json
```

**5. Verify a signed DSSE attestation.**

```bash
mikebom sbom verify some.dsse.json --public-key signer.pub
# → PASS — verified with public_key sha256:…
```

**6. Generate a starter in-toto layout bound to a functionary key.**

```bash
mikebom policy init --functionary-key signer.pub --output layout.json
mikebom sbom verify some.dsse.json --layout layout.json
```

**7. Enrich an SBOM with an RFC 6902 JSON Patch.** Each patch is
recorded as a `mikebom:enrichment-patch[N]` property on the BOM
metadata so the provenance of every change survives.

```bash
mikebom sbom enrich project.cdx.json \
  --patch add-supplier.json --author you@example.com
```

**8. Compare mikebom's output against syft / trivy + ground truth.**
Writes a Markdown report and (optionally) a JSON summary.

```bash
mikebom sbom compare \
  --mikebom project.cdx.json \
  --syft syft.cdx.json --trivy trivy.cdx.json \
  --truth Cargo.lock --ecosystem cargo \
  --output compare.md --json
```

**Common flags** across every `sbom *` subcommand: `--offline`,
`--include-dev`, `--include-declared-deps`,
`--include-legacy-rpmdb` (env: `MIKEBOM_INCLUDE_LEGACY_RPMDB=1`).
See `mikebom sbom <verb> --help` for the full set.

## Experimental: build-time trace (Linux only)

> **Status:** experimental. Requires CAP_BPF + CAP_PERFMON. Adds ~2–3×
> wall-clock overhead on syscall-heavy builds. Coverage varies by
> syscall path (gaps on `openat2` / `io_uring`). For most SBOM use
> cases, prefer the scan recipes above — they produce richer output
> with no privilege requirements. Trace-mode exists for workflows
> where the SBOM needs to be provably bound to a specific build event
> (attestation-first provenance).

```bash
# Trace a cargo build and produce an SBOM + signed attestation in one pass.
mikebom trace run \
  --signing-key ./signing.key \
  --sbom-output ripgrep.cdx.json \
  --attestation-output ripgrep.attestation.dsse.json \
  -- cargo install ripgrep

# Then verify from anywhere (works on macOS; verify is pure-scan):
mikebom sbom verify ripgrep.attestation.dsse.json --public-key ./signing.pub
```

See [`docs/architecture/signing.md`](docs/architecture/signing.md),
[`docs/architecture/attestations.md`](docs/architecture/attestations.md),
and
[`specs/006-sbomit-suite/quickstart.md`](specs/006-sbomit-suite/quickstart.md)
for keyless (Fulcio/Rekor) flows, policy layouts, and the
witness-v0.1 attestation format (compatible with `sbomit generate`).

## Documentation

- **[User guide](docs/user-guide/)** — installation, quickstart, CLI
  reference, configuration.
- **[Architecture](docs/architecture/)** — four-stage pipeline
  (scan → resolve → enrich → generate), PURL & CPE emission rules,
  license resolution, in-toto attestation schema.
- **[Ecosystems](docs/ecosystems.md)** — per-ecosystem coverage
  matrix (authoritative).
- **[Design notes](docs/design-notes.md)** — living architectural
  decisions at the cross-cutting level.
- **[Changelog](CHANGELOG.md)** — what shipped in which release.
- **[Specs](specs/)** — per-milestone planning specs
  (001 build-trace → 009 Maven shade-relocation).
- **[Demos](demos/)** — end-to-end demo scripts
  (Debian + Rust build-trace).

## Workspace layout

```
mikebom-cli/      User-space CLI: scan, resolve, enrich, generate, verify, compare, trace
mikebom-common/   Shared types: PURL, attestation schema, resolution types
mikebom-ebpf/     Kernel-side eBPF probes (uprobe on libssl, kprobe on file ops)
xtask/            Workspace build/dev tooling
demos/            End-to-end demo scripts (Debian + Rust)
docs/             User guide, architecture, ecosystems, design notes
specs/            Per-milestone planning specs
tests/fixtures/   Real + synthetic fixtures consumed by integration tests
```

## Reporting issues and contributing

Open an issue or PR at
[github.com/mlieberman85/mikebom](https://github.com/mlieberman85/mikebom).
CI enforces `cargo +stable clippy --workspace --all-targets` and
`cargo +stable test --workspace` on every PR; run both locally before
opening one.

## License

Apache-2.0. See the workspace [`Cargo.toml`](Cargo.toml) for the
declared `license` field.
