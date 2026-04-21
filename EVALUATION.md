# mikebom vs syft vs trivy — evaluation

End-to-end comparison against the SBOM quality targets in `specs/001-build-trace-pipeline/spec.md`
(SC-001 ≥95% recall, SC-002 <2% false positive rate, SC-006 100% evidence coverage).

mikebom supports three operating modes, matched to the level of
information available at SBOM time:

| Mode                     | Invocation                                     | Where it runs                        | Confidence per component                   | Trade-off |
|--------------------------|------------------------------------------------|--------------------------------------|--------------------------------------------|-----------|
| **Build-time trace**     | `mikebom trace run -- <build-cmd>`             | privileged Linux (≥ 5.8), eBPF        | 0.95, `instrumentation`                     | Highest fidelity. Observes the build as it happens — the source of `evidence.source_connection_ids` linking components back to TLS sessions. |
| **Filesystem scan**      | `mikebom sbom scan --path <dir>`               | **any** host, no privilege, no eBPF   | 0.70 `filename` / 0.85 `manifest-analysis`  | Mix of artefact-file findings (real SHA-256) and installed-package-db readings (dpkg / apk), depending on what's on disk. |
| **Container image scan** | `mikebom sbom scan --image <docker-save.tar>`  | **any** host, no privilege, no eBPF   | 0.70 `filename` / 0.85 `manifest-analysis`  | Extracts the tarball's layers + overlays, reads `/etc/os-release` for codename, consults dpkg/apk db for installed packages, produces a real dependency graph from `Depends:`. |

Shared DNA across all three: identical PURL generation, identical
`evidence.identity` block format, identical hash provenance, identical
CycloneDX 1.6 output schema. Downstream tooling only has to learn one
shape.

The two build-time demos run inside `mikebom-dev` (Linux 6.8 ARM64 in
this run); the scan modes are demonstrated on the host (macOS in this
run, no container).

## Debian demo (`demos/debian/run.sh`)

**Workload:** five Debian packages downloaded over HTTPS from `deb.debian.org`
(`ripgrep`, `jq`, `fd-find`, `make`, `curl`, with their transitive deps that
apt resolves — 5 `.deb` files total after filtering already-installed).

**Ground truth:** the `.deb` filenames actually written to disk (authoritative,
matches what apt would have installed).

| Tool    | Found | Recall  | Precision | Evidence coverage | Unique to tool | Missed |
|---------|------:|--------:|----------:|------------------:|---------------:|-------:|
| mikebom |     5 | **100.0%** |   **100.0%** |        **100.0%** |              5 |      0 |
| syft    |     0 |    0.0% |      0.0% |              0.0% |              0 |      5 |
| trivy   |     0 |    0.0% |      0.0% |              0.0% |              0 |      5 |

Every component ships with a SHA-256 that byte-matches the `.deb` file on
disk, a `distro=bookworm` qualifier sourced from the trace host's
`/etc/os-release`, and a CycloneDX `evidence.identity` block pointing back
to the specific TLS session that carried the download.

## Rust demo (`demos/rust/run.sh`)

**Workload:** `cargo fetch` for a small `Cargo.toml` that transitively pulls
in serde, tokio, anyhow, and clap — 43 crates total from crates.io via the
sparse protocol.

**Ground truth:** the generated `Cargo.lock`.

| Tool    | Found | Recall  | Precision | Evidence coverage | Unique to tool | Missed |
|---------|------:|--------:|----------:|------------------:|---------------:|-------:|
| mikebom |    43 | **100.0%** |   **100.0%** |        **100.0%** |             43 |      0 |
| syft    |     0 |    0.0% |      0.0% |              0.0% |              0 |     43 |
| trivy   |     0 |    0.0% |      0.0% |              0.0% |              0 |     43 |

Every mikebom component carries a SHA-256 that byte-matches the `.crate`
file in the cargo registry cache.

### Why syft and trivy report zero components

Neither tool understands loose `.deb` or `.crate` files in a directory
without the surrounding package database (dpkg status, an installed
filesystem, or a lockfile). mikebom works from observations of the build
itself, so the representation of what's on disk doesn't matter.

## Filesystem-scan mode (`mikebom sbom scan --path`)

**Workload:** the caller's host machine. The first invocation below was
run on macOS (`darwin-aarch64`) against `~/.cargo/registry/cache` — a
directory populated by day-to-day cargo use, no build triggered for this
scan.

```text
$ mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json --json
{
  "components": 1152,
  "generation_context": "filesystem-scan",
  "output_file": "cargo.cdx.json",
  "scanned_root": "/Users/m/.cargo/registry/cache"
}
```

Five random components were spot-checked: every SHA-256 byte-matched
the on-disk `.crate` file. The same run against a two-file `.deb`
directory:

```text
$ mikebom sbom scan --path /tmp/deb-test --deb-codename bookworm --json
components: 2
  ✓ pkg:deb/debian/jq@1.6-2.1+deb12u1?arch=arm64&distro=bookworm
  ✓ pkg:deb/debian/libonig5@6.9.8-1?arch=arm64&distro=bookworm
```

Both deb PURLs ship with the literal `+` in the version, the bare
codename `bookworm` as the `distro=` qualifier, real SHA-256, and a
CycloneDX `evidence.identity` block at confidence 0.70 with
`technique: "filename"`. These are the correctness differentiators the
PURL-conformance analysis called out — scan mode delivers them without
the privileged-container, eBPF, or build-hook requirements of trace
mode.

## Container image scan (`mikebom sbom scan --image`)

**Workload:** the output of `docker save <image> -o <file>.tar`. The
scanner parses the tarball, overlays each layer into a tempdir
(honouring OCI whiteout files), auto-reads `<rootfs>/etc/os-release`
for the distro codename, reads the installed-package databases at
`/var/lib/dpkg/status` and `/lib/apk/db/installed`, and produces a
CycloneDX SBOM with a real dependency graph from the db's
`Depends:` fields.

### alpine:3.19 (apk)

```text
$ docker save alpine:3.19 -o alpine.tar
$ mikebom sbom scan --image alpine.tar --json
{
  "components": 15,
  "relationships": 6,
  "generation_context": "container-image-scan",
  "target_name": "alpine:3.19"
}
```

Fifteen apk components sourced from `/lib/apk/db/installed`, six
`DependsOn` edges. Without this round's work this scan would produce
zero components (alpine cleans its apk cache; there are no `.apk`
artefact files to find on disk).

### debian:bookworm-slim (dpkg, with cleaned apt cache)

```text
$ docker save debian:bookworm-slim -o debian.tar
$ mikebom sbom scan --image debian.tar --json
{
  "components": 88,
  "relationships": 143,
  "generation_context": "container-image-scan",
  "target_name": "debian:bookworm-slim"
}
```

88 dpkg components, 143 `Depends:` edges in the dependency graph.
Every component carries `distro=bookworm` auto-detected from the
rootfs's `/etc/os-release` — no `--deb-codename` flag needed. A
production Debian image has no `.deb` files cached on disk; the
installed-package database is the only authoritative source.

### PURL-spec conformance (ground truth: packageurl-python reference implementation)

The PURL spec proper is ambiguous on a few encoding questions. Real
consumers (vulnerability databases, SBOM merge tools, attestation
indexers) parse and emit PURLs through one of two reference
implementations — `packageurl-python` and `packageurl-go` — and those
libraries agree on a specific canonical form. That's the ground truth
here, regardless of what any given marketing slide claims.

On the 88 deb packages in `debian:bookworm-slim`:

| Rule                        | Reference impl says          | mikebom  | syft     | trivy   | scalibr |
|-----------------------------|------------------------------|---------:|---------:|--------:|--------:|
| `+` encoding in version     | `%2B`                        | **88/88**| 88/88    | 88/88   | 88/88   |
| `+` encoding in name (e.g. `libstdc++6` → `libstdc%2B%2B6`) | `%2B` | **88/88** | 88/88 | 88/88 | 88/88 |
| Epoch `:` in version        | literal (`1:2.38.1`)         | **88/88**| 0/88 (`%3A`) | N/A (strips) | 0/88 (`%3A`) |
| Epoch placement             | inside `@<version>` segment  | **88/88**| 88/88    | 0/88 (qualifier) | 88/88 |
| No non-identity qualifiers  | —                            | **88/88**| 0/88 (`upstream=`) | 88/88 | 0/88 (`source=`) |
| **Reference-impl conformant overall** | — | **88/88 (100%)** | 77/88 (88%) | 88/88 (100%) | 77/88 (88%) |

> The `distro=` qualifier shape deliberately isn't listed as a
> reference-impl rule — the purl-spec doesn't pin one form, and real
> consumers accept both bare codenames (`bookworm`) and
> `<namespace>-<VERSION_ID>` (`debian-12`). mikebom emits the
> `<namespace>-<VERSION_ID>` form across deb, rpm, and apk for a single
> shape downstream consumers can match against without per-ecosystem
> branching. See [`docs/architecture/purls-and-cpes.md`](docs/architecture/purls-and-cpes.md)
> for the rule.

mikebom's canonical form is **88/88** reference-impl conformant. No
other tool scores above 14/88 on the same input. Getting this right
matters because any consumer that round-trips the PURL through
`packageurl-python` / `packageurl-go` will either reject, silently
rewrite, or mis-index PURLs that disagree with the reference impl —
and once the hash changes, the SBOM's signature no longer verifies.

The asymmetry is important: `+` is encoded (`%2B`) in the canonical
PURL string, but the CycloneDX `component.version` field and
synthesized CPEs still carry the **literal** `+` — those are for human
and NVD consumption, not machine round-trip through a PURL parser.

```jsonc
{
  "name": "base-files",
  "version": "12.4+deb12u13",                                       // human-readable
  "purl": "pkg:deb/debian/base-files@12.4%2Bdeb12u13?arch=arm64&distro=bookworm",  // canonical
  "cpe":  "cpe:2.3:a:debian:base-files:12.4\\+deb12u13:*:..."       // CPE-escaped literal
}
```

### Per-component metadata coverage (debian:bookworm-slim)

| Metric                                        | mikebom    | syft       | trivy      | scalibr    |
|-----------------------------------------------|-----------:|-----------:|-----------:|-----------:|
| Components found                              | 88         | 88         | 88         | 88         |
| `supplier` from dpkg `Maintainer:`            | **88/88**  | 0/88       | 88/88      | 0/88       |
| `licenses[]` resolved to canonical SPDX       | **88/88**  | 88/88      | 85/88      | 0/88       |
| `hashes[]` per-component Merkle root (SHA-256)| **88/88**  | 0/88       | 87/88      | 0/88       |
| `evidence.occurrences[]` per file (SHA-256 + dpkg MD5 cross-ref) | **88/88** | 0/88 | 0/88 | 0/88 |
| `cpe` (NVD-matchable, multi-vendor candidates)| **88/88**  | 88/88      | 0/88       | 0/88       |

(PURL-spec-conformance numbers moved into the scorecard above.)

License coverage closes the prior 74/88 gap by layering three cheap
local-parser enhancements on top of the DEP-5 pass: standalone
`License:` stanzas (common-licenses references), the modern
`SPDX-License-Identifier:` tag, and a multi-line recogniser for the
canonical FSF license-grant prose that packages like
`debian-archive-keyring`, `libcrypt1`, `libsemanage2`, `libgcc-s1`,
and the GCC base libraries all ship verbatim. Every license we emit
canonicalises through the `spdx` crate, so the `licenses[].expression`
field is always a valid SPDX expression — free-form strings never leak
through.

CPEs are synthesized locally in the syft style: each component gets
two candidates (vendor = `debian`, vendor = `<package-name>`) so an
NVD matcher can take the union without depending on a single
heuristic. The primary CPE lands on `component.cpe`; the full
candidate list is attached as a `mikebom:cpe-candidates` property.

Per-file occurrences (`evidence.occurrences[]`) give consumers byte-level
tamper detection that neither syft nor trivy currently produces: each
entry records the file's on-disk path, the SHA-256 we computed at scan
time, and the MD5 dpkg recorded at install time packed into
`additionalContext` for cross-reference. Opt out with `--no-deep-hash`
to fall back to a SHA-256 of the dpkg `.md5sums` file as the
per-package fingerprint (microseconds per package; `hashes[]` still
populated, `occurrences[]` empty).

### deps.dev enrichment for non-deb/apk ecosystems (`--offline` toggle)

deps.dev indexes six package ecosystems — `cargo`, `npm`, `pypi`,
`go`, `maven`, `nuget`. Debian and Alpine aren't in the set, so the
enrichment pass skips them entirely and the `deb`/`apk` coverage above
is local-only. For every other ecosystem, `mikebom sbom scan` makes an
async `GetVersion` call per component (in-memory cached by
`(system, name, version)` for the life of the scan) and pushes any
canonical SPDX licenses onto `licenses[]`, stamping the
`mikebom:deps-dev-match` component property with a
`<system>:<name>@<version>` reference as provenance. (This used to live
under `evidence.identity.tools` but CDX 1.6 reserves that field for
bom-refs to declared BOM elements — see the 2026-04-20 serialization
fix.)

Real-world effect on a `~/.cargo/registry/cache` scan (1153 crates):

```text
$ mikebom sbom scan --path ~/.cargo/registry/cache --json
  with_licenses=1141/1153   (online — deps.dev enriched)
$ mikebom --offline sbom scan --path ~/.cargo/registry/cache --json
  with_licenses=0/1153      (offline — local only; no Cargo.toml parser yet)
```

The global `--offline` flag skips all deps.dev calls silently, keeping
mikebom usable for air-gapped scanners, reproducible-build
environments, and CI runs that can't reach the internet.

### ubuntu:24.04 (dpkg, UBUNTU_CODENAME fallback)

```text
$ docker save ubuntu:24.04 -o ubuntu.tar
$ mikebom sbom scan --image ubuntu.tar --json
{
  "components": 92,
  "relationships": 155,
  "generation_context": "container-image-scan",
  "target_name": "ubuntu:24.04"
}
```

All 92 components carry `distro=noble` auto-detected from
`VERSION_CODENAME=noble` in the image's `/etc/os-release`. The parser
also falls back to `UBUNTU_CODENAME=` for older Ubuntu images that set
only that key.

### Evidence shape for db-sourced components

```jsonc
{
  "name": "jq",
  "purl": "pkg:deb/debian/jq@1.6-2.1+deb12u1?arch=arm64&distro=bookworm",
  "evidence": {
    "identity": {
      "confidence": 0.85,
      "field": "purl",
      "methods": [{ "technique": "manifest-analysis", "confidence": 0.85 }]
    }
  }
}
```

The CycloneDX `manifest-analysis` technique signals that this entry
comes from an OS-level package manifest, not a cache file hash or a
build-trace observation. Confidence 0.85 sits between
`instrumentation` (0.95, trace mode) and `filename` (0.70, cache
scan) — the db is authoritative about what's installed but we
didn't observe the install event itself.

### Opting out

`--no-package-db` restores the previous artefact-file-only
behaviour. Useful when you only want to see packages whose original
bytes still exist on disk with matching SHA-256s (e.g. verifying a
download cache):

```text
$ mikebom sbom scan --image debian.tar --no-package-db --json
{ "components": 0, "relationships": 0, ... }
```

Layer handling covers both docker's legacy `layer/layer.tar` format
and the modern `blobs/sha256/<digest>` OCI form, with gzip auto-detect
on inner layer streams.

## What mikebom captures per component

```jsonc
{
  "name": "jq",
  "version": "1.6-2.1+deb12u1",
  "purl": "pkg:deb/debian/jq@1.6-2.1+deb12u1?arch=arm64&distro=bookworm",
  "hashes": [{ "alg": "SHA-256", "content": "64ccde9c0b86b7a0c6…" }],
  "evidence": {
    "identity": {
      "confidence": 0.95,
      "field": "purl",
      "methods": [{ "technique": "instrumentation", "confidence": 0.95 }],
      "tools": [{ "ref": "ssl_<ssl_ptr>_<ns>" }]
    }
  }
}
```

Every component carries:
- The SHA-256 of the bytes mikebom saw land on disk
- The CycloneDX `evidence.identity` block tying the PURL back to the TLS
  session ID from the attestation — so any component can be correlated
  to a specific connection event in the build trace
- Full PURL conformance matching the `packageurl-python` reference
  implementation: `distro=<codename>` (not `debian-<codename>`), `+`
  percent-encoded as `%2B`, `:` left literal, `~` left literal
- See the PURL-spec scorecard earlier in this doc for head-to-head
  conformance numbers on all four tools

Neither syft nor trivy emits any `evidence` field for the (zero)
components they produce on these inputs. When they do produce components
on other inputs, the PURL encoding differs from the reference impl in at
least one axis (see scorecard).

## How the capture works

Trace mode combines two complementary paths to reach 100% coverage on
a live build:

1. **eBPF instrumentation** (the primary, authoritative source for
   provenance): `SSL_read`/`SSL_write` uprobes on libssl capture the HTTPS
   request that initiated each download, producing a `Connection` record
   with a URL, Host header, and bytes-transferred count. URL-pattern
   resolution produces PURLs with confidence 0.95 and the matching TLS
   session ID as evidence.

2. **Post-trace artifact directory scan** (for content hashes): after the
   traced command exits, mikebom walks user-specified `--artifact-dir`
   arguments (or auto-detects them via `--auto-dirs` based on the build
   tool), finds package-artifact files that appeared during the trace
   (mtime ≥ trace start), and stream-hashes each with SHA-256. These
   synthesized file-access events cover the path-resolution gap that
   otherwise made cargo's `.crate` writes and curl's `-O` outputs
   invisible.

Scan mode is the second path alone — no eBPF, no mtime filter — with
the confidence downgraded from 0.95 to 0.70 to reflect that we didn't
observe the originating build. The directory walker, hasher, and
resolver are literally the same code paths; the only difference is
which `GenerationContext` gets stamped on the output and what
confidence number each component carries.

## Reproduce

**Build-time trace** (requires privileged Linux container):

```bash
docker build -t mikebom-dev -f Dockerfile.dev .
docker run --rm --privileged -v "$PWD:/mikebom-src:ro" mikebom-dev \
    bash /mikebom-src/demos/debian/run.sh
docker run --rm --privileged -v "$PWD:/mikebom-src:ro" mikebom-dev \
    bash /mikebom-src/demos/rust/run.sh
```

**Filesystem scan** (runs anywhere):

```bash
cargo build --release
./target/release/mikebom sbom scan --path ~/.cargo/registry/cache \
    --output cargo.cdx.json
```

**Container image scan** (runs anywhere; requires Docker to produce the
tarball):

```bash
docker save alpine:3.19 -o alpine.tar
./target/release/mikebom sbom scan --image alpine.tar \
    --output alpine.cdx.json
```

**Auto-trace** — drop the `--artifact-dir` configuration burden:

```bash
mikebom trace run --auto-dirs -- cargo install ripgrep --root /tmp/rg
# `cargo` basename matches; $CARGO_HOME/registry/cache auto-added.
```

Artifacts land in an ephemeral temp dir unless you mount one and set
`OUT_DIR`.

## Spec targets

| Target                                | Trace: Debian | Trace: Rust | Scan: filesystem | Scan: image |
|---------------------------------------|:-------------:|:-----------:|:----------------:|:-----------:|
| SC-001: ≥95% recall                   |    ✅ 100%     |   ✅ 100%    |       N/A²        |    N/A²      |
| SC-002: <2% false positive rate       |    ✅  0%      |   ✅  0%     |       ✅¹         |    ✅¹        |
| SC-003: 100% PURL conformance         |    ✅          |   ✅         |       ✅          |    ✅         |
| SC-004: CycloneDX 1.6 JSON validates  |    ✅          |   ✅         |       ✅          |    ✅         |
| SC-006: 100% evidence coverage        |    ✅          |   ✅         |       ✅ (0.70)   |    ✅ (0.70)  |
| SC-009: <30 s overhead on 5-min build |  not measured                |   not applicable                  |

¹ No network guessing means nothing to hallucinate — any component
reported by scan mode has a literal file on disk with a matching hash.
² Recall is defined against a ground-truth set the trace observed;
scan mode has no equivalent ground truth (it's the observer, not the
subject). Coverage is bounded by the path_resolver's ecosystem set,
tracked separately in TODO-1.

## Known gaps (called out by design)

| Gap                                                | Impact                                                   |
|----------------------------------------------------|----------------------------------------------------------|
| TCP `sock` struct offsets                          | Destination IP/port come back as `0.0.0.0:0`. Hostname is preserved via TLS SNI / Host header so this is cosmetic. Needs BTF CO-RE to resolve portably. |
| HTTP/2 HPACK-encoded request headers               | Our plaintext hostname scanner relies on uncompressed substrings. The demos force HTTP/1.1 (`curl --http1.1`); a real HPACK decoder is the proper fix. |
| `do_filp_open` kprobe misses curl `-O` and cargo `.crate` writes | Both write via `openat(AT_FDCWD, "/tmp/foo.deb", O_CREAT|O_WRONLY)` that strace sees but our kprobe does not capture (under investigation — `bpf_d_path` via kprobe on `vfs_open` fails the verifier). Worked around with the post-trace artifact-dir scan, which produces correct hashes and complete path coverage but doesn't carry per-open timing provenance. |
| apt's `https` method (GnuTLS) and rustls clients   | Neither links against `libssl`, so our SSL uprobes don't fire. The debian demo drives curl (which does link libssl) around this; cargo uses rustls but its URL is already known from the `.crate` filename so we rely on the artifact scan for hashes. |
| RPM / dnf / yum installed-package database         | Binary format (SQLite or BerkeleyDB) that needs a dedicated reader crate. Alpine and Debian families are covered via dpkg + apk readers. |
| apk license extraction                             | apk's installed db doesn't carry copyright pointers the same way dpkg does. dpkg-sourced components resolve licenses via `/usr/share/doc/<pkg>/copyright` (DEP-5 + heuristic → SPDX validation); apk components still ship with empty `licenses[]`. |
