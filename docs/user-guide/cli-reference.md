# CLI reference

mikebom follows a strict `mikebom <noun> <verb>` pattern. Top-level nouns:

- **`sbom`** — SBOM generation, enrichment, verification *(stable)*
- **`policy`** — in-toto layout generation + enforcement *(stable)*
- **`attestation`** — attestation management *(stable)*
- **`trace`** — eBPF build-process tracing *(**experimental**, Linux only)*

> **Experimental** means: the output formats are stable, but the trace-mode
> pipeline adds ~2-3× wall-clock overhead on syscall-heavy builds, requires
> CAP_BPF + CAP_PERFMON, and has coverage gaps on some syscall variants
> (`openat2`, `io_uring`). For most SBOM use cases, prefer `mikebom sbom
> scan` — it produces richer CycloneDX output with no privilege requirements
> and runs on any OS.

Global flags apply to every subcommand and must appear **before** the noun:

```bash
mikebom --offline sbom scan --path .
mikebom --include-dev sbom scan --path .
```

## Global flags

| Flag | Env | Default | Effect |
|---|---|---|---|
| `--offline` | — | off | Disable all outbound network calls (deps.dev, ClearlyDefined). Enrichment falls back to whatever the local filesystem can produce. Useful for air-gapped scanners, reproducible builds, and CI with no internet. |
| `--include-dev` | — | off | Include dev/test/optional dependencies. Affects ecosystems with a dev/prod distinction (npm, Poetry, Pipfile). Included components carry the property `mikebom:dev-dependency = true` so downstream tools can filter them out. |
| `--include-legacy-rpmdb` | `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` | off | Enable reading legacy Berkeley-DB rpmdb (`/var/lib/rpm/Packages`) on pre-RHEL-8 / CentOS-7 / Amazon-Linux-2 images. Default-off preserves milestone-003 behavior (diagnostic log + zero components). The BDB reader itself ships in milestone 004 US4 — the flag threads through today as a no-op until that code lands. |
| `--include-declared-deps` | — | off (`--image`) / on (`--path`) | Include declared-but-not-on-disk dependencies. By default, mikebom emits only components whose bytes are physically present in the scanned tree or image (**artifact SBOM**). When set, also includes: (1) deps.dev-reported transitives not observed locally (`source_type = declared-not-cached`); (2) Maven `pom.xml`-declared direct deps with no matching JAR / `.m2` cache entry (`source_type = workspace`); (3) Maven BFS cache-miss transitives (`source_type = transitive`, no `.pom` on disk). Auto-enabled for `sbom scan --path` scans so source-tree users get a **manifest SBOM** of what *would* be pulled in on build; explicit override for `--image` if you want manifest-style output from a container scan. See `docs/design-notes.md` "Scope: artifact vs manifest SBOM" for the rationale. |

---

## `mikebom trace capture`

**Status:** **Experimental.** Linux-only. On non-Linux hosts this subcommand
errors with a message pointing to Lima / `mikebom-dev`. Adds ~2-3× wall-clock
overhead on syscall-heavy builds; has coverage gaps on `openat2` and
`io_uring`. Prefer `mikebom sbom scan` for most use cases.

Capture a build via eBPF uprobes on `libssl` (`SSL_read` / `SSL_write`) and
kprobes on file operations, produce an in-toto attestation.

```bash
mikebom trace capture --output build.attestation.json -- <command>
mikebom trace capture --target-pid 12345 --output build.attestation.json
```

Exactly one of **`--target-pid <PID>`** or a command after **`--`** is required.
They are mutually exclusive.

| Flag | Default | Purpose |
|---|---|---|
| `--output <path>` | `mikebom.attestation.json` | Attestation output path |
| `--target-pid <pid>` | — | PID to trace (mutually exclusive with `--` command) |
| `--trace-children` | off | Follow forked children of the traced process |
| `--libssl-path <path>` | auto-detect | Override `libssl.so` path for uprobe attachment |
| `--go-binary <path>` | — | Path to a Go binary for Go-specific instrumentation |
| `--ring-buffer-size <bytes>` | `8388608` (8 MB) | BPF ring buffer size (must be power of two) |
| `--timeout <seconds>` | `0` (no timeout) | Abort trace after N seconds |
| `--artifact-dir <path>` | — | Directory to scan for freshly-landed artifact files after the traced command exits. Any recognised package file (`.deb`, `.crate`, `.whl`, `.tar.gz`, …) whose mtime is ≥ trace start is hashed and added to the file-access record. Accepts the flag multiple times or a comma-separated list. |
| `--auto-dirs` | off | Auto-detect artifact directories by matching `argv[0]` against a table of build tools (`cargo` → `$CARGO_HOME/registry/cache`, `pip`, `npm`, `go`, `apt-get`, …). Merges with explicit `--artifact-dir` values; skipped for shell-wrapped commands. |
| `--json` | off | Print a JSON summary to stdout |

The attestation predicate type is
`https://mikebom.dev/attestation/build-trace/v1`; see
[architecture/attestations.md](../architecture/attestations.md) for the schema.

---

## `mikebom trace run`

**Status:** **Experimental.** Linux-only. Same caveats as `trace capture` —
2-3× wall-clock overhead, requires `CAP_BPF + CAP_PERFMON`, coverage gaps on
`openat2` / `io_uring`. Prefer scan-mode unless you specifically need a
trace-backed attestation.

Capture a trace and derive an SBOM from it in one shot. Equivalent to
`trace capture` followed by `sbom generate`.

```bash
mikebom trace run \
  --sbom-output mybuild.cdx.json \
  -- cargo install ripgrep
```

Positional command after `--` is **required**.

| Flag | Default | Purpose |
|---|---|---|
| `--sbom-output <path>` | `mikebom.cdx.json` | SBOM output path |
| `--attestation-output <path>` | `mikebom.attestation.json` | Attestation output path |
| `--format <fmt>` | `cyclonedx-json` | SBOM output format — see [output formats](#output-formats) |
| `--no-enrich` | off | Skip enrichment step (no deps.dev / ClearlyDefined calls) |
| `--include-source-files` | off | Also include observed source files, not just packages. Switches SBOM scope from `packages` to `source`. |
| `--no-hashes` | off | Omit per-component hashes from the SBOM |
| `--trace-children` | off | Follow forked children |
| `--libssl-path <path>` | auto-detect | Override `libssl.so` path |
| `--ring-buffer-size <bytes>` | `8388608` | BPF ring buffer size |
| `--timeout <seconds>` | `0` | Trace timeout |
| `--skip-purl-validation` | off | Skip online PURL existence validation |
| `--lockfile <path>` | — | Path to a lockfile for dependency-relationship enrichment |
| `--artifact-dir <path>` | — | Artifact directory to scan post-trace (see `trace capture`) |
| `--auto-dirs` | off | Auto-detect artifact directories (see `trace capture`) |
| `--json` | off | JSON summary to stdout |

`trace run` currently does not thread the global `--offline` flag through to
the generate step. The enrichment pass is non-fatal on network failure, so
offline users get the same SBOM minus license / CPE upgrades.

---

## `mikebom sbom scan`

**Status:** Implemented. Runs on any platform Rust runs on; no privilege, no eBPF.

Walk a directory or extracted container image, produce a CycloneDX SBOM.

```bash
mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json
mikebom sbom scan --image alpine.tar --output alpine.cdx.json
```

Exactly one of **`--path <DIR>`** or **`--image <TAR>`** is required.

| Flag | Default | Purpose |
|---|---|---|
| `--path <dir>` | — | Directory to walk recursively. Stream-hashes files with recognised package-artifact suffixes (`.deb`, `.crate`, `.whl`, `.tar.gz`, `.jar`, `.gem`, `.apk`, …). |
| `--image <tar>` | — | `docker save` tarball. Extracted to a tempdir (OCI whiteouts honoured), then scanned like `--path`. |
| `--output <[FMT=]PATH>` | per-format default (`mikebom.cdx.json`, `mikebom.spdx.json`, …) | Output path override. Two forms: bare `--output <path>` (applies to the single requested format — rejected with multiple formats) and per-format `--output <fmt>=<path>` (repeatable; each entry retargets one format). The special key `openvex` retargets the OpenVEX sidecar that SPDX emission co-produces when VEX is present — legal only alongside an SPDX format. |
| `--format <fmt>` | `cyclonedx-json` | See [output formats](#output-formats). Comma-separated list + repeatable flag: `--format cyclonedx-json,spdx-2.3-json` produces both from a single scan. Duplicates dedupe silently. |
| `--max-file-size <bytes>` | `268435456` (256 MB) | Skip hashing files larger than this |
| `--no-hashes` | off | Omit per-component content hashes from the SBOM |
| `--deb-codename <value>` | auto | Value to stamp as the `distro=` qualifier on deb PURLs (e.g., `debian-12`, `ubuntu-24.04`, `kali-rolling`). Stamped verbatim. Overrides the value auto-derived from `<root>/etc/os-release` (`ID` + `VERSION_ID` → `distro=<id>-<version_id>`). Despite the flag name, it accepts any string; the canonical shape is `<namespace>-<VERSION_ID>` matching rpm and apk. |
| `--no-package-db` | off (DB reading is on by default) | Skip reading `/var/lib/dpkg/status` and `/lib/apk/db/installed`. Falls back to artefact-file-only scanning. Use when you want to verify a download cache and ignore the installed set. |
| `--no-deep-hash` | off | Skip per-file SHA-256 of installed-package contents. Falls back to a fast SHA-256 of each package's dpkg `.md5sums` file. Produces component-level identity but no `evidence.occurrences[]`. |
| `--json` | off | JSON summary to stdout |

Behaviour notes:

- Enrichment runs inline on scan: deps.dev version info, ClearlyDefined
  concluded licenses, and deps.dev transitive-dep-graph edges (Maven-primary).
  All three respect the global `--offline` flag — under `--offline` they become
  silent no-ops.
- Deb, apk, and RPM components carry a CycloneDX `evidence.identity` block at
  confidence 0.85 with `technique: "manifest-analysis"` — they come from the
  installed-package database, not from observing the install event.
- Artifact-file-resolved components carry confidence 0.70 with
  `technique: "filename"`.
- Maven fat-jars built with the shade-plugin emit nested
  `components[].components[]` entries per shade-relocated ancestor (one
  `pkg:maven/<g>/<a>@<v>` per ancestor declared in the JAR's
  `META-INF/DEPENDENCIES`), tagged with the property
  `mikebom:shade-relocation = true`. Emission is gated on
  bytecode-presence verification — declared-but-not-relocated ancestors
  are dropped. Feature 009; see
  [`docs/ecosystems.md`](../ecosystems.md) and
  [`specs/009-maven-shade-deps/spec.md`](../../specs/009-maven-shade-deps/spec.md).
- `sbom scan` inherits the top-level `--offline`, `--include-dev`,
  `--include-declared-deps`, and `--include-legacy-rpmdb` flags — they
  can be passed either before or after `scan`. See [global flags](#global-flags)
  and [Configuration](configuration.md).

---

## `mikebom sbom generate`

**Status:** Implemented.

Derive a CycloneDX SBOM from an in-toto attestation produced by
`mikebom trace capture`.

```bash
mikebom sbom generate build.attestation.json \
  --output build.cdx.json \
  --scope source \
  --enrich \
  --lockfile Cargo.lock
```

Positional **attestation file** is required.

| Flag | Default | Purpose |
|---|---|---|
| `--output <path>` | `mikebom.cdx.json` | SBOM output path |
| `--format <fmt>` | `cyclonedx-json` | See [output formats](#output-formats) |
| `--scope <kind>` | `packages` | `packages` = resolved PURLs only. `source` = packages plus observed source files (with hashes). |
| `--no-hashes` | off | Omit per-component hashes |
| `--enrich` | off | Run enrichment (license, VEX, supplier). |
| `--lockfile <path>` | — | Path to a lockfile for dependency-relationship enrichment. Auto-detects format (`Cargo.lock`, `package-lock.json`, `go.sum`). Unrecognised formats are logged and skipped. |
| `--deps-dev-timeout <ms>` | `5000` | Timeout per deps.dev API call |
| `--skip-purl-validation` | off | Skip online PURL existence validation |
| `--vex-overrides <path>` | — | VEX override file for manual triage states |
| `--json` | off | JSON summary to stdout |

Note: as of the current code, the only enrichment source wired into the
`EnrichmentPipeline` inside `sbom generate` is `LockfileSource`. Inline
enrichment via deps.dev / ClearlyDefined happens in `sbom scan` but has not
yet been threaded into the `generate` flow — this is why `--enrich` takes
effect but does not currently fetch licenses from deps.dev.

---

## `mikebom sbom enrich`

**Status: Implemented (feature 006 US5).** Detailed documentation is
below in the "`mikebom sbom enrich` — feature 006 US5" section. In
short: accepts one or more RFC 6902 JSON Patch files via `--patch`
and records per-patch provenance on the BOM metadata.

---

## `mikebom attestation validate`

**Status: Implemented.** Validates an attestation file for in-toto /
SBOMit schema conformance (shape checks only — does *not* verify
signatures; use `mikebom sbom verify` for that).

```bash
mikebom attestation validate some.attestation.json
```

Planned purpose: validate an in-toto attestation file for schema conformance.

---

## `mikebom sbom verify` — feature 006 US1

Verify a signed DSSE envelope produced by `mikebom` or any other
SBOMit-compliant tool.

```
mikebom sbom verify <ATTESTATION> [flags]
```

Flags:
- `--public-key <PATH>` — PEM-encoded public key for local-key
  verification (mutually exclusive with `--identity`)
- `--identity <PATTERN>` — keyless identity matcher (email, URL, or
  glob) against the Fulcio cert's SAN
- `--expected-subject <PATH>` — verify on-disk SHA-256 of `PATH`
  matches a subject in the envelope. Repeatable.
- `--layout <PATH>` — enforce an in-toto layout
- `--no-transparency-log` — tolerate keyless envelopes without a
  Rekor inclusion proof
- `--fulcio-url` / `--rekor-url` — custom sigstore endpoints
- `--json` — structured `VerificationReport` on stdout

Exit codes per `specs/006-sbomit-suite/contracts/cli.md`: `0` pass,
`1` crypto failure, `2` envelope failure, `3` layout failure.

## `mikebom policy init` — feature 006 US4

Generate a starter in-toto layout bound to a functionary key.

```
mikebom policy init --functionary-key signing.pub [flags]
```

Flags:
- `--functionary-key <PATH>` *(required)* — PEM public key
- `--step-name <NAME>` — default `build-trace-capture`
- `--expires <DURATION>` — `6m` / `1y` / `18mo` / `2y`; default `1y`
- `--readme <TEXT>` — embedded description
- `--output <PATH>` — default `layout.json`

Use the emitted layout with `mikebom sbom verify --layout …` to enforce
functionary + step-name policy on signed attestations. Layouts are
standard in-toto — any in-toto-aware verifier accepts them.

## Signing flags — `trace capture` / `trace run`

Add one category of new flag to an otherwise-unchanged invocation to
start producing signed DSSE envelopes:

- `--signing-key <PATH>` — local PEM private key (mutually exclusive
  with `--keyless`)
- `--signing-key-passphrase-env <NAME>` — env var name holding the
  passphrase for an encrypted key (no interactive prompt)
- `--keyless` — OIDC → Fulcio → Rekor (CI-friendly; auto-detects
  GitHub Actions)
- `--no-transparency-log` — keyless mode only; skip Rekor upload
- `--fulcio-url` / `--rekor-url` — custom sigstore endpoints
- `--require-signing` — hard-fail if no signing identity configured
- `--subject <PATH>` — explicit subject; repeatable; suppresses
  artifact auto-detection

## `mikebom sbom enrich` — feature 006 US5

Apply one or more RFC 6902 JSON Patch files to a generated CycloneDX
SBOM, recording per-patch provenance (`mikebom:enrichment-patch[N]`)
in the SBOM's top-level `properties[]` array.

```
mikebom sbom enrich <SBOM> --patch <PATCH> [--patch <PATCH>…] [flags]
```

Flags:
- `--patch <PATH>` *(at least one required)* — patch file; repeatable
- `--author <STRING>` — recorded author (defaults to `"unknown"` with
  a warning)
- `--base-attestation <PATH>` — attestation file whose SHA-256 gets
  embedded so verifiers can walk back to the attested source
- `--output <PATH>` — default overwrites the input SBOM

---

## Output formats

The `--format` flag on `sbom scan` accepts a comma-separated list;
the flag itself is repeatable. Duplicates dedupe silently. Default
is `cyclonedx-json`. Every registered format id:

| Value | Status | Default filename |
|---|---|---|
| `cyclonedx-json` | **Stable.** Default. CycloneDX 1.6 JSON. | `mikebom.cdx.json` |
| `spdx-2.3-json` | **Stable.** SPDX 2.3 JSON. Covers all 9 supported ecosystems. Validates clean against the official SPDX 2.3 JSON schema. | `mikebom.spdx.json` |
| `spdx-3-json-experimental` | **[EXPERIMENTAL]** SPDX 3.0.1 JSON-LD. **npm ecosystem only**; non-npm components are filtered out of the `@graph`. License emission, CPE, supplier, and evidence fields are out of stub scope — see `docs/reference/sbom-format-mapping.md` for the full scope contract. Opt-in; the format id carries the `-experimental` suffix so it can't be picked up by accident. | `mikebom.spdx3-experimental.json` |

**OpenVEX sidecar** — when the scan produces VEX statements (via
`ResolvedComponent.advisories`) AND SPDX 2.3 output is requested,
mikebom co-emits an OpenVEX 0.2.0 JSON file alongside the SPDX
file. The SPDX document carries a `DocumentRef-OpenVEX` entry in
`externalDocumentRefs` with a SHA-256 of the sidecar bytes. Use
`--output openvex=<path>` to retarget the sidecar. When the scan
has no advisories, no sidecar is written and no
`externalDocumentRefs` entry appears.

See [architecture/generation.md](../architecture/generation.md) for
the CycloneDX 1.6 mapping details and
[`docs/reference/sbom-format-mapping.md`](../reference/sbom-format-mapping.md)
for the full cross-format data-placement map.
