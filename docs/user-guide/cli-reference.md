# CLI reference

mikebom follows a strict `mikebom <noun> <verb>` pattern. Top-level nouns:

- **`trace`** — eBPF build-process tracing
- **`sbom`** — SBOM generation, enrichment, validation, comparison
- **`attestation`** — attestation management

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

---

## `mikebom trace capture`

**Status:** Implemented (Linux only). On non-Linux hosts this subcommand errors
with a message pointing to Lima / `mikebom-dev`.

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

**Status:** Implemented (Linux only).

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
| `--output <path>` | `mikebom.cdx.json` | SBOM output path |
| `--format <fmt>` | `cyclonedx-json` | See [output formats](#output-formats). Only `cyclonedx-json` is actually written today. |
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

## `mikebom sbom compare`

**Status:** Implemented.

Compare mikebom's CycloneDX output against syft, trivy, and a ground-truth
dependency list. Emits a markdown report with recall, precision, and
evidence-coverage metrics; optional JSON summary to stdout.

```bash
mikebom sbom compare \
  --mikebom mikebom.cdx.json \
  --syft syft.cdx.json \
  --trivy trivy.cdx.json \
  --truth Cargo.lock \
  --ecosystem cargo \
  --output report.md \
  --json
```

| Flag | Required | Purpose |
|---|---|---|
| `--mikebom <path>` | yes | CycloneDX JSON from mikebom |
| `--syft <path>` | no | CycloneDX JSON from syft |
| `--trivy <path>` | no | CycloneDX JSON from trivy |
| `--truth <path>` | yes | Ground truth: `Cargo.lock`, `dpkg-query -W --showformat='${Package}\t${Version}\t${Architecture}\n'` output, or raw PURL list (one per line, starting with `pkg:`) |
| `--ecosystem <eco>` | yes | `cargo` or `deb` (scopes the comparison; PURLs outside this ecosystem are filtered out before the diff) |
| `--output <path>` | yes | Markdown report output path |
| `--json` | no | Print a JSON summary to stdout |

PURLs are canonicalized (lowercased, non-identity qualifiers dropped, `%2b` /
`%3a` decoded) before comparison so minor encoding differences don't inflate
the "unique" sets. See [`EVALUATION.md`](../../EVALUATION.md) for real report
output.

---

## `mikebom sbom enrich`

**Status: Planned (Phase 6 / US4).** The subcommand is wired into `--help` but
currently errors with `enrich command not yet implemented — see Phase 6 (US4)`.

Planned purpose: add license, VEX, and supplier metadata to an existing SBOM
file.

---

## `mikebom sbom validate`

**Status: Planned (Phase 7 / US5).** Currently errors with
`validate command not yet implemented — see Phase 7 (US5)`.

Planned purpose: validate an SBOM or attestation for CycloneDX / SPDX
conformance.

---

## `mikebom attestation validate`

**Status: Planned (Phase 7 / US5).** Currently errors with
`attestation validate not yet implemented — see Phase 7 (US5)`.

Planned purpose: validate an in-toto attestation file for schema conformance.

---

## Output formats

The `--format` flag on `sbom scan`, `sbom generate`, and `trace run` accepts:

| Value | Status |
|---|---|
| `cyclonedx-json` | Implemented. Default. CycloneDX 1.6 JSON. |
| `cyclonedx-xml` | **Partial (stub).** Accepted as a value; written output is currently CycloneDX JSON regardless. |
| `spdx-json` | **Partial (stub).** Accepted as a value; written output is currently CycloneDX JSON regardless. |

See [architecture/generation.md](../architecture/generation.md) for the
CycloneDX 1.6 mapping details.
