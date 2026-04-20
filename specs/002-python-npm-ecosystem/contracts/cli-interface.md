# CLI Contract — Python + npm Ecosystem Support

Surfaces the CLI changes this milestone introduces. Existing flags are shown for context but are not owned by this spec.

## New global flag

### `--include-dev`

**Position**: global (alongside existing `--offline`), defined on the root `Cli` struct in `mikebom-cli/src/main.rs`.

**Type**: boolean (clap `#[arg(long, global = true)]`).

**Default**: `false`.

**Semantics**:
- When `false` (default), the scanner excludes packages marked dev-only by any ecosystem that carries the distinction:
  - npm `devDependencies` + `optionalDependencies` + entries with `dev: true` in `package-lock.json` / `pnpm-lock.yaml`.
  - Poetry `category = "dev"` packages (v1) / packages not in group `"main"` (v2).
  - Pipfile entries under the `develop` section.
- When `true`, the scanner includes those entries; each dev-flagged component gets a `mikebom:dev-dependency = true` property emitted at `component.properties[]`.
- Ignored by ecosystems that don't carry the distinction: Python venv dist-info scans, `requirements.txt`, deb, apk, cargo, go, rpm.

**Propagation**: the flag flows from `Cli` → `sbom_cmd::execute(cmd, offline, include_dev)` → `scan_cmd::execute(args, offline, include_dev)` → `scan_fs::scan_path(..., include_dev)` → each ecosystem reader. Trace mode (`generate`) receives the flag too but currently ignores it (not applicable to trace data sources).

**Help text**:
```
--include-dev
    Include development / test / optional dependencies in the SBOM.
    Off by default: the scanner emits only production components.
    Affects ecosystems that carry a dev/prod distinction (npm, Poetry,
    Pipfile). Venv dist-info scans and requirements.txt scans are
    unaffected — they do not carry a dev/prod marker.
```

---

## Existing flags (unchanged — listed for contract completeness)

| Flag | Scope | Notes |
|------|-------|-------|
| `--offline` | global | Must suppress deps.dev enrichment for Python/npm components too — no new wiring (the deps.dev source already reads the flag). |
| `--path <DIR>` | `sbom scan` | Must accept any directory; Python + npm detection runs in addition to the existing deb/apk/cargo detection. |
| `--image <TAR>` | `sbom scan` | Must trigger image-mode Python / npm walks in addition to the existing dpkg/apk paths. |
| `--output <PATH>` | `sbom scan` | Unchanged. |
| `--format cyclonedx-json` | `sbom scan` | Only supported format this milestone. SPDX output lands in a later milestone (TODO-5). |
| `--no-hashes` | `sbom scan` | Applies to new ecosystems too — component `hashes[]` is suppressed. |
| `--no-package-db` | `sbom scan` | Applies to Python + npm too — when set, skip dist-info and lockfile readers; fall through to filename-only matches. |
| `--no-deep-hash` | `sbom scan` | No effect on Python/npm this milestone (no per-file deep hashing in scope). Preserved for compatibility. |
| `--max-file-size <BYTES>` | `sbom scan` | Applies uniformly. |
| `--deb-codename <NAME>` | `sbom scan` | No effect on Python/npm. |
| `--json` | `sbom scan` | Unchanged. |

---

## Exit codes

Existing:
- `0` — success, SBOM written.
- `non-zero` — any fatal failure during scan.

New hard-fail case this milestone introduces:

| Trigger | Exit | Stderr message |
|---------|------|----------------|
| Scanned project contains a `package-lock.json` whose root declares `"lockfileVersion": 1`. | non-zero (specific code TBD in tasks — match existing convention of `2` for input-validation errors) | `error: package-lock.json v1 not supported; regenerate with npm ≥7` |

Behaviour:
- If ANY other lockfile or source in the same project succeeds (e.g. a sibling `pnpm-lock.yaml` AND a v1 `package-lock.json`), the v1 lockfile's refusal still fires. The SBOM is NOT written partially; the command errors out so consumers never receive a half-scanned output. The user's fix is deterministic (`npm install` with npm ≥7).
- `tracing::error!` log fires alongside stderr, so consumers that redirect stderr still see the reason in their tracing pipeline.

No other new exit codes.

---

## Invocation examples

### Directory scan — Python venv + default behaviour

```bash
mikebom sbom scan --path . --output sbom.cdx.json
# exits 0 on success
# SBOM contains pypi components (one per dist-info found) plus any
# deb/apk/cargo components from existing readers
```

### Directory scan — include dev deps

```bash
mikebom sbom scan --path . --output sbom.cdx.json --include-dev
# same plus poetry/Pipfile/npm dev-flagged components
# each dev component carries mikebom:dev-dependency = true property
```

### Image scan — npm application

```bash
mikebom sbom scan --image app.tar --output sbom.cdx.json --json
# reads image config WORKDIR (when available), walks node_modules/ under it
# AND any global /usr/lib/node_modules/, AND the image's deb/apk db
# --json emits a summary { components, relationships, complete_ecosystems } to stdout
```

### Offline + include-dev combined

```bash
mikebom --offline sbom scan --path . --include-dev --output sbom.cdx.json
# no deps.dev calls; local parsers populate everything available locally;
# devDependencies included; dev flag propagates to property output
```

### Refusal path — legacy lockfile

```bash
cd project-with-old-lockfile
mikebom sbom scan --path . --output sbom.cdx.json
# exits non-zero (no sbom.cdx.json written)
# stderr: "error: package-lock.json v1 not supported; regenerate with npm ≥7"
# user fix: rm -rf node_modules && npm install
```
