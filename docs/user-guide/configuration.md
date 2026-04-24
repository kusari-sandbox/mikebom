# Configuration

mikebom has no configuration file today. Everything is set via CLI flags or
environment variables.

## Global flags

Global flags apply to every subcommand and must appear before the noun
(`mikebom --offline sbom scan ...`, not `mikebom sbom scan --offline`).

| Flag | Env var | Effect |
|---|---|---|
| `--offline` | — | Disables all outbound HTTP calls. Enrichment (deps.dev, ClearlyDefined) becomes a no-op. The scanner still produces a complete SBOM from local sources. |
| `--include-dev` | — | Include dev / test / optional dependencies for ecosystems that carry the distinction (npm, Poetry, Pipfile). Emitted with property `mikebom:dev-dependency = true`. |
| `--include-legacy-rpmdb` | `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` | Enable legacy Berkeley-DB rpmdb (`/var/lib/rpm/Packages`) reading. Default-off preserves milestone-003 behavior; the BDB reader ships in milestone 004 US4 — the flag threads through today as a no-op until that code lands. |

## Environment variables

| Var | Effect |
|---|---|
| `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` | Equivalent to `--include-legacy-rpmdb`. |
| `RUST_LOG=<filter>` | Set the `tracing` log filter. Default is `info`. Useful values: `debug` (verbose), `mikebom_cli=trace` (very verbose, mikebom-only). Logs go to stderr. |
| `HOME` | Used by `trace capture --auto-dirs` to resolve tool caches (`$HOME/.cargo/...`). |
| `CARGO_HOME` | Overrides the cargo cache location when `--auto-dirs` is active. |
| `VIRTUAL_ENV` | Used by `--auto-dirs` to detect Python virtualenv directories. |
| `GOPATH` | Used by `--auto-dirs` to detect Go module caches. |

## Offline mode semantics

Under `--offline`, mikebom disables:

- **deps.dev version info** — no license lookups from deps.dev, no external
  references (VCS, issue tracker) resolved online.
- **ClearlyDefined concluded licenses** — no `concluded_licenses[]` enrichment.
- **deps.dev transitive dep-graph** — Maven transitive edges from shaded JARs
  or cold `~/.m2` caches are not filled in.
- **Hash resolution via deps.dev** — during `sbom generate`, the resolution
  pipeline's hash-match step is skipped.

Offline mode still produces a complete CycloneDX SBOM with:

- Every component that local lockfiles / installed-package DBs / manifests
  declared (the full declared tree for ecosystems whose lockfiles encode it).
- All declared licenses from local manifests (e.g. `dpkg copyright`, Cargo.toml
  `license` field, npm `package.json` `license` field).
- All component hashes that local sources provided (Cargo.lock `checksum`,
  `package-lock.json` `integrity`, Maven sidecar `.jar.sha512`, PyPI
  `requirements.txt --hash=`).
- Full dependency graph from installed-package DBs (dpkg `Depends:`, apk `D:`,
  rpm `REQUIRES`) and from lockfiles that encode the tree.

What changes under `--offline`: licenses for cargo crates drop sharply because
crates.io doesn't publish licenses into `Cargo.lock` — they only come through
the deps.dev enrichment pass.

## Where flags are *not* interchangeable with env vars

Today only `MIKEBOM_INCLUDE_LEGACY_RPMDB` has an env-var form. `--offline` and
`--include-dev` must be set via flag. This matches the principle that
network behavior and filter state are per-invocation, not per-environment.

## Permission model

- **`trace capture` / `trace run`** require Linux kernel ≥ 5.8 and eBPF
  privilege — in practice, either root or a `--privileged` container.
- **`sbom scan` / `sbom generate` / `sbom verify` / `sbom enrich`** run
  unprivileged on any platform Rust compiles on.
- mikebom never writes outside its explicitly specified output paths (default:
  CWD). It does not modify the directories it scans.
