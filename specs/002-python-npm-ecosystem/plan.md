# Implementation Plan: Python + npm Ecosystem Support

**Branch**: `002-python-npm-ecosystem` | **Date**: 2026-04-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/002-python-npm-ecosystem/spec.md`

## Summary

Extend `mikebom sbom scan` (filesystem-scan mode + container-image-scan mode) to emit valid CycloneDX components for Python and Node.js ecosystems, closing Gap #1 from the `fancy-puzzling-garden` roadmap. Two new manifest readers plug into the existing `scan_fs/package_db/` dispatcher alongside `dpkg.rs` and `apk.rs`, and the existing `path_resolver.rs` picks up `.whl` / `.tar.gz` / `.tgz` fallback matchers. The result is dependency-tree-complete, reference-implementation-conformant SBOMs for both ecosystems, with dev/prod scoping controlled by a new global `--include-dev` flag. No architectural rework; the existing dedup → CPE synthesis → per-ecosystem compositions → deps.dev enrichment pipeline handles the new components unchanged.

## Technical Context

**Language/Version**: Rust stable (user-space only; no eBPF touched in this milestone)
**Primary Dependencies**:
- Existing workspace: `mikebom-common` (`Purl`, `SpdxExpression`, `ContentHash`, `encode_purl_segment`), `mikebom-cli::scan_fs` (dispatcher, walker, `PackageDbEntry`, `FileOccurrence`), `mikebom-cli::resolve::path_resolver`, `mikebom-cli::generate::cpe`, `mikebom-cli::enrich::depsdev_source`, `mikebom-cli::enrich::deps_dev_system`.
- New (within `mikebom-cli`): `toml 0.8` for `poetry.lock` + root `pyproject.toml` reads; `serde_yaml 0.9` for `pnpm-lock.yaml`; `serde_json` (workspace) for `package-lock.json` + `Pipfile.lock`. No new workspace crates.

**Storage**: N/A — pure filesystem reads. All state lives in memory for the lifetime of a scan.
**Testing**: `cargo test --workspace` (unit). New fixture directories under `tests/fixtures/python/`, `tests/fixtures/npm/`, `tests/fixtures/images/python-app/`, `tests/fixtures/images/node-app/`.
**Target Platform**: Any host (Linux / macOS / Windows for directory scans; Docker `save`-tarball supplies the filesystem in image mode). No privileged operations, no kernel support required.
**Project Type**: CLI tool (extension of the existing three-crate workspace).
**Performance Goals**: Per SC-007 — `mikebom sbom scan --path .` completes in under 10 seconds on a 500-package Python venv or 1000-package `node_modules/` tree, excluding network latency for deps.dev enrichment.
**Constraints**:
- Zero refactoring of existing scan pipeline (dedup, CPE, compositions, deps.dev) — the new readers emit `PackageDbEntry` records that flow through the existing path unchanged.
- No new workspace crate (Constitution VI).
- No `.unwrap()` in production (Constitution IV).
- 100% `packageurl-python` reference-implementation PURL conformance (SC-004 + prior-round baseline).

**Scale/Scope**: Single-project monorepo `node_modules/` trees up to ~10 000 packages; Python venvs up to ~2 000 installed packages; individual lockfiles up to ~5 MiB.

## Constitution Check

*Gate: must pass before Phase 0 research. Re-checked after Phase 1.*

| Principle | Check | Status |
|-----------|-------|--------|
| I. Pure Rust, Zero C | No C sources or FFI shims introduced. All new parsers are pure Rust. | ✅ |
| II. eBPF-Only Observation / Boundary #1 (No lockfile-based dependency discovery) | **Scoped to trace mode.** This milestone extends existing *scan mode* (`FilesystemScan` + `ContainerImageScan` generation contexts, shipped in milestone 001), which is a separate sanctioned code path with its own confidence tier (0.85 manifest-analysis) and generation-context annotation — consumers can distinguish a scan-mode SBOM from a trace-mode SBOM at a glance. No lockfile is consulted in trace mode; scan mode has always treated the scanned filesystem (including lockfiles on it) as its authoritative observation source. | ✅ (scope-checked; see Phase 0 research R1) |
| III. Fail Closed | Scan-mode failures log at `debug` and continue (established precedent from deb/apk). The one hard-fail this spec adds is the `package-lock.json` v1 refusal (exits non-zero with actionable message) — that's "fail closed on unambiguous input the scanner deliberately won't trust", the stronger version of the principle. | ✅ |
| IV. Type-Driven Correctness | Every emitted PURL flows through `Purl::new` (`mikebom-common/src/types/purl.rs`). Licenses flow through `SpdxExpression::try_canonical`. Hashes through `ContentHash`. No raw `String` passed across module boundaries for these values. | ✅ |
| V. Specification Compliance | PURL reference-impl conformance enforced via golden-fixture tests (SC-004); CycloneDX 1.6 unchanged (no new top-level fields); SPDX unchanged (license expressions canonicalise through existing `try_canonical`). | ✅ |
| VI. Three-Crate Architecture | No new workspace crate. New modules live under existing `mikebom-cli/src/scan_fs/package_db/` and `mikebom-cli/src/resolve/path_resolver.rs`. | ✅ |
| VII. Test Isolation | All new tests are unit-level, no eBPF, no privilege requirement. Run in standard CI. | ✅ |
| VIII. Completeness | Three-tier authority model (venv > lockfile > `requirements.txt` / `package.json` fallback) maximises coverage per scanned project. Drift rules (Python: venv wins; npm: `node_modules/` wins) prevent silent omissions. | ✅ |
| IX. Accuracy | Range-version components (from `requirements.txt` / fallback `package.json`) carry an empty `version` + `mikebom:requirement-range` property so consumers can distinguish "pinned, real" from "ranged, speculative". Confidence tiers (0.85 vs 0.70) encode the authority split. | ✅ |
| X. Transparency | Per-ecosystem `aggregate: complete` compositions (pypi / npm added to the existing deb / apk rollup); confidence annotations on every component; `mikebom:dev-dependency`, `mikebom:requirement-range`, and `mikebom:source-type` properties surface important scoping facts; deps.dev enrichment tagged in `evidence.identity.tools` as established in the prior round. | ✅ |
| XI. Enrichment | Python + npm already mapped in `deps_dev_system_for()`. This spec doesn't add enrichment infra; it adds readers whose output gets enriched by the existing pass. Offline mode inherited. | ✅ |
| XII. External Data Source Enrichment / Boundary #1 (scope of lockfile reads) | The "trace-mode lockfiles = enrichment only, no new components" rule is orthogonal to this spec — scan mode is a different GenerationContext. Scan mode has always discovered components from filesystem state, including package databases and (in this milestone) lockfiles. The constitution's v1.2.0 amendment explicitly permits lockfile enrichment; we go further by allowing scan-mode discovery, which is consistent with the shipped precedent for deb/apk. | ✅ (scope-checked; see Phase 0 research R1) |

**Gate result: PASS.** The Principle-II / Boundary-#1 question is a scope clarification, not a violation — the existing milestone-001 architecture defines three explicit `GenerationContext` values (`BuildTimeTrace`, `FilesystemScan`, `ContainerImageScan`), and trace-mode's lockfile prohibition only applies when emitting under `BuildTimeTrace`. Phase 0 research captures the lineage and the distinguishing CycloneDX markers a consumer uses to tell the modes apart.

## Project Structure

### Documentation (this feature)

```text
specs/002-python-npm-ecosystem/
├── plan.md                        # This file (/speckit.plan)
├── research.md                    # Phase 0 output
├── data-model.md                  # Phase 1 output
├── quickstart.md                  # Phase 1 output
├── contracts/
│   ├── cli-interface.md           # --include-dev flag, exit codes
│   └── component-output.md        # New CycloneDX properties + per-ecosystem compositions
├── checklists/
│   └── requirements.md            # Already generated by /speckit.specify
└── tasks.md                       # Generated later by /speckit.tasks
```

### Source code (repository root)

```text
mikebom-cli/src/
├── scan_fs/
│   ├── mod.rs                     # extend scan_path: wire new readers + --include-dev flag through
│   ├── package_db/
│   │   ├── mod.rs                 # dispatcher: add pip + npm readers alongside dpkg + apk
│   │   ├── dpkg.rs                # (unchanged)
│   │   ├── apk.rs                 # (unchanged)
│   │   ├── pip.rs                 # NEW — dist-info walker + poetry.lock + Pipfile.lock + requirements.txt
│   │   └── npm.rs                 # NEW — package-lock.json (v2/v3) + pnpm-lock.yaml + node_modules/
│   │                              #       walker + root package.json fallback (FR-007a)
│   ├── docker_image.rs            # (unchanged; already reads image config for WORKDIR in a follow-up TODO
│   │                              #  — this milestone uses the existing API surface)
│   └── walker.rs                  # (unchanged)
├── resolve/
│   ├── path_resolver.rs           # extend: resolve_pip_path() for *.whl / *.tar.gz,
│   │                              #         resolve_npm_path() for ~/.npm/_cacache/ tarballs
│   └── deduplicator.rs            # (unchanged; already keys by PURL)
├── generate/
│   └── cpe.rs                     # verify existing pypi + npm match arms cover new shapes;
│                                  # add npm-scope-as-vendor candidate if missing (FR-014)
├── enrich/
│   ├── depsdev_source.rs          # (unchanged; pypi + npm already mapped)
│   └── deps_dev_system.rs         # (unchanged)
└── cli/
    ├── mod.rs                     # add global --include-dev flag parallel to --offline
    └── scan_cmd.rs                # thread --include-dev into scan_path

mikebom-common/src/
└── resolution.rs                  # add `is_dev: bool` to PackageDbEntry and ResolvedComponent for
                                   # downstream `mikebom:dev-dependency` property emission;
                                   # append `pypi` and `npm` to the `ecosystem` list docs

tests/fixtures/                    # NEW fixture tree
├── python/
│   ├── simple-venv/               # 50-package venv with mixed licenses
│   ├── poetry-project/            # poetry.lock + pyproject.toml, no venv
│   ├── pipfile-project/           # Pipfile.lock + dev section
│   ├── requirements-only/         # requirements.txt with pinned + ranged lines
│   └── pyproject-only/            # pyproject.toml [project.dependencies] — scanner must emit empty
└── npm/
    ├── lockfile-v3/               # package-lock.json v3 with prod + dev split
    ├── lockfile-v1-refused/       # v1 lockfile fixture for FR-006 refusal test
    ├── pnpm-v8/                   # pnpm-lock.yaml v8
    ├── node-modules-walk/         # flat node_modules/ without lockfile
    ├── package-json-only/         # FR-007a fallback (uninstalled project)
    └── scoped-package/            # @org/name scoped dep
```

**Structure Decision**: single-project extension (Option 1 from the template). The feature adds two new modules under `mikebom-cli/src/scan_fs/package_db/` and extends existing files in `resolve/`, `cli/`, and `generate/`. No new crates, no new top-level directories beyond the per-feature test-fixture layout. This keeps the three-crate constitution boundary (Principle VI) unchanged and re-uses every pipeline convention already battle-tested on deb + apk.

## Complexity Tracking

No constitution violations. Two items worth pre-surfacing so reviewers don't re-argue them:

| Item | Why it's here | Why it's not a violation |
|------|---------------|--------------------------|
| Two new external parsing dependencies (`toml 0.8`, `serde_yaml 0.9`) | Poetry lockfiles and pnpm lockfiles use formats the workspace doesn't currently parse | Both crates are pure-Rust, widely audited, MIT/Apache-2.0 dual-licensed. No C FFI (Principle I); no kernel-space impact. Already used across the Rust ecosystem at scale. |
| Filesystem-scan mode reads lockfiles as a dependency source | Constitution Principle II + Boundary #1 restrict lockfile *discovery* | Scope restriction to TRACE mode only, per constitution v1.2.0 amendment and milestone-001's explicit `GenerationContext` enum. Scan mode is a sanctioned separate path with its own confidence tier (0.85) and output annotation. Documented in Phase 0 research R1. |
