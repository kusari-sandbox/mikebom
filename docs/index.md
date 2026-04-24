# mikebom documentation

**New here?** Read
[Installation](user-guide/installation.md) → [Quickstart](user-guide/quickstart.md).
That's enough to produce your first CycloneDX SBOM on any supported OS.

Two tracks for everyone else. Pick the one that matches what you're
trying to do.

## Track 1 — Use mikebom

Start here if you want to run the tool on a real codebase, container, or build.

- [Installation](user-guide/installation.md) — prereqs, `cargo build`, Dockerfile.dev, Lima VM
- [Quickstart](user-guide/quickstart.md) — stable recipes (source-tree scan, image scan, cache scan, signed-envelope verify) + the experimental trace-mode recipe
- [CLI reference](user-guide/cli-reference.md) — every `mikebom <noun> <verb>` with flags and examples
- [Configuration](user-guide/configuration.md) — global flags, environment variables, offline mode

**Stability note:** `sbom scan` / `sbom verify` / `policy init` / `sbom enrich`
are stable and run on any OS. `trace capture` / `trace run` are **experimental,
Linux-only** — they add ~2-3× wall-clock overhead and require CAP_BPF +
CAP_PERFMON. For most SBOM use cases, prefer the scan pipeline.

## Track 2 — Understand how mikebom works

Start here if you want to know *why* a particular PURL, license, or CPE came out
the way it did, or contribute to the pipeline.

- [Architecture overview](architecture/overview.md) — the four-stage pipeline
- [Scanning](architecture/scanning.md) — filesystem walk, image extraction, per-ecosystem package DBs
- [Resolution](architecture/resolution.md) — how observations become resolved components
- [Enrichment](architecture/enrichment.md) — deps.dev, ClearlyDefined, lockfile sources
- [Generation](architecture/generation.md) — CycloneDX 1.6 mapping
- [PURLs and CPEs](architecture/purls-and-cpes.md) — canonicalization and multi-candidate CPE emission
- [Licenses](architecture/licenses.md) — declared vs. concluded, SPDX normalization
- [Attestations](architecture/attestations.md) — in-toto Statement v1 + `BuildTracePredicate`
- [Signing](architecture/signing.md) — DSSE envelope signing + verification (feature 006)

## Reference material

- [Ecosystems](ecosystems.md) — per-ecosystem coverage matrix for all nine supported ecosystems (authoritative source of truth)
- [Design notes](design-notes.md) — architectural decisions at the cross-cutting level. Maven layered resolution, source-type markers, CycloneDX shape decisions, known limitations.
- [Changelog](../CHANGELOG.md) — what shipped in which release; dated release notes; deprecations and stability-surface changes.
- [Research](research/) — one-off investigations (e.g. Go binary scope analysis)
