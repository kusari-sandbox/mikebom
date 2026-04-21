# Architecture overview

mikebom is organized as a four-stage pipeline. Evidence flows in at the left
— eBPF-captured events from a live build, or filesystem contents from a scan
— and a CycloneDX 1.6 SBOM flows out at the right.

```
┌──────────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
│  evidence    │   │          │   │          │   │          │   │              │
│              ├──▶│   SCAN   ├──▶│ RESOLVE  ├──▶│  ENRICH  ├──▶│   GENERATE   │
│  attestation │   │          │   │          │   │          │   │              │
│  filesystem  │   │          │   │          │   │          │   │  CycloneDX   │
└──────────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────────┘
```

Each stage has a single clear job and a clear output type. The stages are
separate because the *sources* of evidence differ (the build trace sees TLS
events; the filesystem sees package DBs; deps.dev sees the package registry),
and the rules for combining them have to be explicit.

## The four stages at a glance

| Stage | Input | Output | Key entry points |
|---|---|---|---|
| **Scan** | An attestation (for trace mode) **or** a directory / container image (for scan mode). | Raw, un-deduplicated candidate components + raw relationships. | `mikebom-cli/src/scan_fs/mod.rs` (scan-mode root), `mikebom-cli/src/resolve/pipeline.rs::ResolutionPipeline::resolve` (trace-mode root — resolves attestation events into components). |
| **Resolve** | Candidate components from multiple sources (URL match, hash match, file path match, package DB). | Deduplicated `ResolvedComponent[]`. | `mikebom-cli/src/resolve/deduplicator.rs`, `mikebom-cli/src/resolve/pipeline.rs` |
| **Enrich** | Resolved components. | Components with licenses / supplier / external references filled in, plus additional dependency relationships. | `mikebom-cli/src/enrich/pipeline.rs::EnrichmentPipeline` (for `sbom generate`), plus inline calls in `mikebom-cli/src/cli/scan_cmd.rs` (for `sbom scan`). |
| **Generate** | `ResolvedComponent[]` + `Relationship[]` + trace integrity counters. | CycloneDX 1.6 JSON. | `mikebom-cli/src/generate/cyclonedx/builder.rs::CycloneDxBuilder::build` |

## Where the stages live

- **Scan mode** (`mikebom sbom scan`): `cli/scan_cmd.rs` orchestrates the
  pipeline. It walks the filesystem / extracts the image, calls `scan_fs`
  which invokes each per-ecosystem `package_db/*` module, then runs deps.dev
  + ClearlyDefined + deps.dev-graph enrichers inline, then hands the
  deduplicated component set to the CycloneDX builder.
- **Trace mode** (`mikebom trace run` → `sbom generate`): `cli/run.rs` runs
  the eBPF capture, writes the attestation, then delegates to
  `cli/generate.rs` which loads the attestation, runs `ResolutionPipeline` to
  turn connections + file ops into components, runs `EnrichmentPipeline`
  (lockfile source if `--lockfile` was provided), and hands the result to the
  same CycloneDX builder.

Both paths produce structurally identical CycloneDX output. The only
user-visible difference is `metadata.component.properties.mikebom:generation-context`:
`build-time-trace` vs. `filesystem-scan` vs. `container-image-scan`.

## Why a four-stage pipeline

Three reasons the stages are separate:

1. **Sources differ.** Trace mode's primary evidence is TLS SNI + URL +
   content hash; scan mode's primary evidence is an on-disk file path +
   installed-package DB stanza. Fusing these into one stage would tangle the
   rules.
2. **Resolve must deduplicate across techniques.** The same package can be
   reached via URL pattern (0.95), hash match (0.90), package DB (0.85), and
   file path (0.70). The deduplicator merges them on `(ecosystem, name,
   version)` and picks the highest-confidence evidence. See
   [resolution.md](resolution.md).
3. **Enrichment is replaceable.** deps.dev and ClearlyDefined are external
   services with their own failure modes. They run *after* resolution so a
   network outage can never cause mikebom to emit fewer components — just
   less-enriched ones.

## What each stage is *not* responsible for

- **Scan does not decide identity.** It produces candidate components and
  hands them to resolve. Same crate found via both URL match and file walk →
  two candidates; resolve merges them.
- **Resolve does not fetch from the network.** The hash-match resolution step
  does call deps.dev (for `sbom generate` only), but only to *lookup* a hash
  that's already in the attestation — it doesn't add new data beyond
  name/version lookup. All network enrichment (licenses, VCS, dep-graph) is in
  Enrich.
- **Enrich does not create unknown components out of nothing.** The
  `EnrichmentPipeline` has a guard rail at `enrich/pipeline.rs` that filters
  any relationship whose source or target is not already in the component set.
  The one exception is `deps_dev_graph.rs` which deliberately emits coords
  marked `source_type = "declared-not-cached"` for transitive deps discovered
  via deps.dev that have no local presence — these flow as components, not
  just relationships.
- **Generate does not invent identity fields.** PURLs, CPEs, licenses, hashes
  are populated by the earlier stages. Generate arranges them into the
  CycloneDX 1.6 shape.

## Cross-cutting concerns

These apply throughout the pipeline:

- **Generation context** (`GenerationContext` in
  `mikebom-common/src/attestation/metadata.rs`) is stamped on every component
  and on the SBOM's `metadata.component.properties`. Values:
  `BuildTimeTrace`, `FilesystemScan`, `ContainerImageScan`. Downstream
  consumers use this to know how much to trust the result.
- **Evidence technique** (`ResolutionTechnique` in
  `mikebom-common/src/resolution.rs`) is stamped on every resolved component.
  `UrlPattern` 0.95 (build-time), `HashMatch` 0.90 (deps.dev lookup),
  `PackageDatabase` 0.85 (installed-package DB), `FilePathPattern` 0.70
  (filesystem artifact), `HostnameHeuristic` 0.40 (logged only, never creates
  a component). Higher-confidence techniques win in the deduplicator.
- **Provenance** (`EnrichmentProvenance` in
  `mikebom-common/src/resolution.rs`) is attached to every enrichment-derived
  relationship: `source` identifies which enricher contributed the edge
  (`deps.dev`, `Cargo.lock`, `ClearlyDefined`), `data_type` identifies what
  kind of data (`dependency-graph`, `license`).

## Reading more

- [Scanning](scanning.md) — filesystem walker, image scanner, `package_db/*`
- [Resolution](resolution.md) — deduplication, confidence ordering
- [Enrichment](enrichment.md) — four sources, two wiring paths
- [Generation](generation.md) — CycloneDX 1.6 mapping, evidence, compositions
- [PURLs and CPEs](purls-and-cpes.md) — canonicalization and CPE candidates
- [Licenses](licenses.md) — declared vs. concluded
- [Attestations](attestations.md) — in-toto Statement v1 schema

The running architectural changelog is in
[`docs/design-notes.md`](../design-notes.md). Anything dated (and most
ecosystem-specific sharp edges) lives there — this page links into it rather
than duplicating.
