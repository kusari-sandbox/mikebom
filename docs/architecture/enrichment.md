# Enrichment

Enrichment adds licenses, supplier / VCS / issue-tracker references, and
dependency-graph edges that the local scan couldn't produce on its own. It
runs *after* resolution so a network outage or a deps.dev rate-limit can
never reduce the set of components the SBOM emits — just the metadata on
them.

**Key files:**

- `mikebom-cli/src/enrich/source.rs` — the `EnrichmentSource` trait.
- `mikebom-cli/src/enrich/pipeline.rs` — `EnrichmentPipeline` with
  source-registration, per-source error tolerance, and the known-PURL guard
  rail.
- `mikebom-cli/src/enrich/lockfile_source.rs` — `Cargo.lock` /
  `package-lock.json` / `go.sum` dependency-edge enricher.
- `mikebom-cli/src/enrich/depsdev_source.rs` + `deps_dev_client.rs` +
  `deps_dev_system.rs` — deps.dev `GetVersion` for declared licenses and
  external references.
- `mikebom-cli/src/enrich/deps_dev_graph.rs` — deps.dev `:dependencies`
  endpoint for transitive edges (Maven-primary).
- `mikebom-cli/src/enrich/clearly_defined_source.rs` +
  `clearly_defined_client.rs` + `clearly_defined_coord.rs` — ClearlyDefined
  curated concluded licenses.

## Two wiring paths

Enrichment is plugged in two different ways depending on which subcommand is
running:

| Subcommand | Wiring | Sources attached |
|---|---|---|
| `sbom generate` / `trace run` | `EnrichmentPipeline` in `cli/generate.rs` | Lockfile only (if `--lockfile` is passed) |
| `sbom scan` | Direct calls in `cli/scan_cmd.rs` | deps.dev version, ClearlyDefined, deps.dev-graph (all three, inline) |

The split is historical: `sbom scan` was wired to deps.dev / ClearlyDefined
directly when those sources were added, and they have not yet been threaded
through the `EnrichmentPipeline` / `sbom generate` path. `sbom generate`
today calls `EnrichmentPipeline::enrich` with only a `LockfileSource`
registered, so while its `--enrich` flag exists and the lockfile-edge
behavior works, the deps.dev / ClearlyDefined enrichment does not yet fire
from trace-mode SBOMs. See
[design-notes §deps.dev policy (critical)](../design-notes.md#depsdev-policy-critical)
for the policy that governs when these come together.

Both paths share the same `ResolvedComponent` shape, so any source can be
moved between paths without touching the component model.

## The `EnrichmentSource` trait

```rust
trait EnrichmentSource {
    fn name(&self) -> &str;
    fn enrich_relationships(&self, components: &[ResolvedComponent])
        -> anyhow::Result<Vec<Relationship>>;
    fn enrich_metadata(&self, component: &mut ResolvedComponent)
        -> anyhow::Result<()>;
}
```

Two methods because a source can contribute either edges (the lockfile knows
A→B relationships), metadata on a component (deps.dev knows licenses and
VCS URLs), or both. Failures from either method are logged as warnings and
the pipeline continues with other sources; the SBOM still emits what it had.

## The four sources

### 1. LockfileSource (`lockfile_source.rs`)

Authoritative dependency edges from machine-readable lockfiles. Auto-detects
format from the filename:

- `Cargo.lock` — TOML, `[[package]]` arrays with `dependencies`.
- `package-lock.json` — v2 / v3 format.
- `go.sum` — Go module checksums.

Contributes `enrich_relationships` only; does not touch component metadata.
Lockfile entries that refer to components not in the resolved set are dropped
by the pipeline guard rail.

### 2. DepsDevSource (`depsdev_source.rs`)

Calls deps.dev's `GetVersion` endpoint per component. Fills in:

- **Declared licenses** — `component.licenses[]` (with `acknowledgement:
  "declared"` in the CycloneDX output).
- **External references** — `externalReferences[]` with types `vcs`,
  `website`, `issue-tracker` from deps.dev's `VersionInfo.links`. A `vcs`
  entry drives sbomqs's `comp_with_source_code` metric.
- **deps.dev match provenance** — stamped on the component as property
  `mikebom:deps-dev-match = <system>:<name>@<version>` so downstream tools
  can see exactly which deps.dev record contributed.

Supported ecosystems (deps.dev's own index):

- cargo, npm, pypi, go, maven, nuget → enrichment runs.
- deb, apk, gem, generic, github, docker → skipped silently.

Ecosystem-specific package-name construction (`deps_dev_system.rs`):

- **Maven**: `groupId:artifactId` (the raw artifactId isn't unique).
- **Go**: full module path (`github.com/sirupsen/logrus`), not the short name.
- **npm scoped**: `@org/name`.
- **others**: bare name.

Per-scan in-memory cache keyed by `(system, name, version)`; misses cached as
`None`. Default 5-second timeout per request. Offline mode short-circuits the
source.

### 3. ClearlyDefinedSource (`clearly_defined_source.rs`)

Calls ClearlyDefined's `/definitions/{type}/{provider}/{namespace}/{name}/{revision}`
endpoint and pulls the curated `licensed.declared` expression into
`component.concluded_licenses[]` (mapped to CycloneDX `acknowledgement:
"concluded"`).

Coordinate mapping in `clearly_defined_coord.rs` is per-ecosystem:

| mikebom PURL ecosystem | CD type | provider | namespace | name | revision |
|---|---|---|---|---|---|
| npm | `npm` | `npmjs` | scope (e.g. `@angular` stripped to `angular`) or `-` | name | version |
| cargo | `crate` | `cratesio` | `-` | name | version |
| pypi | `pypi` | `pypi` | `-` | PEP-503-normalized name | version |
| maven | `maven` | `mavencentral` | groupId (required) | artifactId | version |
| go | `go` | `golang` | url-encoded module prefix | last path segment | `v<version>` (v-prefix added if absent) |
| gem | `gem` | `rubygems` | `-` | name | version |
| deb, apk, rpm, generic, alpm | — | — | — | — | **skipped** |

Non-canonical SPDX strings in CD's response are logged and skipped — the
output never emits free-form license text, only expressions that parse
through the `spdx` crate.

Sequential per-component today; 5-second timeout; per-scan in-memory cache
`Mutex<HashMap<CdCoord, Option<CdDefinition>>>`; offline mode short-circuits.

### 4. DepsDevGraph (`deps_dev_graph.rs`)

Pulls transitive dependency edges from deps.dev's `:dependencies` endpoint.
Policy (see [design-notes §deps.dev policy
(critical)](../design-notes.md#depsdev-policy-critical)):

- **deps.dev is authoritative for edge topology** (A→B).
- **deps.dev is not authoritative for versions.** If deps.dev reports
  `foo@1.0` and the local scan has `foo@1.5`, the emitted edge targets the
  local version.
- When deps.dev names a coord that isn't present locally at any version,
  mikebom emits it as a new component tagged
  `source_type = "declared-not-cached"` so downstream consumers can
  distinguish declared-but-not-installed from actually-installed.
- Concurrency is capped at 8 in-flight requests via
  `tokio::task::JoinSet`.
- Offline mode short-circuits.

Today wired for **Maven only**. The rationale is in
[design-notes §Why deps.dev is only wired for
Maven](../design-notes.md#why-depsdev-is-only-wired-for-maven): cargo /
go-source / npm / ruby local signals already encode the full tree, and
Maven's shaded-JAR / cold-cache cases are the only places the local scan is
structurally incomplete.

## Pipeline behavior

`EnrichmentPipeline::enrich` in `mikebom-cli/src/enrich/pipeline.rs`:

1. For each registered source in registration order:
   - Call `enrich_relationships` once; extend the accumulator on `Ok`, log
     `warn` and continue on `Err`.
   - For each component in the mutable set, call `enrich_metadata`; on
     `Err`, log `warn` for that (component, source) pair and continue.
2. **Guard rail**: filter `all_relationships` so `rel.from` and `rel.to` are
   both in the known-PURL set derived from the component list. Relationships
   referencing unknown components (e.g. lockfile entries that don't match a
   scanned component, deps.dev edges whose target was filtered) are dropped
   with a `debug`-level log.
3. Return the filtered relationship list.

The pipeline is synchronous today (the `EnrichmentSource` trait has sync
methods). Async sources (deps.dev, ClearlyDefined) are called from
`scan_cmd.rs` at `.await` points outside the pipeline.

## Network posture

- **HTTP library**: `reqwest` for both deps.dev and ClearlyDefined.
- **Timeouts**: 5 s per request (both services).
- **Retries**: none. Transient errors (timeout, connection) return `Err` from
  the client, which the source logs at `debug` / `warn` and skips.
- **Concurrency**: sequential per-component for deps.dev version and CD;
  `JoinSet`-capped at 8 for deps.dev-graph (Maven-only).
- **Caching**: per-scan, in-memory, `Mutex<HashMap<..., Option<...>>>`. Misses
  are cached to prevent re-hits.
- **Offline mode**: all three network sources short-circuit. Guard rail is
  unaffected; it works off the local component set regardless.

## Provenance

Every enrichment-derived relationship carries an `EnrichmentProvenance`
(`source`, `data_type`). This is how the generator distinguishes
lockfile-derived edges from deps.dev-derived edges in the output — it drives
whether the edge gets surfaced with a `mikebom:declared-not-cached` marker
and how compositions are annotated.
