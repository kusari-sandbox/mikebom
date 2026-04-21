# Resolution

Resolution turns raw evidence (attestation events or filesystem observations)
into deduplicated `ResolvedComponent[]`. Two entry points, one deduplicator.

## The two entry points

- **Trace mode** (`sbom generate`, `trace run`):
  `mikebom-cli/src/resolve/pipeline.rs::ResolutionPipeline::resolve`. Reads
  the in-toto attestation's `network_trace.connections` and
  `file_access.operations` and produces candidate components.
- **Scan mode** (`sbom scan`): `mikebom-cli/src/scan_fs/mod.rs::scan_path`.
  Each per-ecosystem module (`scan_fs/package_db/*.rs`) emits candidates
  directly; no `ResolutionPipeline` is invoked because the evidence is
  already ecosystem-typed.

Both paths feed into the same deduplicator
(`mikebom-cli/src/resolve/deduplicator.rs::deduplicate`) and produce the same
`ResolvedComponent` shape, so the downstream enrichment and generation stages
don't need to know which mode produced the input.

## Resolution techniques and confidence

Defined in `mikebom-common/src/resolution.rs::ResolutionTechnique`:

| Technique | Confidence | When it fires |
|---|---|---|
| `UrlPattern` | 0.95 | A traced HTTPS connection's URL matched a known package-registry pattern (e.g. `https://static.crates.io/crates/<name>/<name>-<version>.crate`). Build-time trace only. |
| `HashMatch` | 0.90 | A traced response's content SHA-256 returned a hit from a deps.dev lookup. Build-time trace only, skipped under `--skip-purl-validation`. |
| `PackageDatabase` | 0.85 | An installed-package DB stanza identified the component. Scan mode. |
| `FilePathPattern` | 0.70 | A file with a recognised cache-path pattern exists on disk (e.g. `~/.cargo/registry/cache/...*.crate`). Scan mode and trace-mode artifact-dir post-scan. |
| `HostnameHeuristic` | 0.40 | The observed hostname matched a known registry but no specific package URL was extracted. **Logged only** — does not create a component. |

Trace mode's resolution order inside `ResolutionPipeline::resolve`:

1. For each network connection, try URL pattern. If it matches, build the
   component, attach the hash from the correlated file-access event (by
   basename match), and `continue` to the next connection.
2. Otherwise, if the response had a content hash and online validation isn't
   skipped, try hash resolution via deps.dev. Emit one component per match.
3. Otherwise, log the hostname-heuristic ecosystem if any, but don't create a
   component.
4. After all connections are processed, walk file-access operations and try
   file-path pattern resolution on each (confidence 0.70).
5. Deduplicate.

The order matters: URL pattern is highest-confidence because it captures both
name and version from the download URL; hash match is next because a deps.dev
hash lookup is authoritative but expensive; file path is last because a
package cache file's name alone doesn't prove it was actually used.

## The deduplicator

`deduplicate` groups `ResolvedComponent`s by `(ecosystem, name, version)` (via
PURL canonicalization) and merges them:

- **Evidence technique**: the highest-confidence technique wins — if a
  component was observed via both URL match (0.95) and file path (0.70), the
  merged component reports `UrlPattern` at 0.95.
- **Source connection IDs**: unioned. A serde crate observed via both crates.io
  HTTPS and the post-trace registry cache walk reports both connection IDs
  under `evidence.source_connection_ids` so a consumer can correlate back to
  the TLS session and the file op.
- **Source file paths**: unioned.
- **Hashes**: unioned.
- **Dev flag**: `Some(false)` (prod) wins over `Some(true)` (dev-only).
  `None` is replaced by any concrete value.
- **Licenses / concluded_licenses / CPEs / etc.**: unioned by equality.

This lets the pipeline merge partial evidence from multiple sources without
privileging the first one seen. It's also why URL+file-path dual observation
in the trace mode tests produces a component with confidence 0.95 and
*both* a `source_connection_ids` and a `source_file_paths` populated.

## Hash-based correlation (trace mode)

Build-time trace captures two kinds of events:

- **TLS connection** events from the libssl uprobes — URL + host + (optional)
  response body hash, but the uprobe only sees ~512 B of each record, so the
  hash computed there is unreliable.
- **File operation** events from kprobes + a post-trace walk of
  `--artifact-dir` directories — real SHA-256 of the written artifact.

`ResolutionPipeline::resolve` builds a `basename → ContentHash` map from file
operations, then for each URL-pattern-resolved component looks up the hash
under the URL's last path segment. This is why SBOMs emitted by `trace run`
carry SHA-256s that byte-match the `.crate` / `.deb` files on disk — the hash
is captured by the filesystem walker, not by the uprobe.

## Scan-mode resolution

Scan mode doesn't run `ResolutionPipeline`. Each `package_db/*.rs` module
populates a `PackageDbEntry` struct with name / version / hashes / dependency
list, and `scan_fs::mod.rs` converts those to `ResolvedComponent`s directly.
The conversion stamps `ResolutionTechnique::PackageDatabase` (0.85) for
DB-sourced entries and `ResolutionTechnique::FilePathPattern` (0.70) for
walker-sourced entries.

The deduplicator runs after both sources merge. A deb package that both has a
`.deb` in `/var/cache/apt/archives/` and a dpkg stanza at
`/var/lib/dpkg/status` will appear once in the output, at confidence 0.85
(package DB wins), with both the file-path evidence and the DB evidence
retained in the merged record.

## Why resolution is a separate stage

Two reasons:

1. **Identity isn't local to a single source.** The same package can be
   reached through up to four techniques; no single scanner knows the full
   set. Resolution is where cross-source merging happens.
2. **Confidence is an output, not an input.** Each source knows its own
   reliability, but the consumer needs one number per component. The
   deduplicator computes that.

Resolution explicitly does *not* fetch from the network except for
`HashMatch` in trace mode. All other enrichment — licenses, VCS URLs,
transitive edges from deps.dev, ClearlyDefined lookups — happens in the
[enrichment stage](enrichment.md), which runs *after* resolution so that a
network failure can never reduce the set of components the SBOM emits.
