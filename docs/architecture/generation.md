# Generation

The generator converts `ResolvedComponent[]` + `Relationship[]` +
`TraceIntegrity` into CycloneDX 1.6 JSON. It is the rightmost stage of the
pipeline and does **no** identity work — PURLs, CPEs, licenses, hashes are
populated by scanning / resolution / enrichment. Generation arranges them
into the CycloneDX shape, adds tool metadata, compositions, and evidence
blocks, and serializes.

**Key files:**

- `mikebom-cli/src/generate/cyclonedx/builder.rs::CycloneDxBuilder` —
  entry point. Takes a `CycloneDxConfig` and the scanner output, returns a
  BOM struct.
- `mikebom-cli/src/generate/cyclonedx/metadata.rs` — `metadata.component`,
  `metadata.authors`, `metadata.supplier`, trace-integrity properties.
- `mikebom-cli/src/generate/cyclonedx/compositions.rs` — per-ecosystem
  compositions (`aggregate: complete`).
- `mikebom-cli/src/generate/cyclonedx/dependencies.rs` — dependency graph
  emission, primary-dependency fallback.
- `mikebom-cli/src/generate/cyclonedx/evidence.rs` — `evidence.identity[]`
  construction, technique mapping, occurrences.
- `mikebom-cli/src/generate/cyclonedx/serializer.rs` — final JSON write.
- `mikebom-cli/src/generate/cpe.rs` — CPE 2.3 multi-candidate synthesizer
  (see [purls-and-cpes.md](purls-and-cpes.md)).

## Output format

Today only `cyclonedx-json` is fully written. `cyclonedx-xml` and `spdx-json`
are accepted as `--format` values but the serializer path writes JSON
regardless. **Status: Partial (XML / SPDX stubs).**

## CycloneDX 1.6 mapping

### `metadata.component`

Every BOM has a synthetic primary component under `metadata.component` with
both `purl` and `cpe` populated:

- `purl`: `pkg:generic/<name>@<version>`
- `cpe`: `cpe:2.3:a:mikebom:<name>:<version>:*:*:*:*:*:*:*`

The empty-field case is explicitly handled: even when the scan target has
no ecosystem of its own (a raw directory), a synthetic PURL is emitted. This
is required for sbomqs schema validity — the validator rejects
metadata.component entries with empty cpe/purl even though the CDX spec
doesn't require them. See
[design-notes §CycloneDX 1.6 serialization](../design-notes.md#cyclonedx-16-serialization)
for the full rationale.

`metadata.authors`, `metadata.supplier`, and `metadata.licenses` (CC0-1.0)
are hardcoded SBOM-producer identity and data-license per the CISA 2025
minimum-fields profile.

### Evidence

Each component emits `evidence.identity[]` as an **array** of identity
objects, not a single object. CDX 1.5 used a single-object form; 1.6
deprecated it. mikebom always emits an array with exactly one entry:

```json
"evidence": {
  "identity": [
    {
      "confidence": 0.95,
      "field": "purl",
      "methods": [{ "technique": "instrumentation", "confidence": 0.95 }]
    }
  ]
}
```

Technique mapping from `ResolutionTechnique`:

| Internal technique | CDX `method.technique` |
|---|---|
| `UrlPattern` | `instrumentation` |
| `HashMatch` | `hash-comparison` |
| `PackageDatabase` | `manifest-analysis` |
| `FilePathPattern` | `filename` |
| `HostnameHeuristic` | (never emitted — no component) |

For deb components scanned with default deep-hashing, `evidence.occurrences[]`
is populated with per-file entries:

```json
"occurrences": [
  {
    "location": "/usr/bin/jq",
    "additionalContext": {
      "sha256": "64ccde9c...",
      "md5_dpkg": "aabbccdd..."
    }
  }
]
```

The SHA-256 is computed at scan time; the MD5 reference is what dpkg
recorded at install time. Both are packed into `additionalContext` for
cross-reference; no other tool currently emits this.

### Why `evidence.identity[].tools` is empty

CDX 1.6 reserves `evidence.identity[].tools[]` for bom-refs to tools
declared elsewhere in the BOM (`metadata.tools`, `services`, `formulation`).
mikebom's original payload there (TLS connection IDs, deps.dev match
markers) isn't a tool and doesn't exist elsewhere in the BOM, so the field
is never emitted. Both payloads now land on the component as properties:

- `mikebom:source-connection-ids` — comma-joined TLS connection IDs from the
  trace.
- `mikebom:deps-dev-match` — `<system>:<name>@<version>`.

The provenance semantics are preserved; the location is CDX-conformant.

### Compositions

Per-ecosystem compositions with `aggregate: complete`. Each complete
ecosystem record emits both `assemblies[]` (the bom-refs of the components
in that ecosystem) and `dependencies[]` (the bom-refs that also have at
least one dependency edge). sbomqs's `comp_with_dependencies` requires both
fields to be populated.

A separate dep-completeness composition lists the primary's bom-ref under
`dependencies` when the scan had no trace-integrity issues. Without this,
sbomqs reports "no dependency graph present" even when the transitive
edges are fine.

CDX 1.6 compositions have `additionalProperties: false`, so trace-integrity
counters can't ride on the composition. They go under
`metadata.properties` instead:

- `mikebom:trace-integrity-ring-buffer-overflows`
- `mikebom:trace-integrity-events-dropped`
- `mikebom:trace-integrity-uprobe-attach-failures`
- `mikebom:trace-integrity-kprobe-attach-failures`

### Dependency graph

Emitted as `dependencies[]` at the BOM root, keyed by bom-ref. Each entry
lists the bom-refs that depend on it. Three sources of edges:

1. Package-DB dependencies (`dpkg Depends:`, `apk D:`, `rpm REQUIRES`).
2. Lockfile-encoded dependencies (`Cargo.lock`, `package-lock.json`,
   `Gemfile.lock`, `go.sum`, POM + effective POM, `deps.dev :dependencies`
   fallback for Maven).
3. Primary-dependency fallback: when the scanned project's root entry was
   filtered out (e.g. npm `path_key == ""`, cargo `source = None`) and no
   explicit edges connect `metadata.component` to anything, synthesize edges
   from the primary to every "root" component (those that nothing else
   depends on). Without this, sbomqs reports "no dependency graph present"
   even for scans with complete transitive edges. See
   [design-notes §CycloneDX 1.6 serialization](../design-notes.md#cyclonedx-16-serialization).

### License shape

Single-identifier licenses emit as:

```json
"licenses": [{ "license": { "id": "MIT" } }]
```

Compound expressions emit as:

```json
"licenses": [{ "expression": "(MIT OR Apache-2.0)" }]
```

Both forms are required for sbomqs's `comp_with_valid_licenses` check.
`SpdxExpression::as_spdx_id` in `mikebom-common` decides which shape to
emit. Free-form license strings never leak through; everything
canonicalizes through the `spdx` crate.

Declared vs. concluded is controlled by the `acknowledgement` field; see
[licenses.md](licenses.md).

### Component hashes

Populated from per-ecosystem lockfile integrity fields: npm `integrity`
(sha256 / sha384 / sha512), Cargo.lock `checksum` (sha256), Maven sidecar
`.jar.sha512` > `.jar.sha256` > `.jar.sha1`, PyPI `requirements.txt
--hash=alg:hex` flags. Trace mode adds SHA-256 from the post-trace artifact
walk.

Gem, Go, and RPM currently emit no per-component hashes — gem lockfiles
don't include them (until bundler 2.5 adoption stabilizes), Go `go.sum` H1
hashes are Merkle-trie roots (not file SHA-256s, would need a custom CDX
hash type), and rpmdb doesn't record per-package content hashes. See the
deferred backlog in
[design-notes §sbomqs score lift](../design-notes.md#deferred-sbomqs-score-lift)
item 17.

## How the output gets produced

`CycloneDxConfig` controls the three user-visible toggles:

- `include_hashes` — whether to emit `components[].hashes[]`.
- `include_source_files` — whether to include the `evidence.occurrences[]`
  file-level additions (trace-mode `--scope source`).
- `include_dev` — drives the `mikebom:dev-dependency` property filter.

The same builder runs for both scan mode and trace mode — the only
difference is the `generation_context` value (`FilesystemScan`,
`ContainerImageScan`, or `BuildTimeTrace`), which is stamped on
`metadata.component.properties.mikebom:generation-context`. Downstream
consumers use this to know what evidence produced the SBOM.
