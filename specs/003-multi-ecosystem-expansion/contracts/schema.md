# SBOM Schema Deltas — Milestone 003

CycloneDX 1.6 JSON output deltas vs milestone 002. Three surfaces are affected: `compositions[]`, `properties[]` keys, and `dependencies[]` provenance strings. No changes to the envelope (`metadata.lifecycles[]`, `bom.version`, `metadata.component`).

## 1. `compositions[]` — new ecosystem identifiers

Milestone 002 emits one `aggregate: complete` record per authoritative ecosystem: `deb`, `apk`, `pypi`, `npm`. This milestone adds up to five more, each gated on the conditions from the spec:

| `ecosystem` value in composition | Emitted when |
|---|---|
| `golang` | Any `go.sum` was parsed in full (source-tier), OR a Go binary yielded BuildInfo in full (analyzed-tier). Either condition triggers the record. |
| `rpm` | `/var/lib/rpm/rpmdb.sqlite` was parsed in full. |
| `maven` | Any `pom.xml` was parsed in full with all declared `<dependencies>` resolved to concrete versions (no `Placeholder` variants). If any pom contains unresolved property refs, the ecosystem is NOT marked complete — the unresolved placeholders are `design`-tier fallbacks by definition. |
| `cargo` | `Cargo.lock` v3 or v4 was parsed in full. v1/v2 refusal produces zero components AND no composition record (the refusal already short-circuits the whole scan). |
| `gem` | `Gemfile.lock` was parsed in full. |

Each composition record follows the milestone-002 shape:

```json
{
  "aggregate": "complete",
  "assemblies": ["pkg:golang/github.com/spf13/cobra@v1.7.0", "pkg:golang/...@..."]
}
```

`assemblies` lists every PURL for that ecosystem observed in this scan. One composition record per ecosystem; a scan that observes five new ecosystems + the four existing ones produces nine records.

Mixed-tier behaviour (source + analyzed for Go in the same scan): ONE `golang` composition record; it lists every Go PURL regardless of tier.

## 2. `properties[]` — new keys

Added:

| Key | Values | Component where it appears |
|---|---|---|
| `mikebom:buildinfo-status` | `"missing"` \| `"unsupported"` | File-level component for a Go binary where BuildInfo extraction failed. Never on module-level Go components. |

Reused (no new values, no new semantics):

- `mikebom:sbom-tier` — extended domain values: same four as milestone 002 (`source`, `deployed`, `analyzed`, `design`). No new values.
- `mikebom:source-type` — extended domain values: `"git"`, `"path"`, `"local"`, `"url"`. No new values vs. milestone 002.
- `mikebom:requirement-range` — reused for Maven unresolved property placeholders.
- `mikebom:dev-dependency` — reused for Maven `<scope>test</scope>` entries when `--include-dev`.

## 3. `dependencies[]` — provenance strings

Per R9, each ecosystem's `Relationship` edges carry a distinct `data_type`. The CycloneDX `dependencies[]` block itself doesn't expose provenance — CycloneDX 1.6 doesn't have a field for this — but the attestation envelope's `evidence` block does, and the SBOM's `metadata.tools[].notes` records the provenance vocabulary emitted during the scan.

For the SBOM's `dependencies[]` array, each ecosystem produces records in the standard shape:

```json
{
  "ref": "pkg:golang/github.com/mymain/service@v1.0.0",
  "dependsOn": [
    "pkg:golang/github.com/spf13/cobra@v1.7.0",
    "pkg:golang/github.com/sirupsen/logrus@v1.9.0"
  ]
}
```

Dangling references (names in the source data that don't resolve to any observed component) drop silently — same behaviour as dpkg / pypi / npm.

## 4. `metadata.lifecycles[]` — no changes

Lifecycle phase aggregation continues to apply across all ecosystems:

- `source`-tier entries → CycloneDX phase `pre-build`.
- `deployed`-tier entries → CycloneDX phase `operations`.
- `analyzed`-tier entries → CycloneDX phase `post-build`.
- `design`-tier entries → CycloneDX phase `design`.

A scan that produces entries across all four tiers emits all four phases in `metadata.lifecycles[]` — an existing property from milestone 002 that this milestone doesn't alter.

## 5. `evidence.identity.methods[]` — new technique value

One new technique value:

- `"binary-analysis"` — used by Go BuildInfo components and JAR-embedded `pom.properties` / MANIFEST-sourced Maven components.

All other components continue using `"manifest-analysis"` (source, deployed) or `"filename"` (filename-only matches).

## 6. Backwards compatibility for consumers

- An SBOM produced by mikebom 003 against a milestone-002-era fixture (dpkg + pypi + npm only) is byte-identical to what milestone 002 would have produced. The new code is strictly additive.
- An SBOM consumer expecting CycloneDX 1.6 continues to parse output correctly — no new top-level fields, no spec-violating extensions.
- Downstream tooling that ignores unknown property keys will naturally skip `mikebom:buildinfo-status`.
