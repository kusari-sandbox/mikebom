# Component-Output Contract — Python + npm Ecosystem Support

Output-shape expectations for CycloneDX components produced by this milestone. All additions are strictly additive to the existing component schema; no envelope changes.

## 1. Component identity

### 1.1 `name`

Human-readable package name. For Python: the declared form from `METADATA::Name:` (hyphens preserved, case preserved). For npm: the declared `name` field; for scoped packages, the full `@scope/name` form.

### 1.2 `version`

Human-readable resolved version.
- **Populated** for: venv-sourced Python components, lockfile-sourced Python + npm components, node_modules-walked components.
- **Empty string** for: `requirements.txt` range-only entries, `package.json`-only fallback entries. In that case, `properties[]` carries `mikebom:requirement-range` with the original range string.

### 1.3 `purl`

Canonical reference-implementation-conformant PURL.

| Ecosystem | Shape | Example |
|-----------|-------|---------|
| pypi | `pkg:pypi/<declared-name>@<version>` | `pkg:pypi/requests@2.31.0` |
| pypi (scope-like) | — | `pkg:pypi/zope.interface@6.0` (declared form with `.` preserved, not PEP 503-normalised) |
| npm (unscoped) | `pkg:npm/<name>@<version>` | `pkg:npm/lodash@4.17.21` |
| npm (scoped) | `pkg:npm/%40<scope>/<name>@<version>` | `pkg:npm/%40angular/core@16.2.12` |

`+` in any segment is percent-encoded as `%2B` via `encode_purl_segment` (same invariant as deb).

### 1.4 `type`

Always `"library"`. No new component types introduced.

---

## 2. Confidence and evidence

### 2.1 Confidence tiers

| Tier | Source | Confidence |
|------|--------|-----------:|
| Manifest-analysis | Python venv dist-info, poetry.lock, Pipfile.lock, npm lockfile v2/v3, pnpm lockfile v6+, node_modules walk | 0.85 |
| Filename fallback | requirements.txt (pinned or ranged), root package.json fallback | 0.70 |

### 2.2 `evidence.identity.methods[0].technique`

| Source | Value |
|--------|-------|
| Any dist-info / lockfile / node_modules walk | `"manifest-analysis"` |
| requirements.txt or package.json-only fallback | `"filename"` |

### 2.3 `evidence.identity.tools[]`

- `{ "ref": "deps.dev:<system>:<name>@<version>" }` appended when the deps.dev enrichment pass ran successfully for that component (non-offline mode, ecosystem in the supported set). The existing mechanism from milestone 001 handles this; new ecosystems inherit it.

### 2.4 `evidence.source_file_paths[]`

List of absolute paths to the authoritative source files consulted for this component. For components deduplicated from multiple sources, ALL source paths appear here.

---

## 3. Hashes

### 3.1 Population rules

| Source | Emit hash? | Algorithm |
|--------|-----------|-----------|
| Python venv (dist-info) | no | — (RECORD file hashing is out of scope this milestone) |
| Poetry lockfile | optional, from `[[package.files]] hash = "sha256:..."` | SHA-256 |
| Pipfile.lock | optional, from `hashes:` array | SHA-256 (detect `sha256:` prefix) |
| npm `package-lock.json` | yes, from `integrity:` field | Per the SRI prefix — typically SHA-512, sometimes SHA-384 or SHA-256 |
| pnpm lockfile | yes, from `integrity:` field | Same as npm |
| `node_modules/<pkg>/package.json` walk | no | `package.json` doesn't carry integrity |
| requirements.txt or package.json fallback | no | No hash info at that tier |

### 3.2 CycloneDX shape

```jsonc
{
  "hashes": [
    { "alg": "SHA-512", "content": "abc123..." }
  ]
}
```

Algorithm strings follow the existing project convention (`SHA-256`, `SHA-384`, `SHA-512`). Multiple hash algorithms per component are possible when dedup merges entries from different sources.

---

## 4. Licenses

### 4.1 Extraction order (Python)

1. `License-Expression:` (PEP 639) — stored as SPDX-canonical expression via `SpdxExpression::try_canonical`.
2. `License:` — run through shorthand normaliser + `try_canonical`.
3. `Classifier: License :: ...` — mapped via classifier-to-SPDX lookup table.
4. deps.dev `licenses[]` (online mode) — augments anything still empty; never overwrites local values.

### 4.2 Extraction order (npm)

1. `license:` field on `package.json` (in node_modules walk) or lockfile entry.
2. deps.dev `licenses[]` (online mode).

### 4.3 CycloneDX shape

```jsonc
{
  "licenses": [
    { "expression": "Apache-2.0 OR MIT" }
  ]
}
```

Existing `expression` key is used (matches the milestone 001 pattern). Multi-license components get multiple array entries.

---

## 5. New component properties

All emitted under `component.properties[]` (unchanged top-level schema):

| Property name | When emitted | Value | Purpose |
|---------------|--------------|-------|---------|
| `mikebom:dev-dependency` | Component's dedup-final `is_dev == Some(true)` AND `--include-dev` was set | `"true"` | Lets downstream consumers filter dev deps back out without re-running the scan |
| `mikebom:requirement-range` | Component came from the `requirements.txt` fallback (FR-004) or the root `package.json` fallback (FR-007a) | The original range string, e.g. `"^1.2.3"`, `"requests>=2,<3"`, `"git+ssh://git@github.com:org/repo.git#main"` | Surfaces the unresolved range a downstream consumer would have to pin themselves |
| `mikebom:source-type` | Component's PURL is `pkg:generic/...` due to a non-registry source (file:/git:/https:/tarball:) | `"local"` / `"git"` / `"url"` | Distinguishes first-party-sourced components from registry pulls |
| `mikebom:sbom-tier` | Every component (per FR-021a + research.md R13) | `"build"` / `"deployed"` / `"analyzed"` / `"source"` / `"design"` | Categorical traceability-ladder classification — "at what lifecycle point was this observed?" Complementary to the numeric `evidence.identity.confidence` axis |

Existing properties (`mikebom:source-files`, `mikebom:cpe-candidates`, `mikebom:layer-digests`) emit as before; new ecosystems must not accidentally strip them.

### 5a. Envelope-level lifecycle declaration

Per FR-021b, the CycloneDX envelope's `metadata.lifecycles[]` array (CycloneDX 1.5+ native) carries the union of observed tiers mapped to CycloneDX lifecycle phase names:

| mikebom tier | CycloneDX phase |
|---|---|
| `build` | `build` |
| `deployed` | `operations` |
| `analyzed` | `post-build` |
| `source` | `pre-build` |
| `design` | `design` |

Emitted shape:

```jsonc
{
  "metadata": {
    "lifecycles": [
      { "phase": "operations" },
      { "phase": "pre-build" },
      { "phase": "design" }
    ]
  }
}
```

Ordering: sorted alphabetically by phase name for deterministic output.

---

## 6. Compositions

Per-ecosystem `aggregate: complete` records get added to `compositions[]` for ecosystems whose authoritative source was read in full:

- `pypi` when the scan encountered a populated venv OR a parsed `poetry.lock` / `Pipfile.lock`.
- `npm` when the scan encountered a parsed `package-lock.json` v2/v3 OR a parsed `pnpm-lock.yaml` v6+.

Shape (matches milestone 001's existing convention):

```jsonc
{
  "compositions": [
    {
      "aggregate": "complete",
      "assemblies": [
        "pkg:pypi/requests@2.31.0",
        "pkg:pypi/urllib3@2.0.7",
        "..."
      ]
    },
    {
      "aggregate": "complete",
      "assemblies": ["pkg:npm/lodash@4.17.21", "..."]
    },
    {
      "aggregate": "incomplete_first_party_only",
      "assemblies": ["<target>@0.0.0"],
      "properties": [ /* trace integrity, even in scan mode for consistency */ ]
    }
  ]
}
```

Ordering: `aggregate: complete` records emit in sorted ecosystem-name order (`apk`, `deb`, `npm`, `pypi`) for deterministic output. The target's `incomplete_first_party_only` record is always last.

The requirements-fallback and root-package.json-fallback tiers do NOT trigger `aggregate: complete` — those tiers are non-authoritative by definition. A project scanned with only a `requirements.txt` produces pypi components but no "complete" compositions record for pypi. Consumers reading the compositions section learn "this scan was not complete for pypi; take the component list as a best-effort."

---

## 7. Dependencies (CycloneDX `dependencies[]`)

Per-component edges:

```jsonc
{
  "dependencies": [
    {
      "ref": "pkg:pypi/requests@2.31.0",
      "dependsOn": [
        "pkg:pypi/urllib3@2.0.7",
        "pkg:pypi/certifi@2023.7.22",
        "pkg:pypi/charset-normalizer@3.3.0",
        "pkg:pypi/idna@3.4"
      ]
    },
    {
      "ref": "pkg:npm/express@4.18.2",
      "dependsOn": ["pkg:npm/body-parser@1.20.1", "..."]
    }
  ]
}
```

Rules:

- `ref` values are canonical PURLs (`component.bom-ref`).
- `dependsOn` values are canonical PURLs of observed components; references to unobserved components are dropped.
- No double-entries: if A depends on B via two sources (lockfile AND dist-info), emit one `dependsOn: [B]` — dedup by (ref, depended-on) key.

---

## 8. CPE

Existing `cpe` top-level field on each component — one candidate; full list under `mikebom:cpe-candidates` property if multiple. The synthesizer's existing `pypi` and `npm` match arms cover this milestone's output. Verify at test time:

- `pkg:pypi/<name>@<version>` emits at least `cpe:2.3:a:<name>:<name>:<version>:*:*:*:*:*:*:*` and `cpe:2.3:a:python-<name>:<name>:<version>:*:*:*:*:*:*:*`.
- `pkg:npm/<name>@<version>` emits `cpe:2.3:a:<name>:<name>:<version>:*:*:*:*:*:*:*` (and scope-as-vendor when scoped).

No schema changes — just new components flowing through the existing path.

---

## 9. Backwards compatibility

- Existing fixtures (e.g. any SBOM parsed by the milestone-001 attestation tooling) continue to deserialise unchanged. The new component properties are additive.
- Attestation round-trips: a milestone-001 attestation loaded today still serialises identically; only new components added in this milestone would carry the new properties.
- Consumers that only read `components[].purl`, `version`, `licenses`, `hashes`, `evidence.identity.confidence` see exactly one new dimension (more components) and no schema changes.

---

## 10. Validation signals for acceptance tests

Hooks that tasks.md will exercise:

- `jq '.components[] | select(.purl | startswith("pkg:pypi/")) | .purl' | xargs -I{} python3 -c "from packageurl import PackageURL; p = PackageURL.from_string('{}'); print(p.to_string() == '{}')"` — all true.
- Same for `pkg:npm/`.
- `jq '[.components[] | select(.properties[]?.name == "mikebom:dev-dependency")] | length'` — zero when `--include-dev` off; > 0 when `--include-dev` on (for a project with dev deps).
- `jq '[.compositions[] | select(.aggregate == "complete")] | length'` — ≥ 1 when at least one authoritative source was read.
- `jq '.components[] | select(.properties[]?.name == "mikebom:requirement-range") | .version'` — always `""` (empty) when the property is present.
