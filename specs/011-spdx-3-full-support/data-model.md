# Phase 1 Data Model: Full SPDX 3.x Output Support

**Branch**: `011-spdx-3-full-support` | **Date**: 2026-04-24 | **Plan**: [plan.md](plan.md) | **Research**: [research.md](research.md)

This document enumerates every SPDX 3.0.1 JSON-LD element type the milestone-011 emitter produces, with type identifier, required and emitter-populated optional properties, IRI-synthesis rule, and the `ResolvedComponent` / `ScanArtifacts` field that drives each value. Together these elements compose the `@graph` of the emitted document.

The emitter consumes `ScanArtifacts<'_>` (defined in `mikebom-cli/src/generate/mod.rs`) and `OutputConfig` (the same neutral inputs the milestone-010 SPDX 2.3 emitter consumes). No new types in `mikebom-common`.

## IRI synthesis rule (shared)

All `spdxId` values in the emitted document are real IRIs (the SPDX 3.0.1 schema enforces `^(?!_:).+:.+`); only `CreationInfo.@id` is permitted to be a blank node, and the milestone-010 stub already does this and milestone-011 retains the convention.

| Element kind | IRI shape |
|--------------|-----------|
| Document | `https://mikebom.kusari.dev/spdx3/doc-<base32(SHA256(scan-fingerprint))[..24]>` |
| Tool | `<doc IRI>/tool/mikebom` |
| CreationInfo | `_:creation-info` (the one permitted blank node) |
| Package | `<doc IRI>/pkg-<base32(SHA256(<purl>))[..16]>` |
| Relationship | `<doc IRI>/rel-<base32(SHA256(<from-iri> + "\|" + <type> + "\|" + <to-iri>))[..16]>` |
| simplelicensing_LicenseExpression (declared) | `<doc IRI>/license-decl-<base32(SHA256(canonical_expr))[..16]>` |
| simplelicensing_LicenseExpression (concluded) | `<doc IRI>/license-conc-<base32(SHA256(canonical_expr))[..16]>` |
| Organization / Person (Agent) | `<doc IRI>/agent-<kind>-<base32(SHA256(<kind> + "\|" + name))[..16]>` |
| ExternalIdentifier (purl, cpe23) | inlined under the Package's `externalIdentifier` list — no `spdxId` (the SPDX 3.0.1 ExternalIdentifier shape is value-typed, not element-typed) |
| Annotation | `<doc IRI>/anno-<base32(SHA256(<subject-iri> + "\|" + field + "\|" + value))[..16]>` |

The scan-fingerprint hash input is identical to the milestone-010 SPDX 2.3 emitter's `documentNamespace` derivation: target name, mikebom version, sorted PURL list. This guarantees byte-identical output across two runs of the same scan after the timestamp is normalized (FR-015 / SC-006).

## Element catalog

### `CreationInfo`

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | literal `"CreationInfo"` |
| `@id` | yes | literal `"_:creation-info"` (only permitted blank node) |
| `specVersion` | yes | literal `"3.0.1"` |
| `created` | yes | `OutputConfig.created` rendered as RFC 3339 with `Secs` precision |
| `createdBy` | yes | `[<tool IRI>]` |
| `comment` | no | omitted on the stable identifier; alias path sets it to the milestone-010 stub's experimental marker only when the deprecated identifier is invoked (preserves the experimental-labeling guarantee on the alias path per Constitution V) |

### `Tool` (the producing Agent)

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"Tool"` |
| `spdxId` | yes | `<doc IRI>/tool/mikebom` |
| `creationInfo` | yes | reference to the CreationInfo blank node |
| `name` | yes | `"mikebom-" + cfg.mikebom_version` |

### `SpdxDocument`

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"SpdxDocument"` |
| `spdxId` | yes | `<doc IRI>` |
| `creationInfo` | yes | blank-node ref |
| `name` | yes | `ScanArtifacts.target_name` |
| `dataLicense` | yes | `"https://spdx.org/licenses/CC0-1.0"` |
| `rootElement` | yes | `[<root Package IRI>]` — selected by the milestone-010 `synthesize_root` rule (target-name match, else first Package, else synthesized root Package) |
| `externalRef` | conditional | one entry pointing at the OpenVEX sidecar when the scan produces advisories. Shape per the **ExternalRef → OpenVEX** subsection below. (FR-014, clarification Q1.) |
| `comment` | no | omitted on stable identifier; experimental marker on alias path |

### `software_Package` (one per CycloneDX component)

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"software_Package"` |
| `spdxId` | yes | `<doc IRI>/pkg-<…>` |
| `creationInfo` | yes | blank-node ref |
| `name` | yes | `ResolvedComponent.name` |
| `software_packageVersion` | yes when present | `ResolvedComponent.version` |
| `software_packageUrl` | no but always emitted by us | `ResolvedComponent.purl.as_str()` (also indexed via ExternalIdentifier — see below) |
| `verifiedUsing` | conditional | array of `Hash` value-objects when `ResolvedComponent.hashes` is non-empty |
| `software_homePage` | conditional | first `external_references[]` entry of type `homepage` (Section A row A9) |
| `software_sourceInfo` | conditional | first `external_references[]` entry of type `vcs` (Section A row A10) |
| `software_downloadLocation` | conditional | first `external_references[]` entry of type `distribution` (Section A row A11) |
| `externalIdentifier` | conditional | array of `ExternalIdentifier` value-objects: one entry per PURL (always exactly one — `purl`), one per fully-resolved CPE (zero or more — `cpe23`). See A1, A12, C19. |

`Hash` is a value-typed element (no `spdxId`):

```json
{ "type": "Hash", "algorithm": "SHA256", "hashValue": "abc..." }
```

`ExternalIdentifier` is value-typed (no `spdxId`):

```json
{ "type": "ExternalIdentifier", "externalIdentifierType": "purl", "identifier": "pkg:npm/foo@1.2.3" }
```

### `Relationship` (typed; one element per edge)

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"Relationship"` |
| `spdxId` | yes | `<doc IRI>/rel-<…>` |
| `creationInfo` | yes | blank-node ref |
| `from` | yes | source element's IRI |
| `to` | yes | array containing target element's IRI |
| `relationshipType` | yes | one of: `dependsOn`, `devDependencyOf`, `buildDependencyOf`, `contains`, `hasDeclaredLicense`, `hasConcludedLicense`, `suppliedBy`, `originatedBy`, `describes` |

Direction-reversal rule (preserved verbatim from the SPDX 2.3 emitter): `DEV_DEPENDENCY_OF` and `BUILD_DEPENDENCY_OF` reverse `from`/`to` because SPDX 3 (like SPDX 2.3) phrases the relationship "B is a dev-dependency of A" rather than "A devDependsOn B."

### `simplelicensing_LicenseExpression` (one element per distinct expression)

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"simplelicensing_LicenseExpression"` |
| `spdxId` | yes | `<doc IRI>/license-decl-<…>` or `license-conc-<…>` |
| `creationInfo` | yes | blank-node ref |
| `simplelicensing_licenseExpression` | yes | canonical SPDX expression returned by `spdx::Expression::try_canonical(&str)` |

The element is wired to its Package by a `Relationship` with `relationshipType: "hasDeclaredLicense"` or `"hasConcludedLicense"`. Concluded-license element is omitted when the concluded expression equals the declared expression (no redundant edge).

### `Organization` / `Person` (Agent subtypes; one element per distinct supplier/originator)

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"Organization"` or `"Person"` |
| `spdxId` | yes | `<doc IRI>/agent-org-<…>` or `agent-person-<…>` |
| `creationInfo` | yes | blank-node ref |
| `name` | yes | the supplier/originator string verbatim |

Wired to a Package via a `Relationship` with `relationshipType: "suppliedBy"` (Organization) or `"originatedBy"` (Person or Organization, depending on the field).

### `ExternalRef` → OpenVEX sidecar (clarification Q1, FR-014)

Conditional: only emitted when the scan produces at least one advisory and the OpenVEX sidecar is therefore written. Shape:

```json
{
  "type": "ExternalRef",
  "externalRefType": "securityAdvisory",
  "locator": "<relative-path-to-sidecar>",
  "comment": "OpenVEX 0.2.0 sidecar produced by mikebom"
}
```

Lives inside the `SpdxDocument` element's `externalRef` list. The `locator` value comes from the same path-resolution logic the milestone-010 SPDX 2.3 emitter uses (`OutputConfig.overrides["openvex"]` if set, else the OpenVEX serializer's default relative path). The sidecar's bytes are not hashed in the `ExternalRef` (SPDX 3 ExternalRef has no checksum slot) — content-integrity is the consumer's responsibility, matching SPDX 3 vocabulary intent.

### `Annotation` (the Q2 fallback for everything else)

One element per distinct `(subject, field, value)` tuple drawn from `ResolvedComponent.<mikebom signals>` and from `ScanArtifacts.<document-level mikebom signals>`.

| Property | Required | Source |
|----------|----------|--------|
| `type` | yes | `"Annotation"` |
| `spdxId` | yes | `<doc IRI>/anno-<…>` |
| `creationInfo` | yes | blank-node ref |
| `subject` | yes | IRI of the Package or SpdxDocument the annotation describes |
| `annotationType` | yes | literal `"other"` |
| `statement` | yes | JSON-encoded `MikebomAnnotationCommentV1` envelope: `{"schema":"mikebom-annotation/v1","field":"<name>","value":<original>}` |

The envelope JSON shape is **unchanged** from milestone 010 — the same `MikebomAnnotationCommentV1` bytes mikebom puts in SPDX 2.3 `annotations[].comment` it puts in SPDX 3 `Annotation.statement`. Downstream consumers parsing the envelope share one parser across format versions. (Annotation-fidelity test asserts on this directly.)

### Mapping from `ResolvedComponent` fields to SPDX 3 elements (summary)

| `ResolvedComponent` field | SPDX 3 destination |
|---------------------------|--------------------|
| `purl` | `software_packageUrl` + `ExternalIdentifier[purl]` |
| `name` | `software_Package.name` |
| `version` | `software_Package.software_packageVersion` |
| `hashes[]` | `software_Package.verifiedUsing[]` (Hash value-objects) |
| `licenses[]` (declared) | `simplelicensing_LicenseExpression` element + `Relationship[hasDeclaredLicense]` |
| `concluded_licenses[]` | `simplelicensing_LicenseExpression` element + `Relationship[hasConcludedLicense]` (omitted when equal to declared) |
| `supplier` | `Organization` element + `Relationship[suppliedBy]` |
| `evidence.author` (when present) | `Person` or `Organization` element + `Relationship[originatedBy]` |
| `cpes[]` (resolved) | `ExternalIdentifier[cpe23]` entries |
| `cpes[]` (unresolved candidates) | `Annotation[mikebom:cpe-candidates]` |
| `external_references[homepage]` | `software_homePage` |
| `external_references[vcs]` | `software_sourceInfo` |
| `external_references[distribution]` | `software_downloadLocation` |
| `is_dev`, `evidence_kind`, `binary_class`, `binary_stripped`, `linkage_kind`, `detected_go`, `confidence`, `binary_packed`, `npm_role`, `raw_version`, `parent_purl`, `co_owned_by`, `shade_relocation`, `requirement_range`, `source_type`, `sbom_tier`, `buildinfo_status`, `evidence.technique`, `evidence.confidence`, `occurrences[]`, `evidence.deps_dev_match` | `Annotation[mikebom:<field>]` (one per distinct field; envelope reused verbatim from milestone 010) |
| `advisories[]` | OpenVEX sidecar (separate file; cross-referenced via `ExternalRef`) |

| `ScanArtifacts` field (document-level) | SPDX 3 destination |
|----------------------------------------|--------------------|
| `target_name` | `SpdxDocument.name` |
| `generation_context` | `Annotation[mikebom:generation-context]` on the SpdxDocument |
| `os_release_missing_fields` | `Annotation[mikebom:os-release-missing-fields]` on the SpdxDocument |
| `integrity.*` (ring buffer overflows, events dropped, attach failures) | `Annotation[mikebom:trace-integrity-<sub>]` on the SpdxDocument |
| `complete_ecosystems` | `Annotation[compositions]` on the SpdxDocument |

### Deterministic ordering rules

To guarantee byte-determinism (FR-015 / SC-006), the `@graph` is emitted in this fixed order:

1. The single `CreationInfo` element.
2. The `Tool` element.
3. The `SpdxDocument` element.
4. `software_Package` elements, sorted by `spdxId`.
5. `Organization` and `Person` elements, sorted by `spdxId`.
6. `simplelicensing_LicenseExpression` elements, sorted by `spdxId`.
7. `Relationship` elements, sorted by `spdxId`.
8. `Annotation` elements, sorted by `spdxId`.

Within each Package, the `verifiedUsing[]` array is sorted by `(algorithm, hashValue)`, the `externalIdentifier[]` array is sorted by `(externalIdentifierType, identifier)`. These rules mirror milestone 010's sort order for SPDX 2.3 to keep the two emitters' determinism stories congruent.
