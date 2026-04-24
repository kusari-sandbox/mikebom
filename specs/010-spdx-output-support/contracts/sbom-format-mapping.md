# Dual-Format SBOM Data-Placement Map (CycloneDX 1.6 ↔ SPDX 2.3 ↔ SPDX 3.0.1)

**Version**: v1 | **Owner**: milestone 010 | **Canonical home**: `docs/reference/sbom-format-mapping.md` (this `contracts/` copy is a mirror retained for plan-review purposes; when the two disagree, the `docs/reference/` version wins)

This document is the contract that the SPDX 2.3 serializer (and the SPDX 3 stub) MUST honor. Per FR-013, FR-014, FR-015, every data element mikebom emits in CycloneDX has a row here naming its target location in each format and a one-line justification.

## Conventions

- **CycloneDX location**: JSON Pointer-style path into the CycloneDX 1.6 document (`/components/{i}/<field>` etc.).
- **SPDX 2.3 location**: Either a JSON path into the SPDX 2.3 document (`/packages/{i}/<field>`), an SPDX `Relationship` description, an SPDX `Annotation` with the named `field` envelope (per `mikebom-annotation.schema.json`), or `omitted — <reason>`.
- **SPDX 3.0.1 location**: Either a JSON-LD path into a 3.0.1 element graph (`{Element}/<property>`), an `Annotation` element pointer, or `defer — <reason>` for entries the stub does not yet honor.
- "**Annotation** ⟨field⟩" is shorthand for: emit one `SpdxAnnotation` whose `comment` is the JSON-encoded `MikebomAnnotationCommentV1` envelope with the named `field` value.

## Section A — Core identity (native fields in all three formats)

| # | mikebom data | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|--------------|------------------------|-------------------|---------------------|---------------|
| A1 | PURL | `/components/{i}/purl` | `/packages/{i}/externalRefs[]` with `referenceCategory: "PACKAGE-MANAGER"`, `referenceType: "purl"`, `referenceLocator: <PURL>` | `software_Package/software_packageUrl` (populated by the npm stub; non-npm ecosystems defer until the stub extends). | All three formats have native, identical PURL semantics. SPDX 3 uses the dedicated `software_packageUrl` property rather than an `externalRef`. |
| A2 | name | `/components/{i}/name` | `/packages/{i}/name` | `software_Package/name` (populated by the npm stub). | Native in all; inherited from `Element_props` in SPDX 3. |
| A3 | version | `/components/{i}/version` | `/packages/{i}/versionInfo` | `software_Package/software_packageVersion` (populated by the npm stub). | Native in all. |
| A4 | supplier (org) | `/components/{i}/supplier/name` | `/packages/{i}/supplier` (`"Organization: <name>"` or `"NOASSERTION"`) | `defer until SPDX 3 Agent coverage lands in the stub` — SPDX 3 requires a separate `Agent` / `Organization` element plus a `Relationship` edge, out of stub scope. | Native in all; SPDX requires `NOASSERTION` when unknown — never omit (2.3). |
| A5 | author (person) | `/components/{i}/author` | `/packages/{i}/originator` (`"Person: <name>"` or `"NOASSERTION"`) | `defer until SPDX 3 Agent coverage lands` — same reason as A4. | Native in all. |
| A6 | hashes | `/components/{i}/hashes[]` (each: `{alg, content}`) | `/packages/{i}/checksums[]` (each: `{algorithm, checksumValue}`) | `software_Package/verifiedUsing[]` of `Hash` elements with `algorithm` + `hashValue` (populated by the npm stub). | Native in all; mapping is 1-1. |
| A7 | license — declared | `/components/{i}/licenses[]` with `license.id` or `expression` | `/packages/{i}/licenseDeclared` (canonical SPDX expression, `"NOASSERTION"`, or `"NONE"`) | `defer until SPDX 3 license emission lands` — SPDX 3 expresses licenses as `Relationship{relationshipType: "hasDeclaredLicense", from: Package, to: simplelicensing_LicenseExpression}` edges; out of initial-stub scope. | Native in 1.6/2.3; SPDX 3 uses relationships. |
| A8 | license — concluded | `/components/{i}/licenses[]` (concluded marker) | `/packages/{i}/licenseConcluded` | `defer until SPDX 3 license emission lands` — same reason as A7 (`hasConcludedLicense` relationship). | Native in 1.6/2.3; SPDX 3 uses relationships. |
| A9 | external reference — homepage | `/components/{i}/externalReferences[]` with `type: "website"` | `/packages/{i}/externalRefs[]` with category `OTHER`, type `homepage` (or `homepage` field on Package if present in our data) | `software_Package/software_homePage` | Native in 1.6/2.3; 3.0.1 has dedicated `software_homePage`. |
| A10 | external reference — VCS | `/components/{i}/externalReferences[]` with `type: "vcs"` | `/packages/{i}/externalRefs[]` with category `OTHER`, type `vcs` | `software_Package/software_sourceInfo` | Native homes available in all. |
| A11 | external reference — deps.dev / registry | `/components/{i}/externalReferences[]` with `type: "distribution"` | `/packages/{i}/downloadLocation` (when distribution URL is canonical) and/or `externalRefs[]` | `software_Package/software_downloadLocation` | Use `downloadLocation` when authoritative; `NOASSERTION` otherwise. |
| A12 | CPE — primary (single-valued) | `/components/{i}/cpe` | `/packages/{i}/externalRefs[]` with `referenceCategory: "SECURITY"`, `referenceType: "cpe23Type"`, `referenceLocator: <CPE string>` | `defer until SPDX 3 security/externalIdentifier modeling lands in the stub` — SPDX 3 exposes CPE via `ExternalIdentifier` elements; out of initial-stub scope. | Native in all. CDX's single `cpe` field is the highest-signal synthesized candidate; the remaining candidates land in `mikebom:cpe-candidates` per C19. |

## Section B — Graph structure (relationships)

| # | mikebom data | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|--------------|------------------------|-------------------|---------------------|---------------|
| B1 | dependency edge (runtime) | `/dependencies[]/dependsOn[]` | `Relationship` with `relationshipType: "DEPENDS_ON"` | `Relationship` element with `relationshipType: "dependsOn"` | Native graph edges in all. |
| B2 | dependency edge (dev) | `/dependencies[]/dependsOn[]` annotated by `mikebom:dev-dependency` property | `Relationship` with `relationshipType: "DEV_DEPENDENCY_OF"` | `Relationship` with `relationshipType: "devDependencyOf"` | SPDX has a dedicated relationship type — use it instead of generic `DEPENDS_ON` when scope is known. |
| B3 | nested containment (shade-jar parent → children) | `/components/{i}/components[]` (CDX nests inline) | Flat `Package`s + `Relationship` with `relationshipType: "CONTAINS"` from parent SPDXID to child SPDXID | Flat `Package`s + `Relationship` `relationshipType: "contains"` | SPDX has no nesting; containment is expressed by relationships. Edge case: nested components. |
| B4 | image / filesystem root | `/metadata/component` | `documentDescribes: [<root SPDXID>]` plus `Relationship` `DESCRIBES` from document to root | `SpdxDocument/rootElement` | All three formats name the root differently; mapping is mechanical. Synthesize a root if no natural one exists. |

## Section C — mikebom-specific data preserved via fallback

These rows have no native SPDX 2.3 home. Per clarification Q2 (Option A) and FR-016, they land in SPDX `annotations[]` with the named `MikebomAnnotationCommentV1.field` value. The annotation is attached to the document or to the relevant Package as indicated.

| # | mikebom property | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|------------------|------------------------|-------------------|---------------------|---------------|
| C1 | `mikebom:source-type` | `/components/{i}/properties[name="mikebom:source-type"]` | Annotation `mikebom:source-type` on Package | Same as 2.3 (annotation), pending native SPDX 3 profile property | No SPDX 2.3 field. |
| C2 | `mikebom:source-connection-ids` | property | Annotation `mikebom:source-connection-ids` on Package | Annotation (defer until SPDX 3 build/provenance profile stabilizes) | No SPDX 2.3 field. |
| C3 | `mikebom:deps-dev-match` | property | Annotation `mikebom:deps-dev-match` on Package | Annotation | No SPDX 2.3 field. |
| C4 | `mikebom:evidence-kind` | property | Annotation `mikebom:evidence-kind` on Package | Annotation (defer until SPDX 3 evidence profile stabilizes) | No SPDX 2.3 field. |
| C5 | `mikebom:sbom-tier` | property | Annotation `mikebom:sbom-tier` on Package | Annotation | No SPDX 2.3 field. |
| C6 | `mikebom:dev-dependency` | property | (also reflected as `DEV_DEPENDENCY_OF` per B2) + Annotation `mikebom:dev-dependency` on Package | (relationship per B2) + Annotation | Relationship is the primary signal; annotation preserves the boolean. |
| C7 | `mikebom:co-owned-by` | property | Annotation `mikebom:co-owned-by` on Package | Annotation | No SPDX 2.3 field. |
| C8 | `mikebom:shade-relocation` | property | Annotation `mikebom:shade-relocation` on Package | Annotation | No SPDX 2.3 field. |
| C9 | `mikebom:npm-role` | property | Annotation `mikebom:npm-role` on Package | Annotation | No SPDX 2.3 field. |
| C10 | `mikebom:binary-class` | property | Annotation `mikebom:binary-class` on Package | Annotation | No SPDX 2.3 field. |
| C11 | `mikebom:binary-stripped` | property | Annotation `mikebom:binary-stripped` on Package | Annotation | No SPDX 2.3 field. |
| C12 | `mikebom:linkage-kind` | property | Annotation `mikebom:linkage-kind` on Package | Annotation | No SPDX 2.3 field. |
| C13 | `mikebom:buildinfo-status` | property | Annotation `mikebom:buildinfo-status` on Package | Annotation | No SPDX 2.3 field. |
| C14 | `mikebom:detected-go` | property | Annotation `mikebom:detected-go` on Package | Annotation | No SPDX 2.3 field. |
| C15 | `mikebom:binary-packed` | property | Annotation `mikebom:binary-packed` on Package | Annotation | No SPDX 2.3 field. |
| C16 | `mikebom:confidence` | property | Annotation `mikebom:confidence` on Package | Annotation (defer until SPDX 3 evidence profile lands `confidence`) | No SPDX 2.3 field; confidence is a Constitution Principle X transparency signal. |
| C17 | `mikebom:raw-version` (RPM) | property | Annotation `mikebom:raw-version` on Package | Annotation | No SPDX 2.3 field. |
| C18 | `mikebom:source-files` | property | Annotation `mikebom:source-files` on Package | `Package/contentBy` element (SPDX 3 build profile) — defer | No SPDX 2.3 field. |
| C19 | `mikebom:cpe-candidates` | property | Annotation `mikebom:cpe-candidates` on Package (and `externalRefs[]` `SECURITY/cpe23Type` for any candidate that is fully resolved) | Annotation + `externalRef` `cpe23Type` for resolved candidates | Multiple-candidate set has no native home; resolved CPE goes into native externalRefs. |
| C20 | `mikebom:requirement-range` | property | Annotation `mikebom:requirement-range` on Package | Annotation | No SPDX 2.3 field. |
| C21 | `mikebom:generation-context` (document-level) | `/metadata/properties[name="mikebom:generation-context"]` | Document-level Annotation `mikebom:generation-context` | `CreationInfo/comment` if short, otherwise document-level Annotation | Constitution Principle V requires "Generation Context"; document-level annotation honors it. |
| C22 | `mikebom:os-release-missing-fields` (document-level) | metadata property | Document-level Annotation `mikebom:os-release-missing-fields` | Document-level Annotation | No SPDX 2.3 field. |
| C23 | `mikebom:trace-integrity-*` (document-level: ring-buffer-overflows, events-dropped, uprobe/kprobe-attach-failures) | metadata properties | Document-level Annotations `mikebom:trace-integrity-<subkey>` | Document-level Annotations (defer until SPDX 3 build/provenance profile stabilizes) | Constitution Principle X transparency; preserve verbatim. |

## Section D — Evidence (CycloneDX 1.6 has native model; SPDX 2.3 does not)

| # | mikebom data | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|--------------|------------------------|-------------------|---------------------|---------------|
| D1 | evidence — identity (technique + confidence) | `/components/{i}/evidence/identity[0]` | Annotation `evidence.identity` on Package, payload preserves `technique` + `confidence` | `Package/evidence` (SPDX 3 evidence profile) — defer to follow-up | SPDX 2.3 has no evidence model; annotation preserves it losslessly. |
| D2 | evidence — occurrences | `/components/{i}/evidence/occurrences[]` (location + SHA-256 + legacy MD5) | Annotation `evidence.occurrences` on Package, payload is the original CDX array | `Package/evidence/occurrences` (SPDX 3 evidence profile) — defer | Same rationale as D1; deb deep-hash output relies on this. |

## Section E — Compositions / completeness markers

| # | mikebom data | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|--------------|------------------------|-------------------|---------------------|---------------|
| E1 | ecosystem completeness claim | `/compositions[]` with `aggregate` + `assemblies/dependencies` | Document-level Annotation `compositions`, payload is the original CDX array | `SpdxDocument/profileConformance` (when applicable) + Annotation for residual claims — defer | SPDX 2.3 has no `compositions` analogue. |

## Section F — VEX (CycloneDX 1.6 has native section; SPDX 2.3 does not)

| # | mikebom data | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|--------------|------------------------|-------------------|---------------------|---------------|
| F1 | vulnerabilities (VEX statements) | `/vulnerabilities[]` | **Sidecar OpenVEX 0.2.0 file** at `mikebom.openvex.json` (next to the SPDX file). Referenced from the SPDX document via `externalDocumentRefs[]` (`externalDocumentId: "DocumentRef-OpenVEX"`, `spdxDocument: <relative path>`, `checksum: SHA-256 of sidecar bytes`). When no VEX statements exist, no sidecar file is created. | SPDX 3 security profile is the long-term home — defer until profile stabilizes. Same OpenVEX sidecar approach for the stub. | Per clarification Q2 (Option A): annotations would balloon for vulnerable images; OpenVEX is the purpose-built spec; CSAF VEX is overkill. |

## Section G — Document envelope

| # | mikebom data | CycloneDX 1.6 location | SPDX 2.3 location | SPDX 3.0.1 location | Justification |
|---|--------------|------------------------|-------------------|---------------------|---------------|
| G1 | tool name + version | `/metadata/tools/components[name="mikebom"]` | `creationInfo/creators[]: "Tool: mikebom-<version>"` | `CreationInfo/createdUsing` of `Tool` element with `name`/`packageVersion` | Native in all. |
| G2 | created timestamp | `/metadata/timestamp` | `creationInfo/created` | `CreationInfo/created` | Native in all. Sourced from a single `OutputConfig.created` to keep all formats in one invocation in lockstep. |
| G3 | data license | n/a | `dataLicense: "CC0-1.0"` (SPDX-mandated) | `dataLicense` field on document | SPDX-required. |
| G4 | document namespace | n/a (CDX uses `serialNumber: "urn:uuid:..."` — random per emission) | `documentNamespace` derived per R8 (deterministic) | `SpdxDocument/spdxId` URI (deterministic) | CDX `serialNumber` remains random for backward-compat reasons; SPDX namespaces are deterministic per FR-020. |

## Maintenance contract

This map is owned by milestone 010 and MUST be updated in lockstep with any future milestone that adds a new mikebom property, new external reference, new evidence type, or new ecosystem. Per SC-004, a CI check enforces 100% row coverage by scanning the existing CDX output for distinct property names and asserting each has a row here.
