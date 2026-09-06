---
cisa-publication: "2026 Minimum Elements for a Software Bill of Materials (SBOM)"
cisa-publication-date: 2026-07-29
cisa-publication-tlp: TLP:CLEAR
cisa-publication-url: https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf
waybill-milestone: 222
last-verified: 2026-07-31
---

# waybill vs CISA 2026 SBOM Minimum Elements — coverage matrix

**Reader path**: see [`specs/221-cisa-2026-elements-audit/quickstart.md`](../specs/221-cisa-2026-elements-audit/quickstart.md).

**Machine-verified**: `waybill-cli/tests/cisa_2026_coverage_matrix.rs` walks
every ✅ verdict below against a fresh scan on every CI run. A regression
that empties a native slot fails the test.

**Vocabulary**:
- **✅** — native field populated by waybill by default.
- **⚠️** — populated via a `waybill:*` annotation (parity-bridging where
  the target format has no native slot). Documented in
  [`docs/reference/sbom-format-mapping.md`](reference/sbom-format-mapping.md).
- **❌** — absent. Every ❌ links to a follow-up user story in
  [`specs/221-cisa-2026-elements-audit/spec.md`](../specs/221-cisa-2026-elements-audit/spec.md).

---

## Data Fields (17)

Rows 1–9 are SBOM Metadata elements (about the SBOM document itself).
Rows 10–17 are Component Data elements (about the target and its
subcomponents).

| # | Element (CISA 2026) | Category | Change (vs 2021) | CDX 1.6 | SPDX 2.3 | SPDX 3.0.1 | Notes |
|---|---------------------|----------|-------------------|---------|----------|-----------|-------|
| 1 | SBOM Author | Metadata | Major Update | ✅ `metadata.authors[]` at `waybill-cli/src/generate/cyclonedx/metadata.rs:798` | ✅ `creationInfo.creators[]` at `waybill-cli/src/generate/spdx/document.rs:806` | ✅ `CreationInfo.createdBy` at `waybill-cli/src/generate/spdx/v3_document.rs:229` | m080 wires `--creator` / `--annotator` from `waybill trace run`; standalone `waybill sbom scan` uses waybill as the sole author. Distinct from Component Producer (element 10). |
| 2 | SBOM Author Signature | Metadata | New | ⚠️ opt-in, **static key only** — `--sign-key <PATH>` populates the document-root `signature` slot with a JSF (JSON Signature Format, draft-cyberphone-jsf-00) object carrying a JWK public key (m221 US2a, corrected by m777). `--sign` (Sigstore keyless) emits a **detached Sigstore Bundle sidecar** at `<output>.sig.bundle.json` as of m778, rather than an in-document signature. A Sigstore Bundle has no conformant JSF representation — the transparency-log inclusion proof has no slot, and without it a short-lived Fulcio certificate cannot be shown valid at signing time — so embedding it would produce either a schema-invalid document (pre-m777) or a signature with a ten-minute useful life. The document itself stays unsigned and schema-valid, and carries a document-level `externalReferences[]` entry of type `attestation` naming the sidecar by relative filename so consumers can find it. Verify with `cosign verify-blob --bundle <output>.sig.bundle.json <output>`. Static-key path at `waybill-cli/src/sbom/signer.rs::sign_cdx_document_in_place`. **Milestone 777 note**: before that milestone the signature was written to `metadata.signature`, which the schema rejects (`metadata` is `additionalProperties: false`), and the public key was a PEM blob where JSF requires a JWK — signed documents were schema-invalid and read as unsigned by conforming consumers. Absent by default per FR-009. See `specs/222-sigstore-keyless-signing/contracts/keyless-signing-flow.md`. | ⚠️ opt-in — either `--sign-key <PATH>` emits a DSSE envelope sidecar at `<output>.sig.json` (m221 US2a) OR `--sign` emits a Sigstore Bundle sidecar at `<output>.sig.bundle.json` (m222 US2b). SPDX 2.3 has no native in-document envelope-signature slot; both shapes routed through `waybill-cli/src/sbom/signer.rs::sign_spdx_bytes_to_sidecar`. Absent by default. | ⚠️ opt-in — same dual-shape sidecar rules as SPDX 2.3 (SPDX 3 also lacks a native in-document envelope-signature slot). Either `--sign-key <PATH>` emits `.sig.json` (DSSE) or `--sign` emits `.sig.bundle.json` (Sigstore Bundle) per FR-004. Absent by default. | **Static-key signing is CycloneDX-conformant (m777); keyless signs CycloneDX to a detached sidecar (m778)** (Sigstore keyless with the v1 scope constraint below). Feature 221 US2a landed static-key signing (PEM path); feature 222 US2b landed the Sigstore keyless flow — explicit `SIGSTORE_ID_TOKEN` env-var → Fulcio → sign → Rekor inclusion → Sigstore Bundle assembly. **v1 scope constraint**: sigstore-rs 0.11 requires OIDC tokens to emit an `email` claim (used as the CSR subject sent to Fulcio); GitHub Actions ambient tokens do not emit `email`. Compatible providers: `cosign login`, Sigstore-dex, Google, GitLab, any provider emitting `email`. GHA users fetch a token via a helper (e.g., `sigstore/gh-action-sigstore-python`) and export it as `SIGSTORE_ID_TOKEN`. Full GHA-ambient support deferred to a follow-up milestone (requires ~30-50 LOC upstream sigstore-rs change). CLI rejects `--sign` / `--sign-key + --output -` at parse per FR-008a; both signing paths fail-close on any error per FR-009a (unlink partial output). Vendored Sigstore CTFE keys documented in `docs/sigstore-trust-keys.md`. Verification: `jq .signature signed.cdx.json` + JSF-verifier for CDX static-key; `cosign verify-blob --bundle <output>.sig.bundle.json --certificate-identity <expected> --certificate-oidc-issuer <expected> <output>` for keyless, which as of m778 applies to CycloneDX as well as SPDX — both sign to a detached sidecar. |
| 3 | SBOM Data Format Name | Metadata | New | ✅ `bomFormat: "CycloneDX"` at `waybill-cli/src/generate/cyclonedx/builder.rs:813` | ⚠️ implicit in `spdxVersion: "SPDX-2.3"` at `waybill-cli/src/generate/spdx/document.rs:152` (format name and version are combined in one slot per SPDX 2.3 § 6.1) | ⚠️ implicit in top-level `@context` at `waybill-cli/src/generate/spdx/v3_document.rs:863` (SPDX 3 uses JSON-LD, format name is the `@context` URL) | SPDX doesn't split format name from format version the way CDX does; the ⚠️ reflects that the CISA element is technically satisfied but the value has to be inferred from a compound slot. |
| 4 | SBOM Data Format Version | Metadata | New | ✅ `specVersion: "1.6"` at `waybill-cli/src/generate/cyclonedx/builder.rs:814` | ✅ `spdxVersion: "SPDX-2.3"` at `waybill-cli/src/generate/spdx/document.rs:152` | ✅ `CreationInfo.specVersion: "3.0.1"` at `waybill-cli/src/generate/spdx/v3_document.rs:227` | All three formats emit a version literal at document scope. |
| 5 | SBOM Generation Context | Metadata | New | ✅ native `metadata.lifecycles[]` at `waybill-cli/src/generate/cyclonedx/metadata.rs:1099` (m047 aggregates `ScanArtifacts.generation_context` into CDX-native phases). ✅ courtesy alias `metadata.properties[waybill:cisa-2026-lifecycle]` at `metadata.rs` (m221 US3 / FR-012). | ⚠️ doc-scope `Annotation` on `SPDXRef-DOCUMENT` at `waybill-cli/src/generate/spdx/annotations.rs::annotate_document` — carries both `waybill:generation-context` (waybill-native variant) and `waybill:cisa-2026-lifecycle` (CISA-vocab alias) per m221 US3 / FR-010 + FR-012. | ⚠️ top-level `Annotation` element with `subject: <SpdxDocument @id>` at `waybill-cli/src/generate/spdx/v3_annotations.rs::push_document_fields` — same two-annotation shape as SPDX 2.3 per m221 US3 / FR-011 + FR-012. Validates cleanly against SPDX 3.0.1 schema + SHACL via `spdx3-validate==0.0.5`. | CISA "before-build"/"build"/"after-build" vocab satisfied per CISA page 9 ("more specific identifiers can satisfy this element"). Mapping table lives in `waybill_common::attestation::metadata::GenerationContext::as_cisa_2026_lifecycle`: `build-time-trace → build`; `filesystem-scan → after-build`; `container-image-scan → after-build`. Parity extractor row `C141` at `waybill-cli/src/parity/extractors/mod.rs`. |
| 6 | SBOM Timestamp | Metadata | Minor Update | ✅ `metadata.timestamp` (RFC 3339, deterministic via `OutputConfig.created`) at `waybill-cli/src/generate/cyclonedx/metadata.rs:799` | ✅ `creationInfo.created` at `waybill-cli/src/generate/spdx/document.rs:826` | ✅ `CreationInfo.created` at `waybill-cli/src/generate/spdx/v3_document.rs:228` | RFC 9557 tolerates RFC 3339 (RFC 9557 § 3.2 extension). |
| 7 | SBOM Tool Name | Metadata | New | ✅ `metadata.tools.components[].name = "waybill"` at `waybill-cli/src/generate/cyclonedx/metadata.rs:825` | ✅ `creationInfo.creators[]` contains `"Tool: waybill-<version>"` at `waybill-cli/src/generate/spdx/document.rs:806` | ✅ `Tool.name` referenced via `CreationInfo.createdBy` at `waybill-cli/src/generate/spdx/v3_document.rs:229` | Native across all three. |
| 8 | SBOM Tool Version | Metadata | New | ✅ same slot as Tool Name (`metadata.tools.components[].version`) | ✅ version embedded in the `Tool: waybill-<version>` string (same slot as Tool Name) | ✅ version on the `Tool` element (same slot as Tool Name) | Waybill emits the workspace version at build time via `env!("CARGO_PKG_VERSION")`. |
| 9 | SBOM Version | Metadata | New | ✅ native `metadata.version` at `waybill-cli/src/generate/cyclonedx/builder.rs:826` — defaults to `1` (byte-identical to pre-m221) when `--sbom-version` unset; carries the operator-supplied integer when set. ⚠️ parity annotation `metadata.properties[waybill:sbom-version]` emitted only when `--sbom-version` is set (m221 US4 / FR-013). | ⚠️ doc-scope `Annotation` on `SPDXRef-DOCUMENT` carrying `waybill:sbom-version=<N>` at `waybill-cli/src/generate/spdx/annotations.rs::annotate_document` — emitted only when `--sbom-version` is set (m221 US4 / FR-013). SPDX 2.3 has no native SBOM-document-version field; the annotation is the primary carrier. | ⚠️ top-level `Annotation` element with `subject: <SpdxDocument @id>` carrying `waybill:sbom-version` at `waybill-cli/src/generate/spdx/v3_annotations.rs::push_document_fields` — same emission gate as SPDX 2.3. | CISA 2026 § SBOM Version blesses RFC 9562 UUIDs as an alternative pathway; waybill's existing `serialNumber` UUID (CDX at `builder.rs:815`) + content-addressed `documentNamespace` (SPDX 2.3 per m010) + `@id` (SPDX 3 per m010) already satisfy the identity pathway. The `--sbom-version` integer covers the monotonic-counter pathway consumers who key on `metadata.version` expect. Parity extractor row `C142` at `waybill-cli/src/parity/extractors/mod.rs`. Value type: positive integer (`{"type": "integer", "minimum": 1}`); non-integer values and values < 1 rejected at CLI parse per FR-014. |
| 10 | Component Producer | Component | Major Update | ✅ `components[].supplier.name` populated from `ResolvedComponent.supplier` | ✅ `packages[].supplier` at `waybill-cli/src/generate/spdx/packages.rs:186` (uses `NOASSERTION` sentinel per CISA § Explicitly Identifying Unknown Information when unknown; verified at `packages.rs:285` and `641`) | ✅ `Package.suppliedBy` (IRI reference to an `Organization` element in the `@graph`, deduplicated per `v3_agents.rs:68`) | Renamed from 2021 "Supplier Name" — waybill absorbed the rename at m080. Both SPDX 2.3 and SPDX 3 model supplier + originator as separate slots (`supplier` / `originator` on SPDX 2.3 packages, `suppliedBy` / `originatedBy` on SPDX 3 packages); waybill populates the *supplier* slot with the entity that distributed the artifact (which CISA's Component Producer definition covers). |
| 11 | Component Dependency Relationship | Component | Minor Update | ✅ `dependencies[]` array with `ref` + `dependsOn[]` in `waybill-cli/src/generate/cyclonedx/dependencies.rs` | ✅ `relationships[]` with `DEPENDS_ON` (plus m052-native `DEV_DEPENDENCY_OF` / `BUILD_DEPENDENCY_OF` / `TEST_DEPENDENCY_OF` and m179-native `OPTIONAL_DEPENDENCY_OF` per Section B row B2 of `docs/reference/sbom-format-mapping.md`) | ✅ `Relationship` element with `relationshipType: "dependsOn"` plus m052-native `LifecycleScopeType` parameter | Waybill's dep-graph semantics exceed CISA's baseline (dev/build/test scope carried natively per Principle V). |
| 12 | Component Hash Value | Component | New | ✅ `components[].hashes[].content` at `waybill-cli/src/generate/cyclonedx/builder.rs:1048` (when `include_hashes` per `--no-hashes`) | ✅ `packages[].checksums[].checksumValue` at `waybill-cli/src/generate/spdx/packages.rs:192` | ✅ `Package.verifiedUsing[]` Hash object per Section A row A6 of `sbom-format-mapping.md` | Content hash of the executable/package artifact; hex-encoded per CISA. |
| 13 | Component Hash Algorithm | Component | New | ✅ `components[].hashes[].alg` (IANA Hash Function Textual Names per CDX 1.6 § component.hashes enum) at `builder.rs:1048` | ✅ `packages[].checksums[].algorithm` enum at `packages.rs:192` (SPDX 2.3 supports `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`MD5`/etc.) | ✅ `Hash.algorithm` on the verifiedUsing element (lowercase-no-hyphen `sha256` per SPDX 3.0.1 `prop_Hash_algorithm` enum) | All three formats' algorithm identifiers map to IANA-registered names per CISA's requirement. |
| 14 | Component Identifiers | Component | Major Update | ✅ `components[].purl` (always present when derivable) + `components[].cpe` at `builder.rs:1152` + `components[].externalReferences[]` for SWHID / OmniBOR at `builder.rs:1142` | ✅ `packages[].externalRefs[]` with `referenceCategory: "PACKAGE-MANAGER"` (PURL), `"SECURITY"` (CPE), `"OTHER"` (SWHID/OmniBOR) | ✅ `Package.software_packageUrl` + `Package.externalIdentifier[]` for PURL/CPE23/SWHID/OmniBOR per Section A row A1 of `sbom-format-mapping.md` | CISA says "at least one common software identifier"; waybill emits PURL always plus CPE/SWHID/OmniBOR when resolvable. |
| 15 | Component License | Component | New | ✅ `components[].licenses[]` at `builder.rs:1123` (SPDX identifiers/expressions; `waybill:*` fallback annotation for non-canonicalizable per m146 dedupe) | ✅ `packages[].licenseConcluded` + `packages[].licenseDeclared` at `packages.rs:193-195` (canonical SPDX expression / `LicenseRef-<hash>` per m153) | ✅ `simplelicensing_LicenseExpression` element referenced via `Relationship` (`hasDeclaredLicense` / `hasConcludedLicense`) per Section A row A7 of `sbom-format-mapping.md` | All three formats emit SPDX identifiers per CISA's SPDX preference (page 12). |
| 16 | Component Name | Component | Minor Update | ✅ `components[].name` (required by CDX 1.6 schema) | ✅ `packages[].name` at `packages.rs` (required by SPDX 2.3 schema) | ✅ `Package.name` (required by SPDX 3.0.1 schema) | CISA "must allow multiple entries" satisfied via the multiplicity of the `components[]` / `packages[]` array — one entry per distinct name. |
| 17 | Component Version | Component | Major Update | ⚠️ `components[].version` populated when known, omitted when unknown (CDX has no `NOASSERTION` convention — asymmetry with SPDX flagged per Edge Case #1 in `spec.md`) | ✅ `packages[].versionInfo` at `packages.rs:181` — uses `NOASSERTION` when unknown per `packages.rs:641` (satisfies CISA § Explicitly Identifying Unknown Information) | ✅ `Package.software_packageVersion` at `waybill-cli/src/generate/spdx/v3_packages.rs` (with `NOASSERTION`-equivalent omission) | m191 reconciler ensures the version field carries an explicit "unknown" marker on the SPDX side; CDX-side omission is documented and left to consumers to interpret. |

---

## Practices & Processes (6)

Per CISA 2026 § SBOM Minimum Elements page 7, Practices & Processes
"outline principles that guide SBOM operations across the software
lifecycle." They describe how an **organization** engages with SBOM
data — not payload fields inside the SBOM itself. Consumers auditing
this element look for evidence in operator workflows, tooling contracts,
and delivery pipelines, not in a jq-extractable slot.

### Accommodation of Updates to SBOM Data (Major Update)

**CISA text**: > "Organizations should accommodate updates to SBOM data,
including corrections. SBOM authors should correct errors promptly.
Organizations may consider errors, whether stemming from SBOM author
practices or selection of inadequate tools, in organizational risk
management decisions." (page 13)

**Classification**: **Organizational practice** — not a payload
element. Waybill's role is to enable the operator to satisfy the
practice.

**How waybill enables the operator to satisfy this**:
- Every `waybill sbom scan` invocation regenerates the SBOM from
  scratch — no cached state, no stale document. A correction to the
  target (updated lockfile, patched binary, added metadata) reflects
  in the very next scan.
- Deterministic output (RFC 8785 canonical JSON, milestone-010
  content-addressed identifiers) means "re-run to correct" produces
  a byte-comparable diff so operators can prove what changed.
- `--sbom-version <N>` (US4 pending) lets operators tag the corrected
  revision so consumers can order-by-revision.

### Coverage (Major Update — was "Depth")

**CISA text**: > "An SBOM should include information for all components
that make up the target software, including transitive dependencies.
There is no minimum depth. ... SBOMs should provide a comprehensive
listing of the components to facilitate recipients' risk-based
decisions." (page 13)

**Classification**: **Organizational practice** — describes the
recipient's ability to make risk-based decisions, not a payload slot.

**How waybill enables the operator to satisfy this**:
- Every `waybill sbom scan` emits a document-scope
  `waybill:graph-completeness` annotation (milestone 158) tracking
  horizontal breadth (per-ecosystem component enumeration) and
  vertical depth (transitive-dep resolution ladder per m055 + m160).
- Ecosystem-completeness per m158 assigns each ecosystem a
  compact 5-tier state (Complete / TransitivePartial / DirectOnly /
  Manifest / None) so consumers can filter their risk decisions.
- Fail-close on any completeness regression per Constitution
  Principle III (no silent gap-filling).

### Distribution and Delivery (Minor Update — absorbed "Access Control")

**CISA text**: > "SBOMs should be available promptly to those who
need them. Access controls may limit the sharing of SBOM data with
unauthorized parties but should not prevent information sharing
between authorized parties or restrict organizations from integrating
SBOM data into trusted security tools. There are multiple ways of
sharing SBOM data. For example, an SBOM can accompany installation.
Alternatively, an SBOM can be accessible through a version-specific
URL, an application programming interface (API) to a database, or a
public repository. Any such software service or offering should
operate in accordance with the provider's security policy." (page 13)

**Classification**: **Organizational practice** — describes what
happens *after* the SBOM is emitted; entirely outside waybill's
runtime scope.

**How waybill enables the operator to satisfy this**:
- Waybill emits to `--output <path>` (default `waybill.cdx.json`) or
  `--output -` (stdout) — the operator wires that into their delivery
  pipeline of choice (artifact registry, OCI Referrers per m186, S3
  bucket, HTTP endpoint).
- OCI Referrers integration per m186 (`--sbom-source referrer|either`)
  lets the operator pull a pre-existing SBOM instead of scanning —
  supporting "distribution via OCI registry" natively.

### Explicitly Identifying Unknown Information (Major Update — was "Known Unknowns")

**CISA text**: > "If information required for any of the data fields
is not provided, the SBOM author should explicitly state whether the
information is unknown to the SBOM author or whether the SBOM author
is withholding the information from the SBOM." (page 13)

**Classification**: **Organizational practice**, but has native
payload manifestations (see below).

**How waybill enables the operator to satisfy this**:
- SPDX 2.3 emitter uses `NOASSERTION` sentinels for
  `packages[].versionInfo` (`packages.rs:641`) and
  `packages[].supplier` (`packages.rs:285`) when the value is unknown
  to waybill — satisfies the "explicitly state unknown" clause
  natively per SPDX 2.3 convention.
- CDX 1.6 omits unknown fields (no sentinel convention exists); the
  ambiguity between "unknown" and "withheld" for CDX outputs is
  documented in `spec.md` Edge Case #1 and left for consumers to
  interpret from the omission.
- Waybill does NOT withhold information in the default output —
  any absent field means "waybill did not know," never "waybill
  knew but hid." This posture is documented here as the operator's
  guarantee.

### Frequency (Minor Update)

**CISA text**: > "Each software version or update should have an
associated SBOM. When a component producer issues a new build or
release, they (or the SBOM author) should also generate a new SBOM to
reflect the changes. This includes software builds that integrate
updated components or dependencies. When a component producer (or
SBOM author) discovers new details about the underlying components or
corrects an error in the existing SBOM data, they (or the SBOM
author) should issue a revised SBOM." (page 14)

**Classification**: **Organizational practice** — describes the
cadence with which the operator invokes the SBOM generator.

**How waybill enables the operator to satisfy this**:
- Deterministic regeneration per invocation with a fresh
  `serialNumber` (CDX) and content-addressed `documentNamespace` /
  `@id` (SPDX per m010) — every scan produces a distinctly-identified
  document even for the same target.
- No caching of prior SBOMs means the operator's CI can safely
  invoke `waybill sbom scan` on every commit, every release tag,
  every published container image — the operator chooses the
  cadence.
- Fast: typical mid-sized project SBOM emits in <5 seconds per m094
  perf goldens, so per-commit invocation is feasible.

### Machine-Processable Data (Major Update — was "Automation Support")

**CISA text**: > "Automation support is critical for managing
software component data at scale, particularly across organizational
boundaries. SBOM implementations should be compatible with each
other to support automation due to the volume of data, diverse use
cases, and variety of tools involved with SBOMs. The two data
formats currently widely used by software ecosystem stakeholders to
generate and consume SBOMs are SPDX and CycloneDX. These data
formats are a product of open, international processes and are both
machine-processable and human-readable." (page 14)

**Classification**: **Organizational practice** on the operator side
(choose a widely-supported format); native payload guarantee on the
waybill side (waybill emits only in machine-processable formats).

**How waybill enables the operator to satisfy this**:
- Waybill emits CycloneDX 1.6, SPDX 2.3, and SPDX 3.0.1 — the three
  formats CISA 2026 names. Selectable via `--format <name>`;
  multi-format in one invocation via repeated `--format` flags.
- All three outputs are valid JSON (SPDX 3 is JSON-LD).
- SPDX 3 conformance validated in CI via
  `spdx3-validate==0.0.5` (milestone 078) — gated by
  `WAYBILL_REQUIRE_SPDX3_VALIDATOR=1`.
- **2026 change advisory (SWID removed)** <!-- fr-016-swid-advisory -->:
  Per CISA 2026 Appendix B § Automation Support: "Remove Software
  Identification (SWID) Tags from list of data formats. ... SWID tags
  are not a widely used SBOM data format for which multiple tools
  exist." Waybill has never emitted SWID and has no plan to; this is
  a no-change advisory row acknowledging the CISA vocabulary update.

---

## Appendix A — Reproducible verification recipes

Every ✅ cell in the matrix above cites a slot; this appendix gives
the exact `jq` recipe to extract the value from a fresh scan. Every
recipe MUST return a non-empty JSON value when run against a live
scan output; the integration test at
`waybill-cli/tests/cisa_2026_coverage_matrix.rs` asserts this on
every CI run.

**Setup** (run once):

```bash
target_dir=~/.cache/waybill/fixtures/*/transitive_parity/cargo
waybill sbom scan \
  --path "$target_dir" \
  --format cyclonedx-json,spdx-2.3-json,spdx-3-json \
  --output cyclonedx-json=/tmp/scan.cdx.json \
  --output spdx-2.3-json=/tmp/scan.spdx.json \
  --output spdx-3-json=/tmp/scan.spdx3.json
```

Recipes below assume `/tmp/scan.cdx.json` /
`/tmp/scan.spdx.json` / `/tmp/scan.spdx3.json` from the setup.

**Element: SBOM Author** (row 1)
- CDX: `jq -r '.metadata.authors[].name' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.creationInfo.creators[]' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][] | select(.type=="CreationInfo") | .createdBy[]' /tmp/scan.spdx3.json | head -1`

**Element: SBOM Data Format Name** (row 3)
- CDX: `jq -r '.bomFormat' /tmp/scan.cdx.json`
- SPDX 2.3: `jq -r '.spdxVersion' /tmp/scan.spdx.json`
- SPDX 3: `jq -r '.["@context"]' /tmp/scan.spdx3.json`

**Element: SBOM Data Format Version** (row 4)
- CDX: `jq -r '.specVersion' /tmp/scan.cdx.json`
- SPDX 2.3: `jq -r '.spdxVersion' /tmp/scan.spdx.json`
- SPDX 3: `jq -r '.["@graph"][] | select(.type=="CreationInfo") | .specVersion' /tmp/scan.spdx3.json`

**Element: SBOM Generation Context** (row 5, all three formats post-m221 US3)
- CDX: `jq -r '.metadata.lifecycles[].phase' /tmp/scan.cdx.json`
- SPDX 2.3: `jq -r '.annotations[]?.comment | select(contains("waybill:cisa-2026-lifecycle"))' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="Annotation") | .statement | select(contains("waybill:cisa-2026-lifecycle"))' /tmp/scan.spdx3.json | head -1`

**Element: SBOM Timestamp** (row 6)
- CDX: `jq -r '.metadata.timestamp' /tmp/scan.cdx.json`
- SPDX 2.3: `jq -r '.creationInfo.created' /tmp/scan.spdx.json`
- SPDX 3: `jq -r '.["@graph"][] | select(.type=="CreationInfo") | .created' /tmp/scan.spdx3.json`

**Element: SBOM Tool Name** (row 7)
- CDX: `jq -r '.metadata.tools.components[].name' /tmp/scan.cdx.json`
- SPDX 2.3: `jq -r '.creationInfo.creators[] | select(startswith("Tool:"))' /tmp/scan.spdx.json`
- SPDX 3: `jq -r '.["@graph"][] | select(.type=="Tool") | .name' /tmp/scan.spdx3.json`

**Element: SBOM Tool Version** (row 8)
- CDX: `jq -r '.metadata.tools.components[].version' /tmp/scan.cdx.json`
- SPDX 2.3: `jq -r '.creationInfo.creators[] | select(startswith("Tool:"))' /tmp/scan.spdx.json` (version is embedded in the creator string)
- SPDX 3: `jq -r '.["@graph"][] | select(.type=="Tool") | .name' /tmp/scan.spdx3.json` (version embedded in tool name)

**Element: SBOM Version** (row 9)
- CDX (native): `jq '.version' /tmp/scan.cdx.json` (returns 1 by default; the operator-supplied integer when `--sbom-version <N>` is passed)
- SPDX 2.3 (annotation, only when `--sbom-version` is set): `jq -r '.annotations[]?.comment | select(contains("waybill:sbom-version"))' /tmp/scan.spdx.json | head -1`
- SPDX 3 (annotation, only when `--sbom-version` is set): `jq -r '.["@graph"][]? | select(.type=="Annotation") | .statement | select(contains("waybill:sbom-version"))' /tmp/scan.spdx3.json | head -1`

**Element: Component Producer** (row 10)
- CDX: `jq -r '.components[]?.supplier?.name // empty' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.packages[]?.supplier // empty' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="software_Package") | .suppliedBy // empty' /tmp/scan.spdx3.json | head -1`

**Element: Component Dependency Relationship** (row 11)
- CDX: `jq '.dependencies[]?.dependsOn // empty | length' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.relationships[]?.relationshipType' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="Relationship") | .relationshipType' /tmp/scan.spdx3.json | head -1`

**Element: Component Hash Value** (row 12)
- CDX: `jq -r '.components[]?.hashes[]?.content // empty' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.packages[]?.checksums[]?.checksumValue // empty' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="software_Package") | .verifiedUsing[]?.hashValue // empty' /tmp/scan.spdx3.json | head -1`

**Element: Component Hash Algorithm** (row 13)
- CDX: `jq -r '.components[]?.hashes[]?.alg // empty' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.packages[]?.checksums[]?.algorithm // empty' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="software_Package") | .verifiedUsing[]?.algorithm // empty' /tmp/scan.spdx3.json | head -1`

**Element: Component Identifiers** (row 14)
- CDX: `jq -r '.components[]?.purl // empty' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.packages[]?.externalRefs[]?.referenceLocator // empty' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="software_Package") | .software_packageUrl // empty' /tmp/scan.spdx3.json | head -1`

**Element: Component License** (row 15)
- CDX: `jq -r '.components[]?.licenses[]? | (.license.id // .license.name // .expression // empty)' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.packages[]?.licenseDeclared // empty' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="simplelicensing_LicenseExpression") | .simplelicensing_licenseExpression // empty' /tmp/scan.spdx3.json | head -1`

**Element: Component Name** (row 16)
- CDX: `jq -r '.components[]?.name // empty' /tmp/scan.cdx.json | head -1`
- SPDX 2.3: `jq -r '.packages[]?.name // empty' /tmp/scan.spdx.json | head -1`
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="software_Package") | .name // empty' /tmp/scan.spdx3.json | head -1`

**Element: Component Version** (row 17)
- CDX: `jq -r '.components[]?.version // empty' /tmp/scan.cdx.json | head -1` (may be empty for unknown-version components per Edge Case #1)
- SPDX 2.3: `jq -r '.packages[]?.versionInfo // empty' /tmp/scan.spdx.json | head -1` (returns `NOASSERTION` when unknown)
- SPDX 3: `jq -r '.["@graph"][]? | select(.type=="software_Package") | .software_packageVersion // empty' /tmp/scan.spdx3.json | head -1`

---

## Appendix B — SBOM Author Signature verification (row 2)

Row 2 is `⚠️ opt-in` — the default scan is unsigned per FR-009 /
FR-015 (byte-identity preserved). When the operator opts in via
`--sign-key <PATH>` (static PEM) or `--sign` (Sigstore keyless),
verification recipes differ per path.

### Static-key path (m221 US2a)

```bash
# 1. Sign at scan time
waybill sbom scan --path <target> \
    --format cyclonedx-json --output /tmp/signed.cdx.json \
    --sign-key ./signing-key.pem
```

```bash
# 2. Extract the JSF signature envelope
jq '.signature' /tmp/signed.cdx.json

# 3. Verify with any RFC 7515-aware JSF verifier tool, or
#    programmatically via sigstore-rs:
#    CosignVerificationKey::from_pem(pubkey_pem)?
#        .verify_signature(sig_bytes, canonical_bytes_with_empty_value)?
```

For SPDX outputs, waybill emits a DSSE envelope sidecar at
`<output>.sig.json`:

```bash
waybill sbom scan --path <target> \
    --format spdx-2.3-json --output /tmp/signed.spdx.json \
    --sign-key ./signing-key.pem
# → /tmp/signed.spdx.json + /tmp/signed.spdx.json.sig.json
```

Verify by loading the DSSE envelope, base64-decoding its `payload`
field, and confirming that value equals the emitted SPDX file
byte-for-byte.

### Sigstore keyless path (m222 US2b)

**v1 scope**: waybill's `--sign` requires an OIDC token that emits an
`email` claim (used by sigstore-rs 0.11 as the CSR subject sent to
Fulcio). Compatible providers: `cosign login`, Sigstore-dex, Google,
GitLab, any provider emitting `email`. **GitHub Actions ambient
tokens do NOT emit `email` and are not supported in v1** — GHA users
must fetch a token via a helper (see below).

**Local laptop / non-GHA CI**:

```bash
# 1. Fetch an OIDC token via cosign (browser flow, uses Sigstore-dex
#    which emits email). Alternatively use any other tool that produces
#    an email-carrying JWT.
export SIGSTORE_ID_TOKEN=$(cosign login --identity-token)

# 2. Sign at scan time. As of m778 keyless works for CycloneDX too,
#    signing to a detached sidecar rather than into the document.
waybill sbom scan --path <target> \
    --format cyclonedx-json --output /tmp/signed.cdx.json \
    --sign

# 3. Verify the sidecar against production Sigstore with cosign
cosign verify-blob \
    --bundle /tmp/signed.cdx.json.sig.bundle.json \
    --certificate-identity '<your OIDC subject>' \
    --certificate-oidc-issuer '<your OIDC issuer>' \
    /tmp/signed.cdx.json
```

**Inside GitHub Actions** (helper action fetches a compatible token):

```yaml
- name: Fetch OIDC token via sigstore-python
  uses: sigstore/gh-action-sigstore-python@<sha>  # emits SIGSTORE_ID_TOKEN
  with:
    dry-run: true  # we only need the token export, not the signing
- name: Sign SBOM
  run: |
    waybill sbom scan \
        --path ./my-project \
        --format cyclonedx-json --output signed.cdx.json \
        --sign
```

The `sigstore/gh-action-sigstore-python` action runs sigstore-python
which does the issuer-aware OIDC dispatch waybill's sigstore-rs 0.11
substrate can't. Alternative helpers that mint email-carrying tokens
in GHA are equally valid.

For SPDX outputs, waybill emits a Sigstore Bundle sidecar at
`<output>.sig.bundle.json` per FR-004:

```bash
waybill sbom scan --path <target> \
    --format spdx-2.3-json --output /tmp/signed.spdx.json \
    --sign
# → /tmp/signed.spdx.json + /tmp/signed.spdx.json.sig.bundle.json

cosign verify-blob \
    --bundle /tmp/signed.spdx.json.sig.bundle.json \
    --certificate-identity <expected> \
    --certificate-oidc-issuer <expected> \
    /tmp/signed.spdx.json
```

**Audit trail**: every successful `--sign` invocation surfaces three
grep-able fields at INFO level in waybill's own log per FR-016:

```text
INFO waybill::attestation::signer: SBOM signed via Sigstore keyless
  rekor_log_index=12345678
  fulcio_cert_subject=<OIDC email or subject>
  oidc_provider=explicit-env
```

SREs can look up the Rekor entry directly via
`rekor-cli get --log-index <N>` for post-hoc audit.

---

## Regeneration process

When a subsequent CISA publication or a subsequent waybill milestone
changes any cell:

1. Update the affected row's cell (verdict / slot / file:line).
2. Update `last-verified` in the front-matter to the current date.
3. Run `cargo +stable test --workspace --test cisa_2026_coverage_matrix`
   locally to confirm every recipe still resolves to a non-empty
   value.
4. If a CISA element itself was added/removed, bump the section
   header count (`(17)` → `(18)`) and add/remove the matrix row.
5. If a waybill emitter surface moved (line-number churn), the test
   `--nocapture` output will name the failing cell — update the
   citation.
