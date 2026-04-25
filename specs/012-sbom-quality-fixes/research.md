# Phase 0 Research: Cross-format SBOM-Quality Fixes

**Branch**: `012-sbom-quality-fixes` | **Date**: 2026-04-25 | **Plan**: [plan.md](plan.md)

## R1 — SPDX 3 CPE bug confirmation

**Decision**: One-character fix in `mikebom-cli/src/generate/spdx/v3_external_ids.rs::is_fully_resolved_cpe23`. Change `parts[2..7]` to `parts[2..6]`. Update the implementation-comment-line that says "We enforce non-wildcard in the first five fields after the prefix (part / vendor / product / version / update)" to match the doc-comment claim one line above ("vendor, product, and version specifically — i.e., parts[2..6]").

**Rationale**:

- The function's outward-facing doc comment at lines 68-73 of `v3_external_ids.rs` claims the rule is: "no wildcards in its required attribute slots — vendor, product, and version specifically." That's `parts[2..6]` in CPE 2.3 syntax (`cpe:2.3:<part>:<vendor>:<product>:<version>:...`).
- The implementation at line 82 reads `parts[2..7].iter().all(...)` — five slots, including the `update` field at `parts[6]`.
- mikebom's CPE synthesizer produces vectors of the form `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*` — `update` is always `*` because mikebom doesn't infer a software-update version from a discovered package. Result: every synthesized CPE fails the `parts[2..7]` check, and the SPDX 3 emitter drops them all.
- The CDX emitter has no such check; CDX's `component.cpe` is a single-string field, no filtering. The SPDX 2.3 emitter also has no such check; the milestone-010 path in `packages.rs` iterates `c.cpes` and emits one externalRef per entry verbatim.
- The fix passes existing fixtures because they have synthesized CPEs with `update=*`. After the fix, the synthetic-root Package's own CPE (`cpe:2.3:a:mikebom:<target>:0.0.0:*:*:*:*:*:*:*`) also passes the check — the synthetic root carries 1 ExternalIdentifier[cpe23] entry on top of every component's, which matches the spec's "± 1 synthetic root" tolerance.

**Verification**: A new unit test in `v3_external_ids.rs::tests` covers the `cpe:2.3:a:mikebom:foo:1.0:*:*:*:*:*:*:*` shape and asserts `is_fully_resolved_cpe23(...) == true`. After the fix, the existing `spdx3_cdx_parity.rs` per-ecosystem tests pick up the additional CPE entries on Packages that have CPE candidates, exercising the round-trip end-to-end.

**Alternatives considered**:

- *Move CPE filtering out of the SPDX 3 emitter entirely*: rejected — the resolution layer trusts the emitter to filter out malformed CPEs, and SPDX 3.0.1's `prop_ExternalIdentifier_externalIdentifierType` enum is strict (the `cpe23` value must be a syntactically valid CPE-2.3 vector). Some pre-emitter validation is appropriate. The fix tightens to "valid + has a non-wildcard required core" rather than "valid + all 5 first slots non-wildcard."
- *Drop the `update` slot from the comment too, but keep the implementation strict*: rejected — strict-mode rejects too many real CPEs (per the empirical 1/752 polyglot data). The implementation must match the doc.
- *Extract the CPE filter into a shared helper used by SPDX 2.3 too*: deferred — SPDX 2.3 doesn't filter today and that's been fine; introducing the helper now would expand the milestone's blast radius. Can refactor later if a future milestone wants stricter pre-emit validation across formats.

## R2 — 22-component drift root cause: not a code bug

**Decision**: The 22-component drift between CDX (729) and SPDX 2.3 (751) on the polyglot-builder-image fixture is **not a bug** — it's a structural difference between how the two formats represent component containment. The "fix" is (a) tightening the existing `spdx_cdx_parity.rs` parity test with a bidirectional component-set equality check that compares **flattened** CDX (top-level + nested) against SPDX 2.3 packages, and (b) adding a row to the format-mapping doc that documents the structural difference so future readers don't re-investigate it.

**Rationale**:

- CDX 1.6 §6.2.10 supports nested components via `component.components[]`. Mikebom's CDX builder (`mikebom-cli/src/generate/cyclonedx/builder.rs::build_components`) explicitly implements this: components carrying `parent_purl == Some(<top-level-PURL>)` are emitted under that top-level component's `components[]` array (see `effective_parent` logic at lines 166-169). Top-level emission filters `c.parent_purl.is_none()` (line 143).
- SPDX 2.3 §7 has no nested-Package mechanism; the spec calls for flat `packages[]` with `Relationship` edges expressing containment. The mikebom SPDX 2.3 builder (`mikebom-cli/src/generate/spdx/packages.rs::build_packages`) iterates `for c in artifacts.components { … }` (line 215) — every `ResolvedComponent` becomes a top-level Package, regardless of `parent_purl`. The parent-child relationship is then expressed via `CONTAINS` Relationships in `relationships.rs` (existing milestone-010 behavior).
- On the polyglot fixture: 729 top-level + 22 nested children + ?? = 751 SPDX 2.3 packages. The 22-child count exactly matches the drift. Likely the synthetic root Package fits into the 729-vs-751 math: when the scan-target name matches a discovered top-level component (which polyglot satisfies), the SPDX 2.3 emitter does NOT add a synthetic root, so the count is `729 + 22 = 751` exactly.
- The user's comparison report counted CDX *top-level* (`cdx.components.length`) vs. SPDX 2.3 *all* (`spdx23.packages.length`). That's the apples-to-oranges comparison. Comparing flattened CDX to flattened SPDX 2.3 yields exact equality (modulo the 0-or-1 synthetic root).

**Verification**: The new `component_count_parity.rs` test asserts `cdx.flattened_count + (synthetic_root ? 1 : 0) == spdx23.packages.length` per ecosystem. For the polyglot case this means `(729 + 22) + 0 == 751` — passes. The bidirectional addition to `spdx_cdx_parity.rs` tightens the existing one-directional walk by adding the SPDX→CDX reverse: every SPDX 2.3 Package's PURL (excluding synthetic root) must match a flattened CDX component PURL.

**Alternatives considered**:

- *Make SPDX 2.3 also emit nested components only at the parent level (suppress flat children)*: rejected — violates SPDX 2.3 §7 (the spec requires every Package to be top-level; nesting isn't allowed); also drops information consumers may need (a Maven shade-plugin's vendored coords are first-class components in any sensible interpretation).
- *Make CDX flatten components like SPDX 2.3 does*: rejected — CDX's nested representation is the format's idiomatic shape for shade-jar / fat-jar containment; flattening loses the parent-child structure that consumers like grype/syft already parse.
- *Add a non-conformant `parent` field to the SPDX 2.3 Package shape*: rejected — non-conformant. The CONTAINS Relationship is the spec-native mechanism and is already emitted.
- *Document the drift but don't add a CI test*: rejected — milestone 010's parity test exists exactly to catch component-set divergences; tightening it to bidirectional locks the structural-difference understanding into CI rather than relying on documentation alone.

**Operational note**: The format-mapping doc gains a new section/row (or amendment to Section B's containment rows) explaining the structural difference: "CDX nests via `component.components[]`; SPDX 2.3 flattens to top-level `packages[]` + `Relationship[CONTAINS]`. Component count visualizations comparing the two formats must flatten CDX before counting." That's the documentation half of the resolution.

## R3 — LicenseRef-`<hash>` derivation parameters

**Decision**:

- **Hash function**: SHA-256 (matches the existing `SpdxId::for_purl` derivation; reusing the same hash keeps the project's content-addressing scheme uniform).
- **Hash input**: the joined-with-` AND ` raw expression string — exactly what lands in `extractedText`. Same input → same `LicenseRef-<hash>` deterministically.
- **Encoding**: BASE32-NOPAD (`data-encoding::BASE32_NOPAD`), matching `SpdxId::for_purl`.
- **Prefix length**: 16 characters (= 80 bits). Same as `SpdxId::for_purl::PURL_HASH_PREFIX_LEN`.
- **Final SPDX-LicenseRef ID**: `LicenseRef-<16-char-base32-prefix>`. Total length: 11 + 16 = 27 characters. SPDX 2.3 §10.1 requires `LicenseRef-` prefix; the rest is `[A-Za-z0-9.-]` and BASE32-NOPAD's alphabet `[A-Z2-7]` is a subset.
- **`name` field**: literal `"mikebom-extracted-license"`. SPDX 2.3 §10.4 requires `name` non-empty; the value isn't consumer-significant in the way `extractedText` is (consumers parse `extractedText` for the actual expression).

**Rationale**:

- **Reuses existing project conventions**: `SpdxId::for_purl` already uses 16-char BASE32 SHA-256 prefix; doing the same for LicenseRef means one shared `hash_prefix` helper and one mental model.
- **80 bits of collision resistance**: birthday-bound collision at ~1.2 × 10¹² distinct inputs. The polyglot fixture has roughly 700 distinct license expressions; collision probability is ≈ (700² / 2) / 2⁸⁰ ≈ 2 × 10⁻¹⁹. Effectively zero.
- **Deterministic across runs / machines / mikebom versions**: same expression → same hash, satisfying FR-009 verbatim.
- **`extractedText` is the truth**: SPDX 2.3 specifies `extractedText` as the verbatim payload that consumers parse. The `licenseId` is just a stable handle for cross-references inside the document. Choosing a content-addressed handle means downstream tools de-duplicating across SBOMs see the same `LicenseRef-X` for the same expression.

**Verification**: A new unit test in `packages.rs::tests` covers (a) deterministic hash for the same input, (b) different hashes for different inputs, (c) expected prefix shape (`LicenseRef-` + 16 BASE32 chars), (d) hash matches a hand-computed reference for one canonical input. The full-document determinism test (`spdx_determinism.rs`) covers byte-equality across runs.

**Alternatives considered**:

- *Use the component's PURL as part of the hash input*: rejected — would mean the same expression on two different components produces two different LicenseRef IDs, and the document's `hasExtractedLicensingInfos[]` array would carry duplicates. Content-only hashing dedupes naturally.
- *Use a counter (`LicenseRef-001`, `LicenseRef-002`)*: rejected — non-deterministic across runs (component ordering can vary on the millisecond scale); breaks FR-009.
- *Encode the raw expression directly into the LicenseRef name*: rejected — SPDX 2.3 LicenseRef IDs are constrained to `[A-Za-z0-9.-]`. Many license expressions contain spaces, parentheses, slashes, etc. — illegal characters. Hashing is necessary.
- *Different prefix length (8 / 12 / 24 chars)*: rejected — 16 is the project's existing convention. 80 bits is overkill for license-expression scale but consistent with PURL hashing.
- *Use SHA-1 instead of SHA-256*: rejected — `sha2` is already in the dependency closure; SHA-1 would mean adding a separate hasher. SHA-256 with 16-char prefix is faster than SHA-1 (one hash call vs. two for the same total entropy).

## R4 — SPDX 3 LicenseRef parity (no SPDX 3 changes needed)

**Decision**: SPDX 3 emission is **unchanged** by this milestone. The `v3_licenses.rs::canonicalize_or_raw` helper (milestone 011) already preserves non-canonicalizable expressions verbatim via `simplelicensing_LicenseExpression`'s `simplelicensing_licenseExpression` field's text-passthrough mode. After US3 ships the SPDX 2.3 LicenseRef backport, both formats preserve the same data — through structurally different but functionally equivalent mechanisms.

**Rationale**:

- Spec FR-007 names SPDX 2.3 specifically. The milestone-011 SPDX 3 path was always faithful to the source data because SPDX 3's `simplelicensing_LicenseExpression` accepts any string content; mikebom's `try_canonical` failure path falls through to the raw expression in `v3_licenses.rs:151-155`.
- The 107-vs-38 license-count gap on the native-linkage fixture (per the user's report) is exactly what `try_canonical`-fail-path-to-raw preserves in SPDX 3 today. The same fix in SPDX 2.3 closes the gap there.
- Cross-format consistency check (FR-005 / SC-005 in milestone 011, plus the existing `spdx_annotation_fidelity.rs` and `spdx3_annotation_fidelity.rs` tests) keeps both formats accountable to the same source data going forward.

**Alternatives considered**:

- *Add a SPDX 3 LicenseRef-`<hash>` shape too for cross-format ID parity*: rejected — SPDX 3 already has its own native mechanism (`simplelicensing_LicenseExpression` element + `hasDeclaredLicense` Relationship). Adding a parallel `LicenseRef-` mechanism would create two emit paths in one format, violating the Q2 strict-match-or-Annotation principle from milestone 011.

## Open follow-ups (not in scope for this milestone)

- **Format-mapping doc Section H new row**: documenting the CDX-nests / SPDX-flattens structural difference. Lands as part of US2 implementation per the plan.
- **Tooling that produced the comparison report**: should be updated (or noted) to flatten CDX before counting. Out of scope for mikebom's own repo; if the tooling is internal, a follow-up task can address it.

---

**All NEEDS CLARIFICATION items resolved.** Phase 1 proceeds with `data-model.md` and `quickstart.md`.
