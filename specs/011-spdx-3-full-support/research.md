# Phase 0 Research: Full SPDX 3.x Output Support

**Branch**: `011-spdx-3-full-support` | **Date**: 2026-04-24 | **Plan**: [plan.md](plan.md)

This document resolves the two `/speckit.clarify`-deferred items (schema source location, alias deprecation window) plus the SPDX-3-element-shape lookup work that drives Phase 1's `data-model.md`. Each item lists Decision / Rationale / Alternatives.

## R1 — SPDX 3.0.1 schema source: bundle vs. fetch

**Decision**: Bundle the published SPDX 3.0.1 JSON-LD schema as a static fixture under `mikebom-cli/tests/fixtures/spdx3-3.0.1.schema.json`. The schema-validation test loads the bundled file at test-start time via `include_str!` (read at compile time, parsed once per test binary), feeds it to the existing `jsonschema = "0.46"` dev-dep, and validates every emitted SPDX 3 fixture document against it.

**Rationale**:
- Milestone 010 already bundles the SPDX 2.3 schema for the same test suite; bundling SPDX 3 keeps the mental model uniform.
- CI runs `cargo +stable test --workspace` with no implicit network access; a fetch-at-test approach trips on every offline runner and on the air-gapped CI mirror the project plans to enable.
- The bundled schema is a reviewable artifact in git: every revision bump is a visible PR diff with a clear blast radius. Fetched schemas drift silently when the upstream URL is updated.
- The `jsonschema` crate already loads the SPDX 2.3 schema as bytes — extending the same pattern requires zero new dependencies.

**Alternatives considered**:
- *Fetch via `reqwest` at test time*: rejected — flaky on CI, runtime dependency on schema-host availability, breaks `cargo test --offline`.
- *Fetch in `build.rs`*: rejected — adds a build-time network dependency, breaks `cargo build --offline`, and produces a build artifact that's harder to inspect than a checked-in file.
- *Fetch + cache locally on first use*: rejected — first-build flake risk plus a harder-to-reason-about test artifact (cache state isn't a reviewable diff).

**Operational note**: The bundled schema's source URL and revision are recorded as a comment header at the top of `spdx3-3.0.1.schema.json`. When SPDX publishes a 3.0.x dot release whose schema is wire-compatible with 3.0.1, the bump is one PR: replace the file, re-record the comment header, run the test suite. The plan's Assumptions section says target version is "the highest published 3.x revision at implementation time"; that policy applies here.

## R2 — `spdx-3-json-experimental` deprecation window

**Decision**: Keep the alias accepted through milestone 012; remove it in milestone 013 unless usage signals say otherwise. While the alias is accepted it emits **byte-identical** output to `spdx-3-json` (same default filename — `mikebom.spdx3.json` — when the user does not explicitly set `--output`; same document bytes; no experimental marker injected into `CreationInfo.comment` or `SpdxDocument.comment`; see R6 for the constitutional-interpretation argument). Every invocation prints a two-line stderr deprecation notice that reads:

```text
warning: --format spdx-3-json-experimental is deprecated; use --format spdx-3-json instead.
note: in this release the alias produces full-coverage SPDX 3 output across all 9 ecosystems — pre-011 releases of this alias emitted an npm-only stub. If your pipeline asserted byte-equality against the milestone-010 stub shape, those assertions will need updating.
```

The second line — the **shape-change notice** — is load-bearing: it is the only signal a CI-pinned consumer gets that the alias's bytes have changed across releases. Without it, a pipeline that pinned a byte-hash assertion against milestone-010 output would silently fail post-011 with no log indication of why.

**Rationale**:
- Spec FR-002 commits to "at least one release cycle" of alias support; one-milestone overlap is the standard period mikebom's prior format identifier renames have used.
- Existing user pipelines that name `spdx-3-json-experimental` (CI scripts, attestation generators) get a friction-low migration path: their commands keep working with a visible warning rather than a hard break.
- The alias bytes and filename intentionally match the stable identifier — this rules out the failure mode where a user reads the alias output, compares it to a teammate's stable-identifier output, and finds two different bytestreams "for the same scan."

**Alternatives considered**:
- *Remove the alias immediately when 011 ships*: rejected — breaks user scripts the moment they pull the new release, with no migration window. Spec explicitly forbids this (FR-002).
- *Keep the alias indefinitely*: rejected — accumulates legacy aliases over time, violates the spirit of the deprecation track, and creates the long-term confusion the deprecation notice is trying to eliminate.
- *Have the alias preserve the milestone-010 stub bytes*: rejected — would mean two emitters for the same identifier output; violates SC-008 ("CLI accepts the older identifier and emits the same bytes as the stable one"). Users who genuinely need the old npm-only stub bytes can stay on a pre-011 release.

**Operational note**: The deprecation notice goes to stderr (not stdout), so users piping the SBOM to disk don't get warning text mixed into the document bytes. Tests in `tests/spdx3_us3_acceptance.rs` capture stderr and assert on the deprecation-notice substring.

## R3 — SPDX 3.0.1 element shape lookup for the Section A defer rows

The milestone-010 stub deferred five Section A rows in `docs/reference/sbom-format-mapping.md`: A4 (supplier), A5 (originator/author), A7 (declared license), A8 (concluded license), A12 (CPE). This research locks in the exact JSON-LD shape each row resolves to in 3.0.1. The shapes feed `data-model.md`.

**A4 — supplier (Organization)**

- Element type: `Organization` (subtype of `Agent`).
- Required properties: `type: "Organization"`, `spdxId: <IRI>`, `creationInfo: <ref>`, `name: <org name>`.
- Wiring to the Package: a `Relationship` with `relationshipType: "suppliedBy"`, `from: <Package IRI>`, `to: [<Organization IRI>]`.
- IRI synthesis: `<doc IRI>/agent-org-<base32(SHA256("organization|" + name))[..16]>`. Deterministic across runs.

**A5 — originator (Person OR Organization)**

- Element type: `Person` when the originator string is parsed as a single human, else `Organization`.
- Same shape as A4 with `type: "Person"` and a `name` taken from `ResolvedComponent.evidence.author` (or the equivalent originator field once resolution adds it).
- Wiring: `Relationship` with `relationshipType: "originatedBy"`.

**A7 — declared license**

- Element type: `simplelicensing_LicenseExpression`.
- Required properties: `type: "simplelicensing_LicenseExpression"`, `spdxId: <IRI>`, `creationInfo: <ref>`, `simplelicensing_licenseExpression: "<canonical SPDX expression>"`.
- Wiring: `Relationship` with `relationshipType: "hasDeclaredLicense"`, `from: <Package IRI>`, `to: [<LicenseExpression IRI>]`.
- IRI synthesis: `<doc IRI>/license-decl-<base32(SHA256("declared|" + canonical_expr))[..16]>`.
- Canonicalization: same `spdx::Expression::try_canonical(&str)` call the SPDX 2.3 path uses; canonicalization failure ⇒ raw string preserved on the LicenseExpression element via an Annotation, matching FR-008.

**A8 — concluded license**

- Identical to A7 except `relationshipType: "hasConcludedLicense"` and IRI prefix `license-conc-`.
- Edge: only emitted when the concluded license differs from the declared license (matches SPDX 2.3 path's behavior — avoids emitting a redundant edge that just duplicates A7).

**A12 — CPE (and the C19 multi-candidate split)**

- Element type for each fully-resolved CPE: `ExternalIdentifier`.
- Required properties: `type: "ExternalIdentifier"`, `externalIdentifierType: "cpe23"`, `identifier: "<CPE-2.3 string>"`.
- Wiring: appears as an entry in the Package's `externalIdentifier` list (same list that carries the PURL ExternalIdentifier).
- For the C19 multi-candidate case: every CPE that is fully resolved (a complete CPE-2.3 vector with no wildcards in any required attribute) gets an `ExternalIdentifier` entry; the remaining unresolved-candidate set is preserved verbatim in an SPDX 3 Annotation (`field: "mikebom:cpe-candidates"`, `value: <original CDX property value>`). This preserves the SPDX 2.3 split: typed where typeable, Annotation otherwise.

**Per-row mapping update**: every row above transitions from `defer until SPDX 3 …` to a concrete native binding in `docs/reference/sbom-format-mapping.md`. The `data-model.md` artifact (Phase 1) carries the JSON-LD example payload for each.

## R4 — Triple-format dispatcher caching

**Decision**: No new caching layer. The existing single-pass invariant in `mikebom-cli/src/cli/scan_cmd.rs` (the FR-004 amortization mechanism for milestone 010 dual-format) already feeds an arbitrary-length list of serializers from one `ScanArtifacts`. SPDX 3 plugs in as a third serializer — same code path, same amortization profile.

**Rationale**:
- Empirically (milestone 010's `dual_format_perf.rs`) the bulk of per-invocation cost is scan + discovery + deep-hash, not serialization. Adding a third serializer adds the third serializer's cost (small) and zero additional scan cost.
- A caching layer between serializers would only matter if a serializer mutated `ScanArtifacts` — but `ScanArtifacts<'_>` is borrowed immutably (`&'a [ResolvedComponent]`, `&'a [Relationship]`, etc.), so the same input is already shared by reference.
- The triple-format perf test (`tests/triple_format_perf.rs`) is written exactly against this shape: one invocation with `--format cyclonedx-json,spdx-2.3-json,spdx-3-json` vs. three sequential single-format invocations, median-of-3, ≥25% reduction CI gate.

**Alternatives considered**:
- *Add a memoization layer between serializers*: rejected — solves a problem that doesn't exist; the input is already shared by reference and immutable.
- *Run serializers in parallel via `rayon`*: rejected — JSON-LD synthesis is cheap relative to scan; the parallelization gain wouldn't move the gate. Adds tokio/rayon coordination complexity.

## R5 — Q2 borderline rows

The Q2 clarification mandates "native SPDX 3 field only when typed semantics match exactly; Annotation otherwise." A handful of rows in the existing mapping doc were ambiguous; this research locks them in.

| Row | Decision | Rationale |
|-----|----------|-----------|
| C8 (`mikebom:shade-relocation`) | **Annotation** | SPDX 3.0.1 has no typed property for "this artifact contains relocated symbols from another artifact." `software_Package/contentBy` is a build-profile property whose semantics are "what artifact this Package's contents *came from*," which doesn't capture relocation lineage. |
| C16 (`mikebom:confidence`) | **Annotation** | SPDX 3.0.1's evidence profile (where confidence would naturally live) is not in 3.0.1 stable; the property name and shape will land in a follow-up profile revision. Stay on Annotation; the row's mapping note flags revisit when the evidence profile lands. |
| C18 (`mikebom:source-files`) | **Annotation** for 3.0.1 | `software_Package/contentBy` exists in the build profile but its shape ("an Element representing the source the contents came from") doesn't match the mikebom signal ("a list of source-file paths within the package"). Annotation preserves the data losslessly until SPDX 3 publishes a properly-shaped property. |
| C19 (`mikebom:cpe-candidates`) | **Split**: native `ExternalIdentifier[cpe23]` for every fully-resolved candidate; **Annotation** for the unresolved candidate-set residual | Same split the SPDX 2.3 row uses; preserves typed-where-typeable, Annotation-otherwise. Documented in R3 above. |

The mapping doc updates are scoped accordingly: every row that was `defer until SPDX 3 …` becomes either a concrete native binding (Section A: A4, A5, A7, A8, A12) or stays Annotation with a forward-pointing note (Section C borderline rows above).

## R6 — Constitution V experimental-labeling clause and the alias

**Decision**: After this milestone, the `spdx-3-json-experimental` alias is a **deprecation track**, not an experimental emitter. Constitution Principle V's three-place experimental-labeling clause (CLI help, output filename, document creator/tool metadata) does **not** apply to the alias. The alias produces byte-identical output to the stable `spdx-3-json` identifier — same filename `mikebom.spdx3.json`, same document bytes — and signals its lifecycle via a stderr deprecation notice (R2) plus a CLI help-text "(deprecated, use spdx-3-json)" annotation.

**Rationale**:
- Constitution V's clause exists to prevent consumers from mistaking *preview-quality output* for production-grade output. The alias's output is no longer preview quality — it routes through the stable emitter and produces full-coverage, schema-valid, sbomqs-parity-passing SPDX 3 documents.
- Spec FR-002 explicitly states the alias "emits the same output." Adding experimental markers to the alias's document comments would contradict FR-002 and create a footgun: two byte-different outputs for the same logical document.
- An earlier draft of `contracts/spdx-3-emitter.contract.md` proposed injecting `EXPERIMENTAL_MARKER` text into `CreationInfo.comment` and `SpdxDocument.comment` for the alias path, satisfying constitution V's "document creator/tool metadata" labeling but creating a 2-property byte-diff between alias and stable bytes. That gesture is **dropped** in favor of the cleaner "alias is a deprecation track" interpretation.
- The CLI help-text annotation surface-side carries the deprecation signal — so consumers reading `--help` see `spdx-3-json-experimental    (deprecated, use spdx-3-json)` and learn the lifecycle status without needing the per-document comment. The stderr deprecation notice (R2) covers users running the CLI directly. Both signals appear at invocation time, before any document is produced — earlier than constitution V's per-document comment marker.

**Alternatives considered**:
- *Keep the alias as an experimental emitter with all three labels*: rejected — contradicts spec FR-002's "same output" guarantee and creates a permanent 2-property byte-diff between alias and stable that complicates downstream consumer parsers.
- *Rename the alias's filename to `mikebom.spdx3-experimental.json`*: rejected — same FR-002 contradiction; users overriding `--output spdx-3-json-experimental=path` would still get one path, but the implicit-default disagreement between alias and stable is the kind of footgun mikebom has avoided in prior format renames.

**Operational note**: The contract artifact (`contracts/spdx-3-emitter.contract.md`) §1 and §4 reflect this decision: alias bytes are byte-identical to stable bytes; the only difference is the deprecation notice on stderr at CLI invocation time.

---

**All NEEDS CLARIFICATION items resolved.** Phase 1 proceeds with `data-model.md`, `contracts/spdx-3-emitter.contract.md`, and `quickstart.md`.
