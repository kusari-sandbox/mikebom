# Phase 0 Research — SPDX Output Support

**Feature**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md) | **Date**: 2026-04-23

This document resolves the open implementation choices that would otherwise have appeared as `NEEDS CLARIFICATION` in plan.md's Technical Context. Each entry follows the **Decision / Rationale / Alternatives considered** structure.

---

## R1 — SPDX 2.3 JSON serialization approach

**Decision**: Hand-write `serde`-derived structs in `mikebom-cli/src/generate/spdx/`. Do **not** adopt `spdx-rs`.

**Rationale**:
- `spdx-rs` v0.5.5 was last released 2023-09-19; the upstream Doubleopen project has been dormant for >30 months as of 2026-04-23. Adopting it adds a stale supply-chain edge the project would inevitably maintain itself.
- `spdx-rs` is parser-first and imposes its own internal data model. mikebom already has a format-neutral internal model (`mikebom_common::resolution::ResolvedComponent`) that the CycloneDX serializer consumes directly. Routing through `spdx-rs` would mean an extra translation hop.
- The SPDX 2.3 JSON schema is small and stable: ~15 top-level types (`SpdxDocument`, `CreationInfo`, `Package`, `Relationship`, `Annotation`, `ExternalRef`, `Checksum`, `ExternalDocumentRef`, plus enums). Hand-written `#[derive(Serialize)]` definitions are an estimated ~300 LoC.
- Hand-writing gives us full control over field ordering (important for byte-determinism per FR-020) and over which optional fields are emitted vs. omitted.

**Alternatives considered**:
- **`spdx-rs` v0.5.5**: rejected — stale upstream, model impedance mismatch (see above). Pure Rust, no C deps, so it doesn't violate Constitution Principle I — but maintenance risk and impedance cost dominate.
- **`spdx-tools-rs`, `spdx_rs`**: do not exist as published crates as of 2026-04-23 (verified via crates.io search).
- **Generate from the SPDX 2.3 JSON schema** (e.g., via a build-script that calls `schemars` reverse): rejected — adds build-time complexity for no win on a 15-type schema.

---

## R2 — SPDX 3.x version target for the experimental stub

**Decision**: Target **SPDX 3.0.1** for the FR-019a stub. Vendor `https://spdx.org/schema/3.0.1/spdx-json-schema.json` into `tests/fixtures/schemas/spdx-3.0.1.json` for validation. Use a hand-written serializer (`v3_stub.rs`) emitting JSON-LD with `@context: "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"`.

**Rationale**:
- 3.0.1 is the latest *released* SPDX 3.x minor (2024-12-12, per [github.com/spdx/spdx-3-model/releases](https://github.com/spdx/spdx-3-model/releases)). 3.1-rc1 exists (2026-01-24) but is a release candidate; pinning a stub to a pre-release version would invalidate the structural-insurance argument the moment 3.1 final ships.
- No Rust crate offers SPDX 3.x support. Hand-writing is the only path; the cost is small (~150 LoC of `serde_json::json!` macros for a one-ecosystem stub).
- The data-placement map's SPDX 3 column is written to be forward-compatible with subsequent 3.x minor versions (per spec assumption "SPDX 3 target"). When 3.1 stabilizes, extending the stub becomes a serializer-internal change, not a re-architecture.

**Alternatives considered**:
- **Target SPDX 3.1-rc1**: rejected — release candidate, schema may change before final.
- **Target SPDX 3.0.0** (initial 3.0 release): rejected — superseded by 3.0.1 errata; consumers will validate against 3.0.1.
- **Wait for SPDX 3.1 final, defer the stub**: rejected — clarification Q1 (Option C) explicitly requires a working stub in this milestone to exercise the dispatch interface in real code.

---

## R3 — Ecosystem covered by the SPDX 3 stub

**Decision**: Cover **npm** with the SPDX 3 stub.

**Rationale**:
- npm fixtures are the most mature in the existing test suite (multiple `package-lock.json` v2/v3 + pnpm-lock fixtures), so cross-format parity assertions have a known-good baseline.
- npm components have rich identity (PURL with namespace, version, integrity hash, declared license in `package.json`) and a clean, well-bounded entity volume per fixture, making schema-validation iteration fast.
- npm is already first-class in `mikebom-common::resolution::ResolvedComponent` mapping; no new ecosystem-specific code path needed in scan/resolution.

**Alternatives considered**:
- **deb**: rejected — deb fixtures involve image scans (heavier, slower test runs) and per-file deep-hash payloads that would inflate the stub-only test surface.
- **cargo**: viable; chosen npm over cargo only because npm's existing fixture variety is wider.
- **All 9 ecosystems**: rejected — exceeds the "minimal stub" intent of clarification Q1 / FR-019a; risks scope creep that defeats the "experimental" labeling in FR-019b.

---

## R4 — OpenVEX sidecar serialization

**Decision**: Hand-write `serde`-derived structs in `mikebom-cli/src/generate/openvex/`. Target **OpenVEX 0.2.0** (latest spec, released 2023-08-22 per [github.com/openvex/spec](https://github.com/openvex/spec)). Do **not** adopt the `openvex` crate.

**Rationale**:
- The `openvex` crate v0.1.1 (2023-03-10) is 3 years stale, 89 LoC, single author at a defunct organization (seedwing-io).
- OpenVEX 0.2.0 is one JSON document with ~10 fields: `@context`, `@id`, `author`, `timestamp`, `version`, `tooling`, `statements[]` (each carrying `vulnerability`, `products[]`, `status`, optional `justification`/`impact_statement`/`action_statement`).
- ~80 LoC of `#[derive(Serialize)]` is faster to maintain than tracking a stale crate's potential 0.1 → 0.2 migration.

**Alternatives considered**:
- **`openvex` crate v0.1.1**: rejected per above.
- **CSAF VEX instead of OpenVEX**: rejected — CSAF is a complex multi-document spec designed for vendor advisories, overkill for a sidecar to a per-scan SBOM. OpenVEX is purpose-built for this.
- **Embed VEX in SPDX `annotations[]`**: rejected by clarification Q2 (Option A) — VEX is the documented exception to the annotations-default rule because annotation payloads grow unbounded for vulnerable images.

---

## R5 — JSON schema validation in tests

**Decision**: Use `jsonschema = "0.46"` (released 2026-04-20, [crates.io/crates/jsonschema](https://crates.io/crates/jsonschema)). Vendor the SPDX 2.3, SPDX 3.0.1, and OpenVEX 0.2.0 JSON schemas into `mikebom-cli/tests/fixtures/schemas/` and compile-once / validate-many per test.

**Rationale**:
- Pure Rust, supports JSON Schema Draft 2020-12 (which SPDX 2.3 uses).
- No Python (`pyspdxtools`) or JVM (`spdx-tools`) runtime dependency in CI — keeps the CI image minimal and matches the project's "no shell-out for correctness" posture.
- Vendoring the schemas pins the validator's contract to a specific spec revision; CI reproducibility is guaranteed.
- Plays nicely with `cargo +stable test --workspace` (Constitution + CLAUDE.md pre-PR verification).

**Alternatives considered**:
- **Shell out to `pyspdxtools` validator**: rejected — adds Python to CI, runtime variability.
- **Shell out to LF Java `spdx-tools`**: rejected — adds JVM to CI, even larger.
- **Validate at runtime in production**: rejected — pure overhead; correctness guaranteed by schema-validated tests.

---

## R6 — License expression handling

**Decision**: Continue using the existing `spdx` crate (Embark Studios, v0.13.x — already a workspace dependency since milestone 009 for `SpdxExpression::try_canonical`). Route every `licenseDeclared` and `licenseConcluded` value through `try_canonical` before serialization. On parse failure, emit `NOASSERTION` and preserve the raw text in the mikebom annotation envelope per the data-placement map.

**Rationale**:
- Already in the workspace; pure Rust; actively maintained (last release 2026-02-26).
- Validates against the SPDX license list 3.x; emits canonical strings suitable for SPDX 2.3 and SPDX 3.x.
- No additional crate needed.

**Alternatives considered**:
- **`spdx-expression` crate** (a separate crate, v0.5.x, used internally by `spdx-rs`): rejected — adds a parallel parser/canonicalizer for no win.
- **Pass through raw license strings without validation**: rejected — would produce schema-invalid SPDX output for ecosystems that emit non-SPDX-canonical license strings (e.g., npm `"MIT OR Apache-2.0"` vs `"MIT or Apache-2.0"` typo cases).

---

## R7 — `SPDXID` derivation strategy

**Decision**: Derive `SPDXID` for each Package as `SPDXRef-` + a stable, collision-free fingerprint of the component's PURL. Concretely: `SPDXRef-Package-<base32(SHA-256(canonical_purl))[..16]>`. The document's own `SPDXID` is `SPDXRef-DOCUMENT` (SPDX-spec-required value).

**Rationale**:
- Deterministic across runs (FR-020, SC-007): same PURL → same SPDXID.
- Collision-free in practice (16 base32 chars = 80 bits of entropy, far above any realistic component-count ceiling).
- Self-documenting: a reader who knows the algorithm can verify any SPDXID against the Package's PURL.
- Honors the SPDX SPDXID character constraints (`SPDXRef-` prefix + alphanumerics, hyphens, dots — base32 satisfies this).

**Alternatives considered**:
- **Sequential numbering** (`SPDXRef-Package-1`, `-2`, …): rejected — order-dependent, breaks determinism if scan ordering drifts.
- **Use the PURL directly**: rejected — PURLs contain characters (`/`, `@`, `?`, `=`) not allowed in SPDXIDs.
- **UUID per Package**: rejected — non-deterministic; would force special-casing in determinism tests.

---

## R8 — `documentNamespace` strategy

**Decision**: Derive `documentNamespace` as a deterministic URI of the form
```
https://mikebom.kusari.dev/spdx/<scan-fingerprint>
```
where `<scan-fingerprint>` is `base32(SHA-256(canonical_scan_inputs))[..32]`. The `canonical_scan_inputs` payload covers the scan target (filesystem path or image reference + digest), the mikebom version, and the sorted set of resolved component PURLs. Document this in the data-placement map and in the SPDX-output user guide.

**Rationale**:
- Deterministic across runs on identical inputs (preserves FR-020 / SC-007 determinism guarantees).
- Globally unique in practice for distinct scans (any change in inputs cascades into the fingerprint).
- Self-described provenance: the URI authority `mikebom.kusari.dev` makes the producer auditable from the namespace alone.
- Avoids the "random UUID per run" approach that would force the determinism test to special-case a non-content field.

**Alternatives considered**:
- **Random UUID v4 per run**: rejected — breaks byte-level reproducibility; SC-007 would have to allowlist the field, weakening the guarantee.
- **User-supplied namespace via CLI flag**: deferred — the deterministic default is correct for >99% of users; a `--spdx-namespace` override can be added later if requested without changing the default.
- **Use the scan target path/image directly as the namespace**: rejected — paths contain characters that would need escaping; image references can rotate; deterministic fingerprint is cleaner.

---

## R9 — mikebom annotation envelope schema

**Decision**: Emit each preserved mikebom field as one entry in SPDX `annotations[]` (on the document or on the relevant Package per the data-placement map). The annotation has:

- `annotationType`: `"OTHER"` (SPDX 2.3 enum value for tool-specific annotations).
- `annotator`: `"Tool: mikebom-<version>"`.
- `annotationDate`: ISO-8601 timestamp matching the document's `created` field for determinism.
- `comment`: A JSON string conforming to `mikebom-annotation.schema.json` (shipped under `contracts/`):
  ```json
  {
    "schema": "mikebom-annotation/v1",
    "field": "<mikebom field name, e.g. 'evidence.identity', 'mikebom:shade-relocation'>",
    "value": <field value, JSON-typed>
  }
  ```

**Rationale**:
- SPDX 2.3 spec-compliant (`OTHER` is the explicit escape hatch for tool-specific annotations).
- Versioned envelope (`schema: "mikebom-annotation/v1"`) lets us evolve the comment payload without breaking downstream consumers.
- Consumers that ignore annotations see clean SPDX; consumers that read them recover full mikebom fidelity (clarification Q2 outcome).
- Single uniform format across all preserved fields simplifies both the serializer code and any third-party reader.

**Alternatives considered**:
- **`annotationType: "REVIEW"`**: rejected — REVIEW is for human review notes, not tool-emitted metadata.
- **One mega-annotation carrying all mikebom fields as a JSON object**: rejected — fan-out per field maps cleanly to per-Package placement and stays under any consumer's annotation-size limits.
- **Custom `externalRefs[]` entries with non-SPDX category values**: rejected — `externalRefs.referenceCategory` enum is closed; using a non-enum value would fail schema validation.

---

## R10 — CLI multi-format flag syntax

**Decision**: Extend the existing `--format <fmt>` flag on `mikebom sbom scan` to accept either a single format identifier (current behavior, default `cyclonedx-json`) or a comma-separated list (e.g., `--format cyclonedx-json,spdx-2.3-json`). The flag may also be repeated (`--format cyclonedx-json --format spdx-2.3-json`) for shell users who prefer that style; the two forms are equivalent. Duplicate values within one invocation are silently de-duplicated (FR-004).

Format identifiers:
- `cyclonedx-json` (default; current behavior preserved per FR-004b)
- `spdx-2.3-json`
- `spdx-3-json-experimental` (the FR-019a / FR-019b stub; visibly labeled experimental)

Per-format output overrides via `--output <fmt>=<path>` (repeatable). Default filenames: `mikebom.cdx.json`, `mikebom.spdx.json`, `mikebom.spdx3-experimental.json`. The OpenVEX sidecar (`mikebom.openvex.json`, default) is written next to the SPDX file when SPDX is requested AND the scan produces VEX statements.

**Rationale**:
- Comma-separated lists in `--format` are the lowest-friction extension to the current single-value flag and don't require any positional reshuffling.
- Repeated-flag syntax is the more standard `clap` idiom and works for free with `Vec<String>` parsing — supporting both is a one-line `value_delimiter(',')` setting.
- Per-format output overrides are needed for users who want files in different directories (e.g., `--output cyclonedx-json=/tmp/cdx.json --output spdx-2.3-json=/srv/sbom/spdx.json`).
- Experimental opt-in is exposed only via the explicit format identifier name, never by passing `--format spdx-3-json` (no aliasing) — satisfies FR-019b's "visibly labeled" requirement.

**Alternatives considered**:
- **Drop multi-format entirely; require two scans**: rejected by clarification Q3 (Option A) — image scans are too expensive to repeat.
- **Introduce a new flag `--formats` (plural) and deprecate `--format`**: rejected — backwards-incompatible; FR-004b requires existing default behavior to be unchanged.
- **Auto-emit both CDX and SPDX whenever SPDX is requested**: rejected — surprises users; FR-004b says SPDX is opt-in.

---

## Summary

All Technical Context placeholders resolved. No `NEEDS CLARIFICATION` remains. Phase 1 design can proceed.

Sources cited during research:
- [crates.io/crates/spdx-rs/0.5.5](https://crates.io/crates/spdx-rs/0.5.5)
- [crates.io/crates/openvex](https://crates.io/crates/openvex)
- [crates.io/crates/jsonschema](https://crates.io/crates/jsonschema)
- [crates.io/crates/spdx](https://crates.io/crates/spdx)
- [github.com/spdx/spdx-3-model/releases](https://github.com/spdx/spdx-3-model/releases)
- [github.com/spdx/spdx-spec](https://github.com/spdx/spdx-spec)
- [github.com/openvex/spec](https://github.com/openvex/spec)
- [github.com/EmbarkStudios/spdx](https://github.com/EmbarkStudios/spdx)
