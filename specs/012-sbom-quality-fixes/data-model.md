# Phase 1 Data Model: Cross-format SBOM-Quality Fixes

**Branch**: `012-sbom-quality-fixes` | **Date**: 2026-04-25 | **Plan**: [plan.md](plan.md) | **Research**: [research.md](research.md)

## Scope

Three small data-model changes, one per user story:

| US | Change | File |
|---|---|---|
| US1 | None — implementation fix only | (`v3_external_ids.rs` change is a one-line predicate fix; no new types) |
| US2 | None — comparison-test changes only | (no model change; new tests assert existing structure) |
| US3 | Two: `SpdxLicenseField::LicenseRef(String)` enum variant + new `SpdxExtractedLicensingInfo` struct | `mikebom-cli/src/generate/spdx/packages.rs` and `mikebom-cli/src/generate/spdx/document.rs` |

## US3 entities

### `SpdxLicenseField::LicenseRef(String)` (new enum variant)

Existing enum at `mikebom-cli/src/generate/spdx/packages.rs:57-70`:

```rust
pub enum SpdxLicenseField {
    Expression(String),
    NoAssertion,
    None,
    LicenseRef(String),  // NEW (US3)
}
```

| Field / Variant | Type | Source | Validation |
|-----------------|------|--------|------------|
| `LicenseRef(String)` | `String` | Derived from the joined-AND raw expression via `SpdxId::for_license_ref` | Must start with `LicenseRef-`; SPDX 2.3 §10.1's `licenseId` regex `[A-Za-z0-9.\-]+` (BASE32-NOPAD alphabet `[A-Z2-7]` is a subset). |
| Custom `Serialize` impl | n/a | n/a | Emits the `LicenseRef-<hash>` string verbatim — same shape as `Expression(s)` serialization (bare string). |

State transitions: `Expression` ↔ `LicenseRef` is the all-or-nothing decision per `try_canonical` success/failure (clarification Q1). `NoAssertion` is reached only when the source `licenses[]` is empty.

### `SpdxExtractedLicensingInfo` (new struct)

Document-level array entry per SPDX 2.3 §10.1–10.4. New definition at `mikebom-cli/src/generate/spdx/document.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpdxExtractedLicensingInfo {
    #[serde(rename = "licenseId")]
    pub license_id: String,        // "LicenseRef-<16-char-base32-hash>"
    #[serde(rename = "extractedText")]
    pub extracted_text: String,    // joined-AND raw expression
    pub name: String,              // literal "mikebom-extracted-license"
}
```

| Field | Type | Source | Validation |
|-------|------|--------|------------|
| `license_id` | `String` | `SpdxId::for_license_ref(joined_raw_expr)` | Same string as the Package's `licenseDeclared` / `licenseConcluded` reference. |
| `extracted_text` | `String` | The component's `licenses[]` entries joined by ` AND ` verbatim (no canonicalization, no normalization) | Non-empty. |
| `name` | `String` | Literal `"mikebom-extracted-license"` | Non-empty per SPDX 2.3 §10.4. |

Identity / uniqueness: deduped by `license_id` at document level. Two components carrying the same raw expression produce one `SpdxExtractedLicensingInfo` referenced twice. The dedupe is by the deterministic content hash, which guarantees that "the same expression text" → "one entry."

### `SpdxDocument.has_extracted_licensing_infos: Vec<SpdxExtractedLicensingInfo>` (new field)

Existing struct at `mikebom-cli/src/generate/spdx/document.rs::SpdxDocument`. New field added:

```rust
#[serde(rename = "hasExtractedLicensingInfos", skip_serializing_if = "Vec::is_empty")]
pub has_extracted_licensing_infos: Vec<SpdxExtractedLicensingInfo>,
```

State: empty by default; populated during `build_document` when any Package's `reduce_license_vec` returned a `LicenseRef`. The SPDX 2.3 schema's `hasExtractedLicensingInfos` is optional — `skip_serializing_if = "Vec::is_empty"` keeps existing scans byte-identical (no spurious empty array).

## ID-derivation rule

```text
LicenseRef-ID = "LicenseRef-" + base32_nopad(sha256(joined_raw_expression))[..16]
```

Where:
- `joined_raw_expression` = the component's `licenses[]` entries joined by ` AND ` verbatim. Example: a single-entry `["GNU General Public"]` yields `joined = "GNU General Public"`. A two-entry `["MIT", "GNU General Public"]` yields `joined = "MIT AND GNU General Public"`.
- `sha256` is the standard SHA-256.
- `base32_nopad` is RFC 4648 base32 without padding. Output alphabet: `[A-Z2-7]`.
- `[..16]` takes the first 16 characters (= 80 bits).

The rule is exposed as `SpdxId::for_license_ref(raw_expr: &str) -> SpdxId` in `mikebom-cli/src/generate/spdx/ids.rs`. The existing `SpdxId::for_purl` and the new `for_license_ref` share an internal `hash_prefix` helper.

Determinism: same `raw_expr` → same `LicenseRef-ID` everywhere, every run, every machine.

Collision: 80 bits of entropy. Birthday-bound collision at ~1.2 × 10¹² distinct inputs. The polyglot fixture has ~700 distinct expressions — collision probability ≈ 2 × 10⁻¹⁹.

## Interaction with the existing `reduce_license_vec`

Existing function at `packages.rs:164-180`:

```rust
fn reduce_license_vec(items: &[SpdxExpression]) -> SpdxLicenseField { /* current */ }
```

Rewritten signature:

```rust
fn reduce_license_vec(items: &[SpdxExpression])
    -> (SpdxLicenseField, Option<SpdxExtractedLicensingInfo>);
```

The `Option<SpdxExtractedLicensingInfo>` carries the new entry when (and only when) the function chose the `LicenseRef` path. `build_packages` collects these into a deduped `BTreeMap<String, SpdxExtractedLicensingInfo>` keyed by `license_id`, then hands the deduplicated list back to `build_document` via the existing `(packages, …)` return shape.

Rule per clarification Q1 (all-or-nothing):

```text
canonical_count = items.iter().filter(|e| try_canonical(e).is_ok()).count()
if items is empty:
    -> (NoAssertion, None)
elif canonical_count == items.len():
    -> (Expression(joined_canonical), None)        # existing path; unchanged
else:
    -> (LicenseRef(license_ref_id), Some(extracted_info))   # new path
```

The "all canonicalize" branch is byte-identical to today's emission shape (FR-008). The "any failure" branch is the new path (FR-007 / FR-010 / clarification Q1).

## Touch list — every type-or-field this milestone adds, modifies, or removes

| Identifier | Change | File |
|------------|--------|------|
| `SpdxLicenseField::LicenseRef(String)` | NEW variant | `spdx/packages.rs` |
| `SpdxLicenseField::Serialize` impl | EXTENDED — new arm for `LicenseRef(s)` emitting bare `LicenseRef-<hash>` string | `spdx/packages.rs` |
| `SpdxExtractedLicensingInfo` struct | NEW | `spdx/document.rs` |
| `SpdxDocument.has_extracted_licensing_infos` field | NEW | `spdx/document.rs` |
| `SpdxId::for_license_ref(raw: &str) -> SpdxId` | NEW associated function | `spdx/ids.rs` |
| `SpdxId::hash_prefix` (private helper) | NEW (factored out of existing `for_purl` body) | `spdx/ids.rs` |
| `reduce_license_vec` | RENAMED return type | `spdx/packages.rs` |
| `is_fully_resolved_cpe23` | one-character literal change (US1) | `spdx/v3_external_ids.rs` |

No types are removed. No public APIs change (this is all `pub(super)` / module-internal type machinery).
