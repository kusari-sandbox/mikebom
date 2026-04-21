# Licenses

mikebom tracks **two separate** license fields per component: what the
package author declared, and what a curated external analyzer concluded.
Both are emitted in the CycloneDX output with distinct `acknowledgement`
values so downstream tools can trust the right source for their use case.

**Key files:**

- `mikebom-common/src/resolution.rs` — `ResolvedComponent.licenses` and
  `ResolvedComponent.concluded_licenses`.
- `mikebom-common/src/types/license.rs` — `SpdxExpression`, SPDX
  canonicalization via the `spdx` crate.
- `mikebom-cli/src/enrich/clearly_defined_source.rs` — concluded-license
  enricher.
- `mikebom-cli/src/enrich/depsdev_source.rs` — declared-license enricher.

## The two-bucket model

```rust
pub struct ResolvedComponent {
    /// Licenses asserted by the package author in their manifest
    /// (npm package.json, Cargo.toml, etc.) or by the OS package
    /// metadata (dpkg copyright, rpm header). Maps to CycloneDX
    /// `licenses[]` with `acknowledgement: "declared"`.
    pub licenses: Vec<SpdxExpression>,

    /// Licenses determined through external analysis — currently
    /// ClearlyDefined.io's curated `licensed.declared` field. Maps to
    /// CycloneDX `licenses[]` with `acknowledgement: "concluded"`.
    pub concluded_licenses: Vec<SpdxExpression>,
    ...
}
```

Both serialize into CycloneDX `components[].licenses[]` with the
`acknowledgement` field distinguishing them. They may overlap when both
sources agree — the serializer emits each side once.

### Why two buckets

- **Declared** is what the package author claims. It's cheap, universally
  available when a manifest is present, and sometimes wrong (author typos,
  outdated declarations, free-form text that doesn't canonicalize to SPDX).
- **Concluded** is what an external curator (ClearlyDefined) determined
  through its own analysis pass. It's slower, requires network access, and
  isn't available for every package — but when present it's the
  highest-trust signal.

A consumer doing compliance review cares about concluded first, declared
second. A consumer doing vulnerability matching cares about neither — they
want the CPE. Keeping both lets each consumer pick.

## Source precedence

Licenses can come from three places, at three phases of the pipeline:

1. **Scan-time manifest parsing** (scan stage, `scan_fs/package_db/*.rs`).
   Populates `licenses[]` from:
   - dpkg `/usr/share/doc/<pkg>/copyright` — DEP-5 structured form,
     standalone `License:` stanzas (common-licenses references), modern
     `SPDX-License-Identifier:` tag, and a multi-line recogniser for the
     canonical FSF license-grant prose that packages like
     `debian-archive-keyring`, `libcrypt1`, `libsemanage2`, `libgcc-s1`
     ship verbatim.
   - rpm header `License` field.
   - Cargo.toml `license`.
   - npm `package.json` `license`.
   - gemspec `s.license=` / `s.licenses=`.
   - Maven POM `<licenses>`.
   - PyPI wheel `METADATA` `License:` / `License-Expression:` headers.
2. **deps.dev enrichment** (`enrich/depsdev_source.rs`). Populates
   `licenses[]` — same bucket as scan-time — with deps.dev's reported SPDX
   license. This fills the gap when the local manifest has no license
   field (e.g. PyPI wheels that only carry trove classifiers, gems whose
   gemspec has no license).
3. **ClearlyDefined enrichment** (`enrich/clearly_defined_source.rs`).
   Populates `concluded_licenses[]` from CD's `licensed.declared` field,
   which is itself the output of CD's automated curation.

deps.dev and ClearlyDefined populate **different buckets**. They are not in
tension — deps.dev is a stand-in for the author's declaration when the
local manifest didn't carry one; ClearlyDefined is a separate curated
judgment.

## SPDX canonicalization

Every license expression that lands in either bucket passes through the
`spdx` crate. Free-form strings never reach the CycloneDX output — the
serializer only emits valid SPDX expressions.

Non-canonical inputs are logged at `warn` level and dropped. This includes:

- Free-form license text ("Licensed under the BSD").
- Proprietary license names that don't map to SPDX.
- `NOASSERTION` — explicitly **never** emitted. sbomqs's
  `ValidateLicenseText` rejects `NOASSERTION`, so emitting it would cost
  score without any benefit. When a package truly has no determinable
  license, the component emits no `licenses[]` entry at all.

## CycloneDX shape

Single-identifier licenses emit as:

```json
"licenses": [{ "license": { "id": "MIT", "acknowledgement": "declared" } }]
```

Compound expressions emit as:

```json
"licenses": [{ "expression": "(MIT OR Apache-2.0)", "acknowledgement": "concluded" }]
```

The `acknowledgement` field takes either `"declared"` or `"concluded"`.
sbomqs's `comp_with_valid_licenses` requires a valid SPDX expression in
either shape.

A component that has both declared and concluded licenses for the same
expression emits two entries — the serializer doesn't dedupe across
acknowledgement types because they mean different things.

## Coverage in practice

- **deb / rpm**: declared licenses from DEP-5 / rpm header are the primary
  source; ClearlyDefined doesn't cover deb/apk/rpm well today. See
  [design-notes deferred item
  18](../design-notes.md#deferred-sbomqs-score-lift) for the planned
  ClearlyDefined deb arm (priority next).
- **apk**: apk's installed DB doesn't carry copyright pointers like dpkg
  does, so apk components still ship with empty `licenses[]`. See the known
  gap in
  [`EVALUATION.md`](../../EVALUATION.md#known-gaps-called-out-by-design).
- **npm / cargo / gem / pypi / maven / golang**: declared licenses come
  from manifests; deps.dev backfills missing ones; ClearlyDefined
  contributes concluded licenses. This is where the
  [sbomqs score lift to 8.8/10 on
  npm](../design-notes.md#sbomqs-scoring-baseline-2026-04-20-post-cd-pass)
  came from.

## Known limitations

- **License expression canonicalization is best-effort.** The `spdx` crate
  is strict; some legitimate expressions (compound with operators in
  non-standard order, e.g.) may be dropped where a more permissive parser
  would accept.
- **Deprecated-license flagging** (sbomqs `comp_no_deprecated_licenses`)
  and restrictive-license flagging are not yet emitted. The `spdx` crate
  has the data via `is_deprecated()` and OSI/copyleft classifications —
  threading that through `SpdxExpression` into CycloneDX properties is a
  deferred backlog item.
- **Supplier extraction** (sbomqs `comp_with_supplier`) isn't done yet.
  Lockfiles don't carry author info; adding `node_modules/` / `.m2`
  walks for supplier would unlock another ~2% of the sbomqs score. See
  [design-notes deferred item
  14](../design-notes.md#deferred-sbomqs-score-lift).
