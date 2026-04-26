---
description: "Extract ELF NT_GNU_BUILD_ID, DT_RPATH/DT_RUNPATH, and .gnu_debuglink + introduce a generic per-component annotation bag so future per-binary metadata work can land without per-field schema migration"
status: spec
milestone: 023
---

# Spec: ELF binary identity (revised — bag-first design)

## Note on spec amendment (2026-04-26)

The original spec scoped this milestone as a 4-file tighter spec adding three
typed fields directly to `PackageDbEntry` + `ResolvedComponent`. Mid-implementation
discovery: `PackageDbEntry` has 35 struct-literal construction sites and no `Default`
impl (because `Purl` and `SpdxExpression` don't have meaningful defaults), so every
new typed field forces 35 manual `field: None,` additions per milestone. The same
churn would land again in milestones 024 (Mach-O LC_UUID + codesign), 025 (Go VCS
metadata), 026 (version-string library expansion), and 027 (container layer
attribution).

The amendment introduces a **generic `extra_annotations` bag** to both
`PackageDbEntry` and `ResolvedComponent`. Future per-binary metadata stuffs the
bag instead of adding typed fields. The 35-site Default-init churn happens
once. Generic emission code in the three generate/ files iterates the bag.

ELF binary identity (`mikebom:elf-build-id`, `mikebom:elf-runpath`,
`mikebom:elf-debuglink`) lands as the **first consumer** of the bag — proving
the design end-to-end before milestones 024-027 inherit it.

The spec below reflects the revised design. The original spec's claim that the
emission path didn't touch `generate/` was wrong (verified 2026-04-26 via
recon: `mikebom:binary-class` and similar mikebom annotations are emitted by
`generate/cyclonedx/builder.rs:451-454`, `generate/spdx/annotations.rs:148`, and
`generate/spdx/v3_annotations.rs`).

## Background

mikebom's ELF binary scanner already reads systemd FDO Packaging Metadata via
the `object` crate's note-walking API
(`mikebom-cli/src/scan_fs/binary/elf.rs:43-79`). It does NOT read three other
near-universal ELF identity / linkage signals that the same primitives could
surface — see the original Background section below. The architectural change in
this revised spec is **how** those new signals reach the SBOM output, not what
they are.

The three ELF signals (unchanged from original spec):

- **NT_GNU_BUILD_ID** — 20-byte SHA-1-derived note (`.note.gnu.build-id` section)
  emitted by every modern toolchain. The canonical Linux binary identity (used
  by `eu-unstrip`, `coredumpctl`, `debuginfod`, `*-dbgsym` packaging).
- **DT_RPATH / DT_RUNPATH** — embedded library search paths the dynamic loader
  honors. Today mikebom's `linkage.rs` ignores RPATH and false-negatives on
  vendored Rust/C++/JNI binaries.
- **.gnu_debuglink** — pointer to the stripped-debug sibling file.

## User story (US1, P1)

**As an SBOM consumer correlating a binary across container layers or to its
debuginfo package**, I want each ELF component in mikebom output to carry its
NT_GNU_BUILD_ID, RPATH/RUNPATH list, and .gnu_debuglink reference (when
present) — surfaced via the generic per-component annotation bag — so that
downstream tools can stable-identify the binary, resolve runtime linkage
correctly, and locate the matching debug-symbol package.

**Why P1**: this is correctness-flavored. Until build-id lands, mikebom's
binary identity is "absolute path on disk" — not survivable across renames or
container-layer dedup. The bag design simultaneously unlocks future per-binary
metadata milestones (024-027) without recurring per-field schema migrations.

### Independent test

After implementation:

- `target/debug/mikebom sbom scan --path tests/fixtures/binaries/elf/with-build-id`
  emits CDX with property `name: mikebom:elf-build-id`, value matching the
  fixture's known hex build-id.
- Same scan emits SPDX 2.3 annotation envelope with `field:
  mikebom:elf-build-id`.
- Same scan emits SPDX 3 annotation envelope with same field.
- Three new C-section catalog rows appear in
  `docs/reference/sbom-format-mapping.md`; `holistic_parity` asserts
  SymmetricEqual.
- `tests/scan_binary.rs` gains assertions that the three fields populate as
  expected.
- 27 byte-identity goldens regen with deltas only on binary fixtures.

## Acceptance scenarios

(Same as original spec — 4 scenarios. See git history for details if
re-reading the amended file. Carrying forward verbatim:)

**Scenario 1**: Build-id round-trip across CDX / SPDX 2.3 / SPDX 3.
**Scenario 2**: Multi-RPATH binary (no `$ORIGIN` expansion).
**Scenario 3**: Stripped binary with debuglink → JSON object emission.
**Scenario 4**: Absent fields → no empty annotations.

## Edge cases

(Same as original spec. Add one new edge case for the bag:)

- **Empty bag**: when a component has no `extra_annotations` entries, the
  generic emission code skips emission entirely (no empty `properties[]`
  block, no empty `annotations[]` array).
- **Bag key collision with typed field**: if a future caller mistakenly stuffs
  `mikebom:binary-class` into the bag while the typed `binary_class` field
  also populates, both will emit and the parity test will catch the
  duplicate. Spec discipline: typed fields stay typed; only NEW per-component
  data lands in the bag.

## Functional requirements

### Bag introduction

- **FR-001 (NEW)**: `mikebom-cli/src/scan_fs/package_db/mod.rs::PackageDbEntry`
  gains `pub extra_annotations: std::collections::BTreeMap<String, serde_json::Value>`
  with default empty.
- **FR-002 (NEW)**: `mikebom-common/src/resolution.rs::ResolvedComponent`
  gains the same field with the same type and default.
- **FR-003 (NEW)**: 35 `PackageDbEntry { ... }` construction sites and ~5
  `ResolvedComponent { ... }` construction sites add the field
  initialization. (`extra_annotations: Default::default(),`).
- **FR-004 (NEW)**: `mikebom-cli/src/scan_fs/mod.rs` (the
  `PackageDbEntry → ResolvedComponent` conversion at line ~445) clones
  the bag through.
- **FR-005 (NEW)**: `mikebom-cli/src/generate/cyclonedx/builder.rs` emits
  every entry in `c.extra_annotations` as a CDX `properties[]` row
  (`{"name": <key>, "value": <stringified-value>}`) when populated.
  Stringification: `serde_json::Value::as_str` for strings (raw),
  `serde_json::to_string` for non-string Values (matches existing CDX
  property convention for arrays/objects).
- **FR-006 (NEW)**: `mikebom-cli/src/generate/spdx/annotations.rs` emits
  every entry as a SPDX 2.3 `annotations[]` envelope via the existing
  `MikebomAnnotationCommentV1` machinery, one annotation per bag entry.
- **FR-007 (NEW)**: `mikebom-cli/src/generate/spdx/v3_annotations.rs` does
  the same for SPDX 3 graph-element Annotation entries.

### ELF binary identity (the first bag consumer)

- **FR-008**: `mikebom-cli/src/scan_fs/binary/elf.rs` gains the three
  extractors per original FR-001 (already landed in commit `e0d658e`).
- **FR-009**: `mikebom-cli/src/scan_fs/binary/entry.rs::BinaryScan` gains
  three new fields: `build_id: Option<String>`, `runpath: Vec<String>`,
  `debuglink: Option<DebuglinkEntry>` (per original FR-002).
- **FR-010**: `mikebom-cli/src/scan_fs/binary/scan.rs::scan_binary`
  populates the three fields by calling the extractors when ELF (per
  original FR-003).
- **FR-011**: `mikebom-cli/src/scan_fs/binary/entry.rs::make_file_level_component`
  populates `extra_annotations` from BinaryScan: build-id as a string
  Value, runpath as a JSON array, debuglink as a JSON object, when each
  source field is populated. Empty/None values skip insertion.

### Catalog + parity

- **FR-012**: 3 new C-section rows in `docs/reference/sbom-format-mapping.md`
  for the three annotations.
- **FR-013**: `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3}.rs` each
  gain three new `*_anno!` invocations.
- **FR-014**: `mikebom-cli/src/parity/extractors/mod.rs::EXTRACTORS` gains
  three new rows + 9 imports.

### Tests + verification

- **FR-015**: `mikebom-cli/tests/fixtures/binaries/elf/` gains 3 fixtures
  (with-all, with-build-id-only, no-build-id).
- **FR-016**: `mikebom-cli/tests/scan_binary.rs` gains 3 assertions.
- **FR-017**: `mikebom-cli/tests/holistic_parity.rs` continues to pass.
- **FR-018**: 27-golden regen produces deltas only on binary fixtures.
- **FR-019**: Each commit in the milestone leaves `./scripts/pre-pr.sh`
  clean.

## Success criteria

- **SC-001**: All four standard verification gates green (clippy, tests,
  scan_binary new assertions, holistic_parity).
- **SC-002**: Real `/bin/ls` scan emits a non-empty `mikebom:elf-build-id`.
- **SC-003**: `git diff main..HEAD -- mikebom-cli/src/scan_fs/binary/macho.rs mikebom-cli/src/scan_fs/binary/pe.rs` empty.
- **SC-004 (REVISED)**: `wc -l mikebom-cli/src/scan_fs/binary/elf.rs` ≤ 600
  (was 420 in original spec; revised after measuring real test verbosity in
  commit `e0d658e` — see commit message for the breakdown).
- **SC-005 (REVISED)**: This milestone now legitimately touches `generate/`
  (FR-005, FR-006, FR-007) and `mikebom-common/` (FR-002). The original
  SC-005 was wrong. The new constraint: `git diff main..HEAD --
  mikebom-cli/src/cli/ mikebom-cli/src/resolve/` is empty (CLI and resolve
  pipeline untouched).
- **SC-006**: All 3 CI lanes green.
- **SC-007 (NEW)**: `cargo +stable test --workspace` post-merge demonstrates
  zero breakage in any of the 35 PackageDbEntry sites (the bag-init churn
  doesn't break logic).
- **SC-008 (NEW)**: A future no-op call site that would have needed to add
  3 typed-field defaults gets to add 0 lines (the bag absorbs new keys
  without needing struct-literal updates). Verified by inspection: any new
  per-binary metadata milestone (024+) just `entry.extra_annotations.insert(
  "mikebom:foo", value)` without touching the 35 PackageDbEntry sites.

## Clarifications

- **Why a bag and not generic typed fields**: Typed fields require per-field
  schema migration across 35+ struct-literal sites. A bag amortizes that
  cost across all future per-component metadata milestones. Three milestones
  (024-027) are already roadmapped; the bag pays for itself on milestone 024.
- **Why `BTreeMap` instead of `HashMap`**: Deterministic iteration order at
  emission time. `holistic_parity` byte-identity goldens depend on stable
  output; HashMap's randomized order would break that.
- **Bag values are `serde_json::Value`**: matches the
  `MikebomAnnotationCommentV1` envelope's existing `value` field type. No
  new type machinery.
- **Typed fields stay typed**: existing `binary_class`, `is_dev`,
  `evidence_kind`, etc. don't migrate to the bag. The bag is for NEW per-
  binary metadata only. Future milestone could consolidate; not this one.
- **No `$ORIGIN` expansion**, **no CRC32 verification**, **no debuginfod
  lookup** — same clarifications as original spec.

## Out of scope

- Migration of existing typed fields (binary_class, etc.) into the bag
  (separate refactor milestone if ever desired).
- Mach-O LC_UUID / codesign (deferred to milestone 024 — will be the
  bag's first non-ELF consumer).
- PE Delay-Load / subsystem (deferred to milestone 028).
- Go VCS metadata extraction (deferred to milestone 025; will use the bag).
- Container layer attribution (deferred to milestone 027).
