---
description: "Implementation plan — milestone 023 ELF binary identity (revised, bag-first)"
status: plan
milestone: 023
---

# Plan: ELF binary identity (revised — bag-first design)

## Architecture

Two cohorts:

**Cohort A — generic per-component annotation bag** (the foundation):
- New field `extra_annotations: BTreeMap<String, serde_json::Value>` on
  both `PackageDbEntry` (mikebom-cli) and `ResolvedComponent` (mikebom-common).
- Initialization at every existing struct-literal site (35 + ~5 = ~40 sites,
  one line each).
- Plumbing through `scan_fs/mod.rs:445` PackageDbEntry → ResolvedComponent
  conversion.
- Generic emission code in `cyclonedx/builder.rs`, `spdx/annotations.rs`,
  `spdx/v3_annotations.rs` that iterates the bag at the end of per-component
  emission.

**Cohort B — ELF identity as the first bag consumer**:
- `BinaryScan` gains `build_id: Option<String>`, `runpath: Vec<String>`,
  `debuglink: Option<DebuglinkEntry>` (already-prepared parsers in
  `binary/elf.rs` from commit `e0d658e`).
- `scan.rs::scan_binary` populates these fields when ELF.
- `entry.rs::make_file_level_component` translates the populated fields
  into bag entries (`mikebom:elf-build-id` etc.).
- Catalog rows + parity extractors via the established `*_anno!` pattern.

The bag is the architectural payoff. ELF identity is the first consumer that
proves it works end-to-end.

## Reuse inventory

- `BTreeMap` from std + `serde_json::Value` — already in scope everywhere.
- `MikebomAnnotationCommentV1` envelope (`generate/spdx/annotations.rs:43`)
  for SPDX 2.3 emission — generic emission iterates the bag and pushes one
  envelope per entry.
- `push(out, field, value)` helper (existing pattern in
  `generate/spdx/annotations.rs`).
- `properties.push(json!({"name": ..., "value": ...}))` pattern in
  `cyclonedx/builder.rs`.
- ELF extractors in `binary/elf.rs` (already-landed in commit `e0d658e`).
- `cdx_anno!`, `spdx23_anno!`, `spdx3_anno!` macros for parity rows.
- `tests/scan_binary.rs` scaffolding for fixture-driven assertions.

## Touched files (revised — measured against actual code, not estimated)

| File | Change | Approx LOC |
|---|---|---|
| `mikebom-cli/src/scan_fs/package_db/mod.rs` | + `extra_annotations` field on PackageDbEntry | +5 |
| 35 PackageDbEntry init sites across `mikebom-cli/src/scan_fs/` | + `extra_annotations: Default::default(),` per site | +35 |
| `mikebom-common/src/resolution.rs` | + same field on ResolvedComponent | +5 |
| ~5 ResolvedComponent init sites (likely `scan_fs/mod.rs` mostly) | + 1 line each | +5 |
| `mikebom-cli/src/scan_fs/mod.rs:~445` | clone bag through PackageDbEntry → ResolvedComponent conversion | +1 |
| `mikebom-cli/src/generate/cyclonedx/builder.rs` | + generic bag emission | +12 |
| `mikebom-cli/src/generate/spdx/annotations.rs` | + generic bag emission | +10 |
| `mikebom-cli/src/generate/spdx/v3_annotations.rs` | + generic bag emission | +10 |
| `mikebom-cli/src/scan_fs/binary/entry.rs` | + 3 fields on BinaryScan; populate bag in make_file_level_component | +30 |
| `mikebom-cli/src/scan_fs/binary/scan.rs` | populate the 3 fields in scan_binary's ELF arm | +35 |
| `mikebom-cli/src/scan_fs/binary/elf.rs` | (already done in commit `e0d658e`; 3 extractors + tests) | 0 |
| `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3}.rs` | + 3 `*_anno!` invocations each | +9 |
| `mikebom-cli/src/parity/extractors/mod.rs` | + 3 EXTRACTORS rows + 9 fn imports | +12 |
| `docs/reference/sbom-format-mapping.md` | + 3 C-section rows | +6 |
| `mikebom-cli/tests/fixtures/binaries/elf/` | + 3 fixtures (binary blobs) | new dir |
| `mikebom-cli/tests/scan_binary.rs` | + 3 assertions | +60 |

Total: ~13 files (excluding fixtures), ~235 LOC of source changes plus the
35-site init churn (~35 LOC of mechanical default-init).

## Phasing

Four atomic commits in dependency order:

### Commit 1 — `023/extractors` (LANDED in `e0d658e`)
✅ ELF extractors + DebuglinkEntry + 13 inline tests with `#[allow(dead_code)]`.

### Commit 2 — `023/extra-annotations-bag`
- Add `extra_annotations: BTreeMap<String, serde_json::Value>` to
  `PackageDbEntry` and `ResolvedComponent`.
- Init at every struct-literal site (35 + ~5).
- Clone through `scan_fs/mod.rs` conversion.
- Generic emission code in 3 generate/ files.
- Iteration order: `BTreeMap` provides deterministic ordering for byte-
  identity goldens.

After this commit: bag works end-to-end but has no consumers. Run regen on
27 goldens — expect zero diff (no consumer adds keys yet).

### Commit 3 — `023/wire-up-elf-identity`
- Add 3 fields to `BinaryScan`.
- Populate in `scan.rs::scan_binary` ELF arm.
- Translate to bag entries in `entry.rs::make_file_level_component`.
- Remove `#[allow(dead_code)]` from elf.rs extractors (now called).
- Add 3 fixtures + 3 assertions in `tests/scan_binary.rs`.

After this commit: ELF identity emits end-to-end. Goldens regen with deltas
only on binary fixtures.

### Commit 4 — `023/parity-rows`
- 3 catalog rows + 3 `*_anno!` invocations across cdx/spdx2/spdx3.
- 3 EXTRACTORS rows + 9 fn imports in mod.rs.
- holistic_parity asserts SymmetricEqual on the new rows.

Per FR-019 each commit's `./scripts/pre-pr.sh` is clean.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Commit 1 (already done) | — | — |
| Commit 2 (bag) | 4-5 hr | 35-site init is mechanical; emission is the careful step |
| Commit 3 (ELF wire-up + fixtures + tests) | 3-4 hr | Deterministic-fixture construction is the new wrinkle |
| Commit 4 (parity rows) | 1 hr | Mechanical |
| Verification + PR | 1 hr | Goldens regen + CI watch |
| **Total** | **~10 hr** | One focused day. |

## Risks

- **R1 (NEW): Bag ordering must be deterministic across runs.** `BTreeMap`'s
  iteration order is sorted by key — same on every run, every host. Verified
  by spec and enforced by holistic_parity's byte-identity gate.
- **R2 (NEW): Existing typed fields might "double-emit" if someone stuffs the
  same key into the bag.** Mitigation: spec discipline (see Edge Cases). If
  it happens, holistic_parity's SymmetricEqual check on the existing typed
  field's catalog row will catch it (the same field would now have two
  different values across CDX/SPDX).
- **R3 (NEW): Generic emission must skip the bag if empty.** Otherwise CDX
  emits an empty `properties[]` array on every component. Mitigation: emit
  block guarded by `if !c.extra_annotations.is_empty()`.
- **R4: object-crate API for note iteration** — already mitigated in
  commit 1's tests.
- **R5: Fixture builds non-deterministic** — same mitigation as original
  plan: `objcopy --add-section` on a known-good base or programmatic
  `object::write::elf::Writer`.

## Constitution alignment

- **Principle I (zero C):** untouched. ✓
- **Principle IV (no `.unwrap()`):** all bag plumbing uses Default + Option. ✓
- **Principle VI (three-crate architecture):** mikebom-common gains
  `extra_annotations` on ResolvedComponent — this is a contract change but
  follows the existing convention (ResolvedComponent already has typed
  fields like `is_dev`, `co_owned_by`). ✓
- **Per-commit verification:** FR-019 enforced.

## What this milestone does NOT do

- Does not migrate existing typed fields into the bag.
- Does not touch macho.rs / pe.rs (deferred to 024 / 028).
- Does not change CLI args.
- Does not add a debuginfod / debug-symbol-package lookup.
- Does not validate .gnu_debuglink CRC32.
- Does not expand `$ORIGIN` in RPATH/RUNPATH.
