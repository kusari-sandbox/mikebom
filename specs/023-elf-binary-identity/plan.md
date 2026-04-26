---
description: "Implementation plan — milestone 023 ELF binary identity"
status: plan
milestone: 023
---

# Plan: ELF binary identity

## Architecture

Pure additive scanning extension. Three new `pub(super)` extractors in
`elf.rs` follow the established `extract_note_package` shape (parse via
`object::read::elf::*`, return None on failure). Three new fields on
`BinaryScan`. Three new annotation emissions in `mod.rs::read`. Three new
catalog rows + parity extractors via the established C-section pattern.

No new types beyond a small `DebuglinkEntry { file: String, crc32: u32 }`
struct used only inside the binary scanner. No public-API surface change.
No schema migration.

## Reuse inventory

These existing items handle the work; this milestone consumes them:

- `object::read::elf::ElfFile<'_, _>` (already in scope via the `object` crate
  used by `elf.rs::extract_note_package`).
- `object::read::elf::NoteIterator` — produced by `ElfFile::raw_header().e_shoff`-
  driven iteration; same primitive that walks notes today.
- `object::read::elf::SectionTable::section_by_name(b".gnu_debuglink")` — exists
  in the API; returns `Section<'_>` with `.data()`.
- `object::read::elf::Dyn` (DT_RPATH = 0x0F, DT_RUNPATH = 0x1D) — accessed via
  `ElfFile::dynamic()`. Strings interned in `.dynstr`.
- `extract_mikebom_annotation_values` and `cdx_property_values` — established
  C-section emission infrastructure (`parity/extractors/common.rs`,
  `parity/extractors/cdx.rs`).
- `cdx_anno!`, `spdx23_anno!`, `spdx3_anno!` macros — one-line registration
  per format per extractor (3 extractors × 3 formats = 9 lines total).
- `tests/scan_binary.rs` — existing scaffolding for binary-fixture testing.

## Touched files

| File | Change | LOC |
|---|---|---|
| `mikebom-cli/src/scan_fs/binary/elf.rs` | + 3 extractor fns + DebuglinkEntry struct | +180 |
| `mikebom-cli/src/scan_fs/binary/entry.rs` | + 3 fields on BinaryScan + DebuglinkEntry import | +12 |
| `mikebom-cli/src/scan_fs/binary/scan.rs` | populate the 3 fields in scan_binary's ELF arm | +15 |
| `mikebom-cli/src/scan_fs/binary/mod.rs` | emit 3 annotations from BinaryScan when populated | +30 |
| `mikebom-cli/src/parity/extractors/cdx.rs` | + 3 cdx_anno! invocations | +3 |
| `mikebom-cli/src/parity/extractors/spdx2.rs` | + 3 spdx23_anno! invocations | +3 |
| `mikebom-cli/src/parity/extractors/spdx3.rs` | + 3 spdx3_anno! invocations | +3 |
| `mikebom-cli/src/parity/extractors/mod.rs` | + 3 EXTRACTORS table rows + 9 fn imports | +12 |
| `docs/reference/sbom-format-mapping.md` | + 3 C-section rows | +6 |
| `mikebom-cli/tests/fixtures/binaries/elf/` | + 3 fixtures (binary blobs, deterministic build) | new dir |
| `mikebom-cli/tests/scan_binary.rs` | + assertions for the 3 fields × 3 fixtures | +60 |

Total Rust source: ~250 LOC across 8 files.

## Phasing

Three atomic commits in dependency order:

### Commit 1: `023/extractors`
- Add `extract_gnu_build_id`, `extract_runpath_entries`, `extract_debuglink`,
  `DebuglinkEntry` to `elf.rs`.
- Inline tests for each (small in-memory ELF byte-blobs, hand-constructed via
  `object::write::elf::Writer` if practical, else table-tests against tiny
  hand-crafted fixtures).
- No call sites yet — these compile but are unused. `dead_code` may need an
  `#[allow]` on the trio for this commit only; lifted in commit 2.

### Commit 2: `023/wire-up-scan`
- Add 3 fields to `BinaryScan` (`entry.rs`).
- Populate them in `scan.rs::scan_binary` ELF arm.
- Emit 3 annotations from `mod.rs::read` when populated.
- Add the 3 fixtures + 3 `tests/scan_binary.rs` assertions.

### Commit 3: `023/parity-rows`
- Add 3 `*_anno!` invocations across cdx.rs / spdx2.rs / spdx3.rs.
- Add 3 `EXTRACTORS` table rows in `mod.rs`.
- Add 3 catalog rows in `docs/reference/sbom-format-mapping.md`.
- `holistic_parity` should pick them up automatically — assertion is
  SymmetricEqual on each.

Per FR per the spec, each commit's `./scripts/pre-pr.sh` is clean.
Commit 1's `#[allow(dead_code)]` is the only intermediate-state wart.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Commit 1 (extractors) | 4 hr | object-crate API spelunking is the careful step |
| Commit 2 (wire-up) | 3 hr | Fixtures need careful construction (deterministic builds) |
| Commit 3 (parity rows) | 1 hr | Mechanical |
| Verification + PR | 1 hr | Goldens regen + CI watch |
| **Total** | **~9 hr** | One focused day. |

## Risks

- **R1: object-crate API for note iteration.** `object::read::elf` is
  well-documented but the note-walking API is generic over endian/word-size.
  `elf.rs::extract_note_package` already navigates this — my implementation
  mirrors that exactly. If the existing helper turns out to use a private API
  trick, fall back to a direct `.section_by_name(b".note.gnu.build-id")` + raw
  byte parse (the note format is fixed: `name_size + desc_size + type +
  name_bytes + desc_bytes`).
- **R2: DT_RPATH/DT_RUNPATH string-table resolution.** `Dyn::d_val` for
  RPATH/RUNPATH is a string-table offset, not the string itself. Need to
  resolve through `.dynstr`. Same pattern that `linkage.rs:23-32`'s soname
  resolution uses (DT_NEEDED is also a .dynstr offset).
- **R3: Fixture builds are non-deterministic.** Building three small ELF
  binaries with `gcc`/`clang` produces different output per host. Mitigation:
  use `objcopy` to surgically rewrite known-good fixtures: take a known small
  binary (e.g., a static `hello-world`), then `objcopy --set-section-flags`
  / `--add-section` to construct the exact note content. Alternative: use
  `object::write::elf::Writer` to construct fixtures programmatically in
  `build.rs` of the test crate.
- **R4: Catalog row IDs collide.** The catalog parser auto-assigns next
  available IDs (C24, C25, C26 if C23 is the highest). If a future milestone
  has already squatted those, renumber. Easy to adjust.

## Constitution alignment

- **Principle I (zero C in deps):** `object` crate is pure-Rust. ✓
- **Principle IV (no `.unwrap()` in production):** the new extractors return
  `Option`/empty `Vec` on every failure path. No panics. ✓
- **Principle VI (three-crate architecture):** untouched. ✓
- **Per-commit verification (lessons from 018-022):** FR-008 enforced.
- **Recon-first discipline (lesson from 022):** every assumption in the spec
  is grounded in a file:line reference from the recon report.

## What this milestone does NOT do

- Does not touch macho.rs / pe.rs / Mach-O / PE handling.
- Does not change CLI args or output flags.
- Does not implement build-id-based dedup at scan time (recording only).
- Does not add a debuginfod / debug-symbol-package lookup.
- Does not validate .gnu_debuglink CRC32.
- Does not expand `$ORIGIN` in RPATH/RUNPATH strings.
