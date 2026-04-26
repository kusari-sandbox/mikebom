---
description: "Implementation plan — milestone 028 PE binary identity"
status: plan
milestone: 028
---

# Plan: PE binary identity

## Architecture

Pure additive scanning extension. Three new `pub fn` extractors in
`pe.rs` lean on `object` 0.36's typed PE accessors (no byte-level
parsing required, unlike 023 + 024). Three new fields on `BinaryScan`.
Three new annotation emissions via a new `build_pe_identity_annotations`
helper merged into the existing `build_binary_identity_annotations`
unifier. Three new catalog rows + parity extractors via the established
C-section pattern.

No new types beyond a small `PeMachine` / `PeSubsystem` decoder pair
inside `pe.rs` that map raw u16 to lowercase string names. No
public-API surface change. No schema migration.

## Reuse inventory

These existing items handle the work; this milestone consumes them:

- `object::read::pe::PeFile<'data, Pe, R>` — the typed PE reader.
  Already in scope via the `object` crate (Cargo.toml line in
  `mikebom-cli/Cargo.toml`: `features = ["read", "std", "elf",
  "macho", "pe", "coff"]`).
- `object::read::pe::PeFile::pdb_info() -> Result<Option<CodeView<'_>>>` —
  the canonical entry point. Returns the CodeView Type-2 record's
  guid + age + path. Mikebom calls this directly.
- `object::read::CodeView` — `pub fn guid() -> [u8; 16]` (via field
  accessor — actually the field is private but the implementation
  exposes guid() / path() / age() as public methods, per the
  `read/mod.rs` source recon).
- `object::read::pe::PeFile::nt_headers().file_header().machine` —
  IMAGE_FILE_HEADER.Machine (u16).
- `object::read::pe::ImageNtHeaders::optional_header().subsystem()` —
  IMAGE_OPTIONAL_HEADER.Subsystem (u16).
- `object::pe::IMAGE_FILE_MACHINE_*` constants — for human-name lookup.
- `object::pe::IMAGE_SUBSYSTEM_*` constants — for human-name lookup.
- `extract_mikebom_annotation_values` and `cdx_property_values` —
  established C-section emission infrastructure.
- `cdx_anno!`, `spdx23_anno!`, `spdx3_anno!` macros — one-line
  registration per format per extractor (3 × 3 = 9 lines).
- `build_binary_identity_annotations` (milestone 024) — extends with a
  third sub-helper.

## Touched files

| File | Change | LOC |
|---|---|---|
| `mikebom-cli/src/scan_fs/binary/pe.rs` | + 3 extractor fns + machine/subsystem decoder + tests | +220 |
| `mikebom-cli/src/scan_fs/binary/entry.rs` | + 3 fields on BinaryScan + `build_pe_identity_annotations` helper + tests | +75 |
| `mikebom-cli/src/scan_fs/binary/scan.rs` | populate the 3 fields in scan_binary's PE arm | +30 |
| `mikebom-cli/src/parity/extractors/cdx.rs` | + 3 cdx_anno! invocations | +5 |
| `mikebom-cli/src/parity/extractors/spdx2.rs` | + 3 spdx23_anno! invocations | +5 |
| `mikebom-cli/src/parity/extractors/spdx3.rs` | + 3 spdx3_anno! invocations | +5 |
| `mikebom-cli/src/parity/extractors/mod.rs` | + 3 EXTRACTORS rows + 9 fn imports | +12 |
| `docs/reference/sbom-format-mapping.md` | + 3 C-section rows | +3 |

Total Rust source: ~360 LOC across 7 files. Smaller than 024 (~700 LOC)
because `object` carries the heavy lifting.

## Phasing

Three atomic commits in dependency order:

### Commit 1: `028/parsers`
- Promote `pe.rs` from 6-line stub to working module.
- Add `parse_pdb_id`, `parse_machine_type`, `parse_subsystem` parsers.
- Add `machine_to_str(u16) -> Option<&'static str>` and
  `subsystem_to_str(u16) -> Option<&'static str>` decoders covering
  the well-known subset (i386 / amd64 / ia64 / arm / armnt / arm64 /
  riscv32 / riscv64; native / console / windows-gui / windows-cui /
  os2-cui / posix-cui / native-windows / windows-ce-gui / efi-application
  / efi-boot-service / efi-runtime-driver / efi-rom / xbox /
  windows-boot-application). Unknown values map to `"unknown"`.
- Inline tests in `#[cfg(test)] mod tests`:
  - `parse_pdb_id_returns_guid_age_when_codeview_present`
  - `parse_pdb_id_returns_none_for_no_debug_directory`
  - `machine_to_str_known_values`
  - `machine_to_str_unknown_returns_none` (and the wrapper emits "unknown")
  - `subsystem_to_str_known_values`
  - `subsystem_to_str_unknown_returns_none`
- Use a tiny synthetic PE fixture (≤ 1 KB hand-built byte buffer) OR
  an embedded real PE blob (e.g. a minimal `hello.exe` produced by
  `x86_64-w64-mingw32-gcc -o hello.exe hello.c`). Decision deferred
  to T003.
- `#[allow(dead_code)]` on the three parsers + decoder helpers since
  they're not wired up yet. Lifted in commit 2.

### Commit 2: `028/wire-up-bag`
- Add 3 fields to `BinaryScan` (`entry.rs`).
- Populate them in `scan.rs::scan_binary` PE arm.
- Add `build_pe_identity_annotations` helper in `entry.rs` parallel to
  the existing ELF + Mach-O helpers.
- Extend `build_binary_identity_annotations` to merge the PE bag.
- Update the 2 BinaryScan struct-literal sites (scan.rs's existing arm
  + the fat-Mach-O literal at scan.rs:309 + the test `fake_binary_scan`
  helper at entry.rs:597) with the 3 new fields (defaults: None × 3).
- Add 2 inline tests in `entry.rs::tests`:
  - `make_file_level_component_populates_bag_with_all_three_pe_signals`
  - `make_file_level_component_pe_bag_skips_unpopulated_entries`
- Remove `#[allow(dead_code)]` from the parsers in pe.rs.

### Commit 3: `028/parity-rows`
- Add 3 `*_anno!` invocations across cdx.rs / spdx2.rs / spdx3.rs.
- Add 3 `EXTRACTORS` table rows + 9 fn imports in `mod.rs`.
- Add 3 catalog rows in `docs/reference/sbom-format-mapping.md`
  (C33/C34/C35).
- `holistic_parity` and `sbom_format_mapping_coverage` should pick
  them up automatically.

Per FR-010, each commit's `./scripts/pre-pr.sh` is clean. Commit 1's
`#[allow(dead_code)]` is the only intermediate-state wart (same as
milestones 023 + 024).

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (recon + baseline) | 5 min | T001 done; just snapshot |
| Phase 2 (parsers) | 2 hr | `object` provides typed accessors — much easier than 023/024 byte-level work |
| Phase 3 (wire-up) | 2 hr | Mostly mechanical; 3 BinaryScan literal sites |
| Phase 4 (parity rows) | 30 min | Same shape as 024's + 025's |
| Phase 5 (verify + PR) | 1 hr | Goldens regen + CI watch |
| **Total** | **~6 hr** | Faster than 024 thanks to `object`'s typed PE API. |

## Risks

- **R1: `object`-crate CodeView accessor visibility.** Recon showed
  CodeView fields (`guid`, `age`, `path`) are private but the impl
  exposes `path() -> &[u8]` (line 670 in `read/mod.rs`). Need to verify
  guid + age accessors exist or work around via `path()` + raw byte
  re-parsing of the IMAGE_DEBUG_DIRECTORY entry. Mitigation: if
  accessors are missing, drop to byte-level parsing of the CodeView
  Type-2 record (4-byte signature `RSDS` + 16 GUID + 4 age + zero-
  terminated UTF-8 PDB path). Same shape as Mach-O LC_UUID parser
  in 024.
- **R2: PE32 vs PE32+ dispatch.** `PeFile<'data, Pe, R>` is generic
  over `ImageNtHeaders`. Calling `pdb_info()` requires picking
  `PeFile32` or `PeFile64`. Resolution (now canonical in tasks T013):
  read `IMAGE_OPTIONAL_HEADER.Magic` at the optional-header offset
  (`0x10B` = PE32 → `PeFile32::parse`; `0x20B` = PE32+ →
  `PeFile64::parse`). The wrapper fns in pe.rs are generic over
  `ImageNtHeaders` so the body is shared regardless. If the
  dispatch gets ugly inline in scan.rs, extract a `parse_pe(bytes)`
  helper in pe.rs that does the magic-byte read + dispatch + calls
  the three parsers + returns a `(Option<String>, Option<String>,
  Option<String>)` tuple.
- **R3: synthetic fixture construction.** Hand-building a valid PE
  byte buffer is more involved than ELF or Mach-O (DOS stub +
  IMAGE_DOS_HEADER + COFF-style headers + section table + data
  directory references). Mitigation: use a checked-in real
  `mingw-built-hello.exe` (~3 KB) as a `&[u8]` constant in tests.
  CI doesn't need MSVC to build; the binary is a pre-built artifact.
- **R4: catalog row IDs collide.** If a future milestone (027? 026?)
  squats C33-C35, renumber. Easy to adjust before merge.

## Constitution alignment

- **Principle I (zero C in deps):** `object` is pure-Rust. ✓
- **Principle IV (no `.unwrap()` in production):** new extractors return
  `Option<String>` on every failure path. ✓
- **Principle VI (three-crate architecture):** untouched. ✓
- **Per-commit verification (lessons from 016-027):** FR-010 enforced.
- **Recon-first discipline (lesson from 022):** every assumption in
  the spec is grounded in a file:line reference (`pe.rs:1-6`,
  `scan.rs:117 + 213`, `object/read/pe/file.rs:348` for `pdb_info`,
  `object/read/mod.rs:670` for `CodeView::path`).
- **Bag amortization (lessons from 023-024-025):** SC-005 + SC-007
  verify zero churn outside `binary/` + `parity/extractors/`.

## What this milestone does NOT do

- Does not touch elf.rs / macho.rs / ELF / Mach-O handling.
- Does not change CLI args or output flags.
- Does not implement Authenticode / code-sign info extraction.
- Does not parse the Rich header.
- Does not extract DllCharacteristics security flags.
- Does not walk Delay-Load imports (separate linkage-evidence concern).
- Does not emit the full PDB path — only `<guid>:<age>`.
- Does not perform symbol-server lookup or any network I/O.
