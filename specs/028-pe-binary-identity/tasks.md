---
description: "Task list — milestone 028 PE binary identity"
---

# Tasks: PE binary identity — Tighter Spec

**Input**: Design documents from `/specs/028-pe-binary-identity/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: 6+ new inline parser/decoder tests in `pe.rs::tests` + 2 new
bag-emission tests in `entry.rs::tests` + holistic_parity continuing to
pass + sbom_format_mapping_coverage continuing to pass.

**Organization**: Single user story (US1, P1). Three atomic commits.

## Path Conventions

- Touches `mikebom-cli/src/scan_fs/binary/{pe,entry,scan}.rs`,
  `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3,mod}.rs`
  (additive), `docs/reference/sbom-format-mapping.md` (additive).
- Does NOT touch `mikebom-common/`, `mikebom-cli/src/cli/`,
  `mikebom-cli/src/resolve/`, `mikebom-cli/src/generate/`,
  `mikebom-cli/src/scan_fs/binary/elf.rs`,
  `mikebom-cli/src/scan_fs/binary/macho.rs`,
  or any `mikebom-cli/src/scan_fs/package_db/` file.

---

## Phase 1: Setup + baseline

- [X] T001 Recon done. Confirmed pe.rs is a 6-line stub. Confirmed
      `object::read::pe::PeFile::pdb_info()` (file.rs:348) returns
      `Result<Option<CodeView<'_>>>` directly. Confirmed `CodeView`
      exposes `path()` accessor (mod.rs:670); guid/age accessors need
      runtime verification (R1 mitigation: byte-level fallback if
      missing). Confirmed `IMAGE_FILE_MACHINE_*` and
      `IMAGE_SUBSYSTEM_*` const lists in `object::pe`.
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-028.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-028-tests.txt`.

---

## Phase 2: Commit 1 — `028/parsers`

**Goal**: pe.rs becomes a real module with 3 parsers + machine/subsystem
decoders + inline tests; dead-code allowed for this commit only.

- [ ] T003 [US1] Replace pe.rs's stub doc comment with a real module
      header. Add imports: `object::read::pe::{PeFile32, PeFile64,
      ImageNtHeaders}`, `object::pe`.
- [ ] T004 [US1] Add `pub fn parse_pdb_id<Pe: ImageNtHeaders>(file:
      &PeFile<'_, Pe, &[u8]>) -> Option<String>`. Calls
      `file.pdb_info()`. On `Ok(Some(cv))`, hex-encode the GUID
      (16 bytes → 32 lowercase hex chars) + append `:<age>` where age
      is the u32 from CodeView. On `Ok(None)` or `Err(_)` return None.
      If `CodeView::guid()` / `age()` accessors are not public per R1,
      drop into byte-level fallback: locate the IMAGE_DEBUG_DIRECTORY
      entry via `data_directories()`, verify the type field is
      IMAGE_DEBUG_TYPE_CODEVIEW (2), read the entry data, verify the
      `RSDS` signature (`b"RSDS"`), then read `[u8; 16]` guid +
      `u32_le` age + ignore the trailing path.
- [ ] T005 [US1] Add `pub fn parse_machine_type<Pe: ImageNtHeaders>(
      file: &PeFile<'_, Pe, &[u8]>) -> Option<String>`. Reads
      `nt_headers().file_header().machine.get(LE)` → u16, runs through
      `machine_to_str`. Returns Some("amd64") / Some("i386") /
      Some("unknown") / etc.
- [ ] T006 [US1] Add `pub fn parse_subsystem<Pe: ImageNtHeaders>(
      file: &PeFile<'_, Pe, &[u8]>) -> Option<String>`. Reads
      `nt_headers().optional_header().subsystem()` → u16, runs through
      `subsystem_to_str`. Returns Some("console") / Some("windows-gui")
      / Some("efi-application") / Some("unknown") / etc.
- [ ] T007 [US1] Add private decoder helpers:
      - `fn machine_to_str(value: u16) -> &'static str` — maps
        IMAGE_FILE_MACHINE_I386 → "i386", AMD64 → "amd64", ARM → "arm",
        ARMNT → "armnt", ARM64 → "arm64", IA64 → "ia64",
        RISCV32 → "riscv32", RISCV64 → "riscv64", UNKNOWN → "unknown",
        anything else → "unknown".
      - `fn subsystem_to_str(value: u16) -> &'static str` — maps
        IMAGE_SUBSYSTEM_NATIVE → "native",
        IMAGE_SUBSYSTEM_WINDOWS_GUI → "windows-gui",
        IMAGE_SUBSYSTEM_WINDOWS_CUI → "console" (Microsoft toolchain
        idiom — "console" is the human-friendly term for CUI),
        IMAGE_SUBSYSTEM_OS2_CUI → "os2-cui",
        IMAGE_SUBSYSTEM_POSIX_CUI → "posix-cui",
        IMAGE_SUBSYSTEM_NATIVE_WINDOWS → "native-windows",
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI → "windows-ce-gui",
        IMAGE_SUBSYSTEM_EFI_APPLICATION → "efi-application",
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER → "efi-boot-service",
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER → "efi-runtime-driver",
        IMAGE_SUBSYSTEM_EFI_ROM → "efi-rom",
        IMAGE_SUBSYSTEM_XBOX → "xbox",
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION → "windows-boot-application",
        UNKNOWN (0) and anything else → "unknown".
- [ ] T008 [US1] Add inline tests in `#[cfg(test)] mod tests`:
      - `machine_to_str_known_values` — table-test covering ≥4 known
        machines.
      - `machine_to_str_unknown_returns_unknown` — `0xDEAD` → "unknown".
      - `subsystem_to_str_known_values` — covers console / windows-gui
        / efi-application.
      - `subsystem_to_str_unknown_returns_unknown` — `0xDEAD` → "unknown".
      - `parse_pdb_id_synthetic_pe_returns_guid_age` — small synthetic
        PE buffer with valid CodeView record. Hand-built or embedded.
      - `parse_pdb_id_synthetic_pe_no_codeview_returns_none` — same
        synthetic PE without IMAGE_DEBUG_DIRECTORY entries.
      - `parse_machine_type_synthetic_pe` — verify "amd64" emission.
      - `parse_subsystem_synthetic_pe` — verify "console" emission.
- [ ] T009 [US1] Add `#[allow(dead_code)]` on the three parsers
      + decoder helpers. Removed in commit 2.
- [ ] T010 [US1] Verify: `cargo +stable test -p mikebom --bin mikebom
      scan_fs::binary::pe` includes the new tests + they pass.
      `./scripts/pre-pr.sh` clean.
- [ ] T011 [US1] Commit: `feat(028/parsers): add PE CodeView pdb-id, machine type, subsystem readers`.

---

## Phase 3: Commit 2 — `028/wire-up-bag`

**Goal**: BinaryScan gains 3 PE fields; scan.rs populates them on PE
paths; entry.rs translates to bag entries via a parallel
`build_pe_identity_annotations` helper.

- [ ] T012 [US1] Edit `binary/entry.rs::BinaryScan`: add
      `pub pe_pdb_id: Option<String>`, `pub pe_machine: Option<String>`,
      `pub pe_subsystem: Option<String>` after the macho_* fields. Add
      doc comments naming the IMAGE_* sources.
- [ ] T013 [US1] Update the 3 BinaryScan struct-literal sites:
      - `scan.rs` non-fat path (`Some(BinaryScan { ... })` around
        line 187).
      - `scan.rs` fat-Mach-O path (`Some(BinaryScan { ... })` around
        line 309 — defaults: None × 3).
      - `entry.rs::tests::fake_binary_scan` helper.
      The non-fat path: when `class == "pe"`, read the
      `IMAGE_OPTIONAL_HEADER.Magic` byte at the optional-header offset
      (locatable via the existing `e_lfanew` + COFF-header layout, or
      via `object::pe::ImageDosHeader::parse` + `nt_headers_offset()`
      + 24-byte COFF header skip). Magic value `0x10B` → dispatch to
      `PeFile32::parse(bytes)`; `0x20B` → `PeFile64::parse(bytes)`.
      Then call the three FR-001 parsers (which are generic over
      `ImageNtHeaders`). Populate the three new BinaryScan fields.
      ELF / Mach-O paths leave the fields at None.
- [ ] T014 [US1] Edit `entry.rs`: add a parallel
      `build_pe_identity_annotations` helper next to
      `build_macho_identity_annotations`. Same skip-on-empty contract.
      Bag keys:
      - `mikebom:pe-pdb-id` ← Value::String(pdb_id) if Some
      - `mikebom:pe-machine` ← Value::String(machine_name) if Some
      - `mikebom:pe-subsystem` ← Value::String(subsystem_name) if Some
- [ ] T015 [US1] Edit `entry.rs::build_binary_identity_annotations`:
      extend to call `build_pe_identity_annotations(scan)` and merge
      via `bag.extend(...)`. Three identity helpers (ELF + Mach-O + PE)
      now contribute to the unified bag.
- [ ] T016 [US1] Remove `#[allow(dead_code)]` from the 3 parsers +
      decoder helpers in pe.rs.
- [ ] T017 [US1] Add 2 new inline tests in `entry.rs::tests`:
      - `make_file_level_component_populates_bag_with_all_three_pe_signals` —
        `BinaryScan` populated with pe_* fields → bag has 3 PE keys
        with correct values.
      - `make_file_level_component_pe_bag_skips_unpopulated_entries` —
        `BinaryScan` with only `pe_pdb_id` populated → bag has only
        the pdb-id key.
- [ ] T018 [US1] Verify: `cargo +stable test -p mikebom --bin mikebom
      scan_fs::binary::entry::tests` green. `./scripts/pre-pr.sh` clean.
- [ ] T019 [US1] Commit: `feat(028/wire-up-bag): populate PE identity into the extra_annotations bag`.

---

## Phase 4: Commit 3 — `028/parity-rows`

**Goal**: 3 new catalog rows + per-format extractors + EXTRACTORS rows.

- [ ] T020 [US1] Edit `docs/reference/sbom-format-mapping.md`: add 3
      C-section rows (C33/C34/C35 — next available after milestone 024's
      C32). Each `Present` × 3 formats × `SymmetricEqual`. Justification
      lines name the IMAGE_* source field and link to milestone 028.
- [ ] T021 [US1] Edit `mikebom-cli/src/parity/extractors/cdx.rs`: add 3
      `cdx_anno!` invocations:
      ```rust
      cdx_anno!(c33_cdx, "mikebom:pe-pdb-id", component);
      cdx_anno!(c34_cdx, "mikebom:pe-machine", component);
      cdx_anno!(c35_cdx, "mikebom:pe-subsystem", component);
      ```
- [ ] T022 [US1] Edit `mikebom-cli/src/parity/extractors/spdx2.rs`: add
      3 mirror `spdx23_anno!` invocations.
- [ ] T023 [US1] Edit `mikebom-cli/src/parity/extractors/spdx3.rs`: add
      3 mirror `spdx3_anno!` invocations.
- [ ] T024 [US1] Edit `mikebom-cli/src/parity/extractors/mod.rs::EXTRACTORS`:
      add 3 new `ParityExtractor` rows + 9 fn imports across the
      `use cdx::{...}`, `use spdx2::{...}`, `use spdx3::{...}` blocks.
- [ ] T025 [US1] Verify: `cargo +stable test -p mikebom --test holistic_parity`
      green. `cargo +stable test -p mikebom --test sbom_format_mapping_coverage` green.
- [ ] T026 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T027 [US1] Commit: `feat(028/parity-rows): wire PE identity annotations into the holistic-parity matrix`.

---

## Phase 5: Verification

- [ ] T028 SC-001 verification: 3 standard gates green.
- [ ] T029 SC-002 verification: `pe.rs::tests` covers all 3 parsers +
      ≥1 negative case per parser.
- [ ] T030 SC-003 verification: `git diff main..HEAD --
      mikebom-cli/src/scan_fs/binary/elf.rs
      mikebom-cli/src/scan_fs/binary/macho.rs` empty.
- [ ] T031 SC-004 verification: `wc -l mikebom-cli/src/scan_fs/binary/pe.rs` ≤ 250.
- [ ] T032 SC-005 verification: `git diff main..HEAD --
      mikebom-common/ mikebom-cli/src/cli/ mikebom-cli/src/resolve/
      mikebom-cli/src/generate/ mikebom-cli/src/scan_fs/package_db/`
      empty.
- [ ] T033 SC-007 verification (bag amortization): 27-golden regen
      produces zero diff.
- [ ] T034 Push branch; observe all 3 CI lanes green (SC-006).
- [ ] T035 Author the PR description: 3-commit summary, 4th-consumer
      bag-amortization attestation, byte-identity attestation.

---

## Dependency graph

```text
T001-T002 (recon + baseline, recon done)
   │
   ↓
T003-T011 [Commit 1: parsers + decoders + dead_code]
   │
   ↓
T012-T019 [Commit 2: wire-up-bag + tests]
   │
   ↓
T020-T027 [Commit 3: parity-rows]
   │
   ↓
T028-T035 (verification + PR)
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 done; just snapshot |
| Phase 2 (parsers) | 2 hr | `object`'s typed PE API is well-fitted; main risk is CodeView guid/age accessor visibility (R1) |
| Phase 3 (wire-up + tests) | 2 hr | Mostly mechanical; PeFile32 vs PeFile64 dispatch is the new wrinkle |
| Phase 4 (parity rows) | 30 min | Same shape as 023's + 024's + 025's |
| Phase 5 (verify + PR) | 1 hr | Goldens regen + CI watch |
| **Total** | **~6 hr** | Less than 024's 8 hr; `object` does the heavy lifting. |
