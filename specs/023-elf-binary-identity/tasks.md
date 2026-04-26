---
description: "Task list — milestone 023 ELF binary identity"
---

# Tasks: ELF binary identity — Tighter Spec

**Input**: Design documents from `/specs/023-elf-binary-identity/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: 3 new fixtures + 3 new assertions in `tests/scan_binary.rs` + the 27-golden regression surface + holistic_parity continuing to pass.

**Organization**: Single user story (US1, P1). Three atomic commits.

## Path Conventions

- Touches `mikebom-cli/src/scan_fs/binary/{elf,entry,scan,mod}.rs`.
- Touches `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3,mod}.rs` (additive only).
- Adds `mikebom-cli/tests/fixtures/binaries/elf/{with-all,with-build-id-only,no-build-id}/`.
- Adds 3 rows to `docs/reference/sbom-format-mapping.md`.
- Does NOT touch macho.rs, pe.rs, scan_fs/mod.rs above the binary scope, parity_cmd.rs, holistic_parity.rs, generate/, resolve/, attestation/, cli/.

---

## Phase 1: Setup + baseline

- [X] T001 Recon done in plan-mode investigation (2026-04-26). Findings logged in spec.md Background. macho.rs / pe.rs verified as 7-line stubs; ELF lacks any build-id / RPATH / debuglink reading.
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-023.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-023-tests.txt`. Confirm post-023 list shows additions only, no removed tests.

---

## Phase 2: Commit 1 — `023/extractors`

**Goal**: Three new extractor functions in `elf.rs` with inline tests, no call sites yet.

- [ ] T003 [US1] Add `pub(super) struct DebuglinkEntry { pub file: String, pub crc32: u32 }` to `elf.rs`.
- [ ] T004 [US1] Add `pub(super) fn extract_gnu_build_id<'a, Elf: object::read::elf::FileHeader>(file: &object::read::elf::ElfFile<'a, Elf>) -> Option<String>`. Walk `.note.gnu.build-id` section (NT type 3, name "GNU"). Hex-encode the desc bytes (lowercase). Mirror the parse-failure-returns-None posture of `extract_note_package`.
- [ ] T005 [US1] Add `pub(super) fn extract_runpath_entries<'a, Elf>(file: &ElfFile<'a, Elf>) -> Vec<String>`. Walk dynamic section; for each Dyn entry with d_tag = DT_RPATH (0x0F) or DT_RUNPATH (0x1D), resolve d_val as a string-table offset into `.dynstr`. Split on `:` to produce per-entry vector. Dedup. Don't expand `$ORIGIN`.
- [ ] T006 [US1] Add `pub(super) fn extract_debuglink<'a, Elf>(file: &ElfFile<'a, Elf>) -> Option<DebuglinkEntry>`. Read `.gnu_debuglink` section: NUL-terminated filename + 4-byte alignment padding + 4-byte LE CRC32. Return None on absent section or short data.
- [ ] T007 [US1] Add inline `#[cfg(test)] mod tests` to `elf.rs` exercising each of the three extractors against small hand-constructed byte buffers. Reuse the `cfg_attr(test, allow(clippy::unwrap_used))` pattern from existing tests in this file.
- [ ] T008 [US1] Add `#[allow(dead_code)]` to the three new fns + struct since this commit doesn't wire them up yet. (Removed in commit 2.)
- [ ] T009 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T010 [US1] Commit: `feat(023/extractors): add ELF NT_GNU_BUILD_ID, RPATH/RUNPATH, .gnu_debuglink readers`.

---

## Phase 3: Commit 2 — `023/wire-up-scan`

**Goal**: New extractors are called by scan_binary; new fields populate on BinaryScan; three new annotations emit; fixtures + tests exist.

- [ ] T011 [US1] Edit `mikebom-cli/src/scan_fs/binary/entry.rs::BinaryScan`: add `pub build_id: Option<String>`, `pub runpath: Vec<String>`, `pub debuglink: Option<DebuglinkEntry>`. Update Default impl + any test fixture builders.
- [ ] T012 [US1] Edit `mikebom-cli/src/scan_fs/binary/scan.rs::scan_binary`: in the ELF arm (after the existing `object::read::File::parse` call), call the three FR-001 extractors and populate the BinaryScan fields. Non-ELF arms (Mach-O, PE) leave fields at default. Remove the `#[allow(dead_code)]` from elf.rs added in commit 1.
- [ ] T013 [US1] Edit `mikebom-cli/src/scan_fs/binary/mod.rs::read` (or the per-binary entry-conversion site): emit three new annotations on the binary's `PackageDbEntry` when each field is populated:
  - `mikebom:elf-build-id` = `String::from(build_id_hex)` (if Some).
  - `mikebom:elf-runpath` = `serde_json::to_string(&runpath_vec)` if non-empty.
  - `mikebom:elf-debuglink` = `serde_json::to_string(&{file, crc32_hex})` if Some.
  Empty/None fields skip emission per Scenario 4.
- [ ] T014 [US1] Construct fixtures under `mikebom-cli/tests/fixtures/binaries/elf/`:
  - `with-all/binary` — has build-id + RPATH ($ORIGIN/../lib:/opt/vendor/lib) + debuglink (.debug + CRC32).
  - `with-build-id-only/binary` — has build-id, no RPATH, no debuglink.
  - `no-build-id/binary` — built with `-Wl,--build-id=none` + no RPATH + no debuglink.
  Use `objcopy --add-section` / `--set-section-flags` against a known-good tiny binary, OR programmatic `object::write::elf::Writer` in a `build.rs` for the test crate. Whichever produces deterministic byte output.
- [ ] T015 [US1] Add three fixture-driven assertions to `mikebom-cli/tests/scan_binary.rs`:
  ```rust
  #[test] fn elf_with_all_fields_populates_them() { ... }
  #[test] fn elf_with_build_id_only_leaves_others_empty() { ... }
  #[test] fn elf_without_build_id_emits_no_build_id_annotation() { ... }
  ```
  Each spawns the binary against the corresponding fixture and asserts the output JSON.
- [ ] T016 [US1] Verify: `cargo +stable test -p mikebom --test scan_binary` includes the 3 new tests and they pass.
- [ ] T017 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T018 [US1] Commit: `feat(023/wire-up-scan): populate build-id/runpath/debuglink on BinaryScan and emit annotations`.

---

## Phase 4: Commit 3 — `023/parity-rows`

**Goal**: Three new C-section catalog rows; three new annotation extractors per format; EXTRACTORS table extended; holistic_parity still green.

- [ ] T019 [US1] Edit `docs/reference/sbom-format-mapping.md`: add three C-section rows (next available IDs after C23) for `mikebom:elf-build-id`, `mikebom:elf-runpath`, `mikebom:elf-debuglink`. Each classified `Present` × 3 formats × `SymmetricEqual`.
- [ ] T020 [US1] Edit `mikebom-cli/src/parity/extractors/cdx.rs`: add 3 `cdx_anno!` invocations:
  ```rust
  cdx_anno!(c24_cdx, "mikebom:elf-build-id", component);
  cdx_anno!(c25_cdx, "mikebom:elf-runpath", component);
  cdx_anno!(c26_cdx, "mikebom:elf-debuglink", component);
  ```
  (Adjust IDs to match catalog assignments from T019.)
- [ ] T021 [US1] Edit `mikebom-cli/src/parity/extractors/spdx2.rs`: add 3 mirror `spdx23_anno!` invocations.
- [ ] T022 [US1] Edit `mikebom-cli/src/parity/extractors/spdx3.rs`: add 3 mirror `spdx3_anno!` invocations.
- [ ] T023 [US1] Edit `mikebom-cli/src/parity/extractors/mod.rs::EXTRACTORS`: add 3 new `ParityExtractor` rows and add the 9 new fn imports across the existing `use cdx::{...}`, `use spdx2::{...}`, `use spdx3::{...}` blocks.
- [ ] T024 [US1] Verify: `cargo +stable test -p mikebom --test holistic_parity` green. Verify: `cargo +stable test -p mikebom --test sbom_format_mapping_coverage` (or equivalent) green — every catalog row has an extractor.
- [ ] T025 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T026 [US1] Commit: `feat(023/parity-rows): wire build-id/runpath/debuglink into the holistic-parity matrix`.

---

## Phase 5: Verification

- [ ] T027 SC-001 verification: 3 standard gates green per spec.
- [ ] T028 SC-002 verification: scan `/bin/ls` (or equivalent host binary) → confirm `build_id.is_some()`.
- [ ] T029 SC-003 verification: `git diff main..HEAD -- mikebom-cli/src/scan_fs/binary/macho.rs mikebom-cli/src/scan_fs/binary/pe.rs` is empty.
- [ ] T030 SC-004 verification: `wc -l mikebom-cli/src/scan_fs/binary/elf.rs` ≤ 420.
- [ ] T031 SC-005 verification: `git diff main..HEAD -- mikebom-cli/src/cli/ mikebom-cli/src/generate/ mikebom-cli/src/resolve/` is empty.
- [ ] T032 27-golden regen: `MIKEBOM_UPDATE_*_GOLDENS=1`. Expected: deltas only on binary-fixture goldens (where the new annotations now appear); zero diff on non-binary goldens.
- [ ] T033 Push branch; observe all 3 CI lanes green (SC-006).
- [ ] T034 Author the PR description: 3-commit summary, recon-context pointer to spec.md, fixture inventory, byte-identity attestation.

---

## Dependency graph

```text
T001 (recon, done) → T002 (baseline)
                       │
                       ↓
              T003-T010 [Commit 1: extractors + inline tests, dead-code allowed]
                       │
                       ↓
              T011-T018 [Commit 2: wire-up + fixtures + tests]
                       │
                       ↓
              T019-T026 [Commit 3: parity rows]
                       │
                       ↓
              T027-T034 (verify + PR)
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 done; just snapshot |
| Phase 2 (extractors) | 4 hr | object-crate API spelunking is the careful step |
| Phase 3 (wire-up) | 3 hr | Deterministic-fixture construction is the new wrinkle |
| Phase 4 (parity rows) | 1 hr | Mechanical |
| Phase 5 (verify + PR) | 1 hr | Goldens regen + CI watch |
| **Total** | **~9 hr** | One focused day. |
