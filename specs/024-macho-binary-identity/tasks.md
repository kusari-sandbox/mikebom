---
description: "Task list — milestone 024 Mach-O binary identity"
---

# Tasks: Mach-O Binary Identity — Tighter Spec

**Input**: Design documents from `/specs/024-macho-binary-identity/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: 5+ new inline parser tests in `macho.rs::tests` + 1-2
assertions in `scan_binary.rs` (gated on `class == "macho"` for macOS
CI lane) + 27-golden + holistic_parity continuing to pass.

**Organization**: Single user story (US1, P1). Three atomic commits.

## Path Conventions

- Touches `mikebom-cli/src/scan_fs/binary/{macho,entry,scan}.rs`,
  `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3,mod}.rs`
  (additive), `docs/reference/sbom-format-mapping.md` (additive),
  `mikebom-cli/tests/scan_binary.rs` (additive).
- Does NOT touch `mikebom-common/`, `mikebom-cli/src/cli/`,
  `mikebom-cli/src/resolve/`, `mikebom-cli/src/generate/`,
  `mikebom-cli/src/scan_fs/binary/elf.rs`, `mikebom-cli/src/scan_fs/binary/pe.rs`,
  or any `package_db/*.rs`.

---

## Phase 1: Setup + baseline

- [X] T001 Recon done. Confirmed macho.rs is a 7-line stub. Confirmed
      scan_fat_macho already does fat slice iteration + linkage.
      Confirmed object 0.36 LoadCommandIterator API is available.
      Confirmed `/bin/ls` on macOS is fat Mach-O with LC_UUID +
      LC_BUILD_VERSION (verifiable via `otool -l`).
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-024.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-024-tests.txt`.

---

## Phase 2: Commit 1 — `024/parsers`

**Goal**: macho.rs becomes a real module with 3 parsers + inline
tests; dead-code allowed for this commit only.

- [ ] T003 [US1] Replace macho.rs's stub doc comment with a real module
      header. Add imports: `object::read::macho`, std::collections.
- [ ] T004 [US1] Add `pub fn parse_lc_uuid(load_cmds: &mut LoadCommandIterator)
      -> Option<String>`. Walks load commands; matches `LC_UUID` (cmd
      value 0x1B); decodes the `UuidCommand` struct; hex-encodes the
      16-byte uuid lowercase. Returns None on absent or malformed.
- [ ] T005 [US1] Add `pub fn parse_lc_rpath(load_cmds: &mut LoadCommandIterator)
      -> Vec<String>`. Walks load commands; matches `LC_RPATH` (0x1C);
      decodes the `RpathCommand`; reads the path string from the load
      command's data. Dedups in declaration order.
- [ ] T006 [US1] Add `pub fn parse_min_os_version(load_cmds: &mut LoadCommandIterator)
      -> Option<String>`. Two-pass: first walks looking for
      `LC_BUILD_VERSION` (0x32) — extracts platform enum + version,
      formats as `<platform>:<version>`; if absent, fall back to
      `LC_VERSION_MIN_MACOSX` (0x24) / `LC_VERSION_MIN_IPHONEOS` (0x25)
      / `LC_VERSION_MIN_TVOS` (0x2F) / `LC_VERSION_MIN_WATCHOS` (0x30)
      and synthesize a default platform name (`macos` / `ios` /
      `tvos` / `watchos`). Returns lowercase `<platform>:<version>`.
- [ ] T007 [US1] Add inline tests in `#[cfg(test)] mod tests`:
  - `parse_lc_uuid_from_synthetic_mach_o` — hand-built header + LC_UUID
    command bytes.
  - `parse_lc_rpath_dedupes_repeated_paths` — multiple LC_RPATH commands.
  - `parse_min_os_version_prefers_lc_build_version` — both LC_BUILD_VERSION
    and LC_VERSION_MIN_MACOSX present; assert LC_BUILD_VERSION wins.
  - `parse_min_os_version_falls_back_to_lc_version_min` — only
    LC_VERSION_MIN_MACOSX present.
  - `parse_lc_uuid_returns_none_for_no_uuid_binary` — Mach-O with no
    LC_UUID command (e.g., built with `-no_uuid`).
- [ ] T008 [US1] Add `#[allow(dead_code)]` on the three parsers. Removed
      in commit 2.
- [ ] T009 [US1] Verify: `cargo +stable test -p mikebom --bin mikebom scan_fs::binary::macho`
      includes the new tests + they pass. `./scripts/pre-pr.sh` clean.
- [ ] T010 [US1] Commit: `feat(024/parsers): add Mach-O LC_UUID, LC_RPATH, min-OS version readers`.

---

## Phase 3: Commit 2 — `024/wire-up-bag`

**Goal**: BinaryScan gains 3 fields; scan.rs populates them on Mach-O
paths; entry.rs translates to bag entries; SC-002 assertion added.

- [ ] T011 [US1] Edit `binary/entry.rs::BinaryScan`: add
      `pub macho_uuid: Option<String>`, `pub macho_rpath: Vec<String>`,
      `pub macho_min_os: Option<String>`.
- [ ] T012 [US1] Update the 3 BinaryScan struct-literal sites
      (scan.rs ELF arm, scan.rs Mach-O fat arm, entry.rs fake_binary_scan)
      with the 3 new fields. ELF arm + test helper use defaults (None /
      empty Vec / None). Mach-O fat arm populates from FR-001 parsers
      called against the FIRST slice's `LoadCommandIterator`.
- [ ] T013 [US1] Update scan.rs's NON-fat path (line ~138, the generic
      `scan_binary` after `object::read::File::parse`): when
      `class == "macho"`, call the 3 parsers against the file's
      `load_commands()` iterator and populate the BinaryScan fields.
- [ ] T014 [US1] Edit `entry.rs::make_file_level_component`:
      - Either extend `build_elf_identity_annotations` into a unified
        `build_binary_identity_annotations` that handles both ELF and
        Mach-O, OR add a parallel `build_macho_identity_annotations`
        helper. Either is fine; the choice depends on whether the
        emission shapes diverge enough to warrant separate fns.
        (Recommendation: parallel helper — keeps each format's bag
        contract co-located with its source struct field.)
      - Insert into the bag:
        - `mikebom:macho-uuid` ← Value::String(uuid_hex) if Some
        - `mikebom:macho-rpath` ← serde_json::to_value(&runpath_vec) if non-empty
        - `mikebom:macho-min-os` ← Value::String(platform_version) if Some
- [ ] T015 [US1] Remove `#[allow(dead_code)]` from the 3 parsers in macho.rs.
- [ ] T016 [US1] Edit `mikebom-cli/tests/scan_binary.rs::scan_system_binary_emits_file_level_and_linkage`:
      under the existing `class == "macho"` branch (currently empty
      since milestone 023 only added to the ELF branch), assert:
      - `mikebom:macho-uuid` is Some + 32 hex chars
      - `mikebom:macho-min-os` is Some
      - `mikebom:macho-rpath` is Some (every macOS shell binary has
        at least one LC_RPATH for system frameworks)
- [ ] T017 [US1] Verify: `cargo +stable test -p mikebom --test scan_binary` green.
      `./scripts/pre-pr.sh` clean.
- [ ] T018 [US1] Commit: `feat(024/wire-up-bag): populate Mach-O identity into the extra_annotations bag`.

---

## Phase 4: Commit 3 — `024/parity-rows`

**Goal**: 3 new catalog rows + per-format extractors + EXTRACTORS rows.

- [ ] T019 [US1] Edit `docs/reference/sbom-format-mapping.md`: add 3
      C-section rows (C30/C31/C32 — next available after milestone 025's
      C29). Each Present × 3 formats × SymmetricEqual. Justification
      lines name the LC_* source command and link to milestone 024.
- [ ] T020 [US1] Edit `mikebom-cli/src/parity/extractors/cdx.rs`: add 3
      `cdx_anno!` invocations.
- [ ] T021 [US1] Edit `mikebom-cli/src/parity/extractors/spdx2.rs`: add 3
      mirror `spdx23_anno!` invocations.
- [ ] T022 [US1] Edit `mikebom-cli/src/parity/extractors/spdx3.rs`: add 3
      mirror `spdx3_anno!` invocations.
- [ ] T023 [US1] Edit `mikebom-cli/src/parity/extractors/mod.rs::EXTRACTORS`:
      add 3 new `ParityExtractor` rows + 9 fn imports.
- [ ] T024 [US1] Verify: `cargo +stable test -p mikebom --test holistic_parity`
      green. `cargo +stable test -p mikebom --test sbom_format_mapping_coverage` green.
- [ ] T025 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T026 [US1] Commit: `feat(024/parity-rows): wire Mach-O identity annotations into the holistic-parity matrix`.

---

## Phase 5: Verification

- [ ] T027 SC-001 verification: 4 standard gates green.
- [ ] T028 SC-002 verification (macOS CI lane): `/bin/ls` scan emits
      non-empty `mikebom:macho-uuid` (32 hex chars) AND non-empty
      `mikebom:macho-min-os`.
- [ ] T029 SC-003 verification:
      `git diff main..HEAD -- mikebom-cli/src/scan_fs/binary/elf.rs mikebom-cli/src/scan_fs/binary/pe.rs`
      empty.
- [ ] T030 SC-004 verification: `wc -l mikebom-cli/src/scan_fs/binary/macho.rs` ≤ 350.
- [ ] T031 SC-005 verification:
      `git diff main..HEAD -- mikebom-common/ mikebom-cli/src/cli/ mikebom-cli/src/resolve/ mikebom-cli/src/generate/`
      empty.
- [ ] T032 SC-007 verification (bag amortization):
      `git diff main..HEAD -- mikebom-cli/src/scan_fs/package_db/`
      empty.
- [ ] T033 27-golden regen: zero diff (existing fixtures don't include
      Mach-O binaries).
- [ ] T034 Push branch; observe all 3 CI lanes green (SC-006). The
      macOS lane is the SC-002 verification.
- [ ] T035 Author the PR description: 3-commit summary, bag amortization
      attestation, SC-002 macOS-lane payoff, byte-identity attestation.

---

## Dependency graph

```text
T001-T002 (recon + baseline, recon done)
   │
   ↓
T003-T010 [Commit 1: parsers + dead_code]
   │
   ↓
T011-T018 [Commit 2: wire-up-bag + scan_binary assertion]
   │
   ↓
T019-T026 [Commit 3: parity-rows]
   │
   ↓
T027-T035 (verification + PR)
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 done; just snapshot |
| Phase 2 (parsers) | 4-5 hr | Synthetic Mach-O fixtures more involved than ELF — load-command alignment + 64-bit pointers |
| Phase 3 (wire-up + tests) | 2 hr | Mostly mechanical; 3 BinaryScan literal sites |
| Phase 4 (parity rows) | 30 min | Same shape as 023's + 025's |
| Phase 5 (verify + PR) | 1 hr | Goldens regen + macOS CI watch (SC-002) |
| **Total** | **~8 hr** | One focused day. |
