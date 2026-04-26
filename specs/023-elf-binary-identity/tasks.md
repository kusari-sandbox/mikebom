---
description: "Task list — milestone 023 ELF binary identity (revised, bag-first)"
---

# Tasks: ELF binary identity — Revised (bag-first)

**Input**: Design documents from `/specs/023-elf-binary-identity/`
**Prerequisites**: spec.md (✅ amended), plan.md (✅ amended), checklists/requirements.md (✅)

**Tests**: 13 inline elf.rs tests (already landed in commit `e0d658e`) + 3 new fixtures + 3 new scan_binary.rs assertions + 27-golden regression surface + holistic_parity continuing to pass.

**Organization**: Single user story (US1, P1). Four atomic commits (1 already landed).

## Path Conventions

- Mikebom-cli: `scan_fs/binary/{elf,entry,scan,mod}.rs`, `scan_fs/mod.rs`,
  `scan_fs/package_db/mod.rs` + 35 sibling files (the package_db ecosystem
  readers), `generate/{cyclonedx/builder.rs, spdx/annotations.rs,
  spdx/v3_annotations.rs}`, `parity/extractors/{cdx,spdx2,spdx3,mod}.rs`,
  `tests/{fixtures/binaries/elf/, scan_binary.rs}`.
- mikebom-common: `src/resolution.rs`.
- Docs: `docs/reference/sbom-format-mapping.md`.
- Does NOT touch `cli/`, `resolve/`, `attestation/`, `macho.rs`, `pe.rs`.

---

## Phase 1: Setup + baseline (DONE)

- [X] T001 Recon done in plan-mode investigation (2026-04-26). Findings logged
      in spec.md (revised) Background. Bag-first design adopted after
      mid-implementation discovery that PackageDbEntry has 35 init sites.
- [X] T002 Baseline snapshot captured. Pre-implementation tests = 1217.

---

## Phase 2: Commit 1 — `023/extractors` (DONE — `e0d658e`)

- [X] T003-T010 ELF extractors (parse_gnu_build_id, parse_debuglink,
      extract_runpath_entries) + DebuglinkEntry + 13 inline tests landed
      with `#[allow(dead_code)]`. See commit `e0d658e`.

---

## Phase 3: Commit 2 — `023/extra-annotations-bag`

**Goal**: Add the generic `extra_annotations` bag to PackageDbEntry +
ResolvedComponent end-to-end. After this commit, the bag works but has no
consumers.

- [ ] T011 Edit `mikebom-cli/src/scan_fs/package_db/mod.rs::PackageDbEntry`:
      add `pub extra_annotations: std::collections::BTreeMap<String, serde_json::Value>`
      with brief docstring explaining purpose.
- [ ] T012 Add `extra_annotations: Default::default(),` to all 35
      PackageDbEntry struct-literal sites. Use `grep -rn 'PackageDbEntry {'`
      to find them; the compiler error E0063 lists each missing site.
- [ ] T013 Edit `mikebom-common/src/resolution.rs::ResolvedComponent`:
      add the same field with serde `#[serde(default, skip_serializing_if =
      "BTreeMap::is_empty")]`.
- [ ] T014 Add `extra_annotations: Default::default(),` to all
      ResolvedComponent struct-literal sites (count via
      `grep -rn 'ResolvedComponent {'`).
- [ ] T015 Edit `mikebom-cli/src/scan_fs/mod.rs` (the conversion site
      around line 445): add `extra_annotations: entry.extra_annotations.clone()`.
- [ ] T016 Edit `mikebom-cli/src/generate/cyclonedx/builder.rs`:
      after the existing per-component property emission, iterate
      `c.extra_annotations` and push one `properties[]` entry per key.
      Stringification: `Value::String(s) → s.clone()`, other Values →
      `serde_json::to_string(...)`. Skip emission when bag is empty.
- [ ] T017 Edit `mikebom-cli/src/generate/spdx/annotations.rs`: after the
      typed-field annotation emissions, iterate `c.extra_annotations` and
      push one `MikebomAnnotationCommentV1` envelope per entry via the
      existing `push(...)` helper.
- [ ] T018 Edit `mikebom-cli/src/generate/spdx/v3_annotations.rs`: same
      shape as T017 but for SPDX 3 graph-element annotations. Reuse the
      existing `push(out, field, value)` helper.
- [ ] T019 Verify: `cargo +stable check --workspace --tests` clean.
      `./scripts/pre-pr.sh` clean. 27-golden regen produces zero diff (no
      consumers yet, no new keys in bag, no output change).
- [ ] T020 Commit: `feat(023/extra-annotations-bag): add per-component generic annotation bag end-to-end`.

---

## Phase 4: Commit 3 — `023/wire-up-elf-identity`

**Goal**: ELF identity becomes the first bag consumer. After this commit:
binary scans emit the three new annotations; fixtures + tests exist.

- [ ] T021 Edit `mikebom-cli/src/scan_fs/binary/entry.rs::BinaryScan`: add
      `pub build_id: Option<String>`, `pub runpath: Vec<String>`,
      `pub debuglink: Option<elf::DebuglinkEntry>`.
- [ ] T022 Edit the 3 BinaryScan struct-literal sites
      (`scan_fs/binary/scan.rs:138`, `scan.rs:254`, `entry.rs:542`) to
      include the new fields. ELF site populates from extractors;
      Mach-O / test sites use defaults.
- [ ] T023 Edit `mikebom-cli/src/scan_fs/binary/scan.rs::scan_binary`:
      in the ELF arm, after the existing `note_package` extraction, add
      build_id / runpath / debuglink extraction using the FR-008 helpers.
      Use `bytes.get(4) == Some(&2)` for is_64bit and
      `bytes.get(5) != Some(&2)` for little_endian (e_ident bytes).
- [ ] T024 Edit `mikebom-cli/src/scan_fs/binary/entry.rs::make_file_level_component`:
      after the existing PackageDbEntry construction, populate
      `extra_annotations` from BinaryScan:
      - `mikebom:elf-build-id` ← `serde_json::Value::String(scan.build_id.clone()?)`
      - `mikebom:elf-runpath` ← `serde_json::to_value(&scan.runpath)?` if non-empty
      - `mikebom:elf-debuglink` ← serialize the DebuglinkEntry as JSON object
        `{"file": ..., "crc32": "0xdeadbeef"}` when populated.
      Empty/None values skip insertion.
- [ ] T025 Remove `#[allow(dead_code)]` from the three new fns + DebuglinkEntry
      in `binary/elf.rs` (they're now called).
- [ ] T026 Construct fixtures under `mikebom-cli/tests/fixtures/binaries/elf/`:
      - `with-all/binary` (build-id + RPATH + debuglink)
      - `with-build-id-only/binary` (build-id only)
      - `no-build-id/binary` (`-Wl,--build-id=none`)
      Use `objcopy --add-section` against a tiny base, or programmatic
      `object::write::elf::Writer`.
- [ ] T027 Add 3 fixture-driven tests to `mikebom-cli/tests/scan_binary.rs`:
      - `elf_with_all_fields_populates_them`
      - `elf_with_build_id_only_leaves_others_empty`
      - `elf_without_build_id_emits_no_build_id_annotation`
- [ ] T028 Verify: `cargo +stable test -p mikebom --test scan_binary` includes
      the 3 new tests + they pass. `./scripts/pre-pr.sh` clean.
- [ ] T029 Commit: `feat(023/wire-up-elf-identity): populate extra_annotations bag from BinaryScan + 3 fixtures`.

---

## Phase 5: Commit 4 — `023/parity-rows`

**Goal**: Three new C-section catalog rows; per-format anno extractors;
holistic_parity continues to pass.

- [ ] T030 Edit `docs/reference/sbom-format-mapping.md`: add 3 C-section rows
      (next available IDs after C23) for `mikebom:elf-build-id`,
      `mikebom:elf-runpath`, `mikebom:elf-debuglink`. Each Present × 3 ×
      SymmetricEqual.
- [ ] T031 Edit `mikebom-cli/src/parity/extractors/cdx.rs`: add 3
      `cdx_anno!` invocations.
- [ ] T032 Edit `mikebom-cli/src/parity/extractors/spdx2.rs`: add 3
      `spdx23_anno!` invocations.
- [ ] T033 Edit `mikebom-cli/src/parity/extractors/spdx3.rs`: add 3
      `spdx3_anno!` invocations.
- [ ] T034 Edit `mikebom-cli/src/parity/extractors/mod.rs::EXTRACTORS`: add 3
      new `ParityExtractor` rows + 9 fn imports.
- [ ] T035 Verify: `cargo +stable test -p mikebom --test holistic_parity`
      green. Verify: `cargo +stable test -p mikebom --test sbom_format_mapping_coverage`
      green.
- [ ] T036 `./scripts/pre-pr.sh` clean.
- [ ] T037 Commit: `feat(023/parity-rows): wire ELF identity annotations into the holistic-parity matrix`.

---

## Phase 6: Verification

- [ ] T038 SC-001 verification: 4 standard gates green.
- [ ] T039 SC-002 verification: scan `/bin/ls` → confirm
      `mikebom:elf-build-id` annotation populated.
- [ ] T040 SC-003 verification: macho.rs / pe.rs untouched.
- [ ] T041 SC-004 verification: `wc -l mikebom-cli/src/scan_fs/binary/elf.rs`
      ≤ 600.
- [ ] T042 SC-005 (revised) verification: cli/ + resolve/ untouched. (generate/
      and mikebom-common are now legitimately touched per FR-005-007 and
      FR-002.)
- [ ] T043 27-golden regen: deltas only on binary-fixture goldens.
- [ ] T044 SC-007 verification: `cargo +stable test --workspace` green
      across all 35 PackageDbEntry sites + ~5 ResolvedComponent sites.
- [ ] T045 Push branch; observe all 3 CI lanes green (SC-006).
- [ ] T046 Author the PR description: 4-commit summary, bag-first design
      rationale (with milestone-024+ amortization argument), fixture
      inventory, byte-identity attestation, recon-correction note.

---

## Dependency graph

```text
T001-T002 (recon + baseline, done)
   │
   ↓
T003-T010 [Commit 1: extractors] ✅ DONE (e0d658e)
   │
   ↓
T011-T020 [Commit 2: extra_annotations bag end-to-end]
   │
   ↓
T021-T029 [Commit 3: wire ELF identity through the bag + fixtures + tests]
   │
   ↓
T030-T037 [Commit 4: parity rows]
   │
   ↓
T038-T046 (verification + PR)
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (done) | — | — |
| Phase 2 (extractors, done) | — | commit `e0d658e` |
| Phase 3 (bag, T011-T020) | 4-5 hr | 35-site init churn + emission code |
| Phase 4 (ELF wire-up, T021-T029) | 3-4 hr | Fixtures + scan_binary tests |
| Phase 5 (parity rows, T030-T037) | 1 hr | Mechanical |
| Phase 6 (verify + PR) | 1 hr | Goldens regen + CI watch |
| **Total remaining** | **~10 hr** | One focused day. |
