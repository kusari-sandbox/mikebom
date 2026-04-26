---
description: "Task list — milestone 025 Go VCS metadata"
---

# Tasks: Go VCS metadata — Tighter Spec

**Input**: Design documents from `/specs/025-go-vcs-metadata/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: 3 new inline parser tests in `go_binary.rs::tests` + the
27-golden regression surface + holistic_parity continuing to pass.

**Organization**: Single user story (US1, P2). Three atomic commits.

## Path Conventions

- Touches `mikebom-cli/src/scan_fs/package_db/go_binary.rs`,
  `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3,mod}.rs` (additive),
  `docs/reference/sbom-format-mapping.md` (additive).
- Does NOT touch `mikebom-common/`, `mikebom-cli/src/cli/`,
  `mikebom-cli/src/resolve/`, `mikebom-cli/src/generate/`, or any other
  `package_db/*.rs` ecosystem reader (the bag absorbs the new keys).

---

## Phase 1: Setup + baseline

- [X] T001 Recon done in pre-spec investigation (2026-04-26). Findings
      logged in spec.md Background. Confirmed `parse_go_version_from_build_info`
      reads only the first line; VCS keys present in `vers_bytes` but
      discarded.
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-025.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-025-tests.txt`. Confirm post-025 list shows additions only.

---

## Phase 2: Commit 1 — `025/parser`

**Goal**: Parser extracts VCS keys from the BuildInfo vers_info blob;
GoBinaryInfo carries them; existing tests still pass.

- [ ] T003 [US1] Add `pub struct GoVcsInfo { revision: Option<String>, time: Option<String>, modified: Option<bool> }` to `go_binary.rs`. Derive `Clone`, `Debug`, `Default`.
- [ ] T004 [US1] Add `vcs: Option<GoVcsInfo>` field to `GoBinaryInfo` (line 64). `None` means no VCS keys present.
- [ ] T005 [US1] Replace `parse_go_version_from_build_info` (line 346) with a `parse_vers_info(s: &str) -> (Option<String>, Option<GoVcsInfo>)` that:
  1. Reads the first non-empty line as the Go version (existing behavior).
  2. Walks remaining lines; for each line of shape `key\tvalue`, dispatches:
     - `vcs.revision` → `vcs.revision = Some(value)`
     - `vcs.time` → `vcs.time = Some(value)`
     - `vcs.modified` → `vcs.modified = value.parse::<bool>().ok()`
     - others ignored (out of scope per spec).
  3. Returns `(Option<String>, Option<GoVcsInfo>)`. The VCS field is
     `Some(GoVcsInfo)` when at least one key parsed; `None` when all
     three sub-fields are unset.
- [ ] T006 [US1] Update `decode_buildinfo` (line 179) to call
      `parse_vers_info` and populate both `go_version` and `vcs` on the
      returned `GoBinaryInfo`.
- [ ] T007 [US1] Add 3 inline tests to `go_binary.rs::tests`:
  - `parses_all_three_vcs_keys` — build_info string with go version +
    `vcs\tgit`, `vcs.revision\tdeadbeef0123`, `vcs.time\t2026-04-26T12:00:00Z`,
    `vcs.modified\tfalse`. Assert all three GoVcsInfo fields populate
    correctly.
  - `parses_only_revision_other_keys_absent` — only `vcs.revision`
    present. Assert revision is Some, time + modified are None.
  - `no_vcs_keys_yields_none_vcs` — build_info blob has only the Go
    version. Assert `info.vcs == None`.
- [ ] T008 [US1] Verify: `cargo +stable test -p mikebom go_binary` includes
      the 3 new tests + they pass; existing tests
      (`decodes_inline_buildinfo_three_deps` etc.) still pass.
- [ ] T009 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T010 [US1] Commit: `feat(025/parser): extract Go BuildInfo VCS keys (revision + time + modified)`.

---

## Phase 3: Commit 2 — `025/wire-up-bag`

**Goal**: Main-module entries populate `extra_annotations` with the
three new VCS keys; dep entries unchanged.

- [ ] T011 [US1] In `go_binary.rs` (line ~587, the main-module
      `PackageDbEntry` construction), replace `extra_annotations: Default::default(),`
      with a call to a new helper `build_vcs_annotations(info: &GoBinaryInfo) -> BTreeMap<String, Value>`.
- [ ] T012 [US1] Define `build_vcs_annotations`: iterates `info.vcs`,
      inserts up to 3 keys (`mikebom:go-vcs-revision`,
      `mikebom:go-vcs-time`, `mikebom:go-vcs-modified`) when each
      sub-field is `Some`. Returns empty `BTreeMap` when `info.vcs ==
      None` or when all three sub-fields are `None`.
- [ ] T013 [US1] Verify: dep entry construction (line ~623) still uses
      `extra_annotations: Default::default(),` (per FR-006).
- [ ] T014 [US1] Verify: `holistic_parity` still passes (no new catalog
      rows yet, so the new annotations are surfaced via the existing bag
      emission but no row asserts on them).
- [ ] T015 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T016 [US1] Commit: `feat(025/wire-up-bag): populate Go main-module entries with VCS annotations via the extra_annotations bag`.

---

## Phase 4: Commit 3 — `025/parity-rows`

**Goal**: Three new C-section catalog rows; per-format anno extractors;
EXTRACTORS table extended; holistic_parity asserts SymmetricEqual on
the new rows.

- [ ] T017 [US1] Edit `docs/reference/sbom-format-mapping.md`: add 3
      C-section rows (next available IDs after C26 — so C27, C28, C29)
      for `mikebom:go-vcs-revision`, `mikebom:go-vcs-time`,
      `mikebom:go-vcs-modified`. Each Present × 3 formats ×
      SymmetricEqual.
- [ ] T018 [US1] Edit `mikebom-cli/src/parity/extractors/cdx.rs`: add 3
      `cdx_anno!` invocations for c27_cdx, c28_cdx, c29_cdx (component-scope).
- [ ] T019 [US1] Edit `mikebom-cli/src/parity/extractors/spdx2.rs`: add 3
      mirror `spdx23_anno!` invocations.
- [ ] T020 [US1] Edit `mikebom-cli/src/parity/extractors/spdx3.rs`: add 3
      mirror `spdx3_anno!` invocations.
- [ ] T021 [US1] Edit `mikebom-cli/src/parity/extractors/mod.rs::EXTRACTORS`:
      add 3 new `ParityExtractor` rows + 9 fn imports across cdx, spdx2,
      spdx3 import blocks.
- [ ] T022 [US1] Verify: `cargo +stable test -p mikebom --test holistic_parity`
      green. `cargo +stable test -p mikebom --test sbom_format_mapping_coverage`
      green (every catalog row has an extractor).
- [ ] T023 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T024 [US1] Commit: `feat(025/parity-rows): wire Go VCS annotations into the holistic-parity matrix`.

---

## Phase 5: Verification

- [ ] T025 SC-001 verification: 4 standard gates green.
- [ ] T026 SC-005 verification:
      `git diff main..HEAD -- mikebom-common/ mikebom-cli/src/cli/ mikebom-cli/src/resolve/ mikebom-cli/src/generate/`
      empty (the bag absorbs).
- [ ] T027 SC-007 verification (bag amortization proof):
      `git diff main..HEAD -- mikebom-cli/src/scan_fs/package_db/{apk,cargo,dpkg,gem,maven,npm,pip,rpm}.rs`
      empty (other ecosystem readers untouched — this is the milestone-023
      payoff demonstrated).
- [ ] T028 SC-004 verification: `wc -l mikebom-cli/src/scan_fs/package_db/go_binary.rs`
      ≤ 1600.
- [ ] T029 27-golden regen: deltas only on Go-binary fixtures (if any
      exist with VCS metadata; otherwise zero diff).
- [ ] T030 Push branch; observe all 3 CI lanes green (SC-006).
- [ ] T031 Author the PR description: 3-commit summary, bag-amortization
      attestation (SC-007), recon pointer to spec.md, byte-identity
      attestation.

---

## Dependency graph

```text
T001 (recon, done) → T002 (baseline)
                       │
                       ↓
                  T003-T010 [Commit 1: parser]
                       │
                       ↓
                  T011-T016 [Commit 2: wire-up-bag]
                       │
                       ↓
                  T017-T024 [Commit 3: parity-rows]
                       │
                       ↓
                  T025-T031 (verify + PR)
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 done; just snapshot |
| Phase 2 (parser) | 2 hr | Parser + 3 inline tests |
| Phase 3 (wire-up) | 30 min | One helper fn + use site swap |
| Phase 4 (parity rows) | 30 min | Mechanical (same shape as 023's C24-C26) |
| Phase 5 (verify + PR) | 30 min | Goldens + push + CI watch |
| **Total** | **~3.5 hr** | Half a focused day. |
