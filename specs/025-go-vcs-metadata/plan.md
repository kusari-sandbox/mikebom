---
description: "Implementation plan — milestone 025 Go VCS metadata"
status: plan
milestone: 025
---

# Plan: Go VCS metadata

## Architecture

Pure data-plumbing extension — the BuildInfo bytes already carry the VCS
keys; we just stop discarding them. Three new keys land in the
milestone-023 `extra_annotations` bag on the main-module Go entry. Zero
new infrastructure: no new fns/types beyond the `GoVcsInfo` carrier,
no schema migration, no `generate/` plumbing changes (the bag absorbs
new keys for free).

This is the **first follow-on consumer** of the bag introduced in
milestone 023 — proves the amortization payoff (zero churn on the 30
PackageDbEntry-init sites in other ecosystem readers).

## Reuse inventory

- `parse_go_version_from_build_info` in `go_binary.rs:346` — extends to
  also parse VCS lines (or split into two fns; see commit 1).
- `decode_buildinfo` (line 179) — already produces the `vers_info: String`
  that contains the VCS lines.
- `build_inline_buildinfo` test helper (`go_binary.rs::tests`) — accepts
  a `build_info: &str`; we feed it `"go1.22.1\nvcs\tgit\n..."` to
  exercise VCS parsing in unit tests.
- `extra_annotations` bag (milestone 023) — pre-existing; we just
  insert into it.
- `cdx_anno!`, `spdx23_anno!`, `spdx3_anno!` macros — one-line
  registration per format per extractor.
- The catalog → parity → emission chain — fully automated by
  milestones 022 + 023; we just add catalog rows and fn invocations.

## Touched files

| File | Change | LOC |
|---|---|---|
| `mikebom-cli/src/scan_fs/package_db/go_binary.rs` | + GoVcsInfo struct + VCS parser + GoBinaryInfo field + bag population at main-module emission + 3 inline tests | +90 |
| `mikebom-cli/src/parity/extractors/cdx.rs` | + 3 `cdx_anno!` invocations | +3 |
| `mikebom-cli/src/parity/extractors/spdx2.rs` | + 3 `spdx23_anno!` invocations | +3 |
| `mikebom-cli/src/parity/extractors/spdx3.rs` | + 3 `spdx3_anno!` invocations | +3 |
| `mikebom-cli/src/parity/extractors/mod.rs` | + 3 `ParityExtractor` rows + 9 fn imports | +12 |
| `docs/reference/sbom-format-mapping.md` | + 3 C-section rows | +3 |

Total: ~115 LOC across 6 files. **Zero PackageDbEntry-init churn** —
the bag pays its dividend.

## Phasing

Three atomic commits in dependency order:

### Commit 1 — `025/parser`
- Add `GoVcsInfo` struct.
- Extend `parse_go_version_from_build_info` (or add a sibling
  `parse_vers_info`) that returns `(Option<String>, Option<GoVcsInfo>)`.
- Add `vcs: Option<GoVcsInfo>` field to `GoBinaryInfo`.
- Update `decode_buildinfo` to populate the new field.
- 3 inline tests for the parser: with-all-three-keys, only-revision,
  no-vcs-keys.
- All existing tests continue passing (`build_inline_buildinfo` test
  helper signature is unchanged; existing tests with empty `build_info`
  blob produce `vcs: None` as expected).

### Commit 2 — `025/wire-up-bag`
- In the main-module `PackageDbEntry` construction (line ~587),
  populate `extra_annotations` from `info.vcs`.
- Dep entries unchanged (no VCS).
- Verify: existing `holistic_parity` test still green; new annotations
  go through the bag-emission path.

### Commit 3 — `025/parity-rows`
- Add 3 catalog rows in `docs/reference/sbom-format-mapping.md`.
- Add 3 `*_anno!` invocations in cdx/spdx2/spdx3.
- Add 3 EXTRACTORS rows + 9 imports in mod.rs.
- `holistic_parity` automatically picks up the new SymmetricEqual rows.

Per FR-010 each commit's `./scripts/pre-pr.sh` is clean.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Commit 1 (parser) | 2 hr | Parser + 3 inline tests |
| Commit 2 (bag wire-up) | 30 min | One block of 3 conditional inserts |
| Commit 3 (parity rows) | 30 min | Mechanical (same shape as 023's C24-C26) |
| Verification + PR | 30 min | Goldens regen + CI watch |
| **Total** | **~3.5 hr** | Half a focused day. |

## Risks

- **R1 (low): line-ending inconsistency in BuildInfo blob**. Go writes
  `\n`-separated lines; the parser uses `.lines()` which handles both
  `\n` and `\r\n` per Rust's std contract. No special handling needed.
- **R2 (low): dirty tree flag parsing**. `vcs.modified` value is
  always `"true"` or `"false"` per Go's docs. Parse with
  `parse::<bool>()` and store as `Option<bool>`. Unparseable values
  → `None` (defensive); record nothing rather than wrong data.
- **R3 (low): TAB embedded in value**. Per Go's BuildInfo spec, values
  can't contain tabs (encoded out by Go itself). Parser uses
  `splitn(2, '\t')` — first TAB is the separator, anything after is
  value-verbatim.
- **R4 (low): conflict with future milestone 024 (Mach-O)**. None —
  Mach-O has nothing to do with Go BuildInfo. Independent surfaces.

## Constitution alignment

- **Principle I (zero C):** untouched. ✓
- **Principle IV (no `.unwrap()` in production):** parser uses Option
  + ? throughout. ✓
- **Principle VI (three-crate architecture):** untouched.
  mikebom-common not modified.
- **Per-commit verification:** FR-010 enforced.
- **Bag-first design (lesson from 023):** this milestone is the proof
  point — zero PackageDbEntry-init churn, zero generate/ touches.

## What this milestone does NOT do

- Does not surface `vcs` (the system: "git" / "hg" / etc.).
- Does not validate commit SHA format.
- Does not chase the actual repo to verify the commit exists.
- Does not touch macho.rs / pe.rs / linkage / version-strings.
- Does not change CLI args.
