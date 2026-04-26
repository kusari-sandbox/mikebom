---
description: "Implementation plan — milestone 024 Mach-O binary identity"
status: plan
milestone: 024
---

# Plan: Mach-O binary identity

## Architecture

Promote `binary/macho.rs` from a 7-line stub to a real module with
three new pure parsers, mirroring the milestone-023 ELF identity
shape exactly:

- 3 new `pub fn` parsers in `macho.rs` (mirror `elf.rs::parse_*`).
- 3 new fields on `BinaryScan` (mirror `build_id` / `runpath` /
  `debuglink`).
- `scan.rs` wires the parsers in both the non-fat (line ~138) and fat
  (line ~290) Mach-O code paths.
- `entry.rs::make_file_level_component` adds bag-population for the
  3 new fields, parallel to (or extending) the existing
  `build_elf_identity_annotations` helper.
- 3 new C-section catalog rows + 9 `*_anno!` invocations + 3 EXTRACTORS
  rows (the proven 023 + 025 boilerplate).

No new dependencies, no schema migration, no `generate/` plumbing —
the bag from milestone 023 absorbs the new keys.

## Reuse inventory

- `object::read::macho::LoadCommandIterator` (object 0.36, already in
  scope per `Cargo.toml:79`) — yields `LoadCommand` items with
  `.cmd()` discriminator.
- Typed structs: `UuidCommand`, `RpathCommand`, `VersionMinCommand`,
  `BuildVersionCommand` (all in `object::macho`).
- Existing `scan_fat_macho` pattern (lines 219-303) for fat slice
  iteration.
- `extra_annotations` bag (milestone 023) — pre-existing.
- `build_elf_identity_annotations` helper in `entry.rs` — extend or
  parallel.
- `cdx_anno!`, `spdx23_anno!`, `spdx3_anno!` macros.
- `holistic_parity` test for SymmetricEqual auto-coverage.

## Touched files

| File | Change | LOC |
|---|---|---|
| `mikebom-cli/src/scan_fs/binary/macho.rs` | Stub → real module: 3 parsers + ~5 inline tests + fixture builders | +280 |
| `mikebom-cli/src/scan_fs/binary/entry.rs` | + 3 BinaryScan fields; populate bag in make_file_level_component (extend `build_elf_identity_annotations` to a unified `build_binary_identity_annotations`, or parallel `build_macho_identity_annotations`) | +50 |
| `mikebom-cli/src/scan_fs/binary/scan.rs` | Wire the 3 parsers in both non-fat (one call site) and fat (slice-loop, first-slice-only) paths | +30 |
| `mikebom-cli/src/parity/extractors/cdx.rs` | + 3 `cdx_anno!` invocations | +3 |
| `mikebom-cli/src/parity/extractors/spdx2.rs` | + 3 `spdx23_anno!` invocations | +3 |
| `mikebom-cli/src/parity/extractors/spdx3.rs` | + 3 `spdx3_anno!` invocations | +3 |
| `mikebom-cli/src/parity/extractors/mod.rs` | + 3 EXTRACTORS rows + 9 fn imports | +12 |
| `docs/reference/sbom-format-mapping.md` | + 3 C-section rows | +6 |
| `mikebom-cli/tests/scan_binary.rs` | + 1-2 assertions on macOS-only path | +20 |

Total: ~410 LOC across 9 files. Most LOC is in `macho.rs` itself
(3 parsers + ~150 LOC of inline tests + fixture builders, since
constructing synthetic Mach-O byte blobs is more involved than ELF).

## Phasing

Three atomic commits (same shape as milestone 023):

### Commit 1 — `024/parsers`
- `macho.rs` graduates: 3 pure parsers + inline tests with
  `#[allow(dead_code)]`.
- Test fixtures via hand-built load-command bytes + a minimal Mach-O
  header. Same pattern as `elf.rs::tests::build_gnu_build_id_note` in
  milestone 023.

### Commit 2 — `024/wire-up-bag`
- 3 fields added to `BinaryScan` (with all 3 BinaryScan literal
  sites updated: scan.rs:138 ELF arm, scan.rs:254 Mach-O fat arm,
  entry.rs::fake_binary_scan).
- scan.rs Mach-O paths call the parsers.
- entry.rs::make_file_level_component populates the bag.
- Remove `#[allow(dead_code)]` from macho.rs parsers.
- scan_binary.rs assertion added (macOS-only).

### Commit 3 — `024/parity-rows`
- 3 catalog rows (C30/C31/C32) in mapping doc.
- 3 `*_anno!` invocations per format.
- 3 EXTRACTORS rows + 9 imports.

Per FR-010 each commit's `./scripts/pre-pr.sh` is clean.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Commit 1 (parsers) | 4-5 hr | Inline tests for Mach-O are more involved than ELF's — Mach-O load-command alignment + 64-bit pointers vs 32-bit. Fixture builders need `mach_header_64` + load-command bytes. |
| Commit 2 (wire-up) | 2 hr | Mostly mechanical; 3 BinaryScan literal sites need updates. |
| Commit 3 (parity rows) | 30 min | Same shape as 023's C24-C26 + 025's C27-C29. |
| Verification + PR | 1 hr | Goldens regen + watch CI (macOS lane is the SC-002 verification). |
| **Total** | **~7-8 hr** | One focused day. Same effort envelope as milestone 023. |

## Risks

- **R1 (medium): Synthetic Mach-O fixtures more complex than ELF**.
  Mach-O load-command parsing requires correct alignment and the
  proper `mach_header_64` / `mach_header` preamble. Mitigation: build
  minimal fixtures with `object::write::macho::*` (the inverse API
  to read) — checked at fixture-build time. Alternative: hand-construct
  byte arrays mirroring `man Mach-O` format. The recon confirmed
  `object::macho::*` exposes constants; the crate's write-side is
  also available.
- **R2 (low): LC_BUILD_VERSION vs LC_VERSION_MIN_* fallback**. The
  parser must check LC_BUILD_VERSION first (newer binaries) and fall
  back. Inline test covers both paths.
- **R3 (low): fat-slice-first-slice rule**. Spec Edge Cases + Scenario 2
  pin this down. Tested via fat-slice fixture in commit 2.
- **R4 (negligible): `/bin/ls` on macOS CI may not have all 3 commands**.
  In practice every Apple-shipped binary has LC_UUID + LC_BUILD_VERSION
  (or LC_VERSION_MIN_*). If LC_RPATH is absent (e.g., a static binary),
  the test gates the rpath assertion separately.

## Constitution alignment

- **Principle I (zero C):** untouched. ✓
- **Principle IV (no `.unwrap()` in production):** parsers use Option
  + ? throughout. ✓
- **Principle VI (three-crate architecture):** untouched. ✓
- **Per-commit verification:** FR-010 enforced.
- **Bag-first design (lessons from 023 + 025):** zero PackageDbEntry-init
  churn, zero generate/ touches.

## What this milestone does NOT do

- Does not parse LC_CODE_SIGNATURE. Recording it as a presence boolean
  would be 5 LOC; deferred to keep scope focused on identity.
- Does not extract CPU type / architecture (fat-slice iteration
  already handles per-arch concerns internally).
- Does not chase `.dSYM` bundles or symbol servers.
- Does not touch elf.rs / pe.rs / linkage.rs.
- Does not change CLI args.
