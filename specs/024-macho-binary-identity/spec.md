---
description: "Extract Mach-O LC_UUID, LC_RPATH, and minimum-OS version on macOS binary scans via the milestone-023 extra_annotations bag"
status: spec
milestone: 024
---

# Spec: Mach-O binary identity

## Background

mikebom's Mach-O binary scanner (`mikebom-cli/src/scan_fs/binary/scan.rs::scan_fat_macho`,
lines 219-303) already iterates fat / universal slices, extracts
LC_LOAD_DYLIB install-names (linkage), reads `__cstring` / `__const`
string regions, and tracks symbol presence (for stripped detection).
The companion file `mikebom-cli/src/scan_fs/binary/macho.rs` has been a
**7-line doc-comment stub** since milestone 019 — no concrete
implementation. Three Mach-O identity / runtime-linkage signals that
the same `object` crate primitives can read are not yet extracted:

- **LC_UUID** — 16-byte identifier emitted by every Apple toolchain
  (`ld -no_uuid` is the only way to suppress it). The Mach-O equivalent
  of ELF's `NT_GNU_BUILD_ID`. Used by `dsymutil`, the macOS crash
  reporter, `xcrun symbolicatecrash`, Console.app, and every `*.dSYM`
  bundle to correlate stripped binaries with their debug symbols.
- **LC_RPATH** — runtime library search paths the dynamic loader
  consults. The Mach-O analog of `DT_RPATH` / `DT_RUNPATH`. Common in
  bundled apps (`@executable_path/../Frameworks`), Homebrew bottles,
  and macOS-built Rust binaries. Today mikebom doesn't surface them;
  unbundled libraries linked via `@rpath/foo.dylib` emit only the raw
  install-name.
- **Minimum OS version** — Mach-O records the SDK / deployment target
  via `LC_VERSION_MIN_MACOSX` (legacy), `LC_VERSION_MIN_IPHONEOS`,
  `LC_VERSION_MIN_*OS`, or the newer unified `LC_BUILD_VERSION` (which
  carries the platform + version + tools). Useful to know which OS
  releases a binary targets.

These three together establish Mach-O binary identity in the same way
milestone 023's three ELF signals (build-id / runpath / debuglink) did
for Linux. The data is accessible via `object::read::macho::LoadCommandIterator`;
no new dependencies, no schema migration. macOS users today get
**linkage only** from a Mach-O scan — this milestone closes that gap.

This is the **second per-binary-metadata consumer** of the milestone-023
extra_annotations bag (after milestone 025's Go VCS metadata).

## User story (US1, P1)

**As an SBOM consumer correlating a macOS binary across deployments,
crash reports, or to its `.dSYM` debug symbols**, I want each Mach-O
component in mikebom output to carry its LC_UUID, LC_RPATH list, and
minimum-OS version (when present) so that downstream tools can
stable-identify the binary, resolve runtime linkage correctly, and know
what macOS / iOS releases the binary supports.

**Why P1 (not P2)**: same reasoning as milestone 023's ELF identity
work — until LC_UUID lands, mikebom's macOS binary identity is
"absolute path on disk." That doesn't survive renames or correlate to
`.dSYM` packages. Real data-quality gap, not polish.

### Independent test

After implementation:

- `/bin/ls` (or any other macOS system binary, all of which are signed
  fat Mach-O with LC_UUID) emits a CDX file-level component with
  property `mikebom:macho-uuid`, value matching the binary's actual
  UUID (verifiable via `otool -l /bin/ls | grep -A 2 LC_UUID`).
- Same scan emits SPDX 2.3 + SPDX 3 annotation envelopes for the same.
- Three new C-section catalog rows (C30/C31/C32) added; `holistic_parity`
  asserts SymmetricEqual on all three.
- Synthetic Mach-O fixtures exercise the parsers directly (inline
  tests in `macho.rs`).
- 27 byte-identity goldens regen with deltas only on Mach-O fixtures.

## Acceptance scenarios

**Scenario 1: macOS system binary with full identity**
```
Given: /bin/ls on macOS — fat Mach-O, signed, with LC_UUID,
       LC_RPATH (system framework search paths), and LC_BUILD_VERSION
When:  mikebom scans it
Then:  the file-level component has properties:
         mikebom:macho-uuid     = <32-hex-char UUID>
         mikebom:macho-rpath    = <JSON array of paths>
         mikebom:macho-min-os   = "macos:<version>"
       AND the same three annotations land in SPDX 2.3 + SPDX 3.
```

**Scenario 2: Fat Mach-O — UUID per-slice resolution**
```
Given: a fat Mach-O with both arm64 and x86_64 slices
When:  mikebom scans it
Then:  the FIRST slice's LC_UUID is recorded (consistent with how
       linkage dedup'd identical install-names across slices in
       pre-024 code). Per-arch UUID divergence is rare in practice
       and not worth multi-value annotations for this milestone.
```

**Scenario 3: Binary built with `-no_uuid` (or stripped)**
```
Given: a Mach-O binary built without LC_UUID
When:  mikebom scans it
Then:  no mikebom:macho-uuid annotation is emitted (bag entry
       skipped). Other annotations populate normally if present.
```

**Scenario 4: ELF binary on macOS path / Mach-O binary on Linux path**
```
Given: ELF binary scanned (regardless of host)
When:  mikebom emits the file-level component
Then:  no mikebom:macho-* annotations are emitted (those are
       Mach-O-specific). milestone 023's mikebom:elf-* annotations
       continue to populate as before.
```

## Edge cases

- **Fat / universal binaries**: each arch slice has its own LC_UUID.
  We extract from the **first slice** (consistent with how the
  existing fat-slice loop dedups linkage names). Per-slice UUIDs are
  rare in real binaries and adding multi-arch arrays would complicate
  the bag-emission shape for low signal. If divergent per-slice UUIDs
  become a real-world pain point, a follow-on milestone can switch to
  array emission.
- **Multiple LC_RPATH commands**: emit all, dedup'd, in declaration
  order — same pattern as ELF DT_RPATH+DT_RUNPATH dedup in
  milestone 023.
- **`@executable_path` / `@loader_path` / `@rpath`**: recorded raw.
  Substitution is runtime-context-dependent (matches milestone 023's
  `$ORIGIN` policy).
- **Min-OS version source**: prefer `LC_BUILD_VERSION` (newer; carries
  platform identifier explicitly) over `LC_VERSION_MIN_MACOSX` etc.
  When LC_BUILD_VERSION absent, fall back to LC_VERSION_MIN_*. The
  emitted format is `"<platform>:<version>"` (e.g.
  `"macos:14.0"`, `"ios:17.0"`); platform is lowercase. When only the
  legacy LC_VERSION_MIN_MACOSX is present (no LC_BUILD_VERSION),
  default the platform to `macos`.
- **Codesign metadata**: explicitly **out of scope** for this milestone
  (LC_CODE_SIGNATURE points to a CMS-formatted blob in __LINKEDIT;
  parsing requires ASN.1 + cert-chain extraction). Deferred to a
  follow-on milestone.
- **CPU architecture / type**: nice-to-have but not in this milestone's
  scope (fat slice iteration already covers per-arch concerns
  internally).

## Functional requirements

- **FR-001**: `mikebom-cli/src/scan_fs/binary/macho.rs` graduates from
  the 7-line stub to a working module with three new pure parsers:
  - `pub fn parse_lc_uuid(load_cmds: &LoadCommandIterator) -> Option<String>`
    — walks load commands, returns the first LC_UUID's bytes hex-encoded.
  - `pub fn parse_lc_rpath(load_cmds: &LoadCommandIterator) -> Vec<String>`
    — collects every LC_RPATH command's path string; dedup'd.
  - `pub fn parse_min_os_version(load_cmds: &LoadCommandIterator) -> Option<String>`
    — prefers LC_BUILD_VERSION; falls back to LC_VERSION_MIN_*. Returns
    `<platform>:<version>` form.
  - Each follows the milestone-023 ELF-parser shape: parse defensively,
    return None / empty Vec on missing or malformed data, no panics.
- **FR-002**: `mikebom-cli/src/scan_fs/binary/entry.rs::BinaryScan` gains
  three new fields: `macho_uuid: Option<String>`,
  `macho_rpath: Vec<String>`, `macho_min_os: Option<String>`. Defaults
  are `None` / empty / `None`. The non-Mach-O paths leave them at
  defaults.
- **FR-003**: `scan_binary` (the non-fat path) — when the format is
  Mach-O (not fat), it currently goes through the generic `object::read::File::parse`
  path; extend that ELF-only block in scan.rs to also call the FR-001
  parsers when class is "macho".
- **FR-004**: `scan_fat_macho` (the fat-Mach-O path, lines 219+) calls
  the FR-001 parsers on the **first slice only**, populating the
  BinaryScan fields. Per-slice divergence treated per Scenario 2.
- **FR-005**: `mikebom-cli/src/scan_fs/binary/entry.rs::make_file_level_component`
  populates the bag from the new BinaryScan fields:
  - `mikebom:macho-uuid` = `Value::String(uuid_hex)` if Some.
  - `mikebom:macho-rpath` = `Value::Array(paths)` if non-empty.
  - `mikebom:macho-min-os` = `Value::String(platform_version)` if Some.
  Empty/None values skip insertion (per Scenario 3).
  This extends the existing `build_elf_identity_annotations` helper or
  adds a parallel `build_macho_identity_annotations`.
- **FR-006**: `docs/reference/sbom-format-mapping.md` gains 3 new
  C-section rows (C30, C31, C32 — next available after milestone 025's
  C29). Each `Present` × 3 formats × `SymmetricEqual`.
- **FR-007**: `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3}.rs`
  each gain three new `*_anno!` invocations. EXTRACTORS table + 9 fn
  imports per the proven 023 + 025 pattern.
- **FR-008**: 5+ inline tests in `macho.rs`:
  - parses LC_UUID → 32-hex string
  - parses multiple LC_RPATH → dedup'd vec
  - parses LC_BUILD_VERSION → `"<platform>:<version>"`
  - falls back from LC_BUILD_VERSION-absent to LC_VERSION_MIN_MACOSX
  - returns None for binary without any of the three commands
- **FR-009**: `mikebom-cli/tests/scan_binary.rs::scan_system_binary_emits_file_level_and_linkage`
  extends to assert mikebom:macho-uuid + mikebom:macho-min-os when
  `class == "macho"` (the existing test already gates on class). SC-002.
- **FR-010**: Each commit leaves `./scripts/pre-pr.sh` clean (per-commit-clean
  discipline from milestones 018-025).

## Success criteria

- **SC-001**: All four standard verification gates green:
  - `./scripts/pre-pr.sh` clean (default lane).
  - `cargo +stable test -p mikebom --bin mikebom scan_fs::binary::macho` includes
    the new inline tests + they pass.
  - `cargo +stable test -p mikebom --test holistic_parity` green.
  - 27-golden regen: zero diff on existing fixtures (no Mach-O
    fixtures with LC_UUID land in the existing golden suite — the
    synthetic-container-image is ELF Linux; cargo/npm/pip/etc.
    fixtures don't include Mach-O binaries).
- **SC-002**: On macOS CI lane: `/bin/ls` scan emits a non-empty
  `mikebom:macho-uuid` (32-hex string) AND a non-empty
  `mikebom:macho-min-os` (e.g. `"macos:14.0"`). Every macOS system
  binary is built with these load commands.
- **SC-003**: `git diff main..HEAD -- mikebom-cli/src/scan_fs/binary/elf.rs mikebom-cli/src/scan_fs/binary/pe.rs`
  is empty. ELF + PE stubs out of scope.
- **SC-004**: `wc -l mikebom-cli/src/scan_fs/binary/macho.rs` ≤ 350
  (current: 7; budget headroom for 3 parsers + ~5 inline tests + their
  fixture builders).
- **SC-005**: `git diff main..HEAD -- mikebom-common/ mikebom-cli/src/cli/ mikebom-cli/src/resolve/ mikebom-cli/src/generate/`
  empty (the bag absorbs).
- **SC-006**: All 3 CI lanes green.
- **SC-007**: Bag amortization continues:
  `git diff main..HEAD -- mikebom-cli/src/scan_fs/package_db/`
  empty (no ecosystem-reader churn).

## Clarifications

- **Annotations, not first-class fields**: same as milestones 023 + 025
  — the bag absorbs new keys without typed-field schema migration.
- **First-slice-only LC_UUID**: per Scenario 2 + Edge Cases, fat
  binaries record the first slice's UUID. Per-arch divergence is rare
  and not worth array-shaped annotations for this milestone.
- **Min-OS format**: `<platform>:<version>` with lowercase platform.
  Examples: `"macos:14.0"`, `"ios:17.5"`, `"maccatalyst:15.0"`.
- **No LC_CODE_SIGNATURE parsing**: deferred. Recording presence-only
  (boolean "is this binary signed?") would be cheap, but the
  spec-discipline call: defer it cleanly to a follow-on milestone
  rather than half-implement.
- **Mach-O on Linux**: shouldn't happen in practice (filesystem scans
  on Linux don't hit Mach-O), but the parsers are platform-agnostic —
  no `cfg(target_os)` gates beyond what already exists.
- **No dSYM bundle resolution**: mikebom records the LC_UUID;
  downstream tools can use it to find the matching dSYM. mikebom
  doesn't chase the file system or any symbol-server protocol.

## Out of scope

- LC_CODE_SIGNATURE parsing (deferred).
- CPU architecture / type extraction (deferred).
- Per-arch UUID arrays for fat binaries (deferred per Scenario 2 +
  Edge Cases).
- ELF or PE binary metadata changes (milestones 023 / 028).
- Container layer attribution (milestone 027).
- Version-string library expansion (milestone 026).
