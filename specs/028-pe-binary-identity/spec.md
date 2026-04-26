---
description: "Extract PE PDB-id (CodeView GUID + Age), machine type, and subsystem to complete the binary-identity trifecta after milestones 023 (ELF) and 024 (Mach-O)"
status: spec
milestone: 028
---

# Spec: PE binary identity

## Background

mikebom's PE binary scanner is a 6-line stub
(`mikebom-cli/src/scan_fs/binary/pe.rs`). The cross-format scanner already
classifies `class == "pe"` and reads `.rdata` for the version-string region
(`scan.rs:213`), and detects-stripped via `!file.has_debug_symbols()`
(`scan.rs:117`). It does NOT extract any PE-specific identity signals
that the same `object` 0.36 primitives could surface:

- **PDB-id (CodeView GUID + Age)** — the canonical PE binary identity.
  Microsoft toolchains write a CodeView Type-2 record into the
  `IMAGE_DIRECTORY_ENTRY_DEBUG` directory containing a 16-byte GUID + a
  u32 Age + the original PDB filename. The pair `<guid>:<age>` is what
  symbol servers (Microsoft Symbol Server, snapshotted Mozilla / Chromium
  symbol stores), WinDbg, drmingw, and crash-dump analyzers use to locate
  matching `.pdb` files. Without it, mikebom cannot dedupe "same binary
  shipped in two MSI installers" or correlate to the `.pdb` for symbol
  resolution. The macOS analog is LC_UUID (milestone 024); the Linux
  analog is NT_GNU_BUILD_ID (milestone 023).

- **Machine type** — IMAGE_FILE_HEADER.Machine (`i386`, `amd64`, `arm64`,
  `ia64`, etc.). Captures the binary's target architecture in a way the
  current `class == "pe"` field doesn't — a single PE binary could be
  any of i386/amd64/arm64 and downstream consumers need to disambiguate
  for compatibility checks.

- **Subsystem** — IMAGE_OPTIONAL_HEADER.Subsystem (`console`,
  `windows-gui`, `windows-cui`, `efi-application`, `efi-boot-service`,
  `native`, `xbox`, etc.). Captures runtime context: whether the binary
  is a CLI tool, a GUI app, a kernel driver, or an EFI module. The macOS
  analog is `LC_BUILD_VERSION`'s platform field (`macos:14.0` →
  `mikebom:macho-min-os` in milestone 024).

These three together establish PE binary identity in a way mikebom
currently lacks. They are independent of milestones 1-027 — pure
additive scanning that consumes the same `extra_annotations` bag wired
in milestone 023 and proven across 024 + 025.

External callers are unaffected; the changes manifest as new annotation
rows in all three SBOM formats (CDX/SPDX 2.3/SPDX 3) via the established
`mikebom:pe-pdb-id`, `mikebom:pe-machine`, `mikebom:pe-subsystem` keys.

This is the **6th use** of the 4-file tighter-spec template (after 021,
022, 023, 024, 025). The pattern is now stable for genuinely contained
binary-metadata milestones.

## User story (US1, P1)

**As an SBOM consumer correlating a Windows binary across MSI installers
or to its PDB symbol file**, I want each PE component in mikebom output
to carry its CodeView PDB-id, machine type, and subsystem (when present)
so that downstream tools can stable-identify the binary, route to the
right symbol server, and reason about runtime context.

**Why P1 (not P2):** correctness-flavored, not hygiene. Until PDB-id
lands, mikebom's PE binary identity is "absolute path on disk" — which
doesn't deduplicate across installers and doesn't survive renames.
Same data-quality gap that 023 closed for ELF and 024 closed for Mach-O.

### Independent test

After implementation:
- `cargo +stable test -p mikebom --bin mikebom scan_fs::binary::pe`
  exercises new inline parser tests (synthetic PE byte buffers OR
  `object`-crate-driven tests against a tiny real PE fixture).
- `cargo +stable test -p mikebom --bin mikebom scan_fs::binary::entry`
  picks up new bag-emission tests for the 3 PE keys.
- `cargo +stable test -p mikebom --test holistic_parity` continues green
  with 3 new C-section rows (C33/C34/C35 — next available after 024's C32).
- `cargo +stable test -p mikebom --test sbom_format_mapping_coverage` green
  (parser finds C33-C35 + every emitted field has a row).

(Note: there is no Linux/macOS CI-lane equivalent to 024's `/bin/ls`
SC-002 anchor for PE — neither the default Linux lane nor the macOS lane
has a system PE binary lying around. The PE assertions therefore use
synthetic fixtures rather than a host-binary scan, mirroring the spec's
existing "no real-PE binary on host" reality.)

## Acceptance scenarios

**Scenario 1: CodeView round-trip across formats**
```
Given: a PE binary with CodeView GUID = X, Age = N, PDB filename = P
When:  mikebom emits CDX + SPDX 2.3 + SPDX 3 from a single scan
Then:  all three contain a `mikebom:pe-pdb-id` annotation/property whose
       canonical-flatten value equals "<guid-hex-lowercase>:<age>", AND
       `holistic_parity` agrees on SymmetricEqual.
```

**Scenario 2: Machine type emission**
```
Given: an x86_64 PE binary (IMAGE_FILE_HEADER.Machine = 0x8664)
When:  mikebom scans it
Then:  the emitted `mikebom:pe-machine` annotation has value "amd64".
       (Strings, not raw u16 — same shape as `class` already takes.)
```

**Scenario 3: Subsystem emission for an EFI module**
```
Given: a PE binary with Subsystem = IMAGE_SUBSYSTEM_EFI_APPLICATION (10)
When:  mikebom scans it
Then:  the emitted `mikebom:pe-subsystem` annotation has value
       "efi-application".
```

**Scenario 4: Absent CodeView record doesn't produce empty annotations**
```
Given: a PE binary built without CodeView debug info (e.g. a stripped
       .exe with no IMAGE_DEBUG_DIRECTORY entries)
When:  mikebom scans it
Then:  no `mikebom:pe-pdb-id` annotation is emitted (vs an annotation
       with an empty value). `mikebom:pe-machine` and
       `mikebom:pe-subsystem` are still emitted (those come from the
       IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER, which every well-
       formed PE has).
```

## Edge cases

- **CodeView record types:** the IMAGE_DEBUG_DIRECTORY entry can carry
  Type-2 (PDB 7.0, the modern format) or Type-1 (PDB 2.0, NB10, very
  old). `object::PeFile::pdb_info()` handles only Type-2 (the only
  form modern compilers emit; Type-1 has been dead since VS 2003).
  Mikebom inherits that scope: NB10 binaries get no PDB-id annotation.

- **Stripped binaries:** `cl /Z7` embedded debug info or `link /DEBUG:NONE`
  produces a PE with no IMAGE_DEBUG_DIRECTORY. `pdb_info()` returns
  `Ok(None)` — no annotation emitted.

- **Forwarder DLLs and resource-only DLLs:** carry IMAGE_FILE_HEADER +
  IMAGE_OPTIONAL_HEADER (so machine + subsystem emit) but typically no
  CodeView record. Same skip-on-absent contract as Scenario 4.

- **Unknown machine type:** `Machine = 0` (UNKNOWN) or any value not in
  the well-known list (i386 / amd64 / ia64 / arm / armnt / arm64 /
  riscv32 / riscv64) emits `"unknown"` rather than the raw u16 hex
  (consistent with how 024's `<platform>:<version>` emits a known
  platform name + numeric version, not the raw enum index).

- **Unknown subsystem:** same — emit `"unknown"` for any value outside
  the well-known list (native / console / windows-gui / windows-cui /
  os2-cui / posix-cui / native-windows / windows-ce-gui / efi-
  application / efi-boot-service / efi-runtime-driver / efi-rom / xbox
  / windows-boot-application).

- **PDB filename in CodeView:** captured as the full original path
  (e.g. `D:\src\foo\Release\foo.pdb`). The pdb-id annotation does NOT
  include the path — only `<guid>:<age>`. The path is build-host
  specific and not load-bearing for symbol-server lookups. (Symbol
  servers key on guid + age + basename.)

- **Endianness:** PE is always little-endian. No special handling.

- **32-bit vs 64-bit PE:** the `object` crate's typed accessors handle
  both via the `ImageNtHeaders` trait — mikebom's wrapper fns are
  generic over the trait so the body is shared. The call site picks
  the concrete `PeFile32` vs `PeFile64` by reading
  `IMAGE_OPTIONAL_HEADER.Magic` (`0x10B` → PE32, `0x20B` → PE32+).
  No fat-container handling like Mach-O's per-slice walk in 024 —
  PE has no equivalent multi-arch wrapper format.

## Functional requirements

- **FR-001**: `mikebom-cli/src/scan_fs/binary/pe.rs` graduates from a
  6-line stub to a working module with three `pub fn` extractors:
  - `pub fn parse_pdb_id(file: &object::read::pe::PeFile<...>) -> Option<String>`
  - `pub fn parse_machine_type(file: &object::read::pe::PeFile<...>) -> Option<String>`
  - `pub fn parse_subsystem(file: &object::read::pe::PeFile<...>) -> Option<String>`
  Each defensive: returns None on any parse failure. Per the
  `object`-crate API, `pdb_info()` already returns `Result<Option<CodeView>>`
  — wrapper just hex-encodes guid + appends age. Generic over
  `ImageNtHeaders` so both 32-bit (`PeFile32`) and 64-bit (`PeFile64`)
  paths reuse the same impl.

- **FR-002**: `mikebom-cli/src/scan_fs/binary/entry.rs::BinaryScan` gains
  three new fields: `pe_pdb_id: Option<String>`,
  `pe_machine: Option<String>`, `pe_subsystem: Option<String>`. Defaults
  are None / None / None. Same shape as 024's
  `macho_uuid` / `macho_rpath` / `macho_min_os` (Mach-O has a Vec for
  rpath; PE's three are all Option<String>).

- **FR-003**: `mikebom-cli/src/scan_fs/binary/scan.rs::scan_binary`
  populates the three new fields by calling the FR-001 extractors when
  `class == "pe"`. ELF / Mach-O leave the fields at default. Calls
  `object::read::pe::PeFile32::parse(bytes)` / `PeFile64::parse(bytes)`
  according to the bit-width detected from the existing class-detection
  arm (or via dispatch on the `object::BinaryFormat::Pe` branch's
  underlying file type).

- **FR-004**: `mikebom-cli/src/scan_fs/binary/entry.rs` gains a
  parallel `build_pe_identity_annotations` helper next to the existing
  `build_elf_identity_annotations` / `build_macho_identity_annotations`
  helpers (per the established split-helper pattern). The unified
  `build_binary_identity_annotations` extends to merge all three.
  Bag keys:
  - `mikebom:pe-pdb-id` ← `Value::String("<guid-hex>:<age>")` if Some
  - `mikebom:pe-machine` ← `Value::String("<machine-name>")` if Some
  - `mikebom:pe-subsystem` ← `Value::String("<subsystem-name>")` if Some
  Empty/None fields skip emission per Scenario 4.

- **FR-005**: `docs/reference/sbom-format-mapping.md` gains three new
  C-section rows (C33/C34/C35 — next available after milestone 024's
  C32). Each `Present` × 3 formats × `SymmetricEqual`. Justification
  lines name the IMAGE_* source field and link to milestone 028.

- **FR-006**: `mikebom-cli/src/parity/extractors/{cdx,spdx2,spdx3}.rs`
  each gain three new annotation extractors via the `*_anno!` macros.
  `parity/extractors/mod.rs::EXTRACTORS` gains three new
  `ParityExtractor` rows + 9 fn imports.

- **FR-007**: Inline tests in `pe.rs::tests` exercise the three parsers
  against hand-constructed synthetic PE byte buffers (the same approach
  milestone 024 took for Mach-O). Buffers are constructed in
  `#[cfg(test)]`-only fixture-builder helpers, not committed as binary
  blobs. This avoids any embedded-blob licensing/attribution overhead
  and keeps the fixture surface inspectable in source.

- **FR-008**: Bag-emission assertions live in `entry.rs::tests` —
  inline tests mock a populated `BinaryScan` and assert the bag
  shape (3 keys when fully populated; subset when only some PE
  fields are Some). This matches how milestone 024's bag-emission
  tests work in `entry.rs::tests` and avoids the
  `tests/scan_binary.rs` route since none of the host CI lanes
  (Linux default, Linux ebpf, macOS) carry a scannable system PE
  binary the way Linux does for ELF. The `pe.rs::tests` parser
  tests cover the FR-001 path; the `entry.rs::tests` tests cover
  the FR-004 bag-emission path.

- **FR-009**: 27 byte-identity goldens regen produces zero diff
  (existing fixtures don't include PE binaries — same null-deltas
  invariant that held for 024).

- **FR-010**: Per-commit `./scripts/pre-pr.sh` clean. Three commits
  (parsers / wire-up-bag / parity-rows), each independently green.

## Success criteria

- **SC-001**: All three standard verification gates green:
  - `./scripts/pre-pr.sh` clean (default lane).
  - `cargo +stable test -p mikebom --test holistic_parity` green.
  - `cargo +stable test -p mikebom --test sbom_format_mapping_coverage` green.

- **SC-002**: Inline `pe.rs::tests` covers all three parsers + at least
  one negative case per parser (no-CodeView returns None; unknown
  machine type returns "unknown"; unknown subsystem returns "unknown").

- **SC-003**: `git diff main..028-pe-binary-identity -- mikebom-cli/src/scan_fs/binary/elf.rs mikebom-cli/src/scan_fs/binary/macho.rs`
  is empty. ELF / Mach-O code is out of scope.

- **SC-004**: `wc -l mikebom-cli/src/scan_fs/binary/pe.rs` ≤ 250 LOC.
  Tighter than 023's 420 / 024's 350 budgets because `object` provides
  typed accessors — no byte-level parsing required.

- **SC-005**: `git diff main..HEAD -- mikebom-common/ mikebom-cli/src/cli/ mikebom-cli/src/resolve/ mikebom-cli/src/generate/ mikebom-cli/src/scan_fs/package_db/`
  is empty. Bag amortization: 4th consumer of milestone 023's bag
  with zero schema-migration touchpoints.

- **SC-006**: All 3 CI lanes (Linux default + Linux ebpf + macOS) green.

- **SC-007**: 27 byte-identity goldens regen produces zero diff
  (no fixture is a PE binary). Same amortization invariant as 024.

## Clarifications

- **PDB-id format `<guid>:<age>`**: Microsoft Symbol Server uses
  `<guid><age>` (concatenated, no separator) but most modern tooling
  (drmingw, debug-info-rs, snap-symstore-proxy, godbolt's symbol
  service) accepts the colon-separated form, which is more
  human-readable. Mikebom emits with the colon; the GUID is the
  first 32 hex chars and the age is the trailing decimal integer,
  so consumers needing the concatenated form can recover it
  trivially.

- **Machine + subsystem as strings, not raw u16**: matches the existing
  `class` field's "elf" / "macho" / "pe" string convention and 024's
  `<platform>:<version>` shape. Consumers wanting the raw u16 can
  re-derive it from the binary; the SBOM is the human/cross-tool
  surface, not the canonical numeric representation.

- **Do NOT include PDB filename in pe-pdb-id**: the path is
  build-host-specific (`D:\src\...`) and leaks build-environment
  details that are not load-bearing for symbol-server resolution.
  Symbol servers key on guid + age + basename only. Recording the
  filename is a separate concern — could be a future
  `mikebom:pe-pdb-path` if there's demand, but defer for now.

- **Do NOT extract Authenticode signature info**: code-signing data
  (publisher, timestamp, certificate chain) is a much larger surface;
  same scope decision 024 made about Mach-O `LC_CODE_SIGNATURE`.
  Defer to a future milestone if/when consumers ask.

- **Do NOT extract Rich header**: VS-toolchain provenance metadata in
  the Rich header is interesting for forensics but adds parser
  surface area + has corner cases (CRC validation, vendored padding).
  Out of scope.

- **Do NOT extract DllCharacteristics flags**: ASLR / NX_COMPAT /
  GUARD_CF / HIGH_ENTROPY_VA security flags are useful for security
  audits but are a different problem domain (defensive-posture
  signaling) than identity. Defer to a follow-on if there's
  user demand.

## Out of scope

- ELF / Mach-O code paths (covered by 023 and 024).
- Authenticode / digital signatures.
- Rich header parsing.
- DllCharacteristics security flags.
- Delay-Load IMPORT directory walking (better as a separate small
  follow-on focused on linkage evidence, not identity).
- PDB filename / path emission (deferred — build-host specific).
- Symbol-server lookup at scan time (mikebom records the field;
  doesn't do network lookups).
- TimeDateStamp emission (modern Microsoft toolchain "reproducible
  builds" zero this field, so it's a noisy signal — deferred).
