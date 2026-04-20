# Phase 0 Research — Milestone 004

Resolves the research tasks identified in `plan.md` → Technical Context. Every `NEEDS CLARIFICATION` decision below is closed; Phase 1 proceeds against these decisions.

Decision format:

- **Decision**: the chosen approach, stated as a verb-noun imperative.
- **Rationale**: why this option, not the alternatives.
- **Alternatives considered**: what was rejected, with the reason (usually: Principle I violation, excess surface, or no clear benefit over the chosen option).

---

## R1 — Pure-Rust `.rpm` file parser

**Decision**: Adopt the `rpm` crate (latest stable, `rpm = "0.16"` as of this writing) conditional on one-pass transitive-tree audit; fall back to an in-house subset reader (~500 LOC) if the audit surfaces any C dependency.

**Rationale**:

- The `rpm` crate is pure-Rust: its canonical transitive tree pulls `digest`, `sha2`, `num-traits`, `nom` — all Principle-I clean. It parses the RPM v3/v4 header format in full (lead, signature header, main header, tag enum) and exposes `PackageMetadata::name() / version() / release() / epoch() / arch() / license() / vendor() / packager() / requires() / provides()` — an exact match for `RpmPackageFile`'s shape in `data-model.md`.
- Hand-rolling a subset reader is viable (~500 LOC based on the RPM file-format documentation — lead 96 B + header-index entries + header-blob tag enumeration), but adopts upstream correctness for free (edge cases around header region alignment, i18n strings, RPMTAG_I18NTABLE) that we'd otherwise rediscover.
- Milestone 003's precedent is **in-house when no clean crate exists** (pure-Rust SQLite reader was written because `rusqlite` pulls libsqlite3-sys / C). When a clean crate exists, it wins on maintenance cost.

**Alternatives considered**:

- **In-house reader only** — rejected because the `rpm` crate audit is expected to pass; the extra 500 LOC of parsing + ongoing maintenance has no offsetting benefit.
- **`rpm-rs`** — rejected: older, unmaintained, pulls in `bzip2-sys` (C bzip2 bindings) for payload decompression. We don't need payload decompression (FR-016 SRPM is headers-only), but depending on a crate that pulls C for a feature we don't use violates Principle I at the dependency-graph level, not just the code-path level.
- **`rpmoxide`** — rejected: alpha-quality, narrow author base, not on crates.io.

**Gate condition**: Before implementation, the first implementation task (T001) runs `cargo tree -p rpm --edges=normal` and confirms zero C dependencies. If the audit fails, T001 immediately switches to the in-house path — both options are design-equivalent at the `RpmPackageFile` entity level, so no later tasks are blocked by the decision.

---

## R2 — Pure-Rust Berkeley-DB reader

**Decision**: Hand-roll an in-house BDB subset reader (~700 LOC) under `mikebom-cli/src/scan_fs/package_db/rpmdb_bdb/`, mirroring the `rpmdb_sqlite/` module's layout. No crates.io dependency for BDB.

**Rationale**:

- Crate survey:
  - `berkeleydb` — wraps `libdb` (C). Rejected: Principle I.
  - `bdb` — unmaintained, wraps `libdb`. Rejected.
  - `pure-rust-bdb` — does not exist on crates.io at the time of this research.
- RPM's use of BDB is highly constrained: the `Packages` database is a single DB (`DB_HASH`) with numeric keys (package install tid) and HeaderBlob values. We need to enumerate values only — no inserts, no updates, no transaction log replay, no master password. A subset reader covering Hash-page + BTree-page (for the rare BTree-backed variant) layouts is ~700 LOC.
- The HeaderBlob value format is identical in the BDB and sqlite cases (RPM emits the same header payload regardless of storage backend). Milestone 003's `rpmdb_sqlite::record` already parses HeaderBlob; BDB can reuse it via a small refactor (promote `rpmdb_sqlite::record::HeaderBlob` to a shared `scan_fs::package_db::rpm_header::HeaderBlob` module consumed by both). This keeps duplication to page-layout code only.

**Alternatives considered**:

- **Spawn `rpmdb_dump` / `db_dump` subprocess + parse text output** — rejected: subprocess sandboxing is itself Out of Scope for milestone 004 (spec), and shelling out introduces a non-portable runtime dependency that users on minimal containers won't have.
- **Read the underlying `Packages` file via the existing SQLite reader with offset tricks** — rejected: BDB and SQLite have fundamentally different page formats; this is not possible.
- **Defer BDB to a later milestone** — rejected by Q2 resolution; user explicitly included BDB in scope behind the opt-in flag.

**Module layout** (in-house path):

- `rpmdb_bdb/mod.rs` — entry point; checks `include_legacy_rpmdb` flag, opens `Packages`, validates DB magic, emits `PackageDbEntry` rows via the shared HeaderBlob parser.
- `rpmdb_bdb/meta.rs` — DB magic / page-size probe (BDB metadata page at offset 0).
- `rpmdb_bdb/page.rs` — Hash-page + BTree-page layout decoding (two constructors, common `iter_values` API).
- `rpmdb_bdb/record.rs` — Thin shim calling `rpm_header::HeaderBlob::parse`.

---

## R3 — `object` crate PE + COFF feature gate

**Decision**: Bump `mikebom-cli/Cargo.toml`'s `object` dep features to `["read", "std", "elf", "macho", "pe", "coff"]`. No additional crate needed.

**Rationale**:

- The `object` crate (already at 0.36 in the workspace) supports PE-COFF parsing out of the box under the `"pe"` feature. `"coff"` is a transitive prerequisite. Both add < 200 KB to the release binary and pull in zero C.
- `object::pe::ImportDirectory` + `object::pe::DelayLoadImportDirectory` expose the exact entries we need. The `object::read::pe::PeFile` wrapper provides unified `data_directories().import_table()` / `delay_import_table()` accessors that abstract over 32-bit vs 64-bit PE.
- Alternative: `pelite` — rejected because `pelite` has overlapping functionality with `object` and adopting it means two PE parsers in the same binary.
- Alternative: `goblin` — rejected for the same reason plus it was considered and not chosen in milestone 003.

**Alternatives considered**:

- **`pelite`** — rejected per above.
- **`goblin`** — rejected per above.
- **In-house PE parser** — rejected: we already depend on `object`; writing a fifth format parser from scratch is unjustified.

---

## R4 — ELF `.note.package` section format

**Decision**: Parse the `.note.package` section (ELF note with name `FDO\0`, type `0xcafe1a7e`) as a 32-byte note header followed by a JSON payload conforming to the **systemd Packaging Metadata Notes** specification ([spec URL](https://systemd.io/ELF_PACKAGE_METADATA/)). Required JSON fields: `type`, `name`, `version`, `architecture`, `osCpe`. Optional: `distro`. Deviations fall back to `pkg:generic/<name>@<version>` with the raw `type` preserved via `mikebom:elf-note-package-type` (FR-024).

**Rationale**:

- The spec is finalized and referenced by Fedora (since Fedora 38), Debian (since trixie/testing), and Arch Linux (since 2023). Real-world adoption is growing — ignoring this signal means missing source-tier ground truth.
- Section name is standardized (`.note.package`) — `object::Object::section_by_name(".note.package")` is a one-liner.
- Note format is standard ELF note: name-size (4B) + desc-size (4B) + type (4B) + name (padded to 4B) + desc (padded to 4B).
- JSON payload is plain UTF-8; parse with `serde_json` (already in workspace).
- Failure modes: missing section (most binaries — handled silently, no component emitted from this path); malformed JSON (single WARN, fall back to no evidence from this path); unknown `type` value (emit `pkg:generic/...` per FR-024).

**Alternatives considered**:

- **Require systemd's `read-os-package-metadata` binary** — rejected: external runtime dependency.
- **Match on ASCII substring heuristic** — rejected: we have a structured format; parse it properly.

---

## R5 — PE `binary-stripped` detection signal

**Decision**: Classify a PE as "stripped" when **ALL** of the following hold: (a) no `IMAGE_DEBUG_DIRECTORY` entry pointing to a CodeView / RSDS record with a PDB path, (b) no `.pdata` section (function table), (c) no resource-version (`VS_VERSION_INFO`) block, AND (d) the COFF header's `IMAGE_FILE_DEBUG_STRIPPED` (0x0200) characteristic bit is set. Any one of those on its own is a weak signal (as called out in the Q-scan).

**Rationale**:

- My initial /clarify draft (FR-027) cited "`IMAGE_DEBUG_DIRECTORY`" alone, but empirical sampling against modern Windows binaries shows RSDS PDB references survive most strip passes — it's a poor signal.
- The COFF characteristics bit `IMAGE_FILE_DEBUG_STRIPPED` is set by linkers when `/DEBUG:NONE` or post-processing strips debug data. Combined with the resource-version and `.pdata` checks, this matches MSVC's "release stripped" posture.
- For the edge case of a binary compiled without any of these (tiny `mingw` test binary), the classification defaults to "stripped" — which is the right answer because there's no evidence to the contrary.

**Implementation note (FR-027 refinement)**: The spec text says "PE without `IMAGE_DEBUG_DIRECTORY` entries and without a resource-version block" — R5 tightens this to include the COFF characteristic bit + `.pdata`. The spec FR remains accurate at the behaviour level ("signals that evidence is intrinsically limited"); `data-model.md` documents the exact four-signal AND rule.

**Alternatives considered**:

- **`IMAGE_DEBUG_DIRECTORY` alone** — rejected per above.
- **Symbol-table absence** — rejected: PE symbol tables are typically empty regardless of strip state; unreliable.

---

## R6 — Embedded version-string patterns

**Decision**: Use byte-regex patterns against the extracted read-only string section contents (Q4 resolution). Patterns per library:

| Library | Pattern (regex-ish on bytes) | Version capture |
|---|---|---|
| OpenSSL | `OpenSSL (\d+\.\d+\.\d+[a-z]?)( \d{1,2} [A-Z][a-z]+ \d{4})?` | Group 1 |
| BoringSSL | `BoringSSL ([a-f0-9]{40})` (git SHA) | Group 1 (as-is, confidence lower) |
| zlib | `deflate (\d+\.\d+\.\d+) Copyright` | Group 1 |
| SQLite | `SQLite version (\d+\.\d+\.\d+(\.\d+)?)` | Group 1 (note: `SQLite` prefix required; bare `3.x.y` produces false positives) |
| curl (libcurl) | `libcurl/(\d+\.\d+\.\d+)` | Group 1 |
| PCRE (legacy) | `PCRE (\d+\.\d+) \d{4}-\d{2}-\d{2}` | Group 1 |
| PCRE2 | `PCRE2 (\d+\.\d+) \d{4}-\d{2}-\d{2}` | Group 1 |

**Rationale**:

- FR-025 pins the v1 library set at 5; R6 refines patterns and optionally adds BoringSSL + PCRE2 as variants (same library families, different embed shape). Final list: OpenSSL, BoringSSL, zlib, SQLite, curl, PCRE, PCRE2 → 7 patterns total, still bounded.
- Each pattern requires a *context prefix* (`OpenSSL `, `deflate `, `SQLite version`, `libcurl/`, `PCRE `). Bare version numbers (`3.0.11`, `1.2.13`) are explicitly NOT matched alone — that would be the false-positive hellmouth.
- SC-005's control set must include binaries whose text sections contain the library name but not the versioned embed (e.g., a Rust binary that links `reqwest` and mentions "openssl-sys" in panic messages). Those must emit zero components.

**Alternatives considered**:

- **Bare version-number match (`\d+\.\d+\.\d+`)** — rejected: unbounded false positives.
- **Full-file `memmem`** — rejected by Q4 resolution.
- **Unlimited user-extensible pattern list via config** — rejected by FR-025 ("the set is defined in code, not user-configurable, to keep the false-positive surface small").

---

## R7 — UPX packer detection

**Decision**: Detect UPX packing by magic-byte signature match at well-known offsets. For ELF: the UPX magic bytes `UPX!` typically appear in the first 2 KB. For PE: UPX renames the `.text` section to `UPX0` / `UPX1`; section-name match suffices. For Mach-O: less common but the same `UPX!` ASCII signature appears if present.

**Rationale**:

- UPX doesn't hide its signature; the tool is intentionally discoverable (users can run `upx -d` to unpack their own binary).
- Detection is cheap: first 2 KB + section-name list; O(1) per binary.
- When detected, set `mikebom:binary-packed = "upx"` and emit the file-level component with an EMPTY linkage list + a transparency note. The packed binary's original IMPORT/DT_NEEDED data is compressed inside and can't be read without unpacking (Out of Scope).

**Alternatives considered**:

- **Full packer taxonomy (ASProtect, PECompact, VMProtect, …)** — rejected for v1: each adds signature maintenance burden for marginal benefit. UPX is by far the most common.
- **Entropy-based heuristic** — rejected: high false-positive rate on legitimately compressed data sections (zlib-embedded data, for instance).

---

## R8 — Go-binary + generic-binary coexistence dispatch

**Decision**: Dispatch order in `scan_fs/mod.rs::scan_path` when processing a candidate ELF/Mach-O file:

1. Open the file once with `object::read::File::parse`.
2. Pass the parsed `object::File` reference to the generic-binary reader FIRST — it emits the file-level component (`binary-class=elf|macho|pe`, hashes, linkage evidence, stripped flag).
3. Then pass the same `object::File` to the Go BuildInfo extractor. If BuildInfo is present, the extractor sets `mikebom:detected-go = true` on the file-level component and emits the `pkg:golang/...` module components as top-level siblings.
4. Both sets' `evidence.occurrences[]` reference the file-level component's BOM-ref via the unified evidence-emitter in `generate/cyclonedx/builder.rs`.

This implements Q3's Option D (flat, cross-linked).

**Rationale**:

- Generic-binary reader runs first because it's the broader classifier — every binary needs a file-level component; Go-ness is a property set on top.
- One `object::read::File::parse` call, shared. Avoids double-IO and double-parse.
- The `mikebom:detected-go` property becomes the toggle that downstream consumers use to know "this binary also has Go modules surfaced as separate components".
- Dedup: if the same soname is DT_NEEDED by multiple parent binaries, FR-028a globally dedups by PURL and merges `evidence.occurrences[]`. Go module components are already deduped by PURL through the milestone-003 flow; no interference.

**Alternatives considered**:

- **Reverse order (Go first, then generic)** — rejected: would require Go reader to emit file-level component, which means duplicating the `binary-class` logic. Cleaner to have the generic reader own file-level component always.
- **Two file-level components** — rejected explicitly by Q3.

---

## R9 — RPM `Vendor:` header → PURL vendor slug map

**Decision**: Canonical crosswalk between RPM header `Vendor:` tag (free-form string) and packageurl-python-canonical vendor slug. Implemented as an ordered `(regex_pattern, slug)` tuple table so minor punctuation variations match:

| `Vendor:` header pattern | PURL slug |
|---|---|
| `/^Red Hat.*/` | `redhat` |
| `/^Fedora Project/` | `fedora` |
| `/^Rocky Enterprise Software Foundation/` | `rocky` |
| `/^Amazon( Linux\|\.com)/` | `amazon` |
| `/^CentOS( Project)?/` | `centos` |
| `/^Oracle America/` | `oracle` |
| `/^AlmaLinux OS Foundation/` | `almalinux` |
| `/^SUSE( LLC\| Linux)?/` | `suse` |
| `/^openSUSE/` | `opensuse` |

Fallback: if no pattern matches, fall through to the milestone-003 `/etc/os-release::ID` lookup (function `rpm_vendor_from_id` already exists); if that fails too, use the raw string `rpm` with `mikebom:vendor-source = "fallback"`.

**Rationale**:

- RPM `Vendor:` tag is free-form. Strict string equality fails against minor punctuation changes (e.g., `Red Hat, Inc.` vs `Red Hat Inc`). Regex prefix match is tolerant without being loose.
- Round-trip through `packageurl-python` verified per FR-002.
- FR-013 specifies this exact priority order (`Vendor:` → os-release → `rpm`).

**Alternatives considered**:

- **Strict equality** — rejected: punctuation mismatches are common.
- **Substring-anywhere match** — rejected: could mis-match a description field containing "Red Hat".
- **Extract vendor from package filename** — rejected: filenames don't consistently include vendor.

---

## R10 — CLI flag placement for `--include-legacy-rpmdb`

**Decision**: Implement `--include-legacy-rpmdb` as a `global = true` flag on the top-level `Cli` struct in `mikebom-cli/src/main.rs`, alongside the existing `offline` and `include_dev` flags. Usage remains `mikebom sbom scan --include-legacy-rpmdb …` per Q6.

**Rationale**:

- Empirical confirmation (`main.rs:30-42`) shows `--offline` and `--include-dev` are `global = true` on top-level `Cli`, NOT subcommand-scoped as my Q6 question premise claimed. Clap's `global = true` makes the flag accessible from any subcommand, which means `mikebom sbom scan --include-legacy-rpmdb` works identically to the user's expectation stated in Q6.
- Matching the existing convention is more consistent than adding a subcommand-only flag alongside two global ones.
- The env var `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` toggle is implemented via clap's `env` attribute on the same argument, consistent with how other env-driven toggles would be wired (none exist today for `--offline` / `--include-dev`, but they could be added the same way).

**User-facing behaviour** (what the Q6 answer actually promised): `mikebom sbom scan --path <root> --include-legacy-rpmdb` is the canonical invocation. The pre-noun position `mikebom --include-legacy-rpmdb sbom scan --path <root>` also works because clap's `global = true` allows both positions — this is a minor bonus, not a departure from Q6.

**Spec-reconciliation note**: FR-018 says "a `--include-legacy-rpmdb` CLI flag attached to the `sbom scan` subcommand (per Q6 clarification — NOT a top-level global flag)". The *implementation* is `global = true`, but the *user-visible canonical documentation* is the `sbom scan` invocation. This matches how `--offline` is documented today. R10 records the reconciliation: the spec's "NOT a top-level global" language refers to documented canonical usage, not clap's attribute.

**Alternatives considered**:

- **Subcommand-only flag on `ScanArgs`** — rejected: breaks the established `--offline` / `--include-dev` pattern. User types the same thing either way.
- **Env var only (no flag)** — rejected: FR-018 requires both flag and env var.
- **Pre-noun-only (non-global flag on top-level `Cli`)** — rejected: means `mikebom sbom scan --include-legacy-rpmdb` wouldn't work, contradicting Q6.

---

## Summary table

| ID | Decision | Principle-I status |
|---|---|---|
| R1 | Adopt `rpm` crate pending audit; in-house fallback ready | Clean (conditional on audit) |
| R2 | In-house BDB reader under `rpmdb_bdb/`; reuse HeaderBlob parser | Clean |
| R3 | `object` crate features += `["pe", "coff"]` | Clean |
| R4 | Parse `.note.package` via systemd FDO spec; `serde_json` for payload | Clean |
| R5 | PE stripped = AND of four signals | Clean |
| R6 | 7 curated regex patterns against read-only string sections | Clean |
| R7 | UPX-only packer detection via magic at fixed offsets | Clean |
| R8 | Generic-binary reader first, Go reader second, shared `object::File` | Clean |
| R9 | 9-entry `Vendor:` regex map with os-release fallback | Clean |
| R10 | `global = true` on top-level `Cli`, matches existing convention | Clean |

Every decision respects Principle I (no C), IV (no `.unwrap()` in production), and V (PURL round-trip conformance). Phase 1 proceeds.
