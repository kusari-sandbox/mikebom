# Contract: CLI Interface

Defines the user-visible CLI surface changes introduced by milestone 004. Pins flag names, env var names, exit codes, and stderr shape so integration tests can assert stability and downstream consumers (CI pipelines, wrappers) can depend on them.

---

## New flag: `--include-legacy-rpmdb`

**Kind**: `bool` switch, `global = true` on the top-level `Cli` (R10; matches `--offline` / `--include-dev` convention).

**Canonical invocation**: `mikebom sbom scan --path <root> --include-legacy-rpmdb`. The pre-noun position `mikebom --include-legacy-rpmdb sbom scan …` also works because of clap's `global = true`, but `sbom scan …` is the documented form.

**Env var**: `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` sets the flag implicitly (FR-018). Clap's `env` attribute on the argument.

**Default**: `false`.

**Effect when unset** (FR-018, US4 AS-1):

- `/var/lib/rpm/Packages` (BDB) with no sibling `rpmdb.sqlite`: **single WARN log line** naming the file, zero rpm components emitted from the BDB path, scan completes with exit code 0.
- This matches milestone-003 behaviour verbatim. No silent behaviour change.

**Effect when set** (FR-018, US4 AS-2):

- Same rootfs: BDB reader activates, produces one `PackageDbEntry` per HeaderBlob record, components emitted with `mikebom:evidence-kind = "rpmdb-bdb"`, `mikebom:sbom-tier = "deployed"`.
- Rootfs with both `rpmdb.sqlite` AND `Packages`: sqlite path wins (FR-019c); BDB reader is skipped; one INFO log line notes the transitional configuration. Flag has no other effect.
- Rootfs with only `rpmdb.sqlite`: flag is a no-op; sqlite path runs unchanged (Edge Case — "flag no-op on sqlite-only rootfs").

**Help text** (`mikebom sbom scan --help`):

```
      --include-legacy-rpmdb
          Enable reading of legacy Berkeley-DB rpmdb
          (/var/lib/rpm/Packages) on pre-RHEL-8 / CentOS-7 /
          Amazon-Linux-2 images. Off by default; preserves
          milestone-003 behaviour (diagnostic log, zero components).
          Can also be enabled via MIKEBOM_INCLUDE_LEGACY_RPMDB=1.
```

---

## Exit codes

No new exit codes. The milestone reuses the existing contract:

| Condition | Exit code | Stderr |
|---|---|---|
| Successful scan (any component count, including zero) | `0` | Empty or info-level tracing |
| Fatal error (path not readable, image tarball corrupt) | `1` | Error message to stderr |
| Fail-closed reader error (npm v1 / cargo v1/v2 — unchanged from milestone 003) | `3` | Specific refusal message |

**New reader errors** (malformed `.rpm`, malformed BDB, malformed binary) are NOT fail-closed per FR-017 / FR-019b / FR-007. They emit a single WARN log line naming the file and zero components for that file, but exit code remains `0` and other files in the scan root are processed normally (SC-008).

---

## Stderr shape

### `.rpm` malformed (FR-017, SC-008)

```
WARN mikebom::scan_fs::package_db::rpm_file: skipping malformed .rpm file path=/abs/path/to/bad.rpm reason="header-index count exceeds cap"
```

- One line per malformed file.
- `reason` is a short snake-kebab-case string from a closed enum: `"bad-magic"`, `"truncated-lead"`, `"truncated-header"`, `"header-index count exceeds cap"`, `"size-cap-exceeded"`.
- Tests assert both the substring `"skipping malformed .rpm file"` and the specific `reason` on fixture-driven malformed inputs.

### BDB malformed / size-cap / budget-exceeded (FR-019b, US4 AS-4)

```
WARN mikebom::scan_fs::package_db::rpmdb_bdb: skipping malformed BDB rpmdb path=/abs/path/to/rootfs/var/lib/rpm/Packages reason="corrupt-hash-page"
WARN mikebom::scan_fs::package_db::rpmdb_bdb: BDB iteration budget exceeded path=... rows_collected=N budget_ms=2000
```

### BDB flag-unset path (US4 AS-1)

```
WARN mikebom::scan_fs::package_db::rpm: detected legacy rpmdb (Berkeley DB) — BDB is not supported unless --include-legacy-rpmdb is set path=/abs/path/to/rootfs/var/lib/rpm/Packages
```

Matches the milestone-003 text closely (current text says "not supported in this mikebom version"); R10 adjusts it to reference the flag.

### BDB transitional-both config (US4 AS-3, Edge Case)

```
INFO mikebom::scan_fs::package_db::rpmdb_bdb: rootfs contains both rpmdb.sqlite and BDB Packages; sqlite wins, skipping BDB
```

### Binary parse-limit fired (FR-007)

```
WARN mikebom::scan_fs::binary::elf: binary parse limit hit path=/abs/path reason="section-count-cap"
```

Corresponding `mikebom:binary-parse-limit` property set on the file-level component for transparency.

### Binary format skip (US2 AS-6, Edge Case: non-binary file)

No log line. Non-binary files are silently skipped.

---

## Flag-compatibility matrix

| Flag | Interaction with `--include-legacy-rpmdb` |
|---|---|
| `--offline` | Independent. BDB reader is offline-clean regardless. |
| `--include-dev` | Independent. RPM ecosystem doesn't distinguish dev deps. |
| `--no-package-db` | Takes precedence. `--no-package-db` disables both sqlite AND BDB paths regardless of `--include-legacy-rpmdb`. |
| `--no-hashes` | Independent. |
| `--no-deep-hash` | Independent. |
| `--max-file-size` | Applies to file-walker candidate selection. Does NOT change the BDB reader's internal 200 MB `Packages` file-size cap or the `.rpm` reader's 200 MB cap. |
| `--path` vs `--image` | Both work. Image extraction produces a rootfs; BDB reader probes `var/lib/rpm/Packages` under it. |

---

## Backward compatibility

All existing milestone-001 / 002 / 003 CLI invocations continue to work unchanged. The new flag is additive. The retrofit of `mikebom:evidence-kind = "rpmdb-sqlite"` on milestone-003 sqlite-rpmdb components adds a property but doesn't remove any existing output; consumers that don't know the property simply ignore it.

**Breaking-change audit**: zero. Every output field present in a milestone-003 SBOM remains present, with the same value, in a milestone-004 SBOM of the same target.
