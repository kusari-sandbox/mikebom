# CLI Contract — Milestone 003

mikebom's `sbom scan` CLI surface does NOT grow new flags in this milestone. All five new ecosystems activate automatically when the scanner detects their project markers. The only contractual changes are (a) one new non-zero exit condition (Cargo.lock v1/v2 refusal, mirroring the npm v1 pattern) and (b) a handful of new stderr diagnostic strings that are testable.

## Flag compatibility matrix

| Flag | Go source | Go binary | RPM | Maven | Cargo | Gem |
|---|---|---|---|---|---|---|
| `--offline` | ✅ honoured (enrichment only via deps.dev when not set) | ✅ honoured | ✅ always offline (no network surface) | ✅ deps.dev Maven enrichment gated on this | ✅ deps.dev Cargo enrichment gated | ✅ always offline |
| `--include-dev` | ignored (Go has no dev/prod) | ignored | ignored | observed (`<scope>test</scope>` gated) | ignored (Cargo dev-deps live in Cargo.toml, not Cargo.lock) | ignored (Gemfile.lock doesn't carry dev/prod split) |
| `--no-package-db` | applies — disables all package-db readers including the 5 new ones | same | same | same | same | same |
| `--no-deep-hash` | unaffected (Go modules don't have the file-level hash flow dpkg has) | unaffected | **may** be affected — future rpmdb per-file hash work is a follow-up | unaffected | unaffected | unaffected |
| `--deb-codename` | unrelated | unrelated | unrelated | unrelated | unrelated | unrelated |

## New error conditions + exit codes

### Cargo.lock v1/v2 refusal (FR-040)

**Trigger:** a scanned project root contains a `Cargo.lock` declaring `version = 1` or `version = 2`.

**Behaviour:**
- Scan aborts with non-zero exit code (mirror npm v1 refusal — same `2` chosen for parity).
- Stderr contains the exact string: `error: Cargo.lock v1/v2 not supported; regenerate with cargo ≥1.53`.
- No SBOM file is written.
- If ANY other Cargo.lock in a different project root succeeds, the refusal still fires. The SBOM is NOT written partially. The user's fix is deterministic (`cargo generate-lockfile` on any Rust ≥1.53).

**Integration test contract:** `scan_cargo_v1_lockfile_refuses_with_actionable_error` — checks process exit code ≠ 0, stderr contains the message, no output file written.

### Stripped Go binary diagnostic (FR-015)

**Trigger:** a scanned file is detected as a Go binary (ELF or Mach-O with a Go build ID or `.go.buildinfo` section name) but BuildInfo extraction fails (magic missing, format version unsupported).

**Behaviour:**
- Scan succeeds (exit 0).
- One SBOM component is emitted for the binary file itself with property `mikebom:buildinfo-status = "missing"` (or `"unsupported"` for the Go <1.18 format).
- Stderr carries one `WARN`-level log line per affected binary: `warn: go binary <path> has no readable BuildInfo (<status>)`.

**Integration test contract:** `scan_go_stripped_binary_emits_diagnostic_property` — checks exit 0, SBOM contains the file-level component with the expected property value.

### rpmdb.sqlite read failure (FR-020)

**Trigger:** `/var/lib/rpm/rpmdb.sqlite` present but unparseable (corrupted, truncated, exceeds size cap, or sqlite text encoding not UTF-8).

**Behaviour:**
- Scan succeeds (exit 0).
- Zero RPM components emitted.
- Stderr carries one `WARN`-level log line: `warn: rpmdb.sqlite at <path> could not be read (<reason>) — emitting zero rpm components`.

**Integration test contract:** `scan_rpm_malformed_rpmdb_degrades_gracefully` — scan succeeds, zero rpm components, stderr contains the warning.

### Berkeley-DB rpmdb detected (FR-020)

**Trigger:** `/var/lib/rpm/Packages` (classic BDB) present AND `/var/lib/rpm/rpmdb.sqlite` absent.

**Behaviour:**
- Scan succeeds (exit 0).
- Zero RPM components emitted.
- Stderr carries one `WARN`-level log line: `warn: detected legacy rpmdb (Berkeley DB) at <path> — BDB is not supported in this mikebom version; regenerate on rpmdb.sqlite-based RHEL ≥8 to scan`.

**Integration test contract:** `scan_rpm_bdb_diagnoses_and_emits_zero` — scan succeeds, zero rpm components, stderr contains the warning.

## Stderr format for ecosystem loggers

All new readers honour the tracing setup established in milestone 001. Examples:

```text
INFO  mikebom::scan_fs::package_db::golang: parsed go.sum rootfs=/tmp/scan/svc modules=27
INFO  mikebom::scan_fs::package_db::go_binary: extracted BuildInfo binary=/tmp/scan/out/hello modules=143 go_version=go1.22.1
WARN  mikebom::scan_fs::package_db::go_binary: no readable BuildInfo binary=/tmp/scan/out/stripped status=Missing
INFO  mikebom::scan_fs::package_db::rpm: rpmdb.sqlite parsed path=/tmp/scan/var/lib/rpm/rpmdb.sqlite rows=342
ERROR mikebom::cli::scan_cmd: Cargo.lock v1/v2 not supported path=/tmp/scan/Cargo.lock version=2
WARN  mikebom::scan_fs::package_db::maven: pom.xml property unresolved placeholder=${project.version} component=com.example:app
```

## Backwards compatibility

- Every pre-existing `--flag` and exit code from milestones 001–002 retains identical semantics.
- The npm v1 refusal contract is unchanged.
- The `dpkg` / `apk` / `pypi` / `npm` readers are not modified — they continue emitting the same components with the same properties for all existing fixtures.
