# CLI Contract: PURL & Scope Alignment

**Feature**: `005-purl-and-scope-alignment`

This feature does NOT add, rename, or remove any CLI flags, environment variables, or subcommands. The CLI surface remains exactly as it was before this feature landed.

## Invariants

- **No new flags**. `mikebom sbom scan` continues to accept `--image <tarball>`, `--path <dir>`, `--output <file>`, `--no-deep-hash`, and existing helpers. No flag named `--npm-internals`, `--include-tool-internals`, `--distro-id`, or similar is introduced.
- **No new environment variables**. Scan mode inference is derived entirely from which of `--image` / `--path` is passed.
- **Existing invocations produce corrected output without modification**. An operator running `mikebom sbom scan --image fedora40.tar -o out.cdx.json` before and after this feature lands uses the same command line; only the content of `out.cdx.json` differs (see `cyclonedx-output.md` for the specific differences).
- **`--deb-codename` flag remains accepted but its effect is narrowed**. After this change, `--deb-codename` (if it exists today for the deb reader) no longer influences the `distro=` qualifier — that now derives from `<os-release::ID>-<os-release::VERSION_ID>`. If the flag is kept for backward compatibility, document that it's advisory-only; if removed, note the removal in release notes. (Implementation-phase decision; plan defers.)

## Exit codes

No changes. `0` on success, non-zero on hard failure per existing conventions. Missing `/etc/os-release` does NOT produce a non-zero exit; it's a soft-degrade per FR-006 / FR-009.

## Output paths

No changes. SBOM path is the value passed via `--output` as before.

## Stderr / log format

Warnings emitted by FR-006 / FR-009 use the existing `tracing::warn!` pathway. Log format is unchanged. Structured log fields for the new warnings:

```text
mikebom::scan_fs::package_db: WARN /etc/os-release missing field ID; falling back to deb namespace 'debian'
mikebom::scan_fs::package_db: WARN /etc/os-release missing field VERSION_ID; omitting distro= qualifier
```

Both warnings are emitted at most once per scan.

## Compatibility

- **Old CLI invocations continue to work** — same flags, same output file paths.
- **Consumers keying on old PURL strings break**. This is a documented breaking change. Release notes must call it out per FR-017.
- **Programmatic callers (library users)** — none today, but if mikebom ever exposes a library API, this feature's signature changes to `scan_path`, `package_db::read_all`, and `dpkg::read` will be source-breaking. Acceptable because mikebom is a CLI-first project per Constitution VI.
