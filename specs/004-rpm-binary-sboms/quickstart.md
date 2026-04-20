# Quickstart — Milestone 004 Reviewer Smoke Test

End-to-end verification recipe for a reviewer who has just pulled this branch. Every step is copy-pasteable from a clean `cargo` workspace with no fixtures set up.

---

## Prerequisites

- Rust stable toolchain (same as milestones 001–003).
- Optional: `x86_64-pc-windows-gnu` target for PE fixture regeneration (`rustup target add x86_64-pc-windows-gnu`). Not needed to run tests; checked-in PE fixtures cover CI.
- Optional: Python 3 with `packageurl-python` installed for manual PURL round-trip probes (`pip install packageurl-python`). CI tests embed this.

---

## Build

```sh
cargo build --release --workspace
```

No new feature flags. The workspace builds on stable Rust; milestone-004 only bumps the `object` dep's feature list in `mikebom-cli/Cargo.toml` and (conditionally) adds the `rpm` crate per R1.

---

## Regenerate heavy fixtures (only if missing)

```sh
# Pull the small set of real .rpm files from public mirrors (one-shot; committed after).
# tests/fixtures/rpm-files/README.md documents each URL + sha256.
./tests/fixtures/rpm-files/refresh.sh

# Compile PE fixtures (if absent). No-op if the checked-in .exe files exist.
./tests/fixtures/binaries/pe/rebuild.sh
```

Both scripts are idempotent. In CI, the checked-in fixtures suffice and neither script runs.

---

## Run the full test suite

```sh
cargo test --workspace
```

Expected baseline: 585 passing (milestone 003) + milestone-004 additions. Integration tests under `mikebom-cli/tests/`:

- `scan_rpm_file.rs` — US1: scans `tests/fixtures/rpm-files/` and asserts 7 components (5 real `.rpm` + 1 SRPM + deduplicated entries), every PURL round-trips.
- `scan_binary_elf.rs` — US2 ELF slice: DT_NEEDED, `.note.package`, stripped detection, version-string scanner false-positive control.
- `scan_binary_macho.rs` — US2 Mach-O slice: LC_LOAD_DYLIB, fat (universal) slice handling.
- `scan_binary_pe.rs` — US2 PE slice: IMPORT + Delay-Load IMPORT, four-signal stripped detection.
- `scan_binary_version_strings.rs` — curated scanner against positive fixtures + SC-005 control set.
- `scan_rpm_and_binary_polyglot.rs` — US3 polyglot: 5 `.rpm` + 5 ELF + 3 Mach-O + 3 PE in one invocation.
- `scan_bdb_rpmdb.rs` — US4 opt-in BDB: flag-off behaviour, flag-on activation, sqlite-wins, malformed-BDB graceful.

Also expected to pass: every pre-existing milestone-001/002/003 test. No regressions.

---

## Manual smoke test — P1 `.rpm` file reader

```sh
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/rpm-files/ \
  --output /tmp/milestone4-rpm-files.cdx.json

jq '.components | length' /tmp/milestone4-rpm-files.cdx.json
# Expect: 7 (5 real RPMs + 1 SRPM + 1 from dedup; malformed .rpm yields zero)

jq -r '.components[].purl' /tmp/milestone4-rpm-files.cdx.json | sort
# Expect canonical PURLs; every one should begin with "pkg:rpm/"

jq '.components[] | select(.purl | startswith("pkg:rpm/")) | .properties[] | select(.name == "mikebom:evidence-kind") | .value' \
  /tmp/milestone4-rpm-files.cdx.json | sort -u
# Expect: "rpm-file"

# Check the scan emitted exactly one WARN line for the malformed fixture
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/rpm-files/ \
  --output /tmp/x.cdx.json 2>&1 >/dev/null | grep -c "skipping malformed .rpm file"
# Expect: 1
```

---

## Manual smoke test — P2 Generic-binary reader

```sh
# ELF slice
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/binaries/elf/ \
  --output /tmp/milestone4-elf.cdx.json

jq '.components[] | select(.properties[]?.name == "mikebom:binary-class")' \
  /tmp/milestone4-elf.cdx.json | jq -s 'length'
# Expect: 6 (one file-level per ELF fixture)

# Linkage-evidence components emitted by ELF (deduped globally)
jq '.components[] | select(.properties[]?.value == "dynamic-linkage") | .purl' \
  /tmp/milestone4-elf.cdx.json
# Expect: pkg:generic/libc.so.6, pkg:generic/libssl.so.3, pkg:generic/libcrypto.so.3 …

# Distro-authoritative ELF-note-package component
jq '.components[] | select(.properties[]?.value == "elf-note-package") | .purl' \
  /tmp/milestone4-elf.cdx.json
# Expect: pkg:rpm/fedora/curl@8.2.1?arch=x86_64 (from with-note-package-rpm fixture)

# Heuristic embedded-version-string hit
jq '.components[] | select(.properties[]?.value == "embedded-version-string") | .purl' \
  /tmp/milestone4-elf.cdx.json
# Expect: pkg:generic/openssl@3.0.11

# SC-005 control: Rust binary that mentions OpenSSL in .comment — MUST NOT produce a pkg:generic/openssl component
jq '.components[] | select(.purl == "pkg:generic/openssl@3.0.11") | .evidence.occurrences[].location' \
  /tmp/milestone4-elf.cdx.json
# Expect: NOT the false-positive-control-rust-bin path; only the openssl-embed-3.0.11 path.

# Mach-O slice (on macOS host, or using checked-in aarch64-apple-darwin fixtures)
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/binaries/macho/ \
  --output /tmp/milestone4-macho.cdx.json

jq '.components[] | select(.properties[]?.value == "macho") | .name' /tmp/milestone4-macho.cdx.json
# Expect the Mach-O fixture filenames

# PE slice
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/binaries/pe/ \
  --output /tmp/milestone4-pe.cdx.json

jq '.components[] | select(.properties[]?.value == "pe") | .name' /tmp/milestone4-pe.cdx.json
# Expect the PE fixture filenames (dyn-linked-win64.exe, with-delay-load.exe, static-stripped.exe)

jq '.components[] | select(.purl | startswith("pkg:generic/kernel32")) | .evidence.occurrences | length' \
  /tmp/milestone4-pe.cdx.json
# Expect a small integer — one occurrence per PE that imports kernel32.dll
```

---

## Manual smoke test — P3 Polyglot (US3)

```sh
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/polyglot-rpm-binary/ \
  --output /tmp/milestone4-polyglot.cdx.json

jq '.components | length' /tmp/milestone4-polyglot.cdx.json
# Expect ≥ 21 (5 rpm + 5 elf file-level + 3 macho file-level + 3 pe file-level + dedup'd linkage + possibly embedded-string hits)

jq '.compositions[] | select(.aggregate == "incomplete_first_party_only")' /tmp/milestone4-polyglot.cdx.json
# Expect an entry with rpm assemblies (fixture has no rpmdb, only .rpm files)

jq '[.components[] | select(.properties[]?.name == "mikebom:evidence-kind") | .properties[] | select(.name == "mikebom:evidence-kind") | .value] | sort | unique' \
  /tmp/milestone4-polyglot.cdx.json
# Expect: ["dynamic-linkage", "elf-note-package", "embedded-version-string", "rpm-file"]
# (rpmdb-* evidence-kinds absent because there's no rpmdb in this fixture)
```

---

## Manual smoke test — P3 Legacy BDB (US4)

```sh
# Flag-off: existing milestone-003 behaviour
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/bdb-rpmdb/amzn2-minimal/ \
  --output /tmp/milestone4-bdb-off.cdx.json 2>&1 | grep "legacy rpmdb"
# Expect: one WARN line mentioning --include-legacy-rpmdb

jq '[.components[] | select(.purl | startswith("pkg:rpm/"))] | length' /tmp/milestone4-bdb-off.cdx.json
# Expect: 0

# Flag-on: activate BDB reader
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/bdb-rpmdb/amzn2-minimal/ \
  --include-legacy-rpmdb \
  --output /tmp/milestone4-bdb-on.cdx.json

jq '[.components[] | select(.purl | startswith("pkg:rpm/"))] | length' /tmp/milestone4-bdb-on.cdx.json
# Expect ≥ 20 (matches the fixture's installed package count within 2% per SC-012)

jq '.components[] | select(.purl | startswith("pkg:rpm/")) | .properties[] | select(.name == "mikebom:evidence-kind") | .value' \
  /tmp/milestone4-bdb-on.cdx.json | sort -u
# Expect: "rpmdb-bdb"

# Transitional config — both formats, sqlite wins
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/bdb-rpmdb/transitional-both/ \
  --include-legacy-rpmdb \
  --output /tmp/milestone4-bdb-transitional.cdx.json 2>&1 | grep "sqlite wins"
# Expect: one INFO line

jq '.components[] | select(.purl | startswith("pkg:rpm/")) | .properties[] | select(.name == "mikebom:evidence-kind") | .value' \
  /tmp/milestone4-bdb-transitional.cdx.json | sort -u
# Expect: "rpmdb-sqlite" only (BDB skipped per FR-019c)

# Env-var alternative
MIKEBOM_INCLUDE_LEGACY_RPMDB=1 ./target/release/mikebom sbom scan \
  --path ./tests/fixtures/bdb-rpmdb/amzn2-minimal/ \
  --output /tmp/milestone4-bdb-env.cdx.json

# Expect the same output as the --include-legacy-rpmdb invocation
diff <(jq -S '.components' /tmp/milestone4-bdb-on.cdx.json) \
     <(jq -S '.components' /tmp/milestone4-bdb-env.cdx.json)
# Expect: no diff
```

---

## Manual smoke test — CGo binary coexistence (Q3 verification)

```sh
# A Go binary that also DT_NEEDEDs libc (CGo-linked)
./target/release/mikebom sbom scan \
  --path ./tests/fixtures/go/binaries/hello-cgo-linux-amd64 \
  --output /tmp/milestone4-cgo.cdx.json

jq '[.components[] | select(.properties[]?.name == "mikebom:detected-go")] | length' \
  /tmp/milestone4-cgo.cdx.json
# Expect: 1 (single file-level component with detected-go = true)

jq '[.components[] | select(.purl | startswith("pkg:golang/"))] | length' \
  /tmp/milestone4-cgo.cdx.json
# Expect: ≥ 1 (top-level Go modules)

jq '[.components[] | select(.purl | startswith("pkg:generic/lib"))] | length' \
  /tmp/milestone4-cgo.cdx.json
# Expect: ≥ 1 (top-level linkage evidence — libc.so.6 etc.)
```

---

## PURL round-trip probe (SC-007)

```sh
# Extract every PURL produced by milestone-004 evidence-kinds and feed into packageurl-python
python3 - <<'PY'
import json, sys
from packageurl import PackageURL
count, failed = 0, []
for f in [
    "/tmp/milestone4-rpm-files.cdx.json",
    "/tmp/milestone4-elf.cdx.json",
    "/tmp/milestone4-macho.cdx.json",
    "/tmp/milestone4-pe.cdx.json",
    "/tmp/milestone4-bdb-on.cdx.json",
]:
    sbom = json.load(open(f))
    for c in sbom.get("components", []):
        purl = c.get("purl")
        if not purl:
            continue
        try:
            rt = PackageURL.from_string(purl).to_string()
            if rt != purl:
                failed.append((purl, rt))
            count += 1
        except Exception as e:
            failed.append((purl, str(e)))
print(f"tested={count}, failures={len(failed)}")
for pair in failed[:20]:
    print("  failure:", pair)
sys.exit(1 if failed else 0)
PY
# Expect: tested > 50, failures = 0
```

---

## Performance smoke (SC-013)

```sh
time ./target/release/mikebom sbom scan \
  --path ./tests/fixtures/polyglot-rpm-binary/ \
  --output /tmp/milestone4-perf.cdx.json
# Expect wall-clock < 15 s on a modern laptop
```

---

## Exit checklist for reviewers

- [ ] `cargo test --workspace` passes on stable Rust (no regressions vs milestone 003).
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (`#![deny(clippy::unwrap_used)]` enforced at crate root).
- [ ] All manual probes above match their expected outputs on a clean machine.
- [ ] Milestone-003 SBOMs continue to produce identical output for their target fixtures (backward-compat regression — run `scan_rpm.rs` + `scan_rhel_go_image.rs` and diff against golden files, excluding the new `mikebom:evidence-kind` property).
- [ ] `research.md` R1's `rpm`-crate audit outcome is documented either as "adopted" or "fell back to in-house"; corresponding code reflects the choice.
- [ ] `docs/design-notes.md` is updated with a new "Ecosystem coverage" row for the `.rpm`-file reader and with the BDB-opt-in sharp edge noted.
