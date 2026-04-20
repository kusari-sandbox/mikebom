# Quickstart — Milestone 003 (Multi-Ecosystem Expansion)

Smoke-test recipe for reviewers. Assumes `cargo build --release` completed successfully on `main` after merge. All commands should be run from the repo root.

## Prerequisites

- Rust stable (matches workspace compiler).
- `jq` for output inspection (any version).
- Python 3 with `packageurl-python` installed (for PURL conformance checks):
  ```bash
  python3 -m pip install packageurl-python
  ```
- Optional: Go toolchain (≥1.21) for regenerating binary fixtures; otherwise use the checked-in binaries.

## Scenario 1 — Scan a Go source project (US1 primary flow)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/go/simple-module \
  --output /tmp/mikebom-go.json \
  --offline \
  --no-deep-hash

jq '.components[].purl | select(startswith("pkg:golang/"))' /tmp/mikebom-go.json
```

**Expected:** Five `pkg:golang/<module>@<version>` strings, one per entry in `tests/fixtures/go/simple-module/go.sum`. Every PURL round-trips through the packageurl reference impl:

```bash
jq -r '.components[].purl | select(startswith("pkg:golang/"))' /tmp/mikebom-go.json \
  | python3 -c "import sys; from packageurl import PackageURL; [print(PackageURL.from_string(p.strip()).to_string() == p.strip()) for p in sys.stdin]"
# should print: True (five times)
```

## Scenario 2 — Scan a Go binary (US1 distroless path)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/go/binaries/hello-linux-amd64 \
  --output /tmp/mikebom-go-bin.json \
  --offline

jq '.components | length' /tmp/mikebom-go-bin.json
jq '.compositions[] | select(.assemblies[0] | startswith("pkg:golang/"))' /tmp/mikebom-go-bin.json
```

**Expected:** Component count matches the binary's embedded BuildInfo module set (~3 for the minimal `hello-world` fixture, including the main module + a few standard stdlib deps). The compositions record shows `aggregate: complete` for `golang`.

## Scenario 3 — Scan a synthetic RHEL rootfs (US2)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/rpm/rhel-image \
  --output /tmp/mikebom-rpm.json \
  --offline \
  --no-deep-hash

jq '.components[] | select(.purl | startswith("pkg:rpm/")) | {name, purl, license: .licenses[0].license.expression}' /tmp/mikebom-rpm.json
```

**Expected:** One `pkg:rpm/redhat/...` per installed package in the rpmdb.sqlite fixture (≥10 rows). Every component has a populated license field — verifies FR-023. The PURL vendor segment is `redhat` because the fixture's `/etc/os-release::ID=rhel` triggers the explicit map.

## Scenario 4 — Scan a Cargo workspace (US4)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/cargo/lockfile-v3 \
  --output /tmp/mikebom-cargo.json \
  --offline

jq '[.components[] | select(.purl | startswith("pkg:cargo/"))] | length' /tmp/mikebom-cargo.json
jq '.components[] | select(.purl | startswith("pkg:cargo/")) | select(.hashes != null and (.hashes | length > 0))' /tmp/mikebom-cargo.json | head -20
```

**Expected:** Component count matches the `[[package]]` entry count in `Cargo.lock`. Registry-sourced crates have `hashes[]` with a SHA-256 entry; git-sourced crates don't (FR-042, FR-043).

## Scenario 5 — Scan a Gemfile.lock-only project (US5)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/gem/simple-bundle \
  --output /tmp/mikebom-gem.json \
  --offline

jq '.components[] | select(.purl | startswith("pkg:gem/")) | {name, purl, properties: .properties}' /tmp/mikebom-gem.json
```

**Expected:** One `pkg:gem/<name>@<version>` per gem in the `GEM` + `GIT` + `PATH` sections. `GIT` / `PATH` entries carry the `mikebom:source-type` property.

## Scenario 6 — Scan a Maven project (US3 pom.xml)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/maven/pom-three-deps \
  --output /tmp/mikebom-maven.json \
  --offline

jq '[.components[] | select(.purl | startswith("pkg:maven/"))] | length' /tmp/mikebom-maven.json
# should be 3: guava + commons-lang3 + junit
```

## Scenario 7 — Scan a fat JAR (US3 JAR path)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/maven/fat-jar-three-vendored.jar \
  --output /tmp/mikebom-fatjar.json \
  --offline

jq '.components[] | select(.purl | startswith("pkg:maven/")) | select(.properties[]?.value == "analyzed")' /tmp/mikebom-fatjar.json
```

**Expected:** Three Maven components from the vendored `META-INF/maven/*/pom.properties` files, tier `analyzed`.

## Scenario 8 — Polyglot scan (SC-007)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/polyglot-five \
  --output /tmp/mikebom-polyglot.json \
  --offline \
  --no-deep-hash

jq '
  .components
  | group_by(.purl | split("/")[0])
  | map({ ecosystem: .[0].purl | split("/")[0], count: length })
' /tmp/mikebom-polyglot.json
```

**Expected:** A summary showing all five new ecosystems represented, plus pypi + npm from the reused milestone-002 fixtures. Component counts match per-ecosystem expectations.

## Scenario 9 — Cargo v1 refusal (FR-040 contract)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/cargo/lockfile-v1-refused \
  --output /tmp/should-not-exist.json \
  --offline 2>&1 | tee /tmp/stderr.log

echo "exit code: $?"
grep -c "Cargo.lock v1/v2 not supported" /tmp/stderr.log
test ! -e /tmp/should-not-exist.json && echo "no SBOM written OK"
```

**Expected:** Exit code ≠ 0; stderr contains the actionable message; no SBOM file written.

## Scenario 10 — Stripped Go binary diagnostic (FR-015)

```bash
./target/release/mikebom sbom scan \
  --path tests/fixtures/go/binaries/stripped-hello-linux-amd64 \
  --output /tmp/mikebom-stripped.json \
  --offline

jq '.components[] | select(.properties[]?.name == "mikebom:buildinfo-status")' /tmp/mikebom-stripped.json
```

**Expected:** One file-level component with `mikebom:buildinfo-status` property = `"missing"` or `"unsupported"`. Scan exits 0.

## Regenerating Go binary fixtures

```bash
# Requires Go ≥1.21
cd tests/fixtures/go/binaries
GOOS=linux GOARCH=amd64 go build -o hello-linux-amd64 ./src
GOOS=darwin GOARCH=arm64 go build -o hello-darwin-arm64 ./src
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o stripped-hello-linux-amd64 ./src
strip stripped-hello-linux-amd64 2>/dev/null || true
```

If Go isn't installed, the checked-in binaries work as-is; just don't modify the `src/` entry point, since the BuildInfo module list is asserted at known values in the integration tests.

## Full workspace test sweep

```bash
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
```

**Expected:** Zero failures, zero warnings. Integration tests include all new `scan_go.rs`, `scan_rpm.rs`, `scan_maven.rs`, `scan_cargo.rs`, `scan_gem.rs`, `scan_five_ecosystem_polyglot.rs`, and `scan_rhel_go_image.rs`.
