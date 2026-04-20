# Quickstart: PURL & Scope Alignment

**Feature**: `005-purl-and-scope-alignment`
**Purpose**: how to run and verify the post-implementation behaviour end-to-end on four canonical fixtures.

## Build

```sh
cargo build --release -p mikebom
```

## Verify US1 — scan-mode-aware npm scoping

### Image scan includes npm internals

```sh
# From the conformance fixture directory
./target/release/mikebom sbom scan \
  --image /tmp/node-20-slim.tar \
  --output /tmp/node-image.cdx.json

# Count npm internal components — expect > 100 on a full node image
jq '[.components[] | .properties[]? | select(.name=="mikebom:npm-role" and .value=="internal")] | length' /tmp/node-image.cdx.json
```

Expected: the count is strictly positive.

### Directory scan excludes npm internals

```sh
./target/release/mikebom sbom scan \
  --path /tmp/some-node-project-with-vendored-npm/ \
  --output /tmp/node-project.cdx.json

# Same count — expect zero
jq '[.components[] | .properties[]? | select(.name=="mikebom:npm-role" and .value=="internal")] | length' /tmp/node-project.cdx.json
```

Expected: 0.

## Verify US2 — deb `distro=ID-VERSION_ID` qualifier

```sh
./target/release/mikebom sbom scan \
  --path /path/to/extracted/debian-bookworm-rootfs \
  --output /tmp/debian.cdx.json

# Every deb PURL's distro qualifier should equal "debian-12"
jq -r '[.components[] | select(.purl | startswith("pkg:deb/"))
         | .purl
         | capture("distro=(?<d>[^&]+)").d] | unique | .[]' /tmp/debian.cdx.json
```

Expected output:

```text
debian-12
```

Exactly one unique value. Any other value is a bug.

## Verify US3 — deb PURL namespace from `/etc/os-release::ID`

```sh
./target/release/mikebom sbom scan \
  --path /path/to/extracted/ubuntu-24.04-rootfs \
  --output /tmp/ubuntu.cdx.json

# Every deb PURL should start with pkg:deb/ubuntu/
jq -r '[.components[] | select(.purl | startswith("pkg:deb/")) | .purl[:14]] | unique | .[]' /tmp/ubuntu.cdx.json
```

Expected output:

```text
pkg:deb/ubuntu
```

Exactly one unique prefix. The string `pkg:deb/debian` must NOT appear for Ubuntu inputs.

## Verify US4 — rpm version alignment with `rpm -qa`

```sh
# Run a Fedora 40 container matching the polyglot-builder-image fixture
docker run --rm sbom-fixture-polyglot rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' \
  | sort > /tmp/rpm-qa-actual.txt

# Scan the same image with mikebom
./target/release/mikebom sbom scan --image /tmp/polyglot.tar --output /tmp/polyglot.cdx.json

# Extract name + version from the CDX
jq -r '[.components[] | select(.purl | startswith("pkg:rpm/")) | "\(.name) \(.version)"] | sort | .[]' \
  /tmp/polyglot.cdx.json > /tmp/mikebom-rpm.txt

# Diff — expect < 5 mismatches
diff /tmp/rpm-qa-actual.txt /tmp/mikebom-rpm.txt | grep -c '^[<>]'
```

Expected: < 5 (SC-006). The raw rpmdb header values are also accessible via the `mikebom:raw-version` property for round-trip confirmation:

```sh
jq -r '.components[] | select(.purl | startswith("pkg:rpm/"))
         | .properties[]? | select(.name == "mikebom:raw-version") | .value' \
  /tmp/polyglot.cdx.json | head
```

## Verify SC-009 — os-release missing-fields metadata

Create a minimal rootfs with `/etc/os-release` absent:

```sh
mkdir -p /tmp/noosrelease/var/lib/dpkg
touch /tmp/noosrelease/var/lib/dpkg/status
./target/release/mikebom sbom scan --path /tmp/noosrelease --output /tmp/degraded.cdx.json

# The metadata property should be present and list the missing fields
jq -r '.metadata.properties[] | select(.name == "mikebom:os-release-missing-fields") | .value' /tmp/degraded.cdx.json
```

Expected output:

```text
ID,VERSION_ID
```

Running the same scan on a proper rootfs (e.g., the debian-bookworm fixture) should produce no such property:

```sh
jq '[.metadata.properties[] | select(.name == "mikebom:os-release-missing-fields")] | length' /tmp/debian.cdx.json
```

Expected: `0`.

## Regression guards — SC-004, SC-007

Before landing the implementation, capture baseline CDX files for the alpine and rpm fixtures. After landing, diff the PURL sets for byte-equality:

```sh
# Pre-change baseline
./target/release/mikebom sbom scan --path /tmp/alpine-3.20-rootfs \
  --output /tmp/alpine-before.cdx.json
./target/release/mikebom sbom scan --path /tmp/rocky-9-rootfs \
  --output /tmp/rocky-before.cdx.json

# After landing
./target/release/mikebom sbom scan --path /tmp/alpine-3.20-rootfs \
  --output /tmp/alpine-after.cdx.json
./target/release/mikebom sbom scan --path /tmp/rocky-9-rootfs \
  --output /tmp/rocky-after.cdx.json

# PURL sets must be byte-identical
diff <(jq -r '[.components[].purl] | sort | .[]' /tmp/alpine-before.cdx.json) \
     <(jq -r '[.components[].purl] | sort | .[]' /tmp/alpine-after.cdx.json)
diff <(jq -r '[.components[].purl] | sort | .[]' /tmp/rocky-before.cdx.json) \
     <(jq -r '[.components[].purl] | sort | .[]' /tmp/rocky-after.cdx.json)
```

Expected: no output (empty diffs).

## Full conformance pass

```sh
cd /Users/mlieberman/Projects/sbom-conformance
# Run the full fixture matrix against mikebom
./run-conformance-suite.sh mikebom /tmp/mikebom-run
# Compare pre- and post- feature runs
./diff-runs.sh <previous-run-id> /tmp/mikebom-run
```

Acceptance: every SC-NNN line in `spec.md::Success Criteria` is met. No fixture that was previously clean (MISSING=0, FP=0) regresses into an unclean state.

## Running the tests

```sh
# Full workspace — expect all existing tests + new tests per user story
cargo test --workspace

# Specifically the PURL-format tests
cargo test -p mikebom --bin mikebom -- scan_fs::package_db::dpkg
cargo test -p mikebom --bin mikebom -- scan_fs::package_db::npm
cargo test -p mikebom --bin mikebom -- scan_fs::package_db::rpm
cargo test -p mikebom --bin mikebom -- scan_fs::os_release

# Integration tests
cargo test --test scan_binary
```

Expected: all tests pass.
