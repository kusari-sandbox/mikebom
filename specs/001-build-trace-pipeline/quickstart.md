# Quickstart: mikebom

## Prerequisites

- Rust toolchain (stable + nightly for eBPF target)
- Internet access for deps.dev API (resolution/enrichment only)
- **For tracing (scan/run)**: Linux kernel 5.8+ with root or CAP_BPF
- **For non-tracing (generate/enrich/validate)**: Any OS (macOS, Linux)

## macOS Development Setup

eBPF requires Linux. On macOS, use the provided Lima VM config:

```bash
# Start the development VM (provisions Ubuntu 24.04 + Rust + eBPF tools)
limactl start ./lima.yaml

# Open a shell in the VM (workspace is auto-mounted)
limactl shell mikebom

# Inside the VM: build and run tracing commands
cd /Users/<you>/Projects/mikebom
cargo xtask ebpf
cargo build --release
sudo RUST_LOG=info target/release/mikebom scan -- <build-command>
```

Non-tracing commands work natively on macOS:

```bash
# These do NOT need eBPF or root — run directly on macOS
cargo build --release
target/release/mikebom generate build.attestation.json
target/release/mikebom enrich build.cdx.json
target/release/mikebom validate build.cdx.json
cargo test --workspace
```

## Build

```bash
# Build eBPF kernel programs (Linux only — use Lima VM on macOS)
cargo xtask ebpf

# Build user-space application (works on macOS and Linux)
cargo build --release
```

## Basic Usage

### Trace a build and produce an attestation

```bash
# Trace an inline build command
sudo RUST_LOG=info target/release/mikebom scan \
  --output build.attestation.json \
  -- cargo build --release

# Or trace an already-running process
sudo RUST_LOG=info target/release/mikebom scan \
  --target-pid 12345 \
  --output build.attestation.json
```

### Generate SBOM from attestation

```bash
# Generate CycloneDX 1.6 SBOM (no root needed)
target/release/mikebom generate \
  --format cyclonedx-json \
  --output build.cdx.json \
  build.attestation.json

# Generate with enrichment (license, VEX, supplier data)
target/release/mikebom generate \
  --enrich \
  --output build.cdx.json \
  build.attestation.json

# Generate SPDX instead
target/release/mikebom generate \
  --format spdx-json \
  --output build.spdx.json \
  build.attestation.json
```

### All-in-one (trace + resolve + enrich + generate)

```bash
sudo RUST_LOG=info target/release/mikebom run \
  --sbom-output build.cdx.json \
  --attestation-output build.attestation.json \
  -- cargo build --release
```

### Enrich an existing SBOM

```bash
# Add license and vulnerability data
target/release/mikebom enrich \
  --output enriched.cdx.json \
  build.cdx.json
```

### Validate outputs

```bash
# Validate attestation
target/release/mikebom validate build.attestation.json

# Validate SBOM (checks schema + PURL conformance + CISA 2025)
target/release/mikebom validate --strict build.cdx.json
```

## Development

```bash
# Run all unit tests (no root needed)
cargo test --workspace

# Run linter
cargo clippy --all-targets --all-features -- -D warnings

# Check formatting
cargo fmt -- --check
```

## Verifying the Output

After generating an SBOM, verify:

1. **Schema conformance**: `mikebom validate --strict build.cdx.json`
2. **Component count**: Check that the SBOM contains the expected number
   of dependencies for your project
3. **Completeness metadata**: Look for the `compositions` section — it
   tells you whether any trace data was lost
4. **Evidence**: Each component should have an `evidence.identity` section
   showing how it was detected and at what confidence
