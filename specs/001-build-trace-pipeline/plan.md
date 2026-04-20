# Implementation Plan: Build-Trace-to-SBOM Pipeline

**Branch**: `001-build-trace-pipeline` | **Date**: 2026-04-15 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-build-trace-pipeline/spec.md`

## Summary

mikebom is an eBPF-based SBOM generator that traces live build processes
to capture network requests and file operations, stores the raw evidence
in an in-toto attestation (the primary artifact), then resolves the
attestation data into Package URLs and generates standards-compliant
SBOMs (CycloneDX 1.6 / SPDX 3.1) with completeness signaling,
per-component detection evidence, and optional enrichment (licenses, VEX).

The attestation-first architecture follows the SBOMit pattern: the SBOM
is a derived view of the attestation, not the primary output. This
decoupling enables re-generation without re-tracing, multi-format
output, and forensic analysis beyond what fits in an SBOM.

## Technical Context

**Language/Version**: Rust stable (user-space) + nightly (eBPF target via `aya-ebpf`)
**Primary Dependencies**: aya, aya-ebpf, aya-build, tokio, clap, reqwest, serde/serde_json, cyclonedx-bom, packageurl, sha2, chrono, thiserror, anyhow, tracing
**Storage**: Filesystem — attestation JSON files, SBOM JSON/XML files
**Testing**: `cargo test --workspace` (unit, unprivileged); integration tests gated behind CAP_BPF/root; mock eBPF event generators for CI
**Target Platform**: Linux kernel 5.8+ (eBPF tracing); generate/enrich/validate may work cross-platform
**Project Type**: CLI tool (5 subcommands: scan, generate, enrich, run, validate)
**Performance Goals**: <30s overhead on a 5-minute build (excluding API network time)
**Constraints**: Root/CAP_BPF for tracing; no C code; no `.unwrap()` in production; fail-closed on tracing failure
**Scale/Scope**: Builds downloading 50+ dependencies; 6 ecosystems for URL pattern resolution in v1 (Cargo, PyPI, npm, Go, Maven, RubyGems)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Status |
|-----------|------|--------|
| I. Pure Rust, Zero C | All code in Rust via `aya` framework, no C toolchains | PASS |
| II. eBPF-Only Observation | uprobes on TLS libs + kprobes on VFS/TCP, no proxy | PASS |
| III. Fail Closed | FR-014: non-zero exit on trace failure, no fallback | PASS |
| IV. Type-Driven Correctness | Newtypes for Purl, ContentHash, SpdxExpression; anyhow/thiserror | PASS |
| V. Specification Compliance | CycloneDX 1.6, SPDX 3.1, PURL spec, CISA 2025 | PASS |
| VI. Three-Crate Architecture | mikebom-ebpf + mikebom-common + mikebom-cli (+ xtask helper) | PASS |
| VII. Test Isolation | Unit tests unprivileged; eBPF integration gated behind CAP_BPF | PASS |
| VIII. Completeness | All observed events processed; trace_integrity records gaps | PASS |
| IX. Accuracy | PURL validation + confidence scoring; ambiguity flagged | PASS |
| X. Transparency | trace_integrity → CycloneDX compositions + evidence | PASS |
| XI. Enrichment | deps.dev license/VEX/supplier; failure non-blocking per principle | PASS |

**Note on Principle VI**: The `xtask` crate is a standard aya build helper
(compiles eBPF bytecode), not a product crate. It does not violate the
three-crate rule and does not require a constitution amendment.

## Project Structure

### Documentation (this feature)

```text
specs/001-build-trace-pipeline/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── attestation-schema.md
│   └── cli-interface.md
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
Cargo.toml                           # Workspace root
xtask/
├── Cargo.toml
└── src/main.rs                      # eBPF build helper

mikebom-ebpf/
├── Cargo.toml
├── rust-toolchain.toml              # nightly for BPF target
└── src/
    ├── main.rs                      # #![no_std] entry point
    ├── programs/
    │   ├── mod.rs
    │   ├── tls_openssl.rs           # SSL_read/SSL_write uprobes
    │   ├── tls_go.rs                # Go TLS uprobes
    │   ├── tcp_connect.rs           # tcp_v4_connect kprobes
    │   └── file_ops.rs              # vfs_read/write, openat2
    ├── maps.rs                      # eBPF map definitions
    └── helpers.rs                   # PID filtering, hash helpers

mikebom-common/
├── Cargo.toml                       # features: std = [chrono, serde]
└── src/
    ├── lib.rs
    ├── events.rs                    # NetworkEvent, FileEvent (#[repr(C)])
    ├── maps.rs                      # SslBufferInfo, ConnInfo, TraceConfig
    ├── ip.rs                        # no_std IpAddr wrapper
    ├── attestation/                 # (std feature only)
    │   ├── mod.rs
    │   ├── statement.rs             # InTotoStatement, BuildTracePredicate
    │   ├── network.rs               # NetworkTrace, Connection
    │   ├── file.rs                  # FileAccess, FileOperation
    │   ├── integrity.rs             # TraceIntegrity
    │   └── metadata.rs              # TraceMetadata, ToolInfo
    ├── types/                       # (std feature only)
    │   ├── mod.rs
    │   ├── purl.rs                  # Purl newtype with validation
    │   ├── hash.rs                  # ContentHash, HashAlgorithm
    │   ├── license.rs               # SpdxExpression newtype
    │   ├── bomref.rs                # BomRef newtype
    │   └── timestamp.rs             # Timestamp newtype
    └── resolution.rs               # ResolvedComponent, ResolutionEvidence

mikebom-cli/
├── Cargo.toml
├── build.rs                         # aya-build eBPF bytecode inclusion
└── src/
    ├── main.rs                      # clap CLI entry
    ├── cli/
    │   ├── mod.rs
    │   ├── scan.rs
    │   ├── generate.rs
    │   ├── enrich.rs
    │   ├── run.rs
    │   └── validate.rs
    ├── trace/
    │   ├── mod.rs
    │   ├── loader.rs                # eBPF program load + probe attach
    │   ├── processor.rs             # Ring buffer async consumer
    │   ├── aggregator.rs            # Correlate network + file events
    │   ├── http_parser.rs           # Parse HTTP from TLS plaintext
    │   ├── sni_extractor.rs         # Extract SNI from ClientHello
    │   ├── hasher.rs                # Userspace SHA-256 verification
    │   └── pid_tracker.rs           # Child process tracking
    ├── attestation/
    │   ├── mod.rs
    │   ├── builder.rs               # Build InTotoStatement from trace
    │   ├── serializer.rs            # JSON ser/de
    │   └── validator.rs             # Schema conformance checks
    ├── resolve/
    │   ├── mod.rs
    │   ├── pipeline.rs              # Multi-strategy orchestrator
    │   ├── url_resolver.rs          # Registry URL → PURL
    │   ├── hash_resolver.rs         # deps.dev hash → package
    │   ├── path_resolver.rs         # File path → PURL (SBOMit-style)
    │   ├── hostname_resolver.rs     # Hostname → ecosystem
    │   ├── purl_validator.rs        # PURL spec conformance
    │   └── deduplicator.rs          # Merge + confidence ranking
    ├── enrich/
    │   ├── mod.rs
    │   ├── deps_dev_client.rs       # deps.dev v3 API client
    │   ├── license_resolver.rs      # License enrichment
    │   ├── vex_builder.rs           # VEX from advisory data
    │   └── supplier_resolver.rs     # Supplier metadata
    ├── generate/
    │   ├── mod.rs
    │   ├── cyclonedx/
    │   │   ├── mod.rs
    │   │   ├── builder.rs           # CycloneDX 1.6 BOM builder
    │   │   ├── compositions.rs      # Completeness signaling
    │   │   ├── evidence.rs          # Per-component evidence.identity
    │   │   ├── vex.rs               # Vulnerabilities section
    │   │   ├── metadata.rs          # Tool, timestamp, properties
    │   │   └── serializer.rs        # JSON/XML output
    │   └── spdx/
    │       ├── mod.rs
    │       ├── builder.rs           # SPDX 3.1 document builder
    │       ├── relationships.rs     # DEPENDS_ON relationships
    │       └── serializer.rs        # JSON-LD output
    ├── error.rs                     # thiserror error definitions
    └── config.rs                    # CLI config + env vars
```

**Structure Decision**: Three-crate Cargo workspace with `xtask` build helper,
following the standard `aya` project template. The `mikebom-common` crate
uses a `std` feature gate to share `#[repr(C)]` event types with the
`no_std` eBPF crate while also hosting `std`-only attestation and newtype
definitions for the CLI crate.

## Complexity Tracking

> No Constitution Check violations. No complexity justification needed.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| xtask crate (4th crate in workspace) | aya build helper compiles eBPF bytecode | N/A — standard aya pattern, not a product crate |
