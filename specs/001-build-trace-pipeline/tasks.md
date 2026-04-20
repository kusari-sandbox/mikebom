# Tasks: Build-Trace-to-SBOM Pipeline

**Input**: Design documents from `/specs/001-build-trace-pipeline/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Tests**: Unit tests are expected per Constitution Principle VII for all PURL parsing, API response handling, and serialization logic. Include tests alongside implementation in each task rather than as separate test tasks.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Workspace root**: `Cargo.toml`
- **eBPF crate**: `mikebom-ebpf/`
- **Common crate**: `mikebom-common/`
- **CLI crate**: `mikebom-cli/`
- **Build helper**: `xtask/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Scaffold the Cargo workspace and configure all crate boilerplate

- [x] T001 Create workspace root Cargo.toml with members: mikebom-cli, mikebom-common, mikebom-ebpf, xtask in Cargo.toml
- [x] T002 [P] Create xtask build helper crate with eBPF compilation target in xtask/Cargo.toml and xtask/src/main.rs
- [x] T003 [P] Create mikebom-ebpf crate with no_std config and nightly rust-toolchain.toml in mikebom-ebpf/Cargo.toml, mikebom-ebpf/rust-toolchain.toml, mikebom-ebpf/src/main.rs
- [x] T004 [P] Create mikebom-common crate with std feature gate in mikebom-common/Cargo.toml and mikebom-common/src/lib.rs
- [x] T005 [P] Create mikebom-cli crate with all dependencies (aya, tokio, clap, reqwest, serde, cyclonedx-bom, packageurl, sha2, chrono, thiserror, anyhow, tracing) in mikebom-cli/Cargo.toml and mikebom-cli/src/main.rs
- [x] T006 [P] Create .gitignore with Rust/target patterns and eBPF build artifacts in .gitignore
- [x] T006b [P] Create Lima VM config (lima.yaml) with Linux kernel 5.8+, Rust stable+nightly toolchain, and eBPF capabilities for macOS development; update quickstart.md with dual-environment workflow (native macOS for generate/enrich/validate, Lima VM for scan/run/eBPF tests) in lima.yaml and specs/001-build-trace-pipeline/quickstart.md
- [x] T007 Verify workspace builds with `cargo build --workspace` (excluding eBPF target)

**Checkpoint**: `cargo build --workspace` succeeds. `cargo xtask ebpf` runs (even if eBPF programs are stubs). `limactl start ./lima.yaml` provisions a working eBPF dev environment.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared types used by all user stories. MUST complete before any user story.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### no_std Event Types (shared kernel ↔ userspace)

- [x] T008 [P] Implement no_std IpAddr wrapper with IPv4-mapped-v6 support in mikebom-common/src/ip.rs
- [x] T009 [P] Implement NetworkEvent, NetworkEventType, FileEvent, and FileEventType #[repr(C)] structs in mikebom-common/src/events.rs
- [x] T011 [P] Implement SslBufferInfo, ConnInfo, TraceConfig #[repr(C)] map value types in mikebom-common/src/maps.rs

### Validated Newtypes (std feature only)

- [x] T012 [P] Implement Purl newtype with PURL spec validation via packageurl crate in mikebom-common/src/types/purl.rs
- [x] T013 [P] Implement ContentHash, HashAlgorithm, and HexString newtypes with hex validation in mikebom-common/src/types/hash.rs
- [x] T014 [P] Implement SpdxExpression newtype with license expression validation in mikebom-common/src/types/license.rs
- [x] T015 [P] Implement BomRef and Timestamp newtypes in mikebom-common/src/types/bomref.rs and mikebom-common/src/types/timestamp.rs

### Attestation Schema Types (std feature only)

- [x] T016 [P] Implement InTotoStatement and BuildTracePredicate in mikebom-common/src/attestation/statement.rs
- [x] T017 [P] Implement NetworkTrace, Connection, Destination, HttpRequest, HttpResponse, TlsInfo in mikebom-common/src/attestation/network.rs
- [x] T018 [P] Implement FileAccess, FileOperation in mikebom-common/src/attestation/file.rs
- [x] T019 [P] Implement TraceIntegrity and PartialCapture in mikebom-common/src/attestation/integrity.rs
- [x] T020 [P] Implement TraceMetadata, ToolInfo, HostInfo, ProcessInfo, GenerationContext in mikebom-common/src/attestation/metadata.rs
- [x] T021 [P] Implement ResolvedComponent and ResolutionEvidence types in mikebom-common/src/resolution.rs

### CLI Infrastructure

- [x] T022 Implement thiserror error types (MikebomError with all variants from contracts/cli-interface.md) in mikebom-cli/src/error.rs
- [x] T023 [P] Implement config module with CLI arg types and defaults in mikebom-cli/src/config.rs
- [x] T024 Implement clap CLI skeleton with 5 subcommand stubs (scan, generate, enrich, run, validate) in mikebom-cli/src/main.rs and mikebom-cli/src/cli/mod.rs

### Test Fixtures

- [x] T024b [P] Create sample attestation fixture files for testing generate/enrich/validate without eBPF in tests/fixtures/

**Checkpoint**: `cargo test --workspace` passes. `cargo clippy --all-targets --all-features` clean. All newtypes reject invalid input. Test fixtures available for US2+ development.

---

## Phase 3: User Story 1 — Trace a Build and Produce an Attestation (Priority: P1) 🎯 MVP

**Goal**: Operator runs `mikebom scan` against a build process and receives a valid in-toto attestation file with network and file trace data.

**Independent Test**: Trace `curl https://example.com -o /tmp/test` and verify the attestation contains the connection to example.com with correct hostname, HTTP path, and content hash.

### eBPF Programs

- [x] T025 [US1] Implement eBPF map definitions (NETWORK_EVENTS RingBuf, FILE_EVENTS RingBuf, SSL_BUFFERS HashMap, CONN_INFO HashMap, SEEN_HASHES BloomFilter, PID_FILTER HashMap, CONFIG Array) in mikebom-ebpf/src/maps.rs
- [x] T026 [P] [US1] Implement PID filtering and bloom filter helpers in mikebom-ebpf/src/helpers.rs
- [x] T027 [P] [US1] Implement tcp_v4_connect kprobe and kretprobe for connection tracking in mikebom-ebpf/src/programs/tcp_connect.rs
- [x] T028 [P] [US1] Implement SSL_read uprobe/uretprobe for OpenSSL plaintext capture in mikebom-ebpf/src/programs/tls_openssl.rs
- [x] T029 [P] [US1] Implement SSL_write uprobe/uretprobe for OpenSSL plaintext capture in mikebom-ebpf/src/programs/tls_openssl.rs
- [x] T029b [P] [US1] Implement file access kprobes (vfs_read, vfs_write, do_sys_openat2) in mikebom-ebpf/src/programs/file_ops.rs
- [x] T030 [US1] Wire all eBPF programs into no_std main entry point in mikebom-ebpf/src/main.rs
- [x] T031 [US1] Configure aya-build in mikebom-cli/build.rs to include eBPF bytecode

### Trace Pipeline (userspace)

- [x] T032 [US1] Implement eBPF loader with probe attachment and error reporting in mikebom-cli/src/trace/loader.rs
- [x] T033 [US1] Implement async ring buffer processor consuming NetworkEvent and FileEvent in mikebom-cli/src/trace/processor.rs
- [x] T034 [P] [US1] Implement HTTP request/response parser from TLS plaintext fragments in mikebom-cli/src/trace/http_parser.rs
- [x] T035 [P] [US1] Implement SNI extractor from TLS ClientHello in mikebom-cli/src/trace/sni_extractor.rs
- [x] T036 [P] [US1] Implement userspace SHA-256 hasher for content verification in mikebom-cli/src/trace/hasher.rs
- [x] T037 [P] [US1] Implement child PID tracker for process tree isolation in mikebom-cli/src/trace/pid_tracker.rs
- [x] T038 [US1] Implement event aggregator correlating network events into Connection objects and file events into FileOperation objects in mikebom-cli/src/trace/aggregator.rs

### Attestation Builder

- [x] T039 [US1] Implement attestation builder that assembles InTotoStatement from aggregated trace data in mikebom-cli/src/attestation/builder.rs
- [x] T040 [P] [US1] Implement attestation JSON serializer/deserializer with serde in mikebom-cli/src/attestation/serializer.rs

### Scan Command

- [x] T041 [US1] Implement `mikebom scan` subcommand (PID targeting + inline command mode, cgroup isolation, fail-closed on error) in mikebom-cli/src/cli/scan.rs

**Checkpoint**: `sudo mikebom scan -- curl https://example.com -o /tmp/test` produces a valid attestation JSON with the expected connection and file operation.

---

## Phase 4: User Story 2 — Generate SBOM from Attestation (Priority: P2)

**Goal**: Operator runs `mikebom generate` on an attestation file and receives a CycloneDX 1.6 SBOM with resolved PURLs, evidence, and completeness metadata.

**Independent Test**: Feed a pre-recorded attestation JSON (no eBPF needed) through `mikebom generate`, validate CycloneDX output against JSON schema, and confirm all expected packages have valid PURLs.

### Resolution Pipeline

- [x] T042 [P] [US2] Implement URL resolver with patterns for Cargo, PyPI, npm, Go, Maven, RubyGems, and Debian/apt registries in mikebom-cli/src/resolve/url_resolver.rs
- [x] T043 [P] [US2] Implement deps.dev v3 API client (query by hash, PURL lookup, get version) in mikebom-cli/src/enrich/deps_dev_client.rs
- [x] T044 [P] [US2] Implement hash resolver querying deps.dev by SHA-256 in mikebom-cli/src/resolve/hash_resolver.rs
- [x] T045 [P] [US2] Implement file path pattern resolver (SBOMit-style) for Cargo, pip, npm, Go in mikebom-cli/src/resolve/path_resolver.rs
- [x] T046 [P] [US2] Implement hostname-to-ecosystem heuristic resolver in mikebom-cli/src/resolve/hostname_resolver.rs
- [x] T047 [P] [US2] Implement PURL spec conformance validator with deps.dev online check in mikebom-cli/src/resolve/purl_validator.rs
- [x] T048 [US2] Implement deduplicator merging multi-strategy results by confidence ranking in mikebom-cli/src/resolve/deduplicator.rs
- [x] T049 [US2] Implement resolution pipeline orchestrator (URL→hash→path→hostname, confidence scoring) in mikebom-cli/src/resolve/pipeline.rs

### Enrichment Source Abstraction (Constitution Principle XII)

- [x] T049b [US2] Define EnrichmentSource trait (name, enrich_relationships, enrich_metadata) and Relationship type in mikebom-cli/src/enrich/source.rs
- [x] T049c [P] [US2] Implement LockfileSource: parse Cargo.lock, package-lock.json, go.sum for dependency relationships between traced components in mikebom-cli/src/enrich/lockfile_source.rs
- [x] T049d [P] [US2] Implement DepsDevSource wrapping deps_dev_client for relationship + metadata enrichment in mikebom-cli/src/enrich/depsdev_source.rs
- [x] T049e [US2] Implement enrichment pipeline: run all registered sources, merge relationships, enforce guard rail (no unobserved components added) in mikebom-cli/src/enrich/pipeline.rs

### CycloneDX Generator

- [x] T050 [P] [US2] Implement CycloneDX metadata builder (tool name, timestamp, generation context properties) in mikebom-cli/src/generate/cyclonedx/metadata.rs
- [x] T051 [P] [US2] Implement CycloneDX evidence.identity builder mapping ResolutionEvidence to methods[] in mikebom-cli/src/generate/cyclonedx/evidence.rs
- [x] T052 [P] [US2] Implement CycloneDX compositions builder mapping TraceIntegrity to aggregate values in mikebom-cli/src/generate/cyclonedx/compositions.rs
- [x] T053 [US2] Implement CycloneDX 1.6 BOM builder assembling components, metadata, compositions, and evidence in mikebom-cli/src/generate/cyclonedx/builder.rs
- [x] T054 [P] [US2] Implement CycloneDX JSON and XML serializer in mikebom-cli/src/generate/cyclonedx/serializer.rs
- [x] T054b [US2] Implement CycloneDX dependencies section builder mapping enriched relationships to dependency tree in mikebom-cli/src/generate/cyclonedx/dependencies.rs

### SPDX Generator

- [x] T055 [P] [US2] Implement SPDX document builder with Package elements and ExternalIdentifier (PURL) in mikebom-cli/src/generate/spdx/builder.rs
- [x] T056 [P] [US2] Implement SPDX DEPENDS_ON relationships builder in mikebom-cli/src/generate/spdx/relationships.rs
- [x] T057 [P] [US2] Implement SPDX JSON-LD serializer in mikebom-cli/src/generate/spdx/serializer.rs

### Generate Command

- [x] T058 [US2] Implement `mikebom sbom generate` subcommand (attestation loading, resolution, enrichment sources, --scope, --no-hashes, format selection, output) in mikebom-cli/src/cli/generate.rs

**Checkpoint**: `mikebom sbom generate test-attestation.json` produces a CycloneDX 1.6 JSON that validates against the official schema. All components have PURLs, evidence, hashes, and dependency relationships from enrichment sources.

---

## Phase 5: User Story 3 — End-to-End Run Command (Priority: P3)

**Goal**: Operator runs `mikebom run -- <build-cmd>` and receives both attestation and SBOM in one step.

**Independent Test**: Run `sudo mikebom run -- curl https://crates.io/api/v1/crates/serde/1.0.197/download -o /tmp/serde.crate` and verify both attestation and SBOM files are produced.

- [ ] T059 [US3] Implement `mikebom run` subcommand composing scan + generate pipelines with combined option handling in mikebom-cli/src/cli/run.rs
- [ ] T060 [US3] Implement build exit code preservation (build failure → pipeline exit code reflects build failure, not trace failure) in mikebom-cli/src/cli/run.rs

**Checkpoint**: `sudo mikebom run --sbom-output test.cdx.json -- curl <url>` produces both attestation and SBOM. Build exit code is preserved.

---

## Phase 6: User Story 4 — Enrich SBOM (Priority: P4)

**Goal**: Operator runs `mikebom enrich` on an existing SBOM and receives license expressions, VEX entries, and supplier metadata.

**Independent Test**: Feed a CycloneDX SBOM containing `pkg:cargo/serde@1.0.197` through enrichment and verify it gains license (`MIT OR Apache-2.0`) and advisory data.

- [ ] T061 [P] [US4] Implement license resolver querying deps.dev GetVersion for SPDX license expressions in mikebom-cli/src/enrich/license_resolver.rs
- [ ] T062 [P] [US4] Implement VEX builder creating CycloneDX vulnerabilities entries from deps.dev GetAdvisory with default state "in_triage" in mikebom-cli/src/enrich/vex_builder.rs
- [ ] T063 [P] [US4] Implement supplier resolver extracting author/maintainer metadata from deps.dev in mikebom-cli/src/enrich/supplier_resolver.rs
- [ ] T064 [US4] Implement CycloneDX VEX section integrating vulnerability entries into the BOM in mikebom-cli/src/generate/cyclonedx/vex.rs
- [ ] T065 [US4] Implement `mikebom enrich` subcommand (SBOM loading, enrichment pipeline, transparency annotations for unavailable sources) in mikebom-cli/src/cli/enrich.rs
- [ ] T066 [US4] Wire `--enrich` flag into `mikebom generate` to optionally run enrichment inline in mikebom-cli/src/cli/generate.rs

**Checkpoint**: `mikebom enrich test.cdx.json` adds license and VEX data. Enrichment failure (e.g., network offline) still produces output with transparency annotations.

---

## Phase 7: User Story 5 — Validate Conformance (Priority: P5)

**Goal**: Operator runs `mikebom validate` on any attestation or SBOM file and receives a conformance report.

**Independent Test**: Validate a known-good CycloneDX SBOM (passes), then validate one with a malformed PURL (fails with specific error).

- [ ] T067 [P] [US5] Implement attestation validator (schema conformance, trace_integrity analysis, timestamp validity) in mikebom-cli/src/attestation/validator.rs
- [ ] T068 [P] [US5] Implement CycloneDX validator (JSON schema validation, per-component PURL conformance, CISA 2025 field presence) in mikebom-cli/src/generate/cyclonedx/validator.rs
- [ ] T069 [P] [US5] Implement SPDX validator (JSON-LD schema validation, element completeness) in mikebom-cli/src/generate/spdx/validator.rs
- [ ] T070 [US5] Implement `mikebom validate` subcommand with format auto-detection and --strict mode in mikebom-cli/src/cli/validate.rs

**Checkpoint**: `mikebom validate --strict test.cdx.json` passes for valid SBOMs and fails with specific errors for invalid ones.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Additional eBPF probes, hardening, and documentation

- [ ] T071 [P] Implement Go TLS uprobes (crypto/tls.(*Conn).Read and Write) in mikebom-ebpf/src/programs/tls_go.rs
- [ ] T073 [P] Add mock eBPF event generator for CI testing (produces synthetic NetworkEvent/FileEvent streams) in mikebom-cli/src/trace/mock_events.rs
- [ ] T074 Run `cargo clippy --all-targets --all-features -- -D warnings` and fix all warnings
- [ ] T075 Run `cargo fmt -- --check` and fix all formatting issues
- [ ] T077 Run quickstart.md validation end-to-end
- [ ] T078 [P] Create fail-closed test suite: test non-zero exit for probe attach failure, ring buffer overflow, zero dependency activity, TLS library not found, and deps.dev timeout scenarios in tests/fail_closed/
- [ ] T080 [P] Create Debian-focused test fixture: attestation from tracing apt-get install inside a Debian container, with deb PURL conformance tests (encoding, distro qualifier with codename, epoch handling, arch qualifiers) in tests/fixtures/deb-attestation.json and tests/deb_purl_conformance.rs
- [ ] T079 Create performance benchmark: trace a known project build (e.g., small Cargo project with 20+ deps), measure wall-clock overhead, assert <30s per SC-009 in tests/benchmarks/

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - US1 (Phase 3): Can start after Foundational
  - US2 (Phase 4): Can start after Foundational (independent of US1 — uses pre-recorded attestation files)
  - US3 (Phase 5): Depends on both US1 and US2
  - US4 (Phase 6): Can start after US2 (needs CycloneDX builder)
  - US5 (Phase 7): Can start after US2 (needs generated SBOMs to validate)
- **Polish (Phase 8)**: Can start after US1 (for Go TLS probes) and US2 (for fail-closed + benchmark tests)

### User Story Dependencies

- **US1 (P1)**: Can start after Foundational — No dependencies on other stories
- **US2 (P2)**: Can start after Foundational — Uses pre-recorded attestation files, independent of US1
- **US3 (P3)**: Depends on US1 + US2 (composes both pipelines)
- **US4 (P4)**: Depends on US2 (needs CycloneDX builder for VEX integration)
- **US5 (P5)**: Depends on US2 (needs generated output formats to validate)

### Within Each User Story

- eBPF programs before trace pipeline (US1)
- Resolvers before pipeline orchestrator (US2)
- CycloneDX sub-builders before main builder (US2)
- Individual enrichment resolvers before enrich command (US4)
- Individual validators before validate command (US5)

### Parallel Opportunities

- All Setup tasks T002-T006 can run in parallel
- All Foundational no_std types T008, T009, T011 can run in parallel
- All Foundational newtypes T012-T015 can run in parallel
- All Foundational attestation types T016-T021 can run in parallel
- Within US1: eBPF programs T026-T029, T029b can run in parallel
- Within US1: Trace pipeline helpers T034-T037 can run in parallel
- Within US2: All resolvers T042-T047 can run in parallel
- Within US2: CycloneDX sub-builders T050-T052 can run in parallel
- Within US2: SPDX sub-builders T055-T057 can run in parallel
- **US1 and US2 can run in parallel** (US2 uses pre-recorded attestation data)
- Within US4: All enrichment resolvers T061-T063 can run in parallel
- Within US5: All validators T067-T069 can run in parallel
- Polish tasks T071, T073, T078 can run in parallel

---

## Parallel Example: Foundational Phase

```bash
# Launch all no_std types together:
Task: "T008 Implement IpAddr in mikebom-common/src/ip.rs"
Task: "T009 Implement event types in mikebom-common/src/events.rs"
Task: "T011 Implement map types in mikebom-common/src/maps.rs"

# Launch all newtypes together:
Task: "T012 Implement Purl in mikebom-common/src/types/purl.rs"
Task: "T013 Implement ContentHash in mikebom-common/src/types/hash.rs"
Task: "T014 Implement SpdxExpression in mikebom-common/src/types/license.rs"
Task: "T015 Implement BomRef+Timestamp in mikebom-common/src/types/"
```

## Parallel Example: US1 + US2 in Parallel

```bash
# US1 eBPF programs (requires root for testing):
Task: "T027 tcp_connect kprobe in mikebom-ebpf/"
Task: "T028 SSL_read uprobe in mikebom-ebpf/"
Task: "T029 SSL_write uprobe in mikebom-ebpf/"

# US2 resolvers (no eBPF needed, uses fixture data):
Task: "T042 URL resolver in mikebom-cli/src/resolve/url_resolver.rs"
Task: "T043 deps.dev client in mikebom-cli/src/enrich/deps_dev_client.rs"
Task: "T044 Hash resolver in mikebom-cli/src/resolve/hash_resolver.rs"
```

---

## Implementation Strategy

### MVP First (US1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1 (scan command)
4. **STOP and VALIDATE**: Trace a curl command, verify attestation output
5. This proves the core eBPF tracing works end-to-end

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add US1 → Test independently → `mikebom scan` works (MVP!)
3. Add US2 → Test independently → `mikebom generate` works
4. Add US3 → Test independently → `mikebom run` works (convenience)
5. Add US4 → Test independently → `mikebom enrich` works
6. Add US5 → Test independently → `mikebom validate` works
7. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 (eBPF + trace pipeline)
   - Developer B: US2 (resolution + SBOM generation)
3. After US1 + US2: US3 (thin composition layer)
4. US4 and US5 can proceed in parallel after US2

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Unit tests expected per Constitution Principle VII — include with each implementation task
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- No `.unwrap()` in production code (Constitution Principle IV)
