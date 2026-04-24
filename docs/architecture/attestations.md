# Attestations

mikebom is **attestation-first**: the attestation is the primary artifact,
the SBOM is derived from it. This mirrors the SBOMit pattern — rather than
shipping an SBOM whose origin is opaque, mikebom ships an in-toto attestation
that says *exactly* what the build did, and an SBOM generated from that
record.

**Key files:**

- `mikebom-common/src/attestation/` — the schema types.
  - `statement.rs` — `InTotoStatement`, `BuildTracePredicate`, constants.
  - `metadata.rs` — `TraceMetadata`, `ToolInfo`, `HostInfo`, `ProcessInfo`,
    `GenerationContext`.
  - `network.rs` — `NetworkTrace`, `Connection`, `TlsInfo`.
  - `file.rs` — `FileAccess`, `FileOperation`.
  - `integrity.rs` — `TraceIntegrity`.
- `mikebom-cli/src/attestation/builder.rs` — builds the statement from a
  captured trace.
- `mikebom-cli/src/attestation/serializer.rs` — JSON I/O.
- `mikebom-cli/src/cli/scan.rs` — the eBPF capture path that produces the
  trace events.

## Shape

The attestation is an in-toto Statement v1. From
`mikebom-cli/src/config.rs`:

```rust
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://mikebom.dev/attestation/build-trace/v1";
```

Skeleton:

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "build-output", "digest": { "sha256": "..." } }
  ],
  "predicateType": "https://mikebom.dev/attestation/build-trace/v1",
  "predicate": {
    "metadata": { ... },          // tool, timestamps, host, process, context
    "network_trace": { ... },     // TLS connections with SNI + URL + hashes
    "file_access": { ... },       // file operations with per-file hashes
    "trace_integrity": { ... }    // overflow / drop counters + attach failures
  }
}
```

`subject` follows in-toto's ResourceDescriptor shape: a name and an optional
digest map. Today the default subject is a synthetic `"build-output"`; in
the future this will point at a concrete build artifact (the `cargo install`
output binary, the `.deb` package that was built, etc.) with its SHA-256
digest.

## `BuildTracePredicate` fields

### `metadata` (`TraceMetadata`)

- **`tool`**: `{ name: "mikebom", version: "<CARGO_PKG_VERSION>" }`.
- **`trace_start` / `trace_end`**: RFC 3339 timestamps sampled at capture
  start and end.
- **`target_process`**: `{ pid, command, cgroup_id }` of the traced command.
- **`host`**: `{ os, kernel_version, arch, distro_codename }`. The
  `distro_codename` field carries the value that feeds the
  `distro=<namespace>-<VERSION_ID>` qualifier on deb / rpm / apk PURLs
  (e.g., `debian-12`, `ubuntu-24.04`, `alpine-3.19`). The field name is
  historical — it holds the full `<namespace>-<VERSION_ID>` form, not a
  bare codename.
- **`generation_context`**: `BuildTimeTrace` when the attestation was
  produced by `trace capture` / `trace run`.

### `network_trace` (`NetworkTrace`)

Captured via eBPF uprobes on `SSL_read` / `SSL_write` in libssl.

- **`connections`**: array of `Connection` — each carries:
  - `id`: synthetic ID for cross-referencing (e.g. `ssl_<ptr>_<ns>`).
  - `destination`: `{ hostname, ip, port }`. IP/port come back as
    `0.0.0.0:0` today — TCP `sock` struct offsets need BTF CO-RE to resolve
    portably, hostname is preserved via TLS SNI + HTTP Host header.
  - `tls`: `{ sni }` when SNI was observed.
  - `request`: `{ method, path, ... }` parsed from the HTTPS request line.
  - `response`: `{ status, content_hash, bytes_received }`. `content_hash`
    here is unreliable (uprobes only see ~512 B per TLS record); the real
    SHA-256 ends up in `file_access` via the post-trace walk.
- **`summary`**: aggregate counts — total connections, unique hosts,
  unique IPs, protocol counts, total bytes received.

Each `Connection.id` becomes the provenance marker on downstream components:
a `ResolvedComponent` resolved via URL pattern from this connection gets
`evidence.source_connection_ids = ["ssl_..."]`, which ends up as the
`mikebom:source-connection-ids` property on the CycloneDX component. A
downstream consumer can correlate any SBOM component back to the specific
TLS session that fetched it.

### `file_access` (`FileAccess`)

Captured via kprobes on file operations plus the post-trace `--artifact-dir`
walker.

- **`operations`**: array of `FileOperation` — each carries:
  - `path`: on-disk path.
  - `op_type`: `read`, `write`, `create`, …
  - `size`: byte count.
  - `content_hash`: real SHA-256 (from the artifact-dir walker's
    post-trace hash pass, not from the kprobe — the kprobe only sees the
    file descriptor).
  - `timestamp`: wall-clock timestamp of the operation.
- **`summary`**: totals + per-operation-type breakdown.

### `trace_integrity` (`TraceIntegrity`)

Kernel-side health counters that tell the consumer how complete the trace
is:

- **`ring_buffer_overflows`** and **`events_dropped`** — ring-buffer
  pressure indicators. Non-zero means at least one event didn't make it to
  userspace, so the SBOM is incomplete by some quantifiable amount.
- **`uprobe_attach_failures`** and **`kprobe_attach_failures`** — lists of
  probes that failed to attach at capture start. Usually indicates libssl
  wasn't where expected or the kernel refused a kprobe attach point.
- **`partial_captures`** — per-capture notes about known-incomplete paths.
- **`bloom_filter_capacity`** and **`bloom_filter_false_positive_rate`** —
  parameters of the probe-side event-deduplication bloom filter.

These counters surface on the CycloneDX output as `metadata.properties`
(`mikebom:trace-integrity-*`) so an SBOM consumer can decide whether to
trust the result.

## Why attestation-first

Three reasons the attestation is the primary artifact:

1. **Provenance is not inferable from the SBOM alone.** Which TLS session
   fetched which crate? Which file hash matches which download? An SBOM
   that doesn't carry this information can't be audited. The attestation
   is where it lives; the SBOM is a projection.
2. **SBOMs are rewritable; attestations are signed.** Shipping the
   attestation alongside the SBOM means downstream consumers can re-derive
   the SBOM, diff against the shipped one, and detect any post-hoc edits
   (once signing is wired — see the deferred `sbom_signature` backlog
   item).
3. **The same attestation supports multiple SBOM formats.** Once CycloneDX
   XML and SPDX serialization land, they all project from the same
   attestation — the capture cost is paid once.

## Relation to go-witness

mikebom's schema is intentionally shaped to be compatible with the
[go-witness network trace attestor](https://github.com/in-toto/go-witness).
If you know go-witness's network attestor shape, mikebom's `network_trace`
will look familiar — the field names and the Connection + TlsInfo structures
align.

## Consumer workflow

1. `mikebom trace capture` (or the `capture` phase of `trace run`) produces
   `<foo>.attestation.json`.
2. Either consume the attestation directly (vulnerability scanners,
   policy engines, SLSA verifiers), or derive an SBOM with
   `mikebom sbom generate <foo>.attestation.json`.
3. Re-deriving is idempotent and cheap — the attestation is the source of
   truth.

## Known gaps

- **TCP `sock` struct offsets**: destination IP/port come back as
  `0.0.0.0:0`. Hostname via SNI/Host header is preserved so this is
  cosmetic. BTF CO-RE resolution is the proper fix.
- **HTTP/2 HPACK-encoded headers**: our plaintext hostname scanner relies
  on uncompressed substrings. Workaround: force HTTP/1.1 at the client
  (`curl --http1.1`). A real HPACK decoder is the proper fix.
- **curl `-O` / cargo `.crate` writes**: `vfs_open` kprobes don't fire for
  these `openat(AT_FDCWD, ..., O_CREAT|O_WRONLY)` paths (BPF verifier
  rejects `bpf_d_path` from the relevant kprobe). Worked around via the
  post-trace `--artifact-dir` scan, which produces correct hashes and
  complete path coverage without per-open timing provenance.
- **GnuTLS / rustls clients don't hit our libssl uprobes.** apt's `https`
  method uses GnuTLS; cargo uses rustls. Neither links against libssl.
  Workaround for apt-driven traces: drive the install through curl
  (which does link libssl). Cargo's rustls downloads are covered via the
  artifact-dir scan since the URL is already knowable from the `.crate`
  filename.
- **Attestation signing** is landing now under feature 006 (v006 in
  progress). DSSE envelope signing via local PEM key or keyless (OIDC →
  Fulcio → Rekor) using `sigstore-rs`. Verification exposed through
  `mikebom sbom verify`. See
  `specs/006-sbomit-suite/plan.md` for the detailed design.
