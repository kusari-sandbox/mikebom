# Quickstart

Stable recipes come first — they produce a CycloneDX 1.6 JSON SBOM, work on
any OS, and need no special privileges. Trace-mode (experimental, Linux only)
follows at the bottom.

Prereqs: [`mikebom` installed](installation.md) and on `$PATH`.

---

## Recipe 1 — Scan a source tree

Point at any directory that contains lockfiles or manifests. Works on any OS.

```bash
mikebom sbom scan --path ./my-project --output project.cdx.json --json
```

This is the primary recipe. mikebom reads every supported lockfile
(`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `go.mod` + `go.sum`,
`Gemfile.lock`, `pom.xml`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`)
plus Maven JAR `META-INF/maven/...pom.xml`, per-module Go `.mod` files from
the module cache if present, and produces a CycloneDX with:

- SHA-256 content hashes on every component
- Real `dependsOn` edges (not a flat fan-out; e.g. a kyverno source-tree scan
  produces ~6,400 real Go dep edges)
- Evidence blocks pointing back to the file that identified each component
- Strict PURL encoding round-trippable through `packageurl-python`

For richer Go dep graphs, run `go mod download` (or let `go build` populate
`$GOMODCACHE`) before the scan — per-module `.mod` files let mikebom walk
the transitive require graph.

---

## Recipe 2 — Scan a container image

Works on any OS. No privilege, no eBPF.

```bash
docker save alpine:3.19 -o alpine.tar
mikebom sbom scan --image alpine.tar --output alpine.cdx.json --json
```

`--image` takes a `docker save` tarball. mikebom extracts the layers (honouring
OCI whiteouts), auto-reads `<rootfs>/etc/os-release` for `ID` + `VERSION_ID`
(feeding the `distro=<namespace>-<version>` PURL qualifier — e.g.,
`distro=debian-12`, `distro=alpine-3.19`), reads the installed-package
databases (`/var/lib/dpkg/status` for Debian and derivatives,
`/lib/apk/db/installed` for Alpine, `rpmdb.sqlite` for RPM-based images),
and emits a CycloneDX SBOM with a real dependency graph from the db's
`Depends:` fields.

`--json` prints a summary to stdout:

```json
{
  "components": 15,
  "relationships": 6,
  "generation_context": "container-image-scan",
  "target_name": "alpine:3.19"
}
```

For Debian and Ubuntu images the scanner also produces per-file SHA-256
evidence (the `evidence.occurrences[]` block) so every component carries
byte-level tamper detection. Pass `--no-deep-hash` to skip this on very large
images; `--no-package-db` to fall back to artifact-file-only scanning.

---

## Recipe 3 — Scan a package cache

Useful for CI where `~/.cargo/registry/cache`, `$GOMODCACHE`, `~/.m2`, or a
pnpm/npm store is the authoritative copy of what the build pulled.

```bash
mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json --json
```

```json
{
  "components": 1152,
  "generation_context": "filesystem-scan",
  "output_file": "cargo.cdx.json",
  "scanned_root": "/Users/m/.cargo/registry/cache"
}
```

Every resolved crate carries a SHA-256 that byte-matches the `.crate` file on
disk plus a CycloneDX `evidence.identity` block at confidence 0.70 with
`technique: "filename"`. If the directory happens to be a rootfs-shaped tree
(has `etc/os-release` at the top), mikebom reads `ID` + `VERSION_ID` from
there and stamps the `distro=<namespace>-<VERSION_ID>` qualifier on deb
PURLs automatically. Override with `--deb-codename <value>` (e.g.,
`--deb-codename debian-12`) when you're scanning a bare directory of
`.deb` files.

---

## Recipe 4 — Verify a signed DSSE attestation

Works on any OS. Accepts DSSE envelopes produced by mikebom, witness, or any
other SBOMit-compliant tool.

```bash
mikebom sbom verify attest.dsse.json \
  --public-key signer.pub \
  --expected-subject ./my-binary
# → PASS — verified with public_key sha256:…  subject digest matches on-disk binary.
```

For keyless verification, pass `--identity 'user@example.com'` or a glob
instead of `--public-key`. See
[`specs/006-sbomit-suite/quickstart.md`](../../specs/006-sbomit-suite/quickstart.md)
for `--layout` (in-toto policy enforcement), `--fulcio-url`, `--rekor-url`,
and the full FailureMode contract.

---

## Recipe 5 — Generate an in-toto layout

```bash
mikebom policy init --functionary-key ci.pub --step-name build --output layout.json
mikebom sbom verify attest.dsse.json --layout layout.json
# → exit 3 + mode: LayoutViolation when the signer doesn't match
```

---

## Experimental: trace a build (Linux only)

> **Status:** experimental. Requires Linux ≥ 5.8, `CAP_BPF + CAP_PERFMON`
> (or `--privileged` in a container). Adds ~2-3× wall-clock overhead on
> syscall-heavy builds. Coverage gaps on `openat2` and `io_uring` syscalls.
> Most users should stick with the scan recipes above.
>
> The trace-mode pipeline exists for workflows that need the SBOM to be
> *provably bound to a specific build event* — not just a post-hoc scan of
> whatever files happen to be on disk. The attestation ties the built
> artifact's SHA-256 to the observed build, and can be signed with
> sigstore (local-key or keyless OIDC → Fulcio → Rekor).

Trace `cargo install ripgrep` end-to-end, produce a signed attestation of
every TLS download + file write, then derive a CycloneDX SBOM from that
attestation:

```bash
mikebom trace run \
  --sbom-output ripgrep.cdx.json \
  --attestation-output ripgrep.attestation.json \
  --signing-key ./signing.key \
  --auto-dirs \
  -- cargo install ripgrep
```

To re-derive the SBOM later (or after enriching with different flags):

```bash
mikebom sbom generate ripgrep.attestation.json \
  --output ripgrep.cdx.json \
  --enrich --lockfile Cargo.lock
```

On macOS, run trace-mode inside the `mikebom-dev` container (see
[`Dockerfile.dev`](../../Dockerfile.dev)) or a Lima VM.

---

## What's next

- **Find a flag you need?** See the [CLI reference](cli-reference.md).
- **Want to compare SBOM quality to other tools?** See
  [`mikebom sbom compare`](cli-reference.md#mikebom-sbom-compare).
- **Curious why the SBOM looks the way it does?** See the
  [architecture overview](../architecture/overview.md).
- **Running into an unfamiliar ecosystem?** See the
  [per-ecosystem reference](../ecosystems.md).
- **Want the trace + sigstore pipeline?** See
  [`specs/006-sbomit-suite/quickstart.md`](../../specs/006-sbomit-suite/quickstart.md).
