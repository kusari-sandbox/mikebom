# Quickstart

Three working recipes. Each produces a CycloneDX 1.6 JSON SBOM and (for
trace mode) an in-toto attestation.

Prereqs: [`mikebom` installed](installation.md) and on `$PATH`. For recipe 1
you also need Linux with eBPF privilege (or the `mikebom-dev` container).

---

## Recipe 1 — Trace a build

Trace `cargo install ripgrep` end-to-end, produce an in-toto attestation of
every TLS download + file write, then derive a CycloneDX SBOM from that
attestation.

```bash
mikebom trace run \
  --sbom-output ripgrep.cdx.json \
  --attestation-output ripgrep.attestation.json \
  --auto-dirs \
  -- cargo install ripgrep
```

What lands on disk:

- `ripgrep.attestation.json` — in-toto Statement v1 with predicate type
  `https://mikebom.dev/attestation/build-trace/v1`. This is the primary
  artifact: it's the ground truth of what the build actually did.
- `ripgrep.cdx.json` — CycloneDX 1.6 JSON SBOM derived from that attestation.

`--auto-dirs` asks mikebom to infer artifact-cache directories from the
traced command (`cargo` → `$CARGO_HOME/registry/cache`). Pass `--artifact-dir
<path>` one or more times to point at extra directories explicitly.

To re-derive the SBOM from the attestation later (or after enriching with
different flags):

```bash
mikebom sbom generate ripgrep.attestation.json \
  --output ripgrep.cdx.json \
  --enrich --lockfile Cargo.lock
```

---

## Recipe 2 — Scan a container image

Works on any OS. No privilege, no eBPF.

```bash
docker save alpine:3.19 -o alpine.tar
mikebom sbom scan --image alpine.tar --output alpine.cdx.json --json
```

`--image` takes a `docker save` tarball. mikebom extracts the layers (honouring
OCI whiteouts), auto-reads `<rootfs>/etc/os-release` for the distro codename,
reads the installed-package databases (`/var/lib/dpkg/status` for Debian and
derivatives, `/lib/apk/db/installed` for Alpine, `rpmdb.sqlite` for RPM-based
images), and emits a CycloneDX SBOM with a real dependency graph from the
db's `Depends:` fields.

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

## Recipe 3 — Scan a filesystem directory

Point at any directory — a package cache, an extracted rootfs, a source tree
with a lockfile.

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
(has `etc/os-release` at the top), mikebom reads the codename from there and
stamps it on deb PURLs automatically. Override with `--deb-codename <codename>`
when you're scanning a bare directory of `.deb` files.

---

## What's next

- **Find a flag you need?** See the [CLI reference](cli-reference.md).
- **Want to compare SBOM quality to other tools?** See
  [`mikebom sbom compare`](cli-reference.md#mikebom-sbom-compare) and
  [`EVALUATION.md`](../../EVALUATION.md).
- **Curious why the SBOM looks the way it does?** See the
  [architecture overview](../architecture/overview.md).
- **Running into an unfamiliar ecosystem?** See the
  [per-ecosystem reference](../ecosystems.md).
