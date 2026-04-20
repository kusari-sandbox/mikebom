# mikebom demos

Two end-to-end scenarios that run mikebom, syft, and trivy against the same
workload and produce a side-by-side comparison report.

Both demos must run inside the `mikebom-dev` Docker container — they rely on
eBPF (Linux kernel ≥ 5.8), the mikebom release binary at `/mikebom/target/release/mikebom`,
and `syft` + `trivy` installed in `/usr/local/bin`.

## Running

From the repo root:

```bash
# Build the dev image if you haven't yet (also installs syft + trivy)
docker build -t mikebom-dev -f Dockerfile.dev .

# Rust demo: traces `cargo install ripgrep`
docker run --rm --privileged \
  -v "$PWD:/mikebom-src:ro" \
  mikebom-dev \
  bash /mikebom-src/demos/rust/run.sh

# Debian demo: traces `apt-get install`
docker run --rm --privileged \
  -v "$PWD:/mikebom-src:ro" \
  mikebom-dev \
  bash /mikebom-src/demos/debian/run.sh
```

Each script writes its artifacts to a temp directory inside the container and
prints the final `report.md` to stdout. Add `-v <hostdir>:/out` + `OUT_DIR=/out`
to persist them.

## What each demo produces

| File                          | Contents                                                    |
|-------------------------------|-------------------------------------------------------------|
| `mikebom.attestation.json`    | in-toto statement with network + file-access trace          |
| `mikebom.cdx.json`            | CycloneDX SBOM derived from the attestation                 |
| `syft.cdx.json`               | CycloneDX SBOM from syft scanning the same package cache    |
| `trivy.cdx.json`              | CycloneDX SBOM from trivy scanning the same package cache   |
| `truth.txt` (or `Cargo.lock`) | Ground truth: packages that were actually installed         |
| `report.md`                   | Per-tool recall / precision / evidence-coverage / diffs     |

The comparison is produced by `mikebom sbom compare`, which is just another
subcommand of the mikebom binary — no external comparison tool needed.
