# Installation

mikebom has two modes with different runtime requirements.

| Mode | Subcommands | Needs |
|---|---|---|
| **Tracing** | `mikebom trace capture`, `mikebom trace run` | Linux kernel ≥ 5.8, eBPF privilege (`--privileged` container or root) |
| **Scanning** | `mikebom sbom scan`, `mikebom sbom generate`, `mikebom sbom compare` | Any OS Rust runs on. No privilege. No eBPF. |

If you only need `sbom scan` / `sbom generate` / `sbom compare`, you can build
and run mikebom natively on macOS, Windows (WSL2), or Linux. `trace` requires
Linux with eBPF.

## Build from source

Stable Rust, standard workspace build:

```bash
cargo build --release
```

The binary lands at `./target/release/mikebom`. Add it to `$PATH` or invoke it
directly.

```bash
./target/release/mikebom --help
```

The workspace has three crates (`mikebom-cli`, `mikebom-common`, `mikebom-ebpf`)
plus an `xtask` crate. A single `cargo build --release` from the repo root
produces the CLI binary.

## Development container (Linux eBPF, macOS, Windows)

The tracing subcommands need a privileged Linux host. On macOS, Windows, or
when you don't want to build toolchain dependencies locally, use the provided
dev container — it ships a compatible kernel, the BPF toolchain, and `syft` +
`trivy` so you can run the comparison demos.

```bash
docker build -t mikebom-dev -f Dockerfile.dev .
docker run --rm --privileged \
  -v "$PWD:/mikebom-src:ro" \
  mikebom-dev \
  bash /mikebom-src/demos/debian/run.sh
```

`--privileged` is required: eBPF probe attachment uses capabilities that
rootless Docker and unprivileged containers don't expose.

See [`demos/README.md`](../../demos/README.md) for full build and run
instructions for the Debian and Rust demos.

## Lima VM (macOS)

For an interactive Linux shell on macOS without Docker, the repo ships a
[`lima.yaml`](../../lima.yaml) recipe. Provision with:

```bash
limactl start --name=mikebom lima.yaml
limactl shell mikebom
```

Inside the VM, `cargo build --release` and `trace`/`scan` subcommands work as on
any Linux host.

## Verify the install

```bash
mikebom --help
mikebom sbom --help
mikebom trace --help
```

If `mikebom --help` shows the top-level `trace` / `sbom` / `attestation` nouns
and the global flags (`--offline`, `--include-dev`, `--include-legacy-rpmdb`),
the install is ready. Move on to the [quickstart](quickstart.md).
