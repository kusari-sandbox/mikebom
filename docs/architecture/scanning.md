# Scanning

The scan layer turns a filesystem tree (or an extracted container image) into
a set of candidate components. It is the left-hand entry point of the
pipeline for `sbom scan`; for `trace run` / `sbom generate`, the equivalent
role is played by the [resolution pipeline](resolution.md) reading attestation
events.

**Key files:**

- `mikebom-cli/src/scan_fs/mod.rs` — scan entry point (`scan_path`), ecosystem
  orchestration, relationship resolution, generation-context selection.
- `mikebom-cli/src/scan_fs/walker.rs` — generic directory walker, per-file
  streaming SHA-256, artifact-suffix filtering, size cap.
- `mikebom-cli/src/scan_fs/docker_image.rs` — `docker save` tarball extractor:
  layer merging, OCI whiteout handling, os-release reader.
- `mikebom-cli/src/scan_fs/os_release.rs` — `/etc/os-release` + fallback
  `/usr/lib/os-release` parser. Reads `ID` + `VERSION_ID` and populates the
  `distro=<namespace>-<VERSION_ID>` PURL qualifier shared by deb, rpm, and
  apk (e.g., `distro=debian-12`, `distro=ubuntu-24.04`, `distro=alpine-3.19`).
- `mikebom-cli/src/scan_fs/package_db/*.rs` — one module per ecosystem.

## The three evidence sources

Per-component evidence falls into one of three categories, ordered by trust:

| Source | Technique | Confidence | Who knows it |
|---|---|---|---|
| **Installed-package DB** | `PackageDatabase` | 0.85 | dpkg, apk, rpm sqlite, npm lockfile, Cargo.lock, go.sum, Gemfile.lock, Poetry/Pipfile — the OS or package manager's authoritative record of what *is* installed (or should be per the lock). |
| **Artifact file** | `FilePathPattern` / `filename` | 0.70 | mikebom, via directory walk + SHA-256. The file physically exists on disk with matching bytes. |
| **External lookup** | `HashMatch` (deps.dev) | 0.90 | deps.dev, consulted with a content hash pulled from an attestation's TLS response. Only active in `sbom generate` / trace mode. |

The walker stream-hashes every file whose extension matches one of the
recognised artifact suffixes (`.deb`, `.crate`, `.whl`, `.jar`, `.gem`,
`.apk`, `.rpm`, `.tar.gz`, …); these flow to `FilePathPattern` resolution. The
package-DB modules do not stream-hash — their authority is the package
manager's bookkeeping, not the bytes.

## Container-image scanning (`--image`)

`scan_fs::docker_image::extract` handles both formats `docker save` can
produce:

- Legacy `layer/layer.tar` format (pre-buildkit images).
- Modern `blobs/sha256/<digest>` OCI form.

Layers are extracted in manifest order into a tempdir; OCI whiteout files
(`.wh.<name>`) and opaque directories (`.wh..wh..opq`) suppress files and
directories from lower layers. The result is a rootfs-shaped tempdir that the
scanner processes as if `--path <tempdir>` had been passed. `/etc/os-release`
(with fallback to `/usr/lib/os-release`) is read to auto-detect the distro
identity — `ID` + `VERSION_ID` become the `distro=<namespace>-<VERSION_ID>`
PURL qualifier (e.g., `distro=debian-12`). See
[PURL canonicalization](purls-and-cpes.md) for the full rule — the same
shape applies across deb, rpm, and apk so downstream consumers don't need
per-ecosystem branching.

## Per-ecosystem detection

Each `package_db/*.rs` module knows how to find packages in its ecosystem's
idiom. The coverage matrix:

| Ecosystem | Module | Primary source | Dep-graph source | Notes |
|---|---|---|---|---|
| apk | `apk.rs` | `/lib/apk/db/installed` stanzas (P/V/A/D keys) | DB (direct `D:` only) | Alpine apk |
| cargo | `cargo.rs` | `Cargo.lock` v3/v4 | Lockfile | v1/v2 rejected |
| deb | `dpkg.rs` + `copyright.rs` + `file_hashes.rs` | `/var/lib/dpkg/status` + per-file `.list` manifests | DB (`Depends:`) | Optional deep per-file SHA-256 |
| gem | `gem.rs` | `Gemfile.lock` indent structure + `specifications/*.gemspec` | Lockfile indent-6 | Gemspec walker catches stdlib gems |
| golang | `golang.rs` + `go_binary.rs` | `go.mod` / `go.sum` / `$GOMODCACHE/cache/download/<escaped>/@v/<v>.mod` walker; `runtime/debug.BuildInfo` for Go 1.18+ binaries | Cache walker (source); **none** for binaries | Pre-1.18 binaries: `buildinfo-status=unsupported` |
| maven | `maven.rs` | Project `pom.xml`, JAR `META-INF/maven/.../pom.properties,pom.xml`, `~/.m2/repository/.../*.pom` | Layered: project → JAR-embedded → M2 BFS → parent POM chain → deps.dev → empty | Most complex ecosystem — see [design-notes §Dep-graph resolution strategy (Maven)](../design-notes.md#dep-graph-resolution-strategy-maven) |
| npm | `npm.rs` | `package-lock.json` v2/v3, `pnpm-lock.yaml`, `node_modules/` | Lockfile | v1 rejected |
| pip | `pip.rs` | venv `dist-info/METADATA`, Poetry/Pipfile locks, `requirements.txt --hash=` | Poetry/Pipfile (full), venv flat | `requirements.txt --hash=alg:hex` flags captured for per-component integrity |
| rpm | `rpm.rs` + `rpmdb_sqlite/` | `/var/lib/rpm/rpmdb.sqlite` (pure-Rust reader) | DB (`REQUIRES`) | BDB `Packages` format detected but not parsed — diagnostic log, zero components (flag `--include-legacy-rpmdb` threads through for future BDB reader) |

See [`ecosystems.md`](../ecosystems.md) for per-ecosystem detail including
PURL format notes, hash sources, and known limitations.

## Relationship resolution

Package DBs emit dependency edges alongside components. `scan_fs::mod.rs` runs
a post-pass over the combined relationship list to:

1. Drop relationships whose source or target isn't in the deduplicated
   component set (dangling-target filter). Dangling edges typically come from
   `Depends:` lines referencing virtual packages or packages outside the
   install set.
2. Normalize names for cross-package equality (see the `normalize_dep_name`
   function and the [same-artifactId-different-groupId note in
   design-notes](../design-notes.md#maven)).

## Container- vs. path-mode differences

`scan_cmd.rs` tracks a `ScanMode` enum (`Image` vs. `Path`) that flows down
through the pipeline. The only feature currently gated on it is feature 005's
npm internals filtering: inside an extracted image, `node_modules/npm/node_modules/**`
entries are marked `mikebom:npm-role = internal`; in path mode they are
filtered out before resolution. Future scan-mode-aware logic (e.g. treating
`node_modules/` as authoritative vs. derivable) hooks onto the same enum.

## Generation context

Scan mode stamps one of three `GenerationContext` values on the output:

- `FilesystemScan` — `--path <dir>` where the dir is not a rootfs-shaped tree.
  Most filesystem scans (cache directories, source trees).
- `ContainerImageScan` — `--image <tar>`. The scanner extracts the tarball
  and stamps this context.
- `BuildTimeTrace` — never stamped by `sbom scan`; see
  [generation.md](generation.md) for where this value comes from.

This value lands at the top of the CycloneDX BOM under
`metadata.component.properties.mikebom:generation-context` so downstream
consumers know what kind of evidence produced the SBOM.
