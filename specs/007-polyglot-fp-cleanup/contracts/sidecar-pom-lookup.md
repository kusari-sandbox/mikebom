# Contract: Fedora Sidecar POM Lookup

**Scope**: Internal to `mikebom-cli/src/scan_fs/package_db/maven.rs` and the new `maven_sidecar.rs`.
**Consumers**: The existing Maven reader's JAR processing loop.

## Functional contract

**Given** a `FedoraSidecarIndex` built from a rootfs's `/usr/share/maven-poms/` directory, and a JAR file absolute path whose `walk_jar_maven_meta()` returned empty (no `META-INF/maven/` inside),

**When** the Maven reader calls `lookup_sidecar_pom(index, jar_path)`,

**Then** the function:
1. Strips the JAR's filename of its `.jar` suffix and trailing version component (e.g., `guice-5.1.0.jar` → `guice`).
2. Queries the index for the stripped basename.
3. On hit: returns the absolute path to the matching sidecar POM file.
4. On miss: returns `None`.

No I/O beyond the index lookup. Parser invocation is the caller's responsibility.

## API surface

```rust
// In maven_sidecar.rs
pub(crate) fn build_fedora_sidecar_index(rootfs: &Path) -> FedoraSidecarIndex;

pub(crate) fn lookup_sidecar_pom<'a>(
    index: &'a FedoraSidecarIndex,
    jar_path: &Path,
) -> Option<&'a Path>;
```

## Invariants

- `build_fedora_sidecar_index` walks only `<rootfs>/usr/share/maven-poms/`. It does not recurse into subdirectories other than the documented Fedora layout.
- The index is built even when the directory does not exist (result is empty).
- Lookup is case-sensitive on the basename (Fedora POM filenames are canonical ASCII).
- When both `JPP-<name>.pom` and `<name>.pom` are present for the same basename, `<name>.pom` takes precedence (newer Fedora convention).

## Error modes

- Directory not present → empty index; all lookups return `None`; no error.
- Directory present but unreadable (permission error) → log warning, return empty index. Scan continues.
- A POM file present but unreadable mid-scan → skipped silently by the build pass; lookup will return `None` for that basename.

## Test cases (normative)

1. JAR present, matching `JPP-<name>.pom` present → returns Some(path).
2. JAR present, matching `<name>.pom` present → returns Some(path).
3. JAR present, both `JPP-<name>.pom` and `<name>.pom` present → returns the `<name>.pom` path.
4. JAR present, no matching POM → returns None.
5. `/usr/share/maven-poms/` missing → all lookups return None; no panic.
6. JAR name with unusual version format (e.g., `foo-1.0-SNAPSHOT.jar`) → version suffix correctly stripped; basename match works.
