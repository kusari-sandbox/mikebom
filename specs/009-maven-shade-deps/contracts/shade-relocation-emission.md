# Contract: Shade-Relocation Emission

**Scope**: Internal to `mikebom-cli/src/scan_fs/package_db/maven.rs`.
**Consumers**: The existing JAR-processing loop in `read_with_claims`.

## Functional contract

### `parse_dependencies_file`

```rust
fn parse_dependencies_file(bytes: &[u8]) -> Vec<ShadeAncestor>;
```

**Given** the raw bytes of a JAR's `META-INF/DEPENDENCIES` file,

**When** `parse_dependencies_file` is called,

**Then**:
1. Returns a vec of successfully-parsed `ShadeAncestor` entries.
2. Each entry has non-empty `group_id`, `artifact_id`, `version`.
3. 5-part classifier lines yield entries with `classifier = Some(...)`; 4-part lines yield `classifier = None`.
4. `License: <text>` continuation lines are parsed via `SpdxExpression::try_canonical` and stored in `license` on success; unrecognized license text logs WARN and leaves `license = None`.
5. Non-UTF-8 bytes, parse-fail lines, and unrecognized content DO NOT abort — they're silently skipped for robust handling of hand-edited or unusual manifests.

**Error handling**: the function returns `Vec` (not `Result`). All error paths degrade to "fewer entries in the vec." Callers need not handle errors.

### `emit_shade_relocation_entries`

```rust
fn emit_shade_relocation_entries(
    ancestors: Vec<ShadeAncestor>,
    enclosing_primary_purl: &Purl,
    co_owned_by: Option<String>,
    source_path: &str,
    out: &mut Vec<PackageDbEntry>,
    seen_ancestor_keys: &mut HashSet<String>,
);
```

**Given** a set of parsed `ShadeAncestor` entries plus the enclosing JAR's context,

**When** `emit_shade_relocation_entries` is called,

**Then**:
1. For each ancestor, a `PackageDbEntry` is pushed to `out` with:
   - `purl` = `pkg:maven/<g>/<a>@<v>` + `?classifier=<value>` qualifier when applicable
   - `name` = `artifact_id`
   - `version` = version (or version including classifier encoding per PURL spec)
   - `parent_purl` = `Some(enclosing_primary_purl.to_string())`
   - `sbom_tier` = `Some("analyzed".to_string())`
   - `shade_relocation` = `Some(true)`
   - `co_owned_by` = cloned from the arg
   - `source_path` = cloned from the arg (the enclosing JAR's path)
   - `licenses` = from ancestor's `license` when present; empty vec otherwise
   - Other fields at their default values (None / empty)
2. A ShadeAncestor whose coord equals `enclosing_primary_purl`'s coord is dropped (self-reference guard).
3. A ShadeAncestor whose `(group_id, artifact_id, version, classifier)` tuple has already been seen within this JAR (per `seen_ancestor_keys`) is dropped (per-JAR dedup).

## API surface

Both functions are `pub(super)` / private to the module. Not exported outside `maven.rs`.

## Invariants

- Never fabricates a coord or license.
- Never aborts the JAR's other emissions (primary coord, embedded META-INF/maven, etc.) on parse failure.
- Output order is input order (stable, deterministic).
- When the enclosing JAR has no primary coord, the caller MUST NOT invoke `emit_shade_relocation_entries` at all — a WARN is logged at the call site. (This function never receives an empty primary_purl.)

## Test cases (normative)

### `parse_dependencies_file`

1. **Canonical 4-part entries**: three consecutive `- ... <g>:<a>:jar:<v>` lines with License continuations → returns 3 entries, all with licenses populated.
2. **5-part classifier entry**: one line `- ... <g>:<a>:jar:tests:<v>` → returns 1 entry with `classifier = Some("tests")`.
3. **Unrecognized license text**: entry with `License: Apache License, Version 2.0` (not canonical SPDX) → returns the entry with `license = None`; WARN logged.
4. **Missing license line**: coord line followed by blank line → returns the entry with `license = None`; no warning.
5. **Malformed coord**: line with only 3 colons (`:<g>:<a>:<v>`) → silently skipped.
6. **Non-UTF-8 bytes**: input bytes not valid UTF-8 → returns empty vec.
7. **Empty input**: zero-byte slice → returns empty vec.
8. **Mixed valid + invalid entries**: returns only the valid ones.

### `emit_shade_relocation_entries`

1. **Happy path**: 3 ancestors → 3 PackageDbEntries pushed with correct purls, parent_purl set, shade_relocation = Some(true), sbom_tier = "analyzed".
2. **Self-reference**: ancestor coord equals enclosing → NOT emitted.
3. **Within-JAR duplicate**: same ancestor listed twice → emitted once.
4. **License threading**: ancestor with `license = Some(expr)` → PackageDbEntry's `licenses[]` contains that expression.
5. **co_owned_by inheritance**: arg `co_owned_by = Some("rpm")` → all emitted entries carry that tag.
6. **Classifier emission**: ancestor with `classifier = Some("tests")` → PURL contains `?classifier=tests`.
