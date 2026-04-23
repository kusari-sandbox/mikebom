# Phase 1 Data Model: Shade-Relocated Maven Dependency Emission

## New types

### `ShadeAncestor` (private to `maven.rs`)

Intermediate representation of one parsed entry in a JAR's `META-INF/DEPENDENCIES` file. Constructed in memory during JAR processing; consumed immediately to produce a `PackageDbEntry`; not persisted or exposed across module boundaries.

```rust
struct ShadeAncestor {
    group_id: String,
    artifact_id: String,
    classifier: Option<String>,   // None for 4-part coord lines, Some for 5-part
    version: String,
    license: Option<SpdxExpression>,  // Some when License: line parsed + canonicalized
}
```

**Invariants**:
- `group_id`, `artifact_id`, `version` are non-empty after parsing (lines that fail to populate all three are rejected at parse time, per FR-002).
- `classifier` is `Some(non_empty)` or `None`.
- `license` is `Some` only when `SpdxExpression::try_canonical` succeeded on the License continuation line.

**Lifecycle**: Constructed inside `parse_dependencies_file(bytes)`. Vec of these is returned, iterated once by `emit_shade_relocation_entries`, then dropped.

## Existing types extended

### `PackageDbEntry` (in `mikebom-cli/src/scan_fs/package_db/mod.rs`)

Add one field:

```rust
/// Feature 009: `Some(true)` when the entry was derived from a
/// shaded JAR's `META-INF/DEPENDENCIES` file (ancestor dep with
/// relocated bytecode inside the enclosing JAR). Consumers can
/// filter on this to separate "linkable direct deps" from
/// "bytecode-present shaded ancestors." Surfaced via CDX property
/// `mikebom:shade-relocation = true`.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub shade_relocation: Option<bool>,
```

**Default**: `None` everywhere except shade-relocation emissions. Mirrors the existing `detected_go: Option<bool>` pattern.

### `ResolvedComponent` (in `mikebom-common/src/resolution.rs`)

Same addition pattern — add `shade_relocation: Option<bool>` field with identical serialization semantics. Threaded from `PackageDbEntry` → `ResolvedComponent` at the aggregation point in `scan_fs/mod.rs`, mirroring the existing `is_dev`, `detected_go`, etc. threading.

### CDX property emission (in `mikebom-cli/src/generate/cyclonedx/builder.rs` or equivalent)

When `ResolvedComponent.shade_relocation == Some(true)`, emit a property on the component:

```json
{"name": "mikebom:shade-relocation", "value": "true"}
```

No serialization for `None` / `Some(false)` values (those don't surface in output). Follows the same pattern used by `is_dev`, `detected_go`.

## Validation rules

- Shade-relocation entries are emitted only when the enclosing JAR has a resolvable primary coord (embedded META-INF/maven OR Fedora sidecar). When neither yields a primary, emission is skipped with WARN log (per spec Assumptions).
- A ShadeAncestor whose `(group_id, artifact_id, version)` equals the enclosing JAR's primary coord is dropped (FR-005 self-reference guard).
- Within a single JAR, duplicate ShadeAncestors (same GAV + classifier) are collapsed to one emission (FR-006).
- The `licenses[]` field on the emitted `PackageDbEntry` is populated from `ShadeAncestor.license` when `Some`; otherwise empty.
- The `purl` carries `?classifier=<value>` qualifier when `ShadeAncestor.classifier` is `Some`.

## State transitions

None. All new types are constructed + consumed in a single flow; no mutable state machines.

## Deduplicator interaction (no change)

The existing dedup key `(ecosystem, name, version, parent_purl)` already distinguishes shade-relocation entries from standalone JARs with the same coord — the `parent_purl` differs. No code change to `deduplicator.rs` needed.
