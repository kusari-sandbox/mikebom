# Contract: Investigation Evidence (Story 1 deliverable)

**Scope**: Story 1 must produce `specs/008-polyglot-final-cleanup/investigation.md` that satisfies this contract. The document is the gate for Stories 2 and 3 — no code change ships against this feature until the investigation is complete and reviewed.

## Required sections

The investigation document MUST contain one section per target FP, with these subsections each:

### Per-FP section template

```markdown
## FP: <purl>

**Expected suppressor**: <filter name — G3 / G4 / G5 / Main-Class heuristic / classic fat-jar heuristic>
**Observed tier in SBOM**: <"analyzed" | "source" | other>
**Why it didn't fire**: <one sentence>

**Evidence**:

```
<jq output OR tracing::debug line OR file-read snippet that supports the claim>
```

**Minimal-fix option**: <Option A/B/C from research.md R5, OR "no static fix possible — see FU-001", OR "stale-binary; re-run bake-off">

**Status**: <closable in Story 2/3 | known-limitation → Story 4 | stale-binary (no action on mikebom)>
```

## Mandatory evidence artifacts

For each FP, at least ONE of the following pieces of evidence MUST be present:

1. **`jq` output snippet** from the actual polyglot-bake-off SBOM JSON, showing the component's `purl`, `sbom_tier` property, and `source_path`.
2. **`tracing::debug!`-level log output** captured by running mikebom with `RUST_LOG=debug` against the polyglot rootfs, showing the filter's decision for this specific component.
3. **File-read output** (e.g., `unzip -p`, `go version -m`, `find`) that directly supports the "why it didn't fire" claim.

Hand-waving, theorizing, or "I think the reason is…" without a supporting artifact is NOT acceptable. This is the direct lesson of the M4 → G3 post-mortem.

## Global sections

The document MUST also have:

- **Binary freshness check (R7)**: confirmation that the bake-off ran against a post-007-merge mikebom binary. Cite the commit SHA and the binary mtime.
- **Summary table**: 2-column table — target FPs on rows, status on columns (one of: closable / known-limitation / stale-binary).
- **Planned Story 2/3 scope**: the list of FPs that will be actively fixed (`closable`) and those that will be documented (`known-limitation`). Empty list allowed if Story 1 concludes the only gap was stale-binary — in that case Stories 2/3 become no-ops and the feature closes with just Story 4's documentation.

## Non-goals

- The investigation document does NOT propose the final code change — that's Stories 2/3's responsibility. It proposes a minimal-fix OPTION per FP but doesn't commit to it.
- The investigation document does NOT attempt to fix the commons-compress case — that's Story 4's documentation scope, separate from the 5 mikebom-closable FPs.
- The investigation is NOT a complete architectural review. Scoped strictly to the 5 named FPs (4 Go + sbom-fixture).

## Acceptance criteria

A reviewer reading the investigation document MUST be able to:

1. Name, for each FP, the concrete reason it wasn't closed by the shipped filter.
2. See the supporting evidence artifact for each claim.
3. Decide (before implementation starts) which FPs move to Stories 2/3 and which move to Story 4.
