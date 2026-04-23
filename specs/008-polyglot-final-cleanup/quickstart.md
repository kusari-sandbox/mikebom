# Quickstart: Polyglot Final Cleanup

Four slices. Story 1 is the gate for everything downstream.

## Prerequisites

- Branch: `008-polyglot-final-cleanup` (from `/speckit.specify`).
- Main at commit `b06eda8` or later (post-007).
- Access to the polyglot-builder-image rootfs — either extracted locally or via the bake-off harness that produced the FP findings. **Without this, Story 1 cannot be completed honestly.**

## Slice 1 (P1): Story 1 — investigation

No code changes. Deliverable is `specs/008-polyglot-final-cleanup/investigation.md`.

### Step-by-step

1. **Confirm binary freshness (R7)**:
   ```bash
   ./target/release/mikebom --version
   git log -1 --oneline main
   # Confirm the binary was built from a commit at or after b06eda8.
   ```

2. **Run mikebom against the polyglot rootfs with debug logging**:
   ```bash
   RUST_LOG=mikebom=debug ./target/release/mikebom --offline sbom scan \
     --path <polyglot-rootfs> \
     --output /tmp/008-polyglot.cdx.json \
     2> /tmp/008-polyglot.scan.log
   ```

3. **For each of the 4 Go FPs, determine the tier**:
   ```bash
   for mod in "stretchr/testify" "davecgh/go-spew" "pmezard/go-difflib" "gopkg.in/yaml.v3"; do
     echo "=== $mod ==="
     jq --arg m "$mod" '.components[]
        | select(.purl | contains($m))
        | {purl, tier: (.properties[]? | select(.name=="mikebom:sbom-tier") | .value),
           source: (.properties[]? | select(.name=="mikebom:source-files") | .value)}' \
       /tmp/008-polyglot.cdx.json
   done
   ```

4. **Inspect the binary's BuildInfo to see which modules it genuinely links**:
   ```bash
   find <polyglot-rootfs> -name "*.jar" -o -type f -perm -u+x \
     | while read f; do
         if go version -m "$f" >/dev/null 2>&1; then
           echo "=== $f ==="
           go version -m "$f" | grep -E "^\s+(dep|mod)" | head
         fi
       done
   ```
   Requires a local Go toolchain for the DIAGNOSTIC READ. This is NOT a scan-time invocation — it's the investigator manually answering "does the binary link testify?" Acceptable because it's one-off investigation, not a shipped code path.

5. **Inspect sbom-fixture JAR manifest**:
   ```bash
   find <polyglot-rootfs> -name "*sbom-fixture*.jar" -print0 \
     | xargs -0 -I {} sh -c 'echo "=== {} ==="; unzip -p "{}" META-INF/MANIFEST.MF'
   ```

6. **Check scan-log for filter decisions**:
   ```bash
   grep -E "G3 filter|G4 filter|G5 filter|sidecar|executable-jar-heuristic|fat-jar-heuristic" \
     /tmp/008-polyglot.scan.log
   ```

7. **Fill in `investigation.md`** per the contract at `contracts/investigation-evidence.md`. One section per FP, with evidence artifact from steps 3–6.

8. **Finalize summary table** and the "Planned Story 2/3 scope" list.

### Exit criteria for Slice 1

- Every target FP has a named root cause + evidence artifact.
- Every FP is categorized as {closable, known-limitation, stale-binary}.
- Summary table and scope list are final.
- PR opened with `investigation.md` + a brief writeup; reviewed before Slices 2/3 begin.

## Slice 2 (P2): Story 2 — Go test-scope fix

Shape depends entirely on Slice 1's findings. Options from R5:
- If "closable" → ship the minimal code change identified in `investigation.md`. Add a regression test mirroring the polyglot scenario (use Slice 1's evidence to shape a faithful fixture). Verify via `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace`. Run the post-fix binary against the polyglot rootfs; confirm the targeted FPs are gone; attach before/after diff to PR.
- If "known-limitation" → no code change. Roll the limitation into Story 4's documentation.
- If "stale-binary" → no mikebom change at all; communicate to bake-off operator to re-run with a fresh binary.

## Slice 3 (P3): Story 3 — Maven sbom-fixture fix

Same structure as Slice 2 but for `com.example/sbom-fixture@1.0.0`. Fix options (from R5): extend Main-Class heuristic to also trigger on `BOOT-INF/classes/` or `WEB-INF/` presence; OR extend on filename-stem-matches-coord signal; OR path-heuristic. Whichever Slice 1 shows matches the actual polyglot JAR's shape without over-suppressing library JARs.

Must include regression test asserting a library JAR with `Main-Class:` (like `commons-lang3`'s CLI entry point) is still emitted.

## Slice 4 (P4): Story 4 — documentation

`docs/design-notes.md` additions:

1. Paragraph on commons-compress 1.21 vs 1.23.0:
   - Why the two versions appear.
   - mikebom's default: embedded POM wins (cite feature 007 FR-004).
   - Workaround for operators who want the opposite default: exclude `.m2/repository/` or override via future feature flag (pointer to FU-002).
2. Any known-limitation entries surfaced by Stories 2 or 3 (e.g., "Go test-scope modules linked into BuildInfo are not filterable by static signals alone; cross-ref FU-001").
3. Summary: after this feature lands, polyglot-builder-image bake-off has at most 1 open finding (commons-compress), now documented.

## Cumulative success criteria

1. `cargo +stable clippy --workspace --all-targets` clean on every PR.
2. `cargo +stable test --workspace` passing on every PR; total count ≥ 1119 (post-007 baseline).
3. `investigation.md` is committed and reviewed before Stories 2/3 code lands.
4. Polyglot bake-off finding count is ≤ 1 after all four slices land (commons-compress is the documented exception).
5. No regression in cargo/gem/pypi/rpm/binary ecosystem scoreboards.

## Rollback

Each slice is a separate PR. If Slice 2 or 3's fix causes regression, revert just that PR; Story 1's investigation and Story 4's documentation remain on main.
