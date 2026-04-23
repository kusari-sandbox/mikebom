# Investigation: Why feature 007 US2 / US4 filters didn't close polyglot FPs

**Scan artifact**: `/tmp/008-evidence/post-007.cdx.json` (868 components)
**Scan log**: `/tmp/008-evidence/scan.log` (debug level)
**Polyglot rootfs**: `/tmp/008-polyglot-rootfs/` (extracted from `sbom-fixture-polyglot:latest` docker image, container `cc69b6ab39cc`)

## Binary freshness check (R7)

```
binary: mikebom 0.1.0-alpha.3
git HEAD: 89a334f872e41379f8875960d1ca38e9176c7156
commit date: 2026-04-23 15:05:48 -0400   (= PR #11 US4 merge)
binary mtime: Apr 23 14:34:27 2026
```

Scanned binary was built from `main` after all of PR #8, #9, #10, #11 merged. **Freshness confirmed — findings are NOT a stale-binary artifact.**

## FP 1–4: Go test-scope transitives (testify, go-spew, go-difflib, yaml.v3)

**Expected suppressor**: G3 (BuildInfo intersection) + G4 (production-import intersection).

**Observed tier in SBOM**: `analyzed`, NOT `source`.

**Why the filters didn't fire**: G3 and G4 both operate on `DbScanResult.entries` returned by `package_db::read_all` and only touch entries with `sbom_tier = "source"`. The four FPs appear at `sbom_tier = "analyzed"` emitted by a completely different path: the **generic artifact walker** in `scan_fs/mod.rs:126-190` hashes every file in the rootfs and calls `resolve_path_with_context`, which for paths of the form `/go/pkg/mod/cache/download/<module>/@v/<version>.zip` returns `pkg:golang/<module>@<version>` via `path_resolver::resolve_go_path` at `mikebom-cli/src/resolve/path_resolver.rs:295`. The artifact walker's components bypass `package_db::read_all` entirely, so G3 / G4 / G5 never see them.

**Evidence**:

```json
[
  {
    "purl": "pkg:golang/github.com/stretchr/testify@v1.7.0",
    "tier": "analyzed",
    "source": "/private/tmp/008-polyglot-rootfs/root/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.7.0.zip"
  },
  {
    "purl": "pkg:golang/github.com/davecgh/go-spew@v1.1.1",
    "tier": "analyzed",
    "source": "/private/tmp/008-polyglot-rootfs/root/go/pkg/mod/cache/download/github.com/davecgh/go-spew/@v/v1.1.1.zip"
  },
  {
    "purl": "pkg:golang/github.com/pmezard/go-difflib@v1.0.0",
    "tier": "analyzed",
    "source": "/private/tmp/008-polyglot-rootfs/root/go/pkg/mod/cache/download/github.com/pmezard/go-difflib/@v/v1.0.0.zip"
  },
  {
    "purl": "pkg:golang/gopkg.in/yaml.v3@v3.0.0-20200313102051-9f266ea9e77c",
    "tier": "analyzed",
    "source": "/private/tmp/008-polyglot-rootfs/root/go/pkg/mod/cache/download/gopkg.in/yaml.v3/@v/v3.0.0-20200313102051-9f266ea9e77c.zip"
  }
]
```

Corroborating log lines (filters fired correctly on the source-tier set — 20 entries dropped by G3 — but analyzed-tier cache-ZIP entries bypass them):

```
INFO G3 filter: dropped go.sum entries not confirmed by Go binary BuildInfo dropped=20 linked_count=3
INFO G5 filter: dropped main-module self-references dropped=1 main_modules=3
```

(G4 fired silently; it had nothing left to drop because G3 already covered the source-tier set.)

**Why the lab tests didn't catch this**: the synthetic fixtures for G3/G4/G5 (`scan_go_source_plus_binary_filters_go_sum_to_linked_subset`, `scan_go_source_test_only_import_is_dropped`, etc.) deliberately construct go.sum source-tier entries and Go binaries with BuildInfo. They never populate `/root/go/pkg/mod/cache/download/` in the fixture rootfs, so they don't exercise the artifact-walker's cache-ZIP path. The path_resolver comment at `path_resolver.rs:284-294` even calls this out as deliberate: *"This is the fetch-only artifact the operator sees when they want an SBOM without a full build."* — valuable on scratch/distroless scans, but a FP generator when a Go binary is present on the same rootfs.

**Minimal-fix option (new — call it "R5 Option D")**: add a post-merge filter in `scan_fs/mod.rs::scan_path` (after artifact walker + package_db + binary walker merge, before `deduplicate`) that drops `pkg:golang` components sourced from `/cache/download/` paths whose `(name, version)` is not also confirmed by a non-cache analyzed-tier entry (i.e., not in the BuildInfo-linked set). When no Go binary produced BuildInfo anywhere on the rootfs, the filter no-ops and cache-ZIP entries remain the only signal (preserves scratch-scan behavior).

**Status**: `closable` — scope for Story 2's fix.

## FP 5: `com.example/sbom-fixture@1.0.0` (Maven project-self)

**Expected suppressor**: US4 `Main-Class:` manifest heuristic, or the classic M3 fat-jar heuristic.

**Observed tier in SBOM**: `analyzed`, source = `/opt/javaapp/target/sbom-fixture-1.0.0.jar`.

**Why the filters didn't fire**:

- `is_unclaimed_fat_jar` requires `meta_list.len() >= 2`. The sbom-fixture JAR contains only ONE `META-INF/maven/` entry (its own pom.properties + pom.xml for `com.example:sbom-fixture:1.0.0`). No vendored children. Heuristic fails.
- `is_executable_unclaimed_jar` (US4, PR #11) requires `jar_has_main_class_manifest == true`. The JAR's MANIFEST.MF contains only `Manifest-Version`, `Created-By: Maven JAR Plugin 3.3.0`, and `Build-Jdk-Spec: 21`. **No `Main-Class:` entry.** Heuristic fails.
- `target_name_matches` requires an explicit `--scan-target-name` CLI flag passed by the operator. The bake-off doesn't set it.

**Evidence**:

```
=== /tmp/008-polyglot-rootfs/opt/javaapp/target/sbom-fixture-1.0.0.jar ===
Archive:  /tmp/008-polyglot-rootfs/opt/javaapp/target/sbom-fixture-1.0.0.jar
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  04-18-2026 13:30   META-INF/
       81  04-18-2026 13:30   META-INF/MANIFEST.MF
        0  04-18-2026 13:30   com/
        0  04-18-2026 13:30   com/example/
        0  04-18-2026 13:30   META-INF/maven/
        0  04-18-2026 13:30   META-INF/maven/com.example/
        0  04-18-2026 13:30   META-INF/maven/com.example/sbom-fixture/
      528  04-18-2026 13:30   com/example/App.class
      528  04-18-2026 13:22   META-INF/maven/com.example/sbom-fixture/pom.xml
       58  04-18-2026 13:30   META-INF/maven/com.example/sbom-fixture/pom.properties
---------                     -------

--- MANIFEST.MF ---
Manifest-Version: 1.0
Created-By: Maven JAR Plugin 3.3.0
Build-Jdk-Spec: 21
```

No Main-Class line. Only one META-INF/maven entry. The JAR is an ordinary Maven JAR Plugin build output without fat-jar / executable packaging — precisely the case US4's heuristic doesn't cover.

**Minimal-fix option**: extend the heuristic with a **Maven target-dir path signal**: when an unclaimed JAR lives under a directory named `target/` (canonical Maven build-output convention — `<project>/target/<artifactId>-<version>.jar`) AND its primary coord matches the JAR's filename stem, treat it as scan subject. This is narrower than a generic "any primary coord" rule (so dependency JARs in `/usr/share/java/` don't get dropped) and narrower than "any JAR with `/target/` in its path" (so accidentally-named dirs don't trigger). The combination is a high-specificity scan-subject signal.

**Status**: `closable` — scope for Story 3's fix.

## Summary table

| Target FP | Expected suppressor | Status |
|---|---|---|
| `pkg:golang/github.com/stretchr/testify@v1.7.0` | G3 / G4 | **closable** (Story 2 — new "G6" post-merge cache-ZIP filter) |
| `pkg:golang/github.com/davecgh/go-spew@v1.1.1` | G3 / G4 | **closable** (Story 2 — same filter) |
| `pkg:golang/github.com/pmezard/go-difflib@v1.0.0` | G3 / G4 | **closable** (Story 2 — same filter) |
| `pkg:golang/gopkg.in/yaml.v3@v3.0.0-...` | G3 / G4 | **closable** (Story 2 — same filter) |
| `pkg:maven/com.example/sbom-fixture@1.0.0` | US4 Main-Class heuristic | **closable** (Story 3 — Maven target-dir path heuristic) |

## Planned Story 2/3 scope

**Story 2 (Go)**: ALL FOUR Go FPs are closable with a single post-merge filter in `scan_fs/mod.rs::scan_path`. No per-FP work; one change covers all four. Zero FPs move to known-limitation for Go.

**Story 3 (Maven)**: sbom-fixture is closable with the target-dir path heuristic extension to `is_unclaimed_fat_jar` / the US4 `is_executable_unclaimed_jar` branch in `maven.rs`. Zero FPs move to known-limitation for Maven.

**Story 4 (Documentation)**: Only the `commons-compress 1.21 vs 1.23.0` convention case is documented. No Story-2 or Story-3 known-limitation entries needed (because every FP is closable).

**Expected final state after all four slices**: polyglot bake-off finding count goes from 6 to 1 (commons-compress, documented as known behavior per FR-010).
