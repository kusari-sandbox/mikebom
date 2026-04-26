# Research: Module Splits — pip.rs, npm.rs, binary/mod.rs

**Phase 0 output for** `/specs/018-module-splits/spec.md`

This document resolves the open technical questions from `plan.md`. Each section follows: **Decision** / **Rationale** / **Alternatives considered**.

---

## R1. Inline `#[cfg(test)]` test modules — move with code or stay at orchestrator?

**Context**: Each of the three target files carries a `#[cfg(test)] mod tests { ... }` block at the bottom. pip.rs's tests cover `parse_requirements_line`, `parse_hash_alg`, marker matching, and a few orchestrator-level cases. npm.rs's tests cover `derive_name_from_path_key`, integrity parsing, and `classify_npm_source`. binary/mod.rs's tests are smaller (the integration test `tests/scan_binary.rs` carries most binary coverage).

**Decision**: **Tests move with the production code they exercise.** A test like `parse_requirements_line` lives in `pip/requirements_txt.rs::tests`; a test like `parse_pnpm_key` lives in `npm/pnpm_lock.rs::tests`. Tests that exercise cross-cutting orchestrator behavior (the `read()` flow, dedup-and-merge logic) stay at `mod.rs::tests`.

**Rationale**:

- Per-submodule tests can reference the submodule's private items directly (no `pub(super)`-leakage just for testing). This preserves Rust's standard tight-coupling-of-test-and-code idiom.
- Test names are preserved verbatim (FR-007), so the per-target test list at the post-split `cargo test` is a strict superset of pre-split. SC-004 verifies this with a sorted-name diff.
- A reviewer reading `pip/poetry.rs` sees both the parser AND the tests for that parser — same scroll-distance benefit as the production split.

**Alternatives considered**:

- **All tests stay at `mod.rs`**. Rejected — defeats the readability win for tests. Also forces every test that used a private function to gain `pub(super)` visibility.
- **One mega `tests.rs` submodule per directory**. Rejected — drifts from the standard "tests next to code" Rust idiom and adds a layer of indirection without benefit.

---

## R2. Naming convention for new submodules

**Context**: Several plausible names exist for each split. `poetry.rs` vs `poetry_lock.rs` vs `lockfiles_poetry.rs`. `requirements_txt.rs` vs `requirements.rs` vs `pip_requirements.rs`. `walk.rs` vs `node_modules.rs` vs `flat_walk.rs`. The choice affects discoverability via `find` / IDE-fuzzy-search and how the file-tree reads.

**Decision**:

- **`pip/`**: `mod.rs`, `dist_info.rs`, `poetry.rs`, `pipfile.rs`, `requirements_txt.rs`. Each name maps to a published Python-ecosystem concept that a contributor would search for.
- **`npm/`**: `mod.rs`, `package_lock.rs`, `pnpm_lock.rs`, `walk.rs`, `enrich.rs`. The lockfile names are the npm-ecosystem published concepts; `walk.rs` for the `node_modules/` flat walker (no upstream "walker" name to anchor on); `enrich.rs` for the author-backfill layer.
- **`binary/`**: `mod.rs`, `discover.rs`, `scan.rs`, `entry.rs`. Verbs/nouns that describe what each submodule *does*, not what input format it consumes (since binary scan crosses ELF / Mach-O / PE / fat-Mach-O — no single format anchors).

**Rationale**:

- For format-anchored splits (pip, npm), use the upstream-published format name. A contributor searching for "poetry" or "pnpm" finds the module instantly.
- For verb/role-anchored splits (binary), use the role. The binary module isn't split by format (ELF vs Mach-O are still mixed in `scan.rs`) — it's split by step in the pipeline (find files → scan one → produce entry).
- `requirements_txt.rs` rather than `requirements.rs` because requirements.txt is the *file extension that matters*; without `_txt` the name is ambiguous with `cargo install --requirement` etc.

**Alternatives considered**:

- **`pip/lockfiles.rs` (combine poetry + pipfile)**. Rejected — Poetry and Pipfile are independent ecosystems with non-overlapping parsers; combining them produces a 230 + 95 = ~330 LOC file with two unrelated concerns. Two single-concern files at ~140 + ~95 LOC are clearer.
- **`npm/lockfiles.rs` (combine package-lock + pnpm-lock)**. Same rejection rationale — they're independent file formats with independent parsers.
- **`binary/elf.rs` extending the existing sibling for the new scan code**. Rejected — the existing `binary/elf.rs` is for ELF-specific *type* definitions and parsers; the `scan_binary` function in mod.rs handles ELF + Mach-O + PE generically via the `object` crate. Naming the new file `binary/scan.rs` keeps the format-vs-orchestration distinction clean.

---

## R3. Visibility ladder — `pub(super)` vs `pub(crate)` for cross-sibling access

**Context**: When `pip/poetry.rs::poetry_is_dev` is called from `pip/mod.rs::read`, what visibility does `poetry_is_dev` need? Pre-split it was `fn` (private to pip.rs). Post-split it must be visible to `pip/mod.rs`.

**Decision**: **`pub(super)`** for cross-sibling visibility within a directory module. **`pub(crate)`** is reserved for items that legitimately need to be reachable from outside the directory (e.g., `pip::collect_claimed_paths` is called from `scan_fs/mod.rs`). **`pub`** stays only for items that are part of the milestone-stable public surface (e.g., `pip::read`).

**Rationale**:

- `pub(super)` says "this is reachable from siblings in the same parent module" — exactly the seam we're creating. It's the minimum visibility increase that compiles.
- `pub(crate)` is broader than needed for sibling access; using it here would over-expose internal helpers to the rest of `mikebom-cli`. Reserve it for items that have legitimate crate-wide callers.
- Items that were `pub` in `pip.rs` (visible to the full `mikebom_cli` API surface) stay `pub` and get re-exported from `pip/mod.rs` via `pub use`.

**Visibility decisions table** (canonical list of expansions, also captured in data-model.md):

| Item | Pre-split | Post-split | Reason |
|---|---|---|---|
| `pip::read` | `pub` | `pub` (re-exported from `pip/mod.rs`) | External callers in `scan_fs/mod.rs` |
| `pip::collect_claimed_paths` | `pub` | `pub` (re-exported) | External caller |
| `pip::PipDistInfoEntry` (if exposed) | `pub` | `pub` (defined in `pip/dist_info.rs`, re-exported from `pip/mod.rs`) | If pre-split was `pub` |
| `pip::poetry_is_dev` | `fn` | `pub(super) fn` (in `pip/poetry.rs`) | Called from `pip/mod.rs::read` |
| `pip::should_skip_python_descent` | `fn` | `pub(super) fn` (in `pip/mod.rs`) | Called from sibling submodules' walkers |
| `npm::NpmError` | `pub enum` | `pub` (defined in `npm/mod.rs`) | External callers |
| `npm::derive_name_from_path_key` | `fn` | `pub(super) fn` (in `npm/walk.rs`) | Called from `npm/package_lock.rs` |
| `binary::scan_binary` | `fn` | `pub(super) fn` (in `binary/scan.rs`) | Called from `binary/mod.rs::read` |
| `binary::detect_rootfs_kind` | `fn` | stays in `binary/mod.rs` (orchestrator-level) | Called from `read()` only |

**Alternatives considered**:

- **`pub(crate)` for everything cross-sibling**. Rejected — over-exposes; defeats the purpose of having sibling-scoped visibility.
- **Re-export via `pub use` from `mod.rs` for everything cross-sibling**. Rejected — `pub use` is for items meant to be part of the module's public API, not for plumbing internal access between siblings.

---

## R4. Cross-submodule helpers — where do they live?

**Context**: Some helpers are used by multiple parsers within a directory. pip.rs has `merge_without_override` (used after each parser runs to merge its output into the running set), `should_skip_python_descent` (used by walkers in dist-info AND requirements walks), `has_python_project_marker` (project-root discovery). npm.rs has `walk_node_modules`, `should_skip_descent`, `has_npm_signal`. Where do these land post-split?

**Decision**: **Cross-submodule helpers stay in `mod.rs`** when they're used by ≥ 2 sibling submodules. If a helper is used by only one sibling, it moves to that sibling.

**Rationale**:

- `mod.rs` is the orchestrator. It already imports every sibling submodule. Helpers that need to be reachable from multiple siblings naturally belong here.
- Avoids creating a `helpers.rs` or `util.rs` submodule that would degrade into a junk drawer over time.
- Caller-count is the deciding factor: 2+ sibling callers → `mod.rs`; 1 sibling caller → that sibling.

**Cross-submodule helper placement** (canonical decisions):

| Helper | Callers | Lands in |
|---|---|---|
| `pip::merge_without_override` | `pip/mod.rs::read` (post-each-parser merge) | `pip/mod.rs` |
| `pip::should_skip_python_descent` | walker shared between dist-info + requirements walks | `pip/mod.rs` |
| `pip::has_python_project_marker` | `pip/mod.rs::candidate_python_project_roots` | `pip/mod.rs` |
| `pip::candidate_python_project_roots` | `pip/mod.rs::read` | `pip/mod.rs` |
| `pip::candidate_site_packages_roots` | `pip/dist_info.rs::read_venv_dist_info` only | `pip/dist_info.rs` |
| `pip::find_site_packages_under` | `pip/dist_info.rs` only | `pip/dist_info.rs` |
| `pip::build_pypi_purl_str` | every parser submodule | `pip/mod.rs` |
| `pip::marker_probably_matches` | `pip/requirements_txt.rs` only | `pip/requirements_txt.rs` |
| `pip::parse_hash_flags` | `pip/requirements_txt.rs` only | `pip/requirements_txt.rs` |
| `pip::parse_hash_alg` | `pip/requirements_txt.rs` only | `pip/requirements_txt.rs` |
| `pip::egg_fragment` | `pip/requirements_txt.rs` only | `pip/requirements_txt.rs` |
| `pip::pinned_version_from` | `pip/requirements_txt.rs` only | `pip/requirements_txt.rs` |
| `npm::should_skip_descent` | walker used by both lockfile parsers and node_modules walk | `npm/mod.rs` |
| `npm::has_npm_signal` | walker only | `npm/walk.rs` (if walker is the only caller) or `npm/mod.rs` (if multiple) |
| `npm::walk_for_project_roots` | `npm/mod.rs::read` | `npm/mod.rs` |
| `npm::candidate_project_roots` | `npm/mod.rs::read` | `npm/mod.rs` |
| `npm::base64_decode` | `npm/mod.rs` (integrity parsing) | `npm/mod.rs` |
| `npm::derive_name_from_path_key` | `npm/package_lock.rs` only | `npm/package_lock.rs` |
| `npm::build_npm_purl` | every parser submodule | `npm/mod.rs` |
| `npm::parse_pnpm_key` | `npm/pnpm_lock.rs` only | `npm/pnpm_lock.rs` |
| `npm::extract_author_string` | `npm/enrich.rs` only | `npm/enrich.rs` |
| `npm::person_from_value` | `npm/enrich.rs` only | `npm/enrich.rs` |
| `binary::detect_rootfs_kind` | `binary/mod.rs::read` | `binary/mod.rs` |
| `binary::is_host_system_path` | `binary/mod.rs::read` | `binary/mod.rs` |
| `binary::has_rpmdb_at` | `binary/mod.rs::read` | `binary/mod.rs` |
| `binary::is_os_managed_directory` | `binary/mod.rs::read` | `binary/mod.rs` |
| `binary::is_go_binary` | `binary/scan.rs::scan_binary` | `binary/scan.rs` |
| `binary::collect_string_region` | `binary/scan.rs` only | `binary/scan.rs` |

**Alternatives considered**:

- **Dedicated `pip/helpers.rs` / `npm/util.rs`**. Rejected — junk-drawer risk. The "helpers used by ≥ 2 siblings" criterion is small enough (~5-10 items per directory) that they fit comfortably in `mod.rs`.
- **Each parser self-contained, duplicate helpers as needed**. Rejected — defeats the dedup principle. Helpers shared by 2+ siblings are genuinely shared; duplicating would invite drift.

---

## R5. Per-commit chunking strategy

**Context**: Three independent splits. Should they be one commit each? Or sub-commits per submodule extraction within each user story? The PR will bundle all three but reviewers benefit from per-commit-readable diffs.

**Decision**: **One commit per user story** (US1: pip, US2: npm, US3: binary). Within each commit, the entire directory is created at once — `pip.rs` deleted, `pip/` directory added with all submodules. Sub-commits per extraction would require keeping `pip.rs` partially-populated mid-PR, which fights Rust's module system and risks broken intermediate states.

**Rationale**:

- Each user story is one logical, atomic change: "the pip ecosystem reader is now a directory module." Sub-commits would invite half-done states (pip.rs still contains Poetry but Poetry has also been added to pip/poetry.rs → name conflict).
- Per-commit `./scripts/pre-pr.sh` passes (FR-009). Reviewers can `git diff <pip-commit>~..<pip-commit>` and see the whole pip split as one self-contained change.
- Cross-commit dependencies are trivial: US2 (npm) and US3 (binary) don't depend on US1 (pip); they could ship in any order. Picking US1 first because it's the largest single split and validates the milestone's general approach.

**Alternatives considered**:

- **Sub-commit per submodule**: pip-step-1 extracts dist_info.rs, pip-step-2 extracts poetry.rs, etc. Rejected — each intermediate state is broken (pip.rs still has the code, pip/dist_info.rs also has it; or pip.rs lost the code, pip/dist_info.rs has it but is not yet `mod`-declared from `pip/mod.rs`). Either way, mid-commit state breaks compilation. Keeping each commit atomic per directory avoids this.
- **One mega-commit for all three directories**. Rejected — defeats per-user-story reviewability. If US3 (binary) introduces a problem, isolating it via `git bisect` is harder than if each split has its own commit.

---

## R6. Why is maven.rs excluded?

**Context**: maven.rs is the largest file in the codebase at 5702 LOC. The post-016 audit listed it among the splittable targets, but with the qualifier "may be best left alone — its sub-concerns are deeply intertwined." The user's spec clarification confirmed maven is out of scope. This research note documents the empirical reasons in case a future contributor revisits the question.

**Decision**: **maven.rs stays as-is.** No split in this milestone or any near-term follow-up.

**Rationale** (concrete, code-grounded):

1. **Property-interpolation engine threads through every parser callsite.** Maven's pom.xml supports `${property}` references that are resolved against an inheritance chain (parent pom, settings.xml, command-line `-Dprop=value`). The interpolation engine is held as mutable state and fed to every parser call. Splitting "the shade-plugin parser" from "the pom parser" would either duplicate the interpolation state (drift risk) or thread it through a new shared module (re-creates the original tight coupling at module boundaries).

2. **Repo-cache traversal is intermixed with transitive resolution.** When a pom declares a dep, mikebom resolves it by consulting `~/.m2/repository/` for the cached pom; cache lookups can recurse into more poms; recursion shares the running components-and-relationships set being built. Extracting "the cache traversal" as a submodule would require either making the running scan state pub-cross-submodule (defeats encapsulation) or restructuring to a fold-style accumulator (architectural change, not a split).

3. **Shade-plugin detection is half-bytecode-half-pom analysis.** Shade-plugin output is detected by combining (a) JAR bytecode inspection (the existing `binary/elf.rs`-shaped logic, but for class files) with (b) pom-side `<configuration>` introspection of the shade-plugin block. The two halves reference each other within a single function body. Splitting them would leave one half stranded across module boundaries.

4. **Prior art**: every previous attempt to split maven (per `git log --oneline mikebom-cli/src/scan_fs/package_db/maven.rs | head` ... if any history exists) has been deferred. Prior milestones 002 (multi-ecosystem), 005 (purl alignment), 007 (polyglot fp cleanup), 008 (polyglot final cleanup), 009 (maven shade deps), 012 (sbom quality fixes) all touched maven.rs without splitting it. Multiple authors at multiple points elected not to split. That's a signal.

**If a future contributor wants to attempt the split**: the path forward is design-first, not mechanical. Decompose the property-interpolation engine into a pure-function module first (its own milestone). Then extract the repo-cache traversal as a fold-style accumulator (its own milestone). Only then can the per-parser splits be done without re-coupling at module boundaries. Estimated 3-5 milestones of design work before the first parser-style submodule lands. The 1900-LOC pip and 1600-LOC npm files don't have this constraint because their parsers are pure functions of input → entries with no shared mutable state.

**Alternatives considered**:

- **Split maven.rs in this milestone**. Rejected per the empirical reasons above.
- **Split maven.rs in a future "tier 4.5" milestone**. Rejected — would be a misclassification; maven warrants its own design-first track, not Tier 4's mechanical-split track.
