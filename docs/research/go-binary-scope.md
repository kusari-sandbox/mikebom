# Go source-tree scope: root module + test-only transitives

**Status:** research note, not an implemented decision
**Written:** 2026-04-20
**Context:** sbom-conformance benchmark flags 5-37 FPs on go-logrus-small,
go-vendored, and monorepo-mixed fixtures. The extras are (1) the project's own
module, and (2) test-only transitive deps of upstream libraries (spew,
difflib, testify when scanning a logrus consumer).

## What mikebom does today

`mikebom-cli/src/scan_fs/package_db/golang.rs::build_entries_from_go_module`
(lines 442-553):

1. Emits the project's own `module` line from `go.mod` as a component, tagged
   `source_type = "workspace"`, version set to `go.mod`'s declared `go <ver>`
   (pseudo-version).
2. Emits every module in `go.sum` (filtered to kind `Module`, not `GoMod`),
   with transitive edges pulled from each upstream module's own go.mod in the
   module cache.

No distinction between runtime-reachable and test-only transitives. No flag
analogous to Ruby's `--include-dev`.

## What trivy does

- **Analyzer**: `pkg/fanal/analyzer/language/golang/mod/mod.go`
- **Parser**: `pkg/dependency/parser/golang/mod/parse.go`

**Root module**: **emitted**, with `ftypes.RelationshipRoot`. parse.go:159-181
explicitly builds a package from `modFileParsed.Module`. The trivy docs' note
that "Trivy does not detect vulnerabilities of the main module" refers to vuln
lookup only — the SBOM component is present.

**Test-only transitives**: **not filtered**. Trivy iterates `modFileParsed.Require`
directly, tagging each entry Direct/Indirect from the `// indirect` comment.
It does not open upstream go.mod files to look at test scope. Since Go 1.17+
pruned module graphs already put upstream test deps into the consumer's go.mod
as indirect requires, they appear in trivy's output (labeled Indirect).

For Go ≤1.16 (mod.go:91-99) trivy merges go.sum entries too; this is the
legacy case that matches mikebom's current behavior.

## What syft does

- **Source cataloger**: `syft/pkg/cataloger/golang/parse_go_mod.go`
- **Config**: `syft/pkg/cataloger/golang/config.go` (`UsePackagesLib: true` as
  default since 2025)

**Root module (default mode)**: **emitted**. `catalogModules` uses
`golang.org/x/tools/go/packages.Load("all", Tests: true)` and emits every
module it sees except ones matching `isRelativeImportOrMain` (only filters
literal `main` / relative paths).

**Root module (legacy mode `UsePackagesLib=false`)**: **excluded**. Pure
`modFile.Require` iteration, which by definition doesn't contain the main
module. Test `parse_go_mod_test.go::many-packages` confirms: for
`module github.com/anchore/syft`, expected output omits the module itself.

**Test-only transitives**: **not filtered**. Default mode explicitly sets
`Tests: true`. Neither mode has a scope filter. go.sum is used only for H1
digest attachment, not for component enumeration.

## Comparison

| Question | Trivy | Syft (default) | Syft (legacy) | mikebom today |
|---|---|---|---|---|
| Root module emitted? | Yes | Yes | No | Yes (tagged `workspace`) |
| go.sum drives components? | Only Go ≤1.16 | No | No | Yes |
| Upstream test-deps filtered? | No | No | No | No |
| Explicit test/scope flag? | No | No | No | No |

## Recommendation

**Keep emitting the root module.** Trivy and syft-default both do, and users
scanning `logrus/` expect to see `logrus` as the scan subject. Mikebom's
current `source_type = "workspace"` tag is already a reasonable distinguisher.
A future refinement could set `sbom_tier = "subject"` or similar so conformance
harnesses that want "dependencies only" can filter it easily. Low-cost, worth
doing.

**Do not attempt test-only filtering.** Neither mainstream tool does, and no
reliable local signal exists. The Go module graph (1.17+ pruned) intentionally
surfaces upstream test deps as consumer-level indirect requires to support
`go test ./...` on deps. Filtering would require reimplementing the Go module
resolver with test/non-test discrimination per package, diverge from
`go list -m all`, and produce SBOMs inconsistent with every other tool in the
ecosystem.

**Consider switching `go.sum`-driven scan to `go.mod Require`-driven scan**
for Go ≥1.17 sources. Matches trivy's behavior. go.sum would still be read
for H1 hash attachment. This would drop the test-only transitives that aren't
declared as consumer-level indirect requires, which is probably what the
conformance harness expects.

**Action for this milestone:** none in mikebom code. Updates to conformance
fixture ground truth (accept root + declared indirect requires) are more
consistent with trivy/syft than changing the scanner.

## Backlog ties

If the scan semantics change, also:
- Update `docs/design-notes.md` ecosystem table to reflect go.mod Require vs
  go.sum as the primary source.
- Update fixture tests in `mikebom-cli/tests/scan_go.rs` that assert on
  specific go.sum-derived entries.
- Consider a `--go-scope=[runtime|full]` flag if someone files a real use case.

## Primary sources

- Trivy Go mod parser: https://github.com/aquasecurity/trivy/blob/main/pkg/dependency/parser/golang/mod/parse.go
- Trivy analyzer (go.sum merge gate): https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/analyzer/language/golang/mod/mod.go
- Syft source cataloger: https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/golang/parse_go_mod.go
- Syft config (UsePackagesLib default): https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/golang/config.go
- Trivy Go docs: https://trivy.dev/docs/latest/coverage/language/golang/
- Filippo Valsorda on go.sum: https://words.filippo.io/gosum/
- Go Modules Reference (1.17 graph pruning): https://go.dev/ref/mod
