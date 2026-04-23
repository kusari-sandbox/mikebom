# Phase 1 Data Model: Polyglot Final Cleanup

This feature introduces **no new cross-crate or persistent types**. Story 1's deliverable is a Markdown document, not code. Stories 2 and 3 (if they ship code changes) adjust the behavior of existing types, never add new ones:

## Types that may be adjusted by Stories 2/3

- `GoScanSignals` (in `golang.rs`) — unchanged; production-import collection logic may get a new helper.
- `PackageDbEntry` — unchanged.
- `EmbeddedMavenMeta` — unchanged; the `is_primary` flag's detection logic may get refined in Story 3 if Story 1 identifies primary-detection as the gap.

## New Markdown-only artifacts

- `specs/008-polyglot-final-cleanup/investigation.md` — Story 1 deliverable. Structured document with one section per FP, each answering: filter supposed to close it, why it didn't fire, evidence snippet, minimal-fix option, status (closable / known-limitation / stale-binary-rerun).
- `docs/design-notes.md` additions — Story 4 prose about commons-compress convention and any Story 2/3 known-limitation entries.

No invariants, no state transitions, no persistent entities.
