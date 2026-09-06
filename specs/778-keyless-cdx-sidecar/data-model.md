# Phase 1 Data Model: Keyless CycloneDX Signing via Detached Sidecar

**Feature**: 778-keyless-cdx-sidecar
**Date**: 2026-09-06

One new emitted artifact, one new field inside an existing document,
and one changed routing decision. No persistent state, no storage.

---

## E1 — Companion signature artifact (new emitted file)

The detached signature written beside a keyless-signed CycloneDX
document.

| Aspect | Value |
|---|---|
| Produced when | keyless signing AND CycloneDX output requested |
| Path | the document's path plus the bundle suffix, via the existing derivation helper |
| Content | the same bundle shape the SPDX formats already emit |
| Signed payload | the document's bytes **exactly as written to disk** |

**Invariants**

- INV-1: the signed payload is byte-identical to the file on disk; no
  canonicalization, no re-serialization between writing and signing
  (FR-004a).
- INV-2: the artifact is verifiable by standard keyless tooling with no
  waybill-specific preprocessing (FR-004).
- INV-3: if signing fails, neither the document nor the artifact
  remains on disk (FR-008).
- INV-4: static-key CycloneDX produces **no** such artifact — its
  signature stays inside the document (FR-009).

---

## E2 — Signature reference (new field inside the document)

The record identifying E1 from within the document.

| Aspect | Value |
|---|---|
| Carrier | a document-level external reference |
| Type | the attestation reference type the format defines |
| Location value | a **relative name with no directory component** |
| Present when | keyless CycloneDX signing only |

**Invariants**

- INV-5: the location carries no directory component, so it resolves
  wherever document and artifact are stored together (FR-012a, SC-009).
- INV-6: the reference is present in the bytes that get signed —
  injected before the write, never after (FR-013).
- INV-7: the reference carries **no checksum** of E1. The artifact
  signs the document; a hash of the artifact inside the document would
  make each depend on the other. Excluded by construction, not
  preference.
- INV-8: absent entirely from unsigned output, preserving byte-identity
  (FR-011).

**Relationship to the existing attestation-typed reference**

The `attestation:` identifier scheme already emits a reference of the
same type onto the metadata component (catalog row C47). That one binds
an identifier; this one locates a signature. They occupy different
levels of the document and must remain distinguishable to a reader
encountering both.

---

## E3 — Signing route (changed decision, not stored)

Which write-boundary branch a signed run takes.

| Signing mode | Format | Before (post-777) | After |
|---|---|---|---|
| static key | CycloneDX | in-document signature | **unchanged** |
| keyless | CycloneDX | refused | write, then companion artifact |
| keyless | SPDX 2.3 / 3 | write, then companion artifact | **unchanged** |
| static key | SPDX 2.3 / 3 | write, then DSSE sidecar | **unchanged** |
| unsigned | any | write verbatim | **unchanged** |

**Invariants**

- INV-9: only one cell of this table changes; the other five are
  regression surface, not delivery surface.
- INV-10: the in-document signer continues to refuse keyless mode. The
  CLI stops routing to it for that combination; the guard itself stays
  correct for any other caller.

---

## E4 — Operator summary (new output, not persisted)

A per-run record of what was signed and where each artifact landed
(FR-016, SC-010). Emitted to the run's own output; nothing is written
to disk beyond the artifacts themselves.
