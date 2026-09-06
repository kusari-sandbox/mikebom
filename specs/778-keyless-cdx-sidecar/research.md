# Phase 0 Research: Keyless CycloneDX Signing via Detached Sidecar

**Feature**: 778-keyless-cdx-sidecar
**Date**: 2026-09-06

Every finding below was verified against source in this workspace.
Each records what was checked so a reviewer can re-run it. Nothing here
required a live signing identity — that constraint applies to
acceptance, not to design.

---

## R1 — Does the sidecar machinery generalize to CycloneDX?

**Decision**: Yes, essentially unchanged. Reuse
`sign_spdx_bytes_to_sidecar` and `sidecar_extension_for` as-is.

**Rationale**: The signer is byte-generic —
`sign_spdx_bytes_to_sidecar(&[u8], &SigningMode) -> Result<Option<Sidecar>>`.
Nothing inside it is SPDX-specific except the parameter name and a
waybill-level DSSE payload-type constant used only on the static-key
branch, which this feature does not touch. The keyless branch passes
the caller's bytes straight to `sign_keyless_sbom` and wraps the result
as `Sidecar::SigstoreBundle`.

Path derivation is likewise generic: `sidecar_extension_for(target,
sidecar)` appends the variant's suffix to whatever extension the target
already has, so `signed.cdx.json` yields
`signed.cdx.json.sig.bundle.json` with no new logic. FR-006's "same
convention as SPDX" is satisfied by calling the same function rather
than by re-deriving a parallel rule.

**Consequence for naming**: the function should be renamed to reflect
that it is format-agnostic. Leaving it called `sign_spdx_bytes_to_*`
while the CycloneDX path calls it is exactly the kind of stale name
that produced milestone 777's "waybill never emits signed BOMs"
comment.

---

## R2 — What bytes get signed, and is FR-004a achievable?

**Decision**: Yes. Sign the bytes exactly as written, matching SPDX.

**Rationale**: At the write boundary the SPDX branch already does:

```rust
write_bytes_to(&target, &final_bytes)?;
...
sign_spdx_bytes_to_sidecar(&final_bytes, &signing_mode)
```

It signs `final_bytes` — the same buffer just written to disk. So
`cosign verify-blob --bundle <sidecar> <document>` works against the
file as it sits. Applying the identical ordering to CycloneDX satisfies
FR-004a by construction, and FR-004's "no waybill-specific tooling"
follows from it.

**Alternatives considered**: Canonicalizing before signing, as
milestone 777's in-document path does (`canonical_json_bytes` with
`value = ""`). Rejected: it would oblige every verifier to reproduce
the canonicalization before checking anything, which is the
waybill-specific step FR-004 forbids. Worth stating explicitly because
that pattern lives in the same file and is the obvious thing to reach
for by analogy.

---

## R3 — Where can the signature reference be injected?

**Decision**: At the write boundary, not in the CycloneDX builder.

**Rationale**: The reference must name the companion artifact, whose
path is derived from the operator's `--output` target. The builder does
not receive that target — it produces `artifact.bytes` from resolved
components, and the output path is resolved later in the dispatch loop.
Only the write boundary holds both.

The mechanism already exists there. The static-key path currently does
parse → modify → re-serialize on the emitted bytes
(`sign_cdx_bytes_for_write`), so injecting a reference the same way
introduces no new technique — just a different modification.

This also settles FR-013's ordering requirement structurally: the
reference goes into the bytes before they are written, and the bytes
that are written are the bytes that are signed (R2). There is no window
in which the document on disk differs from the signed content.

**Alternatives considered**: Threading the output path down into the
builder so the reference could be emitted natively. Rejected as a
wider blast radius — the builder signature is shared by every format
and by the split-emission path, for a single CycloneDX-only,
keyless-only field.

---

## R4 — Which write-boundary branch does keyless CycloneDX take?

**Decision**: A new branch, parallel to the SPDX one. The existing
CycloneDX signing branch stays for static keys only.

**Rationale**: The write boundary currently distinguishes three cases —
unsigned (write verbatim), CycloneDX + signing (in-document sign,
re-serialize, write), and SPDX + signing (write verbatim, then
sidecar). Keyless CycloneDX belongs in the third shape, not the second.

Milestone 777 left `sign_cdx_document_in_place` refusing keyless mode
outright. That refusal is correct and should stay: it is the
*in-document* signer, and keyless has no conformant in-document form.
What changes is that the CLI stops routing keyless CycloneDX to it, and
routes to the sidecar path instead. The library-level refusal then
becomes unreachable from the CLI while remaining a correct guard for
any other caller — which is what a defence-in-depth check is for.

---

## R5 — Does the signature reference need parity-catalog work?

**Decision**: Not required by any gate. Recommended anyway, as a
`CdxOnly` row.

**Rationale**: Two gates were checked.

`every_catalog_row_has_an_extractor` walks the catalog and requires an
extractor per row — it constrains rows, not emitted fields.
`assert_holistic_parity` likewise iterates catalog rows and evaluates
only those classified universal-parity. Neither gate inspects emitted
output for fields lacking a row. So the reference can ship without a
catalog entry and the pre-PR gate stays green.

That is an argument about the gate, not about whether it should exist.
The catalog is the documented cross-format mapping, and an emitted
field absent from it is a silent gap of exactly the kind milestone 777
was cleaning up. `Directionality::CdxOnly` exists for precisely this
shape — a signal CycloneDX carries that the SPDX sides deliberately do
not — with C42 as precedent. Adding one row plus one extractor is
small and keeps the mapping honest.

Flagged rather than assumed, because it is a judgment call and not gate-forced.

**Adjacent finding worth knowing**: `attestation` is already an emitted
CycloneDX reference type. Catalog row C47 maps the `attestation:`
identifier scheme onto `metadata.component.externalReferences[]` with
`type: "attestation"`. That is a different thing — an identifier
binding, not a signature pointer — and it lives on the metadata
component, whereas this feature's reference belongs at the document
level. The two do not collide, but a reader encountering two
`attestation` references in one document deserves to be told why, so
whichever carrier is chosen should be documented against the other.

---

## R6 — What existing tests and documents are affected?

**Decision**: Five tests and two documents.

| Location | Current state | Needed |
|---|---|---|
| `cisa_2026_signing.rs` — 3 `#[ignore]`d keyless tests | banner-marked SUPERSEDED by m777; assert in-document embedding | retarget to the sidecar path (FR-014) |
| `cisa_2026_signing.rs` — `m777_keyless_with_cyclonedx_is_refused_and_writes_nothing` | asserts the refusal m778 removes | replace with the success path |
| `cisa_2026_signing.rs` — `m777_keyless_with_spdx_only_is_not_refused` | asserts SPDX keyless is unaffected | still valid; keep |
| `docs/cisa-2026-coverage.md` row 2 | states keyless CycloneDX is refused | describe the companion artifact (FR-015) |
| `specs/222-.../keyless-signing-flow.md` | carries an m777 "SUPERSEDED IN PART" banner on its CycloneDX contract | update — the CycloneDX path exists again, in a new shape |

Two m222 tests were retargeted from CycloneDX to SPDX during milestone
777 (`us2b_keyless_no_oidc_token_fails_close_m222`,
`us2b_keyless_signing_failure_cleans_up_output_m222`). They should
*stay* on SPDX: they exercise identity-acquisition and cleanup, which
are format-independent, and moving them back would re-couple them to a
format for no gain.

---

## R7 — What cannot be verified without a signing identity

Stated plainly so it is not discovered at acceptance:

- That the emitted bundle verifies with `cosign verify-blob` against
  the document (FR-004, SC-002).
- That tamper detection behaves as specified (FR-005, SC-003).
- That the three retargeted tests pass (FR-014, SC-007).

Everything else — reference placement and form, schema validity,
byte-identity of unsigned output, the refusal removal, static-key
unchanged, path derivation — is verifiable without one.

The prudent sequencing is to build and verify that second set first, so
that when an identity becomes available the only open questions are the
three above.

---

## Summary of dependency impact

**Zero new Cargo dependencies.** No new files beyond tests; the signer,
the sidecar writer, and the path-derivation helper all already exist.
