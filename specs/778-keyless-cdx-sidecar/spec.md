# Feature Specification: Keyless CycloneDX Signing via Detached Sidecar

**Feature Branch**: `778-keyless-cdx-sidecar`
**Created**: 2026-09-06
**Status**: Draft
**Input**: User description: "804" — GitHub issue #804, the milestone-777 follow-up

## Context

Milestone 777 established that keyless signing cannot produce a
conformant in-document CycloneDX signature, and refused the
combination rather than emit a document that is invalid while
advertising itself as signed. That refusal is currently the entire
behaviour: an operator who signs keylessly and asks for CycloneDX
output gets an error and no artifact.

This feature gives that operator a working path again.

### Why an in-document signature is not the answer

A signing bundle carries three parts. Two have a home in the signature
format CycloneDX defers to; one does not.

| Bundle part | Signature-format slot | Fits? |
|---|---|---|
| signature bytes | the signature value | yes |
| ephemeral certificate chain | the certificate-path field | yes — exactly its purpose |
| transparency-log inclusion proof | — | **nothing** |

The signature format's signer definition admits exactly six properties
and no extension point, so the inclusion proof has nowhere to go.

That omission is not cosmetic. The certificates issued by the keyless
flow are deliberately short-lived — on the order of ten minutes. The
transparency-log entry's timestamp is what establishes that the
signature was produced while its certificate was still valid. Without
it, once the certificate expires a verifier can no longer establish
that, and the signature is unverifiable under the ordinary keyless
trust model unless the verifier is told to skip that check.

So translating the bundle into the in-document format is not a
lossy-but-acceptable conversion; it yields a signature whose useful
life is roughly ten minutes. This feature therefore does not attempt
it.

### What the operator gets instead

The signature travels beside the document rather than inside it — the
same shape the SPDX formats already use, and the shape the operator's
existing verification tooling already understands.

## Clarifications

### Session 2026-09-06

- Q: What form should the document's record of its signature location take — relative name, absolute location, or no record at all? → A: A relative name with no directory component. It stays correct wherever the document and its companion artifact travel together, and its failure mode is honest — a bare name that plainly needs its sibling, rather than an absolute location that looks authoritative but is wrong on every machine except the one that emitted it.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Keyless signing works for CycloneDX again (Priority: P1)

An operator signs with a workload identity rather than a managed
private key, because rotating and guarding a long-lived key is exactly
what they are trying to avoid. They want CycloneDX output, which is
their consumers' format. Today they are told the combination is
refused and must either switch signing method or switch format —
neither of which is their choice to make freely.

After this story, the command succeeds: they get a valid CycloneDX
document and, beside it, a signature they can verify with the tooling
they already run.

**Why this priority**: This is the whole feature. It restores a
capability that exists for every other format, and it is the only
story that delivers operator-visible value on its own.

**Independent Test**: Sign a scan keylessly requesting CycloneDX
output; confirm the command succeeds, the document is written and
valid, a signature artifact is written beside it, and that signature
verifies against the document with standard tooling.

**Acceptance Scenarios**:

1. **Given** an operator with a valid signing identity, **When** they request a keyless-signed CycloneDX scan, **Then** the command succeeds and both the document and a companion signature artifact are written.
2. **Given** that output, **When** the document is validated against the CycloneDX schema, **Then** validation reports zero errors — the document carries no in-document signature and is unaffected by signing.
3. **Given** that output, **When** the signature is verified against the document using standard verification tooling, **Then** verification succeeds.
4. **Given** that output, **When** any byte of the document is altered, **Then** verification fails.
5. **Given** an operator with no valid signing identity, **When** they request the same, **Then** the command fails with the existing identity diagnostic and leaves neither a document nor a signature artifact behind.
6. **Given** the static-key signing path, **When** it is used with CycloneDX output, **Then** it is unchanged: the signature remains inside the document and no companion artifact is produced.

---

### User Story 2 - A CycloneDX document says where its signature is (Priority: P2)

A consumer receives a CycloneDX document alone, without the directory
it was emitted into. Because the signature now lives outside the
document, nothing in the document itself indicates that a signature
exists — a keyless-signed document is byte-indistinguishable from an
unsigned one. The consumer has no way to know they should have asked
for a second file.

After this story, the document records that a signature exists and
where to find it.

**Why this priority**: Recovers most of the self-description lost by
moving the signature out of the document. Valuable, but the feature
delivers its core value without it, and it is the piece with a genuine
design question attached (see Clarifications).

**Independent Test**: Emit a keyless-signed CycloneDX document and
confirm it carries a reference identifying its companion signature
artifact, of a reference type the format defines for attestations.

**Acceptance Scenarios**:

1. **Given** a keyless-signed CycloneDX document, **When** a consumer inspects its external references, **Then** exactly one reference of the attestation type identifies the companion signature artifact, by a relative name carrying no directory component.
2. **Given** a keyless-signed document and its companion artifact placed together in any directory, **When** the reference is resolved relative to the document, **Then** it locates the companion artifact.
3. **Given** that document, **When** it is validated against the CycloneDX schema, **Then** validation reports zero errors.
4. **Given** an unsigned scan, **When** the document is emitted, **Then** no such reference is present and output is byte-identical to pre-change output.
5. **Given** a keyless-signed document carrying the reference, **When** the signature is verified, **Then** verification succeeds — the reference is part of the signed content, not added afterwards.

---

### User Story 3 - The superseded keyless tests cover the new path (Priority: P3)

Three keyless tests are currently disabled and marked superseded: they
assert the pre-777 behaviour of embedding a bundle inside the
CycloneDX document, which no longer happens. Their underlying subject
matter — the identity round-trip, the resulting signature's shape, the
diagnostic fields emitted, and tamper detection — is still worth
covering.

After this story, that coverage exists against the sidecar path
instead of the removed one.

**Why this priority**: Restores lost regression coverage rather than
adding capability. Subordinate to having a working path to cover.

**Independent Test**: With a signing identity available, run the
keyless test set and confirm it exercises the sidecar path and passes;
confirm no test remains that asserts an in-document keyless signature.

**Acceptance Scenarios**:

1. **Given** the keyless test set, **When** it runs with a signing identity available, **Then** it exercises the sidecar path and passes.
2. **Given** the test suite, **When** it is searched for assertions about an in-document keyless signature, **Then** none remain.

---

### Edge Cases

- **Several formats in one invocation.** Requesting CycloneDX and an SPDX format together with keyless signing must produce a correct signature artifact for each, without one format's signature being mistaken for another's.
- **Signing failure after the document is written.** If signing fails, the operator must be left with neither a document nor a partial signature artifact — the existing fail-close behaviour must extend to this path rather than being bypassed by it.
- **Name collision.** The companion artifact's name is derived from the document's; an operator whose chosen output path collides with that derived name must not silently lose either file.
- **Signing-order dependency.** If the document records where its signature lives, that record is part of what gets signed. Adding it after signing would invalidate the signature; the ordering must be fixed by construction rather than by convention.
- **Output to standard output.** Signing already requires a durable output path; that restriction must continue to hold here, since a signature is meaningless without an artifact to verify against.
- **The signature reference cannot carry a checksum of the artifact it points at.** CycloneDX permits hashes on an external reference, and adding one here looks attractive — it would let a consumer detect a swapped companion artifact. It is impossible: the artifact signs the document, the document would contain the artifact's hash, and the artifact's content therefore depends on its own hash. Any implementation that reaches for this will discover the circularity late; it is excluded by construction, not by preference.
- **Split output cannot occur alongside signing.** Signing requires a single durable output path, and split emission requires an output directory and forbids a single path, so the two are already mutually exclusive. There is consequently no case where one run must produce several documents each needing its own companion artifact. Worth knowing before building for it.
- **An operator who was relying on the refusal.** Between milestone 777 and this feature, keyless CycloneDX fails loudly. Anyone who scripted around that failure sees it start succeeding.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Keyless signing combined with CycloneDX output MUST succeed, replacing the current refusal.
- **FR-002**: A keyless-signed CycloneDX run MUST write the document and a companion signature artifact.
- **FR-003**: The emitted document MUST NOT contain an in-document signature, and MUST validate against the CycloneDX schema with zero errors.
- **FR-004**: The companion artifact MUST be verifiable against the document with standard keyless verification tooling, without waybill-specific tooling.
- **FR-004a**: The signed payload MUST be the document's bytes exactly as written to disk — not a canonicalized or otherwise transformed form. This follows from FR-004: a canonicalized payload would oblige the verifier to reproduce that transformation before checking anything, which is precisely the waybill-specific step FR-004 forbids. It also matches what the SPDX formats already sign. The consequence is that verification is sensitive to reserialization: a consumer who reformats the document invalidates it. That is accepted, and is already true of the SPDX artifacts.
- **FR-005**: Verification MUST fail when any byte of the document is altered.
- **FR-006**: The companion artifact's naming MUST follow the same convention already used for the SPDX formats, so operators learn one rule rather than two.
- **FR-007**: When several formats are requested in one invocation, each signed format MUST receive its own correctly-associated signature artifact.
- **FR-008**: A signing failure MUST leave neither a document nor a partial signature artifact for the affected format.
- **FR-009**: The static-key CycloneDX path MUST be unchanged — signature inside the document, no companion artifact.
- **FR-010**: SPDX signing behaviour MUST be unchanged.
- **FR-011**: Unsigned output MUST be byte-identical to pre-change output.
- **FR-012**: The emitted document MUST record the existence and location of its companion signature artifact, using a reference type the format already defines for attestations. The recorded location MUST be a relative reference naming the artifact as a sibling of the document — not an absolute location, which would be correct only on the machine that produced it and would additionally expose that machine's directory layout inside a distributed artifact.
- **FR-012a**: The recorded location MUST NOT include any directory component, so that the reference remains correct wherever the document and its companion artifact are stored together.
- **FR-013**: Any such record MUST be present in the content that is signed, so that adding it cannot invalidate the signature.
- **FR-014**: The three currently-disabled keyless tests MUST be re-established against the sidecar path, and no test may assert an in-document keyless signature.
- **FR-015**: Operator-facing documentation MUST be updated to describe the keyless CycloneDX path as producing a companion artifact, replacing the current statement that the combination is refused.
- **FR-016**: A keyless-signed run MUST emit an operator-visible summary recording which formats were signed and where each companion artifact was written, so an operator can confirm from the run's own output that a signature was produced without inspecting the filesystem.

### Key Entities

- **Signed document**: The emitted CycloneDX document. Carries no signature of its own on this path; optionally records where its signature lives.
- **Companion signature artifact**: The detached signature written beside the document, carrying the signature, the certificate chain, and the transparency-log proof that makes it durably verifiable.
- **Signature reference**: The record inside the document identifying the companion artifact, so a consumer holding only the document knows a signature exists.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of keyless-signed CycloneDX runs produce a document that validates against the CycloneDX schema with zero errors.
- **SC-002**: 100% of keyless-signed CycloneDX runs produce a companion artifact that verifies against its document using standard verification tooling.
- **SC-003**: Verification fails in 100% of attempts against a document altered after signing.
- **SC-004**: A keyless CycloneDX run that fails to sign leaves zero files on disk for that format.
- **SC-005**: Unsigned output is byte-identical to pre-change output — zero golden files change.
- **SC-006**: Static-key CycloneDX output is byte-identical to its post-milestone-777 form.
- **SC-007**: Zero tests assert an in-document keyless signature, and the three currently-disabled keyless tests are enabled and passing where a signing identity is available.
- **SC-008**: An invocation requesting both CycloneDX and an SPDX format with keyless signing produces two correctly-associated signature artifacts.
- **SC-009**: In 100% of keyless-signed CycloneDX runs, the recorded signature location resolves to the companion artifact when the two files are placed together in any directory, including one different from where they were emitted.
- **SC-010**: Every keyless-signed run reports each signed format and its companion artifact's path in the run's own output.

## Assumptions

- **The transparency-log proof is what makes this a sidecar rather than an embedded signature.** If a future revision of the signature format gains a slot for it, the embedded option becomes viable again and this decision is worth revisiting. Until then, embedding is a strictly worse artifact and is out of scope.
- **Verification is byte-exact and therefore reformatting-sensitive.** Because the signed payload is the document as written (FR-004a), a consumer who pretty-prints, re-serializes, or reorders keys before verifying will see verification fail. This is the same contract the SPDX companion artifacts already have, so it introduces no new class of operator surprise — but it is worth stating, since a signature that survives reformatting would require exactly the extra verifier-side step FR-004 rules out.
- **Verification is delegated, not implemented.** Operators verify with the tooling they already use for the SPDX sidecars. Building a waybill-side verification command for these artifacts is out of scope.
- **The static-key path stays embedded.** It produces a conformant in-document signature as of milestone 777, and there is no reason to move it. Offering a sidecar option for static keys is out of scope.
- **This does not restore the pre-777 artifact.** Anything that consumed a bundle from inside a CycloneDX document stays broken; that shape was schema-invalid and is not coming back.
- **Implementation requires a live signing identity to verify.** The behaviour this feature specifies cannot be exercised without one — that is precisely why milestone 777 deferred it rather than guessing. Planning and design do not need one; acceptance does.
- **The signature reference aids discovery, not scoring.** Quality scorers look for an in-document signature, so keyless CycloneDX output will still be reported as unsigned regardless of this reference. Its value is that a consumer holding only the document can tell a signature exists and what to ask for. It is not a substitute for an in-document signature and should not be described as one.
- **The existing fail-close cleanup covers the new artifact.** The mechanism that unlinks partial output on signing failure is assumed to extend to the companion artifact rather than needing replacement.
