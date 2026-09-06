# Feature Specification: CycloneDX Signature Conformance

**Feature Branch**: `777-cdx-signature-conformance`
**Created**: 2026-09-05
**Status**: Draft
**Input**: User description: "Fix CycloneDX signature conformance: relocate the document signature from metadata.signature to the document root, emit publicKey as a JWK per JSON Signature Format, and extend the CycloneDX schema-validation harness to cover signed documents"

## Context

Every CycloneDX document waybill emits with `--sign-key` (and, by
inspection, `--sign`) currently fails validation against the CycloneDX
1.6 JSON schema. This is a direct violation of Constitution Principle V
("Generated SBOMs MUST strictly conform to ... **CycloneDX 1.6** — valid
JSON or XML serialization"). Unsigned output is unaffected and remains
conformant.

Two independent defects combine to produce the failure. Both were
verified empirically against the upstream `bom-1.6.schema.json` (with
`jsf-0.82` and `spdx` schemas resolvable and JSON Schema format
assertion enabled), by signing a fixture with a throwaway P-256 key:

| Document state | Validation result |
|----------------|-------------------|
| As emitted today | INVALID — `metadata`: additional properties not allowed (`signature`) |
| Signature relocated to root only | INVALID — `signature.publicKey`: missing `kty`/`crv`/`x`/`y`; `algorithmHint`, `pem` unexpected |
| Signature relocated **and** `publicKey` emitted as a JWK | **VALID** |

**Defect 1 — the signature is written to a slot the specification
forbids.** The document-level signature is inserted under `metadata`.
CycloneDX 1.6 defines `metadata` with `additionalProperties: false` and
declares no `signature` property on it. The specification's slots for a
signature are the document root and the `component`, `service`,
`compositions`, `annotations`, and `standard` definitions. The correct
location for a document-level enveloped signature is the document root.

**Defect 2 — the public key is not in the format the specification
requires.** CycloneDX delegates the signature object to JSON Signature
Format (JSF). JSF requires `publicKey` to be a JWK: `kty` is mandatory,
and the elliptic-curve branch is `additionalProperties: false` requiring
exactly `kty`, `crv`, `x`, and `y`. waybill emits a PEM string plus an
algorithm hint, both of which the schema rejects outright.

Defect 2 is a **known, documented deferral** rather than an oversight.
The emitting type's own documentation records it: *"Held as a PEM string
for v1 ... full JWK parameter split (kty/crv/x/y for EC, kty/x for OKP)
is a US2b enhancement."* What was not recognised at the time is that the
shortcut makes the emitted document schema-invalid. Defect 1 appears
genuinely unnoticed; the signing module's own documentation asserts that
the slot it writes to is "native CDX 1.6", which is the mistaken belief
that produced it.

**A third defect was found during task generation and is in scope.** The
signature value is encoded with the standard base64 alphabet, while the
emitting module's own documentation states base64url and the signature
format requires the binary representation to follow the JWA rules, which
use base64url. This does not fail schema validation — the format types
the value as a plain string with no pattern or format constraint — so it
is invisible to the conformance check the rest of this feature builds
on. It matters anyway: a conforming verifier decoding base64url rejects
any signature whose standard encoding contains the two alphabet-specific
characters, which is most signatures. Without this, the feature could
ship documents that validate but that no conforming verifier can
consume, which would defeat its purpose.

**One candidate fourth defect was investigated and rejected.** Validating
without format assertion also reports a `oneOf` failure on
`signature.algorithm`, because JSF types `algorithm` as
`oneOf[uri-format string, enum]` and JSON Schema Draft 7 does not assert
`format` by default, so a value like `ES256` satisfies both branches. A
hand-built, fully conformant JSF signature reproduces the same complaint
under the same conditions and validates cleanly once format assertion is
enabled. This is a validator artifact, not a waybill defect, and is out
of scope.

### Why this survived earlier signing work

Both halves of a gate that would have caught Defect 1 already exist in
the repository, but they never intersect:

- The vendored CycloneDX 1.6 schema is the complete upstream document
  and does carry `metadata.additionalProperties: false`. Its only
  consumers are two emission tests, neither of which signs.
- The two tests that do sign never reference the schema. Worse, they
  pin the defective shape — asserting on the `metadata` signature
  pointer and on the presence of a PEM header inside `publicKey` — so
  the current tests actively encode the bug.

## Clarifications

### Session 2026-09-05

- Q: When the keyless signing path is used with CycloneDX output, should waybill emit the non-conformant document with a warning, or refuse? → A: Refuse — fail with a non-zero exit and an actionable error naming the static-key path as the conformant alternative; write no CycloneDX file.
- Q: How far should key-type support extend, given the algorithm is currently hardcoded to EC P-256 regardless of the supplied key? → A: Support EC P-256 only — determine the key's actual type and refuse anything else with a clear error, so the declared algorithm can never disagree with the key in use.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Signed CycloneDX output passes conformance validation (Priority: P1)

An operator signs an SBOM so downstream consumers can establish
authorship and integrity. Today the resulting document is rejected by
any CycloneDX conformance validator, and signature-aware consumers
report the document as unsigned because they inspect the location the
specification defines, which waybill leaves empty. The operator gets a
document that claims to be signed, is advertised as satisfying the
"Author Signature" element, and yet fails validation and reads as
unsigned to every conforming tool.

After this story, a signed document validates cleanly and consumers
find the signature where the specification says it will be.

**Why this priority**: This is the entire user-visible defect and a
Constitution Principle V violation. The two fixes are jointly necessary
— relocating the signature alone still yields an invalid document, and
correcting the key format alone leaves it in a forbidden slot — so they
form one indivisible slice of value.

**Independent Test**: Sign a fixture scan with a locally generated key,
then validate the emitted document against the upstream CycloneDX 1.6
schema. Fully delivers value on its own: the document becomes
conformant and machine-verifiable regardless of whether any other story
lands.

**Acceptance Scenarios**:

1. **Given** a scan signed with a static elliptic-curve key, **When** the emitted document is validated against the CycloneDX 1.6 schema with format assertion enabled, **Then** validation reports zero errors.
2. **Given** the same signed document, **When** a consumer reads the document-root signature slot, **Then** it finds a signature object carrying the algorithm, public key, and signature value.
3. **Given** the same signed document, **When** a consumer inspects the document metadata, **Then** no signature property is present there.
4. **Given** the same signed document, **When** the public key object is examined, **Then** it carries the key-type, curve, and coordinate parameters required by JSON Signature Format and carries no properties the format disallows.
5. **Given** a signed document, **When** any single byte of document content outside the signature is altered, **Then** signature verification against the embedded public key fails.
6. **Given** a signed document, **When** verification is attempted against the embedded public key with content unaltered, **Then** verification succeeds.

---

### User Story 2 - The conformance gap cannot silently reopen (Priority: P2)

A maintainer changes the signing path — adds a key type, adjusts the
envelope, alters canonicalization. Today nothing in the automated gate
would tell them the emitted document had stopped conforming, because
the schema harness and the signing tests occupy disjoint parts of the
suite. That is exactly how the current defect reached a release.

After this story, any change that makes signed output non-conformant
fails the gate.

**Why this priority**: Prevents recurrence of the defect class rather
than the single instance. Valuable but subordinate to actually emitting
conformant documents; a gate protecting broken output has no worth
until the output is fixed.

**Independent Test**: Deliberately reintroduce the old shape (write the
signature under metadata, or emit a PEM-style public key) and confirm
the gate fails; restore and confirm it passes. Testable without any
knowledge of how the fix was implemented.

**Acceptance Scenarios**:

1. **Given** the automated gate, **When** it runs, **Then** at least one signed CycloneDX document is validated against the full CycloneDX 1.6 schema.
2. **Given** a deliberately reintroduced signature placed in the document metadata, **When** the gate runs, **Then** it fails and the failure message identifies the offending location.
3. **Given** a deliberately reintroduced public key lacking the required key-type parameter, **When** the gate runs, **Then** it fails and the failure message identifies the offending property.
4. **Given** existing tests that currently assert the pre-fix signature shape, **When** the change lands, **Then** those assertions describe the conformant shape instead and no test encodes the defective one.

---

### User Story 3 - The keyless signing path refuses rather than emitting invalid output (Priority: P3)

An operator signs using the keyless identity-based flow rather than a
static key. That path inserts an entire signing bundle as the signature
payload. Its conformance is unverified — it could not be exercised
during investigation because it requires a live identity token — but it
is suspected to be worse than the static-key path, since the bundle
carries certificate and transparency-log material that JSON Signature
Format expresses through dedicated properties rather than as an opaque
value.

Bringing that path to conformance is deliberately out of scope here.
What is in scope is that waybill stops producing output it knows to be
invalid. Today the operator receives a silently non-conformant document
advertised as signed. After this story, the request fails outright with
an error that names the conformant alternative, so the operator makes a
deliberate choice instead of unknowingly shipping an invalid artifact.

**Why this priority**: Removes the misleading outcome for the narrower
operator population without committing to unbounded work. The bundle may
not be expressible through JSON Signature Format at all; that
determination requires exercising the path against a real signing
identity and belongs to a separately sized follow-up.

**Independent Test**: Invoke the keyless path requesting CycloneDX
output and confirm the command fails with a non-zero exit, writes no
CycloneDX file, and names the static-key path in its error. Testable
without resolving whether the path can eventually be made conformant.

**Acceptance Scenarios**:

1. **Given** an operator invokes the keyless signing path with CycloneDX output requested, **When** the command runs, **Then** it exits non-zero with an error stating that the keyless path cannot currently produce a conformant CycloneDX signature, and naming the static-key path as the conformant alternative.
2. **Given** that same invocation, **When** the command exits, **Then** no CycloneDX output file has been written.
3. **Given** an operator invokes the keyless signing path requesting only SPDX output, **When** the command runs, **Then** it succeeds unchanged, because SPDX signing is detached and unaffected.
4. **Given** the static-key path with CycloneDX output, **When** it is used, **Then** it succeeds and no refusal is triggered.
5. **Given** the keyless path's limitation, **When** an operator consults operator-facing documentation, **Then** it is recorded there alongside the static-key path's conformant status.

---

### Edge Cases

- **Non-P-256 keys.** JSON Signature Format defines distinct required parameter sets per key type. An operator supplying an Ed25519 or RSA key must receive a clear refusal naming the unsupported type, not a document whose published key parameters or declared algorithm describe a different key than the one that signed it. It is not currently established whether such a key fails inside the signer today or is silently mislabelled; under the chosen disposition this becomes moot, since the type is determined and refused before signing.
- **Canonicalization boundary.** The signature covers a canonical form of the document. Relocating the signature slot changes which bytes are covered. The placeholder-emit-canonicalize-fill sequence must keep the signature slot excluded from its own input, and the resulting signature must still verify.
- **Signing an already-signed document.** The existing path removes a prior signature before signing. That removal must follow the slot to its new location, or a stale signature could survive in the old position and produce a document with two conflicting signature claims — one of them in a forbidden slot.
- **Encrypted key files.** The passphrase-protected key path must reach the same conformant output; the key-format change must not be applied only on the unencrypted branch.
- **Multiple output formats in one invocation.** When both CycloneDX and SPDX output are requested with signing enabled, the CycloneDX change must not disturb the SPDX signing path, which uses a detached mechanism rather than an embedded slot.
- **Keyless plus multiple formats in one invocation.** When keyless signing is requested with both CycloneDX and SPDX output, the refusal must be decided before any output file is written, so the operator is not left with a partial result — an SPDX file on disk and no CycloneDX file — that could be mistaken for a complete run.
- **Scripts that currently invoke the keyless path with CycloneDX output.** These succeed today and will begin failing. This is intentional: they are currently producing invalid documents. See Assumptions.
- **Consumers reading the old location.** Any consumer written against waybill's current non-conformant output stops finding the signature. See Assumptions for why this population is believed empty.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Signed CycloneDX documents MUST carry the document-level signature at the location the CycloneDX 1.6 specification defines for a document-level enveloped signature.
- **FR-002**: Signed CycloneDX documents MUST NOT carry a signature property within the document metadata.
- **FR-003**: The public key accompanying a signature MUST be expressed in the format JSON Signature Format requires, carrying exactly the parameters mandated for the key type in use and no parameters the format disallows.
- **FR-004**: A signed CycloneDX document MUST validate without error against the complete, unmodified upstream CycloneDX 1.6 schema, with JSON Schema format assertion enabled.
- **FR-005**: A signature MUST continue to verify against its embedded public key after the relocation, and MUST fail to verify when any document content outside the signature is altered.
- **FR-006**: Removal of a pre-existing signature prior to re-signing MUST target the conformant location, leaving no signature residue in the previously used location.
- **FR-007**: The system MUST determine the signing key's actual type from the supplied key material rather than assuming one. When that type is anything other than elliptic-curve P-256, the system MUST refuse with an operator-actionable error naming the unsupported key type, rather than emit a document whose declared algorithm or published key parameters do not match the key actually used.
- **FR-008**: The automated verification gate MUST validate at least one signed CycloneDX document against the complete upstream CycloneDX 1.6 schema.
- **FR-009**: No test may assert the pre-fix signature shape; assertions that currently pin the signature to the document metadata or pin a PEM-style public key MUST be updated to describe the conformant shape.
- **FR-010**: Internal documentation that describes the signature slot MUST be corrected where it asserts that the metadata location is specification-native.
- **FR-011**: Operator-facing conformance claims regarding the "Author Signature" element MUST accurately reflect where the signature is emitted after this change.
- **FR-012**: Unsigned CycloneDX output MUST be byte-identical before and after this change.
- **FR-013**: SPDX signing behavior MUST be unchanged by this feature.
- **FR-014**: When the keyless signing path is requested together with CycloneDX output, the system MUST refuse the operation: exit non-zero with an operator-actionable error that states the keyless path cannot currently produce a conformant CycloneDX signature and names the static-key path as the conformant alternative. Bringing the keyless path to conformance is out of scope for this feature.
- **FR-015**: When the system refuses under FR-014, it MUST NOT write a CycloneDX output file.
- **FR-016**: The keyless signing path MUST continue to succeed when CycloneDX output is not requested, since SPDX signing is detached and unaffected.
- **FR-017**: The static-key signing path MUST NOT trigger the FR-014 refusal, since its output conforms.
- **FR-018**: The keyless path's CycloneDX limitation MUST be recorded in operator-facing documentation and tracked as a follow-up work item.
- **FR-019**: The algorithm declared in the signature MUST be derived from the key actually used to sign, such that the declared algorithm and the signing scheme cannot disagree.
- **FR-020**: The CycloneDX signature value MUST be encoded with the base64url alphabet without padding, as the signature format's binary-representation rule requires. This change MUST be scoped to the CycloneDX signature only: the detached SPDX sidecar's payload and signature encoding MUST remain unchanged, because the sidecar's envelope format mandates the standard alphabet. An encoding change applied to both would satisfy FR-020 while breaking FR-013.

### Key Entities

- **Document signature**: The enveloped signature covering a canonicalized form of the emitted document. Carries the signing algorithm, the public key needed for offline verification, and the signature value. Lives at exactly one location in the document, defined by the specification.
- **Public key material**: The verification key published inside the signature so consumers can verify without out-of-band key distribution. Its required shape is determined by the key's type.
- **Conformance gate**: The automated check that validates emitted documents against the published schema. Currently covers unsigned emission only; must be extended to cover the signed path.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of signed CycloneDX documents emitted by the static-key path validate against the upstream CycloneDX 1.6 schema with zero errors, measured across the fixture set used by the conformance gate.
- **SC-002**: A signature-aware quality scorer that inspects the specification-defined signature location detects the signature in signed output, where it detects none today.
- **SC-003**: Reintroducing either defect causes the automated gate to fail, verified by deliberately reintroducing each in turn.
- **SC-004**: Unsigned output is byte-identical to pre-change output across the entire existing golden-file set — zero golden files change.
- **SC-005**: Signature verification succeeds on unmodified signed documents and fails on tampered ones, with no reduction in tamper-detection coverage relative to today.
- **SC-006**: Zero tests in the suite assert the pre-fix signature location or key format after the change.
- **SC-007**: Every invocation combining the keyless path with CycloneDX output exits non-zero and leaves no CycloneDX file on disk; no invocation of the static-key path is refused.
- **SC-008**: Keyless invocations that request only SPDX output succeed at the same rate as before the change.
- **SC-009**: Signing with a non-P-256 key is refused in 100% of attempts, with an error naming the key type; no such attempt produces an output file.
- **SC-010**: The emitted CycloneDX signature value decodes cleanly under the base64url alphabet, and the SPDX sidecar's payload and signature continue to decode under the standard alphabet — both verified in the same run, so an encoding change cannot be applied to one path without the other being checked.

## Assumptions

- **No conforming consumer is broken by the relocation.** The signature slot is written only by the signing module and read only by that module's own tests; the codebase contains no verification path for a CycloneDX document signature. A specification-conforming external consumer cannot be verifying waybill signatures today, because it would inspect the document root and find nothing — which is precisely why signature-aware scoring currently reports the output as unsigned. The population at risk is therefore limited to a bespoke consumer written against waybill's non-conformant shape, and is believed empty. This assumption is the basis for treating the change as a correctness fix rather than a breaking change; if a consumer of the old shape is known to exist, the assumption must be revisited before implementation.
- **The PEM representation of the public key is dropped rather than relocated.** JSON Signature Format's elliptic-curve key branch forbids additional properties, so the PEM cannot remain inside the public key object. The JWK parameters carry the same key material, so no verification capability is lost. Preserving the PEM elsewhere via a vendor-prefixed property is rejected under Constitution Principle V's standards-native-first rule.
- **Elliptic-curve P-256 is the only key type this feature supports.** It is the algorithm the current signing path selects, and the only one whose JSON Signature Format representation this feature produces. Broader key-type support (Ed25519, RSA) is deliberately not implemented speculatively; it becomes a follow-up if demand appears. The current code hardcodes the algorithm label rather than deriving it from the key, and carries a helper mapping in which an RSA key would be labelled one way and signed another — unreachable today because of the hardcode, but in code this feature must touch. FR-007 and FR-019 exist to close that hazard by construction rather than leave it latent.
- **The vendored CycloneDX schema is the gate's source of truth, but is not sufficient on its own.** It is the complete upstream document and already carries the constraint that catches the placement defect. However, the existing test harness resolves the schema's JSON Signature Format reference to a permissive stub that accepts any signature object, so a gate built on the harness as it stands would pass a malformed public key. Closing the gate requires supplying the real referenced schema, not merely feeding the harness a signed document.
- **Format assertion is required, and is the default in the environment the gate runs in.** Without it, a conformant signature produces a spurious failure on the algorithm property, as documented in Context — that is what was observed in the investigation harness, which does not assert formats by default. The gate's own validator does assert formats by default for the schema draft in use, so no configuration is strictly required; setting it explicitly is nonetheless worthwhile, because the default is draft-dependent and a future schema-draft bump would silently disable it.
- **The keyless refusal is an intentional behavioral break.** A command that succeeds today will begin failing when keyless signing is combined with CycloneDX output. This is accepted because the output it produces today is invalid and is reported as unsigned by conforming consumers, so the apparent success is itself the defect. No opt-in escape hatch is provided; adding a flag to emit knowingly invalid output was considered and rejected as a permanent liability in the CLI surface.
- **Keyless-path conformance is deferred, not abandoned.** This feature scopes the fix to the static-key path and limits keyless work to honest operator messaging. The deferral rests on the keyless path serving a narrower operator population and on its conformant representation being genuinely undetermined — the signing bundle may not be expressible through JSON Signature Format's certificate-path and key-identifier properties at all, and settling that requires exercising the path against a live signing identity. A follow-up work item carries it.
- **SPDX output is out of scope.** SPDX signing uses a detached mechanism with no embedded signature slot and is untouched by this feature.
