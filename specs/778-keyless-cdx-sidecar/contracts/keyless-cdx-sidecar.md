# Contract: Keyless-Signed CycloneDX Output

**Feature**: 778-keyless-cdx-sidecar
**Surface**: the files a keyless-signed CycloneDX run produces
**Consumers**: anyone verifying a waybill signature, plus tooling that
reads CycloneDX documents

---

## C1 — What a run produces

A keyless-signed CycloneDX run writes two files: the document at the
operator's chosen path, and a companion signature artifact beside it,
named by appending the bundle suffix to the document's name.

**Guarantees**

- The document is valid CycloneDX and carries **no** in-document
  signature.
- The companion artifact's signed payload is the document's bytes
  exactly as written — not a canonicalization.
- Both files appear, or neither does.

---

## C2 — Verification

```sh
cosign verify-blob \
    --bundle <document>.sig.bundle.json \
    --certificate-identity '<expected>' \
    --certificate-oidc-issuer '<expected>' \
    <document>
```

**Guarantees**

- Verification succeeds against the unmodified document.
- Verification fails if any byte of the document changes.
- No waybill-specific preprocessing is required at any point.

**Consequence worth stating to consumers**: verification is
byte-exact. Reformatting the document — pretty-printing, reordering
keys, re-serializing through a parser — invalidates it. This is already
true of the SPDX companion artifacts and is inherent to detached
signing over concrete bytes.

---

## C3 — Finding the signature from the document alone

The document carries a document-level external reference of the
attestation type whose location is the companion artifact's **bare
filename**, with no directory component.

**Guarantees**

- Resolving that name relative to the document's own directory locates
  the artifact, wherever the pair is stored.
- The reference is part of the signed content — it cannot be added
  afterwards without invalidating the signature.
- The reference carries no checksum of the artifact. That would be
  circular: the artifact signs the document that would contain its
  hash.

**Not a guarantee**: the reference does not make the document
self-verifying, and does not cause signature-aware quality scorers to
report the document as signed — those inspect for an in-document
signature. Its purpose is discovery.

---

## C4 — Behaviour matrix

| Invocation | Outcome |
|---|---|
| keyless + CycloneDX | document + companion artifact; document unsigned in-document, carries the reference |
| keyless + SPDX only | unchanged from today |
| keyless + both | one correctly-associated artifact per format |
| static key + CycloneDX | unchanged — signature inside the document, no companion artifact, no reference |
| keyless, no signing identity | fails; no document, no artifact |
| unsigned | unchanged, byte-identical |

---

## C5 — Changed from the previous release

`--sign` with CycloneDX output previously exited non-zero (milestone
777). It now succeeds. Anyone who scripted around that failure sees the
command start working — a benign direction, but a behaviour change.

The pre-777 shape is **not** restored: a bundle embedded at
`metadata.signature` is not coming back. Anything that consumed it
stays broken, as it has since 777.

---

## C6 — Unaffected

- Unsigned CycloneDX output: byte-identical.
- Static-key CycloneDX: byte-identical to its post-777 form.
- SPDX signing, both modes: unchanged.
- The in-document signer's refusal of keyless mode: retained as a guard
  for non-CLI callers.
