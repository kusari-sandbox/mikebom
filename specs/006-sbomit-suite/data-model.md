# Phase 1 — Data Model: SBOMit compliance suite

New and modified types across `mikebom-common/` (shared) and
`mikebom-cli/` (logic). Types follow Constitution Principle IV
(type-driven correctness): domain newtypes, `thiserror` for errors,
no `String` leakage across module boundaries for identifiers and
hashes.

---

## Modified types (existing)

### `InTotoStatement` (`mikebom-common/src/attestation/statement.rs`)

**Unchanged.** The Statement v1 payload shape is preserved:
`_type`, `subject`, `predicateType`, `predicate`. What changes is
how `subject` is populated (see `Subject` below) and how the
statement is wrapped for distribution (see `SignedEnvelope` below).

### `ResourceDescriptor` (`mikebom-common/src/attestation/statement.rs`)

**Unchanged type, richer population.** Today:
`{ name: String, digest: BTreeMap<String, String> }`. No schema
change; we just populate it with real artifact names and real
SHA-256 digests instead of the synthetic `"build-output"` sentinel.
The `digest` map's algorithm key is `"sha256"` for real artifacts
and `"synthetic"` for the no-artifact fallback (per clarification
Q5).

---

## New types

### `SignedEnvelope` (`mikebom-common/src/attestation/envelope.rs`, NEW)

```rust
/// A DSSE-shaped envelope wrapping an in-toto Statement. The
/// canonical format that SBOMit-compliant verifiers expect.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignedEnvelope {
    /// Always `"application/vnd.in-toto+json"` for Statement v1.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded canonical JSON of the in-toto Statement.
    pub payload: String,
    /// One or more signatures covering the PAE-wrapped payload.
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Signature {
    /// Optional key identifier (certificate hash for keyless;
    /// public-key-thumbprint for local keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Base64-encoded signature bytes.
    pub sig: String,
    /// Per-signature identity metadata for downstream verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityMetadata>,
}

/// The proof-of-identity carried alongside each signature.
/// Exactly one variant is populated per signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IdentityMetadata {
    /// Keyless signing: Fulcio-issued ephemeral certificate plus
    /// the Rekor inclusion proof (when transparency log was used).
    Certificate {
        certificate: String,      // PEM-encoded x509
        chain: Vec<String>,       // intermediate certs in PEM
        rekor_bundle: Option<RekorBundle>,
    },
    /// Local-key signing: reference to the verifying public key.
    PublicKey {
        public_key: String,       // PEM-encoded
        /// Which key algorithm was used (`ecdsa-p256`, `ed25519`,
        /// `rsa-pkcs1`). Enum so parsing can reject unknowns.
        algorithm: KeyAlgorithm,
    },
}

/// Rekor transparency-log inclusion proof, embedded when
/// `--no-transparency-log` was NOT passed during signing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RekorBundle {
    pub log_index: u64,
    pub log_id: String,
    pub integrated_time: i64,
    pub signed_entry_timestamp: String,  // base64
    pub inclusion_proof: InclusionProof,
}
```

Serialized shape (example):

```jsonc
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCAuLi59",
  "signatures": [
    {
      "keyid": "sha256:...",
      "sig": "MEQCIH...",
      "identity": {
        "type": "certificate",
        "certificate": "-----BEGIN CERTIFICATE-----\n...",
        "chain": [],
        "rekor_bundle": {
          "log_index": 12345,
          "log_id": "sha256:...",
          "integrated_time": 1713700000,
          "signed_entry_timestamp": "...",
          "inclusion_proof": { "... " }
        }
      }
    }
  ]
}
```

### `SigningIdentity` (`mikebom-cli/src/attestation/signer.rs`, NEW)

```rust
/// How mikebom signs an attestation. Populated from CLI flags.
#[derive(Clone, Debug)]
pub enum SigningIdentity {
    /// No signing requested — emit unsigned attestation + warning
    /// (preserves legacy behavior per FR-019).
    None,
    /// Local-key signing: PEM file on disk, passphrase optionally
    /// supplied via env var (Q2 clarification).
    LocalKey {
        path: PathBuf,
        /// Name of the env var to read for the passphrase when
        /// the PEM is encrypted. `None` for unencrypted keys.
        passphrase_env: Option<String>,
    },
    /// Keyless signing: Fulcio OIDC flow + Rekor transparency log.
    Keyless {
        fulcio_url: Url,
        rekor_url: Url,
        oidc_provider: OidcProvider,
        /// Whether to upload to Rekor (Q1 clarification: default
        /// true, `--no-transparency-log` sets false).
        transparency_log: bool,
    },
}

#[derive(Clone, Debug)]
pub enum OidcProvider {
    /// Auto-detect from env vars (`ACTIONS_ID_TOKEN_REQUEST_URL`).
    GitHubActions,
    /// Operator-supplied OIDC token via `SIGSTORE_ID_TOKEN` env var.
    Explicit,
    /// Interactive OAuth2 flow (opens browser). Local dev only.
    Interactive,
}
```

### `Subject` / `ArtifactSubject` / `SyntheticSubject` (`mikebom-cli/src/attestation/subject.rs`, NEW)

Today the attestation builder takes a single `subject_name` +
optional `subject_digest`. Replace with a structured enum that the
resolver can populate:

```rust
/// The resource(s) an attestation is about. Maps 1-to-1 with
/// in-toto `ResourceDescriptor[]`.
#[derive(Clone, Debug)]
pub enum Subject {
    /// Real build artifact detected on disk. Emits as
    /// `{ "name": "<file>", "digest": { "sha256": "<hex>" } }`.
    Artifact {
        name: String,         // file path relative to workdir
        digest: ContentHash,  // must be SHA-256 per FR-011
    },
    /// No build artifact found. Emits as
    /// `{ "name": "synthetic:<command-summary>",
    ///    "digest": { "synthetic": "<sha256-of-cmd-and-time>" } }`.
    Synthetic {
        command_summary: String,  // truncated argv[0] + hash
        synthetic_digest: String, // sha256(command + start_ts)
    },
}

/// The resolver walks the traced file-access events + post-trace
/// artifact dirs and produces zero or more `Artifact` subjects.
/// Returns a `Synthetic` subject when no artifact is detected.
pub struct SubjectResolver {
    artifact_suffixes: &'static [&'static str],
    artifact_dirs: Vec<PathBuf>,
    size_cap: u64,
}

impl SubjectResolver {
    pub fn resolve(
        &self,
        trace: &AggregatedTrace,
        trace_command: &str,
        trace_start: Timestamp,
        operator_override: &[PathBuf],
    ) -> Vec<Subject>;
}
```

Detection precedence (per Q4 clarification):
1. Operator-supplied `--subject <file>` flags → `Artifact`
   entries, exact filenames.
2. Files in operator-supplied `--artifact-dir` paths that
   post-date `trace_start` → `Artifact` entries.
3. Files with `ARTIFACT_SUFFIXES` extensions written during the
   trace → `Artifact` entries.
4. Files with ELF / Mach-O / PE magic bytes written during the
   trace → `Artifact` entries.
5. If all above produce zero subjects → single `Synthetic` entry.

### `VerificationReport` / `FailureMode` (`mikebom-cli/src/attestation/verifier.rs`, NEW)

```rust
/// Structured outcome of `mikebom sbom verify`. Never a raw string.
#[derive(Clone, Debug)]
pub enum VerificationReport {
    Pass {
        subject: Vec<Subject>,
        signer_identity: SignerIdentityInfo,
        layout_matched: bool,
    },
    Fail {
        mode: FailureMode,
        detail: String,
        /// Partial info available from successful earlier steps.
        partial_identity: Option<SignerIdentityInfo>,
    },
}

/// Named failure modes (per FR-022). Each maps to a distinct
/// message class so CI tooling can pattern-match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureMode {
    NotSigned,                // envelope is raw JSON, not DSSE
    MalformedEnvelope,        // DSSE fields missing/invalid
    SignatureInvalid,         // signature math fails
    IdentityMismatch,         // cert identity doesn't match policy
    SubjectDigestMismatch,    // on-disk SHA != subject digest
    LayoutViolation {         // passed layout-provided policy fails
        step_name: String,
    },
    TransparencyLogMissing,   // Rekor proof expected but absent
    CertificateExpired,
    TrustRootInvalid,
}

pub struct SignerIdentityInfo {
    pub identity_kind: IdentityKind,   // cert | pubkey | none
    pub identifier: String,            // email/UUID/fingerprint
    pub rekor_log_index: Option<u64>,
}
```

### `Layout` + `Functionary` (`mikebom-cli/src/policy/layout.rs`, NEW)

```rust
/// Minimal in-toto layout shape mikebom generates + verifies.
/// JSON-serialized by `serde_json`; matches the in-toto spec subset
/// from research R2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Layout {
    #[serde(rename = "_type")]
    pub layout_type: String,          // always "layout"
    pub expires: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readme: Option<String>,
    pub keys: BTreeMap<String, LayoutKey>,
    pub steps: Vec<LayoutStep>,
    #[serde(default)]
    pub inspect: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayoutKey {
    pub keytype: String,           // "ecdsa" | "ed25519" | "rsa"
    pub scheme: String,
    pub keyval: KeyVal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVal {
    pub public: String,            // PEM-encoded public key
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayoutStep {
    #[serde(rename = "_name")]
    pub name: String,
    #[serde(default)]
    pub expected_command: Vec<String>,
    pub pubkeys: Vec<String>,      // keyid refs into Layout.keys
    pub threshold: u32,
    #[serde(default)]
    pub expected_materials: Vec<Vec<String>>,
    #[serde(default)]
    pub expected_products: Vec<Vec<String>>,
}
```

### `EnrichmentPatch` (`mikebom-cli/src/sbom/mutator.rs`, NEW — P3)

```rust
/// A recorded-provenance SBOM enrichment. Applied via RFC 6902
/// JSON Patch with author + timestamp metadata attached to the
/// enriched SBOM as a CycloneDX property group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrichmentPatch {
    pub operations: Vec<JsonPatchOp>,  // RFC 6902 patch operations
    pub author: String,
    pub timestamp: DateTime<Utc>,
    /// SHA-256 of the original attestation this enrichment applies
    /// to. Lets a verifier walk from the enriched SBOM back to the
    /// trace-attested source of truth.
    pub base_attestation_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "op")]
pub enum JsonPatchOp {
    Add { path: String, value: serde_json::Value },
    Remove { path: String },
    Replace { path: String, value: serde_json::Value },
    Move { from: String, path: String },
    Copy { from: String, path: String },
    Test { path: String, value: serde_json::Value },
}
```

---

## Error types

Per Constitution Principle IV, each module owns a `thiserror`-derived
error enum:

```rust
// mikebom-cli/src/attestation/signer.rs
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("no signing identity configured and --require-signing was set")]
    NoIdentityConfigured,
    #[error("local key file {0} not found")]
    KeyFileMissing(PathBuf),
    #[error("local key file {0} cannot be decrypted — check {1} env var")]
    KeyPassphraseInvalid(PathBuf, String),
    #[error("OIDC token flow failed: {0}")]
    OidcFailure(String),
    #[error("Fulcio certificate issuance failed: {0}")]
    FulcioFailure(String),
    #[error("Rekor transparency-log upload failed: {0}")]
    RekorFailure(String),
    #[error("signature computation failed: {0}")]
    SignatureComputation(String),
}

// mikebom-cli/src/attestation/verifier.rs
#[derive(Debug, thiserror::Error)]
pub enum VerificationError { /* maps to FailureMode */ }

// mikebom-cli/src/policy/layout.rs
#[derive(Debug, thiserror::Error)]
pub enum LayoutError { /* parse + validate errors */ }
```

---

## Relationships

```text
InTotoStatement  ──┐
                   ├── wrapped-by ──► SignedEnvelope
SigningIdentity ───┘                     │
                                         ├── signatures ──► Vec<Signature>
                                         └── Signature ──► IdentityMetadata
                                                               │
                                                               └── Certificate | PublicKey
Subject (enum) ──────────────────────► InTotoStatement.subject[*]
    │
    ├── Artifact   → ResourceDescriptor { name, digest.sha256 }
    └── Synthetic  → ResourceDescriptor { name: "synthetic:...",
                                           digest.synthetic: "..." }

Layout            ──► verifies ──► SignedEnvelope
                  ──► references ─► LayoutKey → keyid-ref from Signature
                  ──► steps[].expected_products ── match ──► Subject

VerificationReport
    ├── Pass  { subject[], signer_identity, layout_matched }
    └── Fail  { mode: FailureMode, detail, partial_identity }

EnrichmentPatch   ──► applies-to ──► CycloneDX Bom (JSON tree)
                  ──► references ──► base_attestation_ref (SHA-256 of SignedEnvelope)
                  ──► emits ──────► property group in enriched Bom
```

---

## State transitions

**SigningIdentity** is a build-time construction (not runtime state —
once constructed from CLI flags, it's used to sign, then discarded).

**Attestation emission** has three terminal states:
- `Emitted unsigned` (when `SigningIdentity::None`): legacy file with
  warning logged.
- `Emitted signed` (when local or keyless succeeds): DSSE envelope
  written, exit zero.
- `Aborted` (when signing was requested and failed): no file written,
  exit non-zero, `.partial` sidecar may be emitted (Q3 clarification).

**Verification** terminates in `Pass` or `Fail`; no intermediate
state. Partial-info reporting on `Fail` carries whatever was
extracted before the violation (e.g., a signature validated but its
cert expired: `partial_identity: Some(...)`).

---

## Validation rules from requirements

- **FR-011**: `Subject::Artifact::digest` MUST be computed from
  on-disk bytes at attestation-creation time, not trace-event
  inference → enforced in `SubjectResolver::resolve` by always
  calling `stream_hash_sha256(path)` for Artifact candidates.
- **FR-010**: exactly one `Subject::Synthetic` emitted when no
  Artifact candidates → enforced in `SubjectResolver::resolve`
  branch logic.
- **FR-006**: signing determinism: `sign(canonical_payload,
  identity)` MUST use canonical JSON serialization before PAE
  wrapping so identical input produces byte-identical payload →
  use `serde_json::to_vec` with canonical key ordering.
- **FR-006a**: any signing-pipeline error returns
  `Err(SigningError::*)`; the CLI layer maps this to non-zero exit
  without writing an attestation file.
