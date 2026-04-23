use serde::{Deserialize, Serialize};

use crate::types::hash::ContentHash;
use crate::types::license::SpdxExpression;
use crate::types::purl::Purl;

/// A software component resolved from build-trace evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedComponent {
    pub purl: Purl,
    pub name: String,
    pub version: String,
    pub evidence: ResolutionEvidence,
    /// Licenses asserted by the package author in their manifest
    /// (npm package.json, Cargo.toml, etc.) or by the OS package
    /// metadata (dpkg copyright, rpm header). Mapped to CycloneDX
    /// `licenses[]` entries with `acknowledgement: "declared"`.
    pub licenses: Vec<SpdxExpression>,
    /// Licenses determined through external analysis (currently:
    /// ClearlyDefined.io's curated `licensed.declared` field, which
    /// is itself the result of CD's automated analysis pass). Mapped
    /// to CycloneDX `licenses[]` entries with
    /// `acknowledgement: "concluded"`. Empty when no enrichment was
    /// performed (offline mode, ecosystem unsupported by the
    /// enricher, or the package isn't curated by ClearlyDefined).
    /// May overlap with [`licenses`] when both sources agree; the
    /// CDX serializer emits each side once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concluded_licenses: Vec<SpdxExpression>,
    pub hashes: Vec<ContentHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,
    /// CPE 2.3 identifiers for this component. Synthesized locally
    /// using syft-style heuristic vendor candidates (e.g. `debian`,
    /// `<name>`). Multiple entries are emitted per component because
    /// NVD's CPE dictionary uses different vendor slugs for different
    /// packages and no single heuristic wins in all cases — downstream
    /// matchers can use any candidate that hits. Empty for ecosystems
    /// where the synthesizer has no opinion (rare). Serialized in
    /// CycloneDX as the first entry on `component.cpe` plus the full
    /// set under `properties["mikebom:cpe-candidates"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpes: Vec<String>,
    pub advisories: Vec<AdvisoryRef>,
    /// Per-file occurrences when the component is sourced from an OS
    /// installed-package db with deep-hashing enabled. Each entry
    /// records the on-disk path that the package owns plus a SHA-256
    /// of its contents and the dpkg-recorded MD5 (when available) for
    /// cross-reference. Empty for trace-mode and filename-resolved
    /// components, and for db-sourced components when `--no-deep-hash`
    /// was passed. Maps to CycloneDX `evidence.occurrences[]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<FileOccurrence>,
    /// Dev-vs-prod flag for ecosystems that carry the distinction (npm
    /// `devDependencies`, Poetry `category = "dev"`, Pipfile `develop`).
    /// `Some(false)` = prod, `Some(true)` = dev, `None` = source
    /// doesn't carry a dev/prod marker (venv dist-info, requirements.txt,
    /// deb, apk). Drives the `mikebom:dev-dependency = true` property in
    /// the CycloneDX output when `true` AND `--include-dev` was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dev: Option<bool>,
    /// Original unresolved requirement specification for fallback-tier
    /// entries (`requirements.txt` range specs, root `package.json`
    /// dependency declarations without a lockfile). The string is
    /// preserved verbatim so consumers can see what the original
    /// declaration was. Drives the `mikebom:requirement-range` property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement_range: Option<String>,
    /// Source-kind marker for non-registry dependencies: `"local"`
    /// (`file:` URIs), `"git"` (`git+...`), `"url"` (`http(s)://...`).
    /// `None` for normal registry-sourced components. Drives the
    /// `mikebom:source-type` property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// Traceability-ladder tier per milestone 002's research R13:
    /// `"build"` (eBPF trace), `"deployed"` (installed-package-db /
    /// installed venv / populated node_modules), `"analyzed"` (artefact
    /// file on disk identified by filename + hash), `"source"` (lockfile
    /// entry without a corresponding install), `"design"` (unlocked
    /// manifest declaration — requirements range, root package.json
    /// fallback). Drives the `mikebom:sbom-tier` property and the
    /// envelope-level `metadata.lifecycles[]` aggregation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_tier: Option<String>,
    /// Milestone 003 diagnostic for Go binaries: `"missing"` when a
    /// file was detected as a Go binary but `runtime/debug.BuildInfo`
    /// extraction failed (stripped binary, external `strip` run),
    /// `"unsupported"` for Go <1.18 binaries whose pre-inline format
    /// we don't parse. Drives the `mikebom:buildinfo-status` property
    /// on the file-level component emitted when the module list
    /// couldn't be recovered. `None` on every other component,
    /// including successful Go BuildInfo extractions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buildinfo_status: Option<String>,
    /// Milestone 004 canonical evidence-kind per `contracts/schema.md`.
    /// One of: `rpm-file`, `rpmdb-sqlite`, `rpmdb-bdb`, `dynamic-linkage`,
    /// `elf-note-package`, `embedded-version-string`. `None` on every
    /// pre-milestone-004 component (milestones 001–003 non-rpm ecosystems
    /// keep their existing serialization unchanged). Drives the
    /// `mikebom:evidence-kind` property at CycloneDX serialization time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_kind: Option<String>,
    /// Milestone 004 US2 — binary-format classifier for file-level
    /// binary components. `"elf"` / `"macho"` / `"pe"`; `None` for
    /// non-binary components. Drives `mikebom:binary-class`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_class: Option<String>,
    /// Milestone 004 US2 — true when the file-level binary lacks
    /// symbol tables / debug info / version resources. Drives
    /// `mikebom:binary-stripped`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_stripped: Option<bool>,
    /// Milestone 004 US2 — `"dynamic"` / `"static"` / `"mixed"`.
    /// Drives `mikebom:linkage-kind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkage_kind: Option<String>,
    /// Milestone 004 US2 — set on the file-level binary component when
    /// Go BuildInfo extraction succeeded on the same binary (R8 flat
    /// cross-link; FR-026). Drives `mikebom:detected-go`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_go: Option<bool>,
    /// Milestone 004 US2 — heuristic-confidence marker for components
    /// emitted via the curated embedded-version-string scanner.
    /// Exactly `"heuristic"` when present. Drives `mikebom:confidence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// Milestone 004 US2 — packer-signature marker on file-level
    /// binary components. `"upx"` when the scanner hit a UPX
    /// signature (research R7). Drives `mikebom:binary-packed`.
    /// `None` for unpacked binaries + non-binary components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_packed: Option<String>,
    /// Feature 005 US1 — npm-role classifier. Exactly `"internal"`
    /// when present, on components discovered inside npm's own bundled
    /// tree (`**/node_modules/npm/node_modules/**`) during `--image`
    /// scans. `None` on application deps and on every `--path`-mode
    /// scan (internals are filtered out before resolution). Drives the
    /// `mikebom:npm-role` property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_role: Option<String>,
    /// Feature 005 US4 — verbatim `VERSION-RELEASE` string from the
    /// rpmdb header (or equivalent source in other ecosystems that
    /// opt into this). Preserved so consumers can cross-reference
    /// `rpm -qa`'s `%{VERSION}-%{RELEASE}` column without re-parsing
    /// the PURL. Populated on every rpm component (both rpmdb-sourced
    /// via `rpm.rs` and standalone-artefact via `rpm_file.rs`); `None`
    /// elsewhere until another ecosystem adopts the pattern. Drives
    /// the `mikebom:raw-version` property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_version: Option<String>,
    /// PURL of a parent/container component that physically bundles
    /// this one. Set when the component was discovered inside another
    /// component — e.g. a vendored coord extracted from a Maven
    /// shade-plugin fat-jar's `META-INF/maven/<g>/<a>/` directory. The
    /// enclosing fat-jar's own PURL is recorded here so the CDX
    /// emitter can nest this component under its parent's
    /// `component.components[]` array (CDX 1.6 nested-components
    /// shape). Deduplication groups by `(ecosystem, name, version,
    /// parent_purl)` so the same coord vendored in two different
    /// parents surfaces as two distinct nested children rather than
    /// collapsing to one. `None` on top-level components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_purl: Option<String>,
    /// Ecosystem (other than this component's own) that owns the
    /// bytes from which this component's identity was extracted. Set
    /// when the same on-disk artifact carries two valid package
    /// identities — e.g. a JAR at `/usr/share/java/guava/guava.jar`
    /// owned by a Fedora RPM AND carrying a Maven coord in its
    /// embedded `META-INF/maven/.../pom.properties`. The Maven coord
    /// emits with `co_owned_by = Some("rpm")`; the RPM coord emits
    /// independently. Drives the CDX property `mikebom:co-owned-by`
    /// so downstream consumers can filter to a single-identity view.
    /// `None` on standalone artifacts (no cross-ecosystem overlap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_owned_by: Option<String>,
    /// Feature 009: `Some(true)` when the component was derived from a
    /// shaded JAR's `META-INF/DEPENDENCIES` file (ancestor dep with
    /// relocated bytecode inside the enclosing JAR). Vulnerability
    /// scanners can match against these coords even when the classes
    /// are namespace-relocated in the image. Surfaced via CDX property
    /// `mikebom:shade-relocation = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shade_relocation: Option<bool>,
    /// External references for this component — repository URLs,
    /// homepages, issue trackers. Maps to CycloneDX
    /// `components[].externalReferences[]`. Populated from PURL
    /// heuristics (e.g. `pkg:golang/github.com/X/Y` → vcs
    /// `https://github.com/X/Y`) and from deps.dev `VersionInfo.links`.
    /// Drives sbomqs `comp_with_source_code` when a `vcs`-type
    /// entry is present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,
}

/// A single external reference on a `ResolvedComponent`. The
/// `ref_type` values mirror CDX 1.6's `externalReferences[].type`
/// enum: `vcs` (source-code repo), `website` (project homepage),
/// `issue-tracker`, `distribution`, etc. Kept as a string rather
/// than an enum so new values flow through without a crate release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    pub ref_type: String,
    pub url: String,
}

/// One installed file owned by a `ResolvedComponent`. The presence of
/// per-file occurrences is what distinguishes a deep-hashed db-sourced
/// component from a fast db-sourced one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOccurrence {
    /// Canonical on-disk path the package owns — the path dpkg's
    /// `<pkg>.list` manifest declares (e.g. `/usr/bin/jq`), not the
    /// tempdir-prefixed path observed during an image-rootfs scan. This
    /// keeps occurrences comparable across hosts and the per-component
    /// Merkle root deterministic across scans.
    pub location: String,
    /// SHA-256 of the file contents at scan time, lowercase hex.
    pub sha256: String,
    /// MD5 reference dpkg recorded at install time, lowercase hex.
    /// `None` when the file was on disk but had no entry in the
    /// package's `.md5sums` (config files, /etc overrides, files
    /// created post-install).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5_legacy: Option<String>,
}

/// Evidence describing how a component was resolved from trace data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolutionEvidence {
    pub technique: ResolutionTechnique,
    pub confidence: f64,
    pub source_connection_ids: Vec<String>,
    pub source_file_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deps_dev_match: Option<DepsDevMatch>,
}

/// The technique used to resolve a component from observed activity.
///
/// Ordered by typical confidence (highest first). When the deduplicator
/// merges components that resolve from multiple techniques, the entry
/// with the highest per-component confidence wins; the variant ordering
/// is documentary only.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionTechnique {
    /// HTTPS download URL matched a known package-registry pattern
    /// during a build-time trace. Confidence 0.95.
    UrlPattern,
    /// Content hash returned a hit from a deps.dev lookup.
    /// Confidence 0.90.
    HashMatch,
    /// Read directly from an OS-level installed-package database
    /// (`/var/lib/dpkg/status`, `/lib/apk/db/installed`, …).
    /// Authoritative for what's installed but doesn't carry per-file
    /// content hashes and didn't observe the install event.
    /// Confidence 0.85.
    PackageDatabase,
    /// A file matching a recognised cache path pattern
    /// (`~/.cargo/registry/cache/...*.crate`, `/var/cache/apt/archives/...deb`,
    /// etc.) present on disk. Confidence 0.70.
    FilePathPattern,
    /// The observed hostname matched a known registry but no specific
    /// package URL was extracted. Confidence 0.40.
    HostnameHeuristic,
}

/// Reference to a security advisory affecting a resolved component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryRef {
    pub id: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// A match result from the deps.dev dependency resolution service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepsDevMatch {
    pub system: String,
    pub name: String,
    pub version: String,
}

/// A dependency relationship between two resolved components.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    /// The component that depends on another (PURL string).
    pub from: String,
    /// The component being depended upon (PURL string).
    pub to: String,
    /// Type of relationship.
    pub relationship_type: RelationshipType,
    /// Where this relationship was discovered.
    pub provenance: EnrichmentProvenance,
}

/// Type of dependency relationship.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    DependsOn,
    DevDependsOn,
    BuildDependsOn,
}

/// Provenance tracking for enriched data (Constitution Principle X).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnrichmentProvenance {
    /// Name of the enrichment source (e.g., "Cargo.lock", "deps.dev", "osv")
    pub source: String,
    /// What type of data this source provided
    pub data_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_technique_serde_snake_case() {
        let json = serde_json::to_string(&ResolutionTechnique::UrlPattern)
            .expect("serialize technique");
        assert_eq!(json, "\"url_pattern\"");

        let back: ResolutionTechnique =
            serde_json::from_str("\"hash_match\"").expect("deserialize technique");
        assert_eq!(back, ResolutionTechnique::HashMatch);
    }

    #[test]
    fn resolved_component_omits_none_fields() {
        let component = ResolvedComponent {
            purl: Purl::new("pkg:cargo/serde@1.0.197").expect("valid purl"),
            name: "serde".to_string(),
            version: "1.0.197".to_string(),
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::UrlPattern,
                confidence: 0.95,
                source_connection_ids: vec!["conn-1".to_string()],
                source_file_paths: vec![],
                deps_dev_match: None,
            },
            licenses: vec![],
            concluded_licenses: Vec::new(),
            hashes: vec![],
            supplier: None,
            cpes: vec![],
            advisories: vec![],
            occurrences: vec![],
            is_dev: None,
            requirement_range: None,
            source_type: None,
            sbom_tier: None,
            buildinfo_status: None,
            evidence_kind: None,
            binary_class: None,
            binary_stripped: None,
            linkage_kind: None,
            detected_go: None,
            confidence: None,
            binary_packed: None,
            npm_role: None,
            raw_version: None,
            parent_purl: None,
            co_owned_by: None,
            shade_relocation: None,
            external_references: Vec::new(),
        };

        let json = serde_json::to_string(&component).expect("serialize component");
        assert!(!json.contains("\"supplier\""));
        assert!(!json.contains("\"deps_dev_match\""));
        assert!(!json.contains("\"cpes\""));
    }

    #[test]
    fn resolved_component_serde_round_trip() {
        let component = ResolvedComponent {
            purl: Purl::new("pkg:npm/lodash@4.17.21").expect("valid purl"),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::HashMatch,
                confidence: 0.99,
                source_connection_ids: vec!["conn-5".to_string()],
                source_file_paths: vec!["/tmp/build/node_modules/lodash".to_string()],
                deps_dev_match: Some(DepsDevMatch {
                    system: "npm".to_string(),
                    name: "lodash".to_string(),
                    version: "4.17.21".to_string(),
                }),
            },
            licenses: vec![],
            concluded_licenses: Vec::new(),
            hashes: vec![],
            supplier: Some("Lodash contributors".to_string()),
            cpes: vec![],
            advisories: vec![AdvisoryRef {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                source: "github".to_string(),
                url: Some("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz".to_string()),
            }],
            occurrences: vec![],
            is_dev: None,
            requirement_range: None,
            source_type: None,
            sbom_tier: None,
            buildinfo_status: None,
            evidence_kind: None,
            binary_class: None,
            binary_stripped: None,
            linkage_kind: None,
            detected_go: None,
            confidence: None,
            binary_packed: None,
            npm_role: None,
            raw_version: None,
            parent_purl: None,
            co_owned_by: None,
            shade_relocation: None,
            external_references: Vec::new(),
        };

        let json = serde_json::to_string(&component).expect("serialize component");
        let back: ResolvedComponent = serde_json::from_str(&json).expect("deserialize component");
        assert_eq!(component.purl, back.purl);
        assert_eq!(component.evidence.confidence, back.evidence.confidence);
        assert_eq!(component.supplier, back.supplier);
        assert_eq!(component.advisories.len(), back.advisories.len());
    }
}