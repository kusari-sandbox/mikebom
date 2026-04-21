use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use tracing::{debug, warn};

use mikebom_common::resolution::{
    EnrichmentProvenance, Relationship, RelationshipType, ResolvedComponent,
};

use super::source::EnrichmentSource;

/// Supported lockfile formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockfileType {
    CargoLock,
    PackageLockJson,
    GoSum,
}

/// An enrichment source that extracts dependency relationships from lockfiles.
///
/// Lockfiles provide authoritative dependency graph information but no
/// license or supplier metadata.
pub struct LockfileSource {
    lockfile_path: PathBuf,
    lockfile_type: LockfileType,
}

/// A parsed package entry from a Cargo.lock file.
#[derive(Debug, Clone)]
struct CargoPackage {
    name: String,
    version: String,
    dependencies: Vec<String>,
}

impl LockfileSource {
    /// Create a new lockfile source from a path and type.
    pub fn new(lockfile_path: PathBuf, lockfile_type: LockfileType) -> Self {
        Self {
            lockfile_path,
            lockfile_type,
        }
    }

    /// Auto-detect lockfile type from the filename.
    pub fn detect(path: &Path) -> Option<LockfileType> {
        let filename = path.file_name()?.to_str()?;
        match filename {
            "Cargo.lock" => Some(LockfileType::CargoLock),
            "package-lock.json" => Some(LockfileType::PackageLockJson),
            "go.sum" => Some(LockfileType::GoSum),
            _ => None,
        }
    }

    /// Parse Cargo.lock and return the list of packages.
    fn parse_cargo_lock(content: &str) -> anyhow::Result<Vec<CargoPackage>> {
        let mut packages = Vec::new();
        let mut current: Option<CargoPackage> = None;
        let mut in_deps = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "[[package]]" {
                // Flush the previous package if any.
                if let Some(pkg) = current.take() {
                    packages.push(pkg);
                }
                current = Some(CargoPackage {
                    name: String::new(),
                    version: String::new(),
                    dependencies: Vec::new(),
                });
                in_deps = false;
                continue;
            }

            if let Some(ref mut pkg) = current {
                if trimmed == "dependencies = [" {
                    in_deps = true;
                    continue;
                }

                if in_deps {
                    if trimmed == "]" {
                        in_deps = false;
                        continue;
                    }
                    // Dependency lines look like: "serde 1.0.197",
                    // or "serde 1.0.197 (registry+...)",
                    let dep_str = trimmed.trim_matches(|c| c == '"' || c == ',');
                    // Extract just the package name (first token).
                    if let Some(dep_name) = dep_str.split_whitespace().next() {
                        pkg.dependencies.push(dep_name.to_string());
                    }
                    continue;
                }

                if let Some(rest) = trimmed.strip_prefix("name = ") {
                    pkg.name = rest.trim_matches('"').to_string();
                } else if let Some(rest) = trimmed.strip_prefix("version = ") {
                    pkg.version = rest.trim_matches('"').to_string();
                }
            }
        }

        // Flush the last package.
        if let Some(pkg) = current {
            packages.push(pkg);
        }

        Ok(packages)
    }

    /// Build PURL for a Cargo package.
    fn cargo_purl(name: &str, version: &str) -> String {
        format!("pkg:cargo/{}@{}", name, version)
    }
}

impl EnrichmentSource for LockfileSource {
    fn name(&self) -> &str {
        match self.lockfile_type {
            LockfileType::CargoLock => "Cargo.lock",
            LockfileType::PackageLockJson => "package-lock.json",
            LockfileType::GoSum => "go.sum",
        }
    }

    fn enrich_relationships(
        &self,
        components: &[ResolvedComponent],
    ) -> anyhow::Result<Vec<Relationship>> {
        match self.lockfile_type {
            LockfileType::CargoLock => {
                let content = std::fs::read_to_string(&self.lockfile_path)
                    .with_context(|| format!("reading {}", self.lockfile_path.display()))?;
                let packages = Self::parse_cargo_lock(&content)?;

                // Build a set of PURLs present in the resolved components for the guard rail.
                let component_purls: std::collections::HashSet<String> = components
                    .iter()
                    .map(|c| c.purl.as_str().to_string())
                    .collect();

                // Build a lookup: (name, version) -> purl for lockfile packages.
                let mut lockfile_lookup: HashMap<(&str, &str), String> = HashMap::new();
                for pkg in &packages {
                    let purl = Self::cargo_purl(&pkg.name, &pkg.version);
                    lockfile_lookup.insert((&pkg.name, &pkg.version), purl);
                }

                // Also build name -> [(version, purl)] for dependency resolution
                // (Cargo.lock deps only specify name, we need to find the version).
                let mut name_to_versions: HashMap<&str, Vec<(&str, String)>> = HashMap::new();
                for pkg in &packages {
                    let purl = Self::cargo_purl(&pkg.name, &pkg.version);
                    name_to_versions
                        .entry(&pkg.name)
                        .or_default()
                        .push((&pkg.version, purl));
                }

                let mut relationships = Vec::new();

                for pkg in &packages {
                    let from_purl = Self::cargo_purl(&pkg.name, &pkg.version);
                    if !component_purls.contains(&from_purl) {
                        continue;
                    }

                    for dep_name in &pkg.dependencies {
                        // Find the matching version for this dependency name.
                        let dep_entries = match name_to_versions.get(dep_name.as_str()) {
                            Some(entries) => entries,
                            None => {
                                debug!(
                                    dep = %dep_name,
                                    "lockfile dependency not found in lockfile packages"
                                );
                                continue;
                            }
                        };

                        // If there's exactly one version, use it. Otherwise pick the first
                        // (Cargo.lock v3 uses disambiguated names, but v1/v2 may not).
                        let to_purl = &dep_entries[0].1;

                        if !component_purls.contains(to_purl) {
                            debug!(
                                from = %from_purl,
                                to = %to_purl,
                                "skipping relationship: target not in component set"
                            );
                            continue;
                        }

                        relationships.push(Relationship {
                            from: from_purl.clone(),
                            to: to_purl.clone(),
                            relationship_type: RelationshipType::DependsOn,
                            provenance: EnrichmentProvenance {
                                source: "Cargo.lock".to_string(),
                                data_type: "dependency_graph".to_string(),
                            },
                        });
                    }
                }

                debug!(
                    count = relationships.len(),
                    "extracted relationships from Cargo.lock"
                );
                Ok(relationships)
            }
            LockfileType::PackageLockJson | LockfileType::GoSum => {
                warn!(
                    lockfile_type = ?self.lockfile_type,
                    "lockfile type not yet implemented, returning empty relationships"
                );
                Ok(vec![])
            }
        }
    }

    fn enrich_metadata(
        &self,
        _component: &mut ResolvedComponent,
    ) -> anyhow::Result<()> {
        // Lockfiles don't contain license or supplier metadata.
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::purl::Purl;
    use std::io::Write;

    const SAMPLE_CARGO_LOCK: &str = r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "anyhow"
version = "1.0.82"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "myapp"
version = "0.1.0"
dependencies = [
 "anyhow 1.0.82",
 "serde 1.0.197",
]

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "serde_derive 1.0.197",
]

[[package]]
name = "serde_derive"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    fn make_component(name: &str, version: &str) -> ResolvedComponent {
        let purl_str = format!("pkg:cargo/{}@{}", name, version);
        ResolvedComponent {
            purl: Purl::new(&purl_str).expect("valid purl"),
            name: name.to_string(),
            version: version.to_string(),
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::UrlPattern,
                confidence: 0.9,
                source_connection_ids: vec![],
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
        }
    }

    #[test]
    fn parse_cargo_lock_extracts_packages() {
        let packages =
            LockfileSource::parse_cargo_lock(SAMPLE_CARGO_LOCK).expect("parse cargo lock");
        assert_eq!(packages.len(), 4);

        let myapp = packages.iter().find(|p| p.name == "myapp").expect("myapp");
        assert_eq!(myapp.version, "0.1.0");
        assert_eq!(myapp.dependencies.len(), 2);
        assert!(myapp.dependencies.contains(&"anyhow".to_string()));
        assert!(myapp.dependencies.contains(&"serde".to_string()));

        let serde = packages.iter().find(|p| p.name == "serde").expect("serde");
        assert_eq!(serde.dependencies.len(), 1);
        assert!(serde.dependencies.contains(&"serde_derive".to_string()));
    }

    #[test]
    fn enrich_relationships_respects_component_set() {
        // Write sample lockfile to a temp file.
        let mut tmpfile = tempfile::NamedTempFile::new().expect("create temp file");
        tmpfile
            .write_all(SAMPLE_CARGO_LOCK.as_bytes())
            .expect("write temp file");

        let source = LockfileSource::new(
            tmpfile.path().to_path_buf(),
            LockfileType::CargoLock,
        );

        // Only include myapp and serde in the component set (not anyhow or serde_derive).
        let components = vec![
            make_component("myapp", "0.1.0"),
            make_component("serde", "1.0.197"),
        ];

        let rels = source
            .enrich_relationships(&components)
            .expect("enrich relationships");

        // myapp -> serde should be present (both in set).
        assert!(
            rels.iter().any(|r| r.from.contains("myapp") && r.to.contains("serde")),
            "expected myapp -> serde relationship"
        );

        // myapp -> anyhow should NOT be present (anyhow not in component set).
        assert!(
            !rels.iter().any(|r| r.to.contains("anyhow")),
            "anyhow should not appear in relationships"
        );

        // serde -> serde_derive should NOT be present (serde_derive not in component set).
        assert!(
            !rels.iter().any(|r| r.to.contains("serde_derive")),
            "serde_derive should not appear in relationships"
        );
    }

    #[test]
    fn detect_lockfile_type() {
        assert_eq!(
            LockfileSource::detect(Path::new("/project/Cargo.lock")),
            Some(LockfileType::CargoLock)
        );
        assert_eq!(
            LockfileSource::detect(Path::new("/project/package-lock.json")),
            Some(LockfileType::PackageLockJson)
        );
        assert_eq!(
            LockfileSource::detect(Path::new("/project/go.sum")),
            Some(LockfileType::GoSum)
        );
        assert_eq!(LockfileSource::detect(Path::new("/project/random.txt")), None);
    }

    #[test]
    fn enrich_metadata_is_noop_for_lockfiles() {
        let tmpfile = tempfile::NamedTempFile::new().expect("create temp file");
        let source = LockfileSource::new(
            tmpfile.path().to_path_buf(),
            LockfileType::CargoLock,
        );
        let mut component = make_component("serde", "1.0.197");
        source
            .enrich_metadata(&mut component)
            .expect("metadata enrichment");
        // Should not have changed anything.
        assert!(component.licenses.is_empty());
        assert!(component.supplier.is_none());
    }
}