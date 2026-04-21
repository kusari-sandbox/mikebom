//! PURL → ClearlyDefined coordinate mapping.
//!
//! ClearlyDefined identifies packages by a 5-tuple
//! `(type, provider, namespace, name, revision)`. Each tuple becomes a
//! URL path:
//!
//! ```text
//! GET https://api.clearlydefined.io/definitions/{type}/{provider}/{ns}/{name}/{rev}
//! ```
//!
//! Where `ns` is `-` when the package has no namespace (single-name
//! ecosystems like cargo, gem, pypi, npm-non-scoped). The mapping per
//! ecosystem matches CD's published documentation:
//! <https://docs.clearlydefined.io/docs/handbook/coordinates>
//!
//! Ecosystems mikebom maps:
//!
//! | PURL ecosystem | CD type | CD provider | namespace | name | revision |
//! |---|---|---|---|---|---|
//! | npm  | npm    | npmjs        | `@scope` (no `@`) or `-` | name | version |
//! | cargo | crate  | cratesio     | `-`                      | name | version |
//! | gem  | gem    | rubygems     | `-`                      | name | version |
//! | pypi | pypi   | pypi         | `-`                      | name (lowercased) | version |
//! | maven | maven  | mavencentral | groupId                  | artifactId | version |
//! | golang | go    | golang       | URL-encoded module-prefix | last segment | `v`-prefixed version |
//!
//! Unsupported ecosystems (deb, apk, rpm, generic, alpm, etc.) return
//! `None`. Callers skip those silently.

use mikebom_common::resolution::ResolvedComponent;

/// Identifier tuple for a ClearlyDefined package definition.
///
/// All fields are stored as owned `String`s so the cache key
/// (`HashMap<CdCoord, _>`) hashes by value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CdCoord {
    pub cd_type: String,
    pub provider: String,
    pub namespace: String,
    pub name: String,
    pub revision: String,
}

impl CdCoord {
    /// URL path segment after `/definitions/`. Used by the HTTP client.
    pub fn url_path(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            url_encode(&self.cd_type),
            url_encode(&self.provider),
            url_encode(&self.namespace),
            url_encode(&self.name),
            url_encode(&self.revision),
        )
    }
}

/// Compute the ClearlyDefined coord for a `ResolvedComponent`. Returns
/// `None` when the component's ecosystem isn't in CD's supported set
/// or when required fields (name / version) are empty.
pub fn cd_coord_for(component: &ResolvedComponent) -> Option<CdCoord> {
    if component.name.is_empty() || component.version.is_empty() {
        return None;
    }
    let ecosystem = component.purl.ecosystem();
    let namespace = component.purl.namespace();
    match ecosystem {
        "npm" => Some(CdCoord {
            cd_type: "npm".to_string(),
            provider: "npmjs".to_string(),
            namespace: namespace_or_dash_strip_at(namespace),
            name: component.name.clone(),
            revision: component.version.clone(),
        }),
        "cargo" => Some(CdCoord {
            cd_type: "crate".to_string(),
            provider: "cratesio".to_string(),
            namespace: "-".to_string(),
            name: component.name.clone(),
            revision: component.version.clone(),
        }),
        "gem" => Some(CdCoord {
            cd_type: "gem".to_string(),
            provider: "rubygems".to_string(),
            namespace: "-".to_string(),
            name: component.name.clone(),
            revision: component.version.clone(),
        }),
        "pypi" => Some(CdCoord {
            cd_type: "pypi".to_string(),
            provider: "pypi".to_string(),
            namespace: "-".to_string(),
            // PyPI normalizes names to lowercase per PEP 503.
            name: component.name.to_ascii_lowercase(),
            revision: component.version.clone(),
        }),
        "maven" => {
            // Maven requires a non-empty namespace (groupId) for CD lookup.
            let group_id = namespace?;
            if group_id.is_empty() {
                return None;
            }
            Some(CdCoord {
                cd_type: "maven".to_string(),
                provider: "mavencentral".to_string(),
                namespace: group_id.to_string(),
                name: component.name.clone(),
                revision: component.version.clone(),
            })
        }
        "golang" => {
            // Go module paths look like `github.com/sirupsen/logrus`.
            // PURL splits this so namespace = `github.com/sirupsen` and
            // name = `logrus`. CD takes the full path: type=go,
            // provider=golang, namespace=URL-encoded prefix,
            // name=last segment, revision=v-prefixed semver.
            //
            // `component.name` in mikebom is the FULL module path for
            // Go (`github.com/sirupsen/logrus`), not just the last
            // segment, so we can't use it directly — that would double
            // the prefix into the URL and produce 404s. Read the short
            // name from the PURL where `name` is canonically the last
            // path segment.
            let ns = namespace.unwrap_or("");
            let revision = if component.version.starts_with('v') {
                component.version.clone()
            } else {
                format!("v{}", component.version)
            };
            Some(CdCoord {
                cd_type: "go".to_string(),
                provider: "golang".to_string(),
                namespace: if ns.is_empty() { "-".to_string() } else { ns.to_string() },
                name: component.purl.name().to_string(),
                revision,
            })
        }
        _ => None,
    }
}

/// npm scopes are stored with the leading `@` in PURL namespace
/// (`@angular`). CD strips the `@` and uses just `angular`.
fn namespace_or_dash_strip_at(namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) if !ns.is_empty() => ns.trim_start_matches('@').to_string(),
        _ => "-".to_string(),
    }
}

/// Percent-encode a CD URL segment. Only encodes `/` and special chars
/// that would break the URL grammar; unreserved RFC 3986 chars stay
/// literal so `cratesio`, `mavencentral`, etc. remain readable.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric()
            || matches!(c, '-' | '.' | '_' | '~' | '@')
        {
            out.push(c);
        } else {
            for b in c.to_string().as_bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{
        ResolutionEvidence, ResolutionTechnique,
    };
    use mikebom_common::types::purl::Purl;

    fn make_component(purl: &str) -> ResolvedComponent {
        let p = Purl::new(purl).expect("valid purl");
        ResolvedComponent {
            name: p.name().to_string(),
            version: p.version().unwrap_or("").to_string(),
            purl: p,
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::PackageDatabase,
                confidence: 0.85,
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
            external_references: Vec::new(),
        }
    }

    #[test]
    fn cd_coord_for_npm_unscoped() {
        let c = make_component("pkg:npm/express@4.18.2");
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.cd_type, "npm");
        assert_eq!(coord.provider, "npmjs");
        assert_eq!(coord.namespace, "-");
        assert_eq!(coord.name, "express");
        assert_eq!(coord.revision, "4.18.2");
        assert_eq!(coord.url_path(), "npm/npmjs/-/express/4.18.2");
    }

    #[test]
    fn cd_coord_for_npm_scoped_strips_at_sign() {
        let c = make_component("pkg:npm/%40angular/core@16.0.0");
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.namespace, "angular");
        assert_eq!(coord.url_path(), "npm/npmjs/angular/core/16.0.0");
    }

    #[test]
    fn cd_coord_for_cargo() {
        let c = make_component("pkg:cargo/serde@1.0.197");
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.cd_type, "crate");
        assert_eq!(coord.provider, "cratesio");
        assert_eq!(coord.url_path(), "crate/cratesio/-/serde/1.0.197");
    }

    #[test]
    fn cd_coord_for_gem() {
        let c = make_component("pkg:gem/sinatra@3.1.0");
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.url_path(), "gem/rubygems/-/sinatra/3.1.0");
    }

    #[test]
    fn cd_coord_for_pypi_lowercases_name() {
        let c = make_component("pkg:pypi/Django@4.2.0");
        let coord = cd_coord_for(&c).unwrap();
        // PyPI normalizes names to lowercase per PEP 503.
        assert_eq!(coord.name, "django");
        assert_eq!(coord.url_path(), "pypi/pypi/-/django/4.2.0");
    }

    #[test]
    fn cd_coord_for_maven() {
        let c = make_component(
            "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
        );
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.cd_type, "maven");
        assert_eq!(coord.provider, "mavencentral");
        assert_eq!(coord.namespace, "org.apache.commons");
        assert_eq!(coord.name, "commons-lang3");
        assert_eq!(
            coord.url_path(),
            "maven/mavencentral/org.apache.commons/commons-lang3/3.14.0"
        );
    }

    #[test]
    fn cd_coord_for_golang_adds_v_prefix() {
        // mikebom emits Go PURLs with literal slashes in the namespace
        // (e.g. `pkg:golang/github.com/sirupsen/logrus@v1.9.3`); the
        // PURL parser accepts that form. Build the component manually
        // since `Purl::new` rejects multi-segment namespaces.
        let mut c = make_component("pkg:golang/sirupsen/logrus@1.9.3");
        // Override with the realistic shape — multi-segment namespace.
        c.purl = Purl::new("pkg:golang/sirupsen/logrus@1.9.3").unwrap();
        c.name = "logrus".to_string();
        c.version = "1.9.3".to_string();
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.cd_type, "go");
        assert_eq!(coord.provider, "golang");
        assert_eq!(coord.revision, "v1.9.3");
    }

    #[test]
    fn cd_coord_for_golang_keeps_existing_v_prefix() {
        // Many Go modules come with `v` already in the version.
        let c = make_component("pkg:golang/sirupsen/logrus@v1.9.3");
        let coord = cd_coord_for(&c).unwrap();
        assert_eq!(coord.revision, "v1.9.3");
    }

    #[test]
    fn cd_coord_for_unsupported_ecosystem_returns_none() {
        for purl in [
            "pkg:deb/ubuntu/curl@7.88.1",
            "pkg:apk/alpine/musl@1.2.4-r2",
            "pkg:rpm/fedora/bash@5.2.15-1.fc40",
            "pkg:generic/cpython@3.11",
            "pkg:alpm/arch/bash@5.2.015-1",
        ] {
            let c = make_component(purl);
            assert!(
                cd_coord_for(&c).is_none(),
                "{} should not have a CD coord",
                purl
            );
        }
    }

    #[test]
    fn cd_coord_for_empty_name_or_version_returns_none() {
        let mut c = make_component("pkg:npm/foo@1.0.0");
        c.name = String::new();
        assert!(cd_coord_for(&c).is_none());

        let mut c = make_component("pkg:npm/foo@1.0.0");
        c.version = String::new();
        assert!(cd_coord_for(&c).is_none());
    }

    #[test]
    fn cd_coord_for_maven_without_group_returns_none() {
        // Synthesize a maven PURL without a namespace — invalid in
        // practice but the mapper must guard against it.
        let mut c = make_component("pkg:maven/org.apache.commons/commons-lang3@3.14.0");
        // Force the underlying purl to a namespaceless one.
        c.purl = Purl::new("pkg:maven/lone-artifact@1.0").unwrap();
        c.name = "lone-artifact".to_string();
        assert!(cd_coord_for(&c).is_none());
    }
}
