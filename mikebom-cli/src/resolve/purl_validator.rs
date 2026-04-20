//! Validate PURLs beyond basic parsing — ecosystem-specific rules.
//!
//! While `Purl::new()` validates syntax, certain ecosystems have additional
//! requirements for a PURL to be useful in an SBOM context. This module
//! checks those ecosystem-specific constraints and returns warnings.

use mikebom_common::types::purl::Purl;

/// A warning about a PURL that may indicate an incomplete or incorrect resolution.
#[derive(Clone, Debug, PartialEq)]
pub struct PurlWarning {
    pub field: String,
    pub message: String,
    pub severity: WarningSeverity,
}

/// Severity level for PURL validation warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WarningSeverity {
    /// The PURL is invalid or unusable for SBOM purposes.
    Error,
    /// The PURL is valid but missing recommended information.
    Warning,
}

/// Validate a PURL against ecosystem-specific rules.
///
/// Returns a list of warnings. An empty list means the PURL passes all checks.
pub fn validate_purl(purl: &Purl) -> Vec<PurlWarning> {
    let mut warnings = Vec::new();

    // Universal check: version should be present for SBOM use.
    if purl.version().is_none() {
        warnings.push(PurlWarning {
            field: "version".to_string(),
            message: "PURL is missing a version; SBOMs require versioned components".to_string(),
            severity: WarningSeverity::Warning,
        });
    }

    // Ecosystem-specific checks.
    match purl.ecosystem() {
        "maven" => validate_maven(purl, &mut warnings),
        "deb" => validate_deb(purl, &mut warnings),
        _ => {}
    }

    warnings
}

fn validate_maven(purl: &Purl, warnings: &mut Vec<PurlWarning>) {
    if purl.namespace().is_none() {
        warnings.push(PurlWarning {
            field: "namespace".to_string(),
            message: "Maven PURLs must include a namespace (groupId)".to_string(),
            severity: WarningSeverity::Error,
        });
    }
}

fn validate_deb(purl: &Purl, warnings: &mut Vec<PurlWarning>) {
    // Check the canonical string for qualifier presence.
    let canonical = purl.as_str();

    if !canonical.contains("distro=") {
        warnings.push(PurlWarning {
            field: "qualifiers.distro".to_string(),
            message: "Debian PURLs should include a 'distro' qualifier (e.g., distro=bookworm)".to_string(),
            severity: WarningSeverity::Warning,
        });
    }

    if !canonical.contains("arch=") {
        warnings.push(PurlWarning {
            field: "qualifiers.arch".to_string(),
            message: "Debian PURLs should include an 'arch' qualifier (e.g., arch=amd64)".to_string(),
            severity: WarningSeverity::Warning,
        });
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn valid_cargo_purl_no_warnings() {
        let purl = Purl::new("pkg:cargo/serde@1.0.197").expect("valid");
        let warnings = validate_purl(&purl);
        assert!(warnings.is_empty(), "expected no warnings, got: {warnings:?}");
    }

    #[test]
    fn missing_version_warns() {
        let purl = Purl::new("pkg:cargo/serde").expect("valid without version");
        let warnings = validate_purl(&purl);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].field, "version");
        assert_eq!(warnings[0].severity, WarningSeverity::Warning);
    }

    #[test]
    fn maven_without_namespace_errors() {
        // This is an unusual PURL but syntactically valid.
        let purl = Purl::new("pkg:maven/commons-lang3@3.12.0").expect("valid");
        let warnings = validate_purl(&purl);
        let ns_warning = warnings.iter().find(|w| w.field == "namespace");
        assert!(ns_warning.is_some(), "expected namespace error for Maven PURL");
        assert_eq!(ns_warning.unwrap().severity, WarningSeverity::Error);
    }

    #[test]
    fn maven_with_namespace_ok() {
        let purl =
            Purl::new("pkg:maven/org.apache.commons/commons-lang3@3.12.0").expect("valid");
        let warnings = validate_purl(&purl);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
    }

    #[test]
    fn deb_without_qualifiers_warns() {
        let purl = Purl::new("pkg:deb/debian/curl@8.5.0-2").expect("valid");
        let warnings = validate_purl(&purl);
        assert!(warnings.len() >= 2, "expected at least 2 warnings: {warnings:?}");

        let has_distro = warnings.iter().any(|w| w.field == "qualifiers.distro");
        let has_arch = warnings.iter().any(|w| w.field == "qualifiers.arch");
        assert!(has_distro, "expected distro warning");
        assert!(has_arch, "expected arch warning");
    }

    #[test]
    fn deb_with_qualifiers_ok() {
        // Per the PURL deb spec `distro` is the codename alone.
        let purl =
            Purl::new("pkg:deb/debian/curl@8.5.0-2?arch=amd64&distro=bookworm")
                .expect("valid");
        let warnings = validate_purl(&purl);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
    }

    #[test]
    fn npm_purl_only_needs_version() {
        let purl = Purl::new("pkg:npm/lodash@4.17.21").expect("valid");
        let warnings = validate_purl(&purl);
        assert!(warnings.is_empty());
    }
}
