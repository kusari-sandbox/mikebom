use serde_json::json;

use mikebom_common::resolution::ResolvedComponent;

/// Build the CycloneDX `vulnerabilities` section from component advisories.
///
/// Currently returns an empty array. Will be populated when VEX enrichment
/// is wired up in a future phase.
pub fn build_vulnerabilities(_components: &[ResolvedComponent]) -> serde_json::Value {
    // TODO: Map AdvisoryRef entries from components into CycloneDX
    // vulnerability format with analysis/response fields.
    json!([])
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_empty_array() {
        let result = build_vulnerabilities(&[]);
        assert!(result.as_array().expect("array").is_empty());
    }
}
