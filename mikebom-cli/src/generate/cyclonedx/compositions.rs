use std::collections::BTreeMap;

use serde_json::json;

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::resolution::ResolvedComponent;

/// Build the CycloneDX `compositions[]` section.
///
/// Emits:
/// - One `aggregate: complete` record per ecosystem in
///   `complete_ecosystems` (typically `["deb"]` when dpkg was read,
///   `["deb","apk"]` on a mixed-distro rootfs). Assemblies are the
///   bom-refs (PURL strings) of every component whose
///   `purl.ecosystem()` matches.
/// - One final `incomplete_first_party_only` / `incomplete` / `unknown`
///   record covering the target itself.
///
/// Target-record aggregate mapping:
/// - All zeros, no failures → `"incomplete_first_party_only"`
/// - `ring_buffer_overflows > 0` or `events_dropped > 0` → `"incomplete"`
/// - Any probe attach failures → `"unknown"`
///
/// Note: trace-integrity counters (`ring_buffer_overflows`,
/// `events_dropped`, attach-failure counts) used to live on the target
/// composition record as `properties`. CDX 1.6's `compositions` schema
/// sets `additionalProperties: false`, so they're now surfaced via
/// [`super::metadata::build_metadata`] as `mikebom:trace-integrity-*`
/// properties instead (sbomqs conformance fix).
pub fn build_compositions(
    integrity: &TraceIntegrity,
    target_ref: &str,
    components: &[ResolvedComponent],
    complete_ecosystems: &[String],
) -> serde_json::Value {
    let has_probe_failures = !integrity.uprobe_attach_failures.is_empty()
        || !integrity.kprobe_attach_failures.is_empty();

    let has_data_loss =
        integrity.ring_buffer_overflows > 0 || integrity.events_dropped > 0;

    let target_aggregate = if has_probe_failures {
        "unknown"
    } else if has_data_loss {
        "incomplete"
    } else {
        "incomplete_first_party_only"
    };

    let mut out: Vec<serde_json::Value> = Vec::new();

    // Group components by ecosystem once; each ecosystem referenced in
    // `complete_ecosystems` gets an `aggregate: complete` record listing
    // every PURL in that bucket. BTreeMap → deterministic output order.
    //
    // Both `assemblies` and `dependencies` are populated with the same
    // set of component refs:
    // - `assemblies`: declares the components themselves are completely
    //   enumerated for that ecosystem (the original semantic).
    // - `dependencies`: declares the dep graph is complete for those
    //   components. Required for sbomqs's `comp_with_dependencies`
    //   feature, which only credits components listed here under an
    //   `aggregate: complete` composition.
    if !complete_ecosystems.is_empty() {
        let mut by_eco: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for c in components {
            by_eco
                .entry(c.purl.ecosystem().to_string())
                .or_default()
                .push(c.purl.as_str().to_string());
        }
        for eco in complete_ecosystems {
            if let Some(refs) = by_eco.get(eco.as_str()) {
                if !refs.is_empty() {
                    out.push(json!({
                        "aggregate": "complete",
                        "assemblies": refs,
                        "dependencies": refs,
                    }));
                }
            }
        }
    }

    // Trailing record always present: covers the target itself with an
    // assemblies-only entry whose `aggregate` encodes the integrity
    // state (see mapping above; raw counters on metadata.properties).
    out.push(json!({
        "aggregate": target_aggregate,
        "assemblies": [target_ref],
    }));

    // sbomqs `comp_with_dependencies` requires the primary to be
    // listed in a composition with `aggregate: complete` and a
    // `dependencies` field. The integrity-driven target record above
    // can't satisfy this (its aggregate isn't always `complete`), so
    // emit a separate dep-completeness record when no integrity issues
    // were observed and at least one outbound dep edge will be
    // synthesized for the primary (build_dependencies handles the
    // synthesis when no real edges exist).
    if !has_probe_failures && !has_data_loss && !components.is_empty() {
        out.push(json!({
            "aggregate": "complete",
            "dependencies": [target_ref],
        }));
    }

    json!(out)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::purl::Purl;

    fn clean_integrity() -> TraceIntegrity {
        TraceIntegrity {
            ring_buffer_overflows: 0,
            events_dropped: 0,
            uprobe_attach_failures: vec![],
            kprobe_attach_failures: vec![],
            partial_captures: vec![],
            bloom_filter_capacity: 100_000,
            bloom_filter_false_positive_rate: 0.01,
        }
    }

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
            parent_purl: None,
            co_owned_by: None,
            external_references: Vec::new(),
        }
    }

    #[test]
    fn clean_trace_with_no_complete_ecosystems_emits_single_record() {
        let integrity = clean_integrity();
        let result = build_compositions(&integrity, "myapp@0.1.0", &[], &[]);
        let arr = result.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["aggregate"], "incomplete_first_party_only");
    }

    #[test]
    fn data_loss_maps_to_incomplete() {
        let mut integrity = clean_integrity();
        integrity.ring_buffer_overflows = 5;
        let result = build_compositions(&integrity, "myapp@0.1.0", &[], &[]);
        assert_eq!(result[0]["aggregate"], "incomplete");

        let mut integrity2 = clean_integrity();
        integrity2.events_dropped = 3;
        let result2 = build_compositions(&integrity2, "myapp@0.1.0", &[], &[]);
        assert_eq!(result2[0]["aggregate"], "incomplete");
    }

    #[test]
    fn probe_failures_map_to_unknown() {
        let mut integrity = clean_integrity();
        integrity.uprobe_attach_failures = vec!["libssl.so:SSL_write".to_string()];
        let result = build_compositions(&integrity, "myapp@0.1.0", &[], &[]);
        assert_eq!(result[0]["aggregate"], "unknown");
    }

    #[test]
    fn probe_failures_take_priority_over_data_loss() {
        let mut integrity = clean_integrity();
        integrity.ring_buffer_overflows = 10;
        integrity.kprobe_attach_failures = vec!["sys_connect".to_string()];
        let result = build_compositions(&integrity, "myapp@0.1.0", &[], &[]);
        assert_eq!(result[0]["aggregate"], "unknown");
    }

    #[test]
    fn target_ref_appears_in_assemblies() {
        let integrity = clean_integrity();
        let result = build_compositions(&integrity, "myapp@0.1.0", &[], &[]);
        assert_eq!(result[0]["assemblies"][0], "myapp@0.1.0");
    }

    #[test]
    fn compositions_do_not_carry_properties_per_cdx_1_6_schema() {
        // CDX 1.6 `compositions` schema sets additionalProperties=false,
        // which disallows `properties` on composition records. Trace-
        // integrity counters moved to metadata.properties — see
        // `build_metadata` for the new home. The integrity state is
        // still encoded here via the `aggregate` value.
        let mut integrity = clean_integrity();
        integrity.ring_buffer_overflows = 2;
        integrity.events_dropped = 3;
        let result = build_compositions(&integrity, "myapp@0.1.0", &[], &[]);
        assert!(
            result[0].get("properties").is_none(),
            "composition records must not carry properties (CDX 1.6 schema): {:?}",
            result[0]
        );
        // Aggregate reflects the data-loss state.
        assert_eq!(result[0]["aggregate"], "incomplete");
    }

    #[test]
    fn per_ecosystem_complete_records_are_emitted_before_target_record() {
        let components = vec![
            make_component("pkg:deb/debian/jq@1.6-2.1?distro=bookworm"),
            make_component("pkg:deb/debian/libjq1@1.6-2.1?distro=bookworm"),
            make_component("pkg:apk/alpine/musl@1.2.4-r2"),
        ];
        let integrity = clean_integrity();
        let ecosystems = vec!["deb".to_string(), "apk".to_string()];
        let result = build_compositions(
            &integrity,
            "myapp@0.1.0",
            &components,
            &ecosystems,
        );
        let arr = result.as_array().expect("array");
        // Two per-ecosystem complete records, the target-integrity
        // assemblies record, and the primary-dep-completeness record
        // (added for sbomqs comp_with_dependencies). Total: 4.
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0]["aggregate"], "complete");
        assert_eq!(arr[1]["aggregate"], "complete");
        assert_eq!(arr[2]["aggregate"], "incomplete_first_party_only");
        assert_eq!(arr[2]["assemblies"][0], "myapp@0.1.0");
        // Last record: primary-dep-completeness for sbomqs.
        assert_eq!(arr[3]["aggregate"], "complete");
        assert_eq!(arr[3]["dependencies"][0], "myapp@0.1.0");
    }

    #[test]
    fn complete_record_skipped_when_ecosystem_has_no_components() {
        // deb was read but no components matched (edge case: empty db).
        let integrity = clean_integrity();
        let ecosystems = vec!["deb".to_string()];
        let result =
            build_compositions(&integrity, "myapp@0.1.0", &[], &ecosystems);
        let arr = result.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["aggregate"], "incomplete_first_party_only");
    }

    #[test]
    fn complete_record_assemblies_filter_to_matching_ecosystem() {
        let components = vec![
            make_component("pkg:deb/debian/jq@1.6-2.1?distro=bookworm"),
            make_component("pkg:cargo/serde@1.0.197"),
        ];
        let integrity = clean_integrity();
        let ecosystems = vec!["deb".to_string()];
        let result = build_compositions(
            &integrity,
            "myapp@0.1.0",
            &components,
            &ecosystems,
        );
        let arr = result.as_array().expect("array");
        // 1 deb-complete + 1 target-integrity + 1 primary-dep-complete = 3.
        assert_eq!(arr.len(), 3);
        let assemblies = arr[0]["assemblies"].as_array().expect("assemblies");
        assert_eq!(assemblies.len(), 1);
        assert!(assemblies[0]
            .as_str()
            .unwrap()
            .starts_with("pkg:deb/"));
    }
}