//! Merge duplicate component resolutions, keeping the highest confidence.
//!
//! When multiple resolution techniques identify the same package (e.g., URL
//! pattern matching and hash-based lookup both find `serde@1.0.197`), we
//! merge them into a single `ResolvedComponent` with the highest confidence
//! score and combined evidence from all sources.

use std::collections::HashMap;

use mikebom_common::resolution::ResolvedComponent;

/// Deduplicate resolved components by
/// `(ecosystem, name, version, parent_purl)`.
///
/// For each group of duplicates:
/// - Keep the entry with the highest confidence score.
/// - Merge `source_connection_ids` and `source_file_paths` from all entries.
/// - Merge hashes, retaining unique values.
///
/// **`parent_purl` in the dedup key**: a coord vendored inside two
/// different shade-jars should surface as two distinct nested children
/// in the final CDX (one under each parent), not collapse to one
/// component. The `parent_purl` field — set by the Maven scanner when a
/// coord comes from a fat-jar's `META-INF/maven/<g>/<a>/` and is NOT
/// the JAR's primary coord — goes into the group key to preserve that
/// distinction. Top-level components (parent_purl = None) continue to
/// merge across their resolution sources as before.
pub fn deduplicate(components: Vec<ResolvedComponent>) -> Vec<ResolvedComponent> {
    if components.is_empty() {
        return Vec::new();
    }

    // Group by (ecosystem, name, version, parent_purl).
    let mut groups: HashMap<
        (String, String, String, Option<String>),
        Vec<ResolvedComponent>,
    > = HashMap::new();

    for component in components {
        let key = (
            component.purl.ecosystem().to_string(),
            component.name.clone(),
            component.version.clone(),
            component.parent_purl.clone(),
        );
        groups.entry(key).or_default().push(component);
    }

    let mut result = Vec::with_capacity(groups.len());

    for (_key, mut group) in groups {
        if group.len() == 1 {
            result.push(group.remove(0));
            continue;
        }

        // Sort by confidence descending; the first entry is our "winner".
        group.sort_by(|a, b| {
            b.evidence
                .confidence
                .partial_cmp(&a.evidence.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut best = group.remove(0);

        // Merge evidence from remaining entries.
        for other in group {
            for conn_id in other.evidence.source_connection_ids {
                if !best.evidence.source_connection_ids.contains(&conn_id) {
                    best.evidence.source_connection_ids.push(conn_id);
                }
            }
            for file_path in other.evidence.source_file_paths {
                if !best.evidence.source_file_paths.contains(&file_path) {
                    best.evidence.source_file_paths.push(file_path);
                }
            }
            for hash in other.hashes {
                if !best.hashes.contains(&hash) {
                    best.hashes.push(hash);
                }
            }
            // If the best doesn't have a deps_dev_match but another does, take it.
            if best.evidence.deps_dev_match.is_none() && other.evidence.deps_dev_match.is_some() {
                best.evidence.deps_dev_match = other.evidence.deps_dev_match;
            }
            // Dev-flag merge rule per research.md R8: `Some(false)` (prod)
            // wins over `Some(true)` (dev-only). `None` (source without
            // dev/prod info) merges with either without overriding.
            best.is_dev = match (best.is_dev, other.is_dev) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), _) | (_, Some(true)) => Some(true),
                _ => None,
            };
            // Prefer an existing requirement_range / source_type /
            // sbom_tier; only adopt from `other` when best's is None.
            if best.requirement_range.is_none() {
                best.requirement_range = other.requirement_range;
            }
            // Capture `other.source_type` once — it drives both
            // the "adopt when None" rule and the "is other a
            // secondary?" check used for tier-promotion below.
            let other_source_type = other.source_type.clone();
            let other_is_secondary = is_secondary_source_type(other_source_type.as_deref());
            // Don't overwrite `best.source_type = None` with a
            // secondary tag from `other`. A JAR-walker-sourced entry
            // with `source_type = None` is the authoritative on-disk
            // identity; the BFS-sourced entry with
            // `source_type = "transitive"` (or deps.dev's
            // `"declared-not-cached"`) is a weaker witness. Without
            // this guard, pass-1 would collapse the two same-coord
            // entries and the surviving one would carry the weaker
            // tag, masking the strong source — which breaks pass-2's
            // ability to identify it as on-disk (M2).
            if best.source_type.is_none() && !other_is_secondary {
                best.source_type = other_source_type.clone();
            }
            // Same rule for sbom_tier: don't overwrite None with
            // `"source"` when the other side is a secondary. The
            // JAR walker emits `sbom_tier = None` and gets promoted
            // to `"deployed"` below when the secondary's evidence
            // is folded in (M2).
            if best.sbom_tier.is_none() && !other_is_secondary {
                best.sbom_tier = other.sbom_tier.clone();
            }
            // M2 tier promotion + evidence tagging: when the
            // collapsing `other` is a secondary (transitive /
            // declared-not-cached) and `best` carries SHA-256 file
            // evidence (JAR-walker / dpkg / rpm), promote
            // `best.sbom_tier` from None to `"deployed"` and tag
            // the evidence trail with a provenance marker. This
            // catches the same-parent_purl case where pass-1 is
            // the only collapse that fires — pass-2 can't run on
            // entries that pass-1 already merged.
            if other_is_secondary && has_on_disk_file_evidence(&best) {
                if matches!(best.sbom_tier.as_deref(), None | Some("analyzed")) {
                    best.sbom_tier = Some("deployed".to_string());
                }
                let marker = match other_source_type.as_deref() {
                    Some("declared-not-cached") => Some("deps.dev"),
                    Some("transitive") => Some("maven-cache-bfs"),
                    _ => None,
                };
                if let Some(marker) = marker {
                    if !best
                        .evidence
                        .source_file_paths
                        .iter()
                        .any(|p| p == marker)
                    {
                        best.evidence.source_file_paths.push(marker.to_string());
                    }
                }
            }
            // Go-specific rule (milestone 003 US1 T024): when the same
            // pkg:golang/...@... PURL appears once as `source` (go.sum)
            // and once as `analyzed` (binary BuildInfo), prefer
            // `source` — the lockfile hash is authoritative, the
            // binary's embedded module list is derived. The dedup
            // winner is already picked by confidence, but for Go we
            // override the tier choice after the fact.
            if best.purl.ecosystem() == "golang" {
                let other_is_source = matches!(other.sbom_tier.as_deref(), Some("source"));
                let best_is_analyzed = matches!(best.sbom_tier.as_deref(), Some("analyzed"));
                if best_is_analyzed && other_is_source {
                    best.sbom_tier = Some("source".to_string());
                }
            }
        }

        result.push(best);
    }

    // Second pass: cross-source dedup between on-disk components and
    // deps.dev-emitted `declared-not-cached` entries for the same
    // canonical `(ecosystem, group, artifact, version)` coord.
    //
    // The first-pass 4-tuple key includes `parent_purl` so shade-jar
    // vendored coords stay distinct from their top-level twins — see
    // the `parent_purl in dedup key` doc above. But when deps.dev
    // reports a coord that's also on disk inside a shade-jar, the
    // on-disk entry has `parent_purl = Some(...)` while the deps.dev
    // entry has `parent_purl = None`, and pass 1 leaves both. Empirical
    // result: aopalliance-style coords double-emit.
    //
    // Pass 2 folds each declared-not-cached entry into every
    // matching on-disk entry (merging deps.dev evidence) and drops
    // the declared-not-cached entry. Declared-not-cached entries
    // without any on-disk twin are preserved — manifest-SBOM users on
    // `--path` scans expect them.
    fold_declared_not_cached(&mut result);

    // Sort the output deterministically by PURL string.
    result.sort_by(|a, b| a.purl.as_str().cmp(b.purl.as_str()));

    result
}

/// Canonical coord key for Fix A's cross-source fold. Maven coords
/// use the PURL namespace as the group; other ecosystems' namespaces
/// are (by convention) empty and produce `""` here. Name + version
/// come from the struct fields (not PURL parsing) so any subtle PURL
/// string normalization differences don't affect the lookup.
fn canonical_coord_key(c: &ResolvedComponent) -> (String, String, String, String) {
    (
        c.purl.ecosystem().to_string(),
        c.purl.namespace().unwrap_or("").to_string(),
        c.name.clone(),
        c.version.clone(),
    )
}

/// Return true if this source_type marks a "secondary" emission —
/// a coord that mikebom knows about by declaration or transitive
/// resolution but that an authoritative file-walk (JAR walker,
/// dpkg, rpm, apk, npm node_modules, etc.) may ALSO have found.
/// Secondary entries are candidates for folding into on-disk
/// entries with the same `(ecosystem, group, artifact, version)`.
fn is_secondary_source_type(source_type: Option<&str>) -> bool {
    matches!(source_type, Some("declared-not-cached") | Some("transitive"))
}

/// Return true if this component has JAR-walker-style file evidence:
/// a SHA-256 hash attached (computed by `walk_jar_maven_meta` /
/// dpkg file-hash walker / rpm header parser). Used to decide
/// whether a fold-target is authoritative enough to promote a
/// secondary's `sbom_tier` from `source` to `deployed` on merge.
fn has_on_disk_file_evidence(component: &ResolvedComponent) -> bool {
    use mikebom_common::types::hash::HashAlgorithm;
    component
        .hashes
        .iter()
        .any(|h| matches!(h.algorithm, HashAlgorithm::Sha256))
}

/// Fold "secondary" entries (deps.dev declared-not-cached or
/// BFS-resolved transitive) into matching on-disk entries when the
/// canonical `(ecosystem, group, artifact, version)` coord is
/// already represented. Merges evidence + depends, promotes sbom-
/// tier when the on-disk twin carries JAR-walker file evidence,
/// then removes the secondary entry.
///
/// Secondary entries with no on-disk twin stay in place — manifest-
/// SBOM convention for `--path` scans expects declared/transitive
/// coords to remain visible when they're the only evidence.
///
/// **Shape of the fix (M2):** pass-1 dedup keys on
/// `(ecosystem, name, version, parent_purl)` so shade-jar siblings
/// stay distinct. But a top-level JAR-walker emission and a
/// BFS-sourced transitive for the same coord both have
/// `parent_purl = None` yet emerge from `read_with_claims` with
/// different dedup keys (bare PURL vs composite `<purl>#`). Both
/// entries survive pass-1. This pass-2 catches them by canonical
/// coord and promotes the JAR-walker entry (better evidence,
/// `tier = "deployed"`) while preserving the BFS entry's `depends`
/// graph.
fn fold_declared_not_cached(components: &mut Vec<ResolvedComponent>) {
    // Build a canonical-coord index of every "authoritative" entry
    // (not a secondary source type). Value: indices into
    // `components` (plural — shade-jar siblings with different
    // parent_purls legitimately share a key).
    let mut on_disk: HashMap<(String, String, String, String), Vec<usize>> = HashMap::new();
    for (i, c) in components.iter().enumerate() {
        if is_secondary_source_type(c.source_type.as_deref()) {
            continue;
        }
        // Feature 009: shade-relocation entries aren't on-disk twins
        // of a transitive coord — they're nested components at a
        // different semantic level. If a BFS-emitted transitive with
        // parent_purl=None is folded INTO a shade-relocation child
        // (parent_purl=Some) and removed, the shade child loses its
        // ability to nest (its parent PURL vanishes from
        // top_level_purls). Exclude shade-relocation entries from
        // the on-disk set so pass 2's fold skips them.
        if c.shade_relocation == Some(true) {
            continue;
        }
        on_disk.entry(canonical_coord_key(c)).or_default().push(i);
    }

    // Iterate secondary entries in REVERSE so we can `remove(i)`
    // without shifting indices we haven't visited yet. Collect the
    // indices first (the components vec borrow has to be released
    // before we can mutate it).
    let secondary_indices: Vec<usize> = components
        .iter()
        .enumerate()
        .filter(|(_, c)| is_secondary_source_type(c.source_type.as_deref()))
        .map(|(i, _)| i)
        .collect();

    // First pass: fold all secondary→on-disk merges into the `dst`
    // entries WITHOUT removing the secondaries. Record which
    // secondaries to remove afterward. Avoids the index-shift bug
    // where removing secondary at idx K invalidates any on-disk
    // index that was originally > K.
    let mut to_remove: Vec<usize> = Vec::new();
    for &sec_idx in secondary_indices.iter() {
        let key = canonical_coord_key(&components[sec_idx]);
        let Some(on_disk_indices) = on_disk.get(&key).cloned() else {
            // No on-disk twin. Keep the secondary entry —
            // manifest-SBOM convention. Continue.
            continue;
        };
        // Clone the secondary entry's evidence before we drop it,
        // then fold into every on-disk match.
        let sec = components[sec_idx].clone();
        to_remove.push(sec_idx);
        for dst_idx in on_disk_indices {
            let dst = &mut components[dst_idx];
            // Evidence-trail marker: declared-not-cached → "deps.dev",
            // transitive → "maven-cache-bfs". Avoids adding the same
            // marker twice.
            let marker = match sec.source_type.as_deref() {
                Some("declared-not-cached") => "deps.dev",
                Some("transitive") => "maven-cache-bfs",
                _ => continue,
            };
            let already_marked = dst
                .evidence
                .source_file_paths
                .iter()
                .any(|p| p == marker);
            if !already_marked {
                dst.evidence.source_file_paths.push(marker.to_string());
            }
            // Merge `source_connection_ids` (union, no duplicates).
            for conn_id in &sec.evidence.source_connection_ids {
                if !dst.evidence.source_connection_ids.contains(conn_id) {
                    dst.evidence.source_connection_ids.push(conn_id.clone());
                }
            }
            // If the on-disk entry doesn't have a `deps_dev_match` but
            // the secondary one does, carry it forward.
            if dst.evidence.deps_dev_match.is_none() && sec.evidence.deps_dev_match.is_some() {
                dst.evidence.deps_dev_match = sec.evidence.deps_dev_match.clone();
            }
            // Note: the dep graph lives in the separate
            // `Relationship` stream (scan_fs::mod.rs → CDX
            // `dependencies[]`), not on `ResolvedComponent`. BFS-
            // sourced edges survive independently of this component
            // fold — when the BFS-sourced entry's relationships
            // pointed at it by PURL, those edges stay walkable even
            // after the entry itself is dropped here (the pipeline
            // guard rail accepts dangling `to` targets when the
            // `from` side exists).
            //
            // M2: tier promotion. When the on-disk entry carries
            // file evidence (SHA-256 from JAR walker / dpkg / rpm),
            // promote the merged tier from `source` (BFS-inferred)
            // to `deployed` (JAR present on disk). Only applies when
            // the on-disk entry's existing tier is None or explicitly
            // `analyzed` — don't downgrade stronger tiers.
            let existing_tier = dst.sbom_tier.as_deref();
            if has_on_disk_file_evidence(dst)
                && matches!(existing_tier, None | Some("analyzed"))
            {
                dst.sbom_tier = Some("deployed".to_string());
            }
        }
    }
    // Second pass: remove the secondaries. Dedup + sort-descending
    // so removing from the back doesn't shift indices we still
    // need.
    to_remove.sort_unstable();
    to_remove.dedup();
    for sec_idx in to_remove.iter().rev() {
        components.remove(*sec_idx);
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::hash::ContentHash;
    use mikebom_common::types::purl::Purl;

    fn make_component(
        purl_str: &str,
        technique: ResolutionTechnique,
        confidence: f64,
        conn_ids: Vec<&str>,
        file_paths: Vec<&str>,
    ) -> ResolvedComponent {
        let purl = Purl::new(purl_str).expect("valid purl");
        ResolvedComponent {
            name: purl.name().to_string(),
            version: purl.version().unwrap_or("0.0.0").to_string(),
            purl,
            evidence: ResolutionEvidence {
                technique,
                confidence,
                source_connection_ids: conn_ids.into_iter().map(String::from).collect(),
                source_file_paths: file_paths.into_iter().map(String::from).collect(),
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
            extra_annotations: Default::default(),
        }
    }

    #[test]
    fn no_duplicates_unchanged() {
        let components = vec![
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-1"],
                vec![],
            ),
            make_component(
                "pkg:cargo/tokio@1.38.0",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-2"],
                vec![],
            ),
        ];

        let deduped = deduplicate(components);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn duplicates_merged_highest_confidence_wins() {
        let components = vec![
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-1"],
                vec![],
            ),
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::HashMatch,
                0.90,
                vec!["conn-2"],
                vec!["/path/to/serde"],
            ),
        ];

        let deduped = deduplicate(components);
        assert_eq!(deduped.len(), 1);

        let merged = &deduped[0];
        assert_eq!(merged.evidence.confidence, 0.95);
        assert_eq!(merged.evidence.technique, ResolutionTechnique::UrlPattern);
        // Evidence from both sources should be merged.
        assert!(merged.evidence.source_connection_ids.contains(&"conn-1".to_string()));
        assert!(merged.evidence.source_connection_ids.contains(&"conn-2".to_string()));
        assert!(merged.evidence.source_file_paths.contains(&"/path/to/serde".to_string()));
    }

    #[test]
    fn hashes_merged_across_duplicates() {
        let hash1 = ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .expect("valid");
        let hash2 = ContentHash::sha256(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )
        .expect("valid");

        let mut c1 = make_component(
            "pkg:cargo/serde@1.0.197",
            ResolutionTechnique::UrlPattern,
            0.95,
            vec![],
            vec![],
        );
        c1.hashes.push(hash1.clone());

        let mut c2 = make_component(
            "pkg:cargo/serde@1.0.197",
            ResolutionTechnique::HashMatch,
            0.90,
            vec![],
            vec![],
        );
        c2.hashes.push(hash2.clone());

        let deduped = deduplicate(vec![c1, c2]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].hashes.len(), 2);
    }

    #[test]
    fn empty_input_returns_empty() {
        let deduped = deduplicate(vec![]);
        assert!(deduped.is_empty());
    }

    #[test]
    fn is_dev_merge_prod_wins_over_dev() {
        // Same package appears as prod in one source and dev in another.
        // Prod should win per research.md R8 — a package pulled in by
        // any prod dep chain is not really "dev-only".
        let mut prod = make_component(
            "pkg:npm/foo@1.0.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/path/prod-lockfile"],
        );
        prod.is_dev = Some(false);
        let mut dev = make_component(
            "pkg:npm/foo@1.0.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/path/dev-lockfile"],
        );
        dev.is_dev = Some(true);

        let deduped = deduplicate(vec![prod, dev]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].is_dev, Some(false));
    }

    #[test]
    fn is_dev_merge_none_preserves_explicit_flag() {
        // One side has None (source carries no dev/prod), other has
        // Some(true). The flag propagates through the merge.
        let explicit_dev = {
            let mut c = make_component(
                "pkg:npm/bar@2.0.0",
                ResolutionTechnique::PackageDatabase,
                0.85,
                vec![],
                vec![],
            );
            c.is_dev = Some(true);
            c
        };
        let no_flag = make_component(
            "pkg:npm/bar@2.0.0",
            ResolutionTechnique::FilePathPattern,
            0.70,
            vec![],
            vec![],
        ); // is_dev = None by default

        let deduped = deduplicate(vec![explicit_dev, no_flag]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].is_dev, Some(true));
    }

    #[test]
    fn sbom_tier_propagates_when_winner_is_none() {
        let mut lockfile = make_component(
            "pkg:pypi/requests@2.31.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/poetry.lock"],
        );
        lockfile.sbom_tier = Some("source".to_string());
        let venv = make_component(
            "pkg:pypi/requests@2.31.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/venv/.../requests-2.31.0.dist-info/METADATA"],
        ); // sbom_tier = None

        let deduped = deduplicate(vec![lockfile, venv]);
        assert_eq!(deduped.len(), 1);
        // Winner's tier takes precedence; since winners sort-by-confidence
        // is equal here, order-first wins — but either way, the merge
        // preserves the non-None value when the winner is None.
        assert!(deduped[0].sbom_tier.is_some());
    }

    #[test]
    fn different_versions_not_merged() {
        let components = vec![
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-1"],
                vec![],
            ),
            make_component(
                "pkg:cargo/serde@1.0.198",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-2"],
                vec![],
            ),
        ];

        let deduped = deduplicate(components);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn golang_source_wins_over_analyzed_on_dedup() {
        // Same pkg:golang/...@... PURL, one from go.sum (source tier)
        // and one from binary BuildInfo (analyzed tier). The source
        // tier must carry forward; evidence.source_file_paths from
        // both must merge.
        let mut go_source = make_component(
            "pkg:golang/github.com/spf13/cobra@v1.7.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/go.sum"],
        );
        go_source.sbom_tier = Some("source".to_string());
        let mut go_analyzed = make_component(
            "pkg:golang/github.com/spf13/cobra@v1.7.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/hello-bin"],
        );
        go_analyzed.sbom_tier = Some("analyzed".to_string());

        // Put analyzed FIRST so it naturally wins sort-by-confidence
        // with matching scores — this exercises the override path.
        let deduped = deduplicate(vec![go_analyzed, go_source]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].sbom_tier.as_deref(), Some("source"));
        // Both evidence paths present.
        let paths: std::collections::HashSet<&str> = deduped[0]
            .evidence
            .source_file_paths
            .iter()
            .map(String::as_str)
            .collect();
        assert!(paths.contains("/app/go.sum"));
        assert!(paths.contains("/app/hello-bin"));
    }

    // --- Cross-source fold (Fix A) -------------------------------------

    fn make_declared_not_cached(purl_str: &str) -> ResolvedComponent {
        let mut c = make_component(
            purl_str,
            ResolutionTechnique::UrlPattern,
            0.75,
            vec![],
            vec!["deps.dev"],
        );
        c.source_type = Some("declared-not-cached".to_string());
        c.sbom_tier = Some("source".to_string());
        c
    }

    #[test]
    fn declared_not_cached_folds_into_shade_jar_sibling() {
        // On-disk aopalliance is vendored inside a shade-jar (has
        // parent_purl). deps.dev also reports aopalliance as a
        // top-level declared-not-cached dep. Pre-Fix-A, these would
        // NOT merge (different parent_purl means different pass-1
        // dedup key). Post-Fix-A, pass 2 folds the declared entry
        // into the on-disk sibling and drops it.
        let mut on_disk = make_component(
            "pkg:maven/aopalliance/aopalliance@1.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/spring-boot.jar"],
        );
        on_disk.parent_purl =
            Some("pkg:maven/org.springframework.boot/spring-boot@3.0.0".to_string());
        on_disk.sbom_tier = Some("analyzed".to_string());

        let declared = make_declared_not_cached("pkg:maven/aopalliance/aopalliance@1.0");

        let deduped = deduplicate(vec![on_disk, declared]);
        assert_eq!(
            deduped.len(),
            1,
            "declared-not-cached must fold into on-disk sibling: {deduped:?}",
        );
        let survivor = &deduped[0];
        assert_eq!(survivor.name, "aopalliance");
        assert_eq!(survivor.sbom_tier.as_deref(), Some("analyzed"));
        assert!(
            survivor.parent_purl.is_some(),
            "on-disk sibling must retain parent_purl (shade-jar nesting)",
        );
        // deps.dev provenance marker attached.
        assert!(
            survivor
                .evidence
                .source_file_paths
                .iter()
                .any(|p| p == "deps.dev"),
            "declared-not-cached evidence must fold in: {:?}",
            survivor.evidence.source_file_paths,
        );
    }

    #[test]
    fn declared_not_cached_folds_into_multiple_siblings() {
        // aopalliance vendored in TWO different shade-jars (different
        // parent_purls) + one deps.dev declared-not-cached top-level.
        // After dedup: both siblings preserved (distinct parents),
        // each carries the deps.dev marker.
        let mut sib_a = make_component(
            "pkg:maven/aopalliance/aopalliance@1.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/spring-boot.jar"],
        );
        sib_a.parent_purl = Some("pkg:maven/org.springframework.boot/spring-boot@3.0.0".to_string());
        sib_a.sbom_tier = Some("analyzed".to_string());

        let mut sib_b = make_component(
            "pkg:maven/aopalliance/aopalliance@1.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/other-service.jar"],
        );
        sib_b.parent_purl = Some("pkg:maven/com.example/other-service@1.2.3".to_string());
        sib_b.sbom_tier = Some("analyzed".to_string());

        let declared = make_declared_not_cached("pkg:maven/aopalliance/aopalliance@1.0");

        let deduped = deduplicate(vec![sib_a, sib_b, declared]);
        assert_eq!(
            deduped.len(),
            2,
            "two shade-jar siblings must survive (distinct parent_purls): {deduped:?}",
        );
        for entry in &deduped {
            assert_eq!(entry.name, "aopalliance");
            assert!(
                entry
                    .evidence
                    .source_file_paths
                    .iter()
                    .any(|p| p == "deps.dev"),
                "both siblings must pick up the deps.dev marker: {:?}",
                entry.evidence.source_file_paths,
            );
        }
    }

    #[test]
    fn declared_not_cached_without_on_disk_twin_preserved() {
        // A purely declarative coord (provided-scope, shade-stripped,
        // etc.) with no on-disk match must stay in the output —
        // manifest-SBOM convention for `--path` / `--include-declared-deps`.
        let declared = make_declared_not_cached(
            "pkg:maven/javax.servlet/javax.servlet-api@4.0.1",
        );
        let unrelated = make_component(
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/guava.jar"],
        );

        let deduped = deduplicate(vec![declared, unrelated]);
        assert_eq!(deduped.len(), 2, "declared entry with no twin must survive");
        let has_declared = deduped
            .iter()
            .any(|c| c.source_type.as_deref() == Some("declared-not-cached"));
        assert!(
            has_declared,
            "declared-not-cached without twin must be preserved: {deduped:?}",
        );
    }

    #[test]
    fn declared_not_cached_folds_into_top_level_twin() {
        // Both entries top-level (parent_purl = None), same coord.
        // Pass 1 groups by (ecosystem, name, version, None) so it
        // already collapses this case. Pass 2 shouldn't touch it —
        // nothing remains for pass 2 to match. This test is a
        // regression guard: the pass-1 behavior stays intact.
        let mut on_disk = make_component(
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/guava.jar"],
        );
        on_disk.sbom_tier = Some("analyzed".to_string());

        let declared =
            make_declared_not_cached("pkg:maven/com.google.guava/guava@32.1.3-jre");

        let deduped = deduplicate(vec![on_disk, declared]);
        assert_eq!(
            deduped.len(),
            1,
            "top-level + top-level same coord must collapse to one",
        );
        // Pass 1 picks the higher-confidence on-disk entry.
        assert_eq!(deduped[0].sbom_tier.as_deref(), Some("analyzed"));
    }

    // --- Transitive cross-tier fold (M2) --------------------------------

    fn make_jar_walker_entry(purl_str: &str, sha256_hex: &str) -> ResolvedComponent {
        use mikebom_common::types::hash::ContentHash;
        let mut c = make_component(
            purl_str,
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/myjar.jar"],
        );
        // Simulate JAR walker output: no source_type (None), no
        // sbom_tier (None) — the JAR walker emits bare entries that
        // the merge step is supposed to promote.
        c.source_type = None;
        c.sbom_tier = None;
        c.hashes.push(ContentHash::sha256(sha256_hex).expect("valid hash"));
        c
    }

    fn make_transitive_entry(purl_str: &str) -> ResolvedComponent {
        let mut c = make_component(
            purl_str,
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/rootfs"],
        );
        c.source_type = Some("transitive".to_string());
        c.sbom_tier = Some("source".to_string());
        c
    }

    #[test]
    fn transitive_folds_into_on_disk_twin_and_promotes_tier() {
        // JAR walker emits aopalliance@1.0 (no source_type, SHA-256
        // attached). BFS cache walker ALSO emits aopalliance@1.0
        // (source_type=transitive). The pass-2 fold must:
        //   - drop the transitive entry
        //   - leave one surviving component — the JAR-walker one
        //   - promote its sbom_tier: None → "deployed"
        //   - tag its evidence with "maven-cache-bfs"
        let on_disk = make_jar_walker_entry(
            "pkg:maven/aopalliance/aopalliance@1.0",
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        );
        let transitive = make_transitive_entry("pkg:maven/aopalliance/aopalliance@1.0");

        let deduped = deduplicate(vec![on_disk, transitive]);
        assert_eq!(
            deduped.len(),
            1,
            "transitive must fold into on-disk twin: {deduped:?}",
        );
        let survivor = &deduped[0];
        assert_eq!(
            survivor.sbom_tier.as_deref(),
            Some("deployed"),
            "tier must promote to deployed on JAR-evidence merge",
        );
        assert!(
            survivor
                .evidence
                .source_file_paths
                .iter()
                .any(|p| p == "maven-cache-bfs"),
            "BFS evidence marker must fold in: {:?}",
            survivor.evidence.source_file_paths,
        );
    }

    #[test]
    fn transitive_without_on_disk_twin_preserved() {
        // Pure BFS-sourced transitive with no JAR-walker twin (e.g.,
        // `--path` manifest scan with cached POMs but no JARs). The
        // transitive entry must survive (manifest-SBOM convention
        // parallels the declared-not-cached case).
        let transitive = make_transitive_entry(
            "pkg:maven/com.example/purely-bfs@1.0.0",
        );
        let unrelated = make_component(
            "pkg:maven/com.google.guava/guava@32.1.3-jre",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/guava.jar"],
        );

        let deduped = deduplicate(vec![transitive, unrelated]);
        assert_eq!(deduped.len(), 2, "transitive with no twin must survive");
        let has_transitive = deduped
            .iter()
            .any(|c| c.source_type.as_deref() == Some("transitive"));
        assert!(
            has_transitive,
            "transitive without on-disk twin must be preserved: {deduped:?}",
        );
    }

    // --- G2: cross-source dedup for Go coords ---------------------------

    #[test]
    fn duplicate_go_coords_with_matching_names_dedup_to_one() {
        // G2 regression guard. The user's polyglot-builder-image
        // bake-off surfaced `pkg:golang/github.com/davecgh/go-spew@v1.1.1`
        // emitted TWICE with identical PURL: once from the Go reader
        // (name = `github.com/davecgh/go-spew`, full module path) and
        // once from `scan_fs/mod.rs`'s artifact-file walker (name =
        // `go-spew`, `purl.name()` last segment). The deduplicator's
        // `(ecosystem, name, version, parent_purl)` key put them in
        // different groups. Fix: walker derives name as full module
        // path for Go coords (see `scan_fs/mod.rs` artifact-walker
        // name-derivation).
        //
        // This test directly verifies that when both sources agree
        // on `name = "github.com/davecgh/go-spew"`, dedup collapses
        // them. Test helper `make_component` uses `purl.name()` so
        // we manually override `name` here to exercise the
        // post-walker-fix invariant.
        let mut reader_emitted = make_component(
            "pkg:golang/github.com/davecgh/go-spew@v1.1.1",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/go.sum"],
        );
        reader_emitted.name = "github.com/davecgh/go-spew".to_string();
        let mut walker_emitted = make_component(
            "pkg:golang/github.com/davecgh/go-spew@v1.1.1",
            ResolutionTechnique::FilePathPattern,
            0.70,
            vec![],
            vec!["/root/go/pkg/mod/cache/download/github.com/davecgh/go-spew/@v/v1.1.1.zip"],
        );
        walker_emitted.name = "github.com/davecgh/go-spew".to_string();

        let deduped = deduplicate(vec![reader_emitted, walker_emitted]);
        assert_eq!(
            deduped.len(),
            1,
            "same-PURL Go coords from source + walker must dedup to one: {deduped:?}",
        );
        assert_eq!(
            deduped[0].name,
            "github.com/davecgh/go-spew",
            "surviving entry must carry the full module path as name",
        );
    }

    #[test]
    fn duplicate_go_coords_with_mismatched_names_survive_as_two() {
        // Pre-G2-fix reproduction: reader has full module path,
        // walker has just the last segment. Pass-1 dedup groups
        // by `(ecosystem, name, version, parent_purl)`. Different
        // names → two groups → both entries survive. This test
        // fails post-fix only if the walker regresses; today it
        // passes because the inputs simulate the OLD walker
        // behavior.
        let mut reader_emitted = make_component(
            "pkg:golang/github.com/davecgh/go-spew@v1.1.1",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/go.sum"],
        );
        reader_emitted.name = "github.com/davecgh/go-spew".to_string();
        let walker_emitted = make_component(
            "pkg:golang/github.com/davecgh/go-spew@v1.1.1",
            ResolutionTechnique::FilePathPattern,
            0.70,
            vec![],
            vec!["/root/go/pkg/mod/cache/download/github.com/davecgh/go-spew/@v/v1.1.1.zip"],
        );
        // walker_emitted.name stays as `purl.name()` = `go-spew`.
        assert_eq!(walker_emitted.name, "go-spew");

        let deduped = deduplicate(vec![reader_emitted, walker_emitted]);
        assert_eq!(
            deduped.len(),
            2,
            "mismatched names demonstrate the pre-fix bug: {deduped:?}",
        );
    }
}