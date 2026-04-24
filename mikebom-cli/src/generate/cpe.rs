//! Heuristic CPE 2.3 synthesizer — syft-style multi-candidate emission.
//!
//! No authoritative source of CPE identifiers exists for OS-distributed
//! packages at scale. NVD's CPE Dictionary has ~1M entries and the
//! vendor slug for any given package varies (e.g. the `jq` tool lives
//! under `cpe:2.3:a:jqlang:jq:...` in NVD today, under
//! `cpe:2.3:a:jq_project:jq:...` historically, and syft sometimes
//! synthesizes `cpe:2.3:a:debian:jq:...` because that's what the
//! install metadata points at). We follow syft's approach: emit
//! **multiple candidates** per component so a downstream matcher can
//! take the union against NVD and find any hit that exists.
//!
//! Format reference: CPE 2.3 formatted-string binding
//! <https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf>

use mikebom_common::resolution::ResolvedComponent;

/// Build the set of CPE 2.3 candidate strings for a resolved component.
/// Returns empty when the component is in an ecosystem the synthesizer
/// has no opinion on (generic/unknown PURLs).
pub fn synthesize_cpes(component: &ResolvedComponent) -> Vec<String> {
    let ecosystem = component.purl.ecosystem();
    let name = &component.name;
    let version = &component.version;
    if name.is_empty() || version.is_empty() {
        return Vec::new();
    }

    // Build a deduped, ordered vendor candidate list per ecosystem.
    // Ordering matters — the first candidate is emitted as the primary
    // `component.cpe` in CycloneDX; the rest live in a property list.
    let mut vendors: Vec<String> = Vec::new();
    match ecosystem {
        "deb" => {
            push_unique(&mut vendors, "debian");
            push_unique(&mut vendors, name);
        }
        "apk" => {
            push_unique(&mut vendors, "alpinelinux");
            push_unique(&mut vendors, name);
        }
        "rpm" => {
            // RPM PURLs: `pkg:rpm/<vendor>/<name>@...`. The namespace
            // is already the vendor slug (`redhat`, `rocky`, ...), so
            // emit both that and the bare name — NVD references vary.
            if let Some(namespace) = component.purl.namespace() {
                push_unique(&mut vendors, namespace);
            }
            push_unique(&mut vendors, name);
        }
        "gem" => {
            push_unique(&mut vendors, name);
        }
        "cargo" => {
            // Crates rarely match NVD entries, but when they do the
            // vendor is either the crate name or the crate author —
            // deps.dev-driven enrichment can correct this later.
            push_unique(&mut vendors, name);
        }
        "npm" => {
            push_unique(&mut vendors, name);
            // Scoped packages (@org/pkg) — parse the scope out of the
            // PURL namespace so we emit a candidate under that org too.
            if let Some(namespace) = component.purl.namespace() {
                let scope = namespace.trim_start_matches('@');
                if !scope.is_empty() && scope != name {
                    push_unique(&mut vendors, scope);
                }
            }
        }
        "pypi" => {
            push_unique(&mut vendors, name);
            // NVD commonly namespaces Python packages as `python-<name>`.
            push_unique(&mut vendors, &format!("python-{name}"));
        }
        "golang" | "go" => {
            push_unique(&mut vendors, name);
            if let Some(namespace) = component.purl.namespace() {
                push_unique(&mut vendors, namespace);
            }
        }
        "maven" => {
            // Maven PURLs carry groupId as namespace; that's often a
            // reverse-DNS string (com.example.foo) which maps poorly to
            // NVD vendor slugs. Best-effort: emit both the groupId and
            // its final segment (the common case: "org.apache.commons"
            // → `apache`).
            if let Some(namespace) = component.purl.namespace() {
                push_unique(&mut vendors, namespace);
                if let Some(tail) = namespace.rsplit('.').next() {
                    if !tail.is_empty() && tail != namespace {
                        push_unique(&mut vendors, tail);
                    }
                }
            }
            push_unique(&mut vendors, name);
        }
        "nuget" => {
            push_unique(&mut vendors, name);
        }
        _ => {
            // Unknown ecosystem — no opinion.
            return Vec::new();
        }
    }

    vendors
        .into_iter()
        .map(|vendor| format_cpe(&vendor, name, version))
        .collect()
}

/// Insert `value` (lowercased, CPE-segment-safe) into `out` unless it's
/// already present. Empty strings are dropped.
fn push_unique(out: &mut Vec<String>, value: &str) {
    let v = value.to_lowercase();
    if v.is_empty() {
        return;
    }
    if !out.iter().any(|existing| existing == &v) {
        out.push(v);
    }
}

/// Build a CPE 2.3 formatted string from (vendor, product, version).
/// The remaining seven fields are `*` (any) per spec — we don't have
/// update/edition/language/sw_edition/target_sw/target_hw/other info
/// at SBOM time.
fn format_cpe(vendor: &str, product: &str, version: &str) -> String {
    format!(
        "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
        cpe_escape(vendor),
        cpe_escape(product),
        cpe_escape(version),
    )
}

/// Escape the formatted-string special characters per CPE 2.3 §6.2.
/// The characters that require escaping inside a formatted-string
/// attribute are: `\`, `*`, `?`, `!`, `"`, `#`, `$`, `%`, `&`, `'`,
/// `(`, `)`, `+`, `,`, `/`, `:`, `;`, `<`, `=`, `>`, `@`, `[`, `]`,
/// `^`, backtick, `{`, `|`, `}`, `~`. Escape with a leading backslash.
/// Keep ASCII alphanumerics, `-`, `.`, and `_` unescaped (they're
/// safe in an attribute segment).
fn cpe_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_') {
            out.push(ch);
        } else {
            out.push('\\');
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::purl::Purl;

    fn make_component(purl_str: &str) -> ResolvedComponent {
        let purl = Purl::new(purl_str).expect("valid purl");
        ResolvedComponent {
            name: purl.name().to_string(),
            version: purl.version().unwrap_or("0.0.0").to_string(),
            purl,
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
            shade_relocation: None,
            external_references: Vec::new(),
        }
    }

    #[test]
    fn deb_produces_debian_and_product_vendor_candidates() {
        let c = make_component("pkg:deb/debian/jq@1.6-2.1+b1?distro=bookworm");
        let cpes = synthesize_cpes(&c);
        assert_eq!(cpes.len(), 2);
        assert!(cpes[0].starts_with("cpe:2.3:a:debian:jq:"), "{:?}", cpes);
        assert!(cpes[1].starts_with("cpe:2.3:a:jq:jq:"), "{:?}", cpes);
    }

    #[test]
    fn apk_produces_alpinelinux_and_product_vendor_candidates() {
        let c = make_component("pkg:apk/alpine/musl@1.2.4-r2");
        let cpes = synthesize_cpes(&c);
        assert!(cpes.iter().any(|s| s.starts_with("cpe:2.3:a:alpinelinux:musl:")));
        assert!(cpes.iter().any(|s| s.starts_with("cpe:2.3:a:musl:musl:")));
    }

    #[test]
    fn cargo_produces_product_as_vendor() {
        let c = make_component("pkg:cargo/serde@1.0.197");
        let cpes = synthesize_cpes(&c);
        assert_eq!(cpes.len(), 1);
        assert_eq!(
            cpes[0],
            "cpe:2.3:a:serde:serde:1.0.197:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn pypi_emits_name_and_python_prefixed_candidates() {
        let c = make_component("pkg:pypi/requests@2.31.0");
        let cpes = synthesize_cpes(&c);
        assert!(cpes.iter().any(|s| s.starts_with("cpe:2.3:a:requests:requests:")));
        assert!(cpes.iter().any(|s| s.starts_with("cpe:2.3:a:python-requests:requests:")));
    }

    #[test]
    fn npm_scoped_package_emits_scope_as_candidate() {
        let c = make_component("pkg:npm/%40angular/core@16.0.0");
        let cpes = synthesize_cpes(&c);
        assert!(
            cpes.iter().any(|s| s.contains(":angular:core:")),
            "expected angular scope as vendor, got {cpes:?}"
        );
    }

    #[test]
    fn escapes_plus_and_colon_in_version() {
        let c = make_component("pkg:deb/debian/libjq1@1.6-2.1+b1");
        let cpes = synthesize_cpes(&c);
        let primary = &cpes[0];
        // `+` must be escaped as `\+`.
        assert!(
            primary.contains("1.6-2.1\\+b1"),
            "expected escaped + in {primary}"
        );
    }

    #[test]
    fn unknown_ecosystem_returns_empty() {
        let c = make_component("pkg:generic/weird@1.0.0");
        let cpes = synthesize_cpes(&c);
        assert!(cpes.is_empty());
    }

    #[test]
    fn empty_version_returns_empty() {
        // Versionless components can't produce useful CPEs — the
        // version field is required by CPE 2.3 and `*` would
        // over-match.
        let mut c = make_component("pkg:cargo/serde@1.0.0");
        c.version = String::new();
        let cpes = synthesize_cpes(&c);
        assert!(cpes.is_empty(), "got {cpes:?}");
    }

    #[test]
    fn empty_name_returns_empty() {
        let mut c = make_component("pkg:cargo/serde@1.0.0");
        c.name = String::new();
        let cpes = synthesize_cpes(&c);
        assert!(cpes.is_empty(), "got {cpes:?}");
    }

    #[test]
    fn cpe_escape_preserves_safe_chars() {
        assert_eq!(cpe_escape("hello-world_1.2"), "hello-world_1.2");
        assert_eq!(cpe_escape("1.2.3"), "1.2.3");
    }

    #[test]
    fn cpe_escape_backslashes_special_chars() {
        assert_eq!(cpe_escape("1+2"), "1\\+2");
        assert_eq!(cpe_escape("a:b"), "a\\:b");
        assert_eq!(cpe_escape("a/b"), "a\\/b");
    }
}