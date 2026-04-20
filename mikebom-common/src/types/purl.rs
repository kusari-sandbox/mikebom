use serde::{Deserialize, Serialize};

/// A validated Package URL conforming to the PURL specification.
///
/// Stores the canonical string form after validation. Construction
/// via `Purl::new()` validates the input against the PURL spec
/// using the `packageurl` crate. Invalid PURLs cannot exist in
/// memory (Constitution Principle IV).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Purl {
    canonical: String,
    ecosystem: String,
    name: String,
    version: Option<String>,
    namespace: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PurlError {
    #[error("invalid PURL: {0}")]
    Invalid(String),
    #[error("PURL missing required field: {0}")]
    MissingField(&'static str),
}

/// Percent-encode a PURL segment (name or version) to match the
/// packageurl-python reference implementation's canonical form.
///
/// Currently only encodes `+` → `%2B`; `:`, `~`, `-`, `.`, `_` and
/// alphanumerics stay literal (sub-delims / unreserved per RFC 3986,
/// which the reference impl leaves alone). Idempotent — running it on
/// already-encoded input is a no-op aside from case-normalising
/// `%2b` → `%2B`.
///
/// Applies to both the name segment (e.g. `libstdc++6` →
/// `libstdc%2B%2B6`) and the version segment (e.g. `1.6-2.1+b1` →
/// `1.6-2.1%2Bb1`). The reference impl uses the same rules for both.
///
/// Why asymmetric: the reference impl (and the packageurl-go port)
/// percent-encode `+` because it collides with URL form-encoding's
/// "space" convention when a consumer passes the PURL through a
/// URL-parsing library. Colon stays literal because downstream
/// consumers uniformly expect epoch markers in their human-facing
/// form (dpkg's own CLI, apt, apt-cache, the Debian PTS, NVD's CPE
/// matcher all accept literal `:` in version expressions).
pub fn encode_purl_segment(s: &str) -> String {
    // Collapse any existing %2B → + first, so double-encoding can't
    // happen when a caller passes already-encoded input.
    let normalised = s.replace("%2B", "+").replace("%2b", "+");
    normalised.replace('+', "%2B")
}

/// Legacy alias — same behaviour as [`encode_purl_segment`], kept
/// for call-site clarity when the segment being encoded is explicitly
/// a version.
pub fn encode_purl_version(v: &str) -> String {
    encode_purl_segment(v)
}

impl Purl {
    /// Parse and validate a PURL string.
    ///
    /// Stores `raw` verbatim as the canonical form rather than using
    /// `parsed.to_string()`. The `packageurl` crate (v0.3) decodes
    /// percent-escapes into typed accessors on parse but doesn't
    /// re-encode them on serialize, so relying on `to_string()` would
    /// drop the `%2B` encoding our callers constructed on purpose.
    /// Callers build canonical strings via [`encode_purl_version`]
    /// before calling `new`; this preserves that work.
    pub fn new(raw: &str) -> Result<Self, PurlError> {
        let parsed: packageurl::PackageUrl =
            raw.parse().map_err(|e| PurlError::Invalid(format!("{e}")))?;

        if parsed.name().is_empty() {
            return Err(PurlError::MissingField("name"));
        }

        Ok(Self {
            canonical: raw.to_string(),
            ecosystem: parsed.ty().to_string(),
            name: parsed.name().to_string(),
            version: parsed.version().map(|v| v.to_string()),
            namespace: parsed.namespace().map(|n| n.to_string()),
        })
    }

    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl core::fmt::Display for Purl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl core::fmt::Debug for Purl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Purl({})", self.canonical)
    }
}

impl TryFrom<String> for Purl {
    type Error = PurlError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<Purl> for String {
    fn from(p: Purl) -> String {
        p.canonical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cargo_purl() {
        let p = Purl::new("pkg:cargo/serde@1.0.197").unwrap();
        assert_eq!(p.ecosystem(), "cargo");
        assert_eq!(p.name(), "serde");
        assert_eq!(p.version(), Some("1.0.197"));
    }

    #[test]
    fn valid_npm_scoped_purl() {
        let p = Purl::new("pkg:npm/%40angular/core@16.0.0").unwrap();
        assert_eq!(p.ecosystem(), "npm");
        assert_eq!(p.namespace(), Some("@angular"));
        assert_eq!(p.name(), "core");
    }

    #[test]
    fn valid_maven_purl() {
        let p = Purl::new("pkg:maven/org.apache.commons/commons-lang3@3.12.0").unwrap();
        assert_eq!(p.ecosystem(), "maven");
        assert_eq!(p.namespace(), Some("org.apache.commons"));
    }

    #[test]
    fn invalid_purl_rejected() {
        assert!(Purl::new("not-a-purl").is_err());
        assert!(Purl::new("").is_err());
    }

    #[test]
    fn serde_round_trip() {
        let p = Purl::new("pkg:cargo/tokio@1.38.0").unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: Purl = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    /// Apk is used by the scan-mode package-db reader for Alpine
    /// installed-package entries. Ensure the PURL type accepts it; the
    /// spec lists `apk` as a well-known type and the packageurl crate
    /// supports arbitrary types, so this is mostly a guard against a
    /// future crate change accidentally breaking us.
    #[test]
    fn valid_apk_purl_with_arch_qualifier() {
        let p = Purl::new("pkg:apk/alpine/musl@1.2.4-r2?arch=aarch64").unwrap();
        assert_eq!(p.ecosystem(), "apk");
        assert_eq!(p.namespace(), Some("alpine"));
        assert_eq!(p.name(), "musl");
        assert_eq!(p.version(), Some("1.2.4-r2"));
    }

    #[test]
    fn encode_purl_version_encodes_plus() {
        assert_eq!(encode_purl_version("1.6-2.1+b1"), "1.6-2.1%2Bb1");
        assert_eq!(encode_purl_version("12.4+deb12u13"), "12.4%2Bdeb12u13");
    }

    #[test]
    fn encode_purl_version_is_idempotent() {
        let once = encode_purl_version("1.6-2.1+b1");
        let twice = encode_purl_version(&once);
        assert_eq!(once, twice);
        assert_eq!(once, "1.6-2.1%2Bb1");
    }

    #[test]
    fn encode_purl_version_normalises_mixed_case_input() {
        // Filename paths sometimes carry lowercase `%2b`. The encoder
        // canonicalises to uppercase `%2B` via the round-trip.
        assert_eq!(encode_purl_version("1.6-2.1%2bb1"), "1.6-2.1%2Bb1");
        assert_eq!(encode_purl_version("1.6-2.1%2Bb1"), "1.6-2.1%2Bb1");
    }

    #[test]
    fn encode_purl_version_leaves_colon_literal() {
        // Epoch separator is unencoded per reference impl behaviour.
        assert_eq!(encode_purl_version("1:2.3+b1"), "1:2.3%2Bb1");
    }

    #[test]
    fn encode_purl_version_leaves_tilde_literal() {
        // `~` is unreserved per RFC 3986; reference impl doesn't encode.
        assert_eq!(encode_purl_version("3.0.11-1~deb12u2"), "3.0.11-1~deb12u2");
    }

    /// Probe test documenting how `packageurl 0.3` handles percent-encoded
    /// version segments at the parse → serialize boundary. The behaviour
    /// informs why `Purl::new` stores the caller-provided canonical form
    /// rather than `parsed.to_string()`.
    #[test]
    fn packageurl_0_3_parse_serialize_behaviour_probe() {
        let encoded = "pkg:deb/debian/libjq1@1.6-2.1%2Bb1?arch=arm64";
        let p = Purl::new(encoded).expect("parses");
        // Typed accessor decodes `%2B` → literal `+` for human
        // consumers (CycloneDX `component.version`, CPE synthesis).
        assert_eq!(p.version(), Some("1.6-2.1+b1"));
        // Canonical string preserves the caller's encoding.
        assert_eq!(p.as_str(), encoded);

        // Literal `+` round-trips verbatim — it's on the caller to
        // encode before construction if they want canonical form.
        let literal = "pkg:deb/debian/libjq1@1.6-2.1+b1?arch=arm64";
        let p2 = Purl::new(literal).expect("parses");
        assert_eq!(p2.version(), Some("1.6-2.1+b1"));
        assert_eq!(
            p2.as_str(),
            literal,
            "Purl::new preserves caller's literal `+`; use encode_purl_version to canonicalise",
        );
    }
}
