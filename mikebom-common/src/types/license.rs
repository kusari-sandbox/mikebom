use serde::{Deserialize, Serialize};

/// A validated SPDX license expression.
///
/// Basic validation ensures the string is non-empty and contains
/// only characters valid in SPDX expressions. Full SPDX expression
/// parsing can be added later via a dedicated crate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SpdxExpression(String);

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("empty SPDX expression")]
    Empty,
    #[error("invalid SPDX expression: {0}")]
    Invalid(String),
}

impl SpdxExpression {
    /// Permissive constructor — accepts any non-empty, non-control-char
    /// string. Use this when the source data isn't guaranteed to be a
    /// canonical SPDX expression (e.g. raw text from a Debian copyright
    /// file's `License:` field) and the caller has already extracted
    /// the best string available.
    pub fn new(raw: &str) -> Result<Self, LicenseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(LicenseError::Empty);
        }
        // Basic validation: SPDX expressions contain identifiers,
        // AND/OR/WITH operators, and parentheses
        if trimmed.contains(|c: char| c.is_control()) {
            return Err(LicenseError::Invalid(
                "contains control characters".to_string(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Strict constructor — runs the input through the `spdx` crate's
    /// real expression parser. On success, stores the canonical form
    /// the parser produces (e.g. `"GPL-2.0-or-later"` for input
    /// `"GPL-2.0-or-later "`). On failure, returns
    /// [`LicenseError::Invalid`] with the parser's error message.
    ///
    /// Use this when you want a downstream consumer to be able to trust
    /// that the stored value is a real SPDX 2.x expression — useful for
    /// the dpkg copyright reader, where we want to discard noisy
    /// free-form text rather than emit it as a "license."
    pub fn try_canonical(raw: &str) -> Result<Self, LicenseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(LicenseError::Empty);
        }
        match spdx::Expression::parse(trimmed) {
            Ok(expr) => {
                // The expression renders back to its canonical form via
                // Display; that's the value we want stored.
                Ok(Self(expr.to_string()))
            }
            Err(e) => Err(LicenseError::Invalid(e.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for SpdxExpression {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SpdxExpression {
    type Error = LicenseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<SpdxExpression> for String {
    fn from(e: SpdxExpression) -> String {
        e.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_license() {
        let l = SpdxExpression::new("MIT").unwrap();
        assert_eq!(l.as_str(), "MIT");
    }

    #[test]
    fn compound_expression() {
        let l = SpdxExpression::new("MIT OR Apache-2.0").unwrap();
        assert_eq!(l.as_str(), "MIT OR Apache-2.0");
    }

    #[test]
    fn empty_rejected() {
        assert!(SpdxExpression::new("").is_err());
        assert!(SpdxExpression::new("   ").is_err());
    }

    #[test]
    fn serde_round_trip() {
        let l = SpdxExpression::new("MIT OR Apache-2.0").unwrap();
        let json = serde_json::to_string(&l).unwrap();
        let back: SpdxExpression = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn try_canonical_accepts_simple_id() {
        let l = SpdxExpression::try_canonical("MIT").unwrap();
        assert_eq!(l.as_str(), "MIT");
    }

    #[test]
    fn try_canonical_accepts_or_expression() {
        let l = SpdxExpression::try_canonical("MIT OR Apache-2.0").unwrap();
        // Canonical form should be deterministic; ordering preserved.
        assert!(l.as_str().contains("MIT"));
        assert!(l.as_str().contains("Apache-2.0"));
    }

    #[test]
    fn try_canonical_accepts_with_exception() {
        let l = SpdxExpression::try_canonical("GPL-2.0-or-later WITH Classpath-exception-2.0")
            .unwrap();
        assert!(l.as_str().contains("Classpath-exception-2.0"));
    }

    #[test]
    fn try_canonical_rejects_unknown_identifier() {
        // A free-form string the spdx parser doesn't recognise.
        let result = SpdxExpression::try_canonical("Some Random Free Text");
        assert!(result.is_err(), "should reject non-SPDX text");
    }

    #[test]
    fn try_canonical_rejects_empty() {
        assert!(matches!(
            SpdxExpression::try_canonical(""),
            Err(LicenseError::Empty)
        ));
        assert!(matches!(
            SpdxExpression::try_canonical("   "),
            Err(LicenseError::Empty)
        ));
    }
}
