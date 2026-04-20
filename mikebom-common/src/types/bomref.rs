use serde::{Deserialize, Serialize};

/// A CycloneDX bom-ref identifier. Must be non-empty and unique within a BOM.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BomRef(String);

#[derive(Debug, thiserror::Error)]
#[error("BomRef cannot be empty")]
pub struct BomRefError;

impl BomRef {
    pub fn new(raw: &str) -> Result<Self, BomRefError> {
        if raw.trim().is_empty() {
            return Err(BomRefError);
        }
        Ok(Self(raw.to_string()))
    }

    /// Create a BomRef from a PURL string (common pattern).
    pub fn from_purl(purl: &str) -> Result<Self, BomRefError> {
        Self::new(purl)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for BomRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for BomRef {
    type Error = BomRefError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<BomRef> for String {
    fn from(b: BomRef) -> String {
        b.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_bomref() {
        let b = BomRef::new("pkg:cargo/serde@1.0.197").unwrap();
        assert_eq!(b.as_str(), "pkg:cargo/serde@1.0.197");
    }

    #[test]
    fn empty_rejected() {
        assert!(BomRef::new("").is_err());
        assert!(BomRef::new("   ").is_err());
    }
}
