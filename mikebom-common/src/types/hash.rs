use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Sha1,
    Md5,
}

impl HashAlgorithm {
    pub fn expected_hex_len(&self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
            Self::Sha1 => 40,
            Self::Md5 => 32,
        }
    }
}

impl core::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Sha1 => write!(f, "sha1"),
            Self::Md5 => write!(f, "md5"),
        }
    }
}

/// A validated lowercase hex-encoded string.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexString(String);

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("invalid hex string: contains non-hex character")]
    InvalidHex,
    #[error("hash length mismatch: expected {expected} hex chars for {algorithm}, got {actual}")]
    LengthMismatch {
        algorithm: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
}

impl HexString {
    pub fn new(s: &str) -> Result<Self, HashError> {
        let lower = s.to_ascii_lowercase();
        if !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(HashError::InvalidHex);
        }
        Ok(Self(lower))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for HexString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::fmt::Debug for HexString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hex({})", &self.0)
    }
}

impl TryFrom<String> for HexString {
    type Error = HashError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<HexString> for String {
    fn from(h: HexString) -> String {
        h.0
    }
}

/// A cryptographic content hash with algorithm and validated hex value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash {
    pub algorithm: HashAlgorithm,
    pub value: HexString,
}

impl ContentHash {
    pub fn sha256(hex: &str) -> Result<Self, HashError> {
        Self::with_algorithm(HashAlgorithm::Sha256, hex)
    }

    /// Construct a `ContentHash` for any supported algorithm. Verifies
    /// the hex length matches the algorithm's expected output (e.g.
    /// 128 chars for SHA-512, 64 for SHA-256).
    pub fn with_algorithm(algorithm: HashAlgorithm, hex: &str) -> Result<Self, HashError> {
        let value = HexString::new(hex)?;
        let expected = algorithm.expected_hex_len();
        if value.as_str().len() != expected {
            return Err(HashError::LengthMismatch {
                algorithm,
                expected,
                actual: value.as_str().len(),
            });
        }
        Ok(Self { algorithm, value })
    }
}

impl core::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sha256() {
        let hash = ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .unwrap();
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn uppercase_normalized() {
        let hash = ContentHash::sha256(
            "3FB1C873E1B9B056A4DC4C0C198B24C3FFA59243C322BFD971D2D5EF4F463EE1",
        )
        .unwrap();
        assert!(!hash.value.as_str().chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(ContentHash::sha256("abcdef").is_err());
    }

    #[test]
    fn invalid_hex_rejected() {
        assert!(HexString::new("xyz123").is_err());
    }

    #[test]
    fn serde_round_trip() {
        let hash = ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .unwrap();
        let json = serde_json::to_string(&hash).unwrap();
        let back: ContentHash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, back);
    }
}
