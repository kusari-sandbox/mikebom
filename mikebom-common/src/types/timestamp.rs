use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A validated UTC timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }

    pub fn to_iso8601(&self) -> String {
        self.0.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

impl core::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_iso8601())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_produces_valid_timestamp() {
        let ts = Timestamp::now();
        let iso = ts.to_iso8601();
        assert!(iso.ends_with('Z'));
        assert!(iso.contains('T'));
    }

    #[test]
    fn serde_round_trip() {
        let ts = Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, back);
    }
}
