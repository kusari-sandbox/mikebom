use std::path::Path;

use anyhow::Context;

/// Write a CycloneDX BOM as pretty-printed JSON to the given path.
///
/// Creates parent directories if they don't exist.
pub fn write_cyclonedx_json(bom: &serde_json::Value, path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory: {}", parent.display()))?;
        }
    }

    let json_str = serde_json::to_string_pretty(bom)
        .context("serializing CycloneDX BOM to JSON")?;

    std::fs::write(path, json_str)
        .with_context(|| format!("writing CycloneDX BOM to {}", path.display()))?;

    tracing::info!(path = %path.display(), "wrote CycloneDX JSON BOM");
    Ok(())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn write_and_read_back() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("test.cdx.json");

        let bom = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6"
        });

        write_cyclonedx_json(&bom, &path).expect("write bom");

        let content = std::fs::read_to_string(&path).expect("read back");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("parse json");
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.6");
    }

    #[test]
    fn creates_parent_directories() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("nested").join("output").join("test.cdx.json");

        let bom = json!({"bomFormat": "CycloneDX"});
        write_cyclonedx_json(&bom, &path).expect("write bom");
        assert!(path.exists());
    }
}
