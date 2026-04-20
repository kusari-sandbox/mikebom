//! SBOM comparison subcommand.
//!
//! Runs mikebom/syft/trivy (or any set of CycloneDX JSON SBOMs) against a
//! ground-truth dependency list and emits a markdown report with recall,
//! precision, and evidence-coverage metrics. The intent is direct, numeric
//! validation against the spec targets (SC-001 ≥95% recall, SC-002 <2% FP,
//! SC-006 100% evidence coverage).
//!
//! Ground truth can be a `Cargo.lock` (for cargo ecosystem) or a
//! `dpkg-query -W --showformat='${Package}\t${Version}\t${Architecture}\n'`
//! output file (for deb ecosystem), or a raw PURL list (one per line).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};

#[derive(Clone, Debug, ValueEnum)]
pub enum CompareEcosystem {
    Cargo,
    Deb,
}

#[derive(Args)]
pub struct CompareArgs {
    /// CycloneDX JSON produced by mikebom
    #[arg(long)]
    pub mikebom: PathBuf,
    /// CycloneDX JSON produced by syft
    #[arg(long)]
    pub syft: Option<PathBuf>,
    /// CycloneDX JSON produced by trivy
    #[arg(long)]
    pub trivy: Option<PathBuf>,
    /// Ground-truth source: Cargo.lock, dpkg-query output, or a raw PURL list
    #[arg(long)]
    pub truth: PathBuf,
    /// Which ecosystem the comparison is scoped to — used both for
    /// truth parsing and for filtering tool components before the diff.
    #[arg(long, value_enum)]
    pub ecosystem: CompareEcosystem,
    /// Markdown report output path
    #[arg(long)]
    pub output: PathBuf,
    /// Print a JSON summary to stdout as well
    #[arg(long)]
    pub json: bool,
}

/// Components reported by one tool, with per-component evidence signal.
#[derive(Default)]
struct ToolReport {
    name: String,
    purls: BTreeSet<String>,
    /// Subset of `purls` for which the CycloneDX `evidence` field was populated.
    purls_with_evidence: BTreeSet<String>,
}

impl ToolReport {
    fn evidence_coverage(&self) -> f64 {
        if self.purls.is_empty() {
            return 0.0;
        }
        self.purls_with_evidence.len() as f64 / self.purls.len() as f64
    }
}

pub async fn execute(args: CompareArgs) -> Result<()> {
    // Parse all three SBOMs.
    let mut tools: Vec<ToolReport> = Vec::new();
    tools.push(load_tool("mikebom", &args.mikebom, &args.ecosystem)?);
    if let Some(p) = args.syft.as_ref() {
        tools.push(load_tool("syft", p, &args.ecosystem)?);
    }
    if let Some(p) = args.trivy.as_ref() {
        tools.push(load_tool("trivy", p, &args.ecosystem)?);
    }

    // Parse ground truth.
    let truth = load_truth(&args.truth, &args.ecosystem)
        .with_context(|| format!("loading ground truth from {}", args.truth.display()))?;
    if truth.is_empty() {
        anyhow::bail!("ground truth file {} produced zero PURLs — nothing to compare against", args.truth.display());
    }

    // Compute per-tool metrics and aggregate.
    let report = render_report(&tools, &truth, &args.ecosystem)?;
    std::fs::write(&args.output, &report)
        .with_context(|| format!("writing report to {}", args.output.display()))?;
    tracing::info!(path = %args.output.display(), "wrote comparison report");

    if args.json {
        let mut summary = serde_json::Map::new();
        summary.insert(
            "truth_count".into(),
            serde_json::Value::from(truth.len() as u64),
        );
        let mut tool_stats = serde_json::Map::new();
        for t in &tools {
            let stats = tool_metrics(t, &truth, &tools);
            tool_stats.insert(
                t.name.clone(),
                serde_json::json!({
                    "found": t.purls.len(),
                    "recall": stats.recall,
                    "precision": stats.precision,
                    "evidence_coverage": t.evidence_coverage(),
                    "unique": stats.unique.len(),
                    "missed": stats.missed.len(),
                }),
            );
        }
        summary.insert("tools".into(), serde_json::Value::Object(tool_stats));
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(summary))?
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CycloneDX SBOM loading
// ---------------------------------------------------------------------------

fn load_tool(
    name: &str,
    path: &Path,
    ecosystem: &CompareEcosystem,
) -> Result<ToolReport> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;

    let components = json
        .get("components")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut purls = BTreeSet::new();
    let mut purls_with_evidence = BTreeSet::new();

    for comp in components {
        let Some(raw_purl) = comp.get("purl").and_then(|v| v.as_str()) else {
            continue;
        };
        let canonical = match canonicalize_purl(raw_purl, ecosystem) {
            Some(p) => p,
            None => continue,
        };
        if !purl_in_ecosystem(&canonical, ecosystem) {
            continue;
        }
        purls.insert(canonical.clone());
        if comp.get("evidence").is_some() {
            purls_with_evidence.insert(canonical);
        }
    }

    Ok(ToolReport {
        name: name.to_string(),
        purls,
        purls_with_evidence,
    })
}

/// Canonicalize PURLs so minor formatting differences between tools don't
/// inflate the "unique" sets. Drop qualifiers that aren't identity-carrying
/// (download_url, distro, type, repository_url) but keep `arch` for deb.
/// Also percent-decode the common PURL version escapes (`%3a` → `:` for
/// deb epoch separators, `%2b` → `+` for deb build numbers) because
/// different tools emit different encodings for the same identity.
fn canonicalize_purl(raw: &str, ecosystem: &CompareEcosystem) -> Option<String> {
    // Split qualifiers off the end.
    let (base, qualifiers) = match raw.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (raw, None),
    };
    let base_lower = decode_purl_escapes(&base.to_lowercase());

    let keep_qualifiers: &[&str] = match ecosystem {
        CompareEcosystem::Cargo => &[],
        CompareEcosystem::Deb => &["arch"],
    };

    let kept: Vec<String> = qualifiers
        .map(|q| q.split('&'))
        .into_iter()
        .flatten()
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if keep_qualifiers.contains(&k) {
                Some(format!("{}={}", k, decode_purl_escapes(v)))
            } else {
                None
            }
        })
        .collect();

    if kept.is_empty() {
        Some(base_lower)
    } else {
        Some(format!("{}?{}", base_lower, kept.join("&")))
    }
}

/// Decode the small set of percent-escapes that PURL-producing tools
/// commonly disagree on. Intentionally not a full percent-decoder — we
/// want `%20` in a path to survive because it's genuinely different from
/// a space, but for `+` and `:` (which are identity-equivalent) we
/// collapse all spellings to the literal character.
fn decode_purl_escapes(s: &str) -> String {
    s.replace("%2b", "+")
        .replace("%2B", "+")
        .replace("%3a", ":")
        .replace("%3A", ":")
}

fn purl_in_ecosystem(purl: &str, ecosystem: &CompareEcosystem) -> bool {
    match ecosystem {
        CompareEcosystem::Cargo => purl.starts_with("pkg:cargo/"),
        CompareEcosystem::Deb => purl.starts_with("pkg:deb/"),
    }
}

// ---------------------------------------------------------------------------
// Ground truth loading
// ---------------------------------------------------------------------------

fn load_truth(path: &Path, ecosystem: &CompareEcosystem) -> Result<BTreeSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Heuristic: PURL list if any line starts with "pkg:".
    if content
        .lines()
        .any(|l| l.trim_start().starts_with("pkg:"))
    {
        let mut out = BTreeSet::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("pkg:") {
                if let Some(c) = canonicalize_purl(line, ecosystem) {
                    if purl_in_ecosystem(&c, ecosystem) {
                        out.insert(c);
                    }
                }
            }
        }
        return Ok(out);
    }

    match ecosystem {
        CompareEcosystem::Cargo => parse_cargo_lock(&content),
        CompareEcosystem::Deb => parse_dpkg_tsv(&content),
    }
}

fn parse_cargo_lock(content: &str) -> Result<BTreeSet<String>> {
    // Cargo.lock is TOML with [[package]] arrays. We only want crates from
    // the crates.io registry — skip `source = "git+..."` / path deps since
    // those aren't in scope for a crates.io PURL comparison.
    let parsed: toml::Value = toml::from_str(content)
        .context("parsing Cargo.lock as TOML")?;
    let mut out = BTreeSet::new();
    if let Some(pkgs) = parsed.get("package").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            let name = pkg.get("name").and_then(|v| v.as_str());
            let version = pkg.get("version").and_then(|v| v.as_str());
            let source = pkg.get("source").and_then(|v| v.as_str());
            let (Some(name), Some(version)) = (name, version) else { continue };
            if let Some(src) = source {
                if !src.starts_with("registry+") {
                    continue;
                }
            } else {
                // workspace-local / path deps have no source field — skip
                continue;
            }
            let purl = format!("pkg:cargo/{}@{}", name.to_lowercase(), version);
            out.insert(purl);
        }
    }
    Ok(out)
}

fn parse_dpkg_tsv(content: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            anyhow::bail!(
                "line {} in dpkg truth file is not <name>\\t<version>\\t<arch>: {:?}",
                i + 1,
                line
            );
        }
        let (name, version, arch) = (parts[0], parts[1], parts[2]);
        let purl = format!(
            "pkg:deb/debian/{}@{}?arch={}",
            name.to_lowercase(),
            version,
            arch
        );
        out.insert(purl);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

struct ToolMetrics {
    recall: f64,
    precision: f64,
    unique: BTreeSet<String>,
    missed: BTreeSet<String>,
    false_positive: BTreeSet<String>,
}

fn tool_metrics(
    tool: &ToolReport,
    truth: &BTreeSet<String>,
    all_tools: &[ToolReport],
) -> ToolMetrics {
    let truth_set: HashSet<&String> = truth.iter().collect();
    let tool_set: HashSet<&String> = tool.purls.iter().collect();

    let found_in_truth: HashSet<&&String> = tool_set
        .iter()
        .filter(|p| truth_set.contains(**p))
        .collect();
    let recall = if truth.is_empty() {
        0.0
    } else {
        found_in_truth.len() as f64 / truth.len() as f64
    };
    let precision = if tool.purls.is_empty() {
        0.0
    } else {
        found_in_truth.len() as f64 / tool.purls.len() as f64
    };

    let others: HashSet<&String> = all_tools
        .iter()
        .filter(|t| t.name != tool.name)
        .flat_map(|t| t.purls.iter())
        .collect();
    let unique: BTreeSet<String> = tool
        .purls
        .iter()
        .filter(|p| !others.contains(p))
        .cloned()
        .collect();

    let missed: BTreeSet<String> = truth
        .iter()
        .filter(|p| !tool_set.contains(p))
        .cloned()
        .collect();

    let false_positive: BTreeSet<String> = tool
        .purls
        .iter()
        .filter(|p| !truth_set.contains(p))
        .cloned()
        .collect();

    ToolMetrics {
        recall,
        precision,
        unique,
        missed,
        false_positive,
    }
}

fn render_report(
    tools: &[ToolReport],
    truth: &BTreeSet<String>,
    ecosystem: &CompareEcosystem,
) -> Result<String> {
    let mut out = String::new();
    let eco_label = match ecosystem {
        CompareEcosystem::Cargo => "cargo",
        CompareEcosystem::Deb => "deb",
    };
    writeln!(out, "# mikebom SBOM comparison — {} ecosystem", eco_label)?;
    writeln!(out)?;
    writeln!(
        out,
        "Ground truth: **{}** packages",
        truth.len()
    )?;
    writeln!(out)?;

    // Summary table
    writeln!(
        out,
        "| Tool | Found | Recall | Precision | Evidence coverage | Unique | Missed | FP |"
    )?;
    writeln!(
        out,
        "|------|------:|-------:|----------:|------------------:|-------:|-------:|---:|"
    )?;
    let mut metrics: BTreeMap<String, ToolMetrics> = BTreeMap::new();
    for t in tools {
        let m = tool_metrics(t, truth, tools);
        writeln!(
            out,
            "| {} | {} | {:.1}% | {:.1}% | {:.1}% | {} | {} | {} |",
            t.name,
            t.purls.len(),
            m.recall * 100.0,
            m.precision * 100.0,
            t.evidence_coverage() * 100.0,
            m.unique.len(),
            m.missed.len(),
            m.false_positive.len(),
        )?;
        metrics.insert(t.name.clone(), m);
    }

    writeln!(out)?;
    writeln!(out, "## Per-tool detail")?;
    for t in tools {
        writeln!(out)?;
        writeln!(out, "### {}", t.name)?;
        let m = metrics
            .get(&t.name)
            .expect("metrics populated for every tool in the preceding summary-table loop");

        writeln!(out)?;
        writeln!(out, "- Total components in ecosystem: **{}**", t.purls.len())?;
        writeln!(
            out,
            "- With CycloneDX `evidence` populated: **{} ({:.1}%)**",
            t.purls_with_evidence.len(),
            t.evidence_coverage() * 100.0
        )?;
        writeln!(
            out,
            "- True positives (in truth): **{}**",
            (t.purls.len() as i64 - m.false_positive.len() as i64).max(0)
        )?;

        if !m.unique.is_empty() {
            writeln!(out)?;
            writeln!(
                out,
                "<details><summary>Unique to {} ({})</summary>",
                t.name,
                m.unique.len()
            )?;
            writeln!(out)?;
            for p in m.unique.iter().take(200) {
                writeln!(out, "- `{}`", p)?;
            }
            writeln!(out)?;
            writeln!(out, "</details>")?;
        }

        if !m.missed.is_empty() {
            writeln!(out)?;
            writeln!(
                out,
                "<details><summary>Missed by {} ({})</summary>",
                t.name,
                m.missed.len()
            )?;
            writeln!(out)?;
            for p in m.missed.iter().take(200) {
                writeln!(out, "- `{}`", p)?;
            }
            writeln!(out)?;
            writeln!(out, "</details>")?;
        }
    }

    writeln!(out)?;
    writeln!(out, "## Methodology")?;
    writeln!(
        out,
        "- PURLs canonicalized lowercase; non-identity qualifiers dropped."
    )?;
    writeln!(
        out,
        "- Only `pkg:{}/...` PURLs counted — other ecosystems filtered out of each tool's output before the diff.",
        eco_label
    )?;
    writeln!(
        out,
        "- Ground truth: {} file parsed line-by-line (PURL list passthrough, Cargo.lock [[package]] with `source = \"registry+...\"`, or dpkg-query TSV).",
        eco_label
    )?;
    writeln!(
        out,
        "- Evidence coverage = fraction of ecosystem components whose CycloneDX entry has an `evidence` field (build-time provenance, SC-006)."
    )?;

    Ok(out)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_cargo_drops_all_qualifiers() {
        let out = canonicalize_purl(
            "pkg:cargo/Serde@1.0.197?download_url=https://...",
            &CompareEcosystem::Cargo,
        );
        assert_eq!(out.as_deref(), Some("pkg:cargo/serde@1.0.197"));
    }

    #[test]
    fn canonicalize_deb_keeps_arch() {
        let out = canonicalize_purl(
            "pkg:deb/debian/jq@1.7.1-3build1?arch=arm64&distro=bookworm",
            &CompareEcosystem::Deb,
        );
        assert_eq!(
            out.as_deref(),
            Some("pkg:deb/debian/jq@1.7.1-3build1?arch=arm64")
        );
    }

    #[test]
    fn canonicalize_deb_decodes_plus_and_colon() {
        // mikebom, syft, and trivy all emit `%2B` / `%2b` / `+` in
        // various combinations — they're identity-equivalent for deb
        // packages. The comparator collapses them all to the literal
        // form so union/intersection sets across tools are accurate.
        let a = canonicalize_purl(
            "pkg:deb/debian/jq@1.6-2.1%2Bdeb12u1?arch=arm64",
            &CompareEcosystem::Deb,
        );
        let b = canonicalize_purl(
            "pkg:deb/debian/jq@1.6-2.1%2bdeb12u1?arch=arm64",
            &CompareEcosystem::Deb,
        );
        let c = canonicalize_purl(
            "pkg:deb/debian/jq@1.6-2.1+deb12u1?arch=arm64",
            &CompareEcosystem::Deb,
        );
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(
            a.as_deref(),
            Some("pkg:deb/debian/jq@1.6-2.1+deb12u1?arch=arm64")
        );
    }

    #[test]
    fn parse_dpkg_tsv_basic() {
        let input = "jq\t1.7.1-3build1\tarm64\nripgrep\t14.1.0-1\tarm64\n";
        let out = parse_dpkg_tsv(input).expect("parse");
        assert!(out.contains("pkg:deb/debian/jq@1.7.1-3build1?arch=arm64"));
        assert!(out.contains("pkg:deb/debian/ripgrep@14.1.0-1?arch=arm64"));
    }

    #[test]
    fn parse_cargo_lock_basic() {
        let input = r#"
[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "mikebom"
version = "0.1.0"
"#;
        let out = parse_cargo_lock(input).expect("parse");
        assert!(out.contains("pkg:cargo/serde@1.0.197"));
        // workspace crate should be excluded (no source)
        assert!(!out.iter().any(|p| p.contains("mikebom")));
    }

    #[test]
    fn purl_list_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truth.txt");
        std::fs::write(
            &path,
            "pkg:deb/debian/jq@1.7.1?arch=arm64\npkg:deb/debian/curl@8.0.0?arch=arm64\n",
        )
        .unwrap();
        let truth = load_truth(&path, &CompareEcosystem::Deb).expect("load");
        assert_eq!(truth.len(), 2);
    }
}
