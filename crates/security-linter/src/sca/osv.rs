use crate::sca::cache::OsvCache;
use crate::sca::lockfile::ScaDependency;
use serde::{Deserialize, Serialize};

/// Normalizes ecosystem identifiers for OSV.dev API compatibility.
/// OSV strictly rejects "Cargo", requiring "crates.io".
pub fn normalize_ecosystem(raw: &str) -> &'static str {
    match raw.trim().to_lowercase().as_str() {
        "cargo" | "rust" | "crates.io" => "crates.io",
        "npm" | "node" | "javascript" | "typescript" => "npm",
        "packagist" | "composer" | "php" => "Packagist",
        _ => "crates.io",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvSeverity {
    pub r#type: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvReference {
    pub r#type: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvPackageRef {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackageRef>,
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub ranges: Vec<serde_json::Value>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvQueryResponse {
    #[serde(default)]
    pub vulns: Vec<OsvVulnerability>,
}

impl OsvVulnerability {
    /// Extracts all affected function names declared in the advisory metadata
    pub fn extract_affected_functions(&self) -> Vec<String> {
        let mut fns = Vec::new();

        for aff in &self.affected {
            if let Some(eco) = &aff.ecosystem_specific {
                // Check ecosystem_specific.affects.functions
                if let Some(arr) = eco
                    .get("affects")
                    .and_then(|a| a.get("functions"))
                    .and_then(|f| f.as_array())
                {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let s = s.trim().to_string();
                            if !s.is_empty() && !fns.contains(&s) {
                                fns.push(s);
                            }
                        }
                    }
                }
                // Check ecosystem_specific.affected_functions
                if let Some(arr) = eco.get("affected_functions").and_then(|f| f.as_array()) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let s = s.trim().to_string();
                            if !s.is_empty() && !fns.contains(&s) {
                                fns.push(s);
                            }
                        }
                    }
                }
            }

            if let Some(db) = &aff.database_specific {
                if let Some(arr) = db.get("affected_functions").and_then(|f| f.as_array()) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            let s = s.trim().to_string();
                            if !s.is_empty() && !fns.contains(&s) {
                                fns.push(s);
                            }
                        }
                    }
                }
            }
        }

        fns
    }

    /// Resolves canonical CVE identifier from aliases if present, or falls back to primary ID
    pub fn resolve_cve_id(&self) -> String {
        for alias in &self.aliases {
            if alias.starts_with("CVE-") {
                return alias.clone();
            }
        }
        self.id.clone()
    }

    /// Resolves standardized severity level ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    pub fn resolve_severity(&self) -> String {
        if let Some(db) = &self.database_specific {
            if let Some(sev) = db.get("severity").and_then(|s| s.as_str()) {
                let s = sev.to_uppercase();
                if s.contains("CRIT") {
                    return "CRITICAL".to_string();
                }
                if s.contains("HIGH") {
                    return "HIGH".to_string();
                }
                if s.contains("MED") || s.contains("MOD") {
                    return "MEDIUM".to_string();
                }
                if s.contains("LOW") {
                    return "LOW".to_string();
                }
            }
        }

        for s in &self.severity {
            let score = &s.score;
            if score.contains("/C:H/I:H/A:H") {
                return "CRITICAL".to_string();
            }
        }

        "HIGH".to_string()
    }
}

/// Queries the OSV.dev API with local cache checking and offline guarantees
pub fn query_osv(
    dep: &ScaDependency,
    cache: &OsvCache,
    offline_only: bool,
) -> Result<Vec<OsvVulnerability>, String> {
    let normalized_eco = normalize_ecosystem(&dep.ecosystem);

    // 1. Cache-first lookup: if already cached, return immediately with zero network traffic
    if let Some(cached) = cache.get(normalized_eco, &dep.name, &dep.version) {
        return Ok(cached);
    }

    // 2. Offline guarantee: if offline mode is enforced, never open network sockets
    if offline_only {
        return Ok(Vec::new());
    }

    // 3. Online query via curl with timeout
    let payload = serde_json::json!({
        "package": {
            "name": dep.name,
            "ecosystem": normalized_eco
        },
        "version": dep.version
    });
    let body_str = serde_json::to_string(&payload).map_err(|e| e.to_string())?;

    let output = std::process::Command::new("curl")
        .args([
            "-sSL",
            "--max-time", "5",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", &body_str,
            "https://api.osv.dev/v1/query",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let resp_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(resp) = serde_json::from_str::<OsvQueryResponse>(&resp_str) {
                let _ = cache.put(normalized_eco, &dep.name, &dep.version, &resp.vulns);
                Ok(resp.vulns)
            } else {
                Ok(Vec::new())
            }
        }
        _ => {
            // Network failure / air-gapped environment fallback
            Ok(Vec::new())
        }
    }
}
