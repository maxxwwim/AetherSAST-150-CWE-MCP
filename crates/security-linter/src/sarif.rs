//! SARIF v2.1.0 Static Analysis Results Interchange Format Serializer
//! OASIS Standard & GitHub Code Scanning compatible format.

use core_graph::bubble::CveAnomalyRecord;
use crate::linter::{CveRuleDef, LinterViolation, SecurityLinter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub const SARIF_SCHEMA_V2_1_0: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json";
pub const SARIF_VERSION_2_1_0: &str = "2.1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    pub rules: Vec<SarifReportingDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessageString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessageString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifReportingConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessageString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingConfiguration {
    pub level: String, // "error" | "warning" | "note" | "none"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    pub level: String,
    pub message: SarifMessageString,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessageString {
    pub text: String,
}

/// Converts a severity level to a valid SARIF 2.1.0 level.
pub fn severity_to_sarif_level(severity: &str) -> &'static str {
    match severity.trim().to_uppercase().as_str() {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        "LOW" | "WARNING" | "INFO" | "NOTE" => "note",
        _ => "warning",
    }
}

/// Computes an official MITRE CWE helpUri or project repository fallback URI.
pub fn cwe_to_help_uri(cve_id: &str, rule_id: &str) -> String {
    let upper = cve_id.to_uppercase();
    if let Some(pos) = upper.find("CWE-") {
        let remainder = &upper[pos + 4..];
        let digits: String = remainder.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return format!("https://cwe.mitre.org/data/definitions/{}.html", digits);
        }
    }
    format!("https://cwe.mitre.org/data/definitions/{}.html", rule_id.to_lowercase())
}

/// Normalizes raw file paths to relative URIs with forward slashes (`/`).
pub fn normalize_sarif_uri(raw_path: &str) -> String {
    normalize_sarif_uri_with_root(raw_path, None)
}

/// Normalizes raw file paths relative to an optional root path with forward slashes (`/`).
pub fn normalize_sarif_uri_with_root(raw_path: &str, project_root: Option<&Path>) -> String {
    let clean = raw_path
        .strip_prefix(r"\\?\")
        .unwrap_or(raw_path)
        .replace('\\', "/");

    let clean_ref = if let Some(root) = project_root {
        let root_str = root
            .to_string_lossy()
            .strip_prefix(r"\\?\")
            .unwrap_or(&root.to_string_lossy())
            .replace('\\', "/");
        let trimmed_root = root_str.trim_end_matches('/');
        if let Some(stripped) = clean.strip_prefix(trimmed_root) {
            stripped.trim_start_matches('/')
        } else {
            &clean
        }
    } else {
        &clean
    };

    clean_ref
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

impl SarifReport {
    /// Builds a full SARIF 2.1.0 report from anomalies, dynamically cataloging all CWE rules.
    pub fn from_anomalies(anomalies: &[CveAnomalyRecord], custom_rules: Option<&[CveRuleDef]>) -> Self {
        Self::from_anomalies_with_root(anomalies, custom_rules, None)
    }

    /// Builds a full SARIF 2.1.0 report with optional project root path normalization.
    pub fn from_anomalies_with_root(
        anomalies: &[CveAnomalyRecord],
        custom_rules: Option<&[CveRuleDef]>,
        project_root: Option<&Path>,
    ) -> Self {
        let all_rules = match custom_rules {
            Some(r) => r.to_vec(),
            None => SecurityLinter::get_supported_cve_rules(),
        };

        let mut rule_index_map: HashMap<String, usize> = HashMap::with_capacity(all_rules.len());
        let mut descriptors = Vec::with_capacity(all_rules.len());

        for (idx, r) in all_rules.into_iter().enumerate() {
            let help_uri = cwe_to_help_uri(&r.cve_id, &r.rule_id);
            rule_index_map.insert(r.rule_id.clone(), idx);
            descriptors.push(SarifReportingDescriptor {
                id: r.rule_id.clone(),
                name: Some(r.name.clone()),
                short_description: Some(SarifMessageString { text: r.name.clone() }),
                full_description: Some(SarifMessageString { text: r.description.clone() }),
                default_configuration: Some(SarifReportingConfiguration {
                    level: severity_to_sarif_level(&r.severity).to_string(),
                }),
                help_uri: Some(help_uri),
                help: Some(SarifMessageString {
                    text: format!(
                        "CWE: {}\nCategory: {}\nDescription: {}",
                        r.cve_id, r.category, r.description
                    ),
                }),
                properties: Some(serde_json::json!({
                    "cwe": r.cve_id,
                    "category": r.category,
                    "precision": "very-high",
                    "tags": ["security", "sast", "cwe"]
                })),
            });
        }

        let mut results = Vec::with_capacity(anomalies.len());

        for a in anomalies {
            let rule_idx = rule_index_map.get(&a.rule_id).copied().or_else(|| {
                // Dynamically register unknown/plugin rule descriptor if missing
                let new_idx = descriptors.len();
                let help_uri = cwe_to_help_uri(&a.cve_id, &a.rule_id);
                descriptors.push(SarifReportingDescriptor {
                    id: a.rule_id.clone(),
                    name: Some(a.cve_id.clone()),
                    short_description: Some(SarifMessageString { text: a.message.clone() }),
                    full_description: Some(SarifMessageString { text: a.message.clone() }),
                    default_configuration: Some(SarifReportingConfiguration {
                        level: severity_to_sarif_level(&a.severity).to_string(),
                    }),
                    help_uri: Some(help_uri),
                    help: Some(SarifMessageString { text: a.remediation.clone() }),
                    properties: Some(serde_json::json!({
                        "cwe": a.cve_id,
                        "remediation": a.remediation
                    })),
                });
                rule_index_map.insert(a.rule_id.clone(), new_idx);
                Some(new_idx)
            });

            let level = severity_to_sarif_level(&a.severity).to_string();
            let uri = normalize_sarif_uri_with_root(&a.file_path, project_root);
            let start_line = if a.line_number == 0 { 1 } else { a.line_number };

            let snippet = a.transmitted_data.as_ref().map(|snip| SarifArtifactContent {
                text: snip.clone(),
            });

            let full_message = if a.remediation.is_empty() {
                a.message.clone()
            } else {
                format!("{} — Fix: {}", a.message, a.remediation)
            };

            let mut prop_map = serde_json::Map::new();
            prop_map.insert("cveId".to_string(), serde_json::Value::String(a.cve_id.clone()));
            prop_map.insert(
                "remediation".to_string(),
                serde_json::Value::String(a.remediation.clone()),
            );
            prop_map.insert(
                "is_reachable".to_string(),
                serde_json::Value::Bool(a.is_reachable),
            );
            prop_map.insert(
                "exploit_path".to_string(),
                serde_json::to_value(&a.exploit_path).unwrap_or(serde_json::Value::Array(vec![])),
            );
            if let Some(ref data) = a.transmitted_data {
                prop_map.insert("transmittedData".to_string(), serde_json::Value::String(data.clone()));
            }
            if let Some(ref ty) = a.transmitted_type {
                prop_map.insert("transmittedType".to_string(), serde_json::Value::String(ty.clone()));
            }

            results.push(SarifResult {
                rule_id: a.rule_id.clone(),
                rule_index: rule_idx,
                level,
                message: SarifMessageString { text: full_message },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri,
                            uri_base_id: Some("%SRCROOT%".to_string()),
                        },
                        region: SarifRegion {
                            start_line,
                            start_column: Some(1),
                            end_line: None,
                            end_column: None,
                            snippet,
                        },
                    },
                }],
                properties: Some(serde_json::Value::Object(prop_map)),
            });
        }

        SarifReport {
            schema: SARIF_SCHEMA_V2_1_0.to_string(),
            version: SARIF_VERSION_2_1_0.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "AetherScope".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: Some("https://github.com/aether-engine".to_string()),
                        rules: descriptors,
                    },
                },
                results,
            }],
        }
    }

    /// Builds a full SARIF 2.1.0 report from linter violations.
    pub fn from_violations(violations: &[LinterViolation], custom_rules: Option<&[CveRuleDef]>) -> Self {
        Self::from_violations_with_root(violations, custom_rules, None)
    }

    /// Builds a full SARIF 2.1.0 report from linter violations with optional project root path normalization.
    pub fn from_violations_with_root(
        violations: &[LinterViolation],
        custom_rules: Option<&[CveRuleDef]>,
        project_root: Option<&Path>,
    ) -> Self {
        let anomalies: Vec<CveAnomalyRecord> = violations
            .iter()
            .map(|v| CveAnomalyRecord {
                rule_id: v.rule_id.clone(),
                cve_id: v.cve_id.clone(),
                severity: v.severity.clone(),
                line_number: v.line_number,
                file_path: v.file_path.clone(),
                message: v.message.clone(),
                transmitted_data: v.transmitted_data.clone(),
                transmitted_type: v.transmitted_type.clone(),
                remediation: v.remediation.clone(),
                is_reachable: false,
                exploit_path: Vec::new(),
            })
            .collect();
        Self::from_anomalies_with_root(&anomalies, custom_rules, project_root)
    }

    /// Serializes report to compact JSON string.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serializes report to formatted pretty JSON string.
    pub fn to_json_string_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_v2_1_0_schema_and_version() {
        let report = SarifReport::from_anomalies(&[], None);
        assert_eq!(
            report.schema,
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
        );
        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].tool.driver.name, "AetherScope");
        assert_eq!(report.runs[0].tool.driver.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_sarif_rules_catalogue_mapping() {
        let report = SarifReport::from_anomalies(&[], None);
        let rules = &report.runs[0].tool.driver.rules;
        // Verify all 150+ native CWE rules are mapped
        assert!(
            rules.len() >= 150,
            "Expected at least 150 rules, found {}",
            rules.len()
        );

        // Spot check rules for required fields
        for r in rules {
            assert!(!r.id.is_empty(), "Rule id must not be empty");
            assert!(r.name.is_some(), "Rule name must be present");
            assert!(
                r.short_description.is_some(),
                "shortDescription must be present"
            );
            assert!(
                r.default_configuration.is_some(),
                "defaultConfiguration must be present"
            );
            let level = &r.default_configuration.as_ref().unwrap().level;
            assert!(
                level == "error" || level == "warning" || level == "note",
                "Invalid SARIF level: {}",
                level
            );
            assert!(r.help_uri.is_some(), "helpUri must be present");
            assert!(
                r.help_uri.as_ref().unwrap().starts_with("https://"),
                "helpUri must start with https://"
            );
        }
    }

    #[test]
    fn test_sarif_anomaly_results_mapping_and_properties() {
        let anomaly = CveAnomalyRecord {
            rule_id: "CVE-RUST-DESER-BOMB-OOM".to_string(),
            cve_id: "CWE-789 / LENGTH-PREFIX-OOM-BOMB".to_string(),
            severity: "CRITICAL".to_string(),
            line_number: 42,
            file_path: r"crates\network\src\protocol.rs".to_string(),
            message: "Unbounded wire length prefix triggers OOM abort".to_string(),
            transmitted_data: Some("wire_len: u64".to_string()),
            transmitted_type: Some("bincode::deserialize".to_string()),
            remediation: "Add .with_limit(64 * 1024)".to_string(),
            is_reachable: true,
            exploit_path: vec![
                "/api/packet".to_string(),
                "packet_handler".to_string(),
                "deserialize".to_string(),
            ],
        };

        let report = SarifReport::from_anomalies(&[anomaly], None);
        assert_eq!(report.runs[0].results.len(), 1);
        let res = &report.runs[0].results[0];

        assert_eq!(res.rule_id, "CVE-RUST-DESER-BOMB-OOM");
        assert_eq!(res.level, "error");
        assert!(res.rule_index.is_some());
        assert!(res.message.text.contains("Unbounded wire length prefix"));
        assert!(res.message.text.contains("Add .with_limit(64 * 1024)"));

        // Locations check
        assert_eq!(res.locations.len(), 1);
        let loc = &res.locations[0].physical_location;
        assert_eq!(loc.artifact_location.uri, "crates/network/src/protocol.rs");
        assert_eq!(loc.artifact_location.uri_base_id.as_deref(), Some("%SRCROOT%"));
        assert_eq!(loc.region.start_line, 42);
        assert_eq!(loc.region.start_column, Some(1));
        assert_eq!(
            loc.region.snippet.as_ref().map(|s| s.text.as_str()),
            Some("wire_len: u64")
        );

        // Properties check (reachability & exploit path)
        let props = res.properties.as_ref().expect("properties bag present");
        assert_eq!(props["is_reachable"], serde_json::Value::Bool(true));
        let path = props["exploit_path"].as_array().expect("exploit_path array");
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], "/api/packet");
        assert_eq!(path[1], "packet_handler");
        assert_eq!(path[2], "deserialize");
        assert_eq!(props["cveId"], "CWE-789 / LENGTH-PREFIX-OOM-BOMB");
        assert_eq!(props["remediation"], "Add .with_limit(64 * 1024)");
        assert_eq!(props["transmittedData"], "wire_len: u64");
    }

    #[test]
    fn test_sarif_severity_level_mapping() {
        assert_eq!(severity_to_sarif_level("CRITICAL"), "error");
        assert_eq!(severity_to_sarif_level("HIGH"), "error");
        assert_eq!(severity_to_sarif_level("MEDIUM"), "warning");
        assert_eq!(severity_to_sarif_level("LOW"), "note");
        assert_eq!(severity_to_sarif_level("WARNING"), "note");
        assert_eq!(severity_to_sarif_level("INFO"), "note");
        assert_eq!(severity_to_sarif_level("UNKNOWN"), "warning");
    }

    #[test]
    fn test_sarif_path_normalization() {
        assert_eq!(
            normalize_sarif_uri(r"crates\security-linter\src\sarif.rs"),
            "crates/security-linter/src/sarif.rs"
        );
        assert_eq!(
            normalize_sarif_uri(r"\\?\C:\repo\crates\sarif.rs"),
            "C:/repo/crates/sarif.rs"
        );
        assert_eq!(
            normalize_sarif_uri(r"./src/main.rs"),
            "src/main.rs"
        );

        let root = Path::new("C:/repo");
        assert_eq!(
            normalize_sarif_uri_with_root(r"C:\repo\crates\sarif.rs", Some(root)),
            "crates/sarif.rs"
        );
    }

    #[test]
    fn test_sarif_json_serialization_validity() {
        let anomaly = CveAnomalyRecord {
            rule_id: "CVE-TEST-RULE".to_string(),
            cve_id: "CWE-999 / TEST-CWE".to_string(),
            severity: "HIGH".to_string(),
            line_number: 10,
            file_path: "src/test.rs".to_string(),
            message: "Test violation message".to_string(),
            transmitted_data: None,
            transmitted_type: None,
            remediation: "Test remediation".to_string(),
            is_reachable: false,
            exploit_path: Vec::new(),
        };

        let report = SarifReport::from_anomalies(&[anomaly], None);
        let json_str = report.to_json_string_pretty().expect("pretty json serialization");

        // Parse back as generic JSON Value to ensure standard JSON compliance
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");
        assert_eq!(
            parsed["$schema"],
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
        );
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"].is_array());
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "AetherScope");
        assert!(parsed["runs"][0]["tool"]["driver"]["rules"].is_array());
        assert!(parsed["runs"][0]["results"].is_array());
        assert_eq!(parsed["runs"][0]["results"][0]["ruleId"], "CVE-TEST-RULE");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
    }
}
