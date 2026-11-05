use crate::lexer::{self, Lang};
use crate::linter::{CveRuleDef, LinterViolation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn default_true() -> bool {
    true
}

fn default_category() -> String {
    "Plugin / Security".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    LineByLine,
    WholeFile,
}

impl Default for MatchMode {
    fn default() -> Self {
        MatchMode::LineByLine
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConditions {
    /// Mots ou sous-chaînes qui DOIVENT obligatoirement être présents
    #[serde(default)]
    pub must_contain: Vec<String>,
    /// Mots ou motifs qui, s'ils sont présents, neutralisent l'alerte (atténuation valide)
    #[serde(default)]
    pub must_not_contain: Vec<String>,
    /// Expressions régulières déclenchant la violation
    #[serde(default)]
    pub regex_patterns: Vec<String>,
    /// Jetons ou sous-chaînes interdites déclenchant la violation
    #[serde(default)]
    pub forbidden_tokens: Vec<String>,
    /// Si true, évalue sur le code brut (littéraux inclus). Si false, masque commentaires & chaînes
    #[serde(default)]
    pub check_literals: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTestCase {
    pub name: String,
    pub code: String,
    pub file_name: String,
    pub should_trigger: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRule {
    pub id: String,
    pub cwe_id: String,
    pub name: String,
    #[serde(default = "default_category")]
    pub category: String,
    pub severity: String, // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "WARNING"
    pub description: String,
    pub remediation: String,
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub match_mode: MatchMode,
    #[serde(default)]
    pub conditions: RuleConditions,
    #[serde(default)]
    pub test_cases: Vec<RuleTestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: Option<String>,
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<PluginRule>,
}

#[derive(Debug, Clone, Default)]
pub struct PluginTestReport {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

pub struct PluginEngine {
    pub plugins: Vec<PluginManifest>,
    regex_cache: HashMap<String, Result<Regex, String>>,
}

impl PluginEngine {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            regex_cache: HashMap::new(),
        }
    }

    /// Charge un plugin depuis une chaîne YAML ou JSON
    pub fn load_from_str(&mut self, content: &str) -> Result<&PluginManifest, String> {
        let manifest: PluginManifest = match serde_yaml::from_str(content) {
            Ok(m) => m,
            Err(yaml_err) => serde_json::from_str(content)
                .map_err(|json_err| format!("YAML parse error: {yaml_err}; JSON parse error: {json_err}"))?,
        };
        self.plugins.push(manifest);
        Ok(self.plugins.last().unwrap())
    }

    /// Charge tous les fichiers plugins (*.yaml, *.yml, *.json) depuis un dossier
    pub fn load_from_directory<P: AsRef<Path>>(&mut self, dir_path: P) -> Result<usize, String> {
        let p = dir_path.as_ref();
        if !p.exists() {
            return Err(format!("Plugin directory does not exist: {}", p.display()));
        }

        let mut loaded_count = 0;
        self.scan_and_load_dir(p, &mut loaded_count)?;
        Ok(loaded_count)
    }

    fn scan_and_load_dir(&mut self, dir: &Path, count: &mut usize) -> Result<(), String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("Cannot read dir {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.scan_and_load_dir(&path, count)?;
            } else if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                let ext_lower = ext.to_lowercase();
                if ext_lower == "yaml" || ext_lower == "yml" || ext_lower == "json" {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(manifest) = self.load_from_str(&content) {
                            if manifest.enabled {
                                *count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Exporte la liste des définitions de règles au format natif AetherScope (CveRuleDef)
    pub fn get_cve_rule_defs(&self) -> Vec<CveRuleDef> {
        let mut defs = Vec::new();
        for plugin in &self.plugins {
            if !plugin.enabled {
                continue;
            }
            for rule in &plugin.rules {
                defs.push(CveRuleDef {
                    rule_id: rule.id.clone(),
                    cve_id: rule.cwe_id.clone(),
                    name: format!("[{}] {}", plugin.name, rule.name),
                    category: rule.category.clone(),
                    severity: rule.severity.clone(),
                    description: rule.description.clone(),
                    default_enabled: true,
                });
            }
        }
        defs
    }

    fn get_compiled_regex(&mut self, pattern: &str) -> Option<&Regex> {
        if !self.regex_cache.contains_key(pattern) {
            let compiled = Regex::new(pattern).map_err(|e| e.to_string());
            self.regex_cache.insert(pattern.to_string(), compiled);
        }
        match self.regex_cache.get(pattern) {
            Some(Ok(re)) => Some(re),
            _ => None,
        }
    }

    /// Audite un fichier avec les plugins actifs
    pub fn audit_file(&mut self, file_path: &str, content: &str) -> Vec<LinterViolation> {
        let mut violations = Vec::new();
        let lower_path = file_path.to_lowercase();

        // Récupération de la version masquée pour les règles anti-faux-positifs
        let lang = Lang::from_path(&lower_path);
        let masked_content = match lang {
            Some(Lang::Python) | Some(Lang::Php) => lexer::mask_comments_only(content, lang.unwrap()),
            Some(l) => lexer::mask_literals(content, l),
            None => content.to_string(),
        };

        for plugin in self.plugins.clone() {
            if !plugin.enabled {
                continue;
            }

            for rule in &plugin.rules {
                // 1. Filtrage par extension
                let extension_matches = rule.file_extensions.iter().any(|ext| {
                    let ext_clean = ext.to_lowercase();
                    lower_path.ends_with(&ext_clean)
                });
                if !extension_matches {
                    continue;
                }

                let eval_content = if rule.conditions.check_literals {
                    content
                } else {
                    &masked_content
                };

                // 2. Vérification des conditions must_contain sur le fichier complet
                let has_all_must_contain = rule
                    .conditions
                    .must_contain
                    .iter()
                    .all(|pat| eval_content.contains(pat));
                if !rule.conditions.must_contain.is_empty() && !has_all_must_contain {
                    continue;
                }

                // 3. Vérification des conditions must_not_contain sur le fichier complet
                let has_any_mitigation = rule
                    .conditions
                    .must_not_contain
                    .iter()
                    .any(|pat| eval_content.contains(pat));
                if has_any_mitigation {
                    continue;
                }

                // 4. Exécution selon le mode
                match rule.match_mode {
                    MatchMode::WholeFile => {
                        let mut triggered = false;
                        for token in &rule.conditions.forbidden_tokens {
                            if eval_content.contains(token) {
                                triggered = true;
                                break;
                            }
                        }
                        if !triggered {
                            for pattern in &rule.conditions.regex_patterns {
                                if let Some(re) = self.get_compiled_regex(pattern) {
                                    if re.is_match(eval_content) {
                                        triggered = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if triggered {
                            violations.push(LinterViolation {
                                file_path: file_path.to_string(),
                                line_number: 1,
                                rule_id: rule.id.clone(),
                                cve_id: rule.cwe_id.clone(),
                                severity: rule.severity.clone(),
                                message: format!("[Plugin: {}] {}", plugin.name, rule.description),
                                transmitted_data: None,
                                transmitted_type: None,
                                remediation: rule.remediation.clone(),
                            });
                        }
                    }
                    MatchMode::LineByLine => {
                        for (idx, line) in eval_content.lines().enumerate() {
                            let line_no = idx + 1;
                            let mut line_triggered = false;

                            for token in &rule.conditions.forbidden_tokens {
                                if line.contains(token) {
                                    line_triggered = true;
                                    break;
                                }
                            }

                            if !line_triggered {
                                for pattern in &rule.conditions.regex_patterns {
                                    if let Some(re) = self.get_compiled_regex(pattern) {
                                        if re.is_match(line) {
                                            line_triggered = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            if line_triggered {
                                violations.push(LinterViolation {
                                    file_path: file_path.to_string(),
                                    line_number: line_no,
                                    rule_id: rule.id.clone(),
                                    cve_id: rule.cwe_id.clone(),
                                    severity: rule.severity.clone(),
                                    message: format!("[Plugin: {}] {}", plugin.name, rule.description),
                                    transmitted_data: Some(line.trim().to_string()),
                                    transmitted_type: Some("Code Snippet Line".to_string()),
                                    remediation: rule.remediation.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    /// Exécute les cas de tests unitaires intégrés aux plugins
    pub fn run_test_suite(&mut self) -> PluginTestReport {
        let mut report = PluginTestReport::default();

        for plugin in self.plugins.clone() {
            for rule in &plugin.rules {
                for test in &rule.test_cases {
                    report.total_tests += 1;
                    let violations = self.audit_file(&test.file_name, &test.code);
                    let found = violations.iter().any(|v| v.rule_id == rule.id);

                    if found == test.should_trigger {
                        report.passed += 1;
                    } else {
                        report.failed += 1;
                        let reason = if test.should_trigger {
                            format!(
                                "[FAIL] Plugin '{}' / Rule '{}' failed to trigger on test '{}' (expected violation)",
                                plugin.name, rule.id, test.name
                            )
                        } else {
                            format!(
                                "[FAIL] Plugin '{}' / Rule '{}' falsely triggered on test '{}' (expected clean)",
                                plugin.name, rule.id, test.name
                            )
                        };
                        report.failures.push(reason);
                    }
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PLUGIN_YAML: &str = r#"
name: "ZeroDay-Solana-Guard"
version: "1.0.0"
author: "Security Research Team"
description: "Règles personnalisées pour Smart Contracts Solana et Rust Web3"
enabled: true
rules:
  - id: "SOLANA-ACCOUNT-OWNERSHIP-BYPASS"
    cwe_id: "CWE-285 / MISSING-OWNER-CHECK"
    name: "Omission de vérification du Owner d'un compte Solana"
    category: "Web3 / Solana"
    severity: "CRITICAL"
    description: "Compte désérialisé sans validation de `account.owner == program_id`"
    remediation: "Ajoutez `if account.owner != program_id { return Err(ProgramError::IllegalOwner); }`"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      must_contain: ["AccountInfo"]
      must_not_contain: ["IllegalOwner", "owner =="]
      regex_patterns:
        - "try_from_slice\\(&account\\.data\\.borrow\\(\\)\\)"
    test_cases:
      - name: "Vulnérable - pas de vérification de owner"
        file_name: "instruction.rs"
        should_trigger: true
        code: |
          use solana_program::account_info::AccountInfo;
          pub fn process(account: &AccountInfo) {
              let state = MyState::try_from_slice(&account.data.borrow()).unwrap();
          }
      - name: "Sécurisé - vérification présente"
        file_name: "instruction.rs"
        should_trigger: false
        code: |
          use solana_program::account_info::AccountInfo;
          pub fn process(account: &AccountInfo) {
              if account.owner == program_id {
                  let state = MyState::try_from_slice(&account.data.borrow()).unwrap();
              }
          }
"#;

    #[test]
    fn test_plugin_loading_and_audit() {
        let mut engine = PluginEngine::new();
        engine.load_from_str(SAMPLE_PLUGIN_YAML).expect("YAML parsing should succeed");

        assert_eq!(engine.plugins.len(), 1);
        let defs = engine.get_cve_rule_defs();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].rule_id, "SOLANA-ACCOUNT-OWNERSHIP-BYPASS");

        let report = engine.run_test_suite();
        assert_eq!(report.total_tests, 2);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 0);
    }
}
