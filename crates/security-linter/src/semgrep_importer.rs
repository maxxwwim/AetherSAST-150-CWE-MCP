//! Semgrep / Nuclei YAML Rule Importer & Metavariable Compiler
//! Translates Semgrep syntax into AetherScope native PluginManifests and optimized Rust Regexes.

use crate::plugin::{MatchMode, PluginManifest, PluginRule, RuleConditions};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepRuleFile {
    pub rules: Vec<SemgrepRuleDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepRuleDef {
    pub id: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub metadata: Option<SemgrepMetadata>,
    pub pattern: Option<String>,
    #[serde(rename = "pattern-either", default)]
    pub pattern_either: Option<Vec<SemgrepPatternClause>>,
    #[serde(rename = "pattern-not", default)]
    pub pattern_not: Option<SemgrepPatternNotClause>,
    #[serde(rename = "pattern-regex", default)]
    pub pattern_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SemgrepMetadata {
    #[serde(default)]
    pub cwe: Option<SemgrepCweField>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SemgrepCweField {
    Single(String),
    Multiple(Vec<String>),
    Integer(i64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SemgrepPatternClause {
    Obj {
        #[serde(default)]
        pattern: Option<String>,
        #[serde(rename = "pattern-regex", default)]
        pattern_regex: Option<String>,
    },
    Simple(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SemgrepPatternNotClause {
    Single(String),
    Multiple(Vec<SemgrepPatternClause>),
    SingleClause(SemgrepPatternClause),
}

pub struct SemgrepImporter;

impl SemgrepImporter {
    /// Parses a Semgrep YAML string into a SemgrepRuleFile.
    pub fn parse_yaml(yaml_str: &str) -> Result<SemgrepRuleFile, String> {
        serde_yaml::from_str(yaml_str).map_err(|e| format!("Semgrep YAML parsing error: {e}"))
    }

    /// Converts a Semgrep rule file into an AetherScope PluginManifest ready for hot-reload.
    pub fn to_plugin_manifest(
        rule_file: &SemgrepRuleFile,
        manifest_name: &str,
    ) -> Result<PluginManifest, String> {
        let mut plugin_rules = Vec::new();
        for rule in &rule_file.rules {
            let plugin_rule = Self::convert_rule(rule)?;
            plugin_rules.push(plugin_rule);
        }

        Ok(PluginManifest {
            name: manifest_name.to_string(),
            version: "1.0.0".to_string(),
            author: Some("AetherScope Semgrep Importer".to_string()),
            description: Some(format!("Imported from Semgrep rule set: {manifest_name}")),
            enabled: true,
            rules: plugin_rules,
        })
    }

    /// Converts a single Semgrep rule definition into an AetherScope PluginRule.
    pub fn convert_rule(rule: &SemgrepRuleDef) -> Result<PluginRule, String> {
        let cwe_id = match &rule.metadata {
            Some(m) => match &m.cwe {
                Some(SemgrepCweField::Single(s)) => normalize_cwe_string(s),
                Some(SemgrepCweField::Multiple(v)) => {
                    if let Some(first) = v.first() {
                        normalize_cwe_string(first)
                    } else {
                        "CWE-699 / GENERAL".to_string()
                    }
                }
                Some(SemgrepCweField::Integer(n)) => format!("CWE-{n} / GENERAL"),
                None => "CWE-699 / GENERAL".to_string(),
            },
            None => "CWE-699 / GENERAL".to_string(),
        };

        let category = rule
            .metadata
            .as_ref()
            .and_then(|m| m.category.clone())
            .unwrap_or_else(|| "Semgrep / Imported".to_string());

        let severity = match rule.severity.to_uppercase().as_str() {
            "ERROR" | "CRITICAL" => "CRITICAL".to_string(),
            "WARNING" => "HIGH".to_string(),
            "INFO" => "MEDIUM".to_string(),
            "LOW" => "LOW".to_string(),
            "MEDIUM" => "MEDIUM".to_string(),
            "HIGH" => "HIGH".to_string(),
            _ => "HIGH".to_string(),
        };

        let file_extensions = languages_to_extensions(&rule.languages);

        let mut regex_patterns = Vec::new();
        let mut must_not_contain = Vec::new();
        let mut has_literals = false;
        let mut is_multiline = false;

        // 1. Primary pattern
        if let Some(ref pat) = rule.pattern {
            if pat.contains('\n') {
                is_multiline = true;
            }
            let (re, lit) = translate_pattern_to_regex(pat);
            regex_patterns.push(re);
            if lit {
                has_literals = true;
            }
        }

        // 2. pattern-either clauses
        if let Some(ref either) = rule.pattern_either {
            for clause in either {
                match clause {
                    SemgrepPatternClause::Obj {
                        pattern,
                        pattern_regex,
                    } => {
                        if let Some(ref pat) = pattern {
                            if pat.contains('\n') {
                                is_multiline = true;
                            }
                            let (re, lit) = translate_pattern_to_regex(pat);
                            regex_patterns.push(re);
                            if lit {
                                has_literals = true;
                            }
                        } else if let Some(ref reg) = pattern_regex {
                            regex_patterns.push(reg.clone());
                        }
                    }
                    SemgrepPatternClause::Simple(pat) => {
                        if pat.contains('\n') {
                            is_multiline = true;
                        }
                        let (re, lit) = translate_pattern_to_regex(pat);
                        regex_patterns.push(re);
                        if lit {
                            has_literals = true;
                        }
                    }
                }
            }
        }

        // 3. pattern-regex
        if let Some(ref reg) = rule.pattern_regex {
            regex_patterns.push(reg.clone());
        }

        // 4. pattern-not
        if let Some(ref not_clause) = rule.pattern_not {
            extract_not_clause_strings(not_clause, rule.pattern.as_deref(), &mut must_not_contain);
        }

        // Validate compiled regexes
        for pattern in &regex_patterns {
            Regex::new(pattern)
                .map_err(|e| format!("Invalid generated regex '{pattern}': {e}"))?;
        }

        let match_mode = if is_multiline {
            MatchMode::WholeFile
        } else {
            MatchMode::LineByLine
        };

        let remediation = format!(
            "Review code matching rule '{}'. Avoid insecure patterns and validate all inputs.",
            rule.id
        );

        Ok(PluginRule {
            id: rule.id.clone(),
            cwe_id,
            name: format!("[Semgrep] {}", rule.id),
            category,
            severity,
            description: rule.message.clone(),
            remediation,
            file_extensions,
            match_mode,
            conditions: RuleConditions {
                must_contain: Vec::new(),
                must_not_contain,
                regex_patterns,
                forbidden_tokens: Vec::new(),
                check_literals: has_literals,
            },
            test_cases: Vec::new(),
        })
    }
}

/// Convenience function converting raw Semgrep YAML into a PluginManifest.
pub fn convert_semgrep_yaml(
    yaml_content: &str,
) -> Result<PluginManifest, Box<dyn std::error::Error>> {
    let rule_file = SemgrepImporter::parse_yaml(yaml_content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let manifest_name = rule_file
        .rules
        .first()
        .map(|r| r.id.as_str())
        .unwrap_or("imported-semgrep");
    let manifest = SemgrepImporter::to_plugin_manifest(&rule_file, manifest_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(manifest)
}

fn extract_not_clause_strings(
    not_clause: &SemgrepPatternNotClause,
    primary_pattern: Option<&str>,
    out: &mut Vec<String>,
) {
    match not_clause {
        SemgrepPatternNotClause::Single(s) => {
            extract_mitigation_tokens(s, primary_pattern, out);
        }
        SemgrepPatternNotClause::SingleClause(clause) => {
            extract_clause_token(clause, primary_pattern, out);
        }
        SemgrepPatternNotClause::Multiple(clauses) => {
            for clause in clauses {
                extract_clause_token(clause, primary_pattern, out);
            }
        }
    }
}

fn extract_clause_token(
    clause: &SemgrepPatternClause,
    primary_pattern: Option<&str>,
    out: &mut Vec<String>,
) {
    match clause {
        SemgrepPatternClause::Obj {
            pattern,
            pattern_regex,
        } => {
            if let Some(ref p) = pattern {
                extract_mitigation_tokens(p, primary_pattern, out);
            } else if let Some(ref r) = pattern_regex {
                extract_mitigation_tokens(r, primary_pattern, out);
            }
        }
        SemgrepPatternClause::Simple(p) => {
            extract_mitigation_tokens(p, primary_pattern, out);
        }
    }
}

fn extract_mitigation_tokens(raw: &str, primary_pattern: Option<&str>, out: &mut Vec<String>) {
    let clean = raw.trim().trim_matches('"').trim_matches('\'').trim();
    if clean.is_empty() {
        return;
    }

    // If clean is a single word/identifier without special chars
    if clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        if !clean.starts_with('$') && !out.contains(&clean.to_string()) {
            out.push(clean.to_string());
        }
        return;
    }

    // Extract identifiers from primary pattern to avoid suppressing on the trigger itself
    let trigger_idents: Vec<String> = primary_pattern
        .map(|pat| {
            pat.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty() && !s.starts_with('$'))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Extract identifier words from pattern-not
    for word in clean.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        let trimmed = word.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip metavariables (all uppercase like X, EXPR, or starting with $)
        if trimmed.starts_with('$')
            || (trimmed.len() <= 2 && trimmed.chars().all(|c| c.is_ascii_uppercase()))
        {
            continue;
        }
        // Skip words that are part of the primary trigger (e.g. `eval`)
        if trigger_idents.contains(&trimmed.to_string()) {
            continue;
        }
        if !out.contains(&trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }

    // If no specific words extracted, fall back to clean if it doesn't contain `$`
    if out.is_empty() && !clean.contains('$') {
        out.push(clean.to_string());
    }
}

/// Normalizes CWE strings like "CWE-89: SQL Injection" into "CWE-89 / SQL-INJECTION".
pub fn normalize_cwe_string(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some((num, name)) = trimmed.split_once(':') {
        let clean_num = num.trim().to_uppercase();
        let clean_name = name.trim().replace(' ', "-").to_uppercase();
        format!("{clean_num} / {clean_name}")
    } else if trimmed.starts_with("CWE-") || trimmed.starts_with("cwe-") {
        trimmed.to_uppercase()
    } else if trimmed.chars().all(|c| c.is_ascii_digit()) {
        format!("CWE-{trimmed} / GENERAL")
    } else {
        format!("CWE-699 / {}", trimmed.to_uppercase().replace(' ', "-"))
    }
}

/// Maps Semgrep language strings to target file extensions.
pub fn languages_to_extensions(languages: &[String]) -> Vec<String> {
    let mut exts = Vec::new();
    for lang in languages {
        match lang.to_lowercase().as_str() {
            "rust" | "rs" => exts.push(".rs".to_string()),
            "python" | "py" => exts.push(".py".to_string()),
            "javascript" | "js" => {
                exts.extend(vec![
                    ".js".to_string(),
                    ".jsx".to_string(),
                    ".mjs".to_string(),
                    ".cjs".to_string(),
                ]);
            }
            "typescript" | "ts" => {
                exts.extend(vec![".ts".to_string(), ".tsx".to_string()]);
            }
            "php" => {
                exts.extend(vec![".php".to_string(), ".phtml".to_string()]);
            }
            "c" => {
                exts.extend(vec![".c".to_string(), ".h".to_string()]);
            }
            "cpp" | "c++" => {
                exts.extend(vec![
                    ".cpp".to_string(),
                    ".cc".to_string(),
                    ".hpp".to_string(),
                    ".h".to_string(),
                ]);
            }
            "solidity" | "sol" => exts.push(".sol".to_string()),
            "zig" => exts.push(".zig".to_string()),
            "csharp" | "cs" | "c#" => exts.push(".cs".to_string()),
            "go" | "golang" => exts.push(".go".to_string()),
            "java" => exts.push(".java".to_string()),
            "ruby" | "rb" => exts.push(".rb".to_string()),
            "json" => exts.push(".json".to_string()),
            "yaml" | "yml" => {
                exts.extend(vec![".yaml".to_string(), ".yml".to_string()]);
            }
            other => {
                if other.starts_with('.') {
                    exts.push(other.to_string());
                } else {
                    exts.push(format!(".{other}"));
                }
            }
        }
    }
    if exts.is_empty() {
        exts.push(".rs".to_string());
    }
    exts.sort();
    exts.dedup();
    exts
}

/// Translates a Semgrep pattern into an optimized Rust regex and detects literal sensitivity.
pub fn translate_pattern_to_regex(pattern: &str) -> (String, bool) {
    let has_string_literal = pattern.contains('"') || pattern.contains('\'');
    let is_multiline = pattern.contains('\n');
    let mut out = String::with_capacity(pattern.len() * 2);

    if is_multiline {
        out.push_str("(?s)");
    }

    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    let mut i = 0;

    while i < n {
        // Lookahead A: Optional rest argument `, ...)`
        if chars[i] == ',' {
            let mut j = i + 1;
            while j < n && (chars[j] == ' ' || chars[j] == '\t') {
                j += 1;
            }
            if j + 2 < n && chars[j] == '.' && chars[j + 1] == '.' && chars[j + 2] == '.' {
                let mut k = j + 3;
                while k < n && (chars[k] == ' ' || chars[k] == '\t') {
                    k += 1;
                }
                if k < n && chars[k] == ')' {
                    out.push_str(r"(?:\s*,\s*.*?)?");
                    i = j + 3;
                    continue;
                }
            }
        }

        // Lookahead B: Optional prefix argument `(..., `
        if i + 2 < n && chars[i] == '.' && chars[i + 1] == '.' && chars[i + 2] == '.' {
            let mut j = i + 3;
            while j < n && (chars[j] == ' ' || chars[j] == '\t') {
                j += 1;
            }
            if j < n && chars[j] == ',' {
                out.push_str(r"(?:.*?\s*,\s*)?");
                i = j + 1;
                continue;
            }

            // General Ellipsis `...`
            out.push_str(".*?");
            i += 3;
            continue;
        }

        // Lookahead C: Semgrep Metavariable `$X`, `$VAR`, `$_EXPR`, `$1`
        if chars[i] == '$'
            && i + 1 < n
            && (chars[i + 1].is_ascii_uppercase() || chars[i + 1] == '_')
        {
            i += 1;
            while i < n
                && (chars[i].is_ascii_uppercase()
                    || chars[i].is_ascii_digit()
                    || chars[i] == '_')
            {
                i += 1;
            }
            out.push_str(r"([^,;\)\s]+?)");
            continue;
        }

        // Literal dollar sign (e.g. PHP variable $this, $user)
        if chars[i] == '$' {
            out.push_str(r"\$");
            i += 1;
            continue;
        }

        // Regex escaping and whitespace normalization
        match chars[i] {
            '(' => out.push_str(r"\s*\(\s*"),
            ')' => out.push_str(r"\s*\)"),
            '[' => out.push_str(r"\s*\[\s*"),
            ']' => out.push_str(r"\s*\]"),
            '{' => out.push_str(r"\s*\{\s*"),
            '}' => out.push_str(r"\s*\}"),
            '.' => out.push_str(r"\."),
            '+' => out.push_str(r"\+"),
            '*' => out.push_str(r"\*"),
            '?' => out.push_str(r"\?"),
            '^' => out.push_str(r"\^"),
            '|' => out.push_str(r"\|"),
            '\\' => out.push_str(r"\\"),
            ',' => out.push_str(r"\s*,\s*"),
            '=' => out.push_str(r"\s*=\s*"),
            ' ' | '\t' => {
                if !out.ends_with(r"\s*") && !out.ends_with(r"\s+") {
                    out.push_str(r"\s+");
                }
            }
            '\r' | '\n' => {
                if !out.ends_with(r"\s*") && !out.ends_with(r"\s+") {
                    out.push_str(r"\s*");
                }
            }
            other => out.push(other),
        }
        i += 1;
    }

    (out, has_string_literal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginEngine;

    #[test]
    fn test_parse_yaml_single_rule() {
        let yaml = r#"
rules:
  - id: python-pickle-loads
    languages: [python]
    severity: ERROR
    message: "Avoid using pickle.loads() with untrusted data."
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
      category: security
      confidence: HIGH
    pattern: "pickle.loads($X)"
"#;
        let file = SemgrepImporter::parse_yaml(yaml).expect("Valid YAML should parse");
        assert_eq!(file.rules.len(), 1);
        let rule = &file.rules[0];
        assert_eq!(rule.id, "python-pickle-loads");
        assert_eq!(rule.languages, vec!["python"]);
        assert_eq!(rule.severity, "ERROR");
        assert_eq!(rule.pattern.as_deref(), Some("pickle.loads($X)"));
    }

    #[test]
    fn test_parse_yaml_variations() {
        let yaml = r#"
rules:
  - id: test-either-not
    languages: [rust, py]
    severity: WARNING
    message: "Test message"
    metadata:
      cwe:
        - "CWE-89"
        - "CWE-79"
      category: "crypto"
    pattern-either:
      - pattern: "eval($X)"
      - pattern-regex: "danger\\(.*\\)"
    pattern-not:
      - pattern: "eval(safe_val)"
"#;
        let file = SemgrepImporter::parse_yaml(yaml).expect("YAML with either and not clauses should parse");
        assert_eq!(file.rules.len(), 1);
        let rule = &file.rules[0];
        assert_eq!(rule.pattern_either.as_ref().unwrap().len(), 2);
        assert!(rule.pattern_not.is_some());
    }

    #[test]
    fn test_metavariable_translation() {
        let (re_str, has_lit) = translate_pattern_to_regex("pickle.loads($X)");
        assert!(!has_lit);
        let re = Regex::new(&re_str).expect("Generated regex must be valid");
        assert!(re.is_match("pickle.loads(untrusted_payload)"));
        assert!(re.is_match("pickle.loads( req.body )"));
        assert!(!re.is_match("pickle.dumps(untrusted_payload)"));

        let (re_two, _) = translate_pattern_to_regex("foo($A, $B)");
        let re2 = Regex::new(&re_two).expect("Two metavariable regex must be valid");
        assert!(re2.is_match("foo(arg1, arg2)"));
    }

    #[test]
    fn test_ellipsis_translation() {
        let (re_ellipsis, _) = translate_pattern_to_regex("func(...)");
        let re = Regex::new(&re_ellipsis).expect("Ellipsis regex must be valid");
        assert!(re.is_match("func()"));
        assert!(re.is_match("func(1, 2, 3)"));

        let (re_optional_rest, _) = translate_pattern_to_regex("func($X, ...)");
        let re_rest = Regex::new(&re_optional_rest).expect("Optional rest regex must be valid");
        assert!(re_rest.is_match("func(single_arg)"));
        assert!(re_rest.is_match("func(first_arg, second, third)"));
    }

    #[test]
    fn test_translate_pattern_detects_literals() {
        let (_, lit1) = translate_pattern_to_regex("algorithms=['none']");
        assert!(lit1);

        let (_, lit2) = translate_pattern_to_regex("eval($X)");
        assert!(!lit2);
    }

    #[test]
    fn test_cwe_normalization() {
        assert_eq!(
            normalize_cwe_string("CWE-89: SQL Injection"),
            "CWE-89 / SQL-INJECTION"
        );
        assert_eq!(normalize_cwe_string("CWE-502"), "CWE-502");
        assert_eq!(normalize_cwe_string("cwe-79"), "CWE-79");
        assert_eq!(normalize_cwe_string("89"), "CWE-89 / GENERAL");
        assert_eq!(
            normalize_cwe_string("Deserialization"),
            "CWE-699 / DESERIALIZATION"
        );
    }

    #[test]
    fn test_languages_to_extensions() {
        let langs = vec!["python".to_string(), "rust".to_string()];
        let exts = languages_to_extensions(&langs);
        assert_eq!(exts, vec![".py".to_string(), ".rs".to_string()]);

        let js_ts = vec!["javascript".to_string(), "typescript".to_string()];
        let exts_js = languages_to_extensions(&js_ts);
        assert!(exts_js.contains(&".js".to_string()));
        assert!(exts_js.contains(&".ts".to_string()));
    }

    #[test]
    fn test_convert_to_plugin_manifest() {
        let yaml = r#"
rules:
  - id: custom-semgrep-rule
    languages: [python]
    severity: ERROR
    message: "Arbitrary code execution risk"
    metadata:
      cwe: "CWE-94: Code Injection"
      category: "security"
    pattern: "eval($EXPR)"
    pattern-not: "eval(safe_eval($X))"
"#;
        let manifest = convert_semgrep_yaml(yaml).expect("Should convert to PluginManifest");
        assert_eq!(manifest.rules.len(), 1);
        let rule = &manifest.rules[0];
        assert_eq!(rule.id, "custom-semgrep-rule");
        assert_eq!(rule.cwe_id, "CWE-94 / CODE-INJECTION");
        assert_eq!(rule.severity, "CRITICAL");
        assert!(rule.conditions.must_not_contain.contains(&"safe_eval".to_string()));
    }

    #[test]
    fn test_end_to_end_plugin_engine_evaluation() {
        let yaml = r#"
rules:
  - id: eval-injection
    languages: [python]
    severity: ERROR
    message: "Untrusted eval call detected"
    metadata:
      cwe: "CWE-95: Eval Injection"
    pattern: "eval($X)"
    pattern-not: "safe_eval"
"#;
        let manifest = convert_semgrep_yaml(yaml).expect("Conversion ok");
        let manifest_yaml = serde_yaml::to_string(&manifest).expect("YAML serialize ok");

        let mut engine = PluginEngine::new();
        engine
            .load_from_str(&manifest_yaml)
            .expect("PluginEngine should load manifest");

        // 1. Vulnerable code should trigger
        let vulnerable_code = "result = eval(user_input)\n";
        let violations = engine.audit_file("test.py", vulnerable_code);
        assert_eq!(violations.len(), 1, "Should trigger violation on vulnerable code");
        assert_eq!(violations[0].rule_id, "eval-injection");

        // 2. Safe/mitigated code should not trigger
        let safe_code = "result = safe_eval(user_input)\n";
        let clean_violations = engine.audit_file("test.py", safe_code);
        assert_eq!(clean_violations.len(), 0, "Mitigated code should not trigger");
    }
}
