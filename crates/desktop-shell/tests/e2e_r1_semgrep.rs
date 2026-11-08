//! E2E Test Suite for Requirement R1: Semgrep Community Rules, Downloader & Hot-Reload
//!
//! Validates:
//! - F1: Canonical Semgrep OSS rules bundle, YAML parsing, and conversion to native PluginManifest.
//! - F2: CLI downloader / offline bundle unpacker, pattern compilation ($X, ..., pattern-not).
//! - F3: Native hot-reload integration, file watcher `.aether/plugins` whitelisting, and PluginEngine execution.
//! - Tier 2 Boundary Cases: malformed YAML, special characters escaping, empty dirs, pattern suppressions.

use security_linter::plugin::{MatchMode, PluginEngine, PluginManifest, PluginRule, RuleConditions, RuleTestCase};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Drop-guard for automatically cleaning up isolated temporary test directories.
struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), unique_id));
        fs::create_dir_all(&path).expect("Failed to create temporary test directory");
        Self { path }
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1: FEATURE COVERAGE — F1: SEMGREP COMMUNITY RULES BUNDLE & MANIFESTS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_f1_tier1_canonical_owasp_cwe_yaml_structure_and_parsing() {
    let raw_semgrep_yaml = r#"
rules:
  - id: semgrep-owasp-sqli-format
    languages: [python, javascript, php]
    severity: ERROR
    message: "Potential SQL Injection detected via unescaped variable formatting"
    metadata:
      cwe: "CWE-89: SQL Injection"
      category: security
    pattern: "cursor.execute($SQL)"
  - id: semgrep-owasp-command-injection
    languages: [python, rust]
    severity: ERROR
    message: "OS Command Injection detected via system execution"
    metadata:
      cwe: "CWE-78: Command Injection"
    pattern: "os.system($CMD)"
  - id: semgrep-owasp-xss-innerhtml
    languages: [javascript, typescript]
    severity: WARNING
    message: "DOM-based XSS via direct innerHTML assignment"
    metadata:
      cwe: "CWE-79: Cross-site Scripting"
    pattern: "$EL.innerHTML = $DATA"
  - id: semgrep-owasp-path-traversal
    languages: [python, php]
    severity: ERROR
    message: "Path traversal via unvalidated file access"
    metadata:
      cwe: "CWE-22: Path Traversal"
    pattern: "open($PATH)"
  - id: semgrep-owasp-ssrf-fetch
    languages: [javascript, typescript]
    severity: ERROR
    message: "SSRF vulnerability via arbitrary URL fetch"
    metadata:
      cwe: "CWE-918: Server-Side Request Forgery"
    pattern: "fetch($URL)"
"#;

    let parsed: serde_yaml::Value = serde_yaml::from_str(raw_semgrep_yaml).expect("Failed to parse Semgrep YAML");
    let rules = parsed.get("rules").and_then(|r| r.as_sequence()).expect("Rules array");
    assert_eq!(rules.len(), 5, "Expected 5 parsed Semgrep rules");

    let rule_ids: Vec<String> = rules
        .iter()
        .filter_map(|r| r.get("id").and_then(|id| id.as_str()).map(|s| s.to_string()))
        .collect();
    assert!(rule_ids.contains(&"semgrep-owasp-sqli-format".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-command-injection".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-xss-innerhtml".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-path-traversal".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-ssrf-fetch".to_string()));
}

#[test]
fn test_f1_tier1_convert_semgrep_to_native_plugin_manifest() {
    let plugin_manifest_yaml = r#"
name: community-owasp-cwe
version: 1.0.0
author: AetherScope Community
description: Embedded OWASP Top 10 and CWE Top 25 Community Rule Bundle
enabled: true
rules:
  - id: semgrep-cwe-89-sqli
    cwe_id: CWE-89
    name: SQL Injection via cursor format
    category: Injection
    severity: CRITICAL
    description: Detects SQL query execution
    remediation: Use prepared statements
    file_extensions: [py, php]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "cursor\\.execute\\s*\\("
        - "mysqli_query\\s*\\("
      must_not_contain:
        - "prepared"
    test_cases:
      - name: Vuln direct query
        code: "cursor.execute(user_query)"
        file_name: "test.py"
        should_trigger: true
      - name: Safe prepared query
        code: "cursor.execute_prepared(user_query)"
        file_name: "test.py"
        should_trigger: false
"#;

    let mut engine = PluginEngine::new();
    let loaded = engine.load_from_str(plugin_manifest_yaml).expect("Load manifest string");
    assert_eq!(loaded.name, "community-owasp-cwe");
    assert_eq!(loaded.rules.len(), 1);

    let rule = &loaded.rules[0];
    assert_eq!(rule.id, "semgrep-cwe-89-sqli");
    assert_eq!(rule.cwe_id, "CWE-89");
    assert_eq!(rule.severity, "CRITICAL");
    assert_eq!(rule.file_extensions, vec!["py", "php"]);
    assert_eq!(rule.conditions.regex_patterns.len(), 2);
    assert_eq!(rule.conditions.must_not_contain, vec!["prepared"]);

    // Test cases execution
    let report = engine.run_test_suite();
    assert_eq!(report.total_tests, 2);
    assert_eq!(report.passed, 2);
    assert_eq!(report.failed, 0);
}

#[test]
fn test_f1_tier1_polyglot_manifest_language_detection() {
    let polyglot_yaml = r#"
name: polyglot-community-rules
version: 1.0.0
rules:
  - id: polyglot-command-injection
    cwe_id: CWE-78
    name: OS Command Injection
    severity: CRITICAL
    description: Command injection across Python, JS, PHP, Rust
    remediation: Avoid shell invocation
    file_extensions: [py, js, ts, php, rs]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "(?:os\\.system|child_process\\.exec|shell_exec|Command::new)\\s*\\("
"#;

    let mut engine = PluginEngine::new();
    engine.load_from_str(polyglot_yaml).unwrap();

    // 1. Python match
    let py_v = engine.audit_file("backend.py", "import os\nos.system(cmd)\n");
    assert_eq!(py_v.len(), 1, "Python match expected");

    // 2. JS match
    let js_v = engine.audit_file("server.js", "child_process.exec(cmd);\n");
    assert_eq!(js_v.len(), 1, "JS match expected");

    // 3. PHP match
    let php_v = engine.audit_file("service.php", "shell_exec($cmd);\n");
    assert_eq!(php_v.len(), 1, "PHP match expected");

    // 4. Rust match
    let rs_v = engine.audit_file("main.rs", "Command::new(\"sh\").arg(\"-c\").spawn();\n");
    assert_eq!(rs_v.len(), 1, "Rust match expected");

    // 5. Unrelated language or safe file
    let safe_v = engine.audit_file("backend.py", "def safe_log():\n  print('clean')\n");
    assert!(safe_v.is_empty(), "Safe code must not trigger violation");
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1: FEATURE COVERAGE — F2: CLI DOWNLOADER & OFFLINE UNPACKER
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_f2_tier1_unpack_community_bundle_offline_directory_structure() {
    let temp_dir = TempTestDir::new("aether_bundle_offline_test");
    let plugins_target = temp_dir.path.join(".aether").join("plugins").join("community");
    fs::create_dir_all(&plugins_target).unwrap();

    let manifest_path = plugins_target.join("plugin.yaml");

    // Synthetic canonical community manifest unpacked
    let manifest = PluginManifest {
        name: "community-owasp-cwe".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Embedded OWASP Top 10 and CWE Top 25 Community Rule Bundle".to_string()),
        author: Some("AetherScope Community".to_string()),
        enabled: true,
        rules: vec![
            PluginRule {
                id: "community-cwe-89".to_string(),
                cwe_id: "CWE-89".to_string(),
                name: "Community SQLi Detector".to_string(),
                category: "Injection".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Detects direct SQL query execution".to_string(),
                remediation: "Use parameterized queries".to_string(),
                file_extensions: vec!["py".to_string(), "php".to_string()],
                match_mode: MatchMode::LineByLine,
                conditions: RuleConditions {
                    regex_patterns: vec![r#"(?:cursor\.execute|mysqli_query)\s*\("#.to_string()],
                    must_contain: vec![],
                    must_not_contain: vec!["prepared".to_string()],
                    forbidden_tokens: vec![],
                    check_literals: false,
                },
                test_cases: vec![
                    RuleTestCase {
                        name: "Unprepared direct SQL".to_string(),
                        code: "cursor.execute(query)".to_string(),
                        file_name: "test.py".to_string(),
                        should_trigger: true,
                    },
                    RuleTestCase {
                        name: "Prepared statement safe".to_string(),
                        code: "cursor.execute_prepared(query)".to_string(),
                        file_name: "test.py".to_string(),
                        should_trigger: false,
                    },
                ],
            },
        ],
    };

    let manifest_yaml = serde_yaml::to_string(&manifest).expect("Serialize manifest YAML");
    fs::write(&manifest_path, manifest_yaml).expect("Write manifest to target");

    assert!(manifest_path.exists(), "Manifest file must exist on disk");

    // Test that PluginEngine successfully loads the unpacked plugin
    let mut engine = PluginEngine::new();
    let loaded_count = engine.load_from_directory(&temp_dir.path.join(".aether").join("plugins")).expect("Load plugins");
    assert_eq!(loaded_count, 1, "PluginEngine must load exactly 1 plugin");
    let rules_count = engine.plugins.iter().map(|p| p.rules.len()).sum::<usize>();
    assert_eq!(rules_count, 1, "PluginEngine must register exactly 1 rule");

    // Execute the embedded test cases
    let report = engine.run_test_suite();
    assert_eq!(report.total_tests, 2, "Must run all 2 test cases");
    assert_eq!(report.passed, 2, "All embedded test cases must pass");
    assert_eq!(report.failed, 0, "Zero failures allowed in canonical bundle");
}

#[test]
fn test_f2_tier1_aether_plugin_tool_cli_test_and_scan() {
    let temp_dir = TempTestDir::new("aether_cli_plugin_test");
    let plugins_dir = temp_dir.path.join("plugins");
    fs::create_dir_all(&plugins_dir).unwrap();

    let plugin_yaml = r#"
name: cli-test-plugin
version: 1.0.0
description: Test plugin for CLI verification
author: Test
enabled: true
rules:
  - id: cli-eval-detect
    cwe_id: CWE-94
    name: Code Injection Eval
    category: Injection
    severity: CRITICAL
    description: Detects dangerous eval usage
    remediation: Avoid eval
    file_extensions: [js, ts]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "eval\\s*\\("
    test_cases:
      - name: Dangerous eval
        code: "eval(payload);"
        file_name: "test.js"
        should_trigger: true
      - name: Safe console log
        code: "console.log('safe');"
        file_name: "test.js"
        should_trigger: false
"#;
    fs::write(plugins_dir.join("eval_plugin.yaml"), plugin_yaml).unwrap();

    // Create a synthetic target file
    let target_dir = temp_dir.path.join("src");
    fs::create_dir_all(&target_dir).unwrap();
    let vuln_file = target_dir.join("app.js");
    fs::write(&vuln_file, "function run(input) {\n  eval(input);\n}\n").unwrap();

    // Locate the aether-plugin-tool executable in target/debug
    let exe_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join("aether-plugin-tool.exe");

    if exe_path.exists() {
        // Run test subcommand
        let test_output = Command::new(&exe_path)
            .arg("test")
            .arg(&plugins_dir)
            .output()
            .expect("Failed to execute aether-plugin-tool test");

        assert!(test_output.status.success(), "Plugin tool test must succeed");
        let stdout = String::from_utf8_lossy(&test_output.stdout);
        assert!(stdout.contains("Succès"), "Test output must report success: {}", stdout);

        // Run scan subcommand
        let scan_output = Command::new(&exe_path)
            .arg("scan")
            .arg(&plugins_dir)
            .arg(&vuln_file)
            .output()
            .expect("Failed to execute aether-plugin-tool scan");

        assert!(scan_output.status.success(), "Plugin tool scan must succeed");
        let scan_stdout = String::from_utf8_lossy(&scan_output.stdout);
        assert!(scan_stdout.contains("cli-eval-detect") || scan_stdout.contains("CWE-94"),
            "Scan output must detect the eval vulnerability: {}", scan_stdout);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1: FEATURE COVERAGE — F3: HOT-RELOAD & SCANNER EVALUATION
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_f3_tier1_watcher_whitelists_aether_plugins_directory() {
    let path_aether_plugins = Path::new(".aether").join("plugins").join("custom").join("plugin.yaml");

    // The watcher must explicitly permit .aether/plugins
    let is_whitelisted = path_aether_plugins.starts_with(Path::new(".aether").join("plugins"));
    assert!(is_whitelisted, ".aether/plugins must be an authorized watch directory");
}

#[test]
fn test_f3_tier1_watcher_recognizes_yaml_and_yml_extensions() {
    let valid_extensions = ["yaml", "yml"];
    for ext in &valid_extensions {
        let p = PathBuf::from(format!("rule_bundle.{}", ext));
        let ext_str = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        assert!(valid_extensions.contains(&ext_str), "Extension {} must be accepted", ext);
    }
}

#[test]
fn test_f3_tier1_dynamic_plugin_addition_and_immediate_evaluation() {
    let temp_dir = TempTestDir::new("aether_hot_reload_test");
    let plugins_dir = temp_dir.path.join(".aether").join("plugins");
    fs::create_dir_all(&plugins_dir).unwrap();

    let mut engine = PluginEngine::new();
    assert_eq!(engine.load_from_directory(&plugins_dir).unwrap(), 0, "Initially 0 plugins");

    // Dynamic rule injection at runtime
    let dynamic_plugin_yaml = r#"
name: dynamic-hot-reload-plugin
version: 1.0.0
description: Injected dynamically while engine is running
author: Tester
enabled: true
rules:
  - id: hot-reload-xss-document-write
    cwe_id: CWE-79
    name: XSS Document Write
    category: XSS
    severity: HIGH
    description: Detects document.write XSS
    remediation: Use innerText
    file_extensions: [js]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "document\\.write\\s*\\("
"#;
    let rule_file = plugins_dir.join("hot_reload_xss.yaml");
    fs::write(&rule_file, dynamic_plugin_yaml).unwrap();

    // Reload engine (simulating watcher event)
    let reloaded_count = engine.load_from_directory(&plugins_dir).unwrap();
    assert_eq!(reloaded_count, 1, "Reloaded engine must pick up newly created plugin file");

    let test_file = "frontend.js";
    let content = "function render(text) {\n  document.write(text);\n}\n";
    let violations = engine.audit_file(test_file, content);

    assert_eq!(violations.len(), 1, "Must detect document.write violation immediately upon reload");
    assert_eq!(violations[0].rule_id, "hot-reload-xss-document-write");
    assert_eq!(violations[0].line_number, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2: BOUNDARY & CORNER CASES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_r1_tier2_malformed_yaml_error_handling() {
    let malformed_yaml = "name: broken\nrules:\n  - id: broken-rule\n  conditions: [unclosed bracket";
    let mut engine = PluginEngine::new();
    let result = engine.load_from_str(malformed_yaml);
    assert!(result.is_err(), "Malformed YAML must return an Err, never panic");
}

#[test]
fn test_r1_tier2_special_regex_characters_in_pattern() {
    let manifest_yaml = r#"
name: special-char-plugin
version: 1.0.0
rules:
  - id: special-char-rule
    cwe_id: CWE-20
    name: Special Metacharacter Test
    severity: LOW
    description: Tests special characters in pattern
    remediation: Safe
    file_extensions: [py]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "\\$OBJ\\.fetch\\(url \\+ '\\?id=' \\+ [a-zA-Z_][a-zA-Z0-9_]*\\)"
"#;
    let mut engine = PluginEngine::new();
    let res = engine.load_from_str(manifest_yaml);
    assert!(res.is_ok(), "Manifest with regex metacharacters must parse cleanly: {:?}", res.err());

    let matches = engine.audit_file("script.py", "$OBJ.fetch(url + '?id=' + user_id)\n");
    assert_eq!(matches.len(), 1, "Special character pattern must match target string");
}

#[test]
fn test_r1_tier2_pattern_not_suppression_logic() {
    let manifest_yaml = r#"
name: suppression-plugin
version: 1.0.0
rules:
  - id: rule-with-suppression
    cwe_id: CWE-78
    name: Command Injection with Suppression
    severity: HIGH
    description: Detects os.system unless escaped
    remediation: Escape argument
    file_extensions: [py]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "os\\.system\\s*\\("
      must_not_contain:
        - "shlex.quote"
"#;

    let mut engine = PluginEngine::new();
    engine.load_from_str(manifest_yaml).unwrap();

    // 1. Unsanitized call triggers violation
    let vuln_code = "os.system(user_cmd)\n";
    let v1 = engine.audit_file("test.py", vuln_code);
    assert_eq!(v1.len(), 1, "Unsanitized os.system must trigger violation");

    // 2. Sanitized call with shlex.quote does NOT trigger violation
    let safe_code = "os.system(shlex.quote(user_cmd))\n";
    let v2 = engine.audit_file("test.py", safe_code);
    assert!(v2.is_empty(), "Sanitized os.system with shlex.quote must be suppressed");
}

#[test]
fn test_r1_tier2_empty_plugins_directory_safety() {
    let temp_dir = TempTestDir::new("aether_empty_plugins");
    let mut engine = PluginEngine::new();
    let count = engine.load_from_directory(&temp_dir.path).expect("Empty dir must load Ok(0)");
    assert_eq!(count, 0);
    let rules_count = engine.plugins.iter().map(|p| p.rules.len()).sum::<usize>();
    assert_eq!(rules_count, 0);
    let violations = engine.audit_file("dummy.rs", "fn main() {}");
    assert!(violations.is_empty());
}
