//! Unit and integration tests for Semgrep Community Bundle (OWASP Top 10 & CWE Top 25)

use security_linter::community_bundle::CommunityBundle;
use security_linter::plugin::PluginEngine;
use std::fs;
use std::path::Path;

#[test]
fn test_community_bundle_embedded_manifest_loading() {
    let manifest = CommunityBundle::load_embedded_manifest()
        .expect("Embedded community bundle must parse and convert without error");

    assert_eq!(manifest.name, "community");
    assert!(manifest.enabled);
    assert!(
        manifest.rules.len() >= 20,
        "Expected at least 20 rules in community bundle, found {}",
        manifest.rules.len()
    );

    // Verify key CWE categories are covered
    let rule_ids: Vec<String> = manifest.rules.iter().map(|r| r.id.clone()).collect();
    let cwe_ids: Vec<String> = manifest.rules.iter().map(|r| r.cwe_id.clone()).collect();

    assert!(rule_ids.contains(&"semgrep-owasp-sqli-format".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-command-injection".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-xss-innerhtml".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-path-traversal".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-deserialization-pickle".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-hardcoded-secret".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-ssrf-unvalidated-url".to_string()));
    assert!(rule_ids.contains(&"semgrep-owasp-code-injection-eval".to_string()));

    // Verify CWE normalization
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-89")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-78")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-79")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-22")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-502")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-798")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-918")));
    assert!(cwe_ids.iter().any(|c| c.contains("CWE-94")));
}

#[test]
fn test_community_bundle_unpack_to_directory() {
    let temp_dir = std::env::temp_dir().join(format!("aether_bundle_test_{}", std::process::id()));
    if temp_dir.exists() {
        let _ = fs::remove_dir_all(&temp_dir);
    }
    fs::create_dir_all(&temp_dir).unwrap();

    let unpacked_file = CommunityBundle::unpack_to_directory(&temp_dir)
        .expect("CommunityBundle unpack_to_directory should succeed");

    assert!(unpacked_file.exists());
    assert!(unpacked_file.ends_with(Path::new("community").join("plugin.yaml")));

    // Verify content is valid YAML and reloadable by PluginEngine
    let mut engine = PluginEngine::new();
    let loaded = engine
        .load_from_directory(&temp_dir)
        .expect("PluginEngine should load the unpacked community bundle");
    assert_eq!(loaded, 1);
    assert_eq!(engine.plugins.len(), 1);
    assert!(engine.plugins[0].rules.len() >= 20);

    // Test idempotency when passing the community dir directly
    let community_dir = temp_dir.join("community");
    let re_unpacked = CommunityBundle::unpack_to_directory(&community_dir)
        .expect("Unpacking directly into community dir should succeed");
    assert_eq!(re_unpacked, unpacked_file);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_community_bundle_audits_vulnerable_code_snippets() {
    let manifest = CommunityBundle::load_embedded_manifest().unwrap();
    let mut engine = PluginEngine::new();
    engine.plugins.push(manifest);

    // 1. SQL Injection (Python)
    let sqli_snippet = r#"
def get_user(cursor, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"#;
    let v_sqli = engine.audit_file("src/db.py", sqli_snippet);
    assert!(
        v_sqli.iter().any(|v| v.rule_id == "semgrep-owasp-sqli-format"),
        "Expected semgrep-owasp-sqli-format violation in: {:?}",
        v_sqli
    );

    // 2. OS Command Injection (Python)
    let cmd_snippet = r#"
import os
def backup(target):
    cmd = "tar -czf backup.tar.gz " + target
    os.system(cmd)
"#;
    let v_cmd = engine.audit_file("src/backup.py", cmd_snippet);
    assert!(
        v_cmd.iter().any(|v| v.rule_id == "semgrep-owasp-command-injection"),
        "Expected semgrep-owasp-command-injection violation in: {:?}",
        v_cmd
    );

    // 3. XSS via innerHTML (JavaScript)
    let xss_snippet = r#"
function renderBanner(userInput) {
    const banner = document.getElementById("banner");
    banner.innerHTML = userInput;
}
"#;
    let v_xss = engine.audit_file("src/banner.js", xss_snippet);
    assert!(
        v_xss.iter().any(|v| v.rule_id == "semgrep-owasp-xss-innerhtml"),
        "Expected semgrep-owasp-xss-innerhtml violation in: {:?}",
        v_xss
    );

    // 4. Path Traversal (Python)
    let path_snippet = r#"
def read_log(user_filename):
    user_path = "/var/logs/" + user_filename
    f = open(user_path, "r")
    return f.read()
"#;
    let v_path = engine.audit_file("src/logs.py", path_snippet);
    assert!(
        v_path.iter().any(|v| v.rule_id == "semgrep-owasp-path-traversal"),
        "Expected semgrep-owasp-path-traversal violation in: {:?}",
        v_path
    );

    // 5. Pickle Insecure Deserialization (Python)
    let pickle_snippet = r#"
import pickle
def load_session(data):
    return pickle.loads(data)
"#;
    let v_pickle = engine.audit_file("src/session.py", pickle_snippet);
    assert!(
        v_pickle.iter().any(|v| v.rule_id == "semgrep-owasp-deserialization-pickle"),
        "Expected semgrep-owasp-deserialization-pickle violation in: {:?}",
        v_pickle
    );

    // 6. Hardcoded Secret (Python)
    let secret_snippet = r#"
def authenticate():
    api_key = "sk_live_998877665544332211"
    return api_key
"#;
    let v_secret = engine.audit_file("src/auth.py", secret_snippet);
    assert!(
        v_secret.iter().any(|v| v.rule_id == "semgrep-owasp-hardcoded-secret"),
        "Expected semgrep-owasp-hardcoded-secret violation in: {:?}",
        v_secret
    );

    // 7. SSRF Unvalidated URL (Python)
    let ssrf_snippet = r#"
import requests
def fetch_avatar(target_url):
    return requests.get(target_url)
"#;
    let v_ssrf = engine.audit_file("src/avatar.py", ssrf_snippet);
    assert!(
        v_ssrf.iter().any(|v| v.rule_id == "semgrep-owasp-ssrf-unvalidated-url"),
        "Expected semgrep-owasp-ssrf-unvalidated-url violation in: {:?}",
        v_ssrf
    );

    // 8. Dynamic Code Injection (JavaScript)
    let eval_snippet = r#"
function computeFormula(expr) {
    return eval(expr);
}
"#;
    let v_eval = engine.audit_file("src/calculator.js", eval_snippet);
    assert!(
        v_eval.iter().any(|v| v.rule_id == "semgrep-owasp-code-injection-eval"),
        "Expected semgrep-owasp-code-injection-eval violation in: {:?}",
        v_eval
    );
}

#[test]
fn test_community_bundle_safe_code_produces_no_violations() {
    let manifest = CommunityBundle::load_embedded_manifest().unwrap();
    let mut engine = PluginEngine::new();
    engine.plugins.push(manifest);

    let clean_code = r#"
def safe_math(a, b):
    return a + b

def sanitize_name(name):
    return name.strip().lower()
"#;

    let violations = engine.audit_file("src/math_utils.py", clean_code);
    assert!(
        violations.is_empty(),
        "Safe code should produce zero violations, found: {:?}",
        violations
    );
}
