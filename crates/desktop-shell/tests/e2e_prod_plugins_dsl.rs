//! Opaque-box End-to-End Test Suite for R1: Plugin Architecture & Enriched DSL
//!
//! Covers:
//! - F-E2E-1: CLI `--plugins` Selection & Filtering (`omitted`, `auto`, `all`, pack(s), `profile:<name>`)
//! - F-E2E-2: Enriched DSL Contextual Windowing (`not_preceded_within_lines`, `in_path_matching`, `not_in_path_matching`, `ast_scope`)
//! - F-E2E-3: Enriched DSL SSA Dataflow Taint (`taint_sources`, `taint_sinks`, `sanitizers`)
//! - F-E2E-4: Native Rule Parity & `.aether/plugins/` Backwards Compatibility (7 languages + Semgrep/CommunityBundle)
//!
//! Structure: Tiers 1–4 (53 tests total).
//! All tests are strictly opaque-box (invoking `aether-engine` in isolated `tempfile::tempdir()` workspaces).

use security_linter::plugin::PluginManifest;
use security_linter::semgrep_importer::SemgrepImporter;
use serde_json::Value;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Opaque-box CLI & SARIF Test Harness
// ─────────────────────────────────────────────────────────────────────────────

fn aether_bin() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_aether-engine") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb;
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let exe_name = if cfg!(windows) {
        "aether-engine.exe"
    } else {
        "aether-engine"
    };
    let debug_bin = workspace_root.join("target").join("debug").join(exe_name);
    if debug_bin.exists() {
        return debug_bin;
    }
    workspace_root.join("target").join("release").join(exe_name)
}

fn unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

struct CliResult {
    code: i32,
    success: bool,
    stdout: String,
    stderr: String,
}

struct TestRepo {
    dir: TempDir,
}

impl TestRepo {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("create isolated tempdir"),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write_file(&self, rel_path: &str, content: &str) {
        let full = self.path().join(rel_path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&full, content).expect("write fixture file");
    }

    fn write_plugin(&self, plugin_dir_name: &str, yaml_content: &str) {
        let rel = format!(".aether/plugins/{}/plugin.yaml", plugin_dir_name);
        self.write_file(&rel, yaml_content);
    }

    fn run_cli_raw(&self, args: &[&str]) -> CliResult {
        let bin = aether_bin();
        assert!(
            bin.exists(),
            "aether-engine binary not found at {}; build it first",
            bin.display()
        );
        let out = Command::new(&bin)
            .current_dir(self.path())
            .args(args)
            .output()
            .expect("spawn aether-engine");
        CliResult {
            code: out.status.code().unwrap_or(-1),
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        }
    }

    fn run_audit_sarif(&self, extra_args: &[&str]) -> (CliResult, Option<Value>) {
        let port = unused_port().to_string();
        let sarif_path = self.path().join("out.sarif");
        let sarif_str = sarif_path.to_string_lossy().to_string();
        let path_str = self.path().to_string_lossy().to_string();

        let mut args: Vec<&str> = vec![
            "--audit-only",
            "--path",
            &path_str,
            "--port",
            &port,
            "--format",
            "sarif",
            "-o",
            &sarif_str,
        ];
        args.extend_from_slice(extra_args);

        let res = self.run_cli_raw(&args);
        let sarif = if sarif_path.exists() {
            let raw = fs::read_to_string(&sarif_path).expect("read out.sarif");
            Some(serde_json::from_str::<Value>(&raw).expect("parse valid SARIF JSON"))
        } else {
            None
        };
        (res, sarif)
    }

    fn run_audit_text(&self, extra_args: &[&str]) -> (CliResult, Option<String>) {
        let port = unused_port().to_string();
        let path_str = self.path().to_string_lossy().to_string();

        let mut args: Vec<&str> = vec!["--audit-only", "--path", &path_str, "--port", &port];
        args.extend_from_slice(extra_args);

        let res = self.run_cli_raw(&args);
        let live_audit_path = self.path().join(".aether").join("LIVE_AUDIT.md");
        let live_audit = if live_audit_path.exists() {
            Some(fs::read_to_string(&live_audit_path).expect("read LIVE_AUDIT.md"))
        } else {
            None
        };
        (res, live_audit)
    }
}

fn sarif_results(sarif: &Value) -> &[Value] {
    sarif["runs"][0]["results"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn sarif_result_rule_ids(sarif: &Value) -> Vec<String> {
    sarif_results(sarif)
        .iter()
        .filter_map(|r| r["ruleId"].as_str().map(ToString::to_string))
        .collect()
}

fn sarif_driver_rule_ids(sarif: &Value) -> Vec<String> {
    sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r["id"].as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn sarif_result_uri(res: &Value) -> &str {
    res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .unwrap_or("")
}

fn sarif_result_line(res: &Value) -> u64 {
    res["locations"][0]["physicalLocation"]["region"]["startLine"]
        .as_u64()
        .unwrap_or(0)
}

fn has_result_for_file(sarif: &Value, rule_id: &str, file_suffix: &str) -> bool {
    sarif_results(sarif).iter().any(|r| {
        r["ruleId"].as_str() == Some(rule_id)
            && sarif_result_uri(r)
                .replace('\\', "/")
                .ends_with(file_suffix)
    })
}

fn results_for_rule<'a>(sarif: &'a Value, rule_id: &str) -> Vec<&'a Value> {
    sarif_results(sarif)
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some(rule_id))
        .collect()
}

fn std_taint_plugin_yaml(name: &str, profile: Option<&str>, language: Option<&str>) -> String {
    let profile_line = profile
        .map(|p| format!("profile: \"{}\"\n", p))
        .unwrap_or_default();
    let lang_yaml = language
        .map(|l| format!("\"{}\"", l))
        .unwrap_or_else(|| "null".to_string());
    format!(
        r#"name: "{name}"
version: "1.0.0"
enabled: true
{profile_line}taint_sources:
  - name: "custom_http_query"
    source_kind: "HttpQueryParam"
    cwe: "CWE-89"
    patterns: ["extract_query(", "get_untrusted_param("]
    language: {lang_yaml}
    description: "Untrusted external query parameter"
taint_sinks:
  - name: "custom_sql_sink"
    sink_kind: "SqlExecution"
    cwe: "CWE-89"
    rule_id: "PLUGIN-TAINT-SQLI-001"
    severity: "CRITICAL"
    patterns: ["exec_raw_sql(", "db_run_raw("]
    language: {lang_yaml}
    description: "Direct SQL execution without parameterization"
sanitizers:
  - name: "sanitize_sql_param"
    target_cwes: ["CWE-89"]
    match_kind: "ExactName"
    language: {lang_yaml}
    neutralizes_all: false
rules: []
"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1 — F-E2E-1: CLI `--plugins` Selection & Filtering (5 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t1_f1_omitted_plugins_uses_default_and_local_plugins() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "custom-guard",
        r#"name: "custom-guard"
version: "1.0.0"
enabled: true
rules:
  - id: "CUSTOM-GUARD-001"
    cwe_id: "CWE-284"
    name: "Custom unsafe token"
    severity: "HIGH"
    description: "Detects forbidden custom token"
    remediation: "Remove unsafe_token_call"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["unsafe_token_call\\("]
"#,
    );
    repo.write_file(
        "src/handler.rs",
        r#"pub fn run(user_arg: &str) {
    let _ = std::process::Command::new(user_arg);
    unsafe_token_call(user_arg);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(
        res.success,
        "omitted --plugins must exit 0; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif must be created");
    let ids = sarif_result_rule_ids(&sarif);
    assert!(
        ids.iter().any(|id| id == "CVE-RUST-CMD-INJ"),
        "omitted --plugins must run default native rules; got {:?}",
        ids
    );
    assert!(
        ids.iter().any(|id| id == "CUSTOM-GUARD-001"),
        "omitted --plugins must load .aether/plugins/; got {:?}",
        ids
    );
}

#[test]
fn t1_f1_plugins_auto_selects_matching_stack() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "py-stack-guard",
        r#"name: "py-stack-guard"
version: "1.0.0"
enabled: true
rules:
  - id: "PY-STACK-CUSTOM-001"
    cwe_id: "CWE-94"
    name: "Custom Python token"
    severity: "HIGH"
    description: "Detects custom dangerous helper"
    remediation: "Avoid py_custom_danger"
    file_extensions: [".py"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["py_custom_danger\\("]
"#,
    );
    repo.write_file(
        "app/worker.py",
        r#"import os

def dispatch(cmd):
    os.system("echo " + cmd)
    py_custom_danger(cmd)
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "auto"]);
    assert!(
        res.success,
        "--plugins auto must exit 0; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);
    assert!(
        ids.iter().any(|id| id == "CVE-PY-SHELL-INJ"),
        "--plugins auto must activate Python native/migrated pack; got {:?}",
        ids
    );
    assert!(
        ids.iter().any(|id| id == "PY-STACK-CUSTOM-001"),
        "--plugins auto must include local .aether/plugins/ rule; got {:?}",
        ids
    );
}

#[test]
fn t1_f1_plugins_all_loads_all_packs() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "local-extra",
        r#"name: "local-extra"
version: "1.0.0"
enabled: true
rules:
  - id: "LOCAL-EXTRA-001"
    cwe_id: "CWE-20"
    name: "Local extra check"
    severity: "MEDIUM"
    description: "Custom check"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["extra_bad_call\\("]
"#,
    );
    repo.write_file(
        "src/core.rs",
        r#"pub fn run(arg: &str) {
    let _ = std::process::Command::new(arg);
    extra_bad_call(arg);
}
"#,
    );
    repo.write_file(
        "app/task.py",
        "import os\ndef exec_task(c):\n    os.system('echo ' + c)\n",
    );
    repo.write_file(
        "app/web.js",
        "const child_process = require('child_process');\nfunction r(c) { child_process.exec(c); }\n",
    );
    repo.write_file(
        "src/ctrl.php",
        "<?php\nfunction go($c) { return eval($c); }\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "all"]);
    assert!(
        res.success,
        "--plugins all must exit 0; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    let driver_rules = sarif_driver_rule_ids(&sarif);
    assert!(
        driver_rules.len() >= 150,
        "--plugins all must expose full rule catalog (>= 150); got {}",
        driver_rules.len()
    );
    let ids = sarif_result_rule_ids(&sarif);
    for expected in [
        "CVE-RUST-CMD-INJ",
        "CVE-PY-SHELL-INJ",
        "CVE-JS-CMD-INJ",
        "CVE-PHP-EVAL-CODE-INJECTION",
        "LOCAL-EXTRA-001",
    ] {
        assert!(
            ids.iter().any(|id| id == expected),
            "--plugins all missing finding '{}'; got {:?}",
            expected,
            ids
        );
    }
}

#[test]
fn t1_f1_plugins_single_pack_isolates_rules() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "pack-alpha",
        r#"name: "pack-alpha"
version: "1.0.0"
enabled: true
rules:
  - id: "ALPHA-RULE-001"
    cwe_id: "CWE-284"
    name: "Alpha rule"
    severity: "HIGH"
    description: "Alpha"
    remediation: "Fix alpha"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["alpha_danger_call\\("]
"#,
    );
    repo.write_plugin(
        "pack-beta",
        r#"name: "pack-beta"
version: "1.0.0"
enabled: true
rules:
  - id: "BETA-RULE-001"
    cwe_id: "CWE-284"
    name: "Beta rule"
    severity: "HIGH"
    description: "Beta"
    remediation: "Fix beta"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["beta_danger_call\\("]
"#,
    );
    repo.write_file(
        "src/app.rs",
        "pub fn run() {\n    alpha_danger_call();\n    beta_danger_call();\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "pack-alpha"]);
    assert!(
        res.success,
        "--plugins pack-alpha must exit 0; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);
    assert!(
        ids.iter().any(|id| id == "ALPHA-RULE-001"),
        "pack-alpha must fire ALPHA-RULE-001; got {:?}",
        ids
    );
    assert!(
        !ids.iter().any(|id| id == "BETA-RULE-001"),
        "pack-alpha must exclude BETA-RULE-001; got {:?}",
        ids
    );
}

#[test]
fn t1_f1_plugins_profile_filters_by_profile() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "strict-pack",
        r#"name: "strict-pack"
version: "1.0.0"
enabled: true
profile: "strict"
tags: ["prod"]
rules:
  - id: "PROF-STRICT-001"
    cwe_id: "CWE-287"
    name: "Strict profile rule"
    severity: "HIGH"
    description: "Strict"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["strict_trigger_fn\\("]
"#,
    );
    repo.write_plugin(
        "experimental-pack",
        r#"name: "experimental-pack"
version: "1.0.0"
enabled: true
profile: "experimental"
tags: ["beta"]
rules:
  - id: "PROF-EXP-001"
    cwe_id: "CWE-287"
    name: "Experimental profile rule"
    severity: "MEDIUM"
    description: "Experimental"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["exp_trigger_fn\\("]
"#,
    );
    repo.write_file(
        "src/app.rs",
        "pub fn run() {\n    strict_trigger_fn();\n    exp_trigger_fn();\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "profile:strict"]);
    assert!(
        res.success,
        "--plugins profile:strict must exit 0; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);
    assert!(
        ids.iter().any(|id| id == "PROF-STRICT-001"),
        "profile:strict must fire PROF-STRICT-001; got {:?}",
        ids
    );
    assert!(
        !ids.iter().any(|id| id == "PROF-EXP-001"),
        "profile:strict must exclude PROF-EXP-001; got {:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1 — F-E2E-2: Enriched DSL Contextual Windowing (6 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t1_f2_not_preceded_within_lines_triggers_without_guard() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "ctx-window",
        r#"name: "ctx-window"
version: "1.0.0"
enabled: true
rules:
  - id: "CTX-WINDOW-001"
    cwe_id: "CWE-284"
    name: "Unguarded dangerous op"
    severity: "HIGH"
    description: "Must be preceded by guard_ok() within 3 lines"
    remediation: "Call guard_ok() before dangerous_op()"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["dangerous_op\\("]
      not_preceded_within_lines:
        patterns: ["guard_ok\\(\\)"]
        lines: 3
"#,
    );
    repo.write_file(
        "src/ops.rs",
        "pub fn execute(x: u32) {\n    let y = x + 1;\n    dangerous_op(y);\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let hits = results_for_rule(&sarif, "CTX-WINDOW-001");
    assert_eq!(hits.len(), 1, "expected 1 CTX-WINDOW-001 hit; got {:?}", hits);
    assert_eq!(sarif_result_line(hits[0]), 3);
}

#[test]
fn t1_f2_not_preceded_within_lines_suppresses_within_window() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "ctx-window",
        r#"name: "ctx-window"
version: "1.0.0"
enabled: true
rules:
  - id: "CTX-WINDOW-001"
    cwe_id: "CWE-284"
    name: "Unguarded dangerous op"
    severity: "HIGH"
    description: "Must be preceded by guard_ok() within 3 lines"
    remediation: "Call guard_ok() before dangerous_op()"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["dangerous_op\\("]
      not_preceded_within_lines:
        patterns: ["guard_ok\\(\\)"]
        lines: 3
"#,
    );
    repo.write_file(
        "src/ops.rs",
        "pub fn execute(x: u32) {\n    guard_ok();\n    dangerous_op(x);\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        results_for_rule(&sarif, "CTX-WINDOW-001").is_empty(),
        "guard_ok() within 3 lines must suppress CTX-WINDOW-001"
    );
}

#[test]
fn t1_f2_in_path_matching_restricts_to_glob() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "path-include",
        r#"name: "path-include"
version: "1.0.0"
enabled: true
rules:
  - id: "PATH-INC-001"
    cwe_id: "CWE-284"
    name: "API-only restriction"
    severity: "HIGH"
    description: "Only applies under src/api/**"
    remediation: "Fix API call"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["raw_db_bypass\\("]
      in_path_matching: ["src/api/**"]
"#,
    );
    repo.write_file("src/api/handler.rs", "pub fn h() { raw_db_bypass(); }\n");
    repo.write_file("src/worker/job.rs", "pub fn j() { raw_db_bypass(); }\n");

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&sarif, "PATH-INC-001", "src/api/handler.rs"),
        "expected PATH-INC-001 on src/api/handler.rs"
    );
    assert!(
        !has_result_for_file(&sarif, "PATH-INC-001", "src/worker/job.rs"),
        "PATH-INC-001 must NOT trigger on src/worker/job.rs"
    );
}

#[test]
fn t1_f2_not_in_path_matching_excludes_glob() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "path-exclude",
        r#"name: "path-exclude"
version: "1.0.0"
enabled: true
rules:
  - id: "PATH-EXC-001"
    cwe_id: "CWE-284"
    name: "Exclude generated code"
    severity: "HIGH"
    description: "Skips **/generated/**"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["legacy_unsafe_api\\("]
      not_in_path_matching: ["**/generated/**"]
"#,
    );
    repo.write_file("src/prod.rs", "pub fn p() { legacy_unsafe_api(); }\n");
    repo.write_file(
        "src/generated/gen_client.rs",
        "pub fn g() { legacy_unsafe_api(); }\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&sarif, "PATH-EXC-001", "src/prod.rs"),
        "expected PATH-EXC-001 on src/prod.rs"
    );
    assert!(
        !has_result_for_file(&sarif, "PATH-EXC-001", "src/generated/gen_client.rs"),
        "PATH-EXC-001 must NOT trigger on src/generated/gen_client.rs"
    );
}

#[test]
fn t1_f2_ast_scope_outside_test_ignores_cfg_test() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "scope-outside-test",
        r#"name: "scope-outside-test"
version: "1.0.0"
enabled: true
rules:
  - id: "SCOPE-PROD-001"
    cwe_id: "CWE-284"
    name: "Production only call"
    severity: "HIGH"
    description: "Ignores #[cfg(test)]"
    remediation: "Remove forbidden_prod_op()"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["forbidden_prod_op\\("]
      ast_scope: "outside_test"
"#,
    );
    repo.write_file(
        "src/live.rs",
        "pub fn run_live() {\n    forbidden_prod_op();\n}\n",
    );
    repo.write_file(
        "src/svc.rs",
        r#"pub fn healthy() -> u32 { 1 }

#[cfg(test)]
mod tests {
    #[test]
    fn unit_case() {
        forbidden_prod_op();
    }
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&sarif, "SCOPE-PROD-001", "src/live.rs"),
        "ast_scope: outside_test must trigger on src/live.rs"
    );
    assert!(
        !has_result_for_file(&sarif, "SCOPE-PROD-001", "src/svc.rs"),
        "ast_scope: outside_test must ignore #[cfg(test)] in src/svc.rs"
    );
}

#[test]
fn t1_f2_ast_scope_async_fn_distinguishes_async_vs_sync() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "scope-async",
        r#"name: "scope-async"
version: "1.0.0"
enabled: true
rules:
  - id: "SCOPE-ASYNC-001"
    cwe_id: "CWE-400"
    name: "Blocking op in async fn"
    severity: "HIGH"
    description: "Detects blocking_custom_io() only inside async functions"
    remediation: "Use async I/O"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["blocking_custom_io\\("]
      ast_scope: "async_fn"
"#,
    );
    repo.write_file(
        "src/async_worker.rs",
        "pub async fn fetch_async() {\n    blocking_custom_io();\n}\n",
    );
    repo.write_file(
        "src/sync_worker.rs",
        "pub fn fetch_sync() {\n    blocking_custom_io();\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&sarif, "SCOPE-ASYNC-001", "src/async_worker.rs"),
        "ast_scope: async_fn must trigger inside async fn"
    );
    assert!(
        !has_result_for_file(&sarif, "SCOPE-ASYNC-001", "src/sync_worker.rs"),
        "ast_scope: async_fn must NOT trigger inside synchronous fn"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1 — F-E2E-3: Enriched DSL SSA Dataflow Taint (5 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t1_f3_plugin_taint_intra_procedural_rust() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-rust", &std_taint_plugin_yaml("taint-rust", None, None));
    repo.write_file(
        "src/handler.rs",
        r#"pub fn handle_request(req: &str) {
    let raw_id = extract_query(req);
    let sql = raw_id;
    exec_raw_sql(sql);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let hits = results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001");
    assert!(
        !hits.is_empty(),
        "expected PLUGIN-TAINT-SQLI-001 intra-procedural Rust flow; got {:?}",
        sarif_result_rule_ids(&sarif)
    );
    assert_eq!(hits[0]["properties"]["is_reachable"], Value::Bool(true));
}

#[test]
fn t1_f3_plugin_taint_inter_procedural_cross_file() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-inter", &std_taint_plugin_yaml("taint-inter", None, None));
    repo.write_file(
        "src/repo.rs",
        r#"pub fn build_query(param: String) -> String {
    let q = param;
    return q;
}
"#,
    );
    repo.write_file(
        "src/routes.rs",
        r#"pub fn api_lookup(req: &str) {
    let user_q = extract_query(req);
    let stmt = build_query(user_q);
    exec_raw_sql(stmt);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let hits = results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001");
    assert!(
        !hits.is_empty(),
        "expected cross-file inter-procedural PLUGIN-TAINT-SQLI-001; got {:?}",
        sarif_result_rule_ids(&sarif)
    );
    assert_eq!(hits[0]["properties"]["is_reachable"], Value::Bool(true));
    assert!(
        hits[0]["properties"]["exploit_path"].is_array(),
        "expected exploit_path metadata in SARIF properties"
    );
}

#[test]
fn t1_f3_plugin_taint_sanitizer_neutralizes_matching_cwe() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-san", &std_taint_plugin_yaml("taint-san", None, None));
    repo.write_file(
        "src/safe_handler.rs",
        r#"pub fn handle_request(req: &str) {
    let raw_id = extract_query(req);
    let clean_id = sanitize_sql_param(raw_id);
    exec_raw_sql(clean_id);
}
"#,
    );

    let (fail_res, _) = repo.run_audit_sarif(&["--fail-on", "CRITICAL"]);
    assert!(
        fail_res.success,
        "sanitized flow must exit 0 under --fail-on CRITICAL; stderr: {}",
        fail_res.stderr
    );
}

#[test]
fn t1_f3_plugin_taint_python_flow() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-py", &std_taint_plugin_yaml("taint-py", None, None));
    repo.write_file(
        "app/views.py",
        r#"def search_users(req):
    q = get_untrusted_param(req)
    exec_raw_sql(q)
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&sarif, "PLUGIN-TAINT-SQLI-001", "app/views.py"),
        "expected Python taint flow on app/views.py; got {:?}",
        sarif_result_rule_ids(&sarif)
    );
}

#[test]
fn t1_f3_plugin_taint_js_inter_procedural_sarif_properties() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-js", &std_taint_plugin_yaml("taint-js", None, None));
    repo.write_file(
        "app/helpers.js",
        r#"function normalizeInput(raw) {
    const forwarded = raw;
    return forwarded;
}
"#,
    );
    repo.write_file(
        "app/controller.js",
        r#"function handleSearch(req) {
    const input = extract_query(req);
    const q = normalizeInput(input);
    exec_raw_sql(q);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let hits = results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001");
    assert!(
        !hits.is_empty(),
        "expected JS inter-procedural PLUGIN-TAINT-SQLI-001; got {:?}",
        sarif_result_rule_ids(&sarif)
    );
    let hit = hits[0];
    assert_eq!(hit["level"], "error");
    assert_eq!(hit["properties"]["cveId"], "CWE-89");
    assert_eq!(hit["properties"]["is_reachable"], Value::Bool(true));
    assert!(hit["properties"]["exploit_path"].is_array());
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1 — F-E2E-4: Native Rule Parity & `.aether/plugins/` Compat (6 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t1_f4_compat_example_custom_auth_manifest() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "example-custom-auth",
        include_str!("../../../.aether/plugins/example-custom-auth/plugin.yaml"),
    );
    repo.write_file(
        "src/vuln_admin.rs",
        "pub fn admin_drop() {\n    database_drop();\n}\n",
    );
    repo.write_file(
        "src/safe_admin.rs",
        "pub fn admin_drop() {\n    if is_authenticated() {\n        database_drop();\n    }\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&sarif, "CUSTOM-EXAMPLE-CUSTOM-AUTH-001", "src/vuln_admin.rs"),
        "expected CUSTOM-EXAMPLE-CUSTOM-AUTH-001 on src/vuln_admin.rs"
    );
    assert!(
        !has_result_for_file(&sarif, "CUSTOM-EXAMPLE-CUSTOM-AUTH-001", "src/safe_admin.rs"),
        "CUSTOM-EXAMPLE-CUSTOM-AUTH-001 must NOT fire on src/safe_admin.rs"
    );
}

#[test]
fn t1_f4_compat_majestic_injections_manifest() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "majestic-injections",
        include_str!("../../../.aether/plugins/majestic-injections/plugin.yaml"),
    );
    repo.write_file(
        "src/git_vuln.rs",
        r#"pub fn clone_repo(repo_url: &str) {
    std::process::Command::new("git").arg("clone").arg(repo_url).status().unwrap();
}
"#,
    );
    repo.write_file(
        "src/git_safe.rs",
        r#"pub fn clone_repo(repo_url: &str) {
    std::process::Command::new("git").arg("clone").arg("--").arg(repo_url).status().unwrap();
}
"#,
    );
    repo.write_file(
        "app/loader_vuln.ts",
        "export async function loadPlugin(pluginUri: string) {\n    return await import(pluginUri);\n}\n",
    );
    repo.write_file(
        "app/loader_safe.ts",
        "export async function loadPlugin(pluginUri: string) {\n    return ALLOWED_PLUGINS.has(pluginUri) ? await import(pluginUri) : null;\n}\n",
    );
    repo.write_file(
        "src/avatar_vuln.php",
        "<?php\nif (file_exists($_GET['avatar'])) {\n    echo 'ok';\n}\n",
    );
    repo.write_file(
        "src/avatar_safe.php",
        "<?php\nif (file_exists(basename($_GET['avatar']))) {\n    echo 'ok';\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(has_result_for_file(
        &sarif,
        "PLUGIN-INJ-POSIX-FLAG-SMUGGLING",
        "src/git_vuln.rs"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "PLUGIN-INJ-POSIX-FLAG-SMUGGLING",
        "src/git_safe.rs"
    ));
    assert!(has_result_for_file(
        &sarif,
        "PLUGIN-INJ-FILELESS-ESM-DATA-URI",
        "app/loader_vuln.ts"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "PLUGIN-INJ-FILELESS-ESM-DATA-URI",
        "app/loader_safe.ts"
    ));
    assert!(has_result_for_file(
        &sarif,
        "PLUGIN-INJ-PHP-PHAR-STREAM-WRAPPER",
        "src/avatar_vuln.php"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "PLUGIN-INJ-PHP-PHAR-STREAM-WRAPPER",
        "src/avatar_safe.php"
    ));
}

#[test]
fn t1_f4_compat_semgrep_imported_manifest() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "sample-semgrep",
        include_str!("../../../.aether/plugins/imported/sample-semgrep/plugin.yaml"),
    );
    repo.write_file(
        "src/session_vuln.py",
        "import pickle\ndef load_obj(raw):\n    return pickle.loads(raw)\n",
    );
    repo.write_file(
        "src/session_safe.py",
        "import json\ndef load_obj(raw):\n    return json.loads(raw)\n",
    );
    repo.write_file(
        "src/jwt_vuln.py",
        "import jwt\ndef parse_tok(token):\n    return jwt.decode(token, algorithms=['none'])\n",
    );
    repo.write_file(
        "src/jwt_safe.py",
        "import jwt\ndef parse_tok(token, key):\n    return jwt.decode(token, key, algorithms=['HS256'])\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(has_result_for_file(
        &sarif,
        "python-deserialization-pickle",
        "src/session_vuln.py"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "python-deserialization-pickle",
        "src/session_safe.py"
    ));
    assert!(has_result_for_file(
        &sarif,
        "jwt-none-algorithm",
        "src/jwt_vuln.py"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "jwt-none-algorithm",
        "src/jwt_safe.py"
    ));
}

#[test]
fn t1_f4_semgrep_update_rules_and_importer_parity() {
    // Part A: `aether-engine --update-rules` hydrates CommunityBundle and detects rules via CLI
    let repo_a = TestRepo::new();
    let path_str = repo_a.path().to_string_lossy().to_string();
    let port_str = unused_port().to_string();
    let upd = repo_a.run_cli_raw(&[
        "--update-rules",
        "--no-gui",
        "--path",
        &path_str,
        "--port",
        &port_str,
    ]);
    assert!(
        upd.success,
        "--update-rules --no-gui must succeed; stdout: {}; stderr: {}",
        upd.stdout,
        upd.stderr
    );
    let unpacked_manifest = repo_a
        .path()
        .join(".aether")
        .join("plugins")
        .join("community")
        .join("plugin.yaml");
    assert!(
        unpacked_manifest.exists(),
        "community/plugin.yaml must be unpacked by --update-rules"
    );
    let parsed: PluginManifest = serde_yaml::from_str(
        &fs::read_to_string(&unpacked_manifest).expect("read unpacked community plugin"),
    )
    .expect("deserialize unpacked CommunityBundle manifest");
    assert!(
        parsed.rules.len() >= 20,
        "expected >= 20 community rules; got {}",
        parsed.rules.len()
    );

    repo_a.write_file(
        "app/cfg_bad.py",
        "import yaml\ndef load_cfg(raw):\n    return yaml.load(raw, Loader=yaml.Loader)\n",
    );
    repo_a.write_file(
        "app/cfg_ok.py",
        "import yaml\ndef load_cfg(raw):\n    return yaml.safe_load(raw)\n",
    );
    repo_a.write_file(
        "src/BinBad.cs",
        "using System.Runtime.Serialization.Formatters.Binary;\npublic class B {\n    public object R(System.IO.Stream s) { var bf = new BinaryFormatter(); return bf.Deserialize(s); }\n}\n",
    );

    let (res_a, sarif_a) = repo_a.run_audit_sarif(&[]);
    assert!(res_a.success, "stderr: {}", res_a.stderr);
    let sarif_a = sarif_a.expect("out.sarif");
    assert!(has_result_for_file(
        &sarif_a,
        "semgrep-owasp-deserialization-yaml",
        "app/cfg_bad.py"
    ));
    assert!(!has_result_for_file(
        &sarif_a,
        "semgrep-owasp-deserialization-yaml",
        "app/cfg_ok.py"
    ));
    assert!(has_result_for_file(
        &sarif_a,
        "semgrep-csharp-binaryformatter-deser",
        "src/BinBad.cs"
    ));

    // Part B: `SemgrepImporter` conversion executed end-to-end via `aether-engine`
    let repo_b = TestRepo::new();
    let semgrep_yaml = r#"
rules:
  - id: custom-semgrep-eval-rule
    languages: [javascript, typescript]
    severity: WARNING
    message: "Dangerous dynamic eval usage"
    metadata:
      cwe: "CWE-94: Code Injection"
    pattern: "eval($EXPR)"
    pattern-not: "safe_eval($EXPR)"
"#;
    let parsed_sg = SemgrepImporter::parse_yaml(semgrep_yaml).expect("parse semgrep YAML");
    let manifest =
        SemgrepImporter::to_plugin_manifest(&parsed_sg, "custom-semgrep").expect("convert manifest");
    let manifest_yaml = serde_yaml::to_string(&manifest).expect("serialize converted manifest");
    repo_b.write_plugin("custom-semgrep", &manifest_yaml);

    repo_b.write_file("app/bad.js", "function run(x) { return eval(x); }\n");
    repo_b.write_file("app/safe.js", "function run(x) { return safe_eval(x); }\n");

    let (res_b, sarif_b) = repo_b.run_audit_sarif(&[]);
    assert!(res_b.success, "stderr: {}", res_b.stderr);
    let sarif_b = sarif_b.expect("out.sarif");
    assert!(has_result_for_file(
        &sarif_b,
        "custom-semgrep-eval-rule",
        "app/bad.js"
    ));
    assert!(!has_result_for_file(
        &sarif_b,
        "custom-semgrep-eval-rule",
        "app/safe.js"
    ));
}

#[test]
fn t1_f4_parity_native_rust_py_js_rules() {
    let repo = TestRepo::new();

    // Rust vulnerable + clean
    repo.write_file(
        "src/rust_vuln.rs",
        r#"pub fn bad_cast(x: u64) -> [u8; 8] {
    unsafe { std::mem::transmute(x) }
}
pub async fn read_cfg() {
    let _ = std::fs::read_to_string("cfg.toml");
}
pub fn leak_guard(guard: std::sync::MutexGuard<'_, u32>) {
    std::mem::forget(guard);
}
pub fn spawn_cmd(user_arg: &str) {
    let _ = std::process::Command::new(user_arg);
}
pub fn cfg_secret() -> &'static str {
    let api_key = "sk_live_prod_987654321";
    api_key
}
"#,
    );
    repo.write_file(
        "src/rust_clean.rs",
        r#"pub fn safe_cast(x: u64) -> [u8; 8] {
    x.to_ne_bytes()
}
pub fn release_guard(g: std::sync::MutexGuard<'_, u32>) {
    drop(g);
}
"#,
    );

    // Python vulnerable + clean (NO Cargo.toml at root!)
    repo.write_file(
        "app/py_vuln.py",
        r#"import os
import yaml
from sqlalchemy import text

def load_cfg(raw):
    return yaml.load(raw)

def get_user(session, uid):
    return session.execute(text(f"SELECT * FROM users WHERE id = {uid}"))

def run_task(arg):
    os.system("echo " + arg)
"#,
    );
    repo.write_file(
        "app/py_clean.py",
        r#"import subprocess
import yaml

def load_cfg(raw):
    return yaml.safe_load(raw)

def run_task(arg):
    subprocess.run(["echo", arg], shell=False, check=True)
"#,
    );

    // JS vulnerable + clean
    repo.write_file(
        "app/js_vuln.js",
        r#"const vm = require('vm');
const child_process = require('child_process');

function runUntrusted(code) {
    return vm.runInNewContext(code);
}
function configureCors(app, cors) {
    app.use(cors({ origin: true, credentials: true }));
}
function filterItems(req) {
    return new RegExp(req.query.pattern);
}
function runShell(cmd) {
    child_process.exec(cmd);
}
"#,
    );
    repo.write_file(
        "app/js_clean.js",
        r#"function parseUntrusted(raw) {
    return JSON.parse(raw);
}
function filterItems(input) {
    return input.includes("fixed");
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    let expected_rust = [
        "CVE-RUST-TRANSMUTE-SIZE-MISMATCH",
        "CVE-RUST-BLOCKING-IN-ASYNC",
        "CVE-RUST-FORGOTTEN-MEM-LEAK",
        "CVE-RUST-CMD-INJ",
        "SAST_HARDCODED_SECRET",
    ];
    for rule_id in expected_rust {
        assert!(
            has_result_for_file(&sarif, rule_id, "src/rust_vuln.rs"),
            "missing Rust native rule '{}' on src/rust_vuln.rs; got {:?}",
            rule_id,
            sarif_result_rule_ids(&sarif)
        );
    }

    let expected_py = [
        "CVE-PY-YAML-UNSAFE-LOAD",
        "CVE-PY-SQL-ALCHEMY-TEXT-INJECTION",
        "CVE-PY-SHELL-INJ",
    ];
    for rule_id in expected_py {
        assert!(
            has_result_for_file(&sarif, rule_id, "app/py_vuln.py"),
            "missing Python native rule '{}' on app/py_vuln.py; got {:?}",
            rule_id,
            sarif_result_rule_ids(&sarif)
        );
    }

    let expected_js = [
        "CVE-JS-VM-SANDBOX-ESCAPE",
        "CVE-JS-CORS-WILDCARD-CREDENTIALS",
        "CVE-JS-REGEX-DOS-DYNAMIC-INPUT",
        "CVE-JS-CMD-INJ",
    ];
    for rule_id in expected_js {
        assert!(
            has_result_for_file(&sarif, rule_id, "app/js_vuln.js"),
            "missing JS native rule '{}' on app/js_vuln.js; got {:?}",
            rule_id,
            sarif_result_rule_ids(&sarif)
        );
    }

    // Clean files must produce zero findings
    for clean_suffix in ["src/rust_clean.rs", "app/py_clean.py", "app/js_clean.js"] {
        let clean_hits: Vec<&Value> = sarif_results(&sarif)
            .iter()
            .filter(|r| sarif_result_uri(r).ends_with(clean_suffix))
            .collect();
        assert!(
            clean_hits.is_empty(),
            "clean file '{}' produced unexpected findings: {:?}",
            clean_suffix,
            clean_hits
        );
    }
}

#[test]
fn t1_f4_parity_native_sol_php_zig_csharp_rules() {
    let repo = TestRepo::new();

    // Solidity vulnerable + clean
    repo.write_file(
        "contracts/VaultLogic.sol",
        r#"contract AuthVault {
    address owner;
    function withdraw() external {
        require(tx.origin == owner, "denied");
    }
    function onFlashLoan(address initiator, uint256 amount) external returns (bytes32) {
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
    function readPrice(AggregatorV3Interface feed) external view returns (int256) {
        (, int256 ans, , , ) = feed.latestRoundData();
        return ans;
    }
}
"#,
    );
    repo.write_file(
        "contracts/SafeVault.sol",
        r#"contract SafeVault {
    address owner;
    address lender;
    function withdraw() external {
        require(msg.sender == owner, "denied");
    }
    function onFlashLoan(address initiator, uint256 amount) external returns (bytes32) {
        require(msg.sender == lender, "bad caller");
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
    function readPrice(AggregatorV3Interface feed) external view returns (int256) {
        (, int256 ans, , uint256 updatedAt, ) = feed.latestRoundData();
        require(updatedAt > 0 && block.timestamp - updatedAt <= 3600, "stale");
        return ans;
    }
}
"#,
    );

    // PHP vulnerable + clean
    repo.write_file(
        "src/php_vuln.php",
        r#"<?php
function runExpr($code) {
    return eval($code);
}
$obj = unserialize($_POST['payload']);
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
"#,
    );
    repo.write_file(
        "src/php_clean.php",
        r#"<?php
function runExpr($raw) {
    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}
$obj = unserialize($_POST['payload'], ['allowed_classes' => false]);
"#,
    );

    // Zig vulnerable + clean
    repo.write_file(
        "src/zig_vuln.zig",
        r#"pub fn computeSize(a: u32, b: u32) u32 {
    return a +% b;
}
const Hdr = extern struct { id: u32 };
pub fn parseHdr(raw: []const u8) *const Hdr {
    return @ptrCast(@alignCast(raw.ptr));
}
pub fn fastCopy(dst: []u8, src: []const u8) void {
    @setRuntimeSafety(false);
    dst[0] = src[0];
}
"#,
    );
    repo.write_file(
        "src/zig_clean.zig",
        r#"pub fn computeSize(a: u32, b: u32) !u32 {
    const t = @addWithOverflow(a, b);
    if (t[1] != 0) return error.Overflow;
    return t[0];
}
"#,
    );

    // C# vulnerable + clean
    repo.write_file(
        "src/CSharpVuln.cs",
        r#"using System.IO;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;

public class VulnSvc {
    public object Restore(Stream s) {
        var fmt = new BinaryFormatter();
        return fmt.Deserialize(s);
    }
    public void Delete(SqlConnection conn, string user) {
        string sql = $"DELETE FROM Users WHERE Username = '{user}'";
        new SqlCommand(sql, conn).ExecuteNonQuery();
    }
    public byte[] Hash(byte[] pw) {
        using var md5 = MD5.Create();
        return md5.ComputeHash(pw);
    }
}
"#,
    );
    repo.write_file(
        "src/CSharpClean.cs",
        r#"using System.Text.Json;
using System.Security.Cryptography;

public class CleanSvc {
    public T Restore<T>(string json) {
        return JsonSerializer.Deserialize<T>(json);
    }
    public byte[] Hash(byte[] pw) {
        using var sha = SHA256.Create();
        return sha.ComputeHash(pw);
    }
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    let expected_by_file = [
        ("contracts/VaultLogic.sol", "CVE-WEB3-TX-ORIGIN-PHISHING"),
        ("contracts/VaultLogic.sol", "CVE-WEB3-UNPROTECTED-CALLBACK-SELECTOR"),
        ("contracts/VaultLogic.sol", "CVE-WEB3-STALE-ORACLE-HEARTBEAT"),
        ("src/php_vuln.php", "CVE-PHP-EVAL-CODE-INJECTION"),
        ("src/php_vuln.php", "CVE-PHP-UNSERIALIZE-RCE"),
        ("src/php_vuln.php", "CVE-PHP-SQL-INJECTION"),
        ("src/zig_vuln.zig", "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING"),
        ("src/zig_vuln.zig", "CVE-ZIG-INSECURE-POINTER-CAST"),
        ("src/zig_vuln.zig", "CVE-ZIG-RUNTIME-SAFETY-DISABLED"),
        ("src/CSharpVuln.cs", "CVE-CS-INSECURE-DESERIALIZATION"),
        ("src/CSharpVuln.cs", "CVE-CS-SQL-INJECTION"),
        ("src/CSharpVuln.cs", "CVE-CS-WEAK-CRYPTOGRAPHY"),
    ];
    for (file_suffix, rule_id) in expected_by_file {
        assert!(
            has_result_for_file(&sarif, rule_id, file_suffix),
            "missing rule '{}' on '{}'; got {:?}",
            rule_id,
            file_suffix,
            sarif_result_rule_ids(&sarif)
        );
    }

    for clean_suffix in [
        "contracts/SafeVault.sol",
        "src/php_clean.php",
        "src/zig_clean.zig",
        "src/CSharpClean.cs",
    ] {
        let clean_hits: Vec<&Value> = sarif_results(&sarif)
            .iter()
            .filter(|r| sarif_result_uri(r).ends_with(clean_suffix))
            .collect();
        assert!(
            clean_hits.is_empty(),
            "clean file '{}' produced unexpected findings: {:?}",
            clean_suffix,
            clean_hits
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2 — F-E2E-1: Edge Cases, Boundaries & Negative CLI Tests (5 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t2_f1_plugins_comma_list_whitespace_and_dedup() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "pack-a",
        r#"name: "pack-a"
version: "1.0.0"
enabled: true
rules:
  - id: "DEDUP-A-001"
    cwe_id: "CWE-284"
    name: "Pack A"
    severity: "HIGH"
    description: "A"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["trigger_pack_a\\("]
"#,
    );
    repo.write_plugin(
        "pack-b",
        r#"name: "pack-b"
version: "1.0.0"
enabled: true
rules:
  - id: "DEDUP-B-001"
    cwe_id: "CWE-284"
    name: "Pack B"
    severity: "HIGH"
    description: "B"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["trigger_pack_b\\("]
"#,
    );
    repo.write_file(
        "src/main_mod.rs",
        "pub fn run() {\n    trigger_pack_a();\n    trigger_pack_b();\n}\n",
    );

    let (r1, s1) = repo.run_audit_sarif(&["--plugins", "pack-a,pack-b"]);
    let (r2, s2) = repo.run_audit_sarif(&["--plugins", " pack-a , pack-a , pack-b "]);
    assert!(r1.success && r2.success, "both runs must exit 0");

    let s1 = s1.expect("sarif 1");
    let s2 = s2.expect("sarif 2");
    assert_eq!(
        sarif_results(&s1).len(),
        sarif_results(&s2).len(),
        "deduplicated whitespace list must yield identical finding count"
    );
    assert_eq!(
        results_for_rule(&s2, "DEDUP-A-001").len(),
        1,
        "pack-a repeated twice must NOT duplicate DEDUP-A-001"
    );
    assert_eq!(results_for_rule(&s2, "DEDUP-B-001").len(), 1);
}

#[test]
fn t2_f1_plugins_empty_or_whitespace_rejected() {
    let repo = TestRepo::new();
    repo.write_file("src/ok.rs", "pub fn ok() -> u32 { 1 }\n");

    for bad_spec in ["", "   ", ","] {
        let (res, _) = repo.run_audit_sarif(&["--plugins", bad_spec]);
        assert!(
            !res.success && res.code != 0,
            "--plugins {:?} must exit non-zero, got code {}",
            bad_spec,
            res.code
        );
        assert!(
            !res.stderr.trim().is_empty(),
            "--plugins {:?} must print diagnostic to stderr",
            bad_spec
        );
    }
}

#[test]
fn t2_f1_plugins_unknown_pack_or_profile_rejected() {
    let repo = TestRepo::new();
    repo.write_file("src/ok.rs", "pub fn ok() -> u32 { 1 }\n");

    for bad_spec in ["does-not-exist-pack", "profile:unknown-prof"] {
        let (res, _) = repo.run_audit_sarif(&["--plugins", bad_spec]);
        assert!(
            !res.success && res.code != 0,
            "--plugins '{}' must fail non-zero",
            bad_spec
        );
        assert!(
            !res.stderr.trim().is_empty(),
            "--plugins '{}' must report error on stderr",
            bad_spec
        );
    }
}

#[test]
fn t2_f1_clap_unknown_flag_exits_2() {
    let repo = TestRepo::new();
    let path_str = repo.path().to_string_lossy().to_string();
    let res = repo.run_cli_raw(&["--audit-only", "--path", &path_str, "--nonexistent-cli-flag"]);
    assert_eq!(
        res.code, 2,
        "clap must exit with code 2 on unknown flag; stderr: {}",
        res.stderr
    );
    assert!(
        !res.stderr.trim().is_empty(),
        "clap must emit usage error to stderr"
    );
}

#[test]
fn t2_f1_plugins_fail_on_respects_filtered_packs() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "pack-crit",
        r#"name: "pack-crit"
version: "1.0.0"
enabled: true
rules:
  - id: "PACK-CRIT-001"
    cwe_id: "CWE-94"
    name: "Critical custom"
    severity: "CRITICAL"
    description: "Crit"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["crit_custom_call\\("]
"#,
    );
    repo.write_plugin(
        "pack-low",
        r#"name: "pack-low"
version: "1.0.0"
enabled: true
rules:
  - id: "PACK-LOW-001"
    cwe_id: "CWE-20"
    name: "Low custom"
    severity: "LOW"
    description: "Low"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["low_custom_call\\("]
"#,
    );
    repo.write_file(
        "src/app.rs",
        "pub fn run() {\n    crit_custom_call();\n    low_custom_call();\n}\n",
    );

    let (low_res, _) = repo.run_audit_sarif(&["--plugins", "pack-low", "--fail-on", "CRITICAL"]);
    assert!(
        low_res.success,
        "pack-low only has LOW finding so --fail-on CRITICAL must exit 0; stderr: {}",
        low_res.stderr
    );

    let (crit_res, _) = repo.run_audit_sarif(&["--plugins", "pack-crit", "--fail-on", "CRITICAL"]);
    assert_eq!(
        crit_res.code, 1,
        "pack-crit has CRITICAL finding so --fail-on CRITICAL must exit 1"
    );
    assert!(
        crit_res.stderr.contains("[FAIL-ON: CRITICAL]"),
        "expected [FAIL-ON: CRITICAL] on stderr; got {}",
        crit_res.stderr
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2 — F-E2E-2: Window Boundaries, Path Globs, Masking & Lifecycle (5 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t2_f2_window_zero_lines_does_not_suppress() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "win-zero",
        r#"name: "win-zero"
version: "1.0.0"
enabled: true
rules:
  - id: "WIN-ZERO-001"
    cwe_id: "CWE-284"
    name: "Zero window rule"
    severity: "HIGH"
    description: "lines: 0 checks 0 preceding lines"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["dangerous_op\\("]
      not_preceded_within_lines:
        patterns: ["guard_ok\\(\\)"]
        lines: 0
"#,
    );
    repo.write_file(
        "src/ops.rs",
        "pub fn run() {\n    guard_ok();\n    dangerous_op();\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert_eq!(
        results_for_rule(&sarif, "WIN-ZERO-001").len(),
        1,
        "lines: 0 must NOT suppress dangerous_op even when guard_ok() is 1 line above"
    );
}

#[test]
fn t2_f2_window_boundary_n_vs_n_plus_1_and_after() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "win-bound",
        r#"name: "win-bound"
version: "1.0.0"
enabled: true
rules:
  - id: "WIN-BOUND-001"
    cwe_id: "CWE-284"
    name: "Window boundary N=3"
    severity: "HIGH"
    description: "Guard must be within 3 preceding lines"
    remediation: "Move guard_ok() closer"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["dangerous_op\\("]
      not_preceded_within_lines:
        patterns: ["guard_ok\\(\\)"]
        lines: 3
"#,
    );

    // Distance 3 (exactly N lines above): line 2 -> line 5 (5 - 2 = 3) => SUPPRESSED
    repo.write_file(
        "src/at_n.rs",
        "pub fn f() {\n    guard_ok();\n    let a = 1;\n    let b = 2;\n    dangerous_op();\n}\n",
    );
    // Distance 4 (N+1 lines above): line 2 -> line 6 (6 - 2 = 4) => TRIGGERS
    repo.write_file(
        "src/at_n_plus_1.rs",
        "pub fn f() {\n    guard_ok();\n    let a = 1;\n    let b = 2;\n    let c = 3;\n    dangerous_op();\n}\n",
    );
    // Guard placed 1 line AFTER match => TRIGGERS
    repo.write_file(
        "src/after_match.rs",
        "pub fn f() {\n    dangerous_op();\n    guard_ok();\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(
        !has_result_for_file(&sarif, "WIN-BOUND-001", "src/at_n.rs"),
        "guard at distance N=3 must suppress"
    );
    assert!(
        has_result_for_file(&sarif, "WIN-BOUND-001", "src/at_n_plus_1.rs"),
        "guard at distance N+1=4 must NOT suppress"
    );
    assert!(
        has_result_for_file(&sarif, "WIN-BOUND-001", "src/after_match.rs"),
        "guard after dangerous_op must NOT suppress"
    );
}

#[test]
fn t2_f2_path_matching_overlapping_globs_and_win_posix() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "path-overlap",
        r#"name: "path-overlap"
version: "1.0.0"
enabled: true
rules:
  - id: "PATH-OVERLAP-001"
    cwe_id: "CWE-284"
    name: "Overlapping path globs"
    severity: "HIGH"
    description: "not_in_path_matching overrides in_path_matching"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["overlap_trigger\\("]
      in_path_matching: ["src/**"]
      not_in_path_matching: ["src/internal/**"]
"#,
    );
    repo.write_file("src/api/ok.rs", "pub fn ok() { overlap_trigger(); }\n");
    repo.write_file(
        "src/internal/skip.rs",
        "pub fn skip() { overlap_trigger(); }\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(
        has_result_for_file(&sarif, "PATH-OVERLAP-001", "src/api/ok.rs"),
        "src/api/ok.rs matches src/** and not src/internal/**"
    );
    assert!(
        !has_result_for_file(&sarif, "PATH-OVERLAP-001", "src/internal/skip.rs"),
        "not_in_path_matching must override in_path_matching on src/internal/skip.rs"
    );
    for r in results_for_rule(&sarif, "PATH-OVERLAP-001") {
        let uri = sarif_result_uri(r);
        assert!(
            !uri.contains('\\'),
            "SARIF URI must normalize backslashes to '/': {}",
            uri
        );
    }
}

#[test]
fn t2_f2_check_literals_false_vs_true_and_whole_file() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "lit-check",
        r#"name: "lit-check"
version: "1.0.0"
enabled: true
rules:
  - id: "RULE-MASKED-CODE"
    cwe_id: "CWE-20"
    name: "Masked code only"
    severity: "MEDIUM"
    description: "Ignores literals and comments"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["secret_marker_xyz"]
      check_literals: false
  - id: "RULE-LITERAL-WHOLE"
    cwe_id: "CWE-20"
    name: "Literal whole file"
    severity: "MEDIUM"
    description: "Matches literals in whole_file mode"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "whole_file"
    conditions:
      regex_patterns: ["secret_marker_xyz"]
      check_literals: true
"#,
    );
    repo.write_file(
        "src/lit_only.rs",
        "pub fn helper() -> &'static str {\n    // secret_marker_xyz in comment\n    \"secret_marker_xyz\"\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(
        results_for_rule(&sarif, "RULE-MASKED-CODE").is_empty(),
        "check_literals: false must mask string literals and comments"
    );
    let whole_hits = results_for_rule(&sarif, "RULE-LITERAL-WHOLE");
    assert_eq!(whole_hits.len(), 1);
    assert_eq!(
        sarif_result_line(whole_hits[0]),
        1,
        "whole_file mode must emit startLine == 1"
    );
}

#[test]
fn t2_f2_disabled_plugin_and_malformed_yaml_coexistence() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "disabled-pack",
        r#"name: "disabled-pack"
version: "1.0.0"
enabled: false
rules:
  - id: "DISABLED-RULE-001"
    cwe_id: "CWE-20"
    name: "Disabled"
    severity: "HIGH"
    description: "Disabled"
    remediation: "None"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["shared_trigger\\("]
"#,
    );
    repo.write_plugin("corrupt-pack", "name: broken\nrules:\n  - id: [unclosed\n");
    repo.write_plugin(
        "valid-pack",
        r#"name: "valid-pack"
version: "1.0.0"
enabled: true
rules:
  - id: "VALID-COEXIST-001"
    cwe_id: "CWE-20"
    name: "Valid"
    severity: "HIGH"
    description: "Valid"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["shared_trigger\\("]
"#,
    );
    repo.write_file("src/app.rs", "pub fn go() { shared_trigger(); }\n");

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(
        res.success,
        "malformed YAML alongside valid plugin must not crash CLI; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);
    assert!(ids.iter().any(|id| id == "VALID-COEXIST-001"));
    assert!(!ids.iter().any(|id| id == "DISABLED-RULE-001"));
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2 — F-E2E-3: Taint DSL Boundary, Language/CWE Isolation & Sanitizer Edges (7 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t2_f3_taint_empty_vectors_manifest_loads_without_error() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "empty-taint",
        r#"name: "empty-taint"
version: "1.0.0"
enabled: true
taint_sources: []
taint_sinks: []
sanitizers: []
rules: []
"#,
    );
    repo.write_file("src/clean.rs", "pub fn ok() -> u32 { 42 }\n");

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "empty-taint"]);
    assert!(
        res.success,
        "empty taint vectors manifest must load cleanly; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    assert!(sarif_results(&sarif).is_empty());
}

#[test]
fn t2_f3_taint_language_filter_mismatch_ignored() {
    let repo = TestRepo::new();
    // Taint rules restricted to language: "rust" only
    repo.write_plugin(
        "rust-only-taint",
        &std_taint_plugin_yaml("rust-only-taint", None, Some("rust")),
    );
    // Python file (no Cargo.toml at root) matches pattern names, but language is python != rust
    repo.write_file(
        "app/service.py",
        r#"def handle(req):
    q = extract_query(req)
    exec_raw_sql(q)
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "rust-only-taint"]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001").is_empty(),
        "language: \"rust\" taint rules must NOT trigger on .py files"
    );
}

#[test]
fn t2_f3_taint_cwe_mismatch_sanitizer_does_not_neutralize() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "taint-cwe-mismatch",
        r#"name: "taint-cwe-mismatch"
version: "1.0.0"
enabled: true
taint_sources:
  - name: "src_sqli"
    source_kind: "HttpQueryParam"
    cwe: "CWE-89"
    patterns: ["extract_query("]
    language: null
    description: "SQLi source"
taint_sinks:
  - name: "sink_sqli"
    sink_kind: "SqlExecution"
    cwe: "CWE-89"
    rule_id: "PLUGIN-TAINT-SQLI-001"
    severity: "CRITICAL"
    patterns: ["exec_raw_sql("]
    language: null
    description: "SQLi sink"
sanitizers:
  - name: "escape_html_only"
    target_cwes: ["CWE-79"]
    match_kind: "ExactName"
    language: null
    neutralizes_all: false
rules: []
"#,
    );
    repo.write_file(
        "src/handler.rs",
        r#"pub fn handle(req: &str) {
    let raw = extract_query(req);
    let html_esc = escape_html_only(raw);
    exec_raw_sql(html_esc);
}
"#,
    );

    let (res, _) = repo.run_audit_sarif(&["--fail-on", "CRITICAL"]);
    assert_eq!(
        res.code, 1,
        "CWE-79 sanitizer must NOT neutralize CWE-89 sink under --fail-on CRITICAL"
    );
}

#[test]
fn t2_f3_taint_neutralizes_all_clears_any_cwe() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "taint-neutralize-all",
        r#"name: "taint-neutralize-all"
version: "1.0.0"
enabled: true
taint_sources:
  - name: "src_sqli"
    source_kind: "HttpQueryParam"
    cwe: "CWE-89"
    patterns: ["extract_query("]
    language: null
    description: "SQLi source"
taint_sinks:
  - name: "sink_sqli"
    sink_kind: "SqlExecution"
    cwe: "CWE-89"
    rule_id: "PLUGIN-TAINT-SQLI-001"
    severity: "CRITICAL"
    patterns: ["exec_raw_sql("]
    language: null
    description: "SQLi sink"
sanitizers:
  - name: "universal_guard"
    target_cwes: []
    match_kind: "ExactName"
    language: null
    neutralizes_all: true
rules: []
"#,
    );
    repo.write_file(
        "src/handler.rs",
        r#"pub fn handle(req: &str) {
    let raw = extract_query(req);
    let safe_val = universal_guard(raw);
    exec_raw_sql(safe_val);
}
"#,
    );

    let (res, _) = repo.run_audit_sarif(&["--fail-on", "CRITICAL"]);
    assert!(
        res.success,
        "neutralizes_all: true must clear taint flow despite empty target_cwes; stderr: {}",
        res.stderr
    );
}

#[test]
fn t2_f3_taint_custom_kinds_and_sanitizer_match_kinds() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "taint-custom-kinds",
        r#"name: "taint-custom-kinds"
version: "1.0.0"
enabled: true
taint_sources:
  - name: "mq_source"
    source_kind:
      Custom: "MessageQueuePayload"
    cwe: "CWE-502"
    patterns: ["mq_recv("]
    language: null
    description: "Untrusted queue message"
taint_sinks:
  - name: "custom_deser_sink"
    sink_kind:
      Custom: "UnsafeBinaryDecode"
    cwe: "CWE-502"
    rule_id: "PLUGIN-CUSTOM-DESER-001"
    severity: "CRITICAL"
    patterns: ["unsafe_decode_bytes("]
    language: null
    description: "Unsafe binary decode"
sanitizers:
  - name: ".verify_hmac("
    target_cwes: ["CWE-502"]
    match_kind: "MethodCall"
    language: null
    neutralizes_all: false
  - name: "as VerifiedFrame"
    target_cwes: ["CWE-502"]
    match_kind: "TypeCast"
    language: null
    neutralizes_all: false
  - name: "*strict_schema_*"
    target_cwes: ["CWE-502"]
    match_kind: "RegexPattern"
    language: null
    neutralizes_all: false
rules: []
"#,
    );

    // Unsanitized custom source -> custom sink
    repo.write_file(
        "src/vuln_consumer.rs",
        r#"pub fn consume(bus: &str) {
    let msg = mq_recv(bus);
    unsafe_decode_bytes(msg);
}
"#,
    );
    // Sanitized via RegexPattern glob (*strict_schema_*)
    repo.write_file(
        "src/safe_glob.rs",
        r#"pub fn consume_glob(bus: &str) {
    let msg = mq_recv(bus);
    let checked = strict_schema_validate(msg);
    unsafe_decode_bytes(checked);
}
"#,
    );
    // Sanitized via MethodCall (.verify_hmac()
    repo.write_file(
        "src/safe_method.rs",
        r#"pub fn consume_method(bus: &str) {
    let msg = mq_recv(bus);
    let verified = msg.verify_hmac(msg);
    unsafe_decode_bytes(verified);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "taint-custom-kinds"]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(
        has_result_for_file(&sarif, "PLUGIN-CUSTOM-DESER-001", "src/vuln_consumer.rs"),
        "expected Custom source/sink finding on src/vuln_consumer.rs"
    );
    let safe_glob_reachable = sarif_results(&sarif).iter().any(|r| {
        r["ruleId"].as_str() == Some("PLUGIN-CUSTOM-DESER-001")
            && sarif_result_uri(r).ends_with("src/safe_glob.rs")
            && r["properties"]["is_reachable"] == Value::Bool(true)
    });
    assert!(
        !safe_glob_reachable,
        "RegexPattern glob sanitizer must neutralize src/safe_glob.rs"
    );
    let safe_method_reachable = sarif_results(&sarif).iter().any(|r| {
        r["ruleId"].as_str() == Some("PLUGIN-CUSTOM-DESER-001")
            && sarif_result_uri(r).ends_with("src/safe_method.rs")
            && r["properties"]["is_reachable"] == Value::Bool(true)
    });
    assert!(
        !safe_method_reachable,
        "MethodCall sanitizer must neutralize src/safe_method.rs"
    );
}

#[test]
fn t2_f3_taint_branch_one_unsanitized_path_stays_vulnerable() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-branch", &std_taint_plugin_yaml("taint-branch", None, None));
    repo.write_file(
        "src/branching.rs",
        r#"pub fn handle(req: &str, flag: bool) {
    let raw = extract_query(req);
    let safe_branch = sanitize_sql_param(raw);
    let unsafe_branch = raw;
    if flag {
        exec_raw_sql(safe_branch);
    }
    exec_raw_sql(unsafe_branch);
}
"#,
    );

    let (res, _) = repo.run_audit_sarif(&["--fail-on", "CRITICAL"]);
    assert_eq!(
        res.code, 1,
        "having one sanitized branch alongside an unsanitized path must stay vulnerable"
    );
}

#[test]
fn t2_f3_taint_unrelated_vars_and_missing_sink_no_fp() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-clean", &std_taint_plugin_yaml("taint-clean", None, None));
    repo.write_file(
        "src/unrelated.rs",
        r#"pub fn handle_unrelated(req: &str) {
    let tainted = extract_query(req);
    let clean = "constant_safe_id";
    exec_raw_sql(clean);
}
"#,
    );
    repo.write_file(
        "src/no_sink.rs",
        r#"pub fn handle_no_sink(req: &str) {
    let q = extract_query(req);
    log_audit_only(q);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--fail-on", "CRITICAL"]);
    assert!(
        res.success,
        "unrelated variable and missing sink must NOT trigger CRITICAL fail-on; stderr: {}",
        res.stderr
    );
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001").is_empty(),
        "expected 0 PLUGIN-TAINT-SQLI-001 findings; got {:?}",
        results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2 — F-E2E-4: Anti-FP, Output Formats & Legacy Compat Edges (6 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t2_f4_anti_fp_rust_cfg_test_not_flagged() {
    let repo = TestRepo::new();
    repo.write_file(
        "src/service.rs",
        r#"pub fn ok() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_unsafe_and_cmd() {
        let mut val = 0u32;
        let ptr = &mut val as *mut u32;
        unsafe { *ptr = 1; }
        let _ = std::process::Command::new(user_arg);
    }
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);
    assert!(
        !ids.iter().any(|id| id == "CVE-RUST-UNSAFE-MEM"),
        "#[cfg(test)] must not trigger CVE-RUST-UNSAFE-MEM; got {:?}",
        ids
    );
    assert!(
        !ids.iter().any(|id| id == "CVE-RUST-CMD-INJ"),
        "#[cfg(test)] must not trigger CVE-RUST-CMD-INJ; got {:?}",
        ids
    );
}

#[test]
fn t2_f4_anti_fp_safety_comment_suppresses_unsafe_mem() {
    let repo = TestRepo::new();
    repo.write_file(
        "src/network/codec.rs",
        r#"pub fn write_header(packet_ptr: *mut u8) {
    // SAFETY: packet_ptr is guaranteed non-null and valid for 1 byte by caller
    unsafe { *packet_ptr = 1; }
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(
        results_for_rule(&sarif, "CVE-RUST-UNSAFE-MEM").is_empty(),
        "// SAFETY: comment must suppress CVE-RUST-UNSAFE-MEM"
    );
}

#[test]
fn t2_f4_live_audit_md_written_on_text_mode() {
    // Clean repository -> ARCH_OK
    let clean_repo = TestRepo::new();
    clean_repo.write_file("src/lib.rs", "pub fn add(a: u32, b: u32) -> u32 { a + b }\n");
    let (clean_res, clean_md) = clean_repo.run_audit_text(&[]);
    assert!(clean_res.success, "stderr: {}", clean_res.stderr);
    let clean_md = clean_md.expect(".aether/LIVE_AUDIT.md must exist");
    assert!(
        clean_md.contains("ARCH_OK"),
        "clean repo LIVE_AUDIT.md must report ARCH_OK; got:\n{}",
        clean_md
    );

    // Dirty repository -> violation count & rule ID
    let dirty_repo = TestRepo::new();
    dirty_repo.write_file(
        "src/cmd.rs",
        "pub fn run(user_arg: &str) { let _ = std::process::Command::new(user_arg); }\n",
    );
    let (dirty_res, dirty_md) = dirty_repo.run_audit_text(&[]);
    assert!(dirty_res.success, "stderr: {}", dirty_res.stderr);
    let dirty_md = dirty_md.expect(".aether/LIVE_AUDIT.md must exist");
    assert!(
        dirty_md.contains("VIOLATION(S)") && dirty_md.contains("CVE-RUST-CMD-INJ"),
        "dirty repo LIVE_AUDIT.md must list violation count and CVE-RUST-CMD-INJ; got:\n{}",
        dirty_md
    );
}

#[test]
fn t2_f4_sarif_schema_and_uri_normalization() {
    let repo = TestRepo::new();
    repo.write_file(
        "src/sub/mod_a.rs",
        "pub fn run(arg: &str) { let _ = std::process::Command::new(arg); }\n",
    );

    let port = unused_port().to_string();
    let out_file = repo.path().join("reports").join("out.sarif");
    let out_str = out_file.to_string_lossy().to_string();
    let path_str = repo.path().to_string_lossy().to_string();

    let res = repo.run_cli_raw(&[
        "--audit-only",
        "--path",
        &path_str,
        "--port",
        &port,
        "--format",
        "sarif",
        "-o",
        &out_str,
    ]);
    assert!(res.success, "stderr: {}", res.stderr);
    assert!(out_file.exists(), "nested -o reports/out.sarif must be created");

    let sarif: Value =
        serde_json::from_str(&fs::read_to_string(&out_file).expect("read reports/out.sarif"))
            .expect("valid JSON");
    assert!(
        sarif["$schema"]
            .as_str()
            .unwrap_or("")
            .ends_with("sarif-schema-2.1.0.json"),
        "unexpected SARIF $schema: {}",
        sarif["$schema"]
    );
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "AetherScope");

    let results = sarif_results(&sarif);
    assert!(!results.is_empty(), "expected at least 1 SARIF result");
    for r in results {
        let loc = &r["locations"][0]["physicalLocation"]["artifactLocation"];
        let uri = loc["uri"].as_str().unwrap_or("");
        assert!(
            !uri.contains('\\'),
            "SARIF URI must normalize '\\' to '/': {}",
            uri
        );
        assert_eq!(loc["uriBaseId"], "%SRCROOT%");
    }
}

#[test]
fn t2_f4_must_contain_not_contain_and_legacy_optional_fields_compat() {
    let repo = TestRepo::new();
    // Minimal legacy manifest omitting author, description, profile, tags, category, match_mode, test_cases, taint_*
    repo.write_plugin(
        "legacy-minimal",
        r#"name: "legacy-minimal"
version: "1.0.0"
rules:
  - id: "LEGACY-MIN-001"
    cwe_id: "CWE-284"
    name: "Minimal legacy rule"
    severity: "HIGH"
    description: "Requires raw_exec and forbids checked_exec"
    remediation: "Call checked_exec"
    file_extensions: [".rs"]
    conditions:
      must_contain: ["raw_exec"]
      must_not_contain: ["checked_exec"]
      regex_patterns: ["dangerous_call\\("]
"#,
    );
    repo.write_file(
        "src/trigger.rs",
        "pub fn f() {\n    raw_exec();\n    dangerous_call();\n}\n",
    );
    repo.write_file(
        "src/missing_must.rs",
        "pub fn f() {\n    dangerous_call();\n}\n",
    );
    repo.write_file(
        "src/has_not_contain.rs",
        "pub fn f() {\n    raw_exec();\n    checked_exec();\n    dangerous_call();\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(
        has_result_for_file(&sarif, "LEGACY-MIN-001", "src/trigger.rs"),
        "expected LEGACY-MIN-001 on src/trigger.rs"
    );
    assert!(
        !has_result_for_file(&sarif, "LEGACY-MIN-001", "src/missing_must.rs"),
        "must_contain missing must suppress LEGACY-MIN-001"
    );
    assert!(
        !has_result_for_file(&sarif, "LEGACY-MIN-001", "src/has_not_contain.rs"),
        "must_not_contain anywhere in file must suppress LEGACY-MIN-001"
    );
}

#[test]
fn t2_f4_deep_and_epic_novel_rules_parity() {
    let repo = TestRepo::new();
    repo.write_file(
        "src/vault/lending_vault.sol",
        r#"contract LendingVault {
    function readCollateralPrice(ICurvePool pool) external view returns (uint256) {
        return pool.get_virtual_price();
    }
}
"#,
    );
    repo.write_file(
        "src/async_tls.rs",
        r#"thread_local! {
    static TENANT_CTX: std::cell::Cell<u64> = std::cell::Cell::new(0);
}

pub async fn process_tenant(id: u64) {
    TENANT_CTX.with(|c| c.set(id));
    step_async().await;
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);

    assert!(
        ids.iter().any(|id| id == "CVE-DEFI-READ-ONLY-REENTRANCY"),
        "missing DeepSecurityRules finding CVE-DEFI-READ-ONLY-REENTRANCY; got {:?}",
        ids
    );
    assert!(
        ids.iter().any(|id| id == "AETHER-RUST-ASYNC-TLS-BLEED"),
        "missing EpicNovelRules finding AETHER-RUST-ASYNC-TLS-BLEED; got {:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 3 — Pairwise Cross-Feature Combinations (6 tests)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t3_plugins_select_plus_path_window_dsl() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "fintech-ctx",
        r#"name: "fintech-ctx"
version: "1.0.0"
enabled: true
rules:
  - id: "FINTECH-CTX-001"
    cwe_id: "CWE-284"
    name: "Ledger debit guard"
    severity: "HIGH"
    description: "Requires verify_ledger_sig() within 2 lines under src/ledger/**"
    remediation: "Call verify_ledger_sig()"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["ledger_debit\\("]
      in_path_matching: ["src/ledger/**"]
      not_preceded_within_lines:
        patterns: ["verify_ledger_sig\\("]
        lines: 2
"#,
    );
    repo.write_plugin(
        "other-ctx",
        r#"name: "other-ctx"
version: "1.0.0"
enabled: true
rules:
  - id: "OTHER-CTX-001"
    cwe_id: "CWE-20"
    name: "Other"
    severity: "HIGH"
    description: "Other"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["ledger_debit\\("]
"#,
    );
    repo.write_file(
        "src/ledger/unguarded.rs",
        "pub fn pay() {\n    ledger_debit(100);\n}\n",
    );
    repo.write_file(
        "src/ledger/guarded.rs",
        "pub fn pay() {\n    verify_ledger_sig();\n    ledger_debit(100);\n}\n",
    );
    repo.write_file(
        "src/other/outside.rs",
        "pub fn pay() {\n    ledger_debit(100);\n}\n",
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "fintech-ctx"]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(has_result_for_file(
        &sarif,
        "FINTECH-CTX-001",
        "src/ledger/unguarded.rs"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "FINTECH-CTX-001",
        "src/ledger/guarded.rs"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "FINTECH-CTX-001",
        "src/other/outside.rs"
    ));
    assert!(
        results_for_rule(&sarif, "OTHER-CTX-001").is_empty(),
        "non-selected pack OTHER-CTX-001 must not run"
    );
}

#[test]
fn t3_plugins_select_plus_taint_dsl() {
    let repo = TestRepo::new();
    repo.write_plugin("taint-sqli", &std_taint_plugin_yaml("taint-sqli", None, None));
    repo.write_plugin(
        "taint-cmd",
        r#"name: "taint-cmd"
version: "1.0.0"
enabled: true
taint_sources:
  - name: "cmd_src"
    source_kind: "HttpQueryParam"
    cwe: "CWE-78"
    patterns: ["extract_cli_input("]
    language: null
    description: "CLI input"
taint_sinks:
  - name: "cmd_sink"
    sink_kind: "CommandExecution"
    cwe: "CWE-78"
    rule_id: "PLUGIN-TAINT-CMD-001"
    severity: "CRITICAL"
    patterns: ["run_shell_cmd("]
    language: null
    description: "Shell sink"
sanitizers: []
rules: []
"#,
    );
    repo.write_file(
        "src/dual.rs",
        r#"pub fn handle(req: &str) {
    let q = extract_query(req);
    exec_raw_sql(q);
    let c = extract_cli_input(req);
    run_shell_cmd(c);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "taint-sqli"]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let ids = sarif_result_rule_ids(&sarif);

    assert!(
        ids.iter().any(|id| id == "PLUGIN-TAINT-SQLI-001"),
        "selected taint-sqli must report PLUGIN-TAINT-SQLI-001; got {:?}",
        ids
    );
    assert!(
        !ids.iter().any(|id| id == "PLUGIN-TAINT-CMD-001"),
        "unselected taint-cmd must NOT report PLUGIN-TAINT-CMD-001; got {:?}",
        ids
    );
}

#[test]
fn t3_plugins_all_plus_native_parity_and_fail_on() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "custom-low",
        r#"name: "custom-low"
version: "1.0.0"
enabled: true
rules:
  - id: "CUSTOM-LOW-NOTE"
    cwe_id: "CWE-20"
    name: "Low severity note"
    severity: "LOW"
    description: "Low"
    remediation: "Fix"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["low_marker_call\\("]
"#,
    );
    repo.write_file(
        "src/only_low.rs",
        "pub fn ok() {\n    low_marker_call();\n}\n",
    );

    // Only LOW present -> --plugins all --fail-on HIGH exits 0, LIVE_AUDIT.md lists CUSTOM-LOW-NOTE
    let (res_ok, live_ok) = repo.run_audit_text(&["--plugins", "all", "--fail-on", "HIGH"]);
    assert!(
        res_ok.success,
        "only LOW finding present so --fail-on HIGH must exit 0; stderr: {}",
        res_ok.stderr
    );
    let md_ok = live_ok.expect("LIVE_AUDIT.md");
    assert!(md_ok.contains("CUSTOM-LOW-NOTE"));

    // Add native HIGH rule (CVE-RUST-FORGOTTEN-MEM-LEAK) -> --plugins all --fail-on HIGH exits 1
    repo.write_file(
        "src/native_high.rs",
        "pub fn leak_guard(guard: std::sync::MutexGuard<'_, u32>) {\n    std::mem::forget(guard);\n}\n",
    );
    let (res_fail, live_fail) = repo.run_audit_text(&["--plugins", "all", "--fail-on", "HIGH"]);
    assert_eq!(
        res_fail.code, 1,
        "native HIGH finding must trigger --fail-on HIGH exit 1"
    );
    let md_fail = live_fail.expect("LIVE_AUDIT.md");
    assert!(
        md_fail.contains("CVE-RUST-FORGOTTEN-MEM-LEAK") && md_fail.contains("CUSTOM-LOW-NOTE"),
        "LIVE_AUDIT.md must contain both native and plugin findings"
    );
}

#[test]
fn t3_window_dsl_plus_taint_sanitizer_coexistence() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "hybrid-dsl",
        r#"name: "hybrid-dsl"
version: "1.0.0"
enabled: true
taint_sources:
  - name: "src_q"
    source_kind: "HttpQueryParam"
    cwe: "CWE-89"
    patterns: ["extract_query("]
    language: null
    description: "Source"
taint_sinks:
  - name: "sink_q"
    sink_kind: "SqlExecution"
    cwe: "CWE-89"
    rule_id: "PLUGIN-TAINT-SQLI-001"
    severity: "CRITICAL"
    patterns: ["exec_raw_sql("]
    language: null
    description: "Sink"
sanitizers:
  - name: "sanitize_sql_param"
    target_cwes: ["CWE-89"]
    match_kind: "ExactName"
    language: null
    neutralizes_all: false
rules:
  - id: "HYBRID-CTX-001"
    cwe_id: "CWE-284"
    name: "Audit log guard"
    severity: "HIGH"
    description: "Must log_audit() within 2 lines"
    remediation: "Call log_audit()"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["privileged_action\\("]
      not_preceded_within_lines:
        patterns: ["log_audit\\("]
        lines: 2
"#,
    );
    repo.write_file(
        "src/hybrid_vuln.rs",
        r#"pub fn run(req: &str) {
    let q = extract_query(req);
    exec_raw_sql(q);
    privileged_action();
}
"#,
    );
    repo.write_file(
        "src/hybrid_safe.rs",
        r#"pub fn run_safe(req: &str) {
    let q = extract_query(req);
    let clean = sanitize_sql_param(q);
    exec_raw_sql(clean);
    log_audit();
    privileged_action();
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&["--plugins", "hybrid-dsl"]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    assert!(has_result_for_file(
        &sarif,
        "PLUGIN-TAINT-SQLI-001",
        "src/hybrid_vuln.rs"
    ));
    assert!(has_result_for_file(
        &sarif,
        "HYBRID-CTX-001",
        "src/hybrid_vuln.rs"
    ));
    assert!(!has_result_for_file(
        &sarif,
        "HYBRID-CTX-001",
        "src/hybrid_safe.rs"
    ));
}

#[test]
fn t3_window_dsl_plus_native_parity_no_conflict() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "api-ctx",
        r#"name: "api-ctx"
version: "1.0.0"
enabled: true
rules:
  - id: "API-CTX-001"
    cwe_id: "CWE-284"
    name: "API token check"
    severity: "HIGH"
    description: "Require check_csrf() within 2 lines"
    remediation: "Call check_csrf()"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["mutate_account\\("]
      in_path_matching: ["src/api/**"]
      not_preceded_within_lines:
        patterns: ["check_csrf\\("]
        lines: 2
"#,
    );
    repo.write_file(
        "src/api/account.rs",
        r#"pub fn update_acc(user_cmd: &str) {
    let _ = std::process::Command::new(user_cmd);
    mutate_account(user_cmd);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    assert!(has_result_for_file(
        &sarif,
        "CVE-RUST-CMD-INJ",
        "src/api/account.rs"
    ));
    assert!(has_result_for_file(
        &sarif,
        "API-CTX-001",
        "src/api/account.rs"
    ));
}

#[test]
fn t3_taint_dsl_plus_compat_sarif_properties() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "example-custom-auth",
        include_str!("../../../.aether/plugins/example-custom-auth/plugin.yaml"),
    );
    repo.write_plugin("web-taint", &std_taint_plugin_yaml("web-taint", None, None));
    repo.write_file(
        "src/admin_sqli.rs",
        r#"pub fn admin_query_users(req: &str) {
    let q = extract_query(req);
    exec_raw_sql(q);
}
"#,
    );

    let (res, sarif_opt) = repo.run_audit_sarif(&[]);
    assert!(res.success, "stderr: {}", res.stderr);
    let sarif = sarif_opt.expect("out.sarif");

    let driver_ids = sarif_driver_rule_ids(&sarif);
    assert!(driver_ids
        .iter()
        .any(|id| id == "CUSTOM-EXAMPLE-CUSTOM-AUTH-001"));
    assert!(driver_ids.iter().any(|id| id == "PLUGIN-TAINT-SQLI-001"));

    let auth_hits = results_for_rule(&sarif, "CUSTOM-EXAMPLE-CUSTOM-AUTH-001");
    let taint_hits = results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001");
    assert!(!auth_hits.is_empty());
    assert!(!taint_hits.is_empty());
    assert_eq!(auth_hits[0]["level"], "error");
    assert_eq!(taint_hits[0]["level"], "error");
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 4 — Real-World Application Scenarios (2 tests: S1 & S2)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t4_s1_polyglot_fintech_api_plugins_dsl_sarif() {
    let repo = TestRepo::new();
    // Legacy manifest
    repo.write_plugin(
        "example-custom-auth",
        include_str!("../../../.aether/plugins/example-custom-auth/plugin.yaml"),
    );
    // Enriched fintech-guard manifest
    repo.write_plugin(
        "fintech-guard",
        r#"name: "fintech-guard"
version: "2.0.0"
enabled: true
profile: "fintech"
tags: ["fintech", "prod"]
rules:
  - id: "FINTECH-TX-GUARD-001"
    cwe_id: "CWE-284"
    name: "Unverified ledger transfer"
    severity: "CRITICAL"
    description: "Ledger transfer must be preceded by verify_idempotency_key() within 3 lines"
    remediation: "Call verify_idempotency_key() before settle_transfer()"
    file_extensions: [".rs", ".ts"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["settle_transfer\\("]
      in_path_matching: ["api/**", "services/**"]
      not_in_path_matching: ["services/legacy/**"]
      not_preceded_within_lines:
        patterns: ["verify_idempotency_key\\("]
        lines: 3
"#,
    );
    // Unrelated experimental pack that must be excluded by profile:fintech,example-custom-auth
    repo.write_plugin(
        "experimental-noise",
        r#"name: "experimental-noise"
version: "0.1.0"
enabled: true
profile: "experimental"
rules:
  - id: "EXP-NOISE-001"
    cwe_id: "CWE-20"
    name: "Experimental noise"
    severity: "LOW"
    description: "Should not run under fintech profile"
    remediation: "Ignore"
    file_extensions: [".py"]
    match_mode: "line_by_line"
    conditions:
      regex_patterns: ["reconcile_batch\\("]
"#,
    );

    // Polyglot Fintech API repo (NO root Cargo.toml!)
    repo.write_file(
        "services/payments.rs",
        r#"pub fn admin_settle_payout(tx_id: &str) {
    settle_transfer(tx_id);
}
"#,
    );
    repo.write_file(
        "services/legacy/old_payments.rs",
        r#"pub fn legacy_settle(tx_id: &str) {
    settle_transfer(tx_id);
}
"#,
    );
    repo.write_file(
        "api/webhook.ts",
        r#"export function handleWebhook(txId: string) {
    verify_idempotency_key(txId);
    settle_transfer(txId);
}
"#,
    );
    repo.write_file(
        "workers/reconcile.py",
        r#"def admin_reconcile(batch):
    if is_authenticated():
        return reconcile_batch(batch)
    return None
"#,
    );

    let port = unused_port().to_string();
    let path_str = repo.path().to_string_lossy().to_string();
    let sarif_out = repo.path().join("fintech.sarif");
    let sarif_out_str = sarif_out.to_string_lossy().to_string();

    let res = repo.run_cli_raw(&[
        "--audit-only",
        "--path",
        &path_str,
        "--port",
        &port,
        "--plugins",
        "profile:fintech,example-custom-auth",
        "--format",
        "sarif",
        "-o",
        &sarif_out_str,
    ]);
    assert!(res.success, "S1 SARIF run must exit 0; stderr: {}", res.stderr);
    let sarif: Value =
        serde_json::from_str(&fs::read_to_string(&sarif_out).expect("read fintech.sarif"))
            .expect("valid SARIF JSON");

    assert!(sarif["$schema"]
        .as_str()
        .unwrap_or("")
        .ends_with("sarif-schema-2.1.0.json"));
    let driver_ids = sarif_driver_rule_ids(&sarif);
    assert!(driver_ids.iter().any(|id| id == "FINTECH-TX-GUARD-001"));
    assert!(driver_ids
        .iter()
        .any(|id| id == "CUSTOM-EXAMPLE-CUSTOM-AUTH-001"));

    // services/payments.rs has unguarded settle_transfer (line 2) + unauthenticated admin_settle_payout (line 1)
    assert!(has_result_for_file(
        &sarif,
        "FINTECH-TX-GUARD-001",
        "services/payments.rs"
    ));
    let tx_hits: Vec<&Value> = results_for_rule(&sarif, "FINTECH-TX-GUARD-001");
    assert_eq!(sarif_result_line(tx_hits[0]), 2);
    assert!(has_result_for_file(
        &sarif,
        "CUSTOM-EXAMPLE-CUSTOM-AUTH-001",
        "services/payments.rs"
    ));

    // services/legacy/old_payments.rs excluded by not_in_path_matching
    assert!(!has_result_for_file(
        &sarif,
        "FINTECH-TX-GUARD-001",
        "services/legacy/old_payments.rs"
    ));
    // api/webhook.ts guarded by verify_idempotency_key within 3 lines
    assert!(!has_result_for_file(
        &sarif,
        "FINTECH-TX-GUARD-001",
        "api/webhook.ts"
    ));
    // workers/reconcile.py suppressed by legacy is_authenticated() + experimental pack excluded
    assert!(!has_result_for_file(
        &sarif,
        "CUSTOM-EXAMPLE-CUSTOM-AUTH-001",
        "workers/reconcile.py"
    ));
    assert!(results_for_rule(&sarif, "EXP-NOISE-001").is_empty());

    // Text mode writes LIVE_AUDIT.md as well
    let (txt_res, live_md) = repo.run_audit_text(&["--plugins", "profile:fintech,example-custom-auth"]);
    assert!(txt_res.success, "stderr: {}", txt_res.stderr);
    let live_md = live_md.expect(".aether/LIVE_AUDIT.md");
    assert!(live_md.contains("FINTECH-TX-GUARD-001"));
}

#[test]
fn t4_s2_web_backend_ssa_taint_sanitizer_fail_on_gate() {
    let repo = TestRepo::new();
    repo.write_plugin(
        "web-taint-pack",
        &std_taint_plugin_yaml("web-taint-pack", None, None),
    );

    // Multi-file Python Web Backend (NO Cargo.toml at root, no `{}` dict literals inside functions)
    repo.write_file(
        "src/http_input.py",
        r#"def read_search_term(req):
    term = get_untrusted_param(req)
    return term
"#,
    );
    repo.write_file(
        "src/query_builder.py",
        r#"def format_lookup(raw_term):
    sql_arg = raw_term
    return sql_arg
"#,
    );
    repo.write_file(
        "src/db_exec.py",
        r#"def run_user_search(req):
    raw = read_search_term(req)
    stmt = format_lookup(raw)
    exec_raw_sql(stmt)
"#,
    );
    repo.write_file(
        "src/config.py",
        r#"import yaml

def load_app_config(raw):
    return yaml.load(raw)
"#,
    );

    // Phase 1: Unsanitized cross-file flow triggers CRITICAL SARIF finding & fails --fail-on HIGH
    let (res_sarif, sarif_opt) = repo.run_audit_sarif(&["--plugins", "web-taint-pack"]);
    assert!(res_sarif.success, "stderr: {}", res_sarif.stderr);
    let sarif = sarif_opt.expect("out.sarif");
    let taint_hits = results_for_rule(&sarif, "PLUGIN-TAINT-SQLI-001");
    assert!(
        !taint_hits.is_empty(),
        "expected cross-file Python taint hit in S2; got {:?}",
        sarif_result_rule_ids(&sarif)
    );
    assert_eq!(taint_hits[0]["level"], "error");
    assert_eq!(taint_hits[0]["properties"]["is_reachable"], Value::Bool(true));

    let (gate_fail, _) = repo.run_audit_sarif(&["--plugins", "web-taint-pack", "--fail-on", "HIGH"]);
    assert_eq!(
        gate_fail.code, 1,
        "unsanitized CRITICAL taint finding must fail --fail-on HIGH"
    );

    // Phase 2: Remediate db_exec.py using safe_handler sanitizer -> --fail-on HIGH exits 0
    repo.write_file(
        "src/safe_handler.py",
        r#"def safe_lookup(raw_term):
    cleaned = sanitize_sql_param(raw_term)
    return cleaned
"#,
    );
    repo.write_file(
        "src/db_exec.py",
        r#"def run_user_search(req):
    raw = read_search_term(req)
    stmt = safe_lookup(raw)
    exec_raw_sql(stmt)
"#,
    );

    let (gate_pass, sarif_clean_opt) =
        repo.run_audit_sarif(&["--plugins", "web-taint-pack", "--fail-on", "HIGH"]);
    assert!(
        gate_pass.success,
        "sanitized cross-file flow must pass --fail-on HIGH; stderr: {}",
        gate_pass.stderr
    );
    if let Some(sarif_clean) = sarif_clean_opt {
        let any_reachable = results_for_rule(&sarif_clean, "PLUGIN-TAINT-SQLI-001")
            .into_iter()
            .any(|r| r["properties"]["is_reachable"] == Value::Bool(true));
        assert!(
            !any_reachable,
            "sanitized flow must have no reachable PLUGIN-TAINT-SQLI-001 finding"
        );
    }

    // Phase 3: Native parity check (--plugins all still detects CVE-PY-YAML-UNSAFE-LOAD in src/config.py)
    let (all_res, all_sarif_opt) = repo.run_audit_sarif(&["--plugins", "all"]);
    assert!(all_res.success, "stderr: {}", all_res.stderr);
    let all_sarif = all_sarif_opt.expect("out.sarif");
    assert!(
        has_result_for_file(&all_sarif, "CVE-PY-YAML-UNSAFE-LOAD", "src/config.py"),
        "--plugins all must still detect CVE-PY-YAML-UNSAFE-LOAD in src/config.py"
    );
}
