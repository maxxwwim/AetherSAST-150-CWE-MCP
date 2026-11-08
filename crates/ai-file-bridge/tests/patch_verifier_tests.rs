use ai_file_bridge::patch_verifier::{PatchVerifier, PatchVerdict};
use core_graph::bubble::{SymbolBubble, SymbolKind};
use core_graph::graph::AetherGraph;
use std::fs;
use std::path::PathBuf;

fn make_test_dir(suffix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "aether_patch_{}_{}",
        suffix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn test_patch_approved_scenario() {
    let tmp = make_test_dir("t1");
    fs::write(
        tmp.join("README.md"),
        "---\nid: my-crate\nlayer: domain\nmax_lines_per_file: 300\nallowed_imports: [\"std::*\"]\nforbidden_imports: [\"ast_scanner::*\"]\n---\n# My Crate\n",
    )
    .unwrap();
    fs::write(tmp.join("clean.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }\n").unwrap();
    let result = PatchVerifier::verify_patch(&tmp, &["clean.rs".to_string()], None);
    assert_eq!(result.verdict, PatchVerdict::Approved);
    assert!(result.violations.is_empty());
    assert!(result.formatted_output.contains("[PATCH_APPROVED]"));
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_patch_rejected_forbidden_import_and_max_lines() {
    let tmp = make_test_dir("t2");
    fs::write(
        tmp.join("README.md"),
        "---\nid: my-crate\nlayer: domain\nmax_lines_per_file: 3\nallowed_imports: [\"std::*\"]\nforbidden_imports: [\"ast_scanner::*\"]\n---\n# My Crate\n",
    )
    .unwrap();
    fs::write(
        tmp.join("bad.rs"),
        "use ast_scanner::*;\npub fn foo() {}\npub fn bar() {}\npub fn baz() {}\n",
    )
    .unwrap();
    let result = PatchVerifier::verify_patch(&tmp, &["bad.rs".to_string()], None);
    assert_eq!(result.verdict, PatchVerdict::Rejected);
    assert!(result.violations.iter().any(|v| v.rule_id == "RULE_FORBIDDEN_IMPORT"));
    assert!(result.violations.iter().any(|v| v.rule_id == "RULE_MAX_LINES"));
    assert!(result.formatted_output.contains("[PATCH_REJECTED]"));
    assert!(result.offending_target.is_some());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_patch_rejected_blake3_tampered() {
    let tmp = make_test_dir("t3");
    fs::write(
        tmp.join("aether.lock.toml"),
        "[galaxies.root]\npath = \".\"\nreadme_blake3 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
    )
    .unwrap();
    fs::write(tmp.join("README.md"), "---\nid: root\nlayer: domain\n---\n# Altered\n").unwrap();
    let result = PatchVerifier::verify_patch(&tmp, &["README.md".to_string()], None);
    assert_eq!(result.verdict, PatchVerdict::Rejected);
    assert!(result.violations.iter().any(|v| v.rule_id == "BLAKE3_TAMPERED"));
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_reachability_exploit_path_graph() {
    let tmp = make_test_dir("t4");
    fs::write(
        tmp.join("README.md"),
        "---\nid: root\nlayer: domain\nsecurity_rules:\n  no_raw_sql: true\n---\n# Root\n",
    )
    .unwrap();
    fs::write(
        tmp.join("vuln.rs"),
        "pub fn query(user_input: &str) {\n    let q = format!(\"SELECT * FROM users WHERE name = {}\", user_input);\n}\n",
    )
    .unwrap();
    let mut graph = AetherGraph::new("test");
    let ep = SymbolBubble::new(
        "ep".to_string(),
        "ep".to_string(),
        "vuln.rs".to_string(),
        1,
        SymbolKind::FormOrEndpoint,
        "server".to_string(),
        "domain".to_string(),
    );
    graph.add_node(ep);
    let result = PatchVerifier::verify_patch_with_graph(&tmp, &["vuln.rs".to_string()], None, Some(graph));
    assert_eq!(result.verdict, PatchVerdict::Rejected);
    assert!(result.violations.iter().any(|v| v.rule_id == "SAST_RAW_SQL_INJECTION"));
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_patch_rejected_file_not_found() {
    let tmp = make_test_dir("t5");
    let result = PatchVerifier::verify_patch(&tmp, &["non_existent_file.rs".to_string()], None);
    assert_eq!(result.verdict, PatchVerdict::Rejected);
    assert!(result.violations.iter().any(|v| v.rule_id == "FILE_NOT_FOUND"));
    assert!(result.formatted_output.contains("[PATCH_REJECTED]"));
    let _ = fs::remove_dir_all(&tmp);
}
