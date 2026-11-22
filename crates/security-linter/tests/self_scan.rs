//! Auto-scan : le linter ne doit pas se signaler lui-même à cause de ses propres
//! descriptions de règles / catalogues de documentation (faux positifs réflexifs).
//! Lancer avec `--nocapture` pour voir le décompte par fichier et par règle.

use security_linter::SecurityLinter;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn scan(rel: &str) -> Vec<security_linter::LinterViolation> {
    let p = workspace_root().join(rel);
    let content = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e));
    SecurityLinter::audit_file(rel, &content, None)
}

#[test]
fn self_scan_report_and_reflexive_false_positives() {
    let files = [
        "crates/security-linter/src/linter.rs",
        "crates/security-linter/src/rules.rs",
        "crates/security-linter/src/contract.rs",
        "crates/desktop-shell/ui/src/engine/physics.worker.js",
        "crates/desktop-shell/ui/src/engine/shaders.ts",
        "crates/desktop-shell/dist/index.html",
    ];
    let mut total = 0;
    for f in files {
        let v = scan(f);
        let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
        for x in &v {
            *by_rule.entry(x.rule_id.clone()).or_default() += 1;
        }
        println!("{:<55} {:>3} violations {:?}", f, v.len(), by_rule);
        total += v.len();
    }
    println!("TOTAL (6 fichiers): {}", total);

    // Le code JS du worker physique ne contient aucun appel réel à eval/exec/sendFile.
    // Limite connue : CVE-WEB3-AUTH-BYPASS-MOCK, SAST_HARDCODED_SECRET et CVE-JS-XSS-DOM
    // restent signalés (règles sensibles aux littéraux / innerHTML réels à trier à la main).
    let js = scan("crates/desktop-shell/ui/src/engine/physics.worker.js");
    for rule in [
        "CVE-JS-CODE-INJ",
        "CVE-JS-CMD-INJ",
        "CVE-JS-PATH-TRAVERSAL-SENDFILE",
    ] {
        assert!(
            !js.iter().any(|v| v.rule_id == rule),
            "faux positif réflexif {} dans physics.worker.js",
            rule
        );
    }

    // Les définitions de règles (rules.rs) ne doivent déclencher aucune règle de code dangereux.
    let rules = scan("crates/security-linter/src/rules.rs");
    for v in &rules {
        assert!(
            !["CVE-RUST-UNSAFE-MEM", "CVE-RUST-CMD-INJ", "CVE-RUST-ASYNC-MUTEX"]
                .contains(&v.rule_id.as_str()),
            "faux positif réflexif {} ligne {} dans rules.rs",
            v.rule_id,
            v.line_number
        );
    }
}

#[test]
fn self_scan_m2_modularization_and_f7_precision() {
    use security_linter::contract::ReadmeContract;

    let load_contract = |crate_dir: &str| -> ReadmeContract {
        let p = workspace_root().join(crate_dir).join("README.md");
        let md = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e));
        ReadmeContract::parse(crate_dir, &md).unwrap_or_else(|e| panic!("{}: {}", crate_dir, e))
    };

    let ast_c = load_contract("crates/ast-scanner");
    let core_c = load_contract("crates/core-graph");
    let obs_c = load_contract("crates/obsidian-vault");
    let sec_c = load_contract("crates/security-linter");

    let contracted_files: &[(&str, &ReadmeContract)] = &[
        ("crates/ast-scanner/src/lib.rs", &ast_c),
        ("crates/ast-scanner/src/scanner.rs", &ast_c),
        ("crates/ast-scanner/src/lang/mod.rs", &ast_c),
        ("crates/ast-scanner/src/lang/luau.rs", &ast_c),
        ("crates/ast-scanner/src/lang/php.rs", &ast_c),
        ("crates/ast-scanner/src/lang/java.rs", &ast_c),
        ("crates/ast-scanner/src/lang/jsts.rs", &ast_c),
        ("crates/ast-scanner/src/lang/python.rs", &ast_c),
        ("crates/ast-scanner/src/lang/rust.rs", &ast_c),
        ("crates/ast-scanner/src/lang/cpp.rs", &ast_c),
        ("crates/ast-scanner/src/lang/markdown.rs", &ast_c),
        ("crates/ast-scanner/src/lang/solidity.rs", &ast_c),
        ("crates/ast-scanner/src/lang/zig.rs", &ast_c),
        ("crates/ast-scanner/src/lang/csharp.rs", &ast_c),
        ("crates/core-graph/src/dataflow/mod.rs", &core_c),
        ("crates/core-graph/src/dataflow/types.rs", &core_c),
        ("crates/core-graph/src/dataflow/rules.rs", &core_c),
        ("crates/obsidian-vault/src/lib.rs", &obs_c),
        ("crates/obsidian-vault/src/confinement.rs", &obs_c),
        ("crates/obsidian-vault/src/error.rs", &obs_c),
        ("crates/obsidian-vault/src/lexical.rs", &obs_c),
        ("crates/obsidian-vault/src/detector.rs", &obs_c),
        ("crates/security-linter/src/epic_novel_rules.rs", &sec_c),
        ("crates/security-linter/src/deep_rules.rs", &sec_c),
    ];

    for (rel, contract) in contracted_files {
        let p = workspace_root().join(rel);
        let content = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e));
        let violations = SecurityLinter::audit_file(rel, &content, Some(contract));
        assert!(
            !violations.iter().any(|v| v.rule_id == "RULE_MAX_LINES" || v.rule_id == "RULE_FORBIDDEN_IMPORT"),
            "Contract violation in {}: {:?}",
            rel,
            violations
        );
        assert!(
            !violations.iter().any(|v| v.rule_id == "AETHER-RUST-PATH-JOIN-PREFIX-WIPE"),
            "Unexpected AETHER-RUST-PATH-JOIN-PREFIX-WIPE false positive in {}: {:?}",
            rel,
            violations
        );
    }

    // Verify F7 on api_routes.rs (both real file and pre-fix static .args([...]) pattern)
    let api_violations = scan("crates/desktop-shell/src/api_routes.rs");
    assert!(
        !api_violations.iter().any(|v| v.rule_id == "CVE-INJ-POSIX-FLAG-SMUGGLING"),
        "Unexpected CVE-INJ-POSIX-FLAG-SMUGGLING in api_routes.rs: {:?}",
        api_violations
    );

    let legacy_static_git = r#"
pub fn run_git_porcelain(project_root: &std::path::Path) {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["status", "--porcelain=v1", "-uall", "--ignored=no"]).current_dir(project_root);
    let mut branch_cmd = std::process::Command::new("git");
    branch_cmd.args(["rev-parse", "--abbrev-ref", "HEAD"]).current_dir(project_root);
}
"#;
    let legacy_hits = SecurityLinter::audit_file("crates/desktop-shell/src/api_routes.rs", legacy_static_git, None);
    assert!(
        !legacy_hits.iter().any(|v| v.rule_id == "CVE-INJ-POSIX-FLAG-SMUGGLING"),
        "Static .args([...]) should not trigger CVE-INJ-POSIX-FLAG-SMUGGLING: {:?}",
        legacy_hits
    );

    // Confirm genuine CWE patterns still trigger via SecurityLinter::audit_file
    let genuine_path_wipe = r#"
use std::path::PathBuf;
pub fn install(server_id: &str, dir: Option<PathBuf>) -> PathBuf {
    let target_dir = dir.unwrap_or_else(|| PathBuf::from("instances").join(&server_id));
    std::fs::create_dir_all(&target_dir).ok();
    target_dir
}
"#;
    let wipe_hits = SecurityLinter::audit_file("apps/aethercraft/runner/src/main.rs", genuine_path_wipe, None);
    assert!(
        wipe_hits.iter().any(|v| v.rule_id == "AETHER-RUST-PATH-JOIN-PREFIX-WIPE"),
        "Genuine PathBuf::join must still trigger: {:?}",
        wipe_hits
    );

    let genuine_flag_smuggle = r#"
pub fn diff(user_ref: &str) {
    std::process::Command::new("git").args(["diff", user_ref]).status().unwrap();
}
"#;
    let flag_hits = SecurityLinter::audit_file("src/git.rs", genuine_flag_smuggle, None);
    assert!(
        flag_hits.iter().any(|v| v.rule_id == "CVE-INJ-POSIX-FLAG-SMUGGLING"),
        "Genuine dynamic .args([..., user_ref]) must still trigger: {:?}",
        flag_hits
    );
}
