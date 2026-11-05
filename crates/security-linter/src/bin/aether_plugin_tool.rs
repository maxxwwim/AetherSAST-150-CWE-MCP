use security_linter::plugin::{PluginEngine, PluginManifest, PluginRule, RuleConditions, RuleTestCase};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn print_banner() {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║       🪐 AETHERSCOPE SAST PLUGIN TOOLKIT & INTERPRETER         ║");
    println!("║       Moteur d'interprétation & test de règles CWE / Plugins  ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");
}

fn print_usage() {
    print_banner();
    println!("USAGE:");
    println!("  aether-plugin-tool <COMMAND> [OPTIONS]\n");
    println!("COMMANDS:");
    println!("  test <plugins_dir>                 Exécute la suite de tests unitaires intégrée aux plugins");
    println!("  scan <plugins_dir> <target_path>   Audite un fichier ou un dossier complet avec les plugins");
    println!("  list <plugins_dir>                 Liste tous les plugins et règles CWE détectés");
    println!("  init <plugin_name> [output_dir]    Génère un squelette de plugin prêt à l'emploi");
    println!("  export <plugins_dir> [out.md]      Exporte le catalogue des règles en Markdown\n");
    println!("EXEMPLES:");
    println!("  aether-plugin-tool test .aether/plugins");
    println!("  aether-plugin-tool scan .aether/plugins ./crates/core-graph");
    println!("  aether-plugin-tool init my-custom-rules .aether/plugins\n");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(0);
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => {
            print_usage();
        }
        "test" => {
            print_banner();
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".aether/plugins");
            let mut engine = PluginEngine::new();
            println!("🔍 Chargement des plugins depuis : {}", dir);
            match engine.load_from_directory(dir) {
                Ok(count) => {
                    println!("📦 {} plugin(s) actif(s) chargé(s).\n", count);
                    let report = engine.run_test_suite();
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("📊 RÉSULTAT DES TESTS UNITAIRES :");
                    println!("   • Total des tests : {}", report.total_tests);
                    println!("   • Succès          : {}", report.passed);
                    println!("   • Échecs          : {}", report.failed);
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    if report.failed > 0 {
                        println!("\n❌ Détails des échecs :");
                        for f in report.failures {
                            println!("   {}", f);
                        }
                        std::process::exit(1);
                    } else {
                        println!("\n✨ Tous les tests unitaires des plugins sont passés avec succès !");
                    }
                }
                Err(e) => {
                    eprintln!("❌ Erreur lors du chargement : {}", e);
                    std::process::exit(1);
                }
            }
        }
        "list" => {
            print_banner();
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".aether/plugins");
            let mut engine = PluginEngine::new();
            if let Err(e) = engine.load_from_directory(dir) {
                eprintln!("❌ Erreur : {}", e);
                std::process::exit(1);
            }
            println!("📋 Plugins chargés depuis '{}' :\n", dir);
            for p in &engine.plugins {
                println!("• Plugin : {} (v{}) - {}", p.name, p.version, p.description.as_deref().unwrap_or(""));
                for r in &p.rules {
                    println!("    ├── [{}] {} ({}) [Severity: {}]", r.id, r.name, r.cwe_id, r.severity);
                    println!("    │   Extensions: {:?}", r.file_extensions);
                }
                println!();
            }
        }
        "scan" => {
            print_banner();
            if args.len() < 4 {
                eprintln!("❌ Utilisation : aether-plugin-tool scan <plugins_dir> <target_path>");
                std::process::exit(1);
            }
            let plugins_dir = &args[2];
            let target_path = PathBuf::from(&args[3]);

            let mut engine = PluginEngine::new();
            if let Err(e) = engine.load_from_directory(plugins_dir) {
                eprintln!("❌ Erreur de chargement des plugins : {}", e);
                std::process::exit(1);
            }

            println!("🛡️ Audit SAST en cours sur : {}", target_path.display());
            let mut total_violations = 0;

            if target_path.is_file() {
                if let Ok(content) = fs::read_to_string(&target_path) {
                    let v = engine.audit_file(&target_path.to_string_lossy(), &content);
                    print_violations(&target_path.to_string_lossy(), &v);
                    total_violations += v.len();
                }
            } else if target_path.is_dir() {
                scan_directory_recursive(&mut engine, &target_path, &mut total_violations);
            } else {
                eprintln!("❌ Chemin introuvable : {}", target_path.display());
                std::process::exit(1);
            }

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("🎯 Bilan de l'audit : {} violation(s) détectée(s)", total_violations);
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
        "init" => {
            print_banner();
            if args.len() < 3 {
                eprintln!("❌ Utilisation : aether-plugin-tool init <plugin_name> [output_dir]");
                std::process::exit(1);
            }
            let plugin_name = &args[2];
            let base_dir = args.get(3).map(|s| s.as_str()).unwrap_or(".aether/plugins");
            let target_dir = Path::new(base_dir).join(plugin_name);

            if let Err(e) = fs::create_dir_all(&target_dir) {
                eprintln!("❌ Impossible de créer le dossier {} : {}", target_dir.display(), e);
                std::process::exit(1);
            }

            let sample = PluginManifest {
                name: plugin_name.to_string(),
                version: "1.0.0".to_string(),
                author: Some("Security Team".to_string()),
                description: Some(format!("Custom security plugin: {plugin_name}")),
                enabled: true,
                rules: vec![
                    PluginRule {
                        id: format!("CUSTOM-{}-001", plugin_name.to_uppercase()),
                        cwe_id: "CWE-287 / AUTH-BYPASS".to_string(),
                        name: "Exemple de règle personnalisée anti-bypass".to_string(),
                        category: "Custom / Security".to_string(),
                        severity: "HIGH".to_string(),
                        description: "Détection d'un contournement d'authentification ou fonction non protégée".to_string(),
                        remediation: "Appliquez le middleware de vérification d'autorisation avant d'exécuter l'action.".to_string(),
                        file_extensions: vec![".rs".to_string(), ".py".to_string(), ".ts".to_string()],
                        match_mode: security_linter::plugin::MatchMode::LineByLine,
                        conditions: RuleConditions {
                            must_contain: vec![],
                            must_not_contain: vec!["verify_token".to_string(), "is_authenticated".to_string()],
                            regex_patterns: vec!["fn\\s+admin_\\w+\\s*\\(".to_string(), "def\\s+admin_\\w+\\s*\\(".to_string()],
                            forbidden_tokens: vec![],
                            check_literals: false,
                        },
                        test_cases: vec![
                            RuleTestCase {
                                name: "Fonction admin sans vérification (Vulnérable)".to_string(),
                                file_name: "admin.rs".to_string(),
                                should_trigger: true,
                                code: "pub fn admin_delete_user() { database.delete(); }".to_string(),
                            },
                            RuleTestCase {
                                name: "Fonction admin sécurisée (Pass)".to_string(),
                                file_name: "admin.rs".to_string(),
                                should_trigger: false,
                                code: "pub fn admin_delete_user() { if is_authenticated() { database.delete(); } }".to_string(),
                            },
                        ],
                    }
                ],
            };

            let out_file = target_dir.join("plugin.yaml");
            let yaml_str = serde_yaml::to_string(&sample).unwrap();
            if let Err(e) = fs::write(&out_file, yaml_str) {
                eprintln!("❌ Impossible d'écrire le fichier {} : {}", out_file.display(), e);
                std::process::exit(1);
            }

            println!("✅ Plugin initialisé avec succès dans : {}", out_file.display());
            println!("💡 Pour tester ce plugin :");
            println!("   aether-plugin-tool test {}", base_dir);
        }
        "export" => {
            print_banner();
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".aether/plugins");
            let out_path = args.get(3).map(|s| s.as_str()).unwrap_or("PLUGIN_CATALOG.md");
            let mut engine = PluginEngine::new();
            if let Err(e) = engine.load_from_directory(dir) {
                eprintln!("❌ Erreur : {}", e);
                std::process::exit(1);
            }

            let mut md = String::new();
            md.push_str("# 🔌 Catalogue des Règles Plugins AetherScope\n\n");
            md.push_str(&format!("*Généré automatiquement depuis `{}`*\n\n", dir));

            for p in &engine.plugins {
                md.push_str(&format!("## 📦 Plugin : {} (v{})\n\n", p.name, p.version));
                if let Some(desc) = &p.description {
                    md.push_str(&format!("_{}_\n\n", desc));
                }
                md.push_str("| ID Règle | CWE / Vulnérabilité | Sévérité | Extensions | Description |\n");
                md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
                for r in &p.rules {
                    md.push_str(&format!(
                        "| `{}` | `{}` | **{}** | `{}` | {} |\n",
                        r.id,
                        r.cwe_id,
                        r.severity,
                        r.file_extensions.join(", "),
                        r.description
                    ));
                }
                md.push_str("\n---\n\n");
            }

            if let Err(e) = fs::write(out_path, md) {
                eprintln!("❌ Erreur d'écriture : {}", e);
                std::process::exit(1);
            }
            println!("✅ Catalogue Markdown exporté dans : {}", out_path);
        }
        other => {
            eprintln!("❌ Commande inconnue : {}", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn scan_directory_recursive(engine: &mut PluginEngine, dir: &Path, total_violations: &mut usize) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "target" || name == ".git" || name == "node_modules" {
                    continue;
                }
                scan_directory_recursive(engine, &path, total_violations);
            } else if path.is_file() {
                if let Ok(content) = fs::read_to_string(&path) {
                    let v = engine.audit_file(&path.to_string_lossy(), &content);
                    if !v.is_empty() {
                        print_violations(&path.to_string_lossy(), &v);
                        *total_violations += v.len();
                    }
                }
            }
        }
    }
}

fn print_violations(file: &str, violations: &[security_linter::LinterViolation]) {
    if violations.is_empty() {
        return;
    }
    println!("\n📄 {}", file);
    for v in violations {
        let badge = match v.severity.as_str() {
            "CRITICAL" => "🔴 CRITICAL",
            "HIGH" => "🟠 HIGH",
            "MEDIUM" => "🟡 MEDIUM",
            _ => "🔵 WARNING",
        };
        println!("  ├─ Ligne {:<4} | {:<12} | [{}] {}", v.line_number, badge, v.cve_id, v.message);
        if let Some(snippet) = &v.transmitted_data {
            println!("  │  Snippet: {}", snippet);
        }
        println!("  └─ Remédiation : {}\n", v.remediation);
    }
}
