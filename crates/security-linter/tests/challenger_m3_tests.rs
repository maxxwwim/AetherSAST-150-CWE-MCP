//! Empirical Verification & Adversarial Stress Tests for Milestone M3 (Reachable SCA & OSV.dev)
//! Author: teamwork_challenger_v3_2

use core_graph::bubble::{AstMethod, SymbolBubble, SymbolKind};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::AetherGraph;
use security_linter::sca::*;
use std::fs;
use std::path::PathBuf;

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("challenger_{}_{}_{}", prefix, std::process::id(), timestamp));
        fs::create_dir_all(&path).expect("Failed to create temporary directory");
        Self { path }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_bubble(id: &str, kind: SymbolKind) -> SymbolBubble {
    let name = id.split("::").last().unwrap_or(id).to_string();
    SymbolBubble::new(
        id.to_string(),
        name,
        "src/test.rs".to_string(),
        1,
        kind,
        "server".to_string(),
        "domain".to_string(),
    )
}

fn create_call_edge(source: &str, target: &str) -> AffiliationEdge {
    AffiliationEdge::new(
        source.to_string(),
        target.to_string(),
        EdgeType::Call,
        FilterAffiliation::PHYSICAL | FilterAffiliation::SEMANTIC,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. ADVERSARIAL LOCKFILE PARSER STRESS TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_challenger_cargo_lock_robustness() {
    // 1. CRLF line endings, key order variation, git dependencies, comments
    let complex_cargo_lock = "\r\n# Top-level comment\r\nversion = 4\r\n\r\n[[package]]\r\nversion = \"0.1.0\"\r\nname = \"root-crate\"\r\n\r\n[[package]]\r\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\r\nversion = \"1.0.109\"\r\nname = \"syn\"\r\n\r\n[[package]]\r\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\r\nname = \"syn\"\r\nversion = \"2.0.15\"\r\n\r\n[[package]]\r\nname = \"git-dep\"\r\nversion = \"0.4.2\"\r\nsource = \"git+https://github.com/org/git-dep.git?branch=main\"\r\n\r\n[[package]]\r\nname = \"local-path-dep\"\r\nversion = \"0.1.0\"\r\n";

    let deps = parse_cargo_lock_content(complex_cargo_lock, "Cargo.lock")
        .expect("Complex Cargo.lock should parse successfully");

    // Only external registry and git dependencies should be captured; root & local path excluded
    assert_eq!(deps.len(), 3, "Expected 3 dependencies (syn v1, syn v2, git-dep)");

    let syn_v1 = deps.iter().find(|d| d.name == "syn" && d.version == "1.0.109");
    assert!(syn_v1.is_some(), "syn 1.0.109 must be present");
    assert_eq!(syn_v1.unwrap().ecosystem, "crates.io");

    let syn_v2 = deps.iter().find(|d| d.name == "syn" && d.version == "2.0.15");
    assert!(syn_v2.is_some(), "syn 2.0.15 must be present");

    let git_dep = deps.iter().find(|d| d.name == "git-dep");
    assert!(git_dep.is_some(), "git-dep must be captured from git+ source");
    assert_eq!(git_dep.unwrap().version, "0.4.2");

    // 2. Adversarial empty & whitespace-only
    assert_eq!(parse_cargo_lock_content("", "Cargo.lock").unwrap().len(), 0);
    assert_eq!(parse_cargo_lock_content("   \n\n\t  \r\n", "Cargo.lock").unwrap().len(), 0);

    // 3. Syntax errors
    assert!(parse_cargo_lock_content("[[package\nname=\"foo\"", "Cargo.lock").is_err());
    assert!(parse_cargo_lock_content("[[package]]\n=foo", "Cargo.lock").is_err());
}

#[test]
fn test_challenger_package_lock_v1_v2_v3_dedup_and_nesting() {
    // Lockfile v2 containing BOTH "packages" and legacy "dependencies"
    // The parser MUST use "packages" and NOT duplicate findings from "dependencies"
    let v2_dual_format = r#"{
      "name": "dual-app",
      "version": "1.0.0",
      "lockfileVersion": 2,
      "packages": {
        "": {
          "name": "dual-app",
          "version": "1.0.0"
        },
        "node_modules/lodash": {
          "version": "4.17.21"
        },
        "node_modules/@scope/pkg": {
          "version": "2.1.0",
          "dev": true
        },
        "node_modules/express/node_modules/cookie": {
          "name": "cookie",
          "version": "0.4.2"
        }
      },
      "dependencies": {
        "lodash": {
          "version": "4.17.21"
        },
        "@scope/pkg": {
          "version": "2.1.0",
          "dev": true
        },
        "express": {
          "version": "4.18.2",
          "dependencies": {
            "cookie": {
              "version": "0.4.2"
            }
          }
        }
      }
    }"#;

    let deps = parse_package_lock_content(v2_dual_format, "package-lock.json")
        .expect("Dual v2 package-lock.json must parse");

    // Exactly 3 dependencies from "packages": lodash, @scope/pkg, cookie
    assert_eq!(deps.len(), 3, "Parser must not double-count packages and dependencies");

    let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
    assert_eq!(lodash.version, "4.17.21");
    assert!(!lodash.is_dev);

    let scoped = deps.iter().find(|d| d.name == "@scope/pkg").unwrap();
    assert_eq!(scoped.version, "2.1.0");
    assert!(scoped.is_dev);

    let cookie = deps.iter().find(|d| d.name == "cookie").unwrap();
    assert_eq!(cookie.version, "0.4.2");

    // Pure v1 with deep nested tree
    let v1_deep = r#"{
      "name": "deep-v1",
      "version": "1.0.0",
      "lockfileVersion": 1,
      "dependencies": {
        "top-dep": {
          "version": "1.0.0",
          "dependencies": {
            "mid-dep": {
              "version": "2.0.0",
              "dependencies": {
                "leaf-dep": {
                  "version": "3.0.0",
                  "dev": true
                }
              }
            }
          }
        }
      }
    }"#;

    let v1_deps = parse_package_lock_content(v1_deep, "package-lock.json").expect("v1 deep parsing");
    assert_eq!(v1_deps.len(), 3);
    assert!(v1_deps.iter().any(|d| d.name == "top-dep" && d.version == "1.0.0" && !d.is_dev));
    assert!(v1_deps.iter().any(|d| d.name == "mid-dep" && d.version == "2.0.0" && !d.is_dev));
    assert!(v1_deps.iter().any(|d| d.name == "leaf-dep" && d.version == "3.0.0" && d.is_dev));
}

#[test]
fn test_challenger_composer_lock_variations() {
    let composer_content = r#"{
      "packages": [
        {
          "name": "laravel/framework",
          "version": "v10.15.0"
        },
        {
          "name": "symfony/console",
          "version": "6.3.2"
        }
      ],
      "packages-dev": [
        {
          "name": "pestphp/pest",
          "version": "v2.8.1"
        }
      ]
    }"#;

    let deps = parse_composer_lock_content(composer_content, "composer.lock").expect("Parse composer.lock");
    assert_eq!(deps.len(), 3);

    let laravel = deps.iter().find(|d| d.name == "laravel/framework").unwrap();
    assert_eq!(laravel.version, "10.15.0", "Leading 'v' must be stripped");
    assert!(!laravel.is_dev);
    assert_eq!(laravel.ecosystem, "Packagist");

    let symfony = deps.iter().find(|d| d.name == "symfony/console").unwrap();
    assert_eq!(symfony.version, "6.3.2");

    let pest = deps.iter().find(|d| d.name == "pestphp/pest").unwrap();
    assert_eq!(pest.version, "2.8.1", "Leading 'v' stripped on dev dep");
    assert!(pest.is_dev);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. OFFLINE CACHING & AIR-GAPPED VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_challenger_offline_caching_full_guarantee() {
    let temp_guard = TempDirGuard::new("offline_guarantee");
    let project_root = &temp_guard.path;

    // 1. Create a Cargo.lock with smallvec 1.6.0
    let lock_content = r#"
version = 4

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    fs::write(project_root.join("Cargo.lock"), lock_content).expect("Write Cargo.lock");

    // 2. Pre-seed local cache file under .aether/cache/osv/
    let cache = OsvCache::default_for_project(project_root);
    let mock_vulns = vec![OsvVulnerability {
        id: "GHSA-smallvec-uaf".to_string(),
        summary: Some("Use-after-free vulnerability in smallvec".to_string()),
        aliases: vec!["CVE-2021-29930".to_string()],
        database_specific: Some(serde_json::json!({ "severity": "CRITICAL" })),
        affected: vec![OsvAffected {
            ecosystem_specific: Some(serde_json::json!({
                "affects": {
                    "functions": ["smallvec::SmallVec::insert_many"]
                }
            })),
            ..Default::default()
        }],
        ..Default::default()
    }];

    cache.put("crates.io", "smallvec", "1.6.0", &mock_vulns).expect("Seed cache");

    let expected_key = derive_osv_cache_key("crates.io", "smallvec", "1.6.0");
    let cache_file = cache.cache_file_path("crates.io", "smallvec", "1.6.0");
    assert!(cache_file.exists(), "Cache file must exist at expected BLAKE3 hash location");
    assert!(cache_file.to_string_lossy().contains(&expected_key));

    // 3. Execute ScaEngine::scan_project with offline_only = true
    let report = ScaEngine::scan_project(project_root, true).expect("Offline scan_project");

    assert_eq!(report.dependencies.len(), 1);
    assert_eq!(report.vulnerabilities.len(), 1);

    let v = &report.vulnerabilities[0];
    assert_eq!(v.dependency.name, "smallvec");
    assert_eq!(v.dependency.version, "1.6.0");
    assert_eq!(v.advisory_id, "GHSA-smallvec-uaf");
    assert_eq!(v.cve_id, "CVE-2021-29930");
    assert_eq!(v.severity, "CRITICAL");
    assert_eq!(v.affected_functions, vec!["smallvec::SmallVec::insert_many"]);

    // 4. Test uncached query with offline_only = true: must return empty, zero network, no error
    let uncached = ScaDependency::new("tokio", "1.30.0", "Cargo", false, "Cargo.lock");
    let uncached_res = query_osv(&uncached, &cache, true).expect("Uncached query");
    assert!(uncached_res.is_empty(), "Offline uncached query must return empty list without network call");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CALL-GRAPH REACHABILITY ADVERSARIAL CHALLENGES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_challenger_reachability_deep_chain_vs_dead_code_branch() {
    let mut graph = AetherGraph::default();

    // 1. Source Endpoint
    let mut ep = create_bubble("api::v1::orders", SymbolKind::FormOrEndpoint);
    ep.stereotype = "Endpoint".to_string();

    // 2. Intermediate Services: ep -> svc_a -> svc_b -> vuln_dep
    let svc_a = create_bubble("src/service.rs::validate_order", SymbolKind::Function);
    let mut svc_b = create_bubble("src/storage.rs::persist_buffer", SymbolKind::Function);

    // Call registration inside method AST
    svc_b.metadata.methods.push(AstMethod {
        name: "persist_buffer".to_string(),
        args: None,
        returns: None,
        is_async: None,
        calls: vec!["smallvec::SmallVec::insert_many".to_string()],
        docstring: None,
    });

    // 3. Dead helper calling another vulnerable function
    let mut dead_helper = create_bubble("src/dead.rs::unused_cleanup", SymbolKind::Function);
    dead_helper.metadata.methods.push(AstMethod {
        name: "unused_cleanup".to_string(),
        args: None,
        returns: None,
        is_async: None,
        calls: vec!["bad_dep::danger_alloc".to_string()],
        docstring: None,
    });

    // 4. Dead cyclic cluster: dead_1 <-> dead_2 -> dead_helper
    let dead_1 = create_bubble("src/dead.rs::dead_loop_1", SymbolKind::Function);
    let dead_2 = create_bubble("src/dead.rs::dead_loop_2", SymbolKind::Function);

    graph.nodes.push(ep);
    graph.nodes.push(svc_a);
    graph.nodes.push(svc_b);
    graph.nodes.push(dead_helper);
    graph.nodes.push(dead_1);
    graph.nodes.push(dead_2);

    // Edges
    graph.edges.push(create_call_edge("api::v1::orders", "src/service.rs::validate_order"));
    graph.edges.push(create_call_edge("src/service.rs::validate_order", "src/storage.rs::persist_buffer"));
    graph.edges.push(create_call_edge("src/dead.rs::dead_loop_1", "src/dead.rs::dead_loop_2"));
    graph.edges.push(create_call_edge("src/dead.rs::dead_loop_2", "src/dead.rs::dead_loop_1"));
    graph.edges.push(create_call_edge("src/dead.rs::dead_loop_2", "src/dead.rs::unused_cleanup"));

    let mut report = ScaReport {
        dependencies: vec![
            ScaDependency::new("smallvec", "1.6.0", "crates.io", false, "Cargo.lock"),
            ScaDependency::new("bad_dep", "0.1.0", "crates.io", false, "Cargo.lock"),
            ScaDependency::new("uncalled_dep", "1.0.0", "crates.io", false, "Cargo.lock"),
        ],
        vulnerabilities: vec![
            ScaVulnerability {
                dependency: ScaDependency::new("smallvec", "1.6.0", "crates.io", false, "Cargo.lock"),
                advisory_id: "GHSA-1".to_string(),
                cve_id: "CVE-2021-29930".to_string(),
                severity: "CRITICAL".to_string(),
                summary: "UAF in insert_many".to_string(),
                affected_functions: vec!["smallvec::SmallVec::insert_many".to_string()],
                is_reachable: false,
                exploit_path: Vec::new(),
                remediation: "Upgrade".to_string(),
            },
            ScaVulnerability {
                dependency: ScaDependency::new("bad_dep", "0.1.0", "crates.io", false, "Cargo.lock"),
                advisory_id: "GHSA-2".to_string(),
                cve_id: "CVE-2023-0002".to_string(),
                severity: "HIGH".to_string(),
                summary: "OOM in danger_alloc".to_string(),
                affected_functions: vec!["bad_dep::danger_alloc".to_string()],
                is_reachable: false,
                exploit_path: Vec::new(),
                remediation: "Upgrade".to_string(),
            },
            ScaVulnerability {
                dependency: ScaDependency::new("uncalled_dep", "1.0.0", "crates.io", false, "Cargo.lock"),
                advisory_id: "GHSA-3".to_string(),
                cve_id: "CVE-2023-0003".to_string(),
                severity: "MEDIUM".to_string(),
                summary: "Unreferenced advisory".to_string(),
                affected_functions: vec!["uncalled_dep::never_called".to_string()],
                is_reachable: false,
                exploit_path: Vec::new(),
                remediation: "Upgrade".to_string(),
            },
        ],
        ..Default::default()
    };

    ScaEngine::cross_reference_reachability(&mut graph, &mut report);

    assert_eq!(report.reachable_count, 1, "Only smallvec should be reachable");
    assert_eq!(report.unreachable_count, 2, "bad_dep and uncalled_dep must be unreachable");

    // Check smallvec
    let v_reach = report.vulnerabilities.iter().find(|v| v.dependency.name == "smallvec").unwrap();
    assert!(v_reach.is_reachable);
    assert_eq!(
        v_reach.exploit_path,
        vec![
            "api::v1::orders",
            "src/service.rs::validate_order",
            "src/storage.rs::persist_buffer",
            "dep::smallvec::smallvec::SmallVec::insert_many"
        ]
    );

    // Check bad_dep (called only from dead code)
    let v_dead = report.vulnerabilities.iter().find(|v| v.dependency.name == "bad_dep").unwrap();
    assert!(!v_dead.is_reachable, "Dependency called only from dead code must NOT be marked reachable");
    assert!(v_dead.exploit_path.is_empty());

    // Check uncalled_dep
    let v_uncalled = report.vulnerabilities.iter().find(|v| v.dependency.name == "uncalled_dep").unwrap();
    assert!(!v_uncalled.is_reachable);
    assert!(v_uncalled.exploit_path.is_empty());
}

#[test]
fn test_challenger_package_wide_advisory_reachability() {
    let mut graph = AetherGraph::default();

    let mut ep = create_bubble("api::gateway", SymbolKind::FormOrEndpoint);
    ep.stereotype = "Endpoint".to_string();

    let mut app_fn = create_bubble("src/app.rs::init_telemetry", SymbolKind::Function);
    app_fn.metadata.methods.push(AstMethod {
        name: "init_telemetry".to_string(),
        args: None,
        returns: None,
        is_async: None,
        calls: vec!["telemetry_pkg::init".to_string()],
        docstring: None,
    });

    graph.nodes.push(ep);
    graph.nodes.push(app_fn);
    graph.edges.push(create_call_edge("api::gateway", "src/app.rs::init_telemetry"));

    // Package-wide vulnerability with empty affected_functions
    let mut report = ScaReport {
        dependencies: vec![ScaDependency::new("telemetry_pkg", "0.2.0", "crates.io", false, "Cargo.lock")],
        vulnerabilities: vec![ScaVulnerability {
            dependency: ScaDependency::new("telemetry_pkg", "0.2.0", "crates.io", false, "Cargo.lock"),
            advisory_id: "GHSA-PACKAGE-WIDE".to_string(),
            cve_id: "CVE-2024-9999".to_string(),
            severity: "HIGH".to_string(),
            summary: "Package-wide RCE in telemetry_pkg".to_string(),
            affected_functions: Vec::new(), // Empty indicates whole package affected
            is_reachable: false,
            exploit_path: Vec::new(),
            remediation: "Upgrade".to_string(),
        }],
        ..Default::default()
    };

    ScaEngine::cross_reference_reachability(&mut graph, &mut report);

    assert_eq!(report.reachable_count, 1);
    let vuln = &report.vulnerabilities[0];
    assert!(vuln.is_reachable, "Package-wide advisory must be reachable when package is called");
    assert_eq!(
        vuln.exploit_path,
        vec!["api::gateway", "src/app.rs::init_telemetry", "dep::telemetry_pkg"]
    );
}

#[test]
fn test_challenger_cargo_lock_inline_comments() {
    let cargo_lock = r#"
version = 4 # version comment

[[package]] # inline table array comment
name = "serde" # fast serializer
version = "1.0.130" # release version
source = "registry+https://github.com/rust-lang/crates.io-index" # crates.io
"#;
    let res = parse_cargo_lock_content(cargo_lock, "Cargo.lock");
    assert!(res.is_ok(), "Cargo.lock with inline comments on string, number, and table parses cleanly");
    let deps = res.unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "serde");
    assert_eq!(deps[0].version, "1.0.130");
}

#[test]
fn test_challenger_call_matches_target_false_positive_risk() {
    let mut graph = AetherGraph::default();

    let mut ep = create_bubble("api::date_parser", SymbolKind::FormOrEndpoint);
    ep.stereotype = "Endpoint".to_string();

    // App calls local helper parse(), NOT the vulnerable json_lib::parse
    let mut app_fn = create_bubble("src/date.rs::parse_date", SymbolKind::Function);
    app_fn.metadata.methods.push(AstMethod {
        name: "parse_date".to_string(),
        args: None,
        returns: None,
        is_async: None,
        calls: vec!["parse".to_string()], // Generic call name
        docstring: None,
    });

    graph.nodes.push(ep);
    graph.nodes.push(app_fn);
    graph.edges.push(create_call_edge("api::date_parser", "src/date.rs::parse_date"));

    let mut report = ScaReport {
        dependencies: vec![ScaDependency::new("json_lib", "1.0.0", "crates.io", false, "Cargo.lock")],
        vulnerabilities: vec![ScaVulnerability {
            dependency: ScaDependency::new("json_lib", "1.0.0", "crates.io", false, "Cargo.lock"),
            advisory_id: "GHSA-JSON-PARSE".to_string(),
            cve_id: "CVE-2024-1111".to_string(),
            severity: "HIGH".to_string(),
            summary: "Crash in json parse".to_string(),
            affected_functions: vec!["json_lib::parse".to_string()],
            is_reachable: false,
            exploit_path: Vec::new(),
            remediation: "Upgrade".to_string(),
        }],
        ..Default::default()
    };

    ScaEngine::cross_reference_reachability(&mut graph, &mut report);

    let vuln = &report.vulnerabilities[0];
    eprintln!("Is reachable with generic call 'parse': {}", vuln.is_reachable);
    assert!(
        !vuln.is_reachable,
        "Generic local method 'parse' must NOT match third-party dependency json_lib::parse"
    );
}

#[test]
fn test_challenger_osv_severity_resolution() {
    let vuln_crit = OsvVulnerability {
        database_specific: Some(serde_json::json!({ "severity": "CRITICAL" })),
        ..Default::default()
    };
    assert_eq!(vuln_crit.resolve_severity(), "CRITICAL");

    let vuln_high = OsvVulnerability {
        database_specific: Some(serde_json::json!({ "severity": "HIGH" })),
        ..Default::default()
    };
    assert_eq!(vuln_high.resolve_severity(), "HIGH");

    let vuln_med = OsvVulnerability {
        database_specific: Some(serde_json::json!({ "severity": "MODERATE" })),
        ..Default::default()
    };
    assert_eq!(vuln_med.resolve_severity(), "MEDIUM");

    let vuln_low = OsvVulnerability {
        database_specific: Some(serde_json::json!({ "severity": "LOW" })),
        ..Default::default()
    };
    assert_eq!(vuln_low.resolve_severity(), "LOW");

    // CVSS score fallback
    let vuln_cvss = OsvVulnerability {
        severity: vec![OsvSeverity {
            r#type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        }],
        ..Default::default()
    };
    assert_eq!(vuln_cvss.resolve_severity(), "CRITICAL");
}

