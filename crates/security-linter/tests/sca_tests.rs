use core_graph::bubble::{AstMethod, SymbolBubble, SymbolKind};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::AetherGraph;
use security_linter::sca::*;
use std::fs;
use std::path::PathBuf;

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

fn create_bubble(id: &str, kind: SymbolKind) -> SymbolBubble {
    let name = id.split("::").last().unwrap_or(id).to_string();
    SymbolBubble::new(
        id.to_string(),
        name,
        "src/lib.rs".to_string(),
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
        FilterAffiliation::SEMANTIC,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. LOCKFILE PARSER TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cargo_lock_parsing() {
    let cargo_lock = r#"
version = 4

[[package]]
name = "workspace-root"
version = "0.1.0"
dependencies = [
 "smallvec",
]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1a4dcb31"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.130"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5f06ca26"
"#;

    let deps = parse_cargo_lock_content(cargo_lock, "Cargo.lock").expect("Parse Cargo.lock");
    assert_eq!(deps.len(), 2, "Workspace root without external source must be excluded");

    let smallvec = deps.iter().find(|d| d.name == "smallvec").expect("smallvec found");
    assert_eq!(smallvec.version, "1.6.0");
    assert_eq!(smallvec.ecosystem, "crates.io");
    assert!(!smallvec.is_dev);
    assert_eq!(smallvec.manifest_file, "Cargo.lock");

    let serde = deps.iter().find(|d| d.name == "serde").expect("serde found");
    assert_eq!(serde.version, "1.0.130");
    assert_eq!(serde.ecosystem, "crates.io");
}

#[test]
fn test_npm_lock_parsing_v1_and_v3() {
    // Test v3 flat packages map
    let pkg_lock_v3 = r#"
{
  "name": "my-node-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-node-app",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.20"
    },
    "node_modules/@types/node": {
      "version": "20.11.0",
      "dev": true
    },
    "node_modules/express/node_modules/cookie": {
      "name": "cookie",
      "version": "0.4.1"
    }
  }
}
"#;

    let deps_v3 = parse_package_lock_content(pkg_lock_v3, "package-lock.json").expect("Parse v3");
    assert_eq!(deps_v3.len(), 3);

    let lodash = deps_v3.iter().find(|d| d.name == "lodash").unwrap();
    assert_eq!(lodash.version, "4.17.20");
    assert!(!lodash.is_dev);
    assert_eq!(lodash.ecosystem, "npm");

    let types_node = deps_v3.iter().find(|d| d.name == "@types/node").unwrap();
    assert_eq!(types_node.version, "20.11.0");
    assert!(types_node.is_dev);

    let cookie = deps_v3.iter().find(|d| d.name == "cookie").unwrap();
    assert_eq!(cookie.version, "0.4.1");

    // Test v1 recursive dependencies map
    let pkg_lock_v1 = r#"
{
  "name": "legacy-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "axios": {
      "version": "0.21.1"
    },
    "jest": {
      "version": "27.0.0",
      "dev": true,
      "dependencies": {
        "chalk": {
          "version": "4.1.0",
          "dev": true
        }
      }
    }
  }
}
"#;

    let deps_v1 = parse_package_lock_content(pkg_lock_v1, "package-lock.json").expect("Parse v1");
    assert_eq!(deps_v1.len(), 3);

    let axios = deps_v1.iter().find(|d| d.name == "axios").unwrap();
    assert_eq!(axios.version, "0.21.1");
    assert!(!axios.is_dev);

    let chalk = deps_v1.iter().find(|d| d.name == "chalk").unwrap();
    assert_eq!(chalk.version, "4.1.0");
    assert!(chalk.is_dev);
}

#[test]
fn test_composer_lock_parsing() {
    let composer_lock = r#"
{
  "packages": [
    {
      "name": "guzzlehttp/guzzle",
      "version": "6.5.0"
    },
    {
      "name": "monolog/monolog",
      "version": "v2.2.0"
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "9.5.0"
    }
  ]
}
"#;

    let deps = parse_composer_lock_content(composer_lock, "composer.lock").expect("Parse composer.lock");
    assert_eq!(deps.len(), 3);

    let guzzle = deps.iter().find(|d| d.name == "guzzlehttp/guzzle").unwrap();
    assert_eq!(guzzle.version, "6.5.0");
    assert_eq!(guzzle.ecosystem, "Packagist");
    assert!(!guzzle.is_dev);

    let monolog = deps.iter().find(|d| d.name == "monolog/monolog").unwrap();
    assert_eq!(monolog.version, "2.2.0", "Leading 'v' must be stripped from semver");

    let phpunit = deps.iter().find(|d| d.name == "phpunit/phpunit").unwrap();
    assert_eq!(phpunit.version, "9.5.0");
    assert!(phpunit.is_dev);
}

#[test]
fn test_empty_and_malformed_lockfiles() {
    assert!(parse_cargo_lock_content("", "Cargo.lock").unwrap().is_empty());
    assert!(parse_package_lock_content("{}", "package-lock.json").unwrap().is_empty());
    assert!(parse_composer_lock_content("{}", "composer.lock").unwrap().is_empty());

    let bad_toml = "package = [[not valid toml";
    assert!(parse_cargo_lock_content(bad_toml, "Cargo.lock").is_err());

    let bad_json = "{\"packages\": [unterminated";
    assert!(parse_package_lock_content(bad_json, "package-lock.json").is_err());
    assert!(parse_composer_lock_content(bad_json, "composer.lock").is_err());
}

#[test]
fn test_duplicate_coexisting_versions() {
    let cargo_duplicates = r#"
version = 4

[[package]]
name = "syn"
version = "1.0.109"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "syn"
version = "2.0.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    let deps = parse_cargo_lock_content(cargo_duplicates, "Cargo.lock").unwrap();
    assert_eq!(deps.len(), 2, "Both versions of syn must be preserved");

    let versions: Vec<String> = deps.iter().map(|d| d.version.clone()).collect();
    assert!(versions.contains(&"1.0.109".to_string()));
    assert!(versions.contains(&"2.0.15".to_string()));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. OSV & PERSISTENT DISK CACHE TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_osv_ecosystem_normalization() {
    assert_eq!(normalize_ecosystem("Cargo"), "crates.io");
    assert_eq!(normalize_ecosystem("rust"), "crates.io");
    assert_eq!(normalize_ecosystem("crates.io"), "crates.io");
    assert_eq!(normalize_ecosystem("npm"), "npm");
    assert_eq!(normalize_ecosystem("node"), "npm");
    assert_eq!(normalize_ecosystem("Packagist"), "Packagist");
    assert_eq!(normalize_ecosystem("composer"), "Packagist");
}

#[test]
fn test_osv_offline_caching_guarantee() {
    let temp_dir = TempTestDir::new("sca_cache_offline");
    let cache = OsvCache::new(&temp_dir.path);

    let dep = ScaDependency::new("smallvec", "1.6.0", "Cargo", false, "Cargo.lock");

    // Pre-populate the cache with a known vulnerability
    let mock_vulns = vec![OsvVulnerability {
        id: "RUSTSEC-2021-0003".to_string(),
        summary: Some("SmallVec use-after-free on panic in insert_many".to_string()),
        aliases: vec!["CVE-2021-29930".to_string()],
        database_specific: Some(serde_json::json!({
            "severity": "CRITICAL"
        })),
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

    cache
        .put("crates.io", &dep.name, &dep.version, &mock_vulns)
        .expect("Cache write");

    let cache_file = cache.cache_file_path("crates.io", &dep.name, &dep.version);
    assert!(cache_file.exists(), "Cache file must exist on disk");

    // Query in offline mode (offline_only = true)
    let offline_result = query_osv(&dep, &cache, true).expect("Query OSV offline");
    assert_eq!(offline_result.len(), 1);
    assert_eq!(offline_result[0].id, "RUSTSEC-2021-0003");
    assert_eq!(offline_result[0].resolve_cve_id(), "CVE-2021-29930");
    assert_eq!(offline_result[0].resolve_severity(), "CRITICAL");
    assert_eq!(
        offline_result[0].extract_affected_functions(),
        vec!["smallvec::SmallVec::insert_many"]
    );

    // Query an uncached package in offline mode: must return empty list with zero network attempts
    let uncached_dep = ScaDependency::new("safe-crate", "1.0.0", "Cargo", false, "Cargo.lock");
    let uncached_result = query_osv(&uncached_dep, &cache, true).expect("Uncached query");
    assert!(uncached_result.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CALL-GRAPH REACHABILITY CROSS-REFERENCING TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_reachability_cross_reference_reachable_vs_unreachable() {
    let mut graph = AetherGraph::default();

    // 1. Source Endpoint
    let mut endpoint = create_bubble("api::checkout", SymbolKind::FormOrEndpoint);
    endpoint.stereotype = "Endpoint".to_string();

    // 2. Application Service calling SmallVec::insert_many
    let mut checkout_service = create_bubble("src/checkout.rs::process_cart", SymbolKind::Function);
    checkout_service.metadata.methods.push(AstMethod {
        name: "process_cart".to_string(),
        args: None,
        returns: None,
        is_async: None,
        calls: vec!["smallvec::SmallVec::insert_many".to_string()],
        docstring: None,
    });

    // 3. Dead / Isolated application helper
    let dead_fn = create_bubble("src/dead.rs::orphan_helper", SymbolKind::Function);

    graph.nodes.push(endpoint);
    graph.nodes.push(checkout_service);
    graph.nodes.push(dead_fn);

    // Edge: api::checkout -> src/checkout.rs::process_cart
    graph.edges.push(create_call_edge("api::checkout", "src/checkout.rs::process_cart"));

    // Prepare SCA report with 2 vulnerabilities:
    // - smallvec 1.6.0 (called from checkout service)
    // - dead_crate 0.5.0 (never called)
    let mut report = ScaReport {
        project_root: ".".to_string(),
        dependencies: vec![
            ScaDependency::new("smallvec", "1.6.0", "crates.io", false, "Cargo.lock"),
            ScaDependency::new("dead_crate", "0.5.0", "crates.io", false, "Cargo.lock"),
        ],
        vulnerabilities: vec![
            ScaVulnerability {
                dependency: ScaDependency::new("smallvec", "1.6.0", "crates.io", false, "Cargo.lock"),
                advisory_id: "RUSTSEC-2021-0003".to_string(),
                cve_id: "CVE-2021-29930".to_string(),
                severity: "CRITICAL".to_string(),
                summary: "SmallVec UAF on panic".to_string(),
                affected_functions: vec!["smallvec::SmallVec::insert_many".to_string()],
                is_reachable: false,
                exploit_path: Vec::new(),
                remediation: "Upgrade smallvec >= 1.6.1".to_string(),
            },
            ScaVulnerability {
                dependency: ScaDependency::new("dead_crate", "0.5.0", "crates.io", false, "Cargo.lock"),
                advisory_id: "RUSTSEC-2020-0099".to_string(),
                cve_id: "CVE-2020-99999".to_string(),
                severity: "HIGH".to_string(),
                summary: "Memory leak in uncalled dependency".to_string(),
                affected_functions: vec!["dead_crate::leak".to_string()],
                is_reachable: false,
                exploit_path: Vec::new(),
                remediation: "Remove dead_crate".to_string(),
            },
        ],
        ..Default::default()
    };

    // Run cross-referencing
    ScaEngine::cross_reference_reachability(&mut graph, &mut report);

    // Verify smallvec is marked REACHABLE with full exploit path
    let smallvec_vuln = report
        .vulnerabilities
        .iter()
        .find(|v| v.dependency.name == "smallvec")
        .expect("smallvec finding");
    assert!(
        smallvec_vuln.is_reachable,
        "smallvec called from Endpoint must be marked REACHABLE"
    );
    assert_eq!(
        smallvec_vuln.exploit_path,
        vec![
            "api::checkout",
            "src/checkout.rs::process_cart",
            "dep::smallvec::smallvec::SmallVec::insert_many"
        ]
    );

    // Verify dead_crate is marked UNREACHABLE with empty exploit path
    let dead_vuln = report
        .vulnerabilities
        .iter()
        .find(|v| v.dependency.name == "dead_crate")
        .expect("dead_crate finding");
    assert!(
        !dead_vuln.is_reachable,
        "Uncalled dependency must be marked UNREACHABLE"
    );
    assert!(
        dead_vuln.exploit_path.is_empty(),
        "Unreachable vulnerability must have empty exploit path"
    );

    assert_eq!(report.reachable_count, 1);
    assert_eq!(report.unreachable_count, 1);
}
