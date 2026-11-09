#![allow(dead_code, unused_imports, unused_variables)]

//! End-to-End Test Suite for AetherScope Production Obsidian Vault Mode (R1, R2, R3, R4)
//!
//! Validates:
//! - R1: Automatic project detection (`PureObsidianVault`, `PureCode`, `Mixed`) on synthetic fixtures
//!       and dynamic availability of both views (`code` and `vault`).
//! - R2: Complete Obsidian Markdown parsing (`[[note]]`, `[[note|label]]`, `[[note#heading]]`,
//!       `![[embed]]`, `#tag`, YAML frontmatter, backlinks), `core-graph` mapping, and strict
//!       path confinement (`PathGuard`, `TargetJail`).
//! - R3: Axum API (`/api/project/status`, `POST /api/view_mode`), MCP tools, Cockpit WebGL2
//!       dynamic switcher (`#view-mode-toggle`, `switchProjectViewMode`), and dual-mode
//!       standalone HTML viewer bundle.
//! - R4: Synthetic fixtures (`fixture_pure_obsidian_vault`, `fixture_pure_code_project`,
//!       `fixture_mixed_code_vault`) and full end-to-end integration.

#[path = "../src/api_routes.rs"]
mod api_routes;

#[path = "../src/viewer.rs"]
mod viewer;

use api_routes::{AppState, ViewModeError};
use ast_scanner::scanner::ProjectScanner;
use core_graph::edge::EdgeType;
use obsidian_vault::{
    detect_project_type, parse_markdown, scan_obsidian_vault, DetectedProjectType, PathGuard,
    TargetJail,
};
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

// =========================================================================
// R1 & R4: AUTOMATIC DETECTION ON SYNTHETIC FIXTURES
// =========================================================================

#[test]
fn test_r1_detect_pure_obsidian_vault_fixture() {
    let vault_path = fixtures_dir().join("fixture_pure_obsidian_vault");
    let report = detect_project_type(&vault_path).expect("Detection should succeed on pure vault");

    assert_eq!(report.project_type, DetectedProjectType::PureObsidianVault);
    assert!(report.has_obsidian_dir);
    assert_eq!(report.code_files_count, 0);
    assert!(report.markdown_files_count >= 3);
    assert!(report.obsidian_syntax_markers_count >= 5);
    assert_eq!(report.default_view, "vault");
    assert!(report.supported_views.contains(&"vault".to_string()));
}

#[test]
fn test_r1_detect_pure_code_project_fixture() {
    let code_path = fixtures_dir().join("fixture_pure_code_project");
    let report = detect_project_type(&code_path).expect("Detection should succeed on pure code");

    assert_eq!(report.project_type, DetectedProjectType::PureCode);
    assert!(!report.has_obsidian_dir);
    assert!(report.code_files_count >= 2);
    assert_eq!(report.default_view, "code");
    assert_eq!(report.supported_views, vec!["code".to_string()]);
}

#[test]
fn test_r1_detect_mixed_code_vault_fixture() {
    let mixed_path = fixtures_dir().join("fixture_mixed_code_vault");
    let report = detect_project_type(&mixed_path).expect("Detection should succeed on mixed project");

    assert_eq!(report.project_type, DetectedProjectType::Mixed);
    assert!(report.has_obsidian_dir);
    assert!(report.code_files_count >= 1);
    assert!(report.markdown_files_count >= 2);
    assert_eq!(report.default_view, "code");
    assert_eq!(
        report.supported_views,
        vec!["code".to_string(), "vault".to_string()]
    );
}

// =========================================================================
// R2: OBSIDIAN SYNTAX PARSING, CORE-GRAPH MAPPING & STRICT CONFINEMENT
// =========================================================================

#[test]
fn test_r2_full_obsidian_syntax_and_graph_on_pure_vault_fixture() {
    let vault_path = fixtures_dir().join("fixture_pure_obsidian_vault");
    let graph = scan_obsidian_vault(&vault_path).expect("Vault scan should succeed");

    // Verify Note bubbles, Attachment bubble, and GhostNote bubble
    let index_node = graph
        .nodes
        .iter()
        .find(|n| n.id == "note::Index.md" || n.file_path == "Index.md")
        .expect("Index note bubble must exist");
    assert_eq!(index_node.layer, "docs");
    assert_eq!(index_node.stereotype, "«Note»");
    assert!(index_node.layouts.obsidian.is_some());

    let sec_node = graph
        .nodes
        .iter()
        .find(|n| n.file_path.ends_with("SecuritySpecs.md"))
        .expect("SecuritySpecs note bubble must exist");
    let incoming_to_sec = graph
        .edges
        .iter()
        .filter(|e| e.target == sec_node.id)
        .count();
    assert!(
        incoming_to_sec >= 2,
        "SecuritySpecs is linked from both Index and Architecture"
    );

    let ghost_node = graph
        .nodes
        .iter()
        .find(|n| n.name == "FutureRoadmap2030")
        .expect("Unresolved wikilink must materialize a GhostNote bubble");
    assert_eq!(ghost_node.stereotype, "«GhostNote»");

    let attachment_node = graph
        .nodes
        .iter()
        .find(|n| n.name == "Diagram.png")
        .expect("Transcluded attachment Diagram.png must materialize an Attachment bubble");
    assert_eq!(attachment_node.stereotype, "«Attachment»");

    // Verify Edges (EdgeType::Documents / "links_to" for wikilinks, EdgeType::Render / "embeds" for transclusions)
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.source == index_node.id && e.target == sec_node.id && e.edge_type == EdgeType::Documents && e.relation == "links_to"),
        "Wikilink edge from Index to SecuritySpecs must exist"
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.source == index_node.id && e.target == attachment_node.id && e.edge_type == EdgeType::Render && e.relation == "embeds"),
        "Transclusion edge from Index to Diagram.png must exist"
    );

    // Verify code block masking: IgnoredCodeBlockLink must NOT become a GhostNote
    assert!(
        !graph.nodes.iter().any(|n| n.name.contains("IgnoredCodeBlockLink")),
        "Wikilinks inside fenced code blocks must be masked"
    );
}

#[test]
fn test_r2_strict_path_confinement_rejects_escapes() {
    let vault_path = fixtures_dir().join("fixture_pure_obsidian_vault");
    let guard = PathGuard::new(&vault_path).expect("PathGuard init");

    // Reject parent traversal
    assert!(guard.resolve_and_verify(Path::new("../../Cargo.toml")).is_err());
    assert!(TargetJail::sanitize_relative_path("../../etc/passwd").is_err());

    // Reject Windows drive letters & UNC paths
    assert!(TargetJail::sanitize_relative_path(r"C:\Windows\System32\cmd.exe").is_err());
    assert!(TargetJail::sanitize_relative_path(r"\\evil.server\share\note").is_err());

    // Reject null bytes
    assert!(TargetJail::sanitize_relative_path("note\0.md").is_err());

    // Valid in-root note succeeds
    assert!(guard.resolve_and_verify(Path::new("Index.md")).is_ok());
}

// =========================================================================
// R3: AXUM STATE DUAL-VISION SWITCHING & COCKPIT WEBGL2 UI INTEGRATION
// =========================================================================

#[tokio::test]
async fn test_r3_dual_graph_state_and_dynamic_view_mode_toggle_on_mixed_fixture() {
    let mixed_path = fixtures_dir().join("fixture_mixed_code_vault");
    let report = detect_project_type(&mixed_path).expect("Detect mixed fixture");

    let scanner = ProjectScanner::default();
    let code_graph = scanner.scan_project(&mixed_path);
    let vault_graph = scan_obsidian_vault(&mixed_path).expect("Scan vault on mixed fixture");

    let state = AppState::new(
        code_graph.clone(),
        mixed_path.clone(),
        report.project_type,
        "code".to_string(),
        Some(code_graph.clone()),
        Some(vault_graph.clone()),
        Some(report),
    );

    // 1. Check initial status
    let status = state.get_project_status().await;
    assert_eq!(status.project_type, "Mixed");
    assert_eq!(status.active_view_mode, "code");
    assert_eq!(
        status.supported_views,
        vec!["code".to_string(), "vault".to_string()]
    );

    // 2. Switch dynamically to vault view
    let switched_vault = state
        .switch_view_mode("vault")
        .await
        .expect("Switch to vault view should succeed");
    assert!(switched_vault.nodes.iter().any(|n| n.file_path.ends_with("Overview.md")));
    assert!(switched_vault.nodes.iter().any(|n| n.file_path.ends_with("ApiGuide.md")));
    assert_eq!(state.get_project_status().await.active_view_mode, "vault");

    // 3. Switch back to code view
    let switched_code = state
        .switch_view_mode("code")
        .await
        .expect("Switch back to code view should succeed");
    assert!(switched_code
        .nodes
        .iter()
        .any(|n| n.name.contains("HybridService") || n.file_path.contains("service.rs")));
    assert_eq!(state.get_project_status().await.active_view_mode, "code");

    // 4. Reject invalid mode with BadRequest error
    let err = state.switch_view_mode("invalid_mode").await.unwrap_err();
    assert!(matches!(err, ViewModeError::InvalidMode(_)));
}

#[test]
fn test_r3_cockpit_ui_switcher_and_dual_standalone_bundle() {
    let mixed_path = fixtures_dir().join("fixture_mixed_code_vault");
    let scanner = ProjectScanner::default();
    let code_graph = scanner.scan_project(&mixed_path);
    let vault_graph = scan_obsidian_vault(&mixed_path).expect("Vault graph");

    let html = viewer::generate_dual_standalone_html(
        Some(&code_graph),
        Some(&vault_graph),
        DetectedProjectType::Mixed,
        "code",
    );

    // Verify Cockpit UI switcher elements in HTML
    assert!(html.contains("id=\"view-mode-toggle\""));
    assert!(html.contains("id=\"btn-view-mode-code\""));
    assert!(html.contains("id=\"btn-view-mode-vault\""));
    assert!(html.contains("id=\"btn-menu-view-code\""));
    assert!(html.contains("id=\"btn-menu-view-vault\""));
    assert!(html.contains("switchProjectViewMode('code')"));
    assert!(html.contains("switchProjectViewMode('vault')"));

    // Verify embedded dual-vision payload and JS controller functions
    assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
    assert!(html.contains("\"project_type\":\"Mixed\""));
    assert!(html.contains("\"supported_views\":[\"code\",\"vault\"]"));
    assert!(html.contains("async function switchProjectViewMode"));
    assert!(html.contains("fetchProjectStatus"));
}
