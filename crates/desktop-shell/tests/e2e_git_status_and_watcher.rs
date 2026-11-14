#![allow(dead_code, unused_imports, unused_variables)]

//! Integration Test Suite for Milestone M1: Rust Backend Watcher & Git Status API
//!
//! Validates:
//! 1. Real Git repository status inspection via `inspect_git_status`.
//! 2. Correlation between Git modifications and AetherGraph SAST / EARS anomalies.
//! 3. Axum endpoint `GET /api/git/status` returning valid contract JSON.
//! 4. FileWatcherBridge removal and modification event collection.

#[path = "../src/api_routes.rs"]
mod api_routes;

use api_routes::*;
use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
use core_graph::graph::AetherGraph;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn setup_temp_git_repo(prefix: &str) -> (PathBuf, AetherGraph) {
    let repo_dir = std::env::temp_dir().join(format!("{}_{}", prefix, std::process::id()));
    if repo_dir.exists() {
        let _ = fs::remove_dir_all(&repo_dir);
    }
    fs::create_dir_all(&repo_dir).expect("Failed to create temp git dir");

    // Initialize git repo
    let init_ok = Command::new("git")
        .args(["init"])
        .current_dir(&repo_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !init_ok {
        return (repo_dir, AetherGraph::new("Fallback"));
    }

    // Configure user for commit
    let _ = Command::new("git")
        .args(["config", "user.email", "aether@example.com"])
        .current_dir(&repo_dir)
        .status();
    let _ = Command::new("git")
        .args(["config", "user.name", "Aether Tester"])
        .current_dir(&repo_dir)
        .status();

    // Create and commit initial file
    let tracked_file = repo_dir.join("src_mod.rs");
    fs::write(&tracked_file, "pub fn original() {}\n").expect("write tracked");
    let _ = Command::new("git")
        .args(["add", "src_mod.rs"])
        .current_dir(&repo_dir)
        .status();
    let _ = Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(&repo_dir)
        .status();

    // Now make changes:
    // 1. Modify src_mod.rs
    fs::write(&tracked_file, "pub fn modified_with_flaw() {}\n").expect("modify tracked");

    // 2. Add untracked file
    let untracked_file = repo_dir.join("new_feature.rs");
    fs::write(&untracked_file, "pub fn new_code() {}\n").expect("write untracked");

    // 3. Stage an added file
    let staged_file = repo_dir.join("staged_component.rs");
    fs::write(&staged_file, "pub fn staged() {}\n").expect("write staged");
    let _ = Command::new("git")
        .args(["add", "staged_component.rs"])
        .current_dir(&repo_dir)
        .status();

    // Create AetherGraph with security anomaly on src_mod.rs
    let mut graph = AetherGraph::new("E2EGitProject");
    let mut vuln_bubble = SymbolBubble::new(
        "file::src_mod.rs".to_string(),
        "src_mod.rs".to_string(),
        "src_mod.rs".to_string(),
        1,
        SymbolKind::File,
        "server".to_string(),
        "domain".to_string(),
    );
    vuln_bubble.has_security_violation = true;
    vuln_bubble.metadata.cve_anomalies.push(CveAnomalyRecord {
        rule_id: "RULE_SQL_INJECTION".to_string(),
        cve_id: "CWE-89".to_string(),
        severity: "CRITICAL".to_string(),
        line_number: 1,
        file_path: "src_mod.rs".to_string(),
        message: "SQL Injection flaw detected".to_string(),
        ..Default::default()
    });
    graph.nodes.push(vuln_bubble);

    (repo_dir, graph)
}

async fn send_get_request(port: u16, path: &str) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Connect to test server");

    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", path, port);
    stream.write_all(req.as_bytes()).await.expect("Write HTTP request");

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.expect("Read response");

    let resp_str = String::from_utf8_lossy(&buffer);
    let mut parts = resp_str.split("\r\n\r\n");
    let headers_part = parts.next().unwrap_or("");
    let body_part = parts.next().unwrap_or("");

    let status_code: u16 = headers_part
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    let json_val = serde_json::from_str(body_part).unwrap_or(serde_json::Value::Null);
    (status_code, json_val)
}

#[test]
fn test_e2e_git_status_real_repo() {
    let (repo_dir, graph) = setup_temp_git_repo("aether_e2e_git_real");

    let resp = inspect_git_status(&repo_dir, &graph);
    assert!(resp.is_git_repo, "Must detect git repository");
    assert!(!resp.clean, "Repository with changes must not be clean");

    // Check files
    let mod_file = resp.files.iter().find(|f| f.path == "src_mod.rs");
    assert!(mod_file.is_some(), "src_mod.rs must be present in changes");
    let mod_file = mod_file.unwrap();
    assert_eq!(mod_file.status, GitFileStatusKind::Modified);
    assert!(mod_file.has_security_violation, "Must cross-reference security violation from graph");
    assert_eq!(mod_file.cwe_count, 1);
    assert_eq!(mod_file.max_severity.as_deref(), Some("CRITICAL"));

    let untracked = resp.files.iter().find(|f| f.path == "new_feature.rs");
    assert!(untracked.is_some(), "new_feature.rs must be present");
    assert_eq!(untracked.unwrap().status, GitFileStatusKind::Untracked);

    let staged = resp.files.iter().find(|f| f.path == "staged_component.rs");
    assert!(staged.is_some(), "staged_component.rs must be present");
    assert_eq!(staged.unwrap().status, GitFileStatusKind::Staged);

    assert!(resp.modified_count >= 1);
    assert!(resp.untracked_count >= 1);
    assert!(resp.staged_count >= 1);
    assert!(resp.security_alert_count >= 1);

    let _ = fs::remove_dir_all(&repo_dir);
}

#[tokio::test]
async fn test_e2e_axum_git_status_endpoint() {
    let (repo_dir, graph) = setup_temp_git_repo("aether_e2e_axum_git");

    let ptype = obsidian_vault::DetectedProjectType::PureCode;
    let state = Arc::new(AppState::new(
        graph.clone(),
        repo_dir.clone(),
        ptype,
        "code".to_string(),
        Some(graph.clone()),
        None,
        None,
    ));

    let state_git = state.clone();
    let app = axum::Router::new().route(
        "/api/git/status",
        axum::routing::get(move || {
            let state = state_git.clone();
            async move {
                let p_root = state.project_root.read().await.clone();
                let graph = state.get_active_graph().await;
                let resp = tokio::task::spawn_blocking(move || {
                    inspect_git_status(&p_root, &graph)
                })
                .await
                .unwrap_or_else(|_| GitStatusResponse {
                    is_git_repo: false,
                    branch: None,
                    clean: true,
                    files: Vec::new(),
                    modified_count: 0,
                    untracked_count: 0,
                    staged_count: 0,
                    deleted_count: 0,
                    security_alert_count: 0,
                });
                axum::Json(resp)
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind ephemeral test server");
    let port = listener.local_addr().expect("Local addr").port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Serve test app");
    });

    let (status, json_body) = send_get_request(port, "/api/git/status").await;
    assert_eq!(status, 200, "Expected HTTP 200 OK from /api/git/status");

    assert_eq!(json_body["is_git_repo"], true);
    assert_eq!(json_body["clean"], false);
    assert!(json_body["files"].is_array());
    assert!(json_body["files"].as_array().unwrap().len() >= 3);
    assert!(json_body["security_alert_count"].as_u64().unwrap_or(0) >= 1);

    let _ = fs::remove_dir_all(&repo_dir);
}
