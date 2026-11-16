#![allow(dead_code, unused_imports, unused_variables)]

//! E2E Backend Routes Integration Test Suite for AetherScope Dedicated Full-Screen IDE
//!
//! Validates:
//! - POST /api/view_mode: "ide", "IDE", "  ide  ", "editor", invalid mode handling, graph versioning
//! - GET /api/file_content: path traversal defense, secret file defense, raw=true vs raw=false masking
//! - POST /api/save_file: PathGuard confinement, nested directory creation, byte verification, secret blocking
//! - GET /api/files: WalkDir scanning, exclusion of .git/node_modules/target/dist/.aether/.gemini/secrets, metadata
//! - High-concurrency stress: concurrent saves and view-mode flips

#[path = "../src/api_routes.rs"]
mod api_routes;

use ai_file_bridge::{AuditWriter, HandshakePacker};
use api_routes::{
    AiTargetRequest, AiTargetResponse, AppState, FileContentQuery, FileTreeItem,
    ProjectFilesResponse, SaveFileRequest, SaveFileResponse, ViewModeError, ViewModeRequest,
};
use core_graph::graph::AetherGraph;
use core_graph::{SymbolBubble, SymbolKind};
use obsidian_vault::{DetectedProjectType, PathGuard, SecurityError};
use security_linter::contract::ReadmeContract;
use security_linter::{SecretGuard, SecretMasker};
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn security_error_to_status_and_json(
    err: &SecurityError,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::StatusCode;
    match err {
        SecurityError::NullByteDetected(_)
        | SecurityError::PathTraversal(_)
        | SecurityError::UncPathProhibited(_)
        | SecurityError::DriveLetterProhibited(_)
        | SecurityError::AbsolutePathsProhibited(_)
        | SecurityError::UrlSchemeProhibited(_)
        | SecurityError::InvalidPrefix(_)
        | SecurityError::DepthExceeded { .. }
        | SecurityError::ExtensionNotAllowed { .. }
        | SecurityError::NotAFile(_) => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "status": "error",
                "error": "bad_request",
                "message": err.to_string(),
            }),
        ),
        SecurityError::SensitiveFileProhibited(_)
        | SecurityError::PathEscapesRoot { .. }
        | SecurityError::SymlinkEscape { .. }
        | SecurityError::SymlinksDisabled(_) => (
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "status": "error",
                "error": "forbidden",
                "message": err.to_string(),
            }),
        ),
        SecurityError::FileTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            serde_json::json!({
                "status": "error",
                "error": "payload_too_large",
                "message": err.to_string(),
            }),
        ),
        SecurityError::IoError { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "status": "error",
                "error": "not_found",
                "message": err.to_string(),
            }),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "status": "error",
                "error": "internal_error",
                "message": err.to_string(),
            }),
        ),
    }
}

/// Helper to set up a comprehensive mock workspace
fn setup_test_workspace(root: &Path) {
    // Regular project files
    fs::write(root.join("README.md"), "# Welcome to AetherScope IDE Test\nDocumentation here.\n").unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"test-proj\"\nversion = \"0.1.0\"\n").unwrap();
    fs::write(
        root.join("sensitive_tokens.rs"),
        "pub fn get_key() -> &'static str {\n    let token = \"sk-1234567890abcdef1234567890abcdef\";\n    token\n}\n",
    )
    .unwrap();

    // Nested directory structure
    fs::create_dir_all(root.join("src/nested/sub")).unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {\n    println!(\"Hello IDE\");\n}\n").unwrap();
    fs::write(root.join("src/service.rs"), "pub struct Service;\nimpl Service {\n    pub fn run(&self) -> i32 { 42 }\n}\n").unwrap();
    fs::write(root.join("src/nested/sub/mod.rs"), "pub const VERSION: u32 = 1;\n").unwrap();

    // Empty file for 0-byte test
    fs::write(root.join("empty.txt"), "").unwrap();

    // Excluded directories and files
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/config"), "[core]\nrepositoryformatversion = 0\n").unwrap();

    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), "module.exports = {};\n").unwrap();

    fs::create_dir_all(root.join("target/debug")).unwrap();
    fs::write(root.join("target/debug/build.log"), "build output\n").unwrap();

    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("dist/bundle.js"), "console.log('dist');\n").unwrap();

    fs::create_dir_all(root.join(".aether")).unwrap();
    fs::write(root.join(".aether/state.json"), "{\"active\": true}\n").unwrap();

    fs::create_dir_all(root.join(".gemini")).unwrap();
    fs::write(root.join(".gemini/cache.bin"), "cached binary data").unwrap();

    // Sensitive files
    fs::write(root.join(".env"), "SECRET_API_KEY=supersecret123\n").unwrap();
    fs::write(root.join(".env.local"), "LOCAL_KEY=local123\n").unwrap();
    fs::write(root.join("id_rsa"), "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n").unwrap();
    fs::write(root.join("server.key"), "-----BEGIN PRIVATE KEY-----\nMIIE...\n").unwrap();
}

/// Start an ephemeral HTTP server running the IDE backend endpoints
async fn start_ide_test_server(
    project_root: PathBuf,
) -> (u16, tokio::task::JoinHandle<()>, Arc<AppState>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener");
    let port = listener.local_addr().expect("Local addr").port();

    let mut code_graph = AetherGraph::new("TestProject");
    code_graph.project_name = "CodeGraph".to_string();

    // Seed AST symbol for F10 telemetry testing
    let mut sym_node = SymbolBubble::new(
        "sym_service_run".to_string(),
        "run".to_string(),
        "src/service.rs".to_string(),
        3,
        SymbolKind::Function,
        "Core".to_string(),
        "Service".to_string(),
    );
    sym_node.folder = "src".to_string();
    sym_node.docstring = "Runs the service logic".to_string();
    code_graph.nodes.push(sym_node);

    let mut vault_graph = AetherGraph::new("TestProjectVault");
    vault_graph.project_name = "VaultGraph".to_string();

    let state = Arc::new(AppState::new(
        code_graph.clone(),
        project_root.clone(),
        DetectedProjectType::Mixed,
        "code".to_string(),
        Some(code_graph),
        Some(vault_graph),
        None,
    ));

    let state_view_mode = state.clone();
    let state_file_content = state.clone();
    let state_save_file = state.clone();
    let state_files = state.clone();
    let state_graph = state.clone();
    let state_ai_target = state.clone();

    let app = axum::Router::new()
        .route(
            "/api/view_mode",
            axum::routing::post({
                let state = state_view_mode.clone();
                move |axum::extract::Json(req): axum::extract::Json<api_routes::ViewModeRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;
                        match state.switch_view_mode(&req.mode).await {
                            Ok(graph) => (
                                StatusCode::OK,
                                axum::Json(serde_json::to_value(&graph).unwrap_or_default()),
                            )
                                .into_response(),
                            Err(e) => (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": e.to_string(),
                                })),
                            )
                                .into_response(),
                        }
                    }
                }
            }),
        )
        .route(
            "/api/file_content",
            axum::routing::get({
                let state = state_file_content.clone();
                move |axum::extract::Query(query): axum::extract::Query<FileContentQuery>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let rel_path = query.path.unwrap_or_default();
                        let clean_rel = match PathGuard::validate_client_relative_path(&rel_path) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };

                        if SecretGuard::is_secret_path(&clean_rel) {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Access denied: Sensitive file '{}' is protected", clean_rel.display())
                                })),
                            )
                                .into_response();
                        }

                        if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }

                        let p_root = state.project_root.read().await.clone();
                        let guard = match PathGuard::new(&p_root) {
                            Ok(g) => g,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };

                        let mut read_res = guard.read_to_string(&clean_rel);
                        if read_res.is_err() {
                            for attempt in 1..=20 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(attempt * 2)).await;
                                read_res = guard.read_to_string(&clean_rel);
                                if read_res.is_ok() {
                                    break;
                                }
                            }
                        }

                        match read_res {
                            Ok(content) => {
                                let is_raw = query.raw.unwrap_or(false);
                                let final_content = if is_raw {
                                    content
                                } else {
                                    SecretMasker::mask_text(&content)
                                };
                                (
                                    StatusCode::OK,
                                    axum::Json(serde_json::json!({
                                        "status": "ok",
                                        "path": rel_path,
                                        "content": final_content
                                    })),
                                )
                                    .into_response()
                            }
                            Err(e) => {
                                let (code, mut json_val) = security_error_to_status_and_json(&e);
                                if let Some(obj) = json_val.as_object_mut() {
                                    obj.insert("path".to_string(), serde_json::Value::String(rel_path.clone()));
                                }
                                (code, axum::Json(json_val)).into_response()
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/api/save_file",
            axum::routing::post({
                let state = state_save_file.clone();
                move |axum::extract::Json(req): axum::extract::Json<SaveFileRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        match state.save_file(&req.file_path, &req.content).await {
                            Ok(resp) => (StatusCode::OK, axum::Json(resp)).into_response(),
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                (code, axum::Json(json_val)).into_response()
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/api/files",
            axum::routing::get({
                let state = state_files.clone();
                move || {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let files = state.list_files().await;
                        (
                            StatusCode::OK,
                            axum::Json(ProjectFilesResponse {
                                status: "ok".to_string(),
                                files,
                            }),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/api/graph",
            axum::routing::get({
                let state = state_graph.clone();
                move || {
                    let state = state.clone();
                    async move {
                        let g = state.get_active_graph().await;
                        axum::Json(serde_json::to_value(&g).unwrap_or_default())
                    }
                }
            }),
        )
        .route(
            "/api/ai/target",
            axum::routing::post({
                let state = state_ai_target.clone();
                move |axum::extract::Json(req): axum::extract::Json<api_routes::AiTargetRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        if SecretGuard::is_secret_path(&req.symbol_id) {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Access denied: Symbol/path '{}' is a protected secret file (.env, secrets, credentials)", req.symbol_id)
                                })),
                            )
                                .into_response();
                        }

                        let p_root = state.project_root.read().await.clone();
                        let g = state.graph.read().await;

                        let sym_opt = g
                            .nodes
                            .iter()
                            .find(|n| {
                                n.id == req.symbol_id
                                    || n.name == req.symbol_id
                                    || n.file_path == req.symbol_id
                                    || n.id.ends_with(&format!("::{}", req.symbol_id))
                            })
                            .cloned();

                        if let Some(sym) = sym_opt {
                            if SecretGuard::is_secret_path(&sym.file_path) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({
                                        "status": "error",
                                        "message": format!("Access denied: Target file '{}' is a protected secret file", sym.file_path)
                                    })),
                                )
                                    .into_response();
                            }
                            let incoming_edges: Vec<&core_graph::edge::AffiliationEdge> = g
                                .edges
                                .iter()
                                .filter(|e| e.target == sym.id && e.relation != "contains")
                                .collect();
                            let outgoing_edges: Vec<&core_graph::edge::AffiliationEdge> = g
                                .edges
                                .iter()
                                .filter(|e| e.source == sym.id && e.relation != "contains")
                                .collect();

                            let categorized_in = core_graph::edge::CategorizedLiaisons::from_edges(&incoming_edges, &sym.id, true);
                            let categorized_out = core_graph::edge::CategorizedLiaisons::from_edges(&outgoing_edges, &sym.id, false);

                            let callers: Vec<String> = incoming_edges.iter().map(|e| e.source.clone()).collect();
                            let dependencies: Vec<String> = outgoing_edges.iter().map(|e| e.target.clone()).collect();

                            let readme_path = p_root.join("README.md");
                            let contract = fs::read_to_string(&readme_path)
                                .ok()
                                .and_then(|c| ReadmeContract::parse(&sym.folder, &c).ok());

                            let _ = AuditWriter::write_active_target_categorized(
                                &p_root,
                                &sym,
                                &categorized_in,
                                &categorized_out,
                                contract.as_ref(),
                            );

                            let action_type = req.action_type.as_deref().unwrap_or("Target");
                            let handshake_xml = HandshakePacker::build_categorized_prompt(
                                action_type,
                                &sym,
                                &categorized_in,
                                &categorized_out,
                                contract.as_ref(),
                            );
                            let handshake_xml = SecretMasker::mask_text(&handshake_xml);
                            let active_target_path = p_root.join(".aether").join("ACTIVE_TARGET.md").to_string_lossy().to_string();

                            (
                                StatusCode::OK,
                                axum::Json(api_routes::AiTargetResponse {
                                    status: "ok".to_string(),
                                    active_target_path,
                                    handshake_xml,
                                    blake3_hash: sym.metadata.blake3_hash.or_else(|| contract.as_ref().map(|c| c.blake3_hash.clone())),
                                    lock_verified: sym.metadata.lock_verified,
                                    ears_count: contract.as_ref().map(|c| c.ears_requirements.len()).unwrap_or(sym.metadata.ears_count),
                                    symbol_name: Some(sym.name.clone()),
                                    file_path: Some(format!("{}:{}", sym.file_path, sym.line_number)),
                                    layer: Some(sym.layer.clone()),
                                    galaxy: Some(sym.galaxy.clone()),
                                    docstring: if sym.docstring.is_empty() { None } else { Some(sym.docstring.clone()) },
                                    callers,
                                    dependencies,
                                    categorized_incoming: Some(categorized_in),
                                    categorized_outgoing: Some(categorized_out),
                                    formatted_doc_and_liaisons: None,
                                }),
                            )
                                .into_response()
                        } else {
                            (
                                StatusCode::OK,
                                axum::Json(api_routes::AiTargetResponse {
                                    status: "not_found".to_string(),
                                    active_target_path: String::new(),
                                    handshake_xml: String::new(),
                                    blake3_hash: None,
                                    lock_verified: None,
                                    ears_count: 0,
                                    symbol_name: None,
                                    file_path: None,
                                    layer: None,
                                    galaxy: None,
                                    docstring: None,
                                    callers: vec![],
                                    dependencies: vec![],
                                    categorized_incoming: None,
                                    categorized_outgoing: None,
                                    formatted_doc_and_liaisons: None,
                                }),
                            )
                                .into_response()
                        }
                    }
                }
            }),
        );

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (port, handle, state)
}

/// Raw HTTP request helper using standard async socket operations
async fn send_http_request(
    port: u16,
    method: &str,
    uri: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
) -> (u16, HashMap<String, String>, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("Connect to test server");

    let body_bytes = body.unwrap_or(&[]);
    let ct_header = if let Some(ct) = content_type {
        format!("Content-Type: {}\r\n", ct)
    } else if body.is_some() {
        "Content-Type: application/json\r\n".to_string()
    } else {
        String::new()
    };

    let req = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        uri,
        port,
        ct_header,
        body_bytes.len()
    );

    stream.write_all(req.as_bytes()).await.expect("Write request headers");
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).await.expect("Write request body");
    }
    stream.flush().await.expect("Flush request");

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf).await.expect("Read response");

    let header_end = response_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(response_buf.len());

    let header_str = String::from_utf8_lossy(&response_buf[..header_end]);
    let body_part = if header_end + 4 <= response_buf.len() {
        response_buf[header_end + 4..].to_vec()
    } else {
        Vec::new()
    };

    let mut lines = header_str.lines();
    let status_code = lines
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            parts.next()?; // HTTP/1.1
            parts.next()?.parse::<u16>().ok()
        })
        .unwrap_or(0);

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    (status_code, headers, body_part)
}

// =========================================================================
// TIER 1: FEATURE COVERAGE (Endpoints & State Machines)
// =========================================================================

#[tokio::test]
async fn test_tier1_view_mode_and_file_apis() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());
    let (port, _handle, state) = start_ide_test_server(temp_root.path().to_path_buf()).await;

    // T1.1.1: POST /api/view_mode with {"mode": "ide"} returns 200 OK and code graph
    let payload = json!({ "mode": "ide" });
    let req_bytes = serde_json::to_vec(&payload).unwrap();
    let (code, _, body) = send_http_request(port, "POST", "/api/view_mode", Some(&req_bytes), None).await;
    assert_eq!(code, 200, "T1.1.1: /api/view_mode with mode=ide must return 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["project_name"], "CodeGraph");
    assert_eq!(state.get_active_view_mode().await, "ide");

    // T1.1.2: POST /api/view_mode with {"mode": "IDE"} case-insensitive normalization
    let payload_upper = json!({ "mode": "IDE" });
    let req_bytes_upper = serde_json::to_vec(&payload_upper).unwrap();
    let (code, _, _) = send_http_request(port, "POST", "/api/view_mode", Some(&req_bytes_upper), None).await;
    assert_eq!(code, 200, "T1.1.2: Mode IDE (uppercase) must normalize to 200 OK");
    assert_eq!(state.get_active_view_mode().await, "ide");

    // T1.1.4: Calling GET /api/graph in "ide" mode returns code AST graph
    let (code, _, body_g) = send_http_request(port, "GET", "/api/graph", None, None).await;
    assert_eq!(code, 200);
    let json_g: serde_json::Value = serde_json::from_slice(&body_g).unwrap();
    assert_eq!(json_g["project_name"], "CodeGraph");

    // T1.2.1 & T1.2.3: GET /api/file_content?path=sensitive_tokens.rs&raw=true returns unmasked token
    let (code, _, body) = send_http_request(
        port,
        "GET",
        "/api/file_content?path=sensitive_tokens.rs&raw=true",
        None,
        None,
    )
    .await;
    assert_eq!(code, 200, "T1.2.1: raw=true read must succeed");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(
        json["content"].as_str().unwrap().contains("sk-1234567890abcdef1234567890abcdef"),
        "Raw reading must contain exact unredacted token"
    );

    // T1.2.2: GET /api/file_content?path=sensitive_tokens.rs (without raw=true) masks the secret
    let (code, _, body) = send_http_request(
        port,
        "GET",
        "/api/file_content?path=sensitive_tokens.rs",
        None,
        None,
    )
    .await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(
        !json["content"].as_str().unwrap().contains("sk-1234567890abcdef1234567890abcdef"),
        "Default read must redact secret tokens"
    );
    assert!(
        json["content"].as_str().unwrap().contains("[REDACTED]"),
        "Redacted placeholder must be present"
    );

    // T1.3.1 & T1.3.2: POST /api/save_file with new file writes to disk and returns bytes_written
    let save_payload = json!({
        "file_path": "src/sample_new.rs",
        "content": "pub fn sample() -> i32 { 100 }"
    });
    let save_bytes = serde_json::to_vec(&save_payload).unwrap();
    let (code, _, body) = send_http_request(port, "POST", "/api/save_file", Some(&save_bytes), None).await;
    assert_eq!(code, 200, "T1.3.1: Save file must return 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["file_path"], "src/sample_new.rs");
    assert_eq!(json["bytes_written"], 30);

    // Verify on disk byte-for-byte
    let disk_content = fs::read_to_string(temp_root.path().join("src/sample_new.rs")).unwrap();
    assert_eq!(disk_content, "pub fn sample() -> i32 { 100 }");

    // T1.3.3: Overwrite existing file
    let overwrite_payload = json!({
        "file_path": "src/sample_new.rs",
        "content": "pub fn sample() -> i32 { 200 }"
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&overwrite_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);
    let disk_updated = fs::read_to_string(temp_root.path().join("src/sample_new.rs")).unwrap();
    assert_eq!(disk_updated, "pub fn sample() -> i32 { 200 }");

    // T1.3.4: Save 0-byte file
    let empty_payload = json!({
        "file_path": "src/empty_created.rs",
        "content": ""
    });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&empty_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["bytes_written"], 0);
    assert_eq!(fs::read_to_string(temp_root.path().join("src/empty_created.rs")).unwrap(), "");

    // T1.3.5: Save into nested subfolder automatically creates parent directories
    let nested_payload = json!({
        "file_path": "src/brand_new/deep/sub/worker.rs",
        "content": "pub struct Worker;"
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&nested_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);
    assert!(temp_root.path().join("src/brand_new/deep/sub/worker.rs").exists());

    // T1.4.1 - T1.4.5: GET /api/files returns directory structure and excludes forbidden paths
    let (code, _, body) = send_http_request(port, "GET", "/api/files", None, None).await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    let files = json["files"].as_array().expect("files array");
    assert!(!files.is_empty());

    let paths: Vec<String> = files
        .iter()
        .map(|f| f["path"].as_str().unwrap().to_string())
        .collect();

    // Must contain legitimate files
    assert!(paths.contains(&"README.md".to_string()));
    assert!(paths.contains(&"src".to_string()));
    assert!(paths.contains(&"src/main.rs".to_string()));

    // Must NOT contain ignored folders
    for p in &paths {
        assert!(!p.starts_with(".git"), "Must not contain .git: {}", p);
        assert!(!p.starts_with("node_modules"), "Must not contain node_modules: {}", p);
        assert!(!p.starts_with("target"), "Must not contain target: {}", p);
        assert!(!p.starts_with("dist"), "Must not contain dist: {}", p);
        assert!(!p.starts_with(".aether"), "Must not contain .aether: {}", p);
        assert!(!p.starts_with(".gemini"), "Must not contain .gemini: {}", p);
        assert!(!p.contains(".env"), "Must not contain .env: {}", p);
        assert!(!p.contains("id_rsa"), "Must not contain id_rsa: {}", p);
        assert!(!p.ends_with(".key"), "Must not contain .key: {}", p);
    }
}

// =========================================================================
// TIER 2: BOUNDARY, CORNER, AND SECURITY CONFINEMENT CASES
// =========================================================================

#[tokio::test]
async fn test_tier2_boundary_and_confinement_cases() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());
    let (port, _handle, state) = start_ide_test_server(temp_root.path().to_path_buf()).await;

    // T2.1.1: Mode string with leading/trailing whitespace
    let ws_payload = json!({ "mode": "  ide  " });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/view_mode",
        Some(&serde_json::to_vec(&ws_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200, "T2.1.1: Whitespace trimmed mode must succeed");
    assert_eq!(state.get_active_view_mode().await, "ide");

    // T2.1.2: Invalid mode string returns 400 Bad Request
    let inv_payload = json!({ "mode": "unknown_fantasy_mode" });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/view_mode",
        Some(&serde_json::to_vec(&inv_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 400, "T2.1.2: Invalid mode must return 400 Bad Request");

    // T2.2.1: Path traversal attack on /api/file_content (Unix)
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=../../etc/passwd", None, None).await;
    assert_eq!(code, 400, "T2.2.1: Traversal ../ must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "error");
    assert_eq!(json["error"], "bad_request");

    // T2.2.1: Path traversal attack on /api/file_content (Windows)
    let (code, _, body) = send_http_request(port, "GET", r"/api/file_content?path=..\..\windows\win.ini", None, None).await;
    assert_eq!(code, 400, "T2.2.1: Traversal ..\\ must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "error");
    assert_eq!(json["error"], "bad_request");

    // T2.2.2: Sensitive file access (.env, id_rsa)
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.env", None, None).await;
    assert_eq!(code, 403, "T2.2.2: .env read must strictly return 403 Forbidden");
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=id_rsa", None, None).await;
    assert_eq!(code, 403, "T2.2.2: id_rsa read must strictly return 403 Forbidden");

    // T2.2.3: Non-existent file
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=src/ghost_file.rs", None, None).await;
    assert_eq!(code, 404, "T2.2.3: Missing file must return 404");

    // T2.2.4: 0-byte file returns 200 with content: ""
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=empty.txt", None, None).await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["content"], "");

    // T2.2.5: Reading a file exceeding 10MB limit returns HTTP 413 Payload Too Large
    let large_file_path = temp_root.path().join("large_payload.bin");
    let large_file = File::create(&large_file_path).expect("Create large test file");
    // 10MB + 1KB = 10 * 1024 * 1024 + 1024 = 10_486_784 bytes
    large_file.set_len(10 * 1024 * 1024 + 1024).expect("Set file length > 10MB");
    drop(large_file);

    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=large_payload.bin", None, None).await;
    assert_eq!(code, 413, "T2.2.5: Reading file > 10MB must return HTTP 413 Payload Too Large");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("Valid JSON response for 413");
    assert_eq!(json["status"], "error");
    assert_eq!(json["error"], "payload_too_large");
    assert!(json["message"].as_str().unwrap().contains("exceeds maximum limit"));

    // T2.3.1: Path traversal on save (file_path=../outside.txt)
    let trav_save = json!({
        "file_path": "../outside.txt",
        "content": "malicious content"
    });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&trav_save).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 400, "T2.3.1: Save traversal must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    // T2.3.2: Saving to secret path (.env and .env.production)
    let sec_save = json!({
        "file_path": ".env",
        "content": "POISON=1"
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&sec_save).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 403, "T2.3.2: Save to secret path must strictly return 403 Forbidden");

    let sec_save2 = json!({
        "file_path": ".env.production",
        "content": "POISON=2"
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&sec_save2).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 403, "T2.3.2: Save to .env.production must strictly return 403 Forbidden");

    // T2.3.3: Saving with absolute path
    let abs_save = json!({
        "file_path": "/etc/shadow",
        "content": "root:x:0:0"
    });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&abs_save).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 400, "T2.3.3: Absolute path on save must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    // T2.3.4: Saving unicode and special characters preserves exact encoding
    let unicode_content = "let greeting = \"Bonjour le monde! 🌍 🚀 漢字 العربية\";";
    let unicode_payload = json!({
        "file_path": "src/unicode.rs",
        "content": unicode_content
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&unicode_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);
    let disk_unicode = fs::read_to_string(temp_root.path().join("src/unicode.rs")).unwrap();
    assert_eq!(disk_unicode, unicode_content);

    // Windows UNC path injection on GET /api/file_content (backslash and slash forms)
    let (code, _, body) = send_http_request(port, "GET", r"/api/file_content?path=\\server\share\file.rs", None, None).await;
    assert_eq!(code, 400, "UNC backslash path on read must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=//server/share/file.rs", None, None).await;
    assert_eq!(code, 400, "UNC forward-slash path on read must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    // Windows UNC path injection on POST /api/save_file
    let unc_save = json!({
        "file_path": r"\\attacker\share\payload.rs",
        "content": "pub fn evil() {}"
    });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&unc_save).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 400, "UNC path on save must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    // Windows Drive Letter Injection on GET /api/file_content (C:/ and C:\)
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=C:/Windows/win.ini", None, None).await;
    assert_eq!(code, 400, "Drive letter C:/ on read must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    let (code, _, body) = send_http_request(port, "GET", r"/api/file_content?path=C:\Windows\win.ini", None, None).await;
    assert_eq!(code, 400, r"Drive letter C:\ on read must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    // Windows Drive Letter Injection on POST /api/save_file
    let drive_save = json!({
        "file_path": r"C:\Windows\System32\malicious.dll",
        "content": "malicious bytes"
    });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&drive_save).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 400, "Drive letter on save must strictly return 400 Bad Request");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_request");

    // Feature F10: POST /api/ai/target and .aether/ACTIVE_TARGET.md Persistence
    let target_req = json!({
        "symbol_id": "sym_service_run",
        "action_type": "Inspect"
    });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/ai/target",
        Some(&serde_json::to_vec(&target_req).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200, "F10: Targeting seeded symbol must return 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["symbol_name"], "run");
    assert_eq!(json["file_path"], "src/service.rs:3");

    let active_target_file = temp_root.path().join(".aether/ACTIVE_TARGET.md");
    assert!(active_target_file.exists(), ".aether/ACTIVE_TARGET.md must exist on disk");
    let target_md = fs::read_to_string(&active_target_file).unwrap();
    assert!(target_md.contains("# 🎯 AETHER ACTIVE TARGET CONTEXT"));
    assert!(target_md.contains("`run`"));

    // F10: Sensitive target rejection
    let secret_target = json!({ "symbol_id": ".env" });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/ai/target",
        Some(&serde_json::to_vec(&secret_target).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 403, "F10: Target on .env must return 403 Forbidden");

    // F10: Missing symbol graceful handling
    let missing_target = json!({ "symbol_id": "ghost_symbol" });
    let (code, _, body) = send_http_request(
        port,
        "POST",
        "/api/ai/target",
        Some(&serde_json::to_vec(&missing_target).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "not_found");
}

// =========================================================================
// TIER 3 & 4: CROSS-FEATURE INTERACTIONS AND CONCURRENCY STRESS
// =========================================================================

#[tokio::test]
async fn test_tier3_tier4_concurrency_and_stress() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());
    let (port, _handle, state) = start_ide_test_server(temp_root.path().to_path_buf()).await;

    // T3: Round-trip: Read raw -> modify -> Save -> List files -> Read back
    let (code, _, body) = send_http_request(
        port,
        "GET",
        "/api/file_content?path=src/service.rs&raw=true",
        None,
        None,
    )
    .await;
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let original = json["content"].as_str().unwrap();

    let modified = format!("{}\npub fn new_helper() -> bool {{ true }}\n", original);
    let save_payload = json!({
        "file_path": "src/service.rs",
        "content": modified
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&save_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);

    // Verify updated via /api/files
    let (code, _, body_files) = send_http_request(port, "GET", "/api/files", None, None).await;
    assert_eq!(code, 200);
    let json_files: serde_json::Value = serde_json::from_slice(&body_files).unwrap();
    let file_item = json_files["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "src/service.rs")
        .expect("src/service.rs must exist in listing");
    assert_eq!(file_item["size"].as_u64().unwrap(), modified.len() as u64);

    // T4: High concurrency saves to 20 distinct files
    let mut tasks = Vec::new();
    for i in 0..20 {
        let p = port;
        tasks.push(tokio::spawn(async move {
            let rel = format!("src/concurrent_{}.rs", i);
            let payload = json!({
                "file_path": rel,
                "content": format!("// Concurrent file index {}\npub fn f_{}() {{}}", i, i)
            });
            let (code, _, _) = send_http_request(
                p,
                "POST",
                "/api/save_file",
                Some(&serde_json::to_vec(&payload).unwrap()),
                None,
            )
            .await;
            assert_eq!(code, 200);
        }));
    }

    for t in tasks {
        t.await.expect("Concurrent save task failed");
    }

    // Verify all 20 files exist on disk
    for i in 0..20 {
        assert!(temp_root.path().join(format!("src/concurrent_{}.rs", i)).exists());
    }

    // T4: High-concurrency same-file read & write contention (verifying atomic writes / 0 torn reads)
    let shared_rel = "src/shared_race.rs";
    let init_payload = json!({
        "file_path": shared_rel,
        "content": "// Base seed\npub fn base() -> usize { 0 }\n"
    });
    let (code, _, _) = send_http_request(
        port,
        "POST",
        "/api/save_file",
        Some(&serde_json::to_vec(&init_payload).unwrap()),
        None,
    )
    .await;
    assert_eq!(code, 200);

    let writer_count = 5;
    let writer_iters = 12;
    let reader_count = 5;
    let reader_iters = 15;

    let mut writers = Vec::new();
    for w in 0..writer_count {
        let p = port;
        let rel = shared_rel.to_string();
        writers.push(tokio::spawn(async move {
            let mut codes = Vec::new();
            for it in 0..writer_iters {
                let pld = json!({
                    "file_path": rel,
                    "content": format!("// Writer {} Iteration {}\npub fn fn_w{}_{}() -> usize {{ {} }}\n", w, it, w, it, it)
                });
                let (code, _, _) = send_http_request(
                    p,
                    "POST",
                    "/api/save_file",
                    Some(&serde_json::to_vec(&pld).unwrap()),
                    None,
                )
                .await;
                codes.push(code);
                tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
            }
            codes
        }));
    }

    let mut readers = Vec::new();
    for _ in 0..reader_count {
        let p = port;
        let rel = shared_rel.to_string();
        readers.push(tokio::spawn(async move {
            let mut empty_reads = 0;
            let mut codes = Vec::new();
            for _ in 0..reader_iters {
                let (code, _, body) = send_http_request(
                    p,
                    "GET",
                    &format!("/api/file_content?path={}&raw=true", rel),
                    None,
                    None,
                )
                .await;
                codes.push(code);
                if code == 200 {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                        let content = json["content"].as_str().unwrap_or_default();
                        if content.is_empty() {
                            empty_reads += 1;
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
            }
            (codes, empty_reads)
        }));
    }

    for w in writers {
        let codes = w.await.expect("Writer task panicked");
        for c in codes {
            assert_eq!(c, 200, "All concurrent writes to same file must return 200 OK");
        }
    }

    let mut total_empty_reads = 0;
    for r in readers {
        let (codes, empty) = r.await.expect("Reader task panicked");
        for c in codes {
            assert_eq!(c, 200, "All concurrent reads of same file must return 200 OK");
        }
        total_empty_reads += empty;
    }

    assert_eq!(
        total_empty_reads, 0,
        "Zero torn/empty reads permitted during concurrent same-file read/write contention!"
    );

    let disk_final = fs::read_to_string(temp_root.path().join(shared_rel)).unwrap();
    assert!(!disk_final.is_empty(), "Shared file on disk must never end in truncated empty state");
    assert!(disk_final.contains("pub fn fn_w"));

    // T4: Rapid alternating view mode switches (code -> vault -> ide)
    let mut switch_tasks = Vec::new();
    for i in 0..10 {
        let s = state.clone();
        switch_tasks.push(tokio::spawn(async move {
            let modes = ["code", "vault", "ide"];
            for j in 0..15 {
                let m = modes[(i + j) % 3];
                let res = s.switch_view_mode(m).await;
                assert!(res.is_ok(), "Switch to {} failed", m);
            }
        }));
    }

    for t in switch_tasks {
        t.await.expect("Switch task failed");
    }

    let final_mode = state.get_active_view_mode().await;
    assert!(final_mode == "code" || final_mode == "vault" || final_mode == "ide");
}
