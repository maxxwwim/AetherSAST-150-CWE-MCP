#![allow(dead_code, unused_imports, unused_variables)]

//! 4-Tier Automated Security Test Suite for Desktop-Shell CWE-22 Endpoint Hardening
//!
//! Validates:
//! - Tier 1: Core Functional Capabilities (allowed reads & writes across all 4 endpoints)
//! - Tier 2: Boundary & Corner Cases (empty, dot, separators, depth 32/33, 10MB limits, unicode)
//! - Tier 3: Cross-Feature Interactions (create then read, save then stream, symlinks, concurrency)
//! - Tier 4: Real-World Adversarial Attack Scenarios (traversal, UNC, drive letters, null bytes,
//!           symlink escapes, sensitive files, extension bypass)

#[path = "../src/api_routes.rs"]
mod api_routes;

#[path = "../src/local_guard.rs"]
mod local_guard;

use api_routes::{
    AppState, CreateFileRequest, CreateFileResponse, SaveDocRequest, SaveDocResponse,
};
use ast_scanner::ProjectScanner;
use core_graph::graph::AetherGraph;
use obsidian_vault::{DetectedProjectType, PathGuard, SecurityError};
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Maps a `SecurityError` from `PathGuard` to the appropriate HTTP status code and JSON error payload.
fn security_error_to_status_and_json(err: &SecurityError) -> (axum::http::StatusCode, serde_json::Value) {
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
        SecurityError::IoError { source, .. } if source.kind() == std::io::ErrorKind::NotFound => (
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

/// Starts an ephemeral in-process server matching desktop-shell's hardened endpoint router.
async fn start_security_test_server(
    project_root: PathBuf,
) -> (u16, tokio::task::JoinHandle<()>, Arc<AppState>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener");
    let port = listener.local_addr().expect("Local addr").port();

    let active_graph = AetherGraph::new("SecurityTestWorkspace");
    let state = Arc::new(AppState::new(
        active_graph.clone(),
        project_root.clone(),
        DetectedProjectType::Mixed,
        "code".to_string(),
        Some(active_graph.clone()),
        Some(active_graph),
        None,
    ));

    let state_file_content = state.clone();
    let state_raw_file = state.clone();
    let state_create_file = state.clone();
    let state_savedoc = state.clone();
    let state_status = state.clone();

    let app = axum::Router::new()
        .route(
            "/api/file_content",
            axum::routing::get({
                let state = state_file_content.clone();
                move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let rel_path = query.get("path").cloned().unwrap_or_default();

                        // 1. Lexical client-relative validation
                        let clean_rel = match PathGuard::validate_client_relative_path(&rel_path) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };

                        // 2. Sensitive file check
                        if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }

                        // 3. Confinement resolution and read via PathGuard
                        let p_root = state.project_root.read().await.clone();
                        let guard = match PathGuard::new(&p_root) {
                            Ok(g) => g,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };

                        match guard.read_to_string(&clean_rel) {
                            Ok(content) => (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "status": "ok",
                                    "path": rel_path,
                                    "content": content
                                })),
                            )
                                .into_response(),
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
            "/api/raw_file",
            axum::routing::get({
                let state = state_raw_file.clone();
                move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
                    let state = state.clone();
                    async move {
                        use axum::http::{header, StatusCode};
                        use axum::response::IntoResponse;

                        let rel_path = query.get("path").cloned().unwrap_or_default();
                        if rel_path.trim().is_empty() {
                            return (StatusCode::BAD_REQUEST, "Chemin manquant").into_response();
                        }

                        // 1. Lexical client-relative validation
                        let clean_rel = match PathGuard::validate_client_relative_path(&rel_path) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                return (code, body.to_string()).into_response();
                            }
                        };

                        // 2. Allowed extension whitelisting
                        let ext_str = match PathGuard::validate_raw_extension(&clean_rel) {
                            Ok(ext) => ext,
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                return (code, body.to_string()).into_response();
                            }
                        };

                        // 3. Sensitive file validation
                        if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                            let (code, body) = security_error_to_status_and_json(&e);
                            return (code, body.to_string()).into_response();
                        }

                        // 4. Confinement resolution and read via PathGuard
                        let p_root = state.project_root.read().await.clone();
                        let guard = match PathGuard::new(&p_root) {
                            Ok(g) => g,
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                return (code, body.to_string()).into_response();
                            }
                        };

                        match guard.read_bytes(&clean_rel) {
                            Ok(bytes) => {
                                let content_type = match ext_str {
                                    "png" => "image/png",
                                    "jpg" | "jpeg" => "image/jpeg",
                                    "gif" => "image/gif",
                                    "svg" => "image/svg+xml",
                                    "webp" => "image/webp",
                                    "ico" => "image/x-icon",
                                    "bmp" => "image/bmp",
                                    "tiff" => "image/tiff",
                                    "pdf" => "application/pdf",
                                    "json" => "application/json",
                                    "md" | "markdown" | "txt" => "text/plain; charset=utf-8",
                                    "csv" => "text/csv; charset=utf-8",
                                    _ => return (StatusCode::BAD_REQUEST, "Extension non autorisée").into_response(),
                                };
                                (
                                    StatusCode::OK,
                                    [(header::CONTENT_TYPE, content_type)],
                                    bytes,
                                )
                                    .into_response()
                            }
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                (code, body.to_string()).into_response()
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/api/ai/create_file",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<CreateFileRequest>| {
                let state = state_create_file.clone();
                async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;

                    let p_root = state.project_root.read().await.clone();
                    let canonical_p_root = match fs::canonicalize(&p_root) {
                        Ok(p) => p,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Root canonicalization failed: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    };

                    // Validate client project_path if provided
                    let proj_trimmed = req.project_path.trim();
                    if !proj_trimmed.is_empty() && proj_trimmed != "." {
                        let candidate_proj = PathBuf::from(proj_trimmed);
                        if let Ok(canon_cand) = fs::canonicalize(&candidate_proj) {
                            if !canon_cand.starts_with(&canonical_p_root) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({
                                        "status": "error",
                                        "message": "project_path escapes designated project_root"
                                    })),
                                )
                                    .into_response();
                            }
                        } else if candidate_proj != p_root {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": "Invalid project_path"
                                })),
                            )
                                .into_response();
                        }
                    }

                    // Validate file_path lexically
                    let clean_rel = match PathGuard::validate_client_relative_path(&req.file_path) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    // Validate not sensitive
                    if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                        let (code, json_val) = security_error_to_status_and_json(&e);
                        return (code, axum::Json(json_val)).into_response();
                    }

                    // Resolve write target with ancestor canonicalization
                    let guard = match PathGuard::new(&canonical_p_root) {
                        Ok(g) => g,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    let target_path = match guard.resolve_write_target(&clean_rel) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    if let Some(parent) = target_path.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Failed to create parent directory: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    }

                    if let Err(e) = fs::write(&target_path, &req.content) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Failed to write file: {}", e)
                            })),
                        )
                            .into_response();
                    }

                    let scanner = ProjectScanner::default();
                    let new_graph = scanner.scan_project(&p_root);
                    let mut g_guard = state.graph.write().await;
                    *g_guard = new_graph.clone();
                    state.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    let created_symbol = req.file_path.replace(['/', '\\'], "::");
                    (
                        StatusCode::OK,
                        axum::Json(CreateFileResponse {
                            status: "ok".to_string(),
                            file_path: req.file_path,
                            created_symbol,
                            graph: new_graph.clone(),
                            data: new_graph,
                        }),
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/api/save_doc",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<SaveDocRequest>| {
                let state = state_savedoc.clone();
                async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;

                    let p_root = state.project_root.read().await.clone();
                    let canonical_p_root = match fs::canonicalize(&p_root) {
                        Ok(p) => p,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Root canonicalization failed: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    };

                    // Validate client project_path if non-empty / non-dot
                    let proj_trimmed = req.project_path.trim();
                    if !proj_trimmed.is_empty() && proj_trimmed != "." {
                        let candidate_proj = PathBuf::from(proj_trimmed);
                        if let Ok(canon_cand) = fs::canonicalize(&candidate_proj) {
                            if !canon_cand.starts_with(&canonical_p_root) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({
                                        "status": "error",
                                        "message": "project_path escapes designated project_root"
                                    })),
                                )
                                    .into_response();
                            }
                        } else if candidate_proj != p_root {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": "Invalid project_path"
                                })),
                            )
                                .into_response();
                        }
                    }

                    // Validate file_name lexically
                    let clean_file_name = match PathGuard::validate_client_relative_path(&req.file_name) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    // Validate folder and construct clean relative candidate path
                    let clean_rel = if req.folder.trim().is_empty()
                        || req.folder.trim() == "root"
                        || req.folder.trim() == "."
                    {
                        clean_file_name
                    } else {
                        let clean_folder = match PathGuard::validate_client_relative_path(&req.folder) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };
                        clean_folder.join(clean_file_name)
                    };

                    // Validate sensitive file / secret blocking
                    if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                        let (code, json_val) = security_error_to_status_and_json(&e);
                        return (code, axum::Json(json_val)).into_response();
                    }

                    // Resolve write target with ancestor canonicalization and jail containment
                    let guard = match PathGuard::new(&canonical_p_root) {
                        Ok(g) => g,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    let path = match guard.resolve_write_target(&clean_rel) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    if let Some(parent) = path.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Failed to create parent directory: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    }

                    if let Err(e) = fs::write(&path, &req.content) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Failed to write file: {}", e)
                            })),
                        )
                            .into_response();
                    }

                    (
                        StatusCode::OK,
                        axum::Json(SaveDocResponse {
                            status: "ok".to_string(),
                            saved_path: path.to_string_lossy().to_string(),
                            blake3_hash: None,
                            graph: None,
                        }),
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/api/project/status",
            axum::routing::get({
                let state = state_status.clone();
                move || {
                    let state = state.clone();
                    async move {
                        let status_resp = state.get_project_status().await;
                        axum::Json(status_resp)
                    }
                }
            }),
        );

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (port, server_handle, state)
}

/// Helper function to perform raw HTTP requests against the test server.
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

    stream.write_all(req.as_bytes()).await.unwrap();
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).await.unwrap();
    }
    stream.flush().await.unwrap();

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf).await.unwrap();

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

/// Sets up a comprehensive test workspace with real test files.
fn setup_test_workspace(dir: &Path) {
    // 1. Text files
    fs::write(dir.join("README.md"), "# Welcome to Test Project\n").unwrap();
    fs::create_dir_all(dir.join("src").join("sub")).unwrap();
    fs::write(dir.join("src").join("lib.rs"), "pub fn main_engine() {}\n").unwrap();
    fs::write(
        dir.join("src").join("sub").join("module.rs"),
        "pub fn sub_module() {}\n",
    )
    .unwrap();

    // 2. Media assets
    fs::create_dir_all(dir.join("assets")).unwrap();
    let png_magic = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4";
    fs::write(dir.join("assets").join("logo.png"), png_magic).unwrap();
    fs::write(
        dir.join("assets").join("diagram.svg"),
        "<svg viewBox='0 0 100 100'></svg>",
    )
    .unwrap();
    fs::write(dir.join("photo.PNG"), png_magic).unwrap(); // Uppercase extension

    // 3. Documents & Data
    fs::create_dir_all(dir.join("docs")).unwrap();
    fs::write(dir.join("docs").join("manual.pdf"), "%PDF-1.4 test document").unwrap();
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(dir.join("data").join("config.json"), "{\"project\": \"test\"}").unwrap();

    // 4. Unicode filename
    fs::create_dir_all(dir.join("notes")).unwrap();
    fs::write(
        dir.join("notes").join("rapport final 2026.md"),
        "# Rapport Final\n",
    )
    .unwrap();

    // 5. Size boundary files (10 MB and 10 MB + 1 byte)
    let exact_10mb = vec![b'x'; 10 * 1024 * 1024];
    fs::write(dir.join("exact_10mb.txt"), &exact_10mb).unwrap();

    let too_large = vec![b'y'; (10 * 1024 * 1024) + 1];
    fs::write(dir.join("too_large.txt"), &too_large).unwrap();

    // 6. Sensitive files inside repository
    fs::write(dir.join(".env"), "DATABASE_URL=postgres://root:secret@db\n").unwrap();
    fs::write(dir.join(".env.local"), "LOCAL_DEBUG_SECRET=supersecret\n").unwrap();
    fs::create_dir_all(dir.join(".ssh")).unwrap();
    fs::write(
        dir.join(".ssh").join("id_rsa"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nFakeKey\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join(".aws")).unwrap();
    fs::write(
        dir.join(".aws").join("credentials"),
        "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(
        dir.join(".git").join("config"),
        "[core]\nrepositoryformatversion = 0\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join("certs")).unwrap();
    fs::write(
        dir.join("certs").join("server.key"),
        "-----BEGIN PRIVATE KEY-----\nFakeServerKey\n",
    )
    .unwrap();
    fs::write(dir.join("win.ini"), "[fonts]\nArial=1\n").unwrap();

    // 7. Non-media files with disallowed extensions
    fs::write(dir.join("payload.exe"), "MZ fake binary").unwrap();
    fs::write(dir.join("script.sh"), "#!/bin/sh\necho evil\n").unwrap();
    fs::write(dir.join("LICENSE"), "MIT License\n").unwrap();
}

// =========================================================================
// TIER 1: FEATURE COVERAGE (Core Functional Capabilities)
// =========================================================================

#[tokio::test]
async fn test_tier1_feature_coverage() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());
    let (port, _handle, _state) = start_security_test_server(temp_root.path().to_path_buf()).await;

    // T1.1: Read existing text file at project root via /api/file_content
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=README.md", None, None).await;
    assert_eq!(code, 200, "T1.1: README.md read should succeed with 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["content"].as_str().unwrap().contains("# Welcome to Test Project"));

    // T1.2: Read existing nested text file via /api/file_content
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=src/lib.rs", None, None).await;
    assert_eq!(code, 200, "T1.2: src/lib.rs read should succeed with 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["content"].as_str().unwrap().contains("pub fn main_engine()"));

    // T1.3: Read raw image file via /api/raw_file
    let (code, headers, body) = send_http_request(port, "GET", "/api/raw_file?path=assets/logo.png", None, None).await;
    assert_eq!(code, 200, "T1.3: assets/logo.png should return 200 OK");
    assert_eq!(headers.get("content-type").map(|s| s.as_str()), Some("image/png"));
    assert!(body.starts_with(b"\x89PNG"));

    // T1.4: Read raw vector graphic via /api/raw_file
    let (code, headers, body) = send_http_request(port, "GET", "/api/raw_file?path=assets/diagram.svg", None, None).await;
    assert_eq!(code, 200, "T1.4: assets/diagram.svg should return 200 OK");
    assert_eq!(headers.get("content-type").map(|s| s.as_str()), Some("image/svg+xml"));
    assert!(body.starts_with(b"<svg"));

    // T1.5: Read raw document via /api/raw_file
    let (code, headers, body) = send_http_request(port, "GET", "/api/raw_file?path=docs/manual.pdf", None, None).await;
    assert_eq!(code, 200, "T1.5: docs/manual.pdf should return 200 OK");
    assert_eq!(headers.get("content-type").map(|s| s.as_str()), Some("application/pdf"));
    assert!(body.starts_with(b"%PDF"));

    // T1.6: Read raw JSON data via /api/raw_file
    let (code, headers, body) = send_http_request(port, "GET", "/api/raw_file?path=data/config.json", None, None).await;
    assert_eq!(code, 200, "T1.6: data/config.json should return 200 OK");
    assert_eq!(headers.get("content-type").map(|s| s.as_str()), Some("application/json"));
    assert!(body.starts_with(b"{\"project\""));

    // T1.7: Create new file via /api/ai/create_file
    let create_payload = json!({
        "project_path": ".",
        "file_path": "docs/new_doc.md",
        "content": "# Newly Created Document\nContent here."
    });
    let req_bytes = serde_json::to_vec(&create_payload).unwrap();
    let (code, _, body) = send_http_request(port, "POST", "/api/ai/create_file", Some(&req_bytes), None).await;
    assert_eq!(code, 200, "T1.7: /api/ai/create_file should succeed with 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(temp_root.path().join("docs").join("new_doc.md").exists());

    // T1.8: Save doc via /api/save_doc
    let save_payload = json!({
        "project_path": ".",
        "folder": "docs",
        "file_name": "architecture.md",
        "content": "# Architecture Document\nDesign notes."
    });
    let req_bytes = serde_json::to_vec(&save_payload).unwrap();
    let (code, _, body) = send_http_request(port, "POST", "/api/save_doc", Some(&req_bytes), None).await;
    assert_eq!(code, 200, "T1.8: /api/save_doc should succeed with 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(temp_root.path().join("docs").join("architecture.md").exists());
}

// =========================================================================
// TIER 2: BOUNDARY & CORNER CASES
// =========================================================================

#[tokio::test]
async fn test_tier2_boundary_and_corner_cases() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());
    let (port, _handle, _state) = start_security_test_server(temp_root.path().to_path_buf()).await;

    // T2.1: Empty path query -> 400 Bad Request
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=", None, None).await;
    assert_eq!(code, 400, "T2.1: Empty path must return 400 Bad Request");

    // T2.2: Single dot path query -> 400 Bad Request (directory, NotAFile)
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.", None, None).await;
    assert_eq!(code, 400, "T2.2: Single dot path query must return 400 Bad Request");

    // T2.3: Leading dot-slash sanitization -> 200 OK
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=./README.md", None, None).await;
    assert_eq!(code, 200, "T2.3: Leading ./README.md must resolve cleanly to 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");

    // T2.4: Windows backslash separators -> 200 OK
    let (code, _, body) = send_http_request(port, "GET", r"/api/file_content?path=src\lib.rs", None, None).await;
    assert_eq!(code, 200, "T2.4: Windows backslash src\\lib.rs must resolve cleanly to 200 OK");

    // T2.5: Mixed separators -> 200 OK
    let (code, _, body) = send_http_request(port, "GET", r"/api/file_content?path=src/sub\module.rs", None, None).await;
    assert_eq!(code, 200, "T2.5: Mixed separators src/sub\\module.rs must resolve cleanly to 200 OK");

    // T2.6: Path depth exactly 32 components -> Handled without DepthExceeded
    let mut deep_path = temp_root.path().to_path_buf();
    let mut rel_32_vec = Vec::new();
    for i in 0..31 {
        let seg = format!("d{i}");
        deep_path.push(&seg);
        rel_32_vec.push(seg);
    }
    fs::create_dir_all(&deep_path).unwrap();
    fs::write(deep_path.join("leaf.txt"), "leaf content").unwrap();
    rel_32_vec.push("leaf.txt".to_string());
    let rel_32 = rel_32_vec.join("/");
    assert_eq!(rel_32_vec.len(), 32);

    let (code, _, _) = send_http_request(port, "GET", &format!("/api/file_content?path={rel_32}"), None, None).await;
    assert_eq!(code, 200, "T2.6: Path with exactly 32 components must be accepted");

    // T2.7: Path depth exceeding 32 components -> 400 Bad Request (DepthExceeded)
    let depth_33 = (0..33).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/") + "/file.md";
    let (code, _, _) = send_http_request(port, "GET", &format!("/api/file_content?path={depth_33}"), None, None).await;
    assert_eq!(code, 400, "T2.7: Path depth exceeding 32 must return 400 Bad Request");

    // T2.8: Exact 10 MB file reading -> 200 OK
    let (code, _, body) = send_http_request(port, "GET", "/api/raw_file?path=exact_10mb.txt", None, None).await;
    assert_eq!(code, 200, "T2.8: Exactly 10 MB file reading must return 200 OK");
    assert_eq!(body.len(), 10 * 1024 * 1024);

    // T2.9: 10 MB + 1 byte file reading -> 413 Payload Too Large
    let (code, _, _) = send_http_request(port, "GET", "/api/raw_file?path=too_large.txt", None, None).await;
    assert_eq!(code, 413, "T2.9: File exceeding 10 MB limit must return 413 Payload Too Large");

    // T2.10: Case-insensitive whitelisted extension (.PNG) -> 200 OK
    let (code, headers, _) = send_http_request(port, "GET", "/api/raw_file?path=photo.PNG", None, None).await;
    assert_eq!(code, 200, "T2.10: Case-insensitive .PNG must return 200 OK");
    assert_eq!(headers.get("content-type").map(|s| s.as_str()), Some("image/png"));

    // T2.11: Unicode and spaces in path -> 200 OK
    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=notes/rapport%20final%202026.md", None, None).await;
    assert_eq!(code, 200, "T2.11: Unicode and spaces in path must return 200 OK");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");

    // T2.12: Attempting to read directory as file -> 400 Bad Request (NotAFile)
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=src", None, None).await;
    assert_eq!(code, 400, "T2.12: Reading a directory as file must return 400 Bad Request");
}

// =========================================================================
// TIER 3: CROSS-FEATURE INTERACTIONS
// =========================================================================

#[tokio::test]
async fn test_tier3_cross_feature_interactions() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());
    let (port, _handle, _state) = start_security_test_server(temp_root.path().to_path_buf()).await;

    // T3.1: Create in deep nested folder then immediately read back
    let create_payload = json!({
        "project_path": ".",
        "file_path": "a/b/c/nested_doc.md",
        "content": "# Deeply Nested Document Content"
    });
    let req_bytes = serde_json::to_vec(&create_payload).unwrap();
    let (code, _, _) = send_http_request(port, "POST", "/api/ai/create_file", Some(&req_bytes), None).await;
    assert_eq!(code, 200, "T3.1: File creation in new directory tree must succeed");

    let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=a/b/c/nested_doc.md", None, None).await;
    assert_eq!(code, 200, "T3.1: Immediate read back of created file must succeed");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["content"].as_str().unwrap().contains("# Deeply Nested Document Content"));

    // T3.2: Save document via /api/save_doc then stream via /api/raw_file
    let save_payload = json!({
        "project_path": ".",
        "folder": "diagrams",
        "file_name": "flow.svg",
        "content": "<svg xmlns='http://www.w3.org/2000/svg'><circle r='50'/></svg>"
    });
    let req_bytes = serde_json::to_vec(&save_payload).unwrap();
    let (code, _, _) = send_http_request(port, "POST", "/api/save_doc", Some(&req_bytes), None).await;
    assert_eq!(code, 200, "T3.2: Save document flow.svg must succeed");

    let (code, headers, body) = send_http_request(port, "GET", "/api/raw_file?path=diagrams/flow.svg", None, None).await;
    assert_eq!(code, 200, "T3.2: Streaming flow.svg must succeed with 200 OK");
    assert_eq!(headers.get("content-type").map(|s| s.as_str()), Some("image/svg+xml"));
    assert!(body.starts_with(b"<svg"));

    // T3.3: Internal symlink navigation
    let real_note = temp_root.path().join("real_note.md");
    fs::write(&real_note, "# Authentic Note Content").unwrap();
    let internal_sym = temp_root.path().join("symlink_note.md");

    #[cfg(unix)]
    let sym_created = std::os::unix::fs::symlink(&real_note, &internal_sym).is_ok();
    #[cfg(windows)]
    let sym_created = std::os::windows::fs::symlink_file(&real_note, &internal_sym).is_ok();

    if sym_created {
        let (code, _, body) = send_http_request(port, "GET", "/api/file_content?path=symlink_note.md", None, None).await;
        assert_eq!(code, 200, "T3.3: Internal symlink reading within root should succeed");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["content"].as_str().unwrap().contains("# Authentic Note Content"));
    }

    // T3.4: Concurrent stress: simultaneous valid reads, valid writes, and adversarial attempts
    let mut handles = Vec::new();
    let total_success = Arc::new(AtomicUsize::new(0));

    for i in 0..20 {
        let p = port;
        let success = total_success.clone();
        handles.push(tokio::spawn(async move {
            if i % 3 == 0 {
                // Valid read
                let (code, _, _) = send_http_request(p, "GET", "/api/file_content?path=README.md", None, None).await;
                if code == 200 { success.fetch_add(1, Ordering::SeqCst); }
            } else if i % 3 == 1 {
                // Valid write
                let pl = json!({
                    "project_path": ".",
                    "file_path": format!("docs/concurrent_{i}.md"),
                    "content": format!("Concurrent file {i}")
                });
                let req_bytes = serde_json::to_vec(&pl).unwrap();
                let (code, _, _) = send_http_request(p, "POST", "/api/ai/create_file", Some(&req_bytes), None).await;
                if code == 200 { success.fetch_add(1, Ordering::SeqCst); }
            } else {
                // Adversarial traversal attempt
                let (code, _, _) = send_http_request(p, "GET", "/api/file_content?path=../../../../etc/passwd", None, None).await;
                if code == 400 || code == 403 { success.fetch_add(1, Ordering::SeqCst); }
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(total_success.load(Ordering::SeqCst), 20, "T3.4: All concurrent tasks must succeed without race conditions");

    // T3.5: Non-regression on project status endpoint
    let (code, _, body) = send_http_request(port, "GET", "/api/project/status", None, None).await;
    assert_eq!(code, 200, "T3.5: /api/project/status must continue functioning with 200 OK");
}

// =========================================================================
// TIER 4: REAL-WORLD ADVERSARIAL ATTACK SCENARIOS (CWE-22 Exploits)
// =========================================================================

#[tokio::test]
async fn test_tier4_adversarial_attack_scenarios() {
    let temp_root = tempdir().unwrap();
    setup_test_workspace(temp_root.path());

    // Outside directory containing confidential target
    let outside_dir = tempdir().unwrap();
    let outside_secret = outside_dir.path().join("outside_secret.txt");
    fs::write(&outside_secret, "CRITICAL_OUTSIDE_SECRET").unwrap();

    let (port, _handle, _state) = start_security_test_server(temp_root.path().to_path_buf()).await;

    // T4.1: Classic Unix directory traversal on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=../../../../etc/passwd", None, None).await;
    assert!(code == 400 || code == 403, "T4.1: Traversal ../ must be rejected (got {code})");

    // T4.2: Windows directory traversal on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", r"/api/file_content?path=..\..\..\..\Windows\win.ini", None, None).await;
    assert!(code == 400 || code == 403, "T4.2: Traversal ..\\ must be rejected (got {code})");

    // T4.3: Absolute Unix path on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=/etc/shadow", None, None).await;
    assert!(code == 400 || code == 403, "T4.3: Absolute Unix path must be rejected (got {code})");

    // T4.4: Absolute Windows path on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", r"/api/file_content?path=C:\Windows\System32\drivers\etc\hosts", None, None).await;
    assert!(code == 400 || code == 403, "T4.4: Absolute Windows path must be rejected (got {code})");

    // T4.5: Windows drive-relative escape on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=C:relative.txt", None, None).await;
    assert!(code == 400 || code == 403, "T4.5: Windows drive relative escape must be rejected (got {code})");

    // T4.6: Embedded drive letter bypass on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=notes/c:/escape.txt", None, None).await;
    assert!(code == 400 || code == 403, "T4.6: Embedded drive letter must be rejected (got {code})");

    // T4.7: UNC network path on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", r"/api/file_content?path=\\evil.com\share\loot.txt", None, None).await;
    assert!(code == 400 || code == 403, "T4.7: UNC path must be rejected (got {code})");

    // T4.8: Windows NT verbatim device prefix on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", r"/api/file_content?path=\\?\C:\Windows\win.ini", None, None).await;
    assert!(code == 400 || code == 403, "T4.8: NT device prefix must be rejected (got {code})");

    // T4.9: Null byte truncation attack on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=note.md%00.txt", None, None).await;
    assert!(code == 400 || code == 403, "T4.9: Null byte truncation attack must be rejected (got {code})");

    // T4.10: Null byte path traversal on /api/file_content
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=safe.md%00/../../etc/passwd", None, None).await;
    assert!(code == 400 || code == 403, "T4.10: Null byte traversal attack must be rejected (got {code})");

    // T4.11: Symlink directory escape on /api/file_content
    let escaping_link = temp_root.path().join("external_dir_symlink");
    #[cfg(unix)]
    let dir_sym_created = std::os::unix::fs::symlink(outside_dir.path(), &escaping_link).is_ok();
    #[cfg(windows)]
    let dir_sym_created = std::os::windows::fs::symlink_dir(outside_dir.path(), &escaping_link).is_ok();

    if dir_sym_created {
        let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=external_dir_symlink/outside_secret.txt", None, None).await;
        assert_eq!(code, 403, "T4.11: External symlink directory escape must return 403 Forbidden");
    }

    // T4.12: Symlink overwrite escape on /api/save_doc
    let escaping_file_link = temp_root.path().join("hijack_symlink.md");
    #[cfg(unix)]
    let file_sym_created = std::os::unix::fs::symlink(&outside_secret, &escaping_file_link).is_ok();
    #[cfg(windows)]
    let file_sym_created = std::os::windows::fs::symlink_file(&outside_secret, &escaping_file_link).is_ok();

    if file_sym_created {
        let save_payload = json!({
            "project_path": ".",
            "folder": ".",
            "file_name": "hijack_symlink.md",
            "content": "PWNED_CONTENT"
        });
        let req_bytes = serde_json::to_vec(&save_payload).unwrap();
        let (code, _, _) = send_http_request(port, "POST", "/api/save_doc", Some(&req_bytes), None).await;
        assert_eq!(code, 403, "T4.12: External symlink overwrite attempt must return 403 Forbidden");
        // Ensure outside file was NOT modified
        let outside_content = fs::read_to_string(&outside_secret).unwrap();
        assert_eq!(outside_content, "CRITICAL_OUTSIDE_SECRET");
    }

    // T4.13: Sensitive environment file reading (.env) -> 403 Forbidden
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.env", None, None).await;
    assert_eq!(code, 403, "T4.13: .env reading must return 403 Forbidden");

    // T4.14: Sensitive local env variant reading (.env.local) -> 403 Forbidden
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.env.local", None, None).await;
    assert_eq!(code, 403, "T4.14: .env.local reading must return 403 Forbidden");

    // T4.15: Sensitive SSH private key harvesting (.ssh/id_rsa) -> 403 Forbidden
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.ssh/id_rsa", None, None).await;
    assert_eq!(code, 403, "T4.15: .ssh/id_rsa reading must return 403 Forbidden");

    // T4.16: Sensitive AWS credentials harvesting (.aws/credentials) -> 403 Forbidden
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.aws/credentials", None, None).await;
    assert_eq!(code, 403, "T4.16: .aws/credentials reading must return 403 Forbidden");

    // T4.17: Sensitive Git configuration harvesting (.git/config) -> 403 Forbidden
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=.git/config", None, None).await;
    assert_eq!(code, 403, "T4.17: .git/config reading must return 403 Forbidden");

    // T4.18: Sensitive private key reading (certs/server.key) -> 403 Forbidden
    let (code, _, _) = send_http_request(port, "GET", "/api/file_content?path=certs/server.key", None, None).await;
    assert_eq!(code, 403, "T4.18: certs/server.key reading must return 403 Forbidden");

    // T4.19: Sensitive file creation attempt on /api/ai/create_file -> 403 Forbidden
    let create_env_payload = json!({
        "project_path": ".",
        "file_path": ".env",
        "content": "MALICIOUS_KEY=123"
    });
    let req_bytes = serde_json::to_vec(&create_env_payload).unwrap();
    let (code, _, _) = send_http_request(port, "POST", "/api/ai/create_file", Some(&req_bytes), None).await;
    assert_eq!(code, 403, "T4.19: Creating .env file must return 403 Forbidden");

    // T4.20: Extension whitelist bypass on /api/raw_file (.rs) -> 400 Bad Request
    let (code, _, _) = send_http_request(port, "GET", "/api/raw_file?path=src/lib.rs", None, None).await;
    assert_eq!(code, 400, "T4.20: Disallowed extension (.rs) on /api/raw_file must return 400 Bad Request");

    // T4.21: Extension whitelist bypass on /api/raw_file (.exe) -> 400 Bad Request
    let (code, _, _) = send_http_request(port, "GET", "/api/raw_file?path=payload.exe", None, None).await;
    assert_eq!(code, 400, "T4.21: Disallowed extension (.exe) on /api/raw_file must return 400 Bad Request");

    // T4.22: Extension whitelist bypass on /api/raw_file (.sh) -> 400 Bad Request
    let (code, _, _) = send_http_request(port, "GET", "/api/raw_file?path=script.sh", None, None).await;
    assert_eq!(code, 400, "T4.22: Disallowed extension (.sh) on /api/raw_file must return 400 Bad Request");

    // T4.23: File without extension on /api/raw_file (LICENSE) -> 400 Bad Request
    let (code, _, _) = send_http_request(port, "GET", "/api/raw_file?path=LICENSE", None, None).await;
    assert_eq!(code, 400, "T4.23: Missing extension on /api/raw_file must return 400 Bad Request");

    // T4.24: Arbitrary file creation escape on /api/ai/create_file -> 400 Bad Request
    let create_escape_payload = json!({
        "project_path": ".",
        "file_path": "../../../malicious.bat",
        "content": "@echo off\npwned"
    });
    let req_bytes = serde_json::to_vec(&create_escape_payload).unwrap();
    let (code, _, _) = send_http_request(port, "POST", "/api/ai/create_file", Some(&req_bytes), None).await;
    assert!(code == 400 || code == 403, "T4.24: Traversal in create_file must return 400/403 (got {code})");

    // T4.25: Arbitrary doc save escape on /api/save_doc -> 400 Bad Request
    let save_escape_payload = json!({
        "project_path": ".",
        "folder": "../../../Windows/System32",
        "file_name": "pwn.txt",
        "content": "pwned"
    });
    let req_bytes = serde_json::to_vec(&save_escape_payload).unwrap();
    let (code, _, _) = send_http_request(port, "POST", "/api/save_doc", Some(&req_bytes), None).await;
    assert!(code == 400 || code == 403, "T4.25: Traversal in save_doc must return 400/403 (got {code})");
}
