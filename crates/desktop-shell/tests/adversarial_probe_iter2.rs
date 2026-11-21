#![allow(dead_code, unused_variables)]

#[path = "../src/api_routes.rs"]
mod api_routes;

use api_routes::{AiTargetRequest, AppState, FileContentQuery, SaveFileRequest};
use core_graph::graph::AetherGraph;
use core_graph::{SymbolBubble, SymbolKind};
use obsidian_vault::{DetectedProjectType, PathGuard, SecurityError};
use security_linter::{SecretGuard, SecretMasker};
use serde_json::json;
use std::fs::{self, File};
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

async fn start_test_server(
    project_root: PathBuf,
) -> (u16, tokio::task::JoinHandle<()>, Arc<AppState>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener");
    let port = listener.local_addr().expect("Local addr").port();

    let mut code_graph = AetherGraph::new("TestProject");
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

    let vault_graph = AetherGraph::new("TestProjectVault");

    let state = Arc::new(AppState::new(
        code_graph.clone(),
        project_root.clone(),
        DetectedProjectType::Mixed,
        "code".to_string(),
        Some(code_graph),
        Some(vault_graph),
        None,
    ));

    let state_file_content = state.clone();
    let state_save_file = state.clone();
    let state_ai_target = state.clone();

    let app = axum::Router::new()
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
                                        "content": final_content,
                                    })),
                                )
                                    .into_response()
                            }
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
            "/api/save_file",
            axum::routing::post({
                let state = state_save_file.clone();
                move |axum::extract::Json(req): axum::extract::Json<SaveFileRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;
                        match state.save_file(&req.file_path, &req.content).await {
                            Ok(resp) => (
                                StatusCode::OK,
                                axum::Json(serde_json::to_value(&resp).unwrap_or_default()),
                            )
                                .into_response(),
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
            "/api/ai/target",
            axum::routing::post({
                let state = state_ai_target.clone();
                move |axum::extract::Json(req): axum::extract::Json<AiTargetRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;
                        let sym_id = req.symbol_id.trim();

                        if SecretGuard::is_secret_path(Path::new(sym_id)) {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "error": "forbidden",
                                    "message": "Access to secret symbol or file prohibited"
                                })),
                            )
                                .into_response();
                        }

                        let p_root = state.project_root.read().await.clone();
                        let aether_dir = p_root.join(".aether");
                        let _ = fs::create_dir_all(&aether_dir);
                        let target_path = aether_dir.join("ACTIVE_TARGET.md");

                        let g_guard = state.graph.read().await;
                        let target_symbol = g_guard.nodes.iter().find(|n| n.id == sym_id || n.name == sym_id);

                        if let Some(symbol) = target_symbol {
                            let mut md = String::new();
                            md.push_str("# 🎯 AETHER ACTIVE TARGET CONTEXT\n\n");
                            md.push_str(&format!("- **Symbol**: `{}` (`{}`)\n", symbol.name, symbol.id));
                            md.push_str(&format!("- **File**: `{}`\n", symbol.file_path));
                            md.push_str(&format!("- **Line**: {}\n", symbol.line_number));
                            let _ = fs::write(&target_path, &md);

                            (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "status": "ok",
                                    "symbol_id": symbol.id,
                                    "symbol_name": symbol.name,
                                    "file_path": format!("{}:{}", symbol.file_path, symbol.line_number),
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "status": "not_found",
                                    "message": format!("Symbol '{}' not found", sym_id),
                                })),
                            )
                                .into_response()
                        }
                    }
                }
            }),
        );

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Axum server run");
    });

    (port, handle, state)
}

async fn send_req(
    port: u16,
    method: &str,
    uri: &str,
    body: Option<&[u8]>,
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Connect failed");

    let body_bytes = body.unwrap_or(&[]);
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        uri,
        port,
        body_bytes.len()
    );

    stream.write_all(req.as_bytes()).await.expect("Write req");
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).await.expect("Write body");
    }

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await.expect("Read resp");

    let resp_str = String::from_utf8_lossy(&resp_bytes);
    let first_line = resp_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let code: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let split = "\r\n\r\n".as_bytes();
    let body_start = resp_bytes
        .windows(split.len())
        .position(|window| window == split)
        .map(|pos| pos + split.len())
        .unwrap_or(resp_bytes.len());

    (code, resp_bytes[body_start..].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_heavy_same_file_contention() {
    let temp_root = tempdir().expect("tempdir");
    let src_dir = temp_root.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let shared_rel = "src/shared_race.rs";

    let (port, _handle, state) = start_test_server(temp_root.path().to_path_buf()).await;

    // Seed file
    let init_pld = json!({
        "file_path": shared_rel,
        "content": "// SEED CONTENT\npub fn seed() -> usize { 42 }\n"
    });
    let (c, _) = send_req(port, "POST", "/api/save_file", Some(&serde_json::to_vec(&init_pld).unwrap())).await;
    assert_eq!(c, 200);

    let num_writers = 10;
    let writes_per_writer = 30; // 300 total writes
    let num_readers = 10;
    let reads_per_reader = 50;  // 500 total reads

    println!("[ADVERSARIAL STRESS] Starting 10 writers (300 writes) and 10 readers (500 reads)...");

    let mut writers = Vec::new();
    for w in 0..num_writers {
        let p = port;
        let rel = shared_rel.to_string();
        writers.push(tokio::spawn(async move {
            let mut results = Vec::new();
            for it in 0..writes_per_writer {
                let start_token = format!("WRITER_START_{}_{}", w, it);
                let end_token = format!("WRITER_END_{}_{}", w, it);
                // Payload with 2KB padding to guarantee multi-chunk I/O
                let padding = "A".repeat(2048);
                let content = format!("// {}\npub fn f_{}_{}() -> usize {{ {} }}\n// PADDING: {}\n// {}\n",
                    start_token, w, it, it, padding, end_token);

                let pld = json!({
                    "file_path": rel,
                    "content": content
                });
                let (code, body) = send_req(p, "POST", "/api/save_file", Some(&serde_json::to_vec(&pld).unwrap())).await;
                results.push((code, body));
                // Minimal jitter between 0 and 2ms
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
            results
        }));
    }

    let mut readers = Vec::new();
    for r in 0..num_readers {
        let p = port;
        let rel = shared_rel.to_string();
        readers.push(tokio::spawn(async move {
            let mut read_results = Vec::new();
            for _ in 0..reads_per_reader {
                let (code, body) = send_req(p, "GET", &format!("/api/file_content?path={}&raw=true", rel), None).await;
                read_results.push((code, body));
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
            read_results
        }));
    }

    // Collect writers
    let mut total_writes = 0;
    let mut write_errors = 0;
    for w in writers {
        let res = w.await.expect("Writer thread panicked");
        for (code, _) in res {
            total_writes += 1;
            if code != 200 {
                write_errors += 1;
            }
        }
    }

    // Collect readers
    let mut total_reads = 0;
    let mut read_errors = 0;
    let mut empty_or_torn_reads = 0;
    let mut torn_details = Vec::new();

    for r in readers {
        let res = r.await.expect("Reader thread panicked");
        for (code, body) in res {
            total_reads += 1;
            if code != 200 {
                read_errors += 1;
            } else {
                let json_res: Result<serde_json::Value, _> = serde_json::from_slice(&body);
                match json_res {
                    Ok(json) => {
                        let content = json["content"].as_str().unwrap_or("");
                        if content.is_empty() {
                            empty_or_torn_reads += 1;
                            torn_details.push("EMPTY_READ_0_BYTES".to_string());
                        } else if content.contains("SEED CONTENT") {
                            // Valid initial content
                        } else {
                            // Check for atomic consistency: start token and end token must match
                            let has_start = content.contains("WRITER_START_");
                            let has_end = content.contains("WRITER_END_");
                            if !has_start || !has_end {
                                empty_or_torn_reads += 1;
                                torn_details.push(format!("PARTIAL_WRITE_MISSING_MARKERS: len={}", content.len()));
                            } else {
                                // Extract writer id and iter
                                let start_idx = content.find("WRITER_START_").unwrap();
                                let line_end = content[start_idx..].find('\n').unwrap_or(content.len() - start_idx);
                                let start_marker = &content[start_idx..start_idx + line_end].trim();

                                let end_idx = content.find("WRITER_END_").unwrap();
                                let end_line = content[end_idx..].find('\n').unwrap_or(content.len() - end_idx);
                                let end_marker = &content[end_idx..end_idx + end_line].trim();

                                let expected_end = start_marker.replace("WRITER_START_", "WRITER_END_");
                                if end_marker != &expected_end {
                                    empty_or_torn_reads += 1;
                                    torn_details.push(format!("TORN_READ_MISMATCH: start='{}' vs end='{}'", start_marker, end_marker));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        empty_or_torn_reads += 1;
                        torn_details.push(format!("CORRUPT_JSON_RESPONSE: {}", e));
                    }
                }
            }
        }
    }

    println!("[ADVERSARIAL STRESS RESULTS]");
    println!("  Total Writes: {} (Errors: {})", total_writes, write_errors);
    println!("  Total Reads:  {} (Errors: {})", total_reads, read_errors);
    println!("  Torn / Empty Reads: {}", empty_or_torn_reads);
    if !torn_details.is_empty() {
        println!("  Torn details sample: {:?}", &torn_details[..torn_details.len().min(5)]);
    }

    // Check for leftover temp files in src/
    let mut leftover_temp = 0;
    if let Ok(entries) = fs::read_dir(&src_dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.contains(".tmp.") {
                leftover_temp += 1;
                println!("  Leftover temp file detected: {}", fname);
            }
        }
    }

    assert_eq!(write_errors, 0, "Writes must have 0 errors under load");
    assert_eq!(read_errors, 0, "Reads must have 0 errors under load");
    assert_eq!(empty_or_torn_reads, 0, "There must be ZERO torn or empty reads!");
    assert_eq!(leftover_temp, 0, "No temporary files should be orphaned on disk!");
}

#[tokio::test]
async fn test_adversarial_security_and_boundary_strictness() {
    let temp_root = tempdir().expect("tempdir");
    let src_dir = temp_root.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();
    fs::write(temp_root.path().join(".env"), "SECRET=true\n").unwrap();
    fs::write(temp_root.path().join("id_rsa"), "KEY\n").unwrap();

    let (port, _handle, state) = start_test_server(temp_root.path().to_path_buf()).await;

    // 1. Strict Status Code 400 on Traversal (GET and POST)
    let (c1, _) = send_req(port, "GET", "/api/file_content?path=../../etc/passwd", None).await;
    assert_eq!(c1, 400, "Traversal ../ must return 400 Bad Request");

    let (c2, _) = send_req(port, "GET", r"/api/file_content?path=..\..\windows\win.ini", None).await;
    assert_eq!(c2, 400, r"Traversal ..\ must return 400 Bad Request");

    let (c3, _) = send_req(port, "POST", "/api/save_file", Some(br#"{"file_path":"../outside.rs","content":"x"}"#)).await;
    assert_eq!(c3, 400, "Save traversal must return 400 Bad Request");

    // 2. Strict Status Code 400 on Absolute Paths
    let (c4, _) = send_req(port, "POST", "/api/save_file", Some(br#"{"file_path":"/etc/shadow","content":"x"}"#)).await;
    assert_eq!(c4, 400, "Absolute unix path must return 400 Bad Request");

    let (c5, _) = send_req(port, "POST", "/api/save_file", Some(br#"{"file_path":"C:\\Windows\\win.ini","content":"x"}"#)).await;
    assert_eq!(c5, 400, "Absolute windows path must return 400 Bad Request");

    // 3. Strict Status Code 400 on Windows UNC & Drive Letters
    let (c6, _) = send_req(port, "GET", r"/api/file_content?path=\\server\share\file.rs", None).await;
    assert_eq!(c6, 400, "UNC backslash must return 400 Bad Request");

    let (c7, _) = send_req(port, "GET", "/api/file_content?path=//server/share/file.rs", None).await;
    assert_eq!(c7, 400, "UNC slash must return 400 Bad Request");

    let (c8, _) = send_req(port, "POST", "/api/save_file", Some(br#"{"file_path":"\\\\attacker\\share\\p.rs","content":"x"}"#)).await;
    assert_eq!(c8, 400, "UNC save must return 400 Bad Request");

    let (c9, _) = send_req(port, "GET", "/api/file_content?path=C:/Windows/win.ini", None).await;
    assert_eq!(c9, 400, "Drive letter C:/ must return 400 Bad Request");

    let (c10, _) = send_req(port, "GET", r"/api/file_content?path=C:\Windows\win.ini", None).await;
    assert_eq!(c10, 400, r"Drive letter C:\ must return 400 Bad Request");

    // 4. Strict Status Code 403 on Protected Files
    let (c11, _) = send_req(port, "GET", "/api/file_content?path=.env", None).await;
    assert_eq!(c11, 403, ".env read must return 403 Forbidden");

    let (c12, _) = send_req(port, "GET", "/api/file_content?path=id_rsa", None).await;
    assert_eq!(c12, 403, "id_rsa read must return 403 Forbidden");

    let (c13, _) = send_req(port, "POST", "/api/save_file", Some(br#"{"file_path":".env","content":"x"}"#)).await;
    assert_eq!(c13, 403, ".env save must return 403 Forbidden");

    let (c14, _) = send_req(port, "POST", "/api/save_file", Some(br#"{"file_path":".env.production","content":"x"}"#)).await;
    assert_eq!(c14, 403, ".env.production save must return 403 Forbidden");

    // 5. Strict Status Code 404 on Missing File
    let (c15, _) = send_req(port, "GET", "/api/file_content?path=src/nonexistent.rs", None).await;
    assert_eq!(c15, 404, "Missing file must return 404 Not Found");

    // 6. Strict Status Code 413 on >10MB File (T2.2.5)
    let large_file_path = temp_root.path().join("large_10mb_plus_1kb.bin");
    let large_file = File::create(&large_file_path).unwrap();
    large_file.set_len(10 * 1024 * 1024 + 1024).unwrap();
    drop(large_file);

    let (c16, body16) = send_req(port, "GET", "/api/file_content?path=large_10mb_plus_1kb.bin", None).await;
    assert_eq!(c16, 413, "Reading >10MB file must return 413 Payload Too Large");
    let json16: serde_json::Value = serde_json::from_slice(&body16).unwrap();
    assert_eq!(json16["status"], "error");
    assert_eq!(json16["error"], "payload_too_large");

    // 7. Feature F10: POST /api/ai/target Disk Persistence
    let (c17, body17) = send_req(port, "POST", "/api/ai/target", Some(br#"{"symbol_id":"sym_service_run","action_type":"Inspect"}"#)).await;
    assert_eq!(c17, 200, "F10 valid target must return 200 OK");
    let json17: serde_json::Value = serde_json::from_slice(&body17).unwrap();
    assert_eq!(json17["status"], "ok");
    assert_eq!(json17["symbol_name"], "run");

    let target_md_path = temp_root.path().join(".aether/ACTIVE_TARGET.md");
    assert!(target_md_path.exists(), ".aether/ACTIVE_TARGET.md must exist on disk");
    let content_md = fs::read_to_string(&target_md_path).unwrap();
    assert!(content_md.contains("# 🎯 AETHER ACTIVE TARGET CONTEXT"));
    assert!(content_md.contains("`run`"));
    assert!(content_md.contains("`src/service.rs`"));

    // F10 Secret symbol target rejected with 403
    let (c18, _) = send_req(port, "POST", "/api/ai/target", Some(br#"{"symbol_id":".env"}"#)).await;
    assert_eq!(c18, 403, "Targeting .env must return 403 Forbidden");

    println!("[ADVERSARIAL BOUNDARY & SECURITY CHECKS] All 18 assertions passed strictly!");
}

