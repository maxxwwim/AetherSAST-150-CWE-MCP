#![allow(dead_code, unused_imports, unused_variables)]

//! Empirical Concurrency and Endpoint Stress Test Harness for Milestone M2
//! Agent: teamwork_challenger_obs_m2_1 (Empirical Challenger Archetype)
//! Scope:
//!   1. High-concurrency reader/writer stress testing on Axum API and AppState.
//!   2. Deadlock freedom, lock starvation freedom, and monotonic graph versioning.
//!   3. HTTP endpoint validation (400 on invalid modes, 422 on unavailable graphs, "notes" alias).
//!   4. Security LocalGuard boundary enforcement and out-of-process CLI validation.

#[path = "../src/api_routes.rs"]
mod api_routes;

#[path = "../src/local_guard.rs"]
mod local_guard;

use api_routes::*;
use core_graph::graph::AetherGraph;
use obsidian_vault::{DetectedProjectType, ProjectDetectionReport};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// =========================================================================
// TEST HARNESS UTILITIES
// =========================================================================

/// Sends a raw HTTP/1.1 request over TCP to the given port and parses response.
async fn send_raw_http_request(
    port: u16,
    method: &str,
    path: &str,
    custom_headers: &[(&str, &str)],
    body: Option<&serde_json::Value>,
) -> Result<(u16, serde_json::Value, String), String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("Connect error to 127.0.0.1:{}: {}", port, e))?;

    let body_str = body
        .map(|b| serde_json::to_string(b).unwrap_or_default())
        .unwrap_or_default();

    let mut has_host = false;
    let mut has_content_type = false;
    let mut header_lines = String::new();

    for (k, v) in custom_headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        header_lines.push_str(&format!("{}: {}\r\n", k, v));
    }

    if !has_host {
        header_lines.push_str(&format!("Host: 127.0.0.1:{}\r\n", port));
    }
    if !has_content_type && body.is_some() {
        header_lines.push_str("Content-Type: application/json\r\n");
    }

    let req_str = format!(
        "{} {} HTTP/1.1\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        method,
        path,
        header_lines,
        body_str.len(),
        body_str
    );

    stream
        .write_all(req_str.as_bytes())
        .await
        .map_err(|e| format!("Write error: {}", e))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("Flush error: {}", e))?;

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .await
        .map_err(|e| format!("Read error: {}", e))?;

    let response_str = String::from_utf8_lossy(&response_buf).to_string();

    let status_code = response_str
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            parts.next()?; // HTTP/1.1
            parts.next()?.parse::<u16>().ok()
        })
        .unwrap_or(0);

    let json_val = if let Some((_, json_part)) = response_str.split_once("\r\n\r\n") {
        serde_json::from_str(json_part.trim()).unwrap_or_else(|_| json!({ "raw": json_part }))
    } else {
        json!({ "raw": response_str })
    };

    Ok((status_code, json_val, response_str))
}

/// Creates a populated AppState for tests.
fn create_test_app_state(
    project_type: DetectedProjectType,
    initial_mode: &str,
    with_code_graph: bool,
    with_vault_graph: bool,
    project_path: PathBuf,
) -> Arc<AppState> {
    let mut code_graph = None;
    if with_code_graph {
        let mut g = AetherGraph::new("TestCodeProject");
        g.nodes.push(core_graph::bubble::SymbolBubble::new(
            "sym_code_1".to_string(),
            "execute_engine".to_string(),
            "src/engine.rs".to_string(),
            42,
            core_graph::bubble::SymbolKind::Function,
            "backend".to_string(),
            "core".to_string(),
        ));
        code_graph = Some(g);
    }

    let mut vault_graph = None;
    if with_vault_graph {
        let mut g = AetherGraph::new("TestVaultProject");
        g.nodes.push(core_graph::bubble::SymbolBubble::new(
            "note_arch_1".to_string(),
            "Architecture Blueprint".to_string(),
            "docs/Architecture.md".to_string(),
            1,
            core_graph::bubble::SymbolKind::File,
            "vault".to_string(),
            "docs".to_string(),
        ));
        vault_graph = Some(g);
    }

    let active_graph = match initial_mode {
        "vault" => vault_graph.clone().unwrap_or_else(|| AetherGraph::new("Empty")),
        _ => code_graph.clone().unwrap_or_else(|| AetherGraph::new("Empty")),
    };

    let detection_report = ProjectDetectionReport {
        project_type,
        has_obsidian_dir: project_type.is_vault() || project_type.is_mixed(),
        obsidian_dir_path: if project_type.is_vault() || project_type.is_mixed() {
            Some(".obsidian".to_string())
        } else {
            None
        },
        code_files_count: if with_code_graph { 10 } else { 0 },
        markdown_files_count: if with_vault_graph { 15 } else { 0 },
        obsidian_syntax_markers_count: if with_vault_graph { 40 } else { 0 },
        supported_views: project_type.supported_views().into_iter().map(|s| s.to_string()).collect(),
        default_view: project_type.default_view().to_string(),
    };

    Arc::new(AppState::new(
        active_graph,
        project_path,
        project_type,
        initial_mode.to_string(),
        code_graph,
        vault_graph,
        Some(detection_report),
    ))
}

/// Starts an ephemeral in-process Axum server matching desktop-shell's main router.
async fn start_test_server(state: Arc<AppState>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener");
    let port = listener.local_addr().expect("Local addr").port();

    let state_status = state.clone();
    let state_view_mode = state.clone();
    let state_graph = state.clone();
    let state_version = state.clone();

    let app = axum::Router::new()
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
        )
        .route(
            "/api/view_mode",
            axum::routing::post({
                let state = state_view_mode.clone();
                move |axum::extract::Json(req): axum::extract::Json<api_routes::ViewModeRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::response::IntoResponse;
                        match state.switch_view_mode(&req.mode).await {
                            Ok(graph) => (
                                axum::http::StatusCode::OK,
                                axum::Json(serde_json::to_value(graph).unwrap_or_default()),
                            )
                                .into_response(),
                            Err(api_routes::ViewModeError::InvalidMode(err)) => (
                                axum::http::StatusCode::BAD_REQUEST,
                                axum::Json(json!({
                                    "status": "error",
                                    "message": err
                                })),
                            )
                                .into_response(),
                            Err(api_routes::ViewModeError::GraphNotAvailable(err)) => (
                                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                                axum::Json(json!({
                                    "status": "error",
                                    "message": err
                                })),
                            )
                                .into_response(),
                        }
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
                        let g = state.graph.read().await;
                        axum::Json(g.clone())
                    }
                }
            }),
        )
        .route(
            "/api/graph/version",
            axum::routing::get({
                let state = state_version.clone();
                move || {
                    let state = state.clone();
                    async move {
                        let v = state.graph_version.load(std::sync::atomic::Ordering::SeqCst);
                        axum::Json(json!({ "version": v }))
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            local_guard::LocalGuard::new(port),
            local_guard::enforce_local_only,
        ));

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (port, server_handle)
}

// =========================================================================
// TEST SUITE 1: HIGH CONCURRENCY STRESS & DEADLOCK / STARVATION HARNESS
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_axum_high_concurrency_readers_writers_live_server() {
    let tmp = tempfile::tempdir().expect("Failed to create tempdir");
    let state = create_test_app_state(
        DetectedProjectType::Mixed,
        "code",
        true,
        true,
        tmp.path().to_path_buf(),
    );

    let (port, server_handle) = start_test_server(state.clone()).await;

    let initial_version = state.graph_version.load(Ordering::SeqCst);
    assert_eq!(initial_version, 1);

    // Progress metrics
    let total_status_reads = Arc::new(AtomicUsize::new(0));
    let total_graph_reads = Arc::new(AtomicUsize::new(0));
    let total_version_reads = Arc::new(AtomicUsize::new(0));
    let total_view_switches = Arc::new(AtomicUsize::new(0));

    let stop_signal = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    let start_instant = Instant::now();

    // 1. Spawn 25 Reader tasks querying /api/project/status
    for _ in 0..25 {
        let port = port;
        let counter = total_status_reads.clone();
        let stop = stop_signal.clone();
        handles.push(tokio::spawn(async move {
            let mut iters = 0;
            while iters < 25 && !stop.load(Ordering::Relaxed) {
                let res = send_raw_http_request(port, "GET", "/api/project/status", &[], None).await;
                assert!(res.is_ok(), "Status request failed: {:?}", res);
                let (code, body, _) = res.unwrap();
                assert_eq!(code, 200);
                assert_eq!(body["status"], "ok");
                let active = body["active_view_mode"].as_str().unwrap();
                assert!(active == "code" || active == "vault", "Unexpected active mode: {}", active);
                counter.fetch_add(1, Ordering::SeqCst);
                iters += 1;
                tokio::task::yield_now().await;
            }
        }));
    }

    // 2. Spawn 25 Reader tasks querying /api/graph
    for _ in 0..25 {
        let port = port;
        let counter = total_graph_reads.clone();
        let stop = stop_signal.clone();
        handles.push(tokio::spawn(async move {
            let mut iters = 0;
            while iters < 25 && !stop.load(Ordering::Relaxed) {
                let res = send_raw_http_request(port, "GET", "/api/graph", &[], None).await;
                assert!(res.is_ok(), "Graph request failed: {:?}", res);
                let (code, body, _) = res.unwrap();
                assert_eq!(code, 200);
                let p_name = body["project_name"].as_str().unwrap();
                assert!(
                    p_name == "TestCodeProject" || p_name == "TestVaultProject",
                    "Unexpected graph project_name: {}",
                    p_name
                );
                counter.fetch_add(1, Ordering::SeqCst);
                iters += 1;
                tokio::task::yield_now().await;
            }
        }));
    }

    // 3. Spawn 15 Reader tasks querying /api/graph/version (monotonically non-decreasing)
    for _ in 0..15 {
        let port = port;
        let counter = total_version_reads.clone();
        let stop = stop_signal.clone();
        handles.push(tokio::spawn(async move {
            let mut iters = 0;
            let mut last_seen_version = 0u64;
            while iters < 30 && !stop.load(Ordering::Relaxed) {
                let res = send_raw_http_request(port, "GET", "/api/graph/version", &[], None).await;
                assert!(res.is_ok(), "Version request failed: {:?}", res);
                let (code, body, _) = res.unwrap();
                assert_eq!(code, 200);
                let v = body["version"].as_u64().unwrap();
                assert!(
                    v >= last_seen_version,
                    "Graph version non-monotonic anomaly! Last: {}, Seen: {}",
                    last_seen_version,
                    v
                );
                last_seen_version = v;
                counter.fetch_add(1, Ordering::SeqCst);
                iters += 1;
                tokio::task::yield_now().await;
            }
        }));
    }

    // 4. Spawn 15 Writer tasks calling POST /api/view_mode (toggling modes)
    for worker_id in 0..15 {
        let port = port;
        let counter = total_view_switches.clone();
        let stop = stop_signal.clone();
        handles.push(tokio::spawn(async move {
            let mut iters = 0;
            while iters < 20 && !stop.load(Ordering::Relaxed) {
                let requested_mode = match (worker_id + iters) % 3 {
                    0 => "vault",
                    1 => "code",
                    _ => "notes", // Test "notes" alias under concurrent write load
                };
                let payload = json!({ "mode": requested_mode });
                let res = send_raw_http_request(port, "POST", "/api/view_mode", &[], Some(&payload)).await;
                assert!(res.is_ok(), "View mode switch failed: {:?}", res);
                let (code, body, _) = res.unwrap();
                assert_eq!(code, 200, "Expected 200 on switch, got {}", code);
                let p_name = body["project_name"].as_str().unwrap();
                let expected_p_name = if requested_mode == "code" {
                    "TestCodeProject"
                } else {
                    "TestVaultProject"
                };
                assert_eq!(p_name, expected_p_name);
                counter.fetch_add(1, Ordering::SeqCst);
                iters += 1;
                tokio::task::yield_now().await;
            }
        }));
    }

    // 5. Deadlock detection guard: wrap in tokio::time::timeout
    let join_all_future = async {
        for (i, h) in handles.into_iter().enumerate() {
            h.await.unwrap_or_else(|e| panic!("Worker task {} panicked or failed: {:?}", i, e));
        }
    };

    let timeout_res = tokio::time::timeout(Duration::from_secs(35), join_all_future).await;
    stop_signal.store(true, Ordering::SeqCst);
    server_handle.abort();

    assert!(
        timeout_res.is_ok(),
        "DEADLOCK DETECTED! Concurrency stress test timed out after 35 seconds."
    );

    let elapsed = start_instant.elapsed();

    // 6. Lock starvation verification: all operations must have completed
    let status_completed = total_status_reads.load(Ordering::SeqCst);
    let graph_completed = total_graph_reads.load(Ordering::SeqCst);
    let version_completed = total_version_reads.load(Ordering::SeqCst);
    let writes_completed = total_view_switches.load(Ordering::SeqCst);

    println!(
        "Stress Test Succeeded in {:?}: {} status reads, {} graph reads, {} version reads, {} view mode switches (Total: {})",
        elapsed,
        status_completed,
        graph_completed,
        version_completed,
        writes_completed,
        status_completed + graph_completed + version_completed + writes_completed
    );

    assert_eq!(status_completed, 25 * 25, "Status readers experienced lock starvation");
    assert_eq!(graph_completed, 25 * 25, "Graph readers experienced lock starvation");
    assert_eq!(version_completed, 15 * 30, "Version readers experienced lock starvation");
    assert_eq!(writes_completed, 15 * 20, "Writers experienced lock starvation");

    // 7. Final State Consistency Check
    let final_version = state.graph_version.load(Ordering::SeqCst);
    assert_eq!(
        final_version,
        1 + (15 * 20) as u64,
        "Version increments did not match total completed write switches"
    );

    let final_mode = state.get_active_view_mode().await;
    let final_graph = state.get_active_graph().await;
    if final_mode == "code" {
        assert_eq!(final_graph.project_name, "TestCodeProject");
    } else {
        assert_eq!(final_graph.project_name, "TestVaultProject");
    }
}

// =========================================================================
// TEST SUITE 2: HTTP ENDPOINT ERROR VALIDATION & 400 ERROR HANDLING
// =========================================================================

#[tokio::test]
async fn test_axum_view_mode_invalid_modes_and_bad_request_validation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = create_test_app_state(
        DetectedProjectType::Mixed,
        "code",
        true,
        true,
        tmp.path().to_path_buf(),
    );
    let (port, server_handle) = start_test_server(state.clone()).await;

    let invalid_mode_samples = vec![
        "invalid",
        "",
        "   ",
        "unknown_mode_3d",
        "cyberpunk",
        "none",
        "12345",
        "null",
        "../../escape",
        "code; rm -rf /",
    ];

    for sample in invalid_mode_samples {
        let payload = json!({ "mode": sample });
        let (code, body, _) = send_raw_http_request(port, "POST", "/api/view_mode", &[], Some(&payload))
            .await
            .expect("HTTP call failed");

        assert_eq!(
            code, 400,
            "Mode '{}' must return 400 Bad Request, got {}",
            sample, code
        );
        assert_eq!(body["status"], "error");
        let msg = body["message"].as_str().unwrap();
        assert!(
            msg.contains("Mode de vue inconnu") || msg.contains("Modes acceptés: 'code', 'vault'"),
            "Error message must be informative for '{}': {}",
            sample,
            msg
        );
    }

    // Malformed JSON (wrong field key) -> Axum JSON extractor returns 422 Unprocessable Entity
    let bad_field_payload = json!({ "unrecognized_key": "vault" });
    let (code, _, _) = send_raw_http_request(port, "POST", "/api/view_mode", &[], Some(&bad_field_payload))
        .await
        .expect("HTTP call");
    assert!(
        code == 422 || code == 400,
        "Missing field payload should be rejected with 422 or 400, got {}",
        code
    );

    // Non-JSON payload -> 400 Bad Request
    let (code, _, _) = send_raw_http_request(
        port,
        "POST",
        "/api/view_mode",
        &[("Content-Type", "application/json")],
        None, // empty body
    )
    .await
    .expect("HTTP call");
    assert!(code == 400 || code == 422, "Empty body rejected, got {}", code);

    server_handle.abort();
}

// =========================================================================
// TEST SUITE 3: REJECTION WHEN GRAPH UNAVAILABLE (PURE CODE & PURE VAULT)
// =========================================================================

#[tokio::test]
async fn test_axum_view_mode_rejection_when_vault_graph_unavailable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // PureCode with NO vault graph
    let state = create_test_app_state(
        DetectedProjectType::PureCode,
        "code",
        true,
        false, // NO vault graph
        tmp.path().to_path_buf(),
    );
    let (port, server_handle) = start_test_server(state.clone()).await;

    let payload = json!({ "mode": "vault" });
    let (code, body, _) = send_raw_http_request(port, "POST", "/api/view_mode", &[], Some(&payload))
        .await
        .expect("HTTP call");

    assert_eq!(
        code, 422,
        "Switching to vault on PureCode without vault graph must return 422 Unprocessable Entity, got {}",
        code
    );
    assert_eq!(body["status"], "error");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Aucun graphe Obsidian Vault n'est disponible"),
        "Unexpected error message: {:?}",
        body
    );

    // State invariants: active mode and version remain unchanged
    assert_eq!(state.get_active_view_mode().await, "code");
    assert_eq!(state.graph_version.load(Ordering::SeqCst), 1);

    server_handle.abort();
}

#[tokio::test]
async fn test_axum_view_mode_rejection_when_code_graph_unavailable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // PureObsidianVault with NO code graph
    let state = create_test_app_state(
        DetectedProjectType::PureObsidianVault,
        "vault",
        false, // NO code graph
        true,
        tmp.path().to_path_buf(),
    );
    let (port, server_handle) = start_test_server(state.clone()).await;

    let payload = json!({ "mode": "code" });
    let (code, body, _) = send_raw_http_request(port, "POST", "/api/view_mode", &[], Some(&payload))
        .await
        .expect("HTTP call");

    assert_eq!(
        code, 422,
        "Switching to code on PureObsidianVault without code graph must return 422 Unprocessable Entity, got {}",
        code
    );
    assert_eq!(body["status"], "error");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Aucun graphe AST Code n'est disponible"),
        "Unexpected error message: {:?}",
        body
    );

    // State invariants
    assert_eq!(state.get_active_view_mode().await, "vault");
    assert_eq!(state.graph_version.load(Ordering::SeqCst), 1);

    server_handle.abort();
}

// =========================================================================
// TEST SUITE 4: NORMALIZATION, ALIASES & CASE RESILIENCE
// =========================================================================

#[tokio::test]
async fn test_axum_view_mode_normalization_and_aliases() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = create_test_app_state(
        DetectedProjectType::Mixed,
        "code",
        true,
        true,
        tmp.path().to_path_buf(),
    );
    let (port, server_handle) = start_test_server(state.clone()).await;

    let cases = vec![
        ("notes", "vault", "TestVaultProject"),
        ("NOTES", "vault", "TestVaultProject"),
        ("  vault  ", "vault", "TestVaultProject"),
        ("code", "code", "TestCodeProject"),
        ("  CoDe  ", "code", "TestCodeProject"),
        ("Vault", "vault", "TestVaultProject"),
    ];

    for (input, expected_mode, expected_proj) in cases {
        let payload = json!({ "mode": input });
        let (code, body, _) = send_raw_http_request(port, "POST", "/api/view_mode", &[], Some(&payload))
            .await
            .expect("HTTP call");

        assert_eq!(code, 200, "Input '{}' failed with code {}", input, code);
        assert_eq!(body["project_name"], expected_proj);
        assert_eq!(state.get_active_view_mode().await, expected_mode);
    }

    server_handle.abort();
}

// =========================================================================
// TEST SUITE 5: IN-MEMORY APPSTATE CONCURRENCY TORTURE (10,000 OPERATIONS)
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_app_state_concurrency_race_condition_torture() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = create_test_app_state(
        DetectedProjectType::Mixed,
        "code",
        true,
        true,
        tmp.path().to_path_buf(),
    );

    let mut handles = Vec::new();

    // 40 Readers of status, mode, and active graph
    for _ in 0..40 {
        let s = state.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let status = s.get_project_status().await;
                assert_eq!(status.status, "ok");
                let mode = s.get_active_view_mode().await;
                assert!(mode == "code" || mode == "vault");
                let g = s.get_active_graph().await;
                assert!(g.project_name == "TestCodeProject" || g.project_name == "TestVaultProject");
                tokio::task::yield_now().await;
            }
        }));
    }

    // 30 Writers toggling between code and vault
    for worker_id in 0..30 {
        let s = state.clone();
        handles.push(tokio::spawn(async move {
            for j in 0..100 {
                let mode = if (worker_id + j) % 2 == 0 { "code" } else { "vault" };
                let res = s.switch_view_mode(mode).await;
                assert!(res.is_ok(), "switch_view_mode error: {:?}", res.err());
                tokio::task::yield_now().await;
            }
        }));
    }

    // 30 Observers checking version monotonicity
    let version_checks = Arc::new(AtomicU64::new(0));
    for _ in 0..30 {
        let s = state.clone();
        let checks = version_checks.clone();
        handles.push(tokio::spawn(async move {
            let mut prev_v = 0u64;
            for _ in 0..100 {
                let cur_v = s.graph_version.load(Ordering::SeqCst);
                assert!(cur_v >= prev_v, "Monotonicity violated! {} < {}", cur_v, prev_v);
                prev_v = cur_v;
                checks.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        }));
    }

    for h in handles {
        h.await.expect("Task failed");
    }

    // Final checks
    let final_v = state.graph_version.load(Ordering::SeqCst);
    assert_eq!(final_v, 1 + (30 * 100) as u64);
    assert_eq!(version_checks.load(Ordering::SeqCst), 30 * 100);
}

// =========================================================================
// TEST SUITE 6: LOCALGUARD DEFENSE AGAINST SPOOFING & CROSS-ORIGIN ATTACKS
// =========================================================================

#[tokio::test]
async fn test_local_guard_host_and_origin_security_enforcement() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = create_test_app_state(
        DetectedProjectType::Mixed,
        "code",
        true,
        true,
        tmp.path().to_path_buf(),
    );
    let (port, server_handle) = start_test_server(state.clone()).await;

    // 1. Illegitimate Host header (DNS Rebinding attack vector)
    let (code, _, raw) = send_raw_http_request(
        port,
        "GET",
        "/api/project/status",
        &[("Host", "attacker-controlled-domain.com")],
        None,
    )
    .await
    .expect("HTTP call");
    assert_eq!(code, 403, "DNS rebinding Host header must return 403 Forbidden");
    assert!(raw.contains("requête refusée"));

    // 2. Cross-origin request with external Origin (CSRF attack vector)
    let (code, _, _) = send_raw_http_request(
        port,
        "GET",
        "/api/project/status",
        &[
            ("Host", &format!("127.0.0.1:{}", port)),
            ("Origin", "http://evil-tracker.com"),
        ],
        None,
    )
    .await
    .expect("HTTP call");
    assert_eq!(code, 403, "External Origin header must return 403 Forbidden");

    // 3. Cross-site fetch metadata header
    let (code, _, _) = send_raw_http_request(
        port,
        "GET",
        "/api/project/status",
        &[
            ("Host", &format!("127.0.0.1:{}", port)),
            ("Sec-Fetch-Site", "cross-site"),
        ],
        None,
    )
    .await
    .expect("HTTP call");
    assert_eq!(code, 403, "Cross-site Sec-Fetch-Site must return 403 Forbidden");

    // 4. Legitimate request from cockpit (same-origin)
    let (code, body, _) = send_raw_http_request(
        port,
        "GET",
        "/api/project/status",
        &[
            ("Host", &format!("127.0.0.1:{}", port)),
            ("Origin", &format!("http://127.0.0.1:{}", port)),
            ("Sec-Fetch-Site", "same-origin"),
        ],
        None,
    )
    .await
    .expect("HTTP call");
    assert_eq!(code, 200, "Legitimate same-origin request must succeed with 200");
    assert_eq!(body["status"], "ok");

    server_handle.abort();
}

// =========================================================================
// TEST SUITE 7: OUT-OF-PROCESS E2E CLI LIVE SERVER VALIDATION
// =========================================================================

#[tokio::test]
async fn test_cli_live_server_endpoints_and_view_mode_toggle() {
    let mut exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    exe.pop();
    exe.pop();
    let bin_path = exe
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "aether-engine.exe" } else { "aether-engine" });

    if !bin_path.exists() {
        println!("aether-engine binary not found at {:?}, skipping CLI spawn test", bin_path);
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let p_path = tmp.path();

    // Create a mixed project structure
    let src_dir = p_path.join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        src_dir.join("main.rs"),
        "fn main() { println!(\"Hello World\"); }",
    )
    .unwrap();

    let docs_dir = p_path.join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();
    std::fs::write(
        docs_dir.join("Index.md"),
        "# Obsidian Vault\nSee [[Architecture]] for details.",
    )
    .unwrap();
    std::fs::create_dir_all(p_path.join(".obsidian")).unwrap();

    // Pick ephemeral dynamic port in private range
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = listener.local_addr().expect("port").port();
    drop(listener); // release so child process can bind it

    let mut child = std::process::Command::new(&bin_path)
        .arg("--no-gui")
        .arg("--port")
        .arg(port.to_string())
        .arg("--path")
        .arg(p_path.to_string_lossy().to_string())
        .spawn()
        .expect("Failed to spawn aether-engine process");

    // Poll until server is ready (up to 8 seconds)
    let start_wait = Instant::now();
    let mut server_ready = false;
    while start_wait.elapsed() < Duration::from_secs(8) {
        if let Ok((code, body, _)) = send_raw_http_request(port, "GET", "/api/project/status", &[], None).await {
            if code == 200 && body["status"] == "ok" {
                server_ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !server_ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("aether-engine live server failed to become ready on port {}", port);
    }

    // 1. Check Project Status returns Mixed
    let (code, status_body, _) = send_raw_http_request(port, "GET", "/api/project/status", &[], None)
        .await
        .expect("Status query");
    assert_eq!(code, 200);
    assert_eq!(status_body["project_type"], "Mixed");
    let supported = status_body["supported_views"].as_array().unwrap();
    assert!(supported.iter().any(|v| v == "code"));
    assert!(supported.iter().any(|v| v == "vault"));

    // 2. Query initial graph
    let (code, g_body, _) = send_raw_http_request(port, "GET", "/api/graph", &[], None)
        .await
        .expect("Graph query");
    assert_eq!(code, 200);
    assert!(g_body["nodes"].is_array());

    // 3. Switch view mode to "vault"
    let (code, switch_body, _) = send_raw_http_request(
        port,
        "POST",
        "/api/view_mode",
        &[],
        Some(&json!({ "mode": "vault" })),
    )
    .await
    .expect("Switch query");
    assert_eq!(code, 200);
    assert!(switch_body["nodes"].is_array());

    // Verify active view mode is now vault
    let (_, status_after, _) = send_raw_http_request(port, "GET", "/api/project/status", &[], None)
        .await
        .expect("Status query");
    assert_eq!(status_after["active_view_mode"], "vault");

    // 4. Test invalid mode returns 400 Bad Request
    let (code, err_body, _) = send_raw_http_request(
        port,
        "POST",
        "/api/view_mode",
        &[],
        Some(&json!({ "mode": "unknown_mode_xyz" })),
    )
    .await
    .expect("Invalid mode query");
    assert_eq!(code, 400);
    assert_eq!(err_body["status"], "error");

    // Cleanup child process
    let _ = child.kill();
    let _ = child.wait();
}

