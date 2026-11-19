//! E2E Production Hardening Suite — R3: Graph Memory & `/api/graph` Slimming (F-E2E-8, F-E2E-9)
//!
//! Covers:
//! - F-E2E-8: `/api/graph` slimmed `ui_payload` vs `/api/graph?full=1`, `edges_compact`, `LocalGuard`,
//!   `resolve_graph_edges`, `viewer.rs` full export preservation.
//! - F-E2E-9: On-demand `/api/file_content` (masking, `?raw=true`, path confinement), `/api/ai/system_prompt`,
//!   `POST`/`GET /api/analyze`, `POST /api/view_mode` slimming and error handling.
//! - Tiers 1–4 (31 tests total, zero `#[ignore]`).

use ast_scanner::ProjectScanner;
use core_graph::edge::FilterAffiliation;
use core_graph::SymbolKind;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ============================================================================
// Opaque-Box HTTP & Process Harness
// ============================================================================

struct ServerGuard {
    child: Child,
    port: u16,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            let preview = String::from_utf8_lossy(&self.body[..self.body.len().min(512)]);
            panic!(
                "Failed to parse HTTP {} body as JSON ({}): {}",
                self.status, e, preview
            );
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

fn find_aether_engine_bin() -> PathBuf {
    if let Some(bin) = option_env!("CARGO_BIN_EXE_aether-engine") {
        let p = PathBuf::from(bin);
        if p.exists() {
            return p;
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let exe_name = if cfg!(windows) {
        "aether-engine.exe"
    } else {
        "aether-engine"
    };
    let debug_bin = manifest
        .join("..")
        .join("..")
        .join("target")
        .join("debug")
        .join(exe_name);
    if debug_bin.exists() {
        return debug_bin;
    }
    let release_bin = manifest
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join(exe_name);
    if release_bin.exists() {
        return release_bin;
    }
    panic!(
        "Could not locate aether-engine binary at {:?} or {:?}",
        debug_bin, release_bin
    );
}

fn allocate_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

async fn spawn_no_gui_server(root: &Path, extra_args: &[&str]) -> ServerGuard {
    let bin = find_aether_engine_bin();
    let port = allocate_ephemeral_port();
    let mut cmd = Command::new(&bin);
    cmd.arg("--no-gui")
        .arg("--port")
        .arg(port.to_string())
        .arg("--path")
        .arg(root);
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {:?}: {}", bin, e));
    let mut guard = ServerGuard { child, port };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Some(exit_status)) = guard.child.try_wait() {
            panic!(
                "aether-engine exited prematurely with status {:?} before /api/health became ready (args: {:?})",
                exit_status, extra_args
            );
        }
        if let Ok(resp) = send_get_raw(port, "/api/health").await {
            if resp.status == 200 {
                return guard;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "Timed out waiting 30s for aether-engine /api/health on 127.0.0.1:{}",
                port
            );
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn parse_headers_and_status(header_bytes: &[u8]) -> (u16, HashMap<String, String>) {
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    (status, headers)
}

fn decode_chunked_complete(raw: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let rest = &raw[pos..];
        let Some(rel_crlf) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&rest[..rel_crlf])
            .map_err(|e| format!("invalid chunk size utf8: {}", e))?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|e| format!("invalid chunk hex '{}': {}", hex_part, e))?;
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            // Expect final CRLF (or trailers ending in CRLF)
            if raw[pos..].windows(2).any(|w| w == b"\r\n") || raw.len() >= pos + 2 {
                return Ok(Some(out));
            }
            return Ok(None);
        }
        if raw.len() < pos + chunk_len + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&raw[pos..pos + chunk_len]);
        pos += chunk_len + 2;
    }
}

async fn send_raw_http_request(port: u16, raw_req: &[u8]) -> Result<HttpResponse, String> {
    let addr = format!("127.0.0.1:{}", port);
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("TCP connect timeout to {}", addr))?
        .map_err(|e| format!("TCP connect error to {}: {}", addr, e))?;

    tokio::time::timeout(Duration::from_secs(5), stream.write_all(raw_req))
        .await
        .map_err(|_| "TCP write timeout".to_string())?
        .map_err(|e| format!("TCP write error: {}", e))?;
    let _ = stream.flush().await;

    let mut buf: Vec<u8> = Vec::with_capacity(65_536);
    let mut tmp = [0u8; 16_384];

    // 1. Read until `\r\n\r\n` header terminator on raw bytes
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut tmp))
            .await
            .map_err(|_| "HTTP header read timeout".to_string())?
            .map_err(|e| format!("HTTP header read error: {}", e))?;
        if n == 0 {
            return Err(format!(
                "EOF before HTTP headers completed (received {} bytes)",
                buf.len()
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let (status, headers) = parse_headers_and_status(&buf[..header_end]);
    let body_start = header_end + 4;
    let mut body_buf = buf[body_start..].to_vec();

    // 2. Decode body framing: chunked -> content-length -> EOF (Connection: close)
    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    let final_body = if is_chunked {
        loop {
            if let Some(decoded) = decode_chunked_complete(&body_buf)? {
                break decoded;
            }
            let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut tmp))
                .await
                .map_err(|_| "HTTP chunked body read timeout".to_string())?
                .map_err(|e| format!("HTTP chunked body read error: {}", e))?;
            if n == 0 {
                return Err("EOF before final 0-size HTTP chunk".to_string());
            }
            body_buf.extend_from_slice(&tmp[..n]);
        }
    } else if let Some(cl_val) = headers.get("content-length") {
        let expected_len: usize = cl_val
            .trim()
            .parse()
            .map_err(|e| format!("Invalid Content-Length '{}': {}", cl_val, e))?;
        while body_buf.len() < expected_len {
            let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut tmp))
                .await
                .map_err(|_| "HTTP Content-Length body read timeout".to_string())?
                .map_err(|e| format!("HTTP Content-Length body read error: {}", e))?;
            if n == 0 {
                return Err(format!(
                    "Truncated HTTP body: expected {} bytes, got {}",
                    expected_len,
                    body_buf.len()
                ));
            }
            body_buf.extend_from_slice(&tmp[..n]);
        }
        body_buf.truncate(expected_len);
        body_buf
    } else {
        loop {
            let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut tmp))
                .await
                .map_err(|_| "HTTP EOF body read timeout".to_string())?
                .map_err(|e| format!("HTTP EOF body read error: {}", e))?;
            if n == 0 {
                break;
            }
            body_buf.extend_from_slice(&tmp[..n]);
        }
        body_buf
    };

    Ok(HttpResponse {
        status,
        headers,
        body: final_body,
    })
}

async fn send_get_raw(port: u16, path_and_query: &str) -> Result<HttpResponse, String> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        path_and_query, port
    );
    send_raw_http_request(port, req.as_bytes()).await
}

async fn http_get(port: u16, path_and_query: &str) -> HttpResponse {
    send_get_raw(port, path_and_query)
        .await
        .unwrap_or_else(|e| panic!("GET {} failed: {}", path_and_query, e))
}

async fn http_post_json(port: u16, path: &str, payload: &Value) -> HttpResponse {
    let body = serde_json::to_vec(payload).expect("serialize JSON request");
    let header = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        port,
        body.len()
    );
    let mut raw = header.into_bytes();
    raw.extend_from_slice(&body);
    send_raw_http_request(port, &raw)
        .await
        .unwrap_or_else(|e| panic!("POST {} failed: {}", path, e))
}

fn edge_count_from_graph_json(v: &Value) -> usize {
    if let Some(compact) = v.get("edges_compact").and_then(|ec| ec.as_object()) {
        if let Some(src) = compact.get("src").and_then(|s| s.as_array()) {
            return src.len();
        }
    }
    v.get("edges")
        .and_then(|e| e.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

fn assert_slim_ui_payload_invariants(v: &Value, context: &str) {
    assert!(
        v.get("system_prompt").is_none_or(|x| x.is_null()),
        "[{}] slimmed ui_payload must omit top-level system_prompt",
        context
    );
    assert!(
        v.get("dataflow_graph").is_none_or(|x| x.is_null()),
        "[{}] slimmed ui_payload must omit top-level dataflow_graph",
        context
    );
    let nodes = v
        .get("nodes")
        .and_then(|n| n.as_array())
        .unwrap_or_else(|| panic!("[{}] missing nodes array", context));
    for node in nodes {
        let node_id = node.get("id").and_then(|i| i.as_str()).unwrap_or("<unknown>");
        let meta = node
            .get("metadata")
            .unwrap_or_else(|| panic!("[{}] node {} missing metadata", context, node_id));
        assert!(
            meta.get("raw_content").is_none_or(|x| x.is_null()),
            "[{}] node {} must omit metadata.raw_content in slimmed ui_payload",
            context,
            node_id
        );
        let cve_count = meta
            .get("cve_anomalies")
            .and_then(|c| c.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if cve_count > 0 {
            let dup_viol_count = meta
                .get("violations")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            assert_eq!(
                dup_viol_count, 0,
                "[{}] node {} has {} cve_anomalies so duplicate metadata.violations must be empty/omitted (found {})",
                context, node_id, cve_count, dup_viol_count
            );
        }
    }
}

fn write_file_rel(root: &Path, rel: &str, content: &str) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).expect("create_dir_all");
    }
    fs::write(&full, content).expect("fs::write");
}

fn create_pure_code_vuln_fixture(root: &Path) {
    write_file_rel(
        root,
        "AETHER_AI_RULES.md",
        "# AetherScope AI Rules\nNever trust unvalidated HTTP input.\n",
    );
    write_file_rel(
        root,
        "README.md",
        "# Payments Service\nHandles invoice rendering and SQL queries.\nSee [vuln](src/vuln.php) and `handle_user`.\n",
    );
    write_file_rel(
        root,
        "src/vuln.php",
        r#"<?php
function handle_user() {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id=" . $id;
    mysqli_query($conn, $sql);
    eval($_GET['cmd']);
}
"#,
    );
    write_file_rel(
        root,
        "src/helper.py",
        r#"def compute_total(items):
    return sum(items)
"#,
    );
}

fn create_mixed_code_vault_fixture(root: &Path) {
    write_file_rel(
        root,
        "AETHER_AI_RULES.md",
        "# Mixed Workspace Rules\nKeep code and vault synchronized.\n",
    );
    write_file_rel(
        root,
        "README.md",
        "# Mixed Code + Vault Project\nRoot code overview for [api](src/api.py).\n",
    );
    write_file_rel(
        root,
        "src/api.py",
        r#"import os

def run_report(user_cmd):
    os.system(user_cmd)
    return "done"
"#,
    );
    write_file_rel(
        root,
        "src/db.py",
        r#"def fetch_records(limit):
    return [i for i in range(limit)]
"#,
    );
    write_file_rel(root, "docs/.obsidian/app.json", "{}\n");
    write_file_rel(
        root,
        "docs/Architecture.md",
        "---\ntags: [arch, security]\naliases: [ArchOverview]\n---\n# Architecture\nLinks to [[Runbook]] and [[FutureSpec]].\n#vault/architecture\n",
    );
    write_file_rel(
        root,
        "docs/Runbook.md",
        "---\ntags: [ops]\n---\n# Runbook\nBack to [[Architecture]].\n#ops/runbook\n",
    );
}

fn create_pure_obsidian_vault_fixture(root: &Path) {
    write_file_rel(root, ".obsidian/app.json", "{}\n");
    write_file_rel(
        root,
        "Index.md",
        "---\ntags: [index]\naliases: [Home]\n---\n# Vault Home\nSee [[Architecture]] and [[SecuritySpecs]].\n#vault/index\n",
    );
    write_file_rel(
        root,
        "Architecture.md",
        "---\ntags: [design]\n---\n# Architecture\nBack to [[Index]].\n#design/core\n",
    );
    write_file_rel(
        root,
        "notes/SecuritySpecs.md",
        "# Security Specs\nReferences [[Index]].\n#security/specs\n",
    );
}

// ============================================================================
// TIER 1 — Core Behavior Tests (12 Tests)
// ============================================================================

#[tokio::test]
async fn t1_f8_health_and_local_guard_accepts_loopback_host() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "src/lib.rs", "pub fn ping() -> u32 { 1 }\n");
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let health = http_get(guard.port, "/api/health").await;
    assert_eq!(health.status, 200);
    let h_json = health.json();
    assert_eq!(h_json["status"], "ok");
    assert_eq!(h_json["engine"], "aether-v2");

    let ver = http_get(guard.port, "/api/graph/version").await;
    assert_eq!(ver.status, 200);
    let v_json = ver.json();
    assert!(
        v_json["version"].as_u64().unwrap_or(0) >= 1,
        "expected initial graph version >= 1, got {:?}",
        v_json
    );
}

#[tokio::test]
async fn t1_f8_graph_full_retains_complete_aether_graph_fields() {
    let dir = tempdir().unwrap();
    create_pure_code_vuln_fixture(dir.path());
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let resp = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.headers
            .get("content-type")
            .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false),
        "expected application/json Content-Type on /api/graph?full=1, got {:?}",
        resp.headers.get("content-type")
    );
    let g = resp.json();

    let nodes = g["nodes"].as_array().expect("nodes array");
    assert!(!nodes.is_empty(), "nodes must be non-empty");

    let edges = g["edges"].as_array().expect("edges array");
    assert!(!edges.is_empty(), "edges must be non-empty in ?full=1");
    assert!(
        edges[0].get("source").is_some()
            && edges[0].get("target").is_some()
            && edges[0].get("relation").is_some(),
        "full edges must serialize as objects with source/target/relation"
    );
    assert!(
        g.get("edges_compact").is_none(),
        "?full=1 must never include edges_compact"
    );
    assert!(
        g.get("system_prompt")
            .and_then(|s| s.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "?full=1 must retain non-empty system_prompt"
    );

    let readme_node = nodes
        .iter()
        .find(|n| n["file_path"] == "README.md" && n["is_file"] == true)
        .expect("README.md doc node must exist");
    assert!(
        readme_node["metadata"]["raw_content"]
            .as_str()
            .map(|s| s.contains("Payments Service"))
            .unwrap_or(false),
        "?full=1 must retain metadata.raw_content on README.md"
    );

    let has_cve_and_viol = nodes.iter().any(|n| {
        !n["metadata"]["cve_anomalies"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true)
            && !n["metadata"]["violations"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true)
    });
    assert!(
        has_cve_and_viol,
        "?full=1 must retain both cve_anomalies and violations on vulnerable node"
    );
}

#[tokio::test]
async fn t1_f8_graph_ui_omits_system_prompt_and_dataflow_graph() {
    let dir = tempdir().unwrap();
    create_pure_code_vuln_fixture(dir.path());
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let resp = http_get(guard.port, "/api/graph").await;
    assert_eq!(resp.status, 200);
    let g = resp.json();

    assert!(
        g.get("system_prompt").is_none_or(|x| x.is_null()),
        "slimmed /api/graph must omit system_prompt even on small projects"
    );
    assert!(
        g.get("dataflow_graph").is_none_or(|x| x.is_null()),
        "slimmed /api/graph must omit dataflow_graph even when taint analysis runs"
    );
    assert!(
        !g["nodes"].as_array().expect("nodes").is_empty(),
        "slimmed /api/graph must preserve nodes"
    );
    assert!(
        g["stats"]["total_nodes"].as_u64().unwrap_or(0) > 0,
        "stats.total_nodes must remain populated"
    );
    assert!(
        edge_count_from_graph_json(&g) > 0,
        "slimmed /api/graph must preserve edge topology via edges or edges_compact"
    );
}

#[tokio::test]
async fn t1_f8_graph_ui_omits_docs_raw_content_and_duplicate_violations() {
    let dir = tempdir().unwrap();
    write_file_rel(
        dir.path(),
        "README.md",
        "# Service Docs\nDetailed markdown content under 32KB.\n",
    );
    write_file_rel(
        dir.path(),
        "src/app.py",
        r#"import os
def execute_cmd(cmd):
    os.system(cmd)
    eval(cmd)
"#,
    );
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let resp = http_get(guard.port, "/api/graph").await;
    assert_eq!(resp.status, 200);
    let g = resp.json();
    assert_slim_ui_payload_invariants(&g, "t1_f8_graph_ui_omits_docs_raw_content");

    let nodes = g["nodes"].as_array().unwrap();
    assert!(
        nodes.iter().any(|n| n["layer"] == "docs"),
        "expected README.md node with layer == docs"
    );
    assert!(
        nodes.iter().any(|n| {
            n["has_security_violation"] == true
                && !n["metadata"]["cve_anomalies"]
                    .as_array()
                    .map(|a| a.is_empty())
                    .unwrap_or(true)
        }),
        "expected vulnerable node with has_security_violation == true and populated cve_anomalies"
    );
}

#[tokio::test]
async fn t1_f8_graph_ui_payload_strictly_smaller_than_full_graph() {
    let dir = tempdir().unwrap();
    let long_rules = format!(
        "# AetherScope Rules\n{}\n",
        "Always validate input boundaries and sanitize SQL.\n".repeat(80)
    );
    let long_readme = format!(
        "# Architecture Contract\n{}\n",
        "Detailed service contract documentation line.\n".repeat(160)
    );
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", &long_rules);
    write_file_rel(dir.path(), "README.md", &long_readme);
    for i in 0..10 {
        write_file_rel(
            dir.path(),
            &format!("src/mod_{}.py", i),
            &format!(
                "import os\ndef handler_{}(user_input):\n    os.system(user_input)\n    eval(user_input)\n",
                i
            ),
        );
    }

    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let ui_resp = http_get(guard.port, "/api/graph").await;
    let full_resp = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(ui_resp.status, 200);
    assert_eq!(full_resp.status, 200);

    let ui_json = ui_resp.json();
    let full_json = full_resp.json();
    assert_eq!(
        ui_json["nodes"].as_array().unwrap().len(),
        full_json["nodes"].as_array().unwrap().len()
    );
    assert_eq!(ui_json["stats"]["total_nodes"], full_json["stats"]["total_nodes"]);
    assert!(
        ui_resp.body.len() < full_resp.body.len(),
        "expected slimmed /api/graph ({} bytes) < /api/graph?full=1 ({} bytes)",
        ui_resp.body.len(),
        full_resp.body.len()
    );
}

#[test]
fn t1_f8_resolve_graph_edges_preserves_calls_imports_and_api_endpoints() {
    let dir = tempdir().unwrap();
    write_file_rel(
        dir.path(),
        "README.md",
        "# Orders Architecture\nSee [orders](server/orders.rs) and `loadOrders`.\n",
    );
    write_file_rel(
        dir.path(),
        "client/ui.ts",
        r#"import { queryOrders } from '../server/db';
export function loadOrders() {
    if (true) {
        const res = queryOrders();
        return fetch('/api/orders');
    }
    return null;
}
"#,
    );
    write_file_rel(
        dir.path(),
        "server/db.rs",
        "pub fn queryOrders() -> String {\n    String::from(\"orders\")\n}\n",
    );
    write_file_rel(
        dir.path(),
        "server/orders.rs",
        "pub fn list_orders() -> usize {\n    helper_count()\n}\nfn helper_count() -> usize { 42 }\n",
    );

    let graph = ProjectScanner::default().scan_project(dir.path());

    // 1. Materialized api::/api/orders node + network edge
    let api_node = graph
        .nodes
        .iter()
        .find(|n| n.id == "api::/api/orders")
        .expect("materialized api::/api/orders endpoint node must exist");
    assert_eq!(api_node.kind, SymbolKind::FormOrEndpoint);
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.target == "api::/api/orders" && e.relation == "network"),
        "expected network edge to api::/api/orders"
    );

    // 2. Cross-galaxy import violation from client/ui.ts -> server/db.rs
    let cross_import = graph
        .edges
        .iter()
        .find(|e| {
            e.source == "file::client/ui.ts"
                && e.target == "file::server/db.rs"
                && e.relation == "imports"
        })
        .expect("expected imports edge from client/ui.ts to server/db.rs");
    assert!(
        cross_import
            .filters
            .contains(FilterAffiliation::SECURITY_VIOLATES),
        "client->server import must set SECURITY_VIOLATES flag"
    );
    assert!(
        cross_import
            .violation_details
            .as_deref()
            .unwrap_or("")
            .contains("CROSS_GALAXY_VIOLATION"),
        "expected CROSS_GALAXY_VIOLATION detail"
    );

    // 3. Calls & documents edges
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.source == "server/orders.rs::list_orders"
                && e.target == "server/orders.rs::helper_count"
                && e.relation == "calls"),
        "expected calls edge list_orders -> helper_count"
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.source == "file::README.md" && e.relation == "documents"),
        "expected documents edge from README.md"
    );

    // 4. Language keywords never become nodes & degrees match edges
    assert!(
        !graph.nodes.iter().any(|n| n.name == "if" || n.name == "for"),
        "language keywords must not become graph nodes"
    );
    let helper = graph
        .nodes
        .iter()
        .find(|n| n.id == "server/orders.rs::helper_count")
        .expect("helper_count node");
    assert!(helper.in_degree >= 1, "helper_count in_degree should be >= 1");
}

#[tokio::test]
async fn t1_f9_file_content_loads_source_and_docs_on_demand() {
    let dir = tempdir().unwrap();
    let readme_txt = "# On-Demand Docs\nLoaded via /api/file_content.\n";
    let src_txt = "pub fn handle() -> &'static str {\n    \"ok\"\n}\n";
    write_file_rel(dir.path(), "README.md", readme_txt);
    write_file_rel(dir.path(), "src/handler.rs", src_txt);

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let r_doc = http_get(guard.port, "/api/file_content?path=README.md").await;
    assert_eq!(r_doc.status, 200);
    let j_doc = r_doc.json();
    assert_eq!(j_doc["status"], "ok");
    assert_eq!(j_doc["path"], "README.md");
    assert_eq!(j_doc["content"], readme_txt);

    let r_src = http_get(guard.port, "/api/file_content?path=src/handler.rs").await;
    assert_eq!(r_src.status, 200);
    let j_src = r_src.json();
    assert_eq!(j_src["status"], "ok");
    assert_eq!(j_src["path"], "src/handler.rs");
    assert_eq!(j_src["content"], src_txt);
}

#[tokio::test]
async fn t1_f9_file_content_masks_secrets_by_default_and_unmasks_with_raw_true() {
    let dir = tempdir().unwrap();
    let secret = "sk-1234567890abcdef1234567890abcdef";
    let js = format!("export const OPENAI_KEY = \"{}\";\n", secret);
    write_file_rel(dir.path(), "src/config.js", &js);

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let masked_resp = http_get(guard.port, "/api/file_content?path=src/config.js").await;
    assert_eq!(masked_resp.status, 200);
    let masked_content = masked_resp.json()["content"]
        .as_str()
        .expect("content string")
        .to_string();
    assert!(
        masked_content.contains("[REDACTED]"),
        "default /api/file_content must redact secret, got: {}",
        masked_content
    );
    assert!(
        !masked_content.contains(secret),
        "default /api/file_content must not leak raw secret"
    );

    let raw_resp = http_get(guard.port, "/api/file_content?path=src/config.js&raw=true").await;
    assert_eq!(raw_resp.status, 200);
    let raw_content = raw_resp.json()["content"]
        .as_str()
        .expect("raw content string")
        .to_string();
    assert_eq!(raw_content, js);
}

#[tokio::test]
async fn t1_f9_system_prompt_endpoint_serves_prompt_on_demand() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "README.md", "# Service\n");
    write_file_rel(dir.path(), "src/main.rs", "fn main() {}\n");

    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let resp = http_get(guard.port, "/api/ai/system_prompt").await;
    assert_eq!(resp.status, 200);
    let j = resp.json();
    assert_eq!(j["status"], "ok");
    assert!(
        j["project_name"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "project_name must be non-empty"
    );
    assert!(
        j["project_path"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "project_path must be non-empty"
    );
    assert!(
        j["stack"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "stack must be non-empty"
    );
    assert!(
        j["system_prompt"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "system_prompt must be non-empty"
    );
}

#[tokio::test]
async fn t1_f9_analyze_post_and_get_return_slimmed_ui_payload() {
    let dir = tempdir().unwrap();
    create_pure_code_vuln_fixture(dir.path());
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let v0 = http_get(guard.port, "/api/graph/version").await.json()["version"]
        .as_u64()
        .unwrap();

    let post_resp = http_post_json(
        guard.port,
        "/api/analyze",
        &json!({ "path": dir.path().to_string_lossy().to_string() }),
    )
    .await;
    assert_eq!(post_resp.status, 200);
    let post_json = post_resp.json();
    assert_slim_ui_payload_invariants(&post_json, "POST /api/analyze");

    let v1 = http_get(guard.port, "/api/graph/version").await.json()["version"]
        .as_u64()
        .unwrap();
    assert!(v1 > v0, "POST /api/analyze must bump graph_version");

    let get_resp = http_get(guard.port, "/api/analyze?path=.").await;
    assert_eq!(get_resp.status, 200);
    let get_json = get_resp.json();
    assert_slim_ui_payload_invariants(&get_json, "GET /api/analyze");

    let full_resp = http_get(guard.port, "/api/graph?full=1").await;
    assert!(
        post_resp.body.len() < full_resp.body.len(),
        "POST /api/analyze ({} B) must be smaller than ?full=1 ({} B)",
        post_resp.body.len(),
        full_resp.body.len()
    );
}

#[tokio::test]
async fn t1_f9_view_mode_post_switches_mixed_views_with_slimmed_payload() {
    let dir = tempdir().unwrap();
    create_mixed_code_vault_fixture(dir.path());
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    for mode in ["vault", "code", "ide"] {
        let resp = http_post_json(guard.port, "/api/view_mode", &json!({ "mode": mode })).await;
        assert_eq!(resp.status, 200, "mode '{}' failed: {}", mode, resp.text());
        let g = resp.json();
        assert_slim_ui_payload_invariants(&g, &format!("POST /api/view_mode {}", mode));
        let nodes = g["nodes"].as_array().unwrap();
        if mode == "vault" {
            assert!(
                nodes.iter().any(|n| n["file_path"]
                    .as_str()
                    .unwrap_or("")
                    .contains("Architecture.md")),
                "vault view must contain Architecture.md note"
            );
        } else {
            assert!(
                nodes.iter().any(|n| n["file_path"] == "src/api.py"),
                "{} view must contain src/api.py",
                mode
            );
        }
    }
}

#[tokio::test]
async fn t1_f9_view_mode_rejects_invalid_and_unavailable_modes() {
    let pure_code_dir = tempdir().unwrap();
    write_file_rel(pure_code_dir.path(), "src/lib.rs", "pub fn ok() {}\n");
    let code_guard = spawn_no_gui_server(pure_code_dir.path(), &[]).await;

    let bad = http_post_json(
        code_guard.port,
        "/api/view_mode",
        &json!({ "mode": "unknown_mode" }),
    )
    .await;
    assert_eq!(bad.status, 400);
    assert_eq!(bad.json()["status"], "error");

    let unavail_vault = http_post_json(
        code_guard.port,
        "/api/view_mode",
        &json!({ "mode": "vault" }),
    )
    .await;
    assert_eq!(unavail_vault.status, 422);
    assert_eq!(unavail_vault.json()["status"], "error");
    drop(code_guard);

    let pure_vault_dir = tempdir().unwrap();
    create_pure_obsidian_vault_fixture(pure_vault_dir.path());
    let vault_guard = spawn_no_gui_server(pure_vault_dir.path(), &[]).await;

    let unavail_code = http_post_json(
        vault_guard.port,
        "/api/view_mode",
        &json!({ "mode": "code" }),
    )
    .await;
    assert_eq!(unavail_code.status, 422);
    assert_eq!(unavail_code.json()["status"], "error");
}

// ============================================================================
// TIER 2 — Boundary & Edge Case Tests (12 Tests)
// ============================================================================

#[tokio::test]
async fn t2_f8_local_guard_rejects_missing_wrong_host_and_cross_origin() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "src/lib.rs", "pub fn x() {}\n");
    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let p = guard.port;

    let cases: Vec<(&str, String)> = vec![
        (
            "missing Host",
            "GET /api/graph HTTP/1.1\r\nConnection: close\r\n\r\n".to_string(),
        ),
        (
            "wrong port Host",
            "GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n".to_string(),
        ),
        (
            "non-loopback Host",
            format!(
                "GET /api/graph HTTP/1.1\r\nHost: evil.example.com:{}\r\nConnection: close\r\n\r\n",
                p
            ),
        ),
        (
            "foreign Origin",
            format!(
                "GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: https://evil.example.com\r\nConnection: close\r\n\r\n",
                p
            ),
        ),
        (
            "Sec-Fetch-Site cross-site",
            format!(
                "GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nSec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n",
                p
            ),
        ),
        (
            "Sec-Fetch-Site same-site",
            format!(
                "GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nSec-Fetch-Site: same-site\r\nConnection: close\r\n\r\n",
                p
            ),
        ),
    ];

    for (label, raw_req) in cases {
        let resp = send_raw_http_request(p, raw_req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("case '{}' failed: {}", label, e));
        assert_eq!(resp.status, 403, "expected 403 for {}", label);
        assert!(
            resp.headers
                .get("content-type")
                .map(|ct| ct.to_ascii_lowercase().contains("text/plain"))
                .unwrap_or(false),
            "expected text/plain Content-Type for LocalGuard 403 ({})",
            label
        );
        assert!(
            resp.text().contains("origine non locale"),
            "expected LocalGuard message for {}, got: {}",
            label,
            resp.text()
        );
    }
}

#[tokio::test]
async fn t2_f8_graph_empty_directory_produces_valid_slim_and_full_responses() {
    let dir = tempdir().unwrap();
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let slim = http_get(guard.port, "/api/graph").await;
    assert_eq!(slim.status, 200);
    let sj = slim.json();
    assert_slim_ui_payload_invariants(&sj, "empty dir slim");
    assert_eq!(sj["nodes"].as_array().unwrap().len(), 0);
    assert_eq!(sj["stats"]["total_nodes"], 0);

    let full = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(full.status, 200);
    let fj = full.json();
    assert_eq!(fj["nodes"].as_array().unwrap().len(), 0);
    assert_eq!(fj["edges"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn t2_f8_graph_compact_edges_above_threshold_and_docstring_truncation() {
    let dir = tempdir().unwrap();
    write_file_rel(
        dir.path(),
        "AETHER_AI_RULES.md",
        "# Large Graph Rules\nKeep payloads compact.\n",
    );
    let long_doc = "A".repeat(320);
    for file_idx in 0..11 {
        let mut src = String::new();
        if file_idx == 0 {
            src.push_str(&format!("/// {}\npub fn documented_long_fn() -> i32 {{ 42 }}\n", long_doc));
        }
        for fn_idx in 0..300 {
            src.push_str(&format!(
                "pub fn fn_{}_{}() -> i32 {{ {} }}\n",
                file_idx, fn_idx, fn_idx
            ));
        }
        write_file_rel(dir.path(), &format!("src/mod_{:02}.rs", file_idx), &src);
    }

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let slim_resp = http_get(guard.port, "/api/graph").await;
    assert_eq!(slim_resp.status, 200);
    let sj = slim_resp.json();
    assert_slim_ui_payload_invariants(&sj, "large >3000 nodes slim");

    let compact = sj
        .get("edges_compact")
        .and_then(|v| v.as_object())
        .expect("edges_compact must be present when nodes > 3,000");
    assert!(compact.get("src").and_then(|v| v.as_array()).is_some());
    assert!(compact.get("dst").and_then(|v| v.as_array()).is_some());
    assert!(compact.get("rels").and_then(|v| v.as_array()).is_some());
    assert!(compact.get("types").and_then(|v| v.as_array()).is_some());
    assert_eq!(
        sj["edges"].as_array().unwrap().len(),
        0,
        "edges array must be empty when edges_compact is active"
    );

    let slim_doc_node = sj["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "documented_long_fn")
        .expect("documented_long_fn in slim");
    let slim_doc_str = slim_doc_node["docstring"].as_str().unwrap();
    assert!(
        slim_doc_str.len() <= 243 && slim_doc_str.ends_with('…'),
        "expected truncated docstring <= 243 bytes ending with '…', got {} bytes",
        slim_doc_str.len()
    );
    if let Some(h) = slim_doc_node["metadata"]["file_blake3_hash"].as_str() {
        assert!(h.len() <= 16, "expected <= 16-char hash truncation, got {}", h.len());
    }

    let full_resp = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(full_resp.status, 200);
    let fj = full_resp.json();
    assert!(fj.get("edges_compact").is_none());
    assert!(!fj["edges"].as_array().unwrap().is_empty());
    let full_doc_node = fj["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "documented_long_fn")
        .expect("documented_long_fn in full");
    assert!(
        full_doc_node["docstring"].as_str().unwrap().len() >= 320,
        "?full=1 must preserve full docstring"
    );
    if let Some(h) = full_doc_node["metadata"]["file_blake3_hash"].as_str() {
        assert_eq!(h.len(), 64, "?full=1 must retain 64-char BLAKE3 hash");
    }
    assert!(
        slim_resp.body.len() < full_resp.body.len(),
        "compact /api/graph ({} B) must be strictly smaller than ?full=1 ({} B)",
        slim_resp.body.len(),
        full_resp.body.len()
    );
}

#[tokio::test]
async fn t2_f8_graph_preserves_violations_without_cve_anomalies_like_cross_galaxy() {
    let dir = tempdir().unwrap();
    write_file_rel(
        dir.path(),
        "client/ui.ts",
        "import { fetchSecret } from '../server/secret_db';\nexport function renderUi() { return fetchSecret(); }\n",
    );
    write_file_rel(
        dir.path(),
        "server/secret_db.ts",
        "export function fetchSecret() { return 'ok'; }\n",
    );
    write_file_rel(
        dir.path(),
        "server/vuln.py",
        "import os\ndef run_unsafe(x):\n    os.system(x)\n",
    );

    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let resp = http_get(guard.port, "/api/graph").await;
    assert_eq!(resp.status, 200);
    let g = resp.json();
    assert_slim_ui_payload_invariants(&g, "cross_galaxy non-duplicate preservation");

    let ui_node = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "file::client/ui.ts")
        .expect("file::client/ui.ts node");
    let ui_viols = ui_node["metadata"]["violations"]
        .as_array()
        .expect("violations array");
    assert!(
        ui_viols
            .iter()
            .any(|v| v.as_str().unwrap_or("").contains("CROSS_GALAXY_VIOLATION")),
        "slimmed payload must preserve non-duplicate CROSS_GALAXY_VIOLATION when cve_anomalies is empty"
    );
}

#[tokio::test]
async fn t2_f8_graph_query_full_variant_values_and_version_caching() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", "# Rules\nCheck auth.\n");
    write_file_rel(dir.path(), "src/lib.rs", "pub fn alpha() -> i32 { 7 }\n");
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let full_1 = http_get(guard.port, "/api/graph?full=1").await;
    let full_true = http_get(guard.port, "/api/graph?full=true").await;
    assert_eq!(full_1.status, 200);
    assert_eq!(full_true.status, 200);
    assert!(full_1.json()["system_prompt"].is_string());
    assert!(full_true.json()["system_prompt"].is_string());
    assert!(full_true.json()["edges"].is_array());

    let ui_a = http_get(guard.port, "/api/graph").await;
    let ui_b = http_get(guard.port, "/api/graph").await;
    assert_eq!(ui_a.status, 200);
    assert_eq!(ui_b.status, 200);
    assert_eq!(
        ui_a.body, ui_b.body,
        "consecutive GET /api/graph at identical version must be byte-identical"
    );

    let full_zero = http_get(guard.port, "/api/graph?full=0").await;
    assert_eq!(full_zero.status, 200);
    assert_slim_ui_payload_invariants(&full_zero.json(), "GET /api/graph?full=0");
}

#[tokio::test]
async fn t2_f8_viewer_export_and_index_retain_full_graph_and_system_prompt() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", "# Viewer Rules\nFull graph.\n");
    write_file_rel(dir.path(), "README.md", "# Viewer Doc\nExported standalone.\n");
    write_file_rel(dir.path(), "src/main.rs", "fn main() {}\n");

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let index_resp = http_get(guard.port, "/").await;
    assert_eq!(index_resp.status, 200);
    assert!(
        index_resp
            .headers
            .get("content-type")
            .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false),
        "GET / must return text/html Content-Type"
    );
    let html = index_resp.text();
    assert!(
        html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"),
        "GET / must embed __AETHERSCOPE_DUAL_GRAPH__"
    );
    assert!(
        html.contains("system_prompt"),
        "GET / standalone viewer must retain system_prompt"
    );

    let export_resp = http_post_json(guard.port, "/api/export", &json!({})).await;
    assert_eq!(export_resp.status, 200);
    let ej = export_resp.json();
    assert_eq!(ej["status"], "ok");
    let viewer_path = ej["viewer_path"].as_str().expect("viewer_path");
    let exported_html = fs::read_to_string(viewer_path).expect("read exported HTML");
    assert!(exported_html.contains("window.__AETHERSCOPE_DATA__"));
    assert!(exported_html.contains("system_prompt"));
}

#[tokio::test]
async fn t2_f9_file_content_blocks_traversal_absolute_nullbyte_and_secrets() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "src/lib.rs", "pub fn safe() {}\n");
    write_file_rel(dir.path(), ".env", "SECRET=123\n");
    write_file_rel(dir.path(), "id_rsa", "PRIVATE\n");
    write_file_rel(dir.path(), "server.key", "KEY\n");

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    for bad_path in [
        "%2e%2e%2foutside.txt",
        "../../Cargo.toml",
        "/etc/passwd",
        "src/lib.rs%00.txt",
    ] {
        let r = http_get(guard.port, &format!("/api/file_content?path={}", bad_path)).await;
        assert_eq!(r.status, 400, "expected 400 for '{}', got {}", bad_path, r.status);
        assert_eq!(r.json()["status"], "error");
    }

    for secret_path in [".env&raw=true", "id_rsa", "server.key"] {
        let r = http_get(guard.port, &format!("/api/file_content?path={}", secret_path)).await;
        assert_eq!(
            r.status, 403,
            "expected 403 for secret '{}', got {}",
            secret_path, r.status
        );
        assert_eq!(r.json()["status"], "error");
    }
}

#[tokio::test]
async fn t2_f9_file_content_handles_empty_missing_and_unicode_files() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "src/empty.rs", "");
    write_file_rel(dir.path(), "src/unicode_café.rs", "// Héllo 世界\npub fn cafe() {}\n");

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let empty_r = http_get(guard.port, "/api/file_content?path=src/empty.rs").await;
    assert_eq!(empty_r.status, 200);
    assert_eq!(empty_r.json()["content"], "");

    let missing_r = http_get(guard.port, "/api/file_content?path=src/does_not_exist.rs").await;
    assert_eq!(missing_r.status, 404);
    assert_eq!(missing_r.json()["error"], "not_found");

    let uni_r = http_get(guard.port, "/api/file_content?path=src/unicode_caf%C3%A9.rs").await;
    assert_eq!(uni_r.status, 200);
    assert!(
        uni_r.json()["content"]
            .as_str()
            .unwrap_or("")
            .contains("Héllo 世界")
    );
}

#[tokio::test]
async fn t2_f9_file_content_rejects_oversized_file_over_10mb() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "src/lib.rs", "pub fn small() {}\n");
    let huge_path = dir.path().join("src/huge.txt");
    let huge_bytes = vec![b'A'; 10 * 1024 * 1024 + 1024];
    fs::write(&huge_path, huge_bytes).unwrap();

    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let r = http_get(guard.port, "/api/file_content?path=src/huge.txt").await;
    assert_eq!(r.status, 413);
    assert_eq!(r.json()["error"], "payload_too_large");
}

#[tokio::test]
async fn t2_f9_view_mode_aliases_and_case_whitespace_normalization() {
    let dir = tempdir().unwrap();
    create_mixed_code_vault_fixture(dir.path());
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let r_notes = http_post_json(
        guard.port,
        "/api/view_mode",
        &json!({ "mode": "  NOTES  " }),
    )
    .await;
    assert_eq!(r_notes.status, 200);
    assert_slim_ui_payload_invariants(&r_notes.json(), "view_mode NOTES");

    let status_vault = http_get(guard.port, "/api/project/status").await.json();
    assert_eq!(status_vault["active_view_mode"], "vault-notes");

    let r_editor = http_post_json(
        guard.port,
        "/api/view_mode",
        &json!({ "mode": "  EDITOR  " }),
    )
    .await;
    assert_eq!(r_editor.status, 200);
    assert_slim_ui_payload_invariants(&r_editor.json(), "view_mode EDITOR");

    let status_ide = http_get(guard.port, "/api/project/status").await.json();
    assert_eq!(status_ide["active_view_mode"], "ide");
}

#[tokio::test]
async fn t2_f9_analyze_empty_or_dot_path_uses_active_root_with_exclusions() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", "# Rules\n");
    write_file_rel(dir.path(), "src/keep.rs", "pub fn keep_me() -> i32 { 1 }\n");
    write_file_rel(
        dir.path(),
        "ignored_mod/skip.rs",
        "pub fn skip_me() -> i32 { 2 }\n",
    );

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let resp = http_post_json(
        guard.port,
        "/api/analyze",
        &json!({ "path": ".", "exclusions": ["ignored_mod"] }),
    )
    .await;
    assert_eq!(resp.status, 200);
    let g = resp.json();
    assert_slim_ui_payload_invariants(&g, "POST /api/analyze exclusions");
    let nodes = g["nodes"].as_array().unwrap();
    assert!(
        nodes.iter().any(|n| n["file_path"] == "src/keep.rs"),
        "kept module must appear"
    );
    assert!(
        !nodes
            .iter()
            .any(|n| n["file_path"].as_str().unwrap_or("").contains("skip.rs")),
        "excluded module must not appear"
    );
}

#[tokio::test]
async fn t2_f9_file_content_missing_or_empty_path_query_returns_400() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "src/lib.rs", "pub fn x() {}\n");
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let r1 = http_get(guard.port, "/api/file_content").await;
    assert_eq!(r1.status, 400);
    assert_eq!(r1.json()["status"], "error");

    let r2 = http_get(guard.port, "/api/file_content?path=").await;
    assert_eq!(r2.status, 400);
    assert_eq!(r2.json()["status"], "error");
}

// ============================================================================
// TIER 3 — Pairwise Cross-Feature Tests (5 Tests)
// ============================================================================

#[tokio::test]
async fn t3_cross_plugins_cli_flag_with_slim_graph_and_full_parity() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", "# Plugin Rules\n");
    write_file_rel(
        dir.path(),
        ".aether/plugins/custom-r3/plugin.yaml",
        r#"name: custom-r3
version: "1.0.0"
enabled: true
rules:
  - id: CUSTOM-R3-001
    cwe_id: CWE-798
    name: Custom R3 Forbidden Marker
    severity: HIGH
    description: Detects custom R3 marker token
    remediation: Remove forbidden marker
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      must_contain: ["FORBIDDEN_R3_MARKER"]
      check_literals: true
"#,
    );
    write_file_rel(
        dir.path(),
        "src/plugin_target.py",
        "def trigger():\n    return \"FORBIDDEN_R3_MARKER\"\n",
    );

    let guard = spawn_no_gui_server(dir.path(), &["--plugins", "custom-r3"]).await;
    let slim = http_get(guard.port, "/api/graph").await;
    let full = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(slim.status, 200);
    assert_eq!(full.status, 200);

    let sj = slim.json();
    let fj = full.json();
    assert_slim_ui_payload_invariants(&sj, "t3 --plugins slim");
    assert!(fj["system_prompt"].is_string());
    assert!(slim.body.len() < full.body.len());

    let has_custom_rule = sj["nodes"].as_array().unwrap().iter().any(|n| {
        n["metadata"]["cve_anomalies"]
            .as_array()
            .map(|a| a.iter().any(|r| r["rule_id"] == "CUSTOM-R3-001"))
            .unwrap_or(false)
    });
    assert!(
        has_custom_rule,
        "selected --plugins custom-r3 must report CUSTOM-R3-001 in slimmed /api/graph"
    );
}

#[tokio::test]
async fn t3_cross_slim_graph_then_on_demand_drilldown_and_full_parity() {
    let dir = tempdir().unwrap();
    let secret = "sk-abcdef1234567890abcdef1234567890";
    let auth_py = format!(
        "import os\nAPI_KEY = \"{}\"\ndef login(cmd):\n    os.system(cmd)\n",
        secret
    );
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", "# Drilldown Rules\n");
    write_file_rel(dir.path(), "README.md", "# Auth Docs\nInspect `login`.\n");
    write_file_rel(dir.path(), "src/auth.py", &auth_py);

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let slim_j = http_get(guard.port, "/api/graph").await.json();
    assert_slim_ui_payload_invariants(&slim_j, "t3 drilldown slim");

    let flagged = slim_j["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["has_security_violation"] == true)
        .expect("flagged node in slim graph");
    let flagged_path = flagged["file_path"].as_str().unwrap().to_string();

    let masked_file = http_get(
        guard.port,
        &format!("/api/file_content?path={}", flagged_path),
    )
    .await
    .json();
    assert!(masked_file["content"].as_str().unwrap().contains("[REDACTED]"));

    let raw_file = http_get(
        guard.port,
        &format!("/api/file_content?path={}&raw=true", flagged_path),
    )
    .await
    .json();
    assert_eq!(raw_file["content"], auth_py);

    let prompt = http_get(guard.port, "/api/ai/system_prompt").await.json();
    assert!(
        prompt["system_prompt"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    );

    let full_j = http_get(guard.port, "/api/graph?full=1").await.json();
    assert_eq!(
        slim_j["nodes"].as_array().unwrap().len(),
        full_j["nodes"].as_array().unwrap().len()
    );
    assert!(full_j["system_prompt"].is_string());
}

#[tokio::test]
async fn t3_cross_save_file_then_analyze_cache_update_and_version_bump() {
    let dir = tempdir().unwrap();
    write_file_rel(dir.path(), "AETHER_AI_RULES.md", "# Save+Analyze Rules\n");
    write_file_rel(dir.path(), "src/app.py", "def index():\n    return 'ok'\n");

    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let v1 = http_get(guard.port, "/api/graph/version").await.json()["version"]
        .as_u64()
        .unwrap();

    let new_code = "import os\ndef danger(q):\n    os.system(q)\n";
    let save_resp = http_post_json(
        guard.port,
        "/api/save_file",
        &json!({ "file_path": "src/new_endpoint.py", "content": new_code }),
    )
    .await;
    assert_eq!(save_resp.status, 200);

    let analyze_resp = http_post_json(guard.port, "/api/analyze", &json!({ "path": "." })).await;
    assert_eq!(analyze_resp.status, 200);
    let aj = analyze_resp.json();
    assert_slim_ui_payload_invariants(&aj, "t3 save+analyze");
    assert!(
        aj["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["file_path"] == "src/new_endpoint.py"),
        "re-scan must include newly saved src/new_endpoint.py"
    );

    let v2 = http_get(guard.port, "/api/graph/version").await.json()["version"]
        .as_u64()
        .unwrap();
    assert!(v2 > v1, "expected graph_version bump {} -> {}", v1, v2);

    let slim = http_get(guard.port, "/api/graph").await.json();
    assert_slim_ui_payload_invariants(&slim, "t3 post-analyze /api/graph");

    let fetched = http_get(guard.port, "/api/file_content?path=src/new_endpoint.py")
        .await
        .json();
    assert_eq!(fetched["content"], new_code);
    assert!(
        dir.path().join(".aether").join("cache").exists(),
        "incremental BLAKE3 cache directory .aether/cache must be populated"
    );
}

#[tokio::test]
async fn t3_cross_view_mode_and_export_full_html_consistency() {
    let dir = tempdir().unwrap();
    create_mixed_code_vault_fixture(dir.path());
    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let vm = http_post_json(guard.port, "/api/view_mode", &json!({ "mode": "vault" })).await;
    assert_eq!(vm.status, 200);
    assert_slim_ui_payload_invariants(&vm.json(), "t3 view_mode vault");

    let slim = http_get(guard.port, "/api/graph").await;
    assert_eq!(slim.status, 200);
    assert_slim_ui_payload_invariants(&slim.json(), "t3 /api/graph after vault");

    let full = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(full.status, 200);
    assert!(full.json()["system_prompt"].is_string());

    let exp = http_post_json(guard.port, "/api/export", &json!({})).await;
    assert_eq!(exp.status, 200);
    let viewer_path = exp.json()["viewer_path"].as_str().unwrap().to_string();
    let html = fs::read_to_string(&viewer_path).unwrap();
    assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
    assert!(html.contains("\"code\":"));
    assert!(html.contains("\"vault\":"));
    assert!(html.contains("system_prompt"));
}

#[tokio::test]
async fn t3_cross_concurrent_graph_file_content_and_view_mode_readers() {
    let dir = tempdir().unwrap();
    create_mixed_code_vault_fixture(dir.path());
    for i in 0..8 {
        write_file_rel(
            dir.path(),
            &format!("src/worker_{}.py", i),
            &format!("def work_{}(x):\n    return x + {}\n", i, i),
        );
    }
    let guard = spawn_no_gui_server(dir.path(), &[]).await;
    let port = guard.port;

    let mut handles = Vec::new();
    for idx in 0..12 {
        handles.push(tokio::spawn(async move {
            match idx % 5 {
                0 => {
                    let r = http_get(port, "/api/graph").await;
                    assert_eq!(r.status, 200);
                    assert_slim_ui_payload_invariants(&r.json(), "concurrent slim");
                }
                1 => {
                    let r = http_get(port, "/api/graph?full=1").await;
                    assert_eq!(r.status, 200);
                    assert!(r.json()["system_prompt"].is_string());
                }
                2 => {
                    let r = http_get(port, "/api/file_content?path=src/api.py").await;
                    assert_eq!(r.status, 200);
                    assert_eq!(r.json()["status"], "ok");
                }
                3 => {
                    let r = http_get(port, "/api/ai/system_prompt").await;
                    assert_eq!(r.status, 200);
                    assert_eq!(r.json()["status"], "ok");
                }
                _ => {
                    let mode = if idx % 2 == 0 { "vault" } else { "code" };
                    let r = http_post_json(port, "/api/view_mode", &json!({ "mode": mode })).await;
                    assert_eq!(r.status, 200);
                    assert_slim_ui_payload_invariants(&r.json(), "concurrent view_mode");
                }
            }
        }));
    }
    for h in handles {
        h.await.expect("concurrent reader task panicked");
    }
}

// ============================================================================
// TIER 4 — Real-World Application Scenarios (S5 & S6)
// ============================================================================

#[tokio::test]
async fn t4_s5_large_multifile_codebase_slim_graph_drilldown_and_mcp_full() {
    let dir = tempdir().unwrap();
    write_file_rel(
        dir.path(),
        "AETHER_AI_RULES.md",
        &format!(
            "# Enterprise Platform Rules\n{}\n",
            "Enforce zero-trust boundary validation.\n".repeat(40)
        ),
    );
    write_file_rel(
        dir.path(),
        "README.md",
        &format!(
            "# Enterprise Platform Architecture\nSee [order_ctrl](controllers/order_controller.py).\n{}\n",
            "Service topology contract details.\n".repeat(120)
        ),
    );

    for i in 0..15 {
        write_file_rel(
            dir.path(),
            &format!("services/svc_{}.py", i),
            &format!(
                "def process_{}(payload):\n    return payload\ndef validate_{}(x):\n    return bool(x)\n",
                i, i
            ),
        );
        write_file_rel(
            dir.path(),
            &format!("models/model_{}.py", i),
            &format!("class Entity_{}:\n    def save(self):\n        return True\n", i),
        );
    }
    for i in 0..10 {
        write_file_rel(
            dir.path(),
            &format!("controllers/ctrl_{}.ts", i),
            &format!(
                "export async function submit_{}(req: any) {{\n    return fetch('/api/v1/items/{}');\n}}\n",
                i, i
            ),
        );
    }
    write_file_rel(
        dir.path(),
        "controllers/order_controller.py",
        r#"import os
def handle_order(req):
    cmd = req.get("cmd")
    os.system(cmd)
    return "dispatched"
"#,
    );
    write_file_rel(
        dir.path(),
        "server/legacy_php.php",
        r#"<?php
function fetch_invoice() {
    $id = $_GET['id'];
    mysqli_query($conn, "SELECT * FROM invoices WHERE id=" . $id);
}
"#,
    );
    write_file_rel(
        dir.path(),
        "client/portal.ts",
        "import { fetch_invoice } from '../server/legacy_php';\nexport function openPortal() { return fetch('/api/invoices'); }\n",
    );

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let slim_resp = http_get(guard.port, "/api/graph").await;
    let full_resp = http_get(guard.port, "/api/graph?full=1").await;
    assert_eq!(slim_resp.status, 200);
    assert_eq!(full_resp.status, 200);

    let sj = slim_resp.json();
    let fj = full_resp.json();
    assert_slim_ui_payload_invariants(&sj, "S5 slim graph");
    assert!(
        slim_resp.body.len() < full_resp.body.len(),
        "S5 slim payload ({} B) must be strictly smaller than MCP ?full=1 ({} B)",
        slim_resp.body.len(),
        full_resp.body.len()
    );
    assert_eq!(
        sj["nodes"].as_array().unwrap().len(),
        fj["nodes"].as_array().unwrap().len()
    );
    assert_eq!(
        edge_count_from_graph_json(&sj),
        edge_count_from_graph_json(&fj),
        "S5 slimmed graph must preserve identical edge count vs ?full=1"
    );

    // On-demand drill-down of vulnerable file + README + system_prompt
    let vuln_doc = http_get(
        guard.port,
        "/api/file_content?path=controllers/order_controller.py",
    )
    .await;
    assert_eq!(vuln_doc.status, 200);
    assert!(vuln_doc.json()["content"]
        .as_str()
        .unwrap()
        .contains("os.system(cmd)"));

    let readme_doc = http_get(guard.port, "/api/file_content?path=README.md").await;
    assert_eq!(readme_doc.status, 200);
    assert!(readme_doc.json()["content"]
        .as_str()
        .unwrap()
        .contains("Enterprise Platform Architecture"));

    let sys_prompt = http_get(guard.port, "/api/ai/system_prompt").await;
    assert_eq!(sys_prompt.status, 200);
    assert!(sys_prompt.json()["system_prompt"]
        .as_str()
        .unwrap()
        .contains("Enterprise Platform Rules"));

    // MCP ?full=1 retains heavy fields
    assert!(fj["system_prompt"].is_string());
    let full_readme = fj["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["file_path"] == "README.md" && n["is_file"] == true)
        .expect("README.md in ?full=1");
    assert!(full_readme["metadata"]["raw_content"].is_string());
}

#[tokio::test]
async fn t4_s6_mixed_code_obsidian_vault_live_switching_and_rescan_slimming() {
    let dir = tempdir().unwrap();
    create_mixed_code_vault_fixture(dir.path());

    let guard = spawn_no_gui_server(dir.path(), &[]).await;

    let status = http_get(guard.port, "/api/project/status").await;
    assert_eq!(status.status, 200);
    let st_json = status.json();
    assert_eq!(st_json["project_type"], "Mixed");

    let initial_slim = http_get(guard.port, "/api/graph").await;
    assert_eq!(initial_slim.status, 200);
    assert_slim_ui_payload_invariants(&initial_slim.json(), "S6 initial slim");

    let vault_switch = http_post_json(guard.port, "/api/view_mode", &json!({ "mode": "vault" })).await;
    assert_eq!(vault_switch.status, 200);
    let vj = vault_switch.json();
    assert_slim_ui_payload_invariants(&vj, "S6 vault switch");
    assert!(vj["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["file_path"].as_str().unwrap_or("").contains("Runbook.md")));

    let ide_switch = http_post_json(guard.port, "/api/view_mode", &json!({ "mode": "ide" })).await;
    assert_eq!(ide_switch.status, 200);
    assert_slim_ui_payload_invariants(&ide_switch.json(), "S6 ide switch");

    let doc_fetch = http_get(guard.port, "/api/file_content?path=docs/Architecture.md").await;
    assert_eq!(doc_fetch.status, 200);
    assert!(doc_fetch.json()["content"]
        .as_str()
        .unwrap()
        .contains("[[Runbook]]"));

    let code_fetch = http_get(guard.port, "/api/file_content?path=src/api.py").await;
    assert_eq!(code_fetch.status, 200);
    assert!(code_fetch.json()["content"]
        .as_str()
        .unwrap()
        .contains("os.system"));

    let v1 = http_get(guard.port, "/api/graph/version").await.json()["version"]
        .as_u64()
        .unwrap();

    write_file_rel(
        dir.path(),
        "src/billing.py",
        "def charge_card(amount):\n    return amount * 100\n",
    );
    let rescan = http_post_json(guard.port, "/api/analyze", &json!({ "path": "." })).await;
    assert_eq!(rescan.status, 200);
    let rj = rescan.json();
    assert_slim_ui_payload_invariants(&rj, "S6 post-add /api/analyze");
    assert!(rj["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["file_path"] == "src/billing.py"));

    let v2 = http_get(guard.port, "/api/graph/version").await.json()["version"]
        .as_u64()
        .unwrap();
    assert!(v2 > v1, "rescan must bump graph_version");

    let post_slim = http_get(guard.port, "/api/graph").await;
    let post_full = http_get(guard.port, "/api/graph?full=1").await;
    assert_slim_ui_payload_invariants(&post_slim.json(), "S6 post-rescan /api/graph");
    assert!(post_slim.body.len() < post_full.body.len());
    assert!(post_full.json()["system_prompt"].is_string());
}
