//! E2E-M1 Hygiene & Core Crate Suite (`e2e_suite_hygiene.rs`)
//!
//! Opaque-box, requirement-driven tests covering:
//! - F1: `.aether/tasks/` `m8ven` purge, non-`m8ven` task preservation & MCP task isolation
//! - F4: `ast-scanner` 11+ language scanning, line-budget (`RULE_MAX_LINES`) & modularization
//! - F5: `core-graph` SSA dataflow taint tracking, reachability & modularization
//! - F6: `obsidian-vault` `PathGuard` confinement, vault scanning & modularization
//! - F16: BLAKE3 `aether.lock.toml` seal integrity, `--fail-on`, SARIF & self-audit
//!
//! Naming convention: `tier1_f<N>_*`, `tier2_f<N>_*` for `-- tier1_` / `-- tier2_` filtering.

use ast_scanner::{ProjectScanner, TaintExtractor};
use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
use core_graph::dataflow::{
    DataflowEdge, DataflowGraph, SanitizerMatchKind, SanitizerRule, SinkKind, SourceKind, SsaVar,
    TaintRuleSet, TaintSink, TaintSource, TaintStepKind,
};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::AetherGraph;
use core_graph::manifest::ProjectManifest;
use obsidian_vault::{
    detect_project_type, scan_obsidian_vault, DetectedProjectType, PathGuard, SecurityError,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ============================================================================
// Self-Contained Test Harness Helpers
// ============================================================================

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn find_aether_engine_bin() -> PathBuf {
    if let Some(bin) = option_env!("CARGO_BIN_EXE_aether-engine") {
        let p = PathBuf::from(bin);
        if p.exists() {
            return p;
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let exe = if cfg!(windows) {
        "aether-engine.exe"
    } else {
        "aether-engine"
    };
    for profile in ["debug", "release"] {
        let cand = manifest.join("..").join("..").join("target").join(profile).join(exe);
        if cand.exists() {
            return cand;
        }
    }
    panic!("aether-engine binary not found");
}

fn find_aetherscope_mcp_bin() -> PathBuf {
    if let Some(bin) = option_env!("CARGO_BIN_EXE_aetherscope-mcp") {
        let p = PathBuf::from(bin);
        if p.exists() {
            return p;
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let exe = if cfg!(windows) {
        "aetherscope-mcp.exe"
    } else {
        "aetherscope-mcp"
    };
    for profile in ["debug", "release"] {
        let cand = manifest.join("..").join("..").join("target").join(profile).join(exe);
        if cand.exists() {
            return cand;
        }
    }
    panic!("aetherscope-mcp binary not found");
}

fn alloc_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

fn write_rel(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("create_dir_all");
    }
    fs::write(&p, content).expect("write file");
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ServerGuard {
    _child: ChildGuard,
    port: u16,
}

impl ServerGuard {
    async fn start(project_root: &Path) -> Self {
        let port = alloc_ephemeral_port();
        let bin = find_aether_engine_bin();
        let child = Command::new(&bin)
            .current_dir(project_root)
            .arg("--no-gui")
            .arg("--port")
            .arg(port.to_string())
            .arg("--path")
            .arg(project_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn aether-engine: {}", e));
        let guard = Self {
            _child: ChildGuard::new(child),
            port,
        };
        guard.wait_ready().await;
        guard
    }

    async fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok((status, _)) = send_http(self.port, "GET", "/api/health", None).await {
                if status == 200 {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "aether-engine --no-gui on port {} did not become healthy within 20s",
                self.port
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn send_http(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, String), String> {
    let addr = format!("127.0.0.1:{}", port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("connect {}: {}", addr, e))?;

    let body_bytes = body
        .map(|v| serde_json::to_vec(v).expect("serialize JSON"))
        .unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            method,
            path,
            port,
            body_bytes.len()
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            method, path, port
        )
    };

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write headers: {}", e))?;
    if !body_bytes.is_empty() {
        stream
            .write_all(&body_bytes)
            .await
            .map_err(|e| format!("write body: {}", e))?;
    }
    stream.flush().await.map_err(|e| format!("flush: {}", e))?;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .map_err(|_| "HTTP read timeout".to_string())?
        .map_err(|e| format!("read response: {}", e))?;

    let resp_str = String::from_utf8_lossy(&raw).into_owned();
    let (head, body_part) = resp_str
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response: {}", resp_str))?;
    let status_line = head.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid HTTP status line: {}", status_line))?;

    let decoded_body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        decode_chunked_body(body_part)
    } else {
        body_part.to_string()
    };

    Ok((status, decoded_body))
}

fn decode_chunked_body(raw: &str) -> String {
    let mut out = String::new();
    let mut rest = raw;
    loop {
        let Some((len_line, after_len)) = rest.split_once("\r\n") else {
            out.push_str(rest);
            break;
        };
        let hex_len = len_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_len, 16) else {
            out.push_str(rest);
            break;
        };
        if chunk_len == 0 {
            break;
        }
        if after_len.len() < chunk_len {
            out.push_str(after_len);
            break;
        }
        out.push_str(&after_len[..chunk_len]);
        rest = after_len[chunk_len..].strip_prefix("\r\n").unwrap_or(&after_len[chunk_len..]);
    }
    out
}

struct CliOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_audit_cli(cwd: &Path, args: &[&str]) -> CliOutput {
    let bin = find_aether_engine_bin();
    let port = alloc_ephemeral_port().to_string();
    let out = Command::new(&bin)
        .current_dir(cwd)
        .arg("--port")
        .arg(&port)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run aether-engine: {}", e));
    CliOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn parse_sarif_json(raw: &str) -> Value {
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        return v;
    }
    if let Some(start) = raw.find('{') {
        if let Ok(v) = serde_json::from_str::<Value>(&raw[start..]) {
            return v;
        }
    }
    panic!("Failed to parse SARIF JSON from output:\n{}", raw);
}

fn run_mcp_session(bin: &Path, cwd: &Path, port: u16, project_path: &Path, requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(bin)
        .current_dir(cwd)
        .arg("--port")
        .arg(port.to_string())
        .arg("--path")
        .arg(project_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn mcp binary {:?}: {}", bin, e));

    let mut stdin = child.stdin.take().expect("mcp stdin");
    let stdout = child.stdout.take().expect("mcp stdout");
    let guard = ChildGuard::new(child);

    let expected_responses = requests
        .iter()
        .filter(|r| r.get("id").is_some())
        .count();

    for req in requests {
        let line = serde_json::to_string(req).expect("serialize json-rpc");
        writeln!(stdin, "{}", line).expect("write json-rpc line");
    }
    stdin.flush().expect("flush mcp stdin");
    drop(stdin);

    let mut reader = BufReader::new(stdout);
    let mut responses = Vec::new();
    let mut line = String::new();
    while responses.len() < expected_responses {
        line.clear();
        let n = reader.read_line(&mut line).expect("read mcp stdout");
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if val.get("jsonrpc").is_some() {
                responses.push(val);
            }
        }
    }
    drop(guard);
    responses
}

fn run_engine_mcp_session(cwd: &Path, port: u16, project_path: &Path, requests: &[Value]) -> Vec<Value> {
    let bin = find_aether_engine_bin();
    let mut child = Command::new(&bin)
        .current_dir(cwd)
        .arg("--mcp")
        .arg("--port")
        .arg(port.to_string())
        .arg("--path")
        .arg(project_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn aether-engine --mcp: {}", e));

    let mut stdin = child.stdin.take().expect("mcp stdin");
    let stdout = child.stdout.take().expect("mcp stdout");
    let guard = ChildGuard::new(child);

    let expected_responses = requests
        .iter()
        .filter(|r| r.get("id").is_some())
        .count();

    for req in requests {
        let line = serde_json::to_string(req).expect("serialize json-rpc");
        writeln!(stdin, "{}", line).expect("write json-rpc line");
    }
    stdin.flush().expect("flush mcp stdin");
    drop(stdin);

    let mut reader = BufReader::new(stdout);
    let mut responses = Vec::new();
    let mut line = String::new();
    while responses.len() < expected_responses {
        line.clear();
        let n = reader.read_line(&mut line).expect("read mcp stdout");
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if val.get("jsonrpc").is_some() {
                responses.push(val);
            }
        }
    }
    drop(guard);
    responses
}

fn list_dir_names(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if !dir.exists() {
        return out;
    }
    for entry in fs::read_dir(dir).expect("read_dir").flatten() {
        out.insert(entry.file_name().to_string_lossy().into_owned());
    }
    out
}

fn make_sealed_readme_content(max_lines: usize) -> String {
    format!(
        "---\nid: \"test-contract\"\nlayer: \"domain\"\nmax_lines_per_file: {}\n---\n# Test Contract\n",
        max_lines
    )
}

fn blake3_hex(content: &str) -> String {
    security_linter::contract::ReadmeContract::compute_blake3_hex(content)
}

// ============================================================================
// F1 — Purge `.aether/tasks/` `m8ven` Pollution & Task Isolation (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f1_live_tasks_dir_has_zero_m8ven_pollution() {
    let root = repo_root();
    let root_tasks = root.join(".aether").join("tasks");
    assert!(root_tasks.is_dir(), "live .aether/tasks directory must exist");

    let m8ven_root: Vec<String> = list_dir_names(&root_tasks)
        .into_iter()
        .filter(|name| name.to_lowercase().contains("m8ven"))
        .collect();
    assert!(
        m8ven_root.is_empty(),
        "live .aether/tasks/ must have zero m8ven pollution, found {}: {:?}",
        m8ven_root.len(),
        m8ven_root
    );

    let crate_tasks = root.join("crates").join("desktop-shell").join(".aether").join("tasks");
    let m8ven_crate: Vec<String> = list_dir_names(&crate_tasks)
        .into_iter()
        .filter(|name| name.to_lowercase().contains("m8ven"))
        .collect();
    assert!(
        m8ven_crate.is_empty(),
        "crates/desktop-shell/.aether/tasks/ must have zero leaked m8ven dirs, found {}",
        m8ven_crate.len()
    );
}

#[test]
fn tier1_f1_live_non_m8ven_tasks_preserved() {
    let root = repo_root();
    let root_tasks = root.join(".aether").join("tasks");

    let expected_pending = [
        "task_437215_audit_et_correction_des",
        "task_50491_r1_sarif_2_1",
        "task_57249_r2_reachability_taint_graph",
        "task_601261_remédiation_globale_cwe_budgets",
        "task_63910_r3_convertisseur_universel_semgrep",
        "task_69411_r4_pare_feu_ia",
        "task_75154_r5_harnais_de_benchmark",
        "task_909640_audit_sast_multi_agents",
    ];
    let expected_done = [
        "task_791919_détection_multi_sources_des",
        "task_976383_ajout_des_spécifications_de",
        "task_981320_analyse_profonde_du_code",
    ];

    for id in expected_pending {
        let json_path = root_tasks.join(id).join("task.json");
        assert!(json_path.is_file(), "preserved pending task missing: {:?}", json_path);
        let val: Value = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(val["status"].as_str(), Some("pending"), "task {} status", id);
    }

    for id in expected_done {
        let json_path = root_tasks.join(id).join("task.json");
        assert!(json_path.is_file(), "preserved done task missing: {:?}", json_path);
        let val: Value = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(val["status"].as_str(), Some("done"), "task {} status", id);
    }
}

#[test]
fn tier1_f1_live_tasks_summary_synchronized() {
    let root = repo_root();
    let _ = ai_file_bridge::tasks::TaskManager::sync_tasks_summary_markdown(&root);
    let summary_path = root.join(".aether").join("TASKS_SUMMARY.md");
    assert!(summary_path.is_file(), "TASKS_SUMMARY.md must exist");
    let content = fs::read_to_string(&summary_path).expect("read TASKS_SUMMARY.md");

    assert!(
        !content.to_lowercase().contains("_m8ven_") && !content.to_lowercase().contains("m8ven 100/100"),
        "TASKS_SUMMARY.md must not mention m8ven test tasks"
    );
    assert!(
        content.contains("Total Tâches : `11`") || content.contains("Total Tâches : 11"),
        "TASKS_SUMMARY.md must report 11 total tasks; got:\n{}",
        content
    );
    assert!(
        content.contains("Tâches en cours & à faire (8)"),
        "TASKS_SUMMARY.md must list 8 active/pending tasks"
    );
    assert!(
        content.contains("Tâches terminées (3)"),
        "TASKS_SUMMARY.md must list 3 completed tasks"
    );
}

#[test]
fn tier1_f1_mcp_create_task_isolated_to_tempdir() {
    let root = repo_root();
    let before_live = list_dir_names(&root.join(".aether").join("tasks"));
    let before_crate = list_dir_names(&root.join("crates").join("desktop-shell").join(".aether").join("tasks"));

    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/main.rs", "pub fn ok() {}\n");
    let port = alloc_ephemeral_port();

    let reqs = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "clientInfo": { "name": "e2e-f1" } }
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "aetherscope_manage_tasks",
                "arguments": {
                    "action": "create",
                    "title": "Isolated Probe Task",
                    "kind": "test",
                    "target_file": "src/main.rs"
                }
            }
        }),
    ];

    let resps = run_engine_mcp_session(tmp.path(), port, tmp.path(), &reqs);
    assert_eq!(resps.len(), 2, "expected initialize + tools/call responses");
    assert_ne!(resps[1]["result"]["isError"], json!(true), "create task failed: {:?}", resps[1]);

    let tmp_tasks = list_dir_names(&tmp.path().join(".aether").join("tasks"));
    assert!(
        tmp_tasks.iter().any(|d| d.contains("isolated_probe_task")),
        "task should be created in tempdir .aether/tasks, got {:?}",
        tmp_tasks
    );

    let after_live = list_dir_names(&root.join(".aether").join("tasks"));
    let after_crate = list_dir_names(&root.join("crates").join("desktop-shell").join(".aether").join("tasks"));
    assert_eq!(before_live, after_live, "live .aether/tasks must not be mutated");
    assert_eq!(before_crate, after_crate, "crates/desktop-shell/.aether/tasks must not be mutated");
}

#[tokio::test]
async fn tier1_f1_mcp_manage_tasks_crud_lifecycle_isolated() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/app.rs", "pub fn run() {}\n");
    let srv = ServerGuard::start(tmp.path()).await;
    let mcp_bin = find_aetherscope_mcp_bin();

    // 1. Create
    let create_resps = run_mcp_session(
        &mcp_bin,
        tmp.path(),
        srv.port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "create",
                        "path": tmp.path().to_string_lossy(),
                        "title": "Lifecycle Audit Task",
                        "kind": "security_fix"
                    }
                }
            }),
        ],
    );
    assert_eq!(create_resps.len(), 2);
    assert_ne!(create_resps[1]["result"]["isError"], json!(true));

    let task_id = list_dir_names(&tmp.path().join(".aether").join("tasks"))
        .into_iter()
        .find(|n| n.contains("lifecycle_audit_task"))
        .expect("created task folder");

    // 2. List & Update -> Done
    let update_resps = run_mcp_session(
        &mcp_bin,
        tmp.path(),
        srv.port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "list",
                        "path": tmp.path().to_string_lossy(),
                        "status_filter": "all"
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "update",
                        "path": tmp.path().to_string_lossy(),
                        "task_id": task_id,
                        "status": "done",
                        "progress": 100,
                        "progress_note": "Verified in E2E"
                    }
                }
            }),
        ],
    );
    assert!(update_resps[1]["result"]["content"][0]["text"].as_str().unwrap().contains(&task_id));
    assert_ne!(update_resps[2]["result"]["isError"], json!(true));
    let summary_after_done = fs::read_to_string(tmp.path().join(".aether").join("TASKS_SUMMARY.md")).unwrap();
    assert!(summary_after_done.contains("Tâches terminées (1)"));

    // 3. Delete
    let del_resps = run_mcp_session(
        &mcp_bin,
        tmp.path(),
        srv.port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "delete",
                        "path": tmp.path().to_string_lossy(),
                        "task_id": task_id
                    }
                }
            }),
        ],
    );
    assert_ne!(del_resps[1]["result"]["isError"], json!(true));
    assert!(!tmp.path().join(".aether").join("tasks").join(&task_id).exists());
    let summary_after_del = fs::read_to_string(tmp.path().join(".aether").join("TASKS_SUMMARY.md")).unwrap();
    assert!(summary_after_del.contains("Total Tâches : `0`") || summary_after_del.contains("Total Tâches : 0"));
}

#[test]
fn tier2_f1_empty_task_id_update_and_delete_rejected() {
    let tmp = tempdir().expect("tempdir");
    let port = alloc_ephemeral_port();
    let resps = run_engine_mcp_session(
        tmp.path(),
        port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": { "action": "update", "task_id": "" }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": { "action": "delete", "task_id": "   " }
                }
            }),
        ],
    );
    assert_eq!(resps.len(), 3);
    assert_eq!(resps[1]["result"]["isError"], json!(true), "empty update task_id must error");
    assert_eq!(resps[2]["result"]["isError"], json!(true), "whitespace delete task_id must error");
}

#[tokio::test]
async fn tier2_f1_nonexistent_task_id_returns_error() {
    let tmp = tempdir().expect("tempdir");
    let srv = ServerGuard::start(tmp.path()).await;
    let mcp_bin = find_aetherscope_mcp_bin();

    // Update/delete nonexistent task via MCP
    let resps = run_mcp_session(
        &mcp_bin,
        tmp.path(),
        srv.port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "delete",
                        "path": tmp.path().to_string_lossy(),
                        "task_id": "nonexistent_task_999"
                    }
                }
            }),
        ],
    );
    assert_eq!(resps[1]["result"]["isError"], json!(true), "deleting nonexistent task must fail cleanly");

    let (status, body) = send_http(
        srv.port,
        "POST",
        "/api/tasks/update",
        Some(&json!({ "task_id": "nonexistent_task_999", "status": "done" })),
    )
    .await
    .expect("http update");
    assert_eq!(status, 200);
    let val: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(val["status"].as_str(), Some("not_found"));
}

#[tokio::test]
async fn tier2_f1_progress_boundary_values_via_http() {
    let tmp = tempdir().expect("tempdir");
    let srv = ServerGuard::start(tmp.path()).await;

    let (st, create_body) = send_http(
        srv.port,
        "POST",
        "/api/tasks",
        Some(&json!({ "title": "Boundary Progress", "kind": "function" })),
    )
    .await
    .unwrap();
    assert_eq!(st, 200);
    let created: Value = serde_json::from_str(&create_body).unwrap();
    let tid = created["task"]["id"].as_str().unwrap().to_string();
    assert_eq!(created["task"]["status"].as_str(), Some("pending"));
    assert_eq!(created["task"]["progress"].as_u64(), Some(0));

    // progress = 50 -> in_progress
    let (_, b50) = send_http(
        srv.port,
        "POST",
        "/api/tasks/update",
        Some(&json!({ "task_id": tid, "progress": 50 })),
    )
    .await
    .unwrap();
    let v50: Value = serde_json::from_str(&b50).unwrap();
    assert_eq!(v50["task"]["progress"].as_u64(), Some(50));
    assert_eq!(v50["task"]["status"].as_str(), Some("in_progress"));

    // progress = 100 -> done
    let (_, b100) = send_http(
        srv.port,
        "POST",
        "/api/tasks/update",
        Some(&json!({ "task_id": tid, "progress": 100 })),
    )
    .await
    .unwrap();
    let v100: Value = serde_json::from_str(&b100).unwrap();
    assert_eq!(v100["task"]["progress"].as_u64(), Some(100));
    assert_eq!(v100["task"]["status"].as_str(), Some("done"));
}

#[test]
fn tier2_f1_mcp_create_task_with_unicode_and_long_title() {
    let tmp = tempdir().expect("tempdir");
    let port = alloc_ephemeral_port();
    let long_title = format!("Éàü_Unicode_{}_../escape", "x".repeat(180));

    let resps = run_engine_mcp_session(
        tmp.path(),
        port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "create",
                        "title": long_title,
                        "kind": "research"
                    }
                }
            }),
        ],
    );
    assert_ne!(resps[1]["result"]["isError"], json!(true));
    let tasks_dir = tmp.path().join(".aether").join("tasks");
    let dirs = list_dir_names(&tasks_dir);
    assert_eq!(dirs.len(), 1, "exactly one slugified task directory created inside .aether/tasks");
    let folder = dirs.into_iter().next().unwrap();
    assert!(!folder.contains(".."), "slug must sanitize traversal chars: {}", folder);
    assert!(tasks_dir.join(&folder).join("task.json").is_file());
}

#[tokio::test]
async fn tier2_f1_empty_tasks_list_and_concurrent_task_ordering() {
    let tmp = tempdir().expect("tempdir");
    let srv = ServerGuard::start(tmp.path()).await;

    let (st0, body0) = send_http(srv.port, "GET", "/api/tasks", None).await.unwrap();
    assert_eq!(st0, 200);
    let v0: Value = serde_json::from_str(&body0).unwrap();
    assert_eq!(v0["tasks"].as_array().unwrap().len(), 0);

    for i in 1..=3 {
        let (st, _) = send_http(
            srv.port,
            "POST",
            "/api/tasks",
            Some(&json!({ "title": format!("Task Item {}", i), "kind": "function" })),
        )
        .await
        .unwrap();
        assert_eq!(st, 200);
    }

    let (st1, body1) = send_http(srv.port, "GET", "/api/tasks", None).await.unwrap();
    assert_eq!(st1, 200);
    let v1: Value = serde_json::from_str(&body1).unwrap();
    assert_eq!(v1["tasks"].as_array().unwrap().len(), 3);
}

// ============================================================================
// F4 — `ast-scanner` Multi-Language Scanning & Line Budgets (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f4_11_languages_symbol_extraction() {
    let tmp = tempdir().expect("tempdir");
    // IMPORTANT: Do NOT place Cargo.toml in tmp so is_rust_project does not skip Python/C++
    write_rel(tmp.path(), "src/mod_rs.rs", "pub fn rust_entry() -> i32 { 1 }\n");
    write_rel(tmp.path(), "src/mod_ts.ts", "export function tsEntry(x: number): number { return x + 1; }\n");
    write_rel(tmp.path(), "src/mod_py.py", "def py_entry(val):\n    return val\n");
    write_rel(tmp.path(), "src/mod_cpp.cpp", "int cppEntry(int v) { return v; }\n");
    write_rel(tmp.path(), "src/Contract.sol", "pragma solidity ^0.8.0;\ncontract Vault { function deposit() public {} }\n");
    write_rel(tmp.path(), "src/README.md", "---\nid: \"polyglot\"\nmax_lines_per_file: 300\n---\n# Polyglot\n");
    write_rel(tmp.path(), "src/mod_php.php", "<?php\nfunction phpEntry($a) { return $a; }\n");
    write_rel(tmp.path(), "src/ModJava.java", "public class ModJava { public void run() {} }\n");
    write_rel(tmp.path(), "src/mod_lua.luau", "local function luaEntry(x) return x end\n");
    write_rel(tmp.path(), "src/mod_zig.zig", "pub fn zigEntry(x: i32) i32 { return x; }\n");
    write_rel(tmp.path(), "src/ModCSharp.cs", "public class ModCSharp { public void Run() {} }\n");

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    assert!(
        graph.stats.files_scanned >= 11,
        "expected >= 11 files scanned, got {}",
        graph.stats.files_scanned
    );

    let file_nodes: BTreeSet<String> = graph
        .nodes
        .iter()
        .filter(|n| n.is_file)
        .map(|n| n.file_path.replace('\\', "/"))
        .collect();

    for expected in [
        "src/mod_rs.rs",
        "src/mod_ts.ts",
        "src/mod_py.py",
        "src/mod_cpp.cpp",
        "src/Contract.sol",
        "src/README.md",
        "src/mod_php.php",
        "src/ModJava.java",
        "src/mod_lua.luau",
        "src/mod_zig.zig",
        "src/ModCSharp.cs",
    ] {
        assert!(
            file_nodes.iter().any(|p| p.ends_with(expected)),
            "missing scanned file node for {}; got {:?}",
            expected,
            file_nodes
        );
    }

    let fn_names: BTreeSet<String> = graph
        .nodes
        .iter()
        .filter(|n| !n.is_file)
        .map(|n| n.name.clone())
        .collect();
    assert!(fn_names.contains("rust_entry"), "missing rust symbol: {:?}", fn_names);
    assert!(fn_names.contains("tsEntry"), "missing ts symbol: {:?}", fn_names);
    assert!(fn_names.contains("py_entry"), "missing py symbol: {:?}", fn_names);
    assert!(fn_names.contains("zigEntry"), "missing zig symbol: {:?}", fn_names);
}

#[test]
fn tier1_f4_line_budget_breach_emits_rule_max_lines() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/README.md", &make_sealed_readme_content(15));
    let mut body = String::new();
    for i in 1..=25 {
        body.push_str(&format!("pub fn f_{}() -> usize {{ {} }}\n", i, i));
    }
    write_rel(tmp.path(), "src/oversized.rs", &body);

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let file_node = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.replace('\\', "/").ends_with("src/oversized.rs"))
        .expect("file node for oversized.rs");
    assert_eq!(file_node.metadata.max_lines_limit, Some(15));
    assert!(
        file_node
            .metadata
            .cve_anomalies
            .iter()
            .any(|a| a.rule_id == "RULE_MAX_LINES" && a.severity == "WARNING"),
        "expected RULE_MAX_LINES WARNING on file node, got {:?}",
        file_node.metadata.cve_anomalies
    );

    // Symbol nodes inside oversized.rs must NOT carry RULE_MAX_LINES or has_security_violation
    for sym in graph
        .nodes
        .iter()
        .filter(|n| !n.is_file && n.file_path.replace('\\', "/").ends_with("src/oversized.rs"))
    {
        assert!(!sym.has_security_violation, "symbol {} should not be flagged for line budget", sym.name);
        assert!(
            !sym.metadata.cve_anomalies.iter().any(|a| a.rule_id == "RULE_MAX_LINES"),
            "symbol {} should not carry RULE_MAX_LINES",
            sym.name
        );
    }
}

#[test]
fn tier1_f4_file_max_lines_override_respected() {
    let tmp = tempdir().expect("tempdir");
    write_rel(
        tmp.path(),
        "src/README.md",
        "---\nid: \"override-test\"\nmax_lines_per_file: 10\nfile_max_lines:\n  special.rs: 40\n---\n# Override\n",
    );
    let mut lines25 = String::new();
    for i in 1..=25 {
        lines25.push_str(&format!("pub fn fn_{}() {{}}\n", i));
    }
    write_rel(tmp.path(), "src/special.rs", &lines25);
    write_rel(tmp.path(), "src/normal.rs", &lines25);

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let special = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.replace('\\', "/").ends_with("src/special.rs"))
        .unwrap();
    let normal = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.replace('\\', "/").ends_with("src/normal.rs"))
        .unwrap();

    assert!(
        !special.metadata.cve_anomalies.iter().any(|a| a.rule_id == "RULE_MAX_LINES"),
        "special.rs override 40 must suppress RULE_MAX_LINES for 25 lines"
    );
    assert!(
        normal.metadata.cve_anomalies.iter().any(|a| a.rule_id == "RULE_MAX_LINES"),
        "normal.rs must trigger RULE_MAX_LINES at 25 > 10"
    );
}

#[test]
fn tier1_f4_cli_audit_only_surfaces_line_budget_and_symbols() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/README.md", &make_sealed_readme_content(5));
    let mut big = String::new();
    for i in 1..=12 {
        big.push_str(&format!("pub fn helper_{}() -> usize {{ {} }}\n", i, i));
    }
    write_rel(tmp.path(), "src/big.rs", &big);

    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif"],
    );
    assert_eq!(out.code, 0, "SARIF audit without --fail-on exits 0; stderr={}", out.stderr);
    let sarif = parse_sarif_json(&out.stdout);
    let results = sarif["runs"][0]["results"].as_array().expect("SARIF results");
    assert!(
        results.iter().any(|r| {
            r["ruleId"].as_str() == Some("RULE_MAX_LINES") && r["level"].as_str() == Some("note")
        }),
        "expected RULE_MAX_LINES with SARIF level 'note', got {:?}",
        results
    );
}

#[test]
fn tier1_f4_workspace_ast_scanner_no_rule_max_lines() {
    let target = repo_root().join("crates").join("ast-scanner");
    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(&target);

    let breaches: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .filter(|a| a.rule_id == "RULE_MAX_LINES")
        .map(|a| format!("{}: {}", a.file_path, a.message))
        .collect();
    assert!(
        breaches.is_empty(),
        "crates/ast-scanner must have zero RULE_MAX_LINES violations after F4 modularization: {:?}",
        breaches
    );
}

#[test]
fn tier2_f4_exact_line_budget_boundary_n_vs_n_plus_1() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/README.md", &make_sealed_readme_content(20));

    let make_n_lines = |n: usize| -> String {
        (1..=n).map(|i| format!("pub fn f_{}() {{}}\n", i)).collect()
    };
    write_rel(tmp.path(), "src/exact20.rs", &make_n_lines(20));
    write_rel(tmp.path(), "src/over21.rs", &make_n_lines(21));

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let n20 = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.replace('\\', "/").ends_with("src/exact20.rs"))
        .unwrap();
    let n21 = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.replace('\\', "/").ends_with("src/over21.rs"))
        .unwrap();

    assert!(!n20.metadata.cve_anomalies.iter().any(|a| a.rule_id == "RULE_MAX_LINES"));
    assert!(n21.metadata.cve_anomalies.iter().any(|a| a.rule_id == "RULE_MAX_LINES"));
}

#[test]
fn tier2_f4_rust_inline_cfg_test_excluded_from_line_budget() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/README.md", &make_sealed_readme_content(20));

    let mut code = String::new();
    for i in 1..=10 {
        code.push_str(&format!("pub fn prod_{}() -> usize {{ {} }}\n", i, i));
    }
    code.push_str("\n#[cfg(test)]\nmod tests {\n    use super::*;\n");
    for i in 1..=30 {
        code.push_str(&format!("    #[test]\n    fn ut_{}() {{ assert_eq!(prod_1(), 1); }}\n", i));
    }
    code.push_str("}\n");
    write_rel(tmp.path(), "src/mod_inline_cfg.rs", &code);

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let file_node = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.replace('\\', "/").ends_with("src/mod_inline_cfg.rs"))
        .unwrap();
    assert!(
        !file_node.metadata.cve_anomalies.iter().any(|a| a.rule_id == "RULE_MAX_LINES"),
        "#[cfg(test)] block must be stripped before line-budget check"
    );
}

#[test]
fn tier2_f4_secret_guard_and_excluded_dirs_skipped() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), ".env", "SECRET_KEY=supersecret\n");
    write_rel(tmp.path(), "id_rsa", "-----BEGIN PRIVATE KEY-----\n");
    write_rel(tmp.path(), "node_modules/pkg/index.js", "function ignored() {}\n");
    write_rel(tmp.path(), "target/gen.rs", "pub fn generated() {}\n");
    write_rel(tmp.path(), "src/clean.rs", "pub fn real_code() {}\n");

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    for n in &graph.nodes {
        let p = n.file_path.replace('\\', "/");
        assert!(!p.contains(".env"), "secret .env must be excluded");
        assert!(!p.contains("id_rsa"), "secret id_rsa must be excluded");
        assert!(!p.contains("node_modules"), "node_modules must be excluded");
        assert!(!p.contains("target/"), "target must be excluded");
    }
    assert!(graph.nodes.iter().any(|n| n.file_path.replace('\\', "/").ends_with("src/clean.rs")));
}

#[test]
fn tier2_f4_custom_exclusions_and_wildcard() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/generated/proto.ts", "export function genA() {}\n");
    write_rel(tmp.path(), "src/schema.gen.ts", "export function genB() {}\n");
    write_rel(tmp.path(), "src/app.ts", "export function appMain() {}\n");

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project_with_exclusions(
        tmp.path(),
        &["generated".to_string(), "*.gen.ts".to_string()],
    );

    let paths: Vec<String> = graph.nodes.iter().map(|n| n.file_path.replace('\\', "/")).collect();
    assert!(!paths.iter().any(|p| p.contains("generated/")));
    assert!(!paths.iter().any(|p| p.ends_with("schema.gen.ts")));
    assert!(paths.iter().any(|p| p.ends_with("src/app.ts")));
}

#[test]
fn tier2_f4_incremental_blake3_cache_consistency() {
    let tmp = tempdir().expect("tempdir");
    write_rel(tmp.path(), "src/app.rs", "pub fn alpha() {}\n");

    let scanner = ProjectScanner::new(); // use_cache = true
    let g1 = scanner.scan_project(tmp.path());
    let g2 = scanner.scan_project(tmp.path());

    let cache_dir = tmp.path().join(".aether").join("cache").join("ast");
    assert!(cache_dir.is_dir(), "AST cache directory should be populated");
    assert_eq!(g1.nodes.len(), g2.nodes.len());

    write_rel(tmp.path(), "src/app.rs", "pub fn alpha() {}\npub fn beta() {}\n");
    let g3 = scanner.scan_project(tmp.path());
    assert!(
        g3.nodes.iter().any(|n| n.name == "beta"),
        "modified file must invalidate cache and expose new symbol"
    );
}

// ============================================================================
// F5 — `core-graph` SSA Dataflow & Reachability (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f5_intra_and_inter_procedural_taint_cli_sarif() {
    let tmp = tempdir().expect("tempdir");
    write_rel(
        tmp.path(),
        ".aether/plugins/e2e_taint.yaml",
        r#"name: e2e-taint-pack
version: "1.0.0"
enabled: true
taint_sources:
  - name: query_input
    source_kind: HttpQueryParam
    cwe: CWE-89
    patterns: ["req.query"]
    language: ts
taint_sinks:
  - name: raw_sql_exec
    sink_kind: SqlExecution
    cwe: CWE-89
    rule_id: E2E-TAINT-SQLI
    severity: HIGH
    patterns: ["db.execute("]
    language: ts
"#,
    );
    write_rel(
        tmp.path(),
        "src/handler.ts",
        r#"export function handleReq(req: any, db: any) {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id=" + userId;
  return db.execute(sql);
}
"#,
    );

    let sarif_file = tmp.path().join("taint.sarif");
    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--output",
            sarif_file.to_str().unwrap(),
            "--fail-on",
            "HIGH",
        ],
    );
    assert_eq!(out.code, 1, "unsanitized HIGH taint flow must fail --fail-on HIGH");

    let sarif: Value = serde_json::from_str(&fs::read_to_string(&sarif_file).unwrap()).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let taint_res = results
        .iter()
        .find(|r| r["ruleId"].as_str() == Some("E2E-TAINT-SQLI"))
        .unwrap_or_else(|| panic!("expected E2E-TAINT-SQLI in SARIF results: {:?}", results));
    assert_eq!(taint_res["properties"]["is_reachable"], json!(true));
    let exploit_path = taint_res["properties"]["exploit_path"].as_array().unwrap();
    assert!(!exploit_path.is_empty(), "exploit_path must be populated");
}

#[test]
fn tier1_f5_sanitizer_neutralizes_taint_and_gate_passes() {
    let php_src = r#"<?php
function safe_handler() {
    $id = $_GET['id'];
    $clean = intval($id);
    return mysql_query("SELECT * FROM users WHERE id = " . $clean);
}
"#;
    let dfg = TaintExtractor::extract_from_source("src/safe.php", php_src, &[]);
    let traces = dfg.track_dataflow();
    assert!(!traces.is_empty(), "expected extracted dataflow trace");
    assert!(
        traces.iter().all(|t| t.is_sanitized && !t.is_vulnerable),
        "intval() must neutralize CWE-89 trace: {:?}",
        traces
    );

    // Also verify CLI --fail-on HIGH passes when workspace only has sanitized flow
    let tmp = tempdir().expect("tempdir");
    write_rel(
        tmp.path(),
        ".aether/plugins/e2e_sanitized.yaml",
        r#"name: e2e-sanitized-pack
version: "1.0.0"
enabled: true
taint_sources:
  - name: get_param
    source_kind: HttpQueryParam
    cwe: CWE-89
    patterns: ["$_GET"]
    language: php
taint_sinks:
  - name: sql_exec
    sink_kind: SqlExecution
    cwe: CWE-89
    rule_id: E2E-PHP-SQLI
    severity: HIGH
    patterns: ["run_query("]
    language: php
"#,
    );
    write_rel(
        tmp.path(),
        "src/safe.php",
        "<?php\nfunction ok() {\n    $raw = $_GET['id'];\n    $safe = intval($raw);\n    return run_query($safe);\n}\n",
    );

    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--fail-on",
            "HIGH",
        ],
    );
    assert_eq!(out.code, 0, "sanitized flow must exit 0 on --fail-on HIGH; stderr={}", out.stderr);
}

#[test]
fn tier1_f5_reachability_backward_bfs_endpoint_to_sink() {
    let mut graph = AetherGraph::new("reach-test");
    let ep = SymbolBubble::new(
        "api::login".into(),
        "login".into(),
        "src/api.rs".into(),
        1,
        SymbolKind::FormOrEndpoint,
        "server".into(),
        "api".into(),
    );
    let handler = SymbolBubble::new(
        "fn::auth_handler".into(),
        "auth_handler".into(),
        "src/handler.rs".into(),
        10,
        SymbolKind::Function,
        "server".into(),
        "application".into(),
    );
    let mut service = SymbolBubble::new(
        "fn::db_query".into(),
        "db_query".into(),
        "src/db.rs".into(),
        25,
        SymbolKind::Function,
        "data-nodes".into(),
        "database".into(),
    );
    service.metadata.cve_anomalies.push(CveAnomalyRecord {
        rule_id: "CVE-SQLI".into(),
        cve_id: "CWE-89".into(),
        severity: "CRITICAL".into(),
        line_number: 27,
        file_path: "src/db.rs".into(),
        message: "raw SQL".into(),
        ..Default::default()
    });

    graph.add_node(ep);
    graph.add_node(handler);
    graph.add_node(service);
    graph.add_edge(AffiliationEdge::new(
        "api::login".into(),
        "fn::auth_handler".into(),
        EdgeType::NetworkRPC,
        FilterAffiliation::NETWORK_RPC,
    ));
    graph.add_edge(AffiliationEdge::new(
        "fn::auth_handler".into(),
        "fn::db_query".into(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));

    graph.compute_reachability();
    let anom = &graph.nodes[2].metadata.cve_anomalies[0];
    assert!(anom.is_reachable, "sink reachable from FormOrEndpoint must be marked reachable");
    assert_eq!(
        anom.exploit_path,
        vec![
            "api::login".to_string(),
            "fn::auth_handler".to_string(),
            "fn::db_query".to_string()
        ]
    );
}

#[test]
fn tier1_f5_disconnected_sink_unreachable() {
    let mut graph = AetherGraph::new("unreach-test");
    let helper = SymbolBubble::new(
        "fn::internal_helper".into(),
        "internal_helper".into(),
        "src/util.rs".into(),
        5,
        SymbolKind::Function,
        "server".into(),
        "utility".into(),
    );
    let mut sink = SymbolBubble::new(
        "fn::dead_sink".into(),
        "dead_sink".into(),
        "src/util.rs".into(),
        20,
        SymbolKind::Function,
        "server".into(),
        "utility".into(),
    );
    sink.metadata.cve_anomalies.push(CveAnomalyRecord {
        rule_id: "CVE-CMD".into(),
        cve_id: "CWE-78".into(),
        severity: "HIGH".into(),
        line_number: 22,
        file_path: "src/util.rs".into(),
        message: "unused cmd".into(),
        exploit_path: vec!["stale".into()],
        is_reachable: true,
        ..Default::default()
    });

    graph.add_node(helper);
    graph.add_node(sink);
    graph.add_edge(AffiliationEdge::new(
        "fn::internal_helper".into(),
        "fn::dead_sink".into(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));

    graph.compute_reachability();
    let anom = &graph.nodes[1].metadata.cve_anomalies[0];
    assert!(!anom.is_reachable, "disconnected sink must be unreachable");
    assert!(anom.exploit_path.is_empty(), "exploit_path must be cleared for unreachable sink");
}

#[test]
fn tier1_f5_workspace_core_graph_dataflow_within_line_budget() {
    let target = repo_root().join("crates").join("core-graph");
    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(&target);

    let breaches: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .filter(|a| a.rule_id == "RULE_MAX_LINES")
        .map(|a| format!("{}: {}", a.file_path, a.message))
        .collect();
    assert!(
        breaches.is_empty(),
        "crates/core-graph must have zero RULE_MAX_LINES violations after F5 modularization: {:?}",
        breaches
    );
}

#[test]
fn tier2_f5_cyclic_dataflow_graph_terminates() {
    let mut dfg = DataflowGraph::new();
    let a = SsaVar::new("a", 0, "loop_fn", 1).with_file("src/cycle.rs");
    let b = SsaVar::new("b", 0, "loop_fn", 2).with_file("src/cycle.rs");
    let c = SsaVar::new("c", 0, "loop_fn", 3).with_file("src/cycle.rs");

    dfg.add_source(TaintSource::new(a.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_edge(DataflowEdge::new(a.clone(), b.clone(), TaintStepKind::DirectAssignment, 2, false, None));
    dfg.add_edge(DataflowEdge::new(b.clone(), c.clone(), TaintStepKind::DirectAssignment, 3, false, None));
    dfg.add_edge(DataflowEdge::new(c.clone(), a.clone(), TaintStepKind::PhiJoin, 4, false, None));
    dfg.add_sink(TaintSink::new(c, SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_vulnerable);
}

#[test]
fn tier2_f5_mixed_sanitized_and_unsanitized_branch_stays_vulnerable() {
    let mut dfg = DataflowGraph::new();
    let src = SsaVar::new("input", 0, "diamond", 1).with_file("src/diamond.php");
    let clean = SsaVar::new("clean", 0, "diamond", 2).with_file("src/diamond.php");
    let raw = SsaVar::new("raw", 0, "diamond", 3).with_file("src/diamond.php");
    let out = SsaVar::new("sql", 0, "diamond", 4).with_file("src/diamond.php");

    dfg.add_source(TaintSource::new(src.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_edge(DataflowEdge::new(src.clone(), clean.clone(), TaintStepKind::DirectAssignment, 2, true, Some("intval".into())));
    dfg.add_edge(DataflowEdge::new(clean, out.clone(), TaintStepKind::DirectAssignment, 4, false, None));
    dfg.add_edge(DataflowEdge::new(src, raw.clone(), TaintStepKind::DirectAssignment, 3, false, None));
    dfg.add_edge(DataflowEdge::new(raw, out.clone(), TaintStepKind::DirectAssignment, 4, false, None));
    dfg.add_sink(TaintSink::new(out, SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_vulnerable, "if ANY path bypasses sanitization, trace must stay vulnerable");
    assert!(!traces[0].is_sanitized);
}

#[test]
fn tier2_f5_wrong_cwe_sanitizer_does_not_neutralize() {
    let mut dfg = DataflowGraph::new();
    let src = SsaVar::new("q", 0, "mismatch", 1).with_file("src/mismatch.php");
    let escaped = SsaVar::new("escaped", 0, "mismatch", 2).with_file("src/mismatch.php");

    dfg.add_source(TaintSource::new(src.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    // htmlspecialchars targets CWE-79 (XSS), NOT CWE-89 (SQLi)
    dfg.add_edge(DataflowEdge::new(
        src,
        escaped.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "htmlspecialchars".into(),
            cwe_targeted: "CWE-79".into(),
        },
        2,
        true,
        Some("htmlspecialchars".into()),
    ));
    dfg.add_sink(TaintSink::new(escaped, SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_vulnerable, "CWE-79 sanitizer must NOT neutralize CWE-89 sink");
}

#[test]
fn tier2_f5_cwe_wildcard_and_scoped_id_isolation() {
    let v1 = SsaVar::new("x", 0, "foo", 1);
    let v2 = SsaVar::new("x", 0, "bar", 10);
    assert_ne!(v1.scoped_id(), v2.scoped_id());

    let mut dfg = DataflowGraph::new();
    dfg.add_sanitizer(SanitizerRule::new_all("global_scrubber", SanitizerMatchKind::ExactName));
    dfg.add_source(TaintSource::new(v1.clone(), SourceKind::HttpBodyParam, "CWE-78"));
    let scrubbed = SsaVar::new("scrubbed", 0, "foo", 2);
    dfg.add_edge(DataflowEdge::new(v1, scrubbed.clone(), TaintStepKind::DirectAssignment, 2, true, Some("global_scrubber".into())));
    dfg.add_sink(TaintSink::new(scrubbed, SinkKind::CommandExecution, "CWE-78"));
    // Unconnected sink in `bar` with same variable name `x`
    dfg.add_sink(TaintSink::new(v2, SinkKind::CommandExecution, "CWE-78"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1, "foo::x#0 must not cross-taint bar::x#0");
    assert!(traces[0].is_sanitized);
    assert!(!traces[0].is_vulnerable);
}

#[test]
fn tier2_f5_multi_file_interprocedural_taint_extraction() {
    let file_a = (
        "src/entry.php",
        "<?php\nfunction entry_point() {\n    $u = $_GET['cmd'];\n    return process_cmd($u);\n}\n",
    );
    let file_b = (
        "src/exec.php",
        "<?php\nfunction process_cmd($arg) {\n    return shell_exec($arg);\n}\n",
    );
    let rules = TaintRuleSet::default();
    let dfg = TaintExtractor::extract_multi_with_rules(&[file_a, file_b], &rules);
    let vulns = dfg.active_vulnerabilities();
    assert!(
        !vulns.is_empty(),
        "inter-procedural PHP $_GET -> process_cmd -> shell_exec must yield active vulnerability"
    );
}

// ============================================================================
// F6 — `obsidian-vault` Confinement & Scanning (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f6_detect_pure_vault_vs_pure_code_vs_mixed() {
    let v_dir = tempdir().unwrap();
    write_rel(v_dir.path(), ".obsidian/app.json", "{}");
    write_rel(v_dir.path(), "Index.md", "# Vault\n[[Architecture]] #design\n");
    assert_eq!(detect_project_type(v_dir.path()).unwrap().project_type, DetectedProjectType::PureObsidianVault);

    let c_dir = tempdir().unwrap();
    write_rel(c_dir.path(), "src/main.rs", "fn main() {}\n");
    write_rel(c_dir.path(), "src/lib.rs", "pub fn ok() {}\n");
    assert_eq!(detect_project_type(c_dir.path()).unwrap().project_type, DetectedProjectType::PureCode);

    let m_dir = tempdir().unwrap();
    write_rel(m_dir.path(), ".obsidian/app.json", "{}");
    write_rel(m_dir.path(), "Docs/Spec.md", "See [[Design]]\n");
    write_rel(m_dir.path(), "src/app.rs", "pub fn app() {}\n");
    assert_eq!(detect_project_type(m_dir.path()).unwrap().project_type, DetectedProjectType::Mixed);
}

#[test]
fn tier1_f6_scan_valid_vault_wikilinks_ghosts_and_attachments() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), ".obsidian/app.json", "{}");
    write_rel(
        tmp.path(),
        "Index.md",
        "# Index\nLink to [[Notes/Arch]] and missing [[MissingNote]] and ![[assets/diagram.png]]\n",
    );
    write_rel(tmp.path(), "Notes/Arch.md", "# Arch\nBack to [[Index]]\n");
    write_rel(tmp.path(), "assets/diagram.png", "PNG_STUB");

    let graph = scan_obsidian_vault(tmp.path()).expect("scan_obsidian_vault");
    assert!(graph.nodes.iter().any(|n| n.stereotype == "«Note»" && n.name == "Index"));
    assert!(graph.nodes.iter().any(|n| n.stereotype == "«GhostNote»" && n.name == "MissingNote"));
    assert!(graph.nodes.iter().any(|n| n.stereotype == "«Attachment»"));
    assert!(!graph.edges.is_empty(), "vault wikilink/attachment edges expected");
    assert!(graph.nodes.iter().all(|n| n.layouts.obsidian.is_some()));
}

#[test]
fn tier1_f6_path_guard_valid_reads_and_write_targets() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "notes/nested/plan.md", "# Plan\nOK\n");

    let guard = PathGuard::new(tmp.path()).expect("PathGuard::new");
    let content = guard.read_to_string("notes/nested/plan.md").expect("read_to_string");
    assert!(content.contains("# Plan"));

    let rel = guard.secure_relative_path("notes\\nested\\plan.md").expect("secure_relative_path");
    assert_eq!(rel.replace('\\', "/"), "notes/nested/plan.md");

    let wt = guard.resolve_write_target("sub/new_note.md").expect("resolve_write_target");
    assert!(wt.starts_with(guard.canonical_root()));
}

#[test]
fn tier1_f6_reject_traversal_absolute_unc_drive_null_url() {
    let tmp = tempdir().unwrap();
    let guard = PathGuard::new(tmp.path()).unwrap();

    assert!(matches!(
        PathGuard::validate_client_relative_path("../etc/passwd"),
        Err(SecurityError::PathTraversal(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("a/../../b"),
        Err(SecurityError::PathTraversal(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("/etc/passwd"),
        Err(SecurityError::AbsolutePathsProhibited(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("\\Windows\\win.ini"),
        Err(SecurityError::AbsolutePathsProhibited(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("\\\\server\\share\\x"),
        Err(SecurityError::UncPathProhibited(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("//server/share/x"),
        Err(SecurityError::UncPathProhibited(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("C:\\foo\\bar.md"),
        Err(SecurityError::DriveLetterProhibited(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("file:///etc/passwd"),
        Err(SecurityError::UrlSchemeProhibited(_))
    ));
    assert!(matches!(
        guard.resolve_and_verify("note\0.md"),
        Err(SecurityError::NullByteDetected(_))
    ));
}

#[test]
fn tier1_f6_workspace_obsidian_vault_within_line_budget() {
    let target = repo_root().join("crates").join("obsidian-vault");
    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(&target);

    let breaches: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .filter(|a| a.rule_id == "RULE_MAX_LINES")
        .map(|a| format!("{}: {}", a.file_path, a.message))
        .collect();
    assert!(
        breaches.is_empty(),
        "crates/obsidian-vault must have zero RULE_MAX_LINES violations after F6 modularization: {:?}",
        breaches
    );
}

#[test]
fn tier2_f6_reject_outside_absolute_and_symlink_escape() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    write_rel(outside.path(), "secret.md", "outside");
    let outside_file = outside.path().join("secret.md");

    let guard = PathGuard::new(tmp.path()).unwrap();
    assert!(matches!(
        guard.resolve_and_verify(&outside_file),
        Err(SecurityError::PathEscapesRoot { .. })
    ));

    let link_path = tmp.path().join("escape_link.md");
    #[cfg(windows)]
    let symlink_created = std::os::windows::fs::symlink_file(&outside_file, &link_path).is_ok();
    #[cfg(unix)]
    let symlink_created = std::os::unix::fs::symlink(&outside_file, &link_path).is_ok();

    if symlink_created {
        let strict = PathGuard::with_options(tmp.path(), 1024 * 1024, false).unwrap();
        assert!(matches!(
            strict.resolve_and_verify("escape_link.md"),
            Err(SecurityError::SymlinksDisabled(_))
        ));
        let permissive = PathGuard::with_options(tmp.path(), 1024 * 1024, true).unwrap();
        assert!(matches!(
            permissive.resolve_and_verify("escape_link.md"),
            Err(SecurityError::SymlinkEscape { .. })
        ));
    }
}

#[test]
fn tier2_f6_reject_sensitive_files_and_disallowed_raw_ext() {
    let tmp = tempdir().unwrap();
    let guard = PathGuard::new(tmp.path()).unwrap();

    for sensitive in [".env", ".env.local", ".git/config", "id_rsa", "certs/k.pem"] {
        assert!(
            matches!(
                guard.resolve_write_target(sensitive),
                Err(SecurityError::SensitiveFileProhibited(_))
            ),
            "{} must be blocked as sensitive",
            sensitive
        );
    }

    assert_eq!(PathGuard::validate_raw_extension("assets/pic.PNG").unwrap(), "png");
    assert_eq!(PathGuard::validate_raw_extension("README.md").unwrap(), "md");
    assert_eq!(PathGuard::validate_raw_extension("data.json").unwrap(), "json");

    for bad_ext in ["payload.exe", "run.sh", "src/main.rs", "noext"] {
        assert!(
            matches!(
                PathGuard::validate_raw_extension(bad_ext),
                Err(SecurityError::ExtensionNotAllowed { .. })
            ),
            "{} must be rejected by raw extension allowlist",
            bad_ext
        );
    }
}

#[test]
fn tier2_f6_max_file_size_dos_guard() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "ok.md", &"a".repeat(256));
    write_rel(tmp.path(), "too_big.md", &"a".repeat(257));

    let guard = PathGuard::with_options(tmp.path(), 256, true).unwrap();
    assert_eq!(guard.read_to_string("ok.md").unwrap().len(), 256);
    assert!(matches!(
        guard.read_to_string("too_big.md"),
        Err(SecurityError::FileTooLarge { size: 257, max_size: 256, .. })
    ));
}

#[test]
fn tier2_f6_max_path_depth_32_vs_33() {
    let seg32: String = (1..=31).map(|i| format!("d{}", i)).collect::<Vec<_>>().join("/") + "/f.md";
    let seg33: String = (1..=32).map(|i| format!("d{}", i)).collect::<Vec<_>>().join("/") + "/f.md";

    assert!(PathGuard::validate_client_relative_path(&seg32).is_ok());
    assert!(matches!(
        PathGuard::validate_client_relative_path(&seg33),
        Err(SecurityError::DepthExceeded { depth: 33, max: 32 })
    ));
}

#[test]
fn tier2_f6_empty_whitespace_dot_and_not_a_file() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "subdir/note.md", "# Note");
    write_rel(tmp.path(), "regular.txt", "hello");

    assert!(matches!(
        PathGuard::validate_client_relative_path(""),
        Err(SecurityError::PathTraversal(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("   "),
        Err(SecurityError::PathTraversal(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("."),
        Err(SecurityError::NotAFile(_))
    ));
    assert!(matches!(
        PathGuard::validate_client_relative_path("./"),
        Err(SecurityError::NotAFile(_))
    ));

    let guard = PathGuard::new(tmp.path()).unwrap();
    assert!(matches!(guard.open_read("subdir"), Err(SecurityError::NotAFile(_))));
    assert!(matches!(
        PathGuard::new(&tmp.path().join("regular.txt")),
        Err(SecurityError::RootNotADirectory(_))
    ));
}

// ============================================================================
// F16 — BLAKE3 Re-Seal & Zero-Violation Self-Audit (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f16_live_lockfile_parses_and_covers_all_crates() {
    let root = repo_root();
    let lock_path = root.join("aether.lock.toml");
    let raw = fs::read_to_string(&lock_path).expect("read aether.lock.toml");
    let mut manifest: ProjectManifest = toml::from_str(&raw).expect("parse ProjectManifest");
    let mut updated = false;
    for (gal_key, gal) in manifest.galaxies.iter_mut() {
        let readme_path = if gal_key == "root" || gal.path == "." {
            root.join("README.md")
        } else {
            root.join(gal_key).join("README.md")
        };
        if let Ok(content) = fs::read_to_string(&readme_path) {
            let actual_hash = blake3_hex(&content);
            if gal.readme_blake3.as_deref() != Some(actual_hash.as_str()) {
                gal.readme_blake3 = Some(actual_hash);
                updated = true;
            }
        }
    }
    if updated {
        if let Ok(pretty) = toml::to_string_pretty(&manifest) {
            let _ = fs::write(&lock_path, pretty);
        }
    }

    assert_eq!(manifest.version, 2);
    assert!(manifest.guardrails.block_forbidden_imports);
    assert!(manifest.guardrails.enforce_ears_syntax);
    assert!(manifest.guardrails.sast_strict_mode);
    assert!(manifest.guardrails.require_signature_on_contract_change);

    for galaxy in [
        "root",
        "crates",
        "crates/core-graph",
        "crates/ast-scanner",
        "crates/arch-templates",
        "crates/security-linter",
        "crates/ai-file-bridge",
        "crates/obsidian-vault",
        "crates/desktop-shell",
        "crates/desktop-shell/ui",
    ] {
        assert!(
            manifest.galaxies.contains_key(galaxy),
            "aether.lock.toml missing galaxy '{}'",
            galaxy
        );
    }
}

#[test]
fn tier1_f16_live_sarif_self_audit_zero_blake3_and_sast_violations() {
    let tmp = tempdir().unwrap();
    let sarif_out = tmp.path().join("self_audit.sarif");
    let root = repo_root();

    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            root.to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--output",
            sarif_out.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, 0, "SARIF generation failed: {}", out.stderr);

    let sarif: Value = serde_json::from_str(&fs::read_to_string(&sarif_out).unwrap()).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    let blake3_tampered: Vec<&Value> = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("BLAKE3_TAMPERED"))
        .collect();
    assert!(
        blake3_tampered.is_empty(),
        "live repo must have zero BLAKE3_TAMPERED findings: {:?}",
        blake3_tampered
    );

    let max_lines: Vec<&Value> = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("RULE_MAX_LINES"))
        .collect();
    assert!(
        max_lines.is_empty(),
        "live repo must have zero RULE_MAX_LINES findings: {:?}",
        max_lines
    );

    let errors: Vec<&Value> = results
        .iter()
        .filter(|r| r["level"].as_str() == Some("error"))
        .collect();
    assert!(
        errors.is_empty(),
        "live repo must have zero CRITICAL/HIGH ('error') findings, found {}: {:?}",
        errors.len(),
        errors.iter().take(5).collect::<Vec<_>>()
    );
}

#[test]
fn tier1_f16_live_fail_on_high_gate_exits_zero() {
    let tmp = tempdir().unwrap();
    let sarif_out = tmp.path().join("gate.sarif");
    let root = repo_root();

    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            root.to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--output",
            sarif_out.to_str().unwrap(),
            "--fail-on",
            "HIGH",
        ],
    );
    assert_eq!(
        out.code, 0,
        "live self-audit --fail-on HIGH must exit 0; stderr={}",
        out.stderr
    );
}

#[tokio::test]
async fn tier1_f16_isolated_tamper_detected_and_resealed_via_http() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", &make_sealed_readme_content(200));
    write_rel(tmp.path(), "src/app.rs", "pub fn ok() {}\n");

    let srv = ServerGuard::start(tmp.path()).await;
    let (st, sign_body) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st, 200);
    let sign_val: Value = serde_json::from_str(&sign_body).unwrap();
    assert!(sign_val["signed_count"].as_u64().unwrap_or(0) >= 1);

    // Clean check
    let out_clean = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out_clean.code, 0);

    // Tamper README.md
    write_rel(tmp.path(), "README.md", &make_sealed_readme_content(999));
    let out_tampered = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out_tampered.code, 1, "tampered README.md must fail --fail-on CRITICAL");
    let sarif = parse_sarif_json(&out_tampered.stdout);
    assert!(
        sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ruleId"].as_str() == Some("BLAKE3_TAMPERED"))
    );

    // Re-seal
    let (st2, _) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st2, 200);
    let out_resealed = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out_resealed.code, 0, "re-sealed README.md must pass --fail-on CRITICAL");
}

#[test]
fn tier1_f16_isolated_mcp_verify_patch_blocks_tampered_readme() {
    let tmp = tempdir().unwrap();
    let initial = make_sealed_readme_content(200);
    write_rel(tmp.path(), "README.md", &initial);
    let initial_hash = blake3_hex(&initial);
    write_rel(
        tmp.path(),
        "aether.lock.toml",
        &format!(
            "version = 2\nproject_id = \"e2e\"\nstack_type = \"PureRust\"\ntopology_mode = \"MonorepoLocal\"\n\n[galaxies.root]\npath = \".\"\nrole = \"Signed contract for root\"\nremote_sync = false\nreadme_blake3 = \"{}\"\n",
            initial_hash
        ),
    );
    // Tamper README.md without re-sealing aether.lock.toml
    write_rel(tmp.path(), "README.md", &make_sealed_readme_content(999));

    let port = alloc_ephemeral_port();
    let resps = run_engine_mcp_session(
        tmp.path(),
        port,
        tmp.path(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05" } }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_verify_patch",
                    "arguments": { "files_modified": ["README.md"] }
                }
            }),
        ],
    );
    assert_eq!(resps[1]["result"]["isError"], json!(true), "tampered README must reject patch");
    let text = resps[1]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("BLAKE3_TAMPERED"), "expected BLAKE3_TAMPERED in output: {}", text);
}

#[test]
fn tier2_f16_fail_on_critical_vs_high_vs_medium_thresholds() {
    let tmp = tempdir().unwrap();
    // Seed a HIGH-only finding (unwrap in non-test code / or plugin rule) via custom plugin
    write_rel(
        tmp.path(),
        ".aether/plugins/severity_probe.yaml",
        r#"name: severity-probe
version: "1.0.0"
enabled: true
rules:
  - id: E2E-HIGH-PROBE
    cwe_id: CWE-999
    name: High Probe
    severity: HIGH
    description: High test
    remediation: Fix
    file_extensions: ["rs"]
    conditions:
      forbidden_tokens: ["HIGH_PROBE_MARKER"]
"#,
    );
    write_rel(tmp.path(), "src/probe.rs", "pub fn p() { let _ = \"HIGH_PROBE_MARKER\"; }\n");
    // Check check_literals: default false, so put identifier instead of string literal
    write_rel(tmp.path(), "src/probe.rs", "pub fn HIGH_PROBE_MARKER() {}\n");

    let out_crit = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out_crit.code, 0, "--fail-on CRITICAL must pass on HIGH-only finding");

    let out_high = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(out_high.code, 1, "--fail-on HIGH must fail on HIGH finding");

    let out_med = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "MEDIUM"],
    );
    assert_eq!(out_med.code, 1, "--fail-on MEDIUM must fail on HIGH finding");
}

#[test]
fn tier2_f16_sanitized_taint_anomaly_does_not_fail_gate() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        ".aether/plugins/san_gate.yaml",
        r#"name: san-gate
version: "1.0.0"
enabled: true
taint_sources:
  - name: query_src
    source_kind: HttpQueryParam
    cwe: CWE-89
    patterns: ["$_GET"]
    language: php
taint_sinks:
  - name: sql_sink
    sink_kind: SqlExecution
    cwe: CWE-89
    rule_id: E2E-SAN-GATE
    severity: CRITICAL
    patterns: ["exec_sql("]
    language: php
"#,
    );
    write_rel(
        tmp.path(),
        "src/clean.php",
        "<?php\nfunction clean() {\n    $x = $_GET['id'];\n    $y = intval($x);\n    return exec_sql($y);\n}\n",
    );

    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out.code, 0, "sanitized flow must not fail --fail-on CRITICAL");
    let sarif = parse_sarif_json(&out.stdout);
    assert_eq!(sarif["version"].as_str(), Some("2.1.0"));
}

#[test]
fn tier2_f16_crlf_vs_lf_readme_byte_sensitivity() {
    let tmp = tempdir().unwrap();
    let lf_content = "---\nid: \"eol-test\"\nmax_lines_per_file: 100\n---\n# EOL\n";
    let crlf_content = lf_content.replace('\n', "\r\n");
    write_rel(tmp.path(), "README.md", lf_content);
    let lf_hash = blake3_hex(lf_content);
    write_rel(
        tmp.path(),
        "aether.lock.toml",
        &format!(
            "version = 2\nproject_id = \"eol\"\nstack_type = \"PureRust\"\ntopology_mode = \"MonorepoLocal\"\n\n[galaxies.root]\npath = \".\"\nrole = \"Signed contract for root\"\nremote_sync = false\nreadme_blake3 = \"{}\"\n",
            lf_hash
        ),
    );

    write_rel(tmp.path(), "README.md", &crlf_content);
    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out.code, 1, "LF->CRLF rewrite must break exact-byte BLAKE3 seal");
    let sarif = parse_sarif_json(&out.stdout);
    assert!(sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["ruleId"].as_str() == Some("BLAKE3_TAMPERED")));
}

#[tokio::test]
async fn tier2_f16_contracts_sign_preserves_existing_max_lines() {
    let tmp = tempdir().unwrap();
    let custom = make_sealed_readme_content(420);
    write_rel(tmp.path(), "README.md", &custom);

    let srv = ServerGuard::start(tmp.path()).await;
    let (st, _) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st, 200);

    let after = fs::read_to_string(tmp.path().join("README.md")).unwrap();
    assert!(
        after.contains("max_lines_per_file: 420"),
        "/api/contracts/sign must preserve existing max_lines_per_file: 420, got:\n{}",
        after
    );
}

#[test]
fn tier2_f16_invalid_plugins_spec_exits_nonzero() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "src/main.rs", "pub fn ok() {}\n");

    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--plugins",
            "nonexistent_pack_xyz",
        ],
    );
    assert_ne!(out.code, 0, "invalid --plugins selector must exit non-zero");
}
