//! E2E-M1 Backend Pairwise & Real-World Scenarios (`e2e_suite_backend_scenarios.rs`)
//!
//! Covers:
//! - Tier 3 (`tier3_pair_*`): >= 8 cross-feature backend pairwise combinations (10 tests)
//! - Tier 4 (`tier4_scenario_*`): Scenarios 1–4 from `TEST_INFRA.md` (4 comprehensive E2E tests)

use ast_scanner::ProjectScanner;
use core_graph::manifest::ProjectManifest;
use obsidian_vault::{scan_obsidian_vault, PathGuard};
use security_linter::contract::ReadmeContract;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
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

fn runner_bin() -> &'static PathBuf {
    static RUNNER: OnceLock<PathBuf> = OnceLock::new();
    RUNNER.get_or_init(|| {
        let root = repo_root();
        let manifest = root.join("apps").join("aethercraft").join("runner").join("Cargo.toml");
        let status = Command::new("cargo")
            .arg("build")
            .arg("--manifest-path")
            .arg(&manifest)
            .status()
            .expect("cargo build aether-mc-runner");
        assert!(status.success(), "cargo build aether-mc-runner failed");

        let exe = if cfg!(windows) {
            "aether-mc-runner.exe"
        } else {
            "aether-mc-runner"
        };
        let bin = root
            .join("apps")
            .join("aethercraft")
            .join("runner")
            .join("target")
            .join("debug")
            .join(exe);
        assert!(bin.exists(), "built runner binary missing at {:?}", bin);
        bin
    })
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
            _child: ChildGuard { child },
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
                "aether-engine --no-gui on port {} did not become healthy",
                self.port
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn send_http_with_headers(
    port: u16,
    method: &str,
    path: &str,
    host_header: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Result<(u16, String), String> {
    let addr = format!("127.0.0.1:{}", port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("connect {}: {}", addr, e))?;

    let body_bytes = body
        .map(|v| serde_json::to_vec(v).expect("serialize JSON"))
        .unwrap_or_default();

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, path, host_header
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body_bytes.len()
        ));
    }
    req.push_str("\r\n");

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
        .ok_or_else(|| format!("invalid status line: {}", status_line))?;

    let decoded = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        decode_chunked_body(body_part)
    } else {
        body_part.to_string()
    };

    Ok((status, decoded))
}

async fn send_http(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, String), String> {
    let host = format!("127.0.0.1:{}", port);
    send_http_with_headers(port, method, path, &host, &[], body).await
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
    panic!("Failed to parse SARIF JSON:\n{}", raw);
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
    let guard = ChildGuard { child };

    let expected_responses = requests.iter().filter(|r| r.get("id").is_some()).count();
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

struct MockArtifactServer {
    port: u16,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicUsize>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockArtifactServer {
    fn start(payload: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicUsize::new(0));
        let req_c = requests.clone();
        let stop_c = stop.clone();

        let handle = thread::spawn(move || {
            while stop_c.load(Ordering::Relaxed) == 0 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        req_c.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf);
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(&payload);
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/server.jar", self.port)
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for MockArtifactServer {
    fn drop(&mut self) {
        self.stop.store(1, Ordering::SeqCst);
        let _ = StdTcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
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

// ============================================================================
// TIER 3 — Cross-Feature Backend Pairwise Tests (`>= 8` required; 10 implemented)
// ============================================================================

#[tokio::test]
async fn tier3_pair_f1_f3_task_lifecycle_http_and_mcp_sync() {
    let tmp = tempdir().unwrap();
    let _ = Command::new("git").args(["init"]).current_dir(tmp.path()).output();
    write_rel(tmp.path(), "src/app.rs", "pub fn ok() {}\n");

    let srv = ServerGuard::start(tmp.path()).await;
    let mcp_bin = find_aetherscope_mcp_bin();

    // Create task via MCP -> observe via HTTP GET /api/tasks & GET /api/git/status
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
                        "action": "create",
                        "path": tmp.path().to_string_lossy(),
                        "title": "Pairwise Sync Task",
                        "kind": "function"
                    }
                }
            }),
        ],
    );
    assert_ne!(resps[1]["result"]["isError"], json!(true));

    let (st_t, body_t) = send_http(srv.port, "GET", "/api/tasks", None).await.unwrap();
    assert_eq!(st_t, 200);
    let vt: Value = serde_json::from_str(&body_t).unwrap();
    assert_eq!(vt["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(vt["tasks"][0]["title"].as_str(), Some("Pairwise Sync Task"));

    let (st_g, body_g) = send_http(srv.port, "GET", "/api/git/status", None).await.unwrap();
    assert_eq!(st_g, 200);
    let vg: Value = serde_json::from_str(&body_g).unwrap();
    assert_eq!(vg["is_git_repo"], json!(true));
}

#[test]
fn tier3_pair_f2_f6_runner_and_path_guard_shared_traversal_defense() {
    let tmp = tempdir().unwrap();
    let guard = PathGuard::new(tmp.path()).unwrap();
    let mock = MockArtifactServer::start(b"JAR".to_vec());

    for bad_id in ["../escape", "..\\escape", "C:\\Windows\\Temp\\x", "\\\\srv\\share\\x", "sub/dir", "bad\0id"] {
        assert!(
            PathGuard::validate_client_relative_path(bad_id).is_err()
                || guard.resolve_and_verify(bad_id).is_err(),
            "PathGuard must reject '{}'",
            bad_id
        );

        let manifest_path = tmp.path().join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_string(&json!({
                "version": "1.0",
                "server_id": bad_id,
                "name": "Shared Defense",
                "runtime": { "java_major_version": 21 },
                "core": { "type": "paper", "mc_version": "1.21.1", "download_url": mock.url(), "sha256": "" }
            }))
            .unwrap(),
        )
        .unwrap();

        let out = Command::new(runner_bin())
            .current_dir(tmp.path())
            .args(["install", "--manifest", manifest_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!out.status.success(), "Runner must reject '{}'", bad_id);
    }
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn tier3_pair_f3_f16_contracts_update_reseals_and_invalidates_graph_cache() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", "---\nid: \"root\"\nmax_lines_per_file: 5\n---\n# Root\n");
    write_rel(
        tmp.path(),
        "src/mod_a.rs",
        "pub fn a1() {}\npub fn a2() {}\npub fn a3() {}\npub fn a4() {}\npub fn a5() {}\npub fn a6() {}\n",
    );

    let srv = ServerGuard::start(tmp.path()).await;
    let (_, gv1_body) = send_http(srv.port, "GET", "/api/graph/version", None).await.unwrap();
    let gv1 = serde_json::from_str::<Value>(&gv1_body).unwrap()["version"].as_u64().unwrap();

    // Update line budget from 5 -> 50 via HTTP (F3)
    let (st_up, up_body) = send_http(
        srv.port,
        "POST",
        "/api/contracts/update",
        Some(&json!({ "max_lines_per_file": 50 })),
    )
    .await
    .unwrap();
    assert_eq!(st_up, 200);
    let up_val: Value = serde_json::from_str(&up_body).unwrap();
    assert_eq!(up_val["effective_max_lines"].as_u64(), Some(50));

    let (_, gv2_body) = send_http(srv.port, "GET", "/api/graph/version", None).await.unwrap();
    let gv2 = serde_json::from_str::<Value>(&gv2_body).unwrap()["version"].as_u64().unwrap();
    assert!(gv2 > gv1, "graph_version must increment on contract update");

    // Verify F16 self-audit exits 0 with zero RULE_MAX_LINES or BLAKE3_TAMPERED
    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "WARNING"],
    );
    assert_eq!(out.code, 0, "updated + sealed contract must have 0 RULE_MAX_LINES and 0 BLAKE3_TAMPERED");
}

#[test]
fn tier3_pair_f4_f5_polyglot_scanner_with_declarative_taint_plugin() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        ".aether/plugins/polyglot_taint.yaml",
        r#"name: polyglot-taint
version: "1.0.0"
enabled: true
taint_sources:
  - name: py_form
    source_kind: HttpBodyParam
    cwe: CWE-78
    patterns: ["request.form"]
    language: py
taint_sinks:
  - name: os_cmd
    sink_kind: CommandExecution
    cwe: CWE-78
    rule_id: PAIR-F4-F5-CMD
    severity: CRITICAL
    patterns: ["subprocess.call("]
    language: py
"#,
    );
    // Do NOT put Cargo.toml so Python is scanned
    write_rel(
        tmp.path(),
        "src/worker.py",
        "def run_job(request, subprocess):\n    cmd = request.form\n    return subprocess.call(cmd)\n",
    );
    write_rel(tmp.path(), "src/helper.rs", "pub fn ok() {}\n");

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());
    assert!(graph.dataflow_graph.is_some(), "declarative taint plugin must populate dataflow_graph");

    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out.code, 1);
    let sarif = parse_sarif_json(&out.stdout);
    let res = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "PAIR-F4-F5-CMD")
        .expect("PAIR-F4-F5-CMD finding");
    assert_eq!(res["properties"]["is_reachable"], json!(true));
}

#[test]
fn tier3_pair_f4_f7_multi_language_budgets_and_tamper_contract() {
    let tmp = tempdir().unwrap();
    let readme = "---\nid: \"poly\"\nmax_lines_per_file: 4\nfile_max_lines:\n  bridge.php: 20\n---\n# Poly\n";
    write_rel(tmp.path(), "README.md", readme);
    let hash = ReadmeContract::compute_blake3_hex(readme);
    write_rel(
        tmp.path(),
        "aether.lock.toml",
        &format!(
            "version = 2\nproject_id = \"p\"\nstack_type = \"PureRust\"\ntopology_mode = \"MonorepoLocal\"\n\n[galaxies.root]\npath = \".\"\nrole = \"Signed contract for root\"\nremote_sync = false\nreadme_blake3 = \"{}\"\n",
            hash
        ),
    );
    write_rel(tmp.path(), "src/bridge.php", "<?php\nfunction a(){}\nfunction b(){}\nfunction c(){}\nfunction d(){}\nfunction e(){}\n");
    write_rel(tmp.path(), "src/over.ts", "export function t1(){}\nexport function t2(){}\nexport function t3(){}\nexport function t4(){}\nexport function t5(){}\n");

    // RULE_MAX_LINES on over.ts -> SARIF note, --fail-on HIGH exits 0
    let out1 = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(out1.code, 0);
    let s1 = parse_sarif_json(&out1.stdout);
    let r1 = s1["runs"][0]["results"].as_array().unwrap();
    assert!(r1.iter().any(|r| r["ruleId"] == "RULE_MAX_LINES" && r["level"] == "note"));
    assert!(!r1.iter().any(|r| r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .is_some_and(|u| u.ends_with("bridge.php"))));

    // Tamper README.md -> BLAKE3_TAMPERED CRITICAL -> --fail-on HIGH exits 1
    write_rel(tmp.path(), "README.md", "---\nid: \"poly\"\nmax_lines_per_file: 999\n---\n# Tampered\n");
    let out2 = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(out2.code, 1);
}

#[test]
fn tier3_pair_f5_f7_sanitized_vs_unsanitized_taint_gate() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        ".aether/plugins/pair_f5_f7.yaml",
        r#"name: pair-f5-f7
version: "1.0.0"
enabled: true
taint_sources:
  - name: get_src
    source_kind: HttpQueryParam
    cwe: CWE-89
    patterns: ["$_GET"]
    language: php
taint_sinks:
  - name: sql_sink
    sink_kind: SqlExecution
    cwe: CWE-89
    rule_id: PAIR-SQLI
    severity: HIGH
    patterns: ["exec_sql("]
    language: php
"#,
    );
    write_rel(
        tmp.path(),
        "src/safe_ep.php",
        "<?php\nfunction safe_ep() {\n    $a = $_GET['id'];\n    $b = intval($a);\n    return exec_sql($b);\n}\n",
    );
    write_rel(
        tmp.path(),
        "src/vuln_ep.php",
        "<?php\nfunction vuln_ep() {\n    $a = $_GET['name'];\n    return exec_sql($a);\n}\n",
    );

    let out_vuln = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(out_vuln.code, 1, "unsanitized branch must fail --fail-on HIGH");

    // Fix vuln_ep.php using intval()
    write_rel(
        tmp.path(),
        "src/vuln_ep.php",
        "<?php\nfunction vuln_ep() {\n    $a = $_GET['name'];\n    $c = intval($a);\n    return exec_sql($c);\n}\n",
    );
    let out_fixed = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(out_fixed.code, 0, "once all branches sanitized, --fail-on HIGH must exit 0");
}

#[test]
fn tier3_pair_f6_f7_vault_confinement_and_markdown_code_snippet_no_fp() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), ".obsidian/app.json", "{}");
    write_rel(
        tmp.path(),
        "README.md",
        "---\nid: \"vault\"\nmax_lines_per_file: 300\n---\n# Vault\n",
    );
    write_rel(
        tmp.path(),
        "Notes/SecurityNotes.md",
        "# Notes\n```rust\nstd::sync::Mutex::new(1); // .await\nCommand::new(\"git\").arg(x);\n```\nSee [[Index]]\n",
    );
    write_rel(tmp.path(), "Index.md", "# Index\n[[Notes/SecurityNotes]]\n");

    let guard = PathGuard::new(tmp.path()).unwrap();
    assert!(guard.resolve_and_verify("../outside.md").is_err());

    let vault_graph = scan_obsidian_vault(tmp.path()).expect("scan_obsidian_vault");
    assert!(vault_graph.nodes.iter().any(|n| n.name == "SecurityNotes" || n.name == "Notes" || n.file_path.contains("SecurityNotes.md")));

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let code_graph = scanner.scan_project(tmp.path());
    let sec_alerts: Vec<String> = code_graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .filter(|a| a.rule_id != "RULE_MAX_LINES")
        .map(|a| a.rule_id.clone())
        .collect();
    assert!(
        sec_alerts.is_empty(),
        "Markdown code examples must not trigger Rust SAST alerts: {:?}",
        sec_alerts
    );
}

#[tokio::test]
async fn tier3_pair_f3_f7_http_init_project_clean_self_audit() {
    let tmp = tempdir().unwrap();
    let srv = ServerGuard::start(tmp.path()).await;

    let (st, body) = send_http(
        srv.port,
        "POST",
        "/api/init_project",
        Some(&json!({
            "path": tmp.path().to_string_lossy(),
            "stack": "rust",
            "topology": "local"
        })),
    )
    .await
    .unwrap();
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"].as_str(), Some("ok"));

    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(
        out.code, 0,
        "freshly initialized project must pass --fail-on HIGH with 0 BLAKE3/SAST violations; stderr={}",
        out.stderr
    );
}

#[test]
fn tier3_pair_f4_f16_live_workspace_line_budgets_and_lockfile_alignment() {
    let root = repo_root();
    let manifest: ProjectManifest = toml::from_str(
        &fs::read_to_string(root.join("aether.lock.toml")).expect("read aether.lock.toml"),
    )
    .expect("parse aether.lock.toml");

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    for crate_rel in ["crates/ast-scanner", "crates/core-graph", "crates/obsidian-vault"] {
        assert!(
            manifest.galaxies.contains_key(crate_rel),
            "aether.lock.toml must seal {}",
            crate_rel
        );
        let graph = scanner.scan_project(root.join(crate_rel));
        let line_breaches: Vec<String> = graph
            .nodes
            .iter()
            .flat_map(|n| n.metadata.cve_anomalies.iter())
            .filter(|a| a.rule_id == "RULE_MAX_LINES")
            .map(|a| format!("{}: {}", a.file_path, a.message))
            .collect();
        assert!(
            line_breaches.is_empty(),
            "{} must have zero RULE_MAX_LINES violations: {:?}",
            crate_rel,
            line_breaches
        );
    }
}

#[tokio::test]
async fn tier3_pair_f1_f16_mcp_verify_patch_updates_task_on_clean_seal() {
    let tmp = tempdir().unwrap();
    let readme = "---\nid: \"root\"\nmax_lines_per_file: 200\n---\n# Root\n";
    write_rel(tmp.path(), "README.md", readme);
    write_rel(tmp.path(), "src/clean.rs", "pub fn safe_sum(a: i32, b: i32) -> i32 { a + b }\n");

    let srv = ServerGuard::start(tmp.path()).await;
    // Seal contract via HTTP
    let (st, _) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st, 200);

    let mcp_bin = find_aetherscope_mcp_bin();
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
                        "title": "Verify Clean Patch",
                        "kind": "function"
                    }
                }
            }),
        ],
    );
    assert_ne!(create_resps[1]["result"]["isError"], json!(true));
    let task_id = list_dir_names(&tmp.path().join(".aether").join("tasks"))
        .into_iter()
        .next()
        .unwrap();

    let verify_resps = run_mcp_session(
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
                    "name": "aetherscope_verify_patch",
                    "arguments": {
                        "path": tmp.path().to_string_lossy(),
                        "files_modified": ["src/clean.rs"],
                        "task_id": task_id,
                        "status": "done",
                        "progress": 100
                    }
                }
            }),
        ],
    );
    assert_ne!(verify_resps[1]["result"]["isError"], json!(true), "clean patch must be approved");

    let (_, tasks_body) = send_http(srv.port, "GET", "/api/tasks", None).await.unwrap();
    let vt: Value = serde_json::from_str(&tasks_body).unwrap();
    assert_eq!(vt["tasks"][0]["status"].as_str(), Some("done"));
    assert_eq!(vt["tasks"][0]["progress"].as_u64(), Some(100));
}

// ============================================================================
// TIER 4 — Real-World Application Scenarios 1–4 (`TEST_INFRA.md`)
// ============================================================================

#[test]
fn tier4_scenario_1_fresh_workspace_audit_remediate_sarif_gate() {
    let tmp = tempdir().unwrap();
    // 1. Seed workspace with: (a) CWE-667 async mutex, (b) RULE_MAX_LINES breach, (c) unsanitized taint flow
    write_rel(
        tmp.path(),
        ".aether/plugins/s1_taint.yaml",
        r#"name: s1-taint
version: "1.0.0"
enabled: true
taint_sources:
  - name: query_in
    source_kind: HttpQueryParam
    cwe: CWE-89
    patterns: ["$_GET"]
    language: php
taint_sinks:
  - name: sql_out
    sink_kind: SqlExecution
    cwe: CWE-89
    rule_id: S1-SQLI
    severity: HIGH
    patterns: ["run_sql("]
    language: php
"#,
    );
    write_rel(
        tmp.path(),
        "src/README.md",
        "---\nid: \"s1\"\nmax_lines_per_file: 6\n---\n# S1\n",
    );
    write_rel(
        tmp.path(),
        "src/lock_svc.rs",
        "use std::sync::Mutex;\npub async fn hold(m: &Mutex<i32>) { let _g = m.lock().unwrap(); tokio::task::yield_now().await; }\n",
    );
    write_rel(
        tmp.path(),
        "src/big.rs",
        "pub fn f1(){}\npub fn f2(){}\npub fn f3(){}\npub fn f4(){}\npub fn f5(){}\npub fn f6(){}\npub fn f7(){}\n",
    );
    write_rel(
        tmp.path(),
        "src/query.php",
        "<?php\nfunction ep() {\n    $id = $_GET['id'];\n    return run_sql($id);\n}\n",
    );

    // Phase A: Initial SARIF audit + --fail-on HIGH fails (exit 1) and detects all 3 issues
    let sarif_fail = tmp.path().join("fail.sarif");
    let out_fail = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--output",
            sarif_fail.to_str().unwrap(),
            "--fail-on",
            "HIGH",
        ],
    );
    assert_eq!(out_fail.code, 1);
    let sarif: Value = serde_json::from_str(&fs::read_to_string(&sarif_fail).unwrap()).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["ruleId"] == "CVE-RUST-ASYNC-MUTEX"));
    assert!(results.iter().any(|r| r["ruleId"] == "RULE_MAX_LINES"));
    assert!(results.iter().any(|r| r["ruleId"] == "S1-SQLI"));

    // Phase B: Remediate all 3 defects
    write_rel(
        tmp.path(),
        "src/lock_svc.rs",
        "pub async fn hold(m: &tokio::sync::Mutex<i32>) { let _g = m.lock().await; tokio::task::yield_now().await; }\n",
    );
    write_rel(tmp.path(), "src/big.rs", "pub fn f1(){}\npub fn f2(){}\npub fn f3(){}\n");
    write_rel(tmp.path(), "src/big_part2.rs", "pub fn f4(){}\npub fn f5(){}\npub fn f6(){}\npub fn f7(){}\n");
    write_rel(
        tmp.path(),
        "src/query.php",
        "<?php\nfunction ep() {\n    $id = $_GET['id'];\n    $safe = intval($id);\n    return run_sql($safe);\n}\n",
    );

    // Phase C: Re-run SARIF gate -> exits 0, and standard audit writes ARCH_OK
    let sarif_pass = tmp.path().join("pass.sarif");
    let out_pass = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--output",
            sarif_pass.to_str().unwrap(),
            "--fail-on",
            "HIGH",
        ],
    );
    assert_eq!(out_pass.code, 0, "remediated workspace must pass --fail-on HIGH");

    let out_md = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only"],
    );
    assert_eq!(out_md.code, 0);
    let live_audit = fs::read_to_string(tmp.path().join(".aether").join("LIVE_AUDIT.md")).unwrap();
    assert!(live_audit.contains("ARCH_OK"), "expected ARCH_OK in LIVE_AUDIT.md:\n{}", live_audit);
}

#[tokio::test]
async fn tier4_scenario_2_task_hygiene_and_mcp_lifecycle_without_pollution() {
    // 1. Assert live repository task hygiene
    let root = repo_root();
    let live_tasks_before = list_dir_names(&root.join(".aether").join("tasks"));
    assert!(
        !live_tasks_before.iter().any(|d| d.to_lowercase().contains("m8ven")),
        "live .aether/tasks must contain zero m8ven tasks"
    );
    assert_eq!(live_tasks_before.len(), 11, "11 preserved non-m8ven tasks expected");

    // 2. Run isolated MCP + HTTP task lifecycle inside tempdir
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "src/service.rs", "pub fn serve() -> &'static str { \"ok\" }\n");
    let srv = ServerGuard::start(tmp.path()).await;
    let mcp_bin = find_aetherscope_mcp_bin();

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
                        "action": "create",
                        "path": tmp.path().to_string_lossy(),
                        "title": "Scenario 2 Task",
                        "kind": "function",
                        "target_file": "src/service.rs"
                    }
                }
            }),
        ],
    );
    assert_ne!(resps[1]["result"]["isError"], json!(true));
    let tid = list_dir_names(&tmp.path().join(".aether").join("tasks"))
        .into_iter()
        .next()
        .expect("task created in tempdir");

    let lifecycle = run_mcp_session(
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
                        "action": "update",
                        "path": tmp.path().to_string_lossy(),
                        "task_id": tid,
                        "status": "in_progress",
                        "progress": 50
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_verify_patch",
                    "arguments": {
                        "path": tmp.path().to_string_lossy(),
                        "files_modified": ["src/service.rs"],
                        "task_id": tid,
                        "status": "done",
                        "progress": 100
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "aetherscope_manage_tasks",
                    "arguments": {
                        "action": "delete",
                        "path": tmp.path().to_string_lossy(),
                        "task_id": tid
                    }
                }
            }),
        ],
    );
    for r in &lifecycle[1..] {
        assert_ne!(r["result"]["isError"], json!(true), "lifecycle step failed: {:?}", r);
    }

    let live_tasks_after = list_dir_names(&root.join(".aether").join("tasks"));
    assert_eq!(live_tasks_before, live_tasks_after, "live .aether/tasks must remain untouched");
}

#[tokio::test]
async fn tier4_scenario_3_contract_seal_tamper_detect_and_resign_workflow() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        "README.md",
        "---\nid: \"root\"\nlayer: \"domain\"\nmax_lines_per_file: 120\n---\n# Root\n",
    );
    write_rel(tmp.path(), "src/domain.rs", "pub fn compute(v: i32) -> i32 { v * 2 }\n");

    let srv = ServerGuard::start(tmp.path()).await;

    // 1. Initial sign
    let (st1, b1) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st1, 200);
    let hash1 = serde_json::from_str::<Value>(&b1).unwrap()["blake3_hash"].as_str().unwrap().to_string();

    // 2. Clean audit
    let out1 = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out1.code, 0);

    // 3. Manual unauthorized edit to README.md
    write_rel(
        tmp.path(),
        "README.md",
        "---\nid: \"root\"\nlayer: \"domain\"\nmax_lines_per_file: 9999\n---\n# Edited Without Seal\n",
    );
    let out_tamper = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out_tamper.code, 1, "tampered README.md must trip CRITICAL gate");
    let sarif_tamper = parse_sarif_json(&out_tamper.stdout);
    assert!(sarif_tamper["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["ruleId"] == "BLAKE3_TAMPERED"));

    // 4. Re-seal via POST /api/contracts/sign
    let (st2, b2) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st2, 200);
    let v2: Value = serde_json::from_str(&b2).unwrap();
    let hash2 = v2["blake3_hash"].as_str().unwrap().to_string();
    assert_ne!(hash1, hash2, "re-sealed hash must reflect updated README.md");

    // 5. Audit returns clean & graph nodes report lock_verified
    let out_clean = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out_clean.code, 0);

    let (st_g, bg) = send_http(srv.port, "GET", "/api/graph", None).await.unwrap();
    assert_eq!(st_g, 200);
    let vg: Value = serde_json::from_str(&bg).unwrap();
    let readme_node = vg["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["file_path"] == json!("README.md") || n["name"] == json!("README.md"))
        .expect("README.md node");
    assert_eq!(readme_node["metadata"]["lock_verified"], json!(true));
}

#[tokio::test]
async fn tier4_scenario_4_adversarial_traversal_and_injection_defense() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", "---\nid: \"sec\"\nmax_lines_per_file: 300\n---\n# Sec\n");
    write_rel(
        tmp.path(),
        "src/defense.rs",
        r#"use std::path::{Path, PathBuf};
use std::process::Command;

pub fn safe_git_porcelain(repo: &Path) {
    let _ = Command::new("git").args(["status", "--porcelain"]).current_dir(repo).output();
}

pub fn safe_git_branch(repo: &Path, user_ref: &str) {
    let _ = Command::new("git").arg("show").arg("--").arg(user_ref).current_dir(repo).output();
}

pub fn validate_client_relative_path(rel: &str) -> Result<PathBuf, &'static str> {
    if rel.contains("..") || rel.starts_with('/') { return Err("bad"); }
    Ok(PathBuf::from(rel))
}

pub fn safe_join(root: &Path, rel: &str) -> std::io::Result<String> {
    let clean = validate_client_relative_path(rel).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    std::fs::read_to_string(root.join(clean))
}
"#,
    );

    // 1. PathGuard blocks all adversarial lexical & outside escapes
    let guard = PathGuard::new(tmp.path()).unwrap();
    for attack in ["../secret", "..\\secret", "/etc/passwd", "\\\\server\\share\\x", "C:\\Windows\\win.ini", "file:///etc/passwd", "a\0b.md"] {
        assert!(PathGuard::validate_client_relative_path(attack).is_err());
    }
    write_rel(outside.path(), "outside.txt", "sensitive");
    assert!(guard.resolve_and_verify(&outside.path().join("outside.txt")).is_err());

    // 2. Runner blocks traversal server_id before touching network or disk
    let mock = MockArtifactServer::start(b"NO".to_vec());
    let m_path = tmp.path().join("evil_manifest.json");
    fs::write(
        &m_path,
        serde_json::to_string(&json!({
            "version": "1.0",
            "server_id": "../../outside_srv",
            "name": "Evil",
            "runtime": { "java_major_version": 21 },
            "core": { "type": "paper", "mc_version": "1.21.1", "download_url": mock.url(), "sha256": "" }
        }))
        .unwrap(),
    )
    .unwrap();
    let r_out = Command::new(runner_bin())
        .current_dir(tmp.path())
        .args(["install", "--manifest", m_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!r_out.status.success());
    assert_eq!(mock.request_count(), 0);
    assert!(!outside.path().join("outside_srv").exists());

    // 3. HTTP server blocks LocalGuard foreign Origin/Host AND contract traversal escapes
    let srv = ServerGuard::start(tmp.path()).await;
    let valid_host = format!("127.0.0.1:{}", srv.port);
    let (st_lg, _) = send_http_with_headers(
        srv.port,
        "GET",
        "/api/health",
        &valid_host,
        &[("Origin", "https://attacker.invalid")],
        None,
    )
    .await
    .unwrap();
    assert_eq!(st_lg, 403);

    let (st_cu, _) = send_http(
        srv.port,
        "POST",
        "/api/contracts/update",
        Some(&json!({ "folder": "../../escape", "max_lines_per_file": 10 })),
    )
    .await
    .unwrap();
    assert!(st_cu == 400 || st_cu == 403, "expected 400/403 on contract traversal, got {}", st_cu);

    let (st_cs, _) = send_http(
        srv.port,
        "POST",
        "/api/contracts/sign",
        Some(&json!({ "project_path": outside.path().to_string_lossy() })),
    )
    .await
    .unwrap();
    assert!(st_cs == 400 || st_cs == 403, "expected 400/403 on contract sign escape, got {}", st_cs);

    // 4. SecurityLinter / CLI audit reports ZERO false positives on the defending code
    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "HIGH"],
    );
    assert_eq!(out.code, 0, "defending patterns must incur zero HIGH/CRITICAL SAST false positives");
}
