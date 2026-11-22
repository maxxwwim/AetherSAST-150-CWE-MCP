//! E2E-M1 Security & SAST Suite (`e2e_suite_security.rs`)
//!
//! Opaque-box, requirement-driven tests covering:
//! - F2: `apps/aethercraft/runner` (`aether-mc-runner`) `server_id` path confinement (AETHER-PATH-008)
//! - F3: `desktop-shell` HTTP API routes, LocalGuard, contract PathGuard, concurrency & SAST fixes
//! - F7: `security-linter` CWE precision, zero false positives, SARIF v2.1.0, `--fail-on` & contracts
//!
//! Naming convention: `tier1_f<N>_*`, `tier2_f<N>_*` for `-- tier1_` / `-- tier2_` filtering.

use ast_scanner::ProjectScanner;
use security_linter::contract::ReadmeContract;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
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
                        if stop_c.load(Ordering::SeqCst) != 0 {
                            break;
                        }
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0u8; 2048];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        if n > 0 {
                            req_c.fetch_add(1, Ordering::SeqCst);
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                payload.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(&payload);
                            let _ = stream.flush();
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                        }
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

fn write_runner_manifest(path: &Path, server_id: &str, download_url: &str) {
    let manifest = json!({
        "version": "1.0",
        "server_id": server_id,
        "name": "E2E Test Server",
        "runtime": { "java_major_version": 21 },
        "core": {
            "type": "paper",
            "mc_version": "1.21.1",
            "target_jar": "server.jar",
            "download_url": download_url,
            "sha256": ""
        }
    });
    fs::write(path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
}

struct CliOutput {
    code: i32,
    stdout: String,
    #[allow(dead_code)]
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

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap().flatten() {
        let p = entry.path();
        let name = entry.file_name();
        if name == "target" || name == ".aether" || name == ".git" {
            continue;
        }
        let target = dst.join(&name);
        if p.is_dir() {
            copy_dir_recursive(&p, &target);
        } else {
            fs::copy(&p, &target).unwrap();
        }
    }
}

// ============================================================================
// F2 — `apps/aethercraft/runner` Path Confinement & CLI (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f2_valid_server_id_installs_into_instances_subdir() {
    let tmp = tempdir().unwrap();
    let mock = MockArtifactServer::start(b"MOCK_JAR_PAYLOAD_V1".to_vec());
    let manifest_path = tmp.path().join("manifest.json");
    write_runner_manifest(&manifest_path, "survival-01", &mock.url());

    let out = Command::new(runner_bin())
        .current_dir(tmp.path())
        .args(["install", "--manifest", manifest_path.to_str().unwrap()])
        .output()
        .expect("run runner install");

    assert!(
        out.status.success(),
        "valid install failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let jar = tmp.path().join("instances").join("survival-01").join("server.jar");
    assert!(jar.is_file(), "server.jar must exist at {:?}", jar);
    assert_eq!(fs::read(&jar).unwrap(), b"MOCK_JAR_PAYLOAD_V1");
    assert!(tmp.path().join("instances").join("survival-01").join(".aether-manifest.json").is_file());
    assert_eq!(mock.request_count(), 1);
}

#[test]
fn tier1_f2_valid_alnum_dash_underscore_server_ids() {
    let mock = MockArtifactServer::start(b"JAR".to_vec());
    for id in ["mc-prod_01", "lobby1"] {
        let tmp = tempdir().unwrap();
        let manifest_path = tmp.path().join("manifest.json");
        write_runner_manifest(&manifest_path, id, &mock.url());
        let out = Command::new(runner_bin())
            .current_dir(tmp.path())
            .args(["install", "--manifest", manifest_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success(), "server_id '{}' should succeed", id);
        assert!(tmp.path().join("instances").join(id).join("server.jar").is_file());
    }
}

#[test]
fn tier1_f2_explicit_dir_flag_installs_to_target() {
    let tmp = tempdir().unwrap();
    let mock = MockArtifactServer::start(b"CUSTOM_DIR_JAR".to_vec());
    let manifest_path = tmp.path().join("manifest.json");
    let custom_dir = tmp.path().join("custom_srv");
    write_runner_manifest(&manifest_path, "ignored-default", &mock.url());

    let out = Command::new(runner_bin())
        .current_dir(tmp.path())
        .args([
            "install",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--dir",
            custom_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(custom_dir.join("server.jar").is_file());
    assert!(!tmp.path().join("instances").exists());
}

#[test]
fn tier1_f2_doctor_subcommand_runs() {
    let tmp = tempdir().unwrap();
    let out = Command::new(runner_bin())
        .current_dir(tmp.path())
        .arg("doctor")
        .output()
        .expect("run runner doctor");
    assert!(
        out.status.success(),
        "doctor exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Diagnostic"), "unexpected doctor output: {}", stdout);
}

#[test]
fn tier1_f2_cargo_test_runner_passes() {
    let manifest = repo_root().join("apps").join("aethercraft").join("runner").join("Cargo.toml");
    let out = Command::new("cargo")
        .args(["test", "--manifest-path", manifest.to_str().unwrap()])
        .output()
        .expect("cargo test runner");
    assert!(
        out.status.success(),
        "runner unit tests failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn tier2_f2_rejects_parent_traversal_server_id() {
    let mock = MockArtifactServer::start(b"SHOULD_NOT_FETCH".to_vec());
    for bad_id in ["../pwned", "..\\pwned", "a/../../pwned"] {
        let tmp = tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let manifest_path = work.join("manifest.json");
        write_runner_manifest(&manifest_path, bad_id, &mock.url());

        for subcmd in ["install", "install-and-run"] {
            let out = Command::new(runner_bin())
                .current_dir(&work)
                .args([subcmd, "--manifest", manifest_path.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                !out.status.success(),
                "{} with traversal server_id '{}' MUST fail",
                subcmd,
                bad_id
            );
            assert!(
                !tmp.path().join("pwned").exists(),
                "traversal server_id '{}' created escaped directory!",
                bad_id
            );
            assert!(
                !work.join("instances").exists(),
                "traversal server_id '{}' created instances/ before rejecting!",
                bad_id
            );
        }
    }
    assert_eq!(mock.request_count(), 0, "rejected server_id must not trigger network fetch");
}

#[test]
fn tier2_f2_rejects_absolute_and_unc_server_id() {
    let mock = MockArtifactServer::start(b"NO".to_vec());
    let outside = tempdir().unwrap();
    let abs_escape = outside.path().join("escaped_abs").to_string_lossy().into_owned();

    let mut bad_ids = vec![
        "/tmp/e2e_pwned".to_string(),
        "C:\\Windows\\Temp\\e2e_pwn".to_string(),
        "\\\\server\\share\\e2e_pwn".to_string(),
        "\\\\?\\C:\\e2e_pwn".to_string(),
        abs_escape,
    ];
    for bad_id in bad_ids.drain(..) {
        let tmp = tempdir().unwrap();
        let manifest_path = tmp.path().join("manifest.json");
        write_runner_manifest(&manifest_path, &bad_id, &mock.url());

        let out = Command::new(runner_bin())
            .current_dir(tmp.path())
            .args(["install", "--manifest", manifest_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "absolute/UNC server_id '{}' MUST fail",
            bad_id
        );
        assert!(
            !outside.path().join("escaped_abs").exists(),
            "absolute server_id created outside directory!"
        );
    }
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn tier2_f2_rejects_multi_segment_server_id() {
    let mock = MockArtifactServer::start(b"NO".to_vec());
    for bad_id in ["foo/bar", "foo\\bar", "./sub"] {
        let tmp = tempdir().unwrap();
        let manifest_path = tmp.path().join("manifest.json");
        write_runner_manifest(&manifest_path, bad_id, &mock.url());

        let out = Command::new(runner_bin())
            .current_dir(tmp.path())
            .args(["install", "--manifest", manifest_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "multi-segment server_id '{}' must be rejected (single Component::Normal required)",
            bad_id
        );
    }
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn tier2_f2_rejects_dot_empty_and_null_server_id() {
    let mock = MockArtifactServer::start(b"NO".to_vec());
    for bad_id in ["", ".", "..", "   ", "bad\0id"] {
        let tmp = tempdir().unwrap();
        let manifest_path = tmp.path().join("manifest.json");
        write_runner_manifest(&manifest_path, bad_id, &mock.url());

        let out = Command::new(runner_bin())
            .current_dir(tmp.path())
            .args(["install", "--manifest", manifest_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "degenerate server_id {:?} must be rejected",
            bad_id
        );
    }
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn tier2_f2_audit_runner_zero_path_008() {
    let runner_dir = repo_root().join("apps").join("aethercraft").join("runner");
    let tmp = tempdir().unwrap();
    let copy_dir = tmp.path().join("runner_copy");
    copy_dir_recursive(&runner_dir, &copy_dir);

    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            copy_dir.to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
        ],
    );
    assert_eq!(out.code, 0);
    let sarif = parse_sarif_json(&out.stdout);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let path_008: Vec<&Value> = results
        .iter()
        .filter(|r| r["ruleId"].as_str() == Some("AETHER-RUST-PATH-JOIN-PREFIX-WIPE"))
        .collect();
    assert!(
        path_008.is_empty(),
        "apps/aethercraft/runner must have zero AETHER-PATH-008 findings after F2 fix: {:?}",
        path_008
    );
}

// ============================================================================
// F3 — `desktop-shell` SAST, Concurrency, Git, PathGuard & Contracts (Tier 1 & 2)
// ============================================================================

#[tokio::test]
async fn tier1_f3_git_status_real_temp_repo() {
    let tmp = tempdir().unwrap();
    assert!(Command::new("git").args(["init"]).current_dir(tmp.path()).output().unwrap().status.success());
    assert!(Command::new("git").args(["config", "user.email", "e2e@example.com"]).current_dir(tmp.path()).output().unwrap().status.success());
    assert!(Command::new("git").args(["config", "user.name", "E2E"]).current_dir(tmp.path()).output().unwrap().status.success());

    write_rel(tmp.path(), "src/tracked.rs", "pub fn v1() {}\n");
    assert!(Command::new("git").args(["add", "--", "src/tracked.rs"]).current_dir(tmp.path()).output().unwrap().status.success());
    assert!(Command::new("git").args(["commit", "-m", "init"]).current_dir(tmp.path()).output().unwrap().status.success());

    // Modify tracked + create untracked
    write_rel(tmp.path(), "src/tracked.rs", "pub fn v2() {}\n");
    write_rel(tmp.path(), "src/untracked.rs", "pub fn u() {}\n");

    let srv = ServerGuard::start(tmp.path()).await;
    let (st, body) = send_http(srv.port, "GET", "/api/git/status", None).await.unwrap();
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["is_git_repo"], json!(true));
    assert_eq!(v["clean"], json!(false));
    assert!(v["modified_count"].as_u64().unwrap() >= 1);
    assert!(v["untracked_count"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn tier1_f3_contracts_sign_seals_blake3() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        "README.md",
        "---\nid: \"root\"\nmax_lines_per_file: 250\n---\n# Root\n",
    );
    write_rel(tmp.path(), "src/lib.rs", "pub fn ok() {}\n");

    let srv = ServerGuard::start(tmp.path()).await;
    let (st, body) = send_http(srv.port, "POST", "/api/contracts/sign", Some(&json!({}))).await.unwrap();
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"].as_str(), Some("ok"));
    assert!(v["signed_count"].as_u64().unwrap() >= 1);
    assert!(v["blake3_hash"].as_str().is_some_and(|s| s.len() == 64));
    assert!(tmp.path().join("aether.lock.toml").is_file());

    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif"],
    );
    let sarif = parse_sarif_json(&out.stdout);
    assert!(!sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["ruleId"].as_str() == Some("BLAKE3_TAMPERED")));
}

#[tokio::test]
async fn tier1_f3_contracts_update_preserves_and_updates() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", "---\nid: \"root\"\nmax_lines_per_file: 300\n---\n# Root\n");
    write_rel(tmp.path(), "src/app.rs", "pub fn ok() {}\n");

    let srv = ServerGuard::start(tmp.path()).await;
    let (st1, b1) = send_http(
        srv.port,
        "POST",
        "/api/contracts/update",
        Some(&json!({ "max_lines_per_file": 420 })),
    )
    .await
    .unwrap();
    assert_eq!(st1, 200);
    let v1: Value = serde_json::from_str(&b1).unwrap();
    assert_eq!(v1["status"].as_str(), Some("ok"));
    assert_eq!(v1["contract_path"].as_str(), Some("README.md"));
    assert_eq!(v1["effective_max_lines"].as_u64(), Some(420));
    assert!(v1["blake3_hash"].as_str().is_some_and(|s| s.len() == 64));

    // Update per-file override without sending max_lines_per_file -> folder budget 420 preserved
    let (st2, b2) = send_http(
        srv.port,
        "POST",
        "/api/contracts/update",
        Some(&json!({ "file_path": "src/app.rs", "file_max_lines": 550 })),
    )
    .await
    .unwrap();
    assert_eq!(st2, 200);
    let v2: Value = serde_json::from_str(&b2).unwrap();
    assert_eq!(v2["status"].as_str(), Some("ok"));
    assert_eq!(v2["effective_max_lines"].as_u64(), Some(550));
    let readme = fs::read_to_string(tmp.path().join("README.md")).unwrap();
    assert!(readme.contains("max_lines_per_file: 420"), "folder budget 420 must be preserved");
}

#[tokio::test]
async fn tier1_f3_init_project_scaffolds_and_seals() {
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
    assert!(!v["created_dirs"].as_array().unwrap().is_empty());
    assert!(tmp.path().join("aether.lock.toml").is_file());
}

#[tokio::test]
async fn tier1_f3_tasks_and_files_and_graph_roundtrip() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "src/main.rs", "pub fn alpha() {}\n");
    let srv = ServerGuard::start(tmp.path()).await;

    let (st_f, b_f) = send_http(srv.port, "GET", "/api/files", None).await.unwrap();
    assert_eq!(st_f, 200);
    let vf: Value = serde_json::from_str(&b_f).unwrap();
    assert!(vf["files"].as_array().unwrap().iter().any(|f| {
        f["path"].as_str().is_some_and(|p| p.replace('\\', "/").ends_with("src/main.rs"))
    }));

    let (st_g, b_g) = send_http(srv.port, "GET", "/api/graph", None).await.unwrap();
    assert_eq!(st_g, 200);
    let vg: Value = serde_json::from_str(&b_g).unwrap();
    assert!(!vg["nodes"].as_array().unwrap().is_empty());

    let (_, bc) = send_http(
        srv.port,
        "POST",
        "/api/tasks",
        Some(&json!({ "title": "Roundtrip Task", "kind": "test" })),
    )
    .await
    .unwrap();
    let vc: Value = serde_json::from_str(&bc).unwrap();
    let tid = vc["task"]["id"].as_str().unwrap().to_string();

    let (_, bl) = send_http(srv.port, "GET", "/api/tasks", None).await.unwrap();
    let vl: Value = serde_json::from_str(&bl).unwrap();
    assert_eq!(vl["tasks"].as_array().unwrap().len(), 1);

    let (_, bd) = send_http(srv.port, "POST", "/api/tasks/delete", Some(&json!({ "task_id": tid })))
        .await
        .unwrap();
    let vd: Value = serde_json::from_str(&bd).unwrap();
    assert_eq!(vd["deleted"], json!(true));
}

#[tokio::test]
async fn tier2_f3_contracts_update_rejects_traversal_and_absolute() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", "---\nid: \"root\"\nmax_lines_per_file: 300\n---\n# Root\n");

    let srv = ServerGuard::start(tmp.path()).await;

    let payloads = vec![
        json!({ "folder": "../../outside", "max_lines_per_file": 123 }),
        json!({ "file_path": "../../evil.rs", "file_max_lines": 123 }),
        json!({ "project_path": outside.path().to_string_lossy(), "max_lines_per_file": 123 }),
        json!({ "folder": "C:\\Windows\\Temp\\pwn", "max_lines_per_file": 123 }),
    ];

    for p in payloads {
        let (st, _body) = send_http(srv.port, "POST", "/api/contracts/update", Some(&p))
            .await
            .unwrap();
        assert!(
            st == 400 || st == 403,
            "traversal/escaped /api/contracts/update ({}) must return HTTP 400 or 403, got {}",
            p,
            st
        );
    }

    assert!(!outside.path().join("README.md").exists());
    assert!(!outside.path().join("aether.lock.toml").exists());
}

#[tokio::test]
async fn tier2_f3_contracts_sign_rejects_escaped_project_path_and_folder() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    write_rel(outside.path(), "README.md", "---\nid: \"ext\"\nmax_lines_per_file: 100\n---\n# Ext\n");
    write_rel(tmp.path(), "README.md", "---\nid: \"root\"\nmax_lines_per_file: 300\n---\n# Root\n");

    let srv = ServerGuard::start(tmp.path()).await;

    let (st1, _) = send_http(
        srv.port,
        "POST",
        "/api/contracts/sign",
        Some(&json!({ "project_path": outside.path().to_string_lossy() })),
    )
    .await
    .unwrap();
    assert!(
        st1 == 400 || st1 == 403,
        "escaped project_path in /api/contracts/sign must return 400/403, got {}",
        st1
    );
    assert!(
        !outside.path().join("aether.lock.toml").exists(),
        "outside aether.lock.toml must not be created"
    );

    let (st2, _) = send_http(
        srv.port,
        "POST",
        "/api/contracts/sign",
        Some(&json!({ "folder": "../escape" })),
    )
    .await
    .unwrap();
    assert!(
        st2 == 400 || st2 == 403,
        "traversal folder in /api/contracts/sign must return 400/403, got {}",
        st2
    );
}

#[tokio::test]
async fn tier2_f3_local_guard_rejects_foreign_origin_and_bad_host() {
    let tmp = tempdir().unwrap();
    let srv = ServerGuard::start(tmp.path()).await;
    let valid_host = format!("127.0.0.1:{}", srv.port);

    let (st_origin, _) = send_http_with_headers(
        srv.port,
        "GET",
        "/api/health",
        &valid_host,
        &[("Origin", "https://evil.example")],
        None,
    )
    .await
    .unwrap();
    assert_eq!(st_origin, 403, "foreign Origin must return 403 Forbidden");

    let (st_sfs, _) = send_http_with_headers(
        srv.port,
        "GET",
        "/api/health",
        &valid_host,
        &[("Sec-Fetch-Site", "cross-site")],
        None,
    )
    .await
    .unwrap();
    assert_eq!(st_sfs, 403, "cross-site Sec-Fetch-Site must return 403 Forbidden");

    let (st_host, _) = send_http_with_headers(
        srv.port,
        "GET",
        "/api/health",
        "evil.example:80",
        &[],
        None,
    )
    .await
    .unwrap();
    assert_eq!(st_host, 403, "non-local Host header must return 403 Forbidden");
}

#[tokio::test]
async fn tier2_f3_concurrent_git_status_and_contracts_no_deadlock() {
    let tmp = tempdir().unwrap();
    let _ = Command::new("git").args(["init"]).current_dir(tmp.path()).output();
    write_rel(tmp.path(), "README.md", "---\nid: \"root\"\nmax_lines_per_file: 300\n---\n# Root\n");
    write_rel(tmp.path(), "src/main.rs", "pub fn ok() {}\n");

    let srv = ServerGuard::start(tmp.path()).await;
    let port = srv.port;

    let mut handles = Vec::new();
    for i in 0..20usize {
        handles.push(tokio::spawn(async move {
            let res = match i % 4 {
                0 => send_http(port, "GET", "/api/git/status", None).await,
                1 => send_http(port, "POST", "/api/contracts/sign", Some(&json!({}))).await,
                2 => send_http(port, "GET", "/api/graph", None).await,
                _ => send_http(port, "GET", "/api/health", None).await,
            };
            let (st, _) = res.expect("concurrent HTTP request must succeed");
            assert_eq!(st, 200);
        }));
    }

    for h in handles {
        tokio::time::timeout(Duration::from_secs(20), h)
            .await
            .expect("concurrent load timed out (possible Mutex deadlock)")
            .expect("task join");
    }
}

#[test]
fn tier2_f3_sarif_self_audit_zero_f3_cwe_alerts() {
    let tmp = tempdir().unwrap();
    let sarif_out = tmp.path().join("f3_check.sarif");
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
    assert_eq!(out.code, 0);

    let sarif: Value = serde_json::from_str(&fs::read_to_string(&sarif_out).unwrap()).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    let target_rules = [
        "CVE-RUST-ASYNC-MUTEX",
        "CVE-INJ-POSIX-FLAG-SMUGGLING",
        "AETHER-RUST-PATH-JOIN-PREFIX-WIPE",
        "AETHER-RUST-UTF8-LOSSY-SMUGGLING",
    ];

    let hits: Vec<String> = results
        .iter()
        .filter_map(|r| {
            let rid = r["ruleId"].as_str().unwrap_or("");
            let uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap_or("");
            if target_rules.contains(&rid) && uri.starts_with("crates/desktop-shell/src/") {
                Some(format!("{} in {}", rid, uri))
            } else {
                None
            }
        })
        .collect();

    assert!(
        hits.is_empty(),
        "crates/desktop-shell/src must have zero F3 CWE alerts after M1 remediation: {:?}",
        hits
    );
}

// ============================================================================
// F7 — `security-linter` Precision, Zero FP, SARIF & Contracts (Tier 1 & 2)
// ============================================================================

#[test]
fn tier1_f7_detect_true_positive_cwes() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        "src/async_lock.rs",
        r#"use std::sync::Mutex;
pub async fn bad_lock(m: &Mutex<u32>) {
    let _g = m.lock().unwrap();
    tokio::task::yield_now().await;
}
"#,
    );
    write_rel(
        tmp.path(),
        "src/git_dyn.rs",
        r#"use std::process::Command;
pub fn bad_git(user_branch: &str) {
    let _ = Command::new("git").arg(user_branch).output();
}
"#,
    );
    write_rel(
        tmp.path(),
        "src/upload.rs",
        r#"use std::path::Path;
pub fn bad_read(upload_dir: &Path, user_filename: &str) -> std::io::Result<String> {
    let p = upload_dir.join(user_filename);
    std::fs::read_to_string(&p)
}
"#,
    );

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let rule_ids: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .map(|a| a.rule_id.clone())
        .collect();

    assert!(rule_ids.iter().any(|r| r == "CVE-RUST-ASYNC-MUTEX"), "missing CWE-667 TP: {:?}", rule_ids);
    assert!(rule_ids.iter().any(|r| r == "CVE-INJ-POSIX-FLAG-SMUGGLING"), "missing CWE-88 TP: {:?}", rule_ids);
    assert!(rule_ids.iter().any(|r| r == "AETHER-RUST-PATH-JOIN-PREFIX-WIPE"), "missing AETHER-PATH-008 TP: {:?}", rule_ids);
}

#[test]
fn tier1_f7_zero_false_positives_on_clean_f7_patterns() {
    let tmp = tempdir().unwrap();
    // 1. Vec::push on `bases` and `sampled_md_paths` alongside Path::new / fs::
    // 2. Self::validate_client_relative_path without literal `PathGuard` token in fn
    // 3. Static literal Command::new("git").args(["status", "--porcelain"]) without `--`
    // 4. tokio::sync::Mutex across .await
    write_rel(
        tmp.path(),
        "src/clean_patterns.rs",
        r#"use std::path::{Path, PathBuf};
use std::process::Command;

pub fn collect_bases(user_label: &str) -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();
    let _ = Path::new(user_label);
    bases.push(PathBuf::from("safe_root"));
    bases
}

pub fn sample_notes(user_dir: &Path) -> Vec<PathBuf> {
    let mut sampled_md_paths: Vec<PathBuf> = Vec::new();
    let _ = std::fs::metadata(user_dir);
    sampled_md_paths.push(user_dir.to_path_buf());
    sampled_md_paths
}

pub fn validate_client_relative_path(input: &str) -> Result<PathBuf, &'static str> {
    if input.contains("..") || input.starts_with('/') {
        return Err("bad");
    }
    Ok(PathBuf::from(input))
}

pub fn safe_join_via_validator(root: &Path, user_rel: &str) -> std::io::Result<String> {
    let clean = validate_client_relative_path(user_rel).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let target = root.join(clean);
    std::fs::read_to_string(&target)
}

pub fn static_git_porcelain(repo: &Path) {
    let _ = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .output();
}

pub async fn safe_async_lock(m: &tokio::sync::Mutex<u32>) {
    let _g = m.lock().await;
    tokio::task::yield_now().await;
}
"#,
    );

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let fps: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .filter(|a| {
            matches!(
                a.rule_id.as_str(),
                "AETHER-RUST-PATH-JOIN-PREFIX-WIPE"
                    | "CVE-INJ-POSIX-FLAG-SMUGGLING"
                    | "CVE-RUST-ASYNC-MUTEX"
            )
        })
        .map(|a| format!("{} L{}: {}", a.rule_id, a.line_number, a.message))
        .collect();

    assert!(
        fps.is_empty(),
        "clean F7 patterns must yield zero false positives, got: {:?}",
        fps
    );
}

#[test]
fn tier1_f7_blake3_tampered_cwe_353_detection() {
    let tmp = tempdir().unwrap();
    let sealed = "---\nid: \"root\"\nmax_lines_per_file: 200\n---\n# Sealed\n";
    write_rel(tmp.path(), "README.md", sealed);
    let h = ReadmeContract::compute_blake3_hex(sealed);
    write_rel(
        tmp.path(),
        "aether.lock.toml",
        &format!(
            "version = 2\nproject_id = \"t\"\nstack_type = \"PureRust\"\ntopology_mode = \"MonorepoLocal\"\n\n[galaxies.root]\npath = \".\"\nrole = \"Signed contract for root\"\nremote_sync = false\nreadme_blake3 = \"{}\"\n",
            h
        ),
    );
    // Flip 1 byte
    write_rel(tmp.path(), "README.md", "---\nid: \"root\"\nmax_lines_per_file: 201\n---\n# Sealed\n");

    let out = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--format", "sarif", "--fail-on", "CRITICAL"],
    );
    assert_eq!(out.code, 1);
    let sarif = parse_sarif_json(&out.stdout);
    assert!(sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["ruleId"].as_str() == Some("BLAKE3_TAMPERED")
            && r["properties"]["cveId"].as_str().is_some_and(|c| c.contains("CWE-353"))));
}

#[test]
fn tier1_f7_sarif_v2_1_0_schema_and_level_mapping() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", "---\nid: \"s\"\nmax_lines_per_file: 2\n---\n# S\n");
    write_rel(
        tmp.path(),
        "src/bad.rs",
        "use std::sync::Mutex;\npub async fn lock_bad(m: &Mutex<i32>) {\n    let _g = m.lock().unwrap();\n    tokio::task::yield_now().await;\n}\n",
    );

    let sarif_path = tmp.path().join("out.sarif");
    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--output",
            sarif_path.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, 0);

    let sarif: Value = serde_json::from_str(&fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"].as_str(), Some("2.1.0"));
    assert_eq!(
        sarif["$schema"].as_str(),
        Some("https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json")
    );
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"].as_str(), Some("AetherScope"));
    assert!(sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len() >= 150);

    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["ruleId"] == "CVE-RUST-ASYNC-MUTEX" && r["level"] == "error"));
    assert!(results.iter().any(|r| r["ruleId"] == "RULE_MAX_LINES" && r["level"] == "note"));
    for r in results {
        let uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.contains('\\'), "SARIF URI must use forward slashes: {}", uri);
    }
}

#[test]
fn tier1_f7_cli_fail_on_severity_thresholds() {
    let tmp = tempdir().unwrap();
    write_rel(tmp.path(), "README.md", "---\nid: \"w\"\nmax_lines_per_file: 2\n---\n# W\n");
    write_rel(tmp.path(), "src/three.rs", "pub fn a() {}\npub fn b() {}\npub fn c() {}\n");

    let crit = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--fail-on", "CRITICAL"],
    );
    assert_eq!(crit.code, 0, "WARNING only must pass --fail-on CRITICAL");

    let high = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--fail-on", "HIGH"],
    );
    assert_eq!(high.code, 0, "WARNING only must pass --fail-on HIGH");

    let warn = run_audit_cli(
        tmp.path(),
        &["--path", tmp.path().to_str().unwrap(), "--audit-only", "--fail-on", "WARNING"],
    );
    assert_eq!(warn.code, 1, "RULE_MAX_LINES WARNING must fail --fail-on WARNING");
}

#[test]
fn tier2_f7_comments_and_string_literals_masked_no_fp() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        "src/docs_only.rs",
        r#"// std::sync::Mutex held across .await is dangerous
/* Command::new("git").arg(user_branch) without "--" */
pub async fn explain_only() -> &'static str {
    tokio::task::yield_now().await;
    "let _ = std::sync::Mutex::new(1); Command::new(\"git\").arg(user_input)"
}
"#,
    );

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let cwes: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .filter(|a| a.rule_id != "RULE_MAX_LINES")
        .map(|a| a.rule_id.clone())
        .collect();
    assert!(
        cwes.is_empty(),
        "comments/string literals must not trigger SAST CWEs: {:?}",
        cwes
    );
}

#[test]
fn tier2_f7_cwe88_with_posix_dash_guard_accepted() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        "src/git_safe.rs",
        r#"use std::process::Command;
pub fn safe_git(user_branch: &str) {
    let _ = Command::new("git").arg("diff").arg("--").arg(user_branch).output();
}
"#,
    );

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let g_safe = scanner.scan_project(tmp.path());
    assert!(
        !g_safe
            .nodes
            .iter()
            .flat_map(|n| n.metadata.cve_anomalies.iter())
            .any(|a| a.rule_id == "CVE-INJ-POSIX-FLAG-SMUGGLING"),
        "git with '--' separator must not trigger CWE-88"
    );

    // Dynamic .args(user_vec) WITHOUT '--' MUST still trigger CWE-88
    let tmp_bad = tempdir().unwrap();
    write_rel(
        tmp_bad.path(),
        "src/git_dyn_vec.rs",
        r#"use std::process::Command;
pub fn unsafe_git(user_args: &[&str]) {
    let _ = Command::new("git").args(user_args).output();
}
"#,
    );
    let g_bad = scanner.scan_project(tmp_bad.path());
    assert!(
        g_bad
            .nodes
            .iter()
            .flat_map(|n| n.metadata.cve_anomalies.iter())
            .any(|a| a.rule_id == "CVE-INJ-POSIX-FLAG-SMUGGLING"),
        "dynamic .args(user_args) without '--' must still trigger CWE-88"
    );
}

#[test]
fn tier2_f7_readme_contract_forbidden_functions_and_extensions() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        "src/README.md",
        "---\nid: \"strict\"\nmax_lines_per_file: 300\nforbidden_functions: [\"eval\", \"unwrap\"]\nforbidden_extensions: [\"exe\"]\nmax_files_per_folder: 2\n---\n# Strict\n",
    );
    write_rel(tmp.path(), "src/bad.js", "function f(x) { return eval(x); }\n");
    write_rel(tmp.path(), "src/safe.rs", "pub fn ok(o: Option<i32>) -> i32 { o.unwrap_or(1) }\n");
    write_rel(tmp.path(), "src/extra.rs", "pub fn retrieval(x: i32) -> i32 { x }\n");

    let mut scanner = ProjectScanner::new();
    scanner.use_cache = false;
    let graph = scanner.scan_project(tmp.path());

    let rules: Vec<String> = graph
        .nodes
        .iter()
        .flat_map(|n| n.metadata.cve_anomalies.iter())
        .map(|a| format!("{}:{}", a.file_path, a.rule_id))
        .collect();

    assert!(rules.iter().any(|r| r.contains("bad.js") && r.contains("RULE_FORBIDDEN_FUNCTION")));
    assert!(!rules.iter().any(|r| r.contains("safe.rs") && r.contains("RULE_FORBIDDEN_FUNCTION")));
    assert!(!rules.iter().any(|r| r.contains("extra.rs") && r.contains("RULE_FORBIDDEN_FUNCTION")));
    assert!(rules.iter().any(|r| r.contains("RULE_MAX_FILES")));
}

#[test]
fn tier2_f7_plugins_selection_isolation() {
    let tmp = tempdir().unwrap();
    write_rel(
        tmp.path(),
        ".aether/plugins/only_me.yaml",
        r#"name: only-me
version: "1.0.0"
enabled: true
rules:
  - id: ONLY-ME-RULE
    cwe_id: CWE-998
    name: Only Me
    severity: MEDIUM
    description: Test
    remediation: Fix
    file_extensions: ["rs"]
    conditions:
      forbidden_tokens: ["ONLY_ME_TRIGGER"]
"#,
    );
    write_rel(tmp.path(), "src/code.rs", "pub fn ONLY_ME_TRIGGER() {}\n");

    let out = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--format",
            "sarif",
            "--plugins",
            "only-me",
        ],
    );
    assert_eq!(out.code, 0);
    let sarif = parse_sarif_json(&out.stdout);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["ruleId"] == "ONLY-ME-RULE"));

    let bad = run_audit_cli(
        tmp.path(),
        &[
            "--path",
            tmp.path().to_str().unwrap(),
            "--audit-only",
            "--plugins",
            "missing_pack_name",
        ],
    );
    assert_ne!(bad.code, 0);
}

#[test]
fn tier2_f7_self_audit_clean_on_workspace() {
    let tmp = tempdir().unwrap();
    let sarif_out = tmp.path().join("workspace.sarif");
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
    assert_eq!(out.code, 0, "workspace self-audit --fail-on HIGH must exit 0");

    let sarif: Value = serde_json::from_str(&fs::read_to_string(&sarif_out).unwrap()).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let blocked: Vec<String> = results
        .iter()
        .filter_map(|r| {
            let rid = r["ruleId"].as_str().unwrap_or("");
            if matches!(
                rid,
                "CVE-RUST-ASYNC-MUTEX"
                    | "CVE-INJ-POSIX-FLAG-SMUGGLING"
                    | "AETHER-RUST-PATH-JOIN-PREFIX-WIPE"
                    | "AETHER-RUST-UTF8-LOSSY-SMUGGLING"
                    | "BLAKE3_TAMPERED"
                    | "RULE_MAX_LINES"
            ) {
                Some(format!(
                    "{} at {}",
                    rid,
                    r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap_or("?")
                ))
            } else {
                None
            }
        })
        .collect();

    assert!(
        blocked.is_empty(),
        "live workspace self-audit must have zero target CWE/BLAKE3/line-budget alerts: {:?}",
        blocked
    );
}
