//! E2E Production Hardening Suite — R2: BLAKE3 Cache, Invalidation, Parallelism & Benchmark (F-E2E-5, F-E2E-6, F-E2E-7)
//!
//! Strictly 100% Opaque-Box:
//! - Invokes `aether-engine` exclusively via `std::process::Command` (`--audit-only`, `--benchmark`, `--no-gui`)
//!   and raw HTTP/1.1 over `tokio::net::TcpStream` (`Host: 127.0.0.1:<port>`).
//! - Zero internal crate imports (`ast_scanner`, `security_linter`, `core_graph`, etc.).
//! - Covers F-E2E-5 (10 tests), F-E2E-6 (10 tests), F-E2E-7 (10 tests), Tier 3 (6 tests), Tier 4 S3 & S4 (2 tests) = 38 tests.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use walkdir::WalkDir;

// ============================================================================
// Binary, Port, Process & Fixture Helpers
// ============================================================================

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

fn alloc_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

fn write_rel_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("mkdir {:?}: {}", parent, e));
    }
    fs::write(&path, content).unwrap_or_else(|e| panic!("write {:?}: {}", path, e));
}

struct CliOutput {
    status_code: Option<i32>,
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_aether_cli(cwd: &Path, args: &[&str]) -> CliOutput {
    let bin = find_aether_engine_bin();
    let out = Command::new(&bin)
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute {:?} {:?}: {}", bin, args, e));
    CliOutput {
        status_code: out.status.code(),
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ============================================================================
// SARIF v2.1.0 Extraction & Canonicalization Helpers
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SarifFinding {
    uri: String,
    start_line: usize,
    rule_id: String,
    level: String,
    message: String,
    cve_id: String,
    is_reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SarifDoc {
    findings: Vec<SarifFinding>,
}

impl SarifDoc {
    fn canonical_keys(&self) -> Vec<(String, usize, String, String, String)> {
        let mut keys: Vec<(String, usize, String, String, String)> = self
            .findings
            .iter()
            .map(|f| {
                (
                    f.uri.clone(),
                    f.start_line,
                    f.rule_id.clone(),
                    f.level.clone(),
                    f.message.clone(),
                )
            })
            .collect();
        keys.sort();
        keys
    }

    fn has_rule(&self, rule_id: &str) -> bool {
        self.findings.iter().any(|f| f.rule_id == rule_id)
    }

    fn has_rule_in_uri(&self, rule_id: &str, uri_substr: &str) -> bool {
        self.findings
            .iter()
            .any(|f| f.rule_id == rule_id && f.uri.contains(uri_substr))
    }

    fn count_rule(&self, rule_id: &str) -> usize {
        self.findings.iter().filter(|f| f.rule_id == rule_id).count()
    }
}

fn extract_first_json_object(raw: &str) -> Result<Value, String> {
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let is_line_start_brace =
            bytes[i] == b'{' && (i == 0 || bytes[i - 1] == b'\n' || bytes[i - 1] == b'\r');
        if is_line_start_brace {
            let start = i;
            let mut depth = 0usize;
            let mut in_string = false;
            let mut escaped = false;
            let mut j = start;
            while j < bytes.len() {
                let b = bytes[j];
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if b == b'\\' {
                        escaped = true;
                    } else if b == b'"' {
                        in_string = false;
                    }
                } else {
                    match b {
                        b'"' => in_string = true,
                        b'{' => depth += 1,
                        b'}' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                let slice = &raw[start..=j];
                                if let Ok(val) = serde_json::from_str::<Value>(slice) {
                                    return Ok(val);
                                }
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                j += 1;
            }
        }
        i += 1;
    }

    // Fallback: try from first '{' anywhere in raw
    if let Some(start) = raw.find('{') {
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for (offset, b) in raw[start..].bytes().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
            } else {
                match b {
                    b'"' => in_string = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            let slice = &raw[start..=start + offset];
                            return serde_json::from_str::<Value>(slice)
                                .map_err(|e| format!("SARIF JSON parse error: {}", e));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Err("No complete JSON object found in stdout".to_string())
}

fn parse_sarif_value(val: &Value) -> SarifDoc {
    assert_eq!(
        val.get("version").and_then(|v| v.as_str()),
        Some("2.1.0"),
        "SARIF version must be 2.1.0: {}",
        val
    );
    assert_eq!(
        val.get("$schema").and_then(|v| v.as_str()),
        Some("https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"),
        "SARIF $schema mismatch"
    );
    let runs = val
        .get("runs")
        .and_then(|v| v.as_array())
        .expect("SARIF runs array");
    assert_eq!(runs.len(), 1, "SARIF runs must have length 1");
    let driver = runs[0]
        .get("tool")
        .and_then(|t| t.get("driver"))
        .expect("SARIF tool.driver");
    assert_eq!(
        driver.get("name").and_then(|v| v.as_str()),
        Some("AetherScope"),
        "SARIF driver name"
    );
    assert!(
        driver.get("rules").and_then(|v| v.as_array()).is_some(),
        "SARIF driver.rules must be an array"
    );

    let results = runs[0]
        .get("results")
        .and_then(|v| v.as_array())
        .expect("SARIF results array");

    let mut findings = Vec::with_capacity(results.len());
    for r in results {
        let rule_id = r
            .get("ruleId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let level = r
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let message = r
            .get("message")
            .and_then(|m| m.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let loc = r
            .get("locations")
            .and_then(|l| l.as_array())
            .and_then(|a| a.first())
            .and_then(|l| l.get("physicalLocation"));
        let uri = loc
            .and_then(|p| p.get("artifactLocation"))
            .and_then(|a| a.get("uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .replace('\\', "/");
        let start_line = loc
            .and_then(|p| p.get("region"))
            .and_then(|reg| reg.get("startLine"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let props = r.get("properties");
        let cve_id = props
            .and_then(|p| p.get("cveId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let is_reachable = props
            .and_then(|p| p.get("is_reachable"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        findings.push(SarifFinding {
            uri,
            start_line,
            rule_id,
            level,
            message,
            cve_id,
            is_reachable,
        });
    }
    findings.sort();
    SarifDoc { findings }
}

fn run_audit_sarif_file(
    project: &Path,
    cwd: &Path,
    sarif_out: &Path,
    extra_args: &[&str],
) -> (CliOutput, Option<SarifDoc>) {
    let port = alloc_ephemeral_port().to_string();
    let project_str = project.to_string_lossy().into_owned();
    let out_str = sarif_out.to_string_lossy().into_owned();
    let mut args = vec![
        "--audit-only",
        "--path",
        &project_str,
        "--port",
        &port,
        "--format",
        "sarif",
        "-o",
        &out_str,
    ];
    args.extend_from_slice(extra_args);
    let cli = run_aether_cli(cwd, &args);
    let doc = if sarif_out.exists() {
        let raw = fs::read_to_string(sarif_out).expect("read sarif file");
        let val: Value = serde_json::from_str(&raw).expect("parse sarif file json");
        Some(parse_sarif_value(&val))
    } else {
        None
    };
    (cli, doc)
}

fn run_audit_sarif_stdout(project: &Path, extra_args: &[&str]) -> (CliOutput, SarifDoc) {
    let port = alloc_ephemeral_port().to_string();
    let project_str = project.to_string_lossy().into_owned();
    let mut args = vec![
        "--audit-only",
        "--path",
        &project_str,
        "--port",
        &port,
        "--format",
        "sarif",
    ];
    args.extend_from_slice(extra_args);
    let cli = run_aether_cli(project, &args);
    assert!(
        cli.success,
        "audit sarif stdout failed ({:?}): stderr={}",
        cli.status_code, cli.stderr
    );
    let val = extract_first_json_object(&cli.stdout)
        .unwrap_or_else(|e| panic!("{} | stdout={}", e, cli.stdout));
    (cli, parse_sarif_value(&val))
}

// ============================================================================
// BENCHMARK.md & Stdout Metrics Parser
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
struct ParsedBenchmark {
    files_count: usize,
    total_loc: usize,
    lexing_ms: f64,
    ast_ms: f64,
    cwe_ms: f64,
    total_ms: f64,
    throughput_loc_s: f64,
    peak_rss_mb: f64,
    anomalies_count: usize,
}

fn parse_leading_number(raw: &str) -> Result<f64, String> {
    let cleaned = raw.replace('`', "").replace("**", "");
    let token = cleaned
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("missing numeric token in '{}'", raw))?;
    let val = token
        .parse::<f64>()
        .map_err(|e| format!("invalid float '{}': {}", token, e))?;
    if !val.is_finite() {
        return Err(format!("non-finite metric '{}'", token));
    }
    Ok(val)
}

fn parse_benchmark_stdout(stdout: &str) -> Result<ParsedBenchmark, String> {
    let mut map: HashMap<String, f64> = HashMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("- ") {
            if let Some((label, val_part)) = rest.split_once(':') {
                let key = label.trim().to_string();
                if let Ok(num) = parse_leading_number(val_part.trim()) {
                    map.insert(key, num);
                }
            }
        }
    }
    let get = |k: &str| -> Result<f64, String> {
        map.get(k)
            .copied()
            .ok_or_else(|| format!("missing stdout metric '{}'\nstdout:\n{}", k, stdout))
    };
    Ok(ParsedBenchmark {
        files_count: get("Fichiers analysés")? as usize,
        total_loc: get("Lignes de code (LOC)")? as usize,
        lexing_ms: get("Temps Lexing & Masquage")?,
        ast_ms: get("Temps Construction AST (Rayon)")?,
        cwe_ms: get("Temps Évaluation 150+ CWEs")?,
        total_ms: get("Temps Total d'Exécution")?,
        throughput_loc_s: get("Débit Global")?,
        peak_rss_mb: get("Pic Mémoire RAM (Peak RSS)")?,
        anomalies_count: get("Anomalies CVE Détectées")? as usize,
    })
}

fn parse_benchmark_markdown(md: &str) -> Result<ParsedBenchmark, String> {
    let mut map: HashMap<String, f64> = HashMap::new();
    for line in md.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("| **") {
            let parts: Vec<&str> = trimmed.split('|').collect();
            if parts.len() >= 3 {
                let label = parts[1].replace("**", "").trim().to_string();
                let val_str = parts[2].trim();
                if let Ok(num) = parse_leading_number(val_str) {
                    map.insert(label, num);
                }
            }
        }
    }
    let get = |k: &str| -> Result<f64, String> {
        map.get(k)
            .copied()
            .ok_or_else(|| format!("missing BENCHMARK.md row '{}'\nmd:\n{}", k, md))
    };
    Ok(ParsedBenchmark {
        files_count: get("Fichiers analysés")? as usize,
        total_loc: get("Lignes de code (LOC)")? as usize,
        lexing_ms: get("Temps Lexing & Masquage")?,
        ast_ms: get("Temps Construction AST (Rayon)")?,
        cwe_ms: get("Temps Évaluation 150+ Règles CWE")?,
        total_ms: get("Temps Total d'Exécution")?,
        throughput_loc_s: get("Débit Global")?,
        peak_rss_mb: get("Pic Mémoire RAM (Peak RSS)")?,
        anomalies_count: get("Violations & Failles Détectées")? as usize,
    })
}

fn run_benchmark_cli(project: &Path, extra_args: &[&str]) -> (CliOutput, ParsedBenchmark, ParsedBenchmark) {
    let port = alloc_ephemeral_port().to_string();
    let project_str = project.to_string_lossy().into_owned();
    let mut args = vec!["--benchmark", "--path", &project_str, "--port", &port];
    args.extend_from_slice(extra_args);
    let cli = run_aether_cli(project, &args);
    assert!(
        cli.success,
        "--benchmark failed ({:?}): stdout={}\nstderr={}",
        cli.status_code, cli.stdout, cli.stderr
    );
    let stdout_m = parse_benchmark_stdout(&cli.stdout)
        .unwrap_or_else(|e| panic!("stdout parse failed: {}", e));
    let md_path = project.join("BENCHMARK.md");
    assert!(md_path.exists(), "BENCHMARK.md must exist at {:?}", md_path);
    let md_raw = fs::read_to_string(&md_path).expect("read BENCHMARK.md");
    let md_m =
        parse_benchmark_markdown(&md_raw).unwrap_or_else(|e| panic!("md parse failed: {}", e));
    (cli, stdout_m, md_m)
}

// ============================================================================
// Cache Artifact Inspection Helpers (Layout-Agnostic, Excludes `osv/`)
// ============================================================================

fn collect_non_osv_cache_entries(project: &Path) -> BTreeMap<String, (u64, Option<SystemTime>)> {
    let cache_dir = project.join(".aether").join("cache");
    let mut out = BTreeMap::new();
    if !cache_dir.exists() {
        return out;
    }
    for entry in WalkDir::new(&cache_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(&cache_dir)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "osv" || rel.starts_with("osv/") {
            continue;
        }
        let meta = fs::metadata(entry.path()).expect("stat cache entry");
        out.insert(rel, (meta.len(), meta.modified().ok()));
    }
    out
}

fn assert_cache_populated(project: &Path) -> BTreeMap<String, (u64, Option<SystemTime>)> {
    let entries = collect_non_osv_cache_entries(project);
    assert!(
        !entries.is_empty(),
        "Expected .aether/cache/ to contain >= 1 non-osv file after scan at {:?}",
        project
    );
    assert!(
        entries.values().any(|(len, _)| *len > 0),
        "Expected at least one non-empty cache file in .aether/cache/: {:?}",
        entries
    );
    entries
}

// ============================================================================
// Opaque-Box HTTP / --no-gui Server Helpers
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
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            let preview = String::from_utf8_lossy(&self.body[..self.body.len().min(512)]);
            panic!(
                "Failed to parse HTTP {} JSON ({}): {}",
                self.status, e, preview
            );
        })
    }
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
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut tmp))
            .await
            .map_err(|_| "HTTP header read timeout".to_string())?
            .map_err(|e| format!("HTTP header read error: {}", e))?;
        if n == 0 {
            return Err("EOF before HTTP headers completed".to_string());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let status = lines
        .next()
        .unwrap_or("")
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

    let mut body_buf = buf[header_end + 4..].to_vec();
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
                .map_err(|_| "HTTP body read timeout".to_string())?
                .map_err(|e| format!("HTTP body read error: {}", e))?;
            if n == 0 {
                return Err("EOF before Content-Length satisfied".to_string());
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
        body: final_body,
    })
}

async fn http_get_raw(port: u16, path: &str) -> Result<HttpResponse, String> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        path, port
    );
    send_raw_http_request(port, req.as_bytes()).await
}

async fn http_get_json(port: u16, path: &str) -> Value {
    let resp = http_get_raw(port, path)
        .await
        .unwrap_or_else(|e| panic!("GET {} failed: {}", path, e));
    assert_eq!(resp.status, 200, "GET {} expected 200, got {}", path, resp.status);
    resp.json()
}

async fn http_post_json(port: u16, path: &str, body: &Value) -> Value {
    let payload = serde_json::to_vec(body).expect("serialize POST json");
    let header = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        port,
        payload.len()
    );
    let mut raw = header.into_bytes();
    raw.extend_from_slice(&payload);
    let resp = send_raw_http_request(port, &raw)
        .await
        .unwrap_or_else(|e| panic!("POST {} failed: {}", path, e));
    assert_eq!(
        resp.status, 200,
        "POST {} expected 200, got {}",
        path, resp.status
    );
    resp.json()
}

async fn spawn_no_gui_server(root: &Path, extra_args: &[&str]) -> ServerGuard {
    let bin = find_aether_engine_bin();
    let port = alloc_ephemeral_port();
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
                "aether-engine exited prematurely with status {:?} before /api/health",
                exit_status
            );
        }
        if let Ok(resp) = http_get_raw(port, "/api/health").await {
            if resp.status == 200 {
                return guard;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("Timed out waiting 30s for /api/health on port {}", port);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn extract_graph_anomalies(graph: &Value) -> BTreeSet<(String, String, usize)> {
    let mut set = BTreeSet::new();
    if let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) {
        for n in nodes {
            if let Some(anoms) = n
                .get("metadata")
                .and_then(|m| m.get("cve_anomalies"))
                .and_then(|v| v.as_array())
            {
                for a in anoms {
                    let rule_id = a
                        .get("rule_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let file_path = a
                        .get("file_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .replace('\\', "/");
                    let line_number = a
                        .get("line_number")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    set.insert((rule_id, file_path, line_number));
                }
            }
        }
    }
    set
}

fn extract_file_blake3_hashes(graph: &Value) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) {
        for n in nodes {
            let fp = n
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .replace('\\', "/");
            if fp.is_empty() {
                continue;
            }
            if let Some(h) = n
                .get("metadata")
                .and_then(|m| m.get("file_blake3_hash"))
                .and_then(|v| v.as_str())
            {
                let is_file = n.get("is_file").and_then(|v| v.as_bool()).unwrap_or(false);
                if is_file || !map.contains_key(&fp) {
                    map.insert(fp, h.to_string());
                }
            }
        }
    }
    map
}

fn extract_contract_blake3_hashes(graph: &Value) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) {
        for n in nodes {
            let fp = n
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .replace('\\', "/");
            if fp.is_empty() {
                continue;
            }
            if let Some(h) = n
                .get("metadata")
                .and_then(|m| m.get("blake3_hash"))
                .and_then(|v| v.as_str())
            {
                let is_file = n.get("is_file").and_then(|v| v.as_bool()).unwrap_or(false);
                if is_file || !map.contains_key(&fp) {
                    map.insert(fp, h.to_string());
                }
            }
        }
    }
    map
}

fn find_symbol_line(graph: &Value, file_suffix: &str, symbol_name: &str) -> Option<usize> {
    let nodes = graph.get("nodes").and_then(|v| v.as_array())?;
    for n in nodes {
        let fp = n
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .replace('\\', "/");
        let name = n.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let is_file = n.get("is_file").and_then(|v| v.as_bool()).unwrap_or(false);
        if !is_file && fp.ends_with(file_suffix) && name == symbol_name {
            return n
                .get("line_number")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
        }
    }
    None
}

// ============================================================================
// F-E2E-5: BLAKE3 Incremental Cache Hit & Reuse (Tier 1: 5, Tier 2: 5)
// ============================================================================

#[test]
fn test_f5_tier1_cold_scan_creates_blake3_cache_artifacts() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "src/api.py",
        "def fetch_user(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id=\" + uid)\n",
    );
    write_rel_file(
        dir.path(),
        "src/service.ts",
        "export function runEval(payload: string) {\n    return eval(payload);\n}\n",
    );
    write_rel_file(
        dir.path(),
        "src/worker.rs",
        "pub fn get_key() -> &'static str {\n    let api_key = \"AKIA1234567890ABCDEF12\";\n    api_key\n}\n",
    );

    assert!(
        !dir.path().join(".aether").join("cache").exists(),
        ".aether/cache/ must not exist before cold scan"
    );

    let sarif_path = dir.path().join("run1.sarif");
    let (cli, doc_opt) = run_audit_sarif_file(dir.path(), dir.path(), &sarif_path, &[]);
    assert!(cli.success, "cold scan failed: {}", cli.stderr);
    let doc = doc_opt.expect("run1.sarif must exist");
    assert!(
        doc.findings.len() >= 3,
        "Expected >= 3 findings across Python/TS/Rust, got {:?}",
        doc.findings
    );
    assert!(doc.has_rule("SAST_RAW_SQL_INJECTION"));
    assert!(doc.has_rule("CVE-JS-CODE-INJ"));
    assert!(doc.has_rule("SAST_HARDCODED_SECRET"));

    assert_cache_populated(dir.path());
}

#[test]
fn test_f5_tier1_warm_scan_produces_identical_sarif_and_reuses_cache() {
    let dir = tempdir().unwrap();
    for i in 0..8 {
        write_rel_file(
            dir.path(),
            &format!("app/clean_{}.ts", i),
            &format!("export function cleanFn{}(x: number): number {{ return x + {}; }}\n", i, i),
        );
    }
    write_rel_file(
        dir.path(),
        "service/cmd.py",
        "import os\ndef run_cmd(c):\n    os.system(c)\n",
    );
    write_rel_file(
        dir.path(),
        "handlers/dom.js",
        "function show(el, html) {\n    el.innerHTML = html;\n}\n",
    );
    write_rel_file(
        dir.path(),
        "adapters/diag.php",
        "<?php\nfunction diag() {\n    shell_exec($_GET['cmd']);\n}\n",
    );
    write_rel_file(
        dir.path(),
        "domain/cfg.rs",
        "pub fn load_cfg() -> String {\n    std::env::var(\"APP_MODE\").unwrap_or_default()\n}\n",
    );

    let sarif1 = dir.path().join("run1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success, "run1 failed: {}", cli1.stderr);
    let doc1 = doc1.unwrap();
    assert!(doc1.findings.len() >= 4);

    let cache_before = assert_cache_populated(dir.path());
    std::thread::sleep(Duration::from_millis(60));

    let sarif2 = dir.path().join("run2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success, "run2 failed: {}", cli2.stderr);
    let doc2 = doc2.unwrap();

    assert_eq!(
        doc1.canonical_keys(),
        doc2.canonical_keys(),
        "Warm scan must produce 100% identical SARIF findings"
    );

    let cache_after = assert_cache_populated(dir.path());
    assert_eq!(
        cache_before, cache_after,
        "Warm cache hit must reuse existing .aether/cache/ entries without rewriting untouched entries"
    );
}

#[tokio::test]
async fn test_f5_tier1_cross_mode_cache_reuse_sarif_benchmark_and_http_graph() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "src/README.md",
        "---\nid: src\nlayer: domain\nmax_lines_per_file: 50\nsecurity_rules:\n  no_env_access: true\n---\n# Src\n- WHEN env is read directly THE SYSTEM SHALL emit SAST_DIRECT_ENV_ACCESS.\n",
    );
    write_rel_file(
        dir.path(),
        "src/domain.rs",
        "pub fn load_key() -> String {\n    std::env::var(\"SECRET_KEY\").unwrap_or_default()\n}\n",
    );
    write_rel_file(
        dir.path(),
        "src/helper.rs",
        "pub fn helper(v: i32) -> i32 { v + 1 }\n",
    );

    // 1. Cold --audit-only --format sarif
    let sarif_path = dir.path().join("cold.sarif");
    let (cli, doc) = run_audit_sarif_file(dir.path(), dir.path(), &sarif_path, &[]);
    assert!(cli.success, "audit sarif failed: {}", cli.stderr);
    let doc = doc.unwrap();
    assert!(doc.has_rule("SAST_DIRECT_ENV_ACCESS"));
    let cache_after_sarif = assert_cache_populated(dir.path());

    // 2. Warm --benchmark
    let _ = fs::remove_file(dir.path().join("AETHER_AI_RULES.md"));
    let (_bench_cli, stdout_m, md_m) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(stdout_m.files_count, 3);
    assert_eq!(md_m.files_count, 3);
    assert!(stdout_m.anomalies_count >= 1);
    let cache_after_bench = assert_cache_populated(dir.path());
    assert_eq!(
        cache_after_sarif, cache_after_bench,
        "--benchmark should reuse warm cache entries"
    );

    // 3. Warm --no-gui HTTP /api/graph?full=1
    let server = spawn_no_gui_server(dir.path(), &[]).await;
    let graph = http_get_json(server.port, "/api/graph?full=1").await;
    assert_eq!(
        graph["stats"]["files_scanned"].as_u64(),
        Some(3),
        "Graph must scan 3 files (ignoring .aether/cache/ and BENCHMARK.md)"
    );
    let hashes = extract_file_blake3_hashes(&graph);
    assert!(
        hashes.get("src/domain.rs").map(|h| !h.is_empty()).unwrap_or(false),
        "Expected file_blake3_hash for src/domain.rs, got {:?}",
        hashes
    );
    let anomalies = extract_graph_anomalies(&graph);
    assert!(
        anomalies
            .iter()
            .any(|(r, fp, _)| r == "SAST_DIRECT_ENV_ACCESS" && fp == "src/domain.rs"),
        "Expected SAST_DIRECT_ENV_ACCESS on src/domain.rs in /api/graph?full=1: {:?}",
        anomalies
    );
}

#[test]
fn test_f5_tier1_warm_cache_reuses_plugin_and_builtin_findings() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        ".aether/plugins/custom-pack/plugin.yaml",
        r#"name: custom-pack
version: "1.0.0"
enabled: true
rules:
  - id: CUST-PY-01
    cwe_id: CWE-94 / CUSTOM-EXEC
    name: Custom Legacy Exec
    severity: HIGH
    description: Disallowed legacy_exec invocation
    remediation: Replace legacy_exec with safe_exec
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "legacy_exec\\s*\\("
"#,
    );
    write_rel_file(
        dir.path(),
        "app/routes.py",
        "def dispatch(cursor, user_id):\n    legacy_exec(user_id)\n    cursor.execute(\"SELECT * FROM acct WHERE id=\" + user_id)\n",
    );

    let sarif1 = dir.path().join("run1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success, "run1 failed: {}", cli1.stderr);
    let doc1 = doc1.unwrap();
    assert!(doc1.has_rule_in_uri("CUST-PY-01", "app/routes.py"));
    assert!(doc1.has_rule_in_uri("SAST_RAW_SQL_INJECTION", "app/routes.py"));
    let cache1 = assert_cache_populated(dir.path());

    std::thread::sleep(Duration::from_millis(60));
    let sarif2 = dir.path().join("run2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success, "run2 failed: {}", cli2.stderr);
    let doc2 = doc2.unwrap();
    assert_eq!(doc1.canonical_keys(), doc2.canonical_keys());
    let cache2 = assert_cache_populated(dir.path());
    assert_eq!(cache1, cache2);
}

#[test]
fn test_f5_tier1_cache_hit_measurable_speedup_on_sizable_codebase() {
    let dir = tempdir().unwrap();
    // ~128 files x ~130 LOC = ~16,640 LOC across .rs, .ts, .py, .php (no Cargo.toml)
    for i in 0..128usize {
        let mut body = String::new();
        match i % 4 {
            0 => {
                body.push_str(&format!("pub fn worker_{}(seed: i64) -> i64 {{\n", i));
                body.push_str("    let mut acc = seed;\n");
                for l in 0..124 {
                    body.push_str(&format!("    acc = acc.wrapping_add({});\n", l + 1));
                }
                if i < 12 {
                    body.push_str("    let api_key = \"AKIA1234567890ABCDEF12\";\n    let _ = api_key;\n");
                }
                body.push_str("    acc\n}\n");
                write_rel_file(dir.path(), &format!("workers/mod_{:03}.rs", i), &body);
            }
            1 => {
                body.push_str(&format!("export function svc_{}(n: number): number {{\n", i));
                body.push_str("    let total = n;\n");
                for l in 0..124 {
                    body.push_str(&format!("    total += {};\n", l + 1));
                }
                if i < 12 {
                    body.push_str("    eval(String(total));\n");
                }
                body.push_str("    return total;\n}\n");
                write_rel_file(dir.path(), &format!("service/svc_{:03}.ts", i), &body);
            }
            2 => {
                body.push_str(&format!("def task_{}(val):\n", i));
                body.push_str("    acc = val\n");
                for l in 0..124 {
                    body.push_str(&format!("    acc += {}\n", l + 1));
                }
                if i < 12 {
                    body.push_str("    import os\n    os.system(str(acc))\n");
                }
                body.push_str("    return acc\n");
                write_rel_file(dir.path(), &format!("app/task_{:03}.py", i), &body);
            }
            _ => {
                body.push_str("<?php\n");
                body.push_str(&format!("function handle_{}($v) {{\n", i));
                body.push_str("    $sum = $v;\n");
                for l in 0..123 {
                    body.push_str(&format!("    $sum += {};\n", l + 1));
                }
                if i < 12 {
                    body.push_str("    shell_exec($_GET['cmd']);\n");
                }
                body.push_str("    return $sum;\n}\n");
                write_rel_file(dir.path(), &format!("handlers/h_{:03}.php", i), &body);
            }
        }
    }

    // Cold benchmark (populates .aether/cache/)
    let (_, cold_stdout, cold_md) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(cold_stdout.files_count, 128);
    assert_eq!(cold_md.files_count, 128);
    assert!(cold_stdout.total_loc >= 15_000);
    assert!(cold_stdout.anomalies_count >= 12);

    let cache_entries = assert_cache_populated(dir.path());

    // Warm SARIF invariance check
    let sarif1 = dir.path().join("warm1.sarif");
    let sarif2 = dir.path().join("warm2.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli1.success && cli2.success);
    let doc1 = doc1.unwrap();
    let doc2 = doc2.unwrap();
    assert_eq!(doc1.canonical_keys(), doc2.canonical_keys());
    assert!(doc1.findings.len() >= 12);

    // Warm benchmark median over 3 runs must be faster than cold ast_ms
    let mut warm_ast_ms = Vec::new();
    for _ in 0..3 {
        let _ = fs::remove_file(dir.path().join("BENCHMARK.md"));
        let _ = fs::remove_file(dir.path().join("AETHER_AI_RULES.md"));
        let (_, warm_m, _) = run_benchmark_cli(dir.path(), &[]);
        assert_eq!(warm_m.files_count, 128);
        assert_eq!(warm_m.anomalies_count, cold_stdout.anomalies_count);
        warm_ast_ms.push(warm_m.ast_ms);
    }
    warm_ast_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let warm_median = warm_ast_ms[1];
    assert!(
        warm_median < cold_stdout.ast_ms,
        "Expected warm median ast_time_ms ({:.2} ms) < cold ast_time_ms ({:.2} ms); warm samples={:?}",
        warm_median,
        cold_stdout.ast_ms,
        warm_ast_ms
    );
    assert_eq!(
        cache_entries,
        collect_non_osv_cache_entries(dir.path()),
        "Warm benchmarks should not churn .aether/cache/ entries"
    );
}

#[test]
fn test_f5_tier2_empty_project_cache_safety() {
    let dir = tempdir().unwrap();
    let sarif1 = dir.path().join("empty1.sarif");
    let sarif2 = dir.path().join("empty2.sarif");

    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success, "empty cold scan failed: {}", cli1.stderr);
    assert!(doc1.unwrap().findings.is_empty());

    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success, "empty warm scan failed: {}", cli2.stderr);
    assert!(doc2.unwrap().findings.is_empty());

    assert!(
        !dir.path().join("desktop-shell-panic.log").exists(),
        "No panic log should exist on empty project"
    );
}

#[test]
fn test_f5_tier2_corrupted_cache_file_graceful_recovery() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "src/api.py",
        "import os\ndef run(c):\n    os.system(c)\n",
    );
    write_rel_file(
        dir.path(),
        "src/ui.ts",
        "export function x(el: any, h: string) { el.innerHTML = h; }\n",
    );

    let sarif1 = dir.path().join("run1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    let doc1 = doc1.unwrap();
    assert!(doc1.findings.len() >= 2);

    let cache_entries = assert_cache_populated(dir.path());
    let cache_dir = dir.path().join(".aether").join("cache");
    for rel in cache_entries.keys() {
        fs::write(cache_dir.join(rel), b"{corrupt_cache\x00\xff\xfe").expect("corrupt cache file");
    }

    let sarif2 = dir.path().join("run2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success, "scan after cache corruption must succeed: {}", cli2.stderr);
    let doc2 = doc2.unwrap();
    assert_eq!(doc1.canonical_keys(), doc2.canonical_keys());

    let sarif3 = dir.path().join("run3.sarif");
    let (cli3, doc3) = run_audit_sarif_file(dir.path(), dir.path(), &sarif3, &[]);
    assert!(cli3.success);
    assert_eq!(doc1.canonical_keys(), doc3.unwrap().canonical_keys());
    assert!(!dir.path().join("desktop-shell-panic.log").exists());
}

#[test]
fn test_f5_tier2_osv_cache_subpath_isolated_from_ast_sast_cache() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "src/main.rs",
        "pub fn main_ok() -> i32 { 7 }\n",
    );
    let osv_payload = r#"[{"id":"CVE-2021-29930","summary":"preseeded osv cache"}]"#;
    write_rel_file(
        dir.path(),
        ".aether/cache/osv/test_key_64chars.json",
        osv_payload,
    );

    let sarif1 = dir.path().join("run1.sarif");
    let (cli1, _) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);

    let sarif2 = dir.path().join("run2.sarif");
    let (cli2, _) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);

    let osv_after = fs::read_to_string(dir.path().join(".aether/cache/osv/test_key_64chars.json"))
        .expect("osv cache file must still exist");
    assert_eq!(osv_after, osv_payload, "OSV cache subpath must not be altered");
    assert_cache_populated(dir.path());
}

#[tokio::test]
async fn test_f5_tier2_cache_ignored_by_project_scanner_and_benchmark() {
    let dir = tempdir().unwrap();
    write_rel_file(dir.path(), "src/main.rs", "pub fn ok() -> i32 { 1 }\n");
    write_rel_file(
        dir.path(),
        "src/app.ts",
        "export function okTs(n: number): number { return n; }\n",
    );
    write_rel_file(
        dir.path(),
        ".aether/cache/decoy_cached.rs",
        "pub fn fake() { let q = format!(\"SELECT * FROM u WHERE id = {}\", 1); let _ = q; }\n",
    );

    let (_, bench_stdout, bench_md) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(bench_stdout.files_count, 2);
    assert_eq!(bench_md.files_count, 2);
    assert_eq!(bench_stdout.anomalies_count, 0);

    let sarif = dir.path().join("run.sarif");
    let (cli, doc) = run_audit_sarif_file(dir.path(), dir.path(), &sarif, &[]);
    assert!(cli.success);
    let doc = doc.unwrap();
    assert!(
        !doc.findings.iter().any(|f| f.uri.contains(".aether")),
        "SARIF must ignore .aether/cache/ decoy files: {:?}",
        doc.findings
    );

    let server = spawn_no_gui_server(dir.path(), &[]).await;
    let graph = http_get_json(server.port, "/api/graph?full=1").await;
    assert_eq!(graph["stats"]["files_scanned"].as_u64(), Some(2));
}

#[test]
fn test_f5_tier2_zero_byte_and_unicode_files_cached_cleanly() {
    let dir = tempdir().unwrap();
    write_rel_file(dir.path(), "src/empty.py", "");
    write_rel_file(
        dir.path(),
        "src/unicode_mod.rs",
        "// 🚀 Sécurité UTF-8 café 日本語\npub fn cafe_ok() -> usize { 42 }\n",
    );
    write_rel_file(
        dir.path(),
        "src/vuln.ts",
        "export function execRaw(reqBody: string) {\n    return eval(reqBody);\n}\n",
    );

    let sarif1 = dir.path().join("u1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    let doc1 = doc1.unwrap();
    assert!(doc1.has_rule_in_uri("CVE-JS-CODE-INJ", "src/vuln.ts"));
    let cache1 = assert_cache_populated(dir.path());

    std::thread::sleep(Duration::from_millis(60));
    let sarif2 = dir.path().join("u2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    assert_eq!(doc1.canonical_keys(), doc2.unwrap().canonical_keys());
    assert_eq!(cache1, assert_cache_populated(dir.path()));
}

// ============================================================================
// F-E2E-6: BLAKE3 Cache Invalidation (Tier 1: 5, Tier 2: 5)
// ============================================================================

#[tokio::test]
async fn test_f6_tier1_source_file_edit_invalidates_only_modified_file() {
    let dir = tempdir().unwrap();
    write_rel_file(dir.path(), "src/clean_a.py", "def ok_a():\n    return 1\n");
    write_rel_file(dir.path(), "src/clean_b.py", "def ok_b():\n    return 2\n");
    write_rel_file(
        dir.path(),
        "src/vuln_c.py",
        "import os\ndef bad_c(cmd):\n    os.system(cmd)\n",
    );

    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    let doc1 = doc1.unwrap();
    assert!(doc1.has_rule_in_uri("CVE-PY-SHELL-INJ", "src/vuln_c.py"));
    assert!(!doc1.findings.iter().any(|f| f.uri.contains("clean_a.py")));
    assert_cache_populated(dir.path());

    let hashes_before = {
        let srv = spawn_no_gui_server(dir.path(), &[]).await;
        let g = http_get_json(srv.port, "/api/graph?full=1").await;
        extract_file_blake3_hashes(&g)
    };

    // Edit ONLY src/clean_a.py
    write_rel_file(
        dir.path(),
        "src/clean_a.py",
        "def ok_a(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id=\" + uid)\n",
    );

    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    let doc2 = doc2.unwrap();
    assert!(doc2.has_rule_in_uri("SAST_RAW_SQL_INJECTION", "src/clean_a.py"));
    assert!(doc2.has_rule_in_uri("CVE-PY-SHELL-INJ", "src/vuln_c.py"));

    let hashes_after = {
        let srv = spawn_no_gui_server(dir.path(), &[]).await;
        let g = http_get_json(srv.port, "/api/graph?full=1").await;
        extract_file_blake3_hashes(&g)
    };

    assert_ne!(
        hashes_before.get("src/clean_a.py"),
        hashes_after.get("src/clean_a.py"),
        "Edited file file_blake3_hash must change"
    );
    assert_eq!(
        hashes_before.get("src/clean_b.py"),
        hashes_after.get("src/clean_b.py"),
        "Unedited clean_b.py file_blake3_hash must remain identical"
    );
    assert_eq!(
        hashes_before.get("src/vuln_c.py"),
        hashes_after.get("src/vuln_c.py"),
        "Unedited vuln_c.py file_blake3_hash must remain identical"
    );
}

#[test]
fn test_f6_tier1_source_file_remediation_clears_cached_violation() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "src/db.rs",
        "pub fn query_user(id: &str) -> String {\n    format!(\"SELECT * FROM users WHERE id = {}\", id)\n}\n",
    );

    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) =
        run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &["--fail-on", "CRITICAL"]);
    assert_eq!(cli1.status_code, Some(1), "CRITICAL finding must fail-on");
    assert!(doc1.unwrap().has_rule_in_uri("SAST_RAW_SQL_INJECTION", "src/db.rs"));
    assert_cache_populated(dir.path());

    // Remediate src/db.rs
    write_rel_file(
        dir.path(),
        "src/db.rs",
        "pub fn safe_query() -> &'static str {\n    \"SELECT 1\"\n}\n",
    );

    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) =
        run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &["--fail-on", "CRITICAL"]);
    assert_eq!(cli2.status_code, Some(0), "Remediated file must pass --fail-on CRITICAL: {}", cli2.stderr);
    assert!(doc2.unwrap().findings.is_empty());
}

#[test]
fn test_f6_tier1_readme_contract_change_invalidates_affected_files() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "README.md",
        "---\nid: root-svc\nlayer: domain\nmax_lines_per_file: 100\nforbidden_imports: []\nsecurity_rules:\n  no_env_access: false\n---\n# Root\n",
    );
    write_rel_file(
        dir.path(),
        "src/service.rs",
        "use std::fs;\npub fn read_cfg() -> String {\n    let a = 1;\n    let b = 2;\n    let c = a + b;\n    let _ = c;\n    let _ = fs::metadata(\".\");\n    std::env::var(\"KEY\").unwrap_or_default()\n}\n",
    );

    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    let doc1 = doc1.unwrap();
    assert!(!doc1.has_rule("RULE_MAX_LINES"));
    assert!(!doc1.has_rule("RULE_FORBIDDEN_IMPORT"));
    assert!(!doc1.has_rule("SAST_DIRECT_ENV_ACCESS"));
    assert_cache_populated(dir.path());

    // Edit ONLY README.md (do NOT touch src/service.rs)
    write_rel_file(
        dir.path(),
        "README.md",
        "---\nid: root-svc\nlayer: domain\nmax_lines_per_file: 5\nforbidden_imports:\n  - std::fs\nsecurity_rules:\n  no_env_access: true\n---\n# Root\n",
    );

    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    let doc2 = doc2.unwrap();
    assert!(doc2.has_rule_in_uri("RULE_MAX_LINES", "src/service.rs"));
    assert!(doc2.has_rule_in_uri("RULE_FORBIDDEN_IMPORT", "src/service.rs"));
    assert!(doc2.has_rule_in_uri("SAST_DIRECT_ENV_ACCESS", "src/service.rs"));
}

#[test]
fn test_f6_tier1_plugin_manifest_edit_invalidates_cache() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        ".aether/plugins/custom_rule/plugin.yaml",
        r#"name: custom_rule
version: "1.0.0"
enabled: true
rules:
  - id: CUSTOM-CACHE-001
    cwe_id: CWE-94 / CUSTOM-SINK
    name: Custom Sink Detector
    severity: HIGH
    description: Unsafe custom sink
    remediation: Remove unsafe custom sink
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "unsafe_sink_alpha\\s*\\("
"#,
    );
    write_rel_file(
        dir.path(),
        "src/handler.py",
        "def f(x):\n    return unsafe_sink_beta(x)\n",
    );

    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    assert!(!doc1.unwrap().has_rule("CUSTOM-CACHE-001"));
    assert_cache_populated(dir.path());

    // Edit ONLY plugin.yaml (do NOT touch src/handler.py)
    write_rel_file(
        dir.path(),
        ".aether/plugins/custom_rule/plugin.yaml",
        r#"name: custom_rule
version: "1.0.1"
enabled: true
rules:
  - id: CUSTOM-CACHE-001
    cwe_id: CWE-94 / CUSTOM-SINK
    name: Custom Sink Detector
    severity: MEDIUM
    description: Unsafe custom sink
    remediation: Remove unsafe custom sink
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "unsafe_sink_beta\\s*\\("
"#,
    );

    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    let doc2 = doc2.unwrap();
    let hit = doc2
        .findings
        .iter()
        .find(|f| f.rule_id == "CUSTOM-CACHE-001" && f.uri == "src/handler.py")
        .expect("Expected CUSTOM-CACHE-001 after plugin manifest edit");
    assert_eq!(hit.start_line, 2);
    assert_eq!(hit.level, "warning");
}

#[test]
fn test_f6_tier1_cli_plugins_selection_change_invalidates_or_isolates_cache() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        ".aether/plugins/pack_alpha/plugin.yaml",
        r#"name: pack_alpha
version: "1.0.0"
enabled: true
rules:
  - id: RULE-ALPHA
    cwe_id: CWE-200 / ALPHA
    name: Alpha Call
    severity: HIGH
    description: Detects call_alpha
    remediation: Avoid call_alpha
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "call_alpha\\s*\\("
"#,
    );
    write_rel_file(
        dir.path(),
        ".aether/plugins/pack_beta/plugin.yaml",
        r#"name: pack_beta
version: "1.0.0"
enabled: true
rules:
  - id: RULE-BETA
    cwe_id: CWE-200 / BETA
    name: Beta Call
    severity: HIGH
    description: Detects call_beta
    remediation: Avoid call_beta
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "call_beta\\s*\\("
"#,
    );
    write_rel_file(
        dir.path(),
        "src/app.py",
        "def run(x, y):\n    call_alpha(x)\n    call_beta(y)\n",
    );

    let sarif_a = dir.path().join("alpha.sarif");
    let (cli_a, doc_a) =
        run_audit_sarif_file(dir.path(), dir.path(), &sarif_a, &["--plugins", "pack_alpha"]);
    assert!(cli_a.success, "--plugins pack_alpha failed: {}", cli_a.stderr);
    let doc_a = doc_a.unwrap();
    assert!(doc_a.has_rule("RULE-ALPHA"));
    assert!(!doc_a.has_rule("RULE-BETA"));
    assert_cache_populated(dir.path());

    let sarif_b = dir.path().join("beta.sarif");
    let (cli_b, doc_b) =
        run_audit_sarif_file(dir.path(), dir.path(), &sarif_b, &["--plugins", "pack_beta"]);
    assert!(cli_b.success, "--plugins pack_beta failed: {}", cli_b.stderr);
    let doc_b = doc_b.unwrap();
    assert!(doc_b.has_rule("RULE-BETA"));
    assert!(!doc_b.has_rule("RULE-ALPHA"));

    let sarif_all = dir.path().join("all.sarif");
    let (cli_all, doc_all) =
        run_audit_sarif_file(dir.path(), dir.path(), &sarif_all, &["--plugins", "all"]);
    assert!(cli_all.success, "--plugins all failed: {}", cli_all.stderr);
    let doc_all = doc_all.unwrap();
    assert!(doc_all.has_rule("RULE-ALPHA"));
    assert!(doc_all.has_rule("RULE-BETA"));
}

#[tokio::test]
async fn test_f6_tier2_file_deletion_removes_stale_findings_from_sarif_and_graph() {
    let dir = tempdir().unwrap();
    write_rel_file(dir.path(), "src/keep.py", "def ok():\n    return 1\n");
    write_rel_file(
        dir.path(),
        "src/remove_me.py",
        "import os\ndef bad(c):\n    os.system(c)\n",
    );

    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    assert!(doc1.unwrap().has_rule_in_uri("CVE-PY-SHELL-INJ", "src/remove_me.py"));

    fs::remove_file(dir.path().join("src/remove_me.py")).unwrap();

    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    let doc2 = doc2.unwrap();
    assert!(
        !doc2.findings.iter().any(|f| f.uri.contains("remove_me.py")),
        "Deleted file must not produce ghost SARIF findings: {:?}",
        doc2.findings
    );

    let srv = spawn_no_gui_server(dir.path(), &[]).await;
    let g = http_get_json(srv.port, "/api/graph?full=1").await;
    assert_eq!(g["stats"]["files_scanned"].as_u64(), Some(1));
    assert!(!extract_file_blake3_hashes(&g).contains_key("src/remove_me.py"));
}

#[test]
fn test_f6_tier2_file_rename_reindexes_findings_to_new_path() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "src/old_name.py",
        "def query(cursor, uid):\n    cursor.execute(\"SELECT * FROM t WHERE id=\" + uid)\n",
    );

    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    assert!(doc1.unwrap().has_rule_in_uri("SAST_RAW_SQL_INJECTION", "src/old_name.py"));

    fs::rename(
        dir.path().join("src/old_name.py"),
        dir.path().join("src/new_name.py"),
    )
    .unwrap();

    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    let doc2 = doc2.unwrap();
    assert!(doc2.has_rule_in_uri("SAST_RAW_SQL_INJECTION", "src/new_name.py"));
    assert!(
        !doc2.findings.iter().any(|f| f.uri.contains("old_name.py")),
        "Renamed file must not keep old path in SARIF: {:?}",
        doc2.findings
    );
}

#[tokio::test]
async fn test_f6_tier2_same_length_byte_flip_content_change_detected_by_blake3() {
    let dir = tempdir().unwrap();
    let v1 = "def run(d):\n    return safe_call(d)  # pad00\n";
    let v2 = "def run(d):\n    return eval(d)       # pad00\n";
    assert_eq!(v1.len(), v2.len(), "Exact same byte length required");

    write_rel_file(dir.path(), "src/flip.py", v1);
    let sarif1 = dir.path().join("r1.sarif");
    let (cli1, doc1) = run_audit_sarif_file(dir.path(), dir.path(), &sarif1, &[]);
    assert!(cli1.success);
    assert!(doc1.unwrap().findings.is_empty());
    assert_cache_populated(dir.path());

    let h1 = {
        let srv = spawn_no_gui_server(dir.path(), &[]).await;
        let g = http_get_json(srv.port, "/api/graph?full=1").await;
        extract_file_blake3_hashes(&g)
            .get("src/flip.py")
            .cloned()
            .expect("file_blake3_hash before")
    };

    write_rel_file(dir.path(), "src/flip.py", v2);
    let sarif2 = dir.path().join("r2.sarif");
    let (cli2, doc2) = run_audit_sarif_file(dir.path(), dir.path(), &sarif2, &[]);
    assert!(cli2.success);
    let doc2 = doc2.unwrap();
    assert!(
        doc2.has_rule_in_uri("CVE-PY-DESERIALIZE-RCE", "src/flip.py"),
        "Same-byte-length replacement to eval() must invalidate BLAKE3 cache: {:?}",
        doc2.findings
    );

    let h2 = {
        let srv = spawn_no_gui_server(dir.path(), &[]).await;
        let g = http_get_json(srv.port, "/api/graph?full=1").await;
        extract_file_blake3_hashes(&g)
            .get("src/flip.py")
            .cloned()
            .expect("file_blake3_hash after")
    };
    assert_ne!(h1, h2);
}

#[test]
fn test_f6_tier2_plugin_disable_and_removal_invalidates_cache() {
    let dir = tempdir().unwrap();
    let plugin_rel = ".aether/plugins/temp_plug/plugin.yaml";
    let plugin_enabled = r#"name: temp_plug
version: "1.0.0"
enabled: true
rules:
  - id: TMP-DANGER-01
    cwe_id: CWE-94 / TMP
    name: Temp Danger
    severity: HIGH
    description: Detects custom_danger
    remediation: Remove custom_danger
    file_extensions: [".ts"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "custom_danger\\s*\\("
"#;
    let plugin_disabled = plugin_enabled.replace("enabled: true", "enabled: false");

    write_rel_file(dir.path(), plugin_rel, plugin_enabled);
    write_rel_file(
        dir.path(),
        "src/mod.ts",
        "export function go(arg: string) { return custom_danger(arg); }\n",
    );

    let (_, d1) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r1.sarif"), &[]);
    assert!(d1.unwrap().has_rule("TMP-DANGER-01"));
    assert_cache_populated(dir.path());

    write_rel_file(dir.path(), plugin_rel, &plugin_disabled);
    let (_, d2) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r2.sarif"), &[]);
    assert!(!d2.unwrap().has_rule("TMP-DANGER-01"));

    write_rel_file(dir.path(), plugin_rel, plugin_enabled);
    let (_, d3) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r3.sarif"), &[]);
    assert!(d3.unwrap().has_rule("TMP-DANGER-01"));

    fs::remove_file(dir.path().join(plugin_rel)).unwrap();
    let (_, d4) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r4.sarif"), &[]);
    assert!(!d4.unwrap().has_rule("TMP-DANGER-01"));
}

#[tokio::test]
async fn test_f6_tier2_nested_subfolder_readme_override_invalidates_only_subtree() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "README.md",
        "---\nid: root\nlayer: domain\nmax_lines_per_file: 100\n---\n# Root\n",
    );
    write_rel_file(
        dir.path(),
        "app/sub/README.md",
        "---\nid: sub\nlayer: action\nmax_lines_per_file: 50\n---\n# Sub\n",
    );
    let ten_lines = (1..=10)
        .map(|i| format!("pub fn f_{}() -> i32 {{ {} }}\n", i, i))
        .collect::<String>();
    write_rel_file(dir.path(), "app/sub/file_sub.rs", &ten_lines);
    write_rel_file(dir.path(), "app/other/file_other.rs", &ten_lines);

    let (_, d1) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r1.sarif"), &[]);
    assert!(!d1.unwrap().has_rule("RULE_MAX_LINES"));
    assert_cache_populated(dir.path());

    let c1 = {
        let srv = spawn_no_gui_server(dir.path(), &[]).await;
        let g = http_get_json(srv.port, "/api/graph?full=1").await;
        extract_contract_blake3_hashes(&g)
    };

    // Tighten ONLY app/sub/README.md
    write_rel_file(
        dir.path(),
        "app/sub/README.md",
        "---\nid: sub\nlayer: action\nmax_lines_per_file: 5\n---\n# Sub\n",
    );

    let (_, d2) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r2.sarif"), &[]);
    let d2 = d2.unwrap();
    assert!(d2.has_rule_in_uri("RULE_MAX_LINES", "app/sub/file_sub.rs"));
    assert!(!d2.has_rule_in_uri("RULE_MAX_LINES", "app/other/file_other.rs"));

    let c2 = {
        let srv = spawn_no_gui_server(dir.path(), &[]).await;
        let g = http_get_json(srv.port, "/api/graph?full=1").await;
        extract_contract_blake3_hashes(&g)
    };
    assert_ne!(c1.get("app/sub/file_sub.rs"), c2.get("app/sub/file_sub.rs"));
    assert_eq!(c1.get("app/other/file_other.rs"), c2.get("app/other/file_other.rs"));
}

// ============================================================================
// F-E2E-7: Parallel Scan Determinism & --benchmark Integrity (Tier 1: 5, Tier 2: 5)
// ============================================================================

#[tokio::test]
async fn test_f7_tier1_parallel_audit_determinism_across_repeated_runs() {
    let dir = tempdir().unwrap();
    // 24 polyglot files across .rs, .ts, .js, .py, .php, .java, .sol, .luau (no Cargo.toml)
    for i in 0..3 {
        write_rel_file(
            dir.path(),
            &format!("workers/w_{}.rs", i),
            &format!("pub fn w_{}(id: &str) -> String {{ format!(\"SELECT * FROM t WHERE id = {{}}\", id) }}\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("app/a_{}.ts", i),
            &format!("export function a_{}(s: string) {{ return eval(s); }}\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("routes/r_{}.js", i),
            &format!("function r_{}(el, h) {{ el.innerHTML = h; }}\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("service/s_{}.py", i),
            &format!("import os\ndef s_{}(c):\n    os.system(c)\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("adapters/p_{}.php", i),
            &format!("<?php\nfunction p_{}() {{\n    shell_exec($_GET['cmd']);\n}}\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("domain/J_{}.java", i),
            &format!("public class J_{} {{ public int ok() {{ return 1; }} }}\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("contracts/C_{}.sol", i),
            &format!("pragma solidity ^0.8.20;\ncontract C_{} {{ uint256 public v; }}\n", i),
        );
        write_rel_file(
            dir.path(),
            &format!("gateway/g_{}.luau", i),
            &format!("local function g_{}(x)\n    return x + 1\nend\n", i),
        );
    }

    let mut runs = Vec::new();
    for idx in 0..3 {
        let cache = dir.path().join(".aether").join("cache");
        if cache.exists() {
            let _ = fs::remove_dir_all(&cache);
        }
        let sarif_out = dir.path().join(format!("cold_{}.sarif", idx));
        let (cli, doc) = run_audit_sarif_file(dir.path(), dir.path(), &sarif_out, &[]);
        assert!(cli.success, "cold run {} failed: {}", idx, cli.stderr);
        let doc = doc.unwrap();
        assert!(doc.findings.len() >= 15);
        runs.push(doc.canonical_keys());
    }
    assert_eq!(runs[0], runs[1]);
    assert_eq!(runs[1], runs[2]);

    let srv = spawn_no_gui_server(dir.path(), &[]).await;
    let g = http_get_json(srv.port, "/api/graph?full=1").await;
    assert_eq!(g["stats"]["files_scanned"].as_u64(), Some(24));
}

#[test]
fn test_f7_tier1_benchmark_cli_creates_report_and_validates_all_metrics() {
    let dir = tempdir().unwrap();
    let pad = (0..12)
        .map(|i| format!("let v_{} = {};", i, i))
        .collect::<Vec<_>>()
        .join("\n");
    write_rel_file(
        dir.path(),
        "src/main.rs",
        &format!("pub fn main() {{\n{}\n    let api_key = \"AKIA1234567890ABCDEF12\";\n    let _ = api_key;\n}}\n", pad),
    );
    write_rel_file(
        dir.path(),
        "src/app.ts",
        &format!("export function f() {{\n{}\n    return 1;\n}}\n", pad),
    );
    write_rel_file(
        dir.path(),
        "src/api.py",
        "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id=\" + uid)\n",
    );
    write_rel_file(
        dir.path(),
        "src/view.php",
        "<?php\nfunction ok() { return 42; }\n",
    );
    write_rel_file(
        dir.path(),
        "src/Contract.sol",
        "pragma solidity ^0.8.20;\ncontract Token { uint256 public supply = 100; }\n",
    );
    write_rel_file(
        dir.path(),
        "src/README.md",
        "---\nid: src\nlayer: domain\nmax_lines_per_file: 200\nsecurity_rules:\n  no_raw_sql: true\n---\n# Src\n",
    );

    let (cli, stdout_m, md_m) = run_benchmark_cli(dir.path(), &[]);
    assert!(cli.stdout.contains("AETHERSCOPE SAST V2.1"));
    assert_eq!(stdout_m.files_count, 6);
    assert_eq!(md_m.files_count, 6);
    assert_eq!(stdout_m.total_loc, md_m.total_loc);
    assert!(stdout_m.total_loc >= 35);
    assert!(stdout_m.total_ms > 0.0 && md_m.total_ms > 0.0);
    assert!(stdout_m.throughput_loc_s > 0.0 && md_m.throughput_loc_s > 0.0);
    assert!(stdout_m.peak_rss_mb > 0.0 && md_m.peak_rss_mb > 0.0);
    assert!(stdout_m.anomalies_count >= 2);
    assert_eq!(stdout_m.anomalies_count, md_m.anomalies_count);
}

#[test]
fn test_f7_tier1_benchmark_accuracy_of_file_loc_and_violation_counts() {
    let dir = tempdir().unwrap();
    let lines_10 = (1..=10)
        .map(|i| format!("pub fn f_{}() -> i32 {{ {} }}\n", i, i))
        .collect::<String>();
    let lines_15 = (1..=15)
        .map(|i| format!("export const c_{} = {};\n", i, i))
        .collect::<String>();
    let mut lines_20 = (1..=18)
        .map(|i| format!("x_{} = {}\n", i, i))
        .collect::<String>();
    lines_20.push_str("def q(cur, u):\n    cur.execute(\"SELECT * FROM users WHERE id=\" + u)\n");
    let mut lines_25 = String::from("<?php\n");
    for i in 2..=25 {
        lines_25.push_str(&format!("$v_{} = {};\n", i, i));
    }

    write_rel_file(dir.path(), "src/a.rs", &lines_10);
    write_rel_file(dir.path(), "src/b.ts", &lines_15);
    write_rel_file(dir.path(), "src/c.py", &lines_20);
    write_rel_file(dir.path(), "src/d.php", &lines_25);

    let (_, stdout_m, md_m) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(stdout_m.files_count, 4);
    assert_eq!(md_m.files_count, 4);
    assert_eq!(stdout_m.total_loc, 70);
    assert_eq!(md_m.total_loc, 70);
    assert!(stdout_m.anomalies_count >= 1);
    assert!(stdout_m.lexing_ms >= 0.0);
    assert!(stdout_m.ast_ms >= 0.0);
    assert!(stdout_m.cwe_ms >= 0.0);
}

#[test]
fn test_f7_tier1_parallel_plugin_evaluation_thread_safety_and_completeness() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        ".aether/plugins/par_pack_a/plugin.yaml",
        r#"name: par_pack_a
version: "1.0.0"
enabled: true
rules:
  - id: PAR-LINE-01
    cwe_id: CWE-94 / PAR-A
    name: Parallel Line Rule
    severity: HIGH
    description: Detects trigger_parallel_alpha
    remediation: Remove trigger_parallel_alpha
    file_extensions: [".rs", ".ts", ".py", ".php"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "trigger_parallel_alpha\\s*\\("
"#,
    );
    write_rel_file(
        dir.path(),
        ".aether/plugins/par_pack_b/plugin.yaml",
        r#"name: par_pack_b
version: "1.0.0"
enabled: true
rules:
  - id: PAR-WHOLE-01
    cwe_id: CWE-94 / PAR-B
    name: Parallel Whole Rule
    severity: MEDIUM
    description: Detects WHOLE_FILE_MARKER
    remediation: Remove WHOLE_FILE_MARKER
    file_extensions: [".rs", ".ts", ".py", ".php"]
    match_mode: whole_file
    conditions:
      must_contain:
        - "WHOLE_FILE_MARKER"
"#,
    );

    for i in 0..30 {
        match i % 4 {
            0 => write_rel_file(
                dir.path(),
                &format!("src/mod_{:02}.rs", i),
                "pub fn f(x: i32) {\n    let WHOLE_FILE_MARKER = 1;\n    trigger_parallel_alpha(x);\n    let _ = WHOLE_FILE_MARKER;\n}\n",
            ),
            1 => write_rel_file(
                dir.path(),
                &format!("src/mod_{:02}.ts", i),
                "export function f(x: number) {\n    const WHOLE_FILE_MARKER = 1;\n    trigger_parallel_alpha(x);\n    return WHOLE_FILE_MARKER;\n}\n",
            ),
            2 => write_rel_file(
                dir.path(),
                &format!("src/mod_{:02}.py", i),
                "def f(x):\n    WHOLE_FILE_MARKER = 1\n    trigger_parallel_alpha(x)\n    return WHOLE_FILE_MARKER\n",
            ),
            _ => write_rel_file(
                dir.path(),
                &format!("src/mod_{:02}.php", i),
                "<?php\nfunction f($x) {\n    trigger_parallel_alpha($x);\n    $WHOLE_FILE_MARKER = 1;\n    return $WHOLE_FILE_MARKER;\n}\n",
            ),
        }
    }

    let (_, doc) = run_audit_sarif_stdout(dir.path(), &[]);
    assert_eq!(
        doc.count_rule("PAR-LINE-01"),
        30,
        "Expected exactly 30 PAR-LINE-01 findings across 30 files"
    );
    assert_eq!(
        doc.count_rule("PAR-WHOLE-01"),
        30,
        "Expected exactly 30 PAR-WHOLE-01 findings across 30 files"
    );
    for f in doc.findings.iter().filter(|f| f.rule_id == "PAR-LINE-01") {
        assert_eq!(f.start_line, 3, "Expected startLine == 3 for {:?}", f);
    }
}

#[test]
fn test_f7_tier1_benchmark_supports_plugins_flag_filtering() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        ".aether/plugins/bench_pack_a/plugin.yaml",
        r#"name: bench_pack_a
version: "1.0.0"
enabled: true
rules:
  - id: BENCH-A
    cwe_id: CWE-200 / BENCH-A
    name: Bench Alpha
    severity: HIGH
    description: Detects bench_alpha
    remediation: Remove bench_alpha
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "bench_alpha\\s*\\("
"#,
    );
    write_rel_file(
        dir.path(),
        ".aether/plugins/bench_pack_b/plugin.yaml",
        r#"name: bench_pack_b
version: "1.0.0"
enabled: true
rules:
  - id: BENCH-B
    cwe_id: CWE-200 / BENCH-B
    name: Bench Beta
    severity: HIGH
    description: Detects bench_beta
    remediation: Remove bench_beta
    file_extensions: [".py"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "bench_beta\\s*\\("
"#,
    );
    // Zero built-in SecurityLinter findings in app/jobs.py!
    write_rel_file(
        dir.path(),
        "app/jobs.py",
        "def run_jobs(x, y):\n    bench_alpha(x)\n    bench_alpha(x)\n    bench_alpha(x)\n    bench_beta(y)\n    bench_beta(y)\n",
    );

    let (_, ma, _) = run_benchmark_cli(dir.path(), &["--plugins", "bench_pack_a"]);
    assert_eq!(ma.anomalies_count, 3, "bench_pack_a must report 3 violations");

    let (_, mb, _) = run_benchmark_cli(dir.path(), &["--plugins", "bench_pack_b"]);
    assert_eq!(mb.anomalies_count, 2, "bench_pack_b must report 2 violations");

    let (_, mall, _) = run_benchmark_cli(dir.path(), &["--plugins", "all"]);
    assert!(mall.anomalies_count >= 5, "all must report >= 5 violations");
}

#[test]
fn test_f7_tier2_benchmark_empty_directory_zero_division_safety() {
    let dir = tempdir().unwrap();
    let (cli, stdout_m, md_m) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(stdout_m.files_count, 0);
    assert_eq!(stdout_m.total_loc, 0);
    assert_eq!(stdout_m.anomalies_count, 0);
    assert_eq!(stdout_m.throughput_loc_s, 0.0);
    assert_eq!(md_m.files_count, 0);
    assert_eq!(md_m.throughput_loc_s, 0.0);
    assert!(!cli.stdout.contains("NaN") && !cli.stdout.contains("inf"));
}

#[test]
fn test_f7_tier2_benchmark_excludes_git_target_node_modules_and_aether() {
    let dir = tempdir().unwrap();
    write_rel_file(dir.path(), "src/main.rs", "pub fn a() -> i32 { 1 }\n");
    write_rel_file(dir.path(), "src/app.ts", "export const b = 2;\n");
    write_rel_file(dir.path(), ".git/hook.rs", "pub fn g() {}\n");
    write_rel_file(dir.path(), "target/gen.rs", "pub fn t() {}\n");
    write_rel_file(dir.path(), "node_modules/m/index.js", "function m() {}\n");
    write_rel_file(dir.path(), ".aether/cache/x.rs", "pub fn c() {}\n");
    write_rel_file(dir.path(), ".aether/plugins/p/plugin.yaml", "name: p\nversion: \"1.0.0\"\n");
    write_rel_file(dir.path(), "dist/out.js", "function d() {}\n");

    let (_, stdout_m, md_m) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(stdout_m.files_count, 2);
    assert_eq!(md_m.files_count, 2);
}

#[tokio::test]
async fn test_f7_tier2_large_single_file_line_starts_accurate_line_numbers() {
    let dir = tempdir().unwrap();
    let mut lines = Vec::with_capacity(3005);
    for i in 1..=2994 {
        lines.push(format!("const v_{} = {};", i, i));
    }
    // Line 2995: CVE-JS-CODE-INJ
    lines.push("eval(user_payload);".to_string());
    lines.push("const after_a = 1;".to_string());
    lines.push("const after_b = 2;".to_string());
    // Line 2998: re_js_func matches exact declaration line
    lines.push("export function final_sink() { return 99; }".to_string());
    for i in 2999..=3005 {
        lines.push(format!("const tail_{} = {};", i, i));
    }
    let content = lines.join("\n") + "\n";
    write_rel_file(dir.path(), "src/huge.ts", &content);

    let sarif = dir.path().join("huge.sarif");
    let (cli, doc) = run_audit_sarif_file(dir.path(), dir.path(), &sarif, &[]);
    assert!(cli.success);
    let doc = doc.unwrap();
    let hit = doc
        .findings
        .iter()
        .find(|f| f.rule_id == "CVE-JS-CODE-INJ" && f.uri == "src/huge.ts")
        .expect("Expected CVE-JS-CODE-INJ in src/huge.ts");
    assert_eq!(hit.start_line, 2995, "Expected exact startLine == 2995");

    let srv = spawn_no_gui_server(dir.path(), &[]).await;
    let g = http_get_json(srv.port, "/api/graph?full=1").await;
    assert_eq!(
        find_symbol_line(&g, "src/huge.ts", "final_sink"),
        Some(2998),
        "Expected final_sink SymbolBubble line_number == 2998"
    );
}

#[test]
fn test_f7_tier2_benchmark_invalid_plugins_spec_returns_nonzero_exit() {
    let dir = tempdir().unwrap();
    write_rel_file(dir.path(), "src/main.rs", "pub fn ok() -> i32 { 1 }\n");
    let port = alloc_ephemeral_port().to_string();
    let proj = dir.path().to_string_lossy().into_owned();
    let cli = run_aether_cli(
        dir.path(),
        &[
            "--benchmark",
            "--path",
            &proj,
            "--port",
            &port,
            "--plugins",
            "nonexistent_pack_xyz",
        ],
    );
    assert!(
        !cli.success,
        "Invalid --plugins spec must exit non-zero, got {:?} stdout={} stderr={}",
        cli.status_code, cli.stdout, cli.stderr
    );
    let combined = format!("{}\n{}", cli.stdout, cli.stderr).to_lowercase();
    assert!(
        combined.contains("plugin") || combined.contains("nonexistent_pack_xyz") || combined.contains("unknown"),
        "Error output must mention invalid plugin selection: {}",
        combined
    );
}

#[test]
fn test_f7_tier2_concurrent_parallel_scans_on_shared_readonly_fixture() {
    let dir = tempdir().unwrap();
    for i in 0..15 {
        match i % 3 {
            0 => write_rel_file(
                dir.path(),
                &format!("src/m_{:02}.py", i),
                "import os\ndef go(c):\n    os.system(c)\n",
            ),
            1 => write_rel_file(
                dir.path(),
                &format!("src/m_{:02}.ts", i),
                "export function go(s: string) { return eval(s); }\n",
            ),
            _ => write_rel_file(
                dir.path(),
                &format!("src/m_{:02}.rs", i),
                "pub fn ok(x: i32) -> i32 { x + 1 }\n",
            ),
        }
    }

    let mut handles = Vec::new();
    let mut cwds: Vec<TempDir> = Vec::new();
    for idx in 0..4 {
        let cwd = tempdir().unwrap();
        let cwd_path = cwd.path().to_path_buf();
        let proj_path = dir.path().to_path_buf();
        cwds.push(cwd);
        handles.push(std::thread::spawn(move || {
            let out_sarif = cwd_path.join(format!("out_{}.sarif", idx));
            let (cli, doc) = run_audit_sarif_file(&proj_path, &cwd_path, &out_sarif, &[]);
            assert!(
                cli.success,
                "Concurrent CLI #{} failed ({:?}): {}",
                idx, cli.status_code, cli.stderr
            );
            assert!(
                !cwd_path.join("desktop-shell-panic.log").exists(),
                "Concurrent CLI #{} panicked",
                idx
            );
            doc.expect("concurrent sarif output").canonical_keys()
        }));
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .collect();
    assert!(results[0].len() >= 10);
    for r in &results[1..] {
        assert_eq!(&results[0], r, "All 4 concurrent scans must produce identical SARIF");
    }
}

// ============================================================================
// Tier 3: Cross-Feature Combinations (6 tests)
// ============================================================================

#[test]
fn test_tier3_cache_hit_and_invalidation_with_plugins_profile_selection() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        ".aether/plugins/sec_web/plugin.yaml",
        r#"name: sec_web
version: "1.0.0"
enabled: true
profile: web
rules:
  - id: WEB-01
    cwe_id: CWE-79 / WEB
    name: Web Render
    severity: HIGH
    description: Unsafe web render
    remediation: Sanitize web output
    file_extensions: [".ts"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "unsafe_web_render\\s*\\("
"#,
    );
    let crypto_v1 = r#"name: sec_crypto
version: "1.0.0"
enabled: true
profile: crypto
rules:
  - id: CRYPTO-01
    cwe_id: CWE-327 / CRYPTO
    name: Weak XOR Cipher
    severity: HIGH
    description: Weak cipher xor
    remediation: Use AEAD
    file_extensions: [".rs"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "weak_cipher_xor\\s*\\("
"#;
    write_rel_file(dir.path(), ".aether/plugins/sec_crypto/plugin.yaml", crypto_v1);
    write_rel_file(
        dir.path(),
        "src/routes.ts",
        "export function view(d: string) { return unsafe_web_render(d); }\n",
    );
    write_rel_file(
        dir.path(),
        "src/cipher.rs",
        "pub fn enc(b: u8) -> u8 { weak_cipher_xor(b) }\npub fn weak_cipher_xor(x: u8) -> u8 { x ^ 0x55 }\n",
    );

    // 1. Cold --plugins profile:web
    let (_, d1) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("w1.sarif"),
        &["--plugins", "profile:web"],
    );
    let d1 = d1.unwrap();
    assert!(d1.has_rule("WEB-01"));
    assert!(!d1.has_rule("CRYPTO-01"));
    assert_cache_populated(dir.path());

    // 2. Warm --plugins profile:web
    let (_, d2) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("w2.sarif"),
        &["--plugins", "profile:web"],
    );
    assert_eq!(d1.canonical_keys(), d2.unwrap().canonical_keys());

    // 3. Switch to --plugins profile:crypto
    let (_, d3) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("c1.sarif"),
        &["--plugins", "profile:crypto"],
    );
    let d3 = d3.unwrap();
    assert!(d3.has_rule("CRYPTO-01"));
    assert!(!d3.has_rule("WEB-01"));

    // 4. Edit sec_crypto severity HIGH -> MEDIUM and re-run profile:crypto
    write_rel_file(
        dir.path(),
        ".aether/plugins/sec_crypto/plugin.yaml",
        &crypto_v1.replace("severity: HIGH", "severity: MEDIUM"),
    );
    let (_, d4) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("c2.sarif"),
        &["--plugins", "profile:crypto"],
    );
    let d4 = d4.unwrap();
    let hit = d4
        .findings
        .iter()
        .find(|f| f.rule_id == "CRYPTO-01")
        .expect("CRYPTO-01 after edit");
    assert_eq!(hit.level, "warning");
}

#[test]
fn test_tier3_cache_invalidation_on_enriched_dsl_contextual_window_plugin_edit() {
    let dir = tempdir().unwrap();
    let plugin_rel = ".aether/plugins/dsl_ctx/plugin.yaml";
    let make_yaml = |lines: usize| {
        format!(
            r#"name: dsl_ctx
version: "1.0.0"
enabled: true
rules:
  - id: CTX-01
    cwe_id: CWE-862 / MISSING-GUARD
    name: Unguarded Exec
    severity: HIGH
    description: dangerous_exec without nearby verify_auth_guard
    remediation: Add verify_auth_guard within 5 lines
    file_extensions: [".rs"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "dangerous_exec\\s*\\("
      not_preceded_within_lines:
        patterns:
          - "verify_auth_guard"
        lines: {}
"#,
            lines
        )
    };

    write_rel_file(dir.path(), plugin_rel, &make_yaml(2));
    write_rel_file(
        dir.path(),
        "service/auth_handler.rs",
        "pub fn handle(cmd: &str) {\n    // 2\n    // 3\n    // 4\n    // 5\n    // 6\n    verify_auth_guard();\n    let a = 1;\n    let b = a + 1;\n    dangerous_exec(cmd);\n}\npub fn verify_auth_guard() {}\npub fn dangerous_exec(_c: &str) {}\n",
    );

    let (_, d1) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r1.sarif"), &[]);
    let d1 = d1.unwrap();
    assert!(d1.has_rule_in_uri("CTX-01", "service/auth_handler.rs"));
    let cache1 = assert_cache_populated(dir.path());

    let (_, d2) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r2.sarif"), &[]);
    assert_eq!(d1.canonical_keys(), d2.unwrap().canonical_keys());
    assert_eq!(cache1, assert_cache_populated(dir.path()));

    // Widen contextual window lines: 2 -> 5 without touching service/auth_handler.rs
    write_rel_file(dir.path(), plugin_rel, &make_yaml(5));
    let (_, d3) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r3.sarif"), &[]);
    assert!(
        !d3.unwrap().has_rule("CTX-01"),
        "Widening not_preceded_within_lines window must invalidate cache and suppress CTX-01"
    );
}

#[tokio::test]
async fn test_tier3_cache_and_ssa_taint_plugin_invalidation() {
    let dir = tempdir().unwrap();
    let plugin_rel = ".aether/plugins/taint_pack/plugin.yaml";
    let base_yaml = r#"name: taint_pack
version: "1.0.0"
enabled: true
taint_sources:
  - name: custom_src
    source_kind: HttpQueryParam
    cwe: CWE-89
    patterns:
      - "get_custom_param("
    language: python
    description: Untrusted custom query input
taint_sinks:
  - name: custom_sink
    sink_kind: SqlExecution
    cwe: CWE-89
    rule_id: TAINT-PLUG-89
    severity: CRITICAL
    patterns:
      - "run_custom_sink("
    language: python
    description: Unsanitized custom SQL sink
sanitizers: []
"#;
    let sanitized_yaml = base_yaml.replace(
        "sanitizers: []",
        r#"sanitizers:
  - name: custom_clean
    target_cwes:
      - CWE-89
    match_kind: ExactName
    language: python
    neutralizes_all: false"#,
    );

    write_rel_file(dir.path(), plugin_rel, base_yaml);
    write_rel_file(
        dir.path(),
        "src/controller.py",
        "def api_run():\n    raw = get_custom_param()\n    clean = custom_clean(raw)\n    run_custom_sink(clean)\n",
    );

    let (_, d1) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r1.sarif"), &[]);
    let d1 = d1.unwrap();
    assert!(
        d1.has_rule("TAINT-PLUG-89"),
        "Expected TAINT-PLUG-89 before sanitizer added: {:?}",
        d1.findings
    );
    assert_cache_populated(dir.path());

    let (_, d2) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r2.sarif"), &[]);
    assert_eq!(d1.canonical_keys(), d2.unwrap().canonical_keys());

    // Add sanitizer in plugin.yaml without touching src/controller.py
    write_rel_file(dir.path(), plugin_rel, &sanitized_yaml);
    let (_, d3) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("r3.sarif"), &[]);
    let d3 = d3.unwrap();

    let srv = spawn_no_gui_server(dir.path(), &[]).await;
    let g = http_get_json(srv.port, "/api/graph?full=1").await;

    let sarif_still_active = d3
        .findings
        .iter()
        .any(|f| f.rule_id == "TAINT-PLUG-89" && f.is_reachable);
    let graph_still_vulnerable = g["nodes"]
        .as_array()
        .map(|nodes| {
            nodes.iter().any(|n| {
                n["metadata"]["cve_anomalies"]
                    .as_array()
                    .map(|anoms| {
                        anoms.iter().any(|a| {
                            a["rule_id"].as_str() == Some("TAINT-PLUG-89")
                                && a["taint_trace"]["is_vulnerable"].as_bool() == Some(true)
                        })
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    assert!(
        !sarif_still_active && !graph_still_vulnerable,
        "Adding sanitizer in plugin.yaml must invalidate cache and neutralize TAINT-PLUG-89"
    );
}

#[test]
fn test_tier3_benchmark_after_incremental_cache_vs_clean_workspace_consistency() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    for i in 0..40 {
        let (rel, content) = match i % 4 {
            0 => (
                format!("src/f_{:02}.rs", i),
                if i < 8 {
                    "pub fn bad() { let api_key = \"AKIA1234567890ABCDEF12\"; let _ = api_key; }\n".to_string()
                } else {
                    format!("pub fn ok_{}() -> i32 {{ {} }}\n", i, i)
                },
            ),
            1 => (
                format!("app/f_{:02}.ts", i),
                if i < 8 {
                    "export function bad(s: string) { return eval(s); }\n".to_string()
                } else {
                    format!("export const k_{} = {};\n", i, i)
                },
            ),
            2 => (
                format!("service/f_{:02}.py", i),
                if i < 8 {
                    "import os\ndef bad(c):\n    os.system(c)\n".to_string()
                } else {
                    format!("def ok_{}():\n    return {}\n", i, i)
                },
            ),
            _ => (
                format!("adapters/f_{:02}.php", i),
                if i < 8 {
                    "<?php\nfunction bad() {\n    shell_exec($_GET['cmd']);\n}\n".to_string()
                } else {
                    format!("<?php\nfunction ok_{}() {{ return {}; }}\n", i, i)
                },
            ),
        };
        write_rel_file(dir_a.path(), &rel, &content);
        write_rel_file(dir_b.path(), &rel, &content);
    }

    // Populate cache on workspace A first
    let (_, sarif_a) = run_audit_sarif_stdout(dir_a.path(), &[]);
    assert!(sarif_a.findings.len() >= 8);
    let _ = fs::remove_file(dir_a.path().join("AETHER_AI_RULES.md"));

    let (_, ma, _) = run_benchmark_cli(dir_a.path(), &[]);
    let (_, mb, _) = run_benchmark_cli(dir_b.path(), &[]);

    assert_eq!(ma.files_count, 40);
    assert_eq!(mb.files_count, 40);
    assert_eq!(ma.total_loc, mb.total_loc);
    assert_eq!(ma.anomalies_count, mb.anomalies_count);
    assert!(ma.anomalies_count >= 8);
}

#[test]
fn test_tier3_parallel_scan_shared_masking_and_cache_equivalence() {
    let dir = tempdir().unwrap();
    for i in 0..20 {
        if i % 2 == 0 {
            // Comment & string literal decoys ONLY -> 0 vulnerabilities
            write_rel_file(
                dir.path(),
                &format!("src/decoy_{:02}.rs", i),
                "// format!(\"SELECT * FROM users WHERE id = {}\", id)\npub fn clean() -> &'static str {\n    \"std::mem::transmute::<u64, i64>(x)\"\n}\n",
            );
        } else {
            // Real code vulnerabilities + comment decoys
            write_rel_file(
                dir.path(),
                &format!("app/real_{:02}.js", i),
                "// eval(comment_decoy);\nfunction run(el, x) {\n    const note = \"el.innerHTML = decoy\";\n    el.innerHTML = x;\n    return note;\n}\n",
            );
        }
    }

    let (_, cold) = run_audit_sarif_stdout(dir.path(), &[]);
    let (_, warm) = run_audit_sarif_stdout(dir.path(), &[]);

    assert_eq!(cold.canonical_keys(), warm.canonical_keys());
    assert_eq!(
        cold.count_rule("CVE-JS-XSS-DOM"),
        10,
        "Expected 10 real CVE-JS-XSS-DOM hits (not string literal decoys)"
    );
    assert!(
        !cold.findings.iter().any(|f| f.uri.contains("decoy_")),
        "Comment and string literal decoys must produce 0 findings: {:?}",
        cold.findings
    );
}

#[test]
fn test_tier3_readme_contract_and_plugin_combined_invalidation_with_fail_on() {
    let dir = tempdir().unwrap();
    write_rel_file(
        dir.path(),
        "README.md",
        "---\nid: svc\nlayer: service\nmax_lines_per_file: 200\nforbidden_imports: []\n---\n# Service\n",
    );
    let plugin_rel = ".aether/plugins/gate_pack/plugin.yaml";
    let plugin_enabled = r#"name: gate_pack
version: "1.0.0"
enabled: true
rules:
  - id: GATE-HIGH-01
    cwe_id: CWE-94 / GATE
    name: Legacy Danger
    severity: HIGH
    description: Detects legacy_danger
    remediation: Remove legacy_danger
    file_extensions: [".rs"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "legacy_danger\\s*\\("
"#;
    write_rel_file(dir.path(), plugin_rel, plugin_enabled);
    write_rel_file(
        dir.path(),
        "src/service.rs",
        "use std::net::TcpStream;\npub fn safe_fn() -> usize { let _ = std::any::type_name::<TcpStream>(); 1 }\n",
    );

    // 1. Clean -> --fail-on HIGH exits 0
    let (c1, _) =
        run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s1.sarif"), &["--fail-on", "HIGH"]);
    assert_eq!(c1.status_code, Some(0));

    // 2. Add forbidden_imports -> --fail-on CRITICAL exits 1
    write_rel_file(
        dir.path(),
        "README.md",
        "---\nid: svc\nlayer: service\nmax_lines_per_file: 200\nforbidden_imports:\n  - std::net::TcpStream\n---\n# Service\n",
    );
    let (c2, d2) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("s2.sarif"),
        &["--fail-on", "CRITICAL"],
    );
    assert_eq!(c2.status_code, Some(1));
    assert!(d2.unwrap().has_rule("RULE_FORBIDDEN_IMPORT"));

    // 3. Revert README.md, trigger plugin rule in source -> --fail-on HIGH exits 1
    write_rel_file(
        dir.path(),
        "README.md",
        "---\nid: svc\nlayer: service\nmax_lines_per_file: 200\nforbidden_imports: []\n---\n# Service\n",
    );
    write_rel_file(
        dir.path(),
        "src/service.rs",
        "use std::net::TcpStream;\npub fn unsafe_fn() { legacy_danger(); }\npub fn legacy_danger() {}\n",
    );
    let (c3, d3) =
        run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s3.sarif"), &["--fail-on", "HIGH"]);
    assert_eq!(c3.status_code, Some(1));
    assert!(d3.unwrap().has_rule("GATE-HIGH-01"));

    // 4. Disable plugin -> --fail-on HIGH exits 0
    write_rel_file(
        dir.path(),
        plugin_rel,
        &plugin_enabled.replace("enabled: true", "enabled: false"),
    );
    let (c4, d4) =
        run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s4.sarif"), &["--fail-on", "HIGH"]);
    assert_eq!(c4.status_code, Some(0));
    assert!(!d4.unwrap().has_rule("GATE-HIGH-01"));
}

// ============================================================================
// Tier 4: Real-World Application Scenarios S3 & S4 (2 tests)
// ============================================================================

#[tokio::test]
async fn test_tier4_scenario_s3_multi_module_incremental_cache_and_partial_invalidation() {
    let dir = tempdir().unwrap();

    // Multi-module polyglot workspace (no Cargo.toml)
    write_rel_file(
        dir.path(),
        "api/README.md",
        "---\nid: api\nlayer: action\nmax_lines_per_file: 80\n---\n# API\n",
    );
    write_rel_file(
        dir.path(),
        "api/routes.py",
        "def health():\n    return {\"ok\": True}\n",
    );
    write_rel_file(
        dir.path(),
        "api/auth.py",
        "def check_token(tok):\n    return bool(tok)\n",
    );

    write_rel_file(
        dir.path(),
        "billing/README.md",
        "---\nid: billing\nlayer: action\nmax_lines_per_file: 80\n---\n# Billing\n",
    );
    write_rel_file(
        dir.path(),
        "billing/invoice.ts",
        "export function calc(expr: string) {\n    return eval(expr);\n}\n",
    );
    write_rel_file(
        dir.path(),
        "billing/ledger.ts",
        "export function sum(a: number, b: number): number { return a + b; }\n",
    );

    write_rel_file(
        dir.path(),
        "core/README.md",
        "---\nid: core\nlayer: domain\nmax_lines_per_file: 80\nsecurity_rules:\n  no_env_access: false\n---\n# Core\n",
    );
    let core_engine_lines = (1..=10)
        .map(|i| format!("pub fn step_{}() -> i32 {{ {} }}\n", i, i))
        .collect::<String>()
        + "pub fn env_mode() -> String {\n    std::env::var(\"BILLING_MODE\").unwrap_or_default()\n}\n";
    write_rel_file(dir.path(), "core/engine.rs", &core_engine_lines);
    write_rel_file(
        dir.path(),
        "core/utils.rs",
        "pub fn clamp(v: i32) -> i32 { v.max(0) }\n",
    );

    write_rel_file(
        dir.path(),
        ".aether/plugins/org-guard/plugin.yaml",
        r#"name: org-guard
version: "1.0.0"
enabled: true
rules:
  - id: ORG-AUDIT-01
    cwe_id: CWE-778 / AUDIT-BYPASS
    name: Audit Bypass
    severity: HIGH
    description: Detects bypass_audit call
    remediation: Always log audit trail
    file_extensions: [".py", ".ts"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "bypass_audit\\s*\\("
"#,
    );

    // 1. Cold scan
    let (c1, d1) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s3_cold.sarif"), &[]);
    assert!(c1.success);
    let d1 = d1.unwrap();
    assert!(d1.has_rule_in_uri("CVE-JS-CODE-INJ", "billing/invoice.ts"));
    assert!(!d1.has_rule("ORG-AUDIT-01"));
    assert!(!d1.has_rule("RULE_MAX_LINES"));
    let cache1 = assert_cache_populated(dir.path());

    // 2. Warm scan: identical SARIF + cache invariance
    std::thread::sleep(Duration::from_millis(60));
    let (c2, d2) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s3_warm.sarif"), &[]);
    assert!(c2.success);
    let d2 = d2.unwrap();
    assert_eq!(d1.canonical_keys(), d2.canonical_keys());
    assert_eq!(cache1, assert_cache_populated(dir.path()));

    // 3. Targeted source edit ONLY in api/auth.py
    write_rel_file(
        dir.path(),
        "api/auth.py",
        "def check_token(tok):\n    return bypass_audit(tok)\n",
    );
    let (c3, d3) = run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s3_src.sarif"), &[]);
    assert!(c3.success);
    let d3 = d3.unwrap();
    assert!(d3.has_rule_in_uri("ORG-AUDIT-01", "api/auth.py"));
    assert!(d3.has_rule_in_uri("CVE-JS-CODE-INJ", "billing/invoice.ts"));

    // 4. Targeted contract edit ONLY in core/README.md (tighten max_lines_per_file: 5)
    write_rel_file(
        dir.path(),
        "core/README.md",
        "---\nid: core\nlayer: domain\nmax_lines_per_file: 5\nsecurity_rules:\n  no_env_access: true\n---\n# Core\n",
    );
    let (c4, d4) =
        run_audit_sarif_file(dir.path(), dir.path(), &dir.path().join("s3_contract.sarif"), &[]);
    assert!(c4.success);
    let d4 = d4.unwrap();
    assert!(d4.has_rule_in_uri("RULE_MAX_LINES", "core/engine.rs"));
    assert!(d4.has_rule_in_uri("SAST_DIRECT_ENV_ACCESS", "core/engine.rs"));
    assert!(!d4.has_rule_in_uri("RULE_MAX_LINES", "api/auth.py"));
    assert!(!d4.has_rule_in_uri("RULE_MAX_LINES", "billing/invoice.ts"));
    assert!(d4.has_rule_in_uri("ORG-AUDIT-01", "api/auth.py"));
    assert!(d4.has_rule_in_uri("CVE-JS-CODE-INJ", "billing/invoice.ts"));

    // 5. Verify live --no-gui POST /api/analyze reflects same state
    let srv = spawn_no_gui_server(dir.path(), &[]).await;
    let _ = http_post_json(
        srv.port,
        "/api/analyze",
        &serde_json::json!({ "path": dir.path().to_string_lossy() }),
    )
    .await;
    let g = http_get_json(srv.port, "/api/graph?full=1").await;
    let anoms = extract_graph_anomalies(&g);
    assert!(anoms.iter().any(|(r, fp, _)| r == "ORG-AUDIT-01" && fp == "api/auth.py"));
    assert!(anoms.iter().any(|(r, fp, _)| r == "RULE_MAX_LINES" && fp == "core/engine.rs"));
}

#[tokio::test]
async fn test_tier4_scenario_s4_medium_scale_polyglot_benchmark_and_parallel_consistency() {
    let dir = tempdir().unwrap();

    write_rel_file(
        dir.path(),
        ".aether/plugins/s4-sec/plugin.yaml",
        r#"name: s4-sec
version: "1.0.0"
enabled: true
profile: prod
rules:
  - id: S4-CUSTOM-01
    cwe_id: CWE-94 / S4-PROD
    name: Prod Unsafe Hook
    severity: HIGH
    description: Detects prod_unsafe_hook
    remediation: Replace with safe hook
    file_extensions: [".py", ".ts", ".rs", ".php"]
    match_mode: line_by_line
    conditions:
      regex_patterns:
        - "prod_unsafe_hook\\s*\\("
"#,
    );

    // 128 polyglot files (~130 LOC each => ~16,640 LOC) using extensions supported by both benchmark & scanner
    for i in 0..128usize {
        let mut s = String::new();
        match i % 8 {
            0 => {
                s.push_str(&format!("pub fn gw_{}(v: i64) -> i64 {{\n    let mut a = v;\n", i));
                for l in 0..124 {
                    s.push_str(&format!("    a = a.wrapping_add({});\n", l));
                }
                if i == 0 || i == 8 {
                    s.push_str("    let api_key = \"AKIA1234567890ABCDEF12\";\n    let _ = api_key;\n");
                }
                if i == 16 {
                    s.push_str("    prod_unsafe_hook(a);\n");
                }
                s.push_str("    a\n}\n");
                write_rel_file(dir.path(), &format!("gateway/gw_{:03}.rs", i), &s);
            }
            1 => {
                s.push_str(&format!("export function svc_{}(n: number): number {{\n    let t = n;\n", i));
                for l in 0..124 {
                    s.push_str(&format!("    t += {};\n", l));
                }
                if i == 1 || i == 9 {
                    s.push_str("    eval(String(t));\n");
                }
                if i == 17 {
                    s.push_str("    prod_unsafe_hook(t);\n");
                }
                s.push_str("    return t;\n}\n");
                write_rel_file(dir.path(), &format!("services/svc_{:03}.ts", i), &s);
            }
            2 => {
                s.push_str(&format!("function r_{}(el, n) {{\n    let x = n;\n", i));
                for l in 0..124 {
                    s.push_str(&format!("    x += {};\n", l));
                }
                if i == 2 {
                    s.push_str("    el.innerHTML = x;\n");
                }
                s.push_str("    return x;\n}\n");
                write_rel_file(dir.path(), &format!("gateway/r_{:03}.js", i), &s);
            }
            3 => {
                s.push_str(&format!("def w_{}(v):\n    acc = v\n", i));
                for l in 0..124 {
                    s.push_str(&format!("    acc += {}\n", l));
                }
                if i == 3 || i == 11 {
                    s.push_str("    import os\n    os.system(str(acc))\n");
                }
                if i == 19 {
                    s.push_str("    prod_unsafe_hook(acc)\n");
                }
                s.push_str("    return acc\n");
                write_rel_file(dir.path(), &format!("workers/w_{:03}.py", i), &s);
            }
            4 => {
                s.push_str(&format!("<?php\nfunction p_{}($v) {{\n    $x = $v;\n", i));
                for l in 0..123 {
                    s.push_str(&format!("    $x += {};\n", l));
                }
                if i == 4 {
                    s.push_str("    shell_exec($_GET['cmd']);\n");
                }
                if i == 20 {
                    s.push_str("    prod_unsafe_hook($x);\n");
                }
                s.push_str("    return $x;\n}\n");
                write_rel_file(dir.path(), &format!("services/p_{:03}.php", i), &s);
            }
            5 => {
                s.push_str(&format!("public class J_{:03} {{\n    public int run(int v) {{\n        int x = v;\n", i));
                for l in 0..123 {
                    s.push_str(&format!("        x += {};\n", l));
                }
                s.push_str("        return x;\n    }\n}\n");
                write_rel_file(dir.path(), &format!("services/J_{:03}.java", i), &s);
            }
            6 => {
                s.push_str(&format!("pragma solidity ^0.8.20;\ncontract C_{:03} {{\n    function run(uint256 v) public pure returns (uint256) {{\n        uint256 x = v;\n", i));
                for l in 0..122 {
                    s.push_str(&format!("        x += {};\n", l));
                }
                s.push_str("        return x;\n    }\n}\n");
                write_rel_file(dir.path(), &format!("contracts/C_{:03}.sol", i), &s);
            }
            _ => {
                s.push_str(&format!("local function l_{}(v)\n    local x = v\n", i));
                for l in 0..124 {
                    s.push_str(&format!("    x = x + {}\n", l));
                }
                s.push_str("    return x\nend\n");
                write_rel_file(dir.path(), &format!("workers/l_{:03}.luau", i), &s);
            }
        }
    }

    // 1. Cold --benchmark
    let (_, bench_cold, bench_md) = run_benchmark_cli(dir.path(), &[]);
    assert_eq!(bench_cold.files_count, 128);
    assert_eq!(bench_md.files_count, 128);
    assert!(bench_cold.total_loc >= 15_000);
    assert!(bench_cold.lexing_ms > 0.0);
    assert!(bench_cold.ast_ms > 0.0);
    assert!(bench_cold.cwe_ms > 0.0);
    assert!(bench_cold.total_ms > 0.0);
    assert!(bench_cold.throughput_loc_s > 0.0);
    assert!(bench_cold.peak_rss_mb > 0.0);
    assert!(bench_cold.anomalies_count >= 8);

    // 2. --audit-only --plugins all (twice to confirm warm cache stability)
    let (c1, d1) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("s4_all1.sarif"),
        &["--plugins", "all"],
    );
    assert!(c1.success, "s4 --plugins all failed: {}", c1.stderr);
    let d1 = d1.unwrap();
    assert_eq!(d1.count_rule("S4-CUSTOM-01"), 4);
    assert!(d1.findings.len() >= 12);
    let cache1 = assert_cache_populated(dir.path());

    std::thread::sleep(Duration::from_millis(60));
    let (c2, d2) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("s4_all2.sarif"),
        &["--plugins", "all"],
    );
    assert!(c2.success);
    assert_eq!(d1.canonical_keys(), d2.unwrap().canonical_keys());
    assert_eq!(cache1, assert_cache_populated(dir.path()));

    // 3. --audit-only --plugins profile:prod
    let (c3, d3) = run_audit_sarif_file(
        dir.path(),
        dir.path(),
        &dir.path().join("s4_prod.sarif"),
        &["--plugins", "profile:prod"],
    );
    assert!(c3.success, "s4 --plugins profile:prod failed: {}", c3.stderr);
    assert_eq!(d3.unwrap().count_rule("S4-CUSTOM-01"), 4);

    // 4. --no-gui GET /api/graph?full=1 consistency
    let srv = spawn_no_gui_server(dir.path(), &[]).await;
    let g = http_get_json(srv.port, "/api/graph?full=1").await;
    assert_eq!(g["stats"]["files_scanned"].as_u64(), Some(128));
    let anoms = extract_graph_anomalies(&g);
    assert!(
        anoms.iter().filter(|(r, _, _)| r == "S4-CUSTOM-01").count() >= 4,
        "Expected 4 S4-CUSTOM-01 anomalies in /api/graph?full=1"
    );
}
