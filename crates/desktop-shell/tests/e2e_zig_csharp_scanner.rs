//! End-to-End Integration Test Suite for Zig & C# Static Analysis,
//! CWE Vulnerability Engine, Polyglot Isolation, SARIF v2.1.0, and CLI Verification.
//!
//! Milestones Covered:
//! - Milestone M3 (Feature F11: Polyglot E2E CLI & SARIF Integration)
//! - Validation of Features:
//!   - F1: Zig File Discovery
//!   - F2: Zig AST Symbol Extraction
//!   - F3: C# File Discovery
//!   - F4: C# AST Symbol Extraction
//!   - F6: Lexer Masking for Zig and C#
//!   - F7: Zig CWE Rules Catalog (8 rules)
//!   - F8: C# CWE Rules Catalog (10 rules)
//!
//! Test Tier Taxonomy:
//! - Tier 1: Feature Coverage (healthy AST symbol extraction & vulnerability alerts)
//! - Tier 2: Boundary Cases (0 false positives on clean & safe idioms)
//! - Tier 3: Polyglot Cross-Feature Interactions & Isolation (.rs, .zig, .cs, .php)
//! - Tier 4: SARIF v2.1.0 Export, Canonical MITRE Help URIs, and CLI --fail-on Exit Codes

use ast_scanner::ProjectScanner;
use core_graph::bubble::{CveAnomalyRecord, SymbolKind};
use security_linter::sarif::SarifReport;
use security_linter::SecurityLinter;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Drop-guard for automatically cleaning up isolated temporary test directories.
struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), unique_id));
        fs::create_dir_all(&path).expect("Failed to create temporary test directory");
        Self { path }
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Helper function to locate the compiled aether-engine binary.
fn get_aether_engine_exe() -> PathBuf {
    if let Some(exe_str) = option_env!("CARGO_BIN_EXE_aether-engine") {
        let p = PathBuf::from(exe_str);
        if p.exists() {
            return p;
        }
    }
    let target_debug = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "aether-engine.exe" } else { "aether-engine" });
    target_debug
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1: TIER 1 & TIER 2 — FEATURE COVERAGE, AST EXTRACTION & ZERO FALSE POSITIVES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tier1_tier2_healthy_zig_csharp_ast_extraction_and_zero_false_positives() {
    let temp_dir = TempTestDir::new("e2e_zig_cs_healthy");
    let zig_dir = temp_dir.path.join("src").join("zig");
    let cs_dir = temp_dir.path.join("src").join("csharp");
    fs::create_dir_all(&zig_dir).expect("create zig dir");
    fs::create_dir_all(&cs_dir).expect("create csharp dir");

    // 1. Healthy Zig Service Fixture
    let healthy_zig = r#"
const std = @import("std");

pub const ServiceConfig = struct {
    port: u16 = 8080,
    max_connections: u32 = 1000,
    active: bool = true,
};

pub fn initService(allocator: std.mem.Allocator, port: u16) !ServiceConfig {
    const total = @addWithOverflow(port, 10);
    if (total[1] != 0) return error.PortOverflow;
    const buf = try allocator.alloc(u8, 64);
    defer allocator.free(buf);
    @memset(buf, 0);
    return ServiceConfig{ .port = total[0], .max_connections = 1000, .active = true };
}

pub fn handleRequest(self: *ServiceConfig, stream: std.net.Stream) !void {
    _ = stream;
    self.active = true;
}
"#;
    let zig_file = zig_dir.join("service.zig");
    fs::write(&zig_file, healthy_zig).expect("write healthy zig");

    // 2. Healthy C# Web API Controller Fixture
    let healthy_cs = r#"
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace AetherEngine.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase {
    public int MaxRetryLimit { get; set; } = 5;

    [HttpGet("{id}")]
    public async Task<IActionResult> GetUser(int id) {
        using (var sha256 = SHA256.Create()) {
            byte[] hash = sha256.ComputeHash(new byte[] { 1, 2, 3 });
            return Ok(Convert.ToHexString(hash));
        }
    }

    [HttpPost("transfer")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> TransferFunds(decimal amount) {
        return Ok(amount);
    }
}
"#;
    let cs_file = cs_dir.join("UserController.cs");
    fs::write(&cs_file, healthy_cs).expect("write healthy cs");

    // 3. Scan with ProjectScanner
    let scanner = ProjectScanner::default();
    let graph = scanner.scan_project(&temp_dir.path);

    // 4. Verify AST File Nodes & Discovery
    let zig_node = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.ends_with("service.zig"))
        .expect("service.zig file node must be discovered");
    assert_eq!(zig_node.metadata.file_type, "zig", "File type must be 'zig'");

    let cs_node = graph
        .nodes
        .iter()
        .find(|n| n.is_file && n.file_path.ends_with("UserController.cs"))
        .expect("UserController.cs file node must be discovered");
    assert_eq!(cs_node.metadata.file_type, "csharp", "File type must be 'csharp'");

    // 5. Verify Zig Symbol Bubbles (struct, functions, methods)
    let struct_bubble = graph
        .nodes
        .iter()
        .find(|n| n.name == "ServiceConfig")
        .expect("ServiceConfig struct bubble must be extracted");
    assert!(struct_bubble.is_class, "Struct must have is_class = true");
    assert!(
        struct_bubble.metadata.attributes.iter().any(|a| a.name == "port"),
        "Struct attribute 'port' must be captured"
    );

    let init_fn = graph
        .nodes
        .iter()
        .find(|n| n.name == "initService")
        .expect("initService function bubble must be extracted");
    assert!(!init_fn.is_class, "initService is a function");

    let method_bubble = graph
        .nodes
        .iter()
        .find(|n| n.name == "handleRequest")
        .expect("handleRequest method bubble must be extracted");
    assert_eq!(method_bubble.stereotype, "«Method»", "handleRequest should have «Method» stereotype");

    // 6. Verify C# Symbol Bubbles (class, controller stereotype, endpoint)
    let class_bubble = graph
        .nodes
        .iter()
        .find(|n| n.name == "UserController")
        .expect("UserController class bubble must be extracted");
    assert!(class_bubble.is_class, "UserController is a class");
    assert_eq!(class_bubble.stereotype, "«Controller»", "Class inheriting ControllerBase must be «Controller»");

    let endpoint_bubble = graph
        .nodes
        .iter()
        .find(|n| n.name == "GetUser")
        .expect("GetUser endpoint bubble must be extracted");
    assert_eq!(endpoint_bubble.kind, SymbolKind::FormOrEndpoint, "Action method must be FormOrEndpoint");
    assert_eq!(endpoint_bubble.stereotype, "«Endpoint»", "Action method must be stereotyped «Endpoint»");

    // 7. Tier 2: Zero False Positives Assertion on Clean Files
    let zig_violations = SecurityLinter::audit_file("src/zig/service.zig", healthy_zig, None);
    assert!(
        zig_violations.is_empty(),
        "Healthy Zig code must produce 0 false positives, got {:?}",
        zig_violations
    );

    let cs_violations = SecurityLinter::audit_file("src/csharp/UserController.cs", healthy_cs, None);
    assert!(
        cs_violations.is_empty(),
        "Healthy C# code must produce 0 false positives, got {:?}",
        cs_violations
    );

    // 8. Verify Graph Nodes have zero security violations attached
    for node in &graph.nodes {
        if node.file_path.ends_with("service.zig") || node.file_path.ends_with("UserController.cs") {
            assert!(
                node.metadata.cve_anomalies.is_empty(),
                "Node {} should have 0 CVE anomalies, found: {:?}",
                node.name,
                node.metadata.cve_anomalies
            );
            assert!(
                !node.has_security_violation,
                "Node {} has_security_violation must be false",
                node.name
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2: TIER 1 & TIER 2 — VULNERABILITY DETECTION ACROSS ALL 18 CWE RULES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tier1_tier2_vulnerability_detection_across_all_18_rules() {
    let temp_dir = TempTestDir::new("e2e_zig_cs_vuln");
    let zig_dir = temp_dir.path.join("src").join("zig");
    let cs_dir = temp_dir.path.join("src").join("csharp");
    fs::create_dir_all(&zig_dir).expect("create zig dir");
    fs::create_dir_all(&cs_dir).expect("create cs dir");

    // 8 Vulnerable Zig Fixtures
    let vuln_uaf = r#"
const std = @import("std");
pub fn processMessage(allocator: std.mem.Allocator, data: []const u8) !u8 {
    const buf = try allocator.alloc(u8, data.len);
    @memcpy(buf, data);
    allocator.free(buf);
    return buf[0];
}
"#;
    let vuln_unhandled_err = r#"
const std = @import("std");
pub fn saveSession(file: std.fs.File, token: []const u8) void {
    _ = file.write(token);
}
"#;
    let vuln_overflow = r#"
pub fn computeBufferSize(header_len: u32, payload_len: u32) u32 {
    return header_len +% payload_len;
}
"#;
    let vuln_cast = r#"
const PacketHeader = extern struct { id: u32, timestamp: u64 };
pub fn parseHeader(raw_bytes: []const u8) *const PacketHeader {
    return @ptrCast(@alignCast(raw_bytes.ptr));
}
"#;
    let vuln_uninit = r#"
const std = @import("std");
pub fn sendKey(writer: anytype) !void {
    var key: [32]u8 = undefined;
    try writer.writeAll(&key);
}
"#;
    let vuln_c_overrun = r#"
const c = @cImport(@cInclude("stdio.h"));
pub fn printUntrustedName(name: []const u8) void {
    _ = c.printf(name.ptr);
}
"#;
    let vuln_fmt = r#"
const c = @cImport(@cInclude("stdio.h"));
pub fn logEvent(user_msg: [*:0]const u8) void {
    _ = c.printf(user_msg);
}
"#;
    let vuln_leak = r#"
const std = @import("std");
pub fn processTempSession(allocator: std.mem.Allocator) !void {
    const session_data = try allocator.alloc(u8, 2048);
    _ = session_data;
}
"#;

    fs::write(zig_dir.join("uaf.zig"), vuln_uaf).unwrap();
    fs::write(zig_dir.join("unhandled_error.zig"), vuln_unhandled_err).unwrap();
    fs::write(zig_dir.join("wrapping.zig"), vuln_overflow).unwrap();
    fs::write(zig_dir.join("insecure_cast.zig"), vuln_cast).unwrap();
    fs::write(zig_dir.join("uninit.zig"), vuln_uninit).unwrap();
    fs::write(zig_dir.join("buffer_overrun.zig"), vuln_c_overrun).unwrap();
    fs::write(zig_dir.join("format_string.zig"), vuln_fmt).unwrap();
    fs::write(zig_dir.join("alloc_leak.zig"), vuln_leak).unwrap();

    // 10 Vulnerable C# Fixtures
    let vuln_deser = r#"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
public class ImportService {
    public object RestoreState(Stream networkStream) {
        BinaryFormatter formatter = new BinaryFormatter();
        return formatter.Deserialize(networkStream);
    }
}
"#;
    let vuln_sql = r#"
using System.Data.SqlClient;
public class UserRepository {
    public void DeleteUser(SqlConnection conn, string username) {
        string sql = $"DELETE FROM Users WHERE Username = '{username}'";
        SqlCommand cmd = new SqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }
}
"#;
    let vuln_cmd = r#"
using System.Diagnostics;
public class ProcessRunner {
    public void PingHost(string host) {
        Process.Start("cmd.exe", "/c ping -n 1 " + host);
    }
}
"#;
    let vuln_path = r#"
using System.IO;
public class FileController {
    public string ReadUserDocument(string baseFolder, string fileName) {
        string fullPath = Path.Combine(baseFolder, fileName);
        return File.ReadAllText(fullPath);
    }
}
"#;
    let vuln_crypto = r#"
using System.Security.Cryptography;
public class Hasher {
    public byte[] HashPassword(byte[] password) {
        using (var md5 = MD5.Create()) {
            return md5.ComputeHash(password);
        }
    }
}
"#;
    let vuln_xss = r#"
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.RazorPages;
public class UserProfileModel : PageModel {
    public HtmlString RenderBio(string userBio) {
        return new HtmlString(userBio);
    }
}
"#;
    let vuln_xxe = r#"
using System.Xml;
public class XmlParser {
    public void ParseDocument(string xml) {
        XmlDocument doc = new XmlDocument();
        doc.XmlResolver = new XmlUrlResolver();
        doc.LoadXml(xml);
    }
}
"#;
    let vuln_random = r#"
using System;
public class TokenGenerator {
    public int GenerateAuthCode() {
        Random rng = new Random();
        return rng.Next(100000, 999999);
    }
}
"#;
    let vuln_ldap = r#"
using System.DirectoryServices;
public class LdapService {
    public SearchResult FindAccount(DirectoryEntry root, string user) {
        DirectorySearcher searcher = new DirectorySearcher(root);
        searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + user + "))";
        return searcher.FindOne();
    }
}
"#;
    let vuln_csrf = r#"
using Microsoft.AspNetCore.Mvc;
public class AccountController : Controller {
    [HttpPost]
    [IgnoreAntiforgeryToken]
    public IActionResult TransferFunds(decimal amount) {
        return Ok();
    }
}
"#;

    fs::write(cs_dir.join("InsecureDeser.cs"), vuln_deser).unwrap();
    fs::write(cs_dir.join("SqlInjection.cs"), vuln_sql).unwrap();
    fs::write(cs_dir.join("CmdInjection.cs"), vuln_cmd).unwrap();
    fs::write(cs_dir.join("PathTraversal.cs"), vuln_path).unwrap();
    fs::write(cs_dir.join("WeakCrypto.cs"), vuln_crypto).unwrap();
    fs::write(cs_dir.join("XssRawHtml.cs"), vuln_xss).unwrap();
    fs::write(cs_dir.join("XxeInjection.cs"), vuln_xxe).unwrap();
    fs::write(cs_dir.join("InsecureRandom.cs"), vuln_random).unwrap();
    fs::write(cs_dir.join("LdapInjection.cs"), vuln_ldap).unwrap();
    fs::write(cs_dir.join("CsrfDisabled.cs"), vuln_csrf).unwrap();

    // Scan Project with ProjectScanner
    let scanner = ProjectScanner::default();
    let graph = scanner.scan_project(&temp_dir.path);

    // Aggregate all anomalies attached to nodes
    let mut detected_anomalies: Vec<CveAnomalyRecord> = Vec::new();
    for node in &graph.nodes {
        detected_anomalies.extend(node.metadata.cve_anomalies.clone());
    }

    let detected_rule_ids: HashSet<String> = detected_anomalies
        .iter()
        .map(|a| a.rule_id.clone())
        .collect();

    // 8 Expected Zig Rules
    let expected_zig_rules = [
        ("CVE-ZIG-USE-AFTER-FREE", "CRITICAL", "CWE-416"),
        ("CVE-ZIG-UNHANDLED-ERROR-UNION", "HIGH", "CWE-703"),
        ("CVE-ZIG-INTEGER-OVERFLOW-WRAPPING", "HIGH", "CWE-190"),
        ("CVE-ZIG-INSECURE-POINTER-CAST", "CRITICAL", "CWE-843"),
        ("CVE-ZIG-UNINITIALIZED-MEMORY", "HIGH", "CWE-457"),
        ("CVE-ZIG-BUFFER-OVERRUN-C-INTEROP", "CRITICAL", "CWE-119"),
        ("CVE-ZIG-UNPROTECTED-C-FORMAT-STRING", "CRITICAL", "CWE-134"),
        ("CVE-ZIG-RAW-ALLOCATOR-LEAK", "HIGH", "CWE-401"),
    ];

    for (rule_id, expected_sev, expected_cwe_prefix) in &expected_zig_rules {
        assert!(
            detected_rule_ids.contains(*rule_id),
            "Expected Zig rule {} to be detected by ProjectScanner",
            rule_id
        );

        let anomaly = detected_anomalies
            .iter()
            .find(|a| a.rule_id == *rule_id)
            .expect("anomaly must be present");
        assert_eq!(
            anomaly.severity, *expected_sev,
            "Rule {} must have severity {}",
            rule_id, expected_sev
        );
        assert!(
            anomaly.cve_id.contains(expected_cwe_prefix),
            "Rule {} cve_id {} must contain {}",
            rule_id, anomaly.cve_id, expected_cwe_prefix
        );
        assert!(anomaly.line_number > 0, "Line number must be > 0");
        assert!(!anomaly.message.is_empty(), "Message must not be empty");
        assert!(!anomaly.remediation.is_empty(), "Remediation must not be empty");
        assert!(
            anomaly.file_path.ends_with(".zig"),
            "Target file for {} must be a .zig file",
            rule_id
        );
    }

    // 10 Expected C# Rules
    let expected_cs_rules = [
        ("CVE-CS-INSECURE-DESERIALIZATION", "CRITICAL", "CWE-502"),
        ("CVE-CS-SQL-INJECTION", "CRITICAL", "CWE-89"),
        ("CVE-CS-COMMAND-INJECTION", "CRITICAL", "CWE-78"),
        ("CVE-CS-PATH-TRAVERSAL", "HIGH", "CWE-22"),
        ("CVE-CS-WEAK-CRYPTOGRAPHY", "HIGH", "CWE-327"),
        ("CVE-CS-XSS-RAW-HTML", "HIGH", "CWE-79"),
        ("CVE-CS-XXE-INJECTION", "HIGH", "CWE-611"),
        ("CVE-CS-INSECURE-RANDOM", "MEDIUM", "CWE-330"),
        ("CVE-CS-LDAP-INJECTION", "HIGH", "CWE-90"),
        ("CVE-CS-CSRF-DISABLED", "MEDIUM", "CWE-352"),
    ];

    for (rule_id, expected_sev, expected_cwe_prefix) in &expected_cs_rules {
        assert!(
            detected_rule_ids.contains(*rule_id),
            "Expected C# rule {} to be detected by ProjectScanner",
            rule_id
        );

        let anomaly = detected_anomalies
            .iter()
            .find(|a| a.rule_id == *rule_id)
            .expect("anomaly must be present");
        assert_eq!(
            anomaly.severity, *expected_sev,
            "Rule {} must have severity {}",
            rule_id, expected_sev
        );
        assert!(
            anomaly.cve_id.contains(expected_cwe_prefix),
            "Rule {} cve_id {} must contain {}",
            rule_id, anomaly.cve_id, expected_cwe_prefix
        );
        assert!(anomaly.line_number > 0, "Line number must be > 0");
        assert!(!anomaly.message.is_empty(), "Message must not be empty");
        assert!(!anomaly.remediation.is_empty(), "Remediation must not be empty");
        assert!(
            anomaly.file_path.ends_with(".cs"),
            "Target file for {} must be a .cs file",
            rule_id
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3: TIER 3 — POLYGLOT CROSS-FEATURE INTERACTIONS & ISOLATION
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tier3_polyglot_cross_feature_isolation_and_no_rule_bleeding() {
    let temp_dir = TempTestDir::new("e2e_polyglot_isolation");

    let zig_path = temp_dir.path.join("src").join("native").join("engine.zig");
    let cs_path = temp_dir.path.join("src").join("backend").join("Service.cs");
    let rs_path = temp_dir.path.join("src").join("core").join("crypto.rs");
    let php_path = temp_dir.path.join("src").join("web").join("bridge.php");

    fs::create_dir_all(zig_path.parent().unwrap()).unwrap();
    fs::create_dir_all(cs_path.parent().unwrap()).unwrap();
    fs::create_dir_all(rs_path.parent().unwrap()).unwrap();
    fs::create_dir_all(php_path.parent().unwrap()).unwrap();

    // 1. Clean Zig Code
    let clean_zig = r#"
const std = @import("std");

pub fn safeCompute(allocator: std.mem.Allocator) !u32 {
    const mem = try allocator.alloc(u32, 16);
    defer allocator.free(mem);
    @memset(mem, 0);
    return mem[0];
}
"#;
    fs::write(&zig_path, clean_zig).unwrap();

    // 2. Clean C# Code
    let clean_cs = r#"
using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace MyPolyglot.Backend;

public class Service : ControllerBase {
    public byte[] HashToken(byte[] input) {
        using (var sha = SHA256.Create()) {
            return sha.ComputeHash(input);
        }
    }
}
"#;
    fs::write(&cs_path, clean_cs).unwrap();

    // 3. Rust Code containing tokens that might superficially look like C# or Zig
    let adversarial_rs = r#"
// Adversarial test: Rust file with keywords from other languages
// using System.Runtime.Serialization.Formatters.Binary;
// BinaryFormatter.Deserialize(stream);
// @ptrCast(@alignCast(raw.ptr));
// [IgnoreAntiforgeryToken]
// defer allocator.free(buf);

pub fn compute_hash(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(data);
    v
}
"#;
    fs::write(&rs_path, adversarial_rs).unwrap();

    // 4. PHP Code containing similar tokens
    let adversarial_php = r#"<?php
// Adversarial test: PHP file with Zig and C# tokens
// @ptrCast, std.mem.Allocator, BinaryFormatter, DtdProcessing
function handleRequest($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}
"#;
    fs::write(&php_path, adversarial_php).unwrap();

    // Scan the polyglot workspace
    let scanner = ProjectScanner::default();
    let graph = scanner.scan_project(&temp_dir.path);

    // Verify all 4 files are recognized
    assert!(
        graph.nodes.iter().any(|n| n.is_file && n.file_path.ends_with("engine.zig")),
        "engine.zig must be in graph"
    );
    assert!(
        graph.nodes.iter().any(|n| n.is_file && n.file_path.ends_with("Service.cs")),
        "Service.cs must be in graph"
    );
    assert!(
        graph.nodes.iter().any(|n| n.is_file && n.file_path.ends_with("crypto.rs")),
        "crypto.rs must be in graph"
    );
    assert!(
        graph.nodes.iter().any(|n| n.is_file && n.file_path.ends_with("bridge.php")),
        "bridge.php must be in graph"
    );

    // Verify strict isolation: no cross-language rule bleeding
    for node in &graph.nodes {
        let file_path = &node.file_path;

        if file_path.ends_with(".rs") {
            for anomaly in &node.metadata.cve_anomalies {
                assert!(
                    !anomaly.rule_id.starts_with("CVE-ZIG-"),
                    "Zig rule {} must NOT trigger on Rust file {}",
                    anomaly.rule_id, file_path
                );
                assert!(
                    !anomaly.rule_id.starts_with("CVE-CS-"),
                    "C# rule {} must NOT trigger on Rust file {}",
                    anomaly.rule_id, file_path
                );
            }
        } else if file_path.ends_with(".php") {
            for anomaly in &node.metadata.cve_anomalies {
                assert!(
                    !anomaly.rule_id.starts_with("CVE-ZIG-"),
                    "Zig rule {} must NOT trigger on PHP file {}",
                    anomaly.rule_id, file_path
                );
                assert!(
                    !anomaly.rule_id.starts_with("CVE-CS-"),
                    "C# rule {} must NOT trigger on PHP file {}",
                    anomaly.rule_id, file_path
                );
            }
        } else if file_path.ends_with(".zig") {
            for anomaly in &node.metadata.cve_anomalies {
                assert!(
                    !anomaly.rule_id.starts_with("CVE-CS-"),
                    "C# rule {} must NOT trigger on Zig file {}",
                    anomaly.rule_id, file_path
                );
            }
            assert!(
                node.metadata.cve_anomalies.is_empty(),
                "Safe Zig file must have 0 anomalies, found: {:?}",
                node.metadata.cve_anomalies
            );
        } else if file_path.ends_with(".cs") {
            for anomaly in &node.metadata.cve_anomalies {
                assert!(
                    !anomaly.rule_id.starts_with("CVE-ZIG-"),
                    "Zig rule {} must NOT trigger on C# file {}",
                    anomaly.rule_id, file_path
                );
            }
            assert!(
                node.metadata.cve_anomalies.is_empty(),
                "Safe C# file must have 0 anomalies, found: {:?}",
                node.metadata.cve_anomalies
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4: TIER 4 — SARIF V2.1.0 EXPORT & CANONICAL MITRE HELP URIS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tier4_sarif_v2_1_0_export_and_canonical_mitre_help_uris() {
    // 1. Audit sample vulnerable Zig and C# files directly to collect genuine LinterViolations
    let vuln_zig_code = r#"
const std = @import("std");
pub fn leakMem(allocator: std.mem.Allocator) !void {
    const p = try allocator.alloc(u8, 100);
    _ = p;
}
"#;
    let vuln_cs_code = r#"
using System.Data.SqlClient;
public class Repo {
    public void Delete(SqlConnection conn, string id) {
        string q = $"DELETE FROM T WHERE id = '{id}'";
        new SqlCommand(q, conn).ExecuteNonQuery();
    }
}
"#;

    let mut all_anomalies: Vec<CveAnomalyRecord> = Vec::new();

    let zig_violations = SecurityLinter::audit_file("src/leak.zig", vuln_zig_code, None);
    assert!(!zig_violations.is_empty(), "Must find leak violation in Zig");
    for v in zig_violations {
        all_anomalies.push(CveAnomalyRecord {
            rule_id: v.rule_id,
            cve_id: v.cve_id,
            severity: v.severity,
            line_number: v.line_number,
            file_path: v.file_path,
            message: v.message,
            transmitted_data: v.transmitted_data,
            transmitted_type: v.transmitted_type,
            remediation: v.remediation,
            ..Default::default()
        });
    }

    let cs_violations = SecurityLinter::audit_file("src/Repo.cs", vuln_cs_code, None);
    assert!(!cs_violations.is_empty(), "Must find SQL injection violation in C#");
    for v in cs_violations {
        all_anomalies.push(CveAnomalyRecord {
            rule_id: v.rule_id,
            cve_id: v.cve_id,
            severity: v.severity,
            line_number: v.line_number,
            file_path: v.file_path,
            message: v.message,
            transmitted_data: v.transmitted_data,
            transmitted_type: v.transmitted_type,
            remediation: v.remediation,
            ..Default::default()
        });
    }

    // 2. Generate SARIF report using SarifReport::from_anomalies
    let sarif_report = SarifReport::from_anomalies(&all_anomalies, None);
    let sarif_json_str = sarif_report
        .to_json_string_pretty()
        .expect("SARIF serialization must succeed");

    // 3. Parse serialized SARIF JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&sarif_json_str).expect("Serialized SARIF must be valid JSON");

    // 4. Assert SARIF Schema and Version contracts
    assert_eq!(
        parsed.get("$schema").and_then(|v| v.as_str()),
        Some("https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"),
        "$schema must match official SARIF v2.1.0 schema"
    );
    assert_eq!(
        parsed.get("version").and_then(|v| v.as_str()),
        Some("2.1.0"),
        "version must be '2.1.0'"
    );

    // 5. Assert Tool Driver and Rules
    let runs = parsed.get("runs").and_then(|v| v.as_array()).expect("runs array");
    assert_eq!(runs.len(), 1, "Expected exactly 1 run in SARIF report");

    let driver = runs[0].get("tool").and_then(|t| t.get("driver")).expect("tool.driver");
    let driver_name = driver.get("name").and_then(|n| n.as_str()).unwrap_or("");
    assert!(!driver_name.is_empty(), "Driver name must be non-empty");

    let rules = driver.get("rules").and_then(|r| r.as_array()).expect("rules array");
    assert!(rules.len() >= 18, "Rules list must contain at least 18 rules (8 Zig + 10 C#)");

    // Map rules by id
    let rule_map: std::collections::HashMap<String, &serde_json::Value> = rules
        .iter()
        .filter_map(|r| r.get("id").and_then(|id| id.as_str()).map(|id| (id.to_string(), r)))
        .collect();

    // Verify all 8 Zig rules are registered in driver with valid MITRE helpUri
    let zig_rules_expected = [
        ("CVE-ZIG-USE-AFTER-FREE", "416"),
        ("CVE-ZIG-UNHANDLED-ERROR-UNION", "703"),
        ("CVE-ZIG-INTEGER-OVERFLOW-WRAPPING", "190"),
        ("CVE-ZIG-INSECURE-POINTER-CAST", "843"),
        ("CVE-ZIG-UNINITIALIZED-MEMORY", "457"),
        ("CVE-ZIG-BUFFER-OVERRUN-C-INTEROP", "119"),
        ("CVE-ZIG-UNPROTECTED-C-FORMAT-STRING", "134"),
        ("CVE-ZIG-RAW-ALLOCATOR-LEAK", "401"),
    ];

    for (rule_id, cwe_num) in &zig_rules_expected {
        let rule_val = rule_map
            .get(*rule_id)
            .unwrap_or_else(|| panic!("SARIF driver rules must contain {}", rule_id));
        let help_uri = rule_val
            .get("helpUri")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        let expected_uri = format!("https://cwe.mitre.org/data/definitions/{}.html", cwe_num);
        assert_eq!(
            help_uri, expected_uri,
            "helpUri for rule {} must point to canonical MITRE definition {}",
            rule_id, expected_uri
        );
    }

    // Verify all 10 C# rules are registered in driver with valid MITRE helpUri
    let cs_rules_expected = [
        ("CVE-CS-INSECURE-DESERIALIZATION", "502"),
        ("CVE-CS-SQL-INJECTION", "89"),
        ("CVE-CS-COMMAND-INJECTION", "78"),
        ("CVE-CS-PATH-TRAVERSAL", "22"),
        ("CVE-CS-WEAK-CRYPTOGRAPHY", "327"),
        ("CVE-CS-XSS-RAW-HTML", "79"),
        ("CVE-CS-XXE-INJECTION", "611"),
        ("CVE-CS-INSECURE-RANDOM", "330"),
        ("CVE-CS-LDAP-INJECTION", "90"),
        ("CVE-CS-CSRF-DISABLED", "352"),
    ];

    for (rule_id, cwe_num) in &cs_rules_expected {
        let rule_val = rule_map
            .get(*rule_id)
            .unwrap_or_else(|| panic!("SARIF driver rules must contain {}", rule_id));
        let help_uri = rule_val
            .get("helpUri")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        let expected_uri = format!("https://cwe.mitre.org/data/definitions/{}.html", cwe_num);
        assert_eq!(
            help_uri, expected_uri,
            "helpUri for rule {} must point to canonical MITRE definition {}",
            rule_id, expected_uri
        );
    }

    // 6. Assert Results Array in SARIF
    let results = runs[0].get("results").and_then(|r| r.as_array()).expect("results array");
    assert!(results.len() >= 2, "Results must contain at least the 2 audited findings");

    for res in results {
        let rule_id = res.get("ruleId").and_then(|r| r.as_str()).expect("ruleId");
        let level = res.get("level").and_then(|l| l.as_str()).expect("level");
        assert!(level == "error" || level == "warning", "level must be error or warning");

        let locations = res.get("locations").and_then(|l| l.as_array()).expect("locations");
        assert!(!locations.is_empty(), "Must have at least one location for rule {}", rule_id);

        let phys = locations[0].get("physicalLocation").expect("physicalLocation");
        let uri = phys.get("artifactLocation").and_then(|a| a.get("uri")).and_then(|u| u.as_str()).expect("uri");
        assert!(uri.ends_with(".zig") || uri.ends_with(".cs"), "URI must end in .zig or .cs");

        let line = phys.get("region").and_then(|r| r.get("startLine")).and_then(|l| l.as_u64()).expect("startLine");
        assert!(line > 0, "startLine must be > 0");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 5: CLI VERIFICATION — FAIL-ON SEMANTICS & EXIT CODES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cli_audit_fail_on_semantics_and_exit_codes() {
    let exe_path = get_aether_engine_exe();
    assert!(
        exe_path.exists(),
        "aether-engine executable must exist at {:?}",
        exe_path
    );

    // 1. Scenario A: Safe Codebase with --fail-on HIGH -> Exit Code 0 (Success)
    let safe_dir = TempTestDir::new("cli_safe_test");
    let safe_zig_content = r#"
const std = @import("std");
pub fn safeAdd(a: u32, b: u32) !u32 {
    const res = @addWithOverflow(a, b);
    if (res[1] != 0) return error.Overflow;
    return res[0];
}
"#;
    let safe_cs_content = r#"
using System;
using System.Security.Cryptography;
public class SafeService {
    public byte[] Hash(byte[] data) {
        using (var sha = SHA256.Create()) {
            return sha.ComputeHash(data);
        }
    }
}
"#;
    fs::create_dir_all(safe_dir.path.join("src")).unwrap();
    fs::write(safe_dir.path.join("src").join("calc.zig"), safe_zig_content).unwrap();
    fs::write(safe_dir.path.join("src").join("Hasher.cs"), safe_cs_content).unwrap();

    let safe_output = Command::new(&exe_path)
        .arg("--audit-only")
        .arg("--path")
        .arg(&safe_dir.path)
        .arg("--fail-on")
        .arg("HIGH")
        .output()
        .expect("Failed to execute aether-engine on safe codebase");

    assert_eq!(
        safe_output.status.code(),
        Some(0),
        "Safe codebase must pass with exit code 0. Stderr: {}",
        String::from_utf8_lossy(&safe_output.stderr)
    );

    // 2. Scenario B: Vulnerable Zig Codebase with --fail-on CRITICAL -> Exit Code 1 (Failure)
    let vuln_zig_dir = TempTestDir::new("cli_vuln_zig_test");
    let vuln_zig_content = r#"
const std = @import("std");
pub fn uaf(allocator: std.mem.Allocator) !u8 {
    const buf = try allocator.alloc(u8, 16);
    allocator.free(buf);
    return buf[0];
}
"#;
    fs::create_dir_all(vuln_zig_dir.path.join("src")).unwrap();
    fs::write(vuln_zig_dir.path.join("src").join("uaf.zig"), vuln_zig_content).unwrap();

    let vuln_zig_output = Command::new(&exe_path)
        .arg("--audit-only")
        .arg("--path")
        .arg(&vuln_zig_dir.path)
        .arg("--fail-on")
        .arg("CRITICAL")
        .output()
        .expect("Failed to execute aether-engine on vulnerable Zig codebase");

    assert_eq!(
        vuln_zig_output.status.code(),
        Some(1),
        "Vulnerable Zig codebase with CRITICAL UAF must fail with exit code 1"
    );
    let stderr_zig = String::from_utf8_lossy(&vuln_zig_output.stderr);
    let stdout_zig = String::from_utf8_lossy(&vuln_zig_output.stdout);
    assert!(
        stderr_zig.contains("FAIL-ON") || stderr_zig.contains("CVE-ZIG-USE-AFTER-FREE") || stdout_zig.contains("CVE-ZIG-USE-AFTER-FREE"),
        "Output must report the blocking vulnerability: stderr: {}, stdout: {}",
        stderr_zig, stdout_zig
    );

    // 3. Scenario C: Vulnerable C# Codebase with --fail-on HIGH -> Exit Code 1 (Failure)
    let vuln_cs_dir = TempTestDir::new("cli_vuln_cs_test");
    let vuln_cs_content = r#"
using System.Data.SqlClient;
public class BadRepo {
    public void DeleteUser(SqlConnection conn, string name) {
        string q = $"DELETE FROM Users WHERE Name = '{name}'";
        new SqlCommand(q, conn).ExecuteNonQuery();
    }
}
"#;
    fs::create_dir_all(vuln_cs_dir.path.join("src")).unwrap();
    fs::write(vuln_cs_dir.path.join("src").join("BadRepo.cs"), vuln_cs_content).unwrap();

    let vuln_cs_output = Command::new(&exe_path)
        .arg("--audit-only")
        .arg("--path")
        .arg(&vuln_cs_dir.path)
        .arg("--fail-on")
        .arg("HIGH")
        .output()
        .expect("Failed to execute aether-engine on vulnerable C# codebase");

    assert_eq!(
        vuln_cs_output.status.code(),
        Some(1),
        "Vulnerable C# codebase with SQL Injection must fail with exit code 1"
    );
    let stderr_cs = String::from_utf8_lossy(&vuln_cs_output.stderr);
    let stdout_cs = String::from_utf8_lossy(&vuln_cs_output.stdout);
    assert!(
        stderr_cs.contains("FAIL-ON") || stderr_cs.contains("CVE-CS-SQL-INJECTION") || stdout_cs.contains("CVE-CS-SQL-INJECTION"),
        "Output must report the blocking SQL Injection: stderr: {}, stdout: {}",
        stderr_cs, stdout_cs
    );

    // 4. Scenario D: SARIF File Export via CLI -> Exit Code 0 & Valid SARIF Output File
    let sarif_out_dir = TempTestDir::new("cli_sarif_export");
    let sarif_file = sarif_out_dir.path.join("report.sarif");

    let sarif_export_output = Command::new(&exe_path)
        .arg("--audit-only")
        .arg("--path")
        .arg(&vuln_cs_dir.path)
        .arg("--format")
        .arg("sarif")
        .arg("-o")
        .arg(&sarif_file)
        .output()
        .expect("Failed to execute aether-engine SARIF export");

    assert_eq!(
        sarif_export_output.status.code(),
        Some(0),
        "SARIF export without --fail-on must succeed with code 0"
    );
    assert!(sarif_file.exists(), "Exported SARIF file must exist");

    let sarif_content = fs::read_to_string(&sarif_file).expect("Read exported SARIF");
    assert!(sarif_content.contains("\"version\": \"2.1.0\""), "SARIF must have version 2.1.0");
    assert!(sarif_content.contains("CVE-CS-SQL-INJECTION"), "SARIF must contain detected finding");
}
