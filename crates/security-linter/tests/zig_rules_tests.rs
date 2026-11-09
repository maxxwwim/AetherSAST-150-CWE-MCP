use security_linter::{SecurityLinter, ZigSecurityRules};

#[test]
fn test_cwe_catalog_includes_15_zig_rules_and_file_detection() {
    let catalog = SecurityLinter::get_supported_cve_rules();

    let zig_rules: Vec<_> = catalog
        .iter()
        .filter(|r| r.category.starts_with("Zig /") || r.rule_id.starts_with("CVE-ZIG-"))
        .collect();

    assert_eq!(
        zig_rules.len(),
        15,
        "Expected exactly 15 Zig CWE rules in catalog, found {}",
        zig_rules.len()
    );

    let expected_rules = [
        "CVE-ZIG-USE-AFTER-FREE",
        "CVE-ZIG-UNHANDLED-ERROR-UNION",
        "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING",
        "CVE-ZIG-INSECURE-POINTER-CAST",
        "CVE-ZIG-UNINITIALIZED-MEMORY",
        "CVE-ZIG-BUFFER-OVERRUN-C-INTEROP",
        "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING",
        "CVE-ZIG-RAW-ALLOCATOR-LEAK",
        "CVE-ZIG-COMMAND-INJECTION",
        "CVE-ZIG-PATH-TRAVERSAL",
        "CVE-ZIG-RUNTIME-SAFETY-DISABLED",
        "CVE-ZIG-STACK-ADDRESS-RETURN",
        "CVE-ZIG-TLS-VERIFY-DISABLED",
        "CVE-ZIG-WEAK-PRNG-CRYPTO",
        "CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB",
    ];

    for expected_id in &expected_rules {
        assert!(
            zig_rules.iter().any(|r| r.rule_id == *expected_id),
            "Expected rule {} in catalog",
            expected_id
        );
    }

    for r in &zig_rules {
        assert!(
            r.severity == "CRITICAL" || r.severity == "HIGH",
            "Rule {} must have severity CRITICAL or HIGH, got {}",
            r.rule_id,
            r.severity
        );

        assert!(
            SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "src/engine/alloc.zig"),
            "Rule {} should match .zig file",
            r.rule_id
        );
        assert!(
            !SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "src/main.rs"),
            "Rule {} should NOT match .rs file",
            r.rule_id
        );
        assert!(
            !SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "Services/UserService.cs"),
            "Rule {} should NOT match .cs file",
            r.rule_id
        );
        assert!(
            !SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "app.py"),
            "Rule {} should NOT match .py file",
            r.rule_id
        );
        assert!(
            r.matches_file("src/buffer.zig"),
            "CveRuleDef::matches_file should match Zig file"
        );
    }
}

#[test]
fn test_zig_file_detection_filters() {
    assert!(ZigSecurityRules::is_zig_file("src/main.zig"));
    assert!(ZigSecurityRules::is_zig_file("buffer.zig"));
    assert!(ZigSecurityRules::is_zig_file("C:/Projets/engine/core.ZIG"));
    assert!(!ZigSecurityRules::is_zig_file("main.rs"));
    assert!(!ZigSecurityRules::is_zig_file("app.cs"));
    assert!(!ZigSecurityRules::is_zig_file("index.php"));
    assert!(!ZigSecurityRules::is_zig_file("script.py"));
}

#[test]
fn test_zig_cross_language_isolation() {
    let vuln_snippet = r#"
        pub fn processData(allocator: std.mem.Allocator) !void {
            const buffer = try allocator.alloc(u8, 1024);
            allocator.free(buffer);
            buffer[0] = 42;
        }
    "#;

    // Must return 0 violations on non-Zig file extensions
    let v_cs = SecurityLinter::audit_file("src/Buffer.cs", vuln_snippet, None);
    assert!(!v_cs.iter().any(|v| v.rule_id.starts_with("CVE-ZIG-")));

    let v_rs = SecurityLinter::audit_file("src/buffer.rs", vuln_snippet, None);
    assert!(!v_rs.iter().any(|v| v.rule_id.starts_with("CVE-ZIG-")));

    let v_py = SecurityLinter::audit_file("src/buffer.py", vuln_snippet, None);
    assert!(!v_py.iter().any(|v| v.rule_id.starts_with("CVE-ZIG-")));
}

#[test]
fn test_all_8_zig_cwe_vulnerabilities_and_safe_remediations() {
    // -------------------------------------------------------------
    // 1. CWE-416: Use After Free (CVE-ZIG-USE-AFTER-FREE)
    // -------------------------------------------------------------
    let vuln_uaf = r#"
const std = @import("std");

pub fn processMessage(allocator: std.mem.Allocator, data: []const u8) !u8 {
    const buf = try allocator.alloc(u8, data.len);
    @memcpy(buf, data);
    allocator.free(buf);
    return buf[0];
}
"#;
    let safe_uaf = r#"
const std = @import("std");

pub fn processMessage(allocator: std.mem.Allocator, data: []const u8) !u8 {
    const buf = try allocator.alloc(u8, data.len);
    defer allocator.free(buf);
    @memcpy(buf, data);
    return buf[0];
}
"#;
    let v_uaf = SecurityLinter::audit_file("src/buffer.zig", vuln_uaf, None);
    assert!(
        v_uaf.iter().any(|v| v.rule_id == "CVE-ZIG-USE-AFTER-FREE" && v.severity == "CRITICAL"),
        "Expected CVE-ZIG-USE-AFTER-FREE on vulnerable snippet"
    );
    let s_uaf = SecurityLinter::audit_file("src/buffer.zig", safe_uaf, None);
    assert!(
        !s_uaf.iter().any(|v| v.rule_id == "CVE-ZIG-USE-AFTER-FREE"),
        "Unexpected CVE-ZIG-USE-AFTER-FREE on safe snippet"
    );

    // -------------------------------------------------------------
    // 2. CWE-703 / CWE-391: Unhandled Error Union (CVE-ZIG-UNHANDLED-ERROR-UNION)
    // -------------------------------------------------------------
    let vuln_err = r#"
const std = @import("std");

pub fn saveSession(file: std.fs.File, token: []const u8) void {
    _ = file.write(token);
}
"#;
    let safe_err = r#"
const std = @import("std");

pub fn saveSession(file: std.fs.File, token: []const u8) !void {
    try file.writeAll(token);
}
"#;
    let v_err = SecurityLinter::audit_file("src/io.zig", vuln_err, None);
    assert!(
        v_err.iter().any(|v| v.rule_id == "CVE-ZIG-UNHANDLED-ERROR-UNION" && v.severity == "HIGH"),
        "Expected CVE-ZIG-UNHANDLED-ERROR-UNION on vulnerable snippet"
    );
    let s_err = SecurityLinter::audit_file("src/io.zig", safe_err, None);
    assert!(
        !s_err.iter().any(|v| v.rule_id == "CVE-ZIG-UNHANDLED-ERROR-UNION"),
        "Unexpected CVE-ZIG-UNHANDLED-ERROR-UNION on safe snippet"
    );

    // -------------------------------------------------------------
    // 3. CWE-190: Integer Overflow / Wrapping (CVE-ZIG-INTEGER-OVERFLOW-WRAPPING)
    // -------------------------------------------------------------
    let vuln_overflow = r#"
pub fn computeBufferSize(header_len: u32, payload_len: u32) u32 {
    return header_len +% payload_len;
}
"#;
    let safe_overflow = r#"
const std = @import("std");

pub fn computeBufferSize(header_len: u32, payload_len: u32) !u32 {
    const total = @addWithOverflow(header_len, payload_len);
    if (total[1] != 0) return error.IntegerOverflow;
    return total[0];
}
"#;
    let v_overflow = SecurityLinter::audit_file("src/calc.zig", vuln_overflow, None);
    assert!(
        v_overflow.iter().any(|v| v.rule_id == "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING" && v.severity == "HIGH"),
        "Expected CVE-ZIG-INTEGER-OVERFLOW-WRAPPING on vulnerable snippet"
    );
    let s_overflow = SecurityLinter::audit_file("src/calc.zig", safe_overflow, None);
    assert!(
        !s_overflow.iter().any(|v| v.rule_id == "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING"),
        "Unexpected CVE-ZIG-INTEGER-OVERFLOW-WRAPPING on safe snippet"
    );

    // -------------------------------------------------------------
    // 4. CWE-843: Insecure Pointer Cast (CVE-ZIG-INSECURE-POINTER-CAST)
    // -------------------------------------------------------------
    let vuln_cast = r#"
const PacketHeader = extern struct { id: u32, timestamp: u64 };

pub fn parseHeader(raw_bytes: []const u8) *const PacketHeader {
    return @ptrCast(@alignCast(raw_bytes.ptr));
}
"#;
    let safe_cast = r#"
const std = @import("std");
const PacketHeader = extern struct { id: u32, timestamp: u64 };

pub fn parseHeader(raw_bytes: []const u8) !*const PacketHeader {
    if (raw_bytes.len < @sizeOf(PacketHeader)) return error.BufferTooSmall;
    return std.mem.bytesAsValue(PacketHeader, raw_bytes[0..@sizeOf(PacketHeader)]);
}
"#;
    let v_cast = SecurityLinter::audit_file("src/net.zig", vuln_cast, None);
    assert!(
        v_cast.iter().any(|v| v.rule_id == "CVE-ZIG-INSECURE-POINTER-CAST" && v.severity == "CRITICAL"),
        "Expected CVE-ZIG-INSECURE-POINTER-CAST on vulnerable snippet"
    );
    let s_cast = SecurityLinter::audit_file("src/net.zig", safe_cast, None);
    assert!(
        !s_cast.iter().any(|v| v.rule_id == "CVE-ZIG-INSECURE-POINTER-CAST"),
        "Unexpected CVE-ZIG-INSECURE-POINTER-CAST on safe snippet"
    );

    // -------------------------------------------------------------
    // 5. CWE-457: Uninitialized Memory (CVE-ZIG-UNINITIALIZED-MEMORY)
    // -------------------------------------------------------------
    let vuln_uninit = r#"
const std = @import("std");

pub fn sendKey(writer: anytype) !void {
    var key: [32]u8 = undefined;
    try writer.writeAll(&key);
}
"#;
    let safe_uninit = r#"
const std = @import("std");

pub fn sendKey(writer: anytype) !void {
    var key: [32]u8 = undefined;
    @memset(&key, 0);
    try writer.writeAll(&key);
}
"#;
    let v_uninit = SecurityLinter::audit_file("src/crypto.zig", vuln_uninit, None);
    assert!(
        v_uninit.iter().any(|v| v.rule_id == "CVE-ZIG-UNINITIALIZED-MEMORY" && v.severity == "HIGH"),
        "Expected CVE-ZIG-UNINITIALIZED-MEMORY on vulnerable snippet"
    );
    let s_uninit = SecurityLinter::audit_file("src/crypto.zig", safe_uninit, None);
    assert!(
        !s_uninit.iter().any(|v| v.rule_id == "CVE-ZIG-UNINITIALIZED-MEMORY"),
        "Unexpected CVE-ZIG-UNINITIALIZED-MEMORY on safe snippet"
    );

    // -------------------------------------------------------------
    // 6. CWE-119 / CWE-120: Buffer Overrun & C-Interop (CVE-ZIG-BUFFER-OVERRUN-C-INTEROP)
    // -------------------------------------------------------------
    let vuln_c_overrun = r#"
const c = @cImport(@cInclude("stdio.h"));

pub fn printUntrustedName(name: []const u8) void {
    _ = c.printf(name.ptr);
}
"#;
    let safe_c_overrun = r#"
const std = @import("std");
const c = @cImport(@cInclude("stdio.h"));

pub fn printUntrustedName(allocator: std.mem.Allocator, name: []const u8) !void {
    const null_term = try allocator.dupeZ(u8, name);
    defer allocator.free(null_term);
    _ = c.printf("%s", null_term.ptr);
}
"#;
    let v_c = SecurityLinter::audit_file("src/c_bridge.zig", vuln_c_overrun, None);
    assert!(
        v_c.iter().any(|v| v.rule_id == "CVE-ZIG-BUFFER-OVERRUN-C-INTEROP" && v.severity == "CRITICAL"),
        "Expected CVE-ZIG-BUFFER-OVERRUN-C-INTEROP on vulnerable snippet"
    );
    let s_c = SecurityLinter::audit_file("src/c_bridge.zig", safe_c_overrun, None);
    assert!(
        !s_c.iter().any(|v| v.rule_id == "CVE-ZIG-BUFFER-OVERRUN-C-INTEROP"),
        "Unexpected CVE-ZIG-BUFFER-OVERRUN-C-INTEROP on safe snippet"
    );

    // -------------------------------------------------------------
    // 7. CWE-134: Uncontrolled Format String (CVE-ZIG-UNPROTECTED-C-FORMAT-STRING)
    // -------------------------------------------------------------
    let vuln_fmt = r#"
const c = @cImport(@cInclude("stdio.h"));

pub fn logEvent(user_msg: [*:0]const u8) void {
    _ = c.printf(user_msg);
}
"#;
    let safe_fmt = r#"
const c = @cImport(@cInclude("stdio.h"));

pub fn logEvent(user_msg: [*:0]const u8) void {
    _ = c.printf("%s\n", user_msg);
}
"#;
    let v_fmt = SecurityLinter::audit_file("src/log.zig", vuln_fmt, None);
    assert!(
        v_fmt.iter().any(|v| v.rule_id == "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING" && v.severity == "CRITICAL"),
        "Expected CVE-ZIG-UNPROTECTED-C-FORMAT-STRING on vulnerable snippet"
    );
    let s_fmt = SecurityLinter::audit_file("src/log.zig", safe_fmt, None);
    assert!(
        !s_fmt.iter().any(|v| v.rule_id == "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING"),
        "Unexpected CVE-ZIG-UNPROTECTED-C-FORMAT-STRING on safe snippet"
    );

    // -------------------------------------------------------------
    // 8. CWE-401: Raw Allocator Leak (CVE-ZIG-RAW-ALLOCATOR-LEAK)
    // -------------------------------------------------------------
    let vuln_leak = r#"
const std = @import("std");

pub fn processTempSession(allocator: std.mem.Allocator) !void {
    const session_data = try allocator.alloc(u8, 2048);
    _ = session_data;
}
"#;
    let safe_leak = r#"
const std = @import("std");

pub fn processTempSession(allocator: std.mem.Allocator) !void {
    const session_data = try allocator.alloc(u8, 2048);
    defer allocator.free(session_data);
    _ = session_data;
}
"#;
    let v_leak = SecurityLinter::audit_file("src/session.zig", vuln_leak, None);
    assert!(
        v_leak.iter().any(|v| v.rule_id == "CVE-ZIG-RAW-ALLOCATOR-LEAK" && v.severity == "HIGH"),
        "Expected CVE-ZIG-RAW-ALLOCATOR-LEAK on vulnerable snippet"
    );
    let s_leak = SecurityLinter::audit_file("src/session.zig", safe_leak, None);
    assert!(
        !s_leak.iter().any(|v| v.rule_id == "CVE-ZIG-RAW-ALLOCATOR-LEAK"),
        "Unexpected CVE-ZIG-RAW-ALLOCATOR-LEAK on safe snippet"
    );

    // -------------------------------------------------------------
    // 9. CWE-78: OS Command Injection (CVE-ZIG-COMMAND-INJECTION)
    // -------------------------------------------------------------
    let vuln_cmd = r#"
const std = @import("std");

pub fn runHook(allocator: std.mem.Allocator, user_cmd: []const u8) !void {
    var child = std.process.Child.init(&[_][]const u8{ "/bin/sh", "-c", user_cmd }, allocator);
    _ = try child.spawnAndWait();
}
"#;
    let safe_cmd = r#"
const std = @import("std");

pub fn runHook(allocator: std.mem.Allocator, target: []const u8) !void {
    var child = std.process.Child.init(&[_][]const u8{ "/usr/bin/git", "status", target }, allocator);
    _ = try child.spawnAndWait();
}
"#;
    let v_cmd = SecurityLinter::audit_file("src/proc.zig", vuln_cmd, None);
    assert!(
        v_cmd.iter().any(|v| v.rule_id == "CVE-ZIG-COMMAND-INJECTION" && v.severity == "CRITICAL"),
        "Expected CVE-ZIG-COMMAND-INJECTION on vulnerable snippet"
    );
    let s_cmd = SecurityLinter::audit_file("src/proc.zig", safe_cmd, None);
    assert!(
        !s_cmd.iter().any(|v| v.rule_id == "CVE-ZIG-COMMAND-INJECTION"),
        "Unexpected CVE-ZIG-COMMAND-INJECTION on safe snippet"
    );

    // -------------------------------------------------------------
    // 10. CWE-22: Path Traversal (CVE-ZIG-PATH-TRAVERSAL)
    // -------------------------------------------------------------
    let vuln_path = r#"
const std = @import("std");

pub fn readUpload(user_path: []const u8) !std.fs.File {
    return try std.fs.cwd().openFile(user_path, .{});
}
"#;
    let safe_path = r#"
const std = @import("std");

pub fn readUpload(user_path: []const u8) !std.fs.File {
    if (std.mem.indexOf(u8, user_path, "..") != null) return error.AccessDenied;
    const base_name = std.fs.path.basename(user_path);
    return try std.fs.cwd().openFile(base_name, .{});
}
"#;
    let v_path = SecurityLinter::audit_file("src/storage.zig", vuln_path, None);
    assert!(
        v_path.iter().any(|v| v.rule_id == "CVE-ZIG-PATH-TRAVERSAL" && v.severity == "HIGH"),
        "Expected CVE-ZIG-PATH-TRAVERSAL on vulnerable snippet"
    );
    let s_path = SecurityLinter::audit_file("src/storage.zig", safe_path, None);
    assert!(
        !s_path.iter().any(|v| v.rule_id == "CVE-ZIG-PATH-TRAVERSAL"),
        "Unexpected CVE-ZIG-PATH-TRAVERSAL on safe snippet"
    );

    // -------------------------------------------------------------
    // 11. CWE-676: @setRuntimeSafety(false) (CVE-ZIG-RUNTIME-SAFETY-DISABLED)
    // -------------------------------------------------------------
    let vuln_safety = r#"
pub fn fastParse(buf: []const u8, idx: usize) u8 {
    @setRuntimeSafety(false);
    return buf[idx];
}
"#;
    let safe_safety = r#"
pub fn fastParse(buf: []const u8, idx: usize) !u8 {
    if (idx >= buf.len) return error.OutOfBounds;
    return buf[idx];
}
"#;
    let v_safety = SecurityLinter::audit_file("src/parser.zig", vuln_safety, None);
    assert!(
        v_safety.iter().any(|v| v.rule_id == "CVE-ZIG-RUNTIME-SAFETY-DISABLED" && v.severity == "HIGH"),
        "Expected CVE-ZIG-RUNTIME-SAFETY-DISABLED on vulnerable snippet"
    );
    let s_safety = SecurityLinter::audit_file("src/parser.zig", safe_safety, None);
    assert!(
        !s_safety.iter().any(|v| v.rule_id == "CVE-ZIG-RUNTIME-SAFETY-DISABLED"),
        "Unexpected CVE-ZIG-RUNTIME-SAFETY-DISABLED on safe snippet"
    );

    // -------------------------------------------------------------
    // 12. CWE-562: Return of Stack Variable Address (CVE-ZIG-STACK-ADDRESS-RETURN)
    // -------------------------------------------------------------
    let vuln_stack = r#"
pub fn buildToken() []const u8 {
    var local_buf: [64]u8 = [_]u8{0} ** 64;
    local_buf[0] = 'A';
    return &local_buf;
}
"#;
    let safe_stack = r#"
const std = @import("std");

pub fn buildToken(allocator: std.mem.Allocator) ![]u8 {
    const buf = try allocator.alloc(u8, 64);
    @memset(buf, 0);
    buf[0] = 'A';
    return buf;
}
"#;
    let v_stack = SecurityLinter::audit_file("src/token.zig", vuln_stack, None);
    assert!(
        v_stack.iter().any(|v| v.rule_id == "CVE-ZIG-STACK-ADDRESS-RETURN" && v.severity == "CRITICAL"),
        "Expected CVE-ZIG-STACK-ADDRESS-RETURN on vulnerable snippet"
    );
    let s_stack = SecurityLinter::audit_file("src/token.zig", safe_stack, None);
    assert!(
        !s_stack.iter().any(|v| v.rule_id == "CVE-ZIG-STACK-ADDRESS-RETURN"),
        "Unexpected CVE-ZIG-STACK-ADDRESS-RETURN on safe snippet"
    );

    // -------------------------------------------------------------
    // 13. CWE-295: TLS Certificate Verification Disabled (CVE-ZIG-TLS-VERIFY-DISABLED)
    // -------------------------------------------------------------
    let vuln_tls = r#"
const std = @import("std");

pub fn connectInsecure(client: anytype) void {
    client.ca_bundle = .none;
    client. tls_verification = false;
}
"#;
    let safe_tls = r#"
const std = @import("std");

pub fn connectSecure(allocator: std.mem.Allocator) !std.crypto.Certificate.Bundle {
    var bundle = std.crypto.Certificate.Bundle{};
    try bundle.rescan(allocator);
    return bundle;
}
"#;
    let v_tls = SecurityLinter::audit_file("src/tls.zig", vuln_tls, None);
    assert!(
        v_tls.iter().any(|v| v.rule_id == "CVE-ZIG-TLS-VERIFY-DISABLED" && v.severity == "HIGH"),
        "Expected CVE-ZIG-TLS-VERIFY-DISABLED on vulnerable snippet"
    );
    let s_tls = SecurityLinter::audit_file("src/tls.zig", safe_tls, None);
    assert!(
        !s_tls.iter().any(|v| v.rule_id == "CVE-ZIG-TLS-VERIFY-DISABLED"),
        "Unexpected CVE-ZIG-TLS-VERIFY-DISABLED on safe snippet"
    );

    // -------------------------------------------------------------
    // 14. CWE-338: Weak PRNG in Crypto Context (CVE-ZIG-WEAK-PRNG-CRYPTO)
    // -------------------------------------------------------------
    let vuln_prng = r#"
const std = @import("std");

pub fn generateSessionToken(seed: u64) u64 {
    var prng = std.rand.DefaultPrng.init(seed);
    const secret_token = prng.random().int(u64);
    return secret_token;
}
"#;
    let safe_prng = r#"
const std = @import("std");

pub fn generateSessionToken() u64 {
    return std.crypto.random.int(u64);
}
"#;
    let v_prng = SecurityLinter::audit_file("src/auth.zig", vuln_prng, None);
    assert!(
        v_prng.iter().any(|v| v.rule_id == "CVE-ZIG-WEAK-PRNG-CRYPTO" && v.severity == "HIGH"),
        "Expected CVE-ZIG-WEAK-PRNG-CRYPTO on vulnerable snippet"
    );
    let s_prng = SecurityLinter::audit_file("src/auth.zig", safe_prng, None);
    assert!(
        !s_prng.iter().any(|v| v.rule_id == "CVE-ZIG-WEAK-PRNG-CRYPTO"),
        "Unexpected CVE-ZIG-WEAK-PRNG-CRYPTO on safe snippet"
    );

    // -------------------------------------------------------------
    // 15. CWE-125: SIMD @Vector Out-of-Bounds Load (CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB)
    // -------------------------------------------------------------
    let vuln_simd = r#"
pub fn hashChunkSimd(raw_bytes: []const u8) @Vector(16, u8) {
    const vec_ptr: *const @Vector(16, u8) = @ptrCast(raw_bytes.ptr);
    return vec_ptr.*;
}
"#;
    let safe_simd = r#"
pub fn hashChunkSimd(raw_bytes: []const u8) !@Vector(16, u8) {
    if (raw_bytes.len < 16) return error.BufferTooSmall;
    return raw_bytes[0..16].*;
}
"#;
    let v_simd = SecurityLinter::audit_file("src/simd.zig", vuln_simd, None);
    assert!(
        v_simd.iter().any(|v| v.rule_id == "CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB" && v.severity == "HIGH"),
        "Expected CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB on vulnerable snippet"
    );
    let s_simd = SecurityLinter::audit_file("src/simd.zig", safe_simd, None);
    assert!(
        !s_simd.iter().any(|v| v.rule_id == "CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB"),
        "Unexpected CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB on safe snippet"
    );
}
