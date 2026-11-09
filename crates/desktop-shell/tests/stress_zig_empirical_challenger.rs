//! Empirical Stress Tests and Adversarial Oracles for Zig Static Analysis and CWE Rules
//! Agent: teamwork_challenger_lang_1 (Challenger Archetype)
//! Scope:
//!   1. analyze_zig AST Extraction Under Adversarial & Complex Constructs
//!   2. ZigSecurityRules 8 Production CWE Rules True/False Positives
//!   3. Lexer Masking and Boundary Resilience

use ast_scanner::scanner::{analyze_zig, strip_zig_inline_tests};
use core_graph::bubble::SymbolKind;
use security_linter::lexer::{mask_literals, Lang};
use security_linter::{SecurityLinter, ZigSecurityRules};

// Drop-guard used if disk files are needed


// =========================================================================
// SECTION 1: AST Extraction Empirical Tests (analyze_zig)
// =========================================================================

#[test]
fn test_stress_zig_ast_containers_packed_union_error_opaque() {
    let source = r#"
const std = @import("std");

pub const IPVersion = enum {
    IPv4,
    IPv6,
};

pub const NetworkHeader = packed struct {
    version: u4,
    ihl: u4,
    tos: u8,
    total_length: u16,
};

pub const TaggedPacket = union(enum) {
    ping: u32,
    pong: u32,
    data: []const u8,
};

pub const CustomError = error{
    Timeout,
    ConnectionAborted,
    MalformedPacket,
};

pub const SocketHandle = opaque {};
"#;

    let analysis = analyze_zig("src/network.zig", source);

    // Verify File Bubble
    assert_eq!(analysis.rel_path, "src/network.zig");
    let file_bubble = analysis.nodes.iter().find(|n| n.kind == SymbolKind::File);
    assert!(file_bubble.is_some(), "File bubble must be created");

    // Verify Enum
    let enum_node = analysis.nodes.iter().find(|n| n.name == "IPVersion");
    assert!(enum_node.is_some(), "Enum 'IPVersion' should be extracted");
    assert_eq!(enum_node.unwrap().stereotype, "«Enum»");

    // Verify Packed Struct
    let packed_node = analysis.nodes.iter().find(|n| n.name == "NetworkHeader");
    assert!(packed_node.is_some(), "Packed struct 'NetworkHeader' should be extracted");
    let packed = packed_node.unwrap();
    assert_eq!(packed.kind, SymbolKind::ClassOrStruct);
    let field_names: Vec<&str> = packed.metadata.attributes.iter().map(|a| a.name.as_str()).collect();
    assert!(field_names.contains(&"version"), "Field 'version' must be extracted, got: {:?}", field_names);
    assert!(field_names.contains(&"ihl"), "Field 'ihl' must be extracted, got: {:?}", field_names);
    assert!(field_names.contains(&"tos"), "Field 'tos' must be extracted, got: {:?}", field_names);
    assert!(field_names.contains(&"total_length"), "Field 'total_length' must be extracted, got: {:?}", field_names);

    // Verify Union(enum)
    let union_node = analysis.nodes.iter().find(|n| n.name == "TaggedPacket");
    assert!(union_node.is_some(), "Tagged union 'TaggedPacket' should be extracted");
    assert_eq!(union_node.unwrap().stereotype, "«Union»");

    // Verify Error Set
    let error_node = analysis.nodes.iter().find(|n| n.name == "CustomError");
    assert!(error_node.is_some(), "Error set 'CustomError' should be extracted");
    assert_eq!(error_node.unwrap().stereotype, "«ErrorSet»");

    // Verify Opaque
    let opaque_node = analysis.nodes.iter().find(|n| n.name == "SocketHandle");
    assert!(opaque_node.is_some(), "Opaque 'SocketHandle' should be extracted");
    assert_eq!(opaque_node.unwrap().stereotype, "«Opaque»");
}

#[test]
fn test_stress_zig_ast_functions_complex_return_and_cimport() {
    let source = r#"
const std = @import("std");
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("unistd.h");
});

pub fn getStdErr() !void {
    _ = c.printf("stderr init\n");
}

pub export fn entryPoint(argc: i32, argv: [*][*:0]u8) u8 {
    _ = argc;
    _ = argv;
    return 0;
}

pub inline fn calculateHash(comptime T: type, input: T) !u64 {
    _ = input;
    return 42;
}

pub fn handlePacket(self: *ConnectionHandler, buffer: []const u8) !usize {
    _ = self;
    return buffer.len;
}
"#;

    let analysis = analyze_zig("src/entry.zig", source);

    // Verify @cImport extraction
    assert!(
        analysis.calls.iter().any(|c| c.callee == "cImport"),
        "Raw call for cImport must be recorded"
    );
    let cimport_node = analysis.nodes.iter().find(|n| n.name == "c");
    assert!(cimport_node.is_some(), "Bubble for cImport variable 'c' must be created");

    // Verify exported function
    let entry_fn = analysis.nodes.iter().find(|n| n.name == "entryPoint");
    assert!(entry_fn.is_some(), "export fn 'entryPoint' must be extracted");
    let entry_method = &entry_fn.unwrap().metadata.methods[0];
    assert!(entry_method.args.as_ref().unwrap().contains("argc: i32"));

    // Verify inline function
    let inline_fn = analysis.nodes.iter().find(|n| n.name == "calculateHash");
    assert!(inline_fn.is_some(), "inline fn 'calculateHash' must be extracted");

    // Verify method detection and stereotype
    let method_node = analysis.nodes.iter().find(|n| n.name == "handlePacket");
    assert!(method_node.is_some(), "Method 'handlePacket' must be extracted");
    assert_eq!(method_node.unwrap().stereotype, "«Method»");

    // Verify caller edge from ConnectionHandler to handlePacket
    assert!(
        analysis.calls.iter().any(|c| c.caller == "src/entry.zig::ConnectionHandler" && c.callee == "src/entry.zig::handlePacket"),
        "Parent struct connection to method must be linked"
    );
}

#[test]
fn test_stress_zig_inline_test_stripping_behavior() {
    // Scenario A: Standard idiomatic Zig: inline test at the end of the file
    let code_trailing_test = r#"
pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic addition" {
    const std = @import("std");
    try std.testing.expectEqual(@as(i32, 5), add(2, 3));
}
"#;
    let stripped_trailing = strip_zig_inline_tests(code_trailing_test);
    assert!(stripped_trailing.contains("pub fn add"), "Production code before test must be retained");
    assert!(!stripped_trailing.contains("try std.testing"), "Test body must be stripped");

    let analysis_trailing = analyze_zig("src/math.zig", code_trailing_test);
    assert!(
        analysis_trailing.nodes.iter().any(|n| n.name == "add"),
        "Function 'add' must be in AST graph"
    );

    // Scenario B: Test without string name
    let code_anonymous_test = r#"
pub fn mul(a: i32, b: i32) i32 {
    return a * b;
}

test {
    // Anonymous test block
}
"#;
    let stripped_anon = strip_zig_inline_tests(code_anonymous_test);
    assert!(stripped_anon.contains("pub fn mul"));
    assert!(!stripped_anon.contains("Anonymous test block"));

    // Scenario C: Behavioral verification of test block position
    let code_interleaved_test = r#"
pub fn first() void {}

test "unit test" {
    _ = 1;
}

pub fn second() void {}
"#;
    let _stripped_interleaved = strip_zig_inline_tests(code_interleaved_test);
    // Observe scanner truncation behavior on interleaved tests
    let analysis_interleaved = analyze_zig("src/interleaved.zig", code_interleaved_test);
    let has_first = analysis_interleaved.nodes.iter().any(|n| n.name == "first");
    let has_second = analysis_interleaved.nodes.iter().any(|n| n.name == "second");
    println!("Interleaved test extraction: has_first={}, has_second={}", has_first, has_second);
}

#[test]
fn test_stress_zig_nested_structs() {
    let source = r#"
pub const Outer = struct {
    pub const Inner = struct {
        inner_val: u32,
    };
    outer_val: u32,
};
"#;

    let analysis = analyze_zig("src/nested.zig", source);
    let outer = analysis.nodes.iter().find(|n| n.name == "Outer");
    let inner = analysis.nodes.iter().find(|n| n.name == "Inner");

    assert!(outer.is_some(), "Outer struct must be extracted");
    assert!(inner.is_some(), "Inner nested struct must be extracted");
}

// =========================================================================
// SECTION 2: Empirical Verification of Zig CWE Rules (ZigSecurityRules)
// =========================================================================

#[test]
fn test_stress_cwe_416_use_after_free_adversarial_matrix() {
    // Positive 1: Dereference after free
    let tp1 = r#"
pub fn handler(allocator: std.mem.Allocator) !u8 {
    const ptr = try allocator.create(u8);
    allocator.destroy(ptr);
    ptr.* = 5;
    return 0;
}
"#;
    let v1 = ZigSecurityRules::audit("src/uaf.zig", tp1);
    assert!(v1.iter().any(|v| v.rule_id == "CVE-ZIG-USE-AFTER-FREE"), "TP1: ptr.* after destroy must trigger CWE-416");

    // Positive 2: Double free
    let tp2 = r#"
pub fn handler(allocator: std.mem.Allocator, buf: []u8) void {
    allocator.free(buf);
    allocator.free(buf);
}
"#;
    let v2 = ZigSecurityRules::audit("src/uaf.zig", tp2);
    assert!(v2.iter().any(|v| v.rule_id == "CVE-ZIG-USE-AFTER-FREE"), "TP2: double free must trigger CWE-416");

    // False Positive 1: defer free (idiomatic)
    let fp1 = r#"
pub fn handler(allocator: std.mem.Allocator) !u8 {
    const buf = try allocator.alloc(u8, 16);
    defer allocator.free(buf);
    buf[0] = 42;
    return buf[0];
}
"#;
    let v_fp1 = ZigSecurityRules::audit("src/uaf.zig", fp1);
    assert!(!v_fp1.iter().any(|v| v.rule_id == "CVE-ZIG-USE-AFTER-FREE"), "FP1: defer free must NOT trigger CWE-416");

    // False Positive 2: Reallocation after free
    let fp2 = r#"
pub fn handler(allocator: std.mem.Allocator) !u8 {
    var buf = try allocator.alloc(u8, 16);
    allocator.free(buf);
    buf = try allocator.alloc(u8, 32);
    buf[0] = 10;
    defer allocator.free(buf);
    return buf[0];
}
"#;
    let v_fp2 = ZigSecurityRules::audit("src/uaf.zig", fp2);
    assert!(!v_fp2.iter().any(|v| v.rule_id == "CVE-ZIG-USE-AFTER-FREE"), "FP2: Reassignment after free must NOT trigger CWE-416");
}

#[test]
fn test_stress_cwe_703_unhandled_error_union_adversarial_matrix() {
    // Positive 1: _ = fallible call
    let tp1 = r#"
pub fn writeLog(file: std.fs.File, data: []const u8) void {
    _ = file.writeAll(data);
}
"#;
    let v1 = ZigSecurityRules::audit("src/err.zig", tp1);
    assert!(v1.iter().any(|v| v.rule_id == "CVE-ZIG-UNHANDLED-ERROR-UNION"), "TP1: _ = file.writeAll must trigger CWE-703");

    // Positive 2: catch unreachable on network connect
    let tp2 = r#"
pub fn openConn() void {
    const stream = std.net.tcpConnectToHost(alloc, "127.0.0.1", 8080) catch unreachable;
    _ = stream;
}
"#;
    let v2 = ZigSecurityRules::audit("src/err.zig", tp2);
    assert!(v2.iter().any(|v| v.rule_id == "CVE-ZIG-UNHANDLED-ERROR-UNION"), "TP2: catch unreachable on network connect must trigger CWE-703");

    // False Positive 1: try propagation
    let fp1 = r#"
pub fn writeLog(file: std.fs.File, data: []const u8) !void {
    try file.writeAll(data);
}
"#;
    let v_fp1 = ZigSecurityRules::audit("src/err.zig", fp1);
    assert!(!v_fp1.iter().any(|v| v.rule_id == "CVE-ZIG-UNHANDLED-ERROR-UNION"), "FP1: try propagation must NOT trigger CWE-703");

    // False Positive 2: catch block with handling
    let fp2 = r#"
pub fn writeLog(file: std.fs.File, data: []const u8) void {
    _ = file.writeAll(data) catch |err| {
        std.log.err("Failed: {}", .{err});
    };
}
"#;
    let v_fp2 = ZigSecurityRules::audit("src/err.zig", fp2);
    assert!(!v_fp2.iter().any(|v| v.rule_id == "CVE-ZIG-UNHANDLED-ERROR-UNION"), "FP2: catch handler must NOT trigger CWE-703");
}

#[test]
fn test_stress_cwe_190_integer_wrapping_adversarial_matrix() {
    // Positive: Unbounded wrapping operators
    let tp = r#"
pub fn calcOffset(base: usize, offset: usize) usize {
    const wrapped = base +% offset;
    return wrapped *% 4;
}
"#;
    let v_tp = ZigSecurityRules::audit("src/math.zig", tp);
    let wrap_violations: Vec<_> = v_tp.iter().filter(|v| v.rule_id == "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING").collect();
    assert_eq!(wrap_violations.len(), 2, "Expected 2 wrapping violations (+% and *%)");

    // False Positive: @addWithOverflow and standard operators
    let fp = r#"
pub fn calcOffsetSafe(base: usize, offset: usize) !usize {
    const res = @addWithOverflow(base, offset);
    if (res[1] != 0) return error.Overflow;
    const normal = base + offset;
    const modulo = base % 10;
    return res[0] + normal + modulo;
}
"#;
    let v_fp = ZigSecurityRules::audit("src/math.zig", fp);
    assert!(!v_fp.iter().any(|v| v.rule_id == "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING"), "Safe overflow check must NOT trigger CWE-190");
}

#[test]
fn test_stress_cwe_843_insecure_pointer_cast_adversarial_matrix() {
    // Positive: @ptrCast with raw pointer access
    let tp = r#"
pub fn convert(slice: []const u8) *const u32 {
    return @ptrCast(@alignCast(slice.ptr));
}
"#;
    let v_tp = ZigSecurityRules::audit("src/cast.zig", tp);
    assert!(v_tp.iter().any(|v| v.rule_id == "CVE-ZIG-INSECURE-POINTER-CAST"), "Raw @ptrCast must trigger CWE-843");

    // False Positive: bytesAsValue and bytesAsSlice
    let fp = r#"
const std = @import("std");
pub fn convertSafe(slice: []const u8) !*const u32 {
    if (slice.len < @sizeOf(u32)) return error.TooSmall;
    return std.mem.bytesAsValue(u32, slice[0..@sizeOf(u32)]);
}
"#;
    let v_fp = ZigSecurityRules::audit("src/cast.zig", fp);
    assert!(!v_fp.iter().any(|v| v.rule_id == "CVE-ZIG-INSECURE-POINTER-CAST"), "bytesAsValue must NOT trigger CWE-843");
}

#[test]
fn test_stress_cwe_457_uninitialized_memory_adversarial_matrix() {
    // Positive: undefined read without init
    let tp = r#"
pub fn getPayload(writer: anytype) !void {
    var buffer: [256]u8 = undefined;
    try writer.writeAll(&buffer);
}
"#;
    let v_tp = ZigSecurityRules::audit("src/uninit.zig", tp);
    assert!(v_tp.iter().any(|v| v.rule_id == "CVE-ZIG-UNINITIALIZED-MEMORY"), "Undefined writeAll must trigger CWE-457");

    // False Positive: @memset before read
    let fp1 = r#"
pub fn getPayloadSafe(writer: anytype) !void {
    var buffer: [256]u8 = undefined;
    @memset(&buffer, 0);
    try writer.writeAll(&buffer);
}
"#;
    let v_fp1 = ZigSecurityRules::audit("src/uninit.zig", fp1);
    assert!(!v_fp1.iter().any(|v| v.rule_id == "CVE-ZIG-UNINITIALIZED-MEMORY"), "@memset must suppress CWE-457");

    // False Positive: readAll before use
    let fp2 = r#"
pub fn getPayloadSafe2(reader: anytype, writer: anytype) !void {
    var buffer: [256]u8 = undefined;
    _ = try reader.readAll(&buffer);
    try writer.writeAll(&buffer);
}
"#;
    let v_fp2 = ZigSecurityRules::audit("src/uninit.zig", fp2);
    assert!(!v_fp2.iter().any(|v| v.rule_id == "CVE-ZIG-UNINITIALIZED-MEMORY"), "readAll must suppress CWE-457");
}

#[test]
fn test_stress_cwe_119_and_cwe_134_c_interop_adversarial_matrix() {
    // Positive CWE-119: Legacy unsafe C calls
    let tp_c1 = r#"
pub fn legacyCall(dst: [*]u8, src: [*]const u8) void {
    _ = c.strcpy(dst, src);
}
"#;
    let v1 = ZigSecurityRules::audit("src/c.zig", tp_c1);
    assert!(v1.iter().any(|v| v.rule_id == "CVE-ZIG-BUFFER-OVERRUN-C-INTEROP"), "c.strcpy must trigger CWE-119");

    // Positive CWE-134: Dynamic printf format string
    let tp_fmt = r#"
pub fn logDyn(user_msg: [*:0]const u8) void {
    _ = c.printf(user_msg);
}
"#;
    let v2 = ZigSecurityRules::audit("src/fmt.zig", tp_fmt);
    assert!(v2.iter().any(|v| v.rule_id == "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING"), "Dynamic printf must trigger CWE-134");

    // False Positive: Constant literal format string
    let fp_fmt = r#"
pub fn logSafe(user_msg: [*:0]const u8) void {
    _ = c.printf("%s\n", user_msg);
}
"#;
    let v_fp = ZigSecurityRules::audit("src/fmt.zig", fp_fmt);
    assert!(!v_fp.iter().any(|v| v.rule_id == "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING"), "Literal format string must NOT trigger CWE-134");
}

#[test]
fn test_stress_cwe_401_allocator_leak_adversarial_matrix() {
    // Positive: Allocation without defer free or return
    let tp = r#"
pub fn computeData(allocator: std.mem.Allocator) !void {
    const mem = try allocator.alloc(u8, 512);
    _ = mem;
}
"#;
    let v_tp = ZigSecurityRules::audit("src/leak.zig", tp);
    assert!(v_tp.iter().any(|v| v.rule_id == "CVE-ZIG-RAW-ALLOCATOR-LEAK"), "Missing free must trigger CWE-401");

    // False Positive 1: defer allocator.free
    let fp1 = r#"
pub fn computeDataSafe(allocator: std.mem.Allocator) !void {
    const mem = try allocator.alloc(u8, 512);
    defer allocator.free(mem);
    _ = mem;
}
"#;
    let v_fp1 = ZigSecurityRules::audit("src/leak.zig", fp1);
    assert!(!v_fp1.iter().any(|v| v.rule_id == "CVE-ZIG-RAW-ALLOCATOR-LEAK"), "defer allocator.free must NOT trigger CWE-401");

    // False Positive 2: return allocated slice
    let fp2 = r#"
pub fn allocateData(allocator: std.mem.Allocator) ![]u8 {
    const mem = try allocator.alloc(u8, 512);
    return mem;
}
"#;
    let v_fp2 = ZigSecurityRules::audit("src/leak.zig", fp2);
    assert!(!v_fp2.iter().any(|v| v.rule_id == "CVE-ZIG-RAW-ALLOCATOR-LEAK"), "Returning allocated buffer must NOT trigger CWE-401");
}

#[test]
fn test_stress_lexer_multiline_and_comment_masking() {
    // Check that comments and multiline strings in Zig don't trigger false positives
    let commented_code = r#"
// pub fn oldVuln() void {
//     const buf = try allocator.alloc(u8, 1024);
//     allocator.free(buf);
//     buf[0] = 1;
//     _ = c.printf(user_str);
//     return base +% offset;
// }
pub fn realSafe() void {}
"#;

    let violations = SecurityLinter::audit_file("src/comments.zig", commented_code, None);
    assert!(
        violations.is_empty(),
        "Commented-out code must produce 0 violations, got: {:?}",
        violations
    );

    // Multiline string literal with \\ in Zig
    let multiline_string = r#"
pub fn printDoc() []const u8 {
    return 
        \\ This is documentation containing keywords:
        \\ allocator.free(buf);
        \\ c.printf(user_input);
        \\ +% -% *%
        \\ = undefined;
    ;
}
"#;
    let masked = mask_literals(multiline_string, Lang::Zig);
    assert!(!masked.contains("allocator.free"), "Multiline string contents must be masked");
}

#[test]
fn test_stress_zig_taint_and_dataflow_parameters() {
    use ast_scanner::taint_extractor::TaintExtractor;

    let source = r#"
pub fn handleUser(user_id: u32, payload: []const u8, self_context: *Context) !void {
    var local_buf = payload;
    _ = user_id;
    _ = local_buf;
    _ = self_context;
}
"#;

    let dfg = TaintExtractor::extract_from_source("src/taint.zig", source, &[]);
    let var_names: Vec<String> = dfg.nodes.values().map(|v| v.name.clone()).collect();
    assert!(var_names.contains(&"user_id".to_string()), "Parameter 'user_id' should be detected in DFG, got: {:?}", var_names);
    assert!(var_names.contains(&"payload".to_string()), "Parameter 'payload' should be detected in DFG, got: {:?}", var_names);
    // Notice: self_context contains 'self', verify if filtered
    let has_self_context = var_names.contains(&"self_context".to_string());
    println!("DFG parameter 'self_context' present: {}", has_self_context);
}

#[test]
fn test_stress_zig_struct_methods_and_field_ordering() {
    let source = r#"
pub const Service = struct {
    port: u16,
    active: bool,

    pub fn start(self: *Service) !void {
        _ = self;
    }

    trailing_field: u32,
};
"#;

    let analysis = analyze_zig("src/service.zig", source);
    let service_node = analysis.nodes.iter().find(|n| n.name == "Service").expect("Service struct found");
    let attr_names: Vec<&str> = service_node.metadata.attributes.iter().map(|a| a.name.as_str()).collect();
    
    // Check which fields were captured before vs after method declaration
    let has_port = attr_names.contains(&"port");
    let has_active = attr_names.contains(&"active");
    let has_trailing = attr_names.contains(&"trailing_field");
    println!("Struct fields extracted: port={}, active={}, trailing_field={}", has_port, has_active, has_trailing);

    // Method bubble check
    let start_method = analysis.nodes.iter().find(|n| n.name == "start");
    assert!(start_method.is_some(), "Method 'start' must be extracted");
    assert_eq!(start_method.unwrap().stereotype, "«Method»");
}

#[test]
fn test_stress_zig_unusual_cwe_edge_cases() {
    // 1. Multiple wrapping operators in a single line
    let source_wrapping = r#"
pub fn multiWrap(a: u32, b: u32, c: u32) u32 {
    return a +% b -% c;
}
"#;
    let v_wrap = ZigSecurityRules::audit("src/wrap.zig", source_wrapping);
    assert!(
        v_wrap.iter().any(|v| v.rule_id == "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING"),
        "Multiple wrapping operators must trigger CVE-ZIG-INTEGER-OVERFLOW-WRAPPING"
    );

    // 2. Modulo operator (%) vs Wrapping operator (+%)
    let source_modulo = r#"
pub fn calcMod(val: u32, denom: u32) u32 {
    return val % denom;
}
"#;
    let v_mod = ZigSecurityRules::audit("src/mod.zig", source_modulo);
    assert!(
        !v_mod.iter().any(|v| v.rule_id == "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING"),
        "Standard modulo operator (%) must NOT trigger wrapping overflow violation"
    );

    // 3. Nested struct with memory leak inside method
    let source_nested_leak = r#"
pub const Manager = struct {
    pub fn doWork(allocator: std.mem.Allocator) !void {
        const mem = try allocator.alloc(u8, 256);
        _ = mem;
    }
};
"#;
    let v_leak = ZigSecurityRules::audit("src/mgr.zig", source_nested_leak);
    assert!(
        v_leak.iter().any(|v| v.rule_id == "CVE-ZIG-RAW-ALLOCATOR-LEAK"),
        "Allocator leak inside struct method must trigger CVE-ZIG-RAW-ALLOCATOR-LEAK"
    );
}

