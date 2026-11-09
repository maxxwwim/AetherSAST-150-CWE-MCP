//! Empirical Challenger Integration Test Suite for C# Static Analysis,
//! AST Extraction, C# Production CWE Rules, Lexer Masking, and CLI / SARIF Execution.
//!
//! Authored by: teamwork_challenger_lang_2 (Empirical Challenger Agent)

use ast_scanner::scanner::{analyze_csharp, analyze_csharp_symbols};
use core_graph::bubble::SymbolKind;
use security_linter::SecurityLinter;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Guard to automatically clean up temporary directories on drop.
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "aether-engine.exe" } else { "aether-engine" })
}

// =============================================================================
// TEST 1: EMPIRICAL C# MODERN AST CONSTRUCTS
// =============================================================================

#[test]
fn test_empirical_csharp_modern_ast_constructs() {
    let cs_code = r#"
// Global and normal usings
global using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using JSON = System.Text.Json.JsonSerializer;

namespace Enterprise.Billing.Core;

// 1. Standard Record class (body-scoped)
public record class InvoiceRecord : IDisposable {
    public string Id { get; set; } = "";
    public decimal Amount { get; set; }
    public string Status { get; set; } = "Pending";
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

    public void Dispose() { }
}

// 1b. Positional record with primary constructor (modern C# syntax)
public record class PositionalRecord(string Id, decimal Amount) {
}

// 2. Standard Record struct
public record struct GeoCoordinate {
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public double Elevation { get; set; }
}

// 3. Standard Readonly record struct
public readonly record struct TransactionKey {
    public Guid Value { get; init; }
}

// 4. Custom controller inheriting ControllerBase
[ApiController]
[Route("api/[controller]")]
public class BillingController : ControllerBase {
    private readonly List<InvoiceRecord> _invoices = new();

    // Async method with multiple route attributes
    [HttpGet]
    [Route("v1/invoices/{id}")]
    [Route("v2/invoices/{id}")]
    public async Task<IActionResult> GetInvoiceByIdAsync(string id, CancellationToken ct) {
        await Task.Delay(1, ct);
        return Ok(id);
    }

    [HttpPost("v1/invoices")]
    public async Task<IActionResult> CreateInvoiceAsync([FromBody] InvoiceRecord record) {
        _invoices.Add(record);
        return CreatedAtAction(nameof(GetInvoiceByIdAsync), new { id = record.Id }, record);
    }
}

// 5. Custom controller by naming convention (no ControllerBase)
public class AuditReportController {
    public int TotalAudits { get; set; }

    public void GenerateReport() { }
}

// 6. Custom service (not a controller)
public class PaymentGatewayService {
    public string GatewayUrl { get; set; }

    public void ProcessTransaction() { }
}

// 7. Minimal API endpoint handlers simulation
public static class EndpointRouteExtensions {
    public static void MapEndpoints(WebApplication app) {
        app.MapGet("/api/health", () => "OK");
        app.MapPost("/api/billing/charge", (InvoiceRecord req) => Results.Accepted());
    }
}
"#;

    let analysis = analyze_csharp("src/Billing/BillingEngine.cs", cs_code);

    // Assert file bubble
    assert_eq!(analysis.nodes[0].metadata.file_type, "csharp");
    assert_eq!(analysis.nodes[0].name, "BillingEngine.cs");

    // Assert file-scoped namespace bubble
    let ns_bubble = analysis
        .nodes
        .iter()
        .find(|n| n.name == "Enterprise.Billing.Core" && n.stereotype == "«Namespace»");
    assert!(
        ns_bubble.is_some(),
        "Expected file-scoped namespace 'Enterprise.Billing.Core' to be extracted"
    );

    // Assert record class bubble
    let inv_rec = analysis
        .nodes
        .iter()
        .find(|n| n.name == "InvoiceRecord");
    assert!(inv_rec.is_some(), "Expected 'InvoiceRecord' record class bubble");
    let inv_rec = inv_rec.unwrap();
    assert_eq!(inv_rec.stereotype, "«Record»");
    assert_eq!(inv_rec.kind, SymbolKind::ClassOrStruct);

    // Empirical observation: PositionalRecord with primary constructor parameters `(string Id, decimal Amount)`
    // is NOT matched by re_cs_class (which expects `{` right after type name or base `:`).
    // Instead, re_cs_method matches `record class` as return type and `PositionalRecord` as a Function!
    let positional_as_class = analysis
        .nodes
        .iter()
        .find(|n| n.name == "PositionalRecord" && n.kind == SymbolKind::ClassOrStruct);
    assert!(
        positional_as_class.is_none(),
        "Empirical finding: PositionalRecord with primary constructor parameters is NOT extracted as ClassOrStruct"
    );

    // Assert record struct bubble
    let geo_rec = analysis
        .nodes
        .iter()
        .find(|n| n.name == "GeoCoordinate");
    assert!(geo_rec.is_some(), "Expected 'GeoCoordinate' record struct bubble");
    let geo_rec = geo_rec.unwrap();
    assert_eq!(geo_rec.stereotype, "«Record»");

    // Assert readonly record struct bubble
    let tx_key = analysis
        .nodes
        .iter()
        .find(|n| n.name == "TransactionKey");
    assert!(tx_key.is_some(), "Expected 'TransactionKey' record bubble");

    // Assert properties inside records and classes
    let status_prop = analysis
        .nodes
        .iter()
        .find(|n| n.name == "Status" && n.stereotype == "«Property»");
    assert!(status_prop.is_some(), "Expected 'Status' property bubble in InvoiceRecord");

    let elev_prop = analysis
        .nodes
        .iter()
        .find(|n| n.name == "Elevation" && n.stereotype == "«Property»");
    assert!(elev_prop.is_some(), "Expected 'Elevation' property bubble in GeoCoordinate");

    // Assert Controller stereotypes
    // BillingController inherits ControllerBase -> «Controller»
    let billing_ctrl = analysis
        .nodes
        .iter()
        .find(|n| n.name == "BillingController");
    assert!(billing_ctrl.is_some(), "Expected 'BillingController' class bubble");
    assert_eq!(billing_ctrl.unwrap().stereotype, "«Controller»");

    // AuditReportController ends with Controller -> «Controller»
    let report_ctrl = analysis
        .nodes
        .iter()
        .find(|n| n.name == "AuditReportController");
    assert!(report_ctrl.is_some(), "Expected 'AuditReportController' class bubble");
    assert_eq!(report_ctrl.unwrap().stereotype, "«Controller»");

    // PaymentGatewayService does NOT end with Controller and does not inherit ControllerBase -> NOT «Controller»
    let svc = analysis
        .nodes
        .iter()
        .find(|n| n.name == "PaymentGatewayService");
    assert!(svc.is_some(), "Expected 'PaymentGatewayService' class bubble");
    assert_ne!(svc.unwrap().stereotype, "«Controller»");

    // Assert async endpoint methods and route attributes
    let get_inv_method = analysis
        .nodes
        .iter()
        .find(|n| n.name == "GetInvoiceByIdAsync");
    assert!(get_inv_method.is_some(), "Expected 'GetInvoiceByIdAsync' method bubble");
    let get_inv_method = get_inv_method.unwrap();
    assert_eq!(get_inv_method.stereotype, "«Endpoint»");
    assert_eq!(get_inv_method.kind, SymbolKind::FormOrEndpoint);
    assert!(!get_inv_method.metadata.methods.is_empty());
    assert_eq!(get_inv_method.metadata.methods[0].is_async, Some(true));

    let create_inv_method = analysis
        .nodes
        .iter()
        .find(|n| n.name == "CreateInvoiceAsync");
    assert!(create_inv_method.is_some(), "Expected 'CreateInvoiceAsync' method bubble");
    let create_inv_method = create_inv_method.unwrap();
    assert_eq!(create_inv_method.stereotype, "«Endpoint»");
    assert_eq!(create_inv_method.kind, SymbolKind::FormOrEndpoint);
    assert_eq!(create_inv_method.metadata.methods[0].is_async, Some(true));

    // Assert minimal API routes
    assert!(
        analysis
            .routes_declared
            .iter()
            .any(|(r, _)| r.contains("MapGet: /api/health")),
        "Expected minimal API route 'MapGet: /api/health'"
    );
    assert!(
        analysis
            .routes_declared
            .iter()
            .any(|(r, _)| r.contains("MapPost: /api/billing/charge")),
        "Expected minimal API route 'MapPost: /api/billing/charge'"
    );

    // Verify analyze_csharp_symbols API returns matching nodes
    let symbols = analyze_csharp_symbols(Path::new("src/Billing/BillingEngine.cs"), cs_code);
    assert_eq!(symbols.len(), analysis.nodes.len());
}

// =============================================================================
// TEST 2: EMPIRICAL C# CWE TRUE POSITIVE VARIATIONS (ALL 10 RULES)
// =============================================================================

#[test]
fn test_empirical_csharp_cwe_true_positive_variations() {
    // 1. Deserialization variants (BinaryFormatter, NetDataContractSerializer, TypeNameHandling)
    let cs_deser_variants = r#"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using Newtonsoft.Json;

public class DeserVariants {
    public void Variant1(Stream s) {
        var bf = new BinaryFormatter();
        bf.Deserialize(s);
    }
    public void Variant2(Stream s) {
        var ndcs = new NetDataContractSerializer();
        ndcs.Deserialize(s);
    }
    public void Variant3(string json) {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.Auto
        };
        JsonConvert.DeserializeObject(json, settings);
    }
    public void Variant4(string json) {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.All
        };
    }
}
"#;
    let v_deser = SecurityLinter::audit_file("Services/Deser.cs", cs_deser_variants, None);
    let deser_count = v_deser
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-INSECURE-DESERIALIZATION" && v.severity == "CRITICAL")
        .count();
    assert!(
        deser_count >= 4,
        "Expected at least 4 CVE-CS-INSECURE-DESERIALIZATION findings across variants, got {}",
        deser_count
    );

    // 2. SQL injection variants (FromSqlRaw interpolation, ExecuteSqlRaw concat, SqlCommand concat)
    let cs_sql_variants = r#"
using System.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

public class SqlVariants {
    public void Query1(DbContext ctx, string name) {
        ctx.Set<User>().FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'");
    }
    public void Query2(DbContext ctx, string name) {
        ctx.Set<User>().FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");
    }
    public void Query3(DbContext ctx, string status) {
        ctx.Database.ExecuteSqlRaw($"DELETE FROM Logs WHERE Status = '{status}'");
    }
    public void Query4(SqlConnection conn, string role) {
        var cmd = new SqlCommand("SELECT * FROM Accounts WHERE Role = '" + role + "'", conn);
    }
}
"#;
    let v_sql = SecurityLinter::audit_file("Data/SqlRepo.cs", cs_sql_variants, None);
    let sql_count = v_sql
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-SQL-INJECTION" && v.severity == "CRITICAL")
        .count();
    assert!(
        sql_count >= 4,
        "Expected at least 4 CVE-CS-SQL-INJECTION findings across variants, got {}",
        sql_count
    );

    // 3. Command injection variants (cmd.exe, powershell.exe, bash, Arguments concat)
    let cs_cmd_variants = r#"
using System.Diagnostics;

public class CommandVariants {
    public void Exec1(string target) {
        Process.Start("cmd.exe", "/c ping " + target);
    }
    public void Exec2(string script) {
        Process.Start("powershell.exe", $"-File {script}");
    }
    public void Exec3(string cmd) {
        Process.Start($"bash -c {cmd}");
    }
    public void Exec4(string arg) {
        var psi = new ProcessStartInfo {
            FileName = "tool.exe",
            Arguments = "--input " + arg
        };
        Process.Start(psi);
    }
}
"#;
    let v_cmd = SecurityLinter::audit_file("Diagnostics/Runner.cs", cs_cmd_variants, None);
    let cmd_count = v_cmd
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-COMMAND-INJECTION" && v.severity == "CRITICAL")
        .count();
    assert!(
        cmd_count >= 4,
        "Expected at least 4 CVE-CS-COMMAND-INJECTION findings across variants, got {}",
        cmd_count
    );

    // 4. Path traversal (Path.Combine without canonical guard)
    let cs_path_variant = r#"
using System.IO;

public class PathHandler {
    public string LoadFile(string root, string untrusted) {
        string full = Path.Combine(root, untrusted);
        return File.ReadAllText(full);
    }
}
"#;
    let v_path = SecurityLinter::audit_file("IO/PathHandler.cs", cs_path_variant, None);
    assert!(
        v_path.iter().any(|v| v.rule_id == "CVE-CS-PATH-TRAVERSAL" && v.severity == "HIGH"),
        "Expected CVE-CS-PATH-TRAVERSAL finding"
    );

    // 5. Weak cryptography variants (MD5.Create, MD5.HashData, SHA1.Create, DES.Create, CipherMode.ECB)
    let cs_crypto_variants = r#"
using System.Security.Cryptography;

public class CryptoVariants {
    public void Hash1(byte[] d) {
        using var md5 = MD5.Create();
        md5.ComputeHash(d);
    }
    public void Hash2(byte[] d) {
        var h = MD5.HashData(d);
    }
    public void Hash3(byte[] d) {
        using var sha1 = SHA1.Create();
        sha1.ComputeHash(d);
    }
    public void Cipher1() {
        using var des = DES.Create();
    }
    public void Cipher2(Aes aes) {
        aes.Mode = CipherMode.ECB;
    }
}
"#;
    let v_crypto = SecurityLinter::audit_file("Crypto/Hashers.cs", cs_crypto_variants, None);
    let crypto_count = v_crypto
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-WEAK-CRYPTOGRAPHY" && v.severity == "HIGH")
        .count();
    assert!(
        crypto_count >= 5,
        "Expected at least 5 CVE-CS-WEAK-CRYPTOGRAPHY findings across variants, got {}",
        crypto_count
    );

    // 6. XSS via raw HTML (new HtmlString, @Html.Raw, MarkupString)
    let cs_xss_variants = r#"
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Components;

public class XssVariants {
    public HtmlString Render1(string user) => new HtmlString(user);
    public HtmlString Render2(string user) => @Html.Raw(user);
    public MarkupString Render3(string user) => (MarkupString)user;
}
"#;
    let v_xss = SecurityLinter::audit_file("Views/Renderer.cs", cs_xss_variants, None);
    let xss_count = v_xss
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-XSS-RAW-HTML" && v.severity == "HIGH")
        .count();
    assert!(
        xss_count >= 3,
        "Expected at least 3 CVE-CS-XSS-RAW-HTML findings across variants, got {}",
        xss_count
    );

    // 7. XXE variants (DtdProcessing.Parse, XmlUrlResolver)
    let cs_xxe_variants = r#"
using System.Xml;

public class XxeVariants {
    public void Parse1() {
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Parse;
    }
    public void Parse2(XmlDocument doc) {
        doc.XmlResolver = new XmlUrlResolver();
    }
}
"#;
    let v_xxe = SecurityLinter::audit_file("Xml/Reader.cs", cs_xxe_variants, None);
    let xxe_count = v_xxe
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-XXE-INJECTION" && v.severity == "HIGH")
        .count();
    assert!(
        xxe_count >= 2,
        "Expected at least 2 CVE-CS-XXE-INJECTION findings across variants, got {}",
        xxe_count
    );

    // 8. Insecure PRNG (new Random() / Random.Shared in sensitive token/auth/password context)
    let cs_prng_variants = r#"
using System;

public class TokenService {
    public int GenerateAuthToken() {
        var rng = new Random();
        return rng.Next(1000, 9999);
    }
    public int GenerateSessionSecret() {
        return Random.Shared.Next(100000, 999999);
    }
}
"#;
    let v_prng = SecurityLinter::audit_file("Auth/TokenService.cs", cs_prng_variants, None);
    let prng_count = v_prng
        .iter()
        .filter(|v| v.rule_id == "CVE-CS-INSECURE-RANDOM" && v.severity == "MEDIUM")
        .count();
    assert!(
        prng_count >= 2,
        "Expected at least 2 CVE-CS-INSECURE-RANDOM findings, got {}",
        prng_count
    );

    // 9. LDAP injection in DirectorySearcher.Filter
    let cs_ldap_variant = r#"
using System.DirectoryServices;

public class LdapRepo {
    public SearchResult Find(DirectorySearcher searcher, string user) {
        searcher.Filter = $"(&(objectClass=user)(sAMAccountName={user}))";
        return searcher.FindOne();
    }
}
"#;
    let v_ldap = SecurityLinter::audit_file("Auth/LdapRepo.cs", cs_ldap_variant, None);
    assert!(
        v_ldap.iter().any(|v| v.rule_id == "CVE-CS-LDAP-INJECTION" && v.severity == "HIGH"),
        "Expected CVE-CS-LDAP-INJECTION finding"
    );

    // 10. CSRF disabled via [IgnoreAntiforgeryToken]
    let cs_csrf_variant = r#"
using Microsoft.AspNetCore.Mvc;

public class PaymentController : Controller {
    [HttpPost]
    [IgnoreAntiforgeryToken]
    public IActionResult Pay() => Ok();
}
"#;
    let v_csrf = SecurityLinter::audit_file("Controllers/PaymentController.cs", cs_csrf_variant, None);
    assert!(
        v_csrf.iter().any(|v| v.rule_id == "CVE-CS-CSRF-DISABLED" && v.severity == "MEDIUM"),
        "Expected CVE-CS-CSRF-DISABLED finding"
    );
}

// =============================================================================
// TEST 3: EMPIRICAL C# CWE FALSE POSITIVE RESISTANCE
// =============================================================================

#[test]
fn test_empirical_csharp_cwe_false_positive_resistance() {
    let cs_clean_idioms = r#"
using System;
using System.IO;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Xml;
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Html;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;

namespace Production.CleanArchitecture;

public class SecureServicesController : Controller {
    // 1. Safe JSON Deserialization
    public UserProfile ParseProfile(Stream jsonStream) {
        return JsonSerializer.Deserialize<UserProfile>(jsonStream);
    }

    // 2. Safe EF Core FromSqlInterpolated & Parameterized SQL
    public void SafeQueries(DbContext ctx, SqlConnection conn, string username, int id) {
        var users = ctx.Set<UserProfile>().FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}");

        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteNonQuery();
    }

    // 3. Safe Path Canonicalization & GetFileName
    public string SafeFileAccess(string baseFolder, string fileName) {
        string canonicalBase = Path.GetFullPath(baseFolder);
        string fullPath = Path.GetFullPath(Path.Combine(canonicalBase, fileName));
        if (!fullPath.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase)) {
            throw new UnauthorizedAccessException("Path traversal prevented");
        }
        return File.ReadAllText(fullPath);
    }

    public string SafeFileNameOnly(string baseFolder, string untrustedInput) {
        string safeName = Path.GetFileName(untrustedInput);
        string safePath = Path.Combine(baseFolder, safeName);
        return File.ReadAllText(safePath);
    }

    // 4. Safe Cryptography (SHA-256 and AES-CBC)
    public byte[] SafeHash(byte[] input) {
        using var sha = SHA256.Create();
        return sha.ComputeHash(input);
    }

    public void SafeCipher(Aes aes) {
        aes.Mode = CipherMode.CBC;
    }

    // 5. Safe HTML Encoding before HtmlString
    public HtmlString SafeBio(string userInput) {
        string encoded = HtmlEncoder.Default.Encode(userInput);
        return new HtmlString(encoded);
    }

    // 6. Safe XML Processing (DtdProcessing.Prohibit + XmlResolver = null)
    public void SafeXml(string xml) {
        var settings = new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
    }

    // 7. Safe Cryptographic PRNG
    public int GenerateSecureEntropy() {
        return RandomNumberGenerator.GetInt32(100000, 999999);
    }

    // 8. Safe LDAP with input sanitization
    public SearchResult SafeLdap(DirectorySearcher searcher, string user) {
        string clean = user.Replace("(", "\\28").Replace(")", "\\29").Replace("*", "\\2a").Replace("\\", "\\5c");
        searcher.Filter = string.Format("(&(objectClass=user)(sAMAccountName={0}))", clean);
        return searcher.FindOne();
    }

    // 9. Safe CSRF Enforcement via [ValidateAntiForgeryToken]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Transfer(decimal amount) {
        return Ok(amount);
    }

    // 10. Safe ProcessStartInfo with ArgumentList
    public void SafeProcessStart(string host) {
        var psi = new ProcessStartInfo("ping");
        psi.ArgumentList.Add("-n");
        psi.ArgumentList.Add("1");
        psi.ArgumentList.Add(host);
        Process.Start(psi);
    }
}

public class UserProfile {
    public string Username { get; set; }
}
"#;

    let violations = SecurityLinter::audit_file("Controllers/SecureServicesController.cs", cs_clean_idioms, None);

    let csharp_violations: Vec<_> = violations
        .into_iter()
        .filter(|v| v.rule_id.starts_with("CVE-CS-"))
        .collect();

    assert!(
        csharp_violations.is_empty(),
        "Expected ZERO false positives on clean C# architecture idioms, but found {}: {:?}",
        csharp_violations.len(),
        csharp_violations
            .iter()
            .map(|v| format!("{}: line {} - {}", v.rule_id, v.line_number, v.message))
            .collect::<Vec<_>>()
    );

    // Safe Non-Security Random in a clean non-security context (e.g. Game simulation)
    let cs_clean_game = r#"
using System;

namespace Production.Gaming;

public class GameDice {
    public int Roll() {
        var dice = new Random();
        return dice.Next(1, 7);
    }
}
"#;
    let v_game = SecurityLinter::audit_file("Services/GameDice.cs", cs_clean_game, None);
    assert!(
        v_game.is_empty(),
        "Expected ZERO false positives on clean non-security Random in GameDice.cs"
    );

    // Empirical Observation on CWE-330 Sensitivity:
    // In C#, if ANY method in the file contains a standard `CancellationToken token`,
    // the file-wide check `context_lower.contains("token")` becomes true.
    // Consequently, even benign `new Random()` in the same file will trigger CVE-CS-INSECURE-RANDOM.
    let cs_with_cancellation_token = r#"
using System;
using System.Threading;

public class WorkerService {
    public void DoWork(CancellationToken cancellationToken) {
    }

    public int GetRandomBackoff() {
        var rng = new Random();
        return rng.Next(10, 100);
    }
}
"#;
    let v_token = SecurityLinter::audit_file("Services/WorkerService.cs", cs_with_cancellation_token, None);
    let has_prng_flag = v_token.iter().any(|v| v.rule_id == "CVE-CS-INSECURE-RANDOM");
    assert!(
        has_prng_flag,
        "Empirical check: CVE-CS-INSECURE-RANDOM fires on new Random() due to file-wide token presence"
    );
}

// =============================================================================
// TEST 4: EMPIRICAL C# LEXER MASKING RESILIENCE
// =============================================================================

#[test]
fn test_empirical_csharp_lexer_masking_resilience() {
    // 1. Single-line comments (//), XML documentation comments (///), and
    // standard Javadoc-style multiline comments with leading `*` on every line.
    let cs_standard_comments = r#"
namespace SecurityDocs;

/// <summary>
/// Documentation example of what NOT to do:
/// DO NOT USE: BinaryFormatter formatter = new BinaryFormatter();
/// DO NOT USE: Process.Start("cmd.exe", "/c ping " + host);
/// DO NOT USE: ctx.Database.ExecuteSqlRaw($"DELETE FROM Users WHERE Id = {id}");
/// DO NOT USE: MD5.Create();
/// DO NOT USE: [IgnoreAntiforgeryToken]
/// </summary>
public class SecurityGuidelineService {
    // Single line comment: BinaryFormatter.Deserialize(stream);
    // Single line comment: Process.Start("cmd.exe", "/c " + cmd);
    // Single line comment: MD5.Create();

    /**
     * Standard Javadoc/C# multiline comment block:
     * settings.DtdProcessing = DtdProcessing.Parse;
     * searcher.Filter = $"(&(objectClass=user)(sAMAccountName={userInput}))";
     * var bf = new BinaryFormatter();
     */

    public string GetSafeGreeting() {
        return "Hello World";
    }
}
"#;

    let violations = SecurityLinter::audit_file("Docs/SecurityGuidelineService.cs", cs_standard_comments, None);

    let cs_violations: Vec<_> = violations
        .into_iter()
        .filter(|v| v.rule_id.starts_with("CVE-CS-"))
        .collect();

    assert!(
        cs_violations.is_empty(),
        "Expected ZERO false positives on standard '//', '///', and '/** * */' comments, but found {}: {:?}",
        cs_violations.len(),
        cs_violations
            .iter()
            .map(|v| format!("{}: line {}", v.rule_id, v.line_number))
            .collect::<Vec<_>>()
    );

    // 2. Empirical check on LITERAL_AWARE_RULES and non-prefixed multiline comments:
    // When a block comment lacks leading `*` on interior lines, or inside multiline verbatim strings @"...",
    // because all 10 C# rules are in LITERAL_AWARE_RULES, the raw line is evaluated.
    let cs_raw_doc_strings = r#"
public class VerbatimGuide {
    /* Block comment without asterisk prefix:
    settings.DtdProcessing = DtdProcessing.Parse;
    */
    public string Guide => @"Never call BinaryFormatter.Deserialize(stream);";
}
"#;
    let v_raw = SecurityLinter::audit_file("Docs/VerbatimGuide.cs", cs_raw_doc_strings, None);
    assert!(
        v_raw.iter().any(|v| v.rule_id == "CVE-CS-XXE-INJECTION" || v.rule_id == "CVE-CS-INSECURE-DESERIALIZATION"),
        "Empirical check: LITERAL_AWARE_RULES evaluates raw lines for verbatim strings and unstarred comments"
    );
}

// =============================================================================
// TEST 5: EMPIRICAL CLI & SARIF EXECUTION STRESS
// =============================================================================

#[test]
fn test_empirical_csharp_cli_and_sarif_stress() {
    let exe = get_aether_engine_exe();
    assert!(
        exe.exists(),
        "Compiled aether-engine executable must exist at {}",
        exe.display()
    );

    // Setup an ephemeral project sandbox
    let temp_dir = TempTestDir::new("empirical_csharp_cli");

    // 1. Create a safe C# file
    let safe_cs = temp_dir.path.join("SafeService.cs");
    fs::write(
        &safe_cs,
        r#"
using System;
using System.Security.Cryptography;
using System.Text.Json;

public class SafeService {
    public int GetSecureId() {
        return RandomNumberGenerator.GetInt32(100, 999);
    }
    public string Hash(byte[] data) {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(data));
    }
}
"#,
    )
    .unwrap();

    // 2. Subtest A: Audit safe project with --audit-only --format sarif -o safe.sarif
    let sarif_out = temp_dir.path.join("safe.sarif");
    let output_a = Command::new(&exe)
        .arg("--audit-only")
        .arg("--path")
        .arg(&temp_dir.path)
        .arg("--format")
        .arg("sarif")
        .arg("-o")
        .arg(&sarif_out)
        .output()
        .expect("Failed to execute aether-engine CLI for safe SARIF audit");

    assert_eq!(
        output_a.status.code(),
        Some(0),
        "Safe project audit must exit with code 0. Stderr: {}",
        String::from_utf8_lossy(&output_a.stderr)
    );
    assert!(sarif_out.exists(), "Output SARIF file must be created");

    let sarif_content = fs::read_to_string(&sarif_out).unwrap();
    let sarif_json: serde_json::Value =
        serde_json::from_str(&sarif_content).expect("Output SARIF must be valid JSON");
    assert_eq!(sarif_json["version"], "2.1.0");
    assert_eq!(
        sarif_json["$schema"],
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
    );
    assert_eq!(
        sarif_json["runs"][0]["results"].as_array().unwrap().len(),
        0,
        "Safe project must have 0 SARIF results"
    );

    // 3. Subtest B: Safe project with --fail-on HIGH -> Exit 0
    let output_b = Command::new(&exe)
        .arg("--audit-only")
        .arg("--path")
        .arg(&temp_dir.path)
        .arg("--fail-on")
        .arg("HIGH")
        .output()
        .expect("Failed to execute aether-engine CLI for safe --fail-on");

    assert_eq!(
        output_b.status.code(),
        Some(0),
        "Safe project with --fail-on HIGH must exit with 0"
    );

    // 4. Create a vulnerable C# file in the sandbox
    let vuln_cs = temp_dir.path.join("VulnService.cs");
    fs::write(
        &vuln_cs,
        r#"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

public class VulnService {
    // CRITICAL: CWE-502
    public object Deser(Stream s) {
        var bf = new BinaryFormatter();
        return bf.Deserialize(s);
    }
    // HIGH: CWE-327
    public byte[] WeakHash(byte[] d) {
        using var md5 = MD5.Create();
        return md5.ComputeHash(d);
    }
}
"#,
    )
    .unwrap();

    // 5. Subtest C: Vulnerable project with SARIF output (no --fail-on) -> Exit 0, reports findings
    let vuln_sarif_out = temp_dir.path.join("vuln.sarif");
    let output_c = Command::new(&exe)
        .arg("--audit-only")
        .arg("--path")
        .arg(&temp_dir.path)
        .arg("--format")
        .arg("sarif")
        .arg("-o")
        .arg(&vuln_sarif_out)
        .output()
        .expect("Failed to execute aether-engine CLI for vuln SARIF audit");

    assert_eq!(
        output_c.status.code(),
        Some(0),
        "Audit-only without fail-on must exit 0 even if vulnerabilities exist"
    );
    assert!(vuln_sarif_out.exists());
    let vuln_sarif_content = fs::read_to_string(&vuln_sarif_out).unwrap();
    let vuln_sarif_json: serde_json::Value =
        serde_json::from_str(&vuln_sarif_content).expect("Vuln SARIF must be valid JSON");
    let results = vuln_sarif_json["runs"][0]["results"].as_array().unwrap();
    assert!(
        results.len() >= 2,
        "Expected at least 2 vulnerabilities in SARIF report, got {}",
        results.len()
    );
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "CVE-CS-INSECURE-DESERIALIZATION"),
        "SARIF results must contain CVE-CS-INSECURE-DESERIALIZATION"
    );
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "CVE-CS-WEAK-CRYPTOGRAPHY"),
        "SARIF results must contain CVE-CS-WEAK-CRYPTOGRAPHY"
    );

    // 6. Subtest D: Vulnerable project with --fail-on CRITICAL -> Exit 1
    let output_d = Command::new(&exe)
        .arg("--audit-only")
        .arg("--path")
        .arg(&temp_dir.path)
        .arg("--fail-on")
        .arg("CRITICAL")
        .output()
        .expect("Failed to execute CLI for --fail-on CRITICAL");

    assert_eq!(
        output_d.status.code(),
        Some(1),
        "Vulnerable project with CRITICAL finding must exit with code 1 under --fail-on CRITICAL"
    );

    // 7. Subtest E: Vulnerable project with --fail-on HIGH -> Exit 1
    let output_e = Command::new(&exe)
        .arg("--audit-only")
        .arg("--path")
        .arg(&temp_dir.path)
        .arg("--fail-on")
        .arg("HIGH")
        .output()
        .expect("Failed to execute CLI for --fail-on HIGH");

    assert_eq!(
        output_e.status.code(),
        Some(1),
        "Vulnerable project with HIGH/CRITICAL findings must exit with code 1 under --fail-on HIGH"
    );
}
