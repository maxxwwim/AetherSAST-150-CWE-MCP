use security_linter::{CSharpSecurityRules, SecurityLinter};

#[test]
fn test_cwe_catalog_includes_20_csharp_rules_and_file_detection() {
    let catalog = SecurityLinter::get_supported_cve_rules();

    let csharp_rules: Vec<_> = catalog
        .iter()
        .filter(|r| r.category.starts_with("C# /") || r.rule_id.starts_with("CVE-CS-"))
        .collect();

    assert_eq!(
        csharp_rules.len(),
        20,
        "Expected exactly 20 C# CWE rules in catalog, found {}",
        csharp_rules.len()
    );

    let expected_rules = [
        "CVE-CS-INSECURE-DESERIALIZATION",
        "CVE-CS-SQL-INJECTION",
        "CVE-CS-COMMAND-INJECTION",
        "CVE-CS-PATH-TRAVERSAL",
        "CVE-CS-WEAK-CRYPTOGRAPHY",
        "CVE-CS-XSS-RAW-HTML",
        "CVE-CS-XXE-INJECTION",
        "CVE-CS-INSECURE-RANDOM",
        "CVE-CS-LDAP-INJECTION",
        "CVE-CS-CSRF-DISABLED",
        "CVE-CS-SSRF-HTTPCLIENT",
        "CVE-CS-TLS-CERT-BYPASS",
        "CVE-CS-JWT-VALIDATION-BYPASS",
        "CVE-CS-OPEN-REDIRECT",
        "CVE-CS-MASS-ASSIGNMENT",
        "CVE-CS-REDOS-UNBOUNDED-REGEX",
        "CVE-CS-HARDCODED-CREDENTIALS",
        "CVE-CS-UNSAFE-STACKALLOC-OVERFLOW",
        "CVE-CS-UNSAFE-REFLECTION-INVOKE",
        "CVE-CS-SENSITIVE-ERROR-EXPOSURE",
    ];

    for expected_id in &expected_rules {
        assert!(
            csharp_rules.iter().any(|r| r.rule_id == *expected_id),
            "Expected rule {} in catalog",
            expected_id
        );
    }

    for r in &csharp_rules {
        assert!(
            r.severity == "CRITICAL" || r.severity == "HIGH" || r.severity == "MEDIUM",
            "Rule {} must have severity CRITICAL, HIGH, or MEDIUM, got {}",
            r.rule_id,
            r.severity
        );

        assert!(
            SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "Services/UserService.cs"),
            "Rule {} should match .cs file",
            r.rule_id
        );
        assert!(
            !SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "src/main.rs"),
            "Rule {} should NOT match .rs file",
            r.rule_id
        );
        assert!(
            !SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "src/main.zig"),
            "Rule {} should NOT match .zig file",
            r.rule_id
        );
        assert!(
            !SecurityLinter::is_file_eligible_for_cwe(&r.rule_id, "app.py"),
            "Rule {} should NOT match .py file",
            r.rule_id
        );
        assert!(
            r.matches_file("Controllers/AccountController.cs"),
            "CveRuleDef::matches_file should match C# file"
        );
    }
}

#[test]
fn test_csharp_file_detection_filters() {
    assert!(CSharpSecurityRules::is_csharp_file("src/Service.cs"));
    assert!(CSharpSecurityRules::is_csharp_file("Program.CS"));
    assert!(CSharpSecurityRules::is_csharp_file("C:/Projects/App/Repo.cs"));
    assert!(!CSharpSecurityRules::is_csharp_file("main.rs"));
    assert!(!CSharpSecurityRules::is_csharp_file("main.zig"));
    assert!(!CSharpSecurityRules::is_csharp_file("index.php"));
    assert!(!CSharpSecurityRules::is_csharp_file("script.py"));
}

#[test]
fn test_csharp_cross_language_isolation() {
    let vuln_snippet = r#"
        public class Service {
            public void Run() {
                var formatter = new BinaryFormatter();
                formatter.Deserialize(stream);
            }
        }
    "#;

    // Must return 0 violations on non-C# file extensions
    let v_zig = SecurityLinter::audit_file("src/Buffer.zig", vuln_snippet, None);
    assert!(!v_zig.iter().any(|v| v.rule_id.starts_with("CVE-CS-")));

    let v_rs = SecurityLinter::audit_file("src/buffer.rs", vuln_snippet, None);
    assert!(!v_rs.iter().any(|v| v.rule_id.starts_with("CVE-CS-")));

    let v_py = SecurityLinter::audit_file("src/buffer.py", vuln_snippet, None);
    assert!(!v_py.iter().any(|v| v.rule_id.starts_with("CVE-CS-")));
}

#[test]
fn test_all_10_csharp_cwe_vulnerabilities_and_safe_remediations() {
    // -------------------------------------------------------------
    // 1. CWE-502: Insecure Deserialization (CVE-CS-INSECURE-DESERIALIZATION)
    // -------------------------------------------------------------
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
    let safe_deser = r#"
using System.IO;
using System.Text.Json;

public class ImportService {
    public UserProfile RestoreState(Stream networkStream) {
        return JsonSerializer.Deserialize<UserProfile>(networkStream);
    }
}
"#;
    let v_deser = SecurityLinter::audit_file("Services/ImportService.cs", vuln_deser, None);
    assert!(
        v_deser.iter().any(|v| v.rule_id == "CVE-CS-INSECURE-DESERIALIZATION" && v.severity == "CRITICAL"),
        "Expected CVE-CS-INSECURE-DESERIALIZATION on vulnerable snippet"
    );
    let s_deser = SecurityLinter::audit_file("Services/ImportService.cs", safe_deser, None);
    assert!(
        !s_deser.iter().any(|v| v.rule_id == "CVE-CS-INSECURE-DESERIALIZATION"),
        "Unexpected CVE-CS-INSECURE-DESERIALIZATION on safe snippet"
    );

    // -------------------------------------------------------------
    // 2. CWE-89: SQL Injection (CVE-CS-SQL-INJECTION)
    // -------------------------------------------------------------
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
    let safe_sql = r#"
using System.Data.SqlClient;

public class UserRepository {
    public void DeleteUser(SqlConnection conn, string username) {
        string sql = "DELETE FROM Users WHERE Username = @username";
        SqlCommand cmd = new SqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);
        cmd.ExecuteNonQuery();
    }
}
"#;
    let v_sql = SecurityLinter::audit_file("Data/UserRepository.cs", vuln_sql, None);
    assert!(
        v_sql.iter().any(|v| v.rule_id == "CVE-CS-SQL-INJECTION" && v.severity == "CRITICAL"),
        "Expected CVE-CS-SQL-INJECTION on vulnerable snippet"
    );
    let s_sql = SecurityLinter::audit_file("Data/UserRepository.cs", safe_sql, None);
    assert!(
        !s_sql.iter().any(|v| v.rule_id == "CVE-CS-SQL-INJECTION"),
        "Unexpected CVE-CS-SQL-INJECTION on safe snippet"
    );

    // -------------------------------------------------------------
    // 3. CWE-78: Command Injection (CVE-CS-COMMAND-INJECTION)
    // -------------------------------------------------------------
    let vuln_cmd = r#"
using System.Diagnostics;

public class ProcessRunner {
    public void PingHost(string host) {
        Process.Start("cmd.exe", "/c ping -n 1 " + host);
    }
}
"#;
    let safe_cmd = r#"
using System.Diagnostics;

public class ProcessRunner {
    public void PingHost(string host) {
        ProcessStartInfo psi = new ProcessStartInfo("ping");
        psi.ArgumentList.Add("-n");
        psi.ArgumentList.Add("1");
        psi.ArgumentList.Add(host);
        Process.Start(psi);
    }
}
"#;
    let v_cmd = SecurityLinter::audit_file("Diagnostics/ProcessRunner.cs", vuln_cmd, None);
    assert!(
        v_cmd.iter().any(|v| v.rule_id == "CVE-CS-COMMAND-INJECTION" && v.severity == "CRITICAL"),
        "Expected CVE-CS-COMMAND-INJECTION on vulnerable snippet"
    );
    let s_cmd = SecurityLinter::audit_file("Diagnostics/ProcessRunner.cs", safe_cmd, None);
    assert!(
        !s_cmd.iter().any(|v| v.rule_id == "CVE-CS-COMMAND-INJECTION"),
        "Unexpected CVE-CS-COMMAND-INJECTION on safe snippet"
    );

    // -------------------------------------------------------------
    // 4. CWE-22: Path Traversal (CVE-CS-PATH-TRAVERSAL)
    // -------------------------------------------------------------
    let vuln_path = r#"
using System.IO;

public class FileController {
    public string ReadUserDocument(string baseFolder, string fileName) {
        string fullPath = Path.Combine(baseFolder, fileName);
        return File.ReadAllText(fullPath);
    }
}
"#;
    let safe_path = r#"
using System;
using System.IO;

public class FileController {
    public string ReadUserDocument(string baseFolder, string fileName) {
        string canonicalBase = Path.GetFullPath(baseFolder);
        string fullPath = Path.GetFullPath(Path.Combine(canonicalBase, fileName));
        if (!fullPath.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase)) {
            throw new UnauthorizedAccessException("Path traversal detected");
        }
        return File.ReadAllText(fullPath);
    }
}
"#;
    let v_path = SecurityLinter::audit_file("Controllers/FileController.cs", vuln_path, None);
    assert!(
        v_path.iter().any(|v| v.rule_id == "CVE-CS-PATH-TRAVERSAL" && v.severity == "HIGH"),
        "Expected CVE-CS-PATH-TRAVERSAL on vulnerable snippet"
    );
    let s_path = SecurityLinter::audit_file("Controllers/FileController.cs", safe_path, None);
    assert!(
        !s_path.iter().any(|v| v.rule_id == "CVE-CS-PATH-TRAVERSAL"),
        "Unexpected CVE-CS-PATH-TRAVERSAL on safe snippet"
    );

    // -------------------------------------------------------------
    // 5. CWE-327 / CWE-328: Broken Cryptography (CVE-CS-WEAK-CRYPTOGRAPHY)
    // -------------------------------------------------------------
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
    let safe_crypto = r#"
using System.Security.Cryptography;

public class Hasher {
    public byte[] HashPassword(byte[] password) {
        using (var sha256 = SHA256.Create()) {
            return sha256.ComputeHash(password);
        }
    }
}
"#;
    let v_crypto = SecurityLinter::audit_file("Security/Hasher.cs", vuln_crypto, None);
    assert!(
        v_crypto.iter().any(|v| v.rule_id == "CVE-CS-WEAK-CRYPTOGRAPHY" && v.severity == "HIGH"),
        "Expected CVE-CS-WEAK-CRYPTOGRAPHY on vulnerable snippet"
    );
    let s_crypto = SecurityLinter::audit_file("Security/Hasher.cs", safe_crypto, None);
    assert!(
        !s_crypto.iter().any(|v| v.rule_id == "CVE-CS-WEAK-CRYPTOGRAPHY"),
        "Unexpected CVE-CS-WEAK-CRYPTOGRAPHY on safe snippet"
    );

    // -------------------------------------------------------------
    // 6. CWE-79: Cross-Site Scripting via Raw HTML (CVE-CS-XSS-RAW-HTML)
    // -------------------------------------------------------------
    let vuln_xss = r#"
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class UserProfileModel : PageModel {
    public HtmlString RenderBio(string userBio) {
        return new HtmlString(userBio);
    }
}
"#;
    let safe_xss = r#"
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class UserProfileModel : PageModel {
    public HtmlString RenderBio(string userBio) {
        string encoded = HtmlEncoder.Default.Encode(userBio);
        return new HtmlString(encoded);
    }
}
"#;
    let v_xss = SecurityLinter::audit_file("Views/UserProfile.cshtml.cs", vuln_xss, None);
    assert!(
        v_xss.iter().any(|v| v.rule_id == "CVE-CS-XSS-RAW-HTML" && v.severity == "HIGH"),
        "Expected CVE-CS-XSS-RAW-HTML on vulnerable snippet"
    );
    let s_xss = SecurityLinter::audit_file("Views/UserProfile.cshtml.cs", safe_xss, None);
    assert!(
        !s_xss.iter().any(|v| v.rule_id == "CVE-CS-XSS-RAW-HTML"),
        "Unexpected CVE-CS-XSS-RAW-HTML on safe snippet"
    );

    // -------------------------------------------------------------
    // 7. CWE-611: XML External Entity (XXE) (CVE-CS-XXE-INJECTION)
    // -------------------------------------------------------------
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
    let safe_xxe = r#"
using System.Xml;

public class XmlParser {
    public void ParseDocument(string xml) {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.XmlResolver = null;
        using (XmlReader reader = XmlReader.Create(new System.IO.StringReader(xml), settings)) {
            XmlDocument doc = new XmlDocument();
            doc.Load(reader);
        }
    }
}
"#;
    let v_xxe = SecurityLinter::audit_file("Parsers/XmlParser.cs", vuln_xxe, None);
    assert!(
        v_xxe.iter().any(|v| v.rule_id == "CVE-CS-XXE-INJECTION" && v.severity == "HIGH"),
        "Expected CVE-CS-XXE-INJECTION on vulnerable snippet"
    );
    let s_xxe = SecurityLinter::audit_file("Parsers/XmlParser.cs", safe_xxe, None);
    assert!(
        !s_xxe.iter().any(|v| v.rule_id == "CVE-CS-XXE-INJECTION"),
        "Unexpected CVE-CS-XXE-INJECTION on safe snippet"
    );

    // -------------------------------------------------------------
    // 8. CWE-330: Insecure PRNG (CVE-CS-INSECURE-RANDOM)
    // -------------------------------------------------------------
    let vuln_random = r#"
using System;

public class TokenGenerator {
    public int GenerateAuthCode() {
        Random rng = new Random();
        return rng.Next(100000, 999999);
    }
}
"#;
    let safe_random = r#"
using System.Security.Cryptography;

public class TokenGenerator {
    public int GenerateAuthCode() {
        return RandomNumberGenerator.GetInt32(100000, 999999);
    }
}
"#;
    let v_random = SecurityLinter::audit_file("Tokens/TokenGenerator.cs", vuln_random, None);
    assert!(
        v_random.iter().any(|v| v.rule_id == "CVE-CS-INSECURE-RANDOM" && v.severity == "MEDIUM"),
        "Expected CVE-CS-INSECURE-RANDOM on vulnerable snippet"
    );
    let s_random = SecurityLinter::audit_file("Tokens/TokenGenerator.cs", safe_random, None);
    assert!(
        !s_random.iter().any(|v| v.rule_id == "CVE-CS-INSECURE-RANDOM"),
        "Unexpected CVE-CS-INSECURE-RANDOM on safe snippet"
    );

    // -------------------------------------------------------------
    // 9. CWE-90: LDAP Injection (CVE-CS-LDAP-INJECTION)
    // -------------------------------------------------------------
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
    let safe_ldap = r#"
using System.DirectoryServices;

public class LdapService {
    public SearchResult FindAccount(DirectoryEntry root, string user) {
        string cleanUser = user.Replace("(", "\\28").Replace(")", "\\29").Replace("*", "\\2a").Replace("\\", "\\5c");
        DirectorySearcher searcher = new DirectorySearcher(root);
        searcher.Filter = string.Format("(&(objectClass=user)(sAMAccountName={0}))", cleanUser);
        return searcher.FindOne();
    }
}
"#;
    let v_ldap = SecurityLinter::audit_file("Auth/LdapService.cs", vuln_ldap, None);
    assert!(
        v_ldap.iter().any(|v| v.rule_id == "CVE-CS-LDAP-INJECTION" && v.severity == "HIGH"),
        "Expected CVE-CS-LDAP-INJECTION on vulnerable snippet"
    );
    let s_ldap = SecurityLinter::audit_file("Auth/LdapService.cs", safe_ldap, None);
    assert!(
        !s_ldap.iter().any(|v| v.rule_id == "CVE-CS-LDAP-INJECTION"),
        "Unexpected CVE-CS-LDAP-INJECTION on safe snippet"
    );

    // -------------------------------------------------------------
    // 10. CWE-352: CSRF Disabled (CVE-CS-CSRF-DISABLED)
    // -------------------------------------------------------------
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
    let safe_csrf = r#"
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller {
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult TransferFunds(decimal amount) {
        return Ok();
    }
}
"#;
    let v_csrf = SecurityLinter::audit_file("Controllers/AccountController.cs", vuln_csrf, None);
    assert!(
        v_csrf.iter().any(|v| v.rule_id == "CVE-CS-CSRF-DISABLED" && v.severity == "MEDIUM"),
        "Expected CVE-CS-CSRF-DISABLED on vulnerable snippet"
    );
    let s_csrf = SecurityLinter::audit_file("Controllers/AccountController.cs", safe_csrf, None);
    assert!(
        !s_csrf.iter().any(|v| v.rule_id == "CVE-CS-CSRF-DISABLED"),
        "Unexpected CVE-CS-CSRF-DISABLED on safe snippet"
    );

    // -------------------------------------------------------------
    // 11. CWE-918: SSRF Outbound HttpClient (CVE-CS-SSRF-HTTPCLIENT)
    // -------------------------------------------------------------
    let vuln_ssrf = r#"
using System.Net.Http;
using System.Threading.Tasks;

public class WebhookService {
    private readonly HttpClient _httpClient = new HttpClient();
    public async Task<string> FetchRemotePreview(string callbackUrl) {
        return await _httpClient.GetStringAsync(callbackUrl);
    }
}
"#;
    let safe_ssrf = r#"
using System;
using System.Net.Http;
using System.Threading.Tasks;

public class WebhookService {
    private static readonly string[] AllowedHosts = { "api.partner.com" };
    private readonly HttpClient _httpClient = new HttpClient();
    public async Task<string> FetchRemotePreview(string callbackUrl) {
        var uri = new Uri(callbackUrl);
        if (uri.IsLoopback || Array.IndexOf(AllowedHosts, uri.Host) < 0) {
            throw new InvalidOperationException("Host not in allowlist");
        }
        return await _httpClient.GetStringAsync(uri);
    }
}
"#;
    let v_ssrf = SecurityLinter::audit_file("Services/WebhookService.cs", vuln_ssrf, None);
    assert!(
        v_ssrf.iter().any(|v| v.rule_id == "CVE-CS-SSRF-HTTPCLIENT" && v.severity == "HIGH"),
        "Expected CVE-CS-SSRF-HTTPCLIENT on vulnerable snippet"
    );
    let s_ssrf = SecurityLinter::audit_file("Services/WebhookService.cs", safe_ssrf, None);
    assert!(
        !s_ssrf.iter().any(|v| v.rule_id == "CVE-CS-SSRF-HTTPCLIENT"),
        "Unexpected CVE-CS-SSRF-HTTPCLIENT on safe snippet"
    );

    // -------------------------------------------------------------
    // 12. CWE-295: TLS Certificate Bypass (CVE-CS-TLS-CERT-BYPASS)
    // -------------------------------------------------------------
    let vuln_tls = r#"
using System.Net.Http;

public class HttpFactory {
    public HttpClient CreateInsecureClient() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return new HttpClient(handler);
    }
}
"#;
    let safe_tls = r#"
using System.Net.Http;
using System.Net.Security;

public class HttpFactory {
    public HttpClient CreateSecureClient() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => errors == SslPolicyErrors.None;
        return new HttpClient(handler);
    }
}
"#;
    let v_tls = SecurityLinter::audit_file("Net/HttpFactory.cs", vuln_tls, None);
    assert!(
        v_tls.iter().any(|v| v.rule_id == "CVE-CS-TLS-CERT-BYPASS" && v.severity == "CRITICAL"),
        "Expected CVE-CS-TLS-CERT-BYPASS on vulnerable snippet"
    );
    let s_tls = SecurityLinter::audit_file("Net/HttpFactory.cs", safe_tls, None);
    assert!(
        !s_tls.iter().any(|v| v.rule_id == "CVE-CS-TLS-CERT-BYPASS"),
        "Unexpected CVE-CS-TLS-CERT-BYPASS on safe snippet"
    );

    // -------------------------------------------------------------
    // 13. CWE-347: JWT Validation Bypass (CVE-CS-JWT-VALIDATION-BYPASS)
    // -------------------------------------------------------------
    let vuln_jwt = r#"
using Microsoft.IdentityModel.Tokens;

public class AuthConfig {
    public TokenValidationParameters GetParams() {
        return new TokenValidationParameters {
            ValidateIssuerSigningKey = false,
            RequireSignedTokens = false,
            ValidateLifetime = false
        };
    }
}
"#;
    let safe_jwt = r#"
using Microsoft.IdentityModel.Tokens;

public class AuthConfig {
    public TokenValidationParameters GetParams(SecurityKey key) {
        return new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true
        };
    }
}
"#;
    let v_jwt = SecurityLinter::audit_file("Auth/AuthConfig.cs", vuln_jwt, None);
    assert!(
        v_jwt.iter().any(|v| v.rule_id == "CVE-CS-JWT-VALIDATION-BYPASS" && v.severity == "CRITICAL"),
        "Expected CVE-CS-JWT-VALIDATION-BYPASS on vulnerable snippet"
    );
    let s_jwt = SecurityLinter::audit_file("Auth/AuthConfig.cs", safe_jwt, None);
    assert!(
        !s_jwt.iter().any(|v| v.rule_id == "CVE-CS-JWT-VALIDATION-BYPASS"),
        "Unexpected CVE-CS-JWT-VALIDATION-BYPASS on safe snippet"
    );

    // -------------------------------------------------------------
    // 14. CWE-601: Open Redirect (CVE-CS-OPEN-REDIRECT)
    // -------------------------------------------------------------
    let vuln_redir = r#"
using Microsoft.AspNetCore.Mvc;

public class LoginController : Controller {
    public IActionResult OnLoginSuccess(string returnUrl) {
        return Redirect(returnUrl);
    }
}
"#;
    let safe_redir = r#"
using Microsoft.AspNetCore.Mvc;

public class LoginController : Controller {
    public IActionResult OnLoginSuccess(string returnUrl) {
        if (Url.IsLocalUrl(returnUrl)) {
            return LocalRedirect(returnUrl);
        }
        return Redirect("/dashboard");
    }
}
"#;
    let v_redir = SecurityLinter::audit_file("Controllers/LoginController.cs", vuln_redir, None);
    assert!(
        v_redir.iter().any(|v| v.rule_id == "CVE-CS-OPEN-REDIRECT" && v.severity == "HIGH"),
        "Expected CVE-CS-OPEN-REDIRECT on vulnerable snippet"
    );
    let s_redir = SecurityLinter::audit_file("Controllers/LoginController.cs", safe_redir, None);
    assert!(
        !s_redir.iter().any(|v| v.rule_id == "CVE-CS-OPEN-REDIRECT"),
        "Unexpected CVE-CS-OPEN-REDIRECT on safe snippet"
    );

    // -------------------------------------------------------------
    // 15. CWE-915: Mass Assignment / Over-Posting (CVE-CS-MASS-ASSIGNMENT)
    // -------------------------------------------------------------
    let vuln_mass = r#"
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

public class UserAdminController : Controller {
    public async Task<IActionResult> EditUser(AccountEntity user) {
        await TryUpdateModelAsync(user);
        return Ok();
    }
}
"#;
    let safe_mass = r#"
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

public class UserAdminController : Controller {
    public async Task<IActionResult> EditUser(AccountEntity user) {
        await TryUpdateModelAsync(user, "", u => u.DisplayName, u => u.Email);
        return Ok();
    }
}
"#;
    let v_mass = SecurityLinter::audit_file("Controllers/UserAdminController.cs", vuln_mass, None);
    assert!(
        v_mass.iter().any(|v| v.rule_id == "CVE-CS-MASS-ASSIGNMENT" && v.severity == "HIGH"),
        "Expected CVE-CS-MASS-ASSIGNMENT on vulnerable snippet"
    );
    let s_mass = SecurityLinter::audit_file("Controllers/UserAdminController.cs", safe_mass, None);
    assert!(
        !s_mass.iter().any(|v| v.rule_id == "CVE-CS-MASS-ASSIGNMENT"),
        "Unexpected CVE-CS-MASS-ASSIGNMENT on safe snippet"
    );

    // -------------------------------------------------------------
    // 16. CWE-1333: ReDoS Unbounded Regex (CVE-CS-REDOS-UNBOUNDED-REGEX)
    // -------------------------------------------------------------
    let vuln_redos = r#"
using System.Text.RegularExpressions;

public class SearchFilter {
    public bool MatchesPattern(string input, string userPattern) {
        return Regex.IsMatch(input, userPattern);
    }
}
"#;
    let safe_redos = r#"
using System;
using System.Text.RegularExpressions;

public class SearchFilter {
    public bool MatchesPattern(string input, string userPattern) {
        return Regex.IsMatch(input, userPattern, RegexOptions.None, TimeSpan.FromMilliseconds(200));
    }
}
"#;
    let v_redos = SecurityLinter::audit_file("Filters/SearchFilter.cs", vuln_redos, None);
    assert!(
        v_redos.iter().any(|v| v.rule_id == "CVE-CS-REDOS-UNBOUNDED-REGEX" && v.severity == "HIGH"),
        "Expected CVE-CS-REDOS-UNBOUNDED-REGEX on vulnerable snippet"
    );
    let s_redos = SecurityLinter::audit_file("Filters/SearchFilter.cs", safe_redos, None);
    assert!(
        !s_redos.iter().any(|v| v.rule_id == "CVE-CS-REDOS-UNBOUNDED-REGEX"),
        "Unexpected CVE-CS-REDOS-UNBOUNDED-REGEX on safe snippet"
    );

    // -------------------------------------------------------------
    // 17. CWE-798: Hardcoded Credentials (CVE-CS-HARDCODED-CREDENTIALS)
    // -------------------------------------------------------------
    let vuln_secret = r#"
public class DbConfig {
    private const string JwtSecret = "super_secret_production_signing_key_998877";
}
"#;
    let safe_secret = r#"
using System;

public class DbConfig {
    public string GetJwtSecret() => Environment.GetEnvironmentVariable("JWT_SECRET") ?? string.Empty;
}
"#;
    let v_secret = SecurityLinter::audit_file("Config/DbConfig.cs", vuln_secret, None);
    assert!(
        v_secret.iter().any(|v| v.rule_id == "CVE-CS-HARDCODED-CREDENTIALS" && v.severity == "CRITICAL"),
        "Expected CVE-CS-HARDCODED-CREDENTIALS on vulnerable snippet"
    );
    let s_secret = SecurityLinter::audit_file("Config/DbConfig.cs", safe_secret, None);
    assert!(
        !s_secret.iter().any(|v| v.rule_id == "CVE-CS-HARDCODED-CREDENTIALS"),
        "Unexpected CVE-CS-HARDCODED-CREDENTIALS on safe snippet"
    );

    // -------------------------------------------------------------
    // 18. CWE-787: Unsafe Unbounded stackalloc (CVE-CS-UNSAFE-STACKALLOC-OVERFLOW)
    // -------------------------------------------------------------
    let vuln_stackalloc = r#"
using System;

public class PacketBuffer {
    public void ProcessFrame(int packetLength) {
        Span<byte> scratch = stackalloc byte[packetLength];
        scratch[0] = 1;
    }
}
"#;
    let safe_stackalloc = r#"
using System;

public class PacketBuffer {
    public void ProcessFrame(int packetLength) {
        if (packetLength > 1024) throw new ArgumentOutOfRangeException(nameof(packetLength));
        Span<byte> scratch = stackalloc byte[256];
        scratch[0] = 1;
    }
}
"#;
    let v_stackalloc = SecurityLinter::audit_file("Buffers/PacketBuffer.cs", vuln_stackalloc, None);
    assert!(
        v_stackalloc.iter().any(|v| v.rule_id == "CVE-CS-UNSAFE-STACKALLOC-OVERFLOW" && v.severity == "HIGH"),
        "Expected CVE-CS-UNSAFE-STACKALLOC-OVERFLOW on vulnerable snippet"
    );
    let s_stackalloc = SecurityLinter::audit_file("Buffers/PacketBuffer.cs", safe_stackalloc, None);
    assert!(
        !s_stackalloc.iter().any(|v| v.rule_id == "CVE-CS-UNSAFE-STACKALLOC-OVERFLOW"),
        "Unexpected CVE-CS-UNSAFE-STACKALLOC-OVERFLOW on safe snippet"
    );

    // -------------------------------------------------------------
    // 19. CWE-470: Unsafe Reflection Invoke (CVE-CS-UNSAFE-REFLECTION-INVOKE)
    // -------------------------------------------------------------
    let vuln_refl = r#"
using System;

public class PluginLoader {
    public object InstantiateHandler(string userTypeName) {
        Type t = Type.GetType(userTypeName);
        return Activator.CreateInstance(t);
    }
}
"#;
    let safe_refl = r#"
using System;

public class PluginLoader {
    public object InstantiateDefault() {
        Type t = Type.GetType("MyApp.Plugins.DefaultHandler");
        return new object();
    }
}
"#;
    let v_refl = SecurityLinter::audit_file("Plugins/PluginLoader.cs", vuln_refl, None);
    assert!(
        v_refl.iter().any(|v| v.rule_id == "CVE-CS-UNSAFE-REFLECTION-INVOKE" && v.severity == "CRITICAL"),
        "Expected CVE-CS-UNSAFE-REFLECTION-INVOKE on vulnerable snippet"
    );
    let s_refl = SecurityLinter::audit_file("Plugins/PluginLoader.cs", safe_refl, None);
    assert!(
        !s_refl.iter().any(|v| v.rule_id == "CVE-CS-UNSAFE-REFLECTION-INVOKE"),
        "Unexpected CVE-CS-UNSAFE-REFLECTION-INVOKE on safe snippet"
    );

    // -------------------------------------------------------------
    // 20. CWE-209: Sensitive Error Exposure (CVE-CS-SENSITIVE-ERROR-EXPOSURE)
    // -------------------------------------------------------------
    let vuln_err = r#"
using System;
using Microsoft.AspNetCore.Mvc;

public class OrderController : Controller {
    public IActionResult Checkout() {
        try {
            return Ok();
        } catch (Exception ex) {
            return BadRequest(ex.StackTrace);
        }
    }
}
"#;
    let safe_err = r#"
using System;
using Microsoft.AspNetCore.Mvc;

public class OrderController : Controller {
    public IActionResult Checkout() {
        try {
            return Ok();
        } catch (Exception) {
            return Problem("An unexpected error occurred.");
        }
    }
}
"#;
    let v_err = SecurityLinter::audit_file("Controllers/OrderController.cs", vuln_err, None);
    assert!(
        v_err.iter().any(|v| v.rule_id == "CVE-CS-SENSITIVE-ERROR-EXPOSURE" && v.severity == "MEDIUM"),
        "Expected CVE-CS-SENSITIVE-ERROR-EXPOSURE on vulnerable snippet"
    );
    let s_err = SecurityLinter::audit_file("Controllers/OrderController.cs", safe_err, None);
    assert!(
        !s_err.iter().any(|v| v.rule_id == "CVE-CS-SENSITIVE-ERROR-EXPOSURE"),
        "Unexpected CVE-CS-SENSITIVE-ERROR-EXPOSURE on safe snippet"
    );
}
