use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::{timeout, Duration};

#[derive(Deserialize, Debug, Clone)]
pub struct SurfaceScanRequest {
    pub target: String,
    /// 1 = Furtif/Passif, 2 = Services/Versions, 3 = Black-Box Web & Forms, 4 = Audit d'Exposition (.env, .git, Configs - CWE-538 Masqué)
    pub scan_level: Option<u8>,
    pub check_dns: Option<bool>,
    pub check_ports: Option<bool>,
    pub check_headers: Option<bool>,
    pub check_endpoints: Option<bool>,
    pub check_web_forms: Option<bool>,
    pub check_sensitive_files: Option<bool>,
    pub custom_ports: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ExposedArtifactProbe {
    pub path: String,
    pub label: String,
    pub category: String,
    pub exposed: bool,
    pub http_status: String,
    pub risk_level: String, // "CRITICAL", "HIGH", "MEDIUM", "INFO"
    pub redacted_preview: Option<String>,
    pub remediation: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ImpactVisibilityMatrix {
    pub scan_level: u8,
    pub level_name: String,
    pub visibility_footprint: String,
    pub impact_rating: String,
    pub packets_sent_estimate: String,
    pub detected_services_count: usize,
    pub detected_versions_count: usize,
    pub detected_forms_count: usize,
    pub detected_inputs_count: usize,
    pub detected_routes_count: usize,
    pub detected_exposures_count: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct PortProbeResult {
    pub port: u16,
    pub service: String,
    pub protocol: String,
    pub open: bool,
    pub latency_ms: Option<u64>,
    pub risk_level: String,
    pub banner: Option<String>,
    pub detected_version: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct TechFingerprint {
    pub name: String,
    pub category: String, // "Serveur Web", "Framework / Runtime", "CDN / Reverse-Proxy", "Frontend JS", "Session / Auth"
    pub version: Option<String>,
    pub source: String,
    pub confidence: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct HeaderControlResult {
    pub header: String,
    pub present: bool,
    pub value: Option<String>,
    pub status: String, // "PASS", "WARN", "FAIL"
    pub recommendation: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredInput {
    pub name: String,
    pub input_type: String,
    pub tag: String, // "input", "textarea", "select"
    pub required: bool,
    pub classification: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredForm {
    pub index: usize,
    pub id_or_name: String,
    pub method: String,
    pub action: String,
    pub enctype: Option<String>,
    pub has_csrf_token: bool,
    pub has_password_field: bool,
    pub has_file_upload: bool,
    pub inputs: Vec<DiscoveredInput>,
    pub security_posture: String, // "PASS", "WARN", "CRITICAL"
    pub security_notes: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredRoute {
    pub path: String,
    pub method: String,
    pub source: String, // "Form Action", "HTML Link", "Script / API", "robots.txt", "Endpoint Probe"
    pub status: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredWebFile {
    pub path: String,
    pub file_type: String, // "HTML", "JS", "CSS", "JSON"
    pub http_status: String,
    pub size_bytes: usize,
    pub folder_calls: Vec<String>,
    pub api_and_asset_refs: Vec<String>,
    pub json_payload_keys: Vec<String>,
    pub has_sourcemap: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredDirectory {
    pub folder_path: String,
    pub source_files: Vec<String>,
    pub call_count: usize,
    pub classification: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct TrustZoneSummary {
    pub zone_id: u8,
    pub title: String,
    pub subtitle: String,
    pub posture: String, // "PASS", "WARN", "CRITICAL"
    pub controls: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DefensiveVerificationCheck {
    pub id: String,
    pub title: String,
    pub category: String,
    pub assertion_cmd: String,
    pub expected_result: String,
    pub patch_hint: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct BoundaryWeaknessProbe {
    pub id: String,
    pub cwe: String,
    pub side_one_vector: String,
    pub category: String,
    pub status: String, // "ROBUSTE", "FAIBLESSE", "EXPOSÉ"
    pub observed_behavior: String,
    pub side_two_ast_target: String,
    pub negative_test_spec: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct WebArchitectureDiscovery {
    pub is_web_arch: bool,
    pub page_title: Option<String>,
    pub meta_generator: Option<String>,
    pub content_type: Option<String>,
    pub body_size_bytes: usize,
    pub forms: Vec<DiscoveredForm>,
    pub routes: Vec<DiscoveredRoute>,
    pub external_scripts: Vec<String>,
    pub robots_entries: Vec<String>,
    pub security_txt_present: bool,
    pub web_files: Vec<DiscoveredWebFile>,
    pub directories: Vec<DiscoveredDirectory>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SurfaceFinding {
    pub id: String,
    pub cwe: String,
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    pub category: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct SurfaceScanResponse {
    pub status: String,
    pub target_raw: String,
    pub host: String,
    pub scheme: String,
    pub primary_port: u16,
    pub target_classification: String,
    pub resolved_ips: Vec<String>,
    pub dns_latency_ms: u64,
    pub scan_duration_ms: u64,
    pub security_score: u32,
    pub grade: String,
    pub http_status: Option<String>,
    pub impact_matrix: ImpactVisibilityMatrix,
    pub tech_stack: Vec<TechFingerprint>,
    pub open_ports: Vec<PortProbeResult>,
    pub headers_audit: Vec<HeaderControlResult>,
    pub raw_headers: HashMap<String, String>,
    pub web_discovery: Option<WebArchitectureDiscovery>,
    pub exposed_artifacts: Vec<ExposedArtifactProbe>,
    pub trust_zones: Vec<TrustZoneSummary>,
    pub verification_suite: Vec<DefensiveVerificationCheck>,
    pub boundary_weaknesses: Vec<BoundaryWeaknessProbe>,
    pub findings: Vec<SurfaceFinding>,
}

fn parse_target_input(raw: &str) -> (String, String, u16, String) {
    let trimmed = raw.trim();
    let (scheme, rest, has_explicit_scheme) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https".to_string(), r, true)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http".to_string(), r, true)
    } else {
        ("http".to_string(), trimmed, false)
    };

    let (authority, path) = match rest.find('/') {
        Some(idx) => {
            let auth = rest.get(..idx).unwrap_or(rest);
            let p = rest.get(idx..).unwrap_or("/");
            (auth, p.to_string())
        }
        None => (rest, "/".to_string()),
    };

    if authority.starts_with('[') {
        if let Some(close_bracket) = authority.find(']') {
            let host = authority
                .get(1..close_bracket)
                .unwrap_or("127.0.0.1")
                .to_string();
            let after = authority.get(close_bracket + 1..).unwrap_or("");
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            return (scheme, host, port, path);
        }
    }

    if let Some(colon_idx) = authority.rfind(':') {
        let host_part = authority.get(..colon_idx).unwrap_or(authority);
        let port_part = authority.get(colon_idx + 1..).unwrap_or("");
        if let Ok(p) = port_part.parse::<u16>() {
            let final_scheme = if !has_explicit_scheme && (p == 443 || p == 8443) {
                "https".to_string()
            } else {
                scheme
            };
            return (final_scheme, host_part.to_string(), p, path);
        }
    }

    let default_port = if scheme == "https" { 443 } else { 80 };
    (scheme, authority.to_string(), default_port, path)
}

fn classify_ip(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                "Loopback / Localhost (127.0.0.0/8)"
            } else if v4.is_private() {
                "Réseau Privé Interne (RFC 1918)"
            } else if v4.is_link_local() {
                "Lien-Local / Cloud Metadata (169.254.0.0/16)"
            } else {
                "Surface WAN / IP Publique"
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                "Loopback IPv6 (::1)"
            } else {
                "Surface IPv6"
            }
        }
    }
}

fn port_service_info(port: u16) -> (&'static str, &'static str, &'static str) {
    match port {
        21 => ("FTP File Server", "FTP", "HIGH"),
        22 => ("OpenSSH / SSH Daemon", "SSH", "MEDIUM"),
        23 => ("Telnet (Cleartext)", "TELNET", "CRITICAL"),
        25 | 587 => ("SMTP Mail Transfer", "SMTP", "MEDIUM"),
        80 => ("HTTP Web Server", "HTTP", "LOW"),
        443 => ("HTTPS / TLS Web", "HTTPS/TLS", "INFO"),
        3000 => ("Node.js / Vite / React Dev", "HTTP", "LOW"),
        3030 => ("AetherScope / Axum API", "HTTP", "INFO"),
        3306 => ("MySQL / MariaDB Server", "MYSQL", "HIGH"),
        5000 => ("Python Flask / Control-Plane", "HTTP", "LOW"),
        5432 => ("PostgreSQL Database", "PGSQL", "HIGH"),
        6379 => ("Redis Cache / Broker", "RESP", "CRITICAL"),
        8000 => ("Uvicorn / FastAPI / Django", "HTTP", "LOW"),
        8080 => ("HTTP Reverse-Proxy / Alt Web", "HTTP", "LOW"),
        8443 => ("HTTPS Alt / Admin Gateway", "HTTPS/TLS", "INFO"),
        9200 => ("Elasticsearch REST Node", "HTTP", "CRITICAL"),
        27017 => ("MongoDB Wire Daemon", "MONGO", "CRITICAL"),
        _ => ("Custom TCP Service", "TCP", "LOW"),
    }
}

fn extract_version_token(raw: &str) -> Option<String> {
    for token in raw.split([' ', ';', '(', ')']) {
        let t = token.trim();
        if t.contains('/') && t.chars().any(|c| c.is_ascii_digit()) {
            return Some(t.to_string());
        }
        if t.starts_with("SSH-") {
            return Some(t.to_string());
        }
    }
    None
}

async fn probe_single_port(host: String, port: u16, grab_banner: bool) -> PortProbeResult {
    let (service, proto, risk) = port_service_info(port);
    let start = Instant::now();
    let addr = format!("{}:{}", host, port);
    let conn_res = timeout(Duration::from_millis(360), TcpStream::connect(&addr)).await;

    let mut stream = match conn_res {
        Ok(Ok(s)) => s,
        _ => {
            return PortProbeResult {
                port,
                service: service.to_string(),
                protocol: proto.to_string(),
                open: false,
                latency_ms: None,
                risk_level: risk.to_string(),
                banner: None,
                detected_version: None,
            };
        }
    };

    let latency_ms = Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(0));
    let mut banner = None;
    let mut detected_version = None;

    if grab_banner {
        // Pour les ports HTTP, envoyer un HEAD léger afin d'extraire la bannière Server / X-Powered-By
        if matches!(port, 80 | 3000 | 3030 | 5000 | 8000 | 8080 | 9200) {
            let probe = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: AetherScope-ServiceScanner/2.0\r\nConnection: close\r\n\r\n",
                host
            );
            let _ = timeout(Duration::from_millis(250), stream.write_all(probe.as_bytes())).await;
        } else if port == 6379 {
            let _ = timeout(Duration::from_millis(200), stream.write_all(b"PING\r\n")).await;
        }

        let mut buf = vec![0u8; 512];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(280), stream.read(&mut buf)).await {
            if n > 0 {
                let text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).to_string();
                let mut first_line = text.lines().next().unwrap_or("").trim().to_string();
                for line in text.lines() {
                    let lower = line.to_lowercase();
                    if lower.starts_with("server:") || lower.starts_with("x-powered-by:") {
                        let val = line.get(line.find(':').map(|i| i + 1).unwrap_or(0)..).unwrap_or("").trim();
                        if !val.is_empty() {
                            first_line = format!("{} | {}", first_line, val);
                            if detected_version.is_none() {
                                detected_version = Some(val.to_string());
                            }
                        }
                    }
                }
                if detected_version.is_none() {
                    detected_version = extract_version_token(&first_line);
                }
                if !first_line.is_empty() {
                    banner = Some(first_line.chars().take(90).collect());
                }
            }
        }
    }

    PortProbeResult {
        port,
        service: service.to_string(),
        protocol: proto.to_string(),
        open: true,
        latency_ms,
        risk_level: risk.to_string(),
        banner,
        detected_version,
    }
}

async fn send_http_probe(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    method: &str,
) -> Option<(String, HashMap<String, String>, String)> {
    // Si HTTPS (ou port 443/8443), utiliser curl en mode passif sécurisé pour gérer le handshake TLS
    if scheme == "https" || port == 443 || port == 8443 {
        let url = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
            format!("{}://{}{}", scheme, host, path)
        } else {
            format!("{}://{}:{}{}", scheme, host, port, path)
        };
        let mut cmd = tokio::process::Command::new("curl");
        cmd.args([
            "-sSi",
            "-k",
            "-m",
            "4",
            "-X",
            method,
            "-H",
            "User-Agent: AetherScope-SurfaceAuditor/2.0 (Defensive Posture Check)",
            "-H",
            "Origin: https://scanner-probe.aetherscope.local",
            "--",
            &url,
        ]);
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        if let Ok(Ok(out)) = timeout(Duration::from_millis(4200), cmd.output()).await {
            if !out.stdout.is_empty() {
                let raw_resp = String::from_utf8_lossy(&out.stdout).to_string();
                return parse_raw_http_response(&raw_resp);
            }
        }
    }

    // Sonde TCP HTTP/1.1 native ultra-rapide
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(Duration::from_millis(1100), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    let req_str = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: AetherScope-SurfaceAuditor/2.0 (Defensive Posture Check)\r\nOrigin: https://scanner-probe.aetherscope.local\r\nAccept: text/html,application/xhtml+xml,application/json,*/*\r\nConnection: close\r\n\r\n",
        method, path, host
    );

    timeout(Duration::from_millis(700), stream.write_all(req_str.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut full_buf = Vec::with_capacity(32768);
    let mut chunk = [0u8; 4096];
    let read_start = Instant::now();
    while full_buf.len() < 65536 && read_start.elapsed() < Duration::from_millis(1400) {
        match timeout(Duration::from_millis(450), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if let Some(slice) = chunk.get(..n) {
                    full_buf.extend_from_slice(slice);
                }
            }
            _ => break,
        }
    }

    if full_buf.is_empty() {
        return None;
    }

    let raw_resp = String::from_utf8_lossy(&full_buf).to_string();
    parse_raw_http_response(&raw_resp)
}

fn parse_raw_http_response(raw_resp: &str) -> Option<(String, HashMap<String, String>, String)> {
    let (header_block, body_block) = match raw_resp.find("\r\n\r\n") {
        Some(idx) => (
            raw_resp.get(..idx).unwrap_or(raw_resp),
            raw_resp.get(idx + 4..).unwrap_or(""),
        ),
        None => match raw_resp.find("\n\n") {
            Some(idx) => (
                raw_resp.get(..idx).unwrap_or(raw_resp),
                raw_resp.get(idx + 2..).unwrap_or(""),
            ),
            None => (raw_resp, ""),
        },
    };

    let mut lines = header_block.lines();
    let status_line = lines.next().unwrap_or("").trim().to_string();
    if !status_line.starts_with("HTTP/") {
        return None;
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let k = line.get(..colon).unwrap_or("").trim().to_lowercase();
            let v = line.get(colon + 1..).unwrap_or("").trim().to_string();
            if !k.is_empty() {
                headers
                    .entry(k)
                    .and_modify(|existing: &mut String| {
                        existing.push_str(" ; ");
                        existing.push_str(&v);
                    })
                    .or_insert(v);
            }
        }
    }

    Some((status_line, headers, body_block.to_string()))
}

fn extract_attr(tag_html: &str, attr_name: &str) -> Option<String> {
    let lower = tag_html.to_lowercase();
    for pat in [format!("{}=\"", attr_name), format!("{}='", attr_name)] {
        if let Some(start_idx) = lower.find(&pat) {
            let quote_char = pat.chars().last().unwrap_or('"');
            let val_start = start_idx + pat.len();
            if let Some(after) = tag_html.get(val_start..) {
                if let Some(end_idx) = after.find(quote_char) {
                    return Some(after.get(..end_idx).unwrap_or("").trim().to_string());
                }
            }
        }
    }
    None
}

fn fingerprint_technologies(
    headers: &HashMap<String, String>,
    body: &str,
    open_ports: &[PortProbeResult],
) -> Vec<TechFingerprint> {
    let mut stack = Vec::new();
    let mut seen = Vec::new();

    let mut push_tech = |name: &str, cat: &str, ver: Option<String>, src: &str, conf: &str| {
        let key = format!("{}:{}", cat, name.to_lowercase());
        if !seen.contains(&key) {
            seen.push(key);
            stack.push(TechFingerprint {
                name: name.to_string(),
                category: cat.to_string(),
                version: ver,
                source: src.to_string(),
                confidence: conf.to_string(),
            });
        }
    };

    if let Some(srv) = headers.get("server") {
        let ver = extract_version_token(srv).or_else(|| Some(srv.clone()));
        push_tech(srv, "Serveur Web", ver, "Header HTTP Server", "Haute (100%)");
    }
    if let Some(xpb) = headers.get("x-powered-by") {
        let ver = extract_version_token(xpb).or_else(|| Some(xpb.clone()));
        push_tech(xpb, "Framework / Runtime", ver, "Header X-Powered-By", "Haute (100%)");
    }
    if headers.contains_key("cf-ray") || headers.get("server").map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false) {
        push_tech("Cloudflare CDN / WAF", "CDN / Reverse-Proxy", None, "Header CF-Ray / Server", "Haute (100%)");
    }
    if headers.contains_key("x-vercel-id") {
        push_tech("Vercel Edge Network", "CDN / Reverse-Proxy", None, "Header X-Vercel-Id", "Haute (100%)");
    }
    if let Some(via) = headers.get("via") {
        push_tech(via, "CDN / Reverse-Proxy", extract_version_token(via), "Header Via", "Haute (95%)");
    }

    if let Some(cookies) = headers.get("set-cookie") {
        let cl = cookies.to_lowercase();
        if cl.contains("phpsessid") {
            push_tech("PHP Runtime", "Framework / Runtime", None, "Cookie PHPSESSID", "Haute (95%)");
        }
        if cl.contains("laravel_session") || cl.contains("xsrf-token") {
            push_tech("Laravel (PHP)", "Framework / Runtime", None, "Cookie laravel_session", "Haute (95%)");
        }
        if cl.contains("connect.sid") {
            push_tech("Node.js Express (express-session)", "Framework / Runtime", None, "Cookie connect.sid", "Haute (95%)");
        }
        if cl.contains("jsessionid") {
            push_tech("Java Servlet / Spring / Tomcat", "Framework / Runtime", None, "Cookie JSESSIONID", "Haute (95%)");
        }
        if cl.contains("csrftoken") || cl.contains("sessionid") {
            push_tech("Python Django", "Framework / Runtime", None, "Cookie csrftoken/sessionid", "Moyenne (85%)");
        }
    }

    let body_lower = body.to_lowercase();
    if body_lower.contains("aetherscope") || body_lower.contains("__aetherscope_data__") {
        push_tech("AetherScope V2 (Rust Axum + WebGL 2)", "Framework / Runtime", Some("v2.0.8".to_string()), "Signature DOM & API", "Haute (100%)");
    }
    if body_lower.contains("/_next/static") || body_lower.contains("__next_data__") {
        push_tech("Next.js (React SSR)", "Frontend JS", None, "Empreinte DOM /_next/", "Haute (100%)");
    }
    if body_lower.contains("data-v-") || body_lower.contains("__vue__") {
        push_tech("Vue.js / Nuxt", "Frontend JS", None, "Attributs DOM data-v-*", "Haute (90%)");
    }
    if body_lower.contains("ng-version=") {
        let ver = extract_attr(body, "ng-version");
        push_tech("Angular", "Frontend JS", ver, "Attribut DOM ng-version", "Haute (100%)");
    }
    if body_lower.contains("wp-content/") || body_lower.contains("wp-includes/") {
        push_tech("WordPress CMS (PHP)", "Framework / Runtime", None, "Chemins /wp-content/", "Haute (100%)");
    }

    for p in open_ports {
        if p.open {
            if let Some(ref ver) = p.detected_version {
                push_tech(&p.service, "Service Réseau TCP", Some(ver.clone()), &format!("Port TCP :{}", p.port), "Haute (95%)");
            }
        }
    }

    stack
}

fn parse_html_architecture_and_forms(
    body: &str,
    headers: &HashMap<String, String>,
    scheme: &str,
    is_loopback: bool,
    robots_entries: Vec<String>,
    security_txt_present: bool,
) -> (WebArchitectureDiscovery, Vec<SurfaceFinding>) {
    let mut findings = Vec::new();
    let lower_body = body.to_lowercase();

    // 1. Titre de la page
    let page_title = if let (Some(s), Some(e)) = (lower_body.find("<title>"), lower_body.find("</title>")) {
        if s + 7 <= e {
            body.get(s + 7..e).map(|t| t.trim().to_string())
        } else {
            None
        }
    } else {
        None
    };

    // 2. Meta generator
    let mut meta_generator = None;
    let mut search_pos = 0usize;
    while let Some(rel) = lower_body.get(search_pos..).and_then(|s| s.find("<meta ")) {
        let abs = search_pos + rel;
        if let Some(end_rel) = lower_body.get(abs..).and_then(|s| s.find('>')) {
            let tag = body.get(abs..=abs + end_rel).unwrap_or("");
            if extract_attr(tag, "name").map(|n| n.to_lowercase() == "generator").unwrap_or(false) {
                meta_generator = extract_attr(tag, "content");
            }
            search_pos = abs + end_rel + 1;
        } else {
            break;
        }
    }

    // 3. Extraction des Formulaires <form>...</form> et de tous les champs (<input>, <textarea>, <select>)
    let mut forms = Vec::new();
    let mut routes = Vec::new();
    let mut form_pos = 0usize;
    let mut form_idx = 1usize;

    while let Some(f_rel) = lower_body.get(form_pos..).and_then(|s| s.find("<form")) {
        let f_start = form_pos + f_rel;
        let tag_end = match lower_body.get(f_start..).and_then(|s| s.find('>')) {
            Some(te) => f_start + te,
            None => break,
        };
        let form_open_tag = body.get(f_start..=tag_end).unwrap_or("");
        let f_close = lower_body
            .get(tag_end + 1..)
            .and_then(|s| s.find("</form>"))
            .map(|c| tag_end + 1 + c)
            .unwrap_or_else(|| body.len().min(tag_end + 4000));

        let form_inner = body.get(tag_end + 1..f_close).unwrap_or("");
        let form_inner_lower = form_inner.to_lowercase();

        let id_or_name = extract_attr(form_open_tag, "id")
            .or_else(|| extract_attr(form_open_tag, "name"))
            .unwrap_or_else(|| format!("form_{}", form_idx));
        let method = extract_attr(form_open_tag, "method")
            .unwrap_or_else(|| "GET".to_string())
            .to_uppercase();
        let action = extract_attr(form_open_tag, "action").unwrap_or_else(|| "/".to_string());
        let enctype = extract_attr(form_open_tag, "enctype");

        let mut inputs = Vec::new();
        let mut has_csrf_token = false;
        let mut has_password_field = false;
        let mut has_file_upload = false;

        // Parcourir les balises <input, <textarea, <select dans le corps du formulaire
        for (tag_prefix, tag_label) in [("<input", "input"), ("<textarea", "textarea"), ("<select", "select")] {
            let mut ipos = 0usize;
            while let Some(irel) = form_inner_lower.get(ipos..).and_then(|s| s.find(tag_prefix)) {
                let istart = ipos + irel;
                if let Some(iend_rel) = form_inner_lower.get(istart..).and_then(|s| s.find('>')) {
                    let itag = form_inner.get(istart..=istart + iend_rel).unwrap_or("");
                    let iname = extract_attr(itag, "name")
                        .or_else(|| extract_attr(itag, "id"))
                        .or_else(|| extract_attr(itag, "placeholder"))
                        .unwrap_or_else(|| "unnamed_field".to_string());
                    let itype = extract_attr(itag, "type")
                        .unwrap_or_else(|| tag_label.to_string())
                        .to_lowercase();
                    let required = itag.to_lowercase().contains("required");

                    let name_low = iname.to_lowercase();
                    let is_csrf = name_low.contains("csrf")
                        || name_low.contains("_token")
                        || name_low.contains("xsrf")
                        || name_low.contains("authenticity_token")
                        || name_low.contains("nonce");
                    if is_csrf {
                        has_csrf_token = true;
                    }
                    if itype == "password" || name_low.contains("pass") || name_low.contains("pwd") {
                        has_password_field = true;
                    }
                    if itype == "file" {
                        has_file_upload = true;
                    }

                    let classification = if is_csrf {
                        "🛡️ Jeton Anti-CSRF"
                    } else if itype == "password" || name_low.contains("pass") || name_low.contains("secret") || name_low.contains("token") {
                        "🔑 Secret / Authentification"
                    } else if itype == "file" {
                        "📂 Upload de Fichier"
                    } else if itype == "email" || name_low.contains("user") || name_low.contains("login") {
                        "👤 Identifiant / Email"
                    } else if itype == "hidden" {
                        "🔒 Paramètre Caché (Hidden)"
                    } else {
                        "📝 Entrée Utilisateur"
                    }
                    .to_string();

                    inputs.push(DiscoveredInput {
                        name: iname,
                        input_type: itype,
                        tag: tag_label.to_string(),
                        required,
                        classification,
                    });

                    ipos = istart + iend_rel + 1;
                } else {
                    break;
                }
            }
        }

        let mut security_notes = Vec::new();
        let mut posture = "PASS".to_string();

        if method == "POST" && !has_csrf_token {
            posture = "WARN".to_string();
            security_notes.push("Absence de champ anti-CSRF détecté dans le formulaire POST (CWE-352).".to_string());
            findings.push(SurfaceFinding {
                id: format!("SURFACE-FORM-MISSING-CSRF-{}", form_idx),
                cwe: "CWE-352 / FORM-MISSING-CSRF-TOKEN".to_string(),
                severity: "MEDIUM".to_string(),
                category: "Architecture Web & Formulaires".to_string(),
                title: format!("Formulaire POST `{}` (`{}`) sans jeton anti-CSRF apparent", id_or_name, action),
                description: format!(
                    "Le formulaire `{}` soumet {} champ(s) en POST vers `{}` sans champ CSRF (`_token`, `csrf_token`). S'il s'appuie sur des cookies de session sans SameSite=Strict, il est exposé au CSRF.",
                    id_or_name, inputs.len(), action
                ),
                remediation: "Injecter un jeton anti-CSRF aléatoire par session ou imposer l'authentification par en-tête Authorization / SameSite=Strict.".to_string(),
            });
        }

        if has_password_field && method == "GET" {
            posture = "CRITICAL".to_string();
            security_notes.push("CRITIQUE : Champ mot de passe transmis via méthode GET (exposé dans l'URL et les logs) !".to_string());
            findings.push(SurfaceFinding {
                id: format!("SURFACE-FORM-PASSWORD-IN-GET-{}", form_idx),
                cwe: "CWE-598 / PASSWORD-TRANSMITTED-IN-GET-QUERY".to_string(),
                severity: "HIGH".to_string(),
                category: "Architecture Web & Formulaires".to_string(),
                title: format!("Formulaire `{}` transmettant un mot de passe via GET", id_or_name),
                description: "Un champ de type `password` est envoyé avec `method=\"GET\"`, exposant le secret en clair dans la barre d'adresse, l'historique navigateur et les journaux d'accès HTTP.".to_string(),
                remediation: "Forcer `method=\"POST\"` sur tout formulaire contenant des identifiants ou secrets.".to_string(),
            });
        }

        if has_password_field && scheme == "http" && !is_loopback {
            posture = "CRITICAL".to_string();
            security_notes.push("CRITIQUE : Formulaire d'authentification servi sur HTTP non chiffré.".to_string());
            findings.push(SurfaceFinding {
                id: format!("SURFACE-FORM-CLEARTEXT-AUTH-{}", form_idx),
                cwe: "CWE-319 / CLEARTEXT-TRANSMISSION-OF-CREDENTIALS".to_string(),
                severity: "CRITICAL".to_string(),
                category: "Architecture Web & Formulaires".to_string(),
                title: format!("Formulaire avec mot de passe (`{}`) servi en HTTP non chiffré", id_or_name),
                description: "Les identifiants saisis dans ce formulaire sont transmis sans chiffrement TLS sur le réseau.".to_string(),
                remediation: "Forcer la redirection HTTPS (301) et activer HSTS avant d'afficher tout formulaire d'authentification.".to_string(),
            });
        }

        if has_file_upload {
            security_notes.push("Surface d'Upload de Fichier détectée : vérifier le filtrage MIME, l'absence de wrapper phar:// et le stockage hors webroot (CWE-434).".to_string());
        }

        routes.push(DiscoveredRoute {
            path: action.clone(),
            method: method.clone(),
            source: format!("Form Action «{}»", id_or_name),
            status: None,
        });

        forms.push(DiscoveredForm {
            index: form_idx,
            id_or_name,
            method,
            action,
            enctype,
            has_csrf_token,
            has_password_field,
            has_file_upload,
            inputs,
            security_posture: posture,
            security_notes,
        });

        form_idx += 1;
        form_pos = f_close + 1;
    }

    // 4. Découverte des Inputs autonomes (SPA / WebGL / React sans balise <form> englobante)
    if forms.is_empty() && lower_body.contains("<input") {
        let mut spa_inputs = Vec::new();
        let mut ipos = 0usize;
        while let Some(irel) = lower_body.get(ipos..).and_then(|s| s.find("<input")) {
            let istart = ipos + irel;
            if let Some(iend_rel) = lower_body.get(istart..).and_then(|s| s.find('>')) {
                let itag = body.get(istart..=istart + iend_rel).unwrap_or("");
                let iname = extract_attr(itag, "id")
                    .or_else(|| extract_attr(itag, "name"))
                    .or_else(|| extract_attr(itag, "placeholder"))
                    .unwrap_or_else(|| "spa_input".to_string());
                let itype = extract_attr(itag, "type").unwrap_or_else(|| "text".to_string());
                if spa_inputs.len() < 25 {
                    spa_inputs.push(DiscoveredInput {
                        name: iname,
                        input_type: itype.clone(),
                        tag: "input (SPA)".to_string(),
                        required: false,
                        classification: if itype == "checkbox" {
                            "🎛️ Toggle / Option UI".to_string()
                        } else {
                            "⚡ Champ SPA / API".to_string()
                        },
                    });
                }
                ipos = istart + iend_rel + 1;
            } else {
                break;
            }
        }
        if !spa_inputs.is_empty() {
            forms.push(DiscoveredForm {
                index: 1,
                id_or_name: "Interface SPA / Contrôles Dynamiques (fetch/XHR)".to_string(),
                method: "POST / FETCH".to_string(),
                action: "/api/*".to_string(),
                enctype: Some("application/json".to_string()),
                has_csrf_token: true,
                has_password_field: false,
                has_file_upload: false,
                inputs: spa_inputs,
                security_posture: "PASS".to_string(),
                security_notes: vec!["Application SPA : les entrées sont transmises en JSON via fetch() vers les routes /api/*.".to_string()],
            });
        }
    }

    // 5. Extraction des liens <a href="...">, <script src="..."> et routes fetch('/api/...')
    let mut external_scripts = Vec::new();
    let mut spos = 0usize;
    while let Some(srel) = lower_body.get(spos..).and_then(|s| s.find("<script")) {
        let sstart = spos + srel;
        if let Some(send_rel) = lower_body.get(sstart..).and_then(|s| s.find('>')) {
            let stag = body.get(sstart..=sstart + send_rel).unwrap_or("");
            if let Some(src) = extract_attr(stag, "src") {
                if !external_scripts.contains(&src) && external_scripts.len() < 20 {
                    external_scripts.push(src.clone());
                }
                if src.starts_with("http://") || src.starts_with("https://") {
                    let has_sri = extract_attr(stag, "integrity").is_some();
                    if !has_sri {
                        findings.push(SurfaceFinding {
                            id: "SURFACE-EXTERNAL-SCRIPT-NO-SRI".to_string(),
                            cwe: "CWE-353 / MISSING-SUBRESOURCE-INTEGRITY".to_string(),
                            severity: "MEDIUM".to_string(),
                            category: "Architecture Web & Formulaires".to_string(),
                            title: format!("Script tiers chargé sans hachage d'intégrité SRI (`{}`)", src),
                            description: "Une balise `<script src=\"...\">` charge du code externe sans attribut `integrity=\"sha384-...\"` (Subresource Integrity).".to_string(),
                            remediation: "Ajouter les attributs `integrity=\"sha384-...\"` et `crossorigin=\"anonymous\"` sur tous les scripts CDN tiers.".to_string(),
                        });
                    }
                }
            }
            spos = sstart + send_rel + 1;
        } else {
            break;
        }
    }

    // Extraction des liens <a href="...">
    let mut apos = 0usize;
    while let Some(arel) = lower_body.get(apos..).and_then(|s| s.find("<a ")) {
        let astart = apos + arel;
        if let Some(aend_rel) = lower_body.get(astart..).and_then(|s| s.find('>')) {
            let atag = body.get(astart..=astart + aend_rel).unwrap_or("");
            if let Some(href) = extract_attr(atag, "href") {
                if (href.starts_with('/') || href.starts_with("http")) && !href.starts_with("//") && routes.len() < 30 {
                    if !routes.iter().any(|r| r.path == href) {
                        routes.push(DiscoveredRoute {
                            path: href,
                            method: "GET".to_string(),
                            source: "HTML <a href>".to_string(),
                            status: None,
                        });
                    }
                }
            }
            apos = astart + aend_rel + 1;
        } else {
            break;
        }
    }

    // Extraction des routes /api/... mentionnées dans le HTML/JS
    for token in body.split(['\'', '"', '`']) {
        let t = token.trim();
        if (t.starts_with("/api/") || t.starts_with("/v1/") || t.starts_with("/graphql") || t.starts_with("/auth/"))
            && t.len() < 64
            && !t.contains(' ')
            && routes.len() < 35
        {
            if !routes.iter().any(|r| r.path == t) {
                routes.push(DiscoveredRoute {
                    path: t.to_string(),
                    method: "API / RPC".to_string(),
                    source: "Référence API / Fetch".to_string(),
                    status: None,
                });
            }
        }
    }

    for rob in &robots_entries {
        if routes.len() < 40 && !routes.iter().any(|r| &r.path == rob) {
            routes.push(DiscoveredRoute {
                path: rob.clone(),
                method: "GET".to_string(),
                source: "robots.txt".to_string(),
                status: None,
            });
        }
    }

    let content_type = headers.get("content-type").cloned();
    let is_web_arch = content_type
        .as_ref()
        .map(|c| c.contains("html") || c.contains("json") || c.contains("xml"))
        .unwrap_or(false)
        || lower_body.contains("<html")
        || lower_body.contains("<!doctype")
        || !forms.is_empty();

    (
        WebArchitectureDiscovery {
            is_web_arch,
            page_title,
            meta_generator,
            content_type,
            body_size_bytes: body.len(),
            forms,
            routes,
            external_scripts,
            robots_entries,
            security_txt_present,
            web_files: Vec::new(),
            directories: Vec::new(),
        },
        findings,
    )
}

fn extract_calls_from_asset(content: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut folders = Vec::new();
    let mut refs = Vec::new();
    let mut json_keys = Vec::new();

    for token in content.split(['\'', '"', '`', '(', ')']) {
        let t = token.trim();
        if t.len() < 2 || t.len() > 96 || t.contains(' ') || t.contains('\n') || t.contains('<') || t.contains('>') {
            continue;
        }
        // Détection de fichiers (.html, .js, .css, .json, .php, .wasm) ou endpoints (/api/..., /v1/..., /auth/...)
        let is_file_ext = t.ends_with(".html")
            || t.ends_with(".htm")
            || t.ends_with(".js")
            || t.ends_with(".mjs")
            || t.ends_with(".css")
            || t.ends_with(".json")
            || t.ends_with(".php")
            || t.ends_with(".wasm");
        let is_route_prefix = t.starts_with("/api/")
            || t.starts_with("/v1/")
            || t.starts_with("/v2/")
            || t.starts_with("/graphql")
            || t.starts_with("/auth/")
            || t.starts_with("/admin")
            || t.starts_with("/assets/")
            || t.starts_with("/static/")
            || t.starts_with("/public/")
            || t.starts_with("/uploads/");

        if (is_file_ext || is_route_prefix) && !t.starts_with("http://") && !t.starts_with("https://") && !t.starts_with("//") {
            let norm = if t.starts_with('/') {
                t.to_string()
            } else if let Some(stripped) = t.strip_prefix("./") {
                format!("/{}", stripped)
            } else {
                format!("/{}", t)
            };
            if refs.len() < 18 && !refs.contains(&norm) {
                refs.push(norm.clone());
            }
            // Extraire le dossier parent s'il existe (ex: "/api/scan" -> "/api/", "/assets/js/app.js" -> "/assets/js/")
            if let Some(last_slash) = norm.rfind('/') {
                if last_slash > 0 {
                    if let Some(dir_slice) = norm.get(..=last_slash) {
                        let dir_str = dir_slice.to_string();
                        if folders.len() < 14 && !folders.contains(&dir_str) {
                            folders.push(dir_str);
                        }
                    }
                }
            }
        }
    }

    // Extraire les clés de payload JSON autour de JSON.stringify({ ... }) dans les fichiers JS
    let mut search_pos = 0usize;
    while let Some(rel) = content.get(search_pos..).and_then(|s| s.find("JSON.stringify(")) {
        let abs = search_pos + rel + 15;
        if let Some(window) = content.get(abs..content.len().min(abs + 260)) {
            if let Some(end_brace) = window.find('}') {
                let block = window.get(..=end_brace).unwrap_or("");
                for part in block.split([',', '{', '}']) {
                    let p = part.trim();
                    let key_cand = match p.find(':') {
                        Some(col) => p.get(..col).unwrap_or("").trim().trim_matches(['"', '\'']),
                        None => p,
                    };
                    if key_cand.len() >= 2
                        && key_cand.len() <= 32
                        && key_cand.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && !json_keys.iter().any(|k| k == key_cand)
                        && json_keys.len() < 12
                    {
                        json_keys.push(key_cand.to_string());
                    }
                }
            }
        }
        search_pos = abs + 1;
    }

    (folders, refs, json_keys)
}

fn classify_directory(dir: &str) -> &'static str {
    let dl = dir.to_lowercase();
    if dl.contains("/api") || dl.contains("/v1") || dl.contains("/v2") || dl.contains("/graphql") || dl.contains("/rpc") {
        "⚡ API & Endpoints Backend"
    } else if dl.contains("/admin") || dl.contains("/internal") || dl.contains("/config") || dl.contains("/debug") || dl.contains("/.well-known") {
        "🔐 Administration & Gouvernance"
    } else if dl.contains("/upload") || dl.contains("/media") || dl.contains("/files") || dl.contains("/storage") {
        "📂 Stockage & Uploads"
    } else if dl.contains("/asset") || dl.contains("/static") || dl.contains("/js") || dl.contains("/css") || dl.contains("/dist") || dl.contains("/public") {
        "📦 Assets & Bundles Frontend"
    } else {
        "📁 Répertoire Application"
    }
}

async fn inspect_web_files_and_directories(
    scheme: &str,
    host: &str,
    port: u16,
    entry_path: &str,
    entry_body: &str,
    disc: &mut WebArchitectureDiscovery,
    findings: &mut Vec<SurfaceFinding>,
) {
    let mut web_files = Vec::new();
    let mut dir_map: HashMap<String, (Vec<String>, usize)> = HashMap::new();

    let mut record_dir = |folder: &str, src_file: &str| {
        let entry = dir_map.entry(folder.to_string()).or_insert_with(|| (Vec::new(), 0));
        entry.1 = entry.1.saturating_add(1);
        if !entry.0.iter().any(|s| s == src_file) && entry.0.len() < 8 {
            entry.0.push(src_file.to_string());
        }
    };

    // 1. Analyser le fichier d'entrée HTML lui-même
    let entry_label = if entry_path == "/" { "/index.html (Entrée)" } else { entry_path };
    let (entry_folders, entry_refs, entry_json_keys) = extract_calls_from_asset(entry_body);
    for f in &entry_folders {
        record_dir(f, entry_label);
    }

    // Extraire aussi les feuilles CSS <link href="..."> du HTML
    let lower_html = entry_body.to_lowercase();
    let mut candidate_local_files: Vec<(String, String)> = Vec::new();

    for sc in &disc.external_scripts {
        if !sc.starts_with("http://") && !sc.starts_with("https://") && !sc.starts_with("//") {
            let norm = if sc.starts_with('/') { sc.clone() } else { format!("/{}", sc.trim_start_matches("./")) };
            if candidate_local_files.len() < 6 && !candidate_local_files.iter().any(|(p, _)| p == &norm) {
                candidate_local_files.push((norm, "JS".to_string()));
            }
        }
    }

    let mut lpos = 0usize;
    while let Some(lrel) = lower_html.get(lpos..).and_then(|s| s.find("<link")) {
        let lstart = lpos + lrel;
        if let Some(lend_rel) = lower_html.get(lstart..).and_then(|s| s.find('>')) {
            let ltag = entry_body.get(lstart..=lstart + lend_rel).unwrap_or("");
            if let Some(href) = extract_attr(ltag, "href") {
                if !href.starts_with("http://") && !href.starts_with("https://") && !href.starts_with("//") {
                    let norm = if href.starts_with('/') { href } else { format!("/{}", href.trim_start_matches("./")) };
                    let ftype = if norm.ends_with(".css") {
                        "CSS"
                    } else if norm.ends_with(".json") || norm.ends_with(".webmanifest") {
                        "JSON"
                    } else {
                        "ASSET"
                    };
                    if (ftype == "CSS" || ftype == "JSON")
                        && candidate_local_files.len() < 7
                        && !candidate_local_files.iter().any(|(p, _)| p == &norm)
                    {
                        candidate_local_files.push((norm, ftype.to_string()));
                    }
                }
            }
            lpos = lstart + lend_rel + 1;
        } else {
            break;
        }
    }

    for r in &disc.routes {
        if (r.path.ends_with(".html") || r.path.ends_with(".htm") || r.path.ends_with(".json"))
            && !r.path.starts_with("http")
            && candidate_local_files.len() < 8
            && !candidate_local_files.iter().any(|(p, _)| p == &r.path)
        {
            let ftype = if r.path.ends_with(".json") { "JSON" } else { "HTML" };
            candidate_local_files.push((r.path.clone(), ftype.to_string()));
        }
        if let Some(last_slash) = r.path.rfind('/') {
            if last_slash > 0 {
                if let Some(dir_slice) = r.path.get(..=last_slash) {
                    record_dir(dir_slice, &r.source);
                }
            }
        }
    }

    web_files.push(DiscoveredWebFile {
        path: entry_label.to_string(),
        file_type: "HTML".to_string(),
        http_status: "200 OK".to_string(),
        size_bytes: entry_body.len(),
        folder_calls: entry_folders,
        api_and_asset_refs: entry_refs,
        json_payload_keys: entry_json_keys,
        has_sourcemap: false,
    });

    // 2. Inspecter chaque fichier local découvert (.js, .css, .html, .json) pour extraire ses appels d'API et de dossiers
    for (file_path, file_type) in candidate_local_files.into_iter().take(6) {
        if let Some((st_line, _fhdrs, fbody)) = send_http_probe(scheme, host, port, &file_path, "GET").await {
            let is_200 = st_line.contains(" 200 ");
            let (ffolders, frefs, fjson_keys) = if is_200 {
                extract_calls_from_asset(&fbody)
            } else {
                (Vec::new(), Vec::new(), Vec::new())
            };

            if let Some(last_slash) = file_path.rfind('/') {
                if last_slash > 0 {
                    if let Some(dir_slice) = file_path.get(..=last_slash) {
                        record_dir(dir_slice, &file_path);
                    }
                }
            }

            for ff in &ffolders {
                record_dir(ff, &file_path);
            }

            // Ajouter les endpoints /api/* découverts dans le fichier JS/HTML à la carte des routes
            for rf in &frefs {
                if (rf.starts_with("/api/") || rf.starts_with("/v1/") || rf.starts_with("/graphql") || rf.starts_with("/auth/"))
                    && disc.routes.len() < 45
                    && !disc.routes.iter().any(|r| &r.path == rf)
                {
                    disc.routes.push(DiscoveredRoute {
                        path: rf.clone(),
                        method: "API / FETCH".to_string(),
                        source: format!("Fichier {} ({})", file_type, file_path),
                        status: None,
                    });
                }
            }

            let has_sourcemap = fbody.contains("sourceMappingURL=");
            if has_sourcemap && file_type == "JS" {
                findings.push(SurfaceFinding {
                    id: format!("SURFACE-JS-SOURCEMAP-{}", file_path.replace(['/', '.'], "").to_uppercase()),
                    cwe: "CWE-540 / SOURCEMAP-EXPOSURE".to_string(),
                    severity: "LOW".to_string(),
                    category: "Architecture Fichiers (.html / .js)".to_string(),
                    title: format!("Directive SourceMap détectée dans `{}`", file_path),
                    description: format!(
                        "Le script `{}` référence une SourceMap (`//# sourceMappingURL=`). En production, cela permet de reconstruire l'arborescence source originale.",
                        file_path
                    ),
                    remediation: "Désactiver la génération ou restreindre l'accès aux fichiers `.js.map` en production.".to_string(),
                });
            }

            web_files.push(DiscoveredWebFile {
                path: file_path,
                file_type,
                http_status: st_line,
                size_bytes: fbody.len(),
                folder_calls: ffolders,
                api_and_asset_refs: frefs,
                json_payload_keys: fjson_keys,
                has_sourcemap,
            });
        }
    }

    for rob in &disc.robots_entries {
        if let Some(last_slash) = rob.rfind('/') {
            if last_slash > 0 {
                if let Some(dir_slice) = rob.get(..=last_slash) {
                    record_dir(dir_slice, "robots.txt");
                }
            } else if rob.starts_with('/') && rob.len() > 1 {
                let as_dir = format!("{}/", rob);
                record_dir(&as_dir, "robots.txt");
            }
        }
    }

    let mut directories: Vec<DiscoveredDirectory> = dir_map
        .into_iter()
        .map(|(folder_path, (source_files, call_count))| {
            let classification = classify_directory(&folder_path).to_string();
            DiscoveredDirectory {
                folder_path,
                source_files,
                call_count,
                classification,
            }
        })
        .collect();
    directories.sort_by(|a, b| b.call_count.cmp(&a.call_count).then_with(|| a.folder_path.cmp(&b.folder_path)));

    disc.web_files = web_files;
    disc.directories = directories;
}

async fn probe_sensitive_artifacts(
    scheme: &str,
    host: &str,
    port: u16,
) -> (Vec<ExposedArtifactProbe>, Vec<SurfaceFinding>) {
    let mut results = Vec::new();
    let mut findings = Vec::new();

    // Liste défensive d'artefacts sensibles de racine Web (CWE-538 / CWE-215)
    let candidates: [(&str, &str, &str, &str, &str); 8] = [
        (
            "/.env",
            "Fichier d'environnement (.env)",
            "Configuration & Secrets",
            "CRITICAL",
            "Bloquer l'accès aux dotfiles (`location ~ /\\. { deny all; }`) et déplacer `.env` hors du document root.",
        ),
        (
            "/.env.local",
            "Environnement local (.env.local)",
            "Configuration & Secrets",
            "CRITICAL",
            "Retirer `.env.local` du répertoire public et révoquer tout jeton potentiellement exposé.",
        ),
        (
            "/.git/HEAD",
            "Index Git exposé (.git/HEAD)",
            "Dépôt VCS Exposé",
            "CRITICAL",
            "Supprimer le dossier `.git` des artefacts de déploiement ou interdire `/.git` au niveau du reverse-proxy.",
        ),
        (
            "/docker-compose.yml",
            "Manifeste Docker Compose",
            "Infrastructure & Conteneurs",
            "HIGH",
            "Ne jamais servir les fichiers d'orchestration YAML dans le répertoire statique.",
        ),
        (
            "/actuator/health",
            "Spring Boot Actuator",
            "Télémétrie & Debug",
            "MEDIUM",
            "Isoler les endpoints `/actuator/*` sur un port d'administration interne.",
        ),
        (
            "/server-status",
            "Apache mod_status",
            "Télémétrie & Debug",
            "HIGH",
            "Restreindre `/server-status` à `127.0.0.1` via `Require local`.",
        ),
        (
            "/openapi.json",
            "Spécification OpenAPI (JSON)",
            "Documentation API",
            "INFO",
            "Vérifier que la publication du schéma OpenAPI est intentionnelle en production.",
        ),
        (
            "/swagger.json",
            "Spécification Swagger (JSON)",
            "Documentation API",
            "INFO",
            "Protéger Swagger UI / swagger.json par authentification si l'API est privée.",
        ),
    ];

    for (path, label, category, risk, remediation) in candidates {
        if let Some((status_line, hdrs, body)) = send_http_probe(scheme, host, port, path, "GET").await {
            let is_200 = status_line.contains(" 200 ");
            let lower_body = body.trim().to_lowercase();
            let content_type = hdrs.get("content-type").cloned().unwrap_or_default().to_lowercase();

            // Filtrage anti-Soft-404 (évite les faux positifs sur les SPA qui renvoient index.html en 200 OK)
            let is_html_fallback = lower_body.starts_with("<!doctype")
                || lower_body.starts_with("<html")
                || content_type.contains("text/html") && !path.contains("server-status");

            let mut confirmed_exposed = false;
            let mut redacted_preview = None;

            if is_200 && !is_html_fallback {
                if path.starts_with("/.env") {
                    // Vérifier la présence de paires KEY=VALUE et masquer strictement toutes les valeurs (aucune exfiltration)
                    let mut masked_keys = Vec::new();
                    for line in body.lines().take(25) {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        if let Some(eq_idx) = trimmed.find('=') {
                            let key = trimmed.get(..eq_idx).unwrap_or("").trim();
                            if !key.is_empty()
                                && key.len() <= 48
                                && key.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                            {
                                masked_keys.push(format!("{}=******** [MASQUÉ]", key));
                            }
                        }
                    }
                    if !masked_keys.is_empty() {
                        confirmed_exposed = true;
                        let preview_list = masked_keys.into_iter().take(5).collect::<Vec<_>>().join(", ");
                        redacted_preview = Some(format!(
                            "Clés détectées (valeurs strictement masquées) : {}",
                            preview_list
                        ));
                    }
                } else if path == "/.git/HEAD" {
                    if lower_body.starts_with("ref: refs/") || (body.trim().len() == 40 && body.trim().chars().all(|c| c.is_ascii_hexdigit())) {
                        confirmed_exposed = true;
                        let first_line = body.lines().next().unwrap_or("ref: refs/heads/*").trim();
                        redacted_preview = Some(format!(
                            "Signature Git HEAD confirmée : `{}` (Contenu du dépôt non téléchargé)",
                            first_line.chars().take(48).collect::<String>()
                        ));
                    }
                } else if path == "/docker-compose.yml" {
                    if lower_body.contains("services:") && (lower_body.contains("image:") || lower_body.contains("build:")) {
                        confirmed_exposed = true;
                        redacted_preview = Some("Structure YAML `services:` détectée (valeurs d'environnement masquées)".to_string());
                    }
                } else if path == "/actuator/health" {
                    if lower_body.contains("\"status\"") && (lower_body.contains("\"up\"") || lower_body.contains("\"down\"")) {
                        confirmed_exposed = true;
                        redacted_preview = Some("Réponse JSON Spring Actuator `{ \"status\": ... }` active".to_string());
                    }
                } else if path == "/server-status" {
                    if lower_body.contains("apache server status") || lower_body.contains("server version:") {
                        confirmed_exposed = true;
                        redacted_preview = Some("Page de télémétrie Apache `mod_status` accessible publiquement".to_string());
                    }
                } else if path == "/openapi.json" || path == "/swagger.json" {
                    if (lower_body.contains("\"openapi\"") || lower_body.contains("\"swagger\"")) && lower_body.contains("\"paths\"") {
                        confirmed_exposed = true;
                        redacted_preview = Some("Schéma JSON OpenAPI / Swagger public détecté".to_string());
                    }
                }
            }

            if confirmed_exposed && risk != "INFO" {
                findings.push(SurfaceFinding {
                    id: format!("SURFACE-EXPOSED-ARTIFACT-{}", path.replace(['/', '.'], "").to_uppercase()),
                    cwe: "CWE-538 / SENSITIVE-FILE-EXPOSURE".to_string(),
                    severity: risk.to_string(),
                    category: "Module 4 • Fichiers Sensibles (.env / .git)".to_string(),
                    title: format!("Exposition critique détectée sur `{}` ({})", path, label),
                    description: format!(
                        "L'endpoint `{}` est publiquement accessible ({}) et expose une signature structurelle valide ({}). Par sécurité, AetherScope masque automatiquement toutes les valeurs secrètes.",
                        path,
                        status_line,
                        redacted_preview.as_deref().unwrap_or("signature confirmée")
                    ),
                    remediation: remediation.to_string(),
                });
            }

            results.push(ExposedArtifactProbe {
                path: path.to_string(),
                label: label.to_string(),
                category: category.to_string(),
                exposed: confirmed_exposed,
                http_status: if confirmed_exposed {
                    format!("{} (EXPOSÉ)", status_line)
                } else if is_200 && is_html_fallback {
                    "200 Soft-404 (Protégé / Fallback SPA)".to_string()
                } else {
                    status_line
                },
                risk_level: risk.to_string(),
                redacted_preview,
                remediation: remediation.to_string(),
            });
        } else {
            results.push(ExposedArtifactProbe {
                path: path.to_string(),
                label: label.to_string(),
                category: category.to_string(),
                exposed: false,
                http_status: "Fermé / Non accessible".to_string(),
                risk_level: risk.to_string(),
                redacted_preview: None,
                remediation: remediation.to_string(),
            });
        }
    }

    (results, findings)
}

pub async fn run_surface_scan(req: SurfaceScanRequest) -> SurfaceScanResponse {
    let scan_start = Instant::now();
    let raw_target = req.target.trim().to_string();
    let (scheme, host, primary_port, path) = parse_target_input(&raw_target);

    let scan_level = req.scan_level.unwrap_or(4).clamp(1, 4);
    let check_dns = req.check_dns.unwrap_or(true);
    let check_ports = req.check_ports.unwrap_or(scan_level >= 2);
    let check_headers = req.check_headers.unwrap_or(true);
    let check_endpoints = req.check_endpoints.unwrap_or(scan_level >= 2);
    let check_web_forms = req.check_web_forms.unwrap_or(scan_level >= 3);
    let check_sensitive_files = req.check_sensitive_files.unwrap_or(scan_level >= 4);

    let mut findings = Vec::new();
    let mut resolved_ips = Vec::new();
    let mut target_classification = "Inconnu".to_string();

    // 1. Résolution DNS & Classification Réseau
    let dns_start = Instant::now();
    let mut is_loopback_or_private = false;
    let is_literal_ip = host.parse::<IpAddr>().is_ok();
    let lookup_target = format!("{}:{}", host, primary_port);

    if check_dns || check_ports || check_headers {
        if let Ok(Ok(addrs)) = timeout(Duration::from_millis(1500), lookup_host(&lookup_target)).await {
            for sock_addr in addrs {
                let ip = sock_addr.ip();
                let ip_str = ip.to_string();
                if !resolved_ips.contains(&ip_str) {
                    resolved_ips.push(ip_str);
                }
                target_classification = classify_ip(&ip).to_string();
                match ip {
                    IpAddr::V4(v4) => {
                        if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                            is_loopback_or_private = true;
                        }
                    }
                    IpAddr::V6(v6) => {
                        if v6.is_loopback() {
                            is_loopback_or_private = true;
                        }
                    }
                }
            }
        }
    }
    let dns_latency_ms = u64::try_from(dns_start.elapsed().as_millis()).unwrap_or(0);

    if resolved_ips.is_empty() {
        findings.push(SurfaceFinding {
            id: "SURFACE-DNS-UNRESOLVED".to_string(),
            cwe: "CWE-706 / DNS-RESOLUTION-FAILURE".to_string(),
            severity: "HIGH".to_string(),
            category: "DNS & Réseau".to_string(),
            title: format!("Impossible de résoudre l'hôte `{}`", host),
            description: "Le résolveur DNS n'a retourné aucune adresse IPv4 ou IPv6 pour cette cible dans le délai imparti.".to_string(),
            remediation: "Vérifier l'orthographe du domaine, les enregistrements DNS A/AAAA ou la connectivité réseau locale.".to_string(),
        });
    } else if !is_literal_ip && is_loopback_or_private && host != "localhost" && !host.ends_with(".local") {
        findings.push(SurfaceFinding {
            id: "SURFACE-DNS-REBIND-PRIVATE-IP".to_string(),
            cwe: "CWE-350 / DNS-REBINDING-INTERNAL-RESOLUTION".to_string(),
            severity: "HIGH".to_string(),
            category: "DNS & Réseau".to_string(),
            title: "Domaine résolvant vers une IP interne / Loopback (Risque DNS Rebinding / SSRF)".to_string(),
            description: format!(
                "Le nom d'hôte `{}` résout vers une adresse privée ou locale ({:?}). Si ce domaine est accepté par un webhook backend, il contourne les filtres SSRF basés uniquement sur le nom.",
                host, resolved_ips
            ),
            remediation: "Valider systématiquement l'adresse IP résolue par le socket contre les plages RFC 1918, 127.0.0.0/8 et 169.254.0.0/16.".to_string(),
        });
    }

    // 2. Scan de posture des ports TCP + Banner Grabbing (selon le niveau d'impact/visibilité)
    let mut ports_to_scan = if scan_level == 1 {
        vec![primary_port]
    } else if scan_level == 2 {
        vec![22u16, 80, 443, 3000, 3030, 5000, 5432, 6379, 8080, 8443]
    } else {
        vec![21u16, 22, 80, 443, 3000, 3030, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9200, 27017]
    };

    if !ports_to_scan.contains(&primary_port) {
        ports_to_scan.insert(0, primary_port);
    }
    if let Some(ref custom) = req.custom_ports {
        for part in custom.split([',', ' ', ';']) {
            if let Ok(p) = part.trim().parse::<u16>() {
                if p > 0 && !ports_to_scan.contains(&p) {
                    ports_to_scan.push(p);
                }
            }
        }
    }

    let mut open_ports = Vec::new();
    let grab_banners = scan_level >= 2;
    if check_ports && !resolved_ips.is_empty() {
        let mut handles = Vec::new();
        for &p in &ports_to_scan {
            let h = host.clone();
            handles.push(tokio::spawn(async move { probe_single_port(h, p, grab_banners).await }));
        }
        for handle in handles {
            if let Ok(res) = handle.await {
                if res.open && matches!(res.port, 6379 | 5432 | 3306 | 27017 | 9200 | 21 | 23) {
                    findings.push(SurfaceFinding {
                        id: format!("SURFACE-EXPOSED-DATA-PORT-{}", res.port),
                        cwe: "CWE-284 / EXPOSED-DATASTORE-PORT".to_string(),
                        severity: if matches!(res.port, 6379 | 27017 | 9200 | 23) { "CRITICAL".to_string() } else { "HIGH".to_string() },
                        category: "Ports & Services".to_string(),
                        title: format!("Service critique exposé sur le port TCP :{} ({})", res.port, res.service),
                        description: format!(
                            "Le démon `{}` répond sur `{}:{}` ({} ms){}.",
                            res.service,
                            host,
                            res.port,
                            res.latency_ms.unwrap_or(0),
                            res.banner.as_ref().map(|b| format!(" avec la bannière `{}`", b)).unwrap_or_default()
                        ),
                        remediation: format!(
                            "Isoler le port {} ({}) sur 127.0.0.1 ou un VPC privé et imposer une authentification mutuelle.",
                            res.port, res.service
                        ),
                    });
                }
                open_ports.push(res);
            }
        }
        open_ports.sort_by_key(|p| (!p.open, p.port));
    }

    // 3. Audit HTTP, Headers, Stack Technologique & Découverte Web Visuelle / Formulaires
    let mut http_status = None;
    let mut raw_headers = HashMap::new();
    let mut headers_audit = Vec::new();
    let mut web_discovery = None;
    let mut exposed_artifacts = Vec::new();
    let mut last_http_body = String::new();

    if check_headers && !resolved_ips.is_empty() {
        let http_method = if scan_level == 1 && !check_web_forms { "HEAD" } else { "GET" };
        let candidate_http_ports = [primary_port, 443, 80, 3030, 8080, 3000, 5000, 8000];
        let mut probe_result = None;
        let mut probed_port = primary_port;

        for &cp in &candidate_http_ports {
            let probe_scheme = if cp == 443 || cp == 8443 { "https" } else { &scheme };
            if let Some(res) = send_http_probe(probe_scheme, &host, cp, &path, http_method).await {
                probe_result = Some(res);
                probed_port = cp;
                break;
            }
        }

        if let Some((status_line, hdrs, body)) = probe_result {
            http_status = Some(format!("{} (port :{})", status_line, probed_port));
            raw_headers = hdrs.clone();
            last_http_body = body.clone();

            // 3a. Content-Security-Policy (CSP)
            if let Some(csp) = hdrs.get("content-security-policy") {
                let has_unsafe = csp.contains("'unsafe-inline'") || csp.contains("'unsafe-eval'");
                headers_audit.push(HeaderControlResult {
                    header: "Content-Security-Policy".to_string(),
                    present: true,
                    value: Some(csp.clone()),
                    status: if has_unsafe { "WARN".to_string() } else { "PASS".to_string() },
                    recommendation: if has_unsafe {
                        "CSP présente mais contient 'unsafe-inline' ou 'unsafe-eval'.".to_string()
                    } else {
                        "Politique CSP stricte active.".to_string()
                    },
                });
            } else {
                headers_audit.push(HeaderControlResult {
                    header: "Content-Security-Policy".to_string(),
                    present: false,
                    value: None,
                    status: "FAIL".to_string(),
                    recommendation: "Absent : définir default-src 'self'; frame-ancestors 'none'.".to_string(),
                });
                findings.push(SurfaceFinding {
                    id: "SURFACE-MISSING-CSP".to_string(),
                    cwe: "CWE-693 / MISSING-CONTENT-SECURITY-POLICY".to_string(),
                    severity: "MEDIUM".to_string(),
                    category: "Headers HTTP & CORS".to_string(),
                    title: "Absence d'en-tête Content-Security-Policy (CSP)".to_string(),
                    description: "La réponse HTTP ne définit pas de Content-Security-Policy contre l'injection XSS et le chargement de scripts non autorisés.".to_string(),
                    remediation: "Ajouter `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'`.".to_string(),
                });
            }

            // 3b. X-Content-Type-Options
            if let Some(xcto) = hdrs.get("x-content-type-options") {
                headers_audit.push(HeaderControlResult {
                    header: "X-Content-Type-Options".to_string(),
                    present: true,
                    value: Some(xcto.clone()),
                    status: if xcto.to_lowercase().contains("nosniff") { "PASS".to_string() } else { "WARN".to_string() },
                    recommendation: "Protection MIME-Sniffing active (nosniff).".to_string(),
                });
            } else {
                headers_audit.push(HeaderControlResult {
                    header: "X-Content-Type-Options".to_string(),
                    present: false,
                    value: None,
                    status: "FAIL".to_string(),
                    recommendation: "Absent : ajouter `X-Content-Type-Options: nosniff`.".to_string(),
                });
                findings.push(SurfaceFinding {
                    id: "SURFACE-MISSING-NOSNIFF".to_string(),
                    cwe: "CWE-16 / MISSING-MIME-NOSNIFF".to_string(),
                    severity: "LOW".to_string(),
                    category: "Headers HTTP & CORS".to_string(),
                    title: "Absence de protection MIME-Sniffing (X-Content-Type-Options: nosniff)".to_string(),
                    description: "Sans `nosniff`, le navigateur peut deviner et exécuter un type MIME dangereux sur les ressources chargées.".to_string(),
                    remediation: "Ajouter `X-Content-Type-Options: nosniff` sur toutes les réponses.".to_string(),
                });
            }

            // 3c. X-Frame-Options
            let has_frame_ancestors = hdrs.get("content-security-policy").map(|c| c.contains("frame-ancestors")).unwrap_or(false);
            if let Some(xfo) = hdrs.get("x-frame-options") {
                headers_audit.push(HeaderControlResult {
                    header: "X-Frame-Options".to_string(),
                    present: true,
                    value: Some(xfo.clone()),
                    status: "PASS".to_string(),
                    recommendation: "Protection anti-Clickjacking active.".to_string(),
                });
            } else if has_frame_ancestors {
                headers_audit.push(HeaderControlResult {
                    header: "X-Frame-Options".to_string(),
                    present: true,
                    value: Some("via CSP frame-ancestors".to_string()),
                    status: "PASS".to_string(),
                    recommendation: "Couvert par CSP frame-ancestors.".to_string(),
                });
            } else {
                headers_audit.push(HeaderControlResult {
                    header: "X-Frame-Options".to_string(),
                    present: false,
                    value: None,
                    status: "FAIL".to_string(),
                    recommendation: "Absent : ajouter `X-Frame-Options: DENY` ou `SAMEORIGIN`.".to_string(),
                });
                findings.push(SurfaceFinding {
                    id: "SURFACE-CLICKJACKING-EXPOSURE".to_string(),
                    cwe: "CWE-1021 / MISSING-ANTI-CLICKJACKING-HEADER".to_string(),
                    severity: "MEDIUM".to_string(),
                    category: "Headers HTTP & CORS".to_string(),
                    title: "Protection Anti-Clickjacking manquante (X-Frame-Options)".to_string(),
                    description: "Les pages et formulaires peuvent être embarqués dans une `<iframe>` externe pour piéger les clics de l'utilisateur.".to_string(),
                    remediation: "Ajouter `X-Frame-Options: DENY` (ou `SAMEORIGIN`) et `frame-ancestors 'none'`.".to_string(),
                });
            }

            // 3d. HSTS
            if let Some(hsts) = hdrs.get("strict-transport-security") {
                headers_audit.push(HeaderControlResult {
                    header: "Strict-Transport-Security".to_string(),
                    present: true,
                    value: Some(hsts.clone()),
                    status: "PASS".to_string(),
                    recommendation: "Politique HSTS active.".to_string(),
                });
            } else {
                let status_str = if is_loopback_or_private { "WARN" } else { "FAIL" };
                headers_audit.push(HeaderControlResult {
                    header: "Strict-Transport-Security".to_string(),
                    present: false,
                    value: None,
                    status: status_str.to_string(),
                    recommendation: "Ajouter `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.".to_string(),
                });
                if !is_loopback_or_private {
                    findings.push(SurfaceFinding {
                        id: "SURFACE-MISSING-HSTS".to_string(),
                        cwe: "CWE-319 / MISSING-HSTS-HEADER".to_string(),
                        severity: "MEDIUM".to_string(),
                        category: "Headers HTTP & CORS".to_string(),
                        title: "En-tête HSTS (Strict-Transport-Security) absent sur cible distante".to_string(),
                        description: "Expose les utilisateurs au SSL-Stripping lors de la connexion initiale.".to_string(),
                        remediation: "Activer `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.".to_string(),
                    });
                }
            }

            // 3e. CORS
            if let Some(acao) = hdrs.get("access-control-allow-origin") {
                let acac = hdrs.get("access-control-allow-credentials").map(|v| v.to_lowercase() == "true").unwrap_or(false);
                let reflects_probe = acao.contains("scanner-probe.aetherscope.local");
                let is_wildcard = acao.trim() == "*";

                if reflects_probe || (is_wildcard && acac) {
                    headers_audit.push(HeaderControlResult {
                        header: "Access-Control-Allow-Origin".to_string(),
                        present: true,
                        value: Some(acao.clone()),
                        status: "FAIL".to_string(),
                        recommendation: "Réflexion d'origine arbitraire critique détectée !".to_string(),
                    });
                    findings.push(SurfaceFinding {
                        id: "SURFACE-CORS-ORIGIN-REFLECTION".to_string(),
                        cwe: "CWE-942 / OVERLY-PERMISSIVE-CORS-POLICY".to_string(),
                        severity: "CRITICAL".to_string(),
                        category: "Headers HTTP & CORS".to_string(),
                        title: "Politique CORS dangereuse : réflexion de l'Origin arbitraire".to_string(),
                        description: format!("Le serveur reflète l'origine de sonde dans `Access-Control-Allow-Origin: {}`.", acao),
                        remediation: "Valider l'en-tête `Origin` contre une liste blanche stricte.".to_string(),
                    });
                } else {
                    headers_audit.push(HeaderControlResult {
                        header: "Access-Control-Allow-Origin".to_string(),
                        present: true,
                        value: Some(acao.clone()),
                        status: if is_wildcard { "WARN".to_string() } else { "PASS".to_string() },
                        recommendation: if is_wildcard { "Wildcard CORS `*` actif.".to_string() } else { "CORS restreint.".to_string() },
                    });
                }
            } else {
                headers_audit.push(HeaderControlResult {
                    header: "Access-Control-Allow-Origin".to_string(),
                    present: false,
                    value: None,
                    status: "PASS".to_string(),
                    recommendation: "Isolation Same-Origin stricte par défaut.".to_string(),
                });
            }

            // 3f. Server / X-Powered-By version exposure
            if let Some(srv) = hdrs.get("server").or_else(|| hdrs.get("x-powered-by")) {
                let leaks_version = srv.chars().any(|c| c.is_ascii_digit());
                headers_audit.push(HeaderControlResult {
                    header: "Server / X-Powered-By".to_string(),
                    present: true,
                    value: Some(srv.clone()),
                    status: if leaks_version { "WARN".to_string() } else { "PASS".to_string() },
                    recommendation: if leaks_version {
                        "Version logicielle exposée dans les en-têtes.".to_string()
                    } else {
                        "Bannière serveur sobre.".to_string()
                    },
                });
                if leaks_version {
                    findings.push(SurfaceFinding {
                        id: "SURFACE-SERVER-BANNER-VERSION-LEAK".to_string(),
                        cwe: "CWE-200 / SERVER-VERSION-FINGERPRINT-EXPOSURE".to_string(),
                        severity: "LOW".to_string(),
                        category: "Services & Versions".to_string(),
                        title: format!("Version exacte du serveur divulguée (`{}`)", srv),
                        description: "Facilite l'identification automatisée de CVE spécifiques à cette version.".to_string(),
                        remediation: "Masquer la version exacte (`server_tokens off` / `ServerTokens Prod`).".to_string(),
                    });
                }
            }

            // 4. Découverte des Endpoints (robots.txt & security.txt) + Cartographie Web & Formulaires
            let mut robots_entries = Vec::new();
            let mut security_txt_present = false;
            let probe_scheme = if probed_port == 443 || probed_port == 8443 { "https" } else { &scheme };

            if check_endpoints {
                if let Some((sec_st, _, _)) = send_http_probe(probe_scheme, &host, probed_port, "/.well-known/security.txt", "GET").await {
                    if sec_st.contains(" 200 ") {
                        security_txt_present = true;
                    }
                }
                if let Some((rob_st, _, rob_body)) = send_http_probe(probe_scheme, &host, probed_port, "/robots.txt", "GET").await {
                    if rob_st.contains(" 200 ") {
                        for line in rob_body.lines() {
                            let tl = line.trim();
                            if let Some(p) = tl.strip_prefix("Disallow:").or_else(|| tl.strip_prefix("Allow:")) {
                                let clean_p = p.trim();
                                if clean_p.starts_with('/') && robots_entries.len() < 15 {
                                    robots_entries.push(clean_p.to_string());
                                }
                            }
                        }
                    }
                }
            }

            if check_web_forms {
                let (mut disc, form_findings) = parse_html_architecture_and_forms(
                    &body,
                    &hdrs,
                    probe_scheme,
                    is_loopback_or_private,
                    robots_entries,
                    security_txt_present,
                );
                // Sonde rapide sur /api/health si présent
                if let Some((hlth_st, _, _)) = send_http_probe(probe_scheme, &host, probed_port, "/api/health", "GET").await {
                    if hlth_st.contains(" 200 ") && !disc.routes.iter().any(|r| r.path == "/api/health") {
                        disc.routes.push(DiscoveredRoute {
                            path: "/api/health".to_string(),
                            method: "GET".to_string(),
                            source: "Endpoint Probe (200 OK)".to_string(),
                            status: Some("200 OK".to_string()),
                        });
                    }
                }
                findings.extend(form_findings);
                inspect_web_files_and_directories(
                    probe_scheme,
                    &host,
                    probed_port,
                    &path,
                    &body,
                    &mut disc,
                    &mut findings,
                )
                .await;
                web_discovery = Some(disc);
            }

            if check_sensitive_files {
                let (art_probes, art_findings) = probe_sensitive_artifacts(probe_scheme, &host, probed_port).await;
                exposed_artifacts = art_probes;
                findings.extend(art_findings);
            }
        }
    }

    let tech_stack = fingerprint_technologies(&raw_headers, &last_http_body, &open_ports);
    let mut final_tech_stack = tech_stack;
    if let Some(ref wd) = web_discovery {
        if let Some(ref gen) = wd.meta_generator {
            final_tech_stack.push(TechFingerprint {
                name: gen.clone(),
                category: "CMS / Générateur".to_string(),
                version: extract_version_token(gen),
                source: "Balise <meta name=\"generator\">".to_string(),
                confidence: "Haute (100%)".to_string(),
            });
        }
    }

    // 5. Matrice de Niveau d'Impact & Visibilité
    let open_services_count = open_ports.iter().filter(|p| p.open).count();
    let versions_count = open_ports.iter().filter(|p| p.detected_version.is_some()).count()
        + final_tech_stack.iter().filter(|t| t.version.is_some()).count();
    let forms_count = web_discovery.as_ref().map(|w| w.forms.len()).unwrap_or(0);
    let inputs_count = web_discovery
        .as_ref()
        .map(|w| w.forms.iter().map(|f| f.inputs.len()).sum())
        .unwrap_or(0);
    let routes_count = web_discovery.as_ref().map(|w| w.routes.len()).unwrap_or(0);
    let exposures_count = exposed_artifacts.iter().filter(|a| a.exposed).count();

    let (level_name, visibility_footprint, impact_rating, packets_est) = match scan_level {
        1 => (
            "Niveau 1 • Furtif & Empreinte Passive".to_string(),
            "🟢 Visibilité Minimale (1 résolution DNS + 1 sonde HEAD)".to_string(),
            "Impact Nul (0 écriture, 0 crawl)".to_string(),
            "~2-3 paquets TCP".to_string(),
        ),
        2 => (
            "Niveau 2 • Empreinte Services, Bannières & Versions".to_string(),
            "🟡 Visibilité Modérée (Handshake TCP + Lecture Bannières)".to_string(),
            "Impact Très Faible (Lecture passive des bannières)".to_string(),
            "~12-18 paquets TCP".to_string(),
        ),
        3 => (
            "Niveau 3 • Black-Box Complet & Cartographie Web/Forms".to_string(),
            "🔴 Visibilité Complète (Ports + Bannières + DOM HTML + Formulaires «Form» + robots.txt)".to_string(),
            "Impact Contrôlé (Requêtes GET standard en lecture seule)".to_string(),
            "~25-35 paquets TCP/HTTP".to_string(),
        ),
        _ => (
            "Niveau 4 • Audit d'Exposition (.env, .git, Configs & Specs — Masqué)".to_string(),
            "🟣 Visibilité Élevée (Ports + Web + «Form» + Sondes CWE-538 /.env, /.git/HEAD, /docker-compose.yml)".to_string(),
            "Impact Défensif (Vérification anti-Soft-404 avec masquage strict des valeurs [MASQUÉ])".to_string(),
            "~35-45 paquets TCP/HTTP".to_string(),
        ),
    };

    let impact_matrix = ImpactVisibilityMatrix {
        scan_level,
        level_name,
        visibility_footprint,
        impact_rating,
        packets_sent_estimate: packets_est,
        detected_services_count: open_services_count,
        detected_versions_count: versions_count,
        detected_forms_count: forms_count,
        detected_inputs_count: inputs_count,
        detected_routes_count: routes_count,
        detected_exposures_count: exposures_count,
    };

    // 6. Calcul du Score de Posture (0 - 100) & Grade
    let mut penalty = 0u32;
    for f in &findings {
        match f.severity.as_str() {
            "CRITICAL" => penalty = penalty.saturating_add(28),
            "HIGH" => penalty = penalty.saturating_add(16),
            "MEDIUM" => penalty = penalty.saturating_add(8),
            "LOW" => penalty = penalty.saturating_add(4),
            _ => {}
        }
    }
    let security_score = 100u32.saturating_sub(penalty);
    let grade = match security_score {
        92..=100 => "A+",
        84..=91 => "A",
        74..=83 => "B",
        60..=73 => "C",
        45..=59 => "D",
        _ => "F",
    }
    .to_string();

    let scan_duration_ms = u64::try_from(scan_start.elapsed().as_millis()).unwrap_or(0);

    // 7. Construction des 4 Frontières de Confiance (Swimlanes) & Suite de Vérification Défensive
    let has_csp = headers_audit.iter().any(|h| h.header == "Content-Security-Policy" && h.status == "PASS");
    let has_hsts = headers_audit.iter().any(|h| h.header == "Strict-Transport-Security" && h.status == "PASS");
    let has_xfo = headers_audit.iter().any(|h| h.header == "X-Frame-Options" && h.status == "PASS");
    let files_cnt = web_discovery.as_ref().map(|w| w.web_files.len()).unwrap_or(0);
    let dirs_cnt = web_discovery.as_ref().map(|w| w.directories.len()).unwrap_or(0);

    let zone1_posture = if has_csp && has_xfo { "PASS" } else { "WARN" };
    let zone2_posture = if web_discovery
        .as_ref()
        .map(|w| w.forms.iter().any(|f| f.security_posture == "CRITICAL"))
        .unwrap_or(false)
    {
        "CRITICAL"
    } else if web_discovery
        .as_ref()
        .map(|w| w.forms.iter().any(|f| f.security_posture == "WARN"))
        .unwrap_or(false)
    {
        "WARN"
    } else {
        "PASS"
    };
    let zone3_posture = if findings.iter().any(|f| f.id == "SURFACE-CORS-ORIGIN-REFLECTION") {
        "CRITICAL"
    } else if !has_hsts && !is_loopback_or_private {
        "WARN"
    } else {
        "PASS"
    };
    let zone4_posture = if exposures_count > 0
        || findings.iter().any(|f| f.id.starts_with("SURFACE-EXPOSED-DATA-PORT"))
    {
        "CRITICAL"
    } else if versions_count > 0 {
        "WARN"
    } else {
        "PASS"
    };

    let trust_zones = vec![
        TrustZoneSummary {
            zone_id: 1,
            title: "Zone 1 • Client & Fichiers (.html/.js)".to_string(),
            subtitle: format!("{} fichier(s) inspecté(s)", files_cnt),
            posture: zone1_posture.to_string(),
            controls: vec![
                format!("CSP : {}", if has_csp { "Active" } else { "Manquante/Partielle" }),
                format!("Anti-Clickjacking : {}", if has_xfo { "Actif" } else { "Manquant" }),
            ],
        },
        TrustZoneSummary {
            zone_id: 2,
            title: "Zone 2 • Entrées & Formulaires («Form»)".to_string(),
            subtitle: format!("{} form(s) • {} champ(s)", forms_count, inputs_count),
            posture: zone2_posture.to_string(),
            controls: vec![
                format!("Validation CSRF : {}", if zone2_posture == "PASS" { "Conforme" } else { "À renforcer" }),
                format!("Transport Secrets : {}", if scheme == "https" || is_loopback_or_private { "Isolé/TLS" } else { "HTTP Clair" }),
            ],
        },
        TrustZoneSummary {
            zone_id: 3,
            title: "Zone 3 • Passerelle, Dossiers & API".to_string(),
            subtitle: format!("{} dossier(s) • {} route(s)", dirs_cnt, routes_count),
            posture: zone3_posture.to_string(),
            controls: vec![
                format!("Isolation CORS : {}", if zone3_posture == "CRITICAL" { "Réflexion !" } else { "Conforme" }),
                format!("HSTS : {}", if has_hsts { "Actif" } else { "Non défini" }),
            ],
        },
        TrustZoneSummary {
            zone_id: 4,
            title: "Zone 4 • Services TCP & Fichiers (.env/.git)".to_string(),
            subtitle: format!("{} port(s) • {} exposition(s)", open_services_count, exposures_count),
            posture: zone4_posture.to_string(),
            controls: vec![
                format!("Dotfiles CWE-538 : {}", if exposures_count == 0 { "Protégés" } else { "EXPOSÉS !" }),
                format!("Versions : {} empreinte(s)", versions_count),
            ],
        },
    ];

    let base_url = if (scheme == "https" && primary_port == 443) || (scheme == "http" && primary_port == 80) {
        format!("{}://{}", scheme, host)
    } else {
        format!("{}://{}:{}", scheme, host, primary_port)
    };

    let verification_suite = vec![
        DefensiveVerificationCheck {
            id: "VERIFY-HEADERS-POSTURE".to_string(),
            title: "Vérification de non-régression des en-têtes de sécurité HTTP (CSP, HSTS, XFO, Nosniff)".to_string(),
            category: "Headers & Gouvernance HTTP".to_string(),
            assertion_cmd: format!("curl -sSI \"{}/\" | findstr /I \"Content-Security-Policy X-Content-Type-Options X-Frame-Options Strict-Transport-Security\"", base_url),
            expected_result: "Doit retourner Content-Security-Policy (sans unsafe-inline), X-Content-Type-Options: nosniff et X-Frame-Options: DENY.".to_string(),
            patch_hint: "Axum : tower_http::set_header::SetResponseHeaderLayer | Nginx : add_header Content-Security-Policy \"default-src 'self'\" always;".to_string(),
        },
        DefensiveVerificationCheck {
            id: "VERIFY-CORS-ISOLATION".to_string(),
            title: "Test de non-réflexion d'origine CORS arbitraire (CWE-942)".to_string(),
            category: "Passerelle API & CORS".to_string(),
            assertion_cmd: format!("curl -sSI -H \"Origin: https://untrusted-verify.example\" \"{}/\" | findstr /I \"Access-Control-Allow-Origin\"", base_url),
            expected_result: "Ne doit JAMAIS refléter `https://untrusted-verify.example` ni combiner `*` avec `Access-Control-Allow-Credentials: true`.".to_string(),
            patch_hint: "Remplacer CorsLayer::permissive() par CorsLayer::new().allow_origin([\"http://127.0.0.1:3030\".parse()?])".to_string(),
        },
        DefensiveVerificationCheck {
            id: "VERIFY-DOTFILES-BLOCKED".to_string(),
            title: "Vérification d'inaccessibilité des fichiers sensibles (/.env et /.git/HEAD — CWE-538)".to_string(),
            category: "Module 4 • Fichiers Sensibles".to_string(),
            assertion_cmd: format!("curl -s -o NUL -w \"%{{http_code}}\" \"{}/.env\" && curl -s -o NUL -w \" %{{http_code}}\" \"{}/.git/HEAD\"", base_url, base_url),
            expected_result: "Codes HTTP attendus : `403` ou `404` (ou Soft-404 HTML sans aucune paire KEY=VALUE ni signature `ref: refs/`).".to_string(),
            patch_hint: "Nginx : location ~ /\\.(?!well-known) { deny all; return 404; } | Ne jamais monter la racine du dépôt dans ServeDir.".to_string(),
        },
    ];

    // 8. Côté 1 Boosted : Sondes de Faiblesse de Frontière (Externe Black-Box Non-Destructif)
    let mut boundary_weaknesses = Vec::new();

    // 8.1 Sonde CORS & Réflexion d'Origine (CWE-942)
    let acao_val = raw_headers
        .get("access-control-allow-origin")
        .cloned()
        .unwrap_or_default();
    let acac_val = raw_headers
        .get("access-control-allow-credentials")
        .cloned()
        .unwrap_or_default();
    let cors_status = if acao_val.contains("scanner-probe.aetherscope.local")
        || (acao_val == "*" && acac_val.eq_ignore_ascii_case("true"))
    {
        "EXPOSÉ"
    } else if acao_val == "*" {
        "FAIBLESSE"
    } else {
        "ROBUSTE"
    };
    boundary_weaknesses.push(BoundaryWeaknessProbe {
        id: "WEAKNESS-CORS-ORIGIN".to_string(),
        cwe: "CWE-942".to_string(),
        side_one_vector: format!("Header Origin: https://scanner-probe.aetherscope.local ➔ {}", base_url),
        category: "CORS & Origine Croisée".to_string(),
        status: cors_status.to_string(),
        observed_behavior: if acao_val.is_empty() {
            "Aucun en-tête Access-Control-Allow-Origin permissif retourné (Isolation inter-origine stricte).".to_string()
        } else {
            format!("ACA-Origin retourné : `{}` (Credentials : `{}`).", acao_val, if acac_val.is_empty() { "false" } else { &acac_val })
        },
        side_two_ast_target: "Middleware CORS / CorsLayer (Passerelle HTTP)".to_string(),
        negative_test_spec: "Test Négatif : Envoyer une requête avec `Origin: https://untrusted.invalid` et vérifier que `Access-Control-Allow-Origin` est absent ou ne reflète pas l'origine.".to_string(),
    });

    // 8.2 Sonde Active des Verbes HTTP (OPTIONS — CWE-650 / CWE-749)
    let mut allowed_methods_obs = "Sonde OPTIONS non exécutée (Niveau 1).".to_string();
    let mut methods_status = "ROBUSTE";
    if scan_level >= 2 && http_status.is_some() {
        if let Some((opt_status, opt_hdrs, _)) =
            send_http_probe(&scheme, &host, primary_port, &path, "OPTIONS").await
        {
            let allow_h = opt_hdrs
                .get("allow")
                .or_else(|| opt_hdrs.get("access-control-allow-methods"))
                .cloned()
                .unwrap_or_default();
            let upper_allow = allow_h.to_uppercase();
            if upper_allow.contains("TRACE") {
                methods_status = "EXPOSÉ";
            } else if upper_allow.contains("DELETE") || upper_allow.contains("PUT") {
                methods_status = "FAIBLESSE";
            }
            allowed_methods_obs = if allow_h.is_empty() {
                format!("Réponse OPTIONS : `{}` (Aucun verbe dangereux annoncé dans Allow).", opt_status)
            } else {
                format!("Réponse OPTIONS : `{}` — Méthodes annoncées : `{}`.", opt_status, allow_h)
            };
        } else {
            allowed_methods_obs = "OPTIONS rejeté ou fermé par le serveur (Surface réduite).".to_string();
        }
    }
    boundary_weaknesses.push(BoundaryWeaknessProbe {
        id: "WEAKNESS-HTTP-VERBS".to_string(),
        cwe: "CWE-650".to_string(),
        side_one_vector: format!("OPTIONS {}", path),
        category: "Verbes & Méthodes HTTP".to_string(),
        status: methods_status.to_string(),
        observed_behavior: allowed_methods_obs,
        side_two_ast_target: "Routeur HTTP / Table des Routes AST (get/post MethodFilter)".to_string(),
        negative_test_spec: "Test Négatif : Envoyer une requête `TRACE` ou `DELETE` non authentifiée sur la route et exiger `405 Method Not Allowed`.".to_string(),
    });

    // 8.3 Sonde d'Attributs de Session & Cookies (CWE-614 / CWE-1004 / CWE-1275)
    let set_cookie_val = raw_headers.get("set-cookie").cloned().unwrap_or_default();
    let (cookie_status, cookie_obs) = if set_cookie_val.is_empty() {
        (
            "ROBUSTE",
            "Aucun cookie de session émis sur l'entrée (Architecture sans état / Stateless).".to_string(),
        )
    } else {
        let lower_c = set_cookie_val.to_lowercase();
        let has_httponly = lower_c.contains("httponly");
        let has_samesite = lower_c.contains("samesite=strict") || lower_c.contains("samesite=lax");
        let has_secure = lower_c.contains("secure");
        if !has_httponly || !has_samesite || (scheme == "https" && !has_secure) {
            (
                "FAIBLESSE",
                format!(
                    "Cookie détecté avec drapeaux incomplets (HttpOnly: {}, SameSite: {}, Secure: {}).",
                    has_httponly, has_samesite, has_secure
                ),
            )
        } else {
            (
                "ROBUSTE",
                "Cookie(s) protégé(s) par HttpOnly, SameSite et Secure.".to_string(),
            )
        }
    };
    boundary_weaknesses.push(BoundaryWeaknessProbe {
        id: "WEAKNESS-COOKIE-FLAGS".to_string(),
        cwe: "CWE-1004".to_string(),
        side_one_vector: "En-tête HTTP Set-Cookie".to_string(),
        category: "Session & Cookies".to_string(),
        status: cookie_status.to_string(),
        observed_behavior: cookie_obs,
        side_two_ast_target: "Gestionnaire de Session / Auth Cookie Builder".to_string(),
        negative_test_spec: "Test Négatif : Vérifier que tout en-tête `Set-Cookie` contient `HttpOnly; SameSite=Strict` (et `Secure` en HTTPS).".to_string(),
    });

    // 8.4 Sonde d'Indexation des Dossiers Découverts (CWE-548 — Directory Listing)
    if let Some(ref wd) = web_discovery {
        if let Some(first_dir) = wd.directories.first() {
            let mut dir_status = "ROBUSTE";
            let mut dir_obs = format!(
                "Dossier `{}` référencé ({}x) sans exposition d'index détectée.",
                first_dir.folder_path, first_dir.call_count
            );
            if scan_level >= 3 && first_dir.folder_path.starts_with('/') {
                if let Some((d_st, _, d_body)) =
                    send_http_probe(&scheme, &host, primary_port, &first_dir.folder_path, "GET").await
                {
                    let lb = d_body.to_lowercase();
                    if lb.contains("index of /") || lb.contains("directory listing for") {
                        dir_status = "EXPOSÉ";
                        dir_obs = format!(
                            "Indexation de répertoire active (`Index of /`) sur `{}` ({}) !",
                            first_dir.folder_path, d_st
                        );
                    } else {
                        dir_obs = format!(
                            "Sonde GET `{}` ➔ `{}` (Aucun Directory Listing `Index of /` exposé).",
                            first_dir.folder_path, d_st
                        );
                    }
                }
            }
            boundary_weaknesses.push(BoundaryWeaknessProbe {
                id: "WEAKNESS-DIR-LISTING".to_string(),
                cwe: "CWE-548".to_string(),
                side_one_vector: format!("GET {}", first_dir.folder_path),
                category: "Arborescence & Dossiers".to_string(),
                status: dir_status.to_string(),
                observed_behavior: dir_obs,
                side_two_ast_target: "ServeDir / Static File Handler (CWE-59 / CWE-548)".to_string(),
                negative_test_spec: format!(
                    "Test Négatif : Appeler `{}` et `{}` + `../` et vérifier l'absence de `Index of /` ainsi qu'un statut 403/404.",
                    first_dir.folder_path, first_dir.folder_path
                ),
            });
        }

        // 8.5 Contrats des Formulaires «Form» découverts (CWE-352 / CWE-20)
        for f in wd.forms.iter().take(4) {
            let f_status = if f.security_posture == "CRITICAL" {
                "EXPOSÉ"
            } else if f.security_posture == "WARN" {
                "FAIBLESSE"
            } else {
                "ROBUSTE"
            };
            let inp_names: Vec<String> = f.inputs.iter().map(|i| format!("{}({})", i.name, i.input_type)).collect();
            boundary_weaknesses.push(BoundaryWeaknessProbe {
                id: format!("WEAKNESS-FORM-{}", f.index),
                cwe: if !f.has_csrf_token && f.method == "POST" {
                    "CWE-352".to_string()
                } else {
                    "CWE-20".to_string()
                },
                side_one_vector: format!("Form #{} «{}» [{} {}]", f.index, f.id_or_name, f.method, f.action),
                category: "Contrat Formulaire «Form»".to_string(),
                status: f_status.to_string(),
                observed_behavior: format!(
                    "CSRF: {} • {} champ(s) : {}",
                    if f.has_csrf_token { "Présent" } else { "Absent" },
                    f.inputs.len(),
                    if inp_names.is_empty() { "aucun".to_string() } else { inp_names.join(", ") }
                ),
                side_two_ast_target: format!("Handler AST `{}` & Validateur des champs d'entrée", f.action),
                negative_test_spec: format!(
                    "Test Négatif : Soumettre `{}` sans jeton CSRF ou avec types invalides sur [{}] et exiger un rejet 400/403/422.",
                    f.action,
                    inp_names.join(", ")
                ),
            });
        }

        // 8.6 Contrats de Schéma JSON & Routes API extraits des fichiers .js (CWE-20 / CWE-88 / CWE-94)
        for wf in wd.web_files.iter().filter(|w| !w.json_payload_keys.is_empty() || !w.api_and_asset_refs.is_empty()).take(5) {
            let api_refs: Vec<String> = wf
                .api_and_asset_refs
                .iter()
                .filter(|r| r.starts_with("/api/") || r.starts_with("/v1/") || r.starts_with("/auth/"))
                .cloned()
                .collect();
            if !wf.json_payload_keys.is_empty() || !api_refs.is_empty() {
                let keys_preview = if wf.json_payload_keys.is_empty() {
                    "Aucune clé JSON explicite".to_string()
                } else {
                    wf.json_payload_keys.join(", ")
                };
                let routes_preview = if api_refs.is_empty() {
                    wf.path.clone()
                } else {
                    api_refs.join(", ")
                };
                boundary_weaknesses.push(BoundaryWeaknessProbe {
                    id: format!("WEAKNESS-JSON-CONTRACT-{}", wf.path.replace(['/', '.'], "-")),
                    cwe: "CWE-20 / CWE-88".to_string(),
                    side_one_vector: format!("Fichier {} ➔ {}", wf.path, routes_preview),
                    category: "Contrat API & Clés JSON".to_string(),
                    status: (if wf.has_sourcemap { "FAIBLESSE" } else { "ROBUSTE" }).to_string(),
                    observed_behavior: format!(
                        "Clés JSON détectées dans `{}` : [{}]{}.",
                        wf.path,
                        keys_preview,
                        if wf.has_sourcemap { " (SourceMap .map exposée CWE-540)" } else { "" }
                    ),
                    side_two_ast_target: format!("Struct DTO / Deserializer & Sink AST pour `{}`", routes_preview),
                    negative_test_spec: format!(
                        "Test Négatif : Envoyer un payload JSON mal typé, vide ou préfixé par `--` sur les clés [{}] vers `{}` et vérifier le rejet strict (400/415/422) avant tout appel système.",
                        keys_preview, routes_preview
                    ),
                });
            }
        }
    }

    // 8.7 Sonde d'Étanchéité des Fichiers Sensibles (CWE-538)
    if !exposed_artifacts.is_empty() {
        let exp_list: Vec<String> = exposed_artifacts
            .iter()
            .filter(|a| a.exposed)
            .map(|a| a.path.clone())
            .collect();
        boundary_weaknesses.push(BoundaryWeaknessProbe {
            id: "WEAKNESS-SENSITIVE-ARTIFACTS".to_string(),
            cwe: "CWE-538".to_string(),
            side_one_vector: format!("Sondes GET /.env, /.git/HEAD ({} cibles)", exposed_artifacts.len()),
            category: "Fichiers Config & Secrets".to_string(),
            status: if exp_list.is_empty() { "ROBUSTE" } else { "EXPOSÉ" }.to_string(),
            observed_behavior: if exp_list.is_empty() {
                format!("0/{} fichiers sensibles exposés (Protection 403/404 et filtrage Anti-Soft-404 validés).", exposed_artifacts.len())
            } else {
                format!("{} fichier(s) exposé(s) (Valeurs masquées [MASQUÉ]) : {}", exp_list.len(), exp_list.join(", "))
            },
            side_two_ast_target: "Filtre de routage statique / Isolation des dotfiles".to_string(),
            negative_test_spec: "Test Négatif : Requêter `/.env` et `/.git/HEAD` en CI et vérifier que le statut est 403/404 sans fuite de clé.".to_string(),
        });
    }

    SurfaceScanResponse {
        status: "ok".to_string(),
        target_raw: raw_target,
        host,
        scheme,
        primary_port,
        target_classification,
        resolved_ips,
        dns_latency_ms,
        scan_duration_ms,
        security_score,
        grade,
        http_status,
        impact_matrix,
        tech_stack: final_tech_stack,
        open_ports,
        headers_audit,
        raw_headers,
        web_discovery,
        exposed_artifacts,
        trust_zones,
        verification_suite,
        boundary_weaknesses,
        findings,
    }
}
