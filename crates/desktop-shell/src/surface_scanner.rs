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
    /// 1 = Furtif/Passif, 2 = Services/Versions, 3 = Black-Box Web & Forms, 4 = Audit d'Exposition (.env, .git, Configs - CWE-538 MasquÃ©)
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
    pub status: String, // "ROBUSTE", "FAIBLESSE", "EXPOSÃ‰"
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

#[path = "surface_probes.rs"]
mod surface_probes;
use surface_probes::*;
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

    // 1. RÃ©solution DNS & Classification RÃ©seau
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
            category: "DNS & RÃ©seau".to_string(),
            title: format!("Impossible de rÃ©soudre l'hÃ´te `{}`", host),
            description: "Le rÃ©solveur DNS n'a retournÃ© aucune adresse IPv4 ou IPv6 pour cette cible dans le dÃ©lai imparti.".to_string(),
            remediation: "VÃ©rifier l'orthographe du domaine, les enregistrements DNS A/AAAA ou la connectivitÃ© rÃ©seau locale.".to_string(),
        });
    } else if !is_literal_ip && is_loopback_or_private && host != "localhost" && !host.ends_with(".local") {
        findings.push(SurfaceFinding {
            id: "SURFACE-DNS-REBIND-PRIVATE-IP".to_string(),
            cwe: "CWE-350 / DNS-REBINDING-INTERNAL-RESOLUTION".to_string(),
            severity: "HIGH".to_string(),
            category: "DNS & RÃ©seau".to_string(),
            title: "Domaine rÃ©solvant vers une IP interne / Loopback (Risque DNS Rebinding / SSRF)".to_string(),
            description: format!(
                "Le nom d'hÃ´te `{}` rÃ©sout vers une adresse privÃ©e ou locale ({:?}). Si ce domaine est acceptÃ© par un webhook backend, il contourne les filtres SSRF basÃ©s uniquement sur le nom.",
                host, resolved_ips
            ),
            remediation: "Valider systÃ©matiquement l'adresse IP rÃ©solue par le socket contre les plages RFC 1918, 127.0.0.0/8 et 169.254.0.0/16.".to_string(),
        });
    }

    // 2. Scan de posture des ports TCP + Banner Grabbing (selon le niveau d'impact/visibilitÃ©)
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
                        title: format!("Service critique exposÃ© sur le port TCP :{} ({})", res.port, res.service),
                        description: format!(
                            "Le dÃ©mon `{}` rÃ©pond sur `{}:{}` ({} ms){}.",
                            res.service,
                            host,
                            res.port,
                            res.latency_ms.unwrap_or(0),
                            res.banner.as_ref().map(|b| format!(" avec la banniÃ¨re `{}`", b)).unwrap_or_default()
                        ),
                        remediation: format!(
                            "Isoler le port {} ({}) sur 127.0.0.1 ou un VPC privÃ© et imposer une authentification mutuelle.",
                            res.port, res.service
                        ),
                    });
                }
                open_ports.push(res);
            }
        }
        open_ports.sort_by_key(|p| (!p.open, p.port));
    }

    // 3. Audit HTTP, Headers, Stack Technologique & DÃ©couverte Web Visuelle / Formulaires
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
                        "CSP prÃ©sente mais contient 'unsafe-inline' ou 'unsafe-eval'.".to_string()
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
                    recommendation: "Absent : dÃ©finir default-src 'self'; frame-ancestors 'none'.".to_string(),
                });
                findings.push(SurfaceFinding {
                    id: "SURFACE-MISSING-CSP".to_string(),
                    cwe: "CWE-693 / MISSING-CONTENT-SECURITY-POLICY".to_string(),
                    severity: "MEDIUM".to_string(),
                    category: "Headers HTTP & CORS".to_string(),
                    title: "Absence d'en-tÃªte Content-Security-Policy (CSP)".to_string(),
                    description: "La rÃ©ponse HTTP ne dÃ©finit pas de Content-Security-Policy contre l'injection XSS et le chargement de scripts non autorisÃ©s.".to_string(),
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
                    description: "Sans `nosniff`, le navigateur peut deviner et exÃ©cuter un type MIME dangereux sur les ressources chargÃ©es.".to_string(),
                    remediation: "Ajouter `X-Content-Type-Options: nosniff` sur toutes les rÃ©ponses.".to_string(),
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
                    description: "Les pages et formulaires peuvent Ãªtre embarquÃ©s dans une `<iframe>` externe pour piÃ©ger les clics de l'utilisateur.".to_string(),
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
                        title: "En-tÃªte HSTS (Strict-Transport-Security) absent sur cible distante".to_string(),
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
                        recommendation: "RÃ©flexion d'origine arbitraire critique dÃ©tectÃ©e !".to_string(),
                    });
                    findings.push(SurfaceFinding {
                        id: "SURFACE-CORS-ORIGIN-REFLECTION".to_string(),
                        cwe: "CWE-942 / OVERLY-PERMISSIVE-CORS-POLICY".to_string(),
                        severity: "CRITICAL".to_string(),
                        category: "Headers HTTP & CORS".to_string(),
                        title: "Politique CORS dangereuse : rÃ©flexion de l'Origin arbitraire".to_string(),
                        description: format!("Le serveur reflÃ¨te l'origine de sonde dans `Access-Control-Allow-Origin: {}`.", acao),
                        remediation: "Valider l'en-tÃªte `Origin` contre une liste blanche stricte.".to_string(),
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
                    recommendation: "Isolation Same-Origin stricte par dÃ©faut.".to_string(),
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
                        "Version logicielle exposÃ©e dans les en-tÃªtes.".to_string()
                    } else {
                        "BanniÃ¨re serveur sobre.".to_string()
                    },
                });
                if leaks_version {
                    findings.push(SurfaceFinding {
                        id: "SURFACE-SERVER-BANNER-VERSION-LEAK".to_string(),
                        cwe: "CWE-200 / SERVER-VERSION-FINGERPRINT-EXPOSURE".to_string(),
                        severity: "LOW".to_string(),
                        category: "Services & Versions".to_string(),
                        title: format!("Version exacte du serveur divulguÃ©e (`{}`)", srv),
                        description: "Facilite l'identification automatisÃ©e de CVE spÃ©cifiques Ã  cette version.".to_string(),
                        remediation: "Masquer la version exacte (`server_tokens off` / `ServerTokens Prod`).".to_string(),
                    });
                }
            }

            // 4. DÃ©couverte des Endpoints (robots.txt & security.txt) + Cartographie Web & Formulaires
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
                // Sonde rapide sur /api/health si prÃ©sent
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
                category: "CMS / GÃ©nÃ©rateur".to_string(),
                version: extract_version_token(gen),
                source: "Balise <meta name=\"generator\">".to_string(),
                confidence: "Haute (100%)".to_string(),
            });
        }
    }

    // 5. Matrice de Niveau d'Impact & VisibilitÃ©
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
            "Niveau 1 â€¢ Furtif & Empreinte Passive".to_string(),
            "ðŸŸ¢ VisibilitÃ© Minimale (1 rÃ©solution DNS + 1 sonde HEAD)".to_string(),
            "Impact Nul (0 Ã©criture, 0 crawl)".to_string(),
            "~2-3 paquets TCP".to_string(),
        ),
        2 => (
            "Niveau 2 â€¢ Empreinte Services, BanniÃ¨res & Versions".to_string(),
            "ðŸŸ¡ VisibilitÃ© ModÃ©rÃ©e (Handshake TCP + Lecture BanniÃ¨res)".to_string(),
            "Impact TrÃ¨s Faible (Lecture passive des banniÃ¨res)".to_string(),
            "~12-18 paquets TCP".to_string(),
        ),
        3 => (
            "Niveau 3 â€¢ Black-Box Complet & Cartographie Web/Forms".to_string(),
            "ðŸ”´ VisibilitÃ© ComplÃ¨te (Ports + BanniÃ¨res + DOM HTML + Formulaires Â«FormÂ» + robots.txt)".to_string(),
            "Impact ContrÃ´lÃ© (RequÃªtes GET standard en lecture seule)".to_string(),
            "~25-35 paquets TCP/HTTP".to_string(),
        ),
        _ => (
            "Niveau 4 â€¢ Audit d'Exposition (.env, .git, Configs & Specs â€” MasquÃ©)".to_string(),
            "ðŸŸ£ VisibilitÃ© Ã‰levÃ©e (Ports + Web + Â«FormÂ» + Sondes CWE-538 /.env, /.git/HEAD, /docker-compose.yml)".to_string(),
            "Impact DÃ©fensif (VÃ©rification anti-Soft-404 avec masquage strict des valeurs [MASQUÃ‰])".to_string(),
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

    // 7. Construction des 4 FrontiÃ¨res de Confiance (Swimlanes) & Suite de VÃ©rification DÃ©fensive
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
            title: "Zone 1 â€¢ Client & Fichiers (.html/.js)".to_string(),
            subtitle: format!("{} fichier(s) inspectÃ©(s)", files_cnt),
            posture: zone1_posture.to_string(),
            controls: vec![
                format!("CSP : {}", if has_csp { "Active" } else { "Manquante/Partielle" }),
                format!("Anti-Clickjacking : {}", if has_xfo { "Actif" } else { "Manquant" }),
            ],
        },
        TrustZoneSummary {
            zone_id: 2,
            title: "Zone 2 â€¢ EntrÃ©es & Formulaires (Â«FormÂ»)".to_string(),
            subtitle: format!("{} form(s) â€¢ {} champ(s)", forms_count, inputs_count),
            posture: zone2_posture.to_string(),
            controls: vec![
                format!("Validation CSRF : {}", if zone2_posture == "PASS" { "Conforme" } else { "Ã€ renforcer" }),
                format!("Transport Secrets : {}", if scheme == "https" || is_loopback_or_private { "IsolÃ©/TLS" } else { "HTTP Clair" }),
            ],
        },
        TrustZoneSummary {
            zone_id: 3,
            title: "Zone 3 â€¢ Passerelle, Dossiers & API".to_string(),
            subtitle: format!("{} dossier(s) â€¢ {} route(s)", dirs_cnt, routes_count),
            posture: zone3_posture.to_string(),
            controls: vec![
                format!("Isolation CORS : {}", if zone3_posture == "CRITICAL" { "RÃ©flexion !" } else { "Conforme" }),
                format!("HSTS : {}", if has_hsts { "Actif" } else { "Non dÃ©fini" }),
            ],
        },
        TrustZoneSummary {
            zone_id: 4,
            title: "Zone 4 â€¢ Services TCP & Fichiers (.env/.git)".to_string(),
            subtitle: format!("{} port(s) â€¢ {} exposition(s)", open_services_count, exposures_count),
            posture: zone4_posture.to_string(),
            controls: vec![
                format!("Dotfiles CWE-538 : {}", if exposures_count == 0 { "ProtÃ©gÃ©s" } else { "EXPOSÃ‰S !" }),
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
            title: "VÃ©rification de non-rÃ©gression des en-tÃªtes de sÃ©curitÃ© HTTP (CSP, HSTS, XFO, Nosniff)".to_string(),
            category: "Headers & Gouvernance HTTP".to_string(),
            assertion_cmd: format!("curl -sSI \"{}/\" | findstr /I \"Content-Security-Policy X-Content-Type-Options X-Frame-Options Strict-Transport-Security\"", base_url),
            expected_result: "Doit retourner Content-Security-Policy (sans unsafe-inline), X-Content-Type-Options: nosniff et X-Frame-Options: DENY.".to_string(),
            patch_hint: "Axum : tower_http::set_header::SetResponseHeaderLayer | Nginx : add_header Content-Security-Policy \"default-src 'self'\" always;".to_string(),
        },
        DefensiveVerificationCheck {
            id: "VERIFY-CORS-ISOLATION".to_string(),
            title: "Test de non-rÃ©flexion d'origine CORS arbitraire (CWE-942)".to_string(),
            category: "Passerelle API & CORS".to_string(),
            assertion_cmd: format!("curl -sSI -H \"Origin: https://untrusted-verify.example\" \"{}/\" | findstr /I \"Access-Control-Allow-Origin\"", base_url),
            expected_result: "Ne doit JAMAIS reflÃ©ter `https://untrusted-verify.example` ni combiner `*` avec `Access-Control-Allow-Credentials: true`.".to_string(),
            patch_hint: "Remplacer CorsLayer::permissive() par CorsLayer::new().allow_origin([\"http://127.0.0.1:3030\".parse()?])".to_string(),
        },
        DefensiveVerificationCheck {
            id: "VERIFY-DOTFILES-BLOCKED".to_string(),
            title: "VÃ©rification d'inaccessibilitÃ© des fichiers sensibles (/.env et /.git/HEAD â€” CWE-538)".to_string(),
            category: "Module 4 â€¢ Fichiers Sensibles".to_string(),
            assertion_cmd: format!("curl -s -o NUL -w \"%{{http_code}}\" \"{}/.env\" && curl -s -o NUL -w \" %{{http_code}}\" \"{}/.git/HEAD\"", base_url, base_url),
            expected_result: "Codes HTTP attendus : `403` ou `404` (ou Soft-404 HTML sans aucune paire KEY=VALUE ni signature `ref: refs/`).".to_string(),
            patch_hint: "Nginx : location ~ /\\.(?!well-known) { deny all; return 404; } | Ne jamais monter la racine du dÃ©pÃ´t dans ServeDir.".to_string(),
        },
    ];

    // 8. CÃ´tÃ© 1 Boosted : Sondes de Faiblesse de FrontiÃ¨re (Externe Black-Box Non-Destructif)
    let mut boundary_weaknesses = Vec::new();

    // 8.1 Sonde CORS & RÃ©flexion d'Origine (CWE-942)
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
        "EXPOSÃ‰"
    } else if acao_val == "*" {
        "FAIBLESSE"
    } else {
        "ROBUSTE"
    };
    boundary_weaknesses.push(BoundaryWeaknessProbe {
        id: "WEAKNESS-CORS-ORIGIN".to_string(),
        cwe: "CWE-942".to_string(),
        side_one_vector: format!("Header Origin: https://scanner-probe.aetherscope.local âž” {}", base_url),
        category: "CORS & Origine CroisÃ©e".to_string(),
        status: cors_status.to_string(),
        observed_behavior: if acao_val.is_empty() {
            "Aucun en-tÃªte Access-Control-Allow-Origin permissif retournÃ© (Isolation inter-origine stricte).".to_string()
        } else {
            format!("ACA-Origin retournÃ© : `{}` (Credentials : `{}`).", acao_val, if acac_val.is_empty() { "false" } else { &acac_val })
        },
        side_two_ast_target: "Middleware CORS / CorsLayer (Passerelle HTTP)".to_string(),
        negative_test_spec: "Test NÃ©gatif : Envoyer une requÃªte avec `Origin: https://untrusted.invalid` et vÃ©rifier que `Access-Control-Allow-Origin` est absent ou ne reflÃ¨te pas l'origine.".to_string(),
    });

    // 8.2 Sonde Active des Verbes HTTP (OPTIONS â€” CWE-650 / CWE-749)
    let mut allowed_methods_obs = "Sonde OPTIONS non exÃ©cutÃ©e (Niveau 1).".to_string();
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
                methods_status = "EXPOSÃ‰";
            } else if upper_allow.contains("DELETE") || upper_allow.contains("PUT") {
                methods_status = "FAIBLESSE";
            }
            allowed_methods_obs = if allow_h.is_empty() {
                format!("RÃ©ponse OPTIONS : `{}` (Aucun verbe dangereux annoncÃ© dans Allow).", opt_status)
            } else {
                format!("RÃ©ponse OPTIONS : `{}` â€” MÃ©thodes annoncÃ©es : `{}`.", opt_status, allow_h)
            };
        } else {
            allowed_methods_obs = "OPTIONS rejetÃ© ou fermÃ© par le serveur (Surface rÃ©duite).".to_string();
        }
    }
    boundary_weaknesses.push(BoundaryWeaknessProbe {
        id: "WEAKNESS-HTTP-VERBS".to_string(),
        cwe: "CWE-650".to_string(),
        side_one_vector: format!("OPTIONS {}", path),
        category: "Verbes & MÃ©thodes HTTP".to_string(),
        status: methods_status.to_string(),
        observed_behavior: allowed_methods_obs,
        side_two_ast_target: "Routeur HTTP / Table des Routes AST (get/post MethodFilter)".to_string(),
        negative_test_spec: "Test NÃ©gatif : Envoyer une requÃªte `TRACE` ou `DELETE` non authentifiÃ©e sur la route et exiger `405 Method Not Allowed`.".to_string(),
    });

    // 8.3 Sonde d'Attributs de Session & Cookies (CWE-614 / CWE-1004 / CWE-1275)
    let set_cookie_val = raw_headers.get("set-cookie").cloned().unwrap_or_default();
    let (cookie_status, cookie_obs) = if set_cookie_val.is_empty() {
        (
            "ROBUSTE",
            "Aucun cookie de session Ã©mis sur l'entrÃ©e (Architecture sans Ã©tat / Stateless).".to_string(),
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
                    "Cookie dÃ©tectÃ© avec drapeaux incomplets (HttpOnly: {}, SameSite: {}, Secure: {}).",
                    has_httponly, has_samesite, has_secure
                ),
            )
        } else {
            (
                "ROBUSTE",
                "Cookie(s) protÃ©gÃ©(s) par HttpOnly, SameSite et Secure.".to_string(),
            )
        }
    };
    boundary_weaknesses.push(BoundaryWeaknessProbe {
        id: "WEAKNESS-COOKIE-FLAGS".to_string(),
        cwe: "CWE-1004".to_string(),
        side_one_vector: "En-tÃªte HTTP Set-Cookie".to_string(),
        category: "Session & Cookies".to_string(),
        status: cookie_status.to_string(),
        observed_behavior: cookie_obs,
        side_two_ast_target: "Gestionnaire de Session / Auth Cookie Builder".to_string(),
        negative_test_spec: "Test NÃ©gatif : VÃ©rifier que tout en-tÃªte `Set-Cookie` contient `HttpOnly; SameSite=Strict` (et `Secure` en HTTPS).".to_string(),
    });

    // 8.4 Sonde d'Indexation des Dossiers DÃ©couverts (CWE-548 â€” Directory Listing)
    if let Some(ref wd) = web_discovery {
        if let Some(first_dir) = wd.directories.first() {
            let mut dir_status = "ROBUSTE";
            let mut dir_obs = format!(
                "Dossier `{}` rÃ©fÃ©rencÃ© ({}x) sans exposition d'index dÃ©tectÃ©e.",
                first_dir.folder_path, first_dir.call_count
            );
            if scan_level >= 3 && first_dir.folder_path.starts_with('/') {
                if let Some((d_st, _, d_body)) =
                    send_http_probe(&scheme, &host, primary_port, &first_dir.folder_path, "GET").await
                {
                    let lb = d_body.to_lowercase();
                    if lb.contains("index of /") || lb.contains("directory listing for") {
                        dir_status = "EXPOSÃ‰";
                        dir_obs = format!(
                            "Indexation de rÃ©pertoire active (`Index of /`) sur `{}` ({}) !",
                            first_dir.folder_path, d_st
                        );
                    } else {
                        dir_obs = format!(
                            "Sonde GET `{}` âž” `{}` (Aucun Directory Listing `Index of /` exposÃ©).",
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
                    "Test NÃ©gatif : Appeler `{}` et `{}` + `../` et vÃ©rifier l'absence de `Index of /` ainsi qu'un statut 403/404.",
                    first_dir.folder_path, first_dir.folder_path
                ),
            });
        }

        // 8.5 Contrats des Formulaires Â«FormÂ» dÃ©couverts (CWE-352 / CWE-20)
        for f in wd.forms.iter().take(4) {
            let f_status = if f.security_posture == "CRITICAL" {
                "EXPOSÃ‰"
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
                side_one_vector: format!("Form #{} Â«{}Â» [{} {}]", f.index, f.id_or_name, f.method, f.action),
                category: "Contrat Formulaire Â«FormÂ»".to_string(),
                status: f_status.to_string(),
                observed_behavior: format!(
                    "CSRF: {} â€¢ {} champ(s) : {}",
                    if f.has_csrf_token { "PrÃ©sent" } else { "Absent" },
                    f.inputs.len(),
                    if inp_names.is_empty() { "aucun".to_string() } else { inp_names.join(", ") }
                ),
                side_two_ast_target: format!("Handler AST `{}` & Validateur des champs d'entrÃ©e", f.action),
                negative_test_spec: format!(
                    "Test NÃ©gatif : Soumettre `{}` sans jeton CSRF ou avec types invalides sur [{}] et exiger un rejet 400/403/422.",
                    f.action,
                    inp_names.join(", ")
                ),
            });
        }

        // 8.6 Contrats de SchÃ©ma JSON & Routes API extraits des fichiers .js (CWE-20 / CWE-88 / CWE-94)
        for wf in wd.web_files.iter().filter(|w| !w.json_payload_keys.is_empty() || !w.api_and_asset_refs.is_empty()).take(5) {
            let api_refs: Vec<String> = wf
                .api_and_asset_refs
                .iter()
                .filter(|r| r.starts_with("/api/") || r.starts_with("/v1/") || r.starts_with("/auth/"))
                .cloned()
                .collect();
            if !wf.json_payload_keys.is_empty() || !api_refs.is_empty() {
                let keys_preview = if wf.json_payload_keys.is_empty() {
                    "Aucune clÃ© JSON explicite".to_string()
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
                    side_one_vector: format!("Fichier {} âž” {}", wf.path, routes_preview),
                    category: "Contrat API & ClÃ©s JSON".to_string(),
                    status: (if wf.has_sourcemap { "FAIBLESSE" } else { "ROBUSTE" }).to_string(),
                    observed_behavior: format!(
                        "ClÃ©s JSON dÃ©tectÃ©es dans `{}` : [{}]{}.",
                        wf.path,
                        keys_preview,
                        if wf.has_sourcemap { " (SourceMap .map exposÃ©e CWE-540)" } else { "" }
                    ),
                    side_two_ast_target: format!("Struct DTO / Deserializer & Sink AST pour `{}`", routes_preview),
                    negative_test_spec: format!(
                        "Test NÃ©gatif : Envoyer un payload JSON mal typÃ©, vide ou prÃ©fixÃ© par `--` sur les clÃ©s [{}] vers `{}` et vÃ©rifier le rejet strict (400/415/422) avant tout appel systÃ¨me.",
                        keys_preview, routes_preview
                    ),
                });
            }
        }
    }

    // 8.7 Sonde d'Ã‰tanchÃ©itÃ© des Fichiers Sensibles (CWE-538)
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
            status: if exp_list.is_empty() { "ROBUSTE" } else { "EXPOSÃ‰" }.to_string(),
            observed_behavior: if exp_list.is_empty() {
                format!("0/{} fichiers sensibles exposÃ©s (Protection 403/404 et filtrage Anti-Soft-404 validÃ©s).", exposed_artifacts.len())
            } else {
                format!("{} fichier(s) exposÃ©(s) (Valeurs masquÃ©es [MASQUÃ‰]) : {}", exp_list.len(), exp_list.join(", "))
            },
            side_two_ast_target: "Filtre de routage statique / Isolation des dotfiles".to_string(),
            negative_test_spec: "Test NÃ©gatif : RequÃªter `/.env` et `/.git/HEAD` en CI et vÃ©rifier que le statut est 403/404 sans fuite de clÃ©.".to_string(),
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
