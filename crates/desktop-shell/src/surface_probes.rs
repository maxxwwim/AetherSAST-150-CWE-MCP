use super::*;
pub(crate) fn parse_target_input(raw: &str) -> (String, String, u16, String) {
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

pub(crate) fn classify_ip(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                "Loopback / Localhost (127.0.0.0/8)"
            } else if v4.is_private() {
                "RÃ©seau PrivÃ© Interne (RFC 1918)"
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

pub(crate) fn port_service_info(port: u16) -> (&'static str, &'static str, &'static str) {
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

pub(crate) fn extract_version_token(raw: &str) -> Option<String> {
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

pub(crate) async fn probe_single_port(host: String, port: u16, grab_banner: bool) -> PortProbeResult {
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
        // Pour les ports HTTP, envoyer un HEAD lÃ©ger afin d'extraire la banniÃ¨re Server / X-Powered-By
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

pub(crate) async fn send_http_probe(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    method: &str,
) -> Option<(String, HashMap<String, String>, String)> {
    // Si HTTPS (ou port 443/8443), utiliser curl en mode passif sÃ©curisÃ© pour gÃ©rer le handshake TLS
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

pub(crate) fn parse_raw_http_response(raw_resp: &str) -> Option<(String, HashMap<String, String>, String)> {
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

pub(crate) fn extract_attr(tag_html: &str, attr_name: &str) -> Option<String> {
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

pub(crate) fn fingerprint_technologies(
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
                push_tech(&p.service, "Service RÃ©seau TCP", Some(ver.clone()), &format!("Port TCP :{}", p.port), "Haute (95%)");
            }
        }
    }

    stack
}

pub(crate) fn parse_html_architecture_and_forms(
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
                        "ðŸ›¡ï¸ Jeton Anti-CSRF"
                    } else if itype == "password" || name_low.contains("pass") || name_low.contains("secret") || name_low.contains("token") {
                        "ðŸ”‘ Secret / Authentification"
                    } else if itype == "file" {
                        "ðŸ“‚ Upload de Fichier"
                    } else if itype == "email" || name_low.contains("user") || name_low.contains("login") {
                        "ðŸ‘¤ Identifiant / Email"
                    } else if itype == "hidden" {
                        "ðŸ”’ ParamÃ¨tre CachÃ© (Hidden)"
                    } else {
                        "ðŸ“ EntrÃ©e Utilisateur"
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
            security_notes.push("Absence de champ anti-CSRF dÃ©tectÃ© dans le formulaire POST (CWE-352).".to_string());
            findings.push(SurfaceFinding {
                id: format!("SURFACE-FORM-MISSING-CSRF-{}", form_idx),
                cwe: "CWE-352 / FORM-MISSING-CSRF-TOKEN".to_string(),
                severity: "MEDIUM".to_string(),
                category: "Architecture Web & Formulaires".to_string(),
                title: format!("Formulaire POST `{}` (`{}`) sans jeton anti-CSRF apparent", id_or_name, action),
                description: format!(
                    "Le formulaire `{}` soumet {} champ(s) en POST vers `{}` sans champ CSRF (`_token`, `csrf_token`). S'il s'appuie sur des cookies de session sans SameSite=Strict, il est exposÃ© au CSRF.",
                    id_or_name, inputs.len(), action
                ),
                remediation: "Injecter un jeton anti-CSRF alÃ©atoire par session ou imposer l'authentification par en-tÃªte Authorization / SameSite=Strict.".to_string(),
            });
        }

        if has_password_field && method == "GET" {
            posture = "CRITICAL".to_string();
            security_notes.push("CRITIQUE : Champ mot de passe transmis via mÃ©thode GET (exposÃ© dans l'URL et les logs) !".to_string());
            findings.push(SurfaceFinding {
                id: format!("SURFACE-FORM-PASSWORD-IN-GET-{}", form_idx),
                cwe: "CWE-598 / PASSWORD-TRANSMITTED-IN-GET-QUERY".to_string(),
                severity: "HIGH".to_string(),
                category: "Architecture Web & Formulaires".to_string(),
                title: format!("Formulaire `{}` transmettant un mot de passe via GET", id_or_name),
                description: "Un champ de type `password` est envoyÃ© avec `method=\"GET\"`, exposant le secret en clair dans la barre d'adresse, l'historique navigateur et les journaux d'accÃ¨s HTTP.".to_string(),
                remediation: "Forcer `method=\"POST\"` sur tout formulaire contenant des identifiants ou secrets.".to_string(),
            });
        }

        if has_password_field && scheme == "http" && !is_loopback {
            posture = "CRITICAL".to_string();
            security_notes.push("CRITIQUE : Formulaire d'authentification servi sur HTTP non chiffrÃ©.".to_string());
            findings.push(SurfaceFinding {
                id: format!("SURFACE-FORM-CLEARTEXT-AUTH-{}", form_idx),
                cwe: "CWE-319 / CLEARTEXT-TRANSMISSION-OF-CREDENTIALS".to_string(),
                severity: "CRITICAL".to_string(),
                category: "Architecture Web & Formulaires".to_string(),
                title: format!("Formulaire avec mot de passe (`{}`) servi en HTTP non chiffrÃ©", id_or_name),
                description: "Les identifiants saisis dans ce formulaire sont transmis sans chiffrement TLS sur le rÃ©seau.".to_string(),
                remediation: "Forcer la redirection HTTPS (301) et activer HSTS avant d'afficher tout formulaire d'authentification.".to_string(),
            });
        }

        if has_file_upload {
            security_notes.push("Surface d'Upload de Fichier dÃ©tectÃ©e : vÃ©rifier le filtrage MIME, l'absence de wrapper phar:// et le stockage hors webroot (CWE-434).".to_string());
        }

        routes.push(DiscoveredRoute {
            path: action.clone(),
            method: method.clone(),
            source: format!("Form Action Â«{}Â»", id_or_name),
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

    // 4. DÃ©couverte des Inputs autonomes (SPA / WebGL / React sans balise <form> englobante)
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
                            "ðŸŽ›ï¸ Toggle / Option UI".to_string()
                        } else {
                            "âš¡ Champ SPA / API".to_string()
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
                id_or_name: "Interface SPA / ContrÃ´les Dynamiques (fetch/XHR)".to_string(),
                method: "POST / FETCH".to_string(),
                action: "/api/*".to_string(),
                enctype: Some("application/json".to_string()),
                has_csrf_token: true,
                has_password_field: false,
                has_file_upload: false,
                inputs: spa_inputs,
                security_posture: "PASS".to_string(),
                security_notes: vec!["Application SPA : les entrÃ©es sont transmises en JSON via fetch() vers les routes /api/*.".to_string()],
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
                            title: format!("Script tiers chargÃ© sans hachage d'intÃ©gritÃ© SRI (`{}`)", src),
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

    // Extraction des routes /api/... mentionnÃ©es dans le HTML/JS
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
                    source: "RÃ©fÃ©rence API / Fetch".to_string(),
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

pub(crate) fn extract_calls_from_asset(content: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut folders = Vec::new();
    let mut refs = Vec::new();
    let mut json_keys = Vec::new();

    for token in content.split(['\'', '"', '`', '(', ')']) {
        let t = token.trim();
        if t.len() < 2 || t.len() > 96 || t.contains(' ') || t.contains('\n') || t.contains('<') || t.contains('>') {
            continue;
        }
        // DÃ©tection de fichiers (.html, .js, .css, .json, .php, .wasm) ou endpoints (/api/..., /v1/..., /auth/...)
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

    // Extraire les clÃ©s de payload JSON autour de JSON.stringify({ ... }) dans les fichiers JS
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

pub(crate) fn classify_directory(dir: &str) -> &'static str {
    let dl = dir.to_lowercase();
    if dl.contains("/api") || dl.contains("/v1") || dl.contains("/v2") || dl.contains("/graphql") || dl.contains("/rpc") {
        "âš¡ API & Endpoints Backend"
    } else if dl.contains("/admin") || dl.contains("/internal") || dl.contains("/config") || dl.contains("/debug") || dl.contains("/.well-known") {
        "ðŸ” Administration & Gouvernance"
    } else if dl.contains("/upload") || dl.contains("/media") || dl.contains("/files") || dl.contains("/storage") {
        "ðŸ“‚ Stockage & Uploads"
    } else if dl.contains("/asset") || dl.contains("/static") || dl.contains("/js") || dl.contains("/css") || dl.contains("/dist") || dl.contains("/public") {
        "ðŸ“¦ Assets & Bundles Frontend"
    } else {
        "ðŸ“ RÃ©pertoire Application"
    }
}

pub(crate) async fn inspect_web_files_and_directories(
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

    // 1. Analyser le fichier d'entrÃ©e HTML lui-mÃªme
    let entry_label = if entry_path == "/" { "/index.html (EntrÃ©e)" } else { entry_path };
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

    // 2. Inspecter chaque fichier local dÃ©couvert (.js, .css, .html, .json) pour extraire ses appels d'API et de dossiers
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

            // Ajouter les endpoints /api/* dÃ©couverts dans le fichier JS/HTML Ã  la carte des routes
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
                    title: format!("Directive SourceMap dÃ©tectÃ©e dans `{}`", file_path),
                    description: format!(
                        "Le script `{}` rÃ©fÃ©rence une SourceMap (`//# sourceMappingURL=`). En production, cela permet de reconstruire l'arborescence source originale.",
                        file_path
                    ),
                    remediation: "DÃ©sactiver la gÃ©nÃ©ration ou restreindre l'accÃ¨s aux fichiers `.js.map` en production.".to_string(),
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

pub(crate) async fn probe_sensitive_artifacts(
    scheme: &str,
    host: &str,
    port: u16,
) -> (Vec<ExposedArtifactProbe>, Vec<SurfaceFinding>) {
    let mut results = Vec::new();
    let mut findings = Vec::new();

    // Liste dÃ©fensive d'artefacts sensibles de racine Web (CWE-538 / CWE-215)
    let candidates: [(&str, &str, &str, &str, &str); 8] = [
        (
            "/.env",
            "Fichier d'environnement (.env)",
            "Configuration & Secrets",
            "CRITICAL",
            "Bloquer l'accÃ¨s aux dotfiles (`location ~ /\\. { deny all; }`) et dÃ©placer `.env` hors du document root.",
        ),
        (
            "/.env.local",
            "Environnement local (.env.local)",
            "Configuration & Secrets",
            "CRITICAL",
            "Retirer `.env.local` du rÃ©pertoire public et rÃ©voquer tout jeton potentiellement exposÃ©.",
        ),
        (
            "/.git/HEAD",
            "Index Git exposÃ© (.git/HEAD)",
            "DÃ©pÃ´t VCS ExposÃ©",
            "CRITICAL",
            "Supprimer le dossier `.git` des artefacts de dÃ©ploiement ou interdire `/.git` au niveau du reverse-proxy.",
        ),
        (
            "/docker-compose.yml",
            "Manifeste Docker Compose",
            "Infrastructure & Conteneurs",
            "HIGH",
            "Ne jamais servir les fichiers d'orchestration YAML dans le rÃ©pertoire statique.",
        ),
        (
            "/actuator/health",
            "Spring Boot Actuator",
            "TÃ©lÃ©mÃ©trie & Debug",
            "MEDIUM",
            "Isoler les endpoints `/actuator/*` sur un port d'administration interne.",
        ),
        (
            "/server-status",
            "Apache mod_status",
            "TÃ©lÃ©mÃ©trie & Debug",
            "HIGH",
            "Restreindre `/server-status` Ã  `127.0.0.1` via `Require local`.",
        ),
        (
            "/openapi.json",
            "SpÃ©cification OpenAPI (JSON)",
            "Documentation API",
            "INFO",
            "VÃ©rifier que la publication du schÃ©ma OpenAPI est intentionnelle en production.",
        ),
        (
            "/swagger.json",
            "SpÃ©cification Swagger (JSON)",
            "Documentation API",
            "INFO",
            "ProtÃ©ger Swagger UI / swagger.json par authentification si l'API est privÃ©e.",
        ),
    ];

    for (path, label, category, risk, remediation) in candidates {
        if let Some((status_line, hdrs, body)) = send_http_probe(scheme, host, port, path, "GET").await {
            let is_200 = status_line.contains(" 200 ");
            let lower_body = body.trim().to_lowercase();
            let content_type = hdrs.get("content-type").cloned().unwrap_or_default().to_lowercase();

            // Filtrage anti-Soft-404 (Ã©vite les faux positifs sur les SPA qui renvoient index.html en 200 OK)
            let is_html_fallback = lower_body.starts_with("<!doctype")
                || lower_body.starts_with("<html")
                || content_type.contains("text/html") && !path.contains("server-status");

            let mut confirmed_exposed = false;
            let mut redacted_preview = None;

            if is_200 && !is_html_fallback {
                if path.starts_with("/.env") {
                    // VÃ©rifier la prÃ©sence de paires KEY=VALUE et masquer strictement toutes les valeurs (aucune exfiltration)
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
                                masked_keys.push(format!("{}=******** [MASQUÃ‰]", key));
                            }
                        }
                    }
                    if !masked_keys.is_empty() {
                        confirmed_exposed = true;
                        let preview_list = masked_keys.into_iter().take(5).collect::<Vec<_>>().join(", ");
                        redacted_preview = Some(format!(
                            "ClÃ©s dÃ©tectÃ©es (valeurs strictement masquÃ©es) : {}",
                            preview_list
                        ));
                    }
                } else if path == "/.git/HEAD" {
                    if lower_body.starts_with("ref: refs/") || (body.trim().len() == 40 && body.trim().chars().all(|c| c.is_ascii_hexdigit())) {
                        confirmed_exposed = true;
                        let first_line = body.lines().next().unwrap_or("ref: refs/heads/*").trim();
                        redacted_preview = Some(format!(
                            "Signature Git HEAD confirmÃ©e : `{}` (Contenu du dÃ©pÃ´t non tÃ©lÃ©chargÃ©)",
                            first_line.chars().take(48).collect::<String>()
                        ));
                    }
                } else if path == "/docker-compose.yml" {
                    if lower_body.contains("services:") && (lower_body.contains("image:") || lower_body.contains("build:")) {
                        confirmed_exposed = true;
                        redacted_preview = Some("Structure YAML `services:` dÃ©tectÃ©e (valeurs d'environnement masquÃ©es)".to_string());
                    }
                } else if path == "/actuator/health" {
                    if lower_body.contains("\"status\"") && (lower_body.contains("\"up\"") || lower_body.contains("\"down\"")) {
                        confirmed_exposed = true;
                        redacted_preview = Some("RÃ©ponse JSON Spring Actuator `{ \"status\": ... }` active".to_string());
                    }
                } else if path == "/server-status" {
                    if lower_body.contains("apache server status") || lower_body.contains("server version:") {
                        confirmed_exposed = true;
                        redacted_preview = Some("Page de tÃ©lÃ©mÃ©trie Apache `mod_status` accessible publiquement".to_string());
                    }
                } else if path == "/openapi.json" || path == "/swagger.json" {
                    if (lower_body.contains("\"openapi\"") || lower_body.contains("\"swagger\"")) && lower_body.contains("\"paths\"") {
                        confirmed_exposed = true;
                        redacted_preview = Some("SchÃ©ma JSON OpenAPI / Swagger public dÃ©tectÃ©".to_string());
                    }
                }
            }

            if confirmed_exposed && risk != "INFO" {
                findings.push(SurfaceFinding {
                    id: format!("SURFACE-EXPOSED-ARTIFACT-{}", path.replace(['/', '.'], "").to_uppercase()),
                    cwe: "CWE-538 / SENSITIVE-FILE-EXPOSURE".to_string(),
                    severity: risk.to_string(),
                    category: "Module 4 â€¢ Fichiers Sensibles (.env / .git)".to_string(),
                    title: format!("Exposition critique dÃ©tectÃ©e sur `{}` ({})", path, label),
                    description: format!(
                        "L'endpoint `{}` est publiquement accessible ({}) et expose une signature structurelle valide ({}). Par sÃ©curitÃ©, AetherScope masque automatiquement toutes les valeurs secrÃ¨tes.",
                        path,
                        status_line,
                        redacted_preview.as_deref().unwrap_or("signature confirmÃ©e")
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
                    format!("{} (EXPOSÃ‰)", status_line)
                } else if is_200 && is_html_fallback {
                    "200 Soft-404 (ProtÃ©gÃ© / Fallback SPA)".to_string()
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
                http_status: "FermÃ© / Non accessible".to_string(),
                risk_level: risk.to_string(),
                redacted_preview: None,
                remediation: remediation.to_string(),
            });
        }
    }

    (results, findings)
}

