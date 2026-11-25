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

pub(crate) fn extract_version_label(raw: &str) -> Option<String> {
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
                    detected_version = extract_version_label(&first_line);
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
            "-L",
            "--max-redirs",
            "4",
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
    let host_hdr = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };

    for include_foreign_origin in [true, false] {
        let Ok(Ok(mut stream)) = timeout(Duration::from_millis(1100), TcpStream::connect(&addr)).await else {
            return None;
        };
        let origin_line = if include_foreign_origin {
            "Origin: https://scanner-probe.aetherscope.local\r\n"
        } else {
            ""
        };
        let req_str = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: AetherScope-SurfaceAuditor/2.0 (Defensive Posture Check)\r\n{}Accept: text/html,application/xhtml+xml,application/json,*/*\r\nConnection: close\r\n\r\n",
            method, path, host_hdr, origin_line
        );

        timeout(Duration::from_millis(700), stream.write_all(req_str.as_bytes()))
            .await
            .ok()
            .and_then(|r| r.ok())?;

        let mut full_buf = Vec::with_capacity(65536);
        let mut chunk = [0u8; 32768];
        let read_start = Instant::now();
        while full_buf.len() < 3_500_000 && read_start.elapsed() < Duration::from_millis(2800) {
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
        if let Some((status, hdrs, body)) = parse_raw_http_response(&raw_resp) {
            if include_foreign_origin && status.contains(" 403 ") {
                continue;
            }
            if (status.contains(" 301 ")
                || status.contains(" 302 ")
                || status.contains(" 303 ")
                || status.contains(" 307 ")
                || status.contains(" 308 "))
                && body.trim().len() < 256
            {
                if let Some(loc) = hdrs.get("location") {
                    let loc_trim = loc.trim();
                    if loc_trim.starts_with("https://") || loc_trim.starts_with("http://") {
                        let mut cmd = tokio::process::Command::new("curl");
                        cmd.args([
                            "-sSi",
                            "-L",
                            "--max-redirs",
                            "4",
                            "-k",
                            "-m",
                            "4",
                            "-X",
                            method,
                            "-H",
                            "User-Agent: AetherScope-SurfaceAuditor/2.0 (Defensive Posture Check)",
                            "--",
                            loc_trim,
                        ]);
                        #[cfg(windows)]
                        {
                            cmd.creation_flags(0x08000000);
                        }
                        if let Ok(Ok(out)) = timeout(Duration::from_millis(4200), cmd.output()).await {
                            if !out.stdout.is_empty() {
                                let redir_raw = String::from_utf8_lossy(&out.stdout).to_string();
                                if let Some(parsed) = parse_raw_http_response(&redir_raw) {
                                    return Some(parsed);
                                }
                            }
                        }
                    }
                }
            }
            return Some((status, hdrs, body));
        }
    }
    None
}

pub(crate) fn parse_raw_http_response(raw_resp: &str) -> Option<(String, HashMap<String, String>, String)> {
    let mut current = raw_resp;
    for _ in 0..5 {
        let (header_block, rest, sep_len) = match current.find("\r\n\r\n") {
            Some(idx) => (
                current.get(..idx).unwrap_or(current),
                current.get(idx + 4..).unwrap_or(""),
                4usize,
            ),
            None => match current.find("\n\n") {
                Some(idx) => (
                    current.get(..idx).unwrap_or(current),
                    current.get(idx + 2..).unwrap_or(""),
                    2usize,
                ),
                None => (current, "", 0usize),
            },
        };
        let first_line = header_block.lines().next().unwrap_or("").trim();
        let is_redirect_or_continue = first_line.contains(" 100 ")
            || first_line.contains(" 301 ")
            || first_line.contains(" 302 ")
            || first_line.contains(" 303 ")
            || first_line.contains(" 307 ")
            || first_line.contains(" 308 ");
        if sep_len > 0 && is_redirect_or_continue && rest.trim_start().starts_with("HTTP/") {
            current = rest.trim_start();
            continue;
        }
        break;
    }

    let (header_block, body_block) = match current.find("\r\n\r\n") {
        Some(idx) => (
            current.get(..idx).unwrap_or(current),
            current.get(idx + 4..).unwrap_or(""),
        ),
        None => match current.find("\n\n") {
            Some(idx) => (
                current.get(..idx).unwrap_or(current),
                current.get(idx + 2..).unwrap_or(""),
            ),
            None => (current, ""),
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
    let lower = tag_html.to_ascii_lowercase();
    let attr_low = attr_name.to_ascii_lowercase();
    let is_word_boundary = |idx: usize| -> bool {
        if idx == 0 {
            return true;
        }
        lower
            .get(idx - 1..idx)
            .and_then(|s| s.chars().next())
            .map(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            .unwrap_or(true)
    };

    for (pat, end_delim) in [
        (format!("{}=\"", attr_low), "\""),
        (format!("{}='", attr_low), "'"),
        (format!("{}=\\\"", attr_low), "\\\""),
        (format!("{} = \"", attr_low), "\""),
        (format!("{} = '", attr_low), "'"),
    ] {
        let mut search_from = 0usize;
        while let Some(rel_idx) = lower.get(search_from..).and_then(|s| s.find(&pat)) {
            let start_idx = search_from + rel_idx;
            if is_word_boundary(start_idx) {
                let val_start = start_idx + pat.len();
                if let Some(after) = tag_html.get(val_start..) {
                    if let Some(end_idx) = after.find(end_delim) {
                        let val = after.get(..end_idx).unwrap_or("").trim();
                        if !val.is_empty() && !val.starts_with("${") {
                            return Some(val.replace('\n', " ").replace('\r', ""));
                        }
                    }
                }
            }
            search_from = start_idx + pat.len();
        }
    }

    // Support des attributs HTML minifies sans guillemets (ex: <form action=/login method=post>)
    let unquoted_pat = format!("{}=", attr_low);
    let mut search_from = 0usize;
    while let Some(rel_idx) = lower.get(search_from..).and_then(|s| s.find(&unquoted_pat)) {
        let start_idx = search_from + rel_idx;
        if is_word_boundary(start_idx) {
            let val_start = start_idx + unquoted_pat.len();
            if let Some(after) = tag_html.get(val_start..) {
                let first_ch = after.chars().next().unwrap_or(' ');
                if !matches!(first_ch, '"' | '\'' | '\\' | ' ' | '>') {
                    let end_idx = after
                        .find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
                        .unwrap_or(after.len());
                    let val = after.get(..end_idx).unwrap_or("").trim();
                    if !val.is_empty() && !val.starts_with("${") {
                        return Some(val.to_string());
                    }
                }
            }
        }
        search_from = start_idx + unquoted_pat.len();
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
        let ver = extract_version_label(srv).or_else(|| Some(srv.clone()));
        push_tech(srv, "Serveur Web", ver, "Header HTTP Server", "Haute (100%)");
    }
    if let Some(xpb) = headers.get("x-powered-by") {
        let ver = extract_version_label(xpb).or_else(|| Some(xpb.clone()));
        push_tech(xpb, "Framework / Runtime", ver, "Header X-Powered-By", "Haute (100%)");
    }
    if headers.contains_key("cf-ray") || headers.get("server").map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false) {
        push_tech("Cloudflare CDN / WAF", "CDN / Reverse-Proxy", None, "Header CF-Ray / Server", "Haute (100%)");
    }
    if headers.contains_key("x-vercel-id") {
        push_tech("Vercel Edge Network", "CDN / Reverse-Proxy", None, "Header X-Vercel-Id", "Haute (100%)");
    }
    if let Some(via) = headers.get("via") {
        push_tech(via, "CDN / Reverse-Proxy", extract_version_label(via), "Header Via", "Haute (95%)");
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

pub(crate) fn classify_html_input(name: &str, itype: &str) -> (String, bool, bool, bool) {
    let name_low = name.to_lowercase();
    let is_csrf = name_low.contains("csrf")
        || name_low.contains("_token")
        || name_low.contains("xsrf")
        || name_low.contains("authenticity_token")
        || name_low.contains("nonce");
    let is_password = itype == "password" || name_low.contains("pass") || name_low.contains("pwd");
    let is_file = itype == "file";

    let classification = if is_csrf {
        "🛡️ Jeton Anti-CSRF"
    } else if is_password || name_low.contains("secret") || name_low.contains("api_key") {
        "🔑 Secret / Authentification"
    } else if is_file {
        "📂 Upload de Fichier"
    } else if itype == "email" || name_low.contains("user") || name_low.contains("login") {
        "👤 Identifiant / Email"
    } else if name_low.contains("domaine")
        || name_low.contains("ip:port")
        || name_low.contains("url")
        || name_low.contains("path")
        || name_low.contains("chemin")
        || name_low.contains("dir")
    {
        "🧭 Cible / Path / URL"
    } else if name_low.contains("prompt")
        || name_low.contains("consigne")
        || name_low.contains("analyse")
        || name_low.contains("cwe")
    {
        "🤖 Prompt / Filtre SAST & IA"
    } else if itype == "hidden" {
        "🔒 Paramètre Caché (Hidden)"
    } else if itype == "select" || itype == "checkbox" || itype == "range" || itype == "number" {
        "🎛️ Sélecteur / Paramètre UI"
    } else {
        "📝 Entrée Utilisateur"
    }
    .to_string();

    (classification, is_csrf, is_password, is_file)
}

pub(crate) fn group_standalone_spa_forms(
    standalone_inputs: Vec<DiscoveredInput>,
    start_idx: usize,
    routes: &mut Vec<DiscoveredRoute>,
) -> Vec<DiscoveredForm> {
    let mut scanner_inputs = Vec::new();
    let mut forge_inputs = Vec::new();
    let mut task_inputs = Vec::new();
    let mut ai_inputs = Vec::new();
    let mut gov_inputs = Vec::new();
    let mut search_inputs = Vec::new();
    let mut generic_inputs = Vec::new();

    for inp in standalone_inputs {
        let nl = inp.name.to_lowercase();
        if nl.contains("domaine") || nl.contains("ip:port") || nl.contains("ports +") || nl.contains("surface") {
            scanner_inputs.push(inp);
        } else if nl.contains("forge-") || nl.contains("cf-") || nl.contains("neohotel") || nl.contains("auth_guard") {
            forge_inputs.push(inp);
        } else if nl.contains("task-")
            || nl.contains("tâche")
            || nl.contains("tache")
            || nl.contains("symbole cible")
            || nl.contains("fichier cible")
            || nl.contains("spécifications ears")
        {
            task_inputs.push(inp);
        } else if nl.contains("ai-") || nl.contains("consigne") || nl.contains("demander une analyse") || nl.contains("rule_max_lines") {
            ai_inputs.push(inp);
        } else if nl.contains("inspector-max-lines")
            || nl.contains("blake3-")
            || nl.contains("crates/*")
            || nl.contains("tests/*")
            || nl.contains("scope")
        {
            gov_inputs.push(inp);
        } else if nl.contains("hub-project-path") || nl.contains("rechercher") || nl.contains("filtrer") || nl.contains("continuum") {
            search_inputs.push(inp);
        } else {
            generic_inputs.push(inp);
        }
    }

    let mut out = Vec::new();
    let mut idx = start_idx;
    let groups = [
        (
            "Formulaire Scanner de Surface & Ports (SPA)",
            "POST",
            "/api/surface_scan",
            scanner_inputs,
        ),
        (
            "Formulaire Forge & Création Projet/Fichier (SPA)",
            "POST",
            "/api/scaffold_project",
            forge_inputs,
        ),
        (
            "Formulaire Gestion des Tâches & Kanban (SPA)",
            "POST",
            "/api/tasks/update",
            task_inputs,
        ),
        (
            "Formulaire Copilote IA & Prompt Studio (SPA)",
            "POST",
            "/api/ai/chat",
            ai_inputs,
        ),
        (
            "Formulaire Contrats EARS, Gouvernance & Vault (SPA)",
            "POST",
            "/api/update_contract",
            gov_inputs,
        ),
        (
            "Formulaire Workspace, Recherche & Filtres AST (SPA)",
            "POST / GET",
            "/api/analyze",
            search_inputs,
        ),
        (
            "Formulaire Dynamique HTML / Contrôles SPA",
            "POST / FETCH",
            "/api/*",
            generic_inputs,
        ),
    ];

    for (title, method, action, list) in groups {
        if list.is_empty() {
            continue;
        }
        if !routes.iter().any(|r| r.path == action) && action != "/api/*" {
            routes.push(DiscoveredRoute {
                path: action.to_string(),
                method: method.to_string(),
                source: format!("Form SPA «{}»", title),
                status: None,
            });
        }
        out.push(DiscoveredForm {
            index: idx,
            id_or_name: title.to_string(),
            method: method.to_string(),
            action: action.to_string(),
            enctype: Some("application/json (fetch/XHR)".to_string()),
            has_csrf_token: true,
            has_password_field: list.iter().any(|i| i.input_type == "password"),
            has_file_upload: list.iter().any(|i| i.input_type == "file"),
            inputs: list,
            security_posture: "PASS".to_string(),
            security_notes: vec![format!(
                "Formulaire SPA extrait du code source HTML/DOM ➔ soumission JSON vers `{}` (`{}`).",
                action, method
            )],
        });
        idx += 1;
    }

    out
}

pub(crate) fn extract_html_links_and_anchors(
    body: &str,
    lower_body: &str,
    routes: &mut Vec<DiscoveredRoute>,
) -> Vec<DiscoveredHtmlLink> {
    let mut links: Vec<DiscoveredHtmlLink> = Vec::new();
    let mut push_link = |kind: &str, target: &str, resolved_path: &str, tag_context: &str, label: &str| {
        if target.is_empty() || target.len() > 140 || links.len() >= 80 {
            return;
        }
        if !links.iter().any(|l| l.target == target && l.kind == kind) {
            links.push(DiscoveredHtmlLink {
                kind: kind.to_string(),
                target: target.to_string(),
                resolved_path: resolved_path.to_string(),
                tag_context: tag_context.to_string(),
                label: label.to_string(),
            });
        }
    };

    for (tag_pat, attr_name, ctx_label) in [
        ("<a ", "href", "<a href>"),
        ("<area ", "href", "<area href>"),
        ("<link", "href", "<link href>"),
        ("<iframe", "src", "<iframe src>"),
        ("<img ", "src", "<img src>"),
        ("<form", "action", "<form action>"),
    ] {
        let mut pos = 0usize;
        while let Some(rel) = lower_body.get(pos..).and_then(|s| s.find(tag_pat)) {
            let start = pos + rel;
            let Some(end_rel) = lower_body.get(start..).and_then(|s| s.find('>')) else {
                break;
            };
            if end_rel <= 420 {
                let tag = body.get(start..=start + end_rel).unwrap_or("");
                if let Some(val) = extract_attr(tag, attr_name) {
                    if val.starts_with('#') && val.len() > 1 {
                        let res_path = format!("/{}", val);
                        push_link(
                            "#LINK / ANCRE DOM",
                            &val,
                            &res_path,
                            ctx_label,
                            &format!("Lien d'ancre HTML {}", val),
                        );
                        if routes.len() < 65 && !routes.iter().any(|r| r.path == val || r.path == res_path) {
                            routes.push(DiscoveredRoute {
                                path: val.clone(),
                                method: "ANCHOR (#)".to_string(),
                                source: format!("HTML {}", ctx_label),
                                status: None,
                            });
                        }
                    } else if val.starts_with("http://")
                        || val.starts_with("https://")
                        || val.starts_with("ws://")
                        || val.starts_with("wss://")
                    {
                        push_link("URL EXTERNE", &val, &val, ctx_label, &format!("URL {}", ctx_label));
                    } else if !val.starts_with("javascript:")
                        && !val.starts_with("data:")
                        && !val.starts_with("mailto:")
                    {
                        let norm = if val.starts_with('/') {
                            val.clone()
                        } else {
                            format!("/{}", val.trim_start_matches("./"))
                        };
                        let kind = if tag_pat == "<link" || tag_pat == "<img " {
                            "ASSET / RESSOURCE"
                        } else {
                            "LIEN HTML / PATH"
                        };
                        push_link(kind, &val, &norm, ctx_label, &format!("Ressource HTML {}", norm));
                        if (tag_pat == "<a " || tag_pat == "<iframe" || tag_pat == "<link")
                            && routes.len() < 65
                            && !routes.iter().any(|r| r.path == norm)
                        {
                            routes.push(DiscoveredRoute {
                                path: norm,
                                method: "GET".to_string(),
                                source: format!("HTML {}", ctx_label),
                                status: None,
                            });
                        }
                    }
                }
            }
            pos = start + end_rel + 1;
        }
    }

    for pat in ["id=\"", "id='", "id=\\\""] {
        let mut pos = 0usize;
        while let Some(rel) = lower_body.get(pos..).and_then(|s| s.find(pat)) {
            let start = pos + rel;
            let val_start = start + pat.len();
            let end_delim = if pat.ends_with("\\\"") {
                "\\\""
            } else if pat.ends_with('\'') {
                "'"
            } else {
                "\""
            };
            if let Some(after) = body.get(val_start..body.len().min(val_start + 80)) {
                if let Some(end_idx) = after.find(end_delim) {
                    let id_val = after.get(..end_idx).unwrap_or("").trim();
                    let is_valid_id = id_val.len() >= 2
                        && id_val.len() <= 48
                        && id_val.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        && !id_val.starts_with("uml-arrow")
                        && !id_val.starts_with("bounty-arrow");
                    if is_valid_id {
                        let hash_target = format!("#{}", id_val);
                        let res_path = format!("/#{}", id_val);
                        push_link(
                            "#LINK / ANCRE DOM",
                            &hash_target,
                            &res_path,
                            "DOM id=\"...\"",
                            &format!("Ancre cible DOM #{}", id_val),
                        );
                    }
                    pos = val_start + end_idx + 1;
                    continue;
                }
            }
            pos = val_start + 1;
        }
    }

    for token in body.split(['\'', '"', '`', ' ', '\n', '\r', '(', ')', '<', '>']) {
        let t = token.trim().trim_end_matches([',', ';', '.']);
        if (t.starts_with("http://") || t.starts_with("https://") || t.starts_with("ws://") || t.starts_with("wss://"))
            && t.len() >= 10
            && t.len() <= 120
        {
            if t.contains("w3.org/") || t.contains("svelte.dev/e/") || t.contains("rolldown.rs/") {
                continue;
            }
            let cleaned = if let Some(interp) = t.find("${") {
                format!("{}/{}", t.get(..interp).unwrap_or(t).trim_end_matches('/'), "*")
            } else {
                t.to_string()
            };
            push_link(
                "URL EXTERNE",
                &cleaned,
                &cleaned,
                "HTML / Script URL",
                "URL détectée dans la source HTML/JS",
            );
        } else if (t.starts_with("#/")
            || (t.starts_with('#')
                && t.len() >= 3
                && t.len() <= 36
                && t.get(1..)
                    .unwrap_or("")
                    .chars()
                    .all(|c| c.is_ascii_alphabetic() || c == '-' || c == '_')))
            && !t.starts_with("#0")
            && !t.starts_with("#1")
            && !t.starts_with("#2")
            && !t.starts_with("#3")
            && !t.starts_with("#4")
            && !t.starts_with("#5")
            && !t.starts_with("#6")
            && !t.starts_with("#7")
            && !t.starts_with("#8")
            && !t.starts_with("#9")
            && !t.starts_with("#f")
            && !t.starts_with("#e")
            && !t.starts_with("#d")
            && !t.starts_with("#c")
            && !t.starts_with("#b")
            && !t.starts_with("#a")
        {
            let res_path = format!("/{}", t);
            push_link("#LINK / ANCRE DOM", t, &res_path, "HTML / SPA #link", "Fragment / Route #link");
        }
    }

    links
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
    let lower_body = body.to_ascii_lowercase();

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
    let mut form_ranges: Vec<(usize, usize)> = Vec::new();
    let mut form_pos = 0usize;
    let mut form_idx = 1usize;

    while let Some(f_rel) = lower_body.get(form_pos..).and_then(|s| s.find("<form")) {
        let f_start = form_pos + f_rel;
        let next_ch = lower_body
            .get(f_start + 5..f_start + 6)
            .and_then(|s| s.chars().next())
            .unwrap_or(' ');
        if !matches!(next_ch, ' ' | '>' | '\t' | '\n' | '\r' | '/') {
            form_pos = f_start + 5;
            continue;
        }
        let tag_end = match lower_body.get(f_start..).and_then(|s| s.find('>')) {
            Some(te) if te <= 500 => f_start + te,
            _ => {
                form_pos = f_start + 5;
                continue;
            }
        };
        let form_open_tag = body.get(f_start..=tag_end).unwrap_or("");
        let next_form_bound = lower_body
            .get(tag_end + 1..)
            .and_then(|s| s.find("<form"))
            .map(|nf| tag_end + 1 + nf)
            .unwrap_or_else(|| body.len().min(tag_end + 25000));
        let f_close = lower_body
            .get(tag_end + 1..)
            .and_then(|s| s.find("</form>"))
            .map(|c| (tag_end + 1 + c).min(next_form_bound))
            .unwrap_or(next_form_bound);

        let form_inner = body.get(tag_end + 1..f_close).unwrap_or("");
        let form_inner_lower = form_inner.to_ascii_lowercase();

        let explicit_action = extract_attr(form_open_tag, "action")
            .or_else(|| extract_attr(form_open_tag, "data-action"));
        let explicit_method = extract_attr(form_open_tag, "method")
            .or_else(|| extract_attr(form_open_tag, "data-method"));
        let id_or_name = extract_attr(form_open_tag, "id")
            .or_else(|| extract_attr(form_open_tag, "name"))
            .or_else(|| extract_attr(form_open_tag, "title"))
            .or_else(|| extract_attr(form_open_tag, "aria-label"))
            .or_else(|| extract_attr(form_open_tag, "data-testid"))
            .unwrap_or_else(|| format!("form_{}", form_idx));
        let action = explicit_action.clone().unwrap_or_else(|| {
            let low_title = id_or_name.to_lowercase();
            if low_title.contains("workspace") || low_title.contains("chemin") || low_title.contains("url") {
                "/api/analyze".to_string()
            } else if low_title.contains("search") || low_title.contains("recherch") {
                "/search".to_string()
            } else if low_title.contains("login") || low_title.contains("auth") {
                "/auth/login".to_string()
            } else {
                "/".to_string()
            }
        });
        let method = explicit_method
            .map(|m| m.to_uppercase())
            .unwrap_or_else(|| {
                if explicit_action.is_none() && action.starts_with("/api/") {
                    "POST (SPA Submit)".to_string()
                } else {
                    "GET".to_string()
                }
            });
        let enctype = extract_attr(form_open_tag, "enctype");

        let mut inputs = Vec::new();
        let mut has_csrf_token = false;
        let mut has_password_field = false;
        let mut has_file_upload = false;

        // Parcourir les balises <input, <textarea, <select, <button dans le corps du formulaire
        for (tag_prefix, tag_label) in [
            ("<input", "input"),
            ("<textarea", "textarea"),
            ("<select", "select"),
            ("<button", "button"),
        ] {
            let mut ipos = 0usize;
            while let Some(irel) = form_inner_lower.get(ipos..).and_then(|s| s.find(tag_prefix)) {
                let istart = ipos + irel;
                if let Some(iend_rel) = form_inner_lower.get(istart..).and_then(|s| s.find('>')) {
                    let itag = form_inner.get(istart..=istart + iend_rel).unwrap_or("");
                    let itype = extract_attr(itag, "type")
                        .unwrap_or_else(|| {
                            if tag_label == "button" {
                                "submit".to_string()
                            } else {
                                tag_label.to_string()
                            }
                        })
                        .to_lowercase();
                    if tag_label == "button" && itype == "button" && extract_attr(itag, "name").is_none() {
                        ipos = istart + iend_rel + 1;
                        continue;
                    }
                    let iname = extract_attr(itag, "name")
                        .or_else(|| extract_attr(itag, "id"))
                        .or_else(|| extract_attr(itag, "placeholder"))
                        .or_else(|| extract_attr(itag, "aria-label"))
                        .or_else(|| extract_attr(itag, "title"))
                        .or_else(|| extract_attr(itag, "data-testid"))
                        .or_else(|| extract_attr(itag, "formcontrolname"))
                        .or_else(|| extract_attr(itag, "v-model"))
                        .or_else(|| extract_attr(itag, "value"))
                        .unwrap_or_else(|| format!("{}_{}", tag_label, inputs.len() + 1));
                    let required = itag.to_ascii_lowercase().contains("required");

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

        if inputs.is_empty() && explicit_action.is_none() && form_open_tag.trim().len() <= 7 {
            form_pos = tag_end + 1;
            continue;
        }
        form_ranges.push((f_start, f_close));

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

    let mut standalone_inputs = Vec::new();
    for (tag_prefix, tag_label) in [("<input", "input"), ("<textarea", "textarea"), ("<select", "select")] {
        let mut ipos = 0usize;
        while let Some(irel) = lower_body.get(ipos..).and_then(|s| s.find(tag_prefix)) {
            let istart = ipos + irel;
            let next_ch = lower_body
                .get(istart + tag_prefix.len()..istart + tag_prefix.len() + 1)
                .and_then(|s| s.chars().next())
                .unwrap_or(' ');
            if !matches!(next_ch, ' ' | '>' | '\t' | '\n' | '\r' | '/') {
                ipos = istart + tag_prefix.len();
                continue;
            }
            let in_existing_form = form_ranges.iter().any(|&(s, e)| istart >= s && istart <= e);
            if let Some(iend_rel) = lower_body.get(istart..).and_then(|s| s.find('>')) {
                if !in_existing_form && iend_rel <= 480 {
                    let itag = body.get(istart..=istart + iend_rel).unwrap_or("");
                    let itag_low = itag.to_ascii_lowercase();
                    let is_readonly = itag_low.contains("readonly");
                    let itype = extract_attr(itag, "type")
                        .unwrap_or_else(|| tag_label.to_string())
                        .to_lowercase();
                    let explicit_ident = extract_attr(itag, "id")
                        .or_else(|| extract_attr(itag, "name"))
                        .or_else(|| extract_attr(itag, "placeholder"))
                        .or_else(|| extract_attr(itag, "aria-label"))
                        .or_else(|| extract_attr(itag, "title"))
                        .or_else(|| extract_attr(itag, "data-testid"))
                        .or_else(|| extract_attr(itag, "formcontrolname"))
                        .or_else(|| extract_attr(itag, "v-model"))
                        .or_else(|| extract_attr(itag, "autocomplete"))
                        .or_else(|| {
                            if tag_label == "select"
                                || tag_label == "textarea"
                                || matches!(
                                    itype.as_str(),
                                    "text"
                                        | "search"
                                        | "email"
                                        | "password"
                                        | "number"
                                        | "file"
                                        | "url"
                                        | "tel"
                                        | "date"
                                        | "range"
                                )
                            {
                                let min_v = extract_attr(itag, "min").unwrap_or_default();
                                let max_v = extract_attr(itag, "max").unwrap_or_default();
                                if !min_v.is_empty() || !max_v.is_empty() {
                                    Some(format!("{} [{} {}..{}]", tag_label, itype, min_v, max_v))
                                } else {
                                    Some(format!("{} [{} #{}]", tag_label, itype, standalone_inputs.len() + 1))
                                }
                            } else {
                                None
                            }
                        });

                    if !is_readonly {
                        if let Some(iname) = explicit_ident {
                            if !standalone_inputs.iter().any(|i: &DiscoveredInput| i.name == iname)
                                && standalone_inputs.len() < 70
                            {
                                let (classification, _, _, _) = classify_html_input(&iname, &itype);
                                standalone_inputs.push(DiscoveredInput {
                                    name: iname,
                                    input_type: itype,
                                    tag: format!("{} (HTML/SPA)", tag_label),
                                    required: itag_low.contains("required"),
                                    classification,
                                });
                            }
                        }
                    }
                }
                ipos = istart + iend_rel + 1;
            } else {
                break;
            }
        }
    }

    if !standalone_inputs.is_empty() {
        let spa_forms = group_standalone_spa_forms(standalone_inputs, form_idx, &mut routes);
        forms.extend(spa_forms);
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
                if (href.starts_with('/') || href.starts_with("http")) && !href.starts_with("//") && routes.len() < 30
                    && !routes.iter().any(|r| r.path == href) {
                        routes.push(DiscoveredRoute {
                            path: href,
                            method: "GET".to_string(),
                            source: "HTML <a href>".to_string(),
                            status: None,
                        });
                    }
            }
            apos = astart + aend_rel + 1;
        } else {
            break;
        }
    }

    // Extraction des routes /api/... mentionnées dans le HTML/JS (y compris interpolations ${...}/api/...)
    for token in body.split(['\'', '"', '`']) {
        if let Some(clean_route) = normalize_route_token(token) {
            if (clean_route.starts_with("/api/")
                || clean_route.starts_with("/v1/")
                || clean_route.starts_with("/v2/")
                || clean_route.starts_with("/graphql")
                || clean_route.starts_with("/auth/")
                || clean_route.starts_with("/ws"))
                && routes.len() < 45
                && !routes.iter().any(|r| r.path == clean_route)
            {
                let method = infer_http_method(body, &clean_route);
                routes.push(DiscoveredRoute {
                    path: clean_route,
                    method,
                    source: "HTML / Script ➔ Fetch API".to_string(),
                    status: None,
                });
            }
        }
    }

    let html_links = extract_html_links_and_anchors(body, &lower_body, &mut routes);

    for rob in &robots_entries {
        if routes.len() < 65 && !routes.iter().any(|r| &r.path == rob) {
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
            html_links,
            path_tree: Vec::new(),
        },
        findings,
    )
}

pub(crate) fn normalize_route_token(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    if let Some(after_interp) = t.strip_prefix("${") {
        if let Some(close_idx) = after_interp.find('}') {
            t = after_interp.get(close_idx + 1..).unwrap_or("");
        }
    }
    if let Some(q_idx) = t.find('?') {
        t = t.get(..q_idx).unwrap_or(t);
    }
    if let Some(d_idx) = t.find("${") {
        t = t.get(..d_idx).unwrap_or(t);
    }
    let clean = t.trim().trim_end_matches('/');
    if clean.len() < 2
        || clean.len() > 88
        || clean.contains([' ', '\n', '\r', '<', '>', '{', '}', ';', '(', ')'])
    {
        return None;
    }
    Some(clean.to_string())
}

pub(crate) fn infer_http_method(content: &str, route_path: &str) -> String {
    if route_path.contains("graphql") {
        return "POST (GraphQL)".to_string();
    }
    if route_path.starts_with("/ws") {
        return "WS / WSS".to_string();
    }

    let mut saw_fetch = false;
    for (pos, _) in content.match_indices(route_path).take(12) {
        let pre_start = pos.saturating_sub(90);
        let pre_raw = content.get(pre_start..pos).unwrap_or("");
        let pre_stmt = match pre_raw.rfind(';') {
            Some(sc) => pre_raw.get(sc + 1..).unwrap_or(pre_raw),
            None => pre_raw,
        }
        .to_lowercase();

        let post_end = content.len().min(pos + route_path.len() + 180);
        let post_raw = content.get(pos + route_path.len()..post_end).unwrap_or("");
        let post_stmt = match post_raw.find(';') {
            Some(sc) => post_raw.get(..sc).unwrap_or(post_raw),
            None => post_raw,
        }
        .to_lowercase();

        if pre_stmt.contains(".post(")
            || post_stmt.contains("'post'")
            || post_stmt.contains("\"post\"")
            || post_stmt.contains("method:\"post\"")
            || post_stmt.contains("method: \"post\"")
            || post_stmt.contains("method:'post'")
        {
            return "POST".to_string();
        }
        if pre_stmt.contains(".delete(")
            || post_stmt.contains("'delete'")
            || post_stmt.contains("\"delete\"")
            || post_stmt.contains("method:\"delete\"")
        {
            return "DELETE".to_string();
        }
        if pre_stmt.contains(".put(")
            || post_stmt.contains("'put'")
            || post_stmt.contains("\"put\"")
            || post_stmt.contains("method:\"put\"")
        {
            return "PUT".to_string();
        }
        if pre_stmt.contains(".patch(")
            || post_stmt.contains("'patch'")
            || post_stmt.contains("\"patch\"")
            || post_stmt.contains("method:\"patch\"")
        {
            return "PATCH".to_string();
        }
        if pre_stmt.contains("fetch(") || pre_stmt.contains("axios") {
            saw_fetch = true;
        }
    }

    let rl = route_path.to_lowercase();
    if rl.ends_with("/analyze")
        || rl.ends_with("/surface_scan")
        || rl.ends_with("/update")
        || rl.ends_with("/update_contract")
        || rl.ends_with("/create_file")
        || rl.ends_with("/scaffold_project")
        || rl.ends_with("/save")
        || rl.ends_with("/sync")
        || rl.ends_with("/import")
        || rl.ends_with("/restore")
        || rl.ends_with("/apply")
        || rl.ends_with("/select")
        || rl.ends_with("/launch_cli")
        || rl.ends_with("/cancel")
        || rl.ends_with("/new_session")
        || rl.ends_with("/chat")
        || rl.ends_with("/clear")
        || rl.ends_with("/verify")
        || rl.ends_with("/fix")
    {
        return "POST".to_string();
    }

    if saw_fetch {
        "GET (Fetch)".to_string()
    } else {
        "GET / API".to_string()
    }
}

pub(crate) fn extract_calls_from_asset(content: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut folders = Vec::new();
    let mut refs = Vec::new();
    let mut json_keys = Vec::new();

    for token in content.split(['\'', '"', '`', '(', ')']) {
        let Some(t) = normalize_route_token(token) else {
            continue;
        };
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
                t
            } else if let Some(stripped) = t.strip_prefix("./") {
                format!("/{}", stripped)
            } else {
                format!("/{}", t)
            };
            if refs.len() < 28 && !refs.contains(&norm) {
                refs.push(norm.clone());
            }
            if let Some(last_slash) = norm.rfind('/') {
                if last_slash > 0 {
                    if let Some(dir_slice) = norm.get(..=last_slash) {
                        let dir_str = dir_slice.to_string();
                        if folders.len() < 20 && !folders.contains(&dir_str) {
                            folders.push(dir_str);
                        }
                    }
                }
            }
        }
    }

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
                        && json_keys.len() < 20
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

pub(crate) fn build_html_path_tree(disc: &WebArchitectureDiscovery) -> Vec<DiscoveredPathNode> {
    let mut tree: Vec<DiscoveredPathNode> = Vec::new();
    let mut push_node = |path: &str, node_type: &str, method: &str, source_ref: &str| {
        if path.is_empty() || tree.len() >= 90 {
            return;
        }
        if tree.iter().any(|n| n.path == path && n.node_type == node_type) {
            return;
        }
        let parent_dir = if path.starts_with("http://")
            || path.starts_with("https://")
            || path.starts_with("ws://")
            || path.starts_with("wss://")
        {
            "🌐 URLs Externes://".to_string()
        } else if path.starts_with('#') || path.starts_with("/#") {
            "/#anchors/".to_string()
        } else if let Some(last_slash) = path.rfind('/') {
            if last_slash > 0 {
                path.get(..=last_slash).unwrap_or("/").to_string()
            } else {
                "/".to_string()
            }
        } else {
            "/".to_string()
        };

        tree.push(DiscoveredPathNode {
            path: path.to_string(),
            parent_dir,
            node_type: node_type.to_string(),
            method: method.to_string(),
            source_ref: source_ref.to_string(),
        });
    };

    for f in &disc.forms {
        push_node(
            &f.action,
            "FORM ACTION",
            &f.method,
            &format!("Form #{} «{}» ({} champ(s))", f.index, f.id_or_name, f.inputs.len()),
        );
    }

    for wf in &disc.web_files {
        push_node(&wf.path, "SOURCE / BUNDLE", "GET", &format!("Fichier {}", wf.file_type));
    }

    for r in &disc.routes {
        let ntype = if r.path.starts_with('#') || r.method.contains("ANCHOR") {
            "#LINK / ANCRE"
        } else if r.path.starts_with("/api/")
            || r.path.starts_with("/v1/")
            || r.path.starts_with("/v2/")
            || r.path.starts_with("/graphql")
        {
            "API ENDPOINT"
        } else {
            "HTML ROUTE / PATH"
        };
        push_node(&r.path, ntype, &r.method, &r.source);
    }

    for hl in &disc.html_links {
        let (ntype, mth) = match hl.kind.as_str() {
            "#LINK / ANCRE DOM" => ("#LINK / ANCRE", "ANCHOR (#)"),
            "URL EXTERNE" => ("EXTERNAL URL", "EXTERNAL"),
            "ASSET / RESSOURCE" => ("ASSET", "GET"),
            _ => ("HTML LINK / PATH", "GET"),
        };
        push_node(&hl.resolved_path, ntype, mth, &format!("{} ({})", hl.tag_context, hl.label));
    }

    tree
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

    // 1. Analyser le fichier d'entrée HTML lui-même
    let entry_label = if entry_path == "/" { "/index.html (Entrée)" } else { entry_path };
    let (entry_folders, entry_refs, entry_json_keys) = extract_calls_from_asset(entry_body);
    for f in &entry_folders {
        record_dir(f, entry_label);
    }

    // Extraire aussi les feuilles CSS <link href="..."> du HTML
    let lower_html = entry_body.to_ascii_lowercase();
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

    // 1b. Extraire les bundles <script type="module"> / <script> inline (> 256 octets) liés à la source HTML
    let mut inl_pos = 0usize;
    let mut inl_idx = 1usize;
    while let Some(s_rel) = lower_html.get(inl_pos..).and_then(|s| s.find("<script")) {
        let s_start = inl_pos + s_rel;
        let Some(tag_end_rel) = lower_html.get(s_start..).and_then(|s| s.find('>')) else {
            break;
        };
        let tag_end = s_start + tag_end_rel;
        let open_tag = entry_body.get(s_start..=tag_end).unwrap_or("");
        let s_close = lower_html
            .get(tag_end + 1..)
            .and_then(|s| s.find("</script>"))
            .map(|c| tag_end + 1 + c)
            .unwrap_or(tag_end + 1);
        if extract_attr(open_tag, "src").is_none() && s_close > tag_end + 256 && inl_idx <= 5 {
            let script_body = entry_body.get(tag_end + 1..s_close).unwrap_or("");
            let (m_folders, m_refs, m_keys) = extract_calls_from_asset(script_body);
            let mod_path = format!("{}#module-{}.js", entry_path.trim_end_matches('/'), inl_idx);
            for mf in &m_folders {
                record_dir(mf, &mod_path);
            }
            web_files.push(DiscoveredWebFile {
                path: mod_path,
                file_type: "ES-MODULE".to_string(),
                http_status: "200 Inline DOM".to_string(),
                size_bytes: script_body.len(),
                folder_calls: m_folders,
                api_and_asset_refs: m_refs,
                json_payload_keys: m_keys,
                has_sourcemap: script_body.contains("sourceMappingURL="),
            });
            inl_idx += 1;
        }
        inl_pos = s_close + 1;
    }

    // 2. Inspecter chaque fichier local découvert (.js, .css, .html, .json) pour extraire ses appels d'API et de dossiers
    for (file_path, file_type) in candidate_local_files.into_iter().take(6) {
        if let Some((st_line, _fhdrs, fbody)) = send_http_probe(scheme, host, port, &file_path, "GET").await {
            let is_200 = st_line.contains(" 200 ");
            let (ffolders, frefs, fjson_keys) = if is_200 {
                extract_calls_from_asset(&fbody)
            } else {
                (Vec::new(), Vec::new(), Vec::new())
            };

            if is_200 && (file_type == "JS" || file_type == "HTML") {
                let empty_hdrs = HashMap::new();
                let (sub_disc, sub_findings) = parse_html_architecture_and_forms(
                    &fbody,
                    &empty_hdrs,
                    scheme,
                    true,
                    Vec::new(),
                    disc.security_txt_present,
                );
                for mut sf in sub_disc.forms {
                    if disc.forms.len() < 18 && !disc.forms.iter().any(|ef| ef.id_or_name == sf.id_or_name && ef.action == sf.action) {
                        sf.index = disc.forms.len() + 1;
                        sf.id_or_name = format!("{} [{}]", sf.id_or_name, file_path);
                        disc.forms.push(sf);
                    }
                }
                for hl in sub_disc.html_links {
                    if disc.html_links.len() < 80 && !disc.html_links.iter().any(|el| el.target == hl.target) {
                        disc.html_links.push(hl);
                    }
                }
                findings.extend(sub_findings);
            }

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

            // Ajouter les endpoints /api/* découverts dans le fichier JS/HTML à la carte des routes avec leur type de requête
            for rf in &frefs {
                if (rf.starts_with("/api/")
                    || rf.starts_with("/v1/")
                    || rf.starts_with("/v2/")
                    || rf.starts_with("/graphql")
                    || rf.starts_with("/auth/")
                    || rf.starts_with("/ws"))
                    && disc.routes.len() < 45
                    && !disc.routes.iter().any(|r| &r.path == rf)
                {
                    let req_method = infer_http_method(&fbody, rf);
                    disc.routes.push(DiscoveredRoute {
                        path: rf.clone(),
                        method: req_method,
                        source: format!("{} ➔ Fichier {} ({})", entry_label, file_type, file_path),
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

    for hl in &disc.html_links {
        if hl.kind == "#LINK / ANCRE DOM" {
            record_dir("/#anchors/", entry_label);
        } else if hl.resolved_path.starts_with('/') {
            if let Some(last_slash) = hl.resolved_path.rfind('/') {
                if last_slash > 0 {
                    if let Some(dir_slice) = hl.resolved_path.get(..=last_slash) {
                        record_dir(dir_slice, entry_label);
                    }
                } else {
                    record_dir("/", entry_label);
                }
            }
        }
    }

    let mut directories: Vec<DiscoveredDirectory> = dir_map
        .into_iter()
        .map(|(folder_path, (source_files, call_count))| {
            let classification = if folder_path.contains("/#") {
                "#️⃣ Ancres DOM & Fragments (#link)".to_string()
            } else {
                classify_directory(&folder_path).to_string()
            };
            DiscoveredDirectory {
                folder_path,
                source_files,
                call_count,
                classification,
            }
        })
        .collect();
    directories.sort_by(|a, b| b.call_count.cmp(&a.call_count).then_with(|| a.folder_path.cmp(&b.folder_path)));

    // Synthetiser egalement les surfaces de soumission JSON/POST decouvertes dans les bundles JS mais non couvertes par un <form>
    let all_json_keys: Vec<String> = web_files
        .iter()
        .flat_map(|wf| wf.json_payload_keys.iter().cloned())
        .collect();
    for r in &disc.routes {
        let m_up = r.method.to_uppercase();
        if (m_up.contains("POST") || m_up.contains("PUT") || m_up.contains("PATCH") || m_up.contains("DELETE"))
            && r.path.starts_with('/')
            && disc.forms.len() < 16
            && !disc.forms.iter().any(|f| f.action == r.path)
        {
            let route_seg = r
                .path
                .split('/')
                .filter(|s| !s.is_empty() && *s != "api")
                .collect::<Vec<_>>()
                .join("_");
            let mut matched_inputs = Vec::new();
            for jk in &all_json_keys {
                let jk_low = jk.to_lowercase();
                if ((route_seg.len() >= 3 && (jk_low.contains(&route_seg) || route_seg.contains(&jk_low)))
                    || matched_inputs.len() < 4)
                    && !matched_inputs.iter().any(|i: &DiscoveredInput| &i.name == jk) && matched_inputs.len() < 6 {
                        let (classification, _, _, _) = classify_html_input(jk, "json");
                        matched_inputs.push(DiscoveredInput {
                            name: jk.clone(),
                            input_type: "json_field".to_string(),
                            tag: "fetch/JSON (JS)".to_string(),
                            required: true,
                            classification,
                        });
                    }
            }
            let next_idx = disc.forms.len() + 1;
            disc.forms.push(DiscoveredForm {
                index: next_idx,
                id_or_name: format!("Requete API «{}» ({})", r.path, r.source),
                method: r.method.clone(),
                action: r.path.clone(),
                enctype: Some("application/json (fetch/XHR)".to_string()),
                has_csrf_token: true,
                has_password_field: matched_inputs
                    .iter()
                    .any(|i| i.name.contains("pass") || i.name.contains("token") || i.name.contains("secret")),
                has_file_upload: false,
                inputs: matched_inputs,
                security_posture: "PASS".to_string(),
                security_notes: vec![format!(
                    "Surface d'appel `{}` detectee dans `{}` avec payload JSON vers `{}`.",
                    r.method, r.source, r.path
                )],
            });
        }
    }

    disc.web_files = web_files;
    disc.directories = directories;
    disc.path_tree = build_html_path_tree(disc);
}

pub(crate) async fn probe_sensitive_artifacts(
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
                } else if (path == "/openapi.json" || path == "/swagger.json")
                    && (lower_body.contains("\"openapi\"") || lower_body.contains("\"swagger\"")) && lower_body.contains("\"paths\"") {
                        confirmed_exposed = true;
                        redacted_preview = Some("Schéma JSON OpenAPI / Swagger public détecté".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_surface_route_normalization_and_method_inference() {
        assert_eq!(
            normalize_route_token("${this.baseUrl}/api/surface_scan"),
            Some("/api/surface_scan".to_string())
        );
        assert_eq!(
            normalize_route_token("/api/file_content?path=${encodeURIComponent(p)}"),
            Some("/api/file_content".to_string())
        );

        let js_code = r#"
            await fetch(`${this.baseUrl}/api/surface_scan`, { method: 'POST', body: JSON.stringify({ target, scan_level }) });
            await fetch(`${this.baseUrl}/api/ai/telemetry`, { method: 'DELETE' });
            await fetch(`${this.baseUrl}/api/graph`);
        "#;
        assert_eq!(infer_http_method(js_code, "/api/surface_scan"), "POST");
        assert_eq!(infer_http_method(js_code, "/api/ai/telemetry"), "DELETE");
        assert_eq!(infer_http_method(js_code, "/api/graph"), "GET (Fetch)");

        let (folders, refs, keys) = extract_calls_from_asset(js_code);
        assert!(folders.contains(&"/api/".to_string()));
        assert!(folders.contains(&"/api/ai/".to_string()));
        assert!(refs.contains(&"/api/surface_scan".to_string()));
        assert!(keys.contains(&"target".to_string()));
        assert!(keys.contains(&"scan_level".to_string()));
    }
}


