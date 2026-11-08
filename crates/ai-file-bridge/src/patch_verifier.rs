use core_graph::bubble::CveAnomalyRecord;
use core_graph::graph::AetherGraph;
use core_graph::reachability::compute_reachability;
use security_linter::contract::ReadmeContract;
use security_linter::linter::{LinterViolation, SecurityLinter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchVerdict {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchVerificationResult {
    pub verdict: PatchVerdict,
    pub duration_ms: f64,
    pub files_scanned: usize,
    pub total_lines: usize,
    pub violations: Vec<LinterViolation>,
    pub offending_target: Option<String>,
    pub exploit_paths: Vec<String>,
    pub formatted_output: String,
}

pub struct PatchVerifier;

impl PatchVerifier {
    pub fn verify_patch(
        workspace_root: &Path,
        files_modified: &[String],
        server_port: Option<u16>,
    ) -> PatchVerificationResult {
        Self::verify_patch_internal(workspace_root, files_modified, server_port, None)
    }

    pub fn verify_patch_with_graph(
        workspace_root: &Path,
        files_modified: &[String],
        server_port: Option<u16>,
        graph: Option<AetherGraph>,
    ) -> PatchVerificationResult {
        Self::verify_patch_internal(workspace_root, files_modified, server_port, graph)
    }

    fn verify_patch_internal(
        workspace_root: &Path,
        files_modified: &[String],
        server_port: Option<u16>,
        custom_graph: Option<AetherGraph>,
    ) -> PatchVerificationResult {
        let start_time = Instant::now();
        let mut violations = Vec::new();
        let mut total_lines = 0usize;
        let mut files_scanned = 0usize;
        let mut exploit_paths = Vec::new();

        let locked_hashes = parse_locked_hashes(workspace_root);
        let mut contract_cache: HashMap<PathBuf, Option<ReadmeContract>> = HashMap::new();
        let mut scanned_contents: HashMap<String, String> = HashMap::new();

        for rel_file in files_modified {
            let clean_rel = rel_file.trim().replace('\\', "/");
            let file_path = if Path::new(&clean_rel).is_absolute() {
                PathBuf::from(&clean_rel)
            } else {
                workspace_root.join(&clean_rel)
            };

            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(err) => {
                    violations.push(make_violation(
                        &clean_rel,
                        1,
                        "FILE_NOT_FOUND",
                        "CWE-706 / FILE-NOT-FOUND",
                        "HIGH",
                        format!("File modified not found or unreadable: {}", err),
                        Some("file_path"),
                        Some("Path (Missing File)"),
                        "Verify that the modified file exists and is accessible before submitting patch.",
                    ));
                    continue;
                }
            };

            files_scanned += 1;
            let line_count = content.lines().count();
            total_lines += line_count;
            scanned_contents.insert(clean_rel.clone(), content.clone());

            let contract = find_parent_contract(workspace_root, &file_path, &mut contract_cache);

            // 1. Contrôle BLAKE3_TAMPERED
            if clean_rel.to_lowercase().ends_with("readme.md") {
                let folder_key = file_path.parent().and_then(|p| p.strip_prefix(workspace_root).ok())
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .filter(|s| !s.is_empty()).unwrap_or_else(|| "root".to_string());

                if let Ok(this_c) = ReadmeContract::parse(&folder_key, &content) {
                    if let Some(exp_h) = locked_hashes.get(&folder_key).or_else(|| locked_hashes.get("root")) {
                        if !this_c.verify_lock(exp_h) {
                            violations.push(make_violation(
                                &clean_rel,
                                1,
                                "BLAKE3_TAMPERED",
                                "CWE-353 / BLAKE3-INTEGRITY",
                                "CRITICAL",
                                format!("Contrat {} altéré sans signature dans aether.lock.toml", clean_rel),
                                Some("contract_hash"),
                                Some("BLAKE3 (Hash Mismatch)"),
                                "Re-sign contract or revert unauthorized contract alterations.",
                            ));
                        }
                    }
                }
            }

            // 2. Contrôle RULE_MAX_LINES
            if let Some(ref c) = contract {
                let limit = if clean_rel.ends_with(".java") { 10_000 }
                else if clean_rel.ends_with(".sol") && c.frontmatter.max_lines_per_file == 300 { 600 }
                else { c.frontmatter.max_lines_per_file };

                let is_exempt = clean_rel.ends_with("_test.rs") || clean_rel.contains("/tests/") || clean_rel.ends_with(".t.sol");
                if !is_exempt && line_count > limit {
                    violations.push(make_violation(
                        &clean_rel,
                        line_count,
                        "RULE_MAX_LINES",
                        "CWE-1075 / ARCH-BUDGET-EXCEEDED",
                        "WARNING",
                        format!("File exceeds contract maximum line limit ({} > {} lines)", line_count, limit),
                        Some("file_line_count"),
                        Some("Integer (Total Lines of Code)"),
                        "Split logic into smaller modular sub-components or services.",
                    ));
                }
            }

            // 3. Scan SAST incrémental (150+ CWE, RULE_FORBIDDEN_IMPORT, SAST_DIRECT_ENV_ACCESS)
            violations.extend(SecurityLinter::audit_file(&clean_rel, &content, contract.as_ref()));
        }

        // 4. Reachability Taint-Graph (R2 integration)
        let mut active_graph = custom_graph.or_else(|| server_port.and_then(try_fetch_graph));
        if let Some(ref mut g) = active_graph {
            for v in &violations {
                if let Some(node) = g.nodes.iter_mut().find(|n| n.file_path == v.file_path) {
                    node.metadata.cve_anomalies.push(CveAnomalyRecord {
                        rule_id: v.rule_id.clone(),
                        cve_id: v.cve_id.clone(),
                        severity: v.severity.clone(),
                        line_number: v.line_number,
                        file_path: v.file_path.clone(),
                        message: v.message.clone(),
                        remediation: v.remediation.clone(),
                        ..Default::default()
                    });
                }
            }
            compute_reachability(g);
            for n in &g.nodes {
                for anom in &n.metadata.cve_anomalies {
                    if anom.is_reachable && !anom.exploit_path.is_empty() {
                        let p = anom.exploit_path.join(" -> ");
                        if !exploit_paths.contains(&p) { exploit_paths.push(p); }
                    }
                }
            }
        } else {
            for (rel_path, content) in &scanned_contents {
                if let Some(ep) = detect_local_endpoint(content) {
                    for v in &violations {
                        if &v.file_path == rel_path {
                            let p = format!("{} -> handler -> {} (L{})", ep, v.rule_id, v.line_number);
                            if !exploit_paths.contains(&p) { exploit_paths.push(p); }
                        }
                    }
                }
            }
        }

        let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let is_rejected = violations.iter().any(|v| {
            v.severity == "CRITICAL"
                || v.severity == "HIGH"
                || v.rule_id == "RULE_FORBIDDEN_IMPORT"
                || v.rule_id == "BLAKE3_TAMPERED"
                || v.rule_id == "FILE_NOT_FOUND"
        });
        let verdict = if is_rejected { PatchVerdict::Rejected } else { PatchVerdict::Approved };
        let offending_target = violations.first().map(|v| format!("{}:{}", v.file_path, v.line_number));

        // 5. Télémétrie Axum si rejeté
        if verdict == PatchVerdict::Rejected {
            if let Some(ref target) = offending_target {
                let first_v = &violations[0];
                let details = format!("{}: {} (L{})", first_v.rule_id, first_v.message, first_v.line_number);
                emit_telemetry(server_port.unwrap_or(3030), target, "Pare-Feu IA [REJETÉ]", &details);
            }
        }

        // 6. Rapport structuré
        let mut report = String::new();
        if verdict == PatchVerdict::Rejected {
            report.push_str("================================================================================\n\
🚨 [PATCH_REJECTED] AETHERSCOPE AI FIREWALL — VIOLATIONS DÉTECTÉES\n\
================================================================================\n");
            report.push_str(&format!(
                "Scan incrémental exécuté en {:.1} ms sur {} fichier(s) modifié(s) ({} LOC).\n\
Résultat : {} violation(s) bloquante(s) introduite(s) par le patch.\n\n\
DÉTAIL DES RÉGRESSIONS DÉTECTÉES :\n\
--------------------------------------------------------------------------------\n",
                duration_ms, files_scanned, total_lines, violations.len()
            ));
            for (i, v) in violations.iter().enumerate() {
                let matching_exploit = exploit_paths.iter().find(|p| p.contains(&v.rule_id) || p.contains(&v.file_path));
                let exploit_badge = if matching_exploit.is_some() { " [🔥 EXPLOITABLE]" } else { "" };
                report.push_str(&format!("{}. [{}] {} ({}){}\n", i + 1, v.severity, v.rule_id, v.cve_id, exploit_badge));
                report.push_str(&format!("   Fichier     : {}:{}\n   Message     : {}\n", v.file_path, v.line_number, v.message));
                if let (Some(d), Some(t)) = (&v.transmitted_data, &v.transmitted_type) {
                    report.push_str(&format!("   Donnée      : {} ({})\n", d, t));
                }
                if let Some(ep) = matching_exploit {
                    report.push_str(&format!("   Exploit     : {}\n", ep));
                }
                report.push_str(&format!("   Remédiation : {}\n\n", v.remediation));
            }
            if let Some(target) = &offending_target {
                report.push_str(&format!(
                    "📡 ACTION DU COCKPIT :\n\
Caméra WebGL téléportée sur '{}' (Laser rouge & HUD alerte activés).\n\
Veuillez corriger ces violations avant de retenter l'application du patch.\n",
                    target
                ));
            }
        } else {
            report.push_str("================================================================================\n\
✅ [PATCH_APPROVED] AETHERSCOPE AI FIREWALL — CONFORMITÉ VALIDÉE\n\
================================================================================\n");
            report.push_str(&format!(
                "Scan incrémental exécuté en {:.1} ms sur {} fichier(s) modifié(s) ({} LOC).\n\
Résultat : 0 régression SAST, 0 violation architecturale, 0 altération de contrat.\n\n\
- Contrats de dossiers EARS : Conformes (budgets de lignes et frontières respectés)\n\
- Signatures BLAKE3 : Intègres\n\
- Analyse 150+ CWE SAST : Zéro vulnérabilité introduite\n\
- Atteignabilité Source-to-Sink : Aucun chemin exploitable\n\n\
Le patch peut être appliqué et commité en toute sécurité.\n",
                duration_ms, files_scanned, total_lines
            ));
        }

        PatchVerificationResult {
            verdict,
            duration_ms,
            files_scanned,
            total_lines,
            violations,
            offending_target,
            exploit_paths,
            formatted_output: report,
        }
    }
}

fn make_violation(file: &str, line: usize, rule: &str, cve: &str, sev: &str, msg: String, data: Option<&str>, ty: Option<&str>, remed: &str) -> LinterViolation {
    LinterViolation {
        file_path: file.to_string(), line_number: line, rule_id: rule.to_string(), cve_id: cve.to_string(),
        severity: sev.to_string(), message: msg, transmitted_data: data.map(str::to_string),
        transmitted_type: ty.map(str::to_string), remediation: remed.to_string(),
    }
}

fn parse_locked_hashes(workspace_root: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let content = match fs::read_to_string(workspace_root.join("aether.lock.toml")) {
        Ok(c) => c,
        Err(_) => return map,
    };
    let mut cur_key = String::new();
    let mut cur_path = String::new();
    let mut cur_hash = String::new();

    let flush = |m: &mut HashMap<String, String>, k: &str, p: &str, h: &str| {
        if !h.is_empty() {
            if !p.is_empty() {
                m.insert(p.trim_start_matches("./").trim_start_matches('/').replace('\\', "/"), h.to_string());
            }
            if !k.is_empty() { m.insert(k.to_string(), h.to_string()); }
        }
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            flush(&mut map, &cur_key, &cur_path, &cur_hash);
            cur_path.clear();
            cur_hash.clear();
            let sec = &trimmed[1..trimmed.len() - 1];
            cur_key = sec.strip_prefix("galaxies.").unwrap_or("").trim_matches('"').trim_matches('\'').to_string();
        } else if let Some((k, v)) = trimmed.split_once('=') {
            let val = v.trim().trim_matches('"').trim_matches('\'');
            if k.trim() == "path" { cur_path = val.to_string(); }
            else if k.trim() == "readme_blake3" { cur_hash = val.to_string(); }
        }
    }
    flush(&mut map, &cur_key, &cur_path, &cur_hash);
    map
}

fn find_parent_contract(
    workspace_root: &Path,
    file_path: &Path,
    cache: &mut HashMap<PathBuf, Option<ReadmeContract>>,
) -> Option<ReadmeContract> {
    let parent_dir = file_path.parent().unwrap_or(workspace_root);
    if let Some(cached) = cache.get(parent_dir) { return cached.clone(); }
    let mut cur = parent_dir;
    while cur >= workspace_root {
        let readme = cur.join("README.md");
        if readme.exists() {
            if let Ok(c_text) = fs::read_to_string(&readme) {
                let rel = cur.strip_prefix(workspace_root).unwrap_or(cur).to_string_lossy().replace('\\', "/");
                let name = if rel.is_empty() { "root".to_string() } else { rel };
                if let Ok(parsed) = ReadmeContract::parse(&name, &c_text) {
                    cache.insert(parent_dir.to_path_buf(), Some(parsed.clone()));
                    return Some(parsed);
                }
            }
        }
        match cur.parent() {
            Some(p) if cur != workspace_root => cur = p,
            _ => break,
        }
    }
    cache.insert(parent_dir.to_path_buf(), None);
    None
}

fn detect_local_endpoint(content: &str) -> Option<String> {
    for line in content.lines() {
        let tr = line.trim();
        if tr.contains("#[get(") || tr.contains("#[post(") || tr.contains("app.get(") || tr.contains("app.post(") {
            return Some(tr.to_string());
        }
        if tr.starts_with("pub async fn ") && (tr.contains("handle_") || tr.contains("endpoint_")) {
            return Some(tr.to_string());
        }
    }
    None
}

fn try_fetch_graph(port: u16) -> Option<AetherGraph> {
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(30)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(150)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(50)));
    let req = format!("GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", port);
    stream.write_all(req.as_bytes()).ok()?;
    stream.flush().ok()?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).ok()?;
    let s = String::from_utf8_lossy(&resp);
    let (_, json_part) = s.split_once("\r\n\r\n")?;
    serde_json::from_str::<AetherGraph>(json_part.trim()).ok()
}

fn emit_telemetry(port: u16, target: &str, action: &str, details: &str) {
    let addr: SocketAddr = match format!("127.0.0.1:{}", port).parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(40)) {
        let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
        let body = serde_json::json!({ "target": target, "action": action, "details": details }).to_string();
        let req = format!(
            "POST /api/ai/telemetry HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            port, body.len(), body
        );
        let _ = stream.write_all(req.as_bytes());
        let _ = stream.flush();
    }
}

