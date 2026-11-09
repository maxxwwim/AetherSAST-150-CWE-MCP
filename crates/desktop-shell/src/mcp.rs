#[path = "mcp_catalog.rs"]
mod mcp_catalog;
pub use mcp_catalog::*;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[allow(dead_code)]
pub(crate) struct JsonRpcRequest {
    pub(crate) jsonrpc: String,
    pub(crate) id: Option<Value>,
    pub(crate) method: String,
    pub(crate) params: Option<Value>,
}

#[derive(Serialize)]
pub(crate) struct JsonRpcResponse {
    pub(crate) jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<Value>,
}

pub fn check_server_listening(port: u16) -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    if let Ok(addr) = format!("127.0.0.1:{}", port).parse::<SocketAddr>() {
        TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
    } else {
        false
    }
}

pub async fn run_mcp_stdio_loop(port: u16, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim().trim_start_matches('\u{feff}');
        if trimmed.is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err_res = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(json!({ "code": -32700, "message": format!("Parse error: {}", e) })),
                };
                let _ = writeln!(stdout, "{}", serde_json::to_string(&err_res).unwrap_or_default());
                let _ = stdout.flush();
                continue;
            }
        };

        let resp = handle_mcp_request(req, port, path).await;
        if let Some(res) = resp {
            let _ = writeln!(stdout, "{}", serde_json::to_string(&res).unwrap_or_default());
            let _ = stdout.flush();
        }
    }

    Ok(())
}

pub(crate) async fn handle_mcp_request(req: JsonRpcRequest, server_port: u16, default_path: &str) -> Option<JsonRpcResponse> {
    if let Some(res) = handle_catalog_request(&req, server_port, default_path).await {
        return res;
    }
    let id = req.id;
    match req.method.as_str() {
        "initialize" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": false },
                    "resources": { "subscribe": false, "listChanged": false },
                    "prompts": { "listChanged": false },
                    "logging": {}
                },
                "serverInfo": {
                    "name": "aetherscope-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        }),
        "notifications/initialized" => None,
        "ping" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({})),
            error: None,
        }),
        "tools/call" => {
            let params = req.params.unwrap_or(json!({}));
            let raw_tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            // Normalisation des commandes combinÃ©es (et alias rÃ©trocompatibles)
            let tool_name = match raw_tool_name {
                "aetherscope_manage_tasks" => {
                    match arguments.get("action").and_then(|v| v.as_str()).unwrap_or("list") {
                        "create" => "aetherscope_create_task",
                        "update" => "aetherscope_update_task",
                        _ => "aetherscope_list_tasks",
                    }
                }
                "aetherscope_chat" => {
                    let act = arguments.get("action").and_then(|v| v.as_str()).unwrap_or_else(|| {
                        if arguments.get("text").and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false) {
                            "send"
                        } else {
                            "history"
                        }
                    });
                    if act == "history" {
                        "aetherscope_get_chat_history"
                    } else {
                        "aetherscope_send_chat_message"
                    }
                }
                "aetherscope_manage_plugins" => {
                    match arguments.get("action").and_then(|v| v.as_str()).unwrap_or("list") {
                        "test" => "aetherscope_test_plugins",
                        "scan" => "aetherscope_scan_with_plugins",
                        "upsert" => "aetherscope_upsert_plugin_rule",
                        _ => "aetherscope_list_plugins",
                    }
                }
                other => other,
            };

            let (result_content, is_error) = match tool_name {
                "aetherscope_teleport_camera" => {
                    let target = arguments.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let action = arguments.get("action").and_then(|v| v.as_str()).unwrap_or("Inspection").to_string();
                    let details = arguments.get("details").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    let res = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                        "target": target,
                        "action": action,
                        "details": details
                    }))).await;

                    match res {
                        Ok(_) => (json!([{
                            "type": "text",
                            "text": format!("ðŸª CamÃ©ra AetherScope alignÃ©e sur : {} ({})\nðŸ“¡ Faisceau quantique et fil d'Ariane stellaire illuminÃ©s sur le graphe 3D WebGL 2.", target, action)
                        }]), false),
                        Err(e) => (json!([{
                            "type": "text",
                            "text": format!("âš ï¸ TÃ©lÃ©mÃ©trie enregistrÃ©e : [{}] sur {}\n(DÃ©tails : {})", action, target, e)
                        }]), false),
                    }
                }

                "aetherscope_get_graph_summary" => {
                    let req_path_opt = arguments.get("path").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
                    let rescan = arguments.get("rescan").and_then(|v| v.as_bool()).unwrap_or(false);
                    let include_tasks = arguments.get("include_tasks").and_then(|v| v.as_bool()).unwrap_or(true);
                    let severity_filter = arguments.get("severity").and_then(|v| v.as_str());

                    let graph_val_res = if rescan || req_path_opt.is_some() {
                        let scan_p = req_path_opt.unwrap_or(default_path);
                        let analyze_res = send_http_request(server_port, "POST", "/api/analyze", Some(&json!({
                            "path": scan_p
                        }))).await;
                        match analyze_res {
                            Ok(val) => Ok(val),
                            Err(_) => send_http_request(server_port, "GET", "/api/graph", None).await,
                        }
                    } else {
                        send_http_request(server_port, "GET", "/api/graph", None).await
                    };

                    let target_path = req_path_opt.unwrap_or(default_path);
                    let p_buf = resolve_project_root(target_path);

                    // Query project detection status if server is active
                    let status_val_res = send_http_request(server_port, "GET", "/api/project/status", None).await;
                    let status_opt = status_val_res.ok();

                    let mut summary = match graph_val_res {
                        Ok(graph_val) => format_graph_summary(&graph_val, status_opt.as_ref()),
                        Err(_) => {
                            // Offline fallback: detect project type and scan
                            let report_res = obsidian_vault::detect_project_type(&p_buf);
                            let g = match report_res {
                                Ok(ref rep) if rep.project_type.is_vault() || rep.project_type.is_mixed() => {
                                    obsidian_vault::scan_obsidian_vault(&p_buf)
                                        .unwrap_or_else(|_| ast_scanner::ProjectScanner::default().scan_project(&p_buf))
                                }
                                _ => ast_scanner::ProjectScanner::default().scan_project(&p_buf),
                            };
                            let status_json = report_res.ok().map(|r| serde_json::to_value(&r).unwrap_or_default());
                            let g_val = serde_json::to_value(&g).unwrap_or_default();
                            format_graph_summary(&g_val, status_json.as_ref())
                        }
                    };

                    if let Some(sev) = severity_filter {
                        let scanner = ast_scanner::ProjectScanner::default();
                        let g = scanner.scan_project(&p_buf);
                        summary.push_str("\n\n---\n");
                        summary.push_str(&format_violations_response(&g, Some(sev), None, None));
                    }

                    if include_tasks {
                        let active_tasks: Vec<_> = ai_file_bridge::TaskManager::list_tasks(&p_buf)
                            .into_iter()
                            .filter(|t| t.status != ai_file_bridge::TaskStatus::Done && t.status != ai_file_bridge::TaskStatus::Cancelled)
                            .collect();
                        summary.push_str(&format!("\n\nðŸ“‹ **TÃ¢ches Actives ({} en cours) :**\n", active_tasks.len()));
                        if active_tasks.is_empty() {
                            summary.push_str("  - Aucune tÃ¢che active. Utilisez `aetherscope_manage_tasks({\"action\": \"create\", ...})` pour structurer votre mission.\n");
                        } else {
                            for t in active_tasks.iter().take(10) {
                                summary.push_str(&format!(
                                    "  - `{}` [{:?}] **{}** ({:?}, {}%) â€” Cible: `{}`\n",
                                    t.id,
                                    t.kind,
                                    t.title,
                                    t.status,
                                    t.progress,
                                    t.target_symbol.as_deref().unwrap_or("-")
                                ));
                            }
                        }
                    }

                    (json!([{ "type": "text", "text": summary }]), false)
                }

                "aetherscope_switch_view_mode" => {
                    let mode = arguments
                        .get("mode")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();

                    if mode != "code" && mode != "vault" {
                        (
                            json!([{
                                "type": "text",
                                "text": "⚠️ Erreur: Le paramètre 'mode' est requis et doit être soit 'code' soit 'vault'."
                            }]),
                            true,
                        )
                    } else {
                        let target_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);

                        // 1. Send spatial telemetry to update Cockpit HUD
                        let _ = send_http_request(
                            server_port,
                            "POST",
                            "/api/ai/telemetry",
                            Some(&json!({
                                "target": format!("Vision: {}", mode),
                                "action": "Bascule Vision Cockpit",
                                "details": format!("Bascule du cockpit vers la vision '{}'", mode)
                            })),
                        )
                        .await;

                        // 2. Call POST /api/view_mode on Axum backend
                        let res = send_http_request(
                            server_port,
                            "POST",
                            "/api/view_mode",
                            Some(&json!({ "mode": mode })),
                        )
                        .await;

                        match res {
                            Ok(graph_val) => {
                                if graph_val.get("status").and_then(|s| s.as_str()) == Some("error") {
                                    let err_msg = graph_val
                                        .get("message")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("Erreur lors du basculement de vision");
                                    let text = format!("⚠️ Échec du basculement en mode vision `{}` : {}", mode, err_msg);
                                    (json!([{ "type": "text", "text": text }]), true)
                                } else {
                                    let nodes_cnt = graph_val.get("nodes").and_then(|n| n.as_array()).map(|a| a.len()).unwrap_or(0);
                                    let edges_cnt = graph_val.get("edges").and_then(|e| e.as_array()).map(|a| a.len()).unwrap_or(0);
                                    let text = format!(
                                        "🌌 Cockpit AetherScope basculé avec succès en mode vision : `{}`\n\
                                         • Graphe actif synchronisé : {} nœuds, {} relations\n\
                                         • Visualiseur WebGL 2 actualisé en direct sur http://127.0.0.1:{}",
                                        mode, nodes_cnt, edges_cnt, server_port
                                    );
                                    (json!([{ "type": "text", "text": text }]), false)
                                }
                            }
                            Err(e) => {
                                if e.starts_with("HTTP error") {
                                    let text = format!("⚠️ Échec du basculement en mode vision `{}` : {}", mode, e);
                                    (json!([{ "type": "text", "text": text }]), true)
                                } else {
                                    // Offline fallback
                                    let p_buf = resolve_project_root(target_path);
                                    let report = obsidian_vault::detect_project_type(&p_buf).ok();
                                    let is_avail = report.as_ref().map(|r| r.is_vault_mode_available()).unwrap_or(false);
                                    let text = format!(
                                        "🌌 Mode vision sélectionné : `{}` (Mode hors-ligne / Autonome)\n\
                                         • Projet : `{}`\n\
                                         • Disponibilité vision vault : {}\n\
                                         💡 Lancez `aether-engine` pour visualiser le basculement dynamique dans le cockpit WebGL 2.",
                                        mode,
                                        p_buf.display(),
                                        if is_avail { "Oui (Vault/Mixed)" } else { "Non disponible (PureCode)" }
                                    );
                                    (json!([{ "type": "text", "text": text }]), false)
                                }
                            }
                        }
                    }
                }

                "aetherscope_send_chat_message" => {
                    let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let thought = arguments.get("thought").and_then(|v| v.as_str()).unwrap_or("");
                    let target = arguments.get("target_symbol").and_then(|v| v.as_str()).map(|s| s.to_string());

                    if text.trim().is_empty() {
                        (json!([{ "type": "text", "text": "âš ï¸ Erreur: Le paramÃ¨tre 'text' ne peut pas Ãªtre vide." }]), true)
                    } else {
                        if let Some(ref sym) = target {
                            if !sym.trim().is_empty() {
                                let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                                    "target": sym,
                                    "action": "Debrief Chat IA",
                                    "details": &text
                                }))).await;
                            }
                        }

                        let full_payload = if !thought.is_empty() {
                            format!("<thought>\n{}\n</thought>\n{}", thought, text)
                        } else {
                            text
                        };

                        let res = send_http_request(server_port, "POST", "/api/ai/chat", Some(&json!({
                            "text": full_payload,
                            "sender": "ai",
                            "target_symbol": target
                        }))).await;

                        match res {
                            Ok(_) => (json!([{ "type": "text", "text": "ðŸ’¬ Message affichÃ© dans le HUD AetherScope de l'utilisateur." }]), false),
                            Err(e) => (json!([{ "type": "text", "text": format!("âš ï¸ Erreur envoi chat AetherScope : {}", e) }]), true),
                        }
                    }
                }

                "aetherscope_get_chat_history" => {
                    let res = send_http_request(server_port, "GET", "/api/ai/chat", None).await;
                    match res {
                        Ok(val) => (json!([{ "type": "text", "text": serde_json::to_string_pretty(&val).unwrap_or_default() }]), false),
                        Err(e) => (json!([{ "type": "text", "text": format!("âš ï¸ Erreur historique chat : {}", e) }]), true),
                    }
                }

                "aetherscope_get_active_target" => {
                    let symbol_id = arguments.get("symbol_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let target_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                    let action = arguments.get("action").and_then(|v| v.as_str()).unwrap_or("Inspection");
                    let details = arguments.get("details").and_then(|v| v.as_str()).unwrap_or("Inspection combinÃ©e Cible + Contrat EARS + Flux");
                    let trace_direction = arguments.get("trace_direction").and_then(|v| v.as_str()).unwrap_or("both");
                    let max_depth = arguments.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(2) as usize;

                    if symbol_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "âš ï¸ Erreur: Le paramÃ¨tre 'symbol_id' est requis." }]), true)
                    } else {
                        // 1. TÃ©lÃ©portation automatique de la camÃ©ra 3D + tÃ©lÃ©mÃ©trie HUD
                        let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                            "target": symbol_id,
                            "action": action,
                            "details": details
                        }))).await;

                        // 2. RÃ©cupÃ©ration du contexte cible + contrat EARS + Handshake
                        let res = send_http_request(server_port, "POST", "/api/ai/target", Some(&json!({
                            "symbol_id": symbol_id
                        }))).await;

                        let (mut text, is_err) = match res {
                            Ok(val) if val.get("status").and_then(|v| v.as_str()) == Some("ok") => {
                                let t = format_active_target_response(&val);
                                (t, false)
                            }
                            _ => {
                                let t = offline_active_target_fallback(target_path, &symbol_id);
                                let err = t.starts_with("⚠️") || t.contains("introuvable dans") || t.starts_with("âš");
                                (t, err)
                            }
                        };

                        // 3. TraÃ§age automatique des flux amont/aval combinÃ© dans la mÃªme rÃ©ponse
                        if !is_err && trace_direction != "none" {
                            let p_buf = resolve_project_root(target_path);
                            let scanner = ast_scanner::ProjectScanner::default();
                            let g = scanner.scan_project(&p_buf);
                            let flow_text = format_trace_flow_response(&g, &symbol_id, trace_direction, max_depth);
                            if !flow_text.starts_with("âš ï¸") {
                                text.push_str("\n\n---\n");
                                text.push_str(&flow_text);
                            }
                        }

                        (json!([{ "type": "text", "text": text }]), is_err)
                    }
                }

                "aetherscope_scan_project" => {
                    let scan_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                    let res = send_http_request(server_port, "POST", "/api/analyze", Some(&json!({
                        "path": scan_path
                    }))).await;

                    match res {
                        Ok(val) => {
                            let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                                "target": scan_path,
                                "action": "Scan de Projet AST",
                                "details": "RÃ©analyse complÃ¨te dÃ©clenchÃ©e par l'agent IA via MCP"
                            }))).await;

                            let status_opt = send_http_request(server_port, "GET", "/api/project/status", None).await.ok();
                            let summary = format_graph_summary(&val, status_opt.as_ref());
                            (json!([{
                                "type": "text",
                                "text": format!("⚡ Projet `{}` réanalysé et synchronisé avec succès dans AetherScope V2 !\n\n{}", scan_path, summary)
                            }]), false)
                        }
                        Err(e) => {
                            // Fallback direct AST scanner offline si le serveur n'est pas joignable
                            let p_buf = PathBuf::from(scan_path);
                            let report_res = obsidian_vault::detect_project_type(&p_buf);
                            let g = match report_res {
                                Ok(ref rep) if rep.project_type.is_vault() || rep.project_type.is_mixed() => {
                                    obsidian_vault::scan_obsidian_vault(&p_buf)
                                        .unwrap_or_else(|_| ast_scanner::ProjectScanner::default().scan_project(&p_buf))
                                }
                                _ => ast_scanner::ProjectScanner::default().scan_project(&p_buf),
                            };
                            let status_json = report_res.ok().map(|r| serde_json::to_value(&r).unwrap_or_default());
                            let g_val = serde_json::to_value(&g).unwrap_or_default();
                            let summary = format_graph_summary(&g_val, status_json.as_ref());
                            (json!([{
                                "type": "text",
                                "text": format!("⚡ Projet `{}` analysé (mode autonome AST direct - serveur: {}) :\n\n{}", scan_path, e, summary)
                            }]), false)
                        }
                    }
                }

                "aetherscope_create_task" => {
                    let title = arguments.get("title").and_then(|v| v.as_str()).unwrap_or("Nouvelle tÃ¢che").to_string();
                    let kind_str = arguments.get("kind").and_then(|v| v.as_str()).unwrap_or("function").to_string();
                    let target_symbol = arguments.get("target_symbol").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let target_file = arguments.get("target_file").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let priority = arguments.get("priority").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let initial_readme = arguments.get("initial_readme").and_then(|v| v.as_str()).map(|s| s.to_string());

                    if let Some(ref sym) = target_symbol {
                        if !sym.trim().is_empty() {
                            let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                                "target": sym,
                                "action": "CrÃ©ation TÃ¢che",
                                "details": &title
                            }))).await;
                        }
                    }

                    let payload = json!({
                        "title": title,
                        "kind": kind_str,
                        "target_symbol": target_symbol,
                        "target_file": target_file,
                        "author": "model",
                        "priority": priority,
                        "initial_readme": initial_readme
                    });

                    let res = send_http_request(server_port, "POST", "/api/tasks", Some(&payload)).await;
                    match res {
                        Ok(val) => {
                            let task_obj = val.get("task");
                            let task_id = task_obj.and_then(|t| t.get("id")).and_then(|i| i.as_str()).unwrap_or("");
                            (json!([{
                                "type": "text",
                                "text": format!("ðŸ“‹ TÃ¢che `{}` crÃ©Ã©e avec succÃ¨s !\nðŸ“ Mini-README disponible dans `.aether/tasks/{}/README.md`\n{}", task_id, task_id, serde_json::to_string_pretty(&val).unwrap_or_default())
                            }]), false)
                        }
                        Err(_) => {
                            let p_buf = PathBuf::from(default_path);
                            let kind = ai_file_bridge::TaskKind::from_str_loose(&kind_str);
                            match ai_file_bridge::TaskManager::create_task(
                                &p_buf,
                                &title,
                                kind,
                                target_symbol.as_deref(),
                                target_file.as_deref(),
                                "model",
                                priority.as_deref(),
                                initial_readme.as_deref(),
                            ) {
                                Ok(t) => (json!([{
                                    "type": "text",
                                    "text": format!("ðŸ“‹ TÃ¢che `{}` crÃ©Ã©e (mode offline) !\nðŸ“ Fichier : `.aether/tasks/{}/README.md`", t.id, t.id)
                                }]), false),
                                Err(e) => (json!([{ "type": "text", "text": format!("âš ï¸ Erreur crÃ©ation tÃ¢che : {}", e) }]), true),
                            }
                        }
                    }
                }

                "aetherscope_update_task" => {
                    let task_id = arguments.get("task_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let status_str = arguments.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let progress = arguments.get("progress").and_then(|v| v.as_u64()).map(|p| p as u8);
                    let progress_note = arguments.get("progress_note").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let full_readme = arguments.get("full_readme").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let target_symbol = arguments.get("target_symbol").and_then(|v| v.as_str()).map(|s| s.to_string());

                    if task_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "âš ï¸ Erreur: 'task_id' requis pour la mise Ã  jour." }]), true)
                    } else {
                        if let Some(ref sym) = target_symbol {
                            if !sym.trim().is_empty() {
                                let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                                    "target": sym,
                                    "action": "Mise Ã  jour TÃ¢che",
                                    "details": progress_note.as_deref().unwrap_or(&task_id)
                                }))).await;
                            }
                        }

                        let payload = json!({
                            "task_id": task_id,
                            "status": status_str,
                            "progress": progress,
                            "progress_note": progress_note,
                            "full_readme": full_readme
                        });

                        let res = send_http_request(server_port, "POST", "/api/tasks/update", Some(&payload)).await;
                        match res {
                            Ok(val) => (json!([{
                                "type": "text",
                                "text": format!("âš¡ TÃ¢che `{}` mise Ã  jour avec succÃ¨s :\n{}", task_id, serde_json::to_string_pretty(&val).unwrap_or_default())
                            }]), false),
                            Err(_) => {
                                let p_buf = PathBuf::from(default_path);
                                let status = status_str.as_deref().map(ai_file_bridge::TaskStatus::from_str_loose);
                                match ai_file_bridge::TaskManager::update_task(
                                    &p_buf,
                                    &task_id,
                                    status,
                                    progress,
                                    progress_note.as_deref(),
                                    full_readme.as_deref(),
                                ) {
                                    Ok(Some(t)) => (json!([{
                                        "type": "text",
                                        "text": format!("âš¡ TÃ¢che `{}` mise Ã  jour (mode offline). Statut: {:?}, ProgrÃ¨s: {}%", t.id, t.status, t.progress)
                                    }]), false),
                                    Ok(None) => (json!([{ "type": "text", "text": format!("âš ï¸ TÃ¢che `{}` introuvable.", task_id) }]), true),
                                    Err(e) => (json!([{ "type": "text", "text": format!("âš ï¸ Erreur mise Ã  jour tÃ¢che : {}", e) }]), true),
                                }
                            }
                        }
                    }
                }

                "aetherscope_list_tasks" => {
                    let filter = arguments
                        .get("status_filter")
                        .or_else(|| arguments.get("status"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("active");
                    let res = send_http_request(server_port, "GET", "/api/tasks", None).await;

                    let tasks = match res {
                        Ok(val) => {
                            if let Some(arr) = val.get("tasks").and_then(|t| t.as_array()) {
                                arr.clone()
                            } else {
                                vec![]
                            }
                        }
                        Err(_) => {
                            let p_buf = PathBuf::from(default_path);
                            let raw_tasks = ai_file_bridge::TaskManager::list_tasks(&p_buf);
                            serde_json::to_value(&raw_tasks).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default()
                        }
                    };

                    let filtered: Vec<&Value> = tasks.iter().filter(|t| {
                        let st = t.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        match filter {
                            "all" => true,
                            "done" => st == "done",
                            _ => st != "done" && st != "cancelled",
                        }
                    }).collect();

                    if filtered.is_empty() {
                        (json!([{ "type": "text", "text": "ðŸ“‹ Aucune tÃ¢che trouvÃ©e pour ce filtre." }]), false)
                    } else {
                        let mut output = format!("ðŸ“‹ TÃ¢ches AetherScope (Total : {}):\n\n", filtered.len());
                        for t in filtered {
                            let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let title = t.get("title").and_then(|v| v.as_str()).unwrap_or("");
                            let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                            let status = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                            let progress = t.get("progress").and_then(|v| v.as_u64()).unwrap_or(0);
                            let target = t.get("target_symbol").and_then(|v| v.as_str()).unwrap_or("-");
                            let summary = t.get("readme_summary").and_then(|v| v.as_str()).unwrap_or("");

                            output.push_str(&format!("â€¢ `{}` [{}] **{}** ({}, {}%)\n  - Cible : `{}`\n  - Avancement : {}\n\n", id, kind, title, status, progress, target, summary));
                        }
                        (json!([{ "type": "text", "text": output }]), false)
                    }
                }

                "aetherscope_search_symbols" => {
                    let query = arguments.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    let layer = arguments.get("layer").and_then(|v| v.as_str());
                    let kind = arguments.get("kind").and_then(|v| v.as_str());
                    let stereotype = arguments.get("stereotype").and_then(|v| v.as_str());
                    let has_violation = arguments.get("has_violation").and_then(|v| v.as_bool());
                    let cwe_id = arguments.get("cwe_id").and_then(|v| v.as_str());
                    let severity = arguments.get("severity").and_then(|v| v.as_str());
                    let file_pattern = arguments.get("file_pattern").and_then(|v| v.as_str());
                    let limit = arguments.get("limit").and_then(|v| v.as_u64()).unwrap_or(15) as usize;
                    let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);

                    let p_buf = resolve_project_root(req_path);
                    let is_vault_project = obsidian_vault::detect_project_type(&p_buf)
                        .map(|rep| rep.project_type.is_vault() || rep.project_type.is_mixed())
                        .unwrap_or(false);
                    let g = if is_vault_project {
                        obsidian_vault::scan_obsidian_vault(&p_buf)
                            .unwrap_or_else(|_| ast_scanner::ProjectScanner::default().scan_project(&p_buf))
                    } else {
                        ast_scanner::ProjectScanner::default().scan_project(&p_buf)
                    };

                    let effective_has_violation = if cwe_id.is_some() || severity.is_some() {
                        Some(true)
                    } else {
                        has_violation
                    };

                    let mut text = format_search_symbols_response(&g, query, layer, kind, stereotype, effective_has_violation, limit);

                    if cwe_id.is_some() || severity.is_some() || file_pattern.is_some() {
                        let viol_block = format_violations_response(&g, severity, cwe_id, file_pattern.or(if !query.is_empty() { Some(query) } else { None }));
                        text.push_str("\n\n---\n");
                        text.push_str(&viol_block);
                    }

                    (json!([{ "type": "text", "text": text }]), false)
                }

                "aetherscope_trace_flow" => {
                    let symbol_id = arguments.get("symbol_id").and_then(|v| v.as_str()).unwrap_or("");
                    if symbol_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "âš ï¸ Erreur: Le paramÃ¨tre 'symbol_id' est requis." }]), true)
                    } else {
                        let direction = arguments.get("direction").and_then(|v| v.as_str()).unwrap_or("both");
                        let max_depth = arguments.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(2) as usize;
                        let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);

                    let p_buf = resolve_project_root(req_path);
                    let is_vault_project = obsidian_vault::detect_project_type(&p_buf)
                        .map(|rep| rep.project_type.is_vault() || rep.project_type.is_mixed())
                        .unwrap_or(false);
                    let g = if is_vault_project {
                        obsidian_vault::scan_obsidian_vault(&p_buf)
                            .unwrap_or_else(|_| ast_scanner::ProjectScanner::default().scan_project(&p_buf))
                    } else {
                        ast_scanner::ProjectScanner::default().scan_project(&p_buf)
                    };
                        let text = format_trace_flow_response(&g, symbol_id, direction, max_depth);
                        (json!([{ "type": "text", "text": text }]), false)
                    }
                }

                "aetherscope_query_violations" => {
                    let severity = arguments.get("severity").and_then(|v| v.as_str());
                    let cwe_id = arguments.get("cwe_id").and_then(|v| v.as_str());
                    let file_pattern = arguments.get("file_pattern").and_then(|v| v.as_str());
                    let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);

                    let p_buf = resolve_project_root(req_path);
                    let is_vault_project = obsidian_vault::detect_project_type(&p_buf)
                        .map(|rep| rep.project_type.is_vault() || rep.project_type.is_mixed())
                        .unwrap_or(false);
                    let g = if is_vault_project {
                        obsidian_vault::scan_obsidian_vault(&p_buf)
                            .unwrap_or_else(|_| ast_scanner::ProjectScanner::default().scan_project(&p_buf))
                    } else {
                        ast_scanner::ProjectScanner::default().scan_project(&p_buf)
                    };
                    let text = format_violations_response(&g, severity, cwe_id, file_pattern);
                    (json!([{ "type": "text", "text": text }]), false)
                }

                "aetherscope_list_plugins" => {
                    let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                    let plugins_sub = arguments.get("plugins_dir").and_then(|v| v.as_str()).unwrap_or(".aether/plugins");
                    let p_buf = resolve_project_root(req_path);
                    let plug_dir = resolve_plugins_dir(&p_buf, plugins_sub);

                    if !plug_dir.exists() {
                        let text = serde_json::to_string_pretty(&json!({
                            "status": "ok",
                            "plugins_dir": plug_dir.to_string_lossy(),
                            "total_plugins": 0,
                            "total_rules": 0,
                            "plugins": []
                        })).unwrap_or_default();
                        (json!([{ "type": "text", "text": text }]), false)
                    } else {
                        let mut engine = security_linter::plugin::PluginEngine::new();
                        match engine.load_from_directory(&plug_dir) {
                            Ok(_) => {
                                let mut plugins_info = Vec::new();
                                let mut total_rules = 0;
                                for p in &engine.plugins {
                                    total_rules += p.rules.len();
                                    plugins_info.push(json!({
                                        "name": p.name,
                                        "version": p.version,
                                        "author": p.author,
                                        "description": p.description,
                                        "enabled": p.enabled,
                                        "rules_count": p.rules.len(),
                                        "rules": p.rules.iter().map(|r| json!({
                                            "id": r.id,
                                            "cwe_id": r.cwe_id,
                                            "name": r.name,
                                            "category": r.category,
                                            "severity": r.severity,
                                            "extensions": r.file_extensions,
                                            "tests_count": r.test_cases.len()
                                        })).collect::<Vec<_>>()
                                    }));
                                }
                                let text = serde_json::to_string_pretty(&json!({
                                    "status": "ok",
                                    "plugins_dir": plug_dir.to_string_lossy(),
                                    "total_plugins": engine.plugins.len(),
                                    "total_rules": total_rules,
                                    "plugins": plugins_info
                                })).unwrap_or_default();
                                (json!([{ "type": "text", "text": text }]), false)
                            }
                            Err(e) => (json!([{ "type": "text", "text": format!("Erreur lors du chargement des plugins : {}", e) }]), true),
                        }
                    }
                }

                "aetherscope_test_plugins" => {
                    let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                    let plugins_sub = arguments.get("plugins_dir").and_then(|v| v.as_str()).unwrap_or(".aether/plugins");
                    let p_buf = resolve_project_root(req_path);
                    let plug_dir = resolve_plugins_dir(&p_buf, plugins_sub);

                    if !plug_dir.exists() {
                        let text = serde_json::to_string_pretty(&json!({
                            "status": "passed",
                            "total_tests": 0,
                            "passed": 0,
                            "failed": 0,
                            "failures": []
                        })).unwrap_or_default();
                        (json!([{ "type": "text", "text": text }]), false)
                    } else {
                        let mut engine = security_linter::plugin::PluginEngine::new();
                        match engine.load_from_directory(&plug_dir) {
                            Ok(_) => {
                                let report = engine.run_test_suite();
                                let text = serde_json::to_string_pretty(&json!({
                                    "status": if report.failed == 0 { "passed" } else { "failed" },
                                    "total_tests": report.total_tests,
                                    "passed": report.passed,
                                    "failed": report.failed,
                                    "failures": report.failures
                                })).unwrap_or_default();
                                let is_error = report.failed > 0;
                                (json!([{ "type": "text", "text": text }]), is_error)
                            }
                            Err(e) => (json!([{ "type": "text", "text": format!("Erreur : {}", e) }]), true),
                        }
                    }
                }

                "aetherscope_scan_with_plugins" => {
                    let target_str = arguments.get("target_path").and_then(|v| v.as_str()).unwrap_or("");
                    if target_str.is_empty() {
                        (json!([{ "type": "text", "text": "ParamÃ¨tre 'target_path' manquant pour le scan par plugins." }]), true)
                    } else {
                        let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                        let plugins_sub = arguments.get("plugins_dir").and_then(|v| v.as_str()).unwrap_or(".aether/plugins");
                        let p_buf = resolve_project_root(req_path);
                        let plug_dir = resolve_plugins_dir(&p_buf, plugins_sub);

                        let mut engine = security_linter::plugin::PluginEngine::new();
                        if plug_dir.exists() {
                            let _ = engine.load_from_directory(&plug_dir);
                        }

                        let target = if Path::new(target_str).is_absolute() {
                            PathBuf::from(target_str)
                        } else {
                            p_buf.join(target_str)
                        };

                        let mut all_violations = Vec::new();
                        if target.is_file() {
                            if let Ok(content) = std::fs::read_to_string(&target) {
                                let rel = target.strip_prefix(&p_buf).unwrap_or(&target).to_string_lossy().to_string();
                                all_violations.extend(engine.audit_file(&rel, &content));
                            }
                        } else if target.is_dir() {
                            for entry in walkdir::WalkDir::new(&target).into_iter().filter_map(|e| e.ok()) {
                                let p = entry.path();
                                if p.is_file() {
                                    let p_str = p.to_string_lossy();
                                    if p_str.contains("target") || p_str.contains(".git") || p_str.contains("node_modules") {
                                        continue;
                                    }
                                    if let Ok(content) = std::fs::read_to_string(p) {
                                        let rel = p.strip_prefix(&p_buf).unwrap_or(p).to_string_lossy().to_string();
                                        all_violations.extend(engine.audit_file(&rel, &content));
                                    }
                                }
                            }
                        }

                        let text = serde_json::to_string_pretty(&json!({
                            "status": "ok",
                            "target": target.to_string_lossy(),
                            "total_violations": all_violations.len(),
                            "violations": all_violations.iter().map(|v| json!({
                                "file": v.file_path,
                                "line": v.line_number,
                                "rule_id": v.rule_id,
                                "cwe_id": v.cve_id,
                                "severity": v.severity,
                                "message": v.message,
                                "snippet": v.transmitted_data,
                                "remediation": v.remediation
                            })).collect::<Vec<_>>()
                        })).unwrap_or_default();
                        (json!([{ "type": "text", "text": text }]), false)
                    }
                }

                "aetherscope_upsert_plugin_rule" => {
                    let plugin_name = arguments.get("plugin_name").and_then(|v| v.as_str()).unwrap_or("");
                    let rule_id = arguments.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
                    let cwe_id = arguments.get("cwe_id").and_then(|v| v.as_str()).unwrap_or("");
                    let name = arguments.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let severity = arguments.get("severity").and_then(|v| v.as_str()).unwrap_or("HIGH");
                    let description = arguments.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    let remediation = arguments.get("remediation").and_then(|v| v.as_str()).unwrap_or("");
                    let file_extensions: Vec<String> = arguments.get("file_extensions")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                        .unwrap_or_default();

                    if plugin_name.is_empty() || rule_id.is_empty() || cwe_id.is_empty() || file_extensions.is_empty() {
                        (json!([{ "type": "text", "text": "ParamÃ¨tres obligatoires manquants: plugin_name, rule_id, cwe_id, file_extensions" }]), true)
                    } else {
                        let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                        let plugins_sub = arguments.get("plugins_dir").and_then(|v| v.as_str()).unwrap_or(".aether/plugins");
                        let p_buf = resolve_project_root(req_path);
                        let plugin_dir = p_buf.join(plugins_sub).join(plugin_name);
                        let yaml_path = plugin_dir.join("plugin.yaml");

                        if let Err(e) = std::fs::create_dir_all(&plugin_dir) {
                            (json!([{ "type": "text", "text": format!("Impossible de crÃ©er le dossier {} : {}", plugin_dir.display(), e) }]), true)
                        } else {
                            let mut manifest: security_linter::plugin::PluginManifest = if yaml_path.exists() {
                                let content = std::fs::read_to_string(&yaml_path).unwrap_or_default();
                                serde_yaml::from_str(&content).unwrap_or_else(|_| security_linter::plugin::PluginManifest {
                                    name: plugin_name.to_string(),
                                    version: "1.0.0".to_string(),
                                    author: Some("AI Security Agent".to_string()),
                                    description: Some(format!("Custom security plugin {}", plugin_name)),
                                    enabled: true,
                                    rules: Vec::new(),
                                })
                            } else {
                                security_linter::plugin::PluginManifest {
                                    name: plugin_name.to_string(),
                                    version: "1.0.0".to_string(),
                                    author: Some("AI Security Agent".to_string()),
                                    description: Some(format!("Custom security plugin {}", plugin_name)),
                                    enabled: true,
                                    rules: Vec::new(),
                                }
                            };

                            let match_mode = match arguments.get("match_mode").and_then(|v| v.as_str()) {
                                Some("whole_file") => security_linter::plugin::MatchMode::WholeFile,
                                _ => security_linter::plugin::MatchMode::LineByLine,
                            };

                            let must_contain = arguments.get("must_contain")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                                .unwrap_or_default();

                            let must_not_contain = arguments.get("must_not_contain")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                                .unwrap_or_default();

                            let regex_patterns = arguments.get("regex_patterns")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                                .unwrap_or_default();

                            let forbidden_tokens = arguments.get("forbidden_tokens")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
                                .unwrap_or_default();

                            let check_literals = arguments.get("check_literals").and_then(|v| v.as_bool()).unwrap_or(false);

                            let mut test_cases = Vec::new();
                            if let Some(tarr) = arguments.get("test_cases").and_then(|v| v.as_array()) {
                                for t in tarr {
                                    if let (Some(tname), Some(code), Some(fname), Some(should_trig)) = (
                                        t.get("name").and_then(|s| s.as_str()),
                                        t.get("code").and_then(|s| s.as_str()),
                                        t.get("file_name").and_then(|s| s.as_str()),
                                        t.get("should_trigger").and_then(|s| s.as_bool()),
                                    ) {
                                        test_cases.push(security_linter::plugin::RuleTestCase {
                                            name: tname.to_string(),
                                            code: code.to_string(),
                                            file_name: fname.to_string(),
                                            should_trigger: should_trig,
                                        });
                                    }
                                }
                            }

                            let new_rule = security_linter::plugin::PluginRule {
                                id: rule_id.to_string(),
                                cwe_id: cwe_id.to_string(),
                                name: name.to_string(),
                                category: "Custom / Security".to_string(),
                                severity: severity.to_string(),
                                description: description.to_string(),
                                remediation: remediation.to_string(),
                                file_extensions,
                                match_mode,
                                conditions: security_linter::plugin::RuleConditions {
                                    must_contain,
                                    must_not_contain,
                                    regex_patterns,
                                    forbidden_tokens,
                                    check_literals,
                                },
                                test_cases,
                            };

                            if let Some(pos) = manifest.rules.iter().position(|r| r.id == rule_id) {
                                manifest.rules[pos] = new_rule;
                            } else {
                                manifest.rules.push(new_rule);
                            }

                            let mut test_engine = security_linter::plugin::PluginEngine::new();
                            test_engine.plugins.push(manifest.clone());
                            let report = test_engine.run_test_suite();

                            if report.failed > 0 {
                                (json!([{
                                    "type": "text",
                                    "text": format!("Validation Ã©chouÃ©e : {} test(s) unitaire(s) ont Ã©chouÃ© pour la rÃ¨gle {}. Fichier non modifiÃ©.\nErreurs : {:?}", report.failed, rule_id, report.failures)
                                }]), true)
                            } else {
                                match serde_yaml::to_string(&manifest) {
                                    Ok(yaml_str) => {
                                        if let Err(e) = std::fs::write(&yaml_path, yaml_str) {
                                            (json!([{ "type": "text", "text": format!("Ã‰chec d'Ã©criture {}: {}", yaml_path.display(), e) }]), true)
                                        } else {
                                            let text = serde_json::to_string_pretty(&json!({
                                                "status": "ok",
                                                "plugin": plugin_name,
                                                "rule_id": rule_id,
                                                "file": yaml_path.to_string_lossy(),
                                                "tests_passed": report.passed,
                                                "total_rules": manifest.rules.len(),
                                                "message": format!("RÃ¨gle {} sauvegardÃ©e et certifiÃ©e avec succÃ¨s !", rule_id)
                                            })).unwrap_or_default();
                                            (json!([{ "type": "text", "text": text }]), false)
                                        }
                                    }
                                    Err(e) => (json!([{ "type": "text", "text": format!("Erreur de sÃ©rialisation YAML : {}", e) }]), true),
                                }
                            }
                        }
                    }
                }

                "aetherscope_verify_patch" => {
                    let files = arguments
                        .get("files_modified")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();

                    if files.is_empty() {
                        (
                            json!([{
                                "type": "text",
                                "text": "âš ï¸ Erreur: Le paramÃ¨tre 'files_modified' ne peut pas Ãªtre une liste vide."
                            }]),
                            true,
                        )
                    } else {
                        let root = Path::new(default_path);
                        let result = ai_file_bridge::patch_verifier::PatchVerifier::verify_patch(
                            root,
                            &files,
                            Some(server_port),
                        );
                        let is_rejected = result.verdict == ai_file_bridge::patch_verifier::PatchVerdict::Rejected;
                        let mut out_text = result.formatted_output;

                        // Actions combinÃ©es automatiques si le patch est approuvÃ©
                        if !is_rejected {
                            if let Some(tid) = arguments.get("task_id").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                                let status_str = arguments.get("status").and_then(|v| v.as_str()).unwrap_or("done");
                                let progress = arguments.get("progress").and_then(|v| v.as_u64()).map(|p| p as u8).or(Some(100));
                                let note = arguments.get("progress_note").and_then(|v| v.as_str()).unwrap_or("Patch validÃ© par aetherscope_verify_patch");
                                let status = Some(ai_file_bridge::TaskStatus::from_str_loose(status_str));
                                let _ = ai_file_bridge::TaskManager::update_task(root, tid, status, progress, Some(note), None);
                                let _ = send_http_request(server_port, "POST", "/api/tasks/update", Some(&json!({
                                    "task_id": tid,
                                    "status": status_str,
                                    "progress": progress,
                                    "progress_note": note
                                }))).await;
                                out_text.push_str(&format!("\nâš¡ **TÃ¢che `{}` mise Ã  jour automatiquement** (`{}` â€¢ `{}%`).", tid, status_str, progress.unwrap_or(100)));
                            }

                            if let Some(chat_msg) = arguments.get("chat_message").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                                let _ = send_http_request(server_port, "POST", "/api/ai/chat", Some(&json!({
                                    "text": chat_msg,
                                    "sender": "ai",
                                    "target_symbol": files.first()
                                }))).await;
                                out_text.push_str("\nðŸ’¬ **Compte-rendu publiÃ© dans le Chat Copilot AetherScope.**");
                            }
                        }

                        (
                            json!([{
                                "type": "text",
                                "text": out_text
                            }]),
                            is_rejected,
                        )
                    }
                }

                _ => (json!([{ "type": "text", "text": format!("Outil inconnu : {}", tool_name) }]), true),
            };

            Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(json!({
                    "content": result_content,
                    "isError": is_error
                })),
                error: None,
            })
        }

        _ => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(json!({ "code": -32601, "message": "Method not found" })),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_initialize_declares_multi_primitives() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("initialize should return response");
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, Some(json!(1)));
        let res = resp.result.expect("result should be present");
        assert_eq!(res["protocolVersion"], "2024-11-05");
        assert!(res["capabilities"]["tools"].is_object());
        assert!(res["capabilities"]["resources"].is_object());
        assert!(res["capabilities"]["prompts"].is_object());
    }

    #[tokio::test]
    async fn test_mcp_resources_list_and_read() {
        let list_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "resources/list".to_string(),
            params: None,
        };
        let list_resp = handle_mcp_request(list_req, 3030, ".").await.expect("resources/list response");
        let list_res = list_resp.result.expect("result present");
        let resources = list_res["resources"].as_array().expect("resources array");
        assert_eq!(resources.len(), 4);
        let uris: Vec<&str> = resources.iter().filter_map(|r| r["uri"].as_str()).collect();
        assert!(uris.contains(&"aether://graph/summary"));
        assert!(uris.contains(&"aether://audit/live"));
        assert!(uris.contains(&"aether://contracts/manifest"));
        assert!(uris.contains(&"aether://tasks/active"));

        let read_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "resources/read".to_string(),
            params: Some(json!({ "uri": "aether://contracts/manifest" })),
        };
        let read_resp = handle_mcp_request(read_req, 3030, ".").await.expect("resources/read response");
        let read_res = read_resp.result.expect("result present");
        let contents = read_res["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], "aether://contracts/manifest");
    }

    #[tokio::test]
    async fn test_mcp_prompts_list_and_get() {
        let list_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(4)),
            method: "prompts/list".to_string(),
            params: None,
        };
        let list_resp = handle_mcp_request(list_req, 3030, ".").await.expect("prompts/list response");
        let list_res = list_resp.result.expect("result present");
        let prompts = list_res["prompts"].as_array().expect("prompts array");
        assert_eq!(prompts.len(), 5);

        let get_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(5)),
            method: "prompts/get".to_string(),
            params: Some(json!({
                "name": "scaffold_game_server",
                "arguments": { "engine": "roblox", "package_name": "CombatEngine" }
            })),
        };
        let get_resp = handle_mcp_request(get_req, 3030, ".").await.expect("prompts/get response");
        let get_res = get_resp.result.expect("result present");
        let messages = get_res["messages"].as_array().expect("messages array");
        assert!(!messages.is_empty());
        let text = messages[0]["content"]["text"].as_str().expect("text string");
        assert!(text.contains("CombatEngine"));
        assert!(text.contains("aetherscope_manage_tasks"));
        assert!(text.contains("aetherscope_verify_patch"));
    }

    #[tokio::test]
    async fn test_mcp_tools_list_declares_all_four_hints_on_every_tool() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(10)),
            method: "tools/list".to_string(),
            params: None,
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("tools/list response");
        let res = resp.result.expect("tools/list result");
        let tools = res["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 9);

        let expected_tools = [
            ("aetherscope_get_graph_summary", true, false, true, false),
            ("aetherscope_get_active_target", true, false, true, false),
            ("aetherscope_search_symbols", true, false, true, false),
            ("aetherscope_switch_view_mode", false, false, true, false),
            ("aetherscope_manage_tasks", false, false, false, false),
            ("aetherscope_verify_patch", true, false, true, false),
            ("aetherscope_chat", false, false, false, false),
            ("aetherscope_manage_plugins", false, false, true, false),
            ("aetherscope_teleport_camera", true, false, true, false),
        ];

        for (name, ro, dest, idemp, ow) in expected_tools {
            let tool = tools.iter().find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("Tool {} missing from tools/list", name));

            assert_eq!(tool["readOnlyHint"].as_bool(), Some(ro), "top-level readOnlyHint on {}", name);
            assert_eq!(tool["destructiveHint"].as_bool(), Some(dest), "top-level destructiveHint on {}", name);
            assert_eq!(tool["idempotentHint"].as_bool(), Some(idemp), "top-level idempotentHint on {}", name);
            assert_eq!(tool["openWorldHint"].as_bool(), Some(ow), "top-level openWorldHint on {}", name);

            let ann = &tool["annotations"];
            assert!(ann.is_object(), "annotations object on {}", name);
            assert_eq!(ann["readOnlyHint"].as_bool(), Some(ro), "annotations readOnlyHint on {}", name);
            assert_eq!(ann["destructiveHint"].as_bool(), Some(dest), "annotations destructiveHint on {}", name);
            assert_eq!(ann["idempotentHint"].as_bool(), Some(idemp), "annotations idempotentHint on {}", name);
            assert_eq!(ann["openWorldHint"].as_bool(), Some(ow), "annotations openWorldHint on {}", name);
        }
    }

    #[tokio::test]
    async fn test_combined_tools_manage_tasks_chat_and_plugins() {
        let req_tasks = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(301)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_manage_tasks",
                "arguments": { "action": "list", "status_filter": "all" }
            })),
        };
        let resp_tasks = handle_mcp_request(req_tasks, 3030, ".").await.expect("manage_tasks response");
        assert_eq!(resp_tasks.result.expect("result")["isError"], false);

        let req_plugins = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(302)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_manage_plugins",
                "arguments": { "action": "list", "plugins_dir": ".aether/plugins" }
            })),
        };
        let resp_plugins = handle_mcp_request(req_plugins, 3030, ".").await.expect("manage_plugins response");
        assert_eq!(resp_plugins.result.expect("result")["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_verify_patch() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(17)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_verify_patch",
                "arguments": {
                    "files_modified": ["Cargo.toml"]
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("aetherscope_verify_patch response");
        let res = resp.result.expect("aetherscope_verify_patch result");
        assert!(!res["content"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_tool_aetherscope_teleport_camera() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(101)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_teleport_camera",
                "arguments": {
                    "target": "crates/desktop-shell/src/mcp.rs",
                    "action": "Inspection",
                    "details": "Telemetry camera alignment unit test"
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("teleport_camera response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
        assert!(res["content"].as_array().is_some());
    }

    #[tokio::test]
    async fn test_tool_aetherscope_get_graph_summary() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(102)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_graph_summary",
                "arguments": { "path": "." }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("get_graph_summary response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
        let content = res["content"].as_array().expect("content array");
        assert!(!content.is_empty());
    }

    #[tokio::test]
    async fn test_tool_aetherscope_send_chat_message() {
        let req_valid = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(103)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_send_chat_message",
                "arguments": {
                    "text": "Unit test chat broadcast message",
                    "thought": "Testing MCP chat telemetry"
                }
            })),
        };
        let resp_valid = handle_mcp_request(req_valid, 3030, ".").await.expect("send_chat_message response");
        assert!(resp_valid.result.is_some());

        let req_empty = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(104)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_send_chat_message",
                "arguments": { "text": "" }
            })),
        };
        let resp_empty = handle_mcp_request(req_empty, 3030, ".").await.expect("empty text chat response");
        let res_empty = resp_empty.result.expect("result present");
        assert_eq!(res_empty["isError"], true);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_get_chat_history() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(105)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_chat_history",
                "arguments": {}
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("get_chat_history response");
        assert!(resp.result.is_some());
    }

    #[tokio::test]
    async fn test_tool_aetherscope_get_active_target() {
        let req_valid = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(106)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_active_target",
                "arguments": { "symbol_id": "crates/desktop-shell/src/mcp.rs" }
            })),
        };
        let resp_valid = handle_mcp_request(req_valid, 3030, ".").await.expect("get_active_target response");
        assert!(resp_valid.result.is_some());

        let req_empty = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(107)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_active_target",
                "arguments": { "symbol_id": "" }
            })),
        };
        let resp_empty = handle_mcp_request(req_empty, 3030, ".").await.expect("empty symbol target response");
        let res_empty = resp_empty.result.expect("result present");
        assert_eq!(res_empty["isError"], true);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_scan_project() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(108)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_scan_project",
                "arguments": { "path": "." }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("scan_project response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_create_task() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(109)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_create_task",
                "arguments": {
                    "title": "M8ven 100/100 Tool Annotation Audit Task",
                    "kind": "test",
                    "priority": "high",
                    "initial_readme": "### Scope\n- Verify annotations\n- Ensure tests coverage"
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("create_task response");
        assert!(resp.result.is_some());
    }

    #[tokio::test]
    async fn test_tool_aetherscope_update_task() {
        let req_empty = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(110)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_update_task",
                "arguments": { "task_id": "" }
            })),
        };
        let resp_empty = handle_mcp_request(req_empty, 3030, ".").await.expect("empty task_id response");
        let res_empty = resp_empty.result.expect("result present");
        assert_eq!(res_empty["isError"], true);

        let req_valid = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(111)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_update_task",
                "arguments": {
                    "task_id": "non_existent_task_test_999",
                    "status": "in_progress",
                    "progress": 75,
                    "progress_note": "Executing automated tests verification"
                }
            })),
        };
        let resp_valid = handle_mcp_request(req_valid, 3030, ".").await.expect("update_task response");
        assert!(resp_valid.result.is_some());
    }

    #[tokio::test]
    async fn test_tool_aetherscope_list_tasks() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(112)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_list_tasks",
                "arguments": { "status_filter": "all" }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("list_tasks response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_search_symbols() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(113)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_search_symbols",
                "arguments": {
                    "query": "mcp",
                    "limit": 5
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("search_symbols response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_trace_flow() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(114)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_trace_flow",
                "arguments": {
                    "symbol_id": "crates/desktop-shell/src/mcp.rs",
                    "direction": "both"
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("trace_flow response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_query_violations() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(115)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_query_violations",
                "arguments": {
                    "severity": "all"
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("query_violations response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_plugin_suite() {
        // 1. List plugins
        let req_list = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(200)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_list_plugins",
                "arguments": { "plugins_dir": ".aether/plugins" }
            })),
        };
        let resp_list = handle_mcp_request(req_list, 3030, ".").await.expect("list_plugins response");
        assert_eq!(resp_list.result.expect("result present")["isError"], false);

        // 2. Test plugins
        let req_test = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(201)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_test_plugins",
                "arguments": { "plugins_dir": ".aether/plugins" }
            })),
        };
        let resp_test = handle_mcp_request(req_test, 3030, ".").await.expect("test_plugins response");
        assert_eq!(resp_test.result.expect("result present")["isError"], false);

        // 3. Scan with plugins
        let req_scan = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(202)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_scan_with_plugins",
                "arguments": {
                    "target_path": "crates/core-graph/src/bubble.rs",
                    "plugins_dir": ".aether/plugins"
                }
            })),
        };
        let resp_scan = handle_mcp_request(req_scan, 3030, ".").await.expect("scan_with_plugins response");
        assert_eq!(resp_scan.result.expect("result present")["isError"], false);
    }

    #[tokio::test]
    async fn test_tool_aetherscope_switch_view_mode_valid() {
        for mode in &["code", "vault"] {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(701)),
                method: "tools/call".to_string(),
                params: Some(json!({
                    "name": "aetherscope_switch_view_mode",
                    "arguments": {
                        "mode": mode,
                        "path": "."
                    }
                })),
            };
            let resp = handle_mcp_request(req, 3030, ".").await.expect("switch_view_mode response");
            let res = resp.result.expect("result present");
            assert_eq!(res["isError"], false);
            let content = res["content"].as_array().expect("content array");
            assert!(!content.is_empty());
            let text = content[0]["text"].as_str().expect("text content");
            assert!(text.contains(mode), "Expected response to mention switched mode '{}'", mode);
        }
    }

    #[tokio::test]
    async fn test_tool_aetherscope_switch_view_mode_invalid() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(702)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_switch_view_mode",
                "arguments": {
                    "mode": "invalid_mode"
                }
            })),
        };
        let resp = handle_mcp_request(req, 3030, ".").await.expect("invalid mode response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], true);
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("doit être soit 'code' soit 'vault'"));
    }

    #[tokio::test]
    async fn test_tool_aetherscope_get_graph_summary_vault_reporting() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp_dir.path().join(".obsidian")).unwrap();
        std::fs::write(
            temp_dir.path().join("Architecture.md"),
            "---\ntags:\n  - kb/architecture\n  - core\naliases:\n  - ArchSpec\n---\n# Architecture\nSee [[Overview]] and ![[diagram.png]].",
        ).unwrap();

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(703)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_graph_summary",
                "arguments": {
                    "path": temp_dir.path().to_str().unwrap(),
                    "rescan": true
                }
            })),
        };

        let resp = handle_mcp_request(req, 3030, ".").await.expect("get_graph_summary response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
        let text = res["content"][0]["text"].as_str().unwrap();

        assert!(text.contains("Type de Projet"), "Expected Type de Projet in summary");
        assert!(text.contains("Obsidian Vault"), "Expected Obsidian Vault classification in summary");
        assert!(text.contains("Notes Markdown"), "Expected Notes Markdown metric in summary");
        assert!(text.contains("Wikilinks"), "Expected Wikilinks metric in summary");
        assert!(text.contains("Tags uniques"), "Expected Tags uniques metric in summary");
    }

    #[tokio::test]
    async fn test_tool_aetherscope_get_active_target_note_bubble() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp_dir.path().join(".obsidian")).unwrap();
        std::fs::write(
            temp_dir.path().join("Guide.md"),
            "---\ntags:\n  - guide/install\nstatus: ready\n---\n# Installation Guide\nDetailed steps to run.\n## Prerequisites\nRust 1.80+ required.\nSee [[Configuration#Advanced|Setup]].",
        ).unwrap();

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(704)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_active_target",
                "arguments": {
                    "symbol_id": "Guide",
                    "path": temp_dir.path().to_str().unwrap()
                }
            })),
        };

        let resp = handle_mcp_request(req, 3030, ".").await.expect("get_active_target note response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
        let text = res["content"][0]["text"].as_str().unwrap();

        assert!(text.contains("Cible Note Obsidian"), "Expected Note header in target response");
        assert!(text.contains("Guide"), "Expected note name in response");
        assert!(text.contains("guide/install"), "Expected tag in response");
        assert!(text.contains("Prerequisites"), "Expected section heading in response");
        assert!(text.contains("Configuration"), "Expected outgoing wikilink target in response");
    }

    #[tokio::test]
    async fn test_tool_aetherscope_search_symbols_note_and_tags() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp_dir.path().join(".obsidian")).unwrap();
        std::fs::write(
            temp_dir.path().join("Security.md"),
            "---\ntags:\n  - security/sast\naliases:\n  - SecGuide\n---\n# Security Policies\nAudit guidelines.",
        ).unwrap();

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(705)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_search_symbols",
                "arguments": {
                    "query": "#security/sast",
                    "path": temp_dir.path().to_str().unwrap()
                }
            })),
        };

        let resp = handle_mcp_request(req, 3030, ".").await.expect("search_symbols tag response");
        let res = resp.result.expect("result present");
        assert_eq!(res["isError"], false);
        let text = res["content"][0]["text"].as_str().unwrap();

        assert!(text.contains("Security"), "Expected Security note found in search results");
        assert!(text.contains("«Note»") || text.contains("Note"), "Expected note stereotype/status badge");
    }
}
