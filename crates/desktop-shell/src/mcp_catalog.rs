use super::{JsonRpcRequest, JsonRpcResponse};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) async fn handle_catalog_request(
    req: &JsonRpcRequest,
    server_port: u16,
    default_path: &str,
) -> Option<Option<JsonRpcResponse>> {
    let id = req.id.clone();
    let res = match req.method.as_str() {
        "resources/list" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "resources": [
                    {
                        "uri": "aether://graph/summary",
                        "name": "AetherScope 3D AST Graph Summary",
                        "description": "SynthÃ¨se temps rÃ©el du graphe AST 3D (nÅ“uds, arÃªtes, clusters, mÃ©triques de santÃ©) pour injection de contexte immÃ©diat.",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aether://audit/live",
                        "name": "AetherScope Live Security Audit (SAST/CWE)",
                        "description": "Rapport d'audit SAST live (.aether/LIVE_AUDIT.md) analysant les 150+ motifs de vulnÃ©rabilitÃ©s CWE dÃ©tectÃ©es.",
                        "mimeType": "text/markdown"
                    },
                    {
                        "uri": "aether://contracts/manifest",
                        "name": "Aether Architecture Manifest",
                        "description": "Manifeste d'architecture aether.manifest.json ou aether.lock.toml dÃ©finissant les contrats EARS et les frontiÃ¨res de couches.",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aether://tasks/active",
                        "name": "AetherScope Active AI Tasks",
                        "description": "Registre des tâches d'ingénierie et de refactorisation pilotées par l'IA (.aether/tasks/).",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aether://agents/swarm",
                        "name": "AetherScope Multi-Agent Swarm & Chat",
                        "description": "État temps réel de tous les agents IA connectés (agent_id, nom, couleur, symbole inspecté, action) et derniers messages inter-agents.",
                        "mimeType": "application/json"
                    }
                ]
            })),
            error: None,
        }),

        "resources/read" => {
            let params = req.params.clone().unwrap_or(json!({}));
            let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");

            match uri {
                "aether://graph/summary" => {
                    let res = send_http_request(server_port, "GET", "/api/graph", None).await;
                    let text = match res {
                        Ok(val) => serde_json::to_string_pretty(&val).unwrap_or_default(),
                        Err(_) => {
                            let p_buf = PathBuf::from(default_path);
                            let scanner = ast_scanner::ProjectScanner::default();
                            let g = scanner.scan_project(&p_buf);
                            serde_json::to_string_pretty(&g).unwrap_or_default()
                        }
                    };
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "contents": [
                                {
                                    "uri": "aether://graph/summary",
                                    "mimeType": "application/json",
                                    "text": text
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                "aether://audit/live" => {
                    let audit_path = Path::new(default_path).join(".aether").join("LIVE_AUDIT.md");
                    let text = if audit_path.exists() {
                        std::fs::read_to_string(&audit_path).unwrap_or_else(|e| format!("Erreur lecture LIVE_AUDIT.md: {}", e))
                    } else {
                        let p_buf = PathBuf::from(default_path);
                        let scanner = ast_scanner::ProjectScanner::default();
                        let g = scanner.scan_project(&p_buf);
                        format_ast_summary(&g, &p_buf)
                    };
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "contents": [
                                {
                                    "uri": "aether://audit/live",
                                    "mimeType": "text/markdown",
                                    "text": text
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                "aether://contracts/manifest" => {
                    let manifest_path = Path::new(default_path).join("aether.manifest.json");
                    let dot_manifest_path = Path::new(default_path).join(".aether").join("manifest.json");
                    let lock_path = Path::new(default_path).join("aether.lock.toml");
                    let text = if manifest_path.exists() {
                        std::fs::read_to_string(&manifest_path).unwrap_or_default()
                    } else if dot_manifest_path.exists() {
                        std::fs::read_to_string(&dot_manifest_path).unwrap_or_default()
                    } else if lock_path.exists() {
                        std::fs::read_to_string(&lock_path).unwrap_or_default()
                    } else {
                        json!({
                            "project": default_path,
                            "status": "unlocked",
                            "info": "Aucun fichier aether.manifest.json ou aether.lock.toml dÃ©tectÃ© Ã  la racine."
                        }).to_string()
                    };
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "contents": [
                                {
                                    "uri": "aether://contracts/manifest",
                                    "mimeType": "application/json",
                                    "text": text
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                "aether://tasks/active" => {
                    let p_buf = PathBuf::from(default_path);
                    let raw_tasks = ai_file_bridge::TaskManager::list_tasks(&p_buf);
                    let active_tasks: Vec<_> = raw_tasks.into_iter().filter(|t| t.status != ai_file_bridge::TaskStatus::Done && t.status != ai_file_bridge::TaskStatus::Cancelled).collect();
                    let text = serde_json::to_string_pretty(&active_tasks).unwrap_or_else(|_| "[]".to_string());
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "contents": [
                                {
                                    "uri": "aether://tasks/active",
                                    "mimeType": "application/json",
                                    "text": text
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                "aether://agents/swarm" => {
                    let telem = send_http_request(server_port, "GET", "/api/ai/telemetry", None).await.ok();
                    let chat = send_http_request(server_port, "GET", "/api/ai/chat", None).await.ok();
                    let agents = telem.as_ref().and_then(|v| v.get("agents")).cloned().unwrap_or_else(|| json!([]));
                    let messages: Vec<Value> = chat
                        .as_ref()
                        .and_then(|v| v.get("messages").and_then(|m| m.as_array()))
                        .map(|arr| arr.iter().rev().take(20).cloned().collect::<Vec<_>>().into_iter().rev().collect())
                        .unwrap_or_default();
                    let text = serde_json::to_string_pretty(&json!({
                        "agents_count": agents.as_array().map(|a| a.len()).unwrap_or(0),
                        "agents": agents,
                        "recent_messages": messages
                    })).unwrap_or_else(|_| "{}".to_string());
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "contents": [
                                {
                                    "uri": "aether://agents/swarm",
                                    "mimeType": "application/json",
                                    "text": text
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                _ => Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(json!({
                        "code": -32602,
                        "message": format!("Resource not found: {}", uri)
                    })),
                }),
            }
        }

        "prompts/list" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "prompts": [
                    {
                        "name": "diagnostic_session_start",
                        "description": "Initialise la session IA en 1 seule commande MCP combinÃ©e : rÃ©sumÃ© du graphe 3D, audit des failles CWE actives et liste des tÃ¢ches en cours.",
                        "arguments": [
                            {
                                "name": "path",
                                "description": "Chemin optionnel du projet Ã  analyser (par dÃ©faut '.').",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "surgical_feature_workflow",
                        "description": "Workflow guidÃ© d'implÃ©mentation ou de refactoring chirurgical utilisant les commandes MCP combinÃ©es (Cible+CamÃ©ra+Flux -> TÃ¢che -> Code -> Pare-Feu Verify Patch).",
                        "arguments": [
                            {
                                "name": "symbol_id",
                                "description": "Symbole ou fichier cible principal (ex: 'BookingService', 'crates/core-graph/src/graph.rs').",
                                "required": true
                            },
                            {
                                "name": "objective",
                                "description": "Objectif technique Ã  rÃ©aliser sur la cible.",
                                "required": true
                            }
                        ]
                    },
                    {
                        "name": "audit_security_cwe",
                        "description": "GÃ©nÃ¨re un prompt d'audit, PoC ou remÃ©diation ciblÃ©e pour une vulnÃ©rabilitÃ© SAST / violation CWE avec les commandes MCP combinÃ©es explicites.",
                        "arguments": [
                            {
                                "name": "symbol_name",
                                "description": "Nom du symbole (fonction, classe, struct) ou chemin du fichier Ã  auditer.",
                                "required": true
                            },
                            {
                                "name": "cwe_id",
                                "description": "Identifiant CWE ou catÃ©gorie de la faille (ex: CWE-89, CWE-79, CVE-RUST-DESER-BOMB-OOM).",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "refactor_contract_violation",
                        "description": "GÃ©nÃ¨re un prompt d'analyse et de correction lorsqu'une rupture de contrat EARS, de limite de lignes ou d'import interdit est dÃ©tectÃ©e.",
                        "arguments": [
                            {
                                "name": "contract_name",
                                "description": "Nom du contrat, fichier ou module en violation.",
                                "required": true
                            },
                            {
                                "name": "violation_details",
                                "description": "DÃ©tails de l'incompatibilitÃ© ou de la violation de frontiÃ¨re.",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "scaffold_game_server",
                        "description": "GÃ©nÃ¨re un prompt guidÃ© pour l'implÃ©mentation d'une architecture serveur de jeu (Roblox Luau ou Minecraft Paper/Purpur) pilotÃ©e par les commandes MCP combinÃ©es.",
                        "arguments": [
                            {
                                "name": "engine",
                                "description": "Moteur cible : 'roblox' ou 'minecraft'.",
                                "required": true
                            },
                            {
                                "name": "package_name",
                                "description": "Nom du composant ou plugin serveur Ã  crÃ©er.",
                                "required": true
                            }
                        ]
                    }
                ]
            })),
            error: None,
        }),

        "prompts/get" => {
            let params = req.params.clone().unwrap_or(json!({}));
            let prompt_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            match prompt_name {
                "diagnostic_session_start" => {
                    let proj_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(".");
                    let prompt_text = format!(
                        "# ðŸª PROTOCOLE D'INITIALISATION MCP COMBINÃ‰ â€” AETHERSCOPE V2\n\n\
                        ExÃ©cutez votre diagnostic initial en **un minimum d'appels MCP combinÃ©s** :\n\n\
                        1. **Diagnostic Global + TÃ¢ches + Violations (1 seul appel)** :\n\
                           Appelez `aetherscope_get_graph_summary` avec `{{\"path\": \"{}\", \"rescan\": false, \"include_tasks\": true}}`.\n\
                           *(Cette commande unique remplace `get_graph_summary` + `list_tasks` + `query_violations`).*\n\
                        2. **Recherche CiblÃ©e Symboles & Failles CWE (si nÃ©cessaire)** :\n\
                           Appelez `aetherscope_search_symbols` avec `{{\"query\": \"...\", \"has_violation\": true, \"severity\": \"critical\"}}`.\n\
                        3. **Inspection ComplÃ¨te Cible + CamÃ©ra 3D + Flux Amont/Aval (1 seul appel)** :\n\
                           DÃ¨s qu'un symbole cible est identifiÃ©, appelez `aetherscope_get_active_target` avec :\n\
                           `{{\"symbol_id\": \"<symbole>\", \"action\": \"Inspection\", \"details\": \"Analyse du contrat EARS et des flux\", \"trace_direction\": \"both\"}}`.\n\
                           *(Cette commande unique tÃ©lÃ©porte automatiquement la camÃ©ra WebGL 3D, charge le contrat EARS et trace les dÃ©pendances amont/aval).*",
                        proj_path
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Diagnostic initial MCP combinÃ© pour {}", proj_path),
                            "messages": [{
                                "role": "user",
                                "content": { "type": "text", "text": prompt_text }
                            }]
                        })),
                        error: None,
                    })
                }

                "surgical_feature_workflow" => {
                    let symbol_id = arguments.get("symbol_id").and_then(|v| v.as_str()).unwrap_or("<symbole>");
                    let objective = arguments.get("objective").and_then(|v| v.as_str()).unwrap_or("ImplÃ©mentation chirurgicale");
                    let prompt_text = format!(
                        "# âš¡ WORKFLOW D'IMPLÃ‰MENTATION CHIRURGICALE MCP â€” AETHERSCOPE V2\n\
                        - **Cible :** `{}`\n\
                        - **Objectif :** {}\n\n\
                        ## ðŸ› ï¸ SÃ‰QUENCE STRICTE DES COMMANDES MCP COMBINÃ‰ES\n\
                        1. **Inspection + CamÃ©ra 3D + Trace Flux (1 appel)** :\n\
                           `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Analyse\", \"details\": \"{}\", \"trace_direction\": \"both\"}})`\n\
                        2. **CrÃ©ation / Suivi de TÃ¢che + Focus CamÃ©ra (1 appel)** :\n\
                           `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"{}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                        3. **Modification Chirurgicale du Code** :\n\
                           Ã‰ditez uniquement les fonctions ciblÃ©es dans le respect strict du `README.md` parent (invariants EARS, imports autorisÃ©s, budget de lignes).\n\
                        4. **Pare-Feu Temps RÃ©el <50ms + ClÃ´ture TÃ¢che + Debrief Chat (1 appel combinÃ©)** :\n\
                           `aetherscope_verify_patch({{\"files_modified\": [\"<fichier_modifiÃ©>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"progress_note\": \"Patch validÃ© par le pare-feu SAST/EARS\", \"chat_message\": \"Objectif terminÃ© et certifiÃ© sans rÃ©gression sur `{}`.\"}})`",
                        symbol_id, objective, symbol_id, objective, objective, symbol_id, symbol_id
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Workflow chirurgical MCP pour {} : {}", symbol_id, objective),
                            "messages": [{
                                "role": "user",
                                "content": { "type": "text", "text": prompt_text }
                            }]
                        })),
                        error: None,
                    })
                }

                "audit_security_cwe" => {
                    let symbol_name = arguments.get("symbol_name").and_then(|v| v.as_str()).unwrap_or("<symbole>");
                    let cwe_id = arguments.get("cwe_id").and_then(|v| v.as_str()).unwrap_or("CWE Anomaly");
                    let prompt_text = format!(
                        "# ðŸ›¡ï¸ AUDIT & REMÃ‰DIATION SAST/CWE MCP â€” AETHERSCOPE V2\n\
                        Vous Ãªtes l'architecte de sÃ©curitÃ© AetherScope. Auditez et corrigez la cible `{}` concernÃ©e par la vulnÃ©rabilitÃ© `{}`.\n\n\
                        ## ðŸ› ï¸ COMMANDES MCP COMBINÃ‰ES Ã€ EXÃ‰CUTER\n\
                        1. **Focus CamÃ©ra 3D + Contrat EARS + Trace d'AtteignabilitÃ© Source-to-Sink (1 appel)** :\n\
                           `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Correction CVE\", \"details\": \"Audit {} sur {}\", \"trace_direction\": \"both\"}})`\n\
                        2. **Filtrage PrÃ©cis des Violations CWE (si besoin de contexte additionnel)** :\n\
                           `aetherscope_search_symbols({{\"query\": \"{}\", \"cwe_id\": \"{}\", \"has_violation\": true}})`\n\
                        3. **DÃ©claration de la TÃ¢che de SÃ©curitÃ© (1 appel)** :\n\
                           `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Fix {} sur {}\", \"kind\": \"security_fix\", \"target_symbol\": \"{}\", \"priority\": \"critical\"}})`\n\
                        4. **Application du Patch Minimal & Certification Pare-Feu <50ms + ClÃ´ture (1 appel)** :\n\
                           AprÃ¨s avoir corrigÃ© la faille sans casser les signatures publiques, appelez obligatoirement :\n\
                           `aetherscope_verify_patch({{\"files_modified\": [\"<fichier_corrigÃ©>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"VulnÃ©rabilitÃ© {} corrigÃ©e et vÃ©rifiÃ©e sur `{}`.\"}})`",
                        symbol_name, cwe_id, symbol_name, cwe_id, symbol_name, symbol_name, cwe_id, cwe_id, symbol_name, symbol_name, cwe_id, symbol_name
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Audit de sÃ©curitÃ© AetherScope pour {} ({})", symbol_name, cwe_id),
                            "messages": [
                                {
                                    "role": "user",
                                    "content": {
                                        "type": "text",
                                        "text": prompt_text
                                    }
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                "scaffold_game_server" => {
                    let engine = arguments.get("engine").and_then(|v| v.as_str()).unwrap_or("roblox");
                    let package_name = arguments.get("package_name").and_then(|v| v.as_str()).unwrap_or("GameCore");
                    let prompt_text = if engine.to_lowercase().contains("roblox") {
                        format!(
                            "# ðŸŽ® SCAFFOLDING SERVEUR ROBLOX LUAU MCP â€” `{}`\n\n\
                            SpÃ©cifications techniques :\n\
                            - Architecture contractuelle stricte : `contracts/` pour les paquets rÃ©seau RemoteEvent/RemoteFunction avec typage Luau strict (`--!strict`).\n\
                            - SÃ©paration stricte : `server/` (logique d'autoritÃ© exclusive), `client/` (prÃ©diction locale, zÃ©ro trust), `data-nodes/` (sauvegarde DataStore atomique).\n\n\
                            ## ðŸ› ï¸ COMMANDES MCP COMBINÃ‰ES Ã€ EXÃ‰CUTER\n\
                            1. `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Scaffolding module Roblox {}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                            2. `aetherscope_verify_patch({{\"files_modified\": [\"<fichiers_crÃ©Ã©s>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Module Roblox Luau `{}` gÃ©nÃ©rÃ© et validÃ©.\"}})`",
                            package_name, package_name, package_name, package_name
                        )
                    } else {
                        format!(
                            "# ðŸŽ® SCAFFOLDING SERVEUR MINECRAFT PAPER/PURPUR MCP â€” `{}`\n\n\
                            SpÃ©cifications techniques :\n\
                            - Architecture dÃ©couplÃ©e : API & Contrats d'Ã©vÃ©nements sÃ©parÃ©s de l'implÃ©mentation Bukkit/Spigot.\n\
                            - Concurrency & Tick-safety : Aucun blocage sur le Main Thread tick de 50ms, utilisation d'AsyncScheduler et collections concurrentes.\n\n\
                            ## ðŸ› ï¸ COMMANDES MCP COMBINÃ‰ES Ã€ EXÃ‰CUTER\n\
                            1. `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Scaffolding plugin Paper {}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                            2. `aetherscope_verify_patch({{\"files_modified\": [\"<fichiers_crÃ©Ã©s>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Plugin Minecraft `{}` gÃ©nÃ©rÃ© et validÃ©.\"}})`",
                            package_name, package_name, package_name, package_name
                        )
                    };
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Scaffolding serveur de jeu {} pour {}", engine, package_name),
                            "messages": [
                                {
                                    "role": "user",
                                    "content": {
                                        "type": "text",
                                        "text": prompt_text
                                    }
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                "refactor_contract_violation" => {
                    let contract_name = arguments.get("contract_name").and_then(|v| v.as_str()).unwrap_or("<contrat>");
                    let details = arguments.get("violation_details").and_then(|v| v.as_str()).unwrap_or("Non-respect des rÃ¨gles EARS ou fuite de dÃ©pendances.");
                    let prompt_text = format!(
                        "# ðŸ›ï¸ RÃ‰SOLUTION DE VIOLATION DE CONTRAT EARS MCP â€” `{}`\n\
                        DÃ©tails de l'infraction : `{}`\n\n\
                        ## ðŸ› ï¸ COMMANDES MCP COMBINÃ‰ES Ã€ EXÃ‰CUTER\n\
                        1. **Inspection Cible + CamÃ©ra 3D + Trace Flux Amont/Aval (1 appel)** :\n\
                           `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Refactoring\", \"details\": \"RÃ©solution violation de contrat EARS\", \"trace_direction\": \"both\"}})`\n\
                        2. **CrÃ©ation de la TÃ¢che de Refactoring (1 appel)** :\n\
                           `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"ConformitÃ© contrat EARS {}\", \"kind\": \"arch_refactor\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                        3. **Correction Chirurgicale** :\n\
                           Supprimez les imports interdits (`RULE_FORBIDDEN_IMPORT`), respectez le budget de lignes (`RULE_MAX_LINES`) et les invariants EARS du `README.md`.\n\
                        4. **Validation Pare-Feu <50ms + ClÃ´ture TÃ¢che + Notification Chat (1 appel)** :\n\
                           `aetherscope_verify_patch({{\"files_modified\": [\"<fichier_modifiÃ©>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Contrat EARS restaurÃ© et certifiÃ© pour `{}`.\"}})`",
                        contract_name, details, contract_name, contract_name, contract_name, contract_name
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("RÃ©solution violation contrat {}", contract_name),
                            "messages": [
                                {
                                    "role": "user",
                                    "content": {
                                        "type": "text",
                                        "text": prompt_text
                                    }
                                }
                            ]
                        })),
                        error: None,
                    })
                }

                _ => Some(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(json!({
                        "code": -32602,
                        "message": format!("Prompt not found: {}", prompt_name)
                    })),
                }),
            }
        }

        "tools/list" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "tools": [
                    {
                        "name": "aetherscope_get_graph_summary",
                        "description": "[COMMANDE COMBINÉE 4-EN-1] Récupère en 1 seul appel l'architecture globale du projet (nœuds, arêtes, dossiers), la classification du projet (Obsidian Vault, Code Project ou Mixed), le mode de vision actif ('code' ou 'vault'), les métriques de notes Obsidian (wikilinks, tags, backlinks), les violations de sécurité SAST/CWE actives, la liste des tâches en cours (include_tasks=true) et peut forcer une réanalyse complète AST/Vault (rescan=true).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet à analyser ou basculer (par défaut le projet actif)",
                                    "examples": [".", "crates/desktop-shell", "crates/core-graph"]
                                },
                                "rescan": {
                                    "type": "boolean",
                                    "description": "Si true, force une réanalyse complète de l'arbre AST ou du vault Obsidian avant de renvoyer le résumé"
                                },
                                "include_tasks": {
                                    "type": "boolean",
                                    "description": "Si true (défaut), inclut directement la liste des tâches actives du projet dans le résumé"
                                },
                                "severity": {
                                    "type": "string",
                                    "description": "Filtre optionnel de sévérité pour détailler les violations SAST/CWE ('critical', 'high', 'all')",
                                    "enum": ["all", "critical", "high", "medium", "low", "warning"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Diagnostic Global Combiné (Code AST + Vault Obsidian + Tâches + CWE)",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_get_active_target",
                        "description": "[COMMANDE COMBINÉE 3-EN-1] En 1 seul appel : (1) Téléporte la caméra 3D WebGL et met à jour le HUD de télémétrie, (2) Récupère le contexte complet : contrat EARS/MVC pour les symboles de code OU métadonnées YAML, tags, en-têtes et wikilinks pour les notes Obsidian («Note»), et (3) Trace automatiquement le flux amont/aval ou les backlinks/wikilinks (trace_direction='both').",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "symbol_id": {
                                    "type": "string",
                                    "description": "Nom ou identifiant du symbole, fichier de code ou note Obsidian cible (ex: 'handle_booking', 'note::docs/Architecture.md', 'Architecture')",
                                    "examples": ["handle_booking", "Architecture", "docs/overview.md"]
                                },
                                "action": {
                                    "type": "string",
                                    "description": "Badge d'action affiché en direct sur le HUD 3D lors de la téléportation caméra (défaut: 'Inspection')",
                                    "examples": ["Inspection", "Analyse", "Refactoring", "Correction CVE", "Audit Notes"]
                                },
                                "details": {
                                    "type": "string",
                                    "description": "Description technique courte affichée dans le journal de télémétrie 3D"
                                },
                                "trace_direction": {
                                    "type": "string",
                                    "description": "Direction du traçage de flux / liens : 'both' (défaut), 'upstream' (appelants/backlinks), 'downstream' (dépendances/wikilinks), ou 'none'",
                                    "enum": ["both", "upstream", "downstream", "none"]
                                },
                                "max_depth": {
                                    "type": "integer",
                                    "description": "Profondeur maximale du traçage (défaut: 2, max: 5)",
                                    "minimum": 1,
                                    "maximum": 5
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet cible"
                                },
                                "agent_id": {
                                    "type": "string",
                                    "description": "Identifiant unique de l'agent appelant pour la coordination multi-agents (ex: 'claude-sec-1', 'gemini-ui')"
                                },
                                "agent_name": {
                                    "type": "string",
                                    "description": "Nom lisible de l'agent affiché sur la constellation 3D (ex: 'Claude Security', 'Gemini Architect')"
                                },
                                "color": {
                                    "type": "string",
                                    "description": "Couleur hexadécimale optionnelle de l'halo de l'agent sur le graphe 3D (ex: '#f472b6', '#38bdf8')"
                                }
                            },
                            "required": ["symbol_id"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Inspection Cible Combinée (Code AST / Note Obsidian + Caméra 3D + Flux)",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_search_symbols",
                        "description": "[COMMANDE COMBINÉE 2-EN-1] Recherche multi-critères dans l'index (symboles AST de code, notes Obsidian, tags '#tag', alias YAML, couche MVC/docs, stéréotype '«Note»') ET filtrage détaillé des violations SAST/CWE avec recommandations de remédiation.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Texte ou mot-clé à rechercher : nom de symbole, titre de note, tag Obsidian (ex: '#dev/db'), alias YAML ou en-tête",
                                    "examples": ["checkout", "#kb/arch", "Architecture", "BookingService"]
                                },
                                "layer": {
                                    "type": "string",
                                    "description": "Couche architecturale : 'ui', 'action', 'domain', 'database', 'utility', 'config', 'docs' ou 'all'",
                                    "enum": ["ui", "action", "domain", "database", "utility", "config", "docs", "all"]
                                },
                                "kind": {
                                    "type": "string",
                                    "description": "Type de symbole : 'function', 'file', 'class', 'endpoint', 'contract' ou 'all'",
                                    "enum": ["function", "file", "class", "endpoint", "contract", "all"]
                                },
                                "stereotype": {
                                    "type": "string",
                                    "description": "Stéréotype architectural ou Obsidian (ex: '«Model»', '«Controller»', '«Note»', '«GhostNote»', '«Attachment»')"
                                },
                                "has_violation": {
                                    "type": "boolean",
                                    "description": "Filtrer uniquement les symboles ayant des violations de sécurité ou CVE détectées"
                                },
                                "cwe_id": {
                                    "type": "string",
                                    "description": "Filtre direct sur un identifiant CWE ou règle SAST (ex: 'CWE-89', 'CWE-22')"
                                },
                                "severity": {
                                    "type": "string",
                                    "description": "Niveau de sévérité des violations à auditer : 'all', 'critical', 'high', 'medium', 'low', 'warning'",
                                    "enum": ["all", "critical", "high", "medium", "low", "warning"]
                                },
                                "file_pattern": {
                                    "type": "string",
                                    "description": "Filtre sur le chemin ou nom de fichier pour l'audit de violations"
                                },
                                "limit": {
                                    "type": "integer",
                                    "description": "Nombre maximum de résultats (défaut: 15, max: 50)",
                                    "minimum": 1,
                                    "maximum": 50
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet cible"
                                },
                                "agent_id": {
                                    "type": "string",
                                    "description": "Identifiant de l'agent effectuant la recherche (partage sa zone de recherche avec les pairs)"
                                },
                                "agent_name": {
                                    "type": "string",
                                    "description": "Nom affiché de l'agent chercheur"
                                },
                                "color": {
                                    "type": "string",
                                    "description": "Couleur hexadécimale de l'agent chercheur"
                                },
                                "scope_mode": {
                                    "type": "string",
                                    "description": "Mode Bug Bounty PoC Scope : 'all' (défaut), 'in_scope_only' (filtre les cibles In-Scope), 'out_of_scope_only', 'recommend_scope' (calcule les recommandations In-Scope/Out-Scope selon la surface d'attaque AST/CWE), ou 'configure_scope' (met à jour le scope PoC du projet)",
                                    "enum": ["all", "in_scope_only", "out_of_scope_only", "recommend_scope", "configure_scope"]
                                },
                                "in_scope": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Liste des dossiers/modules à placer en In-Scope (pour scope_mode='configure_scope')"
                                },
                                "out_of_scope": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Liste des dossiers/modules à exclure en Out-of-Scope (pour scope_mode='configure_scope')"
                                },
                                "scope_rationale": {
                                    "type": "string",
                                    "description": "Justification de l'IA sur le choix du périmètre In-Scope / Out-of-Scope"
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Recherche AST & Notes Obsidian + Audit Violations Combinés",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_switch_view_mode",
                        "description": "Bascule dynamiquement le mode de vision du cockpit AetherScope entre 'code' (graphe d'architecture AST 3D) et 'vault' (graphe de notes Obsidian 3D). Met à jour en direct le graphe actif dans le visualiseur WebGL 2.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "mode": {
                                    "type": "string",
                                    "description": "Mode de vision cible dans le cockpit : 'code' (architecture logicielle) ou 'vault' (graphe de notes Obsidian)",
                                    "enum": ["code", "vault"]
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet cible (par défaut le projet actif)"
                                }
                            },
                            "required": ["mode"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Bascule Vision Cockpit (Code / Vault)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_manage_tasks",
                        "description": "[COMMANDE COMBINÃ‰E 3-EN-1] Gestion unifiÃ©e des tÃ¢ches AetherScope (action = 'list' | 'create' | 'update') avec mini-README dans .aether/tasks/ et tÃ©lÃ©portation automatique de la camÃ©ra 3D lorsque target_symbol est renseignÃ©.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "OpÃ©ration Ã  effectuer : 'list' (lister les tÃ¢ches), 'create' (crÃ©er une tÃ¢che), ou 'update' (mettre Ã  jour statut/progrÃ¨s/README)",
                                    "enum": ["list", "create", "update"],
                                    "examples": ["list", "create", "update"]
                                },
                                "task_id": {
                                    "type": "string",
                                    "description": "Identifiant de la tÃ¢che (requis pour action='update')"
                                },
                                "title": {
                                    "type": "string",
                                    "description": "Titre explicite de la tÃ¢che (requis pour action='create')"
                                },
                                "kind": {
                                    "type": "string",
                                    "description": "Type de tÃ¢che pour 'create' : 'function', 'research', 'security_fix', 'arch_refactor', 'documentation', 'test', 'other'",
                                    "enum": ["function", "research", "security_fix", "arch_refactor", "documentation", "test", "other"]
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Symbole AST ciblÃ© (aligne automatiquement la camÃ©ra 3D sur ce symbole)"
                                },
                                "target_file": {
                                    "type": "string",
                                    "description": "Chemin du fichier concernÃ©"
                                },
                                "priority": {
                                    "type": "string",
                                    "description": "PrioritÃ© ('low', 'medium', 'high', 'critical')",
                                    "enum": ["low", "medium", "high", "critical"]
                                },
                                "status": {
                                    "type": "string",
                                    "description": "Nouveau statut pour 'update' ('pending', 'in_progress', 'blocked', 'done', 'cancelled')",
                                    "enum": ["pending", "in_progress", "blocked", "done", "cancelled"]
                                },
                                "progress": {
                                    "type": "integer",
                                    "description": "Pourcentage d'avancement 0-100 pour 'update'",
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "progress_note": {
                                    "type": "string",
                                    "description": "Note d'avancement ajoutÃ©e au mini-README de la tÃ¢che"
                                },
                                "initial_readme": {
                                    "type": "string",
                                    "description": "Contenu Markdown initial pour 'create'"
                                },
                                "full_readme": {
                                    "type": "string",
                                    "description": "Contenu Markdown complet de remplacement pour 'update'"
                                },
                                "status_filter": {
                                    "type": "string",
                                    "description": "Filtre pour action='list' : 'active' (dÃ©faut), 'all', 'done'",
                                    "enum": ["active", "all", "done"]
                                }
                            },
                            "required": ["action"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Gestionnaire UnifiÃ© des TÃ¢ches (List / Create / Update)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_verify_patch",
                        "description": "[COMMANDE COMBINÃ‰E 4-EN-1] Pare-Feu IA Temps RÃ©el (< 50 ms) : (1) Analyse incrÃ©mentale SAST 150+ CWE + conformitÃ© contrat EARS/BLAKE3 sur files_modified, (2) TÃ©lÃ©porte la camÃ©ra 3D, (3) Met Ã  jour automatiquement la tÃ¢che associÃ©e (si task_id fourni et patch approuvÃ©), et (4) Publie le compte-rendu dans le chat AetherScope (si chat_message fourni).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "files_modified": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Chemins relatifs ou absolus des fichiers modifiÃ©s ou gÃ©nÃ©rÃ©s par l'IA"
                                },
                                "task_id": {
                                    "type": "string",
                                    "description": "Optionnel : ID de la tÃ¢che Ã  mettre Ã  jour automatiquement si le pare-feu approuve le patch"
                                },
                                "status": {
                                    "type": "string",
                                    "description": "Optionnel : Nouveau statut de la tÃ¢che (ex: 'done', 'in_progress') si task_id est fourni",
                                    "enum": ["pending", "in_progress", "blocked", "done", "cancelled"]
                                },
                                "progress": {
                                    "type": "integer",
                                    "description": "Optionnel : Pourcentage d'avancement (0-100) de la tÃ¢che si task_id est fourni",
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "progress_note": {
                                    "type": "string",
                                    "description": "Optionnel : Note de progrÃ¨s Ã  consigner dans la tÃ¢che si task_id est fourni"
                                },
                                "chat_message": {
                                    "type": "string",
                                    "description": "Optionnel : Compte-rendu final envoyÃ© simultanÃ©ment dans le Chat Copilot AetherScope"
                                }
                            },
                            "required": ["files_modified"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Pare-Feu IA Temps RÃ©el + ClÃ´ture TÃ¢che & Chat CombinÃ©s",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_chat",
                        "description": "[COMMANDE COMBINÉE 3-EN-1 Multi-Agents] Poste un message/hand-off dans le canal partagé (action='send', avec identité agent_id/agent_name et destinataire optionnel @recipient), lit l'historique filtrable (action='history'), ou liste l'essaim d'agents actifs (action='swarm').",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "'send' (défaut si text est présent) pour poster, 'history' pour lire les messages (filtrable par recipient), ou 'swarm' pour lister les agents actifs et leurs cibles",
                                    "enum": ["send", "history", "swarm"]
                                },
                                "text": {
                                    "type": "string",
                                    "description": "Contenu Markdown du message à afficher dans le chat AetherScope (requis si action='send')"
                                },
                                "thought": {
                                    "type": "string",
                                    "description": "Raisonnement interne de l'IA (optionnel)"
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Symbole ou fichier associé au message (aligne aussi la caméra 3D)"
                                },
                                "agent_id": {
                                    "type": "string",
                                    "description": "Identifiant unique de l'agent émetteur (ex: 'claude-sec', 'codex-refactor')"
                                },
                                "agent_name": {
                                    "type": "string",
                                    "description": "Nom affiché de l'agent émetteur dans le chat partagé"
                                },
                                "recipient": {
                                    "type": "string",
                                    "description": "Agent destinataire (@mention pour hand-off en send, ou filtre d'inbox en history, ex: 'gemini-ui' ou 'all')"
                                },
                                "color": {
                                    "type": "string",
                                    "description": "Couleur badge hexadécimale de l'agent (ex: '#38bdf8')"
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Chat Copilot AetherScope CombinÃ© (Send & History)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_manage_plugins",
                        "description": "[COMMANDE COMBINÃ‰E 4-EN-1] Gestion complÃ¨te des plugins de sÃ©curitÃ© YAML dans .aether/plugins : 'list' (inventaire), 'test' (exÃ©cution des tests unitaires des rÃ¨gles), 'scan' (audit d'un fichier/dossier), ou 'upsert' (crÃ©ation/mise Ã  jour et certification d'une rÃ¨gle CWE).",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "OpÃ©ration plugin : 'list', 'test', 'scan', ou 'upsert'",
                                    "enum": ["list", "test", "scan", "upsert"]
                                },
                                "target_path": {
                                    "type": "string",
                                    "description": "Fichier ou dossier Ã  auditer (requis pour action='scan')"
                                },
                                "plugins_dir": {
                                    "type": "string",
                                    "description": "Chemin du dossier plugins (dÃ©faut: '.aether/plugins')"
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin racine optionnel du projet"
                                },
                                "plugin_name": { "type": "string", "description": "Nom du plugin (pour action='upsert')" },
                                "rule_id": { "type": "string", "description": "ID unique de la rÃ¨gle (pour action='upsert')" },
                                "cwe_id": { "type": "string", "description": "Identifiant CWE (pour action='upsert')" },
                                "name": { "type": "string", "description": "Nom court de la rÃ¨gle (pour action='upsert')" },
                                "severity": {
                                    "type": "string",
                                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW"],
                                    "description": "SÃ©vÃ©ritÃ© (pour action='upsert')"
                                },
                                "description": { "type": "string", "description": "Description de la faille (pour action='upsert')" },
                                "remediation": { "type": "string", "description": "RemÃ©diation certifiÃ©e (pour action='upsert')" },
                                "file_extensions": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Extensions ciblÃ©es ex: ['.rs', '.py', '.ts'] (pour action='upsert')"
                                },
                                "match_mode": {
                                    "type": "string",
                                    "enum": ["line_by_line", "whole_file"]
                                },
                                "must_contain": { "type": "array", "items": { "type": "string" } },
                                "must_not_contain": { "type": "array", "items": { "type": "string" } },
                                "regex_patterns": { "type": "array", "items": { "type": "string" } },
                                "forbidden_tokens": { "type": "array", "items": { "type": "string" } },
                                "check_literals": { "type": "boolean" },
                                "test_cases": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "code": { "type": "string" },
                                            "file_name": { "type": "string" },
                                            "should_trigger": { "type": "boolean" }
                                        },
                                        "required": ["name", "code", "file_name", "should_trigger"]
                                    }
                                }
                            },
                            "required": ["action"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Gestionnaire UnifiÃ© des Plugins CWE (List / Test / Scan / Upsert)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_teleport_camera",
                        "description": "Oriente directement la camÃ©ra WebGL 3D d'AetherScope vers un symbole ou un fichier et met Ã  jour le fil d'Ariane stellaire (utile pour un dÃ©placement rapide sans recharger le contrat complet).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "Nom du symbole, fichier ou dossier cible (ex: 'RoomBooking', 'contracts/packets.rs')",
                                    "examples": ["RoomBooking", "BookingEngine", "contracts/packets.rs", "server/api"]
                                },
                                "action": {
                                    "type": "string",
                                    "description": "Action en cours (ex: 'Inspection', 'Analyse', 'Refactoring', 'Correction CVE', 'Audit', 'Tests')",
                                    "examples": ["Inspection", "Refactoring", "Correction CVE", "Audit", "Tests"]
                                },
                                "details": {
                                    "type": "string",
                                    "description": "Courte description technique de ce que vous observez ou réalisez",
                                    "examples": ["Vérification des invariants et de la non-nullabilité du token d'accès"]
                                },
                                "agent_id": {
                                    "type": "string",
                                    "description": "Identifiant unique de l'agent pour afficher son propre halo et fil d'Ariane sans écraser les autres agents"
                                },
                                "agent_name": {
                                    "type": "string",
                                    "description": "Nom court de l'agent (ex: 'Claude-Sec', 'Gemini-Arch')"
                                },
                                "color": {
                                    "type": "string",
                                    "description": "Couleur hexadécimale du halo de l'agent (ex: '#f472b6', '#34d399')"
                                }
                            },
                            "required": ["target", "action", "details"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Téléportation Caméra 3D AetherScope",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_scan_project",
                        "description": "Déclenche une réanalyse complète de l'architecture d'un projet pour rafraîchir l'arbre AST et le graphe 3D.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Chemin du projet à réanalyser",
                                    "examples": [".", "../monorepo", "crates/desktop-shell"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Scan & Analyse Architecturale du Projet",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    }
                ]
            })),
            error: None,
        }),

        _ => return None,
    };
    Some(res)
}

pub(crate) fn format_graph_summary(val: &Value, status_opt: Option<&Value>) -> String {
    let project_name = val.get("project_name").and_then(|v| v.as_str()).unwrap_or("Projet AetherScope");
    let project_path = val.get("project_path").and_then(|v| v.as_str()).unwrap_or("");
    let nodes = val.get("nodes").and_then(|v| v.as_array());
    let edges = val.get("edges").and_then(|v| v.as_array());
    let total_nodes = nodes.map(|n| n.len()).unwrap_or(0);
    let total_edges = edges.map(|e| e.len()).unwrap_or(0);

    let mut folders = std::collections::BTreeMap::new();
    let mut violations = Vec::new();
    let mut notes_count = 0usize;
    let mut ghost_notes_count = 0usize;
    let mut attachments_count = 0usize;
    let mut code_symbols_count = 0usize;
    let mut unique_tags = std::collections::HashSet::new();

    if let Some(nodes_arr) = nodes {
        for n in nodes_arr {
            let f = n.get("folder").and_then(|v| v.as_str()).unwrap_or("root");
            *folders.entry(f.to_string()).or_insert(0usize) += 1;

            let st = n.get("stereotype").and_then(|v| v.as_str()).unwrap_or("");
            let sym_type = n.get("symbol_type").and_then(|v| v.as_str()).unwrap_or("");
            let layer = n.get("layer").and_then(|v| v.as_str()).unwrap_or("");

            if st == "«GhostNote»" || sym_type == "ghost_note" {
                ghost_notes_count += 1;
            } else if st == "«Attachment»" || sym_type == "attachment" {
                attachments_count += 1;
            } else if st == "«Note»" || sym_type == "note" || layer == "docs" {
                notes_count += 1;
                if let Some(attrs) = n.get("metadata").and_then(|m| m.get("attributes")).and_then(|a| a.as_array()) {
                    for attr in attrs {
                        if attr.get("name").and_then(|v| v.as_str()) == Some("tag") {
                            if let Some(t) = attr.get("type").and_then(|v| v.as_str()) {
                                unique_tags.insert(t.to_string());
                            }
                        }
                    }
                }
            } else {
                code_symbols_count += 1;
            }

            if n.get("has_security_violation").and_then(|v| v.as_bool()).unwrap_or(false) {
                let name = n.get("name").and_then(|v| v.as_str()).unwrap_or("inconnu");
                let file = n.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                let cve_list = n.get("metadata").and_then(|m| m.get("cve_anomalies")).and_then(|c| c.as_array());
                let cve_desc = if let Some(arr) = cve_list {
                    if !arr.is_empty() {
                        let cve_id = arr[0].get("cve_id").and_then(|i| i.as_str()).unwrap_or("CVE");
                        let sev = arr[0].get("severity").and_then(|s| s.as_str()).unwrap_or("HIGH");
                        format!(" [{}: {}]", sev, cve_id)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                violations.push(format!("- 🚨 `{}`{} — `{}`", name, cve_desc, file));
            }
        }
    }

    let mut wikilinks_count = 0usize;
    let mut embeds_count = 0usize;
    if let Some(edges_arr) = edges {
        for e in edges_arr {
            let rel = e.get("relation").and_then(|v| v.as_str()).unwrap_or("");
            if rel == "links_to" {
                wikilinks_count += 1;
            } else if rel == "embeds" {
                embeds_count += 1;
            }
        }
    }

    // Determine Project Type and Active View Mode
    let (project_type_str, active_view_str, supported_views_str) = if let Some(st) = status_opt {
        let raw_p_type = st.get("project_type").and_then(|v| v.as_str()).unwrap_or("Code Project");
        let p_type = match raw_p_type {
            "PureObsidianVault" | "Obsidian Vault" => "Obsidian Vault",
            "Mixed" | "Mixed Project" => "Mixed Project",
            "PureCode" | "Code Project" => "Code Project",
            other => other,
        };
        let a_view = st.get("active_view")
            .or_else(|| st.get("active_view_mode"))
            .or_else(|| st.get("default_view"))
            .and_then(|v| v.as_str())
            .unwrap_or(if p_type == "Obsidian Vault" { "vault" } else { "code" });
        let s_views: Vec<String> = st.get("supported_views")
            .and_then(|v| v.as_array())
            .filter(|arr| !arr.is_empty())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| format!("'{}'", s))).collect())
            .unwrap_or_else(|| {
                if p_type == "Obsidian Vault" {
                    vec!["'vault'".to_string(), "'code'".to_string()]
                } else if p_type == "Mixed Project" {
                    vec!["'code'".to_string(), "'vault'".to_string()]
                } else {
                    vec!["'code'".to_string()]
                }
            });
        (p_type.to_string(), a_view.to_string(), s_views.join(", "))
    } else if notes_count > 0 && code_symbols_count > 0 {
        ("Mixed Project".to_string(), "vault".to_string(), "'code', 'vault'".to_string())
    } else if notes_count > 0 {
        ("Obsidian Vault".to_string(), "vault".to_string(), "'vault', 'code'".to_string())
    } else {
        ("Code Project".to_string(), "code".to_string(), "'code'".to_string())
    };

    let mut folders_str = String::new();
    for (f, cnt) in folders.iter().take(15) {
        folders_str.push_str(&format!("  - 📁 `{}` : {} symbole(s)\n", f, cnt));
    }
    if folders.len() > 15 {
        folders_str.push_str(&format!("  - ... et {} autre(s) dossier(s)\n", folders.len() - 15));
    }

    let violations_str = if violations.is_empty() {
        "✅ Aucune violation de sécurité ou CVE détectée.".to_string()
    } else {
        let total_v = violations.len();
        let display_v: Vec<String> = violations.into_iter().take(15).collect();
        let more_msg = if total_v > 15 {
            format!("\n  ... et {} autre(s) violation(s). Rapport complet disponible dans `.aether/LIVE_AUDIT.md`", total_v - 15)
        } else {
            String::new()
        };
        format!("⚠️ {} Violation(s) de sécurité / CVE détectée(s) :\n{}{}", total_v, display_v.join("\n"), more_msg)
    };

    let path_line = if !project_path.is_empty() {
        format!("• Emplacement : `{}`\n", project_path)
    } else {
        String::new()
    };

    let mut vault_section = String::new();
    if notes_count > 0 || ghost_notes_count > 0 || attachments_count > 0 || project_type_str.contains("Vault") || project_type_str.contains("Mixed") {
        vault_section = format!(
            "• Graphe de Notes Obsidian :\n\
               - 📝 Notes Markdown : {}\n\
               - 🔗 Wikilinks : {} relations\n\
               - 📎 Transclusions & Pièces jointes : {} embeds ({} fichiers joints)\n\
               - 🏷️ Tags uniques : {} tags\n\
               - 👻 Notes fantômes : {} cible(s) non résolue(s)\n",
            notes_count, wikilinks_count, embeds_count, attachments_count, unique_tags.len(), ghost_notes_count
        );
    }

    format!(
        "🪐 Résumé Architectural & Connaissances AetherScope V2 :\n\
         • Projet Actif : `{}`\n\
         • Type de Projet : `{}`\n\
         • Mode de Vision Actif : `{}` (Visions disponibles: [{supp}])\n\
         {}\
         {}\
         • Total Nœuds (Bulles) : {}\n\
         • Total Relations (Arêtes) : {}\n\
         • Modules / Dossiers ({} au total) :\n{}\
         • Statut Sécurité & Règles :\n{}\n\
         • Visualiseur WebGL 2 disponible sur http://127.0.0.1:3030",
        project_name,
        project_type_str,
        active_view_str,
        path_line,
        vault_section,
        total_nodes,
        total_edges,
        folders.len(),
        folders_str,
        violations_str,
        supp = supported_views_str
    )
}

pub(crate) fn format_ast_summary(g: &core_graph::graph::AetherGraph, project_root: &Path) -> String {
    let total_nodes = g.nodes.len();
    let total_edges = g.edges.len();

    let mut folders = std::collections::BTreeMap::new();
    let mut violations = Vec::new();
    for n in &g.nodes {
        let f = if n.folder.is_empty() { "root" } else { &n.folder };
        *folders.entry(f.to_string()).or_insert(0usize) += 1;
        if n.has_security_violation {
            let cve_desc = if !n.metadata.cve_anomalies.is_empty() {
                format!(" [{}: {}]", n.metadata.cve_anomalies[0].severity, n.metadata.cve_anomalies[0].cve_id)
            } else {
                String::new()
            };
            violations.push(format!("- ðŸš¨ `{}`{} â€” `{}`", n.name, cve_desc, n.file_path));
        }
    }

    let mut folders_str = String::new();
    for (f, cnt) in folders.iter().take(15) {
        folders_str.push_str(&format!("  - ðŸ“ `{}` : {} symbole(s)\n", f, cnt));
    }
    if folders.len() > 15 {
        folders_str.push_str(&format!("  - ... et {} autre(s) dossier(s)\n", folders.len() - 15));
    }

    let violations_str = if violations.is_empty() {
        "âœ… Aucune violation de sÃ©curitÃ© ou CVE dÃ©tectÃ©e.".to_string()
    } else {
        let total_v = violations.len();
        let display_v: Vec<String> = violations.into_iter().take(15).collect();
        let more_msg = if total_v > 15 {
            format!("\n  ... et {} autre(s) violation(s). Rapport complet disponible dans `.aether/LIVE_AUDIT.md`", total_v - 15)
        } else {
            String::new()
        };
        format!("âš ï¸ {} Violation(s) de sÃ©curitÃ© / CVE dÃ©tectÃ©e(s) :\n{}{}", total_v, display_v.join("\n"), more_msg)
    };

    format!(
        "ðŸª RÃ©sumÃ© Architectural AetherScope V2 (Mode Autonome AST) :\n\
         â€¢ Projet Actif : `{}`\n\
         â€¢ Emplacement : `{}`\n\
         â€¢ Total NÅ“uds (Bulles) : {}\n\
         â€¢ Total Relations (ArÃªtes) : {}\n\
         â€¢ Modules / Dossiers ({} au total) :\n{}\
         â€¢ Statut SÃ©curitÃ© & RÃ¨gles :\n{}\n\
         â€¢ Note : Lancez `aether-engine` pour activer la vue WebGL 2 interactive en direct.",
        g.project_name, project_root.display(), total_nodes, total_edges, folders.len(), folders_str, violations_str
    )
}

pub(crate) fn format_active_target_response(val: &Value) -> String {
    let status = val.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
    if status != "ok" {
        return "âš ï¸ Symbole ou module non trouvÃ© dans le graphe actif AetherScope.".to_string();
    }

    if let Some(md) = val.get("formatted_doc_and_liaisons").and_then(|v| v.as_str()) {
        let handshake = val.get("handshake_xml").and_then(|v| v.as_str()).unwrap_or("");
        if !handshake.is_empty() {
            format!("{}\n\n### ðŸ¤ Handshake Copilote IA :\n```xml\n{}\n```", md, handshake)
        } else {
            md.to_string()
        }
    } else {
        serde_json::to_string_pretty(val).unwrap_or_default()
    }
}

pub fn resolve_plugins_dir(p_buf: &Path, plugins_sub: &str) -> PathBuf {
    let direct = p_buf.join(plugins_sub);
    if direct.exists() {
        return direct;
    }
    let mut curr = p_buf;
    while let Some(parent) = curr.parent() {
        let candidate = parent.join(plugins_sub);
        if candidate.exists() {
            return candidate;
        }
        curr = parent;
    }
    direct
}

pub fn resolve_project_root(path_str: &str) -> PathBuf {
    let raw = path_str.trim().trim_matches('"').trim_matches('\'');
    let clean = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let p = if clean.is_empty() || clean == "." {
        if let Ok(cur) = std::env::current_dir() {
            cur
        } else {
            PathBuf::from(clean)
        }
    } else {
        PathBuf::from(clean)
    };

    if let Ok(canon) = std::fs::canonicalize(&p) {
        let s = canon.to_string_lossy().to_string();
        let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
        return PathBuf::from(stripped);
    }
    p
}

pub(crate) fn format_note_bubble_details(
    sym: &core_graph::bubble::SymbolBubble,
    incoming: &[&core_graph::edge::AffiliationEdge],
    outgoing: &[&core_graph::edge::AffiliationEdge],
) -> String {
    let mut out = format!(
        "# 📝 Cible Note Obsidian : `{}` (`{}`)\n\
         - **Stéréotype :** `{}` | **Dossier :** `{}` | **Lignes :** {}\n\
         - **Degré de Centralité :** Backlinks entrants: {} | Wikilinks sortants: {}\n\
         - **Complexité (Liens + Tags) :** {}\n\n",
        sym.name,
        sym.file_path,
        sym.stereotype,
        if sym.folder.is_empty() { "root" } else { &sym.folder },
        sym.lines_count,
        sym.in_degree,
        sym.out_degree,
        sym.complexity
    );

    // Frontmatter Tags & Custom Attributes
    let tags: Vec<&str> = sym
        .metadata
        .attributes
        .iter()
        .filter(|a| a.name == "tag")
        .filter_map(|a| a.r#type.as_deref())
        .collect();

    let custom_attrs: Vec<(&str, &str)> = sym
        .metadata
        .attributes
        .iter()
        .filter(|a| a.name != "tag")
        .map(|a| (a.name.as_str(), a.r#type.as_deref().unwrap_or("")))
        .collect();

    out.push_str("## 🏷️ Métadonnées & Frontmatter YAML :\n");
    if tags.is_empty() && custom_attrs.is_empty() {
        out.push_str("*(Aucune métadonnée YAML ou tag détecté)*\n\n");
    } else {
        if !tags.is_empty() {
            let formatted_tags: Vec<String> = tags.iter().map(|t| format!("`#{}`", t)).collect();
            out.push_str(&format!("- **Tags :** {}\n", formatted_tags.join(", ")));
        }
        if !custom_attrs.is_empty() {
            out.push_str("- **Attributs personnalisés :**\n");
            for (k, v) in custom_attrs {
                out.push_str(&format!("  - `{}`: `{}`\n", k, v));
            }
        }
        out.push('\n');
    }

    // Section Headings (AST Methods)
    if !sym.metadata.methods.is_empty() {
        out.push_str("## 📑 Structure des Sections & En-têtes :\n");
        for m in &sym.metadata.methods {
            out.push_str(&format!("- {}\n", m.name));
        }
        out.push('\n');
    }

    // Outgoing Wikilinks and Embeds
    out.push_str(&format!("## 🔗 Liens Wikilinks & Transclusions Sortants (Total: {}) :\n", outgoing.len()));
    if outgoing.is_empty() {
        out.push_str("*(Aucun lien wikilink sortant)*\n\n");
    } else {
        for e in outgoing.iter().take(20) {
            let icon = if e.relation == "embeds" { "📎 Transclusion" } else { "➡️ Wikilink" };
            let alias_str = if let Some(ref l) = e.label {
                format!(" (alias: \"{}\")", l)
            } else {
                String::new()
            };
            let anchor_str = if !e.order_label.is_empty() {
                format!(" #{}", e.order_label)
            } else {
                String::new()
            };
            out.push_str(&format!("- {} vers `{}`{}{}\n", icon, e.target, anchor_str, alias_str));
        }
        if outgoing.len() > 20 {
            out.push_str(&format!("  ... et {} autre(s) lien(s)\n", outgoing.len() - 20));
        }
        out.push('\n');
    }

    // Incoming Backlinks
    out.push_str(&format!("## 📥 Backlinks / Références Entrantes (Total: {}) :\n", incoming.len()));
    if incoming.is_empty() {
        out.push_str("*(Aucun backlink entrant — note racine ou orpheline)*\n\n");
    } else {
        for e in incoming.iter().take(20) {
            let rel_icon = if e.relation == "embeds" { "📎 Intégrée par" } else { "⬅️ Citée par" };
            out.push_str(&format!("- {} `[[{}]]`\n", rel_icon, e.source));
        }
        if incoming.len() > 20 {
            out.push_str(&format!("  ... et {} autre(s) backlink(s)\n", incoming.len() - 20));
        }
        out.push('\n');
    }

    out
}

pub(crate) fn format_ghost_note_details(
    sym: &core_graph::bubble::SymbolBubble,
    incoming: &[&core_graph::edge::AffiliationEdge],
) -> String {
    let mut out = format!(
        "# 👻 Cible Note Fantôme : `{}`\n\
         - **Stéréotype :** `«GhostNote»`\n\
         - **Description :** Cette note est référencée dans des wikilinks du vault mais n'a pas encore de fichier physique `.md`.\n\
         - **Nombre de citations entrantes :** {}\n\n\
         ## 📥 Notes Citant cette Référence :\n",
        sym.name, incoming.len()
    );

    if incoming.is_empty() {
        out.push_str("*(Aucun référent direct)*\n\n");
    } else {
        for e in incoming.iter().take(15) {
            out.push_str(&format!("- ⬅️ `[[{}]]` via `{}`\n", e.source, e.relation));
        }
    }
    out.push_str("\n💡 *Pour résoudre ce lien manquant, créez le fichier correspondant dans le vault.*");
    out
}

pub(crate) fn format_attachment_details(
    sym: &core_graph::bubble::SymbolBubble,
    incoming: &[&core_graph::edge::AffiliationEdge],
) -> String {
    let mut out = format!(
        "# 📎 Fichier Joint / Média : `{}` (`{}`)\n\
         - **Stéréotype :** `«Attachment»` | **Dossier :** `{}`\n\
         - **Total Notes intégrant ce média :** {}\n\n\
         ## 📥 Notes hôtes (Transclusions) :\n",
        sym.name,
        sym.file_path,
        if sym.folder.is_empty() { "assets" } else { &sym.folder },
        incoming.len()
    );

    if incoming.is_empty() {
        out.push_str("*(Pièce jointe orpheline non intégrée dans les notes)*\n\n");
    } else {
        for e in incoming.iter().take(15) {
            out.push_str(&format!("- 📎 `[[{}]]` via `{}`\n", e.source, e.relation));
        }
    }
    out
}

pub(crate) fn offline_active_target_fallback(project_path: &str, symbol_id: &str) -> String {
    let p_buf = resolve_project_root(project_path);

    // Detect if target is an Obsidian Vault or Mixed Project
    let is_vault_project = obsidian_vault::detect_project_type(&p_buf)
        .map(|rep| rep.project_type.is_vault() || rep.project_type.is_mixed())
        .unwrap_or(false);

    let g = if is_vault_project {
        obsidian_vault::scan_obsidian_vault(&p_buf)
            .unwrap_or_else(|_| ast_scanner::ProjectScanner::default().scan_project(&p_buf))
    } else {
        ast_scanner::ProjectScanner::default().scan_project(&p_buf)
    };

    let clean_id = symbol_id.strip_suffix(".md")
        .or_else(|| symbol_id.strip_suffix(".MD"))
        .unwrap_or(symbol_id);

    let norm_sym = symbol_id.replace('\\', "/");
    let norm_clean = clean_id.replace('\\', "/");

    let sym_opt = g.nodes.iter().find(|n| {
        let n_norm_fp = n.file_path.replace('\\', "/");
        n.id == symbol_id
            || n.name.eq_ignore_ascii_case(symbol_id)
            || n.name.eq_ignore_ascii_case(clean_id)
            || n.file_path.eq_ignore_ascii_case(symbol_id)
            || n_norm_fp.eq_ignore_ascii_case(&norm_sym)
            || n_norm_fp.eq_ignore_ascii_case(&format!("{}.md", norm_clean))
            || n.id == format!("note::{}", symbol_id)
            || n.id == format!("note::{}", clean_id)
            || n.id == format!("note::{}.md", clean_id)
            || n.id == format!("ghost::{}", symbol_id)
            || n.id == format!("ghost::{}", clean_id)
            || n.id == format!("attachment::{}", symbol_id)
            || n.id.ends_with(&format!("::{}", symbol_id))
            || n.id.ends_with(&format!("::{}", clean_id))
            || n.id.ends_with(&format!("::{}.md", clean_id))
            || n.file_path.strip_suffix(".md").map(|s| s.eq_ignore_ascii_case(clean_id)).unwrap_or(false)
            || n_norm_fp.ends_with(&format!("/{}", norm_sym))
            || n_norm_fp.ends_with(&format!("/{}.md", norm_clean))
            || n.file_path.ends_with(&format!("/{}", symbol_id))
            || n.file_path.ends_with(&format!("\\{}", symbol_id))
            || n.file_path.ends_with(&format!("/{}.md", clean_id))
            || n.file_path.ends_with(&format!("\\{}.md", clean_id))
    }).or_else(|| {
        g.nodes.iter().find(|n| {
            n.name.to_lowercase().contains(&clean_id.to_lowercase())
        })
    });

    if let Some(sym) = sym_opt {
        let incoming_edges: Vec<&core_graph::edge::AffiliationEdge> = g
            .edges
            .iter()
            .filter(|e| e.target == sym.id && e.relation != "contains")
            .collect();
        let outgoing_edges: Vec<&core_graph::edge::AffiliationEdge> = g
            .edges
            .iter()
            .filter(|e| e.source == sym.id && e.relation != "contains")
            .collect();

        if sym.stereotype == "«GhostNote»" || sym.symbol_type == "ghost_note" {
            format_ghost_note_details(sym, &incoming_edges)
        } else if sym.stereotype == "«Attachment»" || sym.symbol_type == "attachment" {
            format_attachment_details(sym, &incoming_edges)
        } else if sym.stereotype == "«Note»" || sym.symbol_type == "note" || sym.layer == "docs" {
            format_note_bubble_details(sym, &incoming_edges, &outgoing_edges)
        } else {
            let in_cat = core_graph::edge::CategorizedLiaisons::from_edges(&incoming_edges, &sym.id, true);
            let out_cat = core_graph::edge::CategorizedLiaisons::from_edges(&outgoing_edges, &sym.id, false);

            let doc_display = if !sym.docstring.is_empty() {
                &sym.docstring
            } else if let Some(raw) = &sym.metadata.raw_content {
                raw.as_str()
            } else {
                "*(Aucun commentaire AST direct détecté)*"
            };

            let callers_md = in_cat.to_compact_markdown("amont", 4);
            let deps_md = out_cat.to_compact_markdown("aval", 4);

            format!(
                "# 🎯 Cible : `{}` (Mode Autonome AST)\n- **Fichier :** `{}:{}`\n- **Architecture :** Galaxie `{}` | Couche `{}` | Stéréotype `{}`\n\n## 📖 DOCUMENTATION & SPÉCIFICATIONS AST :\n{}\n\n## 📥 FLUX AMONT / APPELANTS (Total: {}):\n{}\n## 📤 FLUX AVAL / DÉPENDANCES & LIAISONS (Total: {}):\n{}",
                sym.name,
                sym.file_path,
                sym.line_number,
                sym.galaxy,
                sym.layer,
                sym.stereotype,
                doc_display,
                in_cat.total(),
                callers_md,
                out_cat.total(),
                deps_md
            )
        }
    } else {
        let sym_low = symbol_id.to_lowercase();
        let suggestions: Vec<&str> = g.nodes.iter()
            .filter(|n| n.name.to_lowercase().contains(&sym_low) || sym_low.contains(&n.name.to_lowercase()))
            .map(|n| n.name.as_str())
            .take(5)
            .collect();
        if !suggestions.is_empty() {
            format!("⚠️ Symbole ou note '{}' introuvable dans '{}'.\n💡 Symboles proches détectés : {}\n👉 Utilisez `aetherscope_search_symbols` pour explorer l'index.", symbol_id, p_buf.display(), suggestions.join(", "))
        } else {
            format!("⚠️ Symbole ou note '{}' introuvable dans '{}'. Utilisez `aetherscope_search_symbols` pour rechercher par mot-clé ou tag.", symbol_id, p_buf.display())
        }
    }
}

pub async fn send_http_request(
    server_port: u16,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, String> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr: SocketAddr = format!("127.0.0.1:{}", server_port)
        .parse()
        .map_err(|e| format!("Adresse invalide: {}", e))?;

    let method_str = method.to_string();
    let path_str = path.to_string();
    let body_str = body.map(|b| serde_json::to_string(b).unwrap_or_default()).unwrap_or_default();

    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
            .map_err(|e| format!("AetherScope non connectÃ© sur http://127.0.0.1:{} ({})", addr.port(), e))?;

        stream.set_read_timeout(Some(Duration::from_secs(45))).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;

        let req = format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method_str,
            path_str,
            addr.port(),
            body_str.len(),
            body_str
        );

        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).map_err(|e| e.to_string())?;

        let response_str = String::from_utf8_lossy(&response_bytes);
        let (header_part, json_part) = match response_str.split_once("\r\n\r\n") {
            Some((h, b)) => (h, b),
            None => ("", response_str.as_ref()),
        };

        let status_code = header_part
            .lines()
            .next()
            .and_then(|line| {
                let mut parts = line.split_whitespace();
                let _proto = parts.next()?;
                let code_str = parts.next()?;
                code_str.parse::<u16>().ok()
            });

        if let Some(code) = status_code {
            if !(200..300).contains(&code) {
                return Err(format!("HTTP error {}: {}", code, json_part.trim()));
            }
        }

        let val: Value = serde_json::from_str(json_part.trim()).unwrap_or_else(|_| json!({ "raw": json_part }));
        Ok(val)
    })
    .await
    .map_err(|e| e.to_string())?
}


pub(crate) fn format_search_symbols_response(
    g: &core_graph::graph::AetherGraph,
    query: &str,
    layer_filter: Option<&str>,
    kind_filter: Option<&str>,
    stereo_filter: Option<&str>,
    violation_filter: Option<bool>,
    limit: usize,
) -> String {
    let q_raw = query.trim().to_lowercase();
    let q_clean = q_raw.strip_prefix('#').unwrap_or(&q_raw);
    let layer_opt = layer_filter.map(|s| s.trim().to_lowercase());
    let kind_opt = kind_filter.map(|s| s.trim().to_lowercase());
    let stereo_opt = stereo_filter.map(|s| s.trim().to_lowercase());

    let mut scored: Vec<(i32, &core_graph::bubble::SymbolBubble)> = Vec::new();

    for n in &g.nodes {
        if let Some(ref l) = layer_opt {
            if !l.is_empty() && l != "all" && !n.layer.to_lowercase().contains(l) {
                continue;
            }
        }
        if let Some(ref k) = kind_opt {
            if !k.is_empty() && k != "all" && !n.symbol_type.to_lowercase().contains(k) {
                continue;
            }
        }
        if let Some(ref s) = stereo_opt {
            if !s.is_empty() && s != "all" && !n.stereotype.to_lowercase().contains(s) {
                continue;
            }
        }
        if let Some(v_only) = violation_filter {
            if v_only && !n.has_security_violation {
                continue;
            }
        }

        if q_raw.is_empty() {
            let base_score = if n.has_security_violation {
                90
            } else if n.stereotype == "«Note»" {
                50
            } else if n.is_class {
                40
            } else {
                10
            };
            scored.push((base_score, n));
        } else {
            let name_lower = n.name.to_lowercase();
            let file_lower = n.file_path.to_lowercase();
            let doc_lower = n.docstring.to_lowercase();
            let id_lower = n.id.to_lowercase();

            let mut score = 0;
            if name_lower == q_clean || id_lower == q_clean {
                score = 100;
            } else if name_lower.starts_with(q_clean) {
                score = 80;
            } else if name_lower.contains(q_clean) {
                score = 60;
            } else if file_lower.contains(q_clean) {
                score = 40;
            } else if doc_lower.contains(q_clean) {
                score = 30;
            } else if n.metadata.methods.iter().any(|m| m.name.to_lowercase().contains(q_clean)) {
                score = 50;
            }

            // Tag & Alias Matching in metadata.attributes
            for attr in &n.metadata.attributes {
                if attr.name == "tag" {
                    if let Some(ref t) = attr.r#type {
                        let t_lower = t.to_lowercase();
                        if t_lower == q_clean {
                            score = score.max(90);
                        } else if t_lower.contains(q_clean) {
                            score = score.max(75);
                        }
                    }
                } else if attr.name == "alias" {
                    if let Some(ref a) = attr.r#type {
                        let a_lower = a.to_lowercase();
                        if a_lower == q_clean {
                            score = score.max(95);
                        } else if a_lower.contains(q_clean) {
                            score = score.max(70);
                        }
                    }
                }
            }

            if score > 0 {
                if n.has_security_violation {
                    score += 15;
                }
                scored.push((score, n));
            }
        }
    }

    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let total_matches = scored.len();
    let display_items: Vec<_> = scored.into_iter().take(limit).collect();

    if display_items.is_empty() {
        return format!("🔍 Aucun symbole ou note trouvé pour la requête '{}' avec les filtres sélectionnés.", query);
    }

    let mut out = format!(
        "🔍 **Résultats de Recherche AetherScope ({}/{} trouvés) :**\n\n| Score | Symbole / Note | Stéréotype | Couche / Galaxie | Fichier : Ligne | Statut |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n",
        display_items.len(),
        total_matches
    );

    for (score, n) in display_items {
        let sec_badge = if n.has_security_violation {
            "🚨 CVE/SAST"
        } else if n.stereotype == "«Note»" {
            "📝 Note"
        } else if n.stereotype == "«GhostNote»" {
            "👻 Fantôme"
        } else if n.stereotype == "«Attachment»" {
            "📎 Média"
        } else if n.is_dead_code {
            "⚪ Inactif"
        } else {
            "✅ Conforme"
        };
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` (`{}`) | `{}:{}` | {} |\n",
            score, n.name, n.stereotype, n.layer, n.galaxy, n.file_path, n.line_number, sec_badge
        ));
    }

    out.push_str("\n💡 *Pour inspecter le contexte précis, les wikilinks ou règles EARS : utilisez `aetherscope_get_active_target(\"<symbole>\")`.*");
    out
}

pub(crate) fn format_trace_flow_response(
    g: &core_graph::graph::AetherGraph,
    symbol_id: &str,
    direction: &str,
    _max_depth: usize,
) -> String {
    let sym_opt = g.nodes.iter().find(|n| {
        n.id == symbol_id
            || n.name == symbol_id
            || n.file_path == symbol_id
            || n.id.ends_with(&format!("::{}", symbol_id))
    });

    let sym = match sym_opt {
        Some(s) => s,
        None => {
            let suggestions: Vec<&str> = g.nodes.iter()
                .filter(|n| n.name.to_lowercase().contains(&symbol_id.to_lowercase()))
                .map(|n| n.name.as_str())
                .take(5)
                .collect();
            if !suggestions.is_empty() {
                return format!("âš ï¸ Symbole '{}' introuvable pour le traÃ§age.\nðŸ’¡ Symboles proches : {}\nðŸ‘‰ Utilisez `aetherscope_search_symbols` pour trouver le nom exact.", symbol_id, suggestions.join(", "));
            } else {
                return format!("âš ï¸ Symbole '{}' introuvable pour le traÃ§age. Utilisez `aetherscope_search_symbols` pour trouver le nom exact.", symbol_id);
            }
        }
    };

    let dir_lower = direction.trim().to_lowercase();
    let trace_up = dir_lower == "upstream" || dir_lower == "both" || dir_lower == "all";
    let trace_down = dir_lower == "downstream" || dir_lower == "both" || dir_lower == "all";

    let mut out = format!(
        "# ðŸŒŠ TraÃ§age de Flux Architectural pour `{}`\n- **Fichier :** `{}:{}`\n- **Couche :** `{}` | **Galaxie :** `{}` | **StÃ©rÃ©otype :** `{}`\n\n",
        sym.name, sym.file_path, sym.line_number, sym.layer, sym.galaxy, sym.stereotype
    );

    if trace_up {
        out.push_str("### ðŸ“¥ Flux Amont (Appelants, Vues UI & ContrÃ´leurs dÃ©clencheurs) :\n");
        let incoming: Vec<&core_graph::edge::AffiliationEdge> = g
            .edges
            .iter()
            .filter(|e| e.target == sym.id && e.relation != "contains")
            .collect();

        if incoming.is_empty() {
            out.push_str("*(Aucun flux amont direct dÃ©tectÃ© â€” point d'entrÃ©e ou racine)*\n\n");
        } else {
            for e in incoming.iter().take(15) {
                let src_node = g.nodes.iter().find(|n| n.id == e.source);
                let (src_name, src_layer, src_file) = match src_node {
                    Some(n) => (n.name.as_str(), n.layer.as_str(), n.file_path.as_str()),
                    None => (e.source.as_str(), "inconnu", ""),
                };
                out.push_str(&format!(
                    "- âž” `[{}]` **{}** (`{}`) via `{}`\n",
                    src_layer, src_name, src_file, e.relation
                ));
            }
            out.push('\n');
        }
    }

    if trace_down {
        out.push_str("### ðŸ“¤ Flux Aval (Services appelÃ©s, ModÃ¨les & Persistance DB) :\n");
        let outgoing: Vec<&core_graph::edge::AffiliationEdge> = g
            .edges
            .iter()
            .filter(|e| e.source == sym.id && e.relation != "contains")
            .collect();

        if outgoing.is_empty() {
            out.push_str("*(Aucun flux aval direct dÃ©tectÃ© â€” feuille ou logique pure)*\n\n");
        } else {
            for e in outgoing.iter().take(15) {
                let tgt_node = g.nodes.iter().find(|n| n.id == e.target);
                let (tgt_name, tgt_layer, tgt_file) = match tgt_node {
                    Some(n) => (n.name.as_str(), n.layer.as_str(), n.file_path.as_str()),
                    None => (e.target.as_str(), "inconnu", ""),
                };
                out.push_str(&format!(
                    "- âž” `[{}]` **{}** (`{}`) via `{}`\n",
                    tgt_layer, tgt_name, tgt_file, e.relation
                ));
            }
            out.push('\n');
        }
    }

    out
}

pub(crate) fn format_violations_response(
    g: &core_graph::graph::AetherGraph,
    severity_filter: Option<&str>,
    cwe_filter: Option<&str>,
    file_filter: Option<&str>,
) -> String {
    let sev_opt = severity_filter.map(|s| s.trim().to_uppercase());
    let cwe_opt = cwe_filter.map(|s| s.trim().to_uppercase());
    let file_opt = file_filter.map(|s| s.trim().to_lowercase());

    let mut list = Vec::new();

    for n in &g.nodes {
        if let Some(ref fp) = file_opt {
            if !fp.is_empty() && !n.file_path.to_lowercase().contains(fp) {
                continue;
            }
        }

        for anom in &n.metadata.cve_anomalies {
            if let Some(ref s) = sev_opt {
                if s != "ALL" && !anom.severity.to_uppercase().contains(s) {
                    continue;
                }
            }
            if let Some(ref c) = cwe_opt {
                if !c.is_empty() && !anom.cve_id.to_uppercase().contains(c) && !anom.rule_id.to_uppercase().contains(c) {
                    continue;
                }
            }
            list.push((&anom.severity, &anom.file_path, anom.line_number, &anom.cve_id, &anom.message, &anom.remediation, &n.name));
        }
    }

    if list.is_empty() {
        return "âœ… Aucune violation de sÃ©curitÃ© ne correspond aux filtres demandÃ©s.".to_string();
    }

    let mut out = format!("ðŸ›¡ï¸ **Audit des Violations SAST/CWE ({}) :**\n\n", list.len());
    for (sev, f, line, cwe, msg, fix, sym) in list.iter().take(20) {
        let icon = match sev.as_str() {
            "CRITICAL" => "ðŸ”´",
            "HIGH" => "ðŸŸ ",
            "MEDIUM" => "ðŸŸ¡",
            _ => "âšª",
        };
        out.push_str(&format!(
            "- {} **[{}] {}** dans `{}:{}` (symbole: `{}`)\n  - *ProblÃ¨me :* {}\n  - *RemÃ©diation :* {}\n\n",
            icon, sev, cwe, f, line, sym, msg, fix
        ));
    }
    out
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FolderScopeRecommendation {
    pub folder: String,
    pub status: String, // "in_scope" | "out_of_scope"
    pub critical_count: usize,
    pub high_count: usize,
    pub total_violations: usize,
    pub entrypoints_count: usize,
    pub score: i32,
    pub reason: String,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BountyScopeConfig {
    #[serde(default)]
    pub in_scope: Vec<String>,
    #[serde(default)]
    pub out_of_scope: Vec<String>,
    #[serde(default)]
    pub mode: String, // "manual" | "ai_recommended" | "mcp_synced"
    #[serde(default)]
    pub updated_by: Option<String>,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub timestamp: u64,
}

pub fn extract_scope_folder(file_path: &str) -> String {
    let norm = file_path.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    if parts.len() > 1 {
        parts[..parts.len().min(2).min(parts.len() - 1)].join("/")
    } else {
        "root".to_string()
    }
}

pub fn is_noise_or_test_folder(folder: &str) -> bool {
    let lower = folder.to_lowercase();
    [
        "test", "tests", "spec", "fixture", "mock", "bench", "docs", "doc",
        "example", "examples", "target", "node_modules", "dist", "vendor",
    ]
    .iter()
    .any(|kw| {
        lower == *kw
            || lower.starts_with(&format!("{}/", kw))
            || lower.ends_with(&format!("/{}", kw))
            || lower.contains(&format!("/{}/", kw))
    })
}

pub fn compute_scope_recommendations(g: &core_graph::graph::AetherGraph) -> Vec<FolderScopeRecommendation> {
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Acc {
        crit: usize,
        high: usize,
        total_v: usize,
        entry: usize,
        domain_db: usize,
        nodes: usize,
    }
    let mut map: BTreeMap<String, Acc> = BTreeMap::new();
    for n in &g.nodes {
        if n.file_path.is_empty() {
            continue;
        }
        let folder = extract_scope_folder(&n.file_path);
        let entry = map.entry(folder).or_default();
        entry.nodes += 1;
        let layer_l = n.layer.to_lowercase();
        let st_l = n.stereotype.to_lowercase();
        if layer_l == "action" || layer_l == "ui" || st_l.contains("endpoint") || st_l.contains("controller") || st_l.contains("route") {
            entry.entry += 1;
        }
        if layer_l == "domain" || layer_l == "database" {
            entry.domain_db += 1;
        }
        for a in &n.metadata.cve_anomalies {
            entry.total_v += 1;
            match a.severity.to_uppercase().as_str() {
                "CRITICAL" => entry.crit += 1,
                "HIGH" => entry.high += 1,
                _ => {}
            }
        }
    }

    let mut recs: Vec<FolderScopeRecommendation> = map
        .into_iter()
        .filter(|(_, acc)| acc.total_v > 0 || acc.entry > 0 || acc.nodes >= 2)
        .map(|(folder, acc)| {
            let is_noise = is_noise_or_test_folder(&folder);
            let mut score: i32 = (acc.crit as i32) * 30
                + (acc.high as i32) * 15
                + (acc.total_v as i32) * 4
                + (acc.entry as i32) * 8
                + (acc.domain_db as i32) * 3;
            if is_noise {
                score -= 120;
            }
            let status = if !is_noise && (acc.total_v > 0 || acc.entry > 0 || score >= 10) {
                "in_scope".to_string()
            } else {
                "out_of_scope".to_string()
            };
            let reason = if is_noise {
                "Hors surface prod (Tests / Fixtures / Docs / Build)".to_string()
            } else if acc.crit > 0 || acc.high > 0 {
                format!(
                    "Surface critique : {} CRITICAL, {} HIGH ({} point(s) d'entrée)",
                    acc.crit, acc.high, acc.entry
                )
            } else if acc.entry > 0 {
                format!("Surface exposée : {} point(s) d'entrée / routes ({} alerte(s))", acc.entry, acc.total_v)
            } else if acc.total_v > 0 {
                format!("Module interne avec {} alerte(s) SAST", acc.total_v)
            } else {
                "Aucune alerte SAST ni point d'entrée exposé".to_string()
            };
            FolderScopeRecommendation {
                folder,
                status,
                critical_count: acc.crit,
                high_count: acc.high,
                total_violations: acc.total_v,
                entrypoints_count: acc.entry,
                score,
                reason,
            }
        })
        .collect();

    recs.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.folder.cmp(&b.folder)));
    recs
}

pub fn build_recommended_scope_config(
    recs: &[FolderScopeRecommendation],
    updated_by: Option<String>,
    rationale: Option<String>,
) -> BountyScopeConfig {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let in_scope = recs
        .iter()
        .filter(|r| r.status == "in_scope")
        .map(|r| r.folder.clone())
        .collect();
    let out_of_scope = recs
        .iter()
        .filter(|r| r.status == "out_of_scope")
        .map(|r| r.folder.clone())
        .collect();
    BountyScopeConfig {
        in_scope,
        out_of_scope,
        mode: "ai_recommended".to_string(),
        updated_by: Some(updated_by.unwrap_or_else(|| "AetherScope AI Recommender".to_string())),
        rationale: Some(rationale.unwrap_or_else(|| {
            "Priorisation automatique des modules exposés (UI/Action/Endpoints) et des CWE CRITICAL/HIGH ; exclusion des tests, fixtures et docs.".to_string()
        })),
        timestamp: now_ms,
    }
}

pub fn load_or_recommend_bounty_scope(
    project_root: &Path,
    g: &core_graph::graph::AetherGraph,
) -> (BountyScopeConfig, Vec<FolderScopeRecommendation>) {
    let recs = compute_scope_recommendations(g);
    let scope_file = project_root.join(".aether").join("bounty_scope.json");
    if scope_file.exists() {
        if let Ok(raw) = std::fs::read_to_string(&scope_file) {
            if let Ok(cfg) = serde_json::from_str::<BountyScopeConfig>(&raw) {
                return (cfg, recs);
            }
        }
    }
    let cfg = build_recommended_scope_config(&recs, None, None);
    (cfg, recs)
}

pub fn save_bounty_scope(project_root: &Path, cfg: &BountyScopeConfig) {
    let dir = project_root.join(".aether");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(json_str) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(dir.join("bounty_scope.json"), json_str);
    }
}

pub fn is_path_in_bounty_scope(file_path: &str, cfg: &BountyScopeConfig) -> bool {
    let folder = extract_scope_folder(file_path);
    let norm = file_path.replace('\\', "/");
    if cfg.out_of_scope.iter().any(|p| p == &folder || norm.starts_with(p)) {
        return false;
    }
    if !cfg.in_scope.is_empty() {
        return cfg.in_scope.iter().any(|p| p == &folder || norm.starts_with(p));
    }
    true
}

pub fn format_bounty_scope_summary(
    cfg: &BountyScopeConfig,
    recs: &[FolderScopeRecommendation],
) -> String {
    let mut out = format!(
        "🎯 **Périmètre Bug Bounty & PoC (`mode: {}`)**\n- Mis à jour par : `{}`\n- Justification : {}\n- **In-Scope ({})** : {}\n- **Out-of-Scope ({})** : {}\n\n### 🤖 Recommandations AST / Surface d'Attaque :\n",
        if cfg.mode.is_empty() { "ai_recommended" } else { &cfg.mode },
        cfg.updated_by.as_deref().unwrap_or("auto"),
        cfg.rationale.as_deref().unwrap_or("-"),
        cfg.in_scope.len(),
        if cfg.in_scope.is_empty() { "*(Tous hors exclusions)*".to_string() } else { cfg.in_scope.iter().map(|s| format!("`{}`", s)).collect::<Vec<_>>().join(", ") },
        cfg.out_of_scope.len(),
        if cfg.out_of_scope.is_empty() { "*(Aucun)*".to_string() } else { cfg.out_of_scope.iter().map(|s| format!("`{}`", s)).collect::<Vec<_>>().join(", ") },
    );
    for r in recs.iter().take(20) {
        let badge = if r.status == "in_scope" { "🎯 IN-SCOPE" } else { "🚫 OUT-SCOPE" };
        out.push_str(&format!(
            "- **{}** `{}` (score `{}`) — {}\n",
            badge, r.folder, r.score, r.reason
        ));
    }
    out
}


