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
                        "description": "Registre des tÃ¢ches d'ingÃ©nierie et de refactorisation pilotÃ©es par l'IA (.aether/tasks/).",
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
                        "description": "[COMMANDE COMBINÃ‰E 4-EN-1] RÃ©cupÃ¨re en 1 seul appel l'architecture globale du projet (nÅ“uds, arÃªtes, dossiers), les violations de sÃ©curitÃ© SAST/CWE actives, la liste des tÃ¢ches en cours (include_tasks=true) et peut forcer une rÃ©analyse complÃ¨te AST (rescan=true).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet Ã  analyser ou basculer (par dÃ©faut le projet actif)",
                                    "examples": [".", "crates/desktop-shell", "crates/core-graph"]
                                },
                                "rescan": {
                                    "type": "boolean",
                                    "description": "Si true, force une rÃ©analyse complÃ¨te de l'arbre AST et des rÃ¨gles SAST avant de renvoyer le rÃ©sumÃ© (remplace aetherscope_scan_project)"
                                },
                                "include_tasks": {
                                    "type": "boolean",
                                    "description": "Si true (dÃ©faut), inclut directement la liste des tÃ¢ches actives du projet dans le rÃ©sumÃ© (remplace un appel sÃ©parÃ© Ã  list_tasks)"
                                },
                                "severity": {
                                    "type": "string",
                                    "description": "Filtre optionnel de sÃ©vÃ©ritÃ© pour dÃ©tailler les violations SAST/CWE ('critical', 'high', 'all')",
                                    "enum": ["all", "critical", "high", "medium", "low", "warning"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Diagnostic Global CombinÃ© (Graphe + Scan + TÃ¢ches + CWE)",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_get_active_target",
                        "description": "[COMMANDE COMBINÃ‰E 3-EN-1] En 1 seul appel : (1) TÃ©lÃ©porte la camÃ©ra 3D WebGL et met Ã  jour le HUD de tÃ©lÃ©mÃ©trie, (2) RÃ©cupÃ¨re le contrat EARS, les rÃ¨gles d'imports et le Handshake du symbole, et (3) Trace automatiquement le flux amont/aval (trace_direction='both').",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "symbol_id": {
                                    "type": "string",
                                    "description": "Nom ou identifiant du symbole ou fichier cible (ex: 'handle_booking', 'crates/core-graph/src/manifest.rs')",
                                    "examples": ["handle_booking", "BookingForm", "crates/core-graph/src/manifest.rs"]
                                },
                                "action": {
                                    "type": "string",
                                    "description": "Badge d'action affichÃ© en direct sur le HUD 3D lors de la tÃ©lÃ©portation camÃ©ra (dÃ©faut: 'Inspection')",
                                    "examples": ["Inspection", "Analyse", "Refactoring", "Correction CVE", "Audit"]
                                },
                                "details": {
                                    "type": "string",
                                    "description": "Description technique courte affichÃ©e dans le journal de tÃ©lÃ©mÃ©trie 3D"
                                },
                                "trace_direction": {
                                    "type": "string",
                                    "description": "Direction du traÃ§age de flux automatique inclus dans la rÃ©ponse : 'both' (dÃ©faut), 'upstream', 'downstream', ou 'none'",
                                    "enum": ["both", "upstream", "downstream", "none"]
                                },
                                "max_depth": {
                                    "type": "integer",
                                    "description": "Profondeur maximale du traÃ§age de flux (dÃ©faut: 2, max: 5)",
                                    "minimum": 1,
                                    "maximum": 5
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet cible"
                                }
                            },
                            "required": ["symbol_id"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Inspection Cible CombinÃ©e (Contexte EARS + CamÃ©ra 3D + Trace Flux)",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_search_symbols",
                        "description": "[COMMANDE COMBINÃ‰E 2-EN-1] Recherche multi-critÃ¨res dans l'index AST (mot-clÃ©, couche MVC, type, stÃ©rÃ©otype) ET filtrage dÃ©taillÃ© des violations SAST/CWE (cwe_id, severity, file_pattern) avec recommandations de remÃ©diation.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Texte ou mot-clÃ© Ã  rechercher dans le nom du symbole, le fichier ou les mÃ©thodes",
                                    "examples": ["checkout", "auth", "BookingService"]
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
                                    "description": "StÃ©rÃ©otype architectural (ex: 'Â«ModelÂ»', 'Â«ControllerÂ»', 'Â«ComponentÂ»', 'Â«ServiceÂ»')"
                                },
                                "has_violation": {
                                    "type": "boolean",
                                    "description": "Filtrer uniquement les symboles ayant des violations de sÃ©curitÃ© ou CVE dÃ©tectÃ©es"
                                },
                                "cwe_id": {
                                    "type": "string",
                                    "description": "Filtre direct sur un identifiant CWE ou rÃ¨gle SAST (ex: 'CWE-89', 'CWE-22', 'CVE-RUST-') : inclut le rapport dÃ©taillÃ© de remÃ©diation"
                                },
                                "severity": {
                                    "type": "string",
                                    "description": "Niveau de sÃ©vÃ©ritÃ© des violations Ã  auditer : 'all', 'critical', 'high', 'medium', 'low', 'warning'",
                                    "enum": ["all", "critical", "high", "medium", "low", "warning"]
                                },
                                "file_pattern": {
                                    "type": "string",
                                    "description": "Filtre sur le chemin ou nom de fichier pour l'audit de violations"
                                },
                                "limit": {
                                    "type": "integer",
                                    "description": "Nombre maximum de rÃ©sultats (dÃ©faut: 15, max: 50)",
                                    "minimum": 1,
                                    "maximum": 50
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet cible"
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Recherche AST & Audit Violations SAST/CWE CombinÃ©s",
                            "readOnlyHint": true,
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
                        "description": "[COMMANDE COMBINÃ‰E 2-EN-1] Envoie un message/debrief dans le chat intÃ©grÃ© AetherScope (action='send', avec tÃ©lÃ©portation camÃ©ra optionnelle via target_symbol) OU rÃ©cupÃ¨re l'historique des Ã©changes (action='history').",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "'send' (dÃ©faut si text est prÃ©sent) pour envoyer un message, ou 'history' pour lire l'historique du chat",
                                    "enum": ["send", "history"]
                                },
                                "text": {
                                    "type": "string",
                                    "description": "Contenu Markdown du message Ã  afficher dans le chat AetherScope (requis si action='send')"
                                },
                                "thought": {
                                    "type": "string",
                                    "description": "Raisonnement interne de l'IA (optionnel)"
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Symbole ou fichier associÃ© au message (aligne aussi la camÃ©ra 3D)"
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
                                    "description": "Courte description technique de ce que vous observez ou rÃ©alisez",
                                    "examples": ["VÃ©rification des invariants et de la non-nullabilitÃ© du token d'accÃ¨s"]
                                }
                            },
                            "required": ["target", "action", "details"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "TÃ©lÃ©portation CamÃ©ra 3D AetherScope",
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

pub(crate) fn format_graph_summary(val: &Value) -> String {
    let project_name = val.get("project_name").and_then(|v| v.as_str()).unwrap_or("Projet AetherScope");
    let project_path = val.get("project_path").and_then(|v| v.as_str()).unwrap_or("");
    let nodes = val.get("nodes").and_then(|v| v.as_array());
    let edges = val.get("edges").and_then(|v| v.as_array());
    let total_nodes = nodes.map(|n| n.len()).unwrap_or(0);
    let total_edges = edges.map(|e| e.len()).unwrap_or(0);

    let mut folders = std::collections::BTreeMap::new();
    let mut violations = Vec::new();

    if let Some(nodes_arr) = nodes {
        for n in nodes_arr {
            let f = n.get("folder").and_then(|v| v.as_str()).unwrap_or("root");
            *folders.entry(f.to_string()).or_insert(0usize) += 1;
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
                violations.push(format!("- ðŸš¨ `{}`{} â€” `{}`", name, cve_desc, file));
            }
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

    let path_line = if !project_path.is_empty() {
        format!("â€¢ Emplacement : `{}`\n", project_path)
    } else {
        String::new()
    };

    format!(
        "ðŸª RÃ©sumÃ© Architectural AetherScope V2 :\n\
         â€¢ Projet Actif : `{}`\n\
         {}\
         â€¢ Total NÅ“uds (Bulles) : {}\n\
         â€¢ Total Relations (ArÃªtes) : {}\n\
         â€¢ Modules / Dossiers ({} au total) :\n{}\
         â€¢ Statut SÃ©curitÃ© & RÃ¨gles :\n{}\n\
         â€¢ Visualiseur WebGL 2 disponible sur http://127.0.0.1:3030",
        project_name, path_line, total_nodes, total_edges, folders.len(), folders_str, violations_str
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

pub(crate) fn offline_active_target_fallback(project_path: &str, symbol_id: &str) -> String {
    let p_buf = resolve_project_root(project_path);
    let scanner = ast_scanner::ProjectScanner::default();
    let g = scanner.scan_project(&p_buf);

    let sym_opt = g.nodes.iter().find(|n| {
        n.id == symbol_id
            || n.name == symbol_id
            || n.file_path == symbol_id
            || n.id.ends_with(&format!("::{}", symbol_id))
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

        let in_cat = core_graph::edge::CategorizedLiaisons::from_edges(&incoming_edges, &sym.id, true);
        let out_cat = core_graph::edge::CategorizedLiaisons::from_edges(&outgoing_edges, &sym.id, false);

        let doc_display = if !sym.docstring.is_empty() {
            &sym.docstring
        } else if let Some(raw) = &sym.metadata.raw_content {
            raw.as_str()
        } else {
            "*(Aucun commentaire AST direct dÃ©tectÃ©)*"
        };

        let callers_md = in_cat.to_compact_markdown("amont", 4);
        let deps_md = out_cat.to_compact_markdown("aval", 4);

        format!(
            "# ðŸŽ¯ Cible : `{}` (Mode Autonome AST)\n- **Fichier :** `{}:{}`\n- **Architecture :** Galaxie `{}` | Couche `{}` | StÃ©rÃ©otype `{}`\n\n## ðŸ“– DOCUMENTATION & SPÃ‰CIFICATIONS AST :\n{}\n\n## ðŸ“¥ FLUX AMONT / APPELANTS (Total: {}):\n{}\n## ðŸ“¤ FLUX AVAL / DÃ‰PENDANCES & LIAISONS (Total: {}):\n{}",
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
    } else {
        let sym_low = symbol_id.to_lowercase();
        let suggestions: Vec<&str> = g.nodes.iter()
            .filter(|n| n.name.to_lowercase().contains(&sym_low) || sym_low.contains(&n.name.to_lowercase()))
            .map(|n| n.name.as_str())
            .take(5)
            .collect();
        if !suggestions.is_empty() {
            format!("âš ï¸ Symbole '{}' introuvable dans '{}'.\nðŸ’¡ Symboles proches dÃ©tectÃ©s : {}\nðŸ‘‰ Utilisez `aetherscope_search_symbols` pour explorer l'index.", symbol_id, p_buf.display(), suggestions.join(", "))
        } else {
            format!("âš ï¸ Symbole '{}' introuvable dans '{}'. Utilisez `aetherscope_search_symbols` pour rechercher par mot-clÃ©.", symbol_id, p_buf.display())
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
        if let Some((_, json_part)) = response_str.split_once("\r\n\r\n") {
            let val: Value = serde_json::from_str(json_part.trim()).unwrap_or_else(|_| json!({ "raw": json_part }));
            Ok(val)
        } else {
            Ok(json!({ "raw": response_str }))
        }
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
    let q_lower = query.trim().to_lowercase();
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

        if q_lower.is_empty() {
            let base_score = if n.has_security_violation { 90 } else if n.is_class { 40 } else { 10 };
            scored.push((base_score, n));
        } else {
            let name_lower = n.name.to_lowercase();
            let file_lower = n.file_path.to_lowercase();
            let doc_lower = n.docstring.to_lowercase();
            let id_lower = n.id.to_lowercase();

            let mut score = 0;
            if name_lower == q_lower || id_lower == q_lower {
                score = 100;
            } else if name_lower.starts_with(&q_lower) {
                score = 80;
            } else if name_lower.contains(&q_lower) {
                score = 60;
            } else if file_lower.contains(&q_lower) {
                score = 40;
            } else if doc_lower.contains(&q_lower) {
                score = 30;
            } else if n.metadata.methods.iter().any(|m| m.name.to_lowercase().contains(&q_lower)) {
                score = 50;
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
        return format!("ðŸ” Aucun symbole trouvÃ© pour la requÃªte '{}' avec les filtres sÃ©lectionnÃ©s.", query);
    }

    let mut out = format!(
        "ðŸ” **RÃ©sultats de Recherche AetherScope ({}/{} trouvÃ©s) :**\n\n| Score | Symbole | StÃ©rÃ©otype | Couche / Galaxie | Fichier : Ligne | Statut |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n",
        display_items.len(),
        total_matches
    );

    for (score, n) in display_items {
        let sec_badge = if n.has_security_violation {
            "ðŸš¨ CVE/SAST"
        } else if n.is_dead_code {
            "âšª Inactif"
        } else {
            "âœ… Conforme"
        };
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` (`{}`) | `{}:{}` | {} |\n",
            score, n.name, n.stereotype, n.layer, n.galaxy, n.file_path, n.line_number, sec_badge
        ));
    }

    out.push_str("\nðŸ’¡ *Pour inspecter le contexte prÃ©cis, les flux et rÃ¨gles EARS d'un symbole : utilisez `aetherscope_get_active_target(\"<symbole>\")` ou `aetherscope_trace_flow(\"<symbole>\")`.*");
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

