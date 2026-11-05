#![recursion_limit = "512"]
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[allow(dead_code)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
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

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AetherScope V2 - Dedicated MCP Server for AI Agents", long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = ".")]
    pub path: String,

    #[arg(long, default_value_t = 3030)]
    pub port: u16,

    #[arg(long, default_value_t = false)]
    pub mcp: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let port = args.port;
    let path = args.path.clone();

    // 1. VÃƒÆ’Ã‚Â©rifie si AetherScope tourne sur le port
    let is_server_listening = check_server_listening(port);

    if !is_server_listening {
        eprintln!("ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã‚Â¡ [AetherScope MCP] Serveur non dÃƒÆ’Ã‚Â©tectÃƒÆ’Ã‚Â© sur le port {}. DÃƒÆ’Ã‚Â©marrage automatique de l'agent en tÃƒÆ’Ã‚Â¢che de fond...", port);
        // Note: mcp_main est le binaire autonome stdio, on s'exÃƒÆ’Ã‚Â©cute directement en mode pont
    } else {
        eprintln!("ÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã‚Â¡ [AetherScope MCP] ConnectÃƒÆ’Ã‚Â© ÃƒÆ’Ã‚Â  l'instance active AetherScope sur http://127.0.0.1:{}", port);
    }

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
                let _ = writeln!(stdout, "{}", serde_json::to_string(&err_res).unwrap());
                let _ = stdout.flush();
                continue;
            }
        };

        let resp = handle_mcp_request(req, port, &path).await;
        if let Some(res) = resp {
            let _ = writeln!(stdout, "{}", serde_json::to_string(&res).unwrap());
            let _ = stdout.flush();
        }
    }

    Ok(())
}

async fn handle_mcp_request(req: JsonRpcRequest, server_port: u16, default_path: &str) -> Option<JsonRpcResponse> {
    let id = req.id;

    match req.method.as_str() {
        "initialize" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    },
                    "resources": {
                        "subscribe": false,
                        "listChanged": false
                    },
                    "prompts": {
                        "listChanged": false
                    },
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
            let params = req.params.unwrap_or(json!({}));
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
                        "name": "audit_security_cwe",
                        "description": "GÃ©nÃ¨re un prompt d'audit et de remÃ©diation ciblÃ©e pour corriger une vulnÃ©rabilitÃ© SAST / violation CWE dÃ©tectÃ©e dans le graphe AetherScope.",
                        "arguments": [
                            {
                                "name": "symbol_name",
                                "description": "Nom du symbole (fonction, classe, struct) ou chemin du fichier Ã  auditer.",
                                "required": true
                            },
                            {
                                "name": "cwe_id",
                                "description": "Identifiant CWE ou catÃ©gorie de la faille (ex: CWE-89, CWE-79, Memory Safety).",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "scaffold_game_server",
                        "description": "GÃ©nÃ¨re un prompt guidÃ© pour l'implÃ©mentation d'une architecture serveur de jeu (Roblox Luau ou Minecraft Paper/Purpur) optimisÃ©e pour AetherScope.",
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
                    },
                    {
                        "name": "refactor_contract_violation",
                        "description": "GÃ©nÃ¨re un prompt d'analyse et de correction lorsqu'une rupture de contrat EARS ou une violation d'import de couche est dÃ©tectÃ©e.",
                        "arguments": [
                            {
                                "name": "contract_name",
                                "description": "Nom du contrat ou de l'interface en violation.",
                                "required": true
                            },
                            {
                                "name": "violation_details",
                                "description": "DÃ©tails de l'incompatibilitÃ© ou de la violation de frontiÃ¨re.",
                                "required": false
                            }
                        ]
                    }
                ]
            })),
            error: None,
        }),

        "prompts/get" => {
            let params = req.params.unwrap_or(json!({}));
            let prompt_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            match prompt_name {
                "audit_security_cwe" => {
                    let symbol_name = arguments.get("symbol_name").and_then(|v| v.as_str()).unwrap_or("<symbole>");
                    let cwe_id = arguments.get("cwe_id").and_then(|v| v.as_str()).unwrap_or("CWE Anomaly");
                    let prompt_text = format!(
                        "Vous Ãªtes l'architecte de sÃ©curitÃ© AetherScope. Effectuez l'audit et la remÃ©diation de la cible `{}` concernÃ©e par la vulnÃ©rabilitÃ© `{}`.\n\n\
                        Protocole obligatoire :\n\
                        1. Utilisez `aetherscope_teleport_camera` vers `{}` avec l'action 'Correction CVE'.\n\
                        2. Utilisez `aetherscope_get_active_target` sur `{}` pour vÃ©rifier les contrats EARS et les appelants en amont.\n\
                        3. Proposez une correction sÃ©curisÃ©e (validation stricte des entrÃ©es, typage invariant, absence d'allocation superflue) sans rompre l'API publique.\n\
                        4. CrÃ©ez ou mettez Ã  jour une tÃ¢che via `aetherscope_create_task` (type: 'security_fix').",
                        symbol_name, cwe_id, symbol_name, symbol_name
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
                            "Vous implÃ©mentez un module serveur de jeu haute performance sous Roblox Luau (`{}`) intÃ©grÃ© dans l'Ã©cosystÃ¨me AetherScope.\n\n\
                            SpÃ©cifications techniques :\n\
                            - Architecture contractuelle stricte : `contracts/` pour les paquets rÃ©seau RemoteEvent/RemoteFunction avec typage Luau strict (`--!strict`).\n\
                            - SÃ©paration stricte : `server/` (logique d'autoritÃ© exclusive), `client/` (prÃ©diction locale, pas de trust), `data-nodes/` (sauvegarde DataStore atomique).\n\
                            - Utilisez `aetherscope_create_task` avec le type 'function' pour suivre l'implÃ©mentation de `{}`.\n\
                            - TÃ©lÃ©portez la camÃ©ra sur le module via `aetherscope_teleport_camera`.",
                            package_name, package_name
                        )
                    } else {
                        format!(
                            "Vous implÃ©mentez un plugin serveur Minecraft Paper/Purpur (`{}`) haute performance selon les standards AetherScope.\n\n\
                            SpÃ©cifications techniques :\n\
                            - Architecture dÃ©couplÃ©e : API & Contrats d'Ã©vÃ©nements sÃ©parÃ©s de l'implÃ©mentation Bukkit/Spigot.\n\
                            - Concurrency & Tick-safety : Aucun blocage sur le Main Thread tick de 50ms, utilisation d'AsyncScheduler et collections concurrentes.\n\
                            - Utilisez `aetherscope_create_task` pour dÃ©clarer les jalons du plugin `{}`.\n\
                            - VÃ©rifiez l'absence de fuite mÃ©moire sur les EventHandler dÃ©senregistrÃ©s.",
                            package_name, package_name
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
                        "Une violation de contrat d'architecture a Ã©tÃ© relevÃ©e sur `{}` :\n`{}`\n\n\
                        Directives AetherScope :\n\
                        1. Inspectez les liaisons amont/aval via `aetherscope_get_active_target` sur `{}`.\n\
                        2. VÃ©rifiez le respect du README de spÃ©cification EARS et du fichier `aether.manifest.json`.\n\
                        3. Supprimez les imports circulaires ou illicites entre couches (ex: core ne doit jamais importer desktop-shell).\n\
                        4. Signalez l'avancement via `aetherscope_send_chat_message`.",
                        contract_name, details, contract_name
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
                        "name": "aetherscope_teleport_camera",
                        "description": "Oriente la camÃ©ra WebGL en direct dans AetherScope vers un symbole ou un fichier, et affiche oÃ¹ l'IA travaille en temps rÃ©el (fil d'Ariane violet, faisceau laser et rÃ©ticule tactique).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "Nom du symbole, fichier ou dossier cible (ex: 'RoomBooking', 'BookingEngine', 'contracts/packets.rs', 'server/api')",
                                    "examples": ["RoomBooking", "BookingEngine", "contracts/packets.rs", "server/api"]
                                },
                                "action": {
                                    "type": "string",
                                    "description": "Action en cours (ex: 'Inspection', 'Analyse', 'CrÃ©ation', 'Refactoring', 'Correction CVE', 'Audit', 'Tests')",
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
                    },
                    {
                        "name": "aetherscope_get_graph_summary",
                        "description": "RÃ©cupÃ¨re l'architecture complÃ¨te du projet (nombre de nÅ“uds, flux, liste des dossiers, santÃ© globale et violations de sÃ©curitÃ© CVE) depuis AetherScope.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet Ã  analyser (par dÃ©faut le projet actif)",
                                    "examples": [".", "crates/desktop-shell", "crates/core-graph"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "RÃ©sumÃ© d'Architecture & SantÃ© Projet",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_send_chat_message",
                        "description": "Envoie un message ou debrief technique de l'IA directement dans le chat intÃ©grÃ© de l'interface AetherScope du dÃ©veloppeur.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Contenu du message ou compte-rendu pour l'utilisateur",
                                    "examples": ["Analyse terminÃ©e : 0 vulnÃ©rabilitÃ© dÃ©tectÃ©e sur le module d'authentification."]
                                },
                                "thought": {
                                    "type": "string",
                                    "description": "Raisonnement ou rÃ©flexion interne de l'IA (optionnel)",
                                    "examples": ["Le scan SAST valide l'arbre AST et les contrats EARS sans anomalie de mÃ©moire."]
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Symbole ou fichier associÃ© au message (optionnel)",
                                    "examples": ["AuthService", "crates/desktop-shell/src/mcp.rs"]
                                }
                            },
                            "required": ["text"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Envoi Message Chat AetherScope",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_get_chat_history",
                        "description": "RÃ©cupÃ¨re l'historique des Ã©changes rÃ©cents du chat AetherScope.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Historique du Chat AetherScope",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_get_active_target",
                        "description": "RÃ©cupÃ¨re le contexte ciblÃ© et le handshake pour un symbole : appelants amont, dÃ©pendances aval, rÃ¨gles README EARS et imports interdits.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "symbol_id": {
                                    "type": "string",
                                    "description": "Nom ou identifiant du symbole ou fichier (ex: 'handle_booking', 'BookingForm')",
                                    "examples": ["handle_booking", "BookingForm", "crates/core-graph/src/manifest.rs"]
                                }
                            },
                            "required": ["symbol_id"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Contexte & Handshake Symbole",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_scan_project",
                        "description": "DÃ©clenche une rÃ©analyse complÃ¨te de l'architecture d'un projet pour rafraÃ®chir le graphe 3D.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Chemin du projet Ã  rÃ©analyser",
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
                    },
                    {
                        "name": "aetherscope_create_task",
                        "description": "CrÃ©e une nouvelle tÃ¢che (fonction, recherche, sÃ©curitÃ©, refactorisation, etc.) avec son mini-README d'avancement pour structurer le travail dans le contexte du modÃ¨le et du dÃ©veloppeur.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "title": {
                                    "type": "string",
                                    "description": "Titre explicite de la tÃ¢che Ã  accomplir",
                                    "examples": ["Correction vulnÃ©rabilitÃ© CWE-89 dans SQL Query Builder"]
                                },
                                "kind": {
                                    "type": "string",
                                    "description": "Type de tÃ¢che : 'function', 'research', 'security_fix', 'arch_refactor', 'documentation', 'test', ou 'other'",
                                    "enum": ["function", "research", "security_fix", "arch_refactor", "documentation", "test", "other"],
                                    "examples": ["security_fix", "function", "arch_refactor"]
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Nom optionnel du symbole AST ciblÃ© dans le graphe (ex: 'BookingService', 'verify_token')",
                                    "examples": ["execute_query", "BookingService"]
                                },
                                "target_file": {
                                    "type": "string",
                                    "description": "Chemin optionnel du fichier concernÃ© (ex: 'src/auth.rs', 'contracts/ports.rs')",
                                    "examples": ["src/db/query.rs", "contracts/packets.rs"]
                                },
                                "priority": {
                                    "type": "string",
                                    "description": "PrioritÃ© de la tÃ¢che ('low', 'medium', 'high', 'critical')",
                                    "enum": ["low", "medium", "high", "critical"],
                                    "examples": ["critical", "high", "medium"]
                                },
                                "initial_readme": {
                                    "type": "string",
                                    "description": "Contenu Markdown optionnel pour initialiser le mini-README d'avancement (objectifs, checklist d'Ã©tapes)",
                                    "examples": ["### Objectifs\n- Remplacer interpolation par requÃªte prÃ©parÃ©e\n- VÃ©rifier tests unitaires"]
                                }
                            },
                            "required": ["title"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "CrÃ©ation de TÃ¢che AetherScope",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_update_task",
                        "description": "Met Ã  jour l'Ã©tat d'avancement d'une tÃ¢che, son statut ('pending', 'in_progress', 'blocked', 'done'), son pourcentage (0-100%) et ajoute des notes au mini-README.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "task_id": {
                                    "type": "string",
                                    "description": "Identifiant unique de la tÃ¢che (ex: 'task_123456_nom')",
                                    "examples": ["task_1730000000_sec", "task_01_game_server"]
                                },
                                "status": {
                                    "type": "string",
                                    "description": "Nouveau statut de la tÃ¢che ('pending', 'in_progress', 'blocked', 'done', 'cancelled')",
                                    "enum": ["pending", "in_progress", "blocked", "done", "cancelled"],
                                    "examples": ["in_progress", "done", "blocked"]
                                },
                                "progress": {
                                    "type": "integer",
                                    "description": "Pourcentage d'avancement estimÃ© de la tÃ¢che entre 0 et 100",
                                    "minimum": 0,
                                    "maximum": 100,
                                    "examples": [50, 100]
                                },
                                "progress_note": {
                                    "type": "string",
                                    "description": "Courte note de progrÃ¨s Ã  consigner dans le mini-README de la tÃ¢che",
                                    "examples": ["Contrat validÃ©, implÃ©mentation des tests unitaires en cours."]
                                },
                                "full_readme": {
                                    "type": "string",
                                    "description": "Nouveau contenu complet du mini-README de la tÃ¢che (si rÃ©Ã©criture / mise Ã  jour complÃ¨te de la checklist)",
                                    "examples": ["# TÃ¢che TerminÃ©e\n- [x] SpÃ©cifications rÃ©digÃ©es\n- [x] Code validÃ©\n- [x] Audit SAST 0 faille"]
                                }
                            },
                            "required": ["task_id"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Mise Ã  Jour de TÃ¢che AetherScope",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_list_tasks",
                        "description": "RÃ©cupÃ¨re la liste des tÃ¢ches du projet AetherScope avec leur type, statut, avancement et rÃ©sumÃ© du mini-README.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "status_filter": {
                                    "type": "string",
                                    "description": "Filtre optionnel : 'active' (par dÃ©faut, exclut les terminÃ©es), 'all' (toutes les tÃ¢ches), 'done' (uniquement terminÃ©es)",
                                    "enum": ["active", "all", "done"],
                                    "examples": ["active", "all", "done"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Liste des TÃ¢ches AetherScope",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_search_symbols",
                        "description": "Recherche avancÃ©e dans l'index AST d'AetherScope par mot-clÃ©, couche MVC (ui, action, domain, database), stÃ©rÃ©otype (Â«ModelÂ», Â«ControllerÂ», Â«ComponentÂ») ou statut de sÃ©curitÃ©.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Texte ou mot-clÃ© Ã  rechercher dans le nom du symbole, le fichier, la docstring ou les mÃ©thodes",
                                    "examples": ["checkout", "Item", "auth", "BookingService"]
                                },
                                "layer": {
                                    "type": "string",
                                    "description": "Couche architecturale : 'ui' (Vue), 'action' (ContrÃ´leur), 'domain' (MÃ©tier), 'database' (ModÃ¨le/Persistance), 'utility', 'config', 'docs' ou 'all'",
                                    "enum": ["ui", "action", "domain", "database", "utility", "config", "docs", "all"],
                                    "examples": ["action", "database", "ui"]
                                },
                                "kind": {
                                    "type": "string",
                                    "description": "Type de symbole : 'function', 'file', 'class', 'endpoint', 'contract' ou 'all'",
                                    "enum": ["function", "file", "class", "endpoint", "contract", "all"],
                                    "examples": ["endpoint", "class", "function"]
                                },
                                "stereotype": {
                                    "type": "string",
                                    "description": "StÃ©rÃ©otype architectural (ex: 'Â«ModelÂ»', 'Â«ControllerÂ»', 'Â«ComponentÂ»', 'Â«FormÂ»', 'Â«ServiceÂ»', 'Â«EndpointÂ»')",
                                    "examples": ["Â«ControllerÂ»", "Â«ModelÂ»", "Â«ComponentÂ»"]
                                },
                                "has_violation": {
                                    "type": "boolean",
                                    "description": "Filtrer uniquement les symboles ayant des violations de sÃ©curitÃ© ou CVE dÃ©tectÃ©es"
                                },
                                "limit": {
                                    "type": "integer",
                                    "description": "Nombre maximum de rÃ©sultats Ã  renvoyer (par dÃ©faut 15, max 50)",
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
                            "title": "Recherche Multi-CritÃ¨res AST & Couches MVC",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_trace_flow",
                        "description": "Trace le flux complet d'une fonctionnalitÃ© Ã  travers l'architecture MVC (Vue -> ContrÃ´leur -> Service MÃ©tier -> ModÃ¨le -> Base de donnÃ©es).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "symbol_id": {
                                    "type": "string",
                                    "description": "Identifiant ou nom du symbole de dÃ©part pour le traÃ§age",
                                    "examples": ["checkout", "handle_booking", "store_service", "AuditWriter"]
                                },
                                "direction": {
                                    "type": "string",
                                    "description": "Direction du traÃ§age : 'upstream' (appelants & vues), 'downstream' (dÃ©pendances, modÃ¨les & DB), ou 'both' (les deux)",
                                    "enum": ["upstream", "downstream", "both"],
                                    "examples": ["both", "upstream", "downstream"]
                                },
                                "max_depth": {
                                    "type": "integer",
                                    "description": "Profondeur maximale de parcours des relations dans le graphe (dÃ©faut 2, max 5)",
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
                            "title": "TraÃ§age de Flux MVC & DÃ©pendances",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_query_violations",
                        "description": "RequÃªte directement les violations de sÃ©curitÃ© SAST, motifs Zero-Day et failles CWE dÃ©tectÃ©es sur l'architecture avec recommandations de correction.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "severity": {
                                    "type": "string",
                                    "description": "Niveau de sÃ©vÃ©ritÃ© requis : 'all', 'critical', 'high', 'medium', 'low', 'warning'",
                                    "enum": ["all", "critical", "high", "medium", "low", "warning"],
                                    "examples": ["critical", "high", "all"]
                                },
                                "cwe_id": {
                                    "type": "string",
                                    "description": "Identifiant CWE ou nom de rÃ¨gle recherchÃ© (ex: 'CWE-22', 'CWE-89', 'CWE-248', 'SQL-INJECTION')",
                                    "examples": ["CWE-22", "CWE-89", "CWE-248"]
                                },
                                "file_pattern": {
                                    "type": "string",
                                    "description": "Filtre optionnel sur le chemin ou nom de fichier concernÃ©",
                                    "examples": ["audit_writer", "api_routes", "server.rs"]
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
                            "title": "Audit & Filtrage des Violations SAST/CWE",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_list_plugins",
                        "description": "Liste tous les plugins de sÃ©curitÃ© SAST et leurs rÃ¨gles CWE dÃ©claratives chargÃ©s depuis .aether/plugins (ou dossier spÃ©cifiÃ©).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "plugins_dir": {
                                    "type": "string",
                                    "description": "Chemin optionnel vers le dossier des plugins (dÃ©faut: '.aether/plugins')"
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin racine optionnel du projet"
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Inventaire des Plugins & RÃ¨gles CWE Custom",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_test_plugins",
                        "description": "ExÃ©cute la suite de tests unitaires intÃ©grÃ©e aux rÃ¨gles des plugins pour valider l'absence de faux positifs et certifier la dÃ©tection.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "plugins_dir": {
                                    "type": "string",
                                    "description": "Chemin optionnel vers le dossier des plugins (dÃ©faut: '.aether/plugins')"
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin racine optionnel du projet"
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Validation des Tests Unitaires Plugins",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_scan_with_plugins",
                        "description": "Audite un fichier ou un dossier avec les plugins de rÃ¨gles CWE personnalisÃ©s et renvoie les violations dÃ©tectÃ©es avec remÃ©diations.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target_path": {
                                    "type": "string",
                                    "description": "Fichier ou dossier cible Ã  analyser avec les rÃ¨gles des plugins"
                                },
                                "plugins_dir": {
                                    "type": "string",
                                    "description": "Chemin optionnel vers le dossier des plugins (dÃ©faut: '.aether/plugins')"
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin racine optionnel du projet"
                                }
                            },
                            "required": ["target_path"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Scan SAST avec Plugins CWE",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_upsert_plugin_rule",
                        "description": "CrÃ©e ou met Ã  jour une rÃ¨gle de sÃ©curitÃ© CWE dans un plugin YAML (.aether/plugins/<plugin_name>/plugin.yaml). Valide automatiquement les cas de test avant enregistrement.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "plugin_name": {
                                    "type": "string",
                                    "description": "Nom du plugin (ex: 'api-security-rules')"
                                },
                                "rule_id": {
                                    "type": "string",
                                    "description": "Identifiant unique de la rÃ¨gle (ex: 'CUSTOM-SEC-001')"
                                },
                                "cwe_id": {
                                    "type": "string",
                                    "description": "Identifiant CWE (ex: 'CWE-89 / SQL-INJECTION')"
                                },
                                "name": {
                                    "type": "string",
                                    "description": "Nom court de la rÃ¨gle"
                                },
                                "severity": {
                                    "type": "string",
                                    "description": "SÃ©vÃ©ritÃ© : 'CRITICAL', 'HIGH', 'MEDIUM', 'WARNING', 'LOW'",
                                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW"]
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description dÃ©taillÃ©e de la vulnÃ©rabilitÃ©"
                                },
                                "remediation": {
                                    "type": "string",
                                    "description": "Conseil technique de correction certifiÃ©"
                                },
                                "file_extensions": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Liste des extensions de fichiers visÃ©es (ex: ['.rs', '.py', '.php', '.ts'])"
                                },
                                "match_mode": {
                                    "type": "string",
                                    "enum": ["line_by_line", "whole_file"],
                                    "description": "Mode d'Ã©valuation (dÃ©faut: 'line_by_line')"
                                },
                                "must_contain": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Sous-chaÃ®nes devant obligatoirement Ãªtre prÃ©sentes dans le fichier"
                                },
                                "must_not_contain": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Sous-chaÃ®nes neutralisant l'alerte (attÃ©nuation valide)"
                                },
                                "regex_patterns": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Expressions rÃ©guliÃ¨res dÃ©clenchant la violation"
                                },
                                "forbidden_tokens": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Mots-clÃ©s ou fonctions interdites"
                                },
                                "check_literals": {
                                    "type": "boolean",
                                    "description": "Si true, Ã©value Ã©galement les chaÃ®nes et commentaires littÃ©raux"
                                },
                                "test_cases": {
                                    "type": "array",
                                    "description": "Cas de tests unitaires pour valider la rÃ¨gle",
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
                                },
                                "plugins_dir": {
                                    "type": "string",
                                    "description": "Dossier des plugins (dÃ©faut: '.aether/plugins')"
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin racine optionnel du projet"
                                }
                            },
                            "required": ["plugin_name", "rule_id", "cwe_id", "name", "severity", "description", "remediation", "file_extensions"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "CrÃ©ation / Mise Ã  jour de RÃ¨gle Plugin CWE",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    }
                ]
            })),
            error: None,
        }),

        "tools/call" => {
            let params = req.params.unwrap_or(json!({}));
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

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

                    // Si un chemin spÃ©cifique a Ã©tÃ© fourni, on ordonne au serveur de basculer et d'analyser ce projet
                    let graph_val_res = if let Some(req_path) = req_path_opt {
                        let analyze_res = send_http_request(server_port, "POST", "/api/analyze", Some(&json!({
                            "path": req_path
                        }))).await;
                        match analyze_res {
                            Ok(val) => Ok(val),
                            Err(_) => send_http_request(server_port, "GET", "/api/graph", None).await,
                        }
                    } else {
                        send_http_request(server_port, "GET", "/api/graph", None).await
                    };

                    match graph_val_res {
                        Ok(graph_val) => {
                            let summary = format_graph_summary(&graph_val);
                            (json!([{ "type": "text", "text": summary }]), false)
                        }
                        Err(_) => {
                            // Fallback direct AST scanner offline : scanne directement le projet sans dÃ©pendre du serveur web
                            let target_path = req_path_opt.unwrap_or(default_path);
                            let p_buf = PathBuf::from(target_path);
                            let scanner = ast_scanner::ProjectScanner::default();
                            let g = scanner.scan_project(&p_buf);
                            let summary = format_ast_summary(&g, &p_buf);
                            (json!([{ "type": "text", "text": summary }]), false)
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
                    if symbol_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "âš ï¸ Erreur: Le paramÃ¨tre 'symbol_id' est requis." }]), true)
                    } else {
                        let res = send_http_request(server_port, "POST", "/api/ai/target", Some(&json!({
                            "symbol_id": symbol_id
                        }))).await;

                        match res {
                            Ok(val) => {
                                let text = format_active_target_response(&val);
                                let is_err = val.get("status").and_then(|v| v.as_str()) != Some("ok");
                                (json!([{ "type": "text", "text": text }]), is_err)
                            }
                            Err(_) => {
                                let text = offline_active_target_fallback(target_path, &symbol_id);
                                let is_err = text.starts_with("âš ï¸");
                                (json!([{ "type": "text", "text": text }]), is_err)
                            }
                        }
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

                            let summary = format_graph_summary(&val);
                            (json!([{
                                "type": "text",
                                "text": format!("âš¡ Projet `{}` rÃ©analysÃ© et synchronisÃ© avec succÃ¨s dans AetherScope V2 !\n\n{}", scan_path, summary)
                            }]), false)
                        }
                        Err(e) => {
                            // Fallback direct AST scanner offline si le serveur n'est pas joignable
                            let p_buf = PathBuf::from(scan_path);
                            let scanner = ast_scanner::ProjectScanner::default();
                            let g = scanner.scan_project(&p_buf);
                            let summary = format_ast_summary(&g, &p_buf);
                            (json!([{
                                "type": "text",
                                "text": format!("âš¡ Projet `{}` analysÃ© (mode autonome AST direct - serveur: {}) :\n\n{}", scan_path, e, summary)
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

                    if task_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "âš ï¸ Erreur: 'task_id' requis pour la mise Ã  jour." }]), true)
                    } else {
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
                    let filter = arguments.get("status_filter").and_then(|v| v.as_str()).unwrap_or("active");
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
                    let limit = arguments.get("limit").and_then(|v| v.as_u64()).unwrap_or(15) as usize;
                    let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);

                    let p_buf = resolve_project_root(req_path);
                    let scanner = ast_scanner::ProjectScanner::default();
                    let g = scanner.scan_project(&p_buf);
                    let text = format_search_symbols_response(&g, query, layer, kind, stereotype, has_violation, limit);
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
                        let scanner = ast_scanner::ProjectScanner::default();
                        let g = scanner.scan_project(&p_buf);
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
                    let scanner = ast_scanner::ProjectScanner::default();
                    let g = scanner.scan_project(&p_buf);
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

fn format_graph_summary(val: &Value) -> String {
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

fn format_ast_summary(g: &core_graph::graph::AetherGraph, project_root: &Path) -> String {
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

fn format_active_target_response(val: &Value) -> String {
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

fn offline_active_target_fallback(project_path: &str, symbol_id: &str) -> String {
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


fn format_search_symbols_response(
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

fn format_trace_flow_response(
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

fn format_violations_response(
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
        assert_eq!(prompts.len(), 3);

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
        assert_eq!(tools.len(), 16);

        let expected_tools = [
            ("aetherscope_teleport_camera", true, false, true, false),
            ("aetherscope_get_graph_summary", true, false, true, false),
            ("aetherscope_send_chat_message", false, false, false, false),
            ("aetherscope_get_chat_history", true, false, true, false),
            ("aetherscope_get_active_target", true, false, true, false),
            ("aetherscope_scan_project", true, false, true, false),
            ("aetherscope_create_task", false, false, false, false),
            ("aetherscope_update_task", false, false, true, false),
            ("aetherscope_list_tasks", true, false, true, false),
            ("aetherscope_search_symbols", true, false, true, false),
            ("aetherscope_trace_flow", true, false, true, false),
            ("aetherscope_query_violations", true, false, true, false),
            ("aetherscope_list_plugins", true, false, true, false),
            ("aetherscope_test_plugins", true, false, true, false),
            ("aetherscope_scan_with_plugins", true, false, true, false),
            ("aetherscope_upsert_plugin_rule", false, false, true, false),
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
}
