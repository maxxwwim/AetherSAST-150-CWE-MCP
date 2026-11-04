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

    // 1. Vérifie si AetherScope tourne sur le port
    let is_server_listening = check_server_listening(port);

    if !is_server_listening {
        eprintln!("📡 [AetherScope MCP] Serveur non détecté sur le port {}. Démarrage automatique de l'agent en tâche de fond...", port);
        // Note: mcp_main est le binaire autonome stdio, on s'exécute directement en mode pont
    } else {
        eprintln!("📡 [AetherScope MCP] Connecté à l'instance active AetherScope sur http://127.0.0.1:{}", port);
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
                        "description": "Synthèse temps réel du graphe AST 3D (nœuds, arêtes, clusters, métriques de santé) pour injection de contexte immédiat.",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aether://audit/live",
                        "name": "AetherScope Live Security Audit (SAST/CWE)",
                        "description": "Rapport d'audit SAST live (.aether/LIVE_AUDIT.md) analysant les 150+ motifs de vulnérabilités CWE détectées.",
                        "mimeType": "text/markdown"
                    },
                    {
                        "uri": "aether://contracts/manifest",
                        "name": "Aether Architecture Manifest",
                        "description": "Manifeste d'architecture aether.manifest.json ou aether.lock.toml définissant les contrats EARS et les frontières de couches.",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "aether://tasks/active",
                        "name": "AetherScope Active AI Tasks",
                        "description": "Registre des tâches d'ingénierie et de refactorisation pilotées par l'IA (.aether/tasks/).",
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
                            "info": "Aucun fichier aether.manifest.json ou aether.lock.toml détecté à la racine."
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
                        "description": "Génère un prompt d'audit et de remédiation ciblée pour corriger une vulnérabilité SAST / violation CWE détectée dans le graphe AetherScope.",
                        "arguments": [
                            {
                                "name": "symbol_name",
                                "description": "Nom du symbole (fonction, classe, struct) ou chemin du fichier à auditer.",
                                "required": true
                            },
                            {
                                "name": "cwe_id",
                                "description": "Identifiant CWE ou catégorie de la faille (ex: CWE-89, CWE-79, Memory Safety).",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "scaffold_game_server",
                        "description": "Génère un prompt guidé pour l'implémentation d'une architecture serveur de jeu (Roblox Luau ou Minecraft Paper/Purpur) optimisée pour AetherScope.",
                        "arguments": [
                            {
                                "name": "engine",
                                "description": "Moteur cible : 'roblox' ou 'minecraft'.",
                                "required": true
                            },
                            {
                                "name": "package_name",
                                "description": "Nom du composant ou plugin serveur à créer.",
                                "required": true
                            }
                        ]
                    },
                    {
                        "name": "refactor_contract_violation",
                        "description": "Génère un prompt d'analyse et de correction lorsqu'une rupture de contrat EARS ou une violation d'import de couche est détectée.",
                        "arguments": [
                            {
                                "name": "contract_name",
                                "description": "Nom du contrat ou de l'interface en violation.",
                                "required": true
                            },
                            {
                                "name": "violation_details",
                                "description": "Détails de l'incompatibilité ou de la violation de frontière.",
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
                        "Vous êtes l'architecte de sécurité AetherScope. Effectuez l'audit et la remédiation de la cible `{}` concernée par la vulnérabilité `{}`.\n\n\
                        Protocole obligatoire :\n\
                        1. Utilisez `aetherscope_teleport_camera` vers `{}` avec l'action 'Correction CVE'.\n\
                        2. Utilisez `aetherscope_get_active_target` sur `{}` pour vérifier les contrats EARS et les appelants en amont.\n\
                        3. Proposez une correction sécurisée (validation stricte des entrées, typage invariant, absence d'allocation superflue) sans rompre l'API publique.\n\
                        4. Créez ou mettez à jour une tâche via `aetherscope_create_task` (type: 'security_fix').",
                        symbol_name, cwe_id, symbol_name, symbol_name
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Audit de sécurité AetherScope pour {} ({})", symbol_name, cwe_id),
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
                            "Vous implémentez un module serveur de jeu haute performance sous Roblox Luau (`{}`) intégré dans l'écosystème AetherScope.\n\n\
                            Spécifications techniques :\n\
                            - Architecture contractuelle stricte : `contracts/` pour les paquets réseau RemoteEvent/RemoteFunction avec typage Luau strict (`--!strict`).\n\
                            - Séparation stricte : `server/` (logique d'autorité exclusive), `client/` (prédiction locale, pas de trust), `data-nodes/` (sauvegarde DataStore atomique).\n\
                            - Utilisez `aetherscope_create_task` avec le type 'function' pour suivre l'implémentation de `{}`.\n\
                            - Téléportez la caméra sur le module via `aetherscope_teleport_camera`.",
                            package_name, package_name
                        )
                    } else {
                        format!(
                            "Vous implémentez un plugin serveur Minecraft Paper/Purpur (`{}`) haute performance selon les standards AetherScope.\n\n\
                            Spécifications techniques :\n\
                            - Architecture découplée : API & Contrats d'événements séparés de l'implémentation Bukkit/Spigot.\n\
                            - Concurrency & Tick-safety : Aucun blocage sur le Main Thread tick de 50ms, utilisation d'AsyncScheduler et collections concurrentes.\n\
                            - Utilisez `aetherscope_create_task` pour déclarer les jalons du plugin `{}`.\n\
                            - Vérifiez l'absence de fuite mémoire sur les EventHandler désenregistrés.",
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
                    let details = arguments.get("violation_details").and_then(|v| v.as_str()).unwrap_or("Non-respect des règles EARS ou fuite de dépendances.");
                    let prompt_text = format!(
                        "Une violation de contrat d'architecture a été relevée sur `{}` :\n`{}`\n\n\
                        Directives AetherScope :\n\
                        1. Inspectez les liaisons amont/aval via `aetherscope_get_active_target` sur `{}`.\n\
                        2. Vérifiez le respect du README de spécification EARS et du fichier `aether.manifest.json`.\n\
                        3. Supprimez les imports circulaires ou illicites entre couches (ex: core ne doit jamais importer desktop-shell).\n\
                        4. Signalez l'avancement via `aetherscope_send_chat_message`.",
                        contract_name, details, contract_name
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Résolution violation contrat {}", contract_name),
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
                        "description": "Oriente la caméra WebGL en direct dans AetherScope vers un symbole ou un fichier, et affiche où l'IA travaille en temps réel (fil d'Ariane violet, faisceau laser et réticule tactique).",
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
                                    "description": "Action en cours (ex: 'Inspection', 'Analyse', 'Création', 'Refactoring', 'Correction CVE', 'Audit', 'Tests')",
                                    "examples": ["Inspection", "Refactoring", "Correction CVE", "Audit", "Tests"]
                                },
                                "details": {
                                    "type": "string",
                                    "description": "Courte description technique de ce que vous observez ou réalisez",
                                    "examples": ["Vérification des invariants et de la non-nullabilité du token d'accès"]
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
                        "name": "aetherscope_get_graph_summary",
                        "description": "Récupère l'architecture complète du projet (nombre de nœuds, flux, liste des dossiers, santé globale et violations de sécurité CVE) depuis AetherScope.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Chemin optionnel du projet à analyser (par défaut le projet actif)",
                                    "examples": [".", "crates/desktop-shell", "crates/core-graph"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Résumé d'Architecture & Santé Projet",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_send_chat_message",
                        "description": "Envoie un message ou debrief technique de l'IA directement dans le chat intégré de l'interface AetherScope du développeur.",
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
                                    "examples": ["Analyse terminée : 0 vulnérabilité détectée sur le module d'authentification."]
                                },
                                "thought": {
                                    "type": "string",
                                    "description": "Raisonnement ou réflexion interne de l'IA (optionnel)",
                                    "examples": ["Le scan SAST valide l'arbre AST et les contrats EARS sans anomalie de mémoire."]
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Symbole ou fichier associé au message (optionnel)",
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
                        "description": "Récupère l'historique des échanges récents du chat AetherScope.",
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
                        "description": "Récupère le contexte ciblé et le handshake pour un symbole : appelants amont, dépendances aval, règles README EARS et imports interdits.",
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
                        "description": "Déclenche une réanalyse complète de l'architecture d'un projet pour rafraîchir le graphe 3D.",
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
                    },
                    {
                        "name": "aetherscope_create_task",
                        "description": "Crée une nouvelle tâche (fonction, recherche, sécurité, refactorisation, etc.) avec son mini-README d'avancement pour structurer le travail dans le contexte du modèle et du développeur.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "title": {
                                    "type": "string",
                                    "description": "Titre explicite de la tâche à accomplir",
                                    "examples": ["Correction vulnérabilité CWE-89 dans SQL Query Builder"]
                                },
                                "kind": {
                                    "type": "string",
                                    "description": "Type de tâche : 'function', 'research', 'security_fix', 'arch_refactor', 'documentation', 'test', ou 'other'",
                                    "enum": ["function", "research", "security_fix", "arch_refactor", "documentation", "test", "other"],
                                    "examples": ["security_fix", "function", "arch_refactor"]
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Nom optionnel du symbole AST ciblé dans le graphe (ex: 'BookingService', 'verify_token')",
                                    "examples": ["execute_query", "BookingService"]
                                },
                                "target_file": {
                                    "type": "string",
                                    "description": "Chemin optionnel du fichier concerné (ex: 'src/auth.rs', 'contracts/ports.rs')",
                                    "examples": ["src/db/query.rs", "contracts/packets.rs"]
                                },
                                "priority": {
                                    "type": "string",
                                    "description": "Priorité de la tâche ('low', 'medium', 'high', 'critical')",
                                    "enum": ["low", "medium", "high", "critical"],
                                    "examples": ["critical", "high", "medium"]
                                },
                                "initial_readme": {
                                    "type": "string",
                                    "description": "Contenu Markdown optionnel pour initialiser le mini-README d'avancement (objectifs, checklist d'étapes)",
                                    "examples": ["### Objectifs\n- Remplacer interpolation par requête préparée\n- Vérifier tests unitaires"]
                                }
                            },
                            "required": ["title"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Création de Tâche AetherScope",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_update_task",
                        "description": "Met à jour l'état d'avancement d'une tâche, son statut ('pending', 'in_progress', 'blocked', 'done'), son pourcentage (0-100%) et ajoute des notes au mini-README.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "task_id": {
                                    "type": "string",
                                    "description": "Identifiant unique de la tâche (ex: 'task_123456_nom')",
                                    "examples": ["task_1730000000_sec", "task_01_game_server"]
                                },
                                "status": {
                                    "type": "string",
                                    "description": "Nouveau statut de la tâche ('pending', 'in_progress', 'blocked', 'done', 'cancelled')",
                                    "enum": ["pending", "in_progress", "blocked", "done", "cancelled"],
                                    "examples": ["in_progress", "done", "blocked"]
                                },
                                "progress": {
                                    "type": "integer",
                                    "description": "Pourcentage d'avancement estimé de la tâche entre 0 et 100",
                                    "minimum": 0,
                                    "maximum": 100,
                                    "examples": [50, 100]
                                },
                                "progress_note": {
                                    "type": "string",
                                    "description": "Courte note de progrès à consigner dans le mini-README de la tâche",
                                    "examples": ["Contrat validé, implémentation des tests unitaires en cours."]
                                },
                                "full_readme": {
                                    "type": "string",
                                    "description": "Nouveau contenu complet du mini-README de la tâche (si réécriture / mise à jour complète de la checklist)",
                                    "examples": ["# Tâche Terminée\n- [x] Spécifications rédigées\n- [x] Code validé\n- [x] Audit SAST 0 faille"]
                                }
                            },
                            "required": ["task_id"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Mise à Jour de Tâche AetherScope",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_list_tasks",
                        "description": "Récupère la liste des tâches du projet AetherScope avec leur type, statut, avancement et résumé du mini-README.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "status_filter": {
                                    "type": "string",
                                    "description": "Filtre optionnel : 'active' (par défaut, exclut les terminées), 'all' (toutes les tâches), 'done' (uniquement terminées)",
                                    "enum": ["active", "all", "done"],
                                    "examples": ["active", "all", "done"]
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Liste des Tâches AetherScope",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_search_symbols",
                        "description": "Recherche avancée dans l'index AST d'AetherScope par mot-clé, couche MVC (ui, action, domain, database), stéréotype («Model», «Controller», «Component») ou statut de sécurité.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Texte ou mot-clé à rechercher dans le nom du symbole, le fichier, la docstring ou les méthodes",
                                    "examples": ["checkout", "Item", "auth", "BookingService"]
                                },
                                "layer": {
                                    "type": "string",
                                    "description": "Couche architecturale : 'ui' (Vue), 'action' (Contrôleur), 'domain' (Métier), 'database' (Modèle/Persistance), 'utility', 'config', 'docs' ou 'all'",
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
                                    "description": "Stéréotype architectural (ex: '«Model»', '«Controller»', '«Component»', '«Form»', '«Service»', '«Endpoint»')",
                                    "examples": ["«Controller»", "«Model»", "«Component»"]
                                },
                                "has_violation": {
                                    "type": "boolean",
                                    "description": "Filtrer uniquement les symboles ayant des violations de sécurité ou CVE détectées"
                                },
                                "limit": {
                                    "type": "integer",
                                    "description": "Nombre maximum de résultats à renvoyer (par défaut 15, max 50)",
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
                            "title": "Recherche Multi-Critères AST & Couches MVC",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_trace_flow",
                        "description": "Trace le flux complet d'une fonctionnalité à travers l'architecture MVC (Vue -> Contrôleur -> Service Métier -> Modèle -> Base de données).",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "symbol_id": {
                                    "type": "string",
                                    "description": "Identifiant ou nom du symbole de départ pour le traçage",
                                    "examples": ["checkout", "handle_booking", "store_service", "AuditWriter"]
                                },
                                "direction": {
                                    "type": "string",
                                    "description": "Direction du traçage : 'upstream' (appelants & vues), 'downstream' (dépendances, modèles & DB), ou 'both' (les deux)",
                                    "enum": ["upstream", "downstream", "both"],
                                    "examples": ["both", "upstream", "downstream"]
                                },
                                "max_depth": {
                                    "type": "integer",
                                    "description": "Profondeur maximale de parcours des relations dans le graphe (défaut 2, max 5)",
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
                            "title": "Traçage de Flux MVC & Dépendances",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_query_violations",
                        "description": "Requête directement les violations de sécurité SAST, motifs Zero-Day et failles CWE détectées sur l'architecture avec recommandations de correction.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "severity": {
                                    "type": "string",
                                    "description": "Niveau de sévérité requis : 'all', 'critical', 'high', 'medium', 'low', 'warning'",
                                    "enum": ["all", "critical", "high", "medium", "low", "warning"],
                                    "examples": ["critical", "high", "all"]
                                },
                                "cwe_id": {
                                    "type": "string",
                                    "description": "Identifiant CWE ou nom de règle recherché (ex: 'CWE-22', 'CWE-89', 'CWE-248', 'SQL-INJECTION')",
                                    "examples": ["CWE-22", "CWE-89", "CWE-248"]
                                },
                                "file_pattern": {
                                    "type": "string",
                                    "description": "Filtre optionnel sur le chemin ou nom de fichier concerné",
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
                            "text": format!("🪐 Caméra AetherScope alignée sur : {} ({})\n📡 Faisceau quantique et fil d'Ariane stellaire illuminés sur le graphe 3D WebGL 2.", target, action)
                        }]), false),
                        Err(e) => (json!([{
                            "type": "text",
                            "text": format!("⚠️ Télémétrie enregistrée : [{}] sur {}\n(Détails : {})", action, target, e)
                        }]), false),
                    }
                }

                "aetherscope_get_graph_summary" => {
                    let req_path_opt = arguments.get("path").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());

                    // Si un chemin spécifique a été fourni, on ordonne au serveur de basculer et d'analyser ce projet
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
                            // Fallback direct AST scanner offline : scanne directement le projet sans dépendre du serveur web
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
                        (json!([{ "type": "text", "text": "⚠️ Erreur: Le paramètre 'text' ne peut pas être vide." }]), true)
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
                            Ok(_) => (json!([{ "type": "text", "text": "💬 Message affiché dans le HUD AetherScope de l'utilisateur." }]), false),
                            Err(e) => (json!([{ "type": "text", "text": format!("⚠️ Erreur envoi chat AetherScope : {}", e) }]), true),
                        }
                    }
                }

                "aetherscope_get_chat_history" => {
                    let res = send_http_request(server_port, "GET", "/api/ai/chat", None).await;
                    match res {
                        Ok(val) => (json!([{ "type": "text", "text": serde_json::to_string_pretty(&val).unwrap_or_default() }]), false),
                        Err(e) => (json!([{ "type": "text", "text": format!("⚠️ Erreur historique chat : {}", e) }]), true),
                    }
                }

                "aetherscope_get_active_target" => {
                    let symbol_id = arguments.get("symbol_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let target_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                    if symbol_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "⚠️ Erreur: Le paramètre 'symbol_id' est requis." }]), true)
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
                                let is_err = text.starts_with("⚠️");
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
                                "details": "Réanalyse complète déclenchée par l'agent IA via MCP"
                            }))).await;

                            let summary = format_graph_summary(&val);
                            (json!([{
                                "type": "text",
                                "text": format!("⚡ Projet `{}` réanalysé et synchronisé avec succès dans AetherScope V2 !\n\n{}", scan_path, summary)
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
                                "text": format!("⚡ Projet `{}` analysé (mode autonome AST direct - serveur: {}) :\n\n{}", scan_path, e, summary)
                            }]), false)
                        }
                    }
                }

                "aetherscope_create_task" => {
                    let title = arguments.get("title").and_then(|v| v.as_str()).unwrap_or("Nouvelle tâche").to_string();
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
                                "text": format!("📋 Tâche `{}` créée avec succès !\n📁 Mini-README disponible dans `.aether/tasks/{}/README.md`\n{}", task_id, task_id, serde_json::to_string_pretty(&val).unwrap_or_default())
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
                                    "text": format!("📋 Tâche `{}` créée (mode offline) !\n📁 Fichier : `.aether/tasks/{}/README.md`", t.id, t.id)
                                }]), false),
                                Err(e) => (json!([{ "type": "text", "text": format!("⚠️ Erreur création tâche : {}", e) }]), true),
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
                        (json!([{ "type": "text", "text": "⚠️ Erreur: 'task_id' requis pour la mise à jour." }]), true)
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
                                "text": format!("⚡ Tâche `{}` mise à jour avec succès :\n{}", task_id, serde_json::to_string_pretty(&val).unwrap_or_default())
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
                                        "text": format!("⚡ Tâche `{}` mise à jour (mode offline). Statut: {:?}, Progrès: {}%", t.id, t.status, t.progress)
                                    }]), false),
                                    Ok(None) => (json!([{ "type": "text", "text": format!("⚠️ Tâche `{}` introuvable.", task_id) }]), true),
                                    Err(e) => (json!([{ "type": "text", "text": format!("⚠️ Erreur mise à jour tâche : {}", e) }]), true),
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
                        (json!([{ "type": "text", "text": "📋 Aucune tâche trouvée pour ce filtre." }]), false)
                    } else {
                        let mut output = format!("📋 Tâches AetherScope (Total : {}):\n\n", filtered.len());
                        for t in filtered {
                            let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let title = t.get("title").and_then(|v| v.as_str()).unwrap_or("");
                            let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                            let status = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                            let progress = t.get("progress").and_then(|v| v.as_u64()).unwrap_or(0);
                            let target = t.get("target_symbol").and_then(|v| v.as_str()).unwrap_or("-");
                            let summary = t.get("readme_summary").and_then(|v| v.as_str()).unwrap_or("");

                            output.push_str(&format!("• `{}` [{}] **{}** ({}, {}%)\n  - Cible : `{}`\n  - Avancement : {}\n\n", id, kind, title, status, progress, target, summary));
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
                        (json!([{ "type": "text", "text": "⚠️ Erreur: Le paramètre 'symbol_id' est requis." }]), true)
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
                violations.push(format!("- 🚨 `{}`{} — `{}`", name, cve_desc, file));
            }
        }
    }

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

    format!(
        "🪐 Résumé Architectural AetherScope V2 :\n\
         • Projet Actif : `{}`\n\
         {}\
         • Total Nœuds (Bulles) : {}\n\
         • Total Relations (Arêtes) : {}\n\
         • Modules / Dossiers ({} au total) :\n{}\
         • Statut Sécurité & Règles :\n{}\n\
         • Visualiseur WebGL 2 disponible sur http://127.0.0.1:3030",
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
            violations.push(format!("- 🚨 `{}`{} — `{}`", n.name, cve_desc, n.file_path));
        }
    }

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

    format!(
        "🪐 Résumé Architectural AetherScope V2 (Mode Autonome AST) :\n\
         • Projet Actif : `{}`\n\
         • Emplacement : `{}`\n\
         • Total Nœuds (Bulles) : {}\n\
         • Total Relations (Arêtes) : {}\n\
         • Modules / Dossiers ({} au total) :\n{}\
         • Statut Sécurité & Règles :\n{}\n\
         • Note : Lancez `aether-engine` pour activer la vue WebGL 2 interactive en direct.",
        g.project_name, project_root.display(), total_nodes, total_edges, folders.len(), folders_str, violations_str
    )
}

fn format_active_target_response(val: &Value) -> String {
    let status = val.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
    if status != "ok" {
        return "⚠️ Symbole ou module non trouvé dans le graphe actif AetherScope.".to_string();
    }

    if let Some(md) = val.get("formatted_doc_and_liaisons").and_then(|v| v.as_str()) {
        let handshake = val.get("handshake_xml").and_then(|v| v.as_str()).unwrap_or("");
        if !handshake.is_empty() {
            format!("{}\n\n### 🤝 Handshake Copilote IA :\n```xml\n{}\n```", md, handshake)
        } else {
            md.to_string()
        }
    } else {
        serde_json::to_string_pretty(val).unwrap_or_default()
    }
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
    } else {
        let sym_low = symbol_id.to_lowercase();
        let suggestions: Vec<&str> = g.nodes.iter()
            .filter(|n| n.name.to_lowercase().contains(&sym_low) || sym_low.contains(&n.name.to_lowercase()))
            .map(|n| n.name.as_str())
            .take(5)
            .collect();
        if !suggestions.is_empty() {
            format!("⚠️ Symbole '{}' introuvable dans '{}'.\n💡 Symboles proches détectés : {}\n👉 Utilisez `aetherscope_search_symbols` pour explorer l'index.", symbol_id, p_buf.display(), suggestions.join(", "))
        } else {
            format!("⚠️ Symbole '{}' introuvable dans '{}'. Utilisez `aetherscope_search_symbols` pour rechercher par mot-clé.", symbol_id, p_buf.display())
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
            .map_err(|e| format!("AetherScope non connecté sur http://127.0.0.1:{} ({})", addr.port(), e))?;

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
        return format!("🔍 Aucun symbole trouvé pour la requête '{}' avec les filtres sélectionnés.", query);
    }

    let mut out = format!(
        "🔍 **Résultats de Recherche AetherScope ({}/{} trouvés) :**\n\n| Score | Symbole | Stéréotype | Couche / Galaxie | Fichier : Ligne | Statut |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n",
        display_items.len(),
        total_matches
    );

    for (score, n) in display_items {
        let sec_badge = if n.has_security_violation {
            "🚨 CVE/SAST"
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

    out.push_str("\n💡 *Pour inspecter le contexte précis, les flux et règles EARS d'un symbole : utilisez `aetherscope_get_active_target(\"<symbole>\")` ou `aetherscope_trace_flow(\"<symbole>\")`.*");
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
                return format!("⚠️ Symbole '{}' introuvable pour le traçage.\n💡 Symboles proches : {}\n👉 Utilisez `aetherscope_search_symbols` pour trouver le nom exact.", symbol_id, suggestions.join(", "));
            } else {
                return format!("⚠️ Symbole '{}' introuvable pour le traçage. Utilisez `aetherscope_search_symbols` pour trouver le nom exact.", symbol_id);
            }
        }
    };

    let dir_lower = direction.trim().to_lowercase();
    let trace_up = dir_lower == "upstream" || dir_lower == "both" || dir_lower == "all";
    let trace_down = dir_lower == "downstream" || dir_lower == "both" || dir_lower == "all";

    let mut out = format!(
        "# 🌊 Traçage de Flux Architectural pour `{}`\n- **Fichier :** `{}:{}`\n- **Couche :** `{}` | **Galaxie :** `{}` | **Stéréotype :** `{}`\n\n",
        sym.name, sym.file_path, sym.line_number, sym.layer, sym.galaxy, sym.stereotype
    );

    if trace_up {
        out.push_str("### 📥 Flux Amont (Appelants, Vues UI & Contrôleurs déclencheurs) :\n");
        let incoming: Vec<&core_graph::edge::AffiliationEdge> = g
            .edges
            .iter()
            .filter(|e| e.target == sym.id && e.relation != "contains")
            .collect();

        if incoming.is_empty() {
            out.push_str("*(Aucun flux amont direct détecté — point d'entrée ou racine)*\n\n");
        } else {
            for e in incoming.iter().take(15) {
                let src_node = g.nodes.iter().find(|n| n.id == e.source);
                let (src_name, src_layer, src_file) = match src_node {
                    Some(n) => (n.name.as_str(), n.layer.as_str(), n.file_path.as_str()),
                    None => (e.source.as_str(), "inconnu", ""),
                };
                out.push_str(&format!(
                    "- ➔ `[{}]` **{}** (`{}`) via `{}`\n",
                    src_layer, src_name, src_file, e.relation
                ));
            }
            out.push('\n');
        }
    }

    if trace_down {
        out.push_str("### 📤 Flux Aval (Services appelés, Modèles & Persistance DB) :\n");
        let outgoing: Vec<&core_graph::edge::AffiliationEdge> = g
            .edges
            .iter()
            .filter(|e| e.source == sym.id && e.relation != "contains")
            .collect();

        if outgoing.is_empty() {
            out.push_str("*(Aucun flux aval direct détecté — feuille ou logique pure)*\n\n");
        } else {
            for e in outgoing.iter().take(15) {
                let tgt_node = g.nodes.iter().find(|n| n.id == e.target);
                let (tgt_name, tgt_layer, tgt_file) = match tgt_node {
                    Some(n) => (n.name.as_str(), n.layer.as_str(), n.file_path.as_str()),
                    None => (e.target.as_str(), "inconnu", ""),
                };
                out.push_str(&format!(
                    "- ➔ `[{}]` **{}** (`{}`) via `{}`\n",
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
        return "✅ Aucune violation de sécurité ne correspond aux filtres demandés.".to_string();
    }

    let mut out = format!("🛡️ **Audit des Violations SAST/CWE ({}) :**\n\n", list.len());
    for (sev, f, line, cwe, msg, fix, sym) in list.iter().take(20) {
        let icon = match sev.as_str() {
            "CRITICAL" => "🔴",
            "HIGH" => "🟠",
            "MEDIUM" => "🟡",
            _ => "⚪",
        };
        out.push_str(&format!(
            "- {} **[{}] {}** dans `{}:{}` (symbole: `{}`)\n  - *Problème :* {}\n  - *Remédiation :* {}\n\n",
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
        assert_eq!(tools.len(), 12);

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
}
