use crate::Args;
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

pub async fn run_mcp_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let port = args.port;
    let path = args.path.clone();

    // 1. Détection intelligente : Si le serveur WebGL n'est pas déjà actif sur le port,
    // on le démarre automatiquement en tâche de fond pour garantir la disponibilité de l'API !
    let is_server_listening = check_server_listening(port);

    if !is_server_listening {
        eprintln!("📡 [AetherScope MCP] Démarrage du serveur Axum & FileWatcher en arrière-plan sur http://127.0.0.1:{}...", port);
        let server_args = args.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::run_server_and_watcher(server_args).await {
                eprintln!("⚠️ [AetherScope MCP] Erreur serveur interne : {}", e);
            }
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(350)).await;
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
                        "name": "diagnostic_session_start",
                        "description": "Initialise la session IA en 1 seule commande MCP combinée : résumé du graphe 3D, audit des failles CWE actives et liste des tâches en cours.",
                        "arguments": [
                            {
                                "name": "path",
                                "description": "Chemin optionnel du projet à analyser (par défaut '.').",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "surgical_feature_workflow",
                        "description": "Workflow guidé d'implémentation ou de refactoring chirurgical utilisant les commandes MCP combinées (Cible+Caméra+Flux -> Tâche -> Code -> Pare-Feu Verify Patch).",
                        "arguments": [
                            {
                                "name": "symbol_id",
                                "description": "Symbole ou fichier cible principal (ex: 'BookingService', 'crates/core-graph/src/graph.rs').",
                                "required": true
                            },
                            {
                                "name": "objective",
                                "description": "Objectif technique à réaliser sur la cible.",
                                "required": true
                            }
                        ]
                    },
                    {
                        "name": "audit_security_cwe",
                        "description": "Génère un prompt d'audit, PoC ou remédiation ciblée pour une vulnérabilité SAST / violation CWE avec les commandes MCP combinées explicites.",
                        "arguments": [
                            {
                                "name": "symbol_name",
                                "description": "Nom du symbole (fonction, classe, struct) ou chemin du fichier à auditer.",
                                "required": true
                            },
                            {
                                "name": "cwe_id",
                                "description": "Identifiant CWE ou catégorie de la faille (ex: CWE-89, CWE-79, CVE-RUST-DESER-BOMB-OOM).",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "refactor_contract_violation",
                        "description": "Génère un prompt d'analyse et de correction lorsqu'une rupture de contrat EARS, de limite de lignes ou d'import interdit est détectée.",
                        "arguments": [
                            {
                                "name": "contract_name",
                                "description": "Nom du contrat, fichier ou module en violation.",
                                "required": true
                            },
                            {
                                "name": "violation_details",
                                "description": "Détails de l'incompatibilité ou de la violation de frontière.",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "scaffold_game_server",
                        "description": "Génère un prompt guidé pour l'implémentation d'une architecture serveur de jeu (Roblox Luau ou Minecraft Paper/Purpur) pilotée par les commandes MCP combinées.",
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
                "diagnostic_session_start" => {
                    let proj_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(".");
                    let prompt_text = format!(
                        "# 🪐 PROTOCOLE D'INITIALISATION MCP COMBINÉ — AETHERSCOPE V2\n\n\
                        Exécutez votre diagnostic initial en **un minimum d'appels MCP combinés** :\n\n\
                        1. **Diagnostic Global + Tâches + Violations (1 seul appel)** :\n\
                           Appelez `aetherscope_get_graph_summary` avec `{{\"path\": \"{}\", \"rescan\": false, \"include_tasks\": true}}`.\n\
                           *(Cette commande unique remplace `get_graph_summary` + `list_tasks` + `query_violations`).*\n\
                        2. **Recherche Ciblée Symboles & Failles CWE (si nécessaire)** :\n\
                           Appelez `aetherscope_search_symbols` avec `{{\"query\": \"...\", \"has_violation\": true, \"severity\": \"critical\"}}`.\n\
                        3. **Inspection Complète Cible + Caméra 3D + Flux Amont/Aval (1 seul appel)** :\n\
                           Dès qu'un symbole cible est identifié, appelez `aetherscope_get_active_target` avec :\n\
                           `{{\"symbol_id\": \"<symbole>\", \"action\": \"Inspection\", \"details\": \"Analyse du contrat EARS et des flux\", \"trace_direction\": \"both\"}}`.\n\
                           *(Cette commande unique téléporte automatiquement la caméra WebGL 3D, charge le contrat EARS et trace les dépendances amont/aval).*",
                        proj_path
                    );
                    Some(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id,
                        result: Some(json!({
                            "description": format!("Diagnostic initial MCP combiné pour {}", proj_path),
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
                    let objective = arguments.get("objective").and_then(|v| v.as_str()).unwrap_or("Implémentation chirurgicale");
                    let prompt_text = format!(
                        "# ⚡ WORKFLOW D'IMPLÉMENTATION CHIRURGICALE MCP — AETHERSCOPE V2\n\
                        - **Cible :** `{}`\n\
                        - **Objectif :** {}\n\n\
                        ## 🛠️ SÉQUENCE STRICTE DES COMMANDES MCP COMBINÉES\n\
                        1. **Inspection + Caméra 3D + Trace Flux (1 appel)** :\n\
                           `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Analyse\", \"details\": \"{}\", \"trace_direction\": \"both\"}})`\n\
                        2. **Création / Suivi de Tâche + Focus Caméra (1 appel)** :\n\
                           `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"{}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                        3. **Modification Chirurgicale du Code** :\n\
                           Éditez uniquement les fonctions ciblées dans le respect strict du `README.md` parent (invariants EARS, imports autorisés, budget de lignes).\n\
                        4. **Pare-Feu Temps Réel <50ms + Clôture Tâche + Debrief Chat (1 appel combiné)** :\n\
                           `aetherscope_verify_patch({{\"files_modified\": [\"<fichier_modifié>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"progress_note\": \"Patch validé par le pare-feu SAST/EARS\", \"chat_message\": \"Objectif terminé et certifié sans régression sur `{}`.\"}})`",
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
                        "# 🛡️ AUDIT & REMÉDIATION SAST/CWE MCP — AETHERSCOPE V2\n\
                        Vous êtes l'architecte de sécurité AetherScope. Auditez et corrigez la cible `{}` concernée par la vulnérabilité `{}`.\n\n\
                        ## 🛠️ COMMANDES MCP COMBINÉES À EXÉCUTER\n\
                        1. **Focus Caméra 3D + Contrat EARS + Trace d'Atteignabilité Source-to-Sink (1 appel)** :\n\
                           `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Correction CVE\", \"details\": \"Audit {} sur {}\", \"trace_direction\": \"both\"}})`\n\
                        2. **Filtrage Précis des Violations CWE (si besoin de contexte additionnel)** :\n\
                           `aetherscope_search_symbols({{\"query\": \"{}\", \"cwe_id\": \"{}\", \"has_violation\": true}})`\n\
                        3. **Déclaration de la Tâche de Sécurité (1 appel)** :\n\
                           `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Fix {} sur {}\", \"kind\": \"security_fix\", \"target_symbol\": \"{}\", \"priority\": \"critical\"}})`\n\
                        4. **Application du Patch Minimal & Certification Pare-Feu <50ms + Clôture (1 appel)** :\n\
                           Après avoir corrigé la faille sans casser les signatures publiques, appelez obligatoirement :\n\
                           `aetherscope_verify_patch({{\"files_modified\": [\"<fichier_corrigé>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Vulnérabilité {} corrigée et vérifiée sur `{}`.\"}})`",
                        symbol_name, cwe_id, symbol_name, cwe_id, symbol_name, symbol_name, cwe_id, cwe_id, symbol_name, symbol_name, cwe_id, symbol_name
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
                            "# 🎮 SCAFFOLDING SERVEUR ROBLOX LUAU MCP — `{}`\n\n\
                            Spécifications techniques :\n\
                            - Architecture contractuelle stricte : `contracts/` pour les paquets réseau RemoteEvent/RemoteFunction avec typage Luau strict (`--!strict`).\n\
                            - Séparation stricte : `server/` (logique d'autorité exclusive), `client/` (prédiction locale, zéro trust), `data-nodes/` (sauvegarde DataStore atomique).\n\n\
                            ## 🛠️ COMMANDES MCP COMBINÉES À EXÉCUTER\n\
                            1. `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Scaffolding module Roblox {}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                            2. `aetherscope_verify_patch({{\"files_modified\": [\"<fichiers_créés>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Module Roblox Luau `{}` généré et validé.\"}})`",
                            package_name, package_name, package_name, package_name
                        )
                    } else {
                        format!(
                            "# 🎮 SCAFFOLDING SERVEUR MINECRAFT PAPER/PURPUR MCP — `{}`\n\n\
                            Spécifications techniques :\n\
                            - Architecture découplée : API & Contrats d'événements séparés de l'implémentation Bukkit/Spigot.\n\
                            - Concurrency & Tick-safety : Aucun blocage sur le Main Thread tick de 50ms, utilisation d'AsyncScheduler et collections concurrentes.\n\n\
                            ## 🛠️ COMMANDES MCP COMBINÉES À EXÉCUTER\n\
                            1. `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Scaffolding plugin Paper {}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                            2. `aetherscope_verify_patch({{\"files_modified\": [\"<fichiers_créés>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Plugin Minecraft `{}` généré et validé.\"}})`",
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
                    let details = arguments.get("violation_details").and_then(|v| v.as_str()).unwrap_or("Non-respect des règles EARS ou fuite de dépendances.");
                    let prompt_text = format!(
                        "# 🏛️ RÉSOLUTION DE VIOLATION DE CONTRAT EARS MCP — `{}`\n\
                        Détails de l'infraction : `{}`\n\n\
                        ## 🛠️ COMMANDES MCP COMBINÉES À EXÉCUTER\n\
                        1. **Inspection Cible + Caméra 3D + Trace Flux Amont/Aval (1 appel)** :\n\
                           `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Refactoring\", \"details\": \"Résolution violation de contrat EARS\", \"trace_direction\": \"both\"}})`\n\
                        2. **Création de la Tâche de Refactoring (1 appel)** :\n\
                           `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Conformité contrat EARS {}\", \"kind\": \"arch_refactor\", \"target_symbol\": \"{}\", \"priority\": \"high\"}})`\n\
                        3. **Correction Chirurgicale** :\n\
                           Supprimez les imports interdits (`RULE_FORBIDDEN_IMPORT`), respectez le budget de lignes (`RULE_MAX_LINES`) et les invariants EARS du `README.md`.\n\
                        4. **Validation Pare-Feu <50ms + Clôture Tâche + Notification Chat (1 appel)** :\n\
                           `aetherscope_verify_patch({{\"files_modified\": [\"<fichier_modifié>\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Contrat EARS restauré et certifié pour `{}`.\"}})`",
                        contract_name, details, contract_name, contract_name, contract_name, contract_name
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
                        "name": "aetherscope_get_graph_summary",
                        "description": "[COMMANDE COMBINÉE 4-EN-1] Récupère en 1 seul appel l'architecture globale du projet (nœuds, arêtes, dossiers), les violations de sécurité SAST/CWE actives, la liste des tâches en cours (include_tasks=true) et peut forcer une réanalyse complète AST (rescan=true).",
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
                                    "description": "Si true, force une réanalyse complète de l'arbre AST et des règles SAST avant de renvoyer le résumé (remplace aetherscope_scan_project)"
                                },
                                "include_tasks": {
                                    "type": "boolean",
                                    "description": "Si true (défaut), inclut directement la liste des tâches actives du projet dans le résumé (remplace un appel séparé à list_tasks)"
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
                            "title": "Diagnostic Global Combiné (Graphe + Scan + Tâches + CWE)",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_get_active_target",
                        "description": "[COMMANDE COMBINÉE 3-EN-1] En 1 seul appel : (1) Téléporte la caméra 3D WebGL et met à jour le HUD de télémétrie, (2) Récupère le contrat EARS, les règles d'imports et le Handshake du symbole, et (3) Trace automatiquement le flux amont/aval (trace_direction='both').",
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
                                    "description": "Badge d'action affiché en direct sur le HUD 3D lors de la téléportation caméra (défaut: 'Inspection')",
                                    "examples": ["Inspection", "Analyse", "Refactoring", "Correction CVE", "Audit"]
                                },
                                "details": {
                                    "type": "string",
                                    "description": "Description technique courte affichée dans le journal de télémétrie 3D"
                                },
                                "trace_direction": {
                                    "type": "string",
                                    "description": "Direction du traçage de flux automatique inclus dans la réponse : 'both' (défaut), 'upstream', 'downstream', ou 'none'",
                                    "enum": ["both", "upstream", "downstream", "none"]
                                },
                                "max_depth": {
                                    "type": "integer",
                                    "description": "Profondeur maximale du traçage de flux (défaut: 2, max: 5)",
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
                            "title": "Inspection Cible Combinée (Contexte EARS + Caméra 3D + Trace Flux)",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_search_symbols",
                        "description": "[COMMANDE COMBINÉE 2-EN-1] Recherche multi-critères dans l'index AST (mot-clé, couche MVC, type, stéréotype) ET filtrage détaillé des violations SAST/CWE (cwe_id, severity, file_pattern) avec recommandations de remédiation.",
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Texte ou mot-clé à rechercher dans le nom du symbole, le fichier ou les méthodes",
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
                                    "description": "Stéréotype architectural (ex: '«Model»', '«Controller»', '«Component»', '«Service»')"
                                },
                                "has_violation": {
                                    "type": "boolean",
                                    "description": "Filtrer uniquement les symboles ayant des violations de sécurité ou CVE détectées"
                                },
                                "cwe_id": {
                                    "type": "string",
                                    "description": "Filtre direct sur un identifiant CWE ou règle SAST (ex: 'CWE-89', 'CWE-22', 'CVE-RUST-') : inclut le rapport détaillé de remédiation"
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
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Recherche AST & Audit Violations SAST/CWE Combinés",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_manage_tasks",
                        "description": "[COMMANDE COMBINÉE 3-EN-1] Gestion unifiée des tâches AetherScope (action = 'list' | 'create' | 'update') avec mini-README dans .aether/tasks/ et téléportation automatique de la caméra 3D lorsque target_symbol est renseigné.",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "Opération à effectuer : 'list' (lister les tâches), 'create' (créer une tâche), ou 'update' (mettre à jour statut/progrès/README)",
                                    "enum": ["list", "create", "update"],
                                    "examples": ["list", "create", "update"]
                                },
                                "task_id": {
                                    "type": "string",
                                    "description": "Identifiant de la tâche (requis pour action='update')"
                                },
                                "title": {
                                    "type": "string",
                                    "description": "Titre explicite de la tâche (requis pour action='create')"
                                },
                                "kind": {
                                    "type": "string",
                                    "description": "Type de tâche pour 'create' : 'function', 'research', 'security_fix', 'arch_refactor', 'documentation', 'test', 'other'",
                                    "enum": ["function", "research", "security_fix", "arch_refactor", "documentation", "test", "other"]
                                },
                                "target_symbol": {
                                    "type": "string",
                                    "description": "Symbole AST ciblé (aligne automatiquement la caméra 3D sur ce symbole)"
                                },
                                "target_file": {
                                    "type": "string",
                                    "description": "Chemin du fichier concerné"
                                },
                                "priority": {
                                    "type": "string",
                                    "description": "Priorité ('low', 'medium', 'high', 'critical')",
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
                                    "description": "Note d'avancement ajoutée au mini-README de la tâche"
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
                                    "description": "Filtre pour action='list' : 'active' (défaut), 'all', 'done'",
                                    "enum": ["active", "all", "done"]
                                }
                            },
                            "required": ["action"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Gestionnaire Unifié des Tâches (List / Create / Update)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_verify_patch",
                        "description": "[COMMANDE COMBINÉE 4-EN-1] Pare-Feu IA Temps Réel (< 50 ms) : (1) Analyse incrémentale SAST 150+ CWE + conformité contrat EARS/BLAKE3 sur files_modified, (2) Téléporte la caméra 3D, (3) Met à jour automatiquement la tâche associée (si task_id fourni et patch approuvé), et (4) Publie le compte-rendu dans le chat AetherScope (si chat_message fourni).",
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
                                    "description": "Chemins relatifs ou absolus des fichiers modifiés ou générés par l'IA"
                                },
                                "task_id": {
                                    "type": "string",
                                    "description": "Optionnel : ID de la tâche à mettre à jour automatiquement si le pare-feu approuve le patch"
                                },
                                "status": {
                                    "type": "string",
                                    "description": "Optionnel : Nouveau statut de la tâche (ex: 'done', 'in_progress') si task_id est fourni",
                                    "enum": ["pending", "in_progress", "blocked", "done", "cancelled"]
                                },
                                "progress": {
                                    "type": "integer",
                                    "description": "Optionnel : Pourcentage d'avancement (0-100) de la tâche si task_id est fourni",
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "progress_note": {
                                    "type": "string",
                                    "description": "Optionnel : Note de progrès à consigner dans la tâche si task_id est fourni"
                                },
                                "chat_message": {
                                    "type": "string",
                                    "description": "Optionnel : Compte-rendu final envoyé simultanément dans le Chat Copilot AetherScope"
                                }
                            },
                            "required": ["files_modified"],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Pare-Feu IA Temps Réel + Clôture Tâche & Chat Combinés",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_chat",
                        "description": "[COMMANDE COMBINÉE 2-EN-1] Envoie un message/debrief dans le chat intégré AetherScope (action='send', avec téléportation caméra optionnelle via target_symbol) OU récupère l'historique des échanges (action='history').",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "'send' (défaut si text est présent) pour envoyer un message, ou 'history' pour lire l'historique du chat",
                                    "enum": ["send", "history"]
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
                                }
                            },
                            "required": [],
                            "additionalProperties": false
                        },
                        "annotations": {
                            "title": "Chat Copilot AetherScope Combiné (Send & History)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": false,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_manage_plugins",
                        "description": "[COMMANDE COMBINÉE 4-EN-1] Gestion complète des plugins de sécurité YAML dans .aether/plugins : 'list' (inventaire), 'test' (exécution des tests unitaires des règles), 'scan' (audit d'un fichier/dossier), ou 'upsert' (création/mise à jour et certification d'une règle CWE).",
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": "Opération plugin : 'list', 'test', 'scan', ou 'upsert'",
                                    "enum": ["list", "test", "scan", "upsert"]
                                },
                                "target_path": {
                                    "type": "string",
                                    "description": "Fichier ou dossier à auditer (requis pour action='scan')"
                                },
                                "plugins_dir": {
                                    "type": "string",
                                    "description": "Chemin du dossier plugins (défaut: '.aether/plugins')"
                                },
                                "path": {
                                    "type": "string",
                                    "description": "Chemin racine optionnel du projet"
                                },
                                "plugin_name": { "type": "string", "description": "Nom du plugin (pour action='upsert')" },
                                "rule_id": { "type": "string", "description": "ID unique de la règle (pour action='upsert')" },
                                "cwe_id": { "type": "string", "description": "Identifiant CWE (pour action='upsert')" },
                                "name": { "type": "string", "description": "Nom court de la règle (pour action='upsert')" },
                                "severity": {
                                    "type": "string",
                                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW"],
                                    "description": "Sévérité (pour action='upsert')"
                                },
                                "description": { "type": "string", "description": "Description de la faille (pour action='upsert')" },
                                "remediation": { "type": "string", "description": "Remédiation certifiée (pour action='upsert')" },
                                "file_extensions": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Extensions ciblées ex: ['.rs', '.py', '.ts'] (pour action='upsert')"
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
                            "title": "Gestionnaire Unifié des Plugins CWE (List / Test / Scan / Upsert)",
                            "readOnlyHint": false,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    },
                    {
                        "name": "aetherscope_teleport_camera",
                        "description": "Oriente directement la caméra WebGL 3D d'AetherScope vers un symbole ou un fichier et met à jour le fil d'Ariane stellaire (utile pour un déplacement rapide sans recharger le contrat complet).",
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
                    }
                ]
            })),
            error: None,
        }),

        "tools/call" => {
            let params = req.params.unwrap_or(json!({}));
            let raw_tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            // Normalisation des commandes combinées (et alias rétrocompatibles)
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

                    let mut summary = match graph_val_res {
                        Ok(graph_val) => format_graph_summary(&graph_val),
                        Err(_) => {
                            let scanner = ast_scanner::ProjectScanner::default();
                            let g = scanner.scan_project(&p_buf);
                            format_ast_summary(&g, &p_buf)
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
                        summary.push_str(&format!("\n\n📋 **Tâches Actives ({} en cours) :**\n", active_tasks.len()));
                        if active_tasks.is_empty() {
                            summary.push_str("  - Aucune tâche active. Utilisez `aetherscope_manage_tasks({\"action\": \"create\", ...})` pour structurer votre mission.\n");
                        } else {
                            for t in active_tasks.iter().take(10) {
                                summary.push_str(&format!(
                                    "  - `{}` [{:?}] **{}** ({:?}, {}%) — Cible: `{}`\n",
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

                "aetherscope_send_chat_message" => {
                    let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let thought = arguments.get("thought").and_then(|v| v.as_str()).unwrap_or("");
                    let target = arguments.get("target_symbol").and_then(|v| v.as_str()).map(|s| s.to_string());

                    if text.trim().is_empty() {
                        (json!([{ "type": "text", "text": "⚠️ Erreur: Le paramètre 'text' ne peut pas être vide." }]), true)
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
                    let action = arguments.get("action").and_then(|v| v.as_str()).unwrap_or("Inspection");
                    let details = arguments.get("details").and_then(|v| v.as_str()).unwrap_or("Inspection combinée Cible + Contrat EARS + Flux");
                    let trace_direction = arguments.get("trace_direction").and_then(|v| v.as_str()).unwrap_or("both");
                    let max_depth = arguments.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(2) as usize;

                    if symbol_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "⚠️ Erreur: Le paramètre 'symbol_id' est requis." }]), true)
                    } else {
                        // 1. Téléportation automatique de la caméra 3D + télémétrie HUD
                        let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                            "target": symbol_id,
                            "action": action,
                            "details": details
                        }))).await;

                        // 2. Récupération du contexte cible + contrat EARS + Handshake
                        let res = send_http_request(server_port, "POST", "/api/ai/target", Some(&json!({
                            "symbol_id": symbol_id
                        }))).await;

                        let (mut text, is_err) = match res {
                            Ok(val) => {
                                let t = format_active_target_response(&val);
                                let err = val.get("status").and_then(|v| v.as_str()) != Some("ok");
                                (t, err)
                            }
                            Err(_) => {
                                let t = offline_active_target_fallback(target_path, &symbol_id);
                                let err = t.starts_with("⚠️");
                                (t, err)
                            }
                        };

                        // 3. Traçage automatique des flux amont/aval combiné dans la même réponse
                        if !is_err && trace_direction != "none" {
                            let p_buf = resolve_project_root(target_path);
                            let scanner = ast_scanner::ProjectScanner::default();
                            let g = scanner.scan_project(&p_buf);
                            let flow_text = format_trace_flow_response(&g, &symbol_id, trace_direction, max_depth);
                            if !flow_text.starts_with("⚠️") {
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

                    if let Some(ref sym) = target_symbol {
                        if !sym.trim().is_empty() {
                            let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                                "target": sym,
                                "action": "Création Tâche",
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
                    let target_symbol = arguments.get("target_symbol").and_then(|v| v.as_str()).map(|s| s.to_string());

                    if task_id.trim().is_empty() {
                        (json!([{ "type": "text", "text": "⚠️ Erreur: 'task_id' requis pour la mise à jour." }]), true)
                    } else {
                        if let Some(ref sym) = target_symbol {
                            if !sym.trim().is_empty() {
                                let _ = send_http_request(server_port, "POST", "/api/ai/telemetry", Some(&json!({
                                    "target": sym,
                                    "action": "Mise à jour Tâche",
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
                    let cwe_id = arguments.get("cwe_id").and_then(|v| v.as_str());
                    let severity = arguments.get("severity").and_then(|v| v.as_str());
                    let file_pattern = arguments.get("file_pattern").and_then(|v| v.as_str());
                    let limit = arguments.get("limit").and_then(|v| v.as_u64()).unwrap_or(15) as usize;
                    let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);

                    let p_buf = resolve_project_root(req_path);
                    let scanner = ast_scanner::ProjectScanner::default();
                    let g = scanner.scan_project(&p_buf);

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
                        (json!([{ "type": "text", "text": "Paramètre 'target_path' manquant pour le scan par plugins." }]), true)
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
                        (json!([{ "type": "text", "text": "Paramètres obligatoires manquants: plugin_name, rule_id, cwe_id, file_extensions" }]), true)
                    } else {
                        let req_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(default_path);
                        let plugins_sub = arguments.get("plugins_dir").and_then(|v| v.as_str()).unwrap_or(".aether/plugins");
                        let p_buf = resolve_project_root(req_path);
                        let plugin_dir = p_buf.join(plugins_sub).join(plugin_name);
                        let yaml_path = plugin_dir.join("plugin.yaml");

                        if let Err(e) = std::fs::create_dir_all(&plugin_dir) {
                            (json!([{ "type": "text", "text": format!("Impossible de créer le dossier {} : {}", plugin_dir.display(), e) }]), true)
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
                                    "text": format!("Validation échouée : {} test(s) unitaire(s) ont échoué pour la règle {}. Fichier non modifié.\nErreurs : {:?}", report.failed, rule_id, report.failures)
                                }]), true)
                            } else {
                                match serde_yaml::to_string(&manifest) {
                                    Ok(yaml_str) => {
                                        if let Err(e) = std::fs::write(&yaml_path, yaml_str) {
                                            (json!([{ "type": "text", "text": format!("Échec d'écriture {}: {}", yaml_path.display(), e) }]), true)
                                        } else {
                                            let text = serde_json::to_string_pretty(&json!({
                                                "status": "ok",
                                                "plugin": plugin_name,
                                                "rule_id": rule_id,
                                                "file": yaml_path.to_string_lossy(),
                                                "tests_passed": report.passed,
                                                "total_rules": manifest.rules.len(),
                                                "message": format!("Règle {} sauvegardée et certifiée avec succès !", rule_id)
                                            })).unwrap_or_default();
                                            (json!([{ "type": "text", "text": text }]), false)
                                        }
                                    }
                                    Err(e) => (json!([{ "type": "text", "text": format!("Erreur de sérialisation YAML : {}", e) }]), true),
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
                                "text": "⚠️ Erreur: Le paramètre 'files_modified' ne peut pas être une liste vide."
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

                        // Actions combinées automatiques si le patch est approuvé
                        if !is_rejected {
                            if let Some(tid) = arguments.get("task_id").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                                let status_str = arguments.get("status").and_then(|v| v.as_str()).unwrap_or("done");
                                let progress = arguments.get("progress").and_then(|v| v.as_u64()).map(|p| p as u8).or(Some(100));
                                let note = arguments.get("progress_note").and_then(|v| v.as_str()).unwrap_or("Patch validé par aetherscope_verify_patch");
                                let status = Some(ai_file_bridge::TaskStatus::from_str_loose(status_str));
                                let _ = ai_file_bridge::TaskManager::update_task(root, tid, status, progress, Some(note), None);
                                let _ = send_http_request(server_port, "POST", "/api/tasks/update", Some(&json!({
                                    "task_id": tid,
                                    "status": status_str,
                                    "progress": progress,
                                    "progress_note": note
                                }))).await;
                                out_text.push_str(&format!("\n⚡ **Tâche `{}` mise à jour automatiquement** (`{}` • `{}%`).", tid, status_str, progress.unwrap_or(100)));
                            }

                            if let Some(chat_msg) = arguments.get("chat_message").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                                let _ = send_http_request(server_port, "POST", "/api/ai/chat", Some(&json!({
                                    "text": chat_msg,
                                    "sender": "ai",
                                    "target_symbol": files.first()
                                }))).await;
                                out_text.push_str("\n💬 **Compte-rendu publié dans le Chat Copilot AetherScope.**");
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
        assert_eq!(tools.len(), 8);

        let expected_tools = [
            ("aetherscope_get_graph_summary", true, false, true, false),
            ("aetherscope_get_active_target", true, false, true, false),
            ("aetherscope_search_symbols", true, false, true, false),
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
}
