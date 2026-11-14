---
id: desktop-shell
layer: ui
max_lines_per_file: 5000
allowed_imports: ["core_graph::*", "ast_scanner::*", "security_linter::*", "ai_file_bridge::*", "arch_templates::*", "obsidian_vault::*", "axum::*", "tokio::*", "clap::*", "colored::*", "webbrowser::*", "walkdir::*", "toml::*", "wry::*", "tao::*", "rfd::*", "serde::*", "serde_json::*", "serde_yaml::*", "std::*"]
forbidden_imports: []
security_rules:
  no_raw_sql: true
  no_env_access: false
---
#  🖥️ desktop-shell — Cockpit Desktop WebGL 2, Serveur Axum & Serveur MCP (v2.4.0)

Exécutable principal d'AetherScope V2 (`aether-engine`) et serveur MCP dédié (`aetherscope-mcp`). Héberge la fenêtre native WebView2 (`tao`/`wry`), le serveur REST local (`Axum`), l'éditeur live de contrats BLAKE3 et le moteur graphique hybride Svelte 5 + WebGL 2.

## 📦 Contenu

| Fichier / Dossier | Rôle |
| :--- | :--- |
| `src/main.rs` | Entrée principale, CLI `clap`, serveur HTTP Axum (`127.0.0.1:3030`) et fenêtre native `tao`/`wry` |
| `src/api_routes.rs` | Routes REST (`/api/contracts/update`, `/api/contracts/sign`, `/api/git/status`, `/api/save_doc`, `/api/ai/*`, `/api/tasks/*`) |
| `src/mcp_main.rs` | Binaire dédié `aetherscope-mcp` pour la boucle JSON-RPC 2.0 sur `stdio` |
| `src/mcp.rs` | Implémentation des outils MCP (`aetherscope_*`) et synchronisation cockpit |
| `src/viewer.rs` | Chargement et assemblage du bundle single-file (`dist/index.html`) et export standalone |
| `ui/` | Cockpit Frontend Svelte 5 Runes + TypeScript + Vite 8 (`vite-plugin-singlefile`) |

## 🛡️ Règles EARS

- WHEN `aether-engine` starts THE SYSTEM SHALL bind the local REST API to `127.0.0.1` and initialize the FileWatcher.
- WHEN `aetherscope-mcp` receives a JSON-RPC 2.0 tool call THE SYSTEM SHALL return a structured MCP response and synchronize telemetry with the cockpit if active.
- WHEN a file of this folder exceeds `max_lines_per_file` (or its `file_max_lines` override) THE SYSTEM SHALL report a `RULE_MAX_LINES` warning in orange.
