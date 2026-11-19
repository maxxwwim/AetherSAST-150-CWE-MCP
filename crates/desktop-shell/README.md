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
# 🖥️ desktop-shell — Native Desktop Cockpit, Axum Backend & MCP Server (v2.5.1)

Top-level presentation and orchestrator crate. Builds two primary binaries: `aether-engine` (native Tao/Wry window + Axum REST server on port 3030) and `aetherscope-mcp` (stdio JSON-RPC 2.0 MCP server with 10 tools, 5 resources, 5 prompts). Enforces `LocalGuard` anti-DNS-rebinding/CSRF middleware, `PathGuard` confinement jail, and `SecretGuard`/`SecretMasker` secret isolation; hosts attack surface probers, `--plugins` selection, benchmark harness, and embeds the single-file Svelte 5 + WebGL 2 Cockpit & full-screen multi-tab IDE.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/main.rs` | Main CLI entrypoint (`clap`, including `--plugins`, `--audit-only`, `--sca`, `--benchmark`), Axum HTTP server on `127.0.0.1:3030` (51 routes), `PathGuard`/`SecretGuard` guards, and native Tao/Wry desktop window. |
| `src/plugin_routes.rs` | `PathGuard`-confined REST API for declarative YAML/JSON SAST & Taint plugins (`/api/plugins`, `/toggle`, `/test`, `/init_bundle`, `/import_semgrep`, `/upsert`, `/delete`) with live rescan & unit-test certification. |
| `src/visual_plugin_routes.rs` | `PathGuard`-confined REST API for WebGL 2 visual theme packs & GLSL ES 3.00 shader hooks (`/api/visual_plugins`, `/activate`, `/upsert`, `/delete`) with static anti-DoS GLSL validation and live `.glsl` hot-reload. |
| `src/mcp_main.rs` | Dedicated binary `aetherscope-mcp` executing the JSON-RPC 2.0 stdio server loop, auto-spawning Axum backend if offline. |
| `src/mcp.rs` | Model Context Protocol engine: multi-agent swarm telemetry, 12-color badge assignment, `SecretGuard`/`SecretMasker` redaction, and stdio JSON-RPC request handling. |
| `src/mcp_catalog.rs` | Catalog exposing 10 consolidated MCP tools, 5 resources (`aether://*`), and 5 engineering prompts. |
| `src/api_routes.rs` | REST DTOs and handlers for contracts (`/api/contracts/update`, `/api/contracts/sign`), Git status (`/api/git/status`), IDE file operations (`/api/files`, `/api/file_content`, `/api/save_file`, `/api/fs/list`), docs (`/api/save_doc`, `/api/raw_file`), bounty scope (`/api/bounty/scope`), AI telemetry/chat, and tasks. |
| `src/local_guard.rs` | `LocalGuard` security middleware protecting against DNS rebinding, CSRF, and untrusted cross-origin requests. |
| `src/viewer.rs` | Single-file bundle loader (`dist/index.html`) injecting dynamic initial dual-vision graph state into the webview and standalone exports. |
| `src/benchmark.rs` | Performance benchmark harness measuring lexing, AST parsing, and SAST throughput under the `--benchmark` flag. |
| `src/surface_probes.rs` | Network and TCP port probe engine auditing local and remote attack surfaces. |
| `src/surface_scanner.rs` | Surface vulnerability analyzer evaluating SSL/TLS posture, security headers, and open ports via `/api/surface_scan`. |
| `ui/` | Modern reactive frontend built with Svelte 5 Runes (`$state`), Tailwind CSS v4, and Vite 8 (`vite-plugin-singlefile`), including WebGL 2 Cockpit and full-screen IDE. |

## 🛡️ EARS Architectural Requirements

- WHEN `aether-engine` starts THE SYSTEM SHALL bind the local REST API to `127.0.0.1` on port 3030 and initialize the FileWatcher.
- WHEN `aetherscope-mcp` receives a JSON-RPC 2.0 tool call THE SYSTEM SHALL return a structured MCP response and synchronize telemetry with the cockpit.
- WHEN an HTTP request arrives with an untrusted `Host` or `Origin` header THE SYSTEM SHALL reject the request with HTTP 403 Forbidden.
- WHEN a file in this folder exceeds `max_lines_per_file` (or its `file_max_lines` override) THE SYSTEM SHALL report a `RULE_MAX_LINES` warning in orange.
