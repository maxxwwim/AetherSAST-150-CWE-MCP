---
id: crates-workspace
layer: domain
max_lines_per_file: 4000
allowed_imports: ["core_graph::*", "ast_scanner::*", "security_linter::*", "ai_file_bridge::*", "arch_templates::*", "obsidian_vault::*", "desktop_shell::*", "std::*"]
forbidden_imports: []
security_rules:
  no_raw_sql: true
  no_env_access: false
---
# 📦 crates — Workspace des 7 Crates Rust d'AetherScope V2 (v2.4.0)

Ce dossier regroupe les 7 crates modulaires qui composent le moteur **AetherScope V2 (`aether-engine` v2.4.0)** selon une architecture hexagonale stricte :

| Crate | Couche | Responsabilité Principale |
| :--- | :--- | :--- |
| **`core-graph`** | `domain` | Modèle de données du graphe (`SymbolBubble`, `AffiliationEdge`), métadonnées BLAKE3 par fichier et 4 algorithmes de layout (`Z-1` à `Z-4`) |
| **`security-linter`** | `domain` | Moteur SAST temps réel (215 règles CWE & hors-CWE `AETHER-*`), lexer anti-faux-positifs et contrats EARS/BLAKE3 (`max_lines_per_file` & `file_max_lines`) |
| **`arch-templates`** | `utility` | Générateur de topologies multi-stacks (Rust, Python, Node/TS, Hybride Web3/MMO) |
| **`ast-scanner`** | `action` | Scanner AST polyglotte multithread (`rayon`), calcul `file_blake3_hash` et extraction des liaisons inter-symboles |
| **`obsidian-vault`** | `application` | Moteur de coffre Obsidian (`.obsidian`, wikilinks, transclusions, tags) et confinement `PathGuard` |
| **`ai-file-bridge`** | `action` | Passerelle IA Zero-Shell (`.aether/`), `FileWatcher`, `TaskManager`, `PatchVerifier` et paquets `<aether_handshake>` |
| **`desktop-shell`** | `ui` | Fenêtre native WebView2 GPU (`tao`/`wry`), serveur REST `Axum`, cockpit Svelte 5 (`ui/`) et serveur MCP (`aetherscope-mcp`) |

## 🛡️ Règles EARS

- WHEN a crate is compiled THE SYSTEM SHALL enforce its own `README.md` architectural contract.
- WHEN a file in any sub-crate is modified THE SYSTEM SHALL re-evaluate SAST rules and update `.aether/LIVE_AUDIT.md` in less than 50 ms.
