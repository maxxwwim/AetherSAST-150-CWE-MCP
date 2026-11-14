---
id: ai-file-bridge
layer: action
max_lines_per_file: 2000
allowed_imports: ["core_graph::*", "ast_scanner::*", "security_linter::*", "notify::*", "serde::*", "serde_json::*", "chrono::*", "thiserror::*", "std::*"]
forbidden_imports: ["desktop_shell::*", "arch_templates::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: false
---
# 🤖 ai-file-bridge — Passerelle IA Zero-Shell & Gestionnaire de tâches (v2.4.0)

Synchronise l'état du graphe avec le dossier `.aether/` en moins de 50 ms (`LIVE_AUDIT.md`, `ACTIVE_TARGET.md`, `TASKS_SUMMARY.md`), vérifie les patchs IA (`PatchVerifier` avec prise en charge de `effective_max_lines`), sérialise les paquets `<aether_handshake version="2.0">` et gère la persistance des tâches dans `.aether/tasks/`.

## 📦 Contenu

| Fichier | Rôle |
| :--- | :--- |
| `src/watcher.rs` | `FileWatcherBridge` basé sur `notify` (détection temps réel des sauvegardes) |
| `src/audit_writer.rs` | Écriture de `.aether/LIVE_AUDIT.md`, `.aether/ACTIVE_TARGET.md` et génération de prompts système |
| `src/handshake.rs` | Sérialisation XML `<aether_handshake version="2.0">` (~300 tokens) et protocole `[AETHER_ACK]` |
| `src/patch_verifier.rs` | Pare-feu IA temps réel (`aetherscope_verify_patch`) : contrats EARS/BLAKE3, `effective_max_lines` et SAST incrémental |
| `src/tasks.rs` | `TaskManager` CRUD (`task.json`, mini-`README.md`, `TASKS_SUMMARY.md`) |

## 🛡️ Règles EARS

- WHEN a monitored source file changes on disk THE SYSTEM SHALL trigger an incremental rescan and refresh `.aether/LIVE_AUDIT.md` in less than 50 ms.
- WHEN a target symbol is selected THE SYSTEM SHALL write `.aether/ACTIVE_TARGET.md` and generate a compact `<aether_handshake version="2.0">` packet.
- WHEN a task is created or updated THE SYSTEM SHALL persist its `task.json` and `README.md` under `.aether/tasks/<task_id>/` and regenerate `.aether/TASKS_SUMMARY.md`.
