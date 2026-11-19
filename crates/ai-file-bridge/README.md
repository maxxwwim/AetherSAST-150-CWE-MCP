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
# 🤖 ai-file-bridge — Zero-Shell AI Bridge, Real-Time Watcher & Patch Firewall (v2.5.1)

High-speed zero-shell filesystem bridge and real-time AI guardrail system. Synchronizes live project state with the `.aether/` runtime directory in under 50 ms (`LIVE_AUDIT.md`, `ACTIVE_TARGET.md`, `TASKS_SUMMARY.md`), verifies AI patches in <50ms (`PatchVerifier` with `SecretGuard` protection against `PROHIBITED_SECRET_FILE_MODIFICATION` / CWE-538), serializes `<aether_handshake version="2.0">` XML packets, and manages persistent task lifecycles in `.aether/tasks/`.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/watcher.rs` | `FileWatcherBridge`: low-latency disk monitoring built on `notify` with a 250ms debouncer, triggering incremental rescans within 50 ms. |
| `src/audit_writer.rs` | Live Markdown report writer producing `.aether/LIVE_AUDIT.md`, `.aether/ACTIVE_TARGET.md`, and `AETHER_AI_RULES.md` system prompts (including Section 6 secret isolation). |
| `src/handshake.rs` | Compact XML serializer for `<aether_handshake version="2.0">` packets (~300 tokens) and the `[AETHER_ACK]` protocol. |
| `src/patch_verifier.rs` | Real-time AI patch verification firewall (`aetherscope_verify_patch`): validates modified files against `SecretGuard` (CWE-538), EARS contracts, BLAKE3 locks, line limits (`effective_max_lines`), and incremental SAST rules. |
| `src/tasks.rs` | `TaskManager` CRUD lifecycle engine managing `task.json`, mini-`README.md` documents, and `.aether/TASKS_SUMMARY.md`. |
| `src/lib.rs` | Public crate root exporting file watcher and patch firewall interfaces. |

## 🛡️ EARS Architectural Requirements

- WHEN a monitored source file changes on disk THE SYSTEM SHALL trigger an incremental rescan and refresh `.aether/LIVE_AUDIT.md` in less than 50 ms.
- WHEN a target symbol is selected THE SYSTEM SHALL write `.aether/ACTIVE_TARGET.md` and generate a compact `<aether_handshake version="2.0">` packet.
- WHEN an AI patch is evaluated THE SYSTEM SHALL validate modified files against contract line limits, BLAKE3 seals, and SAST rules before approving the change.
- WHEN a task is created or updated THE SYSTEM SHALL persist its metadata under `.aether/tasks/<task_id>/` and regenerate `.aether/TASKS_SUMMARY.md`.
