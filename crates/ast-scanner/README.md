---
id: ast-scanner
layer: action
max_lines_per_file: 2500
allowed_imports: ["core_graph::*", "security_linter::*", "obsidian_vault::*", "walkdir::*", "rayon::*", "regex::*", "serde::*", "thiserror::*", "std::*"]
forbidden_imports: ["ai_file_bridge::*", "arch_templates::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
---
# 🔍 ast-scanner — Scanner AST polyglotte multithread & Empreintes BLAKE3 (v2.4.0)

Parcourt l'arborescence d'un projet en parallèle (`rayon`), extrait les symboles AST multi-langages (Rust, PHP, Zig, C#, Java, TypeScript/JS, Python, C/C++, Solidity/Move/Cairo, Markdown), calcule l'empreinte BLAKE3 de chaque fichier (`file_blake3_hash`), résout le contrat de dossier/fichier applicable et invoque `security-linter`.

## 📦 Contenu

| Fichier | Rôle |
| :--- | :--- |
| `src/scanner.rs` | `ProjectScanner`, regex compilées `OnceLock`, calcul BLAKE3 par fichier (`file_blake3_hash`), résolution des contrats (`find_contract_for_file`) et constructeurs d'arêtes d'affiliation |
| `src/lib.rs` | Point d'entrée public du crate |

## 🛡️ Règles EARS

- WHEN a project directory is scanned THE SYSTEM SHALL parse source files in parallel using `rayon` and skip excluded directories (`target`, `node_modules`, `.git`, `.aether`).
- WHEN a symbol is extracted THE SYSTEM SHALL attach its source file path, `file_blake3_hash`, `contract_folder`, `max_lines_limit`, `file_max_lines_override`, line number, complexity, and SAST anomalies.
- IF a file of this folder exceeds `max_lines_per_file` THEN THE SYSTEM SHALL report a `RULE_MAX_LINES` warning.
