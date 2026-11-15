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
# 🔍 ast-scanner — Parallel Polyglot AST Extractor & BLAKE3 Fingerprinting (v2.4.0)

High-speed Rayon-parallel polyglot AST extractor supporting 11 programming languages (Rust, PHP, Zig, C#, Java, TypeScript/JavaScript, Python, C/C++, Solidity/Move/Cairo, Luau, and Markdown). Extracts AST symbols, computes per-file cryptographic BLAKE3 hashes (`file_blake3_hash`), resolves hierarchical directory contracts, extracts inter-procedural taint flows, and projects affiliation edges into `core-graph`.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/scanner.rs` | `ProjectScanner`: parallel AST parsing via Rayon, compiled regex caching (`OnceLock`), file BLAKE3 digest calculation (`file_blake3_hash`), contract resolution (`find_contract_for_file`), and `AffiliationEdge` projection. |
| `src/taint_extractor.rs` | Inter-procedural taint extractor discovering untrusted sources, propagators, and dangerous sinks for SAST dataflow analysis. |
| `src/lib.rs` | Public crate root exposing AST scanning and contract resolution interfaces. |

## 🛡️ EARS Architectural Requirements

- WHEN a project directory is scanned THE SYSTEM SHALL parse source files in parallel using `rayon` and skip excluded directories (`target`, `node_modules`, `.git`, `.aether`).
- WHEN a symbol is extracted THE SYSTEM SHALL attach its source file path, `file_blake3_hash`, `contract_folder`, `max_lines_limit`, `file_max_lines_override`, line number, complexity, and SAST anomalies.
- WHEN an imported dependency violates contract boundaries THE SYSTEM SHALL create a red forbidden import edge in the graph.
- IF a file in this folder exceeds `max_lines_per_file` THEN THE SYSTEM SHALL report a `RULE_MAX_LINES` warning.
