---
id: arch-templates
layer: utility
max_lines_per_file: 300
allowed_imports: ["core_graph::*", "serde::*", "serde_json::*", "toml::*", "blake3::*", "std::*"]
forbidden_imports: ["security_linter::*", "ast_scanner::*", "ai_file_bridge::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
---
# 🏗️ arch-templates — Multi-Stack Scaffolding & Architecture Topology Hub (v2.5.1)

Automated scaffolding engine for standardized 11-folder project structures. Generates pre-signed BLAKE3 EARS contract `README.md` files and `AETHER_AI_RULES.md` governance specifications for Pure Rust, Python (`uv`), Node/TypeScript (`pnpm`), and Hybrid Web3/MMO development stacks.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/templates.rs` | Scaffolding generators producing normalized directory trees for Pure Rust, Python (`uv`), Node/TS (`pnpm`), and Hybrid Web3/MMO stacks. |
| `src/lib.rs` | Public crate root exporting project initialization and contract signing functions. |

## 🛡️ EARS Architectural Requirements

- WHEN a project stack is selected THE SYSTEM SHALL generate the normalized 11-folder directory structure for that stack.
- WHEN a directory is scaffolded THE SYSTEM SHALL include its contract `README.md` pre-signed with a valid BLAKE3 hash.
- IF the target project directory already contains existing files THEN THE SYSTEM SHALL NOT overwrite them silently.
