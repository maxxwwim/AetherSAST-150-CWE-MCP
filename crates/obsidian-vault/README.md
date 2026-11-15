---
id: obsidian-vault
layer: application
max_lines_per_file: 700
allowed_imports: ["core_graph::*", "walkdir::*", "rayon::*", "regex::*", "serde::*", "serde_yaml::*", "serde_json::*", "bitflags::*", "chrono::*", "thiserror::*", "std::*"]
forbidden_imports: ["ai_file_bridge::*", "arch_templates::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
---
# 🔮 obsidian-vault — Obsidian Knowledge Graph Engine & PathGuard Confinement (v2.4.0)

Dedicated knowledge base parser and security confinement engine for Obsidian vaults (`.obsidian`, Markdown notes, YAML frontmatter, wikilinks `[[...]]`, transclusions `![[...]]`, and `#tags`). Enforces strict `PathGuard` confinement against CWE-22 path traversal, executes a 4-stage project classifier (`PureObsidianVault`, `PureCode`, `Mixed`), and projects notes into `core-graph` for Dual-Vision 3D cockpit visualization.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/confinement.rs` | `PathGuard` & `TargetJail` security confinement: rejects null bytes, parent references (`..`), UNC paths, symlink escapes, and enforces 10 MB file read limits (`DEFAULT_MAX_FILE_SIZE`). |
| `src/detector.rs` | 4-stage heuristic project classifier categorizing repositories into `PureObsidianVault`, `PureCode`, or `Mixed` based on `.obsidian/` detection, file ratios, and syntax density. |
| `src/parser.rs` | Markdown AST parser utilizing CommonMark comment and code-block masking to extract wikilinks (`[[note]]`), alias wikilinks (`[[note\|alias]]`), section anchors, block refs, transclusions (`![[attachment]]`), and hierarchical `#tags`. |
| `src/graph_builder.rs` | Knowledge graph builder projecting parsed notes into `AetherGraph` nodes (`«Note»`), ghost references (`«GhostNote»`), attachments (`«Attachment»`), and affiliation links. |
| `src/types.rs` | Domain data types: `VaultDocument`, `WikiLink`, `VaultConfig`, and `ParsedNote`. |
| `src/lib.rs` | Public crate root exporting the vault ingestion and graph generation interfaces. |

## 🛡️ EARS Architectural Requirements

- WHEN a vault path is resolved THE SYSTEM SHALL enforce strict canonical path confinement inside the vault root and reject path traversal attempts.
- WHEN a note is parsed THE SYSTEM SHALL extract frontmatter, wikilinks, embeds, and hierarchical tags deterministically.
- IF a crate from a higher architectural layer (`desktop_shell`, `ai_file_bridge`) is imported THEN THE SYSTEM SHALL report a `RULE_FORBIDDEN_IMPORT` violation.
- WHEN a file in this folder exceeds `max_lines_per_file` THE SYSTEM SHALL report a `RULE_MAX_LINES` violation.
