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
# 🔮 obsidian-vault — Parseur de Vault Obsidian & Générateur de Graphe

Analyse les coffres Obsidian (`.obsidian`, notes Markdown, YAML frontmatter, wikilinks `[[...]]`, transclusions `![[...]]`, tags `#tag`), garantit le confinement de sécurité anti-traversée de répertoire, et projette le graphe de connaissances dans `core-graph`.

## 📦 Contenu

| Fichier | Rôle |
| :--- | :--- |
| `src/confinement.rs` | Confinement de sécurité des chemins et protection contre Path Traversal / Symlink Escape |
| `src/detector.rs` | Détection et classification de projet (`CodeProject`, `ObsidianVault`, `HybridProject`) |
| `src/parser.rs` | Extraction zero-copy / regex des frontmatters YAML, wikilinks, alias, tags et en-têtes |
| `src/graph_builder.rs` | Construction de l'`AetherGraph` pour les notes, liens, pièces jointes et notes fantômes |
| `src/types.rs` | Structures de données du domaine Obsidian (`VaultDocument`, `WikiLink`, `VaultConfig`) |
| `src/lib.rs` | Point d'entrée public du crate |

## 🛡️ Règles EARS

- WHEN a vault path is resolved THE SYSTEM SHALL enforce strict canonical path confinement inside the vault root.
- WHEN a note is parsed THE SYSTEM SHALL extract frontmatter, wikilinks, embeds, and hierarchical tags deterministically.
- IF a crate from a higher layer (`desktop_shell`, `ai_file_bridge`) is imported THEN THE SYSTEM SHALL report a `RULE_FORBIDDEN_IMPORT` violation.
- WHEN a file of this folder exceeds `max_lines_per_file` THE SYSTEM SHALL report a `RULE_MAX_LINES` violation.
