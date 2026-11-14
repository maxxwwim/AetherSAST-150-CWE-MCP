---
id: core-graph
layer: domain
max_lines_per_file: 800
allowed_imports: ["serde::*", "serde_json::*", "toml::*", "bitflags::*", "thiserror::*", "std::*"]
forbidden_imports: ["ast_scanner::*", "security_linter::*", "ai_file_bridge::*", "arch_templates::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
  deterministic_only: true
---
# 🪐 core-graph — Modèle de données & Algorithmes spatiaux (v2.4.0)

Socle domaine pur d'AetherScope V2. Définit les structures du graphe (`AetherGraph`, `SymbolBubble`, `AffiliationEdge`, `CveAnomalyRecord`), les métadonnées de contrat BLAKE3 par fichier et implémente les 4 algorithmes de positionnement géométrique.

## 📦 Contenu

| Fichier | Rôle |
| :--- | :--- |
| `src/bubble.rs` | `SymbolBubble`, `SymbolKind`, `SymbolMetadata` (`file_blake3_hash`, `contract_folder`, `max_lines_limit`, `file_max_lines_override`), `Point2D` et `CveAnomalyRecord` |
| `src/edge.rs` | `AffiliationEdge`, `CategorizedLiaisons` (6 catégories) et `FilterAffiliation` (`bitflags`) |
| `src/graph.rs` | `AetherGraph`, indexation des nœuds/arêtes, calculs de degrés et statistiques de santé |
| `src/layout.rs` | 4 algorithmes de layout (`Z-1` Galaxie, `Z-2` 7 couches, `Z-3` DAG, `Z-4` Matrice UML) |
| `src/manifest.rs` | Sérialisation de `aether.manifest.json` et `aether.lock.toml` (verrous BLAKE3) |

## 🛡️ Règles EARS

- WHEN a graph layout is computed THE SYSTEM SHALL execute deterministically without I/O or network calls.
- IF a crate from a higher layer (`ast_scanner`, `security_linter`, `desktop_shell`) is imported THEN THE SYSTEM SHALL report a `RULE_FORBIDDEN_IMPORT` violation.
- WHEN a file of this folder exceeds `max_lines_per_file` THE SYSTEM SHALL report a `RULE_MAX_LINES` warning.
