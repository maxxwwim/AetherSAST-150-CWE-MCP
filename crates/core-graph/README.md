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
# 🪐 core-graph — Domain Graph Models, Spatial Layouts & SSA Dataflow (v2.5.1)

Pure invariant domain core of AetherScope V2. Defines core graph topologies (`AetherGraph`, `SymbolBubble`, `AffiliationEdge`, `CveAnomalyRecord`), per-file BLAKE3 contract metadata, 4 geometric spatial layout engines (Z-1 to Z-4), reverse BFS reachability analysis, and Static Single Assignment (SSA) dataflow taint modeling.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/bubble.rs` | Domain symbol primitives: `SymbolBubble`, `SymbolKind`, `SymbolMetadata` (`file_blake3_hash`, `contract_folder`, `max_lines_limit`, `file_max_lines_override`), `Point2D`, and `CveAnomalyRecord`. |
| `src/edge.rs` | Graph connections: `AffiliationEdge`, `CategorizedLiaisons` (6 categories), `AffiliationKind`, and bitflag-accelerated filters (`FilterAffiliation`). |
| `src/graph.rs` | `AetherGraph`: node/edge indexing, topological degree calculations, health metrics, and JSON serialization. |
| `src/layout.rs` | 4 spatial positioning algorithms: `Z-1` Fermat Spiral Galaxy, `Z-2` 7-Layer Structural Hierarchy, `Z-3` Directed Acyclic Graph (DAG), and `Z-4` UML Matrix Grid. |
| `src/manifest.rs` | Architectural manifest and cryptographic lockfile serialization (`aether.manifest.json` and `aether.lock.toml`). |
| `src/reachability.rs` | Reverse Breadth-First Search (BFS) reachability engine tracing call paths from entrypoints to vulnerable sinks. |
| `src/dataflow/mod.rs` | Root module for the inter-procedural SSA dataflow and taint tracking subsystem. |
| `src/dataflow/engine.rs` | SSA taint evaluation engine tracking taint propagation, sanitized variables, and reachability. |
| `src/dataflow/graph.rs` | `DataflowGraph`: SSA control-flow nodes, definition-use chains, and variable assignment tracking. |
| `src/dataflow/types.rs` | Core dataflow types: `SsaVar`, `SsaVersion`, `TaintState`, `TaintFlowTrace`, and `SanitizerCatalog`. |
| `src/lib.rs` | Public domain API re-exporting graph structures and spatial algorithms. |

## 🛡️ EARS Architectural Requirements

- WHEN a graph layout is computed THE SYSTEM SHALL execute deterministically without runtime I/O or network calls.
- WHEN a taint flow path is evaluated THE SYSTEM SHALL trace SSA variables from source to sink and check for neutralizing sanitizers.
- IF a crate from a higher architectural layer (`ast_scanner`, `security_linter`, `desktop_shell`) is imported THEN THE SYSTEM SHALL report a `RULE_FORBIDDEN_IMPORT` violation.
- WHEN a file in this folder exceeds `max_lines_per_file` THE SYSTEM SHALL report a `RULE_MAX_LINES` warning.
