# Spatial Graph Engine

The Spatial Graph Engine transforms polyglot source trees into an interactive `AetherGraph` with 4 mathematical layouts, reverse BFS reachability, and compact WebGL transport.

## Overview

When `aether-engine` analyzes a repository, `ast-scanner` (`ProjectScanner`) parses files in parallel with `rayon` and constructs a unified `AetherGraph` defined in `core-graph`. Every file, class, endpoint, contract, and function becomes a `SymbolBubble` node connected by bitflag-typed `AffiliationEdge` links.

Before serving the graph to the desktop cockpit or headless API clients, the engine runs four deterministic stages:

1. **Polyglot Extraction**: Scans 11 language/format analyzers (32 file extensions) while honoring `SecretGuard`, size caps, and project exclusions.
2. **Cross-File & Galaxy Linking**: Resolves imports, calls, `NetworkRPC` HTTP bridges, `RealtimeWS` sockets, and `[CROSS_GALAXY_VIOLATION]` edges.
3. **4-Layout Positioning**: Computes deterministic `Z-1` through `Z-4` coordinates inside `LayoutPositions` using `compute_all_layouts`.
4. **Reachability & Dead-Code Analysis**: Executes reverse BFS `compute_reachability` from SAST/CWE sinks back to entrypoints and flags unreachable non-UI/non-docs symbols.

{% hint style="info" %}
All core graph types live in `crates/core-graph/src/` (`graph.rs`, `bubble.rs`, `edge.rs`, `layout.rs`, `reachability.rs`), while scanning and edge resolution run in `crates/ast-scanner/src/scanner.rs`.
{% endhint %}

## Graph Data Model

### `AetherGraph` and `GraphStats`

`AetherGraph` is the root container returned by `ProjectScanner::scan_project` and serialized by `/api/graph` and `/api/export`.

| Struct | Key Fields | Purpose |
| :--- | :--- | :--- |
| `AetherGraph` | `project_name`, `project_path`, `generated_at`, `system_prompt`, `nodes`, `edges`, `stats`, `dataflow_graph` | Top-level graph payload; `system_prompt` loads from `AETHER_AI_RULES.md` and `dataflow_graph` holds optional SSA taint state. |
| `GraphStats` | `total_nodes`, `total_edges`, `files_scanned`, `rpc_count`, `realtime_count`, `violation_count`, `dead_code_count`, `elapsed_ms`, `layers`, `relations`, `sides` | Aggregated telemetry counters and distribution maps computed by `AetherGraph::compute_stats()`. |

### `SymbolKind`, `SymbolBubble`, and `SymbolMetadata`

Each node in `AetherGraph.nodes` is a `SymbolBubble` whose default color and radius are assigned directly from its `SymbolKind` variant (`crates/core-graph/src/bubble.rs`).

| `SymbolKind` Variant | Numeric ID | Stereotype | `symbol_type` | Default Color (RGBA) | Default Radius |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Function` | `0` | `«Function»` | `function` | `[0.22, 0.74, 0.97, 1.0]` | `5.0` |
| `File` | `1` | `«File»` | `file` | `[0.63, 0.52, 0.95, 1.0]` | `14.0` |
| `ClassOrStruct` | `2` | `«Class»` | `class` | `[0.13, 0.77, 0.36, 1.0]` | `10.0` |
| `FormOrEndpoint` | `3` | `«Endpoint»` | `endpoint` | `[0.96, 0.62, 0.13, 1.0]` | `9.0` |
| `Contract` | `4` | `«Contract»` | `contract` | `[0.94, 0.27, 0.27, 1.0]` | `12.0` |

Every `SymbolBubble` carries architectural classification (`galaxy`: `"contracts"`, `"client"`, `"server"`, `"data-nodes"`, or `"core"`; `layer`: `"ui"`, `"action"`, `"domain"`, `"database"`, `"utility"`, `"config"`, or `"docs"`), connectivity (`in_degree`, `out_degree`, `stage_idx`), metrics (`complexity`, `lines_count`, `is_dead_code`, `has_security_violation`), spatial state (`x`, `y`, `layouts`, `birth_time`), and `metadata: SymbolMetadata`.

`SymbolMetadata` stores AST and governance details for each symbol:

* **Source & Hashing**: `lines`, `file_type`, `raw_content`, `blake3_hash` (contract digest), `file_blake3_hash` (per-file source digest), `lock_verified`.
* **AST Structure**: `methods: Vec<AstMethod>` (`name`, `args`, `returns`, `is_async`, `calls`, `docstring`) and `attributes: Vec<AstAttribute>` (`name`, `type`).
* **Governance & Findings**: `ears_count`, `contract_folder`, `max_lines_limit`, `file_max_lines_override`, `violations`, and `cve_anomalies: Vec<CveAnomalyRecord>` (`rule_id`, `cve_id`, `severity`, `line_number`, `file_path`, `message`, `transmitted_data`, `transmitted_type`, `remediation`, `is_reachable`, `exploit_path`, `taint_trace`).

### `AffiliationEdge`, `EdgeType`, and `FilterAffiliation`

Edges use `FilterAffiliation` `u32` bitflags so the WebGL cockpit and reachability pass can filter relationships in O(1) bitmask checks.

| `FilterAffiliation` Flag | Bitmask | Value | Visual / Semantic Role |
| :--- | :--- | :--- | :--- |
| `PHYSICAL` | `1 << 0` | `1` | Topology and direct file imports |
| `NETWORK_RPC` | `1 << 1` | `2` | Form/Fetch call to server route (orange laser) |
| `REALTIME_WS` | `1 << 2` | `4` | WebSocket packet or Web3 on-chain call (cyan laser) |
| `SEMANTIC` | `1 << 3` | `8` | Role and stereotype conventions |
| `SECURITY_VIOLATES` | `1 << 4` | `16` | Contract, CVE, or cross-galaxy violation (red blinking) |
| `DATABASE_QUERY` | `1 << 5` | `32` | Database and SQL persistence (emerald laser) |

`EdgeType` maps each relationship to a canonical `relation` string and default `weight` (`1.0` standard, `1.5` warning, `2.0` `NetworkRPC`, `2.5` `RealtimeWS`, `3.0` CVE violation):

| `EdgeType` Variant | `relation` | Typical `FilterAffiliation` |
| :--- | :--- | :--- |
| `Contains` | `"contains"` | `PHYSICAL` |
| `Import` | `"imports"` | `PHYSICAL` |
| `Call` | `"calls"` | `SEMANTIC` |
| `Render` | `"renders"` | `PHYSICAL` / `SEMANTIC` |
| `Inherit` | `"inherits"` | `SEMANTIC` |
| `Network` | `"network"` | `NETWORK_RPC` |
| `NetworkRPC` | `"submits"` | `NETWORK_RPC \| PHYSICAL` |
| `RealtimeWS` | `"realtime"` | `REALTIME_WS \| PHYSICAL` |
| `ContractBinding` | `"binds"` | `SEMANTIC` |
| `IllegalCrossGalaxy` | `"violates"` (or `"warns"`) | `SECURITY_VIOLATES` |
| `Documents` | `"documents"` | `SEMANTIC` |
| `DatabaseQuery` | `"queries"` | `DATABASE_QUERY` |

### `CategorizedLiaisons`

To keep AI handshakes and inspector panels concise, `CategorizedLiaisons::from_edges` classifies incoming and outgoing `AffiliationEdge` items into 8 `LiaisonCategory` buckets and formats them via `to_compact_markdown(prefix, max_per_category)`:

| `LiaisonCategory` | Badge | `CategorizedLiaisons` Vector | Source Matching Logic |
| :--- | :--- | :--- | :--- |
| `FormSubmit` | `📝` | `form_submits` | `EdgeType::NetworkRPC` or `relation == "submits"` |
| `NetworkHttp` | `🌐` | `network_http` | `EdgeType::Network` or `NETWORK_RPC` filter |
| `RealtimeWs` | `⚡` | `realtime_ws` | `EdgeType::RealtimeWS` or `REALTIME_WS` filter |
| `DatabaseQuery` | `🗄️` | `database_queries` | `EdgeType::DatabaseQuery` or `DATABASE_QUERY` filter |
| `SecurityAlert` | `🚨` | `violations` | `EdgeType::IllegalCrossGalaxy` or `SECURITY_VIOLATES` filter |
| `InternalCall` | `📦` | `internal_calls` | Internal `Call` / `Import` / `Render` / `Inherit` / `Contains` |
| `ExternalDep` | `🏛️` | `external_deps` | `ContractBinding` or external `std::` / `api::` / `crate::` targets |
| `Documentation` | `📖` | `internal_calls` (rendered) | `EdgeType::Documents` |

## Polyglot `ProjectScanner` and Filtering Rules

`ProjectScanner::scan_project_with_exclusions` discovers candidate source files recursively and runs 11 language/format analyzers across 32 extensions in parallel.

| Analyzer | Supported Extensions | Key Extraction Behavior |
| :--- | :--- | :--- |
| Rust | `rs` | Strips inline `#[cfg(test)]` blocks before symbol/import extraction |
| TypeScript / JavaScript | `ts`, `tsx`, `js`, `jsx`, `mjs`, `cjs` | Extracts components, functions, imports, `fetch`/route calls, WebSocket events |
| Python | `py` | Extracts classes, functions, imports, Flask/FastAPI routes |
| C / C++ | `cpp`, `hpp`, `cc`, `hh`, `cxx`, `hxx`, `c`, `h`, `inl` | Extracts functions, structs/classes, includes |
| Solidity / Yul | `sol`, `yul` | Extracts contracts, functions, modifiers, state variables |
| Markdown (Contracts) | `md` (`README.md` only) | Parses YAML frontmatter and EARS rules; retains `raw_content` up to `32,768` bytes |
| PHP | `php`, `phtml`, `php3`, `php4`, `php5`, `php7`, `phps` | Extracts classes, functions, includes, HTTP superglobals |
| Java | `java` | Extracts classes, methods, imports, annotations |
| Lua / Luau | `lua`, `luau` | Extracts modules, functions, Roblox remote events |
| Zig | `zig` | Strips inline `test` blocks before symbol extraction |
| C# | `cs` | Extracts namespaces, classes, methods, attributes |

### Scanner Filtering & Exclusion Rules

Before parsing any file, `ProjectScanner` applies deterministic safety and noise filters (`crates/ast-scanner/src/scanner.rs`):

* **1.5 MB Size Cap**: Files with `meta.len() > 1_500_000` bytes are skipped to prevent memory spikes.
* **`SecretGuard` Path Block**: Any path matching `SecretGuard::is_secret_path` (`.env*`, `.git`, `.ssh`, `.pem`, `.key`, credentials) is skipped outright.
* **Non-README Markdown Skip**: All `.md` files except `readme.md` (case-insensitive) are skipped by `ast-scanner`.
* **Rust-Project `.c/.h/.cpp/.py` Skip**: When a workspace root contains `Cargo.toml`, `Cargo.lock`, `crates/`, or Tauri/workspace `Cargo.toml` manifests, `ast-scanner` skips `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx`, `.inl`, and `.py` files to avoid scanning vendored native bindings or helper scripts as primary code.
* **Generated & Test Filenames**: Skips `*.min.js`, `*.bundle.js`, `*.d.ts`, `build.rs`, `test.rs`, `tests.rs`, `temp_*`, `test_*`, `*_test.rs`, `*_tests.rs`, and `*_check.rs`.
* **Excluded Directories**: Ignores dot-directories (`.*`), `target`, `node_modules`, `dist`, `build`, `docs`, `doc`, `vendor`, `WebView2`, `*.tmp`, toolchain folders, and user-supplied `custom_exclusions`.

### Cross-File Linking & Project Type Detection

During `resolve_graph_edges`, `ProjectScanner` links symbol calls across files, materializes `api::<callee>` `FormOrEndpoint` nodes for unresolved network targets, connects `routes_called` to `routes_declared` (`NetworkRPC` via normalized lowercase substring match), connects `ws_emits` to `ws_handlers` (`RealtimeWS`), and emits `IllegalCrossGalaxy` (`[CROSS_GALAXY_VIOLATION]`) when `client` imports `server`/`data-nodes` or `contracts` imports `client`/`server`.

Alongside code scanning, `crates/obsidian-vault/src/detector.rs` runs `detect_project_type` (sampling up to `10` `.md` files at `65,536` bytes each and checking `.obsidian/` up to depth `2` plus 28 code extensions) to classify projects as `PureObsidianVault`, `PureCode`, or `Mixed`.

{% content-ref url="../cockpit-ide/obsidian-dual-vision.md" %}
[Obsidian Vault & Dual-Vision Mode](../cockpit-ide/obsidian-dual-vision.md)
{% endcontent-ref %}

## The 4 Mathematical Layouts (`Z-1` to `Z-4`)

`compute_all_layouts` (`crates/core-graph/src/layout.rs`) precomputes four coordinate spaces on every `SymbolBubble` so switching views in the cockpit is instantaneous.

| Layout | Field | Mathematical Model & Exact Constants | Best Use Case |
| :--- | :--- | :--- | :--- |
| **Z-1 Obsidian Galaxy** | `layouts.obsidian` | Hierarchical branch & folder clusters. Folder radius: `((n.sqrt() * 95.0) + 90.0).clamp(150.0, 950.0)`. Subfolders fan out (`sub_angle_spread = 0.68`). Inside each folder, nodes follow a Fermat spiral with `r0 = 48.0`, `GOLDEN_ANGLE = 2.399_963_229_728_653` rad (~`137.507764°`), and `dist = 48.0 + ((i + 0.6) / n).sqrt() * (radius - 48.0)`. | Default spatial exploration by directory topology |
| **Z-2 System Architecture** | `layouts.system` | 7 vertical layer X-columns: `docs` (`-1050.0`), `ui` (`-760.0`), `config` (`-530.0`), `action` (`-300.0`), `domain` (`260.0`), `utility` (`540.0`), `database` (`820.0`), fallback `0.0`. Sub-grid spacing: `95.0` (X) × `105.0` (Y). | Inspecting clean layered architecture boundaries |
| **Z-3 DAG Execution Flow** | `layouts.flow` | 4 horizontal `stage_idx` columns (`(stage_idx - 1.5) * 560.0`, placing stages at `-840.0`, `-280.0`, `280.0`, `840.0`). Sub-grid spacing: `90.0` (X) × `100.0` (Y). | Tracing request flow from entrypoints to persistence |
| **Z-4 UML Classes Grid** | `layouts.classes` | Centered matrix grid with `cols = ((total_nodes * 1.4).sqrt().ceil()).max(2)` and cell spacing `380.0` (X) × `210.0` (Y). | Browsing classes, structs, and contracts uniformly |

In **Z-3 DAG Execution Flow**, `ProjectScanner` assigns `stage_idx` (`0..3`) deterministically from node degrees and layers:
* `stage_idx = 0` (**Entrypoint**): `in_degree == 0 && out_degree > 0`
* `stage_idx = 1` (**Coordinator**): `out_degree > 0 && in_degree > 0`
* `stage_idx = 3` (**Persistence**): `layer == "database"` or `name` contains `"model"` (case-insensitive)
* `stage_idx = 2` (**Processing**): all remaining nodes

## Reverse BFS Reachability and Dead Code Detection

### Reverse BFS (`compute_reachability`)

`compute_reachability` (`crates/core-graph/src/reachability.rs`) determines whether SAST/CWE findings are reachable from an external entrypoint rather than isolated in internal helper code:

1. **Entrypoint Predicate (`is_source_node`)**: Matches nodes where `kind == SymbolKind::FormOrEndpoint`, `stereotype` contains `"Endpoint"` or `"Form"`, or `id.starts_with("api::")`.
2. **Allowed Edge Filter**: Builds a reverse adjacency list `incoming_adj` using only self-loop-free edges whose `filters` overlap `FilterAffiliation::NETWORK_RPC | FilterAffiliation::REALTIME_WS | FilterAffiliation::SEMANTIC`.
3. **Backward Traversal & Path Reconstruction**: Starting from every node with `cve_anomalies`, BFS walks backward along `incoming_adj` until it reaches the first `is_source_node`, reconstructing the forward `exploit_path` (`Endpoint -> ... -> Sink`) and setting `is_reachable = true`.
4. **SSA Taint Deferral**: If an anomaly carries `taint_trace: Some(trace)` from the SSA engine, `is_reachable` defers to `trace.is_vulnerable && !trace.is_sanitized` and `exploit_path` uses `trace.traversed_scoped_variables()`.

### Dead Code Heuristic

Inside `AetherGraph::compute_stats()` (`crates/core-graph/src/graph.rs`), any symbol satisfying `layer != "ui" && layer != "docs" && in_degree == 0` is flagged with `is_dead_code = true` and increments `stats.dead_code_count`.

## Compact UI Payload (`ui_payload` and `decodeCompactGraph`)

Large monorepos can generate hundreds of thousands of edge strings that bloat JSON serialization and WebView2 memory. `ui_payload::build_payload` (`crates/desktop-shell/src/api_routes.rs`) automatically compacts payloads whenever `nodes.len() > 3_000` (`COMPACT_NODE_THRESHOLD`) or `edges.len() > 20_000` (`COMPACT_EDGE_THRESHOLD`).

* **Always Applied**: Strips `metadata.raw_content`, clears `metadata.violations` when `cve_anomalies` is non-empty, and omits `system_prompt` and `dataflow_graph`.
* **When `compact == true`**: Truncates `node.docstring` to `240` chars, truncates `blake3_hash` and `file_blake3_hash` to `16` hex chars, caps `AstMethod.calls` to `8` entries (`docstring` to `160` chars), and replaces `edges` (`[]`) with `edges_compact: CompactEdges`.

{% code title="CompactEdges Wire Format & Client Decoding" overflow="wrap" %}
```json
{
  "nodes": [ { "id": "src/main.rs::main", "name": "main", "..." : "..." } ],
  "edges": [],
  "edges_compact": {
    "ids": ["api::/api/analyze"],
    "rels": ["submits", "calls"],
    "types": ["NetworkRPC", "Call"],
    "src": [0],
    "dst": [1],
    "rel": [0],
    "typ": [0],
    "extra": {
      "0": { "label": "/api/analyze", "weight": 2.0 }
    }
  }
}
```
{% endcode %}

On the TypeScript side (`crates/desktop-shell/ui/src/lib/graphCodec.ts`), `decodeCompactGraph(g)` resolves indices `< nodes.length` directly to existing `node.id` string references (and `>= nodes.length` to `edges_compact.ids`), merges sparse `extra[i]` fields via `Object.assign`, and deletes `edges_compact` before returning a standard `AetherGraph`.

### 🎮 Signature / Endpoint

```http
GET /api/graph
Host: 127.0.0.1:3030
```

### 📝 Arguments / Parameters

| Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Host` | `Header (string)` | Yes | Must match `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>` (`LocalGuard`). |

### 💎 Return Value / Response

| Status / Field | Type | Description |
| :--- | :--- | :--- |
| `200 OK` (`nodes`, `stats`) | `UiGraphPayload` | Complete or compacted `AetherGraph` JSON (`raw_content`, `system_prompt`, `dataflow_graph` stripped). |
| `edges_compact` | `CompactEdges \| null` | Present only when `nodes.len() > 3_000` or `edges.len() > 20_000`. |

### 💡 Example

```bash
curl -s http://127.0.0.1:3030/api/graph | jq '{nodes: (.nodes | length), compact: (.edges_compact != null), stats: .stats}'
```

{% content-ref url="./ssa-dataflow-taint.md" %}
[SSA Dataflow & Taint Engine](./ssa-dataflow-taint.md)
{% endcontent-ref %}

{% content-ref url="./blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](./blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-workspace-graph.md" %}
[REST API: Workspace, Filesystem & Graph](../api-mcp/rest-api-workspace-graph.md)
{% endcontent-ref %}
