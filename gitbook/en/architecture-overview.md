# Architecture Overview

Understand the 7-crate Rust workspace DAG, end-to-end scan pipeline, Svelte 5 WebGL 2 embedding, and external AetherCraft extension.

## Workspace Dependency Graph

`Cargo.toml` defines a Rust 2021 workspace (`resolver = "2"`, version `2.6.0`) composed of **7 member crates** under `crates/` and **1 explicitly excluded** standalone crate (`apps/aethercraft/runner`).

```text
                       ┌──────────────────┐
                       │    core-graph    │  (0 internal deps, pure domain)
                       └────────┬─────────┘
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  arch-templates  │  │ security-linter  │  │  obsidian-vault  │
└──────────────────┘  └────────┬─────────┘  └────────┬─────────┘
          │                ┌───┴───────┐             │
          │                ▼           ▼             │
          │     ┌──────────────┐ ┌───────────────┐   │
          │     │ ast-scanner  │ │ai-file-bridge │   │
          │     └──────┬───────┘ └──────┬────────┘   │
          └────────────┼────────────────┼────────────┘
                       ▼                ▼
                ┌─────────────────────────────┐
                │        desktop-shell        │  (aether-engine, aetherscope-mcp)
                └─────────────────────────────┘
```

| Crate | Internal Dependencies | Key Types & Responsibilities |
|---|---|---|
| `core-graph` | None | `AetherGraph`, `SymbolBubble`, `AffiliationEdge`, `CategorizedLiaisons`, Z-1..Z-4 `compute_all_layouts`, reverse BFS `compute_reachability`, `DataflowGraph` SSA taint engine, `ProjectManifest`. Zero runtime I/O. |
| `arch-templates` | `core-graph` | `ArchScaffolder::create_manifest` generating `aether.lock.toml` galaxy layouts for 7 `StackType` stacks and 2 `TopologyMode` topologies. |
| `security-linter` | `core-graph` | `SecurityLinter` (223 native rules across `linter.rs`, `rules.rs`, `deep_rules.rs`, `php_rules.rs`, `zig_rules.rs`, `csharp_rules.rs`, `epic_novel_rules.rs`), `CommunityBundle` (24 Semgrep rules), `PluginEngine`, `AuditContext` lexer, `ReadmeContract`, `ScaEngine`, `SarifReport`, `SecretGuard`, `SecretMasker`, and binary `aether-plugin-tool`. |
| `obsidian-vault` | `core-graph` | `PathGuard`/`TargetJail` (CWE-22 confinement), `detect_project_type` (`PureCode` / `PureObsidianVault` / `Mixed`), `parse_markdown`, `scan_obsidian_vault` (`«Note»`, `«Attachment»`, `«GhostNote»`). |
| `ast-scanner` | `core-graph`, `security-linter` | Rayon parallel `ProjectScanner` for 11 languages, incremental BLAKE3 cache in `.aether/cache/ast/`, `TaintExtractor`, BLAKE3 contract verification (`BLAKE3_TAMPERED`), folder rule evaluation, cross-boundary RPC/WS linking. |
| `ai-file-bridge` | `core-graph`, `security-linter` | `<50ms` `PatchVerifier` firewall, `HandshakePacker` (`<aether_handshake version="2.1">`), `AuditWriter` (`LIVE_AUDIT.md`, `ACTIVE_TARGET.md`, `AETHER_AI_RULES.md`), `TaskManager` (`.aether/tasks/`), and `notify`-based `FileWatcherBridge`. |
| `desktop-shell` | All 6 library crates | Produces `aether-engine` and `aetherscope-mcp`. Embeds the Svelte UI (`viewer.rs`), runs Axum (`127.0.0.1:3030`) with `LocalGuard`, hosts `tao`/`wry` WebView2, serves CLI/SARIF/SCA/benchmark modes, Surface Scanner, and MCP JSON-RPC 2.0. |

## End-to-End Pipeline (Scan, Watch & Transport)

1. **Classification**: `obsidian_vault::detect_project_type` determines whether the target folder is `PureCode`, `PureObsidianVault`, or `Mixed`.
2. **Parallel Scan & Linting**: `ProjectScanner` loads `aether.lock.toml`, parses folder `README.md` contracts, initializes `PluginEngine` from `.aether/plugins/`, and hashes each file with BLAKE3. On a cache hit in `.aether/cache/ast/<entry_key>.json` (keyed by path, file hash, contract signature, and `plugin_digest`), parsing is skipped; on a miss, AST extraction, `SecurityLinter::audit_file_with_context`, and plugin rules execute in parallel.
3. **Dataflow, Locks & Layout**: `TaintExtractor` and `compute_dataflow_taint` build SSA taint traces, `aether.lock.toml` digests are verified (`BLAKE3_TAMPERED`), folder rules (`RULE_FORBIDDEN_EXTENSION`, `RULE_MAX_FILES`) run, client-server RPC/WS edges are linked, and `compute_all_layouts` calculates Z-1..Z-4 coordinates.
4. **Live Watcher & Filtering**: `desktop-shell` applies `.aether/settings.json` filters (`exclusions`, `active_cve_rules`, `ignored_cwes`), writes `.aether/LIVE_AUDIT.md`, stores the graph in `AppState`, and starts `FileWatcherBridge` (30 ms polling, 100 ms quiet / 500 ms max burst debounce). Changes trigger incremental re-scans or visual plugin reloads and push `GraphWatchEvent` frames over SSE (`/api/graph/events`).
5. **Adaptive Payload Compaction**: `GET /api/graph` returns the full `AetherGraph` when `?full=1` is passed (for MCP or exports). For large graphs (**`nodes.len() > 3,000`** or **`edges.len() > 20,000`**), `ui_payload` automatically switches to `edges_compact` indexed arrays, strips `raw_content`, and truncates docstrings/hashes.

## Frontend UI Embedding (`Svelte 5 + Vite 8 + WebGL 2`)

The cockpit frontend in `crates/desktop-shell/ui/` uses **Svelte 5**, **Tailwind CSS v4**, **TypeScript**, and **Vite 8** with `vite-plugin-singlefile`:

* `npm run build` compiles the entire UI into a single self-contained HTML bundle at `crates/desktop-shell/dist/index.html`.
* At compile time, `crates/desktop-shell/src/viewer.rs` embeds both `../dist/index.html` (`DIST_INDEX_HTML`) and `../ui/src/engine/physics.worker.js` (`PHYSICS_WORKER_JS`) via `include_str!`.
* At runtime, `get_dist_index_html()` checks disk paths (`crates/desktop-shell/dist/index.html`, `dist/index.html`, `../dist/index.html`) before falling back to the embedded constant, allowing fast frontend iteration without recompiling Rust.
* `generate_modern_standalone_html` injects `window.__AETHERSCOPE_DUAL_GRAPH__`, `window.__PHYSICS_WORKER_CODE__`, `window.__AETHERSCOPE_DATA__`, and offline view-switch shims for `/`, `/legacy`, `/api/export`, and `docs/index.html`.

## Excluded Extension: `apps/aethercraft/`

`apps/aethercraft/` sits outside the main Cargo workspace (`exclude = ["apps/aethercraft/runner"]` in `Cargo.toml`) and consists of two decoupled components:

* **Control Plane (`apps/aethercraft/control-plane/`)**: A Python Flask web service (`app.py`, port `5000`) providing a storefront, market, leaderboards, admin cockpit, Minecraft RCON delivery queue (`services/rcon_service.py`), and JSON manifest generator (`POST /api/v1/servers/generate`).
* **MC Runner (`apps/aethercraft/runner/`)**: A standalone Rust Tokio CLI (`aether-mc-runner` v1.0.0) that reads `.aether-manifest.json`, downloads Paper/Purpur and plugins, checks SHA-256 digests, and launches Java 21 with Aikar G1GC flags.

## Execution Modes Comparison

| Mode | Trigger | Runtime Components | Primary Output / Interface |
|---|---|---|---|
| **Desktop GUI** | `aether-engine` (default) | Tokio Axum (`127.0.0.1:3030`) + `FileWatcherBridge` + `tao`/`wry` WebView2 | Native cockpit window (`--max-old-space-size=4096` on Windows) |
| **Headless Server** | `aether-engine --no-gui` | Tokio Axum (`127.0.0.1:3030`) + `LocalGuard` + `FileWatcherBridge` | Web UI in browser + REST API + SSE `/api/graph/events` |
| **CLI Single-Shot** | `--audit-only`, `--format sarif`, `--sca`, `--sca-only`, `--benchmark`, `--update-rules` | Synchronous / single-shot Tokio pipeline | `.aether/LIVE_AUDIT.md`, SARIF v2.1.0, `BENCHMARK.md`, exit codes (`--fail-on`) |
| **MCP Stdio** | `aether-engine --mcp` or `aetherscope-mcp` | JSON-RPC 2.0 (`2024-11-05`) over `stdin`/`stdout` (auto-spawns `--no-gui` if needed) | 10 MCP tools, 5 `aether://*` resources, 5 prompts |

## Next Steps

{% content-ref url="core/graph-engine.md" %}
[Spatial Graph Engine](core/graph-engine.md)
{% endcontent-ref %}

{% content-ref url="extensions-dev/aethercraft.md" %}
[AetherCraft Minecraft Platform](extensions-dev/aethercraft.md)
{% endcontent-ref %}
