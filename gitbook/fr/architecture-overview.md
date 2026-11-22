# Vue d'ensemble de l'architecture

Comprenez le DAG des 7 crates du workspace Rust, le pipeline d'analyse de bout en bout, l'intégration Svelte 5 / WebGL 2 et l'extension externe AetherCraft.

## Graphe de dépendances du workspace

Le fichier `Cargo.toml` racine définit un workspace Rust 2021 (`resolver = "2"`, version `2.6.0`) regroupant **7 crates membres** sous `crates/` et **1 crate autonome explicitement exclu** (`apps/aethercraft/runner`).

```text
                       ┌──────────────────┐
                       │    core-graph    │  (0 dépendance interne, domaine pur)
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

| Crate | Dépendances internes | Types clés et responsabilités |
|---|---|---|
| `core-graph` | Aucune | `AetherGraph`, `SymbolBubble`, `AffiliationEdge`, `CategorizedLiaisons`, dispositions `Z-1`..`Z-4` (`compute_all_layouts`), BFS inverse `compute_reachability`, moteur de taint SSA `DataflowGraph`, `ProjectManifest`. Aucune I/O runtime. |
| `arch-templates` | `core-graph` | `ArchScaffolder::create_manifest` générant les galaxies `aether.lock.toml` pour 7 variantes `StackType` et 2 modes `TopologyMode`. |
| `security-linter` | `core-graph` | `SecurityLinter` (223 règles natives dans `linter.rs`, `rules.rs`, `deep_rules.rs`, `php_rules.rs`, `zig_rules.rs`, `csharp_rules.rs`, `epic_novel_rules.rs`), `CommunityBundle` (24 règles Semgrep), `PluginEngine`, lexer `AuditContext`, `ReadmeContract`, `ScaEngine`, `SarifReport`, `SecretGuard`, `SecretMasker`, et binaire `aether-plugin-tool`. |
| `obsidian-vault` | `core-graph` | Confinement `PathGuard`/`TargetJail` (CWE-22), `detect_project_type` (`PureCode` / `PureObsidianVault` / `Mixed`), `parse_markdown`, `scan_obsidian_vault` (`«Note»`, `«Attachment»`, `«GhostNote»`). |
| `ast-scanner` | `core-graph`, `security-linter` | `ProjectScanner` parallèle Rayon pour 11 langages, cache incrémental BLAKE3 dans `.aether/cache/ast/`, `TaintExtractor`, vérification BLAKE3 (`BLAKE3_TAMPERED`), règles de dossier et liaison RPC/WS inter-frontières. |
| `ai-file-bridge` | `core-graph`, `security-linter` | Pare-feu `PatchVerifier` (`<50ms`), `HandshakePacker` (`<aether_handshake version="2.1">`), `AuditWriter` (`LIVE_AUDIT.md`, `ACTIVE_TARGET.md`, `AETHER_AI_RULES.md`), `TaskManager` (`.aether/tasks/`) et `FileWatcherBridge` basé sur `notify`. |
| `desktop-shell` | Les 6 autres crates | Compile `aether-engine` et `aetherscope-mcp`. Embarque l'UI Svelte (`viewer.rs`), sert l'API Axum (`127.0.0.1:3030`) protégée par `LocalGuard`, pilote WebView2 (`tao`/`wry`), exécute les modes CLI/SARIF/SCA/benchmark, le Surface Scanner et le serveur MCP JSON-RPC 2.0. |

## Pipeline de bout en bout (Scan, Watcher et Transport)

1. **Classification** : `obsidian_vault::detect_project_type` classe le répertoire cible en `PureCode`, `PureObsidianVault` ou `Mixed`.
2. **Scan parallèle et linting** : `ProjectScanner` charge `aether.lock.toml`, analyse les contrats `README.md`, initialise `PluginEngine` depuis `.aether/plugins/` et calcule le hash BLAKE3 de chaque fichier. En cas de succès dans `.aether/cache/ast/<entry_key>.json` (clé BLAKE3 dérivée du chemin, du hash fichier, de la signature de contrat et de `plugin_digest`), l'analyse est réutilisée ; sinon, l'extraction AST, `SecurityLinter::audit_file_with_context` et les plugins s'exécutent en parallèle.
3. **Flux de données, verrous et disposition** : `TaintExtractor` et `compute_dataflow_taint` construisent les traces de taint SSA, les empreintes `aether.lock.toml` sont vérifiées (`BLAKE3_TAMPERED`), les règles de dossier (`RULE_FORBIDDEN_EXTENSION`, `RULE_MAX_FILES`) s'appliquent, les arêtes client-serveur RPC/WS sont reliées et `compute_all_layouts` calcule les coordonnées Z-1..Z-4.
4. **Surveillance temps réel et filtrage** : `desktop-shell` applique les filtres de `.aether/settings.json` (`exclusions`, `active_cve_rules`, `ignored_cwes`), génère `.aether/LIVE_AUDIT.md`, stocke le graphe dans `AppState` et lance `FileWatcherBridge` (scrutation 30 ms, debounce 100 ms calme / 500 ms rafale max). Chaque modification déclenche un re-scan incrémental ou un rechargement de plugin visuel et diffuse un événement `GraphWatchEvent` sur SSE (`/api/graph/events`).
5. **Compaction adaptative du transport** : `GET /api/graph` renvoie l'objet `AetherGraph` complet lorsque `?full=1` est spécifié (utilisé par MCP et les exports). Pour les grands graphes (**`nodes.len() > 3 000`** ou **`edges.len() > 20 000`**), `ui_payload` bascule automatiquement vers `edges_compact` (tableaux indexés), supprime `raw_content` et tronque les docstrings et empreintes.

## Intégration de l'interface Frontend (`Svelte 5 + Vite 8 + WebGL 2`)

L'interface du Cockpit située dans `crates/desktop-shell/ui/` repose sur **Svelte 5**, **Tailwind CSS v4**, **TypeScript** et **Vite 8** avec `vite-plugin-singlefile` :

* `npm run build` compile toute l'interface dans un unique fichier HTML autonome : `crates/desktop-shell/dist/index.html`.
* À la compilation Rust, `crates/desktop-shell/src/viewer.rs` embarque `../dist/index.html` (`DIST_INDEX_HTML`) ainsi que `../ui/src/engine/physics.worker.js` (`PHYSICS_WORKER_JS`) via `include_str!`.
* Au runtime, `get_dist_index_html()` vérifie d'abord la présence sur disque (`crates/desktop-shell/dist/index.html`, `dist/index.html`, `../dist/index.html`) avant de se replier sur la constante embarquée, ce qui accélère le développement frontend sans recompiler Rust.
* `generate_modern_standalone_html` injecte `window.__AETHERSCOPE_DUAL_GRAPH__`, `window.__PHYSICS_WORKER_CODE__`, `window.__AETHERSCOPE_DATA__` et les shims de bascule hors ligne pour `/`, `/legacy`, `/api/export` et `docs/index.html`.

## Extension exclue : `apps/aethercraft/`

`apps/aethercraft/` est volontairement exclu du workspace Cargo principal (`exclude = ["apps/aethercraft/runner"]` dans `Cargo.toml`) et comprend deux composants indépendants :

* **Control Plane (`apps/aethercraft/control-plane/`)** : Service web Python Flask (`app.py`, port `5000`) offrant boutique, marché, classements, cockpit admin, file de livraison RCON Minecraft (`services/rcon_service.py`) et générateur de manifestes JSON (`POST /api/v1/servers/generate`).
* **MC Runner (`apps/aethercraft/runner/`)** : CLI Rust Tokio autonome (`aether-mc-runner` v1.0.0) qui lit `.aether-manifest.json`, télécharge Paper/Purpur et les plugins, vérifie les sommes SHA-256 et lance Java 21 avec les drapeaux Aikar G1GC.

## Comparatif des modes d'exécution

| Mode | Déclencheur | Composants actifs | Sortie / Interface principale |
|---|---|---|---|
| **GUI Desktop** | `aether-engine` (par défaut) | Axum Tokio (`127.0.0.1:3030`) + `FileWatcherBridge` + `tao`/`wry` WebView2 | Fenêtre Cockpit native (`--max-old-space-size=4096` sous Windows) |
| **Serveur headless** | `aether-engine --no-gui` | Axum Tokio (`127.0.0.1:3030`) + `LocalGuard` + `FileWatcherBridge` | Interface web navigateur + API REST + SSE `/api/graph/events` |
| **CLI ponctuel** | `--audit-only`, `--format sarif`, `--sca`, `--sca-only`, `--benchmark`, `--update-rules` | Pipeline synchrone / Tokio ponctuel | `.aether/LIVE_AUDIT.md`, SARIF v2.1.0, `BENCHMARK.md`, codes de sortie (`--fail-on`) |
| **MCP Stdio** | `aether-engine --mcp` ou `aetherscope-mcp` | JSON-RPC 2.0 (`2024-11-05`) sur `stdin`/`stdout` (lance `--no-gui` si nécessaire) | 10 outils MCP, 5 ressources `aether://*`, 5 prompts |

## Étapes suivantes

{% content-ref url="core/graph-engine.md" %}
[Moteur de graphe spatial](core/graph-engine.md)
{% endcontent-ref %}

{% content-ref url="extensions-dev/aethercraft.md" %}
[Plateforme Minecraft AetherCraft](extensions-dev/aethercraft.md)
{% endcontent-ref %}
