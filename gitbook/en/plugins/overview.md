# Plugins Overview

AetherScope separates declarative security rules and WebGL 2 visual themes under `.aether/plugins/`, with live hot-reload, BLAKE3 cache invalidation, and strict path confinement.

## Dual Plugin Architecture

AetherScope runs two isolated plugin subsystems side by side inside `<project_root>/.aether/plugins/`:

- **SAST & Taint Plugins (`PluginManifest`)**: Declarative `.yaml`, `.yml`, or `.json` packs scanned recursively by `PluginEngine` (`crates/security-linter/src/plugin.rs`) to extend pattern-based CWE rules and inter-procedural SSA taint sources, sinks, and sanitizers.
- **WebGL 2 Visual Plugins (`VisualPluginManifest`)**: Theme packs stored under `.aether/plugins/visuals/<pack>/` (`visual-plugin.yaml`, `visual-plugin.yml`, or `visual-plugin.json`) with optional `backdrop.glsl` and `node_sdf.glsl` GLSL ES 3.00 hooks (`crates/desktop-shell/src/visual_plugin_routes.rs`).

To prevent cross-contamination, `PluginEngine::scan_and_load_dir` and `plugin_routes::collect_plugin_files` explicitly skip any directory named `visuals` (case-insensitive) and any file whose stem is `visual-plugin` (case-insensitive).

```text
.aether/plugins/
├── community/
│   └── plugin.yaml                    # Unpacked 24-rule OWASP/CWE CommunityBundle
├── imported/
│   └── <slug>/
│       └── plugin.yaml                # Semgrep YAML imports (CLI / REST / UI)
├── <custom-pack>/
│   └── plugin.yaml                    # Custom SAST & Taint DSL v2 manifest
└── visuals/
    └── <visual-slug>/
        ├── visual-plugin.yaml         # VisualPluginManifest (or .yml / .json)
        ├── backdrop.glsl              # Optional aetherBackdrop(...) GLSL hook
        └── node_sdf.glsl              # Optional aetherNodeSurface(...) GLSL hook
```

{% hint style="info" %}
AetherScope executes SAST plugins lock-free in parallel using `OnceLock<CompiledRuleMatchers>` per rule—regexes, path globs, and lowercased extensions are precompiled once at manifest load with zero runtime `Mutex` contention.
{% endhint %}

## Live Hot-Reload & BLAKE3 Cache Invalidation

You can edit plugin manifests or GLSL shaders on disk while the Cockpit is running. `FileWatcherBridge` (`crates/ai-file-bridge/src/watcher.rs`) and the `desktop-shell` background loop keep the UI and audit state synchronized without manual restarts.

### How `FileWatcherBridge` Filters `.aether/`

1. On startup and `switch_root()`, `FileWatcherBridge` creates `<project_root>/.aether/plugins` if missing and polls the filesystem via `notify::RecommendedWatcher` (`100 ms` poll interval).
2. `is_excluded_dir_name` ignores dot-directories (`.git`, `.vscode`, `.idea`), `WebView2`, and 30 build/dependency directories (`target`, `node_modules`, `dist`, `build`, etc.), while explicitly exempting `.aether`.
3. Inside `.aether` (depth 1), `watch_filtered_tree` skips every subdirectory **except** `plugins` (such as `.aether/cache` or `.aether/tasks`), then recursively watches `.aether/plugins` (`depth >= 2`).
4. `poll_changed_files()` listens for `Create`, `Modify`, and `Remove` events on 38 supported extensions (`rs, ts, tsx, js, jsx, mjs, cjs, py, md, mdx, svelte, vue, html, css, scss, cpp, hpp, cc, hh, cxx, hxx, c, h, inl, java, sol, yul, php, phtml, zig, cs, lua, luau, json, toml, yaml, yml, glsl`) while ignoring `.log`, `aetherscope_viewer.html`, and `AETHER_AI_RULES.md`.

### Debounce & Visual-Only Optimization

The `desktop-shell` watcher loop (`crates/desktop-shell/src/main.rs`) polls `FileWatcherBridge` every `30 ms` and waits for a `100 ms` quiet-window debounce (`debounce_delay`) or a `500 ms` maximum batch window (`max_batch_delay`) before dispatching work:

- **Visual-only changes**: If every modified path lives inside `.aether/plugins/visuals/` or has a `.glsl` extension, the server increments `visual_plugins_version` and **skips** the full AST/SAST rescan. The frontend polls `GET /api/graph/version` every `2 s` and hot-swaps the updated theme or shader.
- **SAST plugin or source changes**: When `.yaml`, `.yml`, or `.json` SAST manifests change, `ProjectScanner` reloads `.aether/plugins/`, clears `ui_graph_cache`, updates `LIVE_AUDIT.md`, and increments `graph_version`.

### BLAKE3 `config_digest()` Cache Key

`PluginEngine::config_digest()` computes a deterministic BLAKE3 hex digest across `"aether-plugin-engine-v2:"`, the canonical `--plugins` selection key, and every **enabled** plugin serialized via `serde_json::to_vec`. `ProjectScanner` embeds that digest into every `.aether/cache/ast/<entry_key>.json` key:

```text
entry_key = blake3("v1|{rel_path}|{file_hash}|{contract_sig}|{plugin_digest}")
```

Toggling `enabled`, editing a rule, or changing `--plugins` automatically invalidates stale AST/SAST cache entries on the next scan without deleting `.aether/cache/ast/`.

{% content-ref url="../core/blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](../core/blake3-governance.md)
{% endcontent-ref %}

## Security Confinement & Guardrails

Every plugin HTTP endpoint and file operation enforces four layered security boundaries:

| Guardrail | Scope | Enforcement Behavior |
|---|---|---|
| `LocalGuard` | All `/api/plugins/*` and `/api/visual_plugins/*` routes | Restricts `Host` and `Origin` to `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` and requires `Sec-Fetch-Site` (`same-origin` or `none`), blocking DNS rebinding and CSRF with `403 Forbidden`. |
| `sanitize_plugin_slug` | Pack folder names on upsert/import | Rejects empty strings, lengths `> 64`, `\0`, `/`, `\`, `..`, `:`, and `.`; lowercases ASCII `[a-z0-9_-]`, converts spaces to `-`, and trims leading/trailing `-`/`_`. |
| `resolve_confined_plugin_file` | `POST /api/plugins/toggle` and `delete` | Rejects non-normal path components, restricts extensions strictly to `.yaml`, `.yml`, `.json`, checks `SecretGuard::is_secret_path`, and verifies `fs::canonicalize(target).starts_with(canon_plugins)` (`403` on symlink escape). |
| `SecretGuard` | `.aether/plugins/` and `visuals/` paths | Blocks `.env*`, `.ssh`, `.git`, `.aws`, `credentials*`, `secrets*`, `*.pem`, `*.key`, and similar sensitive paths. |

{% hint style="warning" %}
**HTTP 422 Unit-Test Gate on Upsert**: `POST /api/plugins/upsert` runs every `test_cases` entry in memory via `PluginEngine::run_test_suite()` **before** writing anything to disk. If any test fails (`report.failed > 0`), the server returns `422 Unprocessable Entity` and leaves your `.aether/plugins/` directory untouched.
{% endhint %}

Note also how project settings interact with plugins after mutation: `apply_settings_filters_to_graph` preserves custom plugin findings even when `.aether/settings.json` restricts `active_cve_rules` to specific built-in rules, unless `active_cve_rules` is explicitly empty (`[]`) or the plugin rule/CWE is listed in `ignored_cwes`.

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}

## Management Interfaces & Workflows

You can inspect, test, author, and deploy plugins across four synchronized interfaces:

### 1. Cockpit `PluginsModal` (Shortcut `G`)

Press `G` anywhere in the Cockpit (outside text inputs) to open the 6-tab **Plugins & Security Studio**:

| Tab | Internal ID | Purpose |
|---|---|---|
| `Catalogue SAST` | `plugins` | View KPIs, deploy the 24-rule `CommunityBundle` (`Déployer (24)`), upload `.yaml`/`.yml`/`.json` packs (auto-routes Semgrep YAML), preview/download YAML, toggle `ON`/`OFF`, run `Test`, or delete packs. |
| `Règle DSL v2` | `create` | Author rules with 4 built-in presets (`Auth Guard CWE-287`, `POSIX Flag Smuggling CWE-88`, `SQLi Concat/Format CWE-89`, `Async Lock Guard CWE-667`), `ast_scope`, `not_preceded_within_lines`, path globs, and inline unit tests. |
| `Taint SSA` | `taint` | 3-column builder (`Sources`, `Sinks`, `Sanitizers`) covering all 9 `SourceKind`s + `Custom` (10 total) and all 8 `SinkKind`s + `Custom` (9 total). |
| `Bac à Sable` | `playground` | 5 preloaded multi-language samples with virtual `file_name` testing using instant client-side evaluation (`demoPlugins.ts`). |
| `Import Semgrep` | `semgrep` | Convert Semgrep YAML rules into `.aether/plugins/imported/<slug>/plugin.yaml` via `POST /api/plugins/import_semgrep`. |
| `Studio WebGL` | `visuals` | Switch among the 5 built-in visual packs, edit layer/severity palettes and uniforms, live-preview `backdrop.glsl` / `node_sdf.glsl`, and save packs to `.aether/plugins/visuals/`. |

In offline or standalone HTML demo mode (when `127.0.0.1:3030` is unavailable), `PluginsModal` transparently switches to the in-memory `demoPlugins.ts` evaluator with 3 preloaded sample packs.

### 2. CLI Binaries (`aether-engine` & `aether-plugin-tool`)

- `aether-engine --plugins <spec>` selects profiles or packs for headless/GUI scans, and `aether-engine --update-rules` unpacks the 24-rule `CommunityBundle` into `<path>/.aether/plugins/community/plugin.yaml`.
- `aether-plugin-tool` provides `init`, `list`, `test`, `scan`, `export`, `import-semgrep`, `download-semgrep-rules` / `update-rules`, and `init-bundle`.

### 3. Local REST API (`127.0.0.1:3030`)

The desktop backend exposes 7 SAST plugin endpoints (`/api/plugins`, `/api/plugins/toggle`, `/api/plugins/test`, `/api/plugins/init_bundle`, `/api/plugins/import_semgrep`, `/api/plugins/upsert`, `/api/plugins/delete`) and 4 visual plugin endpoints (`/api/visual_plugins`, `/api/visual_plugins/activate`, `/api/visual_plugins/upsert`, `/api/visual_plugins/delete`).

### 4. MCP Tool (`aetherscope_manage_plugins`)

AI agents connected over stdio JSON-RPC (`aetherscope-mcp`) can invoke `aetherscope_manage_plugins` with actions `list`, `test`, `scan`, `upsert`, `toggle`, and `init_bundle` (plugin deletion uses `POST /api/plugins/delete` or the Cockpit UI rather than MCP).

## Next Steps

{% content-ref url="sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="semgrep-and-community-bundle.md" %}
[Semgrep Importer & Community Bundle](semgrep-and-community-bundle.md)
{% endcontent-ref %}

{% content-ref url="webgl-visual-plugins.md" %}
[WebGL 2 Visual Plugins](webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-security-plugins.md" %}
[REST API: Settings, Bounty, Surface & Plugins](../api-mcp/rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[Plugin, MCP & Runner CLIs](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
