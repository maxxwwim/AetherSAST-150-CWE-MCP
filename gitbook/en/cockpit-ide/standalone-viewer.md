# Standalone HTML Viewer & GitHub Pages

AetherScope packages its entire WebGL 2 cockpit, Dual-Vision graph payload, and off-thread physics worker into a single self-contained HTML file (`aetherscope_viewer.html` or `docs/index.html`) that runs directly from `file://` or GitHub Pages.

---

## Single-File Assembly (`viewer.rs`)

`crates/desktop-shell/src/viewer.rs` combines the Vite-bundled Svelte 5 frontend (`vite-plugin-singlefile` output in `crates/desktop-shell/dist/index.html`, embedded via `DIST_INDEX_HTML`) with `PHYSICS_WORKER_JS` (`include_str!("../ui/src/engine/physics.worker.js")`) and a serialized `DualGraphBundle`:

### 🎮 Core Generator & Data Contract

```rust
pub struct DualGraphBundle<'a> {
    pub project_type: &'a str,
    pub supported_views: Vec<&'static str>,
    pub active_view: &'a str,
    pub code: Option<&'a AetherGraph>,
    pub vault: Option<&'a AetherGraph>,
}
```

When `generate_modern_standalone_html(code_graph, vault_graph, project_type, active_view)` runs:

1. **System Prompt Hydration**: Calls `ensure_system_prompt` so every present graph includes an `AuditWriter::generate_optimized_system_prompt` payload.
2. **XSS / Script Breakout Escaping**: Escapes `</` → `<\/` and `<!--` → `<\!--` in both the worker string and serialized `DualGraphBundle` JSON before embedding inside `<script>`.
3. **Global Injection**: Injects five globals right before `<div id="app"></div>` (or `<body`):
   - `window.__AETHERSCOPE_DUAL_GRAPH__` (and alias `window.AETHER_DUAL_GRAPH`)
   - `window.__PHYSICS_WORKER_CODE__`
   - `window.__AETHERSCOPE_DATA__` (and alias `window.AETHER_GRAPH_DATA`)
   - Helper functions `switchProjectViewMode(mode)` and `fetchProjectStatus()` alongside a hidden `#view-mode-toggle` container.

### Inline Blob Web Worker (`physics.ts`)

Because browsers block loading external module workers from `file://` origins, `PhysicsController.initWorker()` (`crates/desktop-shell/ui/src/engine/physics.ts:34-40`) checks for `window.__PHYSICS_WORKER_CODE__` at boot:

- If present (both in live `GET /` responses and standalone HTML files), it creates an in-memory `Blob` (`type: 'application/javascript'`) and spawns `new Worker(URL.createObjectURL(blob))`.
- If absent (during pure `vite dev`), it falls back to `new Worker(new URL('./physics.worker.js', import.meta.url), { type: 'module' })`.

---

## Exporting Standalone HTML

You can export or serve the standalone bundle through three mechanisms:

{% tabs %}
{% tab title="Cockpit UI" %}
Open **Project Hub** (click the active project pill in `HeaderDeck.svelte`) and click **Exporter `aetherscope_viewer.html` Autonome**. This triggers `POST /api/export` and writes the bundle into your active workspace root.
{% endtab %}

{% tab title="REST API (POST /api/export)" %}
```bash
# Export aetherscope_viewer.html into a target directory (defaults to project_root)
curl -X POST http://127.0.0.1:3030/api/export \
  -H "Content-Type: application/json" \
  -d '{"path": "."}'
```

Returns `ExportResponse`:
```json
{
  "status": "ok",
  "viewer_path": "C:\\path\\to\\project\\aetherscope_viewer.html",
  "total_nodes": 128,
  "total_edges": 342
}
```
{% endtab %}

{% tab title="Live Server & Docs Snapshot" %}
- **Live HTTP routes**: `GET /` and `GET /legacy` dynamically stream `generate_modern_standalone_html(...)` with `Cache-Control: no-cache, no-store, must-revalidate`.
- **Repository Snapshot (`docs/index.html`)**: Running `cargo test -p desktop-shell --bin aether-engine viewer::tests::test_export_docs_index_html` scans the repository (both AST and Obsidian Vault if present) and writes `docs/index.html`.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
The CLI `--format` flag (`text`, `markdown`, `sarif`) controls `--audit-only` SAST output only. Use `POST /api/export`, the Cockpit **Project Hub**, or `test_export_docs_index_html` to produce standalone HTML bundles.
{% endhint %}

---

## GitHub Pages Deployment (`deploy-gh-pages.ps1` & CI)

AetherScope supports both zero-CI-minute local publishing and manual GitHub Actions deployment:

### Direct Local Script (`deploy-gh-pages.ps1`)

1. Builds the Vite single-file bundle inside `crates/desktop-shell/ui` (`npm run build`).
2. Runs `cargo test -p desktop-shell --bin aether-engine viewer::tests::test_export_docs_index_html` to regenerate `docs/index.html` with the live repository AST graph embedded.
3. Copies `crates/desktop-shell/dist/*` to a temporary directory, overwrites `index.html` with `docs/index.html`, adds an empty `.nojekyll` marker, and force-pushes a clean commit to the `gh-pages` branch.

### GitHub Actions Workflow (`.github/workflows/deploy-pages.yml`)

Configured as manual `workflow_dispatch` (automatic `push` triggers are intentionally commented out to conserve CI minutes):

- Checks out the repo on `ubuntu-latest` with Node `22`, runs `npm ci` and `npm run build` inside `crates/desktop-shell/ui`, creates `crates/desktop-shell/dist/.nojekyll`, and publishes via `actions/upload-pages-artifact@v3` + `actions/deploy-pages@v4`.

{% hint style="warning" %}
**Graph Embedding Difference**: `deploy-gh-pages.ps1` runs `test_export_docs_index_html` so the deployed site opens directly on the full `aether-engine` AST graph. By contrast, `.github/workflows/deploy-pages.yml` builds `crates/desktop-shell/dist` directly without running Cargo, so the resulting page boots into the 24-node interactive offline demo (`DEMO_AETHER_GRAPH`).
{% endhint %}

---

## Offline & GitHub Pages Demo Fallback

When the frontend boots in an environment with no injected `window.__AETHERSCOPE_DATA__` and no local backend on `127.0.0.1:3030` (such as a static `vite build` hosted on GitHub Pages):

1. **2-Second Boot Race (`App.svelte`)**: Races `api.getGraph()` against a `2000 ms` timeout.
2. **Demo Mode Activation**: On timeout or empty response, sets `cockpitState.isDemoMode = true` (showing the cyan `DÉMO LIVE` badge in `HeaderDeck.svelte`) and slows background `/api/graph/version` reconnect polling to every 10th tick (`20 s`).
3. **Interactive Demo Dataset (`crates/desktop-shell/ui/src/data/demoGraph.ts`)**:
   - `DEMO_AETHER_GRAPH`: `24` nodes across `5` clusters (`core_engine`, `security_sast`, `cockpit_ui`, `ai_swarm`, `api_network`) and `27` edges, featuring `CWE-89` (`HIGH`), `CWE-78` (`CRITICAL`), `CWE-79` (`MEDIUM`), and a `RULE_MAX_LINES` (`LOW`) budget warning.
   - `DEMO_TASKS` (`3` tasks), `DEMO_GIT_STATUS` (`3` modified/staged files on `main`), and `DEMO_ACTIVE_AGENTS` (`3` live agents: `Gemini Architect`, `Claude Security Auditor`, `Antigravity Sweeper`).
4. **Client-Side Plugin & Taint Playground (`crates/desktop-shell/ui/src/lib/demoPlugins.ts`)**: Preloads `DEMO_COMMUNITY_RULES` (`4` OWASP rules) and `INITIAL_DEMO_PLUGINS` (`3` packs: `majestic-injections`, `example-custom-auth`, `sample-semgrep`), running `evaluatePluginRulesInBrowser` locally so the DSL v2 and SSA taint playground remain interactive without a backend.

---

## Related Pages

{% content-ref url="./webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](./webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="./obsidian-dual-vision.md" %}
[Obsidian Vault & Dual-Vision Engine](./obsidian-dual-vision.md)
{% endcontent-ref %}

{% content-ref url="../console/launchers-and-scripts.md" %}
[Launchers, Installers & CI/CD Workflows](../console/launchers-and-scripts.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-workspace-graph.md" %}
[REST API: Workspace, Graph & Export](../api-mcp/rest-api-workspace-graph.md)
{% endcontent-ref %}
