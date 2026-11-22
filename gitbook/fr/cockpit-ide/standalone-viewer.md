# Visionneuse HTML autonome et GitHub Pages

AetherScope empaquette l'intégralité de son cockpit WebGL 2, son graphe Dual-Vision et son worker physique dans un unique fichier HTML autonome (`aetherscope_viewer.html` ou `docs/index.html`) exécutable directement depuis `file://` ou GitHub Pages.

---

## Assemblage mono-fichier (`viewer.rs`)

`crates/desktop-shell/src/viewer.rs` fusionne l'interface Svelte 5 compilée par Vite (`vite-plugin-singlefile` dans `crates/desktop-shell/dist/index.html`, embarquée via `DIST_INDEX_HTML`) avec `PHYSICS_WORKER_JS` (`include_str!("../ui/src/engine/physics.worker.js")`) et un conteneur sérialisé `DualGraphBundle` :

### 🎮 Générateur principal et contrat de données

```rust
pub struct DualGraphBundle<'a> {
    pub project_type: &'a str,
    pub supported_views: Vec<&'static str>,
    pub active_view: &'a str,
    pub code: Option<&'a AetherGraph>,
    pub vault: Option<&'a AetherGraph>,
}
```

Lors de l'appel à `generate_modern_standalone_html(code_graph, vault_graph, project_type, active_view)` :

1. **Hydratation du prompt système** : Appelle `ensure_system_prompt` afin que chaque graphe présent embarque un `system_prompt` généré par `AuditWriter::generate_optimized_system_prompt`.
2. **Échappement anti-XSS / sortie de `<script>`** : Remplace `</` → `<\/` et `<!--` → `<\!--` dans la chaîne du worker et dans le JSON `DualGraphBundle` avant l'injection HTML.
3. **Injection globale** : Insère cinq variables globales juste avant `<div id="app"></div>` (ou `<body`) :
   - `window.__AETHERSCOPE_DUAL_GRAPH__` (et l'alias `window.AETHER_DUAL_GRAPH`)
   - `window.__PHYSICS_WORKER_CODE__`
   - `window.__AETHERSCOPE_DATA__` (et l'alias `window.AETHER_GRAPH_DATA`)
   - Les fonctions utilitaires `switchProjectViewMode(mode)` et `fetchProjectStatus()` ainsi qu'un conteneur caché `#view-mode-toggle`.

### Web Worker `Blob` intégré (`physics.ts`)

Comme les navigateurs bloquent le chargement de workers externes depuis l'origine `file://`, `PhysicsController.initWorker()` (`crates/desktop-shell/ui/src/engine/physics.ts:34-40`) détecte `window.__PHYSICS_WORKER_CODE__` au démarrage :

- Si la variable est présente (autant sur `GET /` en direct que dans les exports HTML autonomes), il crée un `Blob` en mémoire (`type: 'application/javascript'`) et lance `new Worker(URL.createObjectURL(blob))`.
- Sinon (pendant `vite dev`), il utilise `new Worker(new URL('./physics.worker.js', import.meta.url), { type: 'module' })`.

---

## Exporter la visionneuse HTML autonome

Vous pouvez générer ou servir l'export autonome via trois mécanismes :

{% tabs %}
{% tab title="Interface Cockpit" %}
Ouvrez le **Hub Multi-Architectures** (cliquez sur la pilule du projet actif dans `HeaderDeck.svelte`) puis cliquez sur **Exporter `aetherscope_viewer.html` Autonome**. L'action appelle `POST /api/export` et écrit le fichier à la racine du projet.
{% endtab %}

{% tab title="API REST (POST /api/export)" %}
```bash
# Exporte aetherscope_viewer.html dans un dossier cible (project_root par défaut)
curl -X POST http://127.0.0.1:3030/api/export \
  -H "Content-Type: application/json" \
  -d '{"path": "."}'
```

Retourne `ExportResponse` :
```json
{
  "status": "ok",
  "viewer_path": "C:\\path\\to\\project\\aetherscope_viewer.html",
  "total_nodes": 128,
  "total_edges": 342
}
```
{% endtab %}

{% tab title="Serveur direct et snapshot docs" %}
- **Routes HTTP en direct** : `GET /` et `GET /legacy` servent dynamiquement `generate_modern_standalone_html(...)` avec `Cache-Control: no-cache, no-store, must-revalidate`.
- **Snapshot du dépôt (`docs/index.html`)** : Exécuter `cargo test -p desktop-shell --bin aether-engine viewer::tests::test_export_docs_index_html` analyse le dépôt (AST et coffre Obsidian s'il existe) et écrit `docs/index.html`.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
L'option CLI `--format` (`text`, `markdown`, `sarif`) concerne uniquement les rapports SAST `--audit-only`. Utilisez `POST /api/export`, le **Project Hub** du cockpit ou `test_export_docs_index_html` pour produire un export HTML autonome.
{% endhint %}

---

## Déploiement GitHub Pages (`deploy-gh-pages.ps1` et CI)

AetherScope propose un déploiement local sans consommer de minutes CI ainsi qu'un workflow GitHub Actions manuel :

### Script local direct (`deploy-gh-pages.ps1`)

1. Compile le bundle mono-fichier Vite dans `crates/desktop-shell/ui` (`npm run build`).
2. Exécute `cargo test -p desktop-shell --bin aether-engine viewer::tests::test_export_docs_index_html` pour régénérer `docs/index.html` avec le graphe AST du dépôt embarqué.
3. Copie `crates/desktop-shell/dist/*` dans un dossier temporaire, remplace `index.html` par `docs/index.html`, ajoute un fichier `.nojekyll` vide et pousse de force sur la branche `gh-pages`.

### Workflow GitHub Actions (`.github/workflows/deploy-pages.yml`)

Configuré en déclenchement manuel `workflow_dispatch` (le déclencheur automatique `push` est volontairement commenté pour préserver le quota CI) :

- Exécute `npm ci` et `npm run build` dans `crates/desktop-shell/ui` sur `ubuntu-latest` (Node `22`), crée `crates/desktop-shell/dist/.nojekyll` puis déploie via `actions/upload-pages-artifact@v3` et `actions/deploy-pages@v4`.

{% hint style="warning" %}
**Différence de graphe embarqué** : `deploy-gh-pages.ps1` lance `test_export_docs_index_html` afin que le site publié s'ouvre directement sur le graphe AST complet d'`aether-engine`. À l'inverse, `.github/workflows/deploy-pages.yml` publie `crates/desktop-shell/dist` sans compilation Cargo : la page démarre alors sur la démo interactive hors-ligne de 24 nœuds (`DEMO_AETHER_GRAPH`).
{% endhint %}

---

## Repli de démonstration hors-ligne et GitHub Pages

Lorsque l'interface démarre sans `window.__AETHERSCOPE_DATA__` injecté et sans backend local sur `127.0.0.1:3030` (comme un build Vite statique hébergé sur GitHub Pages) :

1. **Course de démarrage de 2 secondes (`App.svelte`)** : Met `api.getGraph()` en concurrence avec un délai maximal de `2000 ms`.
2. **Activation du mode Démo** : En cas de délai dépassé ou d'erreur, active `cockpitState.isDemoMode = true` (badge cyan `DÉMO LIVE` dans `HeaderDeck.svelte`) et espace le polling de reconnexion `/api/graph/version` toutes les 10 itérations (`20 s`).
3. **Jeu de données interactif (`crates/desktop-shell/ui/src/data/demoGraph.ts`)** :
   - `DEMO_AETHER_GRAPH` : `24` nœuds répartis en `5` clusters (`core_engine`, `security_sast`, `cockpit_ui`, `ai_swarm`, `api_network`) et `27` arêtes, incluant `CWE-89` (`HIGH`), `CWE-78` (`CRITICAL`), `CWE-79` (`MEDIUM`) et un avertissement de budget `RULE_MAX_LINES` (`LOW`).
   - `DEMO_TASKS` (`3` tâches), `DEMO_GIT_STATUS` (`3` fichiers modifiés/indexés sur `main`) et `DEMO_ACTIVE_AGENTS` (`3` agents actifs : `Gemini Architect`, `Claude Security Auditor`, `Antigravity Sweeper`).
4. **Bac à sable plugins et taint côté navigateur (`crates/desktop-shell/ui/src/lib/demoPlugins.ts`)** : Précharge `DEMO_COMMUNITY_RULES` (`4` règles OWASP) et `INITIAL_DEMO_PLUGINS` (`3` packs : `majestic-injections`, `example-custom-auth`, `sample-semgrep`) et exécute `evaluatePluginRulesInBrowser` localement pour tester DSL v2 et Taint SSA sans backend.

---

## Pages associées

{% content-ref url="./webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](./webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="./obsidian-dual-vision.md" %}
[Coffre Obsidian et moteur Dual-Vision](./obsidian-dual-vision.md)
{% endcontent-ref %}

{% content-ref url="../console/launchers-and-scripts.md" %}
[Lanceurs, installeurs et workflows CI/CD](../console/launchers-and-scripts.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-workspace-graph.md" %}
[API REST : Workspace, Graphe et Export](../api-mcp/rest-api-workspace-graph.md)
{% endcontent-ref %}
