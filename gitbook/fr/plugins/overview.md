# Vue d'ensemble des Plugins

AetherScope sépare les règles de sécurité déclaratives et les thèmes visuels WebGL 2 sous `.aether/plugins/`, avec rechargement à chaud, invalidation de cache BLAKE3 et confinement strict des chemins.

## Architecture Double des Plugins

AetherScope exécute côte à côte deux sous-systèmes de plugins isolés dans `<project_root>/.aether/plugins/` :

- **Plugins SAST & Taint (`PluginManifest`)** : Packs déclaratifs `.yaml`, `.yml` ou `.json` parcourus récursivement par `PluginEngine` (`crates/security-linter/src/plugin.rs`) pour étendre les règles CWE par motifs ainsi que les sources, puits (`sinks`) et assainisseurs (`sanitizers`) SSA inter-procéduraux.
- **Plugins Visuels WebGL 2 (`VisualPluginManifest`)** : Packs de thèmes placés sous `.aether/plugins/visuals/<pack>/` (`visual-plugin.yaml`, `visual-plugin.yml` ou `visual-plugin.json`) avec hooks GLSL ES 3.00 optionnels `backdrop.glsl` et `node_sdf.glsl` (`crates/desktop-shell/src/visual_plugin_routes.rs`).

Pour éviter toute collision entre les deux moteurs, `PluginEngine::scan_and_load_dir` et `plugin_routes::collect_plugin_files` ignorent explicitement tout répertoire nommé `visuals` (insensible à la casse) et tout fichier dont le nom de base est `visual-plugin` (insensible à la casse).

```text
.aether/plugins/
├── community/
│   └── plugin.yaml                    # CommunityBundle OWASP/CWE de 24 règles déplié
├── imported/
│   └── <slug>/
│       └── plugin.yaml                # Imports Semgrep YAML (CLI / REST / UI)
├── <custom-pack>/
│   └── plugin.yaml                    # Manifeste SAST & Taint DSL v2 personnalisé
└── visuals/
    └── <visual-slug>/
        ├── visual-plugin.yaml         # VisualPluginManifest (ou .yml / .json)
        ├── backdrop.glsl              # Hook GLSL optionnel aetherBackdrop(...)
        └── node_sdf.glsl              # Hook GLSL optionnel aetherNodeSurface(...)
```

{% hint style="info" %}
AetherScope exécute les plugins SAST sans verrou en parallèle grâce à `OnceLock<CompiledRuleMatchers>` par règle : les expressions régulières, les globs de chemins et les extensions en minuscules sont précompilés une seule fois au chargement, sans aucune contention `Mutex` à l'exécution.
{% endhint %}

## Rechargement à chaud et invalidation de cache BLAKE3

Vous pouvez modifier vos manifestes de plugins ou shaders GLSL sur disque pendant que le Cockpit est ouvert. `FileWatcherBridge` (`crates/ai-file-bridge/src/watcher.rs`) et la boucle d'arrière-plan de `desktop-shell` synchronisent l'interface et l'état d'audit sans redémarrage manuel.

### Filtrage de `.aether/` par `FileWatcherBridge`

1. Au démarrage et lors de `switch_root()`, `FileWatcherBridge` crée `<project_root>/.aether/plugins` s'il n'existe pas et surveille l'arborescence via `notify::RecommendedWatcher` (intervalle de sondage de `100 ms`).
2. `is_excluded_dir_name` ignore les répertoires commençant par un point (`.git`, `.vscode`, `.idea`), `WebView2` et 30 répertoires de build/dépendances (`target`, `node_modules`, `dist`, `build`, etc.), tout en exemptant explicitement `.aether`.
3. À l'intérieur de `.aether` (profondeur 1), `watch_filtered_tree` ignore tous les sous-répertoires **sauf** `plugins` (comme `.aether/cache` ou `.aether/tasks`), puis surveille récursivement `.aether/plugins` (`depth >= 2`).
4. `poll_changed_files()` capte les événements `Create`, `Modify` et `Remove` sur 38 extensions supportées (`rs, ts, tsx, js, jsx, mjs, cjs, py, md, mdx, svelte, vue, html, css, scss, cpp, hpp, cc, hh, cxx, hxx, c, h, inl, java, sol, yul, php, phtml, zig, cs, lua, luau, json, toml, yaml, yml, glsl`) en ignorant `.log`, `aetherscope_viewer.html` et `AETHER_AI_RULES.md`.

### Anti-rebond et optimisation « Visuel uniquement »

La boucle de surveillance de `desktop-shell` (`crates/desktop-shell/src/main.rs`) interroge `FileWatcherBridge` toutes les `30 ms` et attend une fenêtre calme de `100 ms` (`debounce_delay`) ou un délai maximal de lot de `500 ms` (`max_batch_delay`) avant d'agir :

- **Modifications visuelles uniquement** : Si tous les fichiers modifiés se trouvent dans `.aether/plugins/visuals/` ou portent l'extension `.glsl`, le serveur incrémente `visual_plugins_version` et **évite** la ré-analyse AST/SAST complète. Le frontend interroge `GET /api/graph/version` toutes les `2 s` et applique à chaud le thème ou le shader.
- **Modifications SAST ou code source** : Lorsque des manifestes `.yaml`, `.yml` ou `.json` sont modifiés, `ProjectScanner` recharge `.aether/plugins/`, vide `ui_graph_cache`, met à jour `LIVE_AUDIT.md` et incrémente `graph_version`.

### Clé de cache BLAKE3 `config_digest()`

`PluginEngine::config_digest()` calcule une empreinte hexadécimale BLAKE3 déterministe sur `"aether-plugin-engine-v2:"`, la clé canonique de `--plugins` et chaque plugin **actif** sérialisé via `serde_json::to_vec`. `ProjectScanner` intègre cette empreinte dans chaque clé `.aether/cache/ast/<entry_key>.json` :

```text
entry_key = blake3("v1|{rel_path}|{file_hash}|{contract_sig}|{plugin_digest}")
```

Activer/désactiver un plugin (`enabled`), modifier une règle ou changer `--plugins` invalide automatiquement les entrées de cache AST/SAST obsolètes dès l'analyse suivante, sans avoir à supprimer `.aether/cache/ast/`.

{% content-ref url="../core/blake3-governance.md" %}
[Cryptographie BLAKE3 & Gouvernance EARS](../core/blake3-governance.md)
{% endcontent-ref %}

## Confinement de sécurité et garde-fous

Chaque route HTTP et opération fichier liée aux plugins applique quatre barrières de sécurité complémentaires :

| Garde-fou | Portée | Comportement appliqué |
|---|---|---|
| `LocalGuard` | Toutes les routes `/api/plugins/*` et `/api/visual_plugins/*` | Restreint `Host` et `Origin` à `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` et exige `Sec-Fetch-Site` (`same-origin` ou `none`), bloquant DNS rebinding et CSRF en `403 Forbidden`. |
| `sanitize_plugin_slug` | Noms de dossiers de packs à la création/import | Rejette les chaînes vides, longueurs `> 64`, `\0`, `/`, `\`, `..`, `:` et `.` ; passe en minuscules ASCII `[a-z0-9_-]`, convertit les espaces en `-` et supprime les `-`/`_` en bordure. |
| `resolve_confined_plugin_file` | `POST /api/plugins/toggle` et `delete` | Rejette tout composant de chemin non normal, limite les extensions à `.yaml`, `.yml`, `.json`, vérifie `SecretGuard::is_secret_path` et contrôle `fs::canonicalize(target).starts_with(canon_plugins)` (`403` sur évasion par lien symbolique). |
| `SecretGuard` | Chemins `.aether/plugins/` et `visuals/` | Bloque `.env*`, `.ssh`, `.git`, `.aws`, `credentials*`, `secrets*`, `*.pem`, `*.key` et autres chemins sensibles. |

{% hint style="warning" %}
**Validation HTTP 422 par tests unitaires avant écriture** : `POST /api/plugins/upsert` exécute tous les `test_cases` du manifeste en mémoire via `PluginEngine::run_test_suite()` **avant** d'écrire sur disque. Si un seul test échoue (`report.failed > 0`), le serveur renvoie `422 Unprocessable Entity` et laisse `.aether/plugins/` intact.
{% endhint %}

Notez également le comportement de filtrage post-mutation : `apply_settings_filters_to_graph` préserve les alertes des plugins personnalisés même lorsque `.aether/settings.json` limite `active_cve_rules` à certaines règles natives, sauf si `active_cve_rules` est explicitement vide (`[]`) ou si la règle/CWE du plugin figure dans `ignored_cwes`.

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité et garde-fous](../core/security-confinement.md)
{% endcontent-ref %}

## Interfaces de gestion et workflows

Vous pouvez inspecter, tester, créer et déployer vos plugins depuis quatre interfaces synchronisées :

### 1. Modale Cockpit `PluginsModal` (Raccourci `G`)

Appuyez sur `G` n'importe où dans le Cockpit (hors champs de saisie) pour ouvrir le studio à 6 onglets **Plugins & Security Studio** :

| Onglet | Identifiant interne | Rôle |
|---|---|---|
| `Catalogue SAST` | `plugins` | Consulter les KPI, déployer le `CommunityBundle` de 24 règles (`Déployer (24)`), importer un `.yaml`/`.yml`/`.json` (redirige automatiquement un YAML Semgrep vers l'onglet Semgrep), prévisualiser/télécharger le YAML, basculer `ON`/`OFF`, lancer `Test` ou supprimer un pack. |
| `Règle DSL v2` | `create` | Créer des règles avec 4 modèles intégrés (`Auth Guard CWE-287`, `POSIX Flag Smuggling CWE-88`, `SQLi Concat/Format CWE-89`, `Async Lock Guard CWE-667`), `ast_scope`, `not_preceded_within_lines`, globs de chemins et tests unitaires intégrés. |
| `Taint SSA` | `taint` | Constructeur en 3 colonnes (`Sources`, `Sinks`, `Sanitizers`) couvrant les 9 `SourceKind` + `Custom` (10 au total) et les 8 `SinkKind` + `Custom` (9 au total). |
| `Bac à Sable` | `playground` | 5 exemples multi-langages préchargés avec `file_name` virtuel et évaluation instantanée côté navigateur (`demoPlugins.ts`). |
| `Import Semgrep` | `semgrep` | Convertir des règles Semgrep YAML vers `.aether/plugins/imported/<slug>/plugin.yaml` via `POST /api/plugins/import_semgrep`. |
| `Studio WebGL` | `visuals` | Basculer entre les 5 packs visuels intégrés, éditer les palettes de couches/sévérités et uniforms, prévisualiser `backdrop.glsl` / `node_sdf.glsl` à chaud et enregistrer dans `.aether/plugins/visuals/`. |

En mode démo hors-ligne ou HTML autonome (lorsque `127.0.0.1:3030` est inaccessible), `PluginsModal` bascule automatiquement vers l'évaluateur en mémoire `demoPlugins.ts` avec 3 packs préchargés.

### 2. Binaires CLI (`aether-engine` & `aether-plugin-tool`)

- `aether-engine --plugins <spec>` sélectionne des profils ou packs lors d'analyses headless/GUI, et `aether-engine --update-rules` déploie le `CommunityBundle` de 24 règles dans `<path>/.aether/plugins/community/plugin.yaml`.
- `aether-plugin-tool` fournit les sous-commandes `init`, `list`, `test`, `scan`, `export`, `import-semgrep`, `download-semgrep-rules` / `update-rules` et `init-bundle`.

### 3. API REST locale (`127.0.0.1:3030`)

Le backend desktop expose 7 routes pour les plugins SAST (`/api/plugins`, `/api/plugins/toggle`, `/api/plugins/test`, `/api/plugins/init_bundle`, `/api/plugins/import_semgrep`, `/api/plugins/upsert`, `/api/plugins/delete`) et 4 routes pour les plugins visuels (`/api/visual_plugins`, `/api/visual_plugins/activate`, `/api/visual_plugins/upsert`, `/api/visual_plugins/delete`).

### 4. Outil MCP (`aetherscope_manage_plugins`)

Les agents IA connectés en stdio JSON-RPC (`aetherscope-mcp`) peuvent appeler `aetherscope_manage_plugins` avec les actions `list`, `test`, `scan`, `upsert`, `toggle` et `init_bundle` (la suppression d'un plugin passe par `POST /api/plugins/delete` ou l'interface Cockpit, pas par MCP).

## Pour aller plus loin

{% content-ref url="sast-taint-dsl.md" %}
[DSL Déclaratif SAST & Taint v2](sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="semgrep-and-community-bundle.md" %}
[Importateur Semgrep & Bundle Communautaire](semgrep-and-community-bundle.md)
{% endcontent-ref %}

{% content-ref url="webgl-visual-plugins.md" %}
[Plugins Visuels WebGL 2](webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-security-plugins.md" %}
[API REST : Paramètres, Bounty, Surface & Plugins](../api-mcp/rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[CLIs Plugins, MCP & Runner](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
