# Vue d'ensemble de l'API REST & Client

Le backend `desktop-shell` expose un serveur HTTP local Axum `0.7` sur `127.0.0.1:3030` avec **52 enregistrements `.route(...)`** (**60 opérations méthode HTTP + chemin**). Chaque requête est filtrée par `LocalGuard` (sans CORS permissif) et consommée par le cockpit via `AetherApiClient`, le flux SSE `/api/graph/events` ou des outils locaux comme `aetherscope-mcp`.

{% hint style="info" %}
Tous les endpoints REST écoutent exclusivement sur `127.0.0.1:<port>` (par défaut `3030`), tel que défini dans `crates/desktop-shell/src/main.rs` (`Args.port`). Vous pouvez changer le port au démarrage avec `--port <PORT>`.
{% endhint %}

## Architecture serveur & modes de démarrage

Le serveur Axum et la boucle d'arrière-plan `FileWatcherBridge` démarrent automatiquement dans les trois modes d'exécution interactifs ou démon :

* **WebView Desktop (par défaut)** : Lance la fenêtre native `tao` + `wry` pointant vers `http://127.0.0.1:<port>`. Sous Windows, WebView2 reçoit `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --js-flags=--max-old-space-size=4096` pour éviter la saturation mémoire du tas V8 sur les grands graphes.
* **Serveur headless (`--no-gui`)** : Démarre le serveur HTTP Axum et `FileWatcherBridge` sans ouvrir de fenêtre desktop, idéal pour un navigateur externe, des scripts ou des prévisualisations CI.
* **Pont MCP (`--mcp`)** : Appelle `mcp::check_server_listening(port)` ; si aucune instance n'écoute, lance le serveur Axum et `FileWatcherBridge` en tâche de fond, patiente `350 ms`, puis entre dans la boucle JSON-RPC 2.0 `stdio`.

{% tabs %}
{% tab title="Headless + curl" %}
```bash
# Démarrer le serveur REST headless sur le port 3030
aether-engine -p . --no-gui --port 3030

# Vérifier l'état du serveur (LocalGuard exige Host: 127.0.0.1:3030)
curl -s http://127.0.0.1:3030/api/health
```
{% endtab %}

{% tab title="PowerShell" %}
```powershell
# Démarrer le serveur REST headless sur le port 3030
.\aether-engine.exe -p . --no-gui --port 3030

# Vérifier l'état du serveur
Invoke-RestMethod -Uri "http://127.0.0.1:3030/api/health" -Method Get
```
{% endtab %}
{% endtabs %}

### Synchronisation temps réel (`FileWatcherBridge`)

`FileWatcherBridge` scrute `project_root` toutes les **30 ms** avec un anti-rebond adaptatif (**100 ms** de fenêtre calme, **500 ms** d'attente maximale en rafale). Dès que les écritures disque se stabilisent, il exécute des mises à jour ciblées :

* Invalide `git_raw_cache` afin que le prochain `GET /api/git/status` voie immédiatement les modifications.
* Incrémente `visual_plugins_version` lors de la modification de fichiers sous `.aether/plugins/visuals/` ou de shaders `.glsl`.
* Relance l'analyse de `vault_graph` lors de changements `.md`/`.mdx` dans un projet Vault/Mixed ou en mode `vault-notes`, et relance l'analyse de `code_graph` (avec `custom_exclusions`, `active_cve_rules` et `ignored_cwes`) tout en réécrivant `.aether/LIVE_AUDIT.md` lors de changements de code ou de contrats `README.md`.
* Vide `ui_graph_cache`, incrémente `graph_version` et `fs_version`, puis diffuse un événement `GraphWatchEvent` à tous les clients abonnés à [`GET /api/graph/events`](./rest-api-workspace-graph.md#get-apigraphevents).

## Couches de sécurité & correspondance des erreurs

AetherScope applique une défense en profondeur combinant validation d'origine réseau, confinement de chemins et protection des secrets.

### `LocalGuard` (Middleware transport & anti-CSRF)

Le routeur Axum n'attache **aucun `CorsLayer`**. À la place, `local_guard::enforce_local_only` inspecte trois en-têtes sur chaque requête :

| En-tête | Exigence | Valeurs autorisées (insensible à la casse) | En cas d'échec |
| :--- | :--- | :--- | :--- |
| `Host` | **Requis** | `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` | `403 Forbidden` |
| `Origin` | Optionnel (vérifié si présent) | `http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>` | `403 Forbidden` |
| `Sec-Fetch-Site` | Optionnel (vérifié si présent) | `same-origin`, `none` | `403 Forbidden` |

L'absence d'`Origin` et de `Sec-Fetch-Site` est acceptée afin que les outils CLI locaux (`curl`, PowerShell) et le pont TCP `aetherscope-mcp` puissent appeler `127.0.0.1:3030` directement. Les requêtes refusées reçoivent `403 Forbidden` avec le corps `text/plain; charset=utf-8` `"AetherScope: requête refusée (origine non locale)"`.

### `PathGuard`, `SecretGuard` & `SecretMasker`

Les endpoints manipulant des fichiers du projet (`GET /api/file_content`, `POST /api/save_file`, `GET /api/raw_file`, `POST /api/save_doc`, `POST /api/ai/create_file`, `POST /api/ai/target` et `GET /api/files`) appliquent des gardes supplémentaires :

* **`PathGuard` (`TargetJail`)** : Impose `DEFAULT_MAX_FILE_SIZE = 10 MiB`, `MAX_PATH_DEPTH = 32`, le rejet lexical des chemins vides, `.`/`./`, octets nuls, schémas URL (`scheme://`), chemins UNC (`\\...`), lettres de lecteur (`C:`), préfixes `/`/`\` et traversées `..`, suivi d'une vérification canonique (`starts_with(&canonical_root)`) contre l'évasion par lien symbolique.
* **`SecretGuard` / `PathGuard::is_sensitive_path`** : Bloque l'accès aux fichiers `.env*`, dossiers sensibles (`.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets*`, `credentials*`), fichiers sensibles (`service-account*`, `master.key`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `authorized_keys`, `known_hosts`, `id_rsa*`/`id_ed25519*`/`id_ecdsa*`/`id_dsa*`, fichiers système de mots de passe/registre) et extensions cryptographiques (`.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`, `.kdbx`, `.der`, `.crt`, `.cer`, `.jks`, `.keystore`).
* **`SecretMasker` (12 familles de secrets)** : Détecte et masque les blocs de clés privées PEM, clés API `sk-*`, jetons GitHub `ghp_*`/`github_pat_*`/`gh[ousr]_*`, clés AWS `AKIA*`, clés Stripe `sk_live_`/`rk_live_`, jetons Slack `xox*-*`, JWT (`ey*.*.*`), mots de passe dans les URI de base de données et affectations secrètes avec ou sans guillemets. Les routes d'écriture (`POST /api/save_doc`, `POST /api/ai/create_file`) **bloquent** les contenus contenant un secret (`403 Forbidden`), tandis que `GET /api/file_content` (si `raw=false`) et `POST /api/ai/target` **masquent** les secrets à la volée.

### Correspondance standard `SecurityError` -> HTTP

| Statut HTTP | Champ JSON `error` | Variantes `SecurityError` |
| :--- | :--- | :--- |
| `400 Bad Request` | `"bad_request"` | `NullByteDetected`, `PathTraversal`, `UncPathProhibited`, `DriveLetterProhibited`, `AbsolutePathsProhibited`, `UrlSchemeProhibited`, `InvalidPrefix`, `DepthExceeded`, `ExtensionNotAllowed`, `NotAFile` |
| `403 Forbidden` | `"forbidden"` | `SensitiveFileProhibited`, `PathEscapesRoot`, `SymlinkEscape`, `SymlinksDisabled` |
| `404 Not Found` | `"not_found"` | `IoError` (`ErrorKind::NotFound`) |
| `413 Payload Too Large` | `"payload_too_large"` | `FileTooLarge` (`> 10 MiB`) |
| `500 Internal Server Error` | `"internal_error"` | `RootCanonicalizationFailed`, `RootNotADirectory`, autres `IoError` |

Format JSON d'erreur : `{ "status": "error", "error": "<code_slug>", "message": "<details>" }` (`GET /api/file_content` ajoute également `"path"`, tandis que `GET /api/raw_file` renvoie une chaîne texte brute).

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité & Garde-fous](../core/security-confinement.md)
{% endcontent-ref %}

## Proxy dev Vite & `AetherApiClient`

En développement (`crates/desktop-shell/ui/vite.config.ts`), Vite sert le frontend Svelte 5 sur le port `5173` et proxifie toutes les requêtes `/api` vers `http://127.0.0.1:3030`. En build de production (`npm run build`), `vite-plugin-singlefile` compile l'interface dans `crates/desktop-shell/dist/index.html`, embarqué à la compilation dans le binaire Rust et servi depuis `127.0.0.1:3030`.

Le client TypeScript `AetherApiClient` (`crates/desktop-shell/ui/src/lib/api.ts`) utilise par défaut `baseUrl = ''` (URLs relatives same-origin) et expose **51 méthodes** (`49` wrappers `fetch` + `getRawFileUrl(path)` + `getGraphEventsUrl()`) :

```typescript
import { AetherApiClient, api } from '$lib/api';

// Le singleton par défaut utilise des URLs relatives same-origin ('')
const status = await api.getProjectStatus();

// Client personnalisé vers un port local différent (hors cockpit)
const customClient = new AetherApiClient('http://127.0.0.1:4040');
const health = await fetch('http://127.0.0.1:4040/api/health').then((r) => r.text());
```

{% hint style="warning" %}
**Différences client & routes non encapsulées à retenir** :
* **9 opérations HTTP sans méthode dédiée** : `GET /`, `GET /legacy`, `GET /favicon.ico`, `GET /api/health`, `GET /api/workspace`, `POST /api/workspace`, `GET /api/git/status` (appelé via `fetch` direct dans `graphState.svelte.ts`), `GET /api/analyze` (`api.analyzeProject` utilise `POST`) et `GET /api/ai/status`.
* **Méthodes renommées** : `teleportCamera(...)` appelle `POST /api/ai/telemetry` ; `initCommunityPluginBundle()` appelle `POST /api/plugins/init_bundle`.
* **Écarts de valeurs par défaut / typage TypeScript** : `api.getFileContent(path, raw = true)` met `raw` à `true` par défaut, alors que le backend Rust utilise `false` par défaut. `api.getProjects()` type `projects: string[]` tandis que Rust renvoie `{ name, path }[]`. `api.updateContract(...)` type `folder` dans la réponse là où Rust renvoie `contract_path` et `file_blake3_hash` optionnel. `api.switchViewMode(...)` omet les alias `'notes'` et `'editor'` acceptés par Rust, et `api.saveSettings(...)` omet `active_visual_plugin`.
* **Fallback `3333` hérité dans `McpControlModal.svelte`** : Lorsque `window.location.port` est vide (par exemple lors de l'ouverture d'un export HTML autonome en `file://`), `McpControlModal.svelte` affiche `'3333'` par défaut dans ses exemples. Le port canonique du serveur reste `3030`.
{% endhint %}

## Compaction du graphe (`ui_payload` & `decodeCompactGraph`)

Pour maintenir des temps de réponse fluides sur des graphes de 40 000 nœuds et 250 000 arêtes dans WebView2, `ui_payload::build_payload` (`crates/desktop-shell/src/api_routes.rs`) allège les réponses :

1. **Toujours appliqué sur les payloads UI** : Supprime `node.metadata.raw_content` (chargé à la demande via `GET /api/file_content`), vide `node.metadata.violations` lorsque `cve_anomalies` est non vide, et met `system_prompt = None` et `dataflow_graph = None`.
2. **Compaction au-delà des seuils (`nodes.len() > 3_000 || edges.len() > 20_000`)** :
   * Tronque `node.docstring` à `240` octets (`'…'`) et les docstrings de méthodes à `160` octets (`'…'`), limite `method.calls` à `8` entrées et tronque `blake3_hash` / `file_blake3_hash` à `16` caractères.
   * Remplace `edges` par `[]` et remplit `edges_compact` (`CompactEdges` avec tableaux d'indices entiers `src`, `dst`, `rel`, `typ`, tables dédupliquées `ids`, `rels`, `types`, et métadonnées rares `extra`).
3. **Décodage zero-copy côté frontend** : `decodeCompactGraph` (`crates/desktop-shell/ui/src/lib/graphCodec.ts`) reconstruit `AffiliationEdge[]` en réutilisant la même référence de chaîne `node.id` sans dupliquer les identifiants sur le tas JS.
4. **Export complet non compacté** : Passez `?full=1` ou `?full=true` à `GET /api/graph` pour obtenir les objets `edges` complets, `system_prompt` et `dataflow_graph`.

## Index complet des routes (52 routes / 60 opérations)

### Workspace, système de fichiers, initialisation, graphe & export

| # | Chemin | Méthode(s) | Méthode `AetherApiClient` | Référence |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `/` | `GET` | *(non encapsulé)* | [Workspace & Graphe](./rest-api-workspace-graph.md#get--et-get-legacy) |
| 2 | `/legacy` | `GET` | *(non encapsulé)* | [Workspace & Graphe](./rest-api-workspace-graph.md#get--et-get-legacy) |
| 3 | `/favicon.ico` | `GET` | *(non encapsulé)* | [Workspace & Graphe](./rest-api-workspace-graph.md#get-faviconico) |
| 4 | `/api/health` | `GET` | *(non encapsulé)* | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apihealth) |
| 5 | `/api/projects` | `GET` | `getProjects()` | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apiprojects) |
| 6 | `/api/workspace` | `GET`, `POST` | *(non encapsulé)* | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apiworkspace-et-post-apiworkspace) |
| 7 | `/api/fs/list` | `GET` | `listDirectory(path?)` | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apifslist) |
| 8 | `/api/dialog/pick_workspace` | `POST` | `pickWorkspace()` | [Workspace & Graphe](./rest-api-workspace-graph.md#post-apidialogpick_workspace) |
| 9 | `/api/dialog/pick_project` | `POST` | `pickProject()` | [Workspace & Graphe](./rest-api-workspace-graph.md#post-apidialogpick_project) |
| 10 | `/api/init_project` | `POST` | `initProject(path, stack, topology?)` | [Workspace & Graphe](./rest-api-workspace-graph.md#post-apiinit_project) |
| 11 | `/api/project/status` | `GET` | `getProjectStatus()` | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apiprojectstatus) |
| 12 | `/api/git/status` | `GET` | *(non encapsulé)* | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apigitstatus) |
| 13 | `/api/view_mode` | `POST` | `switchViewMode(mode)` | [Workspace & Graphe](./rest-api-workspace-graph.md#post-apiview_mode) |
| 14 | `/api/analyze` | `POST`, `GET` | `analyzeProject(path, exclusions?)` (`POST`) | [Workspace & Graphe](./rest-api-workspace-graph.md#post-apianalyze-et-get-apianalyze) |
| 15 | `/api/graph` | `GET` | `getGraph()` | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apigraph) |
| 16 | `/api/graph/version` | `GET` | `getGraphVersion()` | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apigraphversion) |
| 17 | `/api/graph/events` | `GET` (SSE) | `getGraphEventsUrl()` | [Workspace & Graphe](./rest-api-workspace-graph.md#get-apigraphevents) |
| 18 | `/api/export` | `POST` | `exportHtml(path?)` | [Workspace & Graphe](./rest-api-workspace-graph.md#post-apiexport) |

### IDE, Contrats, IA, Télémétrie, Chat & Tâches

| # | Chemin | Méthode(s) | Méthode `AetherApiClient` | Référence |
| :--- | :--- | :--- | :--- | :--- |
| 19 | `/api/files` | `GET` | `getFiles()` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-apifiles) |
| 20 | `/api/file_content` | `GET` | `getFileContent(path, raw?)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-apifile_content) |
| 21 | `/api/save_file` | `POST` | `saveFile(filePath, content)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apisave_file) |
| 22 | `/api/raw_file` | `GET` | `getRawFileUrl(path)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-apiraw_file) |
| 23 | `/api/ai/create_file` | `POST` | `createFile(payload)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apiaicreate_file) |
| 24 | `/api/save_doc` | `POST` | `saveDoc(payload)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apisave_doc) |
| 25 | `/api/contracts/sign` | `POST` | `signContracts(payload)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apicontractssign) |
| 26 | `/api/contracts/update` | `POST` | `updateContract(payload)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apicontractsupdate) |
| 27 | `/api/ai/target` | `POST` | `setAiTarget(symbolId, actionType?)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apiaitarget) |
| 28 | `/api/ai/telemetry` | `GET`, `POST`, `DELETE` | `getTelemetry()`, `teleportCamera(...)`, `clearTelemetry()` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-post-delete-apiaitelemetry) |
| 29 | `/api/ai/chat` | `GET`, `POST` | `getChatHistory()`, `sendChatMessage(...)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-et-post-apiaichat) |
| 30 | `/api/ai/chat/clear` | `POST` | `clearChatHistory()` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apiaichatclear) |
| 31 | `/api/ai/status` | `GET` | *(non encapsulé)* | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-apiaistatus) |
| 32 | `/api/ai/cancel` | `POST` | `cancelAi()` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apiaicancel) |
| 33 | `/api/ai/new_session` | `POST` | `newAiSession()` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apiainew_session) |
| 34 | `/api/ai/launch_cli` | `POST` | `launchCli(tool, projectPath?, prompt?)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apiailaunch_cli) |
| 35 | `/api/ai/system_prompt` | `GET` | `getSystemPrompt()` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-apiaisystem_prompt) |
| 36 | `/api/tasks` | `GET`, `POST` | `getTasks()`, `createTask(payload)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#get-et-post-apitasks) |
| 37 | `/api/tasks/update` | `POST` | `updateTask(...)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apitasksupdate) |
| 38 | `/api/tasks/delete` | `POST` | `deleteTask(taskId)` | [IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md#post-apitasksdelete) |

### Paramètres, Bounty, Surface & Plugins

| # | Chemin | Méthode(s) | Méthode `AetherApiClient` | Référence |
| :--- | :--- | :--- | :--- | :--- |
| 39 | `/api/settings` | `GET`, `POST` | `getSettings()`, `saveSettings(payload)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 40 | `/api/bounty/scope` | `GET`, `POST` | `getBountyScope()`, `updateBountyScope(payload)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 41 | `/api/surface_scan` | `POST` | `surfaceScan(req)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 42 | `/api/plugins` | `GET` | `getPlugins()` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 43 | `/api/plugins/toggle` | `POST` | `togglePlugin(relPath, enabled)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 44 | `/api/plugins/test` | `POST` | `testPlugins(relPath?)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 45 | `/api/plugins/init_bundle` | `POST` | `initCommunityPluginBundle()` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 46 | `/api/plugins/import_semgrep` | `POST` | `importSemgrepPlugin(pluginName, yamlContent)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 47 | `/api/plugins/upsert` | `POST` | `upsertPluginRule(payload)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 48 | `/api/plugins/delete` | `POST` | `deletePlugin(relPath)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 49 | `/api/visual_plugins` | `GET` | `getVisualPlugins()` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 50 | `/api/visual_plugins/activate` | `POST` | `activateVisualPlugin(id)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 51 | `/api/visual_plugins/upsert` | `POST` | `upsertVisualPlugin(payload)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 52 | `/api/visual_plugins/delete` | `POST` | `deleteVisualPlugin(id)` | [Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |

## Pour aller plus loin

{% content-ref url="./rest-api-workspace-graph.md" %}
[API REST : Workspace, système de fichiers, init, graphe & export](./rest-api-workspace-graph.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-ide-contracts-ai.md" %}
[API REST : IDE, Contrats, IA, Télémétrie, Chat & Tâches](./rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-security-plugins.md" %}
[API REST : Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="./mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](./mcp-server.md)
{% endcontent-ref %}
