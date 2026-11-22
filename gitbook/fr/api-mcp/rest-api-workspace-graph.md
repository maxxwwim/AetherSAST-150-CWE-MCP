# API REST : Workspace, système de fichiers, init, graphe & export

Ces 18 routes (20 opérations HTTP) gèrent la distribution du Cockpit HTML, la découverte des workspaces, le scaffolding multi-stack, l'analyse du projet, la lecture du graphe, le suivi temps réel SSE/polling et l'export HTML autonome. Tous ces endpoints sont protégés globalement par [`LocalGuard`](./rest-api-overview.md#localguard-middleware-transport--anti-csrf).

{% hint style="info" %}
Contrairement aux routes IDE confinées au projet, les endpoints de navigation workspace (`/api/workspace`, `/api/fs/list`, `/api/analyze`, `/api/init_project`, `/api/export`) acceptent par conception des dossiers du système de fichiers hôte afin de parcourir et changer de projet depuis le Cockpit.
{% endhint %}

---

## GET / et GET /legacy

Sert le bundle HTML autonome Svelte 5 + WebGL 2 du Cockpit avec `code_graph` et `vault_graph` embarqués en ligne. `/legacy` est un alias strictement identique.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/
GET http://127.0.0.1:3030/legacy
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Content-Type | Champ / Corps | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `text/html; charset=utf-8` | Document HTML | Généré par `viewer::generate_modern_standalone_html`, injectant `#view-mode-toggle` ainsi que `window.__AETHERSCOPE_DUAL_GRAPH__` / `window.__AETHERSCOPE_DATA__` / `window.AETHER_GRAPH_DATA` / `window.AETHER_DUAL_GRAPH` / `window.__PHYSICS_WORKER_CODE__`. Envoie `Cache-Control: no-cache, no-store, must-revalidate`. |
| `403 Forbidden` | `text/plain; charset=utf-8` | Texte d'erreur | Refusé par `LocalGuard` si `Host`, `Origin` ou `Sec-Fetch-Site` est invalide. |

### 💡 Exemple

```bash
curl -sI http://127.0.0.1:3030/
```

---

## GET /favicon.ico

Silencie les requêtes automatiques de favicon des navigateurs avec une réponse vide `204`.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/favicon.ico
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Content-Type | Champ / Corps | Description |
| :--- | :--- | :--- | :--- |
| `204 No Content` | *(vide)* | *(vide)* | Corps de réponse vide. |
| `403 Forbidden` | `text/plain; charset=utf-8` | Texte d'erreur | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -sI http://127.0.0.1:3030/favicon.ico
```

---

## GET /api/health

Sonde légère de disponibilité utilisée par les scripts et le démarrage automatique du serveur MCP.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/health
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Content-Type | Champ | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `text/plain; charset=utf-8` | `status` | Toujours `"ok"`. |
| `200 OK` | `text/plain; charset=utf-8` | `engine` | Toujours `"aether-v2"`. |
| `403 Forbidden` | `text/plain; charset=utf-8` | Texte d'erreur | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/health
# {"status":"ok","engine":"aether-v2"}
```

{% hint style="warning" %}
`GET /api/health` renvoie une chaîne statique `&'static str` avec `Content-Type: text/plain; charset=utf-8` plutôt que `application/json`. Utilisez `JSON.parse()` si votre client vérifie strictement l'en-tête `Content-Type`.
{% endhint %}

---

## GET /api/projects

Liste les sous-dossiers projets candidats dans le `project_root` courant et son dossier parent immédiat.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/projects
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `projects` | `ProjectItem[]` | Tableau d'objets `{ name: string, path: string }`, triés sans distinction de casse par `name`. Exclut les dossiers cachés `.`, `target`, `node_modules` et `dist`. |
| `200 OK` | `default_project` | `string \| null` | Chemin `project_root` actif nettoyé de tout préfixe Windows `\\?\`. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s http://127.0.0.1:3030/api/projects
```
```json
{
  "projects": [
    { "name": "aether-engine", "path": "C:\\Users\\dev\\Projets\\aether-engine" }
  ],
  "default_project": "C:\\Users\\dev\\Projets\\aether-engine"
}
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

// Note : api.ts type `projects: string[]`, alors que Rust renvoie `{ name, path }[]`
const res = await api.getProjects();
```
{% endtab %}
{% endtabs %}

---

## GET /api/workspace et POST /api/workspace

Lit ou met à jour en mémoire le chemin `project_root` **sans** lancer d'analyse ni incrémenter `graph_version`.

### 🎮 Endpoint

```text
GET  http://127.0.0.1:3030/api/workspace
POST http://127.0.0.1:3030/api/workspace
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `workspace` | Corps JSON (`POST`) | `string` | Optionnel | Nouveau chemin `project_root`. S'il est absent ou non textuel, l'appel n'effectue aucune modification et renvoie tout de même `200 OK`. |

### 💎 Réponse

| Méthode / Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `workspace` | `string` | Chemin `project_root` actuel. |
| `POST` (`200 OK`) | `status` | `string` | Toujours `"ok"`. |
| `400` / `422` (`POST`) | *(texte)* | `string` | Erreur d'extraction JSON Axum si le corps n'est pas un JSON valide. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/workspace

curl -s -X POST http://127.0.0.1:3030/api/workspace \
  -H "Content-Type: application/json" \
  -d '{"workspace":"C:\\Users\\dev\\Projets\\my-app"}'
```

---

## GET /api/fs/list

Explorateur de dossiers côté serveur utilisé par la modale Project Hub pour lister les lecteurs système et sous-dossiers non cachés avec détection de stack.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/fs/list?path=<dir>
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Query | `string` | Optionnel | Dossier à lister (guillemets et `\\?\` supprimés ; utilise le parent si le chemin pointe vers un fichier). Par défaut `project_root.parent()` s'il s'agit d'un dossier, sinon `project_root`. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "error"` | `"error"` si le dossier cible n'existe pas (`message` vaut `"Dossier introuvable : ..."`). |
| `200 OK` | `current_path` | `string` | Dossier canonisé actuellement listé. |
| `200 OK` | `parent_path` | `string \| null` | Dossier parent, ou `null` à la racine du système de fichiers. |
| `200 OK` | `drives` | `string[]` | Lecteurs disponibles (`["C:\\", ...]` sous Windows, `["/"]` sous Unix). |
| `200 OK` | `entries` | `FsDirEntry[]` | Tableau `{ name, path, is_project, stack_hint, is_obsidian }` trié par `is_project` décroissant puis `name` croissant. Ignore les dossiers cachés, `node_modules`, `target`, `dist`, `build`, `__pycache__`, `.venv`, `venv`, `vendor`, `$recycle.bin` et `system volume information`. `stack_hint` détecte `Rust`, `Node / TS`, `Python`, `PHP`, `Go`, `Obsidian Vault` et `Git`. |
| `200 OK` | `message` | `string` *(optionnel)* | Présent uniquement en cas d'erreur. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s "http://127.0.0.1:3030/api/fs/list?path=."
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

const listing = await api.listDirectory();
console.log(listing.drives, listing.entries);
```
{% endtab %}
{% endtabs %}

---

## POST /api/dialog/pick_workspace

Ouvre le sélecteur de dossier natif de l'OS (`rfd::FileDialog`, avec repli PowerShell `FolderBrowserDialog` sous Windows) pour choisir un workspace et découvrir ses projets candidats, sans modifier `project_root`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/dialog/pick_workspace
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun corps requis. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "cancelled"` | `"cancelled"` si l'utilisateur ferme le dialogue OS. |
| `200 OK` | `workspace` | `string \| null` | Dossier sélectionné, ou `null` si annulé. |
| `200 OK` | `projects` | `ProjectItem[]` | Projets candidats dans `workspace` (`[]` si annulé). |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

```typescript
import { api } from '$lib/api';

const picked = await api.pickWorkspace();
if (picked.status === 'ok') {
  console.log(picked.workspace, picked.projects);
}
```

---

## POST /api/dialog/pick_project

Ouvre le sélecteur de dossier natif pour choisir un projet et exécute immédiatement le pipeline complet `execute_project_pipeline`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/dialog/pick_project
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun corps requis. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "cancelled"` | `"cancelled"` si le dialogue a été annulé. |
| `200 OK` | `project_path` | `string \| null` | Dossier du projet sélectionné, ou `null` si annulé. |
| `200 OK` | `graph` | `UiGraphPayload \| null` | Graphe analysé sérialisé via `ui_payload::ser_graph_opt` (compacté si `> 3 000` nœuds ou `> 20 000` arêtes), ou `null` si annulé. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

**Effets de bord (si `status == "ok"`)** : Met à jour `project_root`, `project_type`, `detection_report`, `active_view_mode`, `code_graph`, `vault_graph` et `graph` ; recharge `.aether/ai_telemetry_cache.json` si la racine change ; incrémente `graph_version` ; écrit `.aether/AETHER_AI_RULES.md` et `.aether/LIVE_AUDIT.md` ; met à jour la télémétrie et les messages chat.

### 💡 Exemple

```typescript
import { api } from '$lib/api';

const res = await api.pickProject();
if (res.status === 'ok' && res.graph) {
  console.log(`${res.graph.nodes.length} nœuds chargés depuis ${res.project_path}`);
}
```

---

## POST /api/init_project

Génère une arborescence multi-couches pilotée par contrats avec frontmatter YAML `README.md`, fichier `aether.lock.toml` signé BLAKE3, `AETHER_AI_RULES.md` et fichiers de démarrage adaptés à la stack.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/init_project
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Corps JSON | `string` | **Oui** | Dossier cible du projet (créé s'il n'existe pas). |
| `stack` | Corps JSON | `string` | **Oui** | Sélecteur de stack : `"rust"` (`PureRust`), `"python"` (`PurePythonUv`), `"ts"` / `"node"` (`PureNodePnpm`), `"roblox"` / `"roblox-server"` / `"luau"` (`RobloxLuau`), `"minecraft"` / `"mc"` (`MinecraftServer`), `"mvc"` / `"classic-mvc"` / `"clean-mvc"` (`ClassicMvc`), ou `"hybrid"` / toute autre chaîne (`HybridMmoWeb3`). |
| `topology` | Corps JSON | `string` | Optionnel | `"dissociated"` / `"distributed"` (`TopologyMode::Dissociated`) ou `"local"` (par défaut, `TopologyMode::MonorepoLocal`). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `message` | `string` | Résumé (`"Projet initialisé avec 11 dossiers et contrats README.md signés BLAKE3"`). |
| `200 OK` | `created_dirs` | `string[]` | Liste des 11 sous-dossiers générés (`contracts`, `client`, `client/ui`, `client/state`, `server`, `server/domain`, `server/application`, `server/api`, `data-nodes`, `data-nodes/db-primary`, `data-nodes/cache-worker`). |
| `400` / `422` | *(texte)* | `string` | Erreur d'extraction JSON Axum si le corps est invalide ou si `path`/`stack` manque. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

{% hint style="info" %}
`POST /api/init_project` écrit uniquement les fichiers sur disque sans exécuter `execute_project_pipeline`. Appelez ensuite `POST /api/analyze` pour charger le projet nouvellement créé dans `AppState`.
{% endhint %}

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/init_project \
  -H "Content-Type: application/json" \
  -d '{"path":"./my-new-service","stack":"rust","topology":"local"}'
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

const init = await api.initProject('./my-new-service', 'rust', 'local');
await api.analyzeProject('./my-new-service');
```
{% endtab %}
{% endtabs %}

{% content-ref url="../extensions-dev/arch-scaffolder.md" %}
[Générateur d'architecture multi-stack (arch-templates)](../extensions-dev/arch-scaffolder.md)
{% endcontent-ref %}

---

## GET /api/project/status

Renvoie la classification détectée du projet (`PureCode`, `PureObsidianVault`, `Mixed`), les statistiques de syntaxe Obsidian et les vues actives/supportées dans le Cockpit.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/project/status
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `project_type` | `"PureCode" \| "PureObsidianVault" \| "Mixed"` | Classification détectée par `obsidian-vault`. |
| `200 OK` | `has_obsidian_dir` | `boolean` | `true` si un dossier `.obsidian/` est présent. |
| `200 OK` | `obsidian_dir_path` | `string` *(optionnel)* | Chemin vers `.obsidian/` si présent. |
| `200 OK` | `supported_views` | `string[]` | `["code"]` (`PureCode`), `["vault-notes", "code"]` (`PureObsidianVault`) ou `["code", "vault-notes"]` (`Mixed`). |
| `200 OK` | `active_view_mode` | `string` | Mode actif (`"code"`, `"vault"`, `"vault-notes"` ou `"ide"`). |
| `200 OK` | `active_view` | `string` | Reflète `active_view_mode`. |
| `200 OK` | `code_files_count` | `number` | Nombre de fichiers sources détectés. |
| `200 OK` | `markdown_files_count` | `number` | Nombre de fichiers Markdown détectés. |
| `200 OK` | `obsidian_syntax_markers_count` | `number` | Nombre de marqueurs Obsidian (wikilinks, embeds, tags). |
| `200 OK` | `detection_report` | `ProjectDetectionReport` *(optionnel)* | Rapport détaillé lorsqu'il est disponible. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/project/status
```

---

## GET /api/git/status

Exécute `git status --porcelain=v1 -uall --ignored=no` et `git rev-parse --abbrev-ref HEAD` (mis en cache **3 secondes** dans `git_raw_cache`) puis corrèle les fichiers modifiés avec les alertes CWE SAST et les contrats EARS de `graph.nodes`.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/git/status
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `is_git_repo` | `boolean` | `false` si `project_root` n'est pas un dépôt Git (valeurs vides par défaut). |
| `200 OK` | `branch` | `string \| null` | Branche courante issue de `git rev-parse --abbrev-ref HEAD`. |
| `200 OK` | `clean` | `boolean` | `true` si `files` est vide. |
| `200 OK` | `files` | `GitFileChange[]` | Tableau `{ path, status ("modified" \| "untracked" \| "staged" \| "deleted" \| "renamed" \| "conflict"), index_code, worktree_code, has_security_violation, cwe_count, ears_violation, max_severity }`. Les avertissements de budget de lignes (`RULE_MAX_LINES` / `ARCH-BUDGET-EXCEEDED`) sont exclus de `cwe_count` et `has_security_violation`. |
| `200 OK` | `modified_count`, `untracked_count`, `staged_count`, `deleted_count`, `security_alert_count` | `number` | Compteurs agrégés. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/git/status
```

---

## POST /api/view_mode

Bascule le mode de vue actif du Cockpit entre Code AST, Notes Obsidian Vault et IDE, en analysant le graphe cible à la volée s'il n'est pas encore en cache.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/view_mode
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `mode` | Corps JSON | `string` | **Oui** | Mode cible (insensible à la casse) : `"code"` -> `"code"`, `"vault"` / `"notes"` / `"vault-notes"` -> `"vault-notes"`, `"ide"` / `"editor"` -> `"ide"`. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | *(racine)* | `UiGraphPayload` | Graphe actif sérialisé via `ui_payload::build_payload`. |
| `400 Bad Request` | `status`, `message` | `string` | Mode inconnu (`ViewModeError::InvalidMode`) ou JSON invalide. |
| `422 Unprocessable Entity` | `status`, `message` | `string` | Graphe cible indisponible pour ce projet (`ViewModeError::GraphNotAvailable`) ou champ `mode` manquant. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

**Effets de bord** : Peuple `vault_graph` ou `code_graph` à la demande, met à jour `active_view_mode` et `graph`, incrémente `graph_version` (invalidant `ui_graph_cache`) et enregistre un événement télémétrie `"Cockpit"`.

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/view_mode \
  -H "Content-Type: application/json" \
  -d '{"mode":"vault-notes"}'
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

const vaultPayload = await api.switchViewMode('vault-notes');
```
{% endtab %}
{% endtabs %}

{% content-ref url="../cockpit-ide/obsidian-dual-vision.md" %}
[Coffre Obsidian & Moteur Dual-Vision](../cockpit-ide/obsidian-dual-vision.md)
{% endcontent-ref %}

---

## POST /api/analyze et GET /api/analyze

Exécute la classification complète du projet (`PureCode`, `PureObsidianVault`, `Mixed`), l'analyse AST/SAST et/ou Obsidian Vault sur un dossier, puis renvoie le `UiGraphPayload` résultant.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/analyze
GET  http://127.0.0.1:3030/api/analyze?path=<dir>
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Corps JSON (`POST`) / Query (`GET`) | `string` | Requis en `POST` ; Optionnel en `GET` | Dossier cible (guillemets et `\\?\` supprimés ; repli sur `state.project_root` si vide ou `"."` ; utilise le parent si c'est un fichier). |
| `exclusions` | Corps JSON (`POST` uniquement) | `string[]` | Optionnel | Motifs d'exclusion glob/chemin ; remplace `state.custom_exclusions` lorsqu'il est fourni. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | *(racine)* | `UiGraphPayload` | Graphe analysé passé par `ui_payload::build_payload`. |
| `400 Bad Request` | `status`, `message` | `string` | Chemin inexistant (`"Chemin introuvable : ..."`) ou JSON syntaxiquement invalide. |
| `422 Unprocessable Entity` | *(texte)* | `string` | Champ `path` absent ou mal typé dans le JSON `POST`. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

**Effets de bord** : Met à jour `project_root`, `project_type`, `detection_report`, `active_view_mode`, `code_graph`, `vault_graph` et `graph` ; recharge `ai_telemetry_cache.json` si la racine change ; incrémente `graph_version` ; écrit `.aether/AETHER_AI_RULES.md` et `.aether/LIVE_AUDIT.md` ; met à jour la télémétrie et les messages chat.

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"path":".","exclusions":["dist","fixtures"]}'
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

const payload = await api.analyzeProject('.', ['dist', 'fixtures']);
```
{% endtab %}
{% endtabs %}

---

## GET /api/graph

Renvoie le graphe `AetherGraph` actif, soit sous forme `UiGraphPayload` optimisé et mis en cache (par défaut), soit complet et non compacté (`?full=1`).

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/graph
GET http://127.0.0.1:3030/api/graph?full=1
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `full` | Query | `string` | Optionnel | Passez `"1"` ou `"true"` (insensible à la casse) pour recevoir le `AetherGraph` complet non compacté (avec `edges` complets, `system_prompt` et `dataflow_graph`). Sinon, renvoie le `UiGraphPayload` en cache (avec `edges_compact` si `nodes > 3 000 || edges > 20 000`). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `project_name`, `project_path`, `generated_at` | `string` | Métadonnées du projet et horodatage. |
| `200 OK` | `nodes` | `SymbolBubble[]` | Bulles du graphe (`raw_content` retiré dans le payload UI). |
| `200 OK` | `edges` | `AffiliationEdge[]` | Objets d'arêtes complets (`[]` lorsque compacté). |
| `200 OK` | `edges_compact` | `CompactEdges` *(optionnel)* | Présent uniquement lors de la compaction (`> 3 000` nœuds ou `> 20 000` arêtes sans `full`). |
| `200 OK` | `stats` | `GraphStats` | Métriques agrégées des nœuds, arêtes et violations. |
| `200 OK` | `system_prompt`, `dataflow_graph` | `string \| null`, `DataflowGraph \| null` | Présents uniquement avec `?full=1` ou `?full=true`. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
# Graphe complet non compacté pour CLI / MCP
curl -s "http://127.0.0.1:3030/api/graph?full=1"
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';
import { decodeCompactGraph } from '$lib/graphCodec';

const rawPayload = await api.getGraph();
const graph = decodeCompactGraph(rawPayload);
```
{% endtab %}
{% endtabs %}

---

## GET /api/graph/version

Endpoint de polling léger utilisé en repli toutes les 2 secondes par le Cockpit pour détecter les ré-analyses de graphe, le rechargement des plugins visuels et les changements disque.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/graph/version
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `version` | `number` (`u64`) | Compteur monotone `graph_version` (démarre à `1`). |
| `200 OK` | `visual_version` | `number` (`u64`) | Compteur monotone `visual_plugins_version` (démarre à `1`). |
| `200 OK` | `fs_version` | `number` (`u64`) | Compteur monotone `fs_version` incrémenté à chaque notification de `FileWatcherBridge` (démarre à `1`). |
| `200 OK` | `changed_files` | `string[]` | Chemins relatifs normalisés avec `/` modifiés lors du dernier lot du watcher. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/graph/version
# {"version":3,"visual_version":1,"fs_version":5,"changed_files":["src/main.rs"]}
```

---

## GET /api/graph/events

Flux Server-Sent Events (SSE) délivrant en moins de 150 ms les notifications push de `FileWatcherBridge` pour le rechargement du graphe, de l'IDE et des plugins visuels.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/graph/events
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Abonnement SSE standard (`Accept: text/event-stream`). |

### 💎 Réponse

| Statut | Champ (`GraphWatchEvent` JSON dans `data:`) | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` (`text/event-stream`) | `version` | `number` (`u64`) | `graph_version` courant. |
| `200 OK` | `visual_version` | `number` (`u64`) | `visual_plugins_version` courant. |
| `200 OK` | `fs_version` | `number` (`u64`) | `fs_version` courant. |
| `200 OK` | `changed_files` | `string[]` | Chemins relatifs modifiés dans le lot (`[]` lors du `"sync"` initial). |
| `200 OK` | `kind` | `"sync" \| "watcher" \| "visual" \| "lag_resync"` | Origine de l'événement (`"sync"` à la connexion, `"visual"` pour des changements shaders/visuels seuls, `"watcher"` pour le code/vault, `"lag_resync"` en cas de retard sur le canal de `128` slots). Un keep-alive (`keep-alive`) est envoyé toutes les `15 s`. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -N http://127.0.0.1:3030/api/graph/events
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

const es = new EventSource(api.getGraphEventsUrl());
es.onmessage = (ev) => {
  const event = JSON.parse(ev.data);
  console.log(event.kind, event.version, event.changed_files);
};
```
{% endtab %}
{% endtabs %}

---

## POST /api/export

Génère et écrit sur disque un bundle HTML autonome du Cockpit (`aetherscope_viewer.html`).

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/export
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Corps JSON | `string \| null` | Optionnel | Dossier de destination. Par défaut `state.project_root`. Envoyez toujours un objet JSON valide (au minimum `{}`). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `viewer_path` | `string` | Chemin du fichier généré (`<target_dir>/aetherscope_viewer.html`). |
| `200 OK` | `total_nodes` | `number` | Nombre de nœuds dans `state.graph`. |
| `200 OK` | `total_edges` | `number` | Nombre d'arêtes dans `state.graph`. |
| `400` / `422` | *(texte)* | `string` | Corps JSON malformé (`{}` manquant). |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

{% hint style="warning" %}
`POST /api/export` ignore actuellement les erreurs de `fs::write` (`let _ = fs::write(...)`) et renvoie tout de même `200 OK`. Vérifiez la présence de `viewer_path` sur disque lorsque vous exportez vers des répertoires personnalisés.
{% endhint %}

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/export \
  -H "Content-Type: application/json" \
  -d '{}'
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

const exported = await api.exportHtml();
console.log(exported.viewer_path);
```
{% endtab %}
{% endtabs %}

{% content-ref url="../cockpit-ide/standalone-viewer.md" %}
[Visionneuse HTML autonome & GitHub Pages](../cockpit-ide/standalone-viewer.md)
{% endcontent-ref %}
