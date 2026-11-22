# API REST : IDE, Contrats, IA, Télémétrie, Chat & Tâches

Ces 20 routes (23 opérations HTTP) pilotent l'arborescence de l'IDE plein écran et la sauvegarde atomique, le scellement BLAKE3 des contrats, les handshakes IA zero-shell, la télémétrie multi-agents, la boîte de réception chat et le gestionnaire de tâches. Toutes les opérations sur fichiers sont confinées par `PathGuard`, `SecretGuard` et `SecretMasker` en plus de [`LocalGuard`](./rest-api-overview.md#localguard-middleware-transport--anti-csrf).

{% hint style="warning" %}
**Masquage vs Blocage** : Les endpoints de lecture (`GET /api/file_content?raw=false`, `POST /api/ai/target`) **masquent** les secrets à la volée via `SecretMasker::mask_text`, tandis que les endpoints d'écriture IA/doc (`POST /api/save_doc`, `POST /api/ai/create_file`) **refusent** tout contenu contenant un secret avec `403 Forbidden` via `SecretMasker::contains_secret`.
{% endhint %}

---

## GET /api/files

Renvoie l'arborescence à plat des fichiers et dossiers du projet pour la barre latérale de l'IDE, en ignorant les caches de build et les fichiers sensibles.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/files
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `files` | `FileTreeItem[]` | Tableau trié lexicographiquement d'objets `{ name, path, is_dir, size, extension }` (`path` utilise `/` ; `size = 0` et `extension = ""` pour les dossiers). Ignore `.git`, `node_modules`, `target`, `dist`, `.aether`, `.gemini`, ainsi que tout chemin détecté par `SecretGuard::is_secret_path` ou `PathGuard::is_sensitive_path`. |
| `403 Forbidden` | *(texte)* | `string` | Refusé par `LocalGuard`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/files
```

---

## GET /api/file_content

Lit un fichier texte UTF-8 à l'intérieur de `project_root` (jusqu'à `10 MiB`), avec jusqu'à 20 tentatives en cas de verrouillage temporaire sous Windows et masquage optionnel des secrets.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/file_content?path=<rel_path>&raw=false
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Query | `string` | **Oui** | Chemin relatif au projet validé par `PathGuard`, `SecretGuard` et `PathGuard::validate_not_sensitive`. |
| `raw` | Query | `boolean` | Optionnel | Le serveur utilise `false` par défaut (applique `SecretMasker::mask_text`). Passez `raw=true` pour lire le contenu non masqué (utilisé par `api.getFileContent(path, raw = true)` dans l'IDE). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `path`, `content` | `string` | Contenu du fichier (masqué si `raw=false`). |
| `400` / `403` / `404` / `413` / `500` | `status`, `error`, `message`, `path` | `string` | Erreur de confinement `PathGuard` / `SecretGuard` (correspondance `SecurityError` ; `SecretGuard` renvoie `403` sans champ `error`). |

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s "http://127.0.0.1:3030/api/file_content?path=src/main.rs&raw=false"
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

// Note : le client TS met raw = true par défaut (alors que Rust utilise raw = false)
const file = await api.getFileContent('src/main.rs', true);
```
{% endtab %}
{% endtabs %}

---

## POST /api/save_file

Écrit de manière atomique un fichier du projet (utilisé par `Ctrl+S` dans l'IDE), sérialisé par `file_save_lock` (`tokio::sync::Mutex`) via un fichier temporaire voisin et un renommage atomique.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/save_file
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `file_path` | Corps JSON | `string` | **Oui** | Chemin de destination relatif au projet (crée les dossiers parents manquants ; vérifié par `PathGuard` et `SecretGuard`). |
| `content` | Corps JSON | `string` | **Oui** | Contenu UTF-8 complet à écrire. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `file_path` | `string` | Chemin relatif écrit. |
| `200 OK` | `bytes_written` | `number` | Nombre d'octets écrits. |
| `400` / `403` / `500` | `status`, `error`, `message` | `string` | Erreur de confinement ou d'E/S (`SecurityError`). |

{% hint style="info" %}
`POST /api/save_file` n'exécute **pas** `SecretMasker::contains_secret` et ne déclenche **pas** de ré-analyse synchrone du graphe. `FileWatcherBridge` détecte l'écriture sur disque de façon asynchrone (fenêtre calme de 100 ms) et actualise le graphe ainsi que `.aether/LIVE_AUDIT.md`.
{% endhint %}

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/save_file \
  -H "Content-Type: application/json" \
  -d '{"file_path":"src/lib.rs","content":"pub fn ok() {}\n"}'
```

{% content-ref url="../cockpit-ide/integrated-ide.md" %}
[IDE multi-onglets plein écran](../cockpit-ide/integrated-ide.md)
{% endcontent-ref %}

---

## GET /api/raw_file

Sert des ressources binaires brutes (images, PDF, Markdown, CSV, JSON) dans `project_root` pour la visionneuse Obsidian Vault et les aperçus IDE.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/raw_file?path=<rel_path>
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Query | `string` | **Oui** | Chemin relatif au projet. L'extension doit figurer parmi les 15 `ALLOWED_RAW_EXTENSIONS` : `png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `markdown`, `txt`, `csv`. Taille max `10 MiB`. |

### 💎 Réponse

| Statut | Content-Type | Corps | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | Type MIME de l'extension | Octets bruts | Correspondance MIME exacte (`image/png`, `image/jpeg`, `image/gif`, `image/svg+xml`, `image/webp`, `image/x-icon`, `image/bmp`, `image/tiff`, `application/pdf`, `application/json`, `text/plain; charset=utf-8` pour `md`/`markdown`/`txt`, `text/csv; charset=utf-8`). |
| `400` / `403` / `404` / `413` / `500` | `text/plain; charset=utf-8` | Chaîne brute | Renvoie `"Chemin manquant"` (`400`) ou le message texte `SecurityError` (sans encapsulation JSON). |

### 💡 Exemple

```bash
curl -s "http://127.0.0.1:3030/api/raw_file?path=docs/diagram.png" --output diagram.png
```

---

## POST /api/ai/create_file

Crée un nouveau fichier source dans `project_root` avec détection des secrets, puis ré-analyse immédiatement le projet et incrémente `graph_version`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/create_file
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | Corps JSON | `string` | **Oui** | Dossier du projet (`""` ou `"."` utilise le `project_root` actif ; doit rester confiné dans le `project_root` canonique). |
| `file_path` | Corps JSON | `string` | **Oui** | Chemin relatif du fichier à créer (`PathGuard` + `SecretGuard`). |
| `content` | Corps JSON | `string` | **Oui** | Contenu du fichier ; refusé avec `403 Forbidden` si `SecretMasker::contains_secret` correspond. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `file_path` | `string` | Chemin relatif créé. |
| `200 OK` | `created_symbol` | `string` | Chemin normalisé avec séparateurs `::`. |
| `200 OK` | `graph`, `data` | `UiGraphPayload` | Payloads de graphe mis à jour et identiques sérialisés via `ui_payload::ser_graph`. |
| `400` / `403` / `500` | `status`, `error`, `message` | `string` | Refus pour évasion, chemin sensible ou secret intégré. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/create_file \
  -H "Content-Type: application/json" \
  -d '{"project_path":".","file_path":"src/new_mod.rs","content":"pub fn run() {}\n"}'
```

---

## POST /api/save_doc

Écrit un document ou contrat architectural `README.md` ; lorsque `file_name` vaut `README.md` (insensible à la casse), scelle automatiquement son empreinte BLAKE3 dans `aether.lock.toml` et ré-analyse le graphe.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/save_doc
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | Corps JSON | `string` | **Oui** | Racine projet confinée (`""` ou `"."` utilise le `project_root` actif). |
| `folder` | Corps JSON | `string` | **Oui** | Sous-dossier cible (`""`, `"root"` ou `"."` cible la racine du projet). |
| `file_name` | Corps JSON | `string` | **Oui** | Nom du fichier (ex. `"README.md"`). |
| `content` | Corps JSON | `string` | **Oui** | Contenu ; bloqué avec `403 Forbidden` si `SecretMasker::contains_secret` correspond. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `saved_path` | `string` | Chemin absolu enregistré. |
| `200 OK` | `blake3_hash` | `string` *(optionnel)* | Nouveau condensat BLAKE3 lorsque `file_name` est `README.md`. |
| `200 OK` | `graph` | `UiGraphPayload` *(optionnel)* | Payload du graphe mis à jour après ré-analyse pour `README.md`. |
| `400` / `403` / `500` | `status`, `error`, `message` | `string` | Refus de confinement ou de secret. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/save_doc \
  -H "Content-Type: application/json" \
  -d '{"project_path":".","folder":"server","file_name":"README.md","content":"---\nid: server\nlayer: domain\nmax_lines_per_file: 250\n---\n# Server\n"}'
```

---

## POST /api/contracts/sign

Parcourt les dossiers non cachés (`.*`, `target`, `node_modules`, `dist` ignorés) pour calculer les empreintes BLAKE3 des contrats `README.md`, met à jour `aether.lock.toml`, ré-analyse le projet et incrémente `graph_version`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/contracts/sign
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | Corps JSON | `string` | Optionnel | Racine projet (par défaut `state.project_root`). |
| `folder` | Corps JSON | `string` | Optionnel | Dossier spécifique à signer (signe tous les dossiers si omis). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `message` | `string` | Résumé des contrats signés. |
| `200 OK` | `signed_count` | `number` | Nombre de manifestes `README.md` signés. |
| `200 OK` | `blake3_hash` | `string` *(optionnel)* | Empreinte du contrat principal/ciblé. |
| `200 OK` | `graph` | `UiGraphPayload` | Graphe ré-analysé (`ui_payload::ser_graph`). |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/contracts/sign \
  -H "Content-Type: application/json" \
  -d '{"folder":"server"}'
```

{% content-ref url="../core/blake3-governance.md" %}
[Cryptographie BLAKE3 & Gouvernance EARS](../core/blake3-governance.md)
{% endcontent-ref %}

---

## POST /api/contracts/update

Met à jour ou insère les contraintes EARS dans le `README.md` le plus proche (en héritant du frontmatter parent lors de la création d'un contrat de sous-dossier), re-scelle `aether.lock.toml` et ré-analyse le projet.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/contracts/update
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | Corps JSON | `string` | Optionnel | Racine projet (par défaut `state.project_root`). |
| `folder` | Corps JSON | `string` | Optionnel | Dossier cible contenant `README.md`. |
| `file_path` | Corps JSON | `string` | Optionnel | Chemin d'un fichier source ; remonte vers le `README.md` le plus proche si `folder` est omis. |
| `max_lines_per_file` | Corps JSON | `number` | Optionnel | Budget de lignes au niveau du dossier. |
| `file_max_lines` | Corps JSON | `number` | Optionnel | Surcharge de budget de lignes par fichier. |
| `clear_file_override` | Corps JSON | `boolean` | Optionnel | Par défaut `false`. Supprime la surcharge par fichier si `true`. |
| `allowed_imports`, `forbidden_imports`, `forbidden_functions`, `allowed_extensions`, `forbidden_extensions` | Corps JSON | `string[]` | Optionnel | Règles de frontières architecturales et de langages. |
| `max_files_per_folder` | Corps JSON | `number` | Optionnel | Limite du nombre de fichiers par dossier (`0` supprime la limite). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "error"` | Note : renvoie HTTP `200 OK` avec `status: "error"` en cas d'échec de `update_contract_rules`. |
| `200 OK` | `message` | `string` | Message de confirmation ou d'erreur. |
| `200 OK` | `contract_path` | `string` | Chemin relatif du `README.md` modifié (note : `api.ts` type ce champ comme `folder`). |
| `200 OK` | `blake3_hash` | `string` | Nouvelle empreinte BLAKE3 du `README.md` (`""` en cas d'erreur). |
| `200 OK` | `file_blake3_hash` | `string` *(optionnel)* | Empreinte BLAKE3 de `file_path` le cas échéant. |
| `200 OK` | `effective_max_lines` | `number` | Limite de lignes effective (`300` par défaut en cas d'erreur). |
| `200 OK` | `graph` | `UiGraphPayload` | Payload du graphe mis à jour. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/contracts/update \
  -H "Content-Type: application/json" \
  -d '{"folder":"server","max_lines_per_file":220,"forbidden_imports":["client::*"]}'
```

---

## POST /api/ai/target

Cible le pont IA zero-shell sur un symbole du graphe : écrit `.aether/ACTIVE_TARGET.md`, génère un paquet XML `<aether_handshake version="2.1">` avec les liaisons catégorisées et masque les éventuels secrets intégrés.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/target
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `symbol_id` | Corps JSON | `string` | **Oui** | Correspond à `node.id`, `node.name`, `node.file_path` ou `::<symbol_id>`. Vérifié par `SecretGuard`. |
| `action_type` | Corps JSON | `string` | Optionnel | Libellé d'action (par défaut `"Target"`). |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "not_found"` | Résultat de la recherche. |
| `200 OK` | `active_target_path` | `string` | Chemin vers `.aether/ACTIVE_TARGET.md`. |
| `200 OK` | `handshake_xml` | `string` | XML `<aether_handshake version="2.1">` masqué via `SecretMasker::mask_text`. |
| `200 OK` | `blake3_hash`, `lock_verified`, `ears_count` | `string?`, `boolean?`, `number` | Métadonnées de vérification du contrat BLAKE3. |
| `200 OK` | `symbol_name`, `file_path`, `layer`, `galaxy`, `docstring` | `string?` | Métadonnées du symbole ciblé. |
| `200 OK` | `callers`, `dependencies` | `string[]` | Identifiants des appelants et dépendances. |
| `200 OK` | `categorized_incoming`, `categorized_outgoing`, `formatted_doc_and_liaisons` | `CategorizedLiaisons?`, `string?` | Détail des liaisons catégorisées et résumé formaté. |
| `403 Forbidden` | `status`, `message` | `string` | Renvoyé si `symbol_id` ou `file_path` déclenche `SecretGuard`. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/target \
  -H "Content-Type: application/json" \
  -d '{"symbol_id":"save_file","action_type":"Audit"}'
```

{% content-ref url="../core/improvements-and-workflows.md" %}
[Améliorations, Workflows & Pare-feu IA](../core/improvements-and-workflows.md)
{% endcontent-ref %}

---

## GET, POST, DELETE /api/ai/telemetry

Gère la télémétrie multi-agents (`AI_AGENT_TTL_SECS = 300` secondes), attribue des couleurs déterministes parmi une palette de 12 teintes par hachage FNV-1a et persiste jusqu'à 250 événements dans `.aether/ai_telemetry_cache.json`.

### 🎮 Endpoint

```text
GET    http://127.0.0.1:3030/api/ai/telemetry
POST   http://127.0.0.1:3030/api/ai/telemetry
DELETE http://127.0.0.1:3030/api/ai/telemetry
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `target` | Corps JSON (`POST`) | `string` | **Oui** | Symbole, fichier ou libellé ciblé. |
| `action` | Corps JSON (`POST`) | `string` | **Oui** | Nom de l'action (ex. `"Inspect"`, `"Audit"`). |
| `details` | Corps JSON (`POST`) | `string` | **Oui** | Description concise de l'activité. |
| `timestamp` | Corps JSON (`POST`) | `number` | Optionnel | Secondes Unix (`0` remplit l'heure courante ; les valeurs `> 1_000_000_000_000` sont converties de ms en s). |
| `agent_id`, `agent_name`, `color` | Corps JSON (`POST`) | `string` | Optionnel | `agent_id` vaut `"primary-agent"` par défaut ; `color` est choisi de manière déterministe dans `AI_AGENT_PALETTE` (12 couleurs) s'il est omis. |

### 💎 Réponse

| Méthode / Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `telemetry`, `agents`, `history` | `AiTelemetryEvent?`, `AiTelemetryEvent[]`, `AiTelemetryEvent[]` | Recharge `.aether/ai_telemetry_cache.json` si vide, purge les agents inactifs depuis plus de `300 s`, trie `agents` du plus récent au plus ancien et renvoie l'historique (max `250` entrées). |
| `POST` (`200 OK`) | `status`, `event` | `"ok"`, `AiTelemetryEvent` | Déduplique les couples `(agent_id, target, action)` identiques espacés de `<= 1 s` dans l'historique et sauvegarde le cache. |
| `DELETE` (`200 OK`) | `status` | `"ok"` | Vide la télémétrie en mémoire et supprime `.aether/ai_telemetry_cache.json`. |

### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/telemetry \
  -H "Content-Type: application/json" \
  -d '{"target":"src/main.rs","action":"Inspect","details":"Auditing LocalGuard","agent_id":"claude-sec","agent_name":"Claude Sec"}'
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

// Note : api.teleportCamera() encapsule POST /api/ai/telemetry
await api.teleportCamera('src/main.rs', 'Inspect', 'Auditing LocalGuard', {
  agent_id: 'claude-sec',
  agent_name: 'Claude Sec',
});
```
{% endtab %}
{% endtabs %}

---

## GET et POST /api/ai/chat

Lit ou ajoute des messages dans le canal de discussion bidirectionnel Cockpit <-> IA et synchronise `.aether/CHAT_INBOX.md` pour le réveil zero-token des agents.

### 🎮 Endpoint

```text
GET  http://127.0.0.1:3030/api/ai/chat
POST http://127.0.0.1:3030/api/ai/chat
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `text` | Corps JSON (`POST`) | `string` | **Oui** | Contenu du message. |
| `sender` | Corps JSON (`POST`) | `string` | Optionnel | Par défaut `"user"`. Passe `.aether/CHAT_INBOX.md` à `PENDING_AI_RESPONSE` si `"user"`, ou `ANSWERED` sinon. |
| `target_symbol`, `agent_id`, `agent_name`, `recipient`, `color` | Corps JSON (`POST`) | `string` | Optionnel | Métadonnées de routage et badge essaim. Un `target_symbol` non vide émis par un agent enregistre également un événement `"Chat / Hand-off"`. |

### 💎 Réponse

| Méthode / Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `messages` | `AiChatMessage[]` | Historique complet (`{ id, sender, text, target_symbol?, timestamp, agent_id?, agent_name?, recipient?, color? }`). |
| `GET` (`200 OK`) | `agent_status` | `"thinking" \| "ready"` | `"thinking"` lorsque le dernier message a `sender == "user"`, sinon `"ready"`. |
| `POST` (`200 OK`) | `status`, `message` | `"ok"`, `AiChatMessage` | Message ajouté (`id: "msg_<ms>"`). |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"text":"Audit auth module","sender":"user","target_symbol":"auth"}'
```

---

## POST /api/ai/chat/clear

Vide `chat_messages` en mémoire et supprime `.aether/CHAT_INBOX.md`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/chat/clear
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun corps requis. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/chat/clear
```

---

## GET /api/ai/status

Renvoie le statut statique du pont IA (`{"status":"idle"}`). L'état temps réel `thinking`/`ready` est exposé sur `GET /api/ai/chat` via `agent_status`.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/ai/status
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | Toujours `"idle"`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/ai/status
```

---

## POST /api/ai/cancel

Efface la `telemetry` active et ajoute un message d'annulation `"ai"` si le dernier message du chat provenait de `"user"`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/cancel
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun corps requis. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `message` | `string` | `"ok"` et `"Requête IA annulée"`. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/cancel
```

---

## POST /api/ai/new_session

Réinitialise la session IA en vidant `chat_messages`, en effaçant la télémétrie et en supprimant `.aether/ai_telemetry_cache.json`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/new_session
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun corps requis. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `message` | `string` | `"ok"` et `"Nouvelle session démarrée"`. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/new_session
```

---

## POST /api/ai/launch_cli

Enregistre et acquitte une demande de lancement d'outil CLI externe sans exécuter de sous-processus terminal sur le serveur.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/launch_cli
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `tool` | Corps JSON | `string` | Optionnel | Identifiant de l'outil (par défaut `"gemini"`). |
| `project_path` | Corps JSON | `string` | Optionnel | Métadonnée du chemin projet cible. |
| `prompt` | Corps JSON | `string` | Optionnel | Métadonnée du prompt initial. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `message`, `tool`, `project_path`, `prompt` | `string` / `null` | Métadonnées renvoyées en écho. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/launch_cli \
  -H "Content-Type: application/json" \
  -d '{"tool":"gemini","project_path":".","prompt":"Audit security"}'
```

---

## GET /api/ai/system_prompt

Détecte la stack du projet actif et génère le prompt système optimisé (incluant `server_port` actif et `AETHER_AI_RULES.md` s'il est présent).

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/ai/system_prompt
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Non | Aucun paramètre de requête ni corps. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `project_name`, `project_path`, `stack`, `system_prompt` | `string` | `stack` détectée parmi `"rust"`, `"python"`, `"php"`, `"cpp"`, `"java"`, `"ts"` ou `"hybrid"`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/ai/system_prompt
```

---

## GET et POST /api/tasks

Liste ou crée des tâches persistantes enregistrées sous `.aether/tasks/<task_id>/task.json` + `README.md` et indexées dans `.aether/TASKS_SUMMARY.md`.

### 🎮 Endpoint

```text
GET  http://127.0.0.1:3030/api/tasks
POST http://127.0.0.1:3030/api/tasks
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `title` | Corps JSON (`POST`) | `string` | **Oui** | Titre de la tâche. |
| `kind` | Corps JSON (`POST`) | `string` | Optionnel | `function` (défaut), `research`, `security_fix`, `arch_refactor`, `documentation`, `test` ou `other`. |
| `target_symbol`, `target_file` | Corps JSON (`POST`) | `string` | Optionnel | Symbole ou fichier ciblé (enregistre `"Création de Tâche"` en télémétrie pour les agents/auteurs non-`user`). |
| `author`, `agent_id`, `agent_name`, `color`, `priority`, `initial_readme` | Corps JSON (`POST`) | `string` | Optionnel | `author` vaut `"user"` par défaut ; `priority` vaut `"medium"` par défaut. |

### 💎 Réponse

| Méthode / Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `status`, `tasks` | `"ok"`, `TaskItem[]` | Tâches triées par `updated_at` décroissant. |
| `POST` (`200 OK`) | `status`, `task` | `"ok"`, `TaskItem` | Tâche créée (ou `{ "status": "error", "message": ... }` en cas d'erreur d'E/S). |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title":"Fix CWE-89","kind":"security_fix","target_file":"src/db.rs","priority":"high"}'
```

---

## POST /api/tasks/update

Met à jour les métadonnées, le statut, la progression ou les notes Markdown d'une tâche dans `.aether/tasks/<task_id>/`, en régénérant `.aether/TASKS_SUMMARY.md`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/tasks/update
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `task_id` | Corps JSON | `string` | **Oui** | Identifiant de la tâche. |
| `status` | Corps JSON | `string` | Optionnel | `pending`, `in_progress`, `blocked`, `done` ou `cancelled`. Passer `done` force `progress = 100`. |
| `progress` | Corps JSON | `number` (`0..=100`) | Optionnel | Fait automatiquement passer `pending` -> `in_progress` si `> 0`, ou `done` si `100`. |
| `progress_note`, `full_readme`, `title`, `target_symbol`, `target_file`, `priority`, `agent_id`, `agent_name`, `color` | Corps JSON | `string` | Optionnel | `progress_note` s'ajoute au `README.md` de la tâche ; `full_readme` le remplace. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "not_found" \| "error"` | `"not_found"` renvoie `message: "Tâche introuvable"`. |
| `200 OK` | `task` | `TaskItem` *(si `"ok"`)* | Objet tâche mis à jour. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/tasks/update \
  -H "Content-Type: application/json" \
  -d '{"task_id":"task_123_fix_cwe_89","status":"done","progress":100,"progress_note":"Parameterized query"}'
```

---

## POST /api/tasks/delete

Supprime le dossier d'une tâche dans `.aether/tasks/` et actualise `.aether/TASKS_SUMMARY.md`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/tasks/delete
```

### 📝 Paramètres

| Nom | Emplacement | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `task_id` | Corps JSON | `string` | **Oui** | Identifiant de la tâche à supprimer. |

### 💎 Réponse

| Statut | Champ | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "error"` | Résultat de l'opération. |
| `200 OK` | `deleted` | `boolean` *(si `"ok"`)* | `true` si la tâche existait et a été supprimée. |

### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/tasks/delete \
  -H "Content-Type: application/json" \
  -d '{"task_id":"task_123_fix_cwe_89"}'
```

## Pour aller plus loin

{% content-ref url="./rest-api-security-plugins.md" %}
[API REST : Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="./mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](./mcp-server.md)
{% endcontent-ref %}
