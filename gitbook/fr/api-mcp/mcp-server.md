# Serveur MCP Natif (aetherscope-mcp)

Connectez vos agents IA à AetherScope via le transport stdio JSON-RPC 2.0 (`2024-11-05`) avec démarrage automatique du backend headless, 10 outils consolidés (et 15 alias rétrocompatibles), 5 ressources `aether://*`, 5 prompts et une télémétrie d'essaim en 12 couleurs.

Le binaire dédié `aetherscope-mcp` (`2.6.0`) fonctionne hors ligne directement sur `.aether/` et les crates AST Rust, ou se connecte au serveur local `127.0.0.1:3030` tout en appliquant `LocalGuard`, `PathGuard`, `SecretGuard` et `SecretMasker`.

{% hint style="info" %}
**Version canonique (`2.6.0`) vs libellés hérités** : `Cargo.toml`, `mcp.json` et `initialize.serverInfo.version` (`env!("CARGO_PKG_VERSION")`) déclarent tous **`2.6.0`**. Deux chaînes de packaging/bannière conservent d'anciens numéros dans le dépôt : `smithery.yaml` indique `version: "2.5.1"` et l'attribut clap `about` dans `crates/desktop-shell/src/mcp_main.rs` affiche `"AetherScope V2.4 - Dedicated MCP Server for AI Agents"`.
{% endhint %}

---

## Modes de lancement & Configuration client

Vous pouvez démarrer le serveur MCP stdio via le binaire dédié `aetherscope-mcp` ou directement via `aether-engine --mcp`.

{% tabs %}
{% tab title="aetherscope-mcp (Auto-Spawn)" %}
```bash
# Lancement par défaut sur le port 3030 ciblant le dossier courant
aetherscope-mcp --port 3030 --path .

# Lancement avec identité d'essaim explicite
aetherscope-mcp --port 3030 --path C:\projects\my-app \
  --agent-id sec-auditor --agent-name "Sec Auditor" --color "#f472b6"
```

Au démarrage, `aetherscope-mcp` :
1. Teste `127.0.0.1:<port>` avec un timeout TCP de `150 ms` (`mcp::check_server_listening`).
2. Si aucun serveur n'écoute, recherche `aether-engine.exe` à côté de `std::env::current_exe()` et lance `aether-engine.exe --no-gui --port <port> --path <path>`.
3. Effectue jusqu'à **10 tentatives × 150 ms** (`1,5 s` max) pour confirmer l'écoute TCP.
4. Démarre `mcp::run_mcp_stdio_loop(port, &path)` même si le backend HTTP n'est pas joignable (repli AST/disque hors ligne).
{% endtab %}
{% tab title="aether-engine --mcp (In-Process)" %}
```bash
# Embarque le serveur Axum et la boucle MCP stdio dans un seul processus
aether-engine --mcp --port 3030 --path .
```

Lorsque `aether-engine --mcp` démarre et que `127.0.0.1:<port>` est libre, il lance `run_server_and_watcher` dans une tâche Tokio interne, patiente `350 ms` et entre dans `mcp::run_mcp_stdio_loop`. Notez que les options `--agent-id`, `--agent-name` et `--color` n'existent que sur `aetherscope-mcp` ; `aether-engine --mcp` s'appuie sur les variables `AETHER_AGENT_*`, `initialize.params.clientInfo.name` ou les arguments par appel d'outil.
{% endtab %}
{% tab title="setup-mcp.ps1 (Auto-Setup)" %}
```powershell
# Configure automatiquement Claude Desktop, Antigravity / Gemini CLI et Cursor
.\setup-mcp.ps1 -Port 3030
```

`setup-mcp.ps1` recherche `aetherscope-mcp.exe` dans `[scriptDir, target\release, %LOCALAPPDATA%\AetherScope\bin]` et fusionne `"aetherscope": { "command": "...", "args": ["--port", "3030"] }` sous `mcpServers` dans :
* `%APPDATA%\Claude\claude_desktop_config.json` (Claude Desktop)
* `%USERPROFILE%\.gemini\config\mcp_config.json` (Antigravity / Gemini CLI)
* `%USERPROFILE%\.cursor\mcp.json` (Cursor)
{% endtab %}
{% endtabs %}

### Options CLI & Fichiers de packaging

| Composant | Options / Clés | Défaut | Remarques |
|---|---|---|---|
| `aetherscope-mcp` (`mcp_main.rs`) | `-p, --path`, `--port`, `--mcp`, `--agent-id`, `--agent-name`, `--color` | `"."`, `3030`, `false` | Démarre automatiquement `aether-engine.exe --no-gui` si le port est libre. |
| `mcp.json` | `name`, `version`, `capabilities`, `mcpServers.aetherscope` | `2.6.0`, `--port 3030 --path .` | Manifeste standard déclarant `tools`, `resources` et `prompts`. |
| `smithery.yaml` | `startCommand.type: stdio`, `configSchema.{port, path}` | `3030`, `"."` | Exécute `aetherscope-mcp --port <port> --path <path>` (`version: "2.5.1"`). |
| `GET /api/settings` | `mcp_binary_path` | `aetherscope-mcp(.exe)` adjacent | Expose le chemin résolu pour la configuration rapide dans le Cockpit. |

---

## Protocole JSON-RPC 2.0 & Transport

`run_mcp_stdio_loop` lit des lignes UTF-8 JSON-RPC 2.0 sur `stdin`, retire un éventuel BOM UTF-8 (`\u{feff}`), ignore les lignes vides et écrit des réponses JSON sur une ligne immédiatement flushées sur `stdout`.

| Méthode | Rôle | Erreurs & Comportement |
|---|---|---|
| `initialize` | Enregistre `params.clientInfo.name`, émet la télémétrie `"Connexion MCP"` et retourne `protocolVersion: "2024-11-05"`, `capabilities` et `serverInfo` (avec `agentIdentity`). | `capabilities` définit `listChanged: false` et `subscribe: false`. |
| `notifications/initialized` | Notification de disponibilité du client. | Retourne `None` (aucune réponse émise sur `stdout`). |
| `ping` | Vérification de disponibilité. | Retourne `{}`. |
| `resources/list` | Liste les 5 ressources `aether://*`. | — |
| `resources/read` | Lit une ressource via `params.uri`. | Retourne `-32602` (`"Resource not found: <uri>"`) si l'URI est inconnue. |
| `prompts/list` | Liste les 5 prompts de workflow. | — |
| `prompts/get` | Génère les messages du prompt via `params.name` et `params.arguments`. | Retourne `-32602` (`"Prompt not found: <name>"`) si le nom est inconnu. |
| `tools/list` | Liste les 10 outils consolidés (hors des 15 alias hérités). | Chaque outil impose `additionalProperties: false` et les 4 indices MCP. |
| `tools/call` | Exécute un outil consolidé ou un alias hérité via `params.name` et `params.arguments`. | Retourne `{ content: [{ type: "text", text }], isError }`. |

Un JSON mal formé renvoie `-32700` (`"Parse error: ..."`) et une méthode inconnue renvoie `-32601` (`"Method not found"`).

---

## Identité d'Essaim Multi-Agents & Mode Hors Ligne

Lorsque plusieurs agents IA analysent le même projet simultanément, AetherScope attribue à chacun un badge et une couleur distincte dans le HUD 3D du Cockpit et le tiroir de chat.

### Ordre de priorité & Palette de 12 couleurs

L'identité est résolue selon cette priorité stricte :
1. **Arguments par appel d'outil** : `agent_id` (ou `agent`, `caller`, `author`, `sender`, `role`), `agent_name` (ou `name`) et `color`.
2. **Options CLI** : `--agent-id`, `--agent-name`, `--color` sur `aetherscope-mcp` (active `explicit_identity = true`).
3. **Variables d'environnement** : `AETHER_AGENT_ID`, `AETHER_AGENT_NAME`, `AETHER_AGENT_COLOR`.
4. **Handshake MCP** : `initialize.params.clientInfo.name` (si `explicit_identity` vaut `false`, génère `{slug}-{pid % 10000}` et `{clean_name} (#{pid % 1000})`).
5. **Repli processus** : `mcp-agent-{pid % 10000}` et `IA MCP #{pid % 1000}`.

Si `color` est omis, `mcp_assign_agent_color` calcule un **hash FNV-1a 64 bits** (`init = 14695981039346656037`, `prime = 1099511628211`) sur `"{agent_id}:{agent_name}"` (retourne `#38bdf8` si vide ou `primary-agent:`) modulo 12 dans `MCP_AGENT_PALETTE` :

| Index | Hex | Libellé | Index | Hex | Libellé |
|---|---|---|---|---|---|
| `0` | `#38bdf8` | Cyan (Sky) | `6` | `#22d3ee` | Bright Cyan |
| `1` | `#c084fc` | Purple | `7` | `#fb7185` | Rose |
| `2` | `#34d399` | Emerald | `8` | `#818cf8` | Indigo |
| `3` | `#f472b6` | Pink | `9` | `#fb923c` | Orange |
| `4` | `#f59e0b` | Amber | `10` | `#2dd4bf` | Teal |
| `5` | `#a3e635` | Lime | `11` | `#e879f9` | Fuchsia |

### Cache de télémétrie & Transport HTTP `LocalGuard`

* **Persistance locale** : `emit_mcp_telemetry` écrit dans `.aether/ai_telemetry_cache.json` (`{ telemetry, agents, history }`, dédupliquant les doublons consécutifs `(agent_id, target, action)` et limitant `history` à `250` entrées) avant de tenter `POST /api/ai/telemetry`.
* **Client HTTP brut** : `send_http_request` se connecte à `127.0.0.1:<port>` (`1500 ms` connexion, `45 s` lecture, `30 s` écriture) avec `Host: 127.0.0.1:<port>` et **sans en-tête `Origin`**, validant `LocalGuard`.
* **Exécution hors ligne** : Si le serveur Axum est absent, les outils de graphe, cible, recherche, mode de vue, tâches, vérification et plugins s'exécutent directement sur les crates locales (`ast_scanner`, `obsidian_vault`, `ai_file_bridge`, `security_linter`). Seul `aetherscope_chat` (`send` et `history`) exige le serveur HTTP actif (`/api/ai/chat`) et retourne `isError: true` s'il est inaccessible.

---

## Outils MCP Consolidés (10 Outils)

Les 10 outils exposés par `tools/list` déclarent `additionalProperties: false` et fournissent les 4 indices MCP (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) à la racine et sous `annotations`. Tous acceptent également les surcharges d'essaim optionnelles `agent_id`, `agent_name` et `color`.

### 1. `aetherscope_get_graph_summary`

Résume la topologie AST du projet, les violations SAST/CWE, les tâches actives et les alertes de chat en attente.

#### 🎮 Outil

```text
aetherscope_get_graph_summary
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `path` | `string` | Non | Racine du projet (par défaut `--path` du serveur). |
| `rescan` | `boolean` | Non | Force `POST /api/analyze` avant le résumé (défaut `false`). |
| `include_tasks` | `boolean` | Non | Ajoute jusqu'à 10 tâches actives (hors `Done`/`Cancelled`) depuis `TaskManager` (défaut `true`). |
| `severity` | `string` | Non | Filtre de violations optionnel : `"all"`, `"critical"`, `"high"`, `"medium"`, `"low"` ou `"warning"`. |
| `agent_id` / `agent_name` / `color` | `string` | Non | Surcharges optionnelles d'identité d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Résumé AST formaté, tâches actives optionnelles, ventilation par sévérité et alerte `PENDING_AI_RESPONSE` si `.aether/CHAT_INBOX.md` attend une réponse. |
| `isError` | `boolean` | `false` en cas de succès ; `true` si l'analyse échoue. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_get_graph_summary",
    "arguments": { "path": ".", "rescan": false, "include_tasks": true, "severity": "critical" }
  }
}
```

---

### 2. `aetherscope_get_active_target`

Inspecte un symbole, un fichier ou une note Obsidian, récupère son contrat EARS `<aether_handshake>`, ses appelants/dépendances et trace son flux.

#### 🎮 Outil

```text
aetherscope_get_active_target
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `symbol_id` | `string` | **Oui** | ID/nom de symbole, chemin relatif de fichier ou ID de note Obsidian (`note::...`). |
| `action` | `string` | Non | Badge d'action dans le HUD 3D (défaut `"Inspection"`). |
| `details` | `string` | Non | Note de télémétrie courte (défaut `"Inspection combinée Cible + Contrat EARS + Flux"`). |
| `trace_direction` | `string` | Non | Direction du flux : `"both"` (défaut), `"upstream"`, `"downstream"` ou `"none"`. |
| `max_depth` | `integer` | Non | Profondeur `1..=5` (défaut `2`). Remarque : `format_trace_flow_response` inspecte actuellement les arêtes directes à 1 saut (`take(15)`). |
| `path` / `agent_id` / `agent_name` / `color` | `string` | Non | Chemin de projet et surcharges d'essaim optionnels. |

{% hint style="danger" %}
**SecretGuard & SecretMasker** : Tout chemin correspondant à `SecretGuard::is_secret_path` (`.env`, clés SSH, identifiants) est immédiatement bloqué avec `isError: true`, et tout texte retourné est filtré par `SecretMasker::mask_text`.
{% endhint %}

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | XML de handshake de la cible, règles EARS du contrat, statut BLAKE3 et trace amont/aval. |
| `isError` | `boolean` | `true` si bloqué par `SecretGuard` ou symbole introuvable. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_get_active_target",
    "arguments": { "symbol_id": "handle_booking", "trace_direction": "both", "max_depth": 2 }
  }
}
```

---

### 3. `aetherscope_search_symbols`

Recherche des symboles, fichiers, violations CWE, notes/tags Obsidian et gère le filtrage de périmètre Bug Bounty PoC.

#### 🎮 Outil

```text
aetherscope_search_symbols
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `query` | `string` | Non | Mot-clé, `#tag`, alias YAML ou titre (défaut `""`). |
| `layer` | `string` | Non | `"ui"`, `"action"`, `"domain"`, `"database"`, `"utility"`, `"config"`, `"docs"` ou `"all"`. |
| `kind` | `string` | Non | `"function"`, `"file"`, `"class"`, `"endpoint"`, `"contract"` ou `"all"`. |
| `stereotype` | `string` | Non | Filtre stéréotype tel que `'«Model»'`, `'«Controller»'`, `'«Note»'`, `'«GhostNote»'` ou `'«Attachment»'`. |
| `has_violation` | `boolean` | Non | Filtre les symboles porteurs de violations SAST (forcé à `true` si `cwe_id` ou `severity` est fourni). |
| `cwe_id` / `severity` / `file_pattern` | `string` | Non | Filtre CWE (ex. `"CWE-89"`), sévérité (`"all"`, `"critical"`, `"high"`, `"medium"`, `"low"`, `"warning"`) et motif de fichier. |
| `limit` | `integer` | Non | Nombre maximal de résultats `1..=50` (défaut `15`). |
| `scope_mode` | `string` | Non | Action/filtre Bug Bounty : `"all"` (défaut), `"in_scope_only"`, `"out_of_scope_only"`, `"recommend_scope"` ou `"configure_scope"`. |
| `in_scope` / `out_of_scope` | `string[]` | Non | Listes de dossiers enregistrées dans `.aether/bounty_scope.json` avec `scope_mode="configure_scope"`. |
| `scope_rationale` | `string` | Non | Justification enregistrée dans `BountyScopeConfig`. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | Non | Chemin de projet et surcharges d'essaim optionnels. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Symboles/notes/violations correspondants (hors chemins `SecretGuard` et masqués par `SecretMasker::mask_text`), ou configuration/recommandations de périmètre. |
| `isError` | `boolean` | `false` en cas de succès. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_search_symbols",
    "arguments": { "cwe_id": "CWE-89", "scope_mode": "in_scope_only", "limit": 10 }
  }
}
```

---

### 4. `aetherscope_switch_view_mode`

Bascule le mode de rendu du Cockpit entre l'AST du code source (`"code"`) et le coffre Markdown Obsidian (`"vault"`).

#### 🎮 Outil

```text
aetherscope_switch_view_mode
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `mode` | `string` | **Oui** | `"code"` ou `"vault"`. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | Non | Chemin du projet (utilisé en repli hors ligne `detect_project_type`) et identité d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Confirmation du mode actif (via `POST /api/view_mode` ou repli hors ligne `obsidian_vault::detect_project_type`). |
| `isError` | `boolean` | `true` si le mode est invalide. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_switch_view_mode",
    "arguments": { "mode": "vault" }
  }
}
```

---

### 5. `aetherscope_manage_tasks`

Liste, crée, met à jour ou supprime les tâches IA persistantes sous `.aether/tasks/` et `.aether/TASKS_SUMMARY.md`.

#### 🎮 Outil

```text
aetherscope_manage_tasks
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `action` | `string` | **Oui** | `"list"`, `"create"`, `"update"` ou `"delete"`. |
| `task_id` | `string` | Conditionnel | Requis à l'exécution pour `"update"` et `"delete"`. |
| `title` | `string` | Non | Titre de la tâche (par défaut `"Nouvelle tâche"` pour `"create"`). |
| `kind` | `string` | Non | `"function"` (défaut), `"research"`, `"security_fix"`, `"arch_refactor"`, `"documentation"`, `"test"` ou `"other"`. |
| `target_symbol` / `target_file` | `string` | Non | Symbole et fichier cibles ; émet une télémétrie caméra 3D sur `"create"`/`"update"`. |
| `priority` | `string` | Non | `"low"`, `"medium"`, `"high"` ou `"critical"`. |
| `status` | `string` | Non | `"pending"`, `"in_progress"`, `"blocked"`, `"done"` ou `"cancelled"` (utilisé sur `"update"`). |
| `progress` | `integer` | Non | Avancement `0..=100` (utilisé sur `"update"`). |
| `progress_note` | `string` | Non | Note horodatée ajoutée au `README.md` de la tâche. |
| `initial_readme` / `full_readme` | `string` | Non | Markdown initial sur `"create"` ou Markdown complet de remplacement sur `"update"`. |
| `status_filter` | `string` | Non | Filtre pour `"list"` : `"active"` (défaut), `"all"` ou `"done"` (accepte aussi l'ancien champ `status`). |
| `path` / `agent_id` / `agent_name` / `color` | `string` | Non | Chemin de projet et surcharges d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Liste des tâches formatée ou confirmation de création/mise à jour/suppression. |
| `isError` | `boolean` | `true` si `task_id` est absent/introuvable ou en cas d'erreur I/O. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_manage_tasks",
    "arguments": {
      "action": "create",
      "title": "Parameterize SQL query",
      "kind": "security_fix",
      "target_file": "src/db.rs",
      "priority": "high"
    }
  }
}
```

---

### 6. `aetherscope_verify_patch`

Exécute le pare-feu IA `<50ms` `PatchVerifier` sur les fichiers modifiés (verrous BLAKE3, limites EARS, imports interdits et régressions SAST/CWE), avec mise à jour optionnelle de tâche et debrief chat.

#### 🎮 Outil

```text
aetherscope_verify_patch
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `files_modified` | `string[]` | **Oui** | Liste non vide de chemins relatifs modifiés à auditer. |
| `task_id` | `string` | Non | ID de tâche mis à jour automatiquement si le patch n'est **pas** rejeté. |
| `status` | `string` | Non | Statut de tâche si `task_id` est fourni (`"done"` par défaut). |
| `progress` | `integer` | Non | Progression `0..=100` si `task_id` est fourni (`100` par défaut). |
| `progress_note` | `string` | Non | Note ajoutée si `task_id` est fourni (`"Patch validé par aetherscope_verify_patch"` par défaut). |
| `chat_message` | `string` | Non | Message de synthèse publié sur `POST /api/ai/chat` si le patch est validé. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | Non | Chemin de projet et surcharges d'essaim. |

{% hint style="danger" %}
**Rejet immédiat `PATCH_REJECTED`** : Si un chemin de `files_modified` correspond à `SecretGuard::is_secret_path` ou si `PatchVerifier::verify_patch` retourne `PatchVerdict::Rejected`, l'outil retourne `isError: true` et annule toute mise à jour automatique de tâche ou de chat.
{% endhint %}

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Verdict du pare-feu (`APPROVED` / `WARNING` / `PATCH_REJECTED`), détails des violations EARS/SAST et confirmation éventuelle de tâche. |
| `isError` | `boolean` | `true` en cas de rejet ou si `files_modified` est vide. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_verify_patch",
    "arguments": {
      "files_modified": ["src/db.rs"],
      "task_id": "task_123_fix_sql",
      "chat_message": "Replaced string concatenation with bound parameters."
    }
  }
}
```

---

### 7. `aetherscope_chat`

Envoie des messages ou hand-offs au tiroir de chat du Cockpit, lit l'historique récent ou liste les agents actifs de l'essaim.

#### 🎮 Outil

```text
aetherscope_chat
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `action` | `string` | Non | `"send"`, `"history"` ou `"swarm"`. Vaut `"send"` par défaut si `text` est non vide, sinon `"history"`. |
| `text` | `string` | Conditionnel | Corps du message (requis non vide pour `action="send"`). |
| `thought` | `string` | Non | Raisonnement optionnel encapsulé dans `<thought>\n...\n</thought>\n` avant `text`. |
| `target_symbol` | `string` | Non | Symbole ciblé ; émet une télémétrie `"Debrief Chat IA"` si non vide. |
| `recipient` | `string` | Non | Destinataire sur `"send"`, ou filtre insensible à la casse sur `"history"` (`recipient == filter \|\| recipient == "all" \|\| text.contains("@filter")`). |
| `agent_id` / `agent_name` / `color` | `string` | Non | Surcharges d'identité d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Confirmation d'envoi, historique filtré ou liste des agents actifs de l'essaim. |
| `isError` | `boolean` | `true` si `"send"` ou `"history"` est appelé sans serveur HTTP Axum actif. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_chat",
    "arguments": {
      "action": "send",
      "text": "@sec-auditor Please review src/auth.rs",
      "target_symbol": "verify_jwt",
      "recipient": "sec-auditor"
    }
  }
}
```

---

### 8. `aetherscope_manage_plugins`

Liste, teste unitairement, scanne avec, crée/met à jour, active/désactive ou déploie des plugins déclaratifs YAML/JSON SAST et taint SSA dans `.aether/plugins/`.

#### 🎮 Outil

```text
aetherscope_manage_plugins
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `action` | `string` | **Oui** | `"list"`, `"test"`, `"scan"`, `"upsert"`, `"toggle"` ou `"init_bundle"`. |
| `target_path` | `string` | Conditionnel | Requis pour `"scan"` ; confiné par `SecretGuard` et la vérification canonique `PathGuard` dans la racine du projet. |
| `plugins_dir` | `string` | Non | Répertoire des plugins (`".aether/plugins"` par défaut). |
| `plugin_name` | `string` | Conditionnel | Requis pour `"upsert"` (strictement `[a-zA-Z0-9_-]`) et `"toggle"`. |
| `enabled` | `boolean` | Conditionnel | Requis pour `"toggle"`. |
| `rule_id` / `cwe_id` / `file_extensions` | `string` / `string` / `string[]` | Conditionnel | Requis à l'exécution pour `"upsert"`. |
| `profile` / `tags` / `name` / `description` / `remediation` / `category` | mixte | Non | Métadonnées optionnelles pour `"upsert"` (`category` vaut `"Custom / Security"` par défaut). |
| `severity` / `match_mode` | `string` | Non | `severity` : `"CRITICAL"`, `"HIGH"` (défaut), `"MEDIUM"`, `"WARNING"`, `"LOW"`. `match_mode` : `"line_by_line"` (défaut) ou `"whole_file"`. |
| `must_contain` / `must_not_contain` / `regex_patterns` / `forbidden_tokens` | `string[]` | Non | Conditions de correspondance pour `"upsert"`. |
| `check_literals` | `boolean` | Non | Inclure littéraux et commentaires (défaut `false`). |
| `not_preceded_within_lines` | `object` | Non | `{ "patterns": string[], "lines": integer >= 1 }`. |
| `in_path_matching` / `not_in_path_matching` | `string[]` | Non | Globs d'inclusion/exclusion de chemins. |
| `ast_scope` | `string` | Non | `"outside_test"`, `"test"`, `"async_fn"`, `"sync_fn"` ou `"fn"`. |
| `taint_sources` / `taint_sinks` / `sanitizers` | `object[]` | Non | Objets `TaintSourceRule`, `TaintSinkRule` et `SanitizerRule`. |
| `test_cases` | `object[]` | Non | Tableau `{ name, code, file_name, should_trigger }` vérifié par `run_test_suite()` avant l'écriture de `<plugins_dir>/<plugin_name>/plugin.yaml`. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | Non | Chemin du projet et surcharges d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Inventaire des plugins, rapport de tests, alertes de scan confinées (masquées par `SecretMasker`) ou confirmation upsert/toggle. |
| `isError` | `boolean` | `true` si le confinement échoue, si des paramètres manquent ou si les tests unitaires échouent lors d'un `upsert`. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_manage_plugins",
    "arguments": { "action": "init_bundle" }
  }
}
```

---

### 9. `aetherscope_teleport_camera`

Centre la caméra du Cockpit 3D sur un symbole ou fichier et diffuse un badge de télémétrie (ainsi que la liste des pairs actifs si plusieurs agents sont connectés).

#### 🎮 Outil

```text
aetherscope_teleport_camera
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `target` | `string` | **Oui** | Nom de symbole, structure ou chemin relatif (ex. `"RoomBooking"`, `"contracts/packets.rs"`). |
| `action` | `string` | **Oui** | Verbe court affiché dans le HUD 3D (repli runtime `"Inspection"`). |
| `details` | `string` | **Oui** | Note de statut concise affichée à l'utilisateur (repli runtime `""`). |
| `agent_id` / `agent_name` / `color` | `string` | Non | Surcharges d'identité d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Confirmation d'envoi de télémétrie, plus la liste des pairs actifs lorsque `peers.len() > 1`. |
| `isError` | `boolean` | `false` |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_teleport_camera",
    "arguments": {
      "target": "BookingEngine",
      "action": "Audit",
      "details": "Checking lock contention on seat allocation"
    }
  }
}
```

---

### 10. `aetherscope_scan_project`

Déclenche une analyse complète AST, contrats BLAKE3 et SAST/CWE du projet (ou un scan de coffre Obsidian en mode double vision).

#### 🎮 Outil

```text
aetherscope_scan_project
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Nom | Type | Requis | Description |
|---|---|---|---|
| `path` | `string` | Non | Racine du projet (par défaut `--path` du serveur). |
| `agent_id` / `agent_name` / `color` | `string` | Non | Surcharges d'identité d'essaim. |

#### 💎 Valeur de retour

| Champ | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Statut du scan et compteurs nœuds/arêtes/violations (via `POST /api/analyze` ou repli hors ligne `ProjectScanner` / `scan_obsidian_vault`). |
| `isError` | `boolean` | `true` si l'analyse échoue. |

#### 💡 Exemple

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "aetherscope_scan_project",
    "arguments": { "path": "." }
  }
}
```

---

## Alias d'Outils Hérités (15 Alias)

Bien que `tools/list` n'annonce que les 10 outils consolidés ci-dessus, `tools/call` conserve une rétrocompatibilité complète avec les 15 anciens noms d'outils :

| Ancien nom d'outil | Outil consolidé cible | Correspondance automatique des arguments |
|---|---|---|
| `aetherscope_list_tasks` | `aetherscope_manage_tasks` | `action: "list"` |
| `aetherscope_create_task` | `aetherscope_manage_tasks` | `action: "create"` |
| `aetherscope_update_task` | `aetherscope_manage_tasks` | `action: "update"` |
| `aetherscope_delete_task` | `aetherscope_manage_tasks` | `action: "delete"` |
| `aetherscope_send_chat_message` | `aetherscope_chat` | `action: "send"` |
| `aetherscope_get_chat_history` | `aetherscope_chat` | `action: "history"` |
| `aetherscope_get_swarm_state` | `aetherscope_chat` | `action: "swarm"` |
| `aetherscope_list_plugins` | `aetherscope_manage_plugins` | `action: "list"` |
| `aetherscope_test_plugins` | `aetherscope_manage_plugins` | `action: "test"` |
| `aetherscope_scan_with_plugins` | `aetherscope_manage_plugins` | `action: "scan"` |
| `aetherscope_upsert_plugin_rule` | `aetherscope_manage_plugins` | `action: "upsert"` |
| `aetherscope_toggle_plugin` | `aetherscope_manage_plugins` | `action: "toggle"` |
| `aetherscope_init_plugin_bundle` | `aetherscope_manage_plugins` | `action: "init_bundle"` |
| `aetherscope_trace_flow` | `aetherscope_get_active_target` | `direction` (`"both"` par défaut) et `max_depth` (`2` par défaut) |
| `aetherscope_query_violations` | `aetherscope_get_graph_summary` / `aetherscope_search_symbols` | Filtre par `severity` ou `cwe_id` + `file_pattern` |

---

## Ressources MCP (5 URI `aether://*`)

Interrogez l'état du projet directement via `resources/read` :

| URI | Nom | Type MIME | Source active & Repli hors ligne |
|---|---|---|---|
| `aether://graph/summary` | `AetherScope 3D AST Graph Summary` | `application/json` | Actif : `GET /api/graph?full=1`. Hors ligne : `ProjectScanner::default().scan_project(&default_path)` en JSON formaté. |
| `aether://audit/live` | `AetherScope Live Security Audit (SAST/CWE)` | `text/markdown` | Lit `<default_path>/.aether/LIVE_AUDIT.md` ; sinon scanne et exécute `format_ast_summary`. |
| `aether://contracts/manifest` | `Aether Architecture Manifest` | `application/json` | Lit `aether.manifest.json`, puis `.aether/manifest.json`, puis `aether.lock.toml` brut ; sinon `{"status": "unlocked", ...}`. |
| `aether://tasks/active` | `AetherScope Active AI Tasks` | `application/json` | `TaskManager::list_tasks` filtré sans `Done` ni `Cancelled`. |
| `aether://agents/swarm` | `AetherScope Multi-Agent Swarm & Chat` | `application/json` | Interroge `GET /api/ai/telemetry` (`agents`) et `GET /api/ai/chat` (20 derniers messages). |

---

## Prompts MCP (5 Prompts de Workflow)

Déclenchez des workflows guidés normalisés via `prompts/get` :

| Nom du prompt | Arguments | Séquence de workflow générée |
|---|---|---|
| `diagnostic_session_start` | `path` (optionnel, défaut `"."`) | 1) `aetherscope_get_graph_summary` (`rescan: false, include_tasks: true`) -> 2) `aetherscope_search_symbols` (`has_violation: true, severity: "critical"`) -> 3) `aetherscope_get_active_target` (`trace_direction: "both"`). |
| `surgical_feature_workflow` | `symbol_id` (**requis**), `objective` (**requis**) | 1) `aetherscope_get_active_target` -> 2) `aetherscope_manage_tasks` (`create`, `kind: "function"`, `priority: "high"`) -> 3) modification respectant les invariants EARS du `README.md` parent -> 4) `aetherscope_verify_patch` (`status: "done", progress: 100`). |
| `audit_security_cwe` | `symbol_name` (**requis**), `cwe_id` (optionnel, défaut `"CWE Anomaly"`) | 1) `aetherscope_get_active_target` -> 2) `aetherscope_search_symbols` (`cwe_id`, `has_violation: true`) -> 3) `aetherscope_manage_tasks` (`create`, `kind: "security_fix"`, `priority: "critical"`) -> 4) `aetherscope_verify_patch`. |
| `refactor_contract_violation` | `contract_name` (**requis**), `violation_details` (optionnel) | 1) `aetherscope_get_active_target` -> 2) `aetherscope_manage_tasks` (`create`, `kind: "arch_refactor"`, `priority: "high"`) -> 3) correction `RULE_FORBIDDEN_IMPORT` / `RULE_MAX_LINES` / EARS -> 4) `aetherscope_verify_patch`. |
| `scaffold_game_server` | `engine` (**requis** : `'roblox'` \| `'minecraft'`), `package_name` (**requis**) | Oriente vers Roblox Luau (`--!strict`, `contracts/`, `server/`, `client/`, `data-nodes/`) ou Minecraft Paper/Purpur (budget tick Main Thread `50ms`, `AsyncScheduler`) ; exécute `aetherscope_manage_tasks(create)` -> `aetherscope_verify_patch`. |

---

## Guides associés

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[CLI des Plugins, MCP & Runner](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="../core/improvements-and-workflows.md" %}
[Améliorations, PatchVerifier & Pare-feu IA](../core/improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité & Garde-fous](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-security-plugins.md" %}
[API REST : Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}
