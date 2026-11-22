# Scaffolder d'Architecture Multi-Stack

`ArchScaffolder` génère des squelettes de projets polyglottes prêts pour la gouvernance, avec `aether.lock.toml`, 11 contrats `README.md` EARS en couches, des empreintes cryptographiques BLAKE3 et du code de démarrage adapté à votre stack.

## Vue d'ensemble

Au lieu d'assembler manuellement vos répertoires et règles d'architecture, vous pouvez initialiser un nouveau projet depuis le **Project Hub** du Cockpit ou via `POST /api/init_project`. Sous le capot, `crates/arch-templates` construit un `ProjectManifest` (`version = 2`), tandis que `crates/desktop-shell` matérialise l'arborescence, signe les contrats en BLAKE3 et génère `AETHER_AI_RULES.md`.

{% hint style="info" %}
Chaque projet échafaudé active par défaut les quatre protections `GuardrailSettings` : `block_forbidden_imports`, `enforce_ears_syntax`, `sast_strict_mode` et `require_signature_on_contract_change`.
{% endhint %}

## Templates de stacks supportés

`ArchScaffolder::create_manifest` (`crates/arch-templates/src/templates.rs`) prend en charge 7 variantes `StackType`. Chaque template définit un ensemble de galaxies dans `aether.lock.toml` et génère les fichiers de démarrage correspondants via `init_project_structure_with_topology` (`crates/desktop-shell/src/api_routes.rs`).

| Variante `StackType` | Alias API / UI `stack` | Galaxies dans `aether.lock.toml` | Fichiers de démarrage générés |
| :--- | :--- | :--- | :--- |
| `PureRust` | `rust` | `contracts`, `client`, `server`, `data-nodes` | `contracts/src/lib.rs`, `server/domain/src/lib.rs`, `server/application/src/lib.rs`, `server/api/src/lib.rs`, `client/ui/src/form.rs`, `data-nodes/db-primary/src/lib.rs` |
| `PurePythonUv` | `python` | `contracts`, `client`, `server`, `data-nodes` | `contracts/schemas.py`, `server/domain/models.py`, `server/api/router.py`, `client/ui/form.py` |
| `PureNodePnpm` | `ts`, `node` | `contracts`, `client`, `server`, `data-nodes` | `contracts/index.ts`, `server/domain/pricing.ts`, `server/api/routes.ts`, `client/ui/BookingForm.tsx` |
| `HybridMmoWeb3` *(défaut)* | `hybrid` *(ou toute chaîne non reconnue)* | `contracts`, `client`, `data-nodes`, `server` | `contracts/packets.rs`, `server/domain/world.rs`, `server/api/websocket.rs`, `client/ui/GameCanvas.ts` |
| `RobloxLuau` | `roblox`, `roblox-server`, `luau` | `contracts`, `server`, `client`, `data-nodes` | `contracts/NetworkContracts.luau`, `contracts/Types.luau`, `server/ServerController.luau`, `server/domain/CombatService.luau`, `client/ClientController.luau`, `data-nodes/DataStoreServiceAdapter.luau`, `default.project.json`, `wally.toml`, `selene.toml` |
| `MinecraftServer` | `minecraft`, `mc` | `contracts`, `server`, `plugins`, `data-nodes` | `contracts/AETHER_MC_MANIFEST_SPEC.md`, `server/server.properties`, `server/start.bat`, `server/start.sh`, `server/paper-global.yml`, `plugins/README.md` |
| `ClassicMvc` | `mvc`, `classic-mvc`, `clean-mvc` | `models`, `views`, `controllers`, `services`, `data-nodes` | `models/README.md`, `views/README.md`, `controllers/README.md`, `services/README.md` |

## Modes de topologie : MonorepoLocal vs Dissociated

`TopologyMode` (`crates/core-graph/src/manifest.rs`) détermine si toutes les galaxies résident dans un dépôt unique ou s'étendent sur des services distribués :

* **`MonorepoLocal`** (alias API : `"local"`, par défaut) : toutes les galaxies utilisent des chemins relatifs locaux (`./contracts`, `./client`, `./server`, `./data-nodes`) avec `remote_sync = false` et `remote_endpoint = None`.
* **`Dissociated`** (alias API : `"dissociated"`, `"distributed"`) : indique une topologie distribuée dans `aether.lock.toml`. Pour `HybridMmoWeb3`, la galaxie `server` active automatiquement `remote_sync = true` et définit `remote_endpoint = "wss://game-server.internal/aether-sync"`.

{% code title="aether.lock.toml (extrait HybridMmoWeb3 + Dissociated)" overflow="wrap" %}
```toml
version = 2
project_id = "my-mmo"
stack_type = "HybridMmoWeb3"
topology_mode = "Dissociated"

[galaxies.server]
path = "./server"
role = "Rust WebSocket high-concurrency game loop and domain services"
remote_sync = true
remote_endpoint = "wss://game-server.internal/aether-sync"
readme_blake3 = "<empreinte hex 64 caractères>"

[guardrails]
block_forbidden_imports = true
enforce_ears_syntax = true
sast_strict_mode = true
require_signature_on_contract_change = true
```
{% endcode %}

## Squelette à 11 dossiers EARS et scellement BLAKE3

Quelle que soit la stack choisie, `init_project_structure_with_topology` crée une **architecture en couches standardisée à 11 dossiers** et place dans chaque répertoire un `README.md` à en-tête YAML (`ReadmeFrontmatter`) accompagné d'exigences EARS (`WHEN ... THE SYSTEM SHALL ...`).

| Dossier | `id` | `layer` | `max_lines_per_file` | `allowed_imports` | `forbidden_imports` | Règles `security_rules` / EARS clés |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `contracts` | `contracts` | `contracts` | `200` | `[]` | `client::*`, `server::*` | Valide les schémas d'API et la sûreté de type des réponses serveur |
| `client` | `client` | `ui` | `300` | `contracts::*` | `server::domain::*`, `data-nodes::*` | Met à jour l'état local réactif lors des interactions utilisateur |
| `client/ui` | `client-ui` | `ui` | `250` | `contracts::*`, `client/state::*` | `server::*` | Déclenche la validation côté client à la soumission des formulaires |
| `client/state` | `client-state` | `ui` | `200` | `contracts::*` | `server::domain::*` | Isolation de l'état client local |
| `server` | `server` | `domain` | `300` | `contracts::*` | `client::*` | `no_raw_sql: true`, `no_env_access: true` |
| `server/domain` | `server-domain` | `domain` | `200` | `[]` | `server/api::*`, `client::*`, `data-nodes::*` | `deterministic_only: true` ; évaluation métier pure sans I/O |
| `server/application` | `server-app` | `action` | `250` | `server/domain::*`, `contracts::*` | `client::*` | Couche d'orchestration des cas d'usage |
| `server/api` | `server-api` | `action` | `250` | `server/application::*`, `contracts::*` | `server/domain::*` | Route les paquets réseau via les schémas `contracts` |
| `data-nodes` | `data-nodes` | `database` | `300` | `contracts::*` | `client::*` | Frontière de persistance |
| `data-nodes/db-primary` | `db-primary` | `database` | `250` | `contracts::*` | `client::*` | Adaptateur de base de données primaire |
| `data-nodes/cache-worker` | `cache-worker` | `utility` | `200` | `contracts::*` | `client::*` | Cache et worker d'arrière-plan |

Juste après la création des 11 dossiers, le scaffolder exécute deux étapes de gouvernance :

1. **Scellement des contrats BLAKE3** : appelle `sign_project_contracts(base, None)`, qui calcule l'empreinte hexadécimale BLAKE3 sur 64 caractères de chaque `README.md` et l'inscrit dans `galaxies.<folder>.readme_blake3` au sein de `aether.lock.toml` (en ajoutant automatiquement les sous-dossiers tels que `"client/ui"`).
2. **Génération des règles IA** : appelle `AuditWriter::generate_optimized_system_prompt` (`crates/ai-file-bridge/src/audit_writer.rs`) pour créer `AETHER_AI_RULES.md` à la racine du projet avec 6 sections couvrant le workflow MCP en 3 appels, les 10 outils `aetherscope_*`, les règles EARS/BLAKE3 sans shell, les invariants par couche, l'atomicité `< 35` lignes et les contraintes `SecretGuard`/`SecretMasker`.

{% hint style="warning" %}
`sign_project_contracts` s'exécute **avant** l'écriture des fichiers de démarrage propres à chaque stack. Pour `MinecraftServer` (`plugins/README.md`) et `ClassicMvc` (`models/README.md`, `views/README.md`, `controllers/README.md`, `services/README.md`), ces `README.md` supplémentaires sont créés après la passe initiale de scellement et ne figurent pas dans `created_dirs`. Si vous les personnalisez ensuite, déclenchez `POST /api/contracts/sign` ou utilisez le bouton **Signer** du Cockpit pour les sceller dans `aether.lock.toml`.
{% endhint %}

## Forger un projet dans le Cockpit

Depuis la modale **Project Hub** du Cockpit (`ProjectHubModal.svelte`), ouvrez l'onglet **Create** pour échafauder un projet visuellement :

1. Sélectionnez l'une des 7 cartes de stack (`rust`, `python`, `ts`, `mvc`, `hybrid`, `roblox`, `minecraft`).
2. Basculez le mode de topologie entre **Monorepo Local** (`local`) et **Distribué / Dissocié** (`dissociated`).
3. Choisissez le répertoire parent (ou utilisez le sélecteur natif adossé à `/api/dialog/pick_folder`) et saisissez le nom de votre projet.
4. Cliquez sur **Forger l'Architecture & Entrer dans le Cockpit**. L'interface appelle `api.initProject(...)`, lance `api.analyzeProject(...)`, synchronise le statut du projet et cadre automatiquement la caméra 3D sur les 11 galaxies fraîchement forgées.

## Référence HTTP : POST /api/init_project

### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/init_project
```

### 📝 Paramètres

Envoyez un corps JSON conforme à `InitProjectRequest` (`crates/desktop-shell/src/api_routes.rs`) :

| Champ | Type | Requis | Défaut | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | `string` | Oui | — | Chemin système cible où le projet échafaudé sera créé. |
| `stack` | `string` | Non | `"hybrid"` | Alias du template de stack (`rust`, `python`, `ts`/`node`, `hybrid`, `roblox`/`luau`, `minecraft`/`mc`, `mvc`). |
| `topology` | `string` \| `null` | Non | `null` (`local`) | Mode de topologie (`"local"` pour `MonorepoLocal` ; `"dissociated"` ou `"distributed"` pour `Dissociated`). |

### 💎 Réponse

| Statut / Champ | Type | Description |
| :--- | :--- | :--- |
| `200 OK` — `status` | `string` | `"ok"` lorsque l'initialisation se termine. |
| `200 OK` — `message` | `string` | `"Projet initialisé avec 11 dossiers et contrats README.md signés BLAKE3"`. |
| `200 OK` — `created_dirs` | `string[]` | Liste des 11 répertoires de base créés (`contracts` jusqu'à `data-nodes/cache-worker`). |
| `400` / `422` | `text` | Renvoyé par Axum si le JSON est malformé ou si `path` est manquant. |
| `403 Forbidden` | `text` | Renvoyé par `LocalGuard` (`"AetherScope: requête refusée (origine non locale)"`) si `Host`, `Origin` ou `Sec-Fetch-Site` n'est pas local. |

### 💡 Exemple

{% tabs %}
{% tab title="PowerShell" %}
```powershell
$body = @{
  path     = "C:\Projects\my-rust-service"
  stack    = "rust"
  topology = "local"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:3030/api/init_project" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```
{% endtab %}
{% tab title="curl (Linux/macOS)" %}
```bash
curl -s -X POST "http://127.0.0.1:3030/api/init_project" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/tmp/my-rust-service",
    "stack": "rust",
    "topology": "local"
  }'
```
{% endtab %}
{% tab title="TypeScript (AetherApiClient)" %}
```ts
const res = await api.initProject('/tmp/my-mmo', 'hybrid', 'dissociated');
// { status: 'ok', message: '...', created_dirs: ['contracts', 'client', ...] }
```
{% endtab %}
{% endtabs %}

{% content-ref url="../core/blake3-governance.md" %}
[Cryptographie BLAKE3 et gouvernance EARS](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-workspace-graph.md" %}
[API REST : Workspace, système de fichiers et graphe](../api-mcp/rest-api-workspace-graph.md)
{% endcontent-ref %}

{% content-ref url="aethercraft.md" %}
[Plateforme Minecraft AetherCraft](aethercraft.md)
{% endcontent-ref %}
