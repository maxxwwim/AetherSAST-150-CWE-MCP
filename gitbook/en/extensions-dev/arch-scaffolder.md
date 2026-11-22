# Multi-Stack Architecture Scaffolder

`ArchScaffolder` generates polyglot, governance-ready project skeletons with `aether.lock.toml`, 11 layered EARS `README.md` contracts, BLAKE3 cryptographic seals, and stack-specific starter code in one call.

## Overview

Instead of assembling directory trees and architectural rules by hand, you can initialize a new project from the **Project Hub** in the Cockpit or via `POST /api/init_project`. Under the hood, `crates/arch-templates` builds a `ProjectManifest` (`version = 2`), while `crates/desktop-shell` materializes the directory hierarchy, signs the contracts with BLAKE3, and generates `AETHER_AI_RULES.md`.

{% hint style="info" %}
Every scaffolded project activates all four `GuardrailSettings` protections by default: `block_forbidden_imports`, `enforce_ears_syntax`, `sast_strict_mode`, and `require_signature_on_contract_change`.
{% endhint %}

## Supported Stack Templates

`ArchScaffolder::create_manifest` (`crates/arch-templates/src/templates.rs`) supports 7 `StackType` variants. Each template defines a set of galaxies in `aether.lock.toml` and generates matching starter files through `init_project_structure_with_topology` (`crates/desktop-shell/src/api_routes.rs`).

| `StackType` Variant | API / UI `stack` Aliases | Galaxies in `aether.lock.toml` | Starter Code Files Generated |
| :--- | :--- | :--- | :--- |
| `PureRust` | `rust` | `contracts`, `client`, `server`, `data-nodes` | `contracts/src/lib.rs`, `server/domain/src/lib.rs`, `server/application/src/lib.rs`, `server/api/src/lib.rs`, `client/ui/src/form.rs`, `data-nodes/db-primary/src/lib.rs` |
| `PurePythonUv` | `python` | `contracts`, `client`, `server`, `data-nodes` | `contracts/schemas.py`, `server/domain/models.py`, `server/api/router.py`, `client/ui/form.py` |
| `PureNodePnpm` | `ts`, `node` | `contracts`, `client`, `server`, `data-nodes` | `contracts/index.ts`, `server/domain/pricing.ts`, `server/api/routes.ts`, `client/ui/BookingForm.tsx` |
| `HybridMmoWeb3` *(default)* | `hybrid` *(or any unrecognized string)* | `contracts`, `client`, `data-nodes`, `server` | `contracts/packets.rs`, `server/domain/world.rs`, `server/api/websocket.rs`, `client/ui/GameCanvas.ts` |
| `RobloxLuau` | `roblox`, `roblox-server`, `luau` | `contracts`, `server`, `client`, `data-nodes` | `contracts/NetworkContracts.luau`, `contracts/Types.luau`, `server/ServerController.luau`, `server/domain/CombatService.luau`, `client/ClientController.luau`, `data-nodes/DataStoreServiceAdapter.luau`, `default.project.json`, `wally.toml`, `selene.toml` |
| `MinecraftServer` | `minecraft`, `mc` | `contracts`, `server`, `plugins`, `data-nodes` | `contracts/AETHER_MC_MANIFEST_SPEC.md`, `server/server.properties`, `server/start.bat`, `server/start.sh`, `server/paper-global.yml`, `plugins/README.md` |
| `ClassicMvc` | `mvc`, `classic-mvc`, `clean-mvc` | `models`, `views`, `controllers`, `services`, `data-nodes` | `models/README.md`, `views/README.md`, `controllers/README.md`, `services/README.md` |

## Topology Modes: MonorepoLocal vs Dissociated

`TopologyMode` (`crates/core-graph/src/manifest.rs`) controls whether all galaxies live inside a single repository or span distributed services:

* **`MonorepoLocal`** (API alias: `"local"`, default): All galaxies use local relative paths (`./contracts`, `./client`, `./server`, `./data-nodes`) with `remote_sync = false` and `remote_endpoint = None`.
* **`Dissociated`** (API aliases: `"dissociated"`, `"distributed"`): Marks distributed topology in `aether.lock.toml`. For `HybridMmoWeb3`, the `server` galaxy automatically enables `remote_sync = true` and sets `remote_endpoint = "wss://game-server.internal/aether-sync"`.

{% code title="aether.lock.toml (HybridMmoWeb3 + Dissociated excerpt)" overflow="wrap" %}
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
readme_blake3 = "<64-char hex digest>"

[guardrails]
block_forbidden_imports = true
enforce_ears_syntax = true
sast_strict_mode = true
require_signature_on_contract_change = true
```
{% endcode %}

## 11-Folder EARS Skeleton & BLAKE3 Sealing

Regardless of the chosen stack, `init_project_structure_with_topology` creates a standardized **11-folder layered architecture** and populates each directory with a YAML-frontmatter `README.md` contract (`ReadmeFrontmatter`) and EARS requirements (`WHEN ... THE SYSTEM SHALL ...`).

| Folder | `id` | `layer` | `max_lines_per_file` | `allowed_imports` | `forbidden_imports` | Extra `security_rules` / EARS Highlights |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `contracts` | `contracts` | `contracts` | `200` | `[]` | `client::*`, `server::*` | Validates API schemas and server response type safety |
| `client` | `client` | `ui` | `300` | `contracts::*` | `server::domain::*`, `data-nodes::*` | Updates reactive local state on user interaction |
| `client/ui` | `client-ui` | `ui` | `250` | `contracts::*`, `client/state::*` | `server::*` | Triggers client validation on form submission |
| `client/state` | `client-state` | `ui` | `200` | `contracts::*` | `server::domain::*` | Local client state isolation |
| `server` | `server` | `domain` | `300` | `contracts::*` | `client::*` | `no_raw_sql: true`, `no_env_access: true` |
| `server/domain` | `server-domain` | `domain` | `200` | `[]` | `server/api::*`, `client::*`, `data-nodes::*` | `deterministic_only: true`; pure domain evaluation without I/O |
| `server/application` | `server-app` | `action` | `250` | `server/domain::*`, `contracts::*` | `client::*` | Use-case orchestration layer |
| `server/api` | `server-api` | `action` | `250` | `server/application::*`, `contracts::*` | `server/domain::*` | Routes network packets through `contracts` schemas |
| `data-nodes` | `data-nodes` | `database` | `300` | `contracts::*` | `client::*` | Persistence boundary |
| `data-nodes/db-primary` | `db-primary` | `database` | `250` | `contracts::*` | `client::*` | Primary database adapter |
| `data-nodes/cache-worker` | `cache-worker` | `utility` | `200` | `contracts::*` | `client::*` | Cache & background worker |

Immediately after creating the 11 folders, the scaffolder executes two governance steps:

1. **BLAKE3 Contract Sealing**: Calls `sign_project_contracts(base, None)`, computing the 64-character BLAKE3 hex digest of each `README.md` and storing it in `galaxies.<folder>.readme_blake3` inside `aether.lock.toml` (adding sub-folder keys such as `"client/ui"` automatically).
2. **AI Rules Generation**: Calls `AuditWriter::generate_optimized_system_prompt` (`crates/ai-file-bridge/src/audit_writer.rs`) to write `AETHER_AI_RULES.md` at the project root with 6 sections covering the 3-call MCP workflow, all 10 `aetherscope_*` tools, zero-shell EARS/BLAKE3 rules, per-layer invariants, `< 35`-line patch atomicity, and `SecretGuard`/`SecretMasker` constraints.

{% hint style="warning" %}
`sign_project_contracts` runs **before** stack-specific starter files are written. For `MinecraftServer` (`plugins/README.md`) and `ClassicMvc` (`models/README.md`, `views/README.md`, `controllers/README.md`, `services/README.md`), those extra `README.md` files are created after the initial sealing pass and are not included in `created_dirs`. If you customize them later, trigger `POST /api/contracts/sign` or use the Cockpit **Signer** button to seal them in `aether.lock.toml`.
{% endhint %}

## Forging a Project in the Cockpit UI

From the Cockpit **Project Hub** modal (`ProjectHubModal.svelte`), open the **Create** tab to scaffold a project visually:

1. Select one of the 7 stack cards (`rust`, `python`, `ts`, `mvc`, `hybrid`, `roblox`, `minecraft`).
2. Toggle the topology mode between **Monorepo Local** (`local`) and **Distribué / Dissocié** (`dissociated`).
3. Choose the parent directory (or click the native folder picker backed by `/api/dialog/pick_folder`) and enter your project name.
4. Click **Forger l'Architecture & Entrer dans le Cockpit**. The UI calls `api.initProject(...)`, runs `api.analyzeProject(...)`, refreshes the project status, and fits the 3D camera onto the newly forged 11-galaxy graph.

## HTTP Endpoint Reference: POST /api/init_project

### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/init_project
```

### 📝 Parameters

Send a JSON body matching `InitProjectRequest` (`crates/desktop-shell/src/api_routes.rs`):

| Field | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | `string` | Yes | — | Target filesystem path where the scaffolded project will be created. |
| `stack` | `string` | No | `"hybrid"` | Stack template alias (`rust`, `python`, `ts`/`node`, `hybrid`, `roblox`/`luau`, `minecraft`/`mc`, `mvc`). |
| `topology` | `string` \| `null` | No | `null` (`local`) | Topology mode (`"local"` for `MonorepoLocal`; `"dissociated"` or `"distributed"` for `Dissociated`). |

### 💎 Response

| Status / Field | Type | Description |
| :--- | :--- | :--- |
| `200 OK` — `status` | `string` | `"ok"` when initialization finishes. |
| `200 OK` — `message` | `string` | `"Projet initialisé avec 11 dossiers et contrats README.md signés BLAKE3"`. |
| `200 OK` — `created_dirs` | `string[]` | List of the 11 base directories created (`contracts` through `data-nodes/cache-worker`). |
| `400` / `422` | `text` | Returned by Axum if the JSON payload is malformed or missing `path`. |
| `403 Forbidden` | `text` | Returned by `LocalGuard` (`"AetherScope: requête refusée (origine non locale)"`) on non-local `Host`, `Origin`, or `Sec-Fetch-Site`. |

### 💡 Example

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
[BLAKE3 Cryptography & EARS Governance](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-workspace-graph.md" %}
[REST API: Workspace, Filesystem & Graph](../api-mcp/rest-api-workspace-graph.md)
{% endcontent-ref %}

{% content-ref url="aethercraft.md" %}
[AetherCraft Minecraft Platform](aethercraft.md)
{% endcontent-ref %}
