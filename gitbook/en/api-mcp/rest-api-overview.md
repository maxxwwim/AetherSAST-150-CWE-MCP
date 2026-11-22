# REST API Overview & Client

The `desktop-shell` backend exposes a local Axum `0.7` HTTP server on `127.0.0.1:3030` with **52 `.route(...)` registrations** (**60 HTTP method + path operations**). Every request is protected by `LocalGuard` (without permissive CORS) and consumed by the cockpit through `AetherApiClient`, the SSE `/api/graph/events` stream, or local tools such as `aetherscope-mcp`.

{% hint style="info" %}
All REST endpoints bind exclusively to `127.0.0.1:<port>` (default `3030`) as defined in `crates/desktop-shell/src/main.rs` (`Args.port`). Change the port at startup with `--port <PORT>`.
{% endhint %}

## Server Architecture & Startup Modes

The Axum server and `FileWatcherBridge` background loop start automatically across all three interactive/daemon execution modes:

* **Desktop WebView (default)**: Launches the native `tao` + `wry` window pointing to `http://127.0.0.1:<port>`. On Windows, WebView2 receives `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --js-flags=--max-old-space-size=4096` to prevent V8 heap pressure on large graphs.
* **Headless Server (`--no-gui`)**: Runs the Axum HTTP server and `FileWatcherBridge` without opening a desktop window, ideal for external browsers, scripts, or CI previews.
* **MCP Bridge (`--mcp`)**: Checks `mcp::check_server_listening(port)`; if no instance is listening, spawns the Axum server and `FileWatcherBridge` in the background, waits `350 ms`, and enters the JSON-RPC 2.0 `stdio` loop.

{% tabs %}
{% tab title="Headless + curl" %}
```bash
# Start headless REST server on port 3030
aether-engine -p . --no-gui --port 3030

# Probe liveness (LocalGuard requires Host: 127.0.0.1:3030)
curl -s http://127.0.0.1:3030/api/health
```
{% endtab %}

{% tab title="PowerShell" %}
```powershell
# Start headless REST server on port 3030
.\aether-engine.exe -p . --no-gui --port 3030

# Probe liveness
Invoke-RestMethod -Uri "http://127.0.0.1:3030/api/health" -Method Get
```
{% endtab %}
{% endtabs %}

### Live Synchronization (`FileWatcherBridge`)

`FileWatcherBridge` polls the active `project_root` every **30 ms** using an adaptive debouncer (**100 ms** quiet window, **500 ms** maximum batch wait). When filesystem changes settle, it performs targeted updates:

* Invalidates `git_raw_cache` so the next `GET /api/git/status` sees disk edits immediately.
* Increments `visual_plugins_version` when files under `.aether/plugins/visuals/` or any `.glsl` shader change.
* Rescans `vault_graph` when `.md`/`.mdx` files change in Vault/Mixed projects or `vault-notes` view mode, and rescans `code_graph` (applying `custom_exclusions`, `active_cve_rules`, and `ignored_cwes`) while rewriting `.aether/LIVE_AUDIT.md` when code or `README.md` contracts change.
* Clears `ui_graph_cache`, bumps `graph_version` and `fs_version`, and broadcasts a `GraphWatchEvent` to all subscribers connected to [`GET /api/graph/events`](./rest-api-workspace-graph.md#get-apigraphevents).

## Security Layers & Error Mapping

AetherScope enforces defense-in-depth across network origin validation, path confinement, and secret protection.

### `LocalGuard` (Transport & Anti-CSRF Middleware)

The Axum router attaches **no `CorsLayer`**. Instead, `local_guard::enforce_local_only` inspects three headers on every request:

| Header | Requirement | Allowed Values (Case-Insensitive) | On Failure |
| :--- | :--- | :--- | :--- |
| `Host` | **Required** | `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` | `403 Forbidden` |
| `Origin` | Optional (checked if present) | `http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>` | `403 Forbidden` |
| `Sec-Fetch-Site` | Optional (checked if present) | `same-origin`, `none` | `403 Forbidden` |

Omitting `Origin` and `Sec-Fetch-Site` is allowed so local CLI tools (`curl`, PowerShell) and the `aetherscope-mcp` TCP bridge can call `127.0.0.1:3030` directly. Rejected requests receive `403 Forbidden` with the `text/plain; charset=utf-8` body `"AetherScope: requête refusée (origine non locale)"`.

### `PathGuard`, `SecretGuard` & `SecretMasker`

Project-scoped file endpoints (`GET /api/file_content`, `POST /api/save_file`, `GET /api/raw_file`, `POST /api/save_doc`, `POST /api/ai/create_file`, `POST /api/ai/target`, and `GET /api/files`) enforce additional guards:

* **`PathGuard` (`TargetJail`)**: Enforces `DEFAULT_MAX_FILE_SIZE = 10 MiB`, `MAX_PATH_DEPTH = 32`, and lexical rejection of empty paths, `.`/`./`, null bytes, URL schemes (`scheme://`), UNC paths (`\\...`), drive letters (`C:`), leading `/`/`\`, and `..` traversal, followed by canonical containment (`starts_with(&canonical_root)`) against symlink escapes.
* **`SecretGuard` / `PathGuard::is_sensitive_path`**: Denies access to `.env*`, `.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets*`, `credentials*`, `service-account*`, `master.key`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `authorized_keys`, `known_hosts`, `id_rsa*`/`id_ed25519*`/`id_ecdsa*`/`id_dsa*`, OS password/registry files, and key/certificate extensions (`.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`, `.kdbx`, `.der`, `.crt`, `.cer`, `.jks`, `.keystore`).
* **`SecretMasker` (12 Secret Families)**: Detects and redacts PEM private key blocks, `sk-*` API keys, GitHub `ghp_*`/`github_pat_*`/`gh[ousr]_*`, AWS `AKIA*`, Stripe `sk_live_`/`rk_live_`, Slack `xox*-*`, JWTs (`ey*.*.*`), DB URI passwords, and quoted/unquoted secret assignments. Write routes (`POST /api/save_doc`, `POST /api/ai/create_file`) **block** payloads containing secrets (`403 Forbidden`), whereas `GET /api/file_content` (when `raw=false`) and `POST /api/ai/target` **redact** secrets inline.

### Standard `SecurityError` HTTP Mapping

| HTTP Status | JSON `error` | `SecurityError` Variants |
| :--- | :--- | :--- |
| `400 Bad Request` | `"bad_request"` | `NullByteDetected`, `PathTraversal`, `UncPathProhibited`, `DriveLetterProhibited`, `AbsolutePathsProhibited`, `UrlSchemeProhibited`, `InvalidPrefix`, `DepthExceeded`, `ExtensionNotAllowed`, `NotAFile` |
| `403 Forbidden` | `"forbidden"` | `SensitiveFileProhibited`, `PathEscapesRoot`, `SymlinkEscape`, `SymlinksDisabled` |
| `404 Not Found` | `"not_found"` | `IoError` (`ErrorKind::NotFound`) |
| `413 Payload Too Large` | `"payload_too_large"` | `FileTooLarge` (`> 10 MiB`) |
| `500 Internal Server Error` | `"internal_error"` | `RootCanonicalizationFailed`, `RootNotADirectory`, other `IoError` |

Error JSON shape: `{ "status": "error", "error": "<code_slug>", "message": "<details>" }` (`GET /api/file_content` also includes `"path"`, while `GET /api/raw_file` returns plain text error bodies).

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}

## Vite Dev Proxy & `AetherApiClient`

In development (`crates/desktop-shell/ui/vite.config.ts`), Vite serves the Svelte 5 frontend on port `5173` and proxies all `/api` requests to `http://127.0.0.1:3030`. In production builds (`npm run build`), `vite-plugin-singlefile` bundles the UI into `crates/desktop-shell/dist/index.html`, which Rust embeds at compile time and serves from `127.0.0.1:3030`.

The TypeScript client `AetherApiClient` (`crates/desktop-shell/ui/src/lib/api.ts`) defaults to `baseUrl = ''` (same-origin relative URLs) and exposes **51 methods** (`49` `fetch` wrappers + `getRawFileUrl(path)` + `getGraphEventsUrl()`):

```typescript
import { AetherApiClient, api } from '$lib/api';

// Default singleton uses same-origin relative URLs ('')
const status = await api.getProjectStatus();

// Custom client pointing to a non-default local port (when running outside the cockpit)
const customClient = new AetherApiClient('http://127.0.0.1:4040');
const health = await fetch('http://127.0.0.1:4040/api/health').then((r) => r.text());
```

{% hint style="warning" %}
**Client Differences & Unwrapped Routes to Keep in Mind**:
* **9 unwrapped HTTP operations**: `GET /`, `GET /legacy`, `GET /favicon.ico`, `GET /api/health`, `GET /api/workspace`, `POST /api/workspace`, `GET /api/git/status` (called via raw `fetch` in `graphState.svelte.ts`), `GET /api/analyze` (`api.analyzeProject` uses `POST`), and `GET /api/ai/status`.
* **Method renames**: `teleportCamera(...)` calls `POST /api/ai/telemetry`; `initCommunityPluginBundle()` calls `POST /api/plugins/init_bundle`.
* **Default / TypeScript drift**: `api.getFileContent(path, raw = true)` defaults `raw` to `true`, whereas the Rust endpoint defaults `raw` to `false`. `api.getProjects()` types `projects: string[]` while Rust returns `{ name, path }[]`. `api.updateContract(...)` types `folder` in the response while Rust returns `contract_path` and optional `file_blake3_hash`. `api.switchViewMode(...)` omits `'notes'` and `'editor'` aliases accepted by Rust, and `api.saveSettings(...)` omits `active_visual_plugin`.
* **Legacy `3333` fallback in `McpControlModal.svelte`**: When `window.location.port` is empty (such as opening a standalone `file://` HTML export), `McpControlModal.svelte` falls back to `'3333'` in displayed snippets. The canonical backend port is always `3030`.
{% endhint %}

## Graph Compaction (`ui_payload` & `decodeCompactGraph`)

To keep 40k-node / 250k-edge graphs responsive in WebView2, `ui_payload::build_payload` (`crates/desktop-shell/src/api_routes.rs`) optimizes graph payloads:

1. **Always applied on UI payloads**: Strips `node.metadata.raw_content` (loaded on demand via `GET /api/file_content`), clears `node.metadata.violations` when `cve_anomalies` is non-empty, and sets `system_prompt = None` and `dataflow_graph = None`.
2. **Threshold compaction (`nodes.len() > 3_000 || edges.len() > 20_000`)**:
   * Truncates `node.docstring` to `240` bytes (`'…'`) and method docstrings to `160` bytes (`'…'`), caps `method.calls` at `8`, and truncates `blake3_hash` / `file_blake3_hash` to `16` characters.
   * Replaces `edges` with `[]` and populates `edges_compact` (`CompactEdges` with integer index arrays `src`, `dst`, `rel`, `typ`, deduplicated string tables `ids`, `rels`, `types`, and sparse `extra` metadata).
3. **Zero-copy frontend decoding**: `decodeCompactGraph` (`crates/desktop-shell/ui/src/lib/graphCodec.ts`) reconstructs `AffiliationEdge[]` reusing each `node.id` string reference without duplicating strings on the JS heap.
4. **Full uncompacted export**: Pass `?full=1` or `?full=true` to `GET /api/graph` to receive full `edges` objects, `system_prompt`, and `dataflow_graph`.

## Complete Route Index (52 Routes / 60 Operations)

### Workspace, Filesystem, Init, Graph & Export

| # | Path | Method(s) | `AetherApiClient` Method | Reference |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `/` | `GET` | *(unwrapped)* | [Workspace & Graph](./rest-api-workspace-graph.md#get--and-get-legacy) |
| 2 | `/legacy` | `GET` | *(unwrapped)* | [Workspace & Graph](./rest-api-workspace-graph.md#get--and-get-legacy) |
| 3 | `/favicon.ico` | `GET` | *(unwrapped)* | [Workspace & Graph](./rest-api-workspace-graph.md#get-faviconico) |
| 4 | `/api/health` | `GET` | *(unwrapped)* | [Workspace & Graph](./rest-api-workspace-graph.md#get-apihealth) |
| 5 | `/api/projects` | `GET` | `getProjects()` | [Workspace & Graph](./rest-api-workspace-graph.md#get-apiprojects) |
| 6 | `/api/workspace` | `GET`, `POST` | *(unwrapped)* | [Workspace & Graph](./rest-api-workspace-graph.md#get-apiworkspace-and-post-apiworkspace) |
| 7 | `/api/fs/list` | `GET` | `listDirectory(path?)` | [Workspace & Graph](./rest-api-workspace-graph.md#get-apifslist) |
| 8 | `/api/dialog/pick_workspace` | `POST` | `pickWorkspace()` | [Workspace & Graph](./rest-api-workspace-graph.md#post-apidialogpick_workspace) |
| 9 | `/api/dialog/pick_project` | `POST` | `pickProject()` | [Workspace & Graph](./rest-api-workspace-graph.md#post-apidialogpick_project) |
| 10 | `/api/init_project` | `POST` | `initProject(path, stack, topology?)` | [Workspace & Graph](./rest-api-workspace-graph.md#post-apiinit_project) |
| 11 | `/api/project/status` | `GET` | `getProjectStatus()` | [Workspace & Graph](./rest-api-workspace-graph.md#get-apiprojectstatus) |
| 12 | `/api/git/status` | `GET` | *(unwrapped)* | [Workspace & Graph](./rest-api-workspace-graph.md#get-apigitstatus) |
| 13 | `/api/view_mode` | `POST` | `switchViewMode(mode)` | [Workspace & Graph](./rest-api-workspace-graph.md#post-apiview_mode) |
| 14 | `/api/analyze` | `POST`, `GET` | `analyzeProject(path, exclusions?)` (`POST`) | [Workspace & Graph](./rest-api-workspace-graph.md#post-apianalyze-and-get-apianalyze) |
| 15 | `/api/graph` | `GET` | `getGraph()` | [Workspace & Graph](./rest-api-workspace-graph.md#get-apigraph) |
| 16 | `/api/graph/version` | `GET` | `getGraphVersion()` | [Workspace & Graph](./rest-api-workspace-graph.md#get-apigraphversion) |
| 17 | `/api/graph/events` | `GET` (SSE) | `getGraphEventsUrl()` | [Workspace & Graph](./rest-api-workspace-graph.md#get-apigraphevents) |
| 18 | `/api/export` | `POST` | `exportHtml(path?)` | [Workspace & Graph](./rest-api-workspace-graph.md#post-apiexport) |

### IDE, Contracts, AI, Telemetry, Chat & Tasks

| # | Path | Method(s) | `AetherApiClient` Method | Reference |
| :--- | :--- | :--- | :--- | :--- |
| 19 | `/api/files` | `GET` | `getFiles()` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-apifiles) |
| 20 | `/api/file_content` | `GET` | `getFileContent(path, raw?)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-apifile_content) |
| 21 | `/api/save_file` | `POST` | `saveFile(filePath, content)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apisave_file) |
| 22 | `/api/raw_file` | `GET` | `getRawFileUrl(path)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-apiraw_file) |
| 23 | `/api/ai/create_file` | `POST` | `createFile(payload)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apiaicreate_file) |
| 24 | `/api/save_doc` | `POST` | `saveDoc(payload)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apisave_doc) |
| 25 | `/api/contracts/sign` | `POST` | `signContracts(payload)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apicontractssign) |
| 26 | `/api/contracts/update` | `POST` | `updateContract(payload)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apicontractsupdate) |
| 27 | `/api/ai/target` | `POST` | `setAiTarget(symbolId, actionType?)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apiaitarget) |
| 28 | `/api/ai/telemetry` | `GET`, `POST`, `DELETE` | `getTelemetry()`, `teleportCamera(...)`, `clearTelemetry()` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-post-delete-apiaitelemetry) |
| 29 | `/api/ai/chat` | `GET`, `POST` | `getChatHistory()`, `sendChatMessage(...)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-and-post-apiaichat) |
| 30 | `/api/ai/chat/clear` | `POST` | `clearChatHistory()` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apiaichatclear) |
| 31 | `/api/ai/status` | `GET` | *(unwrapped)* | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-apiaistatus) |
| 32 | `/api/ai/cancel` | `POST` | `cancelAi()` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apiaicancel) |
| 33 | `/api/ai/new_session` | `POST` | `newAiSession()` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apiainew_session) |
| 34 | `/api/ai/launch_cli` | `POST` | `launchCli(tool, projectPath?, prompt?)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apiailaunch_cli) |
| 35 | `/api/ai/system_prompt` | `GET` | `getSystemPrompt()` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-apiaisystem_prompt) |
| 36 | `/api/tasks` | `GET`, `POST` | `getTasks()`, `createTask(payload)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#get-and-post-apitasks) |
| 37 | `/api/tasks/update` | `POST` | `updateTask(...)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apitasksupdate) |
| 38 | `/api/tasks/delete` | `POST` | `deleteTask(taskId)` | [IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md#post-apitasksdelete) |

### Settings, Bounty, Surface & Plugins

| # | Path | Method(s) | `AetherApiClient` Method | Reference |
| :--- | :--- | :--- | :--- | :--- |
| 39 | `/api/settings` | `GET`, `POST` | `getSettings()`, `saveSettings(payload)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 40 | `/api/bounty/scope` | `GET`, `POST` | `getBountyScope()`, `updateBountyScope(payload)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 41 | `/api/surface_scan` | `POST` | `surfaceScan(req)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 42 | `/api/plugins` | `GET` | `getPlugins()` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 43 | `/api/plugins/toggle` | `POST` | `togglePlugin(relPath, enabled)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 44 | `/api/plugins/test` | `POST` | `testPlugins(relPath?)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 45 | `/api/plugins/init_bundle` | `POST` | `initCommunityPluginBundle()` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 46 | `/api/plugins/import_semgrep` | `POST` | `importSemgrepPlugin(pluginName, yamlContent)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 47 | `/api/plugins/upsert` | `POST` | `upsertPluginRule(payload)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 48 | `/api/plugins/delete` | `POST` | `deletePlugin(relPath)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 49 | `/api/visual_plugins` | `GET` | `getVisualPlugins()` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 50 | `/api/visual_plugins/activate` | `POST` | `activateVisualPlugin(id)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 51 | `/api/visual_plugins/upsert` | `POST` | `upsertVisualPlugin(payload)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |
| 52 | `/api/visual_plugins/delete` | `POST` | `deleteVisualPlugin(id)` | [Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md) |

## Next Steps

{% content-ref url="./rest-api-workspace-graph.md" %}
[REST API: Workspace, Filesystem, Init, Graph & Export](./rest-api-workspace-graph.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-ide-contracts-ai.md" %}
[REST API: IDE, Contracts, AI, Telemetry, Chat & Tasks](./rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-security-plugins.md" %}
[REST API: Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="./mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](./mcp-server.md)
{% endcontent-ref %}
