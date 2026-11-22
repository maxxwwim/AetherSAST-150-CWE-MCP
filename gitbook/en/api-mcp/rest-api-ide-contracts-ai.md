# REST API: IDE, Contracts, AI, Telemetry, Chat & Tasks

These 20 routes (23 HTTP operations) power the full-screen IDE file tree and atomic saving, BLAKE3 contract sealing, zero-shell AI handshakes, multi-agent swarm telemetry, chat inbox synchronization, and task management. All file operations are confined by `PathGuard`, `SecretGuard`, and `SecretMasker` on top of [`LocalGuard`](./rest-api-overview.md#localguard-transport--anti-csrf-middleware).

{% hint style="warning" %}
**Masking vs Blocking**: Read endpoints (`GET /api/file_content?raw=false`, `POST /api/ai/target`) **redact** secrets inline via `SecretMasker::mask_text`, whereas AI/doc write endpoints (`POST /api/save_doc`, `POST /api/ai/create_file`) **reject** payloads containing secrets with `403 Forbidden` via `SecretMasker::contains_secret`.
{% endhint %}

---

## GET /api/files

Returns the flat project file and directory tree for the IDE sidebar, automatically skipping build caches and sensitive files.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/files
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(none)* | — | — | No | No query or body parameters. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `files` | `FileTreeItem[]` | Lexicographically sorted array of `{ name, path, is_dir, size, extension }` (`path` uses `/`; `size = 0` and `extension = ""` for dirs). Skips `.git`, `node_modules`, `target`, `dist`, `.aether`, `.gemini`, and any path matching `SecretGuard::is_secret_path` or `PathGuard::is_sensitive_path`. |
| `403 Forbidden` | *(text)* | `string` | Rejected by `LocalGuard`. |

### 💡 Example

```bash
curl -s http://127.0.0.1:3030/api/files
```

---

## GET /api/file_content

Reads a UTF-8 text file inside `project_root` (up to `10 MiB`), retrying up to 20 times on transient Windows file lock contention and optionally masking secrets.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/file_content?path=<rel_path>&raw=false
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Query | `string` | **Yes** | Project-relative path validated by `PathGuard`, `SecretGuard`, and `PathGuard::validate_not_sensitive`. |
| `raw` | Query | `boolean` | Optional | Server defaults to `false` (applies `SecretMasker::mask_text`). Pass `raw=true` to read unredacted source (used by `api.getFileContent(path, raw = true)` in the IDE). |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `path`, `content` | `string` | File text (redacted if `raw=false`). |
| `400` / `403` / `404` / `413` / `500` | `status`, `error`, `message`, `path` | `string` | `PathGuard` / `SecretGuard` confinement error (`SecurityError` mapping; `SecretGuard` returns `403` without `error` slug). |

### 💡 Example

{% tabs %}
{% tab title="curl" %}
```bash
curl -s "http://127.0.0.1:3030/api/file_content?path=src/main.rs&raw=false"
```
{% endtab %}

{% tab title="AetherApiClient" %}
```typescript
import { api } from '$lib/api';

// Note: TS client defaults raw = true (whereas Rust defaults raw = false)
const file = await api.getFileContent('src/main.rs', true);
```
{% endtab %}
{% endtabs %}

---

## POST /api/save_file

Atomically writes a project file (used by IDE `Ctrl+S`), serialized by `file_save_lock` (`tokio::sync::Mutex`) via a temporary sibling file and atomic rename.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/save_file
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `file_path` | JSON Body | `string` | **Yes** | Project-relative destination path (creates missing parent directories; checked by `PathGuard` and `SecretGuard`). |
| `content` | JSON Body | `string` | **Yes** | Full UTF-8 file content to write. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `file_path` | `string` | Written relative path. |
| `200 OK` | `bytes_written` | `number` | Number of bytes written. |
| `400` / `403` / `500` | `status`, `error`, `message` | `string` | Confinement or I/O error (`SecurityError` mapping). |

{% hint style="info" %}
`POST /api/save_file` does **not** run `SecretMasker::contains_secret` and does **not** trigger a synchronous graph rescan. `FileWatcherBridge` detects the disk write asynchronously (100 ms quiet window) and refreshes the graph and `.aether/LIVE_AUDIT.md`.
{% endhint %}

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/save_file \
  -H "Content-Type: application/json" \
  -d '{"file_path":"src/lib.rs","content":"pub fn ok() {}\n"}'
```

{% content-ref url="../cockpit-ide/integrated-ide.md" %}
[Full-Screen Multi-Tab IDE](../cockpit-ide/integrated-ide.md)
{% endcontent-ref %}

---

## GET /api/raw_file

Serves raw binary assets (images, PDFs, Markdown, CSV, JSON) inside `project_root` for the Obsidian Vault viewer and IDE previews.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/raw_file?path=<rel_path>
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `path` | Query | `string` | **Yes** | Project-relative path. Extension must be one of the 15 `ALLOWED_RAW_EXTENSIONS`: `png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `markdown`, `txt`, `csv`. Max size `10 MiB`. |

### 💎 Response

| Status | Content-Type | Body | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | Extension MIME type | Binary bytes | Exact MIME mapping (`image/png`, `image/jpeg`, `image/gif`, `image/svg+xml`, `image/webp`, `image/x-icon`, `image/bmp`, `image/tiff`, `application/pdf`, `application/json`, `text/plain; charset=utf-8` for `md`/`markdown`/`txt`, `text/csv; charset=utf-8`). |
| `400` / `403` / `404` / `413` / `500` | `text/plain; charset=utf-8` | Plain string | Returns `"Chemin manquant"` (`400`) or `SecurityError` body string (not wrapped in JSON). |

### 💡 Example

```bash
curl -s "http://127.0.0.1:3030/api/raw_file?path=docs/diagram.png" --output diagram.png
```

---

## POST /api/ai/create_file

Creates a new source file inside `project_root` with secret scanning, then immediately rescans the project and increments `graph_version`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/create_file
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | JSON Body | `string` | **Yes** | Project directory (`""` or `"."` uses active `project_root`; must stay confined within canonical `project_root`). |
| `file_path` | JSON Body | `string` | **Yes** | Project-relative file path to create (`PathGuard` + `SecretGuard`). |
| `content` | JSON Body | `string` | **Yes** | File content; rejected with `403 Forbidden` if `SecretMasker::contains_secret` matches. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `file_path` | `string` | Relative path created. |
| `200 OK` | `created_symbol` | `string` | Path normalized with `::` separators. |
| `200 OK` | `graph`, `data` | `UiGraphPayload` | Identical updated graph payloads serialized via `ui_payload::ser_graph`. |
| `400` / `403` / `500` | `status`, `error`, `message` | `string` | Confinement, sensitive path, or embedded-secret rejection. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/create_file \
  -H "Content-Type: application/json" \
  -d '{"project_path":".","file_path":"src/new_mod.rs","content":"pub fn run() {}\n"}'
```

---

## POST /api/save_doc

Writes a documentation or `README.md` architectural contract file; when `file_name` is `README.md` (case-insensitive), automatically seals its BLAKE3 hash into `aether.lock.toml` and rescans the graph.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/save_doc
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | JSON Body | `string` | **Yes** | Confined project root (`""` or `"."` uses active `project_root`). |
| `folder` | JSON Body | `string` | **Yes** | Target subfolder (`""`, `"root"`, or `"."` targets project root). |
| `file_name` | JSON Body | `string` | **Yes** | File name (e.g. `"README.md"`). |
| `content` | JSON Body | `string` | **Yes** | File content; blocked with `403 Forbidden` if `SecretMasker::contains_secret` matches. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `saved_path` | `string` | Absolute saved path. |
| `200 OK` | `blake3_hash` | `string` *(optional)* | New BLAKE3 digest when `file_name` is `README.md`. |
| `200 OK` | `graph` | `UiGraphPayload` *(optional)* | Updated graph payload when `README.md` triggered a rescan. |
| `400` / `403` / `500` | `status`, `error`, `message` | `string` | Confinement or secret rejection. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/save_doc \
  -H "Content-Type: application/json" \
  -d '{"project_path":".","folder":"server","file_name":"README.md","content":"---\nid: server\nlayer: domain\nmax_lines_per_file: 250\n---\n# Server\n"}'
```

---

## POST /api/contracts/sign

Walks non-hidden directories (`.*`, `target`, `node_modules`, `dist` skipped) to compute BLAKE3 digests for `README.md` contracts, updates `aether.lock.toml`, rescans the project, and increments `graph_version`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/contracts/sign
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | JSON Body | `string` | Optional | Project root (defaults to active `state.project_root`). |
| `folder` | JSON Body | `string` | Optional | Specific folder to sign (signs all folders when omitted). |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |
| `200 OK` | `message` | `string` | Summary of signed contracts. |
| `200 OK` | `signed_count` | `number` | Count of signed `README.md` manifests. |
| `200 OK` | `blake3_hash` | `string` *(optional)* | Digest of the primary/requested signed contract. |
| `200 OK` | `graph` | `UiGraphPayload` | Rescanned graph payload (`ui_payload::ser_graph`). |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/contracts/sign \
  -H "Content-Type: application/json" \
  -d '{"folder":"server"}'
```

{% content-ref url="../core/blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](../core/blake3-governance.md)
{% endcontent-ref %}

---

## POST /api/contracts/update

Upserts EARS contract constraints in the nearest `README.md` (inheriting parent frontmatter if creating a new subfolder contract), re-seals `aether.lock.toml`, and rescans the project.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/contracts/update
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `project_path` | JSON Body | `string` | Optional | Project root (defaults to `state.project_root`). |
| `folder` | JSON Body | `string` | Optional | Target folder containing `README.md`. |
| `file_path` | JSON Body | `string` | Optional | Source file path; walks upward to nearest `README.md` when `folder` is omitted. |
| `max_lines_per_file` | JSON Body | `number` | Optional | Folder-level line budget. |
| `file_max_lines` | JSON Body | `number` | Optional | Per-file line budget override. |
| `clear_file_override` | JSON Body | `boolean` | Optional | Defaults to `false`. Removes per-file override when `true`. |
| `allowed_imports`, `forbidden_imports`, `forbidden_functions`, `allowed_extensions`, `forbidden_extensions` | JSON Body | `string[]` | Optional | Architectural boundary and language rules. |
| `max_files_per_folder` | JSON Body | `number` | Optional | Folder file-count cap (`0` removes the cap). |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "error"` | Note: returns HTTP `200 OK` with `status: "error"` on `update_contract_rules` failure. |
| `200 OK` | `message` | `string` | Status or error explanation. |
| `200 OK` | `contract_path` | `string` | Updated `README.md` relative path (note: `api.ts` types this field as `folder`). |
| `200 OK` | `blake3_hash` | `string` | New `README.md` BLAKE3 digest (`""` on error). |
| `200 OK` | `file_blake3_hash` | `string` *(optional)* | BLAKE3 digest of `file_path` when applicable. |
| `200 OK` | `effective_max_lines` | `number` | Effective line limit (`300` fallback on error). |
| `200 OK` | `graph` | `UiGraphPayload` | Updated graph payload. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/contracts/update \
  -H "Content-Type: application/json" \
  -d '{"folder":"server","max_lines_per_file":220,"forbidden_imports":["client::*"]}'
```

---

## POST /api/ai/target

Focuses the zero-shell AI bridge on a graph symbol: writes `.aether/ACTIVE_TARGET.md`, builds a `<aether_handshake version="2.1">` XML context packet with categorized liaisons, and redacts any embedded secrets.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/target
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `symbol_id` | JSON Body | `string` | **Yes** | Matches `node.id`, `node.name`, `node.file_path`, or `::<symbol_id>`. Checked against `SecretGuard`. |
| `action_type` | JSON Body | `string` | Optional | Action label (defaults to `"Target"`). |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "not_found"` | Lookup result. |
| `200 OK` | `active_target_path` | `string` | Path to `.aether/ACTIVE_TARGET.md`. |
| `200 OK` | `handshake_xml` | `string` | `<aether_handshake version="2.1">` XML masked via `SecretMasker::mask_text`. |
| `200 OK` | `blake3_hash`, `lock_verified`, `ears_count` | `string?`, `boolean?`, `number` | BLAKE3 contract verification metadata. |
| `200 OK` | `symbol_name`, `file_path`, `layer`, `galaxy`, `docstring` | `string?` | Target symbol metadata. |
| `200 OK` | `callers`, `dependencies` | `string[]` | Caller and dependency symbol IDs. |
| `200 OK` | `categorized_incoming`, `categorized_outgoing`, `formatted_doc_and_liaisons` | `CategorizedLiaisons?`, `string?` | Categorized edge breakdown and formatted summary. |
| `403 Forbidden` | `status`, `message` | `string` | Returned if `symbol_id` or resolved `file_path` triggers `SecretGuard`. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/target \
  -H "Content-Type: application/json" \
  -d '{"symbol_id":"save_file","action_type":"Audit"}'
```

{% content-ref url="../core/improvements-and-workflows.md" %}
[Improvements, Enhancements & AI Firewall](../core/improvements-and-workflows.md)
{% endcontent-ref %}

---

## GET, POST, DELETE /api/ai/telemetry

Manages multi-agent swarm telemetry (`AI_AGENT_TTL_SECS = 300` seconds), assigning deterministic 12-color swarm badges via FNV-1a hashing and persisting up to 250 history events in `.aether/ai_telemetry_cache.json`.

### 🎮 Endpoint

```text
GET    http://127.0.0.1:3030/api/ai/telemetry
POST   http://127.0.0.1:3030/api/ai/telemetry
DELETE http://127.0.0.1:3030/api/ai/telemetry
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `target` | JSON Body (`POST`) | `string` | **Yes** | Target symbol, file, or coordinate label. |
| `action` | JSON Body (`POST`) | `string` | **Yes** | Action name (e.g. `"Inspect"`, `"Audit"`). |
| `details` | JSON Body (`POST`) | `string` | **Yes** | Concise activity description. |
| `timestamp` | JSON Body (`POST`) | `number` | Optional | Unix seconds (`0` auto-fills current time; values `> 1_000_000_000_000` are converted from ms to s). |
| `agent_id`, `agent_name`, `color` | JSON Body (`POST`) | `string` | Optional | `agent_id` defaults to `"primary-agent"`; `color` is deterministically picked from `AI_AGENT_PALETTE` (12 colors) if omitted. |

### 💎 Response

| Method / Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `telemetry`, `agents`, `history` | `AiTelemetryEvent?`, `AiTelemetryEvent[]`, `AiTelemetryEvent[]` | Reloads `.aether/ai_telemetry_cache.json` if empty, prunes agents older than `300 s`, sorts `agents` newest-first, returns history (max `250` items). |
| `POST` (`200 OK`) | `status`, `event` | `"ok"`, `AiTelemetryEvent` | Deduplicates identical `(agent_id, target, action)` within `<= 1 s` in history and saves cache. |
| `DELETE` (`200 OK`) | `status` | `"ok"` | Clears in-memory telemetry and deletes `.aether/ai_telemetry_cache.json`. |

### 💡 Example

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

// Note: api.teleportCamera() wraps POST /api/ai/telemetry
await api.teleportCamera('src/main.rs', 'Inspect', 'Auditing LocalGuard', {
  agent_id: 'claude-sec',
  agent_name: 'Claude Sec',
});
```
{% endtab %}
{% endtabs %}

---

## GET and POST /api/ai/chat

Reads or appends messages in the bidirectional Cockpit <-> AI chat channel and synchronizes `.aether/CHAT_INBOX.md` for zero-token agent wakeups.

### 🎮 Endpoint

```text
GET  http://127.0.0.1:3030/api/ai/chat
POST http://127.0.0.1:3030/api/ai/chat
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `text` | JSON Body (`POST`) | `string` | **Yes** | Message text. |
| `sender` | JSON Body (`POST`) | `string` | Optional | Defaults to `"user"`. Sets `.aether/CHAT_INBOX.md` status to `PENDING_AI_RESPONSE` when `"user"`, or `ANSWERED` otherwise. |
| `target_symbol`, `agent_id`, `agent_name`, `recipient`, `color` | JSON Body (`POST`) | `string` | Optional | Routing and swarm badge metadata. Non-empty `target_symbol` with agent sender also records `"Chat / Hand-off"` telemetry. |

### 💎 Response

| Method / Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `messages` | `AiChatMessage[]` | Full chat history (`{ id, sender, text, target_symbol?, timestamp, agent_id?, agent_name?, recipient?, color? }`). |
| `GET` (`200 OK`) | `agent_status` | `"thinking" \| "ready"` | `"thinking"` when the last message has `sender == "user"`, otherwise `"ready"`. |
| `POST` (`200 OK`) | `status`, `message` | `"ok"`, `AiChatMessage` | Appended message (`id: "msg_<ms>"`). |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"text":"Audit auth module","sender":"user","target_symbol":"auth"}'
```

---

## POST /api/ai/chat/clear

Clears in-memory `chat_messages` and deletes `.aether/CHAT_INBOX.md`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/chat/clear
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(none)* | — | — | No | No request body required. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | `"ok"`. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/chat/clear
```

---

## GET /api/ai/status

Returns the static AI bridge status (`{"status":"idle"}`). Note that live thinking/ready state is exposed on `GET /api/ai/chat` via `agent_status`.

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/ai/status
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(none)* | — | — | No | No query or body parameters. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `string` | Always `"idle"`. |

### 💡 Example

```bash
curl -s http://127.0.0.1:3030/api/ai/status
```

---

## POST /api/ai/cancel

Clears active `telemetry` and appends an `"ai"` cancellation notice if the last chat message was sent by `"user"`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/cancel
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(none)* | — | — | No | No request body required. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `message` | `string` | `"ok"` and `"Requête IA annulée"`. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/cancel
```

---

## POST /api/ai/new_session

Resets the AI session by clearing `chat_messages`, clearing telemetry, and deleting `.aether/ai_telemetry_cache.json`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/new_session
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(none)* | — | — | No | No request body required. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `message` | `string` | `"ok"` and `"Nouvelle session démarrée"`. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/new_session
```

---

## POST /api/ai/launch_cli

Records and acknowledges a CLI launch payload for external AI tools without spawning an OS terminal subprocess on the server.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/ai/launch_cli
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `tool` | JSON Body | `string` | Optional | Tool identifier (defaults to `"gemini"`). |
| `project_path` | JSON Body | `string` | Optional | Target project path metadata. |
| `prompt` | JSON Body | `string` | Optional | Initial prompt metadata. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `message`, `tool`, `project_path`, `prompt` | `string` / `null` | Echoed launch metadata. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/ai/launch_cli \
  -H "Content-Type: application/json" \
  -d '{"tool":"gemini","project_path":".","prompt":"Audit security"}'
```

---

## GET /api/ai/system_prompt

Detects the active project stack and generates the optimized AI system prompt (including active `server_port` and `AETHER_AI_RULES.md` if present).

### 🎮 Endpoint

```text
GET http://127.0.0.1:3030/api/ai/system_prompt
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| *(none)* | — | — | No | No query or body parameters. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status`, `project_name`, `project_path`, `stack`, `system_prompt` | `string` | `stack` is detected as `"rust"`, `"python"`, `"php"`, `"cpp"`, `"java"`, `"ts"`, or `"hybrid"`. |

### 💡 Example

```bash
curl -s http://127.0.0.1:3030/api/ai/system_prompt
```

---

## GET and POST /api/tasks

Lists or creates persistent tasks stored under `.aether/tasks/<task_id>/task.json` + `README.md` and indexed in `.aether/TASKS_SUMMARY.md`.

### 🎮 Endpoint

```text
GET  http://127.0.0.1:3030/api/tasks
POST http://127.0.0.1:3030/api/tasks
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `title` | JSON Body (`POST`) | `string` | **Yes** | Task title. |
| `kind` | JSON Body (`POST`) | `string` | Optional | `function` (default), `research`, `security_fix`, `arch_refactor`, `documentation`, `test`, or `other`. |
| `target_symbol`, `target_file` | JSON Body (`POST`) | `string` | Optional | Target symbol or file path (triggers `"Création de Tâche"` telemetry for agent/non-user authors). |
| `author`, `agent_id`, `agent_name`, `color`, `priority`, `initial_readme` | JSON Body (`POST`) | `string` | Optional | `author` defaults to `"user"`; `priority` defaults to `"medium"`. |

### 💎 Response

| Method / Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` (`200 OK`) | `status`, `tasks` | `"ok"`, `TaskItem[]` | Tasks sorted by `updated_at` descending. |
| `POST` (`200 OK`) | `status`, `task` | `"ok"`, `TaskItem` | Newly created task (or `{ "status": "error", "message": ... }` on I/O failure). |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title":"Fix CWE-89","kind":"security_fix","target_file":"src/db.rs","priority":"high"}'
```

---

## POST /api/tasks/update

Updates task metadata, status, progress percentage, or Markdown notes in `.aether/tasks/<task_id>/`, regenerating `.aether/TASKS_SUMMARY.md`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/tasks/update
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `task_id` | JSON Body | `string` | **Yes** | Task identifier. |
| `status` | JSON Body | `string` | Optional | `pending`, `in_progress`, `blocked`, `done`, or `cancelled`. Setting `done` forces `progress = 100`. |
| `progress` | JSON Body | `number` (`0..=100`) | Optional | Auto-transitions `pending` -> `in_progress` if `> 0`, or `done` if `100`. |
| `progress_note`, `full_readme`, `title`, `target_symbol`, `target_file`, `priority`, `agent_id`, `agent_name`, `color` | JSON Body | `string` | Optional | `progress_note` appends to the task `README.md`; `full_readme` replaces it. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "not_found" \| "error"` | `"not_found"` returns `message: "Tâche introuvable"`. |
| `200 OK` | `task` | `TaskItem` *(when `"ok"`)* | Updated task object. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/tasks/update \
  -H "Content-Type: application/json" \
  -d '{"task_id":"task_123_fix_cwe_89","status":"done","progress":100,"progress_note":"Parameterized query"}'
```

---

## POST /api/tasks/delete

Deletes a task directory from `.aether/tasks/` and refreshes `.aether/TASKS_SUMMARY.md`.

### 🎮 Endpoint

```text
POST http://127.0.0.1:3030/api/tasks/delete
```

### 📝 Parameters

| Name | In | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `task_id` | JSON Body | `string` | **Yes** | Task identifier to remove. |

### 💎 Response

| Status | Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `200 OK` | `status` | `"ok" \| "error"` | Operation outcome. |
| `200 OK` | `deleted` | `boolean` *(when `"ok"`)* | `true` if the task existed and was removed. |

### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/tasks/delete \
  -H "Content-Type: application/json" \
  -d '{"task_id":"task_123_fix_cwe_89"}'
```

## Next Steps

{% content-ref url="./rest-api-security-plugins.md" %}
[REST API: Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="./mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](./mcp-server.md)
{% endcontent-ref %}
