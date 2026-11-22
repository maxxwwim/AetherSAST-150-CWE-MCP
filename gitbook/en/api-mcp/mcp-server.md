# Native MCP Server (aetherscope-mcp)

Connect AI agents to AetherScope over JSON-RPC 2.0 (`2024-11-05`) stdio transport with automatic headless backend startup, 10 consolidated tools (plus 15 legacy aliases), 5 `aether://*` resources, 5 prompts, and 12-color swarm telemetry.

The dedicated `aetherscope-mcp` binary (`2.6.0`) runs standalone against local `.aether/` and Rust AST crates when offline, or proxies live updates to `127.0.0.1:3030` while respecting `LocalGuard`, `PathGuard`, `SecretGuard`, and `SecretMasker`.

{% hint style="info" %}
**Canonical Version (`2.6.0`) vs. Legacy Labels**: Workspace `Cargo.toml`, `mcp.json`, and `initialize.serverInfo.version` (`env!("CARGO_PKG_VERSION")`) all report **`2.6.0`**. Two packaging/banner strings still carry older labels in the repository: `smithery.yaml` declares `version: "2.5.1"`, and the clap `about` banner in `crates/desktop-shell/src/mcp_main.rs` prints `"AetherScope V2.4 - Dedicated MCP Server for AI Agents"`.
{% endhint %}

---

## Launch Modes & Client Configuration

You can start the MCP stdio server either through the dedicated `aetherscope-mcp` binary or directly from `aether-engine --mcp`.

{% tabs %}
{% tab title="aetherscope-mcp (Auto-Spawn)" %}
```bash
# Default launch on port 3030 targeting the current directory
aetherscope-mcp --port 3030 --path .

# Launch with explicit multi-agent swarm identity
aetherscope-mcp --port 3030 --path C:\projects\my-app \
  --agent-id sec-auditor --agent-name "Sec Auditor" --color "#f472b6"
```

When `aetherscope-mcp` starts:
1. Checks `127.0.0.1:<port>` with a `150 ms` TCP connect timeout (`mcp::check_server_listening`).
2. If nothing is listening, looks for `aether-engine.exe` in the same directory as `std::env::current_exe()` and spawns `aether-engine.exe --no-gui --port <port> --path <path>`.
3. Polls TCP readiness up to **10 × 150 ms** (`1.5 s` maximum).
4. Starts `mcp::run_mcp_stdio_loop(port, &path)` even if no HTTP backend is reachable (offline AST/disk fallback).
{% endtab %}
{% tab title="aether-engine --mcp (In-Process)" %}
```bash
# Embed the Axum server and MCP stdio loop in one process
aether-engine --mcp --port 3030 --path .
```

When `aether-engine --mcp` runs and `127.0.0.1:<port>` is free, it spawns `run_server_and_watcher` in a background Tokio task, waits `350 ms`, and enters `mcp::run_mcp_stdio_loop`. Note that `--agent-id`, `--agent-name`, and `--color` CLI flags exist only on `aetherscope-mcp`; `aether-engine --mcp` uses `AETHER_AGENT_*` environment variables, `initialize.params.clientInfo.name`, or per-tool parameters.
{% endtab %}
{% tab title="setup-mcp.ps1 (Auto-Setup)" %}
```powershell
# Automatically configure Claude Desktop, Antigravity / Gemini CLI, and Cursor
.\setup-mcp.ps1 -Port 3030
```

`setup-mcp.ps1` searches `[scriptDir, target\release, %LOCALAPPDATA%\AetherScope\bin]` for `aetherscope-mcp.exe` and merges `"aetherscope": { "command": "...", "args": ["--port", "3030"] }` under `mcpServers` in:
* `%APPDATA%\Claude\claude_desktop_config.json` (Claude Desktop)
* `%USERPROFILE%\.gemini\config\mcp_config.json` (Antigravity / Gemini CLI)
* `%USERPROFILE%\.cursor\mcp.json` (Cursor)
{% endtab %}
{% endtabs %}

### CLI Flags & Packaging Files

| Component | Flags / Keys | Default | Notes |
|---|---|---|---|
| `aetherscope-mcp` (`mcp_main.rs`) | `-p, --path`, `--port`, `--mcp`, `--agent-id`, `--agent-name`, `--color` | `"."`, `3030`, `false` | Auto-spawns `aether-engine.exe --no-gui` if port is unbound. |
| `mcp.json` | `name`, `version`, `capabilities`, `mcpServers.aetherscope` | `2.6.0`, `--port 3030 --path .` | Standard manifest enabling `tools`, `resources`, and `prompts`. |
| `smithery.yaml` | `startCommand.type: stdio`, `configSchema.{port, path}` | `3030`, `"."` | Invokes `aetherscope-mcp --port <port> --path <path>` (`version: "2.5.1"`). |
| `GET /api/settings` | `mcp_binary_path` | Adjacent `aetherscope-mcp(.exe)` | Exposes the resolved binary path for UI copy-paste setup. |

---

## JSON-RPC 2.0 Protocol & Transport

`run_mcp_stdio_loop` reads newline-delimited UTF-8 JSON-RPC 2.0 messages from `stdin`, strips any leading UTF-8 BOM (`\u{feff}`), skips blank lines, and writes single-line flushed JSON responses to `stdout`.

| Method | Purpose | Error / Edge Behavior |
|---|---|---|
| `initialize` | Registers `params.clientInfo.name`, emits `"Connexion MCP"` telemetry, and returns `protocolVersion: "2024-11-05"`, `capabilities`, and `serverInfo` (with `agentIdentity`). | `capabilities` sets `listChanged: false` and `subscribe: false`. |
| `notifications/initialized` | Client readiness notification. | Returns `None` (no stdout response emitted). |
| `ping` | Liveness check. | Returns `{}`. |
| `resources/list` | Lists all 5 `aether://*` resources. | — |
| `resources/read` | Reads a resource by `params.uri`. | Returns `-32602` (`"Resource not found: <uri>"`) for unknown URIs. |
| `prompts/list` | Lists all 5 workflow prompts. | — |
| `prompts/get` | Renders prompt messages using `params.name` and `params.arguments`. | Returns `-32602` (`"Prompt not found: <name>"`) for unknown names. |
| `tools/list` | Lists the 10 consolidated tools (excluding the 15 legacy aliases). | Every tool enforces `additionalProperties: false` and all 4 MCP hints. |
| `tools/call` | Executes a consolidated tool or legacy alias with `params.name` and `params.arguments`. | Returns `{ content: [{ type: "text", text }], isError }`. |

Malformed JSON returns `-32700` (`"Parse error: ..."`), and unknown JSON-RPC methods return `-32601` (`"Method not found"`).

---

## Multi-Agent Swarm Identity & Offline Resilience

When multiple AI agents inspect the same codebase simultaneously, AetherScope assigns each agent a distinct badge and color in the 3D Cockpit HUD and chat drawer.

### Identity Precedence & 12-Color Palette

Identity is resolved in strict priority order:
1. **Per-tool arguments**: `agent_id` (or `agent`, `caller`, `author`, `sender`, `role`), `agent_name` (or `name`), and `color`.
2. **CLI flags**: `--agent-id`, `--agent-name`, `--color` on `aetherscope-mcp` (sets `explicit_identity = true`).
3. **Environment variables**: `AETHER_AGENT_ID`, `AETHER_AGENT_NAME`, `AETHER_AGENT_COLOR`.
4. **MCP handshake**: `initialize.params.clientInfo.name` (when `explicit_identity` is `false`, generates `{slug}-{pid % 10000}` and `{clean_name} (#{pid % 1000})`).
5. **Process fallback**: `mcp-agent-{pid % 10000}` and `IA MCP #{pid % 1000}`.

If `color` is omitted, `mcp_assign_agent_color` computes a **64-bit FNV-1a hash** (`init = 14695981039346656037`, `prime = 1099511628211`) over `"{agent_id}:{agent_name}"` (returning `#38bdf8` for empty or `primary-agent:` seeds) modulo 12 into `MCP_AGENT_PALETTE`:

| Index | Hex | Label | Index | Hex | Label |
|---|---|---|---|---|---|
| `0` | `#38bdf8` | Cyan (Sky) | `6` | `#22d3ee` | Bright Cyan |
| `1` | `#c084fc` | Purple | `7` | `#fb7185` | Rose |
| `2` | `#34d399` | Emerald | `8` | `#818cf8` | Indigo |
| `3` | `#f472b6` | Pink | `9` | `#fb923c` | Orange |
| `4` | `#f59e0b` | Amber | `10` | `#2dd4bf` | Teal |
| `5` | `#a3e635` | Lime | `11` | `#e879f9` | Fuchsia |

### Telemetry Cache & `LocalGuard` HTTP Transport

* **Offline telemetry persistence**: `emit_mcp_telemetry` writes `.aether/ai_telemetry_cache.json` (`{ telemetry, agents, history }`, deduplicating consecutive identical `(agent_id, target, action)` entries and capping `history` at `250`) before attempting `POST /api/ai/telemetry`.
* **Raw HTTP client**: `send_http_request` connects to `127.0.0.1:<port>` (`1500 ms` connect, `45 s` read, `30 s` write) with `Host: 127.0.0.1:<port>` and **no `Origin` header**, satisfying `LocalGuard`.
* **Offline execution**: If the Axum server is down, graph, target, search, view-mode, task, verification, and plugin tools run directly against local crates (`ast_scanner`, `obsidian_vault`, `ai_file_bridge`, `security_linter`). Only `aetherscope_chat` (`send` and `history`) requires the live HTTP backend (`/api/ai/chat`) and returns `isError: true` when unreachable.

---

## Consolidated MCP Tools (10 Tools)

All 10 tools returned by `tools/list` declare `additionalProperties: false` and include all 4 MCP behavior hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) both at top level and under `annotations`. Every tool also accepts optional `agent_id`, `agent_name`, and `color` swarm overrides.

### 1. `aetherscope_get_graph_summary`

Summarize project AST topology, SAST/CWE violations, active tasks, and pending cockpit chat alerts.

#### 🎮 Tool

```text
aetherscope_get_graph_summary
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | No | Project root path (defaults to server `--path`). |
| `rescan` | `boolean` | No | Force `POST /api/analyze` before computing the summary (default `false`). |
| `include_tasks` | `boolean` | No | Append up to 10 active (non-`Done`/non-`Cancelled`) tasks from `TaskManager` (default `true`). |
| `severity` | `string` | No | Optional violation breakdown filter: `"all"`, `"critical"`, `"high"`, `"medium"`, `"low"`, or `"warning"`. |
| `agent_id` / `agent_name` / `color` | `string` | No | Optional multi-agent swarm telemetry overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Formatted AST summary, optional active task list, severity breakdown, and `PENDING_AI_RESPONSE` alert if `.aether/CHAT_INBOX.md` awaits reply. |
| `isError` | `boolean` | `false` on success; `true` if analysis fails. |

#### 💡 Example

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

Inspect a symbol, file, or Obsidian note, retrieve its `<aether_handshake>` EARS contract and callers/dependencies, and trace data/call flow.

#### 🎮 Tool

```text
aetherscope_get_active_target
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `symbol_id` | `string` | **Yes** | Symbol ID/name, relative file path, or Obsidian note ID (`note::...`). |
| `action` | `string` | No | 3D HUD action badge (default `"Inspection"`). |
| `details` | `string` | No | Short telemetry note (default `"Inspection combinée Cible + Contrat EARS + Flux"`). |
| `trace_direction` | `string` | No | Flow trace mode: `"both"` (default), `"upstream"`, `"downstream"`, or `"none"`. |
| `max_depth` | `integer` | No | Flow trace depth `1..=5` (default `2`). Note: current `format_trace_flow_response` inspects direct 1-hop incoming/outgoing edges (`take(15)`). |
| `path` / `agent_id` / `agent_name` / `color` | `string` | No | Optional workspace path and swarm identity overrides. |

{% hint style="danger" %}
**SecretGuard & SecretMasker**: Paths matching `SecretGuard::is_secret_path` (such as `.env`, SSH keys, or credentials) are blocked immediately with `isError: true`, and all returned content passes through `SecretMasker::mask_text`.
{% endhint %}

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Target handshake XML, EARS contract rules, BLAKE3 status, and upstream/downstream trace. |
| `isError` | `boolean` | `true` if blocked by `SecretGuard` or symbol not found. |

#### 💡 Example

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

Search symbols, files, CWE violations, Obsidian notes/tags, and manage Bug Bounty PoC scope filtering.

#### 🎮 Tool

```text
aetherscope_search_symbols
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `query` | `string` | No | Keyword, `#tag`, YAML alias, or heading (default `""`). |
| `layer` | `string` | No | `"ui"`, `"action"`, `"domain"`, `"database"`, `"utility"`, `"config"`, `"docs"`, or `"all"`. |
| `kind` | `string` | No | `"function"`, `"file"`, `"class"`, `"endpoint"`, `"contract"`, or `"all"`. |
| `stereotype` | `string` | No | Stereotype filter such as `'«Model»'`, `'«Controller»'`, `'«Note»'`, `'«GhostNote»'`, or `'«Attachment»'`. |
| `has_violation` | `boolean` | No | Filter symbols with SAST violations (forced `true` automatically if `cwe_id` or `severity` is provided). |
| `cwe_id` / `severity` / `file_pattern` | `string` | No | CWE filter (e.g. `"CWE-89"`), severity (`"all"`, `"critical"`, `"high"`, `"medium"`, `"low"`, `"warning"`), and file glob/substring. |
| `limit` | `integer` | No | Maximum results `1..=50` (default `15`). |
| `scope_mode` | `string` | No | Bug Bounty scope filter/action: `"all"` (default), `"in_scope_only"`, `"out_of_scope_only"`, `"recommend_scope"`, or `"configure_scope"`. |
| `in_scope` / `out_of_scope` | `string[]` | No | Folder lists persisted to `.aether/bounty_scope.json` when `scope_mode="configure_scope"`. |
| `scope_rationale` | `string` | No | Justification saved in `BountyScopeConfig`. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | No | Optional project path and swarm identity overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Matching symbols/notes/violations (excluding `SecretGuard` paths and masked via `SecretMasker::mask_text`), or bounty scope configuration/recommendations. |
| `isError` | `boolean` | `false` on success. |

#### 💡 Example

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

Switch the Cockpit rendering mode between source code AST (`"code"`) and Obsidian Markdown Vault (`"vault"`).

#### 🎮 Tool

```text
aetherscope_switch_view_mode
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `mode` | `string` | **Yes** | `"code"` or `"vault"`. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | No | Project path (used in offline `detect_project_type` fallback) and swarm identity. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Confirmation of active mode (via `POST /api/view_mode` or offline `obsidian_vault::detect_project_type` summary). |
| `isError` | `boolean` | `true` on invalid mode. |

#### 💡 Example

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

List, create, update, or delete persistent AI tasks stored under `.aether/tasks/` and `.aether/TASKS_SUMMARY.md`.

#### 🎮 Tool

```text
aetherscope_manage_tasks
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `action` | `string` | **Yes** | `"list"`, `"create"`, `"update"`, or `"delete"`. |
| `task_id` | `string` | Conditional | Required at runtime for `"update"` and `"delete"`. |
| `title` | `string` | No | Task title (defaults to `"Nouvelle tâche"` on `"create"`). |
| `kind` | `string` | No | `"function"` (default), `"research"`, `"security_fix"`, `"arch_refactor"`, `"documentation"`, `"test"`, or `"other"`. |
| `target_symbol` / `target_file` | `string` | No | Target symbol and file; emits 3D camera telemetry when set on `"create"`/`"update"`. |
| `priority` | `string` | No | `"low"`, `"medium"`, `"high"`, or `"critical"`. |
| `status` | `string` | No | `"pending"`, `"in_progress"`, `"blocked"`, `"done"`, or `"cancelled"` (used on `"update"`). |
| `progress` | `integer` | No | Completion percentage `0..=100` (used on `"update"`). |
| `progress_note` | `string` | No | Timestamped progress entry appended to the task's `README.md`. |
| `initial_readme` / `full_readme` | `string` | No | Initial Markdown on `"create"` or full replacement Markdown on `"update"`. |
| `status_filter` | `string` | No | Filter for `"list"`: `"active"` (default), `"all"`, or `"done"` (also accepts legacy `status` key). |
| `path` / `agent_id` / `agent_name` / `color` | `string` | No | Workspace path and swarm identity overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Formatted task list or created/updated/deleted task confirmation. |
| `isError` | `boolean` | `true` if `task_id` is missing/not found or I/O fails. |

#### 💡 Example

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

Run the `<50ms` `PatchVerifier` AI Firewall over modified files, checking BLAKE3 locks, EARS contract limits, forbidden imports, and SAST/CWE regressions, with optional task completion and chat debrief.

#### 🎮 Tool

```text
aetherscope_verify_patch
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `files_modified` | `string[]` | **Yes** | Non-empty list of modified relative file paths to audit. |
| `task_id` | `string` | No | Optional task ID automatically updated when the patch is **not** rejected. |
| `status` | `string` | No | Task status when `task_id` is provided (default `"done"`). |
| `progress` | `integer` | No | Task progress `0..=100` when `task_id` is provided (default `100`). |
| `progress_note` | `string` | No | Note appended when `task_id` is provided (default `"Patch validé par aetherscope_verify_patch"`). |
| `chat_message` | `string` | No | Debrief message posted to `POST /api/ai/chat` if the patch is approved. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | No | Workspace path and swarm identity overrides. |

{% hint style="danger" %}
**Immediate `PATCH_REJECTED`**: If any path in `files_modified` matches `SecretGuard::is_secret_path`, or if `PatchVerifier::verify_patch` returns `PatchVerdict::Rejected`, the tool returns `isError: true` and skips any automatic task/chat updates.
{% endhint %}

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Firewall verdict (`APPROVED` / `WARNING` / `PATCH_REJECTED`), EARS/SAST violation details, and optional task update confirmation. |
| `isError` | `boolean` | `true` when rejected or `files_modified` is empty. |

#### 💡 Example

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

Send messages or hand-offs to the Cockpit chat drawer, inspect recent conversation history, or list active swarm agents.

#### 🎮 Tool

```text
aetherscope_chat
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `action` | `string` | No | `"send"`, `"history"`, or `"swarm"`. Defaults to `"send"` if `text` is non-empty, otherwise `"history"`. |
| `text` | `string` | Conditional | Message body (required non-empty when `action="send"`). |
| `thought` | `string` | No | Optional reasoning wrapped as `<thought>\n...\n</thought>\n` ahead of `text`. |
| `target_symbol` | `string` | No | Symbol context; emits `"Debrief Chat IA"` telemetry when non-empty. |
| `recipient` | `string` | No | Target agent handle on `"send"`, or case-insensitive filter on `"history"` (`recipient == filter \|\| recipient == "all" \|\| text.contains("@filter")`). |
| `agent_id` / `agent_name` / `color` | `string` | No | Swarm identity overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Message confirmation, filtered chat history, or active swarm roster. |
| `isError` | `boolean` | `true` if `action="send"`/`"history"` is called while the live Axum server is unreachable. |

#### 💡 Example

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

List, unit-test, scan with, create/update, toggle, or initialize declarative YAML/JSON security and SSA taint plugins in `.aether/plugins/`.

#### 🎮 Tool

```text
aetherscope_manage_plugins
Hints: readOnlyHint=false, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `action` | `string` | **Yes** | `"list"`, `"test"`, `"scan"`, `"upsert"`, `"toggle"`, or `"init_bundle"`. |
| `target_path` | `string` | Conditional | Required for `"scan"`; confined by `SecretGuard` and `PathGuard` canonical project-root validation. |
| `plugins_dir` | `string` | No | Plugin directory path (default `".aether/plugins"`). |
| `plugin_name` | `string` | Conditional | Required for `"upsert"` (strictly `[a-zA-Z0-9_-]`) and `"toggle"`. |
| `enabled` | `boolean` | Conditional | Required for `"toggle"`. |
| `rule_id` / `cwe_id` / `file_extensions` | `string` / `string` / `string[]` | Conditional | Required at runtime for `"upsert"`. |
| `profile` / `tags` / `name` / `description` / `remediation` / `category` | mixed | No | Optional manifest/rule metadata for `"upsert"` (`category` defaults to `"Custom / Security"`). |
| `severity` / `match_mode` | `string` | No | `severity`: `"CRITICAL"`, `"HIGH"` (default), `"MEDIUM"`, `"WARNING"`, `"LOW"`. `match_mode`: `"line_by_line"` (default) or `"whole_file"`. |
| `must_contain` / `must_not_contain` / `regex_patterns` / `forbidden_tokens` | `string[]` | No | Rule matching conditions for `"upsert"`. |
| `check_literals` | `boolean` | No | Match inside string literals/comments (default `false`). |
| `not_preceded_within_lines` | `object` | No | `{ "patterns": string[], "lines": integer >= 1 }`. |
| `in_path_matching` / `not_in_path_matching` | `string[]` | No | Path inclusion/exclusion globs. |
| `ast_scope` | `string` | No | `"outside_test"`, `"test"`, `"async_fn"`, `"sync_fn"`, or `"fn"`. |
| `taint_sources` / `taint_sinks` / `sanitizers` | `object[]` | No | `TaintSourceRule`, `TaintSinkRule`, and `SanitizerRule` objects. |
| `test_cases` | `object[]` | No | Array of `{ name, code, file_name, should_trigger }` verified by `run_test_suite()` before writing `<plugins_dir>/<plugin_name>/plugin.yaml`. |
| `path` / `agent_id` / `agent_name` / `color` | `string` | No | Workspace path and swarm identity overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Plugin inventory, unit test report, confined scan findings (masked via `SecretMasker`), or upsert/toggle confirmation. |
| `isError` | `boolean` | `true` if confinement fails, required parameters are missing, or `upsert` unit tests fail. |

#### 💡 Example

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

Focus the 3D Cockpit camera on a symbol or file and broadcast an agent telemetry badge (plus active swarm roster if peers are present).

#### 🎮 Tool

```text
aetherscope_teleport_camera
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | **Yes** | Symbol name, struct, or relative file path (e.g. `"RoomBooking"`, `"contracts/packets.rs"`). |
| `action` | `string` | **Yes** | Short action verb displayed on the 3D HUD (runtime fallback `"Inspection"`). |
| `details` | `string` | **Yes** | Concise status note shown to the user (runtime fallback `""`). |
| `agent_id` / `agent_name` / `color` | `string` | No | Swarm identity overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Confirmation of telemetry dispatch, plus active swarm peer list when `peers.len() > 1`. |
| `isError` | `boolean` | `false` |

#### 💡 Example

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

Trigger a full AST, BLAKE3 contract, and SAST/CWE project scan (or Obsidian vault scan in dual-vision projects).

#### 🎮 Tool

```text
aetherscope_scan_project
Hints: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
```

#### 📝 Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | No | Project root path (defaults to server `--path`). |
| `agent_id` / `agent_name` / `color` | `string` | No | Swarm identity overrides. |

#### 💎 Return Value

| Field | Type | Description |
|---|---|---|
| `content[0].text` | `string` | Scan status and node/edge/violation summary (via `POST /api/analyze` or offline `ProjectScanner` / `scan_obsidian_vault`). |
| `isError` | `boolean` | `true` if analysis fails. |

#### 💡 Example

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

## Legacy Tool Aliases (15 Aliases)

While `tools/list` publishes only the 10 consolidated tools above, `tools/call` retains full backward compatibility for all 15 legacy tool names:

| Legacy Tool Name | Consolidated Target | Automatic Argument Mapping |
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
| `aetherscope_trace_flow` | `aetherscope_get_active_target` | `direction` (default `"both"`) and `max_depth` (default `2`) |
| `aetherscope_query_violations` | `aetherscope_get_graph_summary` / `aetherscope_search_symbols` | Queries `severity` or `cwe_id` + `file_pattern` |

---

## MCP Resources (5 `aether://*` URIs)

Query project state directly via `resources/read`:

| URI | Name | MIME Type | Live Source & Offline Fallback |
|---|---|---|---|
| `aether://graph/summary` | `AetherScope 3D AST Graph Summary` | `application/json` | Live: `GET /api/graph?full=1`. Offline: `ProjectScanner::default().scan_project(&default_path)` as pretty JSON. |
| `aether://audit/live` | `AetherScope Live Security Audit (SAST/CWE)` | `text/markdown` | Reads `<default_path>/.aether/LIVE_AUDIT.md`; falls back to scanning and `format_ast_summary`. |
| `aether://contracts/manifest` | `Aether Architecture Manifest` | `application/json` | Checks `aether.manifest.json`, then `.aether/manifest.json`, then `aether.lock.toml` verbatim; fallback `{"status": "unlocked", ...}`. |
| `aether://tasks/active` | `AetherScope Active AI Tasks` | `application/json` | `TaskManager::list_tasks` filtered to exclude `Done` and `Cancelled`. |
| `aether://agents/swarm` | `AetherScope Multi-Agent Swarm & Chat` | `application/json` | Queries `GET /api/ai/telemetry` (`agents`) and `GET /api/ai/chat` (last 20 messages). |

---

## MCP Prompts (5 Workflow Prompts)

Invoke standardized guided workflows via `prompts/get`:

| Prompt Name | Arguments | Generated Workflow Sequence |
|---|---|---|
| `diagnostic_session_start` | `path` (optional, default `"."`) | 1) `aetherscope_get_graph_summary` (`rescan: false, include_tasks: true`) -> 2) `aetherscope_search_symbols` (`has_violation: true, severity: "critical"`) -> 3) `aetherscope_get_active_target` (`trace_direction: "both"`). |
| `surgical_feature_workflow` | `symbol_id` (**required**), `objective` (**required**) | 1) `aetherscope_get_active_target` -> 2) `aetherscope_manage_tasks` (`create`, `kind: "function"`, `priority: "high"`) -> 3) edit respecting parent `README.md` EARS invariants -> 4) `aetherscope_verify_patch` (`status: "done", progress: 100`). |
| `audit_security_cwe` | `symbol_name` (**required**), `cwe_id` (optional, default `"CWE Anomaly"`) | 1) `aetherscope_get_active_target` -> 2) `aetherscope_search_symbols` (`cwe_id`, `has_violation: true`) -> 3) `aetherscope_manage_tasks` (`create`, `kind: "security_fix"`, `priority: "critical"`) -> 4) `aetherscope_verify_patch`. |
| `refactor_contract_violation` | `contract_name` (**required**), `violation_details` (optional) | 1) `aetherscope_get_active_target` -> 2) `aetherscope_manage_tasks` (`create`, `kind: "arch_refactor"`, `priority: "high"`) -> 3) fix `RULE_FORBIDDEN_IMPORT` / `RULE_MAX_LINES` / EARS invariants -> 4) `aetherscope_verify_patch`. |
| `scaffold_game_server` | `engine` (**required**: `'roblox'` \| `'minecraft'`), `package_name` (**required**) | Branches to Roblox Luau (`--!strict`, `contracts/`, `server/`, `client/`, `data-nodes/`) or Minecraft Paper/Purpur (`50ms` Main Thread tick budget, `AsyncScheduler`); runs `aetherscope_manage_tasks(create)` -> `aetherscope_verify_patch`. |

---

## Related Guides

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[Plugin, MCP & Runner CLIs](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="../core/improvements-and-workflows.md" %}
[Improvements, PatchVerifier & AI Firewall](../core/improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-security-plugins.md" %}
[REST API: Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}
