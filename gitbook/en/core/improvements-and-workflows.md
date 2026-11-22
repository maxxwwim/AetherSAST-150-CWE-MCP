# AI Improvements & Patch Firewall

`aether-engine` orchestrates AI-assisted code modifications through a `<50ms` patch firewall (`PatchVerifier`), persistent workspace tasks (`TaskManager`), XML handshakes (`HandshakePacker`), live audit files (`AuditWriter`), and interactive Cockpit studios.

## Overview

Every AI edit in `aether-engine` follows a closed-loop governance cycle. The cockpit or MCP server exports an `<aether_handshake version="2.1">` context envelope, tracks work in `.aether/tasks/`, and gates every modified file through `PatchVerifier` before closing tasks or updating the 3D HUD.

```text
Cockpit / MCP Context ──► <aether_handshake version="2.1"> ──► AI Agent Edits
         ▲                                                           │
         │                                                           ▼
  3D Camera & HUD ◄── POST /api/ai/telemetry ◄── PatchVerifier (<50 ms)
   (Red Laser)           (on rejection)            ├── Approved ──► Task Auto-Closed (100%)
                                                   └── Rejected ──► [🔥 EXPLOITABLE] + Fixes
```

## Real-Time AI Patch Firewall (`PatchVerifier`)

`PatchVerifier` (`crates/ai-file-bridge/src/patch_verifier.rs`) validates modified files incrementally via `PatchVerifier::verify_patch` or `PatchVerifier::verify_patch_with_graph` and returns a `PatchVerificationResult` containing `verdict` (`PatchVerdict::Approved` or `PatchVerdict::Rejected`), `duration_ms`, `files_scanned`, `total_lines`, `violations`, `offending_target`, `exploit_paths`, and `formatted_output`.

### Verification Pipeline (`< 50 ms`)

For every path in `files_modified`, `PatchVerifier` runs seven sequential checks:

1. **Lock Hash Loading**: `parse_locked_hashes` reads `aether.lock.toml` `[galaxies.*]` sections to map each folder `path` (and galaxy key) to its sealed `readme_blake3` digest.
2. **Secret Path Block (`SecretGuard`)**: `SecretGuard::is_secret_path` rejects `.env`, private keys, or credential paths immediately with `PROHIBITED_SECRET_FILE_MODIFICATION` (`CWE-538 / SENSITIVE-SECRETS-PROHIBITED`, `CRITICAL`) and skips reading file contents.
3. **File Read Check**: `std::fs::read_to_string` verifies the modified path exists and is readable; missing files emit `FILE_NOT_FOUND` (`CWE-706 / FILE-NOT-FOUND`, `HIGH`).
4. **BLAKE3 Contract Integrity**: If the filename ends with `readme.md` (case-insensitive), `ReadmeContract::parse` and `verify_lock` compare its BLAKE3 hash against `aether.lock.toml`; any mismatch emits `BLAKE3_TAMPERED` (`CWE-353 / BLAKE3-INTEGRITY`, `CRITICAL`).
5. **Contract Line Budget (`RULE_MAX_LINES`)**: `find_parent_contract` walks up to the nearest `README.md` contract and checks `effective_max_lines`. Files without an explicit `file_max_lines` override ending in `_test.rs`, containing `/tests/`, or ending in `.t.sol` are exempt; otherwise exceeding the budget emits `RULE_MAX_LINES` (`CONTRACT / ARCH-BUDGET-EXCEEDED`, `WARNING`).
6. **Incremental SAST Audit**: `SecurityLinter::audit_file` runs native CWE/`AETHER-*` detectors alongside EARS contract rules (`RULE_FORBIDDEN_IMPORT`, `RULE_FORBIDDEN_FUNCTION`, `SAST_DIRECT_ENV_ACCESS`).
7. **Source-to-Sink Reachability (`[🔥 EXPLOITABLE]`)**: Using the supplied `AetherGraph` or a live `GET /api/graph` fetch (`30 ms` connect, `150 ms` read, `50 ms` write timeout), `PatchVerifier` injects violations as `CveAnomalyRecord` entries and runs `compute_reachability`. Reachable paths produce `[🔥 EXPLOITABLE]` badges; when no graph is available, `detect_local_endpoint` scans lines for `#[get(`, `#[post(`, `app.get(`, `app.post(`, `pub async fn handle_`, or `pub async fn endpoint_` and builds `"{ep} -> handler -> {rule_id} (L{line})"`.

### Rejection Predicate & Red-Laser Telemetry

A patch returns `PatchVerdict::Rejected` (`[PATCH_REJECTED]`) if **any** violation meets at least one of these conditions:

* `severity == "CRITICAL"` or `severity == "HIGH"`
* `rule_id == "RULE_FORBIDDEN_IMPORT"`
* `rule_id == "BLAKE3_TAMPERED"`
* `rule_id == "FILE_NOT_FOUND"`

{% hint style="info" %}
`RULE_MAX_LINES` carries severity `WARNING`. Line-budget warnings appear in the verification report without triggering patch rejection on their own.
{% endhint %}

When rejected, `emit_telemetry` opens a raw TCP connection to `127.0.0.1:<port>` (default `3030`, `40 ms` connect, `100 ms` write timeout) and sends `POST /api/ai/telemetry` with `agent_name: "Pare-Feu IA [REJETÉ]"` and `target: "{file}:{line}"`. The Cockpit teleports the WebGL camera onto the offending node and activates the red alert laser and HUD banner.

{% tabs %}
{% tab title="Approved Output" %}
```text
================================================================================
✅ [PATCH_APPROVED] AETHERSCOPE AI FIREWALL — CONFORMITÉ VALIDÉE
================================================================================
Scan incrémental exécuté en 14.2 ms sur 1 fichier(s) modifié(s) (128 LOC).
Résultat : 0 régression SAST, 0 violation architecturale, 0 altération de contrat.
```
{% endtab %}

{% tab title="Rejected Output" %}
```text
================================================================================
🚨 [PATCH_REJECTED] AETHERSCOPE AI FIREWALL — VIOLATIONS DÉTECTÉES
================================================================================
1. [CRITICAL] SQL_INJECTION (CWE-89) [🔥 EXPLOITABLE]
   Fichier     : src/api/orders.rs:42
   Exploit     : #[post("/orders")] -> handler -> SQL_INJECTION (L42)
   Remédiation : Use parameterized queries instead of string formatting.

📡 ACTION DU COCKPIT :
Caméra WebGL téléportée sur 'src/api/orders.rs:42' (Laser rouge & HUD alerte activés).
```
{% endtab %}
{% endtabs %}

## Persistent Task Manager (`TaskManager`)

`TaskManager` (`crates/ai-file-bridge/src/tasks.rs`) persists development and remediation tasks on disk inside `.aether/tasks/` so humans, CLI tools, and MCP agents share one source of truth.

### Disk Layout & Summary File

* **Structured task folder**: Each task is stored at `.aether/tasks/<task_id>/task.json` and `.aether/tasks/<task_id>/README.md`.
* **Legacy flat fallback**: `get_task` and `list_tasks` also read legacy `.aether/tasks/<task_id>.json` files seamlessly.
* **Auto-generated summary**: Every `create_task_with_agent`, `update_task_with_meta`, and `delete_task` call regenerates `.aether/TASKS_SUMMARY.md` (`sync_tasks_summary_markdown`) with an active task table, completed checklist, and up to 5 active task `README.md` bodies.
* **Slug ID format**: `task_{timestamp_ms % 1_000_000}_{slug}`, where `slugify` joins up to `4` lowercase alphanumeric words with `_`.

### `TaskKind` & `TaskStatus` Variants

| `TaskKind` | Serde String | Icon | `TaskStatus` | Serde String | Badge |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Function` *(default)* | `"function"` | `⚙️` | `Pending` *(default)* | `"pending"` | `⏳ EN ATTENTE` |
| `Research` | `"research"` | `🔍` | `InProgress` | `"in_progress"` | `⚡ EN COURS` |
| `SecurityFix` | `"security_fix"` | `🛡️` | `Blocked` | `"blocked"` | `⛔ BLOQUÉ` |
| `ArchRefactor` | `"arch_refactor"` | `🏛️` | `Done` | `"done"` | `✅ TERMINÉ` |
| `Documentation` | `"documentation"` | `📖` | `Cancelled` | `"cancelled"` | `⚪ ANNULÉ` |
| `Test` | `"test"` | `🧪` | — | — | — |
| `Other` | `"other"` | `📌` | — | — | — |

### Progress Auto-Promotion & MCP Auto-Closure

* **Status/progress synchronization** (`update_task_with_meta`): Setting `status` to `Done` forces `progress = 100` if below `100`. Setting `progress == 100` on a `Pending` task promotes it to `Done`, while `progress > 0` on `Pending` promotes it to `InProgress`.
* **1-call verification and closure** (`crates/desktop-shell/src/mcp.rs`): When `aetherscope_verify_patch` returns `PatchVerdict::Approved` and `task_id` is provided, the MCP server defaults `status` to `"done"`, `progress` to `100`, and `progress_note` to `"Patch validé par aetherscope_verify_patch"`, updates `.aether/tasks/<task_id>/`, pushes `POST /api/tasks/update` to the running Cockpit, and forwards `chat_message` via `POST /api/ai/chat`.

## XML Handshake (`<aether_handshake>`) & `AuditWriter`

### `<aether_handshake version="2.1">` (`HandshakePacker`)

`HandshakePacker::build_categorized_prompt` (`crates/ai-file-bridge/src/handshake.rs`) packages a symbol's architectural context into compact XML designed to prevent LLM context bloat:

* **`<action>` & `<target>`**: Operation type (`Refactor`, `Test`, `Audit`, `Doc`, `Target`) plus `<name>`, `<file>` (`path:line`), `<galaxy>`, and `<layer>`.
* **`<context>` (`<in_degree>` / `<out_degree>`)**: Groups liaisons into all 7 `CategorizedLiaisons` buckets (`form_submit`, `network_http`, `realtime_ws`, `database_query`, `caller`, `dependency`, `violation`). Each bucket renders at most **4** entries and appends `<more_hidden count="N" />` when larger.
* **`<contract_rules>`**: Optional `<max_lines>`, `<allowed_imports>`, `<forbidden_imports>`, `<forbidden_functions>`, `<allowed_extensions>`, `<forbidden_extensions>`, and `<max_files_per_folder>`.
* **`<mcp_commands>` & `<instruction>`**: Pre-fills `aetherscope_get_active_target`, `aetherscope_manage_tasks`, and `aetherscope_verify_patch`, and requires the agent to reply with `[AETHER_ACK] ... [/AETHER_ACK]` before editing code.

<details>
<summary>Example &lt;aether_handshake version="2.1"&gt; XML payload</summary>

```xml
<aether_handshake version="2.1">
  <action>SecurityFix</action>
  <target>
    <name>handle_order</name>
    <file>crates/api/src/orders.rs:42</file>
    <galaxy>api</galaxy>
    <layer>action</layer>
  </target>
  <context>
    <in_degree total="6">
      <network_http_group count="1">
        <network_http>POST /api/orders</network_http>
      </network_http_group>
      <caller_group count="5">
        <caller>router::mount_routes</caller>
        <caller>tests::smoke_orders</caller>
        <caller>legacy::v1_orders</caller>
        <caller>admin::replay_order</caller>
        <more_hidden count="1" />
      </caller_group>
    </in_degree>
    <out_degree total="1">
      <database_query_group count="1">
        <database_query>sqlx::query</database_query>
      </database_query_group>
    </out_degree>
  </context>
  <instruction>
    Avant d'écrire le code, réponds obligatoirement avec ce bloc de confirmation :
    [AETHER_ACK]
    Cible : handle_order
    Imports interdits pris en compte : OUI
    Commandes MCP combinées : aetherscope_get_active_target -> aetherscope_manage_tasks -> aetherscope_verify_patch
    Audit live surveillé dans .aether/LIVE_AUDIT.md : OUI
    [/AETHER_ACK]
  </instruction>
</aether_handshake>
```

</details>

### `AuditWriter` Files & Stack Detection

Every file produced by `AuditWriter` (`crates/ai-file-bridge/src/audit_writer.rs`) passes through `safe_write_in_root`, which rejects `..` (`Component::ParentDir`) and any target outside `project_root`:

| Generated File | Trigger / Method | Purpose |
| :--- | :--- | :--- |
| `.aether/LIVE_AUDIT.md` | `write_live_audit` (on file watcher save) | Filters out `RULE_MAX_LINES` / `WARNING` entries to show either `## ✅ ARCH_OK` or a severity table (`🔴 CRITIQUE`, `🟠 HAUT`, `🟡 MOYEN`, `⚪ AVERTISSEMENT`) with `📦 Donnée` and `Fix:`. |
| `.aether/ACTIVE_TARGET.md` | `write_active_target_categorized` (on target selection) | Writes symbol metadata, `CategorizedLiaisons` upstream/downstream (`"amont"` / `"aval"`, capped at 4 per category), parent `README.md` EARS rules, matching active tasks, and 3 MCP commands. |
| `AETHER_AI_RULES.md` | `ensure_master_rules_file` | Created at the workspace root on port `3030` only if missing or empty, using `detect_project_stack` + `generate_optimized_system_prompt`. |

`AuditWriter::detect_project_stack` inspects `aether.lock.toml` (matching `"hybrid"`, `"mmo"`, or `"web3"`) and workspace manifests to return `"hybrid"` (also when Cargo + `package.json`/`client/` coexist), `"rust"`, `"python"`, `"php"`, `"cpp"`, `"java"`, or `"ts"` (defaulting to `"hybrid"`). `generate_optimized_system_prompt` additionally supports `"node"`, `"minecraft"`, `"roblox"`, `"roblox-server"`, and `"luau"`, embedding the 3-call MCP workflow, all 10 `aetherscope_*` tools, layer invariants, `< 35`-line function atomicity, `[AETHER_ACK]`, and `SecretGuard`/`SecretMasker` constraints.

## UI Improvement Studios

All interactive AI and remediation workflows live under `crates/desktop-shell/ui/src/`:

### `PromptGeneratorModal` (`components/PromptGeneratorModal.svelte`)

Provides a 4-tab studio (`activeTab`: `context` | `master` | `sysprompt` | `mcp`):

* **Contextual Prompt (`context`)**: Switches between `symbol` and `folder` targets across 5 `taskMode` presets (`refactor`, `security`, `tests`, `docs`, `audit`), automatically appending `settings.aiCustomPrompt`.
* **Master Blueprint (`master`)**: Formats spec-driven architecture instructions tuned for `claude`, `gemini`, or `openai`.
* **System Prompt (`sysprompt`)**: Displays `graph.system_prompt` or fetches `GET /api/ai/system_prompt`.
* **MCP Config (`mcp`)**: Generates ready-to-paste JSON snippets on the active port (`window.location.port || '3030'`) for `antigravity` (`~/.gemini/config/mcp_config.json`), `claude` (`%APPDATA%\Claude\claude_desktop_config.json`), and `cursor` (`.cursor/mcp.json`).

### 4-Step Bug Bounty & Remediation Studio (`BountyModal.svelte` & `components/bounty/bountyEngine.ts`)

1. **Step 1 — Scope (`StepScopePanel.svelte`)**: Pick from 7 `BOUNTY_PRESETS` (`immunefi`, `hackerone`, `yeswehack`, `l1_consensus`, `rust_lowlevel`, `smart_contracts`, `auto`), run AI Auto-Scope (`GET` / `POST /api/bounty/scope`), lock a single folder (`lockedSingleFolder`), edit In-Scope/Out-of-Scope wildcard lists, isolate the scope in the 3D graph, and choose among 4 mission modes (`audit_strict`, `poc_batch`, `patch_ears`, `mcp_autonomous`).
2. **Step 2 — Targets & Functions (`StepTargetsFunctionsPanel.svelte`)**: Filter anomalies (`ALL`/`CRITICAL`/`HIGH`, `reachableOnly`, query) or AST symbols, and inspect `extractFileFunctions` classifying functions as `SOURCE`, `PROPAGATION`, or `SINK` with cyclomatic complexity.
3. **Step 3 — Code & Dataflow (`StepCodeDataPanel.svelte`)**: Toggle `split` / `code` / `data` views, switch between `excerpt` and `full` (up to `1500` lines loaded via `GET /api/file_content`), inspect the directional SVG call graph (`buildDirectionalDiagram`), trace SSA taint steps (`buildSsaSteps`), and review parameter direction tables (`IN`, `TRANSIT`, `OUT`).
4. **Step 4 — Prompts & PoC (`StepPromptsPocPanel.svelte`)**: Generate 8 artifact tabs (`target_prompt`, `scope_prompt`, `poc_code` [Rust `#[test]` for `.rs` else Python `requests`], `curl_command`, `raw_http`, `bounty_report` [formatted preview or raw Markdown with 1-click save to `.aether/bounty_reports/report_<slug>.md` via `POST /api/ai/create_file`], `gold_patch`, `mcp_handshake`). Includes a **Live HTTP Dry-Run** (`5 s` `AbortController` timeout against `http://localhost:3030...`) with automatic `sandbox_ast` taint-simulation fallback.

### Audit Score & Export (`lib/auditReport.ts`)

`computeAuditSummary(cockpitState)` computes `securityScore` clamped to `10..100` and assigns letter grades `A..F`:

```ts
let score = 100;
score -= Math.min(45, criticalCount * 15);
score -= Math.min(30, highCount * 6);
score -= Math.min(15, mediumCount * 2);
score -= Math.min(10, Math.floor(hotspotsCount * 1.5));
if (earsContractsCount > 0) score = Math.min(100, score + 5);
score = Math.max(10, Math.min(100, score));
```

| Grade | Score Threshold | Meaning in Export (`generateAuditMarkdown` / `generateAuditHtml`) |
| :--- | :--- | :--- |
| **A** | `>= 90` | Strong security posture (`Fortement Sécurisé`) |
| **B** | `>= 80` | Good defensive posture (`Bonne Posture Défensive`) |
| **C** | `>= 70` | Moderate risk / remediation required |
| **D** | `>= 50` | High risk / priority vulnerabilities |
| **F** | `< 50` | Critical risk / immediate exposure |

`lowCount` deducts `0` points. `generateAuditMarkdown` exports full GFM Markdown (note that its header banner currently prints the legacy string `AetherScope AST Security Engine (v2.4)`), and `generateAuditHtml` produces a standalone HTML report embedding the interactive bubble graph (`auditGraphHtml.ts`).

### `InspectorDrawer`, `DocReaderDrawer` & `AiChatDrawer`

* **Inspector Drawer (`InspectorDrawer.svelte`)**: Resizable right-hand drawer (`280 px` to `70vw`, default `396 px`, expanded `600 px`) with 5 tabs (`debrief`, `uml`, `relations`, `cve`, `tasks`). Its contract budget editor offers 1-click `max_lines` presets (`200`, `300`, `500`, `800`, `1500`) or custom limits that invoke `POST /api/contracts/update` to seal the folder/file `README.md` with BLAKE3.
* **Bulk Contract Signing (`DocReaderDrawer.svelte`)**: Provides 1.5s auto-save for `README.md` contracts and triggers bulk BLAKE3 folder signing (`signAllContracts()`) via `POST /api/contracts/sign`.
* **AI Chat & Swarm Dock (`AiChatDrawer.svelte` & `graphState.svelte.ts`)**: Polls `/api/ai/telemetry` and `/api/ai/chat` every `1500 ms`, toggles with `C`, switches between `chat` and `agents` subtabs, collapses `<thought>` / `<thinking>` blocks, and provides CLI launch buttons (`gemini`, `claude`, `codex` -> `POST /api/ai/launch_cli`). Messages sent via `POST /api/ai/chat` append to `.aether/CHAT_INBOX.md` (`PENDING_AI_RESPONSE` for `"user"`, `ANSWERED` for agents). Active agents expire after `AI_AGENT_TTL_SECS = 300` (`AI_INACTIVITY_TIMEOUT_MS = 300_000` ms) and receive deterministic colors from the 12-color FNV-1a backend palette (`AI_AGENT_PALETTE` / `MCP_AGENT_PALETTE`, FNV offset `14695981039346656037`) with a 16-color frontend `resolveAgentColor` fallback.

{% content-ref url="./blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](./blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="./security-confinement.md" %}
[Security Confinement & Guardrails](./security-confinement.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[REST API: IDE, Contracts, AI & Tasks](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}
