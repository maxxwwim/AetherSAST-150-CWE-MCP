# REST API: Settings, Bounty, Surface & Plugins

Manage engine settings, bug-bounty scope, black-box surface scans, declarative SAST/Taint plugins, and WebGL 2 visual shader packs over the local Axum HTTP API (`127.0.0.1:3030`).

Every route on this page is protected globally by `LocalGuard` (`Host`, `Origin`, and `Sec-Fetch-Site` validation), and plugin mutations enforce strict path confinement inside `.aether/plugins/`.

{% hint style="info" %}
**Frontend Client (`AetherApiClient`)**: All endpoints below—except where noted—have corresponding typed methods on `AetherApiClient` in `crates/desktop-shell/ui/src/lib/api.ts`. When running outside the Cockpit webview, send requests directly to `http://127.0.0.1:3030` with a matching `Host: 127.0.0.1:3030` header and omit cross-origin `Origin` headers.
{% endhint %}

---

## Settings & Security Policies

Configure folder exclusions, active CWE/SAST rules, ignored CWE IDs, visual display toggles, and memory limits in `.aether/settings.json`.

### `GET /api/settings` & `POST /api/settings`

Retrieve the current project configuration and full CVE/SAST rule catalogue, or apply partial setting updates with optional graph rescanning.

#### 🎮 Endpoint

```http
GET  http://127.0.0.1:3030/api/settings
POST http://127.0.0.1:3030/api/settings
```

* **TypeScript Client**: `api.getSettings()` and `api.saveSettings(payload)` (`api.ts`)
* **Persistence**: `.aether/settings.json`

#### 📝 Parameters

For `GET /api/settings`, no parameters are required. For `POST /api/settings`, send a partial or full `SettingsPayload` JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `exclusions` | `string[]` | No | Directory or glob exclusions. Note: an empty array `[]` preserves existing exclusions unless `rescan: true` is also sent. |
| `active_cve_rules` | `string[] \| null` | No | Allowlist of enabled native rule IDs. When non-empty, `apply_settings_filters_to_graph` still preserves `BLAKE3_TAMPERED` and custom plugin rules; an explicit empty `[]` mutes all alerts. |
| `ignored_cwes` | `string[] \| null` | No | CWE identifiers to suppress across the graph (for example `["CWE-798"]`). |
| `show_alerts` | `boolean \| null` | No | Toggle visibility of SAST/CWE alert indicators in the 3D Cockpit. |
| `show_cwe_bubbles` | `boolean \| null` | No | Toggle CWE satellite bubbles around affected symbols. |
| `show_cwe_titles` | `boolean \| null` | No | Toggle text labels on CWE bubbles. |
| `show_folder_titles` | `boolean \| null` | No | Toggle folder membrane labels in the WebGL scene. |
| `show_file_titles` | `boolean \| null` | No | Toggle file labels in the WebGL scene. |
| `low_memory_mode` | `boolean \| null` | No | Enable reduced-memory rendering and analysis hints for large repositories. |
| `active_visual_plugin` | `string \| null` | No | Active visual pack slug (default `"obsidian-nebula"`). |
| `ui_settings` | `object \| null` | No | Arbitrary JSON blob storing Cockpit UI preferences. |
| `rescan` | `boolean \| null` | No | Force a full `ProjectScanner` rescan and `graph_version` increment. |

{% hint style="warning" %}
**Partial Merge Semantics**: `POST /api/settings` merges provided `Option` fields into `AppState` before writing `.aether/settings.json`, so partial updates (such as adding a single CWE to `ignored_cwes`) never wipe your UI display toggles. A graph rescan runs automatically if `rescan: true`, non-empty `exclusions` changed, `active_cve_rules` changed, or `ignored_cwes` changed.
{% endhint %}

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` (present on `POST /api/settings`). |
| `200 OK` | `exclusions` | `string[]` | Active exclusion patterns. |
| `200 OK` | `active_cve_rules` | `string[]` | Active native rule IDs (defaults to all catalogue IDs on `GET` when unset). |
| `200 OK` | `ignored_cwes` | `string[]` | Currently suppressed CWE IDs. |
| `200 OK` | `cve_catalogue` | `CveRuleDef[]` | Full built-in catalogue returned by `SecurityLinter::get_supported_cve_rules()`. |
| `200 OK` | `mcp_binary_path` | `string \| null` | (`GET` only) Resolved path to `aetherscope-mcp(.exe)` adjacent to the running executable. |
| `200 OK` | `show_*` / `low_memory_mode` / `active_visual_plugin` / `ui_settings` | mixed | (`GET` only) Current persisted Cockpit UI flags and preferences. |
| `200 OK` | `total_nodes` / `total_edges` | `number` | (`POST` only) Graph node and edge counts after any triggered rescan. |

#### 💡 Example

{% tabs %}
{% tab title="curl" %}
```bash
# Read current settings, catalogue, and mcp_binary_path
curl -s http://127.0.0.1:3030/api/settings

# Suppress CWE-798, enable low-memory mode, and trigger a rescan
curl -s -X POST http://127.0.0.1:3030/api/settings \
  -H "Content-Type: application/json" \
  -d '{"ignored_cwes":["CWE-798"],"low_memory_mode":true,"rescan":true}'
```
{% endtab %}
{% tab title="JSON Response (POST 200)" %}
```json
{
  "status": "ok",
  "exclusions": [],
  "active_cve_rules": ["CWE-89-SQLI", "CWE-78-CMD-INJ"],
  "ignored_cwes": ["CWE-798"],
  "cve_catalogue": [
    {
      "rule_id": "CWE-89-SQLI",
      "cwe_id": "CWE-89",
      "name": "SQL Injection"
    }
  ],
  "total_nodes": 412,
  "total_edges": 1084
}
```
{% endtab %}
{% endtabs %}

---

## Bug Bounty Scope & Attack Surface Scan

Define which project folders are in-scope for security triage and trigger black-box HTTP/TCP surface audits.

### `GET /api/bounty/scope` & `POST /api/bounty/scope`

Inspect or update the Bug Bounty PoC scope configuration persisted in `.aether/bounty_scope.json`, or run the AI folder scope recommender (`compute_scope_recommendations`).

#### 🎮 Endpoint

```http
GET  http://127.0.0.1:3030/api/bounty/scope
POST http://127.0.0.1:3030/api/bounty/scope
```

* **TypeScript Client**: `api.getBountyScope()` and `api.updateBountyScope(payload)` (`api.ts`)
* **Persistence**: `.aether/bounty_scope.json`

#### 📝 Parameters

`GET /api/bounty/scope` takes no parameters. If `.aether/bounty_scope.json` does not exist yet, it automatically returns AI-generated recommendations (`mode: "ai_recommended"`).

For `POST /api/bounty/scope`:

| Name | Type | Required | Description |
|---|---|---|---|
| `action` | `string` | No | `"set"` (default) to persist custom lists, or `"auto_recommend"` to generate and save AI-recommended lists. |
| `in_scope` | `string[]` | No | Folder prefixes included in scope (used when `action: "set"`). |
| `out_of_scope` | `string[]` | No | Folder prefixes excluded from scope (used when `action: "set"`). |
| `mode` | `string` | No | Scope mode stored in config (`"manual"` default for `"set"`, `"mcp_synced"`, or `"ai_recommended"`). |
| `updated_by` | `string` | No | Author label (defaults to `"User / MCP"` for `"set"`, `"AetherScope AI Recommender"` for `"auto_recommend"`). |
| `rationale` | `string` | No | Human-readable justification saved alongside the scope config. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `scope` | `BountyScopeConfig` | `{ in_scope, out_of_scope, mode, updated_by?, rationale?, timestamp }`. |
| `200 OK` | `recommendations` | `FolderScopeRecommendation[]` | Per-folder scores and counts (`folder`, `status`, `critical_count`, `high_count`, `total_violations`, `entrypoints_count`, `score`, `reason`). |

#### 💡 Example

```bash
# Auto-compute and persist recommended bounty scope
curl -s -X POST http://127.0.0.1:3030/api/bounty/scope \
  -H "Content-Type: application/json" \
  -d '{"action":"auto_recommend","updated_by":"AppSec"}'
```

---

### `POST /api/surface_scan`

Execute a non-destructive 4-level black-box network and web attack-surface scan against a target URL or host and record a summary telemetry event (`"Scan Surface (<grade>)"`).

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/surface_scan
```

* **TypeScript Client**: `api.surfaceScan(req)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | **Yes** | Target host, IP, `host:port`, or full `http(s)://` URL. |
| `scan_level` | `integer` | No | Audit depth from `1` to `4` (clamped to `1..=4`, default `4`). |
| `check_dns` | `boolean` | No | Enable DNS resolution and IP classification (default `true`). |
| `check_ports` | `boolean` | No | Enable TCP port and banner probing (default `scan_level >= 2`). |
| `check_headers` | `boolean` | No | Enable HTTP security header audit (default `true`). |
| `check_endpoints` | `boolean` | No | Enable `robots.txt` / `security.txt` and `OPTIONS` probing (default `scan_level >= 2`). |
| `check_web_forms` | `boolean` | No | Enable HTML form, DOM, and JS route extraction (default `scan_level >= 3`). |
| `check_sensitive_files` | `boolean` | No | Enable Level 4 CWE-538 artifact probing with `******** [MASQUÉ]` redaction (default `scan_level >= 4`). |
| `custom_ports` | `string` | No | Comma-, space-, or semicolon-separated list of additional TCP ports to probe. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `security_score` / `grade` | `integer` / `string` | Posture score `0..100` and grade (`A+` through `F`). |
| `200 OK` | `impact_matrix` | `ImpactVisibilityMatrix` | Packet footprint estimate and discovered surface counters. |
| `200 OK` | `open_ports` / `headers_audit` | `array` | TCP port/banner results and HTTP security header verdicts. |
| `200 OK` | `web_discovery` / `exposed_artifacts` | `object \| null` / `array` | Forms, routes, JS assets, and redacted CWE-538 probes. |
| `200 OK` | `trust_zones` / `boundary_weaknesses` / `findings` | `array` | 4 trust zones, Side-1 to Side-2 AST probes, and CWE findings. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/surface_scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://127.0.0.1:3030","scan_level":4}'
```

{% content-ref url="./surface-scanner.md" %}
[Network Attack Surface Scanner](./surface-scanner.md)
{% endcontent-ref %}

---

## SAST & Taint Plugin Routes (`/api/plugins/*`)

The 7 plugin endpoints manage declarative YAML/JSON security rules and SSA taint specifications stored under `.aether/plugins/`.

### Confinement & Mutation Pipeline

Every `/api/plugins/*` mutation enforces strict security invariants defined in `crates/desktop-shell/src/plugin_routes.rs`:

* **`sanitize_plugin_slug`**: Enforces a maximum length of 64 characters, rejects `\0`, `/`, `\`, `..`, `:`, and `.`, maps spaces to `-`, converts ASCII letters to lowercase `[a-z0-9_-]`, and trims leading/trailing `-` or `_`.
* **`resolve_confined_plugin_file`**: Verifies that `.aether/plugins` exists (`404` otherwise), rejects traversal/absolute/UNC/drive paths (`400`), restricts extensions to `.yaml`, `.yml`, or `.json` (`400`), blocks sensitive filenames via `SecretGuard::is_secret_path` (`403`), and confirms canonical containment inside `.aether/plugins` (`403` on escape, `404` if missing).
* **`collect_plugin_files`**: Recursively scans `.aether/plugins` while excluding the `visuals` subdirectory and any `visual-plugin.*` stem.
* **`rescan_after_plugin_mutation`**: Re-runs `ProjectScanner::scan_project_with_exclusions`, reapplies `apply_settings_filters_to_graph`, writes `.aether/LIVE_AUDIT.md`, updates `code_graph`, and—when not in Obsidian `vault` mode—updates `graph`, clears `ui_graph_cache`, and increments `graph_version`.

---

### `GET /api/plugins`

List all SAST/Taint plugins in `.aether/plugins/`, including active rule counts, taint specs, and whether the 24-rule Semgrep community bundle is installed.

#### 🎮 Endpoint

```http
GET http://127.0.0.1:3030/api/plugins
```

* **TypeScript Client**: `api.getPlugins()` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| — | — | — | This endpoint accepts no query parameters or request body. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugins_dir` | `string` | Path to `.aether/plugins`. |
| `200 OK` | `community_bundle_installed` | `boolean` | `true` when the embedded community bundle is present on disk. |
| `200 OK` | `community_bundle_rules_count` | `integer` | Fixed count of rules in the embedded bundle (`24`). |
| `200 OK` | `total_plugins` / `enabled_plugins` | `integer` | Total and enabled plugin manifest counts. |
| `200 OK` | `total_active_rules` | `integer` | Count of active rules across enabled plugins. |
| `200 OK` | `total_taint_sources` / `total_taint_sinks` / `total_sanitizers` | `integer` | Totals across enabled plugins. |
| `200 OK` | `plugins` | `PluginEntryInfo[]` | Full metadata, rule summaries, and taint specs for every plugin file. |

#### 💡 Example

```bash
curl -s http://127.0.0.1:3030/api/plugins
```

---

### `POST /api/plugins/toggle`

Enable or disable a plugin file on disk while preserving its original `.json` or `.yaml`/`.yml` serialization format, then rescan the workspace.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/toggle
```

* **TypeScript Client**: `api.togglePlugin(relPath, enabled)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `rel_path` | `string` | **Yes** | Relative path inside `.aether/plugins/` (for example `"custom-guard/plugin.yaml"`). |
| `enabled` | `boolean` | **Yes** | Target enabled state to persist in the manifest. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugin` / `enabled` | `string` / `boolean` | Updated `rel_path` and resulting `enabled` state. |
| `200 OK` | `total_nodes` / `total_edges` | `integer` | Graph counts after `rescan_after_plugin_mutation`. |
| `200 OK` | `inventory` | `PluginsInventoryResponse` | Updated plugin inventory snapshot. |
| `400` / `403` / `404` / `500` | `error` | `string` | Invalid path/extension, `SecretGuard`/escape rejection, missing file, or I/O error. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/toggle \
  -H "Content-Type: application/json" \
  -d '{"rel_path":"custom-guard/plugin.yaml","enabled":true}'
```

---

### `POST /api/plugins/test`

Execute embedded `test_cases` using `PluginEngine::run_test_suite()` across all plugins or a single targeted plugin file.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/test
```

* **TypeScript Client**: `api.testPlugins(relPath?)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `rel_path` | `string \| null` | No | Optional relative path inside `.aether/plugins/`. When provided and non-empty, only that file is loaded and `enabled` is forced to `true` in memory so disabled plugins can still be unit-tested. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"passed"` (if `failed == 0`) or `"failed"`. |
| `200 OK` | `total_tests` / `passed` / `failed` | `integer` | Aggregate unit-test counts. |
| `200 OK` | `failures` | `string[]` | Diagnostic messages for each failing test case. |
| `400` / `403` / `404` / `500` | `error` | `string` | Confinement or parse failure when loading `rel_path`. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/test \
  -H "Content-Type: application/json" \
  -d '{"rel_path":"custom-guard/plugin.yaml"}'
```

---

### `POST /api/plugins/init_bundle`

Unpack the embedded 24-rule Semgrep OWASP/CWE community bundle (`CommunityBundle::unpack_to_directory`) to `.aether/plugins/community/plugin.yaml` and rescan the project.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/init_bundle
```

* **TypeScript Client**: `api.initCommunityPluginBundle()` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| — | — | — | Send no body (empty POST). |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `path` | `string` | Written manifest path (`.aether/plugins/community/plugin.yaml`). |
| `200 OK` | `total_nodes` / `total_edges` | `integer` | Updated graph counts after rescan. |
| `200 OK` | `inventory` | `PluginsInventoryResponse` | Updated plugin inventory. |
| `500` | `error` | `string` | Filesystem unpack failure. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/init_bundle
```

---

### `POST /api/plugins/import_semgrep`

Translate a Semgrep YAML rule file into an AetherScope `PluginManifest` via `SemgrepImporter`, save it under `.aether/plugins/imported/<slug>/plugin.yaml`, and rescan the project.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/import_semgrep
```

* **TypeScript Client**: `api.importSemgrepPlugin(pluginName, yamlContent)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `plugin_name` | `string` | **Yes** | Plugin name sanitized via `sanitize_plugin_slug` into `<slug>`. |
| `yaml_content` | `string` | **Yes** | Raw Semgrep YAML content containing a non-empty `rules` list. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugin` | `string` | Sanitized plugin `<slug>`. |
| `200 OK` | `rules_imported` | `integer` | Number of translated rules. |
| `200 OK` | `rel_path` | `string` | Relative path `"imported/<slug>/plugin.yaml"`. |
| `200 OK` | `total_nodes` / `total_edges` / `inventory` | mixed | Post-rescan graph totals and updated inventory. |
| `400` / `500` | `error` | `string` | Invalid slug, invalid/empty Semgrep YAML (`rules` empty), or write error. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/import_semgrep \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"semgrep-demo","yaml_content":"rules:\n  - id: demo-eval\n    languages: [javascript]\n    severity: ERROR\n    message: Avoid eval\n    pattern: eval($X)\n"}'
```

---

### `POST /api/plugins/upsert`

Create or update a declarative SAST rule and/or SSA taint configuration inside `.aether/plugins/<slug>/plugin.yaml` (or `.aether/plugins/imported/<slug>/plugin.yaml` if it already exists there), gated by automatic unit-test certification.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/upsert
```

* **TypeScript Client**: `api.upsertPluginRule(payload)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `plugin_name` | `string` | **Yes** | Target plugin name, sanitized via `sanitize_plugin_slug`. |
| `profile` / `tags` / `plugin_description` | `string` / `string[]` / `string` | No | Optional manifest-level profile, tags, and description. |
| `rule_id` | `string` | Conditional | Rule ID. Required unless running in **taint-only mode** (`rule_id` empty while `taint_sources`, `taint_sinks`, or `sanitizers` is supplied, which saves under `TAINT-SSA-CONFIG`). |
| `cwe_id` | `string` | Conditional | CWE identifier (required unless taint-only mode). |
| `file_extensions` | `string[]` | Conditional | Target extensions such as `[".rs", ".ts"]` (non-empty unless taint-only mode). |
| `name` / `category` / `severity` | `string` | No | Rule display name, category (default `"Custom / Security"`), and severity (default `"HIGH"`, auto-uppercased). |
| `description` / `remediation` | `string` | No | Rule explanation and fix guidance. |
| `match_mode` | `string` | No | `"line_by_line"` (default) or `"whole_file"`. |
| `must_contain` / `must_not_contain` | `string[]` | No | Substring preconditions and negative exclusions. |
| `regex_patterns` / `forbidden_tokens` | `string[]` | No | Regular expressions (validated via `validate_regexes()`) and forbidden token strings. |
| `check_literals` | `boolean` | No | Include string/comment literals in matching (default `false`). |
| `not_preceded_within_lines` | `object` | No | `{ "patterns": string[], "lines": integer }` guard window. |
| `in_path_matching` / `not_in_path_matching` | `string[]` | No | Path inclusion/exclusion globs. |
| `ast_scope` | `string` | No | Scope filter (for example `"outside_test"`, `"test"`, `"async_fn"`, `"sync_fn"`, `"fn"`). |
| `test_cases` | `RuleTestCase[]` | No | Positive/negative test cases. When updating an existing `rule_id` with an empty `test_cases` array, existing test cases are preserved. |
| `taint_sources` / `taint_sinks` / `sanitizers` | `array` | No | `TaintSourceRule[]`, `TaintSinkRule[]`, and `SanitizerRule[]` entries merged into the manifest. |

{% hint style="danger" %}
**422 Certification Gate**: Before writing anything to disk, the server clones the candidate manifest, forces `enabled = true`, compiles its regexes, and executes `PluginEngine::run_test_suite()`. If `report.failed > 0`, the handler aborts without modifying the filesystem and returns **`422 Unprocessable Entity`** (`"<N> unit test(s) failed — plugin was NOT modified"`).
{% endhint %}

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugin` / `rule_id` | `string` | Sanitized plugin slug and saved rule ID (or `"TAINT-SSA-CONFIG"`). |
| `200 OK` | `tests_passed` | `integer` | Number of passing certification tests. |
| `200 OK` | `total_nodes` / `total_edges` / `inventory` | mixed | Post-rescan graph counts and updated inventory. |
| `422` | `status` / `message` / `total_tests` / `passed` / `failed` / `failures` | mixed | Certification gate failure details; disk remains untouched. |
| `400` / `500` | `error` | `string` | Invalid slug, missing required fields, invalid regex, or write error. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/upsert \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_name": "custom-guard",
    "rule_id": "CUSTOM-EXEC",
    "cwe_id": "CWE-78",
    "name": "Block danger_exec",
    "severity": "CRITICAL",
    "description": "Unsafe command execution",
    "remediation": "Use an explicit command allowlist",
    "file_extensions": [".rs"],
    "regex_patterns": ["danger_exec\\s*\\("],
    "test_cases": [
      {
        "name": "vuln",
        "file_name": "src/app.rs",
        "code": "danger_exec();",
        "should_trigger": true
      }
    ]
  }'
```

---

### `POST /api/plugins/delete`

Delete a confined plugin file from `.aether/plugins/`, clean up its parent directory if empty, and trigger a full project rescan.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/delete
```

* **TypeScript Client**: `api.deletePlugin(relPath)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `rel_path` | `string` | **Yes** | Relative plugin path inside `.aether/plugins/` to remove. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `deleted` | `string` | Deleted `rel_path`. |
| `200 OK` | `total_nodes` / `total_edges` / `inventory` | mixed | Post-rescan graph totals and updated inventory. |
| `400` / `403` / `404` / `500` | `error` | `string` | Path validation, `SecretGuard`/escape check, missing file, or delete error. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/delete \
  -H "Content-Type: application/json" \
  -d '{"rel_path":"custom-guard/plugin.yaml"}'
```

---

## WebGL 2 Visual Plugin Routes (`/api/visual_plugins/*`)

The 4 visual plugin endpoints manage custom theme palettes, overlay geometries, uniforms, and GLSL ES 3.00 shader hooks stored in `.aether/plugins/visuals/<slug>/`.

### Anti-DoS GLSL Validation & Built-In Packs

Custom shader hooks (`backdrop.glsl` and `node_sdf.glsl`) are validated server-side by `validate_glsl_hook` (`visual_plugin_routes.rs`) and mirrored client-side in `ui/src/engine/visualPlugins.ts`:

* **Size & encoding**: Maximum `32 * 1024` bytes (`32 KB`, `MAX_GLSL_BYTES`), no `\0` null bytes.
* **Host-controlled directives**: Strips `//` and `/* ... */` comments, then rejects `#version`, `#extension`, and `#pragma`.
* **Anti-TDR loop bounds**: Rejects `while (` and `do {` loops; requires every `for (init; cond; step)` loop to have 3 semicolon parts, a non-empty condition, and every numeric literal in `cond` `<= 128` (`MAX_FOR_LOOP_BOUND`).
* **Contract entrypoints**:
  * `backdrop.glsl` must declare `vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec)`
  * `node_sdf.glsl` must declare `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha)`

{% hint style="info" %}
**Built-In vs. Disk Visual Packs**: The 5 built-in packs (`obsidian-nebula`, `cyber-pcb`, `architect-blueprint`, `deep-biolum`, `matrix-phosphor`) are compiled directly in `crates/desktop-shell/ui/src/engine/visualPlugins.ts`. `GET /api/visual_plugins` enumerates custom packs stored on disk under `.aether/plugins/visuals/` (`builtin: false`).
{% endhint %}

---

### `GET /api/visual_plugins`

List all custom visual plugin packs discovered in `.aether/plugins/visuals/` along with resolved GLSL sources, uniforms, validation warnings, and the currently active pack ID.

#### 🎮 Endpoint

```http
GET http://127.0.0.1:3030/api/visual_plugins
```

* **TypeScript Client**: `api.getVisualPlugins()` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| — | — | — | No parameters required. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `visuals_dir` | `string` | Path to `.aether/plugins/visuals`. |
| `200 OK` | `active_visual_plugin` | `string` | Active theme slug (defaults to `"obsidian-nebula"`). |
| `200 OK` | `visual_version` | `integer` | Monotonic visual version counter incremented on visual plugin changes. |
| `200 OK` | `plugins` | `VisualPluginResolved[]` | Array containing `schema_version`, `id`, `name`, `version`, `author`, `description`, `enabled`, `builtin` (`false`), `rel_dir` (`"visuals/<folder>"`), `palette`, `overlay`, `uniforms`, `backdrop_glsl`, `node_sdf_glsl`, and `validation_warnings`. |

#### 💡 Example

```bash
curl -s http://127.0.0.1:3030/api/visual_plugins
```

---

### `POST /api/visual_plugins/activate`

Activate a built-in or custom visual plugin pack by ID, persist `active_visual_plugin` to `.aether/settings.json`, and increment `visual_version`.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/visual_plugins/activate
```

* **TypeScript Client**: `api.activateVisualPlugin(id)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | **Yes** | Built-in or custom pack ID, sanitized via `sanitize_plugin_slug`. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `active_visual_plugin` | `string` | Sanitized active pack slug. |
| `200 OK` | `visual_version` | `integer` | Incremented `visual_version`. |
| `400` | `error` | `string` | Invalid slug in `id`. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/visual_plugins/activate \
  -H "Content-Type: application/json" \
  -d '{"id":"obsidian-nebula"}'
```

---

### `POST /api/visual_plugins/upsert`

Create or update a custom visual plugin pack under `.aether/plugins/visuals/<slug>/`, writing `visual-plugin.yaml` plus optional `backdrop.glsl` and `node_sdf.glsl` hooks after anti-DoS GLSL validation.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/visual_plugins/upsert
```

* **TypeScript Client**: `api.upsertVisualPlugin(payload)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | **Yes** | Pack identifier sanitized via `sanitize_plugin_slug`. |
| `name` | `string` | **Yes** | Non-empty display name for the pack. |
| `version` | `string` | No | Semver string (default `"1.0.0"`). |
| `author` / `description` | `string` | No | Optional pack metadata. |
| `palette` | `VisualPaletteConfig` | No | `{ background: string[], layers: Record<string, string>, severities: Record<string, string>, contract_warning?: string }`. |
| `overlay` | `VisualOverlayConfig` | No | `{ membrane_style?: "organic_12lobe" \| "hex_hull" \| "rect_blueprint" \| "none", edge_style?: "bezier" \| "straight" \| "orthogonal_pcb", edge_pulse_speed?: number, membrane_breath_amp?: number, label_font?: string }`. |
| `uniforms` | `Record<string, number>` | No | Custom float uniforms exposed to GLSL hooks. |
| `backdrop_glsl` | `string \| null` | No | Custom backdrop shader validated with `validate_glsl_hook(..., "aetherBackdrop")`. |
| `node_sdf_glsl` | `string \| null` | No | Custom node surface shader validated with `validate_glsl_hook(..., "aetherNodeSurface")`. |
| `activate` | `boolean` | No | Automatically activate this pack and persist `.aether/settings.json` (default `false`). |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `id` | `string` | Sanitized pack slug. |
| `200 OK` | `visual_version` | `integer` | Incremented `visual_version`. |
| `200 OK` | `inventory` | `VisualPluginsInventoryResponse` | Updated visual plugins inventory. |
| `400` / `403` / `500` | `error` | `string` | Invalid slug, empty `name`, GLSL contract/anti-DoS failure, `SecretGuard` rejection, or I/O error. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/visual_plugins/upsert \
  -H "Content-Type: application/json" \
  -d '{
    "id": "neon-grid",
    "name": "Neon Grid",
    "palette": { "background": ["#040a0f", "#06b6d4"] },
    "overlay": { "membrane_style": "hex_hull", "edge_style": "orthogonal_pcb" },
    "uniforms": { "grid_scale": 0.5 },
    "backdrop_glsl": "vec3 aetherBackdrop(vec2 uv, vec2 cam, float z, float t) { return u_theme_colors[0]; }",
    "activate": true
  }'
```

---

### `POST /api/visual_plugins/delete`

Delete a custom visual plugin directory from `.aether/plugins/visuals/<slug>/`. If the deleted pack was currently active, `active_visual_plugin` automatically resets to `"obsidian-nebula"` in both memory and `.aether/settings.json`.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/visual_plugins/delete
```

* **TypeScript Client**: `api.deleteVisualPlugin(id)` (`api.ts`)

#### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | **Yes** | Custom pack ID sanitized via `sanitize_plugin_slug`. |

#### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `deleted` | `string` | Deleted pack slug. |
| `200 OK` | `visual_version` | `integer` | Incremented `visual_version`. |
| `200 OK` | `inventory` | `VisualPluginsInventoryResponse` | Updated visual plugins inventory. |
| `400` / `403` / `404` / `500` | `error` | `string` | Invalid slug, confinement escape, missing pack directory, or deletion error. |

#### 💡 Example

```bash
curl -s -X POST http://127.0.0.1:3030/api/visual_plugins/delete \
  -H "Content-Type: application/json" \
  -d '{"id":"neon-grid"}'
```

---

## Related Guides

{% content-ref url="./rest-api-overview.md" %}
[REST API Overview & Client](./rest-api-overview.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-ide-contracts-ai.md" %}
[REST API: IDE, Contracts, AI & Tasks](./rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[WebGL 2 Visual Plugins](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}
