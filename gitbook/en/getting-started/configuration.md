# Configuration

Complete schema reference for `aether.lock.toml`, `.aether/settings.json`, `README.md` EARS contracts, environment variables, and generated runtime artifacts.

## 1. `aether.lock.toml` (Cryptographic Lockfile)

`aether.lock.toml` sits at `<project_root>/aether.lock.toml` and stores the `ProjectManifest` (`crates/core-graph/src/manifest.rs`) along with BLAKE3 digests for every sealed `README.md` contract.

| Field | Type / Values | Default | Description |
|---|---|---|---|
| `version` | `u32` | `2` | Lockfile schema version. |
| `project_id` | `string` | Project name | Identifier for the locked workspace. |
| `stack_type` | `PureRust` \| `PurePythonUv` \| `PureNodePnpm` \| `HybridMmoWeb3` \| `RobloxLuau` \| `MinecraftServer` \| `ClassicMvc` | — | Architectural stack template. |
| `topology_mode` | `MonorepoLocal` \| `Dissociated` | — | Local monorepo or split client/server topology. |
| `[galaxies.<key>]` | `GalaxyManifest` map | `{}` | Each entry sets `path`, `role`, `remote_sync` (`false`), optional `remote_endpoint`, and `readme_blake3` (64-char hex BLAKE3 digest). |
| `[guardrails]` | `GuardrailSettings` | All `true` | `block_forbidden_imports`, `enforce_ears_syntax`, `sast_strict_mode`, `require_signature_on_contract_change`. |

{% code title="aether.lock.toml (abbreviated from repository root)" overflow="wrap" %}
```toml
version = 2
project_id = "aether-engine"
stack_type = "PureRust"
topology_mode = "MonorepoLocal"

[galaxies.root]
path = "."
role = "Signed contract for root"
remote_sync = false
readme_blake3 = "4cd3d091d0a2fa74ac1223a4d41c845d1070a91135b14c720558ac07d15b55ca"

[galaxies."crates/core-graph"]
path = "./crates/core-graph"
role = "Signed contract for crates/core-graph"
remote_sync = false
readme_blake3 = "3c742885f331dd19d743f6dec53b9bcb383a15a8eae6d209d6f995e3ad12aab2"

[guardrails]
block_forbidden_imports = true
enforce_ears_syntax = true
sast_strict_mode = true
require_signature_on_contract_change = true
```
{% endcode %}

{% hint style="danger" %}
Editing a sealed `README.md` without re-signing `aether.lock.toml` (via `POST /api/contracts/sign`, `POST /api/contracts/update`, `POST /api/save_doc`, or the Cockpit Inspector) triggers **`BLAKE3_TAMPERED`** (`CWE-353`, `CRITICAL`) and causes `PatchVerifier` to reject patches.
{% endhint %}

## 2. `.aether/settings.json` (`SettingsPayload` & `CockpitSettings`)

Persisted at `<project_root>/.aether/settings.json` via `GET/POST /api/settings`. `POST /api/settings` performs a **partial merge** into `AppState`, so updating one key (such as `ignored_cwes` or `active_visual_plugin`) preserves all other fields.

| Field | Type | Persisted? | Default / Behavior |
|---|---|---|---|
| `exclusions` | `string[]` | Yes | Custom path/folder/`*` wildcard exclusions passed to `ProjectScanner` (UI default: `["vendor", "var", "cache", "tests", "*.spec.*", "*.test.*"]`). |
| `active_cve_rules` | `string[] \| null` | Yes | `null` activates all native rules (`GET /api/settings` expands `null` to all rule IDs). Note: `BLAKE3_TAMPERED`, `RULE_MAX_LINES`, `RULE_MAX_FILES`, `RULE_FORBIDDEN_FUNCTION`, `RULE_FORBIDDEN_EXTENSION`, and plugin rules remain active unless set to `[]`. |
| `ignored_cwes` | `string[] \| null` | Yes | Case-insensitive exact or substring filters matched against `rule_id` and `cve_id`. |
| `show_alerts` | `bool \| null` | Yes | UI default `true` — toggles security alert beacons/halos. |
| `show_cwe_bubbles` | `bool \| null` | Yes | UI default `true` — toggles nodes carrying SAST findings. |
| `show_cwe_titles` | `bool \| null` | Yes | UI default `true` — toggles CWE/line-budget pills. |
| `show_folder_titles` | `bool \| null` | Yes | UI default `true` — toggles folder/module titles. |
| `show_file_titles` | `bool \| null` | Yes | UI default `true` — toggles file and symbol labels. |
| `low_memory_mode` | `bool \| null` | Yes | UI default `false` (auto-enabled above `2,500` nodes); locks DPR `1x` and disables heavy `shadowBlur`. |
| `active_visual_plugin` | `string \| null` | Yes | UI fallback `"obsidian-nebula"`. Persists active WebGL 2 visual pack ID. |
| `ui_settings` | `object \| null` | Yes | Stores `CockpitSettings` (`maxLabelLength: 18`, `hideBubbleLabelsOver20: true`, `clusterLabelThreshold: 20`, `lazyReadmes: true`, `fpsLimit: "120"`, `soundEnabled: true`, `showFolderBadges: true`, `showFolderMembranes: true`, `aiAutoCam: true`, `aiTrail: true`, `showAiLines: true`, `showAiNames: true`, `aiCustomPrompt: ""`, `mcpBinaryPath`, plus mirrored UI toggles). |
| `cve_catalogue` | `CveRuleDef[] \| null` | **No** | Runtime-only read field returned by `GET/POST /api/settings`; cleared before writing disk. |
| `mcp_binary_path` | `string \| null` | **No** | Runtime-only resolved path to sibling `aetherscope-mcp`; cleared before writing disk. |
| `rescan` | `bool \| null` | **No** | Request-only flag on `POST /api/settings` that forces an immediate re-scan when `true`. |

## 3. `README.md` YAML Frontmatter & EARS Contracts

Every folder `README.md` can declare structural and security contracts parsed by `ReadmeContract::parse` (`crates/security-linter/src/contract.rs`):

| Key | Type | Default | Enforcement |
|---|---|---|---|
| `id` | `string` | Normalized folder path | Required when YAML frontmatter is present. |
| `layer` | `string` | `"utility"` (upsert: `"domain"`) | Architectural layer (`domain`, `application`, `infrastructure`, etc.). |
| `max_lines_per_file` | `usize` | `300` (`.java`: `10,000`, `.sol`: `600`) | Triggers `RULE_MAX_LINES` (`WARNING`) when exceeded. |
| `file_max_lines` | `map<string, usize>` | `{}` | Per-file line budget overrides matched by full path, folder-relative path, or bare filename. |
| `allowed_imports` | `string[]` | `[]` | Architectural guidance injected into `<aether_handshake>` and `ACTIVE_TARGET.md`. |
| `forbidden_imports` | `string[]` | `[]` | Actively enforced on `use`/`import`/`from` statements; emits `RULE_FORBIDDEN_IMPORT` (`CRITICAL`). |
| `forbidden_functions` | `string[]` | `[]` | Blocks calls/macros (e.g., `println!`) while ignoring function definitions (`RULE_FORBIDDEN_FUNCTION`). |
| `allowed_extensions` | `string[]` | `[]` (allow all) | Whitelist of extensions in the folder (`README.md` and extensionless files like `LICENSE` exempt); emits `RULE_FORBIDDEN_EXTENSION`. |
| `forbidden_extensions` | `string[]` | `[]` | Blacklist of extensions, including multi-part suffixes such as `d.ts` (`RULE_FORBIDDEN_EXTENSION`). |
| `max_files_per_folder` | `usize \| null` | `null` | Caps file count in the folder (`0` in `/api/contracts/update` clears the limit); emits `RULE_MAX_FILES`. |
| `security_rules` | `SecurityRules` | All `false` | Booleans: `no_raw_sql`, `no_env_access` (enforces `SAST_DIRECT_ENV_ACCESS` / `CWE-15`), `untrusted_client_input`, `deterministic_only`. |

In the Markdown body, any line matching `WHEN <trigger> THE SYSTEM SHALL <requirement>` (case-insensitive) is parsed as an `EarsRequirement`, and `pub fn` / `export function` / `def` lines inside fenced blocks are extracted as `exported_signatures`.

{% code title="crates/core-graph/README.md (example contract)" overflow="wrap" %}
```markdown
---
id: core-graph
layer: domain
max_lines_per_file: 800
allowed_imports: ["serde::*", "serde_json::*", "toml::*", "bitflags::*", "thiserror::*", "std::*"]
forbidden_imports: ["ast_scanner::*", "security_linter::*", "ai_file_bridge::*", "arch_templates::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
  deterministic_only: true
---

- WHEN a graph layout is computed THE SYSTEM SHALL execute deterministically without runtime I/O or network calls.
```
{% endcode %}

## 4. Environment Variables

| Variable | Component | Default | Purpose |
|---|---|---|---|
| `AETHER_AGENT_ID` | `aetherscope-mcp` / `--mcp` | `mcp-agent-<pid % 10000>` | Overrides MCP agent identifier (CLI `--agent-id` takes precedence). |
| `AETHER_AGENT_NAME` | `aetherscope-mcp` / `--mcp` | `IA MCP #<pid % 1000>` | Overrides HUD agent display name (CLI `--agent-name` takes precedence). |
| `AETHER_AGENT_COLOR` | `aetherscope-mcp` / `--mcp` | FNV-1a from 12-color palette | Overrides HUD swarm color (CLI `--color` takes precedence). |
| `AETHER_RCON_HOST` | AetherCraft Control Plane | `"127.0.0.1"` | Minecraft server RCON host (`rcon_service.py`). |
| `AETHER_RCON_PORT` | AetherCraft Control Plane | `25575` | Minecraft server RCON TCP port. |
| `AETHER_RCON_PASSWORD` | AetherCraft Control Plane | `"aether2026"` | Minecraft server RCON password. |

{% hint style="warning" %}
**`RUST_LOG` has no effect:** `aether-engine` and `aetherscope-mcp` do not use `env_logger` or `tracing-subscriber`. Do not rely on `RUST_LOG` for debug output.
{% endhint %}

## 5. Generated Artifacts & Diagnostic Logs

| Location | Artifact | Purpose |
|---|---|---|
| `.aether/` | `settings.json` | Persisted `SettingsPayload` & `CockpitSettings`. |
| `.aether/` | `LIVE_AUDIT.md` | Live SAST & architecture violation report (`AuditWriter::write_live_audit`). |
| `.aether/` | `ACTIVE_TARGET.md` | Active inspected symbol context, liaisons, contracts, tasks, and MCP commands. |
| `.aether/` | `CHAT_INBOX.md` | Bidirectional AI chat inbox (`PENDING_AI_RESPONSE` / `ANSWERED`). |
| `.aether/` | `ai_telemetry_cache.json` | Swarm telemetry cache (up to 250 history events, 300 s TTL). |
| `.aether/` | `bounty_scope.json` | Bug bounty scope (`in_scope`, `out_of_scope`, `mode`, `rationale`). |
| `.aether/` | `tasks/<task_id>/{task.json,README.md}` & `TASKS_SUMMARY.md` | Task tracking records and auto-synced summary dashboard (`TaskManager`). |
| `.aether/` | `plugins/` & `plugins/visuals/` | Declarative YAML SAST plugins and WebGL 2 GLSL visual packs. |
| `.aether/` | `cache/ast/` & `cache/osv/` | Incremental BLAKE3 AST cache and offline OSV.dev SCA advisory cache. |
| Project root | `AETHER_AI_RULES.md`, `BENCHMARK.md`, `aetherscope_viewer.html` | Master AI prompt rules, `--benchmark` output, and `/api/export` standalone HTML. |
| Working dir (CWD) | `desktop-shell-panic.log`, `desktop-shell-error.log`, `server-error.log` | Fatal panic hook, `real_main()`, and Axum/watcher startup error logs. |

## Next Steps

{% content-ref url="../core/blake3-governance.md" %}
[BLAKE3 Governance & EARS Contracts](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="best-practices.md" %}
[Golden Best Practices](best-practices.md)
{% endcontent-ref %}
