# Plugin, MCP & Runner CLIs

Alongside `aether-engine`, the repository provides three specialized Rust command-line binaries for SAST plugin management, standalone MCP stdio orchestration, and supervised Minecraft server provisioning.

---

## Companion Binaries Overview

| Binary | Crate / Manifest | Version | Invocation | Primary Purpose |
|---|---|---|---|---|
| `aether-plugin-tool` | `crates/security-linter` | `2.6.0` | `cargo run -p security-linter --bin aether-plugin-tool -- <CMD>` | Scaffold, import, test, list, export, and run YAML/JSON SAST plugins. |
| `aetherscope-mcp` | `crates/desktop-shell` | `2.6.0` | `cargo run -p desktop-shell --bin aetherscope-mcp -- [OPTIONS]` | Dedicated JSON-RPC 2.0 MCP stdio bridge with auto-spawned backend. |
| `aether-mc-runner` | `apps/aethercraft/runner` | `1.0.0` | `cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- <CMD>` | Standalone AetherCraft installer, SHA-256 verifier, and Java supervisor. |

{% content-ref url="aether-engine-cli.md" %}
[aether-engine CLI](aether-engine-cli.md)
{% endcontent-ref %}

---

## aether-plugin-tool

`aether-plugin-tool` manages declarative SAST rule packs stored under `.aether/plugins/`. Invoking it without arguments prints usage help and exits with code `0`; passing an unknown subcommand or flag like `--version` prints an error to `stderr` and exits with code `1`.

### 🎮 Command Summary

| Subcommand & Aliases | Arguments & Flags | Defaults | Exit Behavior |
|---|---|---|---|
| `help`, `--help`, `-h` | None | — | Prints CLI usage to `stdout` and exits `0`. |
| `download-semgrep-rules`, `update-rules` | `-o`/`--output <DIR>`, `-u`/`--url <URL>`, `--offline`, positional `<DIR>`, `--help` | `dir`: `.aether/plugins`, `url`: Semgrep `template.yaml`, `offline`: `false` | Fetches via `curl -sSL --max-time 5`; falls back automatically to the 24-rule embedded `CommunityBundle`. Exits `1` only on disk write failure. |
| `init-bundle` | `[output_dir]` | `.aether/plugins` | Unpacks the embedded 24-rule OWASP/CWE pack to `<output_dir>/community/plugin.yaml`. Exits `1` on write error. |
| `import-semgrep` | `-i`/`--input <PATH>` (or positional `<PATH>`), `-o`/`--output <DIR>`, `--help` | `output`: `.aether/plugins/imported` | Translates Semgrep `.yaml`/`.yml` files into `<output>/<stem>/plugin.yaml`. Exits `0` if no YAML files match; `1` on missing input. |
| `test` | `[plugins_dir]` | `.aether/plugins` | Runs `PluginEngine::run_test_suite()` across manifests (skipping `visuals/`). Exits `1` if `failed > 0` or load error. |
| `scan` | `<plugins_dir> <target_path>` | Both required | Scans a file or directory tree (skipping `target`, `.git`, `node_modules`, `zig-cache`, `zig-out`, `bin`, `obj`). **Exits `0` even with violations.** |
| `list` | `[plugins_dir]` | `.aether/plugins` | Lists loaded plugins, rule IDs, CWE IDs, severities, and target extensions. Exits `1` on load error. |
| `init` | `<plugin_name> [output_dir]` | `output_dir`: `.aether/plugins` | Scaffolds `<output_dir>/<plugin_name>/plugin.yaml` with `CUSTOM-<NAME>-001` (`CWE-287`, `HIGH`) and 2 passing `test_cases`. |
| `export` | `[plugins_dir] [out.md]` | `.aether/plugins`, `PLUGIN_CATALOG.md` | Generates a Markdown rule catalog table across all active plugins. Exits `1` on load or write failure. |

### 📝 Key Subcommands & Edge Cases

- **Offline fallback (`download-semgrep-rules` / `update-rules`)**: Without `--offline`, `aether-plugin-tool` runs `curl -sSL --max-time 5` against `-u <URL>` (defaulting to `https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/template.yaml`). If `curl` fails, times out, or returns invalid/empty Semgrep rules, it unpacks the embedded 24-rule OWASP/CWE `CommunityBundle`.
- **Positional argument quirks**: In `download-semgrep-rules`, any argument not starting with `-` overrides `output_dir`. In `import-semgrep`, the first non-flag argument sets `input_path` if `--input` was omitted; a trailing flag without a value is silently ignored.
- **No CI exit gate on `scan`**: `aether-plugin-tool scan` always exits `0` once scanning finishes, even when findings are printed. Use `aether-engine --audit-only --fail-on <SEVERITY>` when you need non-zero CI exits.

### 💡 Examples

{% tabs %}
{% tab title="Scaffold & Test Plugin" %}
{% code title="Create a new plugin manifest and execute its embedded unit tests" overflow="wrap" %}
```bash
aether-plugin-tool init my-auth-guard .aether/plugins
aether-plugin-tool test .aether/plugins
```
{% endcode %}
{% endtab %}

{% tab title="Import Semgrep & Scan" %}
{% code title="Convert Semgrep YAML rules, export catalog, and scan src/" overflow="wrap" %}
```bash
aether-plugin-tool import-semgrep --input ./semgrep-rules --output .aether/plugins/imported
aether-plugin-tool export .aether/plugins PLUGIN_CATALOG.md
aether-plugin-tool scan .aether/plugins ./src
```
{% endcode %}
{% endtab %}

{% tab title="Offline Community Bundle" %}
{% code title="Unpack the embedded 24-rule OWASP/CWE pack without network access" overflow="wrap" %}
```bash
aether-plugin-tool update-rules --offline --output .aether/plugins
# Equivalent direct command:
aether-plugin-tool init-bundle .aether/plugins
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../plugins/semgrep-and-community-bundle.md" %}
[Semgrep Importer & Community Bundle](../plugins/semgrep-and-community-bundle.md)
{% endcontent-ref %}

---

## aetherscope-mcp

`aetherscope-mcp` exposes AetherScope's graph, SAST, contract, task, and swarm capabilities over **JSON-RPC 2.0 (`protocolVersion: "2024-11-05"`)** on `stdin`/`stdout` for AI clients such as Claude Desktop, Antigravity, Gemini CLI, and Cursor.

### 🎮 Command Signature

```bash
aetherscope-mcp [OPTIONS]
```

### 📝 Arguments, Flags & Environment Variables

| Flag / Env Var | Short | Default | Description |
|---|---|---|---|
| `-p`, `--path <PATH>` | `-p` | `"."` | Root workspace or Obsidian vault directory passed to the backend or offline fallback. |
| `--port <PORT>` | — | `3030` | Axum backend port (`127.0.0.1:<port>`) probed and used for HTTP bridge calls. |
| `--mcp` | — | `false` | Accepted for CLI flag parity with `aether-engine --mcp`; `aetherscope-mcp` always runs MCP stdio. |
| `--agent-id <AGENT_ID>` / `AETHER_AGENT_ID` | — | `mcp-agent-<pid % 10000>` | Explicit swarm agent ID shown in Cockpit 3D telemetry and chat. |
| `--agent-name <AGENT_NAME>` / `AETHER_AGENT_NAME` | — | `IA MCP #<pid % 10000>` | Display name for the connected AI session. |
| `--color <COLOR>` / `AETHER_AGENT_COLOR` | — | Deterministic hash color | Hex color badge (`#38bdf8`..`#e879f9`) from the 12-color `MCP_AGENT_PALETTE`. |
| `-h`, `--help` / `-V`, `--version` | `-h`, `-V` | — | Prints CLI help or workspace version (`2.6.0`). |

{% hint style="info" %}
`aetherscope-mcp --version` and JSON-RPC `initialize` `serverInfo.version` report canonical workspace version `2.6.0`, whereas the CLI `--help` description string still displays the legacy `"AetherScope V2.4 - Dedicated MCP Server for AI Agents"` label (and `smithery.yaml` lists `"2.5.1"`).
{% endhint %}

### Agent Identity Precedence

`aetherscope-mcp` resolves each session's identity using a 5-tier priority order:

1. **Per-tool-call JSON arguments**: `agent_id` (aliases: `agent`, `caller`, `author`, `sender`, `role`), `agent_name` (alias: `name`), and `color`.
2. **CLI flags**: `--agent-id`, `--agent-name`, `--color`.
3. **Environment variables**: `AETHER_AGENT_ID`, `AETHER_AGENT_NAME`, `AETHER_AGENT_COLOR`.
4. **MCP `initialize` `params.clientInfo.name`**: Used only if neither CLI flags nor environment variables set an explicit identity.
5. **PID defaults**: `mcp-agent-<pid % 10000>` and deterministic FNV-1a color selection (`#38bdf8` if empty).

### Auto-Spawn Lifecycle & Transport Discipline

- **Backend probe & auto-spawn**: On startup, `aetherscope-mcp` checks `127.0.0.1:<port>` with a 150 ms TCP probe. If no server is listening, it looks for a sibling `aether-engine.exe` next to `current_exe()`, spawns `aether-engine.exe --no-gui --port <port> --path <path>`, and polls for up to **1.5 s** (`10 × 150 ms`).
- **Offline AST fallback**: If no backend becomes reachable, read and analysis tools automatically fall back to direct AST/Vault/TaskManager scanning and persist telemetry in `.aether/ai_telemetry_cache.json`.
- **Stdio framing**: Reads newline-delimited JSON on `stdin` (stripping whitespace and UTF-8 BOM `\u{feff}`), writes **only** single-line JSON-RPC responses to `stdout`, and routes all startup logs to `stderr`.
- **JSON-RPC errors**: Returns `-32700` on invalid JSON, `-32601` on unknown methods, `-32602` on unknown resource URIs or prompt names, and `isError: true` tool results for `PathGuard`/`SecretGuard` violations.

{% hint style="warning" %}
Auto-spawning looks specifically for `aether-engine.exe` next to `aetherscope-mcp`. On Linux or macOS, start the backend separately with `aether-engine --no-gui` or configure your MCP client to invoke `aether-engine --mcp` directly so the Axum server launches in-process.
{% endhint %}

### 💡 Examples

{% tabs %}
{% tab title="mcp.json" %}
{% code title="Standard MCP client entry with explicit swarm identity" overflow="wrap" %}
```json
{
  "mcpServers": {
    "aetherscope": {
      "command": "aetherscope-mcp",
      "args": ["--port", "3030", "--path", ".", "--agent-id", "claude-sec", "--agent-name", "Claude Security"]
    }
  }
}
```
{% endcode %}
{% endtab %}

{% tab title="CLI & Env Invocation" %}
{% code title="Launch standalone MCP bridge with environment-based agent identity" overflow="wrap" %}
```bash
AETHER_AGENT_ID="auditor-1" AETHER_AGENT_COLOR="#34d399" aetherscope-mcp --path /path/to/repo --port 3030
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}

---

## aether-mc-runner

`aether-mc-runner` (`v1.0.0`) is the standalone Rust/Tokio installer and runtime supervisor for AetherCraft Minecraft servers. Because `apps/aethercraft/runner` is excluded from the root Cargo workspace, build or run it via `--manifest-path apps/aethercraft/runner/Cargo.toml`.

### 🎮 Subcommands & Flags

| Subcommand | Short / Long Flags | Required | Default | Description |
|---|---|---|---|---|
| `install` | `-m`, `--manifest <MANIFEST>`<br>`-d`, `--dir <DIR>` | Manifest: **Yes**<br>Dir: No | `./instances/<server_id>` | Loads a manifest from a local path or `http(s)://` URL (10 s timeout), downloads `core` JAR and `plugins_and_mods`, verifies `Sha256`, writes `configs`, and saves `.aether-manifest.json`. |
| `run` | `-d`, `--dir <DIR>` | **Yes** | None | Reads `<dir>/.aether-manifest.json`, checks `java -version` and `<core.target_jar>`, and starts `java` with filtered `jvm_flags` plus `-jar <target_jar> nogui`. |
| `install-and-run` | `-m`, `--manifest <MANIFEST>`<br>`-d`, `--dir <DIR>` | Manifest: **Yes**<br>Dir: No | `./instances/<server_id>` | Runs `install` followed immediately by `run`. |
| `doctor` | None | — | — | Verifies `java -version` in `PATH` and checks `https://api.papermc.io/v2/projects` (5 s timeout). Prints warnings if unreachable and exits `0`. |

### Security & Supervised Log Tags

- **SHA-256 artifact integrity**: When `sha256` in the manifest is non-empty, `AetherInstaller` compares the streaming SHA-256 digest (case-insensitive) and **deletes the downloaded file** if it mismatches. If `sha256` is empty, it logs the first 8 hex characters and continues.
- **CWE-22 & command-injection guards**: Rejects `..`, leading `/`, or leading `\` in `core.target_jar`, artifact paths/names, and `configs` keys. Filters `runtime.jvm_flags` to allow only entries starting with `-` without shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `\r`, `\n`), invoking `java` directly without a shell.
- **Supervised output prefixes**:

| Log Prefix | Stream | Trigger Condition |
|---|---|---|
| `[MC-WARN]` | `stdout` | Output line contains `WARN`. |
| `[MC-ERR]` | `stdout` | Output line contains `ERROR`. |
| `✨ [MC-READY]` | `stdout` | Output line contains `Done (`. |
| `[MC]` | `stdout` | All other `stdout` lines from the JVM process. |
| `[MC-STDERR]` | `stderr` | All `stderr` lines emitted by the JVM process. |

### 💡 Example

{% code title="Provision and start a PaperMC server instance via AetherCraft manifest" overflow="wrap" %}
```bash
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- doctor
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- install-and-run \
  --manifest http://127.0.0.1:5000/api/v1/servers/my-smp/manifest \
  --dir ./instances/my-smp
```
{% endcode %}

{% content-ref url="../extensions-dev/aethercraft.md" %}
[AetherCraft Minecraft Platform](../extensions-dev/aethercraft.md)
{% endcontent-ref %}
