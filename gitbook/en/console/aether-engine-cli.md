# aether-engine CLI

The `aether-engine` binary (`v2.6.0`) is the primary entry point for the AetherScope desktop Cockpit, headless Axum server, SAST/SCA security auditor, performance benchmark runner, and stdio MCP server.

---

## Execution Modes & Precedence

When you invoke `aether-engine`, `real_main()` evaluates command-line flags in a strict precedence order so CI/CD, MCP, and GUI workflows stay deterministic:

1. **`--update-rules`**: Unpacks the embedded 24-rule Semgrep community bundle into `<path>/.aether/plugins/community/plugin.yaml` offline. Exits immediately unless `--audit-only`, `--port`, or `--mcp` is also passed without `--no-gui`.
2. **`--benchmark`**: Runs the 4-phase performance harness, prints throughput and memory metrics, writes `<path>/BENCHMARK.md`, and exits.
3. **`--mcp`**: Starts the JSON-RPC 2.0 MCP stdio loop on `stdin`/`stdout`. If no backend is listening on `127.0.0.1:<port>` (150 ms TCP probe), it spawns the Axum server and `FileWatcherBridge` in the background and waits 350 ms first.
4. **`--sca-only`**: Runs standalone dependency scanning across supported lockfiles plus AST call-graph reachability, prints a terminal report, evaluates `--fail-on`, and exits.
5. **Headless SAST Audit (`run_audit_cli`)**: Triggered automatically when `--audit-only`, `--format sarif`, `--fail-on`, `--sca`, or `--offline-sca` is specified. Runs AST + CWE + plugin + optional SCA analysis, emits reports, evaluates `--fail-on`, and synchronizes any active Cockpit on `127.0.0.1:<port>`.
6. **Server + Desktop Cockpit / `--no-gui`**: Starts the Axum REST server (`127.0.0.1:<port>`) and `FileWatcherBridge` (`100 ms` poll, `30 ms` loop, `100 ms` quiet-window debounce / `500 ms` max batch). With `--no-gui`, it stays headless indefinitely; otherwise, it opens a maximized `1280×800` native WebView2 window (`tao` + `wry`) with DevTools enabled.

{% hint style="warning" %}
Passing `--format markdown` or `--format text` alone does **not** trigger a headless audit—add `--audit-only` unless `--fail-on`, `--sca`, or `--offline-sca` is already present. Combining `--update-rules` with `--no-gui` also returns immediately after hydrating rules without starting the HTTP server.
{% endhint %}

---

## Flags Reference

### 🎮 Command Signature

```bash
aether-engine [OPTIONS]
```

### 📝 Arguments & Flags

`aether-engine` parses all options with `clap` (`2.6.0`), including standard `-h`/`--help` and `-V`/`--version`.

| Short | Long | Type | Default | Description | Edge Cases |
|---|---|---|---|---|---|
| `-p` | `--path <PATH>` | `String` | `"."` | Target project or Obsidian vault directory. Trims whitespace/quotes and strips Windows `\\?\` prefixes. | An empty string `""` resolves to the current working directory. |
| — | `--port <PORT>` | `u16` | `3030` | Local TCP port for Axum (`127.0.0.1:<port>`), `LocalGuard`, WebView2 URL, `--mcp` bridge, and live Cockpit sync. | If already bound in GUI/`--no-gui` mode, `server-error.log` records the bind error while the window remains open. |
| — | `--audit-only` | `bool` | `false` | Runs the headless SAST audit and exits without opening a window or starting the HTTP server. | Automatically implied by `--format sarif`, `--fail-on`, `--sca`, or `--offline-sca`. |
| — | `--no-gui` | `bool` | `false` | Keeps the Axum backend and `FileWatcherBridge` running headlessly without spawning a desktop window. | Exits early after hydrating rules if combined with `--update-rules`. |
| — | `--mcp` | `bool` | `false` | Enters the JSON-RPC 2.0 MCP stdio loop, auto-starting the in-process backend if port `<port>` is closed. | Checked after `--update-rules` and `--benchmark`, before `--sca-only` and `--audit-only`. |
| — | `--format <FORMAT>` | `String` | `"text"` | Audit report format: `"text"`, `"markdown"`, or `"sarif"` (case-insensitive check for `"sarif"`). | `"text"` and `"markdown"` execute the exact same branch writing `.aether/LIVE_AUDIT.md`. |
| `-o` | `--output <OUTPUT>` | `Option<String>` | `None` | Destination path for SARIF JSON or a copy of `.aether/LIVE_AUDIT.md` (auto-creates parent directories). | Ignored by `--sca-only` and `--benchmark`. |
| — | `--fail-on <SEVERITY>` | `Option<String>` | `None` | CI/CD quality gate threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING`, or exact severity match). | Exits `1` when breached; skips sanitized SSA taint traces (`is_sanitized == true`). |
| — | `--benchmark` | `bool` | `false` | Executes the 4-phase performance harness and writes `<path>/BENCHMARK.md`. | Accepts `--plugins`; ignores `--sca` and `--fail-on`. |
| — | `--update-rules` | `bool` | `false` | Hydrates the embedded offline 24-rule OWASP/CWE bundle into `<path>/.aether/plugins/community/plugin.yaml`. | 100% offline (`include_str!`); requires no network access. |
| — | `--sca` | `bool` | `false` | Enables Reachable OSV SCA (`Cargo.lock`, `package-lock.json`, `composer.lock`) during SAST audit. | Falls back silently to empty results per dependency if `curl` or OSV.dev fails. |
| — | `--offline-sca` | `bool` | `false` | Forces 100% air-gapped SCA reading only `<path>/.aether/cache/osv/<blake3>.json`. | Uncached dependencies return `0` vulnerabilities without spawning `curl`. |
| — | `--sca-only` | `bool` | `false` | Runs standalone SCA + call-graph reachability and prints a terminal report. | Does not write `LIVE_AUDIT.md`, SARIF, or `-o`, and does not pass `--plugins`. |
| — | `--plugins <SPEC>` | `Option<String>` | `None` | Selects active SAST plugins/packs: `"default"`, `"auto"`, `"all"`, pack/folder names, or `profile:<name>`. | Exits `1` on empty specs or unknown packs/profiles. |

{% hint style="info" %}
On Windows, `aether-engine` compiles with `#![windows_subsystem = "windows"]` so double-clicking never flashes an unwanted terminal, while calling `AttachConsole(0xFFFF_FFFF)` at startup so CLI stdout/stderr appear normally in PowerShell and `cmd.exe`. The native WebView2 window also raises V8's heap limit via `--js-flags=--max-old-space-size=4096` and logs unhandled failures to `desktop-shell-panic.log`, `desktop-shell-error.log`, and `server-error.log` in the working directory.
{% endhint %}

---

## Output Formats & Live Cockpit Sync

Headless SAST audits (`run_audit_cli`) support human-readable Markdown reports and machine-readable SARIF v2.1.0 output, followed by automatic synchronization with any running Cockpit instance.

{% tabs %}
{% tab title="text / markdown (Default)" %}
Both `--format text` and `--format markdown` write a timestamped report to `<path>/.aether/LIVE_AUDIT.md` and print a one-line summary to `stdout` with node, edge, violation, and audited-file counts.

- If `-o <file>` is supplied and `.aether/LIVE_AUDIT.md` exists, `aether-engine` creates any missing parent directories and copies `LIVE_AUDIT.md` to `<file>`.
- Clean projects (or projects with only `RULE_MAX_LINES` notices) report `ARCH_OK` inside `.aether/LIVE_AUDIT.md`.
{% endtab %}

{% tab title="sarif (SARIF v2.1.0)" %}
Passing `--format sarif` generates a pretty-printed **SARIF v2.1.0** document (`tool.driver.name = "AetherScope"`, `version = "2.6.0"`).

- **Destination**: Writes to `-o <file>` if provided (creating parent directories), or prints the full JSON payload to `stdout`.
- **Severity mapping**: `CRITICAL` / `HIGH` map to `"error"`, `MEDIUM` to `"warning"`, and `LOW` / `WARNING` / `INFO` / `NOTE` to `"note"`.
- **URI & line normalization**: Strips Windows `\\?\` prefixes, converts `\` to `/`, sets `uriBaseId: "%SRCROOT%"`, clamps line `0` to `1`, and embeds `cveId`, `remediation`, `is_reachable`, and `exploit_path` inside `result.properties`.
- **Documentation URLs (`helpUri`)**: Links `CWE-<digits>` findings to MITRE CWE definitions, `AETHER-*` rules to `CWE_CATALOG.md`, and custom rules cleanly by lowercase rule ID.
{% endtab %}
{% endtabs %}

### Live Cockpit Sync (`POST /api/analyze`)

If `run_audit_cli` completes without exiting on `--fail-on`, it probes `127.0.0.1:<port>` with a 150 ms TCP timeout:

- **Cockpit detected**: Sends `POST http://127.0.0.1:<port>/api/analyze` with `{"path": "<project_root>"}` so the 3D WebGL Cockpit and MCP server refresh immediately with your latest CLI scan.
- **No Cockpit active**: Prints an informational notice and exits `0`.

---

## Exit Codes & Quality Gates (`--fail-on`)

### 💎 Exit Codes

| Exit Code | Trigger Conditions | Output & Side Effects |
|---|---|---|
| `0` | Clean completion of `--update-rules`, `--benchmark`, `--mcp`, `--sca-only`, `run_audit_cli` (no `--fail-on` breach), or GUI exit. | Writes configured output files and runs live Cockpit sync after `run_audit_cli`. |
| `1` | Invalid `--plugins` selector, `--benchmark` runtime/I/O error, or `--fail-on` threshold breached in `run_audit_cli` / `--sca-only`. | Prints `❌` error diagnostics (plus up to 5 sample findings) to `stderr`. Reports (`LIVE_AUDIT.md` / SARIF / `-o`) are written **before** exit `1`, while live Cockpit sync is skipped. |
| `2` / Non-zero | Invalid `clap` syntax (`Args::parse()` exits `2`) or fatal runtime `Err` returned from `real_main()`. | Runtime errors write `desktop-shell-error.log` in the current working directory. |

### `--fail-on` Threshold Rules

| Mode | Evaluated Findings | Threshold Matching |
|---|---|---|
| `run_audit_cli` (SAST + `--sca`) | All active graph anomalies **except** sanitized SSA taint traces (`taint_trace.is_sanitized == true`). | `CRITICAL` -> `CRITICAL`<br>`HIGH` -> `CRITICAL`, `HIGH`<br>`MEDIUM` -> `CRITICAL`, `HIGH`, `MEDIUM`<br>`LOW` / `WARNING` -> `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING`<br>Other value -> exact case-insensitive match |
| `--sca-only` (SCA only) | **Only** reachable dependency vulnerabilities (`is_reachable == true`); unreachable CVEs never fail the build. | `CRITICAL` -> `CRITICAL`<br>`HIGH` -> `CRITICAL`, `HIGH`<br>`MEDIUM` -> `CRITICAL`, `HIGH`, `MEDIUM`<br>Other values -> ignored (never fail) |

{% hint style="success" %}
Sanitized SSA dataflow traces (`is_sanitized == true`) are automatically excluded from `--fail-on` gates during SAST audits, preventing false-positive CI blocks when an input is already neutralized by a recognized sanitizer.
{% endhint %}

---

## Plugin Selection (`--plugins`)

Use `--plugins <SPEC>` to control which local `.aether/plugins/` manifests and built-in rule packs execute during scans or benchmarks:

- **`default`** (default when `--plugins` is omitted): Runs all native built-in SAST rules plus every `enabled: true` YAML/JSON rule plugin in `<path>/.aether/plugins/` (excluding `visuals/` and `visual-plugin.*`).
- **`auto` / `all`**: Runs all native built-in SAST rules plus all enabled local plugins.
- **Comma-separated `Select` list**: Accepts case-insensitive plugin `name` values, parent folder aliases (`folder_alias`), `profile:<name>` selectors (matching a plugin's `profile` field or `tags` list), or any of the 34 built-in pack names below.

<details>
<summary>View all 34 built-in pack names accepted by --plugins</summary>

| Rule Family | Accepted Pack Tokens |
|---|---|
| **Rust** | `builtin-rust`, `rust`, `rust-l1` |
| **Web3 / Solidity / DeFi** | `builtin-web3`, `web3`, `solidity`, `defi` |
| **Python** | `builtin-python`, `python`, `py` |
| **JavaScript / TypeScript** | `builtin-javascript`, `javascript`, `js`, `typescript`, `ts` |
| **PHP** | `builtin-php`, `php` |
| **Zig** | `builtin-zig`, `zig` |
| **C# / .NET** | `builtin-csharp`, `csharp`, `cs`, `dotnet` |
| **C / C++** | `builtin-cpp`, `cpp`, `c` |
| **Deep (Injection / VM / Wasm)** | `builtin-deep`, `deep` |
| **Epic / Novel (`AETHER-*`)** | `builtin-epic`, `epic`, `novel` |
| **Architecture & Core (`RULE_*`, `SAST_*`, `BLAKE3_TAMPERED`)** | `architecture`, `arch`, `core` |

</details>

{% hint style="warning" %}
In `ProjectScanner` (used by `--audit-only`, `--format sarif`, and the Cockpit server), passing a comma-separated `--plugins <spec>` (`PluginSelection::Select`) disables native built-in SAST rules and runs only matching `.aether/plugins/` manifests. In `--benchmark` mode, `SecurityLinter::audit_file_selected` filters native rules matching built-in pack tokens as well.
{% endhint %}

---

## Software Composition Analysis (`--sca`, `--offline-sca`, `--sca-only`)

AetherScope discovers dependencies in `<path>` and immediate 1-level subdirectories across three lockfile formats (skipping `target`, `node_modules`, and `.git`):

- **`Cargo.lock`**: Ecosystem `crates.io` (includes `registry+` and `git+` sources).
- **`package-lock.json`**: Ecosystem `npm` (supports v1 nested `dependencies` and v2/v3 flat `packages`).
- **`composer.lock`**: Ecosystem `Packagist` (`packages` and `packages-dev`, stripping leading `v` tags).

For each dependency, `ScaEngine` checks the local BLAKE3 disk cache at `<path>/.aether/cache/osv/<blake3>.json` (hashed from `"{ecosystem}:{package}:{version}"`). Unless `--offline-sca` is set, cache misses query `https://api.osv.dev/v1/query` via `curl -sSL --max-time 5` and persist responses locally.

Found CVEs are attached to `«Vulnerable Dependency»` nodes, linked by `EdgeType::Call` edges from matching application callers, and traced via reverse BFS (`compute_reachability`) to separate reachable exploit paths from dead-code dependencies.

---

## Benchmark & Offline Rules Update (`--benchmark`, `--update-rules`)

### `--benchmark`

Runs a 4-phase benchmark across your workspace:

1. **Discovery & Lexing**: Collects source files and measures line-of-code counts plus literal masking (`mask_literals`).
2. **AST & Graph**: Builds the parallel Rayon AST and affiliation graph (`ProjectScanner::scan_project`).
3. **CWE & Plugin Evaluation**: Evaluates native and plugin SAST rules across `available_parallelism()` worker threads.
4. **Reachability & Layouts**: Computes reverse-BFS reachability and all four spatial layouts (`Z-1`..`Z-4`).

The command prints phase timings, Peak RSS (`K32GetProcessMemoryInfo` on Windows or `/proc/self/status` on Unix), and LOC/s throughput to `stdout`, then writes `<path>/BENCHMARK.md`.

### `--update-rules`

Extracts the embedded 24-rule OWASP/CWE Semgrep community pack directly from the binary into `<path>/.aether/plugins/community/plugin.yaml` with zero network calls.

---

## Common Examples

{% tabs %}
{% tab title="CI/CD SARIF Gate" %}
{% code title="Run headless SAST + SCA audit and fail on HIGH or CRITICAL" overflow="wrap" %}
```bash
aether-engine --path . --audit-only --sca --format sarif --output results.sarif --fail-on HIGH
```
{% endcode %}
{% endtab %}

{% tab title="Air-Gapped SCA" %}
{% code title="Run standalone SCA strictly from local BLAKE3 cache" overflow="wrap" %}
```bash
aether-engine --path . --sca-only --offline-sca --fail-on CRITICAL
```
{% endcode %}
{% endtab %}

{% tab title="Custom Plugin Profile" %}
{% code title="Hydrate community rules then run only the owasp profile" overflow="wrap" %}
```bash
aether-engine --path . --update-rules
aether-engine --path . --audit-only --plugins profile:owasp
```
{% endcode %}
{% endtab %}

{% tab title="Headless Server & Sync" %}
{% code title="Start headless Axum backend on port 3030, then sync a CLI scan" overflow="wrap" %}
```bash
aether-engine --path . --no-gui --port 3030
# In a second terminal:
aether-engine --path . --audit-only --port 3030
```
{% endcode %}
{% endtab %}

{% tab title="Benchmark" %}
{% code title="Measure AST, SAST, and layout throughput into BENCHMARK.md" overflow="wrap" %}
```bash
aether-engine --path . --benchmark --plugins default
```
{% endcode %}
{% endtab %}
{% endtabs %}

---

## Related Pages

{% content-ref url="plugin-and-mcp-clis.md" %}
[Plugin, MCP & Runner CLIs](plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="launchers-and-scripts.md" %}
[Launchers, Installers & CI/CD Workflows](launchers-and-scripts.md)
{% endcontent-ref %}

{% content-ref url="../core/cwe-sast-engine.md" %}
[CWE & SAST Engine](../core/cwe-sast-engine.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../extensions-dev/benchmark-and-performance.md" %}
[Benchmark & Performance Tuning](../extensions-dev/benchmark-and-performance.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}
