# Troubleshooting & FAQ

This guide helps you diagnose and resolve common `aether-engine` issues on Windows, Linux, and macOS, from WebView2 crashes and port `3030` conflicts to `LocalGuard` `403` errors, `BLAKE3_TAMPERED` alerts, offline SCA caches, and version label differences.

## Desktop Launch, Windows Console & Crash Logs

On Windows, `crates/desktop-shell/src/main.rs` sets `#![windows_subsystem = "windows"]` so double-clicking `aether-engine.exe` does not pop up an extra console window. When launched from PowerShell or `cmd.exe`, it calls `AttachConsole(0xFFFF_FFFF)` (`ATTACH_PARENT_PROCESS`) to attach output to your terminal.

If the desktop shell or HTTP server fails, inspect the diagnostic log files written to your **current working directory**:

| Log File (in CWD) | Trigger | Typical Cause |
| :--- | :--- | :--- |
| `desktop-shell-panic.log` | Panic hook (`PANIC: {:?}`) | Unexpected runtime panic during startup or analysis. |
| `desktop-shell-error.log` | `real_main()` error (`MAIN ERROR: {:?}`) | WebView2 runtime missing/corrupted or Tao window initialization failure. |
| `server-error.log` | `run_server_and_watcher()` error (`SERVER ERROR: {:?}`) | `TcpListener::bind("127.0.0.1:<port>")` failed because port `3030` is already occupied. |

{% hint style="info" %}
On Windows, `aether-engine` passes `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --js-flags=--max-old-space-size=4096` to WebView2 (`main.rs`). If the embedded window still fails to open, verify that the Microsoft Edge WebView2 Runtime is installed and inspect `desktop-shell-error.log`, or launch in headless browser mode with `--no-gui`.
{% endhint %}

## Port 3030 Conflicts

Both `aether-engine` and `aetherscope-mcp` default `--port` to `3030` (`127.0.0.1:3030`). If another instance is still running in the background, `server-error.log` records a bind error.

{% tabs %}
{% tab title="Use a Custom Port" %}
```bash
# Start on an alternate port (for example 3040)
aether-engine --path . --port 3040
```
{% endtab %}
{% tab title="Windows Cleanup Scripts" %}
```bat
:: Option [7] in AetherScope-Launcher.bat runs :KILL_PORT:
:: 1. taskkill /F /IM aether-engine.exe
:: 2. taskkill /F /IM aetherscope-mcp.exe
:: 3. Kills every PID listening on :3030 via netstat -aon

:: Start-Cockpit.bat also clears aether-engine.exe and :3030 automatically before launch.
```
{% endtab %}
{% endtabs %}

## LocalGuard 403 Forbidden Errors

`LocalGuard` (`crates/desktop-shell/src/local_guard.rs`) wraps the entire Axum router and returns HTTP `403 Forbidden` with the plain-text body `"AetherScope: requête refusée (origine non locale)"` if **any** of these three header checks fail:

| Header Checked | Allowed Values | Common Cause of `403 Forbidden` |
| :--- | :--- | :--- |
| `Host` | `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` | Missing port (e.g. `Host: localhost` without `:3030`), wrong port, or non-loopback hostname. |
| `Origin` *(when present)* | `http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>` | `https://` origin, external site, or `Origin: null` when opening a local `file://` HTML page. |
| `Sec-Fetch-Site` *(when present)* | `"same-origin"` or `"none"` | Browser sending `"cross-site"` or `"same-site"` from another local port (use Vite proxy or same-origin `http://127.0.0.1:3030`). |

{% hint style="warning" %}
If you call `/api/*` from `curl` or a script, do not pass a mismatched `Origin` header or omit `:3030` in `Host`. From the browser, open `http://127.0.0.1:3030` directly (or the Vite dev server which proxies `/api` to `http://127.0.0.1:3030`) rather than opening an exported HTML file via `file://`.
{% endhint %}

## BLAKE3_TAMPERED Violations

When a folder's `README.md` exists and `aether.lock.toml` stores a `readme_blake3` digest for that folder, `ast-scanner` verifies `blake3(README.md)` against the lockfile. If they differ, it emits a `CRITICAL` `CWE-353 / BLAKE3-INTEGRITY` finding (`rule_id: "BLAKE3_TAMPERED"`).

{% hint style="danger" %}
`BLAKE3_TAMPERED` is explicitly exempted (`exempt_blake3` in `main.rs`) from standard `active_cve_rules` filtering so contract tampering cannot be silently masked by general rule profiles.
{% endhint %}

Resolve legitimate `README.md` contract updates using any of these 3 methods:

1. **Doc Reader Drawer**: Click **Signer** (`api.signContracts({ project_path, folder })`) to recompute and seal the digest in `aether.lock.toml`.
2. **Inspector Drawer**: Adjust per-folder or per-file rules and click **🔒 Sceller BLAKE3** (`POST /api/contracts/update`), which edits frontmatter and automatically re-signs `aether.lock.toml`.
3. **REST API**: Call `POST http://127.0.0.1:3030/api/contracts/sign` directly:

```bash
curl -s -X POST "http://127.0.0.1:3030/api/contracts/sign" \
  -H "Content-Type: application/json" \
  -d '{"project_path": ".", "folder": "server"}'
```

## Offline OSV SCA Cache & Air-Gapped Scans

Reachable Dependency SCA (`--sca`, `--sca-only`) queries `https://api.osv.dev/v1/query` with a 5-second timeout (`curl --max-time 5`) and caches responses under `<project_root>/.aether/cache/osv/<blake3_hex>.json`.

* **Cache key formula**: `blake3("{ecosystem}:{package}:{version}")` (64-character lowercase hex).
* **Normalized ecosystem names**: `"cargo" | "rust" | "crates.io"` -> `"crates.io"`, `"npm" | "node" | "javascript" | "typescript"` -> `"npm"`, `"packagist" | "composer" | "php"` -> `"Packagist"`.
* **Air-gapped behavior (`--offline-sca`)**: Checks `.aether/cache/osv/` only and returns `Ok(Vec::new())` on cache miss without spawning `curl`.
* **Pre-seeding cache files**: Each `<blake3>.json` file accepts an `OsvCacheEntry` wrapper, an `OsvQueryResponse` (`{"vulns": [...]}`), or a raw `Vec<OsvVulnerability>` JSON array.

## Standalone Viewer Port 3333 Fallback in McpControlModal

`AetherApiClient` (`crates/desktop-shell/ui/src/lib/api.ts`) defaults `baseUrl` to `''` (relative same-origin `/api/*` calls). However, `McpControlModal.svelte` derives the port shown in generated MCP JSON and `curl` snippets as:

```ts
const serverPort = $derived(
  typeof window !== 'undefined' && window.location.port ? window.location.port : '3333'
);
```

When you open the Cockpit at `http://127.0.0.1:3030`, `window.location.port` is `'3030'`, so snippets display `3030` accurately. When you open a standalone HTML export via `file://` or a portless origin (`window.location.port === ''`), `McpControlModal` falls back to `'3333'`. Always replace `3333` with `3030` (or your custom `--port` value) when copying snippets from standalone exports.

## FAQ: Why Do Some Files Show v2.5.1, V2.4, or V2.1 Instead of 2.6.0?

The canonical workspace version of `aether-engine` is **`2.6.0`**, declared in root `Cargo.toml`, `mcp.json`, root `README.md`, `crates/desktop-shell/ui/package.json`, and `aetherscope-mcp` `serverInfo.version` (`env!("CARGO_PKG_VERSION")`).

A few secondary manifests, batch launchers, and internal banners still carry historical strings from earlier releases:

| Legacy Label | Where It Appears in the Codebase | Notes |
| :--- | :--- | :--- |
| `2.5.1` | `smithery.yaml`, `crates/README.md`, `crates/desktop-shell/README.md` | Package/crate README header & Smithery metadata from v2.5.1. |
| `V2.4` | `AetherScope-Launcher.bat`, `Start-Cockpit.bat`, `crates/desktop-shell/src/mcp_main.rs` (`about`) | Launcher UI banners and `aetherscope-mcp --help` description string. |
| `V2.1` / `V2` | `crates/desktop-shell/src/benchmark.rs`, `BENCHMARK.md`, `crates/desktop-shell/src/main.rs` (`{"status":"ok","engine":"aether-v2"}`) | Second-generation engine identifier retained for compatibility. |

{% content-ref url="../getting-started/installation.md" %}
[Installation](../getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="../core/blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="benchmark-and-performance.md" %}
[Benchmark & Performance Tuning](benchmark-and-performance.md)
{% endcontent-ref %}
