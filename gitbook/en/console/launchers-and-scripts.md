# Launchers, Installers & CI/CD Workflows

AetherScope ships Windows batch launchers, PowerShell installation and deployment scripts, and GitHub Actions workflows to automate local startup, MCP client registration, standalone WebGL publishing, and SARIF security gates.

{% hint style="info" %}
The canonical workspace version across `Cargo.toml`, `mcp.json`, and `ui/package.json` is `2.6.0`. Several batch/PowerShell banners and the GitHub Actions binary cache key still display legacy `V2.4` or `v2.5.1` labels from earlier releases.
{% endhint %}

---

## Interactive Control Center (`AetherScope-Launcher.bat`)

`AetherScope-Launcher.bat` is an interactive 9-option Windows menu (`chcp 65001`) that resolves binaries, clears stale port `3030` listeners, synchronizes executables, and launches every AetherScope runtime mode.

### Binary Resolution & `:SYNC_BINARIES`

Before launching GUI or headless modes, the script locates `aether-engine.exe` (exiting with code `1` if missing), `aetherscope-mcp.exe`, and `aether-mc-runner.exe` in strict priority order:

1. `%SCRIPT_DIR%target\release\`
2. `%REPO_DIR%target\release\` (fallback repo directory)
3. `%SCRIPT_DIR%`
4. `%REPO_DIR%`
5. `%LOCALAPPDATA%\AetherScope\bin\`

For options `[1]` and `[3]`, `:SYNC_BINARIES` terminates `aether-engine.exe`, kills any `LISTENING` PID on port `3030` via `netstat -aon`, copies updated binaries into `%LOCALAPPDATA%\AetherScope\bin\` if that directory exists, and copies `aether-engine.exe` to `%SCRIPT_DIR%` when run from a source checkout (`Cargo.toml` present).

### Menu Options (`[1]`–`[9]`)

Pressing **Enter** at the prompt selects option `[1]` by default.

| Option | Menu Action | Underlying Command / Behavior |
|---|---|---|
| `[1]` (default) | Launch Spatial Cockpit | Runs `:SYNC_BINARIES`, starts `aether-engine.exe` (`http://127.0.0.1:3030`), waits 2 s, and exits `0`. |
| `[2]` | Test Interactive MCP Stdio Server | Runs `"%MCP_EXE%" --port 3030` interactively inside the console (`Ctrl+C` to stop). |
| `[3]` | Launch Headless Server | Runs `:SYNC_BINARIES` and blocks on `"%ENGINE_EXE%" --no-gui` (`http://127.0.0.1:3030`). |
| `[4]` | Configure AI Clients | Executes `powershell -NoProfile -ExecutionPolicy Bypass -File setup-mcp.ps1`. |
| `[5]` | Scan & Sync Project (SAST) | Prompts for `SCAN_PATH` (default `.`), runs `"%ENGINE_EXE%" --path "%SCAN_PATH%" --audit-only`, and outputs `.aether\LIVE_AUDIT.md`. |
| `[6]` | Launch AetherCraft Minecraft Cockpit | Opens `http://127.0.0.1:5000` and runs `python apps\aethercraft\control-plane\app.py`. |
| `[7]` | Free Port `3030` | Force-kills `aether-engine.exe`, `aetherscope-mcp.exe`, and any PID listening on `:3030`. |
| `[8]` | Install / Update in Windows | Executes `powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1`. |
| `[9]` | Quit | Exits cleanly with code `0`. |

---

## One-Click Cockpit Launch (`Start-Cockpit.bat`)

`Start-Cockpit.bat` provides a non-interactive fast path to launch the desktop Cockpit without opening the launcher menu.

- Resolves `aether-engine.exe` and `aetherscope-mcp.exe` using the same 5-step directory order as `AetherScope-Launcher.bat`.
- Force-kills `aether-engine.exe` and any PID listening on port `3030`, synchronizes binaries to `%LOCALAPPDATA%\AetherScope\bin\` and `%SCRIPT_DIR%`, starts `"%ENGINE_EXE%"`, and exits `0`.

{% hint style="warning" %}
Unlike option `[7]` of `AetherScope-Launcher.bat`, `Start-Cockpit.bat` does **not** terminate `aetherscope-mcp.exe` processes—so active IDE MCP stdio sessions stay alive when you restart the Cockpit window.
{% endhint %}

---

## Windows Installer (`install.ps1`)

`install.ps1` installs the compiled AetherScope binaries, adds them to your Windows user `PATH`, creates a Desktop shortcut, and registers the MCP server across installed AI clients.

### 🎮 Signature

```powershell
.\install.ps1 [-InstallDir <String>] [-SkipMcp] [-SkipShortcut]
```

### 📝 Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-InstallDir` | `String` | `$env:LOCALAPPDATA\AetherScope` | Target installation root (`bin\` holds executables; root holds helper scripts). |
| `-SkipMcp` | `Switch` | `$false` | Skips automatic execution of `setup-mcp.ps1` at the end of installation. |
| `-SkipShortcut` | `Switch` | `$false` | Skips creating the `AetherScope V2.lnk` shortcut on your Windows Desktop. |

### Installed Layout & Side Effects

- **Binaries copied to `$InstallDir\bin\`**: `aether-engine.exe` (mandatory; exits `1` if missing from `target\release` and script dir), `aetherscope-mcp.exe` (wrapped in `try/catch` in case an IDE currently locks it), `aether-mc-runner.exe`, and `aether-plugin-tool.exe`.
- **Scripts copied to `$InstallDir\`**: `AetherScope-Launcher.bat`, `Start-Cockpit.bat`, and `setup-mcp.ps1`.
- **User `PATH` & Shortcut**: Appends `$InstallDir\bin` to the Windows `User` `PATH` variable if absent, and creates `Desktop\AetherScope V2.lnk` pointing to `Start-Cockpit.bat` (or `aether-engine.exe` as fallback).

### 💡 Examples

{% tabs %}
{% tab title="Standard Install" %}
{% code title="Install binaries, PATH, Desktop shortcut, and MCP configs" overflow="wrap" %}
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```
{% endcode %}
{% endtab %}

{% tab title="Custom Directory (No Shortcut)" %}
{% code title="Install to D:\Tools\AetherScope without Desktop shortcut or MCP setup" overflow="wrap" %}
```powershell
.\install.ps1 -InstallDir "D:\Tools\AetherScope" -SkipShortcut -SkipMcp
```
{% endcode %}
{% endtab %}
{% endtabs %}

---

## MCP Client Auto-Configurator (`setup-mcp.ps1`)

`setup-mcp.ps1` discovers `aetherscope-mcp.exe` (in the script folder, `target\release`, or `%LOCALAPPDATA%\AetherScope\bin`) and writes or updates the `mcpServers.aetherscope` entry in UTF-8 across supported AI clients.

### 🎮 Signature

```powershell
.\setup-mcp.ps1 [-Port <String>]
```

### 📝 Target Configuration Files

| AI Client | Target JSON Path |
|---|---|
| **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Antigravity / Gemini CLI** | `%USERPROFILE%\.gemini\config\mcp_config.json` |
| **Cursor** | `%USERPROFILE%\.cursor\mcp.json` |

### 💡 Generated JSON Entry

{% code title="Injected mcpServers.aetherscope block" overflow="wrap" %}
```json
{
  "mcpServers": {
    "aetherscope": {
      "command": "C:\\Users\\<User>\\AppData\\Local\\AetherScope\\bin\\aetherscope-mcp.exe",
      "args": ["--port", "3030"]
    }
  }
}
```
{% endcode %}

---

## Standalone GitHub Pages Deployment (`deploy-gh-pages.ps1`)

`deploy-gh-pages.ps1` builds the Svelte 5 frontend, exports the self-contained repository graph into `docs/index.html`, and publishes the static demo to the `gh-pages` branch:

1. Runs `npm run build` inside `crates/desktop-shell/ui` to produce `crates/desktop-shell/dist/`.
2. Runs `cargo test -p desktop-shell --bin aether-engine viewer::tests::test_export_docs_index_html`, which scans the repository and embeds `window.__AETHERSCOPE_DATA__` and `window.__AETHERSCOPE_DUAL_GRAPH__` into `docs/index.html`.
3. Stages `crates/desktop-shell/dist/*` into `%TEMP%\aether-gh-pages`, replaces `index.html` with `docs/index.html`, adds an empty `.nojekyll` file, initializes a clean Git repository, and force-pushes to `gh-pages`.

{% hint style="danger" %}
`deploy-gh-pages.ps1` performs `git push origin gh-pages --force` from a fresh staging commit against the hardcoded repository remote (`https://github.com/maxxwwim/AetherSAST-150-CWE-MCP.git`). Inspect the remote URL before running it on a fork.
{% endhint %}

---

## GitHub Actions Workflows (`.github/workflows/`)

Both included GitHub Actions workflows currently configure `on: workflow_dispatch:` (manual trigger only), with automatic `push`, `pull_request`, and `schedule` triggers commented out to prevent unintended CI runs.

{% tabs %}
{% tab title="aetherscope-sarif.yml (SAST CI Gate)" %}
Runs on `ubuntu-24.04` with `contents: read` and `security-events: write` permissions:

1. Checks out the repository with `fetch-depth: 0`.
2. Restores or builds `~/.cargo/bin/aether-engine` via `cargo install --path crates/desktop-shell --bin aether-engine --locked` (note the cache key uses `${{ runner.os }}-aether-engine-v2.5.1`).
3. Executes the SAST gate:
   `aether-engine --path . --audit-only --format sarif --output results.sarif --fail-on HIGH`
4. Uploads `results.sarif` (`if: always()`) to GitHub Code Scanning via `github/codeql-action/upload-sarif@v3` (`category: aetherscope-sast`).
{% endtab %}

{% tab title="deploy-pages.yml (GitHub Pages Build)" %}
Runs a two-job deployment pipeline on `ubuntu-latest` with `contents: read`, `pages: write`, and `id-token: write`:

1. **`build` job**: Checks out the repository, sets up Node.js `22` with npm caching, runs `npm ci` and `npm run build` in `crates/desktop-shell/ui`, creates `crates/desktop-shell/dist/.nojekyll`, and uploads the artifact via `actions/upload-pages-artifact@v3`.
2. **`deploy` job**: Deploys the uploaded artifact to the `github-pages` environment using `actions/deploy-pages@v4`.
{% endtab %}
{% endtabs %}

---

## Related Pages

{% content-ref url="aether-engine-cli.md" %}
[aether-engine CLI](aether-engine-cli.md)
{% endcontent-ref %}

{% content-ref url="plugin-and-mcp-clis.md" %}
[Plugin, MCP & Runner CLIs](plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="../getting-started/installation.md" %}
[Installation](../getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/standalone-viewer.md" %}
[Standalone HTML Viewer & GitHub Pages](../cockpit-ide/standalone-viewer.md)
{% endcontent-ref %}
