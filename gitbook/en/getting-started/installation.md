# Installation

Install `aether-engine` (`2.6.0`) from prebuilt Windows release archives, build from source with Cargo and npm, and wire up MCP clients.

## System Prerequisites

| Requirement | Needed For | Details |
|---|---|---|
| **Rust 1.80+ (2021 edition)** | Building from source (`cargo build` / `cargo install`) | Defined in root `Cargo.toml` (`edition = "2021"`). |
| **C++ Build Tools** | Native Rust compilation | MSVC Build Tools on Windows; `build-essential` on Linux. |
| **Node.js & npm** | Rebuilding the Svelte 5 / Vite 8 UI | Required only if modifying `crates/desktop-shell/ui/`. `crates/desktop-shell/dist/index.html` is already pre-built and embedded. |
| **WebView2 Runtime** | Desktop GUI mode on Windows | Preinstalled on Windows 10/11 (`tao 0.28` + `wry 0.42`). |
| **Python 3 + Java 21+** | AetherCraft extension only | Python packages `flask>=3.0.0`, `requests>=2.31.0` for `control-plane`; Java 21+ on `PATH` for `aether-mc-runner`. |

{% tabs %}
{% tab title="Prebuilt Release (Windows x64)" %}

## Option 1: Prebuilt Windows Release (`v2.6.0`)

Extract `releases/aetherscope-v2.6.0-windows-x64.zip` into a working folder.

<details>
<summary>Verified contents of <code>releases/aetherscope-v2.6.0-windows-x64.zip</code></summary>

* Binaries: `aether-engine.exe`, `aetherscope-mcp.exe`, `aether-plugin-tool.exe`
* Scripts & manifests: `install.ps1`, `setup-mcp.ps1`, `Start-Cockpit.bat`, `AetherScope-Launcher.bat`, `mcp.json`
* Standalone viewer: `index.html`
* Documentation: `README.md`, `README.fr.md`, `CHANGELOG.md`, `CWE_CATALOG.md`, `AETHER_AI_RULES.md`, `BENCHMARK.md`

</details>

{% hint style="info" %}
`aether-mc-runner.exe` is **not** bundled inside `aetherscope-v2.6.0-windows-x64.zip`. Build it separately with `--manifest-path apps/aethercraft/runner/Cargo.toml` if you use AetherCraft.
{% endhint %}

### Run `install.ps1`

From the extracted folder (or repository root after `cargo build --release`), run `install.ps1` to install binaries to `%LOCALAPPDATA%\AetherScope\bin`, update your User `PATH`, create a Desktop shortcut (`AetherScope V2.lnk`), and configure MCP clients:

```powershell
# Default installation (%LOCALAPPDATA%\AetherScope, PATH, shortcut, and MCP setup)
.\install.ps1

# Custom directory, skipping MCP setup and Desktop shortcut
.\install.ps1 -InstallDir "C:\Tools\AetherScope" -SkipMcp -SkipShortcut
```

| Parameter | Default | Behavior |
|---|---|---|
| `-InstallDir` | `"$env:LOCALAPPDATA\AetherScope"` | Target folder (`bin\` holds executables; root holds `.bat` launchers and `setup-mcp.ps1`). |
| `-SkipMcp` | `$false` | Skips automatic execution of `setup-mcp.ps1`. |
| `-SkipShortcut` | `$false` | Skips creating `AetherScope V2.lnk` on your Desktop. |

`install.ps1` searches `target\release\` first and falls back to the script directory. It stops any running `aether-engine` process, copies `aether-engine.exe`, `aetherscope-mcp.exe`, `aether-mc-runner.exe`, and `aether-plugin-tool.exe` (when present), and adds `<InstallDir>\bin` to your User `PATH`.

{% endtab %}
{% tab title="Build from Source (Cargo & npm)" %}

## Option 2: Build from Source (Windows / Linux / macOS)

### 1. Rebuild Frontend UI (Optional)

Only needed if you modified files under `crates/desktop-shell/ui/`:

```bash
cd crates/desktop-shell/ui
npm ci
npm run build
cd ../../..
```

`npm run build` outputs the single-file bundle to `crates/desktop-shell/dist/index.html`, which `viewer.rs` embeds into the Rust binary via `include_str!`.

### 2. Compile Rust Workspace Binaries

```bash
# Build aether-engine, aetherscope-mcp, and aether-plugin-tool in release mode
cargo build --release

# Or build only the plugin CLI tool
cargo build --release -p security-linter --bin aether-plugin-tool
```

### 3. Install Directly into Cargo `PATH`

```bash
cargo install --path crates/desktop-shell --bin aether-engine --locked
cargo install --path crates/desktop-shell --bin aetherscope-mcp --locked
cargo install --path crates/security-linter --bin aether-plugin-tool --locked
```

### 4. Build AetherCraft MC Runner (Optional)

Because `apps/aethercraft/runner` is excluded from the root Cargo workspace, pass `--manifest-path` explicitly:

```bash
cargo build --release --manifest-path apps/aethercraft/runner/Cargo.toml
```

{% endtab %}
{% endtabs %}

## Configure AI Clients with `setup-mcp.ps1`

`setup-mcp.ps1` locates `aetherscope-mcp.exe` (checking the script directory, `target\release\`, and `%LOCALAPPDATA%\AetherScope\bin\`) and registers `mcpServers.aetherscope` across supported AI clients:

```powershell
# Register MCP on default port 3030
.\setup-mcp.ps1

# Register MCP on a custom loopback port
.\setup-mcp.ps1 -Port 3040
```

The script updates these three configuration files if present (or creates them as needed):

* **Claude Desktop:** `%APPDATA%\Claude\claude_desktop_config.json`
* **Antigravity / Gemini:** `%USERPROFILE%\.gemini\config\mcp_config.json`
* **Cursor:** `%USERPROFILE%\.cursor\mcp.json`

{% code title="Generated mcpServers entry" overflow="wrap" %}
```json
{
  "mcpServers": {
    "aetherscope": {
      "command": "C:\\Users\\<you>\\AppData\\Local\\AetherScope\\bin\\aetherscope-mcp.exe",
      "args": ["--port", "3030"]
    }
  }
}
```
{% endcode %}

{% hint style="warning" %}
**Note on legacy script banners:** Although `Cargo.toml`, `ui/package.json`, `mcp.json`, and the `v2.6.0` release archive all use canonical version **`2.6.0`**, helper scripts (`install.ps1`, `setup-mcp.ps1`, `Start-Cockpit.bat`, `AetherScope-Launcher.bat`) and `mcp_main.rs` still print `V2.4` in console banners, and `.github/workflows/aetherscope-sarif.yml` references cache key `aether-engine-v2.5.1`. This is cosmetic only and does not affect `2.6.0` runtime behavior.
{% endhint %}

## Next Steps

{% content-ref url="quickstart.md" %}
[Quickstart](quickstart.md)
{% endcontent-ref %}

{% content-ref url="configuration.md" %}
[Configuration](configuration.md)
{% endcontent-ref %}
