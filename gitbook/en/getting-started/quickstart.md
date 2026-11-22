# Quickstart

Launch `aether-engine` in Desktop GUI, Headless Browser, CLI SAST/SARIF/SCA, or MCP mode and navigate the WebGL 2 Cockpit.

{% tabs %}
{% tab title="Desktop GUI" %}

### 1. Launch the Desktop Cockpit

From any repository root, start the native `tao`/`wry` cockpit window:

```powershell
aether-engine -p .
```

On Windows, you can also use the included batch launchers:

* **`Start-Cockpit.bat`**: Resolves the newest `aether-engine.exe` (`target\release\` -> current folder -> `%LOCALAPPDATA%\AetherScope\bin\`), stops stale port `3030` listeners, syncs binaries, and opens the GUI.
* **`AetherScope-Launcher.bat`**: Interactive 9-option menu covering GUI launch (`[1]`), MCP stdio test (`[2]`), headless `--no-gui` (`[3]`), `setup-mcp.ps1` (`[4]`), SAST scan `--audit-only` (`[5]`), AetherCraft Flask port `5000` (`[6]`), free port `3030` (`[7]`), `install.ps1` (`[8]`), and quit (`[9]`).

{% endtab %}
{% tab title="Headless + Browser" %}

### 1. Start the Headless HTTP Server

Run the Axum server (`127.0.0.1:3030`) and `FileWatcherBridge` without opening a native window:

```bash
aether-engine --no-gui --port 3030 --path .
```

Open `http://127.0.0.1:3030` in your browser. `LocalGuard` restricts access to loopback hosts (`127.0.0.1`, `localhost`, `[::1]`).

{% endtab %}
{% tab title="CLI Audit, SARIF & SCA" %}

### 1. Run Single-Shot Security & Benchmark Commands

```bash
# Write .aether/LIVE_AUDIT.md (and refresh live Cockpit on port 3030 if listening)
aether-engine --path . --audit-only

# Export SARIF v2.1.0 and fail CI on HIGH or CRITICAL findings
aether-engine --path . --audit-only --format sarif -o results.sarif --fail-on HIGH

# Run combined SAST + Reachable OSV.dev SCA (or offline cache-only SCA)
aether-engine --path . --audit-only --sca
aether-engine --path . --audit-only --offline-sca
aether-engine --path . --sca-only --offline-sca --fail-on CRITICAL

# Select plugin packs/profiles or unpack the 24-rule Semgrep bundle
aether-engine --path . --audit-only --plugins auto
aether-engine --path . --update-rules

# Benchmark scanner throughput and Peak RSS -> writes BENCHMARK.md
aether-engine --path . --benchmark
```

{% hint style="warning" %}
**Windows stdout redirection caveat:** `aether-engine.exe` is compiled with `#![windows_subsystem = "windows"]` and attaches to the parent console via `AttachConsole(0xFFFF_FFFF)`. In non-interactive or redirected subshells, captured stdout (such as `--help`) can appear empty even when the command succeeds. Pass `-o results.sarif` or inspect `.aether/LIVE_AUDIT.md` / `BENCHMARK.md` for deterministic output.
{% endhint %}

{% endtab %}
{% tab title="MCP (AI Agents)" %}

### 1. Connect via MCP & Run the 3-Call Surgical Workflow

Configure your AI client with `setup-mcp.ps1` (or launch `aetherscope-mcp --port 3030 --path .` / `aether-engine --mcp`). If port `3030` is not running yet, `aetherscope-mcp` automatically spawns `aether-engine --no-gui`.

Follow the 3-call surgical workflow defined in `AETHER_AI_RULES.md`:

1. **Inspect global state (`aetherscope_get_graph_summary`)**:
   ```json
   { "rescan": true, "include_tasks": true, "severity": "all" }
   ```
2. **Lock a target symbol (`aetherscope_get_active_target`)** to generate `.aether/ACTIVE_TARGET.md` and receive `<aether_handshake version="2.1">`:
   ```json
   { "symbol_id": "<target_symbol_id>", "trace_direction": "both", "action": "Inspection" }
   ```
3. **Verify every edit (`aetherscope_verify_patch`)** through the `<50ms` `PatchVerifier` firewall:
   ```json
   {
     "files_modified": ["crates/core-graph/src/layout.rs"],
     "task_id": "fix-layout-edge",
     "status": "done",
     "progress": 100
   }
   ```

{% endtab %}
{% endtabs %}

## Essential Cockpit Navigation Shortcuts

Once the WebGL 2 Cockpit is open, use these verified keyboard shortcuts (`App.svelte`, `HeaderDeck.svelte`, `VisionModesDeck.svelte`):

| Shortcut | Action |
|---|---|
| `Alt+1` | Switch to **Graph** view (Code AST or Obsidian Vault) |
| `Alt+2` / `Alt+3` | Switch to **Full-Screen Multi-Tab IDE** |
| `Alt+V` | Toggle between **Code AST** and **Obsidian Vault** on `Mixed` projects |
| `1` / `2` / `3` / `4` | Select spatial layout: `Z-1` File Galaxy, `Z-2` 7-Layer Modules, `Z-3` Execution DAG, `Z-4` UML Matrix |
| `V` / `X` / `H` / `D` | Select Vision Mode: **Standard** (`V`), **X-Ray Focus** (`X`), **Complexity Heatmap** (`H`), **Dead Code** (`D`) |
| `Ctrl+K` / `Cmd+K` | Open **Command Palette** and focus the HeaderDeck Omnibox search |
| `F` / `0` / `+` / `-` | Fit camera (`F`), reset zoom (`0` / `Ctrl+0`), zoom in (`+`/`=`), zoom out (`-`/`_`) |
| `P` / `R` | Pause/resume physics simulation (`P`), toggle Radar Minimap (`R`) |
| `G` / `I` / `C` / `N` | Open **Plugins & WebGL Studio** (`G`), **Inspector Drawer** (`I`), **AI Chat** (`C`), **Create File** (`N`) |
| `S` / `B` / `U` / `M` | Open **Settings** (`S`), **Bug Bounty** (`B`), **Surface Scanner** (`U`), **Doc Reader** (`M`) |

## Next Steps

{% content-ref url="configuration.md" %}
[Configuration](configuration.md)
{% endcontent-ref %}

{% content-ref url="best-practices.md" %}
[Golden Best Practices](best-practices.md)
{% endcontent-ref %}

{% content-ref url="../console/aether-engine-cli.md" %}
[aether-engine CLI Reference](../console/aether-engine-cli.md)
{% endcontent-ref %}
