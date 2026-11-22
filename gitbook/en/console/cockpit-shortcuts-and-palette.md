# Cockpit Shortcuts, Command Palette & UI Helpers

The AetherScope WebGL 2 Cockpit and Integrated IDE provide keyboard shortcuts, a `Ctrl+K` Omnibox, pointer/touch canvas controls, and AI agent helpers for fast navigation without leaving your keyboard.

{% hint style="info" %}
Global single-key, `Alt`, and `Ctrl+0` shortcuts in `App.svelte` are automatically suppressed while focus is inside `<input>`, `<textarea>`, `<select>`, or `contentEditable` elements. Single-key shortcuts also require no `Ctrl`, `Meta`, or `Alt` modifiers.
{% endhint %}

---

## Omnibox & Command Palette (`Ctrl+K` / `Cmd+K`)

Pressing `Ctrl+K` (or `Cmd+K` on macOS) opens AetherScope's search interfaces across nodes, call edges, and files:

- **Header Omnibox & `SearchDropdownPanel` (`z-[70]`)**: Focuses the top-bar search input and opens a 4-tab portal panel (`Tout`, `Fonctions & Symboles`, `Appels & Flux`, `Fichiers & Dossiers`) showing up to **60** relevance-scored matches. Supports `ArrowDown`, `ArrowUp`, `Enter` (selects symbol/folder, focuses camera, opens `InspectorDrawer`), and `Escape`.
- **Quick Symbol `CommandPalette` (`z-50`)**: Filters `graph.nodes` by `name` or `file_path` (15 nodes when empty, up to 20 filtered matches) and closes on backdrop click, close button, or `Escape`.

{% hint style="warning" %}
Both `HeaderDeck.svelte` and `CommandPalette.svelte` listen for `Ctrl+K` / `Cmd+K` (`e.key === 'k'`). Because `SearchDropdownPanel` renders in a `z-[70]` portal above `CommandPalette` (`z-50`), it takes visual precedence. In addition, `CommandPalette` only binds `Escape` and mouse click—use the Header Omnibox (`SearchDropdownPanel`) when you want `ArrowUp`/`ArrowDown`/`Enter` keyboard selection.
{% endhint %}

---

## Global Cockpit Shortcuts

### View & Dual-Vision Switching

| Shortcut | Condition | Action |
|---|---|---|
| `Alt+1` | Outside text inputs | Switches to Spatial Graph view (Code AST or Obsidian Vault depending on project type). |
| `Alt+2` / `Alt+3` | Outside text inputs | Switches to the Full-Screen Multi-Tab IDE (`IdeView`). |
| `Alt+V` | `isMixedProject == true` | Toggles between Code AST and Obsidian Vault Notes views in Dual-Vision projects. |

### Camera & Zoom

| Shortcut | Condition | Action |
|---|---|---|
| `Ctrl+0` / `Cmd+0` | Outside text inputs | Fits the camera to the active graph (`requestCameraFit`). |
| `F` | No modifiers, outside inputs | Fits the camera to the active graph. |
| `+` / `=` / `NumpadAdd` | No modifiers, outside inputs | Zooms in (`1.28×`). |
| `-` / `_` / `NumpadSubtract` | No modifiers, outside inputs | Zooms out (`0.78×`). |
| `0` / `Numpad0` | No modifiers, outside inputs | Resets zoom to `1.0` (`100%`). |

### Spatial LoD Continuum (`Z-1`..`Z-4`) & Vision Modes

| Shortcut | Category | Action |
|---|---|---|
| `1` | Spatial Layout | Activates `Z-1` (File Galaxy, `lodLevel = 1`). |
| `2` | Spatial Layout | Activates `Z-2` (Module Architecture, `lodLevel = 2`). |
| `3` | Spatial Layout | Activates `Z-3` (Execution DAG, `lodLevel = 3`). |
| `4` | Spatial Layout | Activates `Z-4` (UML & Class Matrix; keeps current `lodLevel`, whereas the `View` menu sets `lodLevel = 3`). |
| `V` | Vision Mode | Switches to `standard` vision mode. |
| `X` | Vision Mode | Toggles `xray` vision mode on/off. |
| `H` | Vision Mode | Toggles `heatmap` (CWE/complexity heat) vision mode on/off. |
| `D` | Vision Mode | Toggles `deadcode` vision mode on/off. |

### Engine, Drawers & Modals

| Shortcut | Scope | Action |
|---|---|---|
| `P` | Physics | Pauses or resumes the Web Worker force-directed physics simulation. |
| `R` | Minimap | Toggles the bottom-right `RadarMinimap` (suppressed in `<input>`/`<textarea>`). |
| `I` | Drawer | Toggles the right-hand `InspectorDrawer`. |
| `M` | Panel | Toggles the Documentation, EARS & BLAKE3 contract panel. |
| `N` | Modal | Toggles `CreateFileModal` (New AI-assisted file). |
| `S` | Modal | Toggles `SettingsModal`. |
| `B` | Modal | Toggles `BountyModal` (4-step Bug Bounty workflow). |
| `G` | Modal | Toggles `PluginsModal` (SAST & Visual GLSL plugins). |
| `U` | Modal | Toggles `SurfaceScannerModal` (Network Attack Surface Scanner). |
| `C` | Drawer | Bound in `App.svelte` and `AiChatDrawer.svelte` (see warning below). |

{% hint style="warning" %}
Both `App.svelte` and the always-mounted `AiChatDrawer.svelte` attach `window` keydown listeners for `C`, which toggles `isChatOpen` twice in the same keypress. Use the **Chat IA** button in the top-right quick-access bar or the floating chat pill to open or close the AI Chat Drawer reliably.
{% endhint %}

---

## Header Menus & Quick-Access Deck

`HeaderDeck.svelte` provides seven desktop-style menus (`Fichier`, `Vue`, `Affichage`, `Sécurité`, `Plugins`, `IA`, `Outils`) plus a quick-access bar:

- **Menu navigation**: Clicking a menu opens it; hovering over adjacent menus switches immediately while open, `Escape` or clicking outside dismisses it, and items marked `keepOpen` (such as LoD levels, Vision modes, `P`, `R`, Eco mode, and WebAudio) stay open for chained toggles.
- **Inline path/URL analyzer**: Entering a directory path in the `Fichier` menu bar runs an AST/SAST scan, while entering an `http://`, `https://`, `localhost`, or IP target opens `SurfaceScannerModal` automatically.
- **Quick-access bar**: Switches Graph / Vault / IDE views, displays live node/edge counters, and gives 1-click buttons for Fit (`F`), Physics (`P`), CWE Violations, Plugins (`G`), Chat IA (`C`), Inspector (`I`), WebAudio Mute/Unmute, and Settings (`S`).

---

## WebGL Canvas & Radar Mouse/Touch Controls

| Input | Component | Behavior |
|---|---|---|
| `Wheel` / `Shift+Wheel` | `AetherCanvas` | Cursor-centered zoom across `0.0001` (`0.01%`) to `12.0` (`1200%`). Holding `Shift` nearly doubles zoom speed (`0.0042` vs `0.0022`). |
| Toolbar `+` / `-` (`Shift+Click`) | `AetherCanvas` | Normal click zooms `1.28×` / `0.78×`; `Shift+Click` fast-zooms `1.85×` / `0.45×`. |
| Drag on node vs empty space | `AetherCanvas` | Dragging a bubble moves it in the physics engine; dragging empty space pans the camera. |
| Click / Double-click | `AetherCanvas` | Click selects a symbol or folder with spatial WebAudio feedback; double-click focuses the symbol or folder centroid and opens the Doc panel. |
| Two-finger touch | `AetherCanvas` | Multi-touch pinch-to-zoom and two-finger pan. |
| Click on Radar | `RadarMinimap` | Instantly teleports `engine.camera` to the clicked world coordinate on the 130×108 minimap. |

---

## Integrated IDE & Panel Navigation

### `IdeEditor.svelte` Shortcuts

| Shortcut | Context | Action |
|---|---|---|
| `Ctrl+S` / `Cmd+S` | Code textarea | Saves the active file atomically via `POST /api/save_file`. |
| `Ctrl+F` / `Cmd+F` | Code textarea | Opens and focuses the in-file search bar. |
| `Tab` | Code textarea | Inserts 4 spaces (`'    '`) at the current selection/caret. |
| `Enter` / `Shift+Enter` / `Escape` | In-file search bar | Jumps to next match, previous match, or closes search and restores editor focus. |
| `Enter` | Open tab strip | Switches to the focused editor tab. |

### Tree, Dataflow & Hierarchy Navigation

Pressing `Enter` or `Space` activates interactive items across `IdeFileTree` (opens file), `IdeSymbolHierarchy` (jumps to symbol/method), `StepCodeDataPanel` (jumps to upstream/downstream SSA node), `InspectorDrawer` (jumps to source/target symbol), and `SynthesisHud` (toggles Modules/Layers/Links accordions).

---

## Modals & AI Chat Drawer CLI Helpers

- **Modal dismissal**: `Escape` closes `BountyModal`, `CreateFileModal`, `IgnoredCweModal`, `PluginsModal`, `ProjectHubModal`, `PromptGeneratorModal`, `SettingsModal`, `SurfaceScannerModal`, and `TasksModal` (note: `McpControlModal` closes via its `×` button).
- **Submit keys**: `Enter` (without `Shift`) sends messages in `AiChatDrawer`; `Enter` also launches scans in `SurfaceScannerModal` and selects items in `TasksModal`.
- **Agents & MCP CLI helper buttons (`Gemini CLI`, `Claude Code`, `Config MCP`)**: Inside `AiChatDrawer` (`Agents & MCP` tab), `Config MCP` opens `McpControlModal`, while `Gemini CLI` and `Claude Code` invoke `launchAgentCli(tool)`:

{% code title="Payloads sent by Gemini CLI and Claude Code buttons" overflow="wrap" %}
```json
// 1. POST /api/ai/launch_cli
{
  "tool": "gemini",
  "project_path": "<active_project_path>",
  "prompt": "Analyse <active_symbol_or_folder> dans AetherScope (<project_path>) via MCP aetherscope_get_active_target."
}

// 2. POST /api/ai/telemetry (updates 3D camera & agent swarm badge)
{
  "target": "<active_symbol_or_folder>",
  "agent_name": "Agent GEMINI",
  "status": "Session CLI lancée sur <active_symbol_or_folder>"
}
```
{% endcode %}

{% hint style="info" %}
`POST /api/ai/launch_cli` operates under AetherScope's zero-shell model: it records telemetry and returns `{ "status": "ok", "message": "Terminal CLI <tool> initialisé", ... }` without spawning an external OS terminal process.
{% endhint %}

---

## Related Pages

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/integrated-ide.md" %}
[Full-Screen Multi-Tab IDE](../cockpit-ide/integrated-ide.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/obsidian-dual-vision.md" %}
[Obsidian Vault & Dual-Vision Engine](../cockpit-ide/obsidian-dual-vision.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[REST API: IDE, Contracts, AI, Chat & Tasks](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}
