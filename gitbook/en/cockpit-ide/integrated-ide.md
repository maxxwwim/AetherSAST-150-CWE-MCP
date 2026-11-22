# Full-Screen Multi-Tab IDE

AetherScope includes a built-in, multi-tab code editor (`IdeView.svelte`) coupled directly to the AST symbol graph, CWE remediation inspector, and BLAKE3 contract governance engine.

---

## Resident DOM & Instant View Switching

In `crates/desktop-shell/ui/src/App.svelte`, the WebGL 2 canvas (`AetherCanvas`) and `<IdeView />` remain mounted simultaneously in the DOM and toggle visibility via CSS (`class:hidden={cockpitState.viewMode !== 'ide'}`). Switching between the spatial graph and the IDE never unmounts the editor, so open tabs, cursor positions, and unsaved buffers stay intact.

### 🎮 View & Drawer Shortcuts

| Shortcut | Action | Notes |
|---|---|---|
| `Alt+1` | Switch to adaptive Graph view (`code` or `vault-notes`) | Restores `lastGraphMode` |
| `Alt+2` / `Alt+3` | Switch to Full-Screen IDE | Fires `POST /api/view_mode` (`{ mode: "ide" }`) |
| `Alt+V` | Toggle `code` ↔ `vault-notes` | Active only on `Mixed` projects |
| `N` | Toggle `CreateFileModal` | Create or import a file into the graph |
| `M` | Toggle `DocReaderDrawer` (`Docs & EARS`) | Docks on the right inside IDE mode |
| `I` | Toggle `InspectorDrawer` | Opens the 5-tab symbol & CWE inspector |

Global single-key shortcuts are suppressed whenever focus is inside an `<input>`, `<textarea>`, `<select>`, or `contentEditable` element. Clicking any symbol in the WebGL graph (`selectSymbol`) pre-loads its `file_path` and `line_number` in `CockpitState` (`ideActiveFile`, `ideTargetLine`, `ideTargetTick`) so pressing `Alt+2` jumps straight to that declaration.

You can also switch views from the **Zone D** pill bar (`Graph` | `AST`/`Vault` | `IDE`) or the `Vue` menu in `HeaderDeck.svelte`.

---

## 3-Pane Resizable Workspace & Zen Mode

`IdeView.svelte` arranges the workspace into three configurable panes:

1. **Left Sidebar (`<aside>`)**: Default width `320px` (draggable from `180px` to `45%` of viewport width; double-clicking the divider resets to `320px`), collapsible into a `42px` icon rail. Supports four modes:
   - `Fichiers` (`IdeFileTree`)
   - `Symboles` (`IdeSymbolHierarchy`)
   - `Docs & EARS` (`IdeDocSidebar`)
   - `Double` (`split`, default): vertical split of `IdeFileTree` + `IdeSymbolHierarchy` with a draggable horizontal divider (`splitRatio = 50%`, clamped `15%`–`85%`, double-click resets).
2. **Center Editor (`<main>`)**: `<IdeEditor />` taking all remaining horizontal space.
3. **Right Docked Docs & EARS Pane**: Shown when `cockpitState.isDocPanelOpen && !cockpitState.ideZenMode`. Renders `<DocReaderDrawer embedded={true} />` at a default width of `520px` (clamped `320px` to `60vw`; `wideMode` snaps to `760px`; double-click resets to `520px`).

Toggling **Zen Mode** (`ideZenMode` via the `Plein Écran` / `Restaurer` button in the editor toolbar) collapses both the left sidebar and the right `DocReaderDrawer` pane, leaving only `<IdeEditor />` on screen.

---

## Multi-Tab Editor, Shortcuts & Syntax Highlighting

`IdeEditor.svelte` maintains an in-memory `buffers: Record<string, FileBuffer>` map storing `{ content, savedContent, cursorLine, cursorCol }` per open file path.

- **Unmasked Source Loading**: Opening a file fetches `GET /api/file_content?path=<rel>&raw=true` so `SecretMasker` does not rewrite editable source code in memory (secret files such as `.env` or private keys remain blocked by `SecretGuard`).
- **Dirty State Tracking**: Inactive and active tabs track `content !== savedContent`, displaying an amber dot on modified tabs, a pulsing amber `Enregistrer` button, and `● Modifications non enregistrées` in the bottom status bar.
- **Tab Management**: Cycle tab widths between `'auto'` (`max-w-[210px]`), `'compact'` (`130px`), and `'expanded'` (`320px`), close individual tabs, or click `Tout fermer` when multiple tabs are open.
- **Jump-to-Line Flash Highlight**: When `ideTargetTick` / `ideTargetLine` updates, the editor clamps the line to `[1, lineCount]`, scrolls smoothly (`(safeLine - 5) * 21` px in Edit mode or `scrollIntoView({ behavior: 'smooth', block: 'center' })` in Preview mode), and pulses a `2500 ms` sky-blue highlight on the target line.
- **Edit vs. Syntax-Highlighted Preview**: Toggle between `Éditer` (interactive `<textarea>` with synchronized line-number gutter) and `Coloré` (tokenized syntax preview supporting `rust`, `typescript`, `javascript`, `python`, `json`, `toml`, `markdown`, `svelte`, and `text`).

### 🎮 Editor Keyboard Shortcuts

| Shortcut | Behavior |
|---|---|
| `Ctrl+S` / `Cmd+S` | Saves the active buffer atomically via `POST /api/save_file` and shows a 3 s `Enregistré sur disque` confirmation |
| `Ctrl+F` / `Cmd+F` | Opens the case-insensitive in-file search overlay (`Enter` next match, `Shift+Enter` previous match, `Escape` close) |
| `Tab` | Inserts 4 spaces (`'    '`) at the current selection and updates cursor position |

---

## File Tree, Symbol Hierarchy & Docs Sidebar

### `IdeFileTree.svelte`

- **Live + Offline Source**: Calls `GET /api/files` when connected to the local backend, and falls back to `fallbackFromGraph()` (reconstructing files and folders from `cockpitState.graph.nodes`) in standalone/offline mode.
- **Deterministic Branch Colors (`palette.ts`)**: `getFolderColor` assigns coherent HSL hues using `BRANCH_HUES` (`desktop-shell: 196°`, `core-graph: 255°`, `security-linter: 38°`, `ast-scanner: 158°`, `ai-file-bridge: 178°`, `arch-templates: 282°`, `aethercraft: 335°`, `obsidian-vault: 168°`, etc.) and applies subtle hue/lightness shifts per nested subfolder.
- **Anomaly Aggregation & Filtering**: Files with CWE/CVE findings display `#ef4444` alert dots and aggregate `ShieldAlert` violation counts up every parent directory node. Typing in `searchFilter` matches paths case-insensitively and auto-expands matching parent directories.

### `IdeSymbolHierarchy.svelte` & `IdeDocSidebar.svelte`

- **`IdeSymbolHierarchy.svelte`**: Lists all AST symbols inside the active file sorted by `line_number`, with kind badges (`Function`, `Struct`, `Endpoint`, `Contract`, `Method`, `Symbol`), CWE badges, and nested `methods`. Clicking any symbol jumps the editor to its line, notifies `POST /api/ai/target` (`action_type: 'IDE Navigation'`), and focuses the WebGL camera on the symbol.
- **`IdeDocSidebar.svelte`**: Displays an **Active Target EARS Contract** card (`BLAKE3 Scellé / Modifié`, `{loc} / {max_lines_limit || 300} L`, `Inspecter`) alongside all project Markdown docs (READMEs sorted first with BLAKE3 lock icons) and a `Blueprint` architecture view button.

---

## AI File Creation & Local Import

Press `N` (or use `Fichier -> Nouveau fichier IA` / `Importer un fichier…`) to open `CreateFileModal.svelte`:

- **Local File Import**: Reads a local file via `<input type="file">` (`file.text()`) and preserves its relative path (or prefixes `imported/`).
- **4 Quick Architectural Templates**: `+ UI` (`src/ui/panel_widget.ts`), `+ Domain` (`src/domain/model_entity.rs`), `+ Service` (`src/services/service_handler.rs`), and `+ Doc` (`docs/SPECIFICATION.md`).
- **Live Graph Sync**: Submitting calls `POST /api/ai/create_file`, updates `cockpitState.setGraph(res.graph)`, increments `filterVersion`, fits the camera, and selects the newly created symbol.

---

## InspectorDrawer & DocReaderDrawer: CWE Remediation & Contract Sealing

### `InspectorDrawer.svelte` (`I` Shortcut)

Default width `396px` (resizable `280px`–`70vw`), providing a quick action strip (`Ouvrir dans l'IDE`, `Doc / Source`, `Prompt IA`) and **5 tabs**:

| Tab | Capabilities |
|---|---|
| `Débrief` | EARS & BLAKE3 contract badge (`file_blake3_hash`), extracted AST docstrings, security alerts vs. line-budget warnings, and 1-click budget sealing |
| `UML` | Copyable Mermaid `classDiagram` and interactive SVG Mini-DAG |
| `Flux` | Incoming and outgoing AST/taint edges with relation filters |
| `CVE` | Scope (`Cible`/`Projet`), text, and language filters (`ALL`, `Rust`, `Solidity`, `TS/JS`, `Python`, `C#`, `Zig`), displaying `transmitted_data`, **`🛡️ remediation`**, `Préparer PoC` (`BountyModal`), and `Ignorer` (`POST /api/settings`) |
| `Tâches` | Project tasks bound to the active target |

**1-Click Budget Sealing**: In `Débrief`, choose a preset (`200`, `300`, `500`, `800`, `1500`) or custom limit (`10..50000`) and click `📄 Sceller Fichier` (`file_max_lines`), `📁 Sceller Dossier` (`max_lines_per_file`), or `↺ Hériter` (`clear_file_override: true`) via `POST /api/contracts/update`.

### `DocReaderDrawer.svelte` (`M` Shortcut)

Docked on the right in IDE mode (or floating left in Graph mode), `DocReaderDrawer` provides:

- **1-Click Global Contract Signing**: Clicking `Signer` calls `POST /api/contracts/sign` to walk all `README.md` contracts and seal their BLAKE3 digests in `aether.lock.toml`.
- **Budget Sealing**: Same 1-click file/folder/inherit controls (`200`, `300`, `500`, `800`, `1500`, `3000` presets) via `POST /api/contracts/update`.
- **Live Markdown Editing & 1.5 s Auto-Save**: Edits trigger a `1500 ms` debounced `POST /api/save_doc`. Saving any `README.md` automatically re-signs BLAKE3 in `aether.lock.toml` and triggers a live `ProjectScanner` rescan.

---

## Backend IDE & Contract Endpoints

Every endpoint below runs on `127.0.0.1:3030` behind `LocalGuard` (`Host`/`Origin`/`Sec-Fetch-Site` validation), `PathGuard` (CWE-22 canonical jail), `SecretGuard` (blocks `.env*`, `.ssh`, `.git`, private keys), and `SecretMasker::contains_secret`.

| Endpoint | Behavior & Safety Guarantees |
|---|---|
| `GET /api/files` | Walks `project_root` via `WalkDir`, pruning `.git`, `node_modules`, `target`, `dist`, `.aether`, `.gemini`, and secret paths |
| `GET /api/file_content?path=<rel>&raw=<bool>` | Reads up to `10 MB` (`DEFAULT_MAX_FILE_SIZE`) with 20 Windows lock retries; masks secrets unless `raw=true` |
| `POST /api/save_file` | Serialized by `file_save_lock`; writes a sibling temp file `.{filename}.tmp.{pid}_{seq}_{nanos}` and performs atomic `fs::rename` with 20 backoff retries |
| `POST /api/save_doc` | Writes Markdown safely; if the file is `README.md`, automatically re-signs BLAKE3 and refreshes the graph |
| `POST /api/ai/create_file` | Blocks secret paths and embedded secrets (`SecretMasker::contains_secret`), writes the file, and returns the updated `AetherGraph` |
| `POST /api/contracts/sign` | Re-computes and signs `README.md` BLAKE3 digests in `aether.lock.toml` and re-scans the workspace |
| `POST /api/contracts/update` | Updates `max_lines_per_file`, `file_max_lines`, `allowed_imports`, or `forbidden_imports` in the nearest `README.md`, re-signs BLAKE3, and re-scans |

Invalid traversals (`..`, drive letters, UNC paths, depth `> 32`) return `400 Bad Request`; secret or jail escapes return `403 Forbidden`; files above `10 MB` return `413 Payload Too Large`.

---

## Related Pages

{% content-ref url="./webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](./webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../core/blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[REST API: IDE, Contracts & AI](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}
