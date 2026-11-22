# WebGL 2 Spatial Cockpit

AetherScope's spatial cockpit renders your codebase or knowledge vault at up to 120 FPS using an instanced WebGL 2 SDF pipeline, a 7-pass Canvas 2D overlay, and an off-thread Web Worker physics engine.

---

## Architecture Overview

The rendering engine (`AetherEngine` in `crates/desktop-shell/ui/src/engine/engine.ts`) separates high-volume geometry from dynamic annotations across two stacked canvases and a background worker:

- **WebGL 2 Canvas (`webgl2`)**: Initialized with `alpha: false`, `antialias: true`, `powerPreference: 'high-performance'`, and `preserveDrawingBuffer: false`. Renders the procedural cosmos backdrop (Pass 0) and instanced Signed Distance Field (SDF) bubbles (Pass 1).
- **2D Overlay Canvas (`lineCtx`)**: Transparent overlay (`alpha: true`) synced to the same logical dimensions. Renders layout scenery, 12-lobe membranes, routed edges, labels, Git badges, CWE beacons, and AI agent laser orbits (Pass 2).
- **Off-Thread Physics (`PhysicsController` + `physics.worker.js`)**: Computes Hooke spring attraction, Coulomb/Verlet repulsion, and 12-sector cluster envelopes outside the UI thread.

Device pixel ratio (`dpr`) is capped at `Math.min(window.devicePixelRatio || 1, 2)` and forced to `1` when `lowMemoryMode` is enabled.

---

## 12-Float Instanced SDF Pipeline

Each node in the graph is packed into a 12-float instance buffer (`INSTANCE_FLOATS = 12` in `shaders.ts`, stride **48 bytes**) and drawn in a single `gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, nodes.length)` call.

### 🎮 Instance Buffer Layout

| Location | Float Offset | Byte Offset | Attribute | Semantics |
|---|---|---|---|---|
| `0` | — | — | `a_quad_pos` (`vec2`) | Per-vertex unit quad `[-1,-1, 1,-1, -1,1, 1,1]` (`divisor = 0`) |
| `1` | `0..1` | `0` | `a_node_pos` (`vec2`) | World coordinates `(x, y)` |
| `2` | `2` | `8` | `a_radius` (`float`) | Base radius scaled by focus, alert, and LoD multipliers |
| `3` | `3..6` | `12` | `a_color` (`vec4`) | Active RGBA color (layer, folder, severity, or vision mode) |
| `4` | `7` | `28` | `a_is_file` (`float`) | `0.0` function/method, `1.0` file, `2.0` class/struct/trait, `3.0` endpoint/form |
| `5` | `8` | `32` | `a_birth_time` (`float`) | Timestamp (ms) driving the 300 ms spawn animation |
| `6` | `9` | `36` | `a_git_status` (`float`) | `0` clean, `1` modified, `2` new file, `3` violation, `4` doc/text, `5` new folder |
| `7` | `10` | `40` | `a_metric0` (`float`) | Normalized complexity/degree `[0..1]`: `max(cc / 24, (in + out) / 28)` |
| `8` | `11` | `44` | `a_metric1` (`float`) | Security/focus heat `[0..1]`: `1.0` alert, `0.85` focus, `0.5` line budget, `0.0` normal |

### Infinite Dezoom & Living Motion

Zoom bounds span five orders of magnitude, from `MIN_GALAXY_ZOOM = 0.0001` (`0.01%`) to `MAX_GALAXY_ZOOM = 12.0` (`1200%`). To ensure nodes never disappear when you zoom out across massive monorepos, the vertex shader (`vsSource` in `shaders.ts`) enforces a minimum screen-space radius:

- `zoom_factor = clamp(1.0 / sqrt(clamp(u_zoom, 0.0001, 12.0)), 0.85, 6.0)`
- `min_px = (a_is_file > 0.5) ? 2.6 : 1.8`
- `screen_r = max(min_px, actual_r * u_zoom)`

Every node also features a 300 ms cubic ease-out birth curve with a `0.12` breathing overshoot, a deterministic `v_phase` derived from `gl_InstanceID`, and a subtle `±1.5` world-unit organic drift (`buoy_x`, `buoy_y`).

### Default Layer & Severity Palettes (`palette.ts`)

| Category | Keys & Default Hex Colors |
|---|---|
| **Architectural Layers** | `ui` `#38bdf8`, `action` `#a855f7`, `domain` `#10b981`, `database` `#f59e0b`, `config` `#64748b`, `utility` `#ec4899`, `docs` `#6366f1`, `default` `#94a3b8` |
| **SAST Severities** | `CRITICAL` `#f44336`, `HIGH` `#ff6b00`, `MEDIUM` `#ffc107`, `LOW` `#4caf50` |
| **Contract Budget** | `CONTRACT_WARNING_COLOR` `#fbbf24` (applied when `RULE_MAX_LINES` triggers) |
| **Folder Hues (`BRANCH_HUES`)** | Deterministic HSL hues at LoD ≤ 2 (`desktop-shell: 196`, `core-graph: 255`, `security-linter: 38`, `ast-scanner: 158`, `ai-file-bridge: 178`, `arch-templates: 282`, `aethercraft: 335`, `obsidian-vault: 168`, etc.) |

---

## 7-Pass Canvas 2D Overlay

After the WebGL 2 draws complete, `AetherEngine.render` executes seven sequential passes on `lineCtx`:

1. **`renderLayoutScenery`**: Draws background guides per active layout—`Z-1` (3 horizontal tiers: UI, Domain, Services/Infra), `Z-2` (clean cosmos), `Z-3` (4 vertical DAG lanes: `INGESTION`, `TRANSFORM`, `SECURITY / TAINT`, `SINK / EXPORT`), and `Z-4` (48 px UML blueprint grid).
2. **`renderMembranes`**: Syncs 12-lobe radial envelopes (`syncLiveClusterEnvelopes`) and renders module boundaries in `organic_12lobe` (quadratic closed spline + `0.88 * baseR` inner cortex), `hex_hull`, `rect_blueprint`, or `none`, plus up to `42` folder badges (`24` in eco mode) tinted by Git or security status.
3. **`renderEdges`**: Draws up to `48` incident focus edges (with directional chevrons, pulse particles, and relation badges such as `➔ APPEL`, `← APPEL`, `IMPORT`, `EXTENDS`, `MEMBRE`, `DATA`, `NET`, `WS`, `FORM`, `SAST`, `MAX LIGNES`) alongside bucketed `Path2D` background edges (`900..2600` max) using `bezier`, `straight`, or `orthogonal_pcb` 45°/90° routing.
4. **`renderLabels`**: Renders screen-space node names at `zoom >= 0.30` (truncated to `maxLabelLength`, default `18`), suppressing labels inside dense clusters (`> clusterLabelThreshold`, default `20`).
5. **`renderGitDiffBadges`**: Draws status rings (up to `64`) and pills (up to `8`/`16`): `MODIF`, `DOC`, `+FICHIER`, `+DOSSIER`.
6. **`renderSecurityBeacons`**: Draws pulsing severity rings (up to `260`) and collision-avoided CWE pills (up to `14`/`24`/`42`, plus `+N` overflow chips or `loc/maxLim L` budget counters).
7. **`renderAiAgentOverlay`**: Renders connected AI agents (ping `< 5 min`) using a 16-color `DISTINCT_PALETTE`, dashed navigation trails, 3D inclined orbits (`TILT_ALPHA = 0.610865`, `INCLINATION_PSI = 0.436332`), dual-pass laser beams, and billboard icons (`✨` Claude, `⚡` Gemini, `🎯` Cursor, `🪐` Antigravity, `🤖` default).

---

## Off-Thread Physics & 12-Lobe Cluster Solver

`PhysicsController` (`physics.ts`) transfers graph state to `physics.worker.js` as a module Web Worker (or via an inline `Blob` URL when `window.__PHYSICS_WORKER_CODE__` is present in standalone HTML exports). To avoid structured-clone bottlenecks on large graphs, `sendGraph` caps transferred edges at `3000` via strided sampling.

### 🎮 Worker Message Protocol

| Direction | Message `type` | Payload / Purpose |
|---|---|---|
| Main → Worker | `INIT` | Sends `{ nodes, edges, depth }` with precomputed `layouts` (`obsidian`, `system`, `flow`, `classes`) |
| Main → Worker | `STEP` | Advances one simulation step at current `{ zoom }` |
| Main → Worker | `WAKE` | Resets sleep state for `{ steps }` iterations (default `100`) |
| Main → Worker | `SET_DEPTH` | Switches target depth (`1..4`) and wakes the solver |
| Main → Worker | `DRAG` / `DRAG_END` | Pins dragged node `{ id, x, y }` or releases drag |
| Worker → Main | `UPDATE` | Zero-copy `Float32Array` buffer transfer `[positions.buffer]`, throttled `clusters` metadata (every 12 frames), and `isSleeping` flag |
| Worker → Main | `IDLE` | Signals worker is sleeping or paused |

### Simulation Forces (`stepWorkerPhysics`)

1. **Layout Pull**: Pulls each node toward its precomputed coordinate in `n.layouts.{obsidian|system|flow|classes}` (`0.035`/`0.045` at `depth = 1`, `0.18` at `depth > 1`).
2. **Hooke Spring Attraction**: Applies spring forces (`restLen = 110` for `contains` edges, `185` otherwise, stiffness `0.012`, clamped `[-4.5, 4.5]`), capped at `2500` edges when `nodes.length > 1000`.
3. **12-Sector Cluster Envelopes**: `computeFolderClusters` tracks smoothed `folderAnchors` and computes 2-pass smoothed 12-lobe radial multipliers in `[0.82..1.48]`.
4. **Coulomb & Verlet Repulsion**: At `depth === 1`, applies intra-folder minimum separation (`125` class-class, `115` file-involved, `98` class-func, `84` func-func, `78` other) plus inter-cluster repulsion (`safeClusterDist = rA + rB + max(220, sqrt(cA + cB) * 34)`). At `depth > 1`, uses global neighborhood repulsion (`115`/`92`/`76`/`68`).
5. **Damping & Auto-Sleep**: Applies velocity friction (`0.76` at `d = 1`, `0.70` at `d > 1`) with a deadzone `< 0.08`, sleeping automatically once `physicsCooldown <= 0` or the system relaxes.

Press `P` or click the Play/Pause button on the canvas toolbar to freeze or resume `physics.step(...)` at any time.

---

## Vision Modes & LOD Layouts

Switch between four analytical overlays (`VisionModesDeck.svelte`, `VisionModeHuds.svelte`, and `engine.ts`) without re-scanning your project.

| Mode ID | UI Label | Hotkey | Visual & Shader Behavior | Floating HUD (`VisionModeHuds.svelte`) |
|---|---|---|---|---|
| `standard` | `Cosmos Standard` | `V` | Colors by folder (`lod <= 2`) or layer (`lod 3`); security alerts highlight in `CRITICAL`/`HIGH` colors and `RULE_MAX_LINES` in `#fbbf24` (`r × 1.12–1.18`); membranes visible | Clean canvas + `N1..N4` LOD bar |
| `xray` | `Tunnel X-Ray` | `X` | Isolates `activeSymbol` (`#ffffff`) and direct 1-hop neighbors (`activeNeighbors`); hides folder membranes; dims all other nodes (`alpha = 0.07`, `r × 0.55`) | **Tunnel X-Ray** HUD: active symbol, `ENTRANTS` / `SORTANTS` / `TOTAL` link counters, PNG **Snapshot** button |
| `heatmap` | `Heatmap Complexité` | `H` | Colors every node by `cyclomatic_complexity`: `>= 15` `CRITICAL`, `>= 8` `HIGH`, `>= 4` `MEDIUM`, `< 4` `LOW` | **Heatmap Complexité Cyclomatique** HUD: project average CC, hotspot count (`CC >= 10`), top-8 clickable hotspot list, **Audit Architecture IA (Hotspots)** button |
| `deadcode` | `Code Mort` | `D` | Highlights orphan symbols (`is_orphan` or `in_degree === 0 && out_degree === 0`) in `CRITICAL` red (`r × 1.35`); dims connected nodes (`alpha = 0.08`, `r × 0.55`) | **Audit Dead Code & Orphelins** HUD: dead symbol count, reclaimable LOC sum, top-12 clickable orphan list, **Générer Prompt Nettoyage IA** button |

The bottom-left **LOD / Layout Bar** (`N1..N4`, hotkeys `1`–`4`) switches spatial topologies:

- `1` (`N1` / `Z-1`, `lodLevel = 1`): Architecture & Modules
- `2` (`N2` / `Z-2`, `lodLevel = 2`): Files & Classes
- `3` (`N3` / `Z-3`, `lodLevel = 3`): Functions & Methods
- `4` (`N4` / `Z-4`, `lodLevel = 3`): Complete Micro-Flow

---

## RadarMinimap, Picking & Camera Controls

### RadarMinimap (`RadarMinimap.svelte`)

Toggle the bottom-right `RadarMinimap` (`130x108` canvas inside a `w-36 h-36` container) with the `R` key or footer toggle (persisted in `localStorage` under `aetherscope_show_radar`). It automatically shifts left when the Chat (`420px`) or Inspector (`412px`) drawer is open, and hides on narrow screens (`< 640px`) when a drawer is active.

Every third `requestAnimationFrame`, the minimap draws:
- Concentric cyan radar rings (`r = 32, 58`) and crosshairs.
- All nodes as `2x2` markers (`#38bdf8` for `activeSymbol`, slate otherwise).
- The active camera viewport box and live zoom readout (`zoom.toFixed(2)x`, or `(zoom * 100).toFixed(2)%` when `< 0.01`).
- Live AI agent navigation trails and pulsing position beacons (agents with ping `< 5 min`).

Click anywhere on the radar canvas to teleport `engine.camera.targetX` / `targetY` directly to that world coordinate.

### Picking, Touch & Camera Navigation

- **Camera Smoothing**: Interpolates `(x, y, zoom)` exponentially (`1 - Math.exp(-14.0 * dt / 1000)`).
- **Cursor-Centered Zoom**: Mouse wheel and `+`/`-` (`Shift` multiplies zoom step from `1.28x`/`0.78x` to `1.85x`/`0.45x`) preserve the world point under the cursor.
- **Fit & Reset**: Press `F` or `Ctrl+0` / `Cmd+0` to fit the entire graph; press `0` to reset zoom to `1.00x`.
- **Picking (`pickNode`)**: Uses `hitPx = Math.max(13, visualR + 8)` with selection priority bias (`0.65` active node, `0.8` file/class, `1.0` others). Clicking empty space inside a membrane calls `findFolderAt` and selects the cluster.
- **Drag & Pinch**: Moving `>= 6px` on a hit node triggers live `physics.drag(id, x, y)`; dragging background pans the camera; two-pointer touch triggers pinch zoom/pan; double-clicking focuses the symbol (`targetZoom >= 0.85`).
- **PNG Snapshot**: Triggers `captureSnapshot()` to composite both `canvas` and `lineCanvas` into `${project}_snapshot_${timestamp}.png`.

---

## FPS Watchdog & Shader Hot-Swap

Custom WebGL 2 visual plugins compile atomically via `swapNodeShader` and `swapBackdropShader` (`shaders.ts`): a new `WebGLProgram` is compiled and linked before the previous program is deleted. If compilation fails, the previous program stays active and `formatGlslError` subtracts `lineOffset` so reported GLSL line numbers match your snippet.

{% hint style="warning" %}
**Automatic GPU FPS Watchdog**: If a custom backdrop or node shader sustains frame times `dt > 40 ms` (`< 25 FPS`) for `2800 ms` on graphs with fewer than `25,000` nodes, `AetherEngine` automatically reverts both shaders to native defaults (`null`) and reports the fallback in `visualPluginError`. You can also cap frame rate via `settings.fpsLimit` (`'60'`, `'120'`, or `'unlimited'`).
{% endhint %}

---

## Procedural WebAudio Spatial Cues

`playSpatialTone(enabled, kind, panX)` (`crates/desktop-shell/ui/src/lib/sound.ts`) synthesizes zero-asset procedural audio feedback using the browser `AudioContext` and a `StereoPannerNode` clamped to `[-0.9, 0.9]` based on horizontal canvas click position (`(sx / logicalWidth) * 2 - 1`).

| Cue (`kind`) | Waveform | Frequency Sweep | Duration | Peak Gain | Active Triggers |
|---|---|---|---|---|---|
| `select` | `triangle` | `440 Hz` → `660 Hz` | `0.11 s` | `0.04` | Clicking a clean node in `AetherEngine`, `BountyModal`, `SurfaceScannerModal` |
| `alert` | `sawtooth` | `320 Hz` → `190 Hz` | `0.20 s` | `0.03` | Clicking a node with `has_security_violation` or `anomalies.length > 0` |
| `success` | `sine` | `523.25` → `659.25` → `783.99 Hz` (C5–E5–G5) | `0.24 s` | `0.035` | PNG snapshot download (`captureSnapshot`), `SurfaceScannerModal` scans |
| `action` | `sine` | `540 Hz` → `420 Hz` | `0.08 s` | `0.028` | Clicking a folder membrane, canvas toolbar buttons, unmuting sound |
| `hover` | `sine` | `620 Hz` → `760 Hz` | `0.05 s` | `0.014` | Defined in `sound.ts` (currently unreferenced by UI callers) |

Toggle audio at any time via `cockpitState.toggleSound()` in `HeaderDeck`, the canvas telemetry footer, or `SettingsModal` (persisted to `localStorage` and `/api/settings`).

---

## Related Pages

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[WebGL 2 Visual Plugins](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="./integrated-ide.md" %}
[Full-Screen Multi-Tab IDE](./integrated-ide.md)
{% endcontent-ref %}

{% content-ref url="../console/cockpit-shortcuts-and-palette.md" %}
[Cockpit Shortcuts & Command Palette](../console/cockpit-shortcuts-and-palette.md)
{% endcontent-ref %}

{% content-ref url="../core/graph-engine.md" %}
[Spatial Graph Engine](../core/graph-engine.md)
{% endcontent-ref %}
