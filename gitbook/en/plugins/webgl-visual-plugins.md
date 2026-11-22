# WebGL 2 Visual Plugins

Customize the AetherScope Cockpit's palettes, membranes, edges, and GLSL ES 3.00 backdrop and SDF node shaders via confined packs under `.aether/plugins/visuals/`.

{% hint style="warning" %}
**Implemented (M1 + M2) vs. Roadmap-Only (M3)**:
- **Implemented**: Declarative palettes, overlay styles, 5 built-in packs, 12-float SDF instance VBO, `backdrop.glsl` (`aetherBackdrop`) & `node_sdf.glsl` (`aetherNodeSurface`) GLSL ES 3.00 hooks, dual Rust + TS anti-DoS validator, atomic shader swap, FPS watchdog, `PluginsModal` Studio WebGL, and `.glsl` hot-reload.
- **Roadmap-Only (NOT implemented in the codebase)**: `VisionLens` expression DSL (`vision_lenses`), off-screen `postprocess.glsl` FBO pass, YAML `physics` preset block (note `membrane_breath_amp` currently lives under `overlay`, not `physics`), and MCP theme generation (`docs/WEBGL_VISUAL_PLUGINS_SPEC.md`).
{% endhint %}

## Pack Layout & Discovery

Place custom visual packs inside `.aether/plugins/visuals/<pack-slug>/`:

```text
.aether/plugins/visuals/my-theme/
├── visual-plugin.yaml        # Also accepts visual-plugin.yml or visual-plugin.json
├── backdrop.glsl             # Optional GLSL ES 3.00 hook: aetherBackdrop(...)
└── node_sdf.glsl             # Optional GLSL ES 3.00 hook: aetherNodeSurface(...)
```

`visual_plugin_routes.rs` parses `visual-plugin.yaml`, `visual-plugin.yml`, or `visual-plugin.json` via `serde_yaml` (with `serde_json` fallback), validates any referenced `.glsl` files with `read_confined_glsl`, and serves the inventory over `GET /api/visual_plugins`. `PluginEngine` ignores `visuals/` and `visual-plugin.*` so visual packs never interfere with SAST scanning.

## Manifest Schema (`VisualPluginManifest`)

### 📝 Top-Level & Sub-Config Fields

| Section / Field | Type | Default | Description |
|---|---|---|---|
| `schema_version` | `u32` | `1` | Manifest schema version. |
| `id` | `string` | Required | Unique pack slug (`<= 64` chars, confined via `sanitize_plugin_slug`). |
| `name` | `string` | Required | Display name shown in the Studio WebGL and Header menu. |
| `version` | `string` | `"1.0.0"` | Semver string. |
| `author` / `description` | `string` | `None` | Optional metadata. |
| `enabled` | `bool` | `true` | Enables/disables the pack in inventory. |
| `palette.background` | `string[]` | `[]` | Up to 4 `#RGB`/`#RRGGBB` hex colors mapped to `u_theme_colors[0..3]`. |
| `palette.layers` | `map<string, string>` | `{}` | Overrides for `ui`, `action`, `domain`, `database`, `config`, `utility`, `docs`, `default`. |
| `palette.severities` | `map<string, string>` | `{}` | Overrides for `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `palette.contract_warning` | `string` | `None` | Override for `RULE_MAX_LINES` contract warning color (default `#fbbf24`). |
| `overlay.membrane_style` | `string` | `None` | `organic_12lobe`, `hex_hull`, `rect_blueprint`, or `none`. |
| `overlay.edge_style` | `string` | `None` | `bezier`, `straight`, or `orthogonal_pcb`. |
| `overlay.edge_pulse_speed` | `f32` | `None` | Pulse animation speed multiplier on Canvas 2D edges. |
| `overlay.membrane_breath_amp` | `f32` | `None` | Membrane breathing amplitude (`0.0` disables breathing). |
| `overlay.label_font` | `string` | `None` | Optional Canvas 2D label font family override. |
| `shaders.backdrop` | `string` | `None` | Relative `.glsl` filename in the pack folder (e.g. `"backdrop.glsl"`). |
| `shaders.node_sdf` | `string` | `None` | Relative `.glsl` filename in the pack folder (e.g. `"node_sdf.glsl"`). |
| `shaders.uniforms` | `map<string, f32>` | `{}` | Packed into `u_params` (`grid_scale`, `glow_sharpness`, `star_density`, `nebula_speed`, each defaulting to `1.0`). |

## The 5 Built-In Packs

While `docs/WEBGL_VISUAL_PLUGINS_SPEC.md` mentions 3 packs in its M1 milestone summary, the frontend registry (`BUILTIN_VISUAL_PLUGINS` in `crates/desktop-shell/ui/src/engine/visualPlugins.ts`) ships **5 built-in packs** available both live and in offline demo mode:

| Pack `id` | Display Name | `membrane_style` | `edge_style` | `u_theme_colors[0..3]` | `u_params` (`grid, glow, stars, speed`) | Custom GLSL |
|---|---|---|---|---|---|---|
| `obsidian-nebula` | `Obsidian Nebula (Natif)` | `organic_12lobe` | `bezier` | `#04050b`, `#0b304f`, `#2e104d`, `#3d1030` | `1.0, 1.0, 1.0, 1.0` | Native shaders (`null`) |
| `cyber-pcb` | `Cyber-PCB Neon Blueprint` | `hex_hull` | `orthogonal_pcb` | `#03080e`, `#083344`, `#06b6d4`, `#22d3ee` | `1.0, 1.4, 0.0, 1.2` | Custom backdrop + node SDF |
| `architect-blueprint` | `CAD Architect Blueprint` | `rect_blueprint` | `straight` | `#071a33`, `#154273`, `#60a5fa`, `#bae6fd` | `1.0, 1.2, 0.0, 0.6` | Custom backdrop + node SDF |
| `deep-biolum` | `Abyssal Bioluminescence` | `organic_12lobe` | `bezier` | `#020c14`, `#062a3a`, `#0ea5e9`, `#2dd4bf` | `1.0, 1.0, 0.5, 1.0` | Custom backdrop + node SDF |
| `matrix-phosphor` | `Phosphor CRT Oscilloscope` | `hex_hull` | `orthogonal_pcb` | `#020904`, `#0b3b1c`, `#10b981`, `#4ade80` | `1.0, 1.3, 0.0, 1.2` | Custom backdrop + node SDF |

The active pack defaults to `obsidian-nebula`, and deleting an active custom pack via `POST /api/visual_plugins/delete` automatically falls back to `obsidian-nebula`.

## GLSL ES 3.00 Hook Contracts

AetherScope owns `#version 300 es`, camera transforms, subpixel dezoom clamping (`1.8px–2.6px` minimum radius), and `void main()`. Your `.glsl` files only implement the hook functions.

### 🎮 `backdrop.glsl` (`aetherBackdrop`)

```glsl
vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec)
```

Host-provided uniforms and helpers available in `backdrop.glsl`:
- `u_resolution` (`vec2` drawingBuffer size), `u_camera_pos` (`vec2`), `u_zoom` (`float`), `u_time` (`float` ms; `timeSec = u_time * 0.001`)
- `u_theme_colors[4]` (`vec3[4]` from `palette.background`)
- `u_params` (`vec4`: `x = grid_scale`, `y = glow_sharpness`, `z = star_density`, `w = nebula_speed`)
- `float aetherHash21(vec2 p)` and `float aetherNoise2(vec2 p)`

### 🎮 `node_sdf.glsl` (`aetherNodeSurface` & `NodeCtx`)

```glsl
void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha)
```

Every field of `NodeCtx` is populated by `NODE_HOST_FOOTER` from the 12-float WebGL 2 instance buffer (`shaders.ts`):

```glsl
struct NodeCtx {
  vec2 uv;          // Local quad coordinates in [-1.0, 1.0]
  float r;          // length(v_uv); host discards if r > 1.0
  float angle;      // atan(v_uv.y, v_uv.x)
  vec4 color;       // Resolved vision/layer/severity RGBA
  float kind;       // 0.0=Func/Method, 1.0=File, 2.0=Class/Struct, 3.0=Endpoint/Form
  float time;       // v_time * 0.001 (seconds)
  float phase;      // Deterministic per-instance phase in [0, 2*PI)
  float gitStatus;  // 0=clean, 1=modif, 2=new_file, 3=violation, 4=text/doc, 5=new_folder
  float metric0;    // [0..1] max(cyclomatic_complexity/24.0, (in_degree+out_degree)/28.0)
  float metric1;    // [0..1] 1.0=security alert, 0.85=focus/hover, 0.5=lines_exceeded, 0.0=normal
};
```

{% hint style="info" %}
**Immutable Git Diff & Security Halos**: `NODE_HOST_FOOTER` always blends the status rim (`r = 0.86`) and outer glow on top of your `aetherNodeSurface` output whenever `v_git_status > 0.5` (`1.0` amber modified, `2.0` green new file, `3.0` red security violation, `4.0` cyan doc, `5.0` purple new folder), plus the 300ms spawn fade-in. Custom shaders cannot hide security or Git indicators.
{% endhint %}

## Anti-DoS GLSL Validator, Atomic Swap & FPS Watchdog

To prevent GPU driver hangs (TDR) and shader-based denial of service, every hook passes identical static validation on both the Rust backend (`validate_glsl_hook` in `visual_plugin_routes.rs`) and the TypeScript frontend (`validateGlslHookClient` in `visualPlugins.ts`):

| Guard Rule | Limit / Behavior |
|---|---|
| Max file size | `32 KB` (`32,768` bytes) per `.glsl` hook file. |
| Null byte check | Rejects any `\0` character. |
| Comment stripping | Strips `//...` and `/*...*/` comments before structural checks. |
| Forbidden directives | Rejects `#version`, `#extension`, and `#pragma` (managed by the host header). |
| Unbounded loops | Rejects `while (` and `do {` (case-insensitive). |
| Bounded `for` loops | Every `for (init; cond; step)` must have 3 `;`-separated parts, a non-empty `cond`, and any numeric literal in `cond` must be `<= 128`. |
| Contract symbol | Source must contain `aetherBackdrop` (`backdrop.glsl`) or `aetherNodeSurface` (`node_sdf.glsl`). |

### Atomic Program Swap & Line Re-Indexing

In `shaders.ts`, `swapBackdropShader` and `swapNodeShader` compile and link a brand-new `WebGLProgram` **before** deleting the active program. If compilation fails, the previous shader keeps rendering cleanly and `formatGlslError` subtracts the host header's `lineOffset` from `ERROR: col:line:` messages so error line numbers match your snippet.

### FPS Watchdog

In `AetherEngine` (`crates/desktop-shell/ui/src/engine/engine.ts`), whenever a custom backdrop or node shader is active and `nodes.length < 25000`, frames slower than `40 ms` (`< 25 FPS`) accumulate into `slowShaderMs`. If slow rendering persists for `>= 2800 ms` (`2.8 s`), `AetherEngine` automatically swaps both shaders back to `null` (native) and reports `visualPluginError` in the UI.

## Visual Studio (`PluginsModal`), Hot-Reload & REST API

Open `PluginsModal` (`G`) and select the **Studio WebGL** tab (`visuals`) to:
- Preview and activate any of the 5 built-in or custom packs, import/export `.json` packs, or click **Reset Natif** (`obsidian-nebula`).
- Tweak 4 background pickers (`u_theme_colors[0..3]`), `membrane_style`, `edge_style`, optional overrides for all 7 layers and 4 severities, and 4 uniform sliders (`grid_scale`, `glow_sharpness`, `star_density`, `nebula_speed`).
- Edit `backdrop.glsl` and `node_sdf.glsl` using starter presets, preview instantly on the GPU (**Tester en direct (Hot-Swap)** without writing to disk), or save to `.aether/plugins/visuals/<id>/` via `POST /api/visual_plugins/upsert`.

Editing any file under `.aether/plugins/visuals/` or any `.glsl` file on disk triggers `FileWatcherBridge` (`100 ms` watcher poll, `30 ms` `desktop-shell` loop, `100 ms` quiet-window debounce / `500 ms` max batch) to bump `visual_plugins_version` without re-running AST/SAST scans.

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-security-plugins.md" %}
[REST API: Settings, Bounty, Surface & Plugins](../api-mcp/rest-api-security-plugins.md)
{% endcontent-ref %}
