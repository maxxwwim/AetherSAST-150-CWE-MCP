# Changelog

All notable changes to the **AetherScope / AetherSAST** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.6.0] - 2026-11-19

### Added
- **🛡️ Contrats Architecturaux BLAKE3 Étendus (`RULE_FORBIDDEN_FUNCTION`, `RULE_FORBIDDEN_EXTENSION`, `RULE_MAX_FILES`) (`security-linter`, `ast-scanner`, `desktop-shell`, `ai-file-bridge`)**:
  - Nouveaux champs YAML dans le frontmatter des contrats `README.md` : `forbidden_functions`, `allowed_extensions`, `forbidden_extensions` et `max_files_per_folder`.
  - Détection par frontières lexicales des appels de fonctions/macros interdites (`eval`, `unwrap`, `println!`, etc.) sans faux positifs sur les déclarations ou sous-identifiants, générant une alerte critique `RULE_FORBIDDEN_FUNCTION` (`CWE-1075`) sur le nœud appelant et une arête vers le contrat `README.md`.
  - Contrôle de structure de dossier dans `ast-scanner` : vérification des extensions sur tous les fichiers (y compris binaires/non-code rattachés au `README.md` via `RULE_FORBIDDEN_EXTENSION`) et alerte de budget `RULE_MAX_FILES` en cas de dépassement de `max_files_per_folder`.
  - Prise en charge complète dans `POST /api/contracts/update`, `/api/git/status` (`ears_violation`), les filtres cockpit, `ACTIVE_TARGET.md`, le handshake XML IA et l'UI WebGL (`graphState.svelte.ts`, `SynthesisHud.svelte`).
- **🌊 Configurateur Taint Dataflow SSA Inter-Procédural Certifié & Serde Robuste (`core-graph`, `desktop-shell`, `security-linter`, `PluginsModal.svelte`, `demoPlugins.ts`)**:
  - Enrichissement exhaustif du modèle dataflow (`SourceKind`, `SinkKind` avec variantes `EnvironmentVar`, `Deserialization`, `CodeEval`, désérialiseurs Serde multi-formats string/map/tagged enum YAML).
  - Sanitizers multi-patterns (`patterns: Vec<String>`) avec support `target_cwes` (alias `neutralizes_cwes`) et matching multi-regex.
  - Endpoints backend `/api/plugins/taint` avec support des upserts purement taint (sans règle regex préalable) et préservation stricte des suites de tests unitaires existantes.
  - Moteur d'évaluation Taint SSA réactif dans le Playground navigateur (`demoPlugins.ts`) pour simulation instantanée sans backend.
  - Isolation stricte du répertoire de plugins visuels (`visuals/`) vis-à-vis du scanner de plugins SAST, éliminant tout faux positif ou désérialisation parasite.
- **WebGL 2 Visual Plugins Engine — M1 + M2 (`visual_plugin_routes.rs`, `visualPlugins.ts`, `shaders.ts`, `engine.ts`)**: Full visual theme & GLSL ES 3.00 hot-swap plugin system!
  - **5 Built-in Visual Packs** (*Obsidian Nebula*, *Cyber-PCB Neon Blueprint*, *CAD Architect Blueprint*, *Abyssal Bioluminescence*, *Phosphor CRT Oscilloscope*) working both live and offline in the standalone demo, selectable in 1 click from *Affichage → Thème WebGL* or the new **🎨 Visuels WebGL** Studio tab in `PluginsModal`.
  - **12-Float GPU Instance Stride (`a_metric0`, `a_metric1`) & Atomic GLSL Hot-Swap**: Explicit WebGL 2 `layout(location)` bindings enable zero-VAO-rebuild shader swaps (`backdrop.glsl` / `node_sdf.glsl`) with re-indexed GLSL error reporting, `u_theme_colors[4]` + `u_params` uniforms, `hex_hull`/`rect_blueprint`/`organic_12lobe` membranes, and 45°/90° `orthogonal_pcb`/`straight`/`bezier` edge routing.
  - **GPU Security & Resilience**: Static anti-DoS GLSL validator (32 KiB max, blocks `#version`/`#extension`/`while`/`do` and `for` bounds > 128) on both Rust backend and frontend, FPS Watchdog (<25 FPS sustained auto-fallback to native shaders), `webglcontextlost` guard, `PathGuard`-confined `/api/visual_plugins/*` routes (4 endpoints), and `.glsl` hot-reload in `FileWatcherBridge` without full AST rescan.
- **6-Tab Cockpit Plugin Center, DSL v2 Playground & Taint SSA Builder (`PluginsModal.svelte` + `HeaderDeck.svelte` + `demoPlugins.ts` + `plugin_routes.rs`)**: Complete 6-tab Plugin Center accessible from the top-bar `🔌 Plugins` button, `Plugins` menu, or hotkey <kbd>G</kbd> (`📦 Catalogue SAST` with YAML viewer/export & 1-click rule editing, `🛠️ Règle DSL v2` with 4 security presets & unit-test certification, `🌊 Taint SSA` visual source/sink/sanitizer configurator, `🧪 Bac à Sable` real-time browser DSL v2 Playground, `🔄 Import Semgrep` file/snippet converter, and `🎨 Studio WebGL` with 7-layer architectural palette editor & GLSL ES 3.00 starter presets). Works 100% interactively both with the live Rust backend (7 `PathGuard`-confined `/api/plugins/*` routes) and in standalone GitHub Pages demo mode.
- **MCP `aetherscope_manage_plugins` DSL v2 & Actions Upgrade**: Extended schema and handler (`mcp_catalog.rs`, `mcp.rs`) with full DSL v2 fields (`profile`, `tags`, `category`, `not_preceded_within_lines`, `in_path_matching`, `not_in_path_matching`, `ast_scope`, `taint_sources`, `taint_sinks`, `sanitizers`), new actions `toggle` and `init_bundle`, regex pre-validation (`PluginRule::validate_regexes`), and strict `PATH GUARD` slug enforcement on `plugin_name`.
- **WebGL Visual Plugins Architecture Spec (`docs/WEBGL_VISUAL_PLUGINS_SPEC.md`)**: 4-tier architecture specification for declarative visual themes, sandboxed GLSL ES 3.00 hook points (`12`-float instance stride + FPS watchdog), `eval()`-free `VisionLens` DSL, and configurable physics presets.
- **Dedicated Full-Screen Multi-Tab IDE (`IdeView`, `IdeEditor`, `IdeFileTree`, `IdeSymbolHierarchy`, `IdeDocSidebar`)**: Full-screen IDE mode with multi-tab editing, atomic file saves (`/api/save_file`, `/api/files`), auto-open file at function on 3D bubble click, synchronized cosmic cluster file-tree colors, integrated Doc/EARS/Source sidebars, resizable splitters, collapsible sidebars, and Zen mode.
- **Persistent BLAKE3 AST Cache & `--plugins` DSL**: BLAKE3-keyed incremental AST cache delivering **5.6x** faster rescans, CLI `--plugins` pack/profile selection, enriched declarative taint/window plugin DSL, and slimmed `/api/graph` columnar payloads.
- **Cockpit Visual & Ergonomics Upgrades**: Sleek CWE pills, live AI (<5m) left dock, workspace file-system explorer (`/api/fs/list`), visible call/import links with directional chevrons and relation badges, luminous micro-star edge endpoints, and dynamic cellular membrane sync in N2/N3 layouts.

### Changed
- **Codebase Cleanup & Static Hygiene**: Removed dead Rust functions/constants (`analyze_file`, `record_offline_ai_telemetry`, `SwitchViewModeRequest`, `init_project_structure`, `pick_folder_dialog`, `pick_file_dialog`, `MODERN_INDEX_HTML`, and unreachable `if false` probe block), resolved all Clippy errors/warnings across the 7-crate workspace, unified UI icons on `@lucide/svelte` (dropping duplicate `lucide-svelte`), removed unused Vite starter assets and `portal.ts`, and aligned all documentation & BLAKE3 seals.

### Fixed
- **Custom Plugin Rules Silently Filtered Out in Cockpit GUI**: Fixed `apply_settings_filters_to_graph` (`crates/desktop-shell/src/main.rs`) so custom `.aether/plugins/`, Semgrep, and declarative taint-sink rules are no longer silently dropped when `.aether/settings.json` persists a native-only `active_cve_rules` list (while still honoring `ignored_cwes`, plugin `enabled` toggles, and explicit empty "disable all" lists). Aligned the live `FileWatcher` hot-reload path to apply the same filter and invalidate `ui_graph_cache`.
- **UI Type-Safety & Runtime Bugs (`svelte-check`: 35 -> 0 errors)**: Fixed `HeaderDeck` agent target focusing (`selectSymbol(hit.id, true)`), `InspectorDrawer` `api.updateTask` argument mismatch, `AiChatDrawer` AI trail badge field (`step.agentName`), `TasksModal` null guard, `IdeSymbolHierarchy` kind check, and `demoGraph.ts` schema drift.
- **`AETHER_AI_RULES.md` Generator**: Persisted Section 6 (`SecretGuard`/`SecretMasker`) and the 10-tool MCP catalog directly in `crates/ai-file-bridge/src/audit_writer.rs` so regeneration no longer drops secret-isolation directives.

---

## [2.5.1] - 2026-11-16

### Security (Secret Isolation Against AI Agents)
- **`SecretGuard` / `SecretMasker`** (`crates/security-linter`): path detector (`.env*`, `.envrc*`, `secrets`, `.credentials`, private keys, certificates, `service-account.json`, `.htpasswd`, ...) and in-memory redactor (OpenAI/Anthropic/Gemini, GitHub, AWS, Stripe, Slack, JWT, DB URIs, PEM private key blocks).
- **MCP hardening**: `aetherscope_get_active_target`, `aetherscope_search_symbols`, `aetherscope_verify_patch` and `aetherscope_scan_with_plugins` refuse sensitive targets and redact their output. `scan_with_plugins` is now confined to the project root (`PATH GUARD`) and no longer reads absolute or `..` paths.
- **HTTP hardening**: `/api/ai/target`, `/api/file_content` and `/api/ai/create_file` return `403 Forbidden` on sensitive resources or secret-bearing content.
- **Patch verifier**: any AI patch touching a secret file is rejected with `PROHIBITED_SECRET_FILE_MODIFICATION` (CWE-538).
- **Scanner**: `ast-scanner` skips secret paths so they never enter the graph.
- **`AETHER_AI_RULES.md`**: new section 6 forbidding AI access to production secrets and environment files.

### Added
- **AI HUD toggles**: one-click `Lignes / Lasers IA` and `Noms des Agents IA` in the header menu and in Settings (`showAiLines`, `showAiNames`).
- **Auto-hide of AI names** after 5 minutes of agent inactivity.

### Fixed
- **Canvas freezes / crashes with multiple AI agents**: removed per-frame allocations and heavy matrix stacks (`save/translate/rotate/ellipse/restore`), reduced orbit sampling (28 → 12), clamped `dt` to `[1, 50]` ms and pruned `agentSmoothPositions` above 40 agents.
- **Stripe redaction** replacement string (`$1_` → `${1}_`).

---

## [2.5.0] - 2026-11-15

### Security & Hardening (Moltbook Audit Zero-Shell Immunity)
- **Ultra Path Guard Confinement Jail (`PathGuard`)**: Complete remediation of CWE-22 arbitrary file read/write vulnerabilities identified in the Moltbook security analysis (*"Your zero-shell executor can still be a privileged file thief"*).
- **Lexical Zero-I/O Path Validation**: Strict rejection of absolute paths (`is_absolute()`, leading slashes), UNC network paths (`\\`, `//`), NT namespace paths (`\\?\`), drive letters (`C:`), URL protocols (`file://`, `http://`), null bytes (`\0`), and parent directory traversals (`..`).
- **Canonical Boundary Containment**: Enforced `canonical_target.starts_with(&canonical_root)` on all target paths, accompanied by symlink escape defenses and prospective write target resolution (`resolve_write_target`).
- **Sensitive File & Secret Blacklisting**: Case-insensitive blocking for credentials, private keys, and critical system configs (`.env*`, `.git/config`, `.ssh*`, `.aws*`, `.pem`, `.key`, `id_rsa*`, `id_ed25519*`, `win.ini`, `/etc/passwd`, `/etc/shadow`).
- **Whitelisted Raw Media API**: Restricted `/api/raw_file` exclusively to verified media/doc extensions (`png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `txt`, `csv`) and eliminated arbitrary binary fallbacks.
- **Endpoint Hardening**: Guarded `/api/raw_file`, `/api/file_content`, `/api/ai/create_file`, and `/api/save_doc` in `crates/desktop-shell/src/main.rs` with structured HTTP error codes (400 Bad Request, 403 Forbidden, 404 Not Found).
- **Automated 4-Tier Security Test Suite**: Authored 1,109-line live integration test suite (`crates/desktop-shell/tests/e2e_path_confinement_security.rs`) validating 23/23 tests against 541 real-world adversarial attack vectors (100% pass rate, zero bypasses).

### Added
- **Cryptographic BLAKE3 Contract Sealing**: Automated on-the-fly BLAKE3 integrity sealing in `aether.lock.toml` for live contract and budget adjustments via `/api/contracts/update` and `/api/contracts/sign`.
- **Permanent Chat IA Floating Action Button (FAB)**: Persistent neon-styled trigger in the bottom-right corner whenever the chat drawer is closed, displaying live agent presence and unread counts.
- **Restored Keyboard Hotkey**: Pressing <kbd>C</kbd> globally toggles the AI Chat drawer cleanly without modal conflicts.

### Changed
- **Stationary AI Agent Badges**: Agent billboard labels are now firmly anchored directly above target symbol nodes (`pNode`) rather than following revolving 3D orbital particle trajectories, eliminating erratic motion and visual nausea.
- **Streamlined Agent HUD Display**: Stripped verbose action sentences from persistent graph badges in favor of compact, high-contrast agent pills (`✨ Claude-Sec`, `⚡ Gemini-UI`, `🪐 Antigravity`), with automatic text attenuation at wide zoom levels (`zoom < 0.22`).
- **HeaderDeck Chat Trigger**: Removed responsive clipping (`hidden lg:inline`) to keep the "Chat IA" indicator permanently visible across all viewport dimensions.

## [2.4.0] - 2026-11-14 / 2026-11-15

### Added
- **Svelte 5 Runes Cockpit**: Complete modernization of the frontend UI (`crates/desktop-shell/ui`) leveraging Svelte 5 Runes (`$state`, `$derived`, `$effect`), Tailwind CSS v4, and Vite 8 with `vite-plugin-singlefile`.
- **Simultaneous Multi-Agent Swarm**: 12-color agent badge palette, persistent telemetry caching in `.aether/ai_telemetry_cache.json`, real-time camera teleport with quantum laser breadcrumbs, and swarm chat HUD via `.aether/CHAT_INBOX.md`.
- **Live Modifiable BLAKE3 Contracts**: Interactive line budget customization (`file_max_lines` overrides and `max_lines_per_file` folder budgets) with on-the-fly cryptographic BLAKE3 contract sealing in `aether.lock.toml` via `POST /api/contracts/update` and `POST /api/contracts/sign`.
- **Unified Docs, EARS & Source Drawer**: Single-container Markdown reader and editor with live code extracts, AST docstrings, Mermaid diagram rendering, and syntax highlighting.
- **Bug Bounty PoC Scope**: Multi-criteria vulnerability search and scope recommendation engine integrated with MCP tools (`/api/bounty/scope`).
- **Directional Visual Links**: Call, import, and data hover arrows paired with organic 12-lobed cellular bilayer folder membranes tracking dynamic bubble positions.
- **Infinite Dezoom Engine**: Zoom floor lowered to `0.00005` (`0.0001` auto-fit) with vertex shader subpixel clamping (`screen_r >= 2.0px`) preventing nodes from vanishing across 100,000+ symbol galaxies.

### Changed
- Consolidated MCP server catalog down to 10 curated high-impact combined tools to eliminate prompt flooding and context window exhaustion.
- Replaced central HUD overlay with fluid single-container scroll and collapsible floating tool decks.
- Semantic visual separation: orange warnings (`#f97316`) for line-budget thresholds (`RULE_MAX_LINES`) and crimson red (`#ef4444`) for true security violations.

### Fixed
- Fixed Svelte 5 Proxy `DataCloneError` in Web Worker physics transfers.
- Fixed canvas 100vh height collapse during responsive browser window resizing.
- Restored HiDPI display alignment, auto-fit camera motion, and bubble/folder picking.
- Fixed settings persistence by writing to `.aether/settings.json` on disk and auto-syncing without requiring AST rescan.
- Fixed AI agent telemetry jitter by synchronizing movement timestamp clocks (`performance.now()`) and applying continuous exponential smoothing (LERP).
- Added 1-click visibility toggles for security alerts, CWE bubbles, CWE titles, folder titles, and file titles in HeaderDeck and Settings.
- Updated standalone web demo (`docs/index.html`) with latest UI bundle and 1,000+ symbol graph.

### Security
- Reinforced `LocalGuard` middleware on Axum to prevent DNS rebinding and cross-site request forgery (CSRF).
- Cryptographic BLAKE3 integrity verification enforced on all folder contracts and individual source files.

---

## [2.3.0] - 2026-11-12 / 2026-11-13

### Added
- **Gemini 4 Hydrogen Extra**: Introduced 28 specialized non-CWE `AETHER-*` detection rules and stealth RCE vulnerability detectors in `epic_novel_rules.rs`, expanding the active rule catalog to 215 rules.
- Dedicated detection for Trojan Source bidirectional unicode tricks, compiler soundness flaws, async TLS bleed, and hidden backdoors.

### Changed
- Optimized WebGL 2 GPU memory allocation and rendering pipelines for large-scale graphs (1,000+ nodes).

### Fixed
- Fixed variable re-declarations in WebGL renderer and restored label cache buffers.

---

## [2.2.3] - 2026-11-11

### Added
- 3D volumetric SDF (Signed Distance Field) shaders and 120 FPS dual-pass laser glow.
- Interactive CWE callout bubbles for immediate visual inspection of discovered vulnerabilities.

### Security
- Remediated integer overflow (CWE-190) and unhandled exception / architectural boundary violations (CWE-1075).

---

## [2.2.2] - 2026-11-10

### Added
- GitHub-grade Markdown rendering engine with Mermaid diagram support and live Git status inspection.
- `/api/raw_file` streaming endpoint for raw binary media assets (PNG, SVG, WebP, PDF).
- Comprehensive English documentation with bidirectional links to French reference archives.

---

## [2.2.1] - 2026-11-09

### Added
- **Native Obsidian Vault Interoperability**: Created `crates/obsidian-vault` featuring `PathGuard` confinement jail, 4-stage project classifier (`PureObsidianVault`, `PureCode`, `Mixed`), CommonMark code-masked AST parser, and dual-vision WebGL 2 switcher.
- Added `aetherscope_switch_view_mode` and Obsidian graph metrics in `aetherscope_get_graph_summary`.
- Modernized Smithery MCP registry specification to v2.2.1 format.

---

## [2.2.0] - 2026-11-08

### Added
- Extended SAST scanner to support **Zig** (15 CWE rules) and **C# / .NET** (20 CWE rules) with AST taint analysis.
- Semgrep community bundle importer and inter-procedural SSA dataflow taint tracking (`SsaVar`, `TaintFlowTrace`).
- Reachable Software Composition Analysis (SCA) querying OSV.dev vulnerability databases.

### Changed
- Consolidated 17 legacy MCP tools into 8 unified commands.

### Security
- Resolved 13 internal self-audit security violations and deduplicated MCP server implementations.

---

## [2.1.0] - 2026-11-08

### Added
- **SARIF 2.1.0** export engine and GitHub Actions integration (`--format sarif --output report.sarif`).
- Reachability Taint-Graph (Source-to-Sink BFS traversal).
- Real-time AI Firewall MCP tool `aetherscope_verify_patch` (<50ms execution).
- Reproducible benchmark CLI mode (`--benchmark`) establishing 4,446 LOC/s scan throughput at 27.5 MB peak RSS.

### Fixed
- Added on-demand automatic Axum backend spawning when `aetherscope-mcp` is invoked via stdio.

---

## [2.0.9] - 2026-11-08

### Added
- Network and HTTP Surface Scanner modal (`/api/surface_scan`).
- Hierarchical tree layout and anti-collision cellular physics.

---

## [2.0.8] - 2026-11-05

### Added
- Declarative SAST/CWE plugin engine in `.aether/plugins/` and standalone `aether-plugin-tool` CLI.
- 4 MCP plugin management tools (`aetherscope_manage_plugins`).
- Dark Obsidian Studio UI redesign.

---

## [2.0.7] - 2026-11-05

### Added
- Off-thread physics simulation executed in a dedicated Web Worker at 120 FPS via zero-copy `Transferable Float32Array`.
- Modularized game runner logic into `apps/aethercraft`.

---

## [2.0.6] - 2026-11-05

### Added
- Initial Svelte 5 and Tailwind CSS v4 prototype.

### Fixed
- Absolute z-index hierarchy for topbar and streamlined menu structure.

---

## [2.0.5] - 2026-10-31 / 2026-11-04

### Added
- 4 physical vision modes: Standard, X-Ray, Heatmap, and Deadcode.
- Java AST scanning (`.java`) and Minecraft server runner.
- M8ven 100/100 score compliance: MCP resources, prompts, and boolean tool hints.

---

## [2.0.4] - 2026-10-30

### Added
- Exhaustive `CWE_CATALOG.md` documenting 152 CWE rules.
- Per-folder EARS contract `README.md` templates across all workspace crates.
- Live WebGL demo bundle deployed to GitHub Pages.

---

## [2.0.3] - 2026-10-30

### Added
- Multi-criteria live CWE search in PoC generator modal.
- 10 critical PHP CWE vulnerability detectors (25 total).

### Fixed
- MCP active project synchronization on load and 45-second socket timeout.

---

## [2.0.2] - 2026-10-29

### Added
- 10 C++ network and memory corruption CWE detectors.

---

## [2.0.1] - 2026-10-29

### Fixed
- Implemented `LocalGuard` anti-DNS-rebinding and anti-CSRF protection on Axum server.
- Aligned rule IDs across security linter and AST scanner.

---

## [2.0.0] - 2026-10-29

### Added
- Initial release of AetherScope V2: Rust multi-crate engine (`core-graph`, `ast-scanner`, `security-linter`, `ai-file-bridge`, `desktop-shell`).
- 90+ Zero-Day Patterns & CWE SAST rules.
- Dedicated MCP Server for AI copilot orchestration.
- Windows desktop launchers (`Start-Cockpit.bat`, `AetherScope-Launcher.bat`, `install.ps1`, `setup-mcp.ps1`).
- Adopted PolyForm Noncommercial 1.0.0 license.
