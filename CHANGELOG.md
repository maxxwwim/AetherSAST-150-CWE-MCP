# Changelog

All notable changes to the **AetherScope / AetherSAST** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- GitHub-grade Markdown rendering engine with Mermaid diagram support and live Git diff viewing (`GitDiffModal.svelte`).
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
