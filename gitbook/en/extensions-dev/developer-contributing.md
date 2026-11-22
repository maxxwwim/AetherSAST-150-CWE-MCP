# Developer & Contributing Guide

This guide covers the `aether-engine` `2.6.0` hexagonal workspace, Rust and Svelte 5 test suites, and how to extend SAST rules, AST language extractors, and WebGL 2 visual plugins.

## Workspace Architecture (7 Crates + Excluded Runner)

The root `Cargo.toml` (`version = "2.6.0"`, `edition = "2021"`, `license = "PolyForm-Noncommercial-1.0.0"`) organizes `aether-engine` into 7 workspace crates plus one excluded standalone binary crate (`apps/aethercraft/runner`).

| Crate / Path | Layer | Role & Binaries | Key Dependencies |
| :--- | :--- | :--- | :--- |
| `crates/core-graph` | `domain` | Pure graph model (`AetherGraph`, `SymbolBubble`, `AffiliationEdge`, layouts, reachability) — zero I/O | `serde`, `serde_json`, `bitflags`, `rayon` |
| `crates/security-linter` | `domain` | 223 native SAST rules, declarative DSL v2, OSV SCA, EARS/BLAKE3 contracts; bin `aether-plugin-tool` | `core-graph`, `serde`, `serde_json`, `serde_yaml`, `blake3`, `regex` |
| `crates/arch-templates` | `utility` | Multi-stack `ArchScaffolder` templates (`PureRust`..`ClassicMvc`) | `core-graph`, `serde`, `serde_json`, `toml`, `blake3` |
| `crates/ast-scanner` | `action` | Polyglot AST scanner, Rayon walker, BLAKE3 `.aether/cache/ast/` cache | `core-graph`, `security-linter`, `walkdir`, `rayon`, `regex`, `toml` |
| `crates/obsidian-vault` | `application` | Obsidian vault detector & Markdown note/wikilink/tag graph scanner | `core-graph`, `serde`, `serde_yaml`, `regex`, `walkdir`, `rayon`, `thiserror` |
| `crates/ai-file-bridge` | `action` | `FileWatcherBridge`, `TaskManager`, `HandshakePacker`, `AuditWriter`, `PatchVerifier` | `core-graph`, `security-linter`, `notify`, `tokio`, `chrono`, `colored` |
| `crates/desktop-shell` | `ui` | Axum REST server, `LocalGuard`, Wry/Tao WebView2 desktop shell, MCP server; bins `aether-engine`, `aetherscope-mcp` | All 6 sibling crates + `axum`, `tokio`, `clap`, `wry`, `tao`, `rfd` |
| `apps/aethercraft/runner` *(excluded)* | `standalone` | Standalone `aether-mc-runner` (`v1.0.0`) with its own `[workspace]` | `tokio`, `serde`, `blake3`, `clap`, `reqwest`, `sha2`, `anyhow` |

{% hint style="danger" %}
Every folder under `crates/` has a BLAKE3-sealed `README.md` recorded in `aether.lock.toml`. If you modify any `crates/*/README.md` contract, re-sign it via the Cockpit or `POST /api/contracts/sign` so `ast-scanner` does not emit a `CRITICAL` `BLAKE3_TAMPERED` violation.
{% endhint %}

## Building & Running the Test Suites

{% tabs %}
{% tab title="Rust Workspace & V3 E2E" %}
```bash
# Run all workspace unit & integration tests
cargo test --workspace

# Run the 4 V3 E2E suites (44 tests total across these 4 files)
cargo test -p desktop-shell --test e2e_r1_semgrep --test e2e_r2_dataflow_ssa --test e2e_r3_reachable_sca --test e2e_tier3_tier4_scenarios

# Run individual E2E suites with stdout logs
cargo test -p desktop-shell --test e2e_r1_semgrep -- --nocapture          # 12 tests
cargo test -p desktop-shell --test e2e_r2_dataflow_ssa -- --nocapture     # 14 tests
cargo test -p desktop-shell --test e2e_r3_reachable_sca -- --nocapture    # 12 tests
cargo test -p desktop-shell --test e2e_tier3_tier4_scenarios -- --nocapture # 6 tests

# Check/test the excluded AetherCraft runner
cargo check --manifest-path apps/aethercraft/runner/Cargo.toml
```
{% endtab %}
{% tab title="Svelte 5 UI (crates/desktop-shell/ui)" %}
```bash
cd crates/desktop-shell/ui

# Type-check Svelte 5 templates and TypeScript configs
npm run check

# Build production UI bundle (dist/)
npm run build

# Run all 3 UI behavioral & adversarial test scripts
npm test
```
{% endtab %}
{% endtabs %}

`npm test` in `crates/desktop-shell/ui/package.json` executes 3 scripts sequentially:

1. `node verify_header_bindings.mjs` — verifies `HeaderDeck.svelte` two-row layout, Omnibox/SearchDropdownPanel bindings, Dual-Vision, LoD, vision modes, and `BountyModal` triggers.
2. `node empirical_stress_test.mjs` — probes `BountyModal` `tokenizeLine` for ReDoS and XSS safety plus wildcard pattern matching.
3. `node adversarial_challenge_m4.mjs` — Vite SSR harness testing `SearchDropdownPanel` `use:portal`, `RadarMinimap`, audio mute toggle, PoC dry-run sandbox, and audit exporter XSS/scale safety.

{% hint style="info" %}
`TEST_INFRA.md` documents an earlier target of `60+` tests (`15/15/18/12`) across the 4 V3 E2E files; the actual implemented `#[test]` count in those 4 files is `44` (`12 + 14 + 12 + 6`), alongside 15 additional production integration suites in `crates/desktop-shell/tests/` (such as `e2e_prod_plugins_dsl.rs` and `e2e_prod_cache_perf.rs`).
{% endhint %}

## Extending SAST & Taint Rules

### Option A: Declarative `plugin.yaml` (No Recompilation)

For custom security rules, team policies, or Semgrep migrations, add a pack under `.aether/plugins/<pack-name>/plugin.yaml`. `FileWatcherBridge` hot-reloads changes automatically, and `aether-plugin-tool` lets you scaffold and test packs from the CLI:

```bash
aether-plugin-tool init my-org-rules .aether/plugins
aether-plugin-tool test .aether/plugins
aether-plugin-tool scan .aether/plugins ./src
```

Declarative rules (`PluginManifest` / `PluginRule` / `RuleConditions` in `crates/security-linter/src/plugin.rs`) support `match_mode` (`line_by_line` | `whole_file`), `ast_scope` (`outside_test`, `test`, `async_fn`, `sync_fn`, `fn`), `not_preceded_within_lines`, `in_path_matching` / `not_in_path_matching`, `check_literals`, inline `test_cases`, and `--plugins` selectors (`default`, `auto`, `all`, pack names, or `profile:<name>`).

### Option B: Native Rust Rule Modules

When you need compiled Rust pattern logic, add rules to one of the modular packs in `crates/security-linter/src/` (`rules.rs` `AdvancedDefiRules`, `deep_rules.rs` `DeepSecurityRules`, `php_rules.rs` `PhpSecurityRules`, `zig_rules.rs` `ZigSecurityRules`, `csharp_rules.rs` `CSharpSecurityRules`, `epic_novel_rules.rs` `EpicNovelRules`), each exposing `::definitions() -> Vec<CveRuleDef>` and `::audit_file(...) -> Vec<LinterViolation>`:

1. Register the rule definitions in `SecurityLinter::get_supported_cve_rules()`, file extension mappings in `get_file_types_for_cwe()`, and execution in `audit_file_raw()` (`crates/security-linter/src/linter.rs`).
2. Account for **dual-pass lexical masking**: `audit_file_with_context` evaluates `audit_file_raw` on both raw source and `ctx.default_masked()` (comments and string literals stripped). Add your `rule_id` to `SecurityLinter::LITERAL_AWARE_RULES` if it must inspect string literals (e.g. hardcoded secrets or SQL literals).
3. Remember that `strip_rust_inline_tests` truncates `.rs` files at `#[cfg(test)]` / `mod tests {`, and `security-linter/src/` is excluded from self-scanning (`reflexive exclusion`).

## Adding a New AST Language Extractor

To add first-class AST parsing for a new programming language in `crates/ast-scanner/src/scanner.rs` and `crates/security-linter/src/lexer.rs`:

1. **Allowlist the extension**: Add the lowercase file extension(s) to `ProjectScanner::scan_project_with_exclusions` (`scanner.rs`). Note that files `> 1_500_000` bytes are skipped and Rust-centric workspaces prune `.c`/`.h`/`.cpp`/`.py`.
2. **Dispatch in `analyze_file_with_content`**: Add a match arm for your extension calling `analyze_<lang>(rel_path, content)`.
3. **Implement `analyze_<lang>`**: Use `static_regex!` to extract imports, classes/structs, functions/methods, `RawCall` invocations, routes, and WebSocket events. Build `SymbolBubble` nodes with `detect_galaxy`, `detect_layer`, `folder_from_rel_path`, and `compute_complexity`, returning `FileAnalysis` so `resolve_graph_edges` wires `contains`, `imports`, `calls`, `inherits`, and `network` edges automatically.
4. **Add lexical masking in `lexer.rs`**: If the language uses non-C-like comments or string delimiters, add a `Lang` variant and `Lang::from_path` mapping so SAST masking remains accurate.
5. **Automatic Rayon & BLAKE3 caching**: Once wired into `analyze_file_with_content`, your extractor automatically inherits Rayon `par_iter()` execution and `.aether/cache/ast/` BLAKE3 caching.

## Developing WebGL 2 Visual Plugins

Visual packs live under `.aether/plugins/visuals/<pack-name>/` with a `visual-plugin.yaml` (or `.yml`/`.json`) manifest plus optional `backdrop.glsl` and `node_sdf.glsl` shaders.

* **5 built-in packs** (`crates/desktop-shell/ui/src/engine/visualPlugins.ts`): `obsidian-nebula`, `cyber-pcb`, `architect-blueprint`, `deep-biolum`, and `matrix-phosphor` *(note: `docs/WEBGL_VISUAL_PLUGINS_SPEC.md` mentions 3 packs, while the engine ships 5)*.
* **Implemented hooks (M1 + M2)**: `palette`, `overlay` (`membrane_style`: `organic_12lobe` | `hex_hull` | `rect_blueprint` | `none`; `edge_style`: `bezier` | `straight` | `orthogonal_pcb`), `shaders.uniforms`, `backdrop.glsl` (`vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec)`), `node_sdf.glsl` (`void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha)`), FPS watchdog fallback (`> 33 ms` for 2s), and live `FileWatcherBridge` hot-reload on `.glsl` edits.
* **Roadmap only (M3 — not yet implemented)**: `VisionLens` expressions, `postprocess.glsl`, `physics` presets, and MCP theme generation.

### Anti-DoS GLSL & `PathGuard` Constraints

Both Rust (`crates/desktop-shell/src/visual_plugin_routes.rs`) and TypeScript (`visualPlugins.ts`) validate custom GLSL before compilation:

* **Max size**: `32 KB` (`32 * 1024` bytes) and zero `\0` null bytes.
* **Forbidden preprocessor directives**: `#version`, `#extension`, `#pragma` (host-injected).
* **Loop safety**: `while (...)` and `do { ... } while` are rejected; every `for (...)` must have 3 semicolon-separated clauses with a non-empty condition and numeric upper bound `<= 128` (`MAX_FOR_LOOP_BOUND`).
* **Contract & path confinement**: Must define `aetherBackdrop` or `aetherNodeSurface`, and shader filenames must be plain `.glsl` filenames without `/`, `\`, `..`, or `:`.

{% content-ref url="../architecture-overview.md" %}
[Architecture Overview](../architecture-overview.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[WebGL 2 Visual Plugins](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[aether-plugin-tool, aetherscope-mcp & aether-mc-runner CLIs](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
