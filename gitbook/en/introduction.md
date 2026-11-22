# Introduction

Discover how `aether-engine` combines spatial code visualization, static security auditing, and AI guardrails in one local engine.

## What Is `aether-engine`?

`aether-engine` (branded **AetherScope** in the cockpit UI and **AetherSAST** in security workflows) analyzes source files locally on your machine without sending proprietary code to external servers. It builds an in-memory dependency and call graph (`AetherGraph`), overlays security and architectural diagnostics directly onto symbols, and exposes the result through a WebGL 2 desktop interface, a local HTTP API, a CI-ready CLI, and a native MCP server for AI coding agents.

Whether you are auditing a repository for CWE vulnerabilities, supervising an AI assistant editing sensitive modules, or exploring an unfamiliar polyglot codebase or Obsidian knowledge base, `aether-engine` gives both humans and agents a shared, deterministic map of the project.

## Major Subsystems at a Glance

* **Polyglot AST & Call-Graph Scanner (`ast-scanner`, `core-graph`)**: Parses files in parallel with Rayon, extracts symbols (`SymbolBubble`) and calls (`AffiliationEdge`), computes 4 deterministic spatial layouts (`Z-1` to `Z-4`), and persists incremental scan results in `.aether/cache/ast/`.
* **SAST, Taint & Reachable SCA (`security-linter`)**: Evaluates **247 rules** (`223` native rules across 52 categories plus `24` embedded Semgrep OWASP/CWE rules, including `28` novel `AETHER-*` detectors). Dual-pass lexical masking (`AuditContext`) ignores comments and string literals on non-literal rules to cut false positives, while SSA dataflow (`DataflowGraph`) and OSV.dev SCA (`--sca`) separate reachable risks from dead code.
* **BLAKE3 & EARS Governance (`contract.rs`, `aether.lock.toml`)**: Reads YAML frontmatter and EARS (`WHEN ... THE SYSTEM SHALL ...`) clauses from folder `README.md` files, seals their BLAKE3 digests in `aether.lock.toml`, and flags tampering (`BLAKE3_TAMPERED`) or boundary violations (`RULE_MAX_LINES`, `RULE_FORBIDDEN_IMPORT`).
* **AI Bridge & `<50ms` Firewall (`ai-file-bridge`, `aetherscope-mcp`)**: Packages surgical target context into `<aether_handshake version="2.1">` XML, tracks tasks in `.aether/tasks/`, and validates agent edits in under 50 ms through `PatchVerifier` before accepting them.
* **Security Confinement (`LocalGuard`, `PathGuard`, `SecretGuard`, `SecretMasker`)**: Restricts the HTTP server to loopback hosts, prevents path traversal (CWE-22), hard-blocks `.env`/SSH/key files, and redacts 12 secret families.
* **Extensibility & Cockpit IDE (`desktop-shell`, `plugins`)**: Supports hot-reloaded YAML SAST/Taint plugins, custom WebGL 2 GLSL shaders, a full-screen multi-tab IDE, standalone HTML exports (`viewer.rs`), multi-stack scaffolding (`arch-templates`), and the external AetherCraft Minecraft platform (`apps/aethercraft/`).

## Supported Scanner Languages (11 Languages)

The polyglot scanner (`crates/ast-scanner/src/scanner.rs`) inspects the following 11 languages:

| # | Language | Recognized Extensions | Scanner Behavior & Notes |
|---|---|---|---|
| 1 | **Rust** | `.rs` | Skips `*_test.rs`, `*_tests.rs`, `*_check.rs`, and `build.rs`; `AuditContext` truncates inline `#[cfg(test)]` blocks for SAST. |
| 2 | **JavaScript / TypeScript** | `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs` | Skips `.min.js`, `.bundle.js`, and `.d.ts` files. |
| 3 | **Python** | `.py` | Automatically skipped when scanning a Rust-centric project (`Cargo.toml` / `crates/`). |
| 4 | **C / C++** | `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx`, `.inl` | Automatically skipped when scanning a Rust-centric project (`Cargo.toml` / `crates/`). |
| 5 | **Solidity / Yul** | `.sol`, `.yul` | Default line budget raises to `600` lines unless overridden in `README.md`. |
| 6 | **PHP** | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps` | Includes dedicated PHP security rules (`php_rules.rs`). |
| 7 | **Java** | `.java` | Extracts Spring `@GetMapping`..`@RequestMapping` and Minecraft `@EventHandler` routes; default line budget is `10,000` lines. |
| 8 | **Lua / Luau** | `.lua`, `.luau` | Supports Roblox/Luau project patterns. |
| 9 | **Zig** | `.zig` | Includes dedicated Zig safety/memory rules (`zig_rules.rs`). |
| 10 | **C#** | `.cs` | Extracts ASP.NET `[HttpGet]`..`[Route]` and Minimal API `MapGet`..`MapPatch` endpoints (`csharp_rules.rs`). |
| 11 | **Markdown (Contracts)** | `README.md` only | Code scanner skips non-`README.md` Markdown files and skips SAST on `.md`. Full `.md` vault scanning is handled separately by `obsidian-vault`. |

{% hint style="info" %}
`ast-scanner` skips `.md` files other than `README.md` so documentation files never pollute code call graphs or trigger SAST false positives.
{% endhint %}

## Automatic Project Classification (Dual-Vision)

Before scanning, `obsidian_vault::detect_project_type` inspects `.obsidian/` folders (up to depth 2), counts source vs. Markdown files, and samples up to 10 Markdown files (64 KB max each) for Obsidian syntax (wikilinks, note/media embeds, nested `#tag/subtag` tags, and frontmatter tags/aliases). It assigns one of three modes:

* **`PureCode`**: Standard software repository scanned by `ProjectScanner`.
* **`PureObsidianVault`**: Knowledge vault scanned by `scan_obsidian_vault` into `«Note»`, `«Attachment»`, and `«GhostNote»` bubbles.
* **`Mixed`**: Repository containing both code and an Obsidian vault. Both graphs are built and you can switch live in the Cockpit with `Alt+V`.

## Four Execution Modes

1. **Desktop GUI (Default)**: Opens a native `tao`/`wry` WebView2 cockpit window backed by the local Axum HTTP server (`127.0.0.1:3030`) and `FileWatcherBridge`.
2. **Headless HTTP Server (`--no-gui`)**: Runs the exact same Axum REST API, SSE live watcher stream, and embedded WebGL 2 UI for any external browser without opening a native window.
3. **CLI Audit & CI/CD (`--audit-only`, `--format sarif`, `--sca`, `--benchmark`)**: Runs single-shot SAST, OSV.dev SCA, SARIF v2.1.0 export, `--fail-on` CI gates, or performance benchmarks and exits.
4. **Native MCP Server (`--mcp` or `aetherscope-mcp`)**: Exposes JSON-RPC 2.0 (`2024-11-05`) over `stdin`/`stdout` for Claude Desktop, Cursor, and Gemini/Antigravity agents.

## Next Steps

{% content-ref url="architecture-overview.md" %}
[Architecture Overview](architecture-overview.md)
{% endcontent-ref %}

{% content-ref url="getting-started/installation.md" %}
[Installation](getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="getting-started/quickstart.md" %}
[Quickstart](getting-started/quickstart.md)
{% endcontent-ref %}
