# AetherScope / aether-engine

Interactive spatial code intelligence, static security analysis (SAST), and cryptographic AI governance engine (`v2.6.0`).

<mark style="color:$primary;">**Welcome to the official `aether-engine` documentation.**</mark>

`aether-engine` (**AetherScope / AetherSAST**) is a local-first Rust workspace and WebGL 2 Cockpit that turns complex polyglot codebases and Obsidian vaults into an interactive spatial graph while enforcing deterministic architecture and security guardrails.

{% hint style="info" %}
**Canonical version:** `2.6.0` (`Cargo.toml`, `ui/package.json`, `mcp.json`). Licensed under **PolyForm Noncommercial 1.0.0** — see [License](license.md) for commercial restrictions.
{% endhint %}

## Core Pillars

| Pillar | What `aether-engine` Does | Explore |
|---|---|---|
| **Spatial Graph & Dataflow** | Scans 11 languages in parallel, maps symbols and call edges into 4 layouts (`Z-1`..`Z-4`), runs reverse-BFS reachability, and traces SSA taint flows. | [Spatial Graph Engine](core/graph-engine.md) |
| **SAST, CWE & Reachable SCA** | Runs **247 rules** (`223` native + `24` Semgrep, including `28` novel `AETHER-*` detectors) with lexical masking, SARIF v2.1.0 export, and OSV.dev reachability. | [CWE & SAST Engine](core/cwe-sast-engine.md) |
| **BLAKE3 & EARS Governance** | Seals folder `README.md` contracts in `aether.lock.toml` with BLAKE3, enforces line budgets and `forbidden_imports`, and parses `WHEN ... THE SYSTEM SHALL ...` rules. | [BLAKE3 Governance](core/blake3-governance.md) |
| **AI Patch Firewall & MCP** | Protects code edits via a `<50ms` `PatchVerifier` firewall, `<aether_handshake>` XML context packets, `SecretGuard`/`SecretMasker`, and 10 native MCP tools. | [Native MCP Server](api-mcp/mcp-server.md) |
| **Plugins & WebGL 2 Cockpit** | Hot-reloads YAML/Taint DSL v2 plugins and GLSL ES 3.00 visual packs inside a 60 FPS WebGL 2 spatial cockpit and full-screen multi-tab IDE. | [WebGL 2 Spatial Cockpit](cockpit-ide/webgl-cockpit.md) |
| **Obsidian Dual-Vision** | Automatically classifies `PureCode`, `PureObsidianVault`, and `Mixed` workspaces, letting you toggle between AST graphs and note graphs (`Alt+V`). | [Obsidian Dual-Vision](cockpit-ide/obsidian-dual-vision.md) |
| **Scaffolder & AetherCraft** | Scaffolds 7 multi-stack architectures (`arch-templates`) and manages isolated Minecraft servers via the `apps/aethercraft/` control plane and `aether-mc-runner`. | [Multi-Stack Scaffolder](extensions-dev/arch-scaffolder.md) |

## Quick Navigation

{% content-ref url="introduction.md" %}
[Introduction](introduction.md)
{% endcontent-ref %}

{% content-ref url="getting-started/installation.md" %}
[Installation](getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="getting-started/quickstart.md" %}
[Quickstart](getting-started/quickstart.md)
{% endcontent-ref %}

{% content-ref url="architecture-overview.md" %}
[Architecture Overview](architecture-overview.md)
{% endcontent-ref %}

{% content-ref url="api-mcp/mcp-server.md" %}
[Native MCP Server (aetherscope-mcp)](api-mcp/mcp-server.md)
{% endcontent-ref %}

{% content-ref url="api-mcp/rest-api-overview.md" %}
[REST API Overview](api-mcp/rest-api-overview.md)
{% endcontent-ref %}
