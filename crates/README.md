---
id: crates-workspace
layer: domain
max_lines_per_file: 4000
allowed_imports: ["core_graph::*", "ast_scanner::*", "security_linter::*", "ai_file_bridge::*", "arch_templates::*", "obsidian_vault::*", "desktop_shell::*", "std::*"]
forbidden_imports: []
security_rules:
  no_raw_sql: true
  no_env_access: false
---
# 📦 crates — 7-Crate Modular Rust Architecture (v2.5.1)

The core engine of **AetherScope V2 (`aether-engine` v2.5.1)** is structured into 7 modular Rust 2021 workspace crates organized according to a strict hexagonal architecture:

```
crates/
├── core-graph/       [domain]      Pure graph models, spatial layouts (Z-1 to Z-4), BFS reachability, SSA dataflow
├── security-linter/  [domain]      222 native SAST rules (+24 Semgrep = 246), SecretGuard/Masker, EARS, BLAKE3, SARIF 2.1.0, SCA
├── arch-templates/   [utility]     Multi-stack project scaffolder (Rust, Python uv, Node pnpm, Web3/MMO)
├── ast-scanner/      [action]      Rayon-parallel polyglot AST extractor (11 langs), BLAKE3 AST cache (5.6x), SecretGuard filter
├── obsidian-vault/   [application] Obsidian vault engine, PathGuard jail (CWE-22), 4-stage classifier, dual-vision
├── ai-file-bridge/   [action]      Zero-shell file bridge, FileWatcher (<50ms), PatchVerifier firewall, task manager
└── desktop-shell/    [ui]          Tao/Wry window, Axum port 3030 (LocalGuard, 40 routes), aetherscope-mcp, Svelte 5 cockpit & IDE
```

## 🏛️ Crate Overview & Responsibilities

| Crate | Layer | Primary Responsibility | Documentation |
| :--- | :--- | :--- | :--- |
| **`core-graph`** | `domain` | Graph domain models (`AetherGraph`, `SymbolBubble`, `AffiliationEdge`), spatial positioning algorithms (`Z-1` to `Z-4`), reverse BFS reachability, and SSA dataflow models. | [core-graph README](./core-graph/README.md) |
| **`security-linter`** | `domain` | Real-time SAST engine with 222 native rules (including 28 `AETHER-*` detectors) + 24 embedded Semgrep OWASP/CWE community rules (246 total), `--plugins` & enriched taint/window DSL, `SecretGuard`/`SecretMasker`, lexical masking, EARS contracts, BLAKE3 seals, SARIF 2.1.0 exporter, Reachable SCA, and `aether-plugin-tool`. | [security-linter README](./security-linter/README.md) |
| **`arch-templates`** | `utility` | Scaffolds standardized 11-folder project structures with pre-signed BLAKE3 EARS contracts for Rust, Python (`uv`), Node/TS (`pnpm`), and Hybrid Web3/MMO. | [arch-templates README](./arch-templates/README.md) |
| **`ast-scanner`** | `action` | Multithreaded polyglot AST extractor for 11 languages, persistent BLAKE3 AST cache (`5.6x` speedup), per-file BLAKE3 digest calculation (`file_blake3_hash`), `SecretGuard` sensitive-file exclusion, contract resolution, and taint extraction. | [ast-scanner README](./ast-scanner/README.md) |
| **`obsidian-vault`** | `application` | Obsidian vault ingestion, `PathGuard` confinement jail against CWE-22, 4-stage project classifier (`PureObsidianVault`, `PureCode`, `Mixed`), and knowledge graph projection. | [obsidian-vault README](./obsidian-vault/README.md) |
| **`ai-file-bridge`** | `action` | Zero-shell filesystem bridge (`.aether/`), real-time `notify` FileWatcher (<50ms), AI patch verification firewall (`PatchVerifier` with `PROHIBITED_SECRET_FILE_MODIFICATION`), and task manager. | [ai-file-bridge README](./ai-file-bridge/README.md) |
| **`desktop-shell`** | `ui` | Native desktop window (`tao`/`wry`), Axum REST server on port 3030 (40 routes, `LocalGuard` anti-DNS-rebinding/CSRF), `aetherscope-mcp` stdio JSON-RPC 2.0 server (10 tools, 5 resources, 5 prompts), and Svelte 5 WebGL 2 Cockpit + full-screen multi-tab IDE. | [desktop-shell README](./desktop-shell/README.md) |

## 🛡️ EARS Architectural Requirements

- WHEN a crate is compiled THE SYSTEM SHALL enforce its own `README.md` architectural contract.
- WHEN a file in any sub-crate is modified THE SYSTEM SHALL re-evaluate SAST rules and update `.aether/LIVE_AUDIT.md` in less than 50 ms.
- IF an import violates the architectural boundary between layers THEN THE SYSTEM SHALL flag a `RULE_FORBIDDEN_IMPORT` violation.
