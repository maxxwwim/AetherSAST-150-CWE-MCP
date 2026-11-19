---
id: security-linter
layer: domain
max_lines_per_file: 4000
allowed_imports: ["core_graph::*", "regex::*", "serde::*", "serde_yaml::*", "blake3::*", "std::*"]
forbidden_imports: ["ast_scanner::*", "ai_file_bridge::*", "arch_templates::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
---
# 🛡️ security-linter — Real-Time SAST Engine, 222+ Rules, SecretGuard & BLAKE3 Contracts (v2.5.1)

High-performance Static Application Security Testing (SAST) engine evaluating **222 native rules** (including 28 non-CWE `AETHER-*` zero-day detectors) + **24 embedded Semgrep OWASP/CWE community rules** (**246 total rules**) across 35 vulnerability families. Features dual-pass lexical comment/string masking, specialized language security suites (PHP 8.x, Zig, C#/.NET 8+, Rust/LLVM, DeFi/Smart Contracts, ZK-SNARKs), declarative YAML plugins (`--plugins` & enriched taint/window DSL), `SecretGuard`/`SecretMasker` secret isolation, SARIF 2.1.0 exporter, Semgrep YAML plugin importer, Reachable SCA engine, and the `aether-plugin-tool` CLI.

## 📦 Component Inventory

| File / Subsystem | Description & Architectural Responsibility |
| :--- | :--- |
| `src/linter.rs` | Central `SecurityLinter` orchestrator, rule registry (222 native rules), file eligibility filtering, plugin selection (`audit_file_selected`), and violation aggregation. |
| `src/contract.rs` | Architecture contract parser: YAML frontmatter (`max_lines_per_file`, `file_max_lines`), EARS clause extraction, and BLAKE3 verification. |
| `src/lexer.rs` | Dual-pass comment and string literal masking engine eliminating false positives while preserving exact byte and line coordinates. |
| `src/rules.rs` | Web3 & DeFi security suite: oracle spot manipulation, flash loans, reentrancy, and ERC-4337 paymaster griefing. |
| `src/deep_rules.rs` | Systems & cryptography rules: Rust/LLVM unsoundness, ABI panic safety, ZK-SNARK Frozen Heart, Circom signals, EVM L2, and Wasm storage bombs. |
| `src/php_rules.rs` | 26 specialized PHP 8.x and WordPress security rules: SQLi, command injection, dynamic file inclusion (LFI/RFI), and object deserialization. |
| `src/zig_rules.rs` | 15 Zig systems rules: use-after-free, unhandled error unions, `@ptrCast` alignment, SIMD unaligned OOB, and C-interop safety. |
| `src/csharp_rules.rs` | 20 C# / .NET 8+ rules: `BinaryFormatter` deserialization, SQLi, command injection, path traversal, XXE, ReDoS, and unsafe `stackalloc`. |
| `src/epic_novel_rules.rs` | 28 exclusive non-CWE zero-day detectors (`AETHER-*`): Trojan Source unicode, compiler soundness flaws, async TLS bleed, and stealth backdoors. |
| `src/plugin.rs` | Declarative plugin engine (`PluginEngine`, `PluginSelection`) executing external YAML security rules with enriched taint/window DSL from `.aether/plugins/`. |
| `src/secret_guard.rs` | Sensitive-file path detector (`SecretGuard`) blocking AI/HTTP access to `.env*`, private keys, certificates, credentials, and service accounts. |
| `src/secret_masker.rs` | In-memory secret redactor (`SecretMasker`) masking API keys (OpenAI/Anthropic/Gemini, GitHub, AWS, Stripe, Slack), JWTs, DB URIs, and PEM blocks. |
| `src/semgrep_importer.rs` | Bidirectional converter translating Semgrep/Nuclei YAML rules into native compiled Rust regular expressions. |
| `src/sarif.rs` | OASIS-compliant SARIF v2.1.0 JSON serializer for GitHub Code Scanning and automated CI/CD security gates. |
| `src/sanitizer_catalog.rs` | Catalog of established sanitizers neutralizing taint flows across injection and traversal categories. |
| `src/community_bundle.rs` | Embedded offline bundle containing 24 OWASP Top 10 and CWE Top 25 community rules. |
| `src/sca/` | Software Composition Analysis (SCA) subsystem: |
| `src/sca/lockfile.rs` | Lockfile parsers for `Cargo.lock`, `package-lock.json` (v1, v2, v3), and `composer.lock`. |
| `src/sca/osv.rs` | Client querying the OSV.dev vulnerability database with ecosystem normalization. |
| `src/sca/cache.rs` | Deterministic offline BLAKE3 cache located in `.aether/cache/osv/`. |
| `src/sca/cross_ref.rs` | Reachability cross-referencing engine filtering dependencies against the AST call-graph. |
| `src/sca/mod.rs` | Public SCA entrypoint, `ScaEngine`, and `ScaReport` data structures. |
| `src/bin/aether_plugin_tool.rs` | Standalone CLI utility (`aether-plugin-tool`) for importing, testing, and managing plugin rules. |
| `src/lib.rs` | Public crate root exporting linter and contract verification interfaces. |

## 🛡️ EARS Architectural Requirements

- WHEN a source file is audited THE SYSTEM SHALL mask comments and string literals before evaluating syntax rules.
- WHEN a rule specifies target file extensions THE SYSTEM SHALL only evaluate that rule on matching file types.
- WHEN a folder contains a `README.md` contract THE SYSTEM SHALL verify its BLAKE3 hash and enforce `effective_max_lines` as an orange warning and `forbidden_imports` as a red violation.
- WHEN lockfiles are detected during an SCA audit THE SYSTEM SHALL cross-reference identified vulnerabilities against the AST call-graph to identify reachable attack paths.
- IF an AI patch or source edit violates contract rules THEN THE SYSTEM SHALL flag violations before committing changes.
