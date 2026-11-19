---
id: security-linter-tests
layer: test
max_lines_per_file: 900
allowed_imports: ["security_linter::*", "core_graph::*", "tokio::*", "std::*"]
forbidden_imports: []
---
# 🧪 tests — Tests d'intégration du linter

| Fichier | Rôle |
| :--- | :--- |
| `deep_rules_tests.rs` | Règles bas niveau (Rust LLVM/UB/ABI, ZK, VM) |
| `php_rules_tests.rs` | 26 règles PHP 8.x / WordPress |
| `zig_rules_tests.rs` | 15 règles Zig (mémoire, C-ABI, `@Vector` SIMD, OS/FS, crypto) |
| `csharp_rules_tests.rs` | 20 règles C# / .NET (ASP.NET Core, EF Core, JWT, TLS, ReDoS, `stackalloc`) |
| `epic_novel_rules_tests.rs` | 28 détecteurs exclusifs hors-CWE (`AETHER-*`, backdoors, RCE furtives) |
| `community_bundle_tests.rs` | Bundle embarqué de 24 règles Semgrep OWASP/CWE |
| `sca_tests.rs` | Parseurs lockfiles (`Cargo.lock`, `package-lock.json`, `composer.lock`), cache OSV BLAKE3 et atteignabilité |
| `secret_protection_tests.rs` | `SecretGuard` & `SecretMasker` (blocage `.env`/clés privées et masquage `[REDACTED]`) |
| `challenger_m3_tests.rs` | Tests adversariaux SCA & plugins |
| `self_scan.rs` | Le linter audite son propre code source |

Lancer : `cargo test -p security-linter`.

## 🛡️ Règles EARS

- WHEN a new rule is added THE SYSTEM SHALL have at least one positive and one negative test.
- WHEN the self-scan runs THE SYSTEM SHALL report no critical violation on the repository sources.
