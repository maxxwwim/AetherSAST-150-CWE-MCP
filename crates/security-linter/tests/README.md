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
| `php_rules_tests.rs` | 25 règles PHP |
| `zig_rules_tests.rs` | 15 règles Zig (mémoire, C-ABI, `@Vector` SIMD, OS/FS, crypto) |
| `csharp_rules_tests.rs` | 20 règles C# / .NET (ASP.NET Core, EF Core, JWT, TLS, ReDoS, `stackalloc`) |
| `self_scan.rs` | Le linter audite son propre code source |

Lancer : `cargo test -p security-linter`.

## 🛡️ Règles EARS

- WHEN a new rule is added THE SYSTEM SHALL have at least one positive and one negative test.
- WHEN the self-scan runs THE SYSTEM SHALL report no critical violation on the repository sources.
