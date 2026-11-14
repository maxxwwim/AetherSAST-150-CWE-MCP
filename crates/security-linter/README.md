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
# 🛡️ security-linter — Moteur SAST 215 Règles (CWE + AETHER-*), Lexer & Contrats BLAKE3 (v2.4.0)

Moteur d'audit statique temps réel évaluant 215 règles de sécurité (CWE Zero-Day & détecteurs hors-CWE `AETHER-*`), doublé d'un validateur de contrats d'architecture `README.md` (règles EARS, budgets `max_lines_per_file` par dossier et surcharges `file_max_lines` par fichier) scellés par empreinte cryptographique BLAKE3.

## 📦 Contenu

| Fichier | Rôle |
| :--- | :--- |
| `src/contract.rs` | Parseur/Éditeur de frontmatter YAML (`max_lines_per_file`, `file_max_lines`, `effective_max_lines`, `upsert_contract_content`), règles EARS et hachage BLAKE3 (`compute_blake3_hex`) |
| `src/lexer.rs` | Masquage lexical double passe des commentaires et littéraux (anti-faux-positifs) |
| `src/rules.rs` | Règles avancées DeFi, Smart Contracts, Oracles et suivi de teinte intra-fichier |
| `src/deep_rules.rs` | Règles bas-niveau Rust/LLVM/UB/ABI, ZK-SNARKs et machines virtuelles distribuées |
| `src/php_rules.rs` | 25 règles de sécurité dédiées à l'écosystème PHP Web & API |
| `src/zig_rules.rs` | 15 règles Zig Systems, pointeurs, SIMD et interopérabilité C-ABI |
| `src/csharp_rules.rs` | 20 règles C# / .NET 8+ et ASP.NET Core |
| `src/epic_novel_rules.rs` | 28 règles exclusives hors-CWE (`AETHER-*`) : failles runtime/compilateur, backdoors invisibles et RCE furtives |
| `src/linter.rs` | Orchestrateur central des 215 règles, routage par extension et remédiations |

## 🛡️ Règles EARS

- WHEN a source file is audited THE SYSTEM SHALL mask comments and string literals before evaluating syntax rules.
- WHEN a rule specifies file extensions THE SYSTEM SHALL only evaluate that rule on matching file types.
- WHEN a folder contains a `README.md` contract THE SYSTEM SHALL verify its BLAKE3 hash and enforce `effective_max_lines` (`file_max_lines` override or `max_lines_per_file`) as an orange `WARNING` (`RULE_MAX_LINES`) and `forbidden_imports` as a red `CRITICAL`/`HIGH` violation.
