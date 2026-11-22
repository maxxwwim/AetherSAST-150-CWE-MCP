# CWE & SAST Engine

Analyze polyglot source trees and dependency lockfiles in real time using 223 native security detectors, 24 embedded Semgrep OWASP/CWE rules (247 rules total), dual-pass lexical masking, and reachable OSV vulnerability correlation.

## Architecture & Rule Breakdown

The `security-linter` crate runs deterministic static analysis alongside EARS architectural contract checks and reachable Software Composition Analysis (SCA). All native rules are registered through `SecurityLinter::get_supported_cve_rules()` across seven Rust modules, supplemented by an embedded Semgrep community bundle.

| Source Module / Asset | Rust Entrypoint | Rules | Primary Scope |
|---|---|---:|---|
| `crates/security-linter/src/linter.rs` | `SecurityLinter::get_supported_cve_rules()` | **101** | Rust/Network (14 incl. 1 L1), L1/Web3/Crypto (34), MMO/Concurrency (5), SAST/Injection (17), Architecture/Boundary (7), Front-End/DOM (13), C/C++ FFI & Network (11) |
| `crates/security-linter/src/rules.rs` | `AdvancedDefiRules::definitions()` | **6** | DeFi invariants (`DEFI-ASYMMETRIC-ROUNDING`, `DEFI-STALE-CACHE-AFTER-CALL`, `EVC-HOOK-BYPASS`) and Oracle circuit breakers |
| `crates/security-linter/src/deep_rules.rs` | `DeepSecurityRules::definitions()` | **27** | ZK-SNARKs, DeFi read-only reentrancy, Account-Model VMs, Rust/LLVM/ABI/Unwind/Mmap soundness, Wasm, L2 Rollups, ERC-4337, `CVE-INJ-*` |
| `crates/security-linter/src/php_rules.rs` | `PhpSecurityRules::definitions()` | **26** | PHP 8.x & Web Security (SQLi, RCE, `unserialize`, LFI/RFI, `phar://`/`php://filter`, SSTI, XXE, type juggling) |
| `crates/security-linter/src/zig_rules.rs` | `ZigSecurityRules::definitions()` | **15** | Zig allocators, UAF, `@ptrCast`, `@setRuntimeSafety(false)`, C-ABI interop, SIMD `@Vector`, TLS, PRNG |
| `crates/security-linter/src/csharp_rules.rs` | `CSharpSecurityRules::definitions()` | **20** | C# / .NET / ASP.NET Core / EF Core (`BinaryFormatter`, SQLi, `Process.Start`, `Path.Combine`, `stackalloc`, reflection) |
| `crates/security-linter/src/epic_novel_rules.rs` | `EpicNovelRules::definitions()` | **28** | Non-CWE `AETHER-*` semantic flaws, Trojan Source Unicode, and covert RCE/compile-time backdoors |
| **Native Subtotal** | `SecurityLinter::get_supported_cve_rules()` | **223** | **223** unique `rule_id`s, **52** category strings, **84** distinct `CWE-NNN` IDs (**88** total with Community Bundle) |
| `crates/security-linter/rules/community_owasp_cwe.yaml` | `CommunityBundle::load_embedded_manifest()` | **24** | Embedded Semgrep OWASP Top 10 & CWE Top 25 bundle (`22` distinct `CWE-NNN` IDs) |
| **Grand Total** | Native + Embedded Community Bundle | **247** | Unpacked to `.aether/plugins/community/plugin.yaml` via `--update-rules` or `aether-plugin-tool init-bundle` |

Across the **223 native rules**, severities break down as **134 `CRITICAL`**, **83 `HIGH`**, **4 `MEDIUM`**, and **2 `WARNING`** (`RULE_MAX_LINES` and `RULE_MAX_FILES`).

{% hint style="info" %}
**Version 2.6.0 Rule Count Note:** Legacy repository files (`crates/security-linter/README.md`, `CWE_CATALOG.md`, and `cwe/README.md`) still mention `222 + 24 = 246` rules from v2.5.1. Direct inspection of `crates/security-linter/src/` confirms **223 native rules + 24 community rules = 247 total rules** in `aether-engine` v2.6.0.
{% endhint %}

## `SecurityLinter` API & Violation Model

Every native detector and folder-contract rule emits a `LinterViolation` struct, while `CveRuleDef` describes rule metadata and file eligibility.

### 📝 `LinterViolation` & `CveRuleDef` Structs

| Struct | Field | Type | Description |
|---|---|---|---|
| `LinterViolation` | `file_path` | `String` | Relative or normalized path of the audited file. |
| `LinterViolation` | `line_number` | `usize` | 1-indexed source line where the violation occurred. |
| `LinterViolation` | `rule_id` | `String` | Unique rule identifier (for example `CVE-RUST-ASYNC-MUTEX` or `AETHER-RUST-EPHEMERAL-LOCK-DROP`). |
| `LinterViolation` | `cve_id` | `String` | CWE / taxonomy label (for example `CWE-667 / ASYNC-DEADLOCK`). |
| `LinterViolation` | `severity` | `String` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or `"WARNING"` (custom plugins may also emit `"LOW"`). |
| `LinterViolation` | `message` | `String` | Human-readable finding summary. |
| `LinterViolation` | `transmitted_data` | `Option<String>` | Optional matched snippet or parameter payload (`skip_serializing_if = "Option::is_none"`). |
| `LinterViolation` | `transmitted_type` | `Option<String>` | Optional sink/data type descriptor (`skip_serializing_if = "Option::is_none"`). |
| `LinterViolation` | `remediation` | `String` | Actionable fix guidance displayed in Cockpit, CLI, and SARIF outputs. |
| `CveRuleDef` | `rule_id` | `String` | Unique rule ID returned by `get_supported_cve_rules()`. |
| `CveRuleDef` | `cve_id` | `String` | Associated CWE or `AETHER-*` taxonomy string. |
| `CveRuleDef` | `name` | `String` | Rule title. |
| `CveRuleDef` | `category` | `String` | Grouping string (52 distinct values across the native catalog). |
| `CveRuleDef` | `severity` | `String` | Rule severity (`CRITICAL`, `HIGH`, `MEDIUM`, or `WARNING`). |
| `CveRuleDef` | `description` | `String` | Detailed vulnerability explanation. |
| `CveRuleDef` | `default_enabled` | `bool` | Whether the rule runs by default (`true` for all 223 native rules). |

### 🎮 Signature / Endpoint

```rust
use security_linter::lexer::AuditContext;
use security_linter::linter::{CveRuleDef, LinterViolation, SecurityLinter};
use security_linter::plugin::{PluginEngine, PluginSelection};

pub fn get_supported_cve_rules() -> Vec<CveRuleDef>;

pub fn audit_file(
    file_path: &str,
    content: &str,
    contract: Option<&ReadmeContract>,
) -> Vec<LinterViolation>;

pub fn audit_file_with_context(
    ctx: &AuditContext<'_>,
    contract: Option<&ReadmeContract>,
) -> Vec<LinterViolation>;

pub fn audit_file_selected(
    ctx: &AuditContext<'_>,
    contract: Option<&ReadmeContract>,
    selection: &PluginSelection,
) -> Vec<LinterViolation>;

pub fn audit_file_with_plugins(
    file_path: &str,
    content: &str,
    contract: Option<&ReadmeContract>,
    plugin_engine: &mut PluginEngine,
) -> Vec<LinterViolation>;
```

### 📝 Arguments / Parameters

| Method | Parameter | Type | Description |
|---|---|---|---|
| `audit_file` | `file_path` | `&str` | File path used for language/extension routing and test-file filtering. |
| `audit_file` | `content` | `&str` | Raw UTF-8 source text of the file. |
| `audit_file` | `contract` | `Option<&ReadmeContract>` | Optional parent folder EARS contract (`README.md` frontmatter). |
| `audit_file_with_context` | `ctx` | `&AuditContext<'_>` | Shared per-file masking context (`OnceLock`) reused across `SecurityLinter` and `PluginEngine`. |
| `audit_file_selected` | `selection` | `&PluginSelection` | Parsed `--plugins` selector (`Default`, `Auto`, `All`, or `Select(Vec<String>)`). |
| `audit_file_with_plugins` | `plugin_engine` | `&mut PluginEngine` | Runs native rules plus enabled YAML/JSON rules from `.aether/plugins/`. |

### 💎 Return Value / Response

| Method | Return Type | Semantics |
|---|---|---|
| `get_supported_cve_rules` | `Vec<CveRuleDef>` | Returns all **223** native rule definitions; each supports `.target_file_types()` and `.matches_file(path)`. |
| `audit_file*` | `Vec<LinterViolation>` | Returns all dual-pass verified violations for the file. |

### 💡 Example

```rust
use security_linter::lexer::AuditContext;
use security_linter::linter::SecurityLinter;

let source = "pub async fn handler(lock: &std::sync::Mutex<u64>) { let _g = lock.lock(); foo().await; }";
let ctx = AuditContext::new("src/server.rs", source);
let violations = SecurityLinter::audit_file_with_context(&ctx, None);
assert!(violations.iter().any(|v| v.rule_id == "CVE-RUST-ASYNC-MUTEX"));
```

## Dual-Pass Lexical Masking (`AuditContext`)

To stop heuristic rules from firing on comments, docstrings, error messages, or string literals, `crates/security-linter/src/lexer.rs` implements a zero-regex lexical masker shared by `SecurityLinter` and `PluginEngine`.

### Supported `Lang` Variants & Extension Mapping

| `Lang` Variant | Matched Extensions | Lexical Rules Handled |
|---|---|---|
| `Lang::Rust` | `.rs` | `//` line comments, nested `/* ... */` block comments, raw strings (`r"..."`, `r#"..."#`, `br#"..."#`), char literals vs `'a` lifetimes |
| `Lang::Python` | `.py` | `#` comments, single/double quotes, triple-quoted strings (`"""..."""`, `'''...'''`) |
| `Lang::Zig` | `.zig` | `//` comments, `\\` multiline string literals, char literals, double-quoted strings |
| `Lang::CSharp` | `.cs` | `//`, `/* */`, verbatim strings (`@"..."`, `$@"..."`, `@$"..."` with `""`), interpolated `$"..."`, char literals |
| `Lang::Php` | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps` | `//`, `/* */`, `#` comments, single and double-quoted strings |
| `Lang::CLike` | `.js`, `.ts`, `.tsx`, `.jsx`, `.mjs`, `.cjs`, `.sol`, `.circom`, `.c`, `.cpp`, `.cc`, `.h`, `.hpp`, `.java` | `//`, `/* */`, `'`, `"`, template backticks `` ` `` |

### `mask_literals` vs. `mask_comments_only` & `LITERAL_AWARE_RULES`

`AuditContext<'a>` computes `masked_literals` and `masked_comments` lazily at most once per file via `std::sync::OnceLock<String>`, preserving delimiters, `\r`, and `\n` so every line number stays exact:

1. **`mask_literals(src, lang)`**: Replaces both comments and string-literal interiors with `' '`.
2. **`mask_comments_only(src, lang)`**: Replaces only comments with `' '`, keeping string literals intact.
3. **`AuditContext::default_masked()`**: Returns `masked_comments()` for `Lang::Python` and `Lang::Php` (because Python/PHP rules inspect SQL queries, superglobals, and headers inside strings), `masked_literals()` for `Rust`, `CLike`, `Zig`, and `CSharp`, and `raw` when `lang` is `None`.

In `SecurityLinter::audit_file_with_context`, the engine runs `audit_file_raw` on `ctx.raw` first. If `ctx.lang.is_some()` and raw findings exist, it runs a second pass on `ctx.default_masked()` and keeps a violation **only if** either:
- the `(rule_id, line_number)` pair also triggers on the masked pass, **or**
- `rule_id` belongs to **`LITERAL_AWARE_RULES`** (`linter.rs:1080-1155`, **74 rules** that intentionally inspect string contents, including `SAST_HARDCODED_SECRET`, `SAST_RAW_SQL_INJECTION`, `CVE-WEB3-AUTH-BYPASS-MOCK`, `SAST_DIRECT_ENV_ACCESS`, the 5 folder-contract `RULE_*` rules, `CVE-DB-REDIS-UNAUTH-KEYS-DOS`, `CVE-RUST-COMMAND-INJECTION-SHELL`, `CVE-CPP-NET-FORMAT-STRING-LOGGING`, `CVE-INJ-*`, all 26 `CVE-PHP-*` rules, all 20 `CVE-CS-*` rules, 4 `CVE-ZIG-*` rules, and 8 `AETHER-*` rules).

### Scope Stripping & Test Exemptions

- **Self-exclusion (`is_linter_catalog`)**: Skips `security-linter/src/` catalog source files (`linter.rs`, `rules.rs`, `deep_rules.rs`, `epic_novel_rules.rs`, `php_rules.rs`, `zig_rules.rs`, `csharp_rules.rs`, `lexer.rs`) so rule definitions never self-trigger.
- **Test, fixture, and tool exclusion (`is_test_file`)**: Skips `/test/`, `/tests/`, `/testing/`, `/testsuite/`, `/pytest/`, `integration-tests`, `test-loop-tests`, `test-utils`, `testlib`, `test-contracts`, `runtime-params-estimator`, `adversarial`, `/benches/`, `/benchmarks/`, `/examples/`, `/fixtures/`, `/testdata/`, `/genesis-tools/`, `/devtools/`, `/buildtools/`, `/tools/`, `debug_scripts`, `/mock`, `/fuzz/`, `/certora/`, `/script/`, `/scripts/`, `tests.rs`, `test.rs`, `testing.rs`, `test_utils.rs`, `bench.rs`, `benches.rs`, `build.rs`, `*_test.rs`, `*_tests.rs`, `*.pb.rs`, `*.generated.rs`, `*_generated.rs`, `test_*`, `*.t.sol`, and `*.s.sol`.
- **`build.rs` exception in `epic_novel_rules.rs`**: `EpicNovelRules::audit_file` explicitly overrides `is_test_file` for `build.rs` (`is_test_file && !is_build_script`) so `AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR`, `AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR`, `AETHER-RUST-FILELESS-WX-MEMFD-RCE`, `AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE`, and `AETHER-STEALTH-UNICODE-TROJAN-SOURCE` still inspect compile-time build scripts.
- **Rust inline test stripping (`strip_rust_inline_tests`)**: Truncates `.rs` files at the first `#[cfg(test)]`, `#[cfg(all(test...))]`, `mod tests {`, or `mod test {`, and skips individual `#[test]`, `#[tokio::test...]`, and `#[cfg(feature = "test_features"...)]` items.
- **Zig inline `test` nuance**: `ast-scanner` defines `strip_zig_inline_tests` for AST symbol extraction (`analyze_zig`), whereas `SecurityLinter` and `zig_rules.rs` do **not** strip inline `test "..." { ... }` blocks inside production `.zig` files (only files matching `is_test_file` path patterns are skipped).
- **Interfaces & types exemption (`is_interface_or_types`)**: Skips `/interface`, `interface.sol`, `.d.ts`, `I[A-Z]*.sol`, `I[A-Z]*.java`, `/types/`, pure Solidity `interface` files without `contract`, and Java `interface` files. Explicit `file_max_lines` overrides in `README.md` still enforce `RULE_MAX_LINES`.

## Reachable OSV SCA Pipeline (`sca/*`)

Beyond source patterns, `security-linter` parses dependency lockfiles, queries `api.osv.dev` (with an offline BLAKE3 cache), and computes whether vulnerable library functions are actually reachable from your codebase entrypoints.

```text
Lockfiles (Cargo.lock / package-lock.json / composer.lock)
   │  sca/lockfile.rs :: scan_project_lockfiles()
   ▼
OSV Lookup (cache-first -> curl https://api.osv.dev/v1/query unless --offline-sca)
   │  sca/cache.rs    :: .aether/cache/osv/<blake3_hex>.json
   ▼
Call-Graph Sink Attachment (dep::<pkg>::<fn> -> «Vulnerable Dependency»)
   │  sca/cross_ref.rs :: cross_reference_reachability()
   ▼
Reverse BFS Reachability (core_graph::reachability::compute_reachability)
   └─► is_reachable = true/false + shortest exploit_path[]
```

### Supported Lockfiles

`scan_project_lockfiles` (`crates/security-linter/src/sca/lockfile.rs:287-322`) inspects the project root and immediate 1-level subdirectories (skipping `target`, `node_modules`, and `.git`) for **exactly three lockfiles**:

| Lockfile | Parser Function | Supported Formats | OSV Ecosystem |
|---|---|---|---|
| `Cargo.lock` | `parse_cargo_lock_content` | TOML <code>&#91;&#91;package&#93;&#93;</code> entries with `registry+` or `git+` `source` | `crates.io` |
| `package-lock.json` | `parse_package_lock_content` | npm lockfile **v1** (recursive `dependencies`) and **v2 / v3** (flat `packages`), tracking `dev` flag | `npm` |
| `composer.lock` | `parse_composer_lock_content` | `"packages"` (`is_dev: false`) and `"packages-dev"` (`is_dev: true`), normalizing leading `v` | `Packagist` |

{% hint style="warning" %}
**Unsupported Lockfiles (`pnpm-lock.yaml`, `requirements.txt`):** `sca/lockfile.rs` parses **only** `Cargo.lock`, `package-lock.json`, and `composer.lock`. `pnpm-lock.yaml` and `requirements.txt` are **not** parsed by the SCA engine (passing anything else to `parse_lockfile_path` returns `Err("Unsupported lockfile type")`).
{% endhint %}

### Deterministic BLAKE3 OSV Cache & Reachability

- **Cache path & key (`sca/cache.rs`)**: Stored at `<project_root>/.aether/cache/osv/<blake3_hex>.json`, where `<blake3_hex>` is `blake3::hash("{ecosystem}:{package}:{version}".as_bytes()).to_hex()`.
- **Cache seeding**: `OsvCache::get` reads `OsvCacheEntry` (`cache_version: 1`) and also tolerates raw `{"vulns": [...]}` (`OsvQueryResponse`) or `Vec<OsvVulnerability>` JSON files for air-gapped seeding.
- **Online vs. offline query (`sca/osv.rs`)**: Online mode invokes `curl -sSL --max-time 5 -X POST -H "Content-Type: application/json" -d <payload> https://api.osv.dev/v1/query` and falls back cleanly on network errors. Passing `--offline-sca` returns empty results on cache miss with zero socket traffic.
- **Call-graph correlation (`sca/cross_ref.rs`)**: Materializes sink nodes (`dep::<pkg>::<fn>`, `crate::<pkg>::<fn>`, or `dep::<pkg>`) with stereotype `"«Vulnerable Dependency»"` and rule ID `SCA-<advisory_id>`, links matching `metadata.methods[*].calls` via `EdgeType::Call`, and invokes `core_graph::reachability::compute_reachability(graph)` to set `is_reachable`, shortest `exploit_path`, `reachable_count`, and `unreachable_count`.

### SCA & Rule CLI Flags

{% tabs %}
{% tab title="Full SAST + Reachable SCA" %}
```bash
# Run native + plugin SAST together with online OSV reachability
aether-engine --path . --audit-only --sca --format sarif --output results.sarif
```
{% endtab %}
{% tab title="Air-Gapped Offline SCA" %}
```bash
# Force 100% offline cache-only OSV lookups (.aether/cache/osv/)
aether-engine --path . --audit-only --sca --offline-sca
```
{% endtab %}
{% tab title="SCA-Only Gate & Bundle Unpack" %}
```bash
# Run standalone lockfile + reachability audit and fail only on reachable HIGH+ CVEs
aether-engine --path . --sca-only --fail-on HIGH

# Unpack the 24 embedded Semgrep rules into .aether/plugins/community/plugin.yaml
aether-engine --path . --update-rules
```
{% endtab %}
{% endtabs %}

## SARIF v2.1.0 Output & CI/CD Quality Gates

`crates/security-linter/src/sarif.rs` serializes findings into OASIS SARIF v2.1.0 for GitHub Code Scanning and CI pipelines:

- **`$schema`**: `https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json` (`version: "2.1.0"`).
- **`tool.driver`**: `name: "AetherScope"`, `version: "2.6.0"` (`env!("CARGO_PKG_VERSION")`), `informationUri: "https://github.com/aether-engine"`.
- **Severity mapping (`severity_to_sarif_level`)**: `CRITICAL` / `HIGH` -> `"error"`, `MEDIUM` -> `"warning"`, `LOW` / `WARNING` / `INFO` / `NOTE` -> `"note"`.
- **URIs & snippets**: `normalize_sarif_uri_with_root` strips Windows `\\?\` prefixes, converts `\` to `/`, strips `project_root`, sets `uriBaseId: "%SRCROOT%"`, clamps `startLine` to `>= 1`, and attaches `is_reachable`, `exploit_path`, `cveId`, `remediation`, `transmittedData`, and `transmittedType` inside `properties`.
- **Help links (`cwe_to_help_uri`)**: Links `CWE-NNN` findings to `https://cwe.mitre.org/data/definitions/<NNN>.html` and `AETHER-*` detectors to `https://github.com/aether-engine/blob/main/CWE_CATALOG.md#<lowercase_rule_id>`.

### CLI Format & Gate Semantics

| Flag | Accepted Values | Behavior |
|---|---|---|
| `--format` | `text` (default), `markdown`, `sarif` | `sarif` emits SARIF v2.1.0 JSON (to `-o/--output` or stdout). Both `text` and `markdown` generate `.aether/LIVE_AUDIT.md`, print a console summary, and copy to `-o/--output` if given. |
| `-o`, `--output` | `<PATH>` | Destination path for SARIF JSON or copied `LIVE_AUDIT.md` (parent directories are created automatically). |
| `--fail-on` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING` | Exits with code **`1`** if blocking findings match or exceed the threshold (`HIGH` catches `CRITICAL\|HIGH`; `MEDIUM` catches `CRITICAL\|HIGH\|MEDIUM`; `LOW\|WARNING` catches all five). |

{% hint style="warning" %}
**There is no `--format json` flag:** `crates/desktop-shell/src/main.rs` checks only `--format sarif` versus non-SARIF (`text` / `markdown`). Also note two `--fail-on` nuances: in `--audit-only`, findings with `taint_trace.is_sanitized == true` are **skipped** from the failure gate; in `--sca-only`, **only** `is_reachable == true` vulnerabilities can trigger exit code `1`.
{% endhint %}

### 💡 Example: GitHub Actions SARIF Workflow

```yaml
# .github/workflows/aetherscope-sarif.yml
- name: Run AetherScope SAST Audit (SARIF + CI Gate)
  run: |
    aether-engine --path . --audit-only --format sarif --output results.sarif --fail-on HIGH
- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Suppression, Filtering & `--plugins` Selectors

{% hint style="danger" %}
**Inline `// aether-ignore` and `# aether-ignore` comments are NOT implemented:** Adding `// aether-ignore`, `# aether-ignore`, `# noqa`, or `// nolint` in source code has no effect in `aether-engine` v2.6.0. Use the supported mechanisms below instead.
{% endhint %}

1. **`.aether/settings.json` (`SettingsPayload`)**:
   - `active_cve_rules`: Optional allowlist of native `rule_id`s. Contract rules (`BLAKE3_TAMPERED`, `RULE_MAX_LINES`, `RULE_MAX_FILES`, `RULE_FORBIDDEN_FUNCTION`, `RULE_FORBIDDEN_EXTENSION`) and plugin/taint rules remain active unless `active_cve_rules` is `[]`.
   - `ignored_cwes`: Case-insensitive substring matches checked against both `rule_id` and `cve_id` (for example `"CWE-89"` or `"CVE-RUST-PANIC-DOS"`).
   - `exclusions`: Folder or path exclusions passed to `ProjectScanner::scan_project_with_exclusions`.
   - **Scope warning**: `apply_settings_filters_to_graph` runs in the Cockpit, HTTP server (`POST /api/settings`), and FileWatcher pipeline—it is **not** applied during headless `aether-engine --audit-only` CLI runs.
2. **`// SAFETY:` annotations (`[-6..+4]` lines)**:
   - Placing `// SAFETY:`, `// SAFE:`, or `/* SAFETY:` within 6 lines above to 4 lines below an `unsafe` block or `std::mem::transmute` suppresses `CVE-RUST-UNSAFE-MEM` and `CVE-RUST-TRANSMUTE-SIZE-MISMATCH`.
3. **EARS folder contracts (`README.md` frontmatter)**:
   - Configure `security_rules.no_raw_sql`, `security_rules.no_env_access`, `forbidden_imports`, `forbidden_functions`, `allowed_extensions` / `forbidden_extensions`, and `file_max_lines`.
4. **`--plugins` CLI selectors**:
   - `default` (omitted): runs all **223** native rules plus all enabled `.aether/plugins/` manifests.
   - `auto` or `all`: runs all native rules plus matching `.aether/plugins/` manifests.
   - `<pack1>,<pack2>,profile:<name>`: filters native rules against built-in pack aliases (`rust`, `rust-l1`, `web3`, `solidity`, `defi`, `python`, `js`, `ts`, `php`, `zig`, `csharp`, `dotnet`, `cpp`, `deep`, `epic`, `novel`, `architecture`, `core`) and filters local plugins by `name`, `folder_alias`, `profile`, or `tags`. Invalid selectors exit with code `1`.

{% code title=".aether/settings.json" overflow="wrap" %}
```json
{
  "exclusions": ["vendor/", "legacy-fixtures/"],
  "ignored_cwes": ["CVE-RUST-PANIC-DOS", "CWE-829"],
  "active_cve_rules": null
}
```
{% endcode %}

## Related Guides

{% content-ref url="cwe-catalog-reference.md" %}
[CWE & Rule Catalog Reference](cwe-catalog-reference.md)
{% endcontent-ref %}

{% content-ref url="ssa-dataflow-taint.md" %}
[SSA Dataflow & Taint Engine](ssa-dataflow-taint.md)
{% endcontent-ref %}

{% content-ref url="blake3-governance.md" %}
[BLAKE3 Governance & EARS Contracts](blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../console/aether-engine-cli.md" %}
[aether-engine CLI Reference](../console/aether-engine-cli.md)
{% endcontent-ref %}
