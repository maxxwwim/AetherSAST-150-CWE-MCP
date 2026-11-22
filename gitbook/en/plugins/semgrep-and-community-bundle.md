# Semgrep Importer & Community Bundle

Import existing Semgrep YAML rules into AetherScope `PluginManifest` files or deploy the embedded 24-rule OWASP/CWE Community Bundle 100% offline.

## Offline Community Bundle (`CommunityBundle`)

AetherScope compiles `crates/security-linter/rules/community_owasp_cwe.yaml` directly into the binary via `include_str!` (`crates/security-linter/src/community_bundle.rs`). It requires zero network access in air-gapped environments.

When unpacked via `CommunityBundle::unpack_to_directory`, `SemgrepImporter` converts all **24** embedded Semgrep rules (`0` taint rules; all 24 are pattern-based SAST rules) into `<target_dir>/community/plugin.yaml` with `name: "community"`.

### Deploy the Community Bundle

{% tabs %}
{% tab title="CLI (aether-engine)" %}
```bash
# Unpacks to <project_root>/.aether/plugins/community/plugin.yaml
aether-engine -p . --update-rules
```
{% endtab %}

{% tab title="CLI (aether-plugin-tool)" %}
```bash
# Unpack immediately offline
aether-plugin-tool init-bundle .aether/plugins

# Or attempt online sync with automatic offline bundle fallback
aether-plugin-tool download-semgrep-rules --output .aether/plugins
aether-plugin-tool download-semgrep-rules --offline --output .aether/plugins
```
{% endtab %}

{% tab title="REST API & Cockpit UI" %}
```bash
# Local HTTP route (requires LocalGuard localhost Host/Origin)
curl -X POST http://127.0.0.1:3030/api/plugins/init_bundle
```

In the Cockpit (`G`), open the **Catalogue SAST** tab and click **Déployer (24)**.
{% endtab %}
{% endtabs %}

### Exact 24-Rule Community Catalog

Because `SemgrepImporter::convert_rule` maps Semgrep `ERROR` -> `CRITICAL` and `WARNING` -> `HIGH`, the unpacked `community/plugin.yaml` contains **17 `CRITICAL`** rules and **7 `HIGH`** rules across 11 languages:

| # | Rule ID | Raw Semgrep Severity | Imported Severity | CWE | Target Languages |
|---|---|---|---|---|---|
| 1 | `semgrep-owasp-sqli-format` | `ERROR` | `CRITICAL` | `CWE-89` | `python`, `php`, `javascript`, `typescript` |
| 2 | `semgrep-owasp-command-injection` | `CRITICAL` | `CRITICAL` | `CWE-78` | `python`, `javascript`, `typescript`, `rust`, `php` |
| 3 | `semgrep-owasp-xss-innerhtml` | `ERROR` | `CRITICAL` | `CWE-79` | `javascript`, `typescript` |
| 4 | `semgrep-owasp-path-traversal` | `ERROR` | `CRITICAL` | `CWE-22` | `python`, `javascript`, `typescript`, `php` |
| 5 | `semgrep-owasp-deserialization-pickle` | `CRITICAL` | `CRITICAL` | `CWE-502` | `python`, `php` |
| 6 | `semgrep-owasp-deserialization-yaml` | `ERROR` | `CRITICAL` | `CWE-502` | `python` |
| 7 | `semgrep-owasp-hardcoded-secret` | `CRITICAL` | `CRITICAL` | `CWE-798` | `python`, `javascript`, `typescript`, `rust`, `php`, `go` |
| 8 | `semgrep-owasp-broken-crypto-jwt-none` | `CRITICAL` | `CRITICAL` | `CWE-327` | `python`, `javascript`, `typescript` |
| 9 | `semgrep-owasp-weak-hash-md5-sha1` | `WARNING` | `HIGH` | `CWE-328` | `python`, `javascript`, `typescript`, `rust`, `php` |
| 10 | `semgrep-owasp-ssrf-unvalidated-url` | `ERROR` | `CRITICAL` | `CWE-918` | `python`, `javascript`, `typescript`, `rust`, `php`, `go` |
| 11 | `semgrep-owasp-code-injection-eval` | `CRITICAL` | `CRITICAL` | `CWE-94` | `python`, `javascript`, `typescript`, `php` |
| 12 | `semgrep-owasp-auth-bypass-mock` | `CRITICAL` | `CRITICAL` | `CWE-287` | `python`, `javascript`, `typescript`, `rust`, `go` |
| 13 | `semgrep-owasp-xxe-xml-external-entity` | `ERROR` | `CRITICAL` | `CWE-611` | `python`, `php` |
| 14 | `semgrep-owasp-log-injection-crlf` | `WARNING` | `HIGH` | `CWE-117` | `python`, `javascript`, `typescript`, `java` |
| 15 | `semgrep-owasp-stacktrace-exposure` | `WARNING` | `HIGH` | `CWE-209` | `python`, `javascript`, `typescript`, `php` |
| 16 | `semgrep-owasp-cookie-missing-httponly` | `WARNING` | `HIGH` | `CWE-1004` | `javascript`, `typescript`, `python`, `php` |
| 17 | `semgrep-owasp-insecure-curl-pipe-bash` | `ERROR` | `CRITICAL` | `CWE-494` | `python`, `javascript`, `rust` |
| 18 | `semgrep-cwe-integer-overflow-truncation` | `WARNING` | `HIGH` | `CWE-190` | `rust`, `c`, `cpp` |
| 19 | `semgrep-cwe-use-after-free-pointer` | `CRITICAL` | `CRITICAL` | `CWE-416` | `c`, `cpp`, `rust` |
| 20 | `semgrep-cwe-null-pointer-deref` | `ERROR` | `CRITICAL` | `CWE-476` | `c`, `cpp`, `rust` |
| 21 | `semgrep-cwe-race-condition-toctou` | `WARNING` | `HIGH` | `CWE-362` | `python`, `php`, `c`, `cpp` |
| 22 | `semgrep-cwe-buffer-overflow-strcpy` | `CRITICAL` | `CRITICAL` | `CWE-787` | `c`, `cpp`, `zig` |
| 23 | `semgrep-csharp-binaryformatter-deser` | `CRITICAL` | `CRITICAL` | `CWE-502` | `csharp` |
| 24 | `semgrep-zig-unsafe-ptrcast-runtime` | `HIGH` | `HIGH` | `CWE-843` | `zig` |

## How `SemgrepImporter` Translates Rules

`SemgrepImporter` (`crates/security-linter/src/semgrep_importer.rs`) parses `SemgrepRuleFile` (`rules: Vec<SemgrepRuleDef>`) into a native `PluginManifest` (`author: "AetherScope Semgrep Importer"`, `name: "[Semgrep] <rule.id>"`, `category` defaulting to `"Semgrep / Imported"`).

### Severity, CWE & Language Mapping

| Semgrep Input | AetherScope Output |
|---|---|
| `severity`: `ERROR` / `CRITICAL` | `CRITICAL` |
| `severity`: `WARNING` / `HIGH` / unknown | `HIGH` |
| `severity`: `INFO` / `MEDIUM` | `MEDIUM` |
| `severity`: `LOW` | `LOW` |
| `metadata.cwe`: `"CWE-89: SQL Injection"` | `"CWE-89 / SQL-INJECTION"` |
| `metadata.cwe`: `89` (integer) | `"CWE-89 / GENERAL"` |
| `metadata.cwe`: `"Deserialization"` (text) | `"CWE-699 / DESERIALIZATION"` |
| `metadata.cwe`: missing / empty | `"CWE-699 / GENERAL"` |

`languages_to_extensions` sorts and deduplicates mapped extensions (defaulting to `[".rs"]` if `languages` is empty):
- `rust|rs` -> `[".rs"]`, `python|py` -> `[".py"]`, `javascript|js` -> `[".js", ".jsx", ".mjs", ".cjs"]`, `typescript|ts` -> `[".ts", ".tsx"]`
- `php` -> `[".php", ".phtml"]`, `c` -> `[".c", ".h"]`, `cpp|c++` -> `[".cpp", ".cc", ".hpp", ".h"]`, `solidity|sol` -> `[".sol"]`
- `zig` -> `[".zig"]`, `csharp|cs|c#` -> `[".cs"]`, `go|golang` -> `[".go"]`, `java` -> `[".java"]`, `ruby|rb` -> `[".rb"]`, `json` -> `[".json"]`, `yaml|yml` -> `[".yaml", ".yml"]`

### Pattern, Metavariable & `pattern-not` Translation

- **Metavariables (`$VAR`)**: `$` followed by an ASCII uppercase letter or `_` (e.g. `$X`, `$QUERY`, `$_TMP`) compiles to `([^,;\)\s]+?)`. Identical metavariable names do **not** enforce backreference equality across captures.
- **Literal `$` (PHP/JS)**: `$` not followed by uppercase/`_` (such as `$this` or `$user`) is escaped as `\$`.
- **Ellipsis (`...`)**: `, ...)` translates to `(?:\s*,\s*.*?)?`, `(..., ` translates to `(?:.*?\s*,\s*)?`, and standalone `...` translates to `.*?`.
- **String literal auto-detection**: If any `pattern` or `pattern-either` pattern contains `"` or `'`, `conditions.check_literals` is automatically set to `true` so `AuditContext` does not mask quoted values.
- **Multiline patterns**: If any pattern contains `\n`, `(?s)` is prepended to the regex and `match_mode` becomes `whole_file` (otherwise `line_by_line`).
- **`pattern-regex`**: Copied verbatim into `conditions.regex_patterns` and validated with `Regex::new`.
- **`pattern-not`**: `extract_not_clause_strings` extracts mitigation identifier tokens into `conditions.must_not_contain` (skipping quotes, `$` metavariables, short uppercase fragments, and tokens already present in the primary `pattern`).

### Supported vs. Unsupported Semgrep Constructs

| Construct | Status | Notes |
|---|---|---|
| `rules[].id`, `languages`, `severity`, `message` | Supported | Mapped directly to `PluginRule`. |
| `metadata.{cwe, category, confidence}` | Supported | `cwe` supports single string, list (uses first entry), or integer. |
| `pattern`, `pattern-either`, `pattern-regex`, `pattern-not` | Supported | `pattern-either` accepts bare strings or `{ pattern / pattern-regex }` objects. |
| `patterns` (boolean AND), `pattern-inside`, `pattern-not-inside`, `pattern-not-regex` | Not supported | Ignored during YAML deserialization; refine manually in DSL v2. |
| `metavariable-regex`, `metavariable-comparison`, `mode: taint`, `fix`, `paths` | Not supported | Use `sast-taint-dsl.md` `taint_sources` / `taint_sinks` / `in_path_matching` instead. |

## Worked Example: Semgrep YAML to `PluginManifest`

Below is the exact conversion output stored in `.aether/plugins/imported/sample-semgrep/plugin.yaml`:

{% code title=".aether/plugins/imported/sample-semgrep/plugin.yaml" overflow="wrap" %}
```yaml
name: sample-semgrep
version: 1.0.0
author: AetherScope Semgrep Importer
description: 'Imported from Semgrep rule set: sample-semgrep'
enabled: true
rules:
- id: python-deserialization-pickle
  cwe_id: CWE-502 / DESERIALIZATION-OF-UNTRUSTED-DATA
  name: '[Semgrep] python-deserialization-pickle'
  category: security
  severity: CRITICAL
  description: Avoid using pickle.loads() with untrusted data as it can lead to arbitrary code execution.
  remediation: Review code matching rule 'python-deserialization-pickle'. Avoid insecure patterns and validate all inputs.
  file_extensions:
  - .py
  match_mode: line_by_line
  conditions:
    must_contain: []
    must_not_contain:
    - safe_loader
    regex_patterns:
    - pickle\.loads\s*\(\s*([^,;\)\s]+?)\s*\)
    forbidden_tokens: []
    check_literals: false
  test_cases: []
- id: jwt-none-algorithm
  cwe_id: CWE-327 / USE-OF-A-BROKEN-OR-RISKY-CRYPTOGRAPHIC-ALGORITHM
  name: '[Semgrep] jwt-none-algorithm'
  category: security
  severity: HIGH
  description: JWT algorithm 'none' should not be permitted in production.
  remediation: Review code matching rule 'jwt-none-algorithm'. Avoid insecure patterns and validate all inputs.
  file_extensions:
  - .cjs
  - .js
  - .jsx
  - .mjs
  - .py
  match_mode: line_by_line
  conditions:
    must_contain: []
    must_not_contain: []
    regex_patterns:
    - jwt\.decode\s*\(\s*(?:.*?\s*,\s*)?\s+algorithms\s*=\s*\s*\[\s*'none'\s*\](?:\s*,\s*.*?)?\s*\)
    forbidden_tokens: []
    check_literals: true
  test_cases: []
```
{% endcode %}

Notice how `jwt-none-algorithm` automatically enabled `check_literals: true` because `'none'` is a string literal, while `python-deserialization-pickle` kept `check_literals: false` and extracted `safe_loader` from `pattern-not` into `must_not_contain`.

## `aether-plugin-tool` CLI Workflow

The companion `aether-plugin-tool` binary (`crates/security-linter/src/bin/aether_plugin_tool.rs`) handles scaffolding, Semgrep importing, rule listing, unit testing, and standalone scans:

```bash
# 1. Scaffold a starter plugin manifest with 2 embedded unit tests
aether-plugin-tool init my-org-rules .aether/plugins

# 2. Import a file or directory of Semgrep YAML rules into .aether/plugins/imported/
aether-plugin-tool import-semgrep --input ./semgrep-rules --output .aether/plugins/imported

# 3. Install the 24-rule offline Community Bundle
aether-plugin-tool init-bundle .aether/plugins

# 4. List all loaded plugins, CWE IDs, severities, and extensions
aether-plugin-tool list .aether/plugins

# 5. Execute all embedded rule test_cases (exits 1 if any test fails)
aether-plugin-tool test .aether/plugins

# 6. Run a plugin-only scan against a directory and export a Markdown catalog
aether-plugin-tool scan .aether/plugins ./src
aether-plugin-tool export .aether/plugins PLUGIN_CATALOG.md
```

{% hint style="info" %}
In the Cockpit UI (`G`), you can also import rules via the **Import Semgrep** tab (`POST /api/plugins/import_semgrep`) or upload a Semgrep `.yaml`/`.yml` file directly in **Catalogue SAST**—`PluginsModal` detects `pattern-either:`, `pattern:`, or `languages:` and routes you straight to the Semgrep converter.
{% endhint %}

{% content-ref url="sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[Plugin, MCP & Runner CLIs](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
