# Declarative SAST & Taint DSL v2

Author custom pattern-based SAST rules, AST-scoped guards, unit-test gates, and inter-procedural SSA taint sources, sinks, and sanitizers in YAML or JSON under `.aether/plugins/`.

## Evaluation Pipeline Order

When `PluginEngine::audit_file_with_context` evaluates a file (`crates/security-linter/src/plugin.rs`), each enabled plugin rule runs through seven deterministic stages:

1. **Extension filter (`file_extensions`)**: Lowercased path suffixes checked via `lower_path.ends_with(ext)`. Empty list matches all non-Markdown files (`ast-scanner` skips `.md` SAST).
2. **Exclusion path globs (`not_in_path_matching`)**: Compiled via `glob_to_regex` (`(?i)^...$`). Checked **before** `in_path_matching`; if excluded, the rule skips the file even if `in_path_matching` also matches.
3. **Inclusion path globs (`in_path_matching`)**: If non-empty, the normalized path must match at least one glob.
4. **Content mode (`check_literals`)**: `false` (default) uses `AuditContext::default_masked()` (string literals and comments replaced with spaces while preserving line numbers); `true` uses raw source (`ctx.raw`).
5. **Whole-file `must_contain`**: All listed substrings must appear anywhere in `eval_content`, or the rule skips the file.
6. **Whole-file `must_not_contain`**: If **any** listed substring appears anywhere in `eval_content`, the entire rule is suppressed for that file.
7. **Match mode execution (`match_mode`)**: Evaluates `whole_file` (emits at line `1`) or `line_by_line` (checks `ast_scope`, `forbidden_tokens` / `regex_patterns` / `must_contain` fallback, and `not_preceded_within_lines`).

{% hint style="info" %}
Emitted plugin findings automatically prefix `rule.description` with `[Plugin: <plugin.name>] ` and deduplicate `(rule.id, line_number)` per file.
{% endhint %}

## Manifest Schema (`PluginManifest`)

Place each pack inside `.aether/plugins/<pack-name>/plugin.yaml` (or `.yml` / `.json`). `PluginEngine` populates `folder_alias` automatically from the immediate parent directory name.

### 📝 `PluginManifest` Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `string` | Yes | `""` | Display name and bare `--plugins` selector target. |
| `version` | `string` | Yes | `"1.0.0"` | Semver version string. |
| `author` | `string` | No | `None` | Optional author metadata. |
| `description` | `string` | No | `None` | Optional summary displayed in `PluginsModal` and `aether-plugin-tool list`. |
| `enabled` | `bool` | No | `true` | Enables/disables rule execution and contributes to BLAKE3 `config_digest()`. |
| `profile` | `string` | No | `None` | Matched case-insensitively by `--plugins profile:<name>`. |
| `tags` | `string[]` | No | `[]` | Also matched case-insensitively by `--plugins profile:<tag>`. |
| `taint_sources` | `TaintSourceRule[]` | No | `[]` | Declarative SSA taint sources. |
| `taint_sinks` | `TaintSinkRule[]` | No | `[]` | Declarative SSA taint sinks. |
| `sanitizers` | `SanitizerRule[]` | No | `[]` | Declarative SSA sanitizers. |
| `rules` | `PluginRule[]` | No | `[]` | Pattern-based SAST rules. |

## Rule Schema (`PluginRule` & `RuleConditions`)

### 📝 `PluginRule` Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `string` | Yes | `""` | Unique rule ID (for example `PLUGIN-INJ-POSIX-FLAG-SMUGGLING`). |
| `cwe_id` | `string` | Yes | `""` | CWE classification label (for example `CWE-88 / POSIX-ARGUMENT-INJECTION-RCE`). |
| `name` | `string` | Yes | `""` | Human-readable rule title. |
| `category` | `string` | No | `"Plugin / Security"` | Category grouping in reports and UI. |
| `severity` | `string` | Yes | `""` | Expected values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING`. |
| `description` | `string` | Yes | `""` | Violation message emitted on match. |
| `remediation` | `string` | Yes | `""` | Actionable remediation guidance shown in Inspector and SARIF. |
| `file_extensions` | `string[]` | No | `[]` | Lowercased suffixes (`".rs"`, `".py"`); empty matches all non-Markdown files. |
| `match_mode` | `string` | No | `"line_by_line"` | `line_by_line` or `whole_file` (`MatchMode`, serialized `snake_case`). |
| `conditions` | `RuleConditions` | No | `{}` | Matching predicates, scopes, and path globs. |
| `test_cases` | `RuleTestCase[]` | No | `[]` | Embedded unit tests executed by `run_test_suite()` and `/api/plugins/upsert`. |

### 📝 `RuleConditions` Fields

| Field | Type | Default | Semantics |
|---|---|---|---|
| `must_contain` | `string[]` | `[]` | ALL substrings must exist in `eval_content` (whole file). Also serves as a line/file trigger fallback **only** when both `forbidden_tokens` and `regex_patterns` are empty. |
| `must_not_contain` | `string[]` | `[]` | Evaluated across the **entire file** (`eval_content`). If ANY entry appears anywhere in the file, the rule produces zero findings for that file. |
| `forbidden_tokens` | `string[]` | `[]` | OR-ed substring triggers evaluated before `regex_patterns`. |
| `regex_patterns` | `string[]` | `[]` | OR-ed Rust `regex::Regex` triggers. Validated before saving in `/api/plugins/upsert`. |
| `check_literals` | `bool` | `false` | `false`: uses `AuditContext::default_masked()` (strings/comments blanked). `true`: scans raw source including string literals and comments. |
| `not_preceded_within_lines` | `object` | `None` | `{ patterns: string[], lines: usize }`. Active only in `line_by_line` mode when `lines > 0` and `idx > 0`. |
| `in_path_matching` | `string[]` | `[]` | Path globs required to match (`glob_to_regex`). |
| `not_in_path_matching` | `string[]` | `[]` | Path globs excluded. Checked **before** `in_path_matching`. |
| `ast_scope` | `string` | `None` | Lexical/AST line scope filter active only in `line_by_line` mode. |

### Path Globs (`glob_to_regex`)

`glob_to_regex` normalizes `\` to `/`, strips leading `./` and `/`, and compiles a case-insensitive regex `(?i)^...$`:

- `**/` translates to `(?:.*/)?` (zero or more directory segments).
- Trailing `**` translates to `.*`.
- `*` translates to `[^/]*` (single path segment wildcard).
- `?` translates to `[^/]` (single non-slash character).
- Regex metacharacters (`.+^$()[]{}|\`) are escaped automatically.

### `ast_scope` Values & Detection

In `line_by_line` mode, `compute_line_ast_scopes` tracks test files (`/tests/`, `/test/`, `tests/...`, `test/...`, `_test.rs`, `_tests.rs`, `.spec.`, `.test.`), Python indentation (`def ` / `async def ` / `test_*`), and brace-language blocks (`#[cfg(test)]`, `mod tests {`, `#[test]`, `#[tokio::test...]`, `#[rstest...]`, `async fn `, `async function`, `fn `, `function `).

| Accepted `ast_scope` Values (case-insensitive) | Condition Enforced |
|---|---|
| `outside_test`, `non_test`, `prod`, `production` | Line is NOT inside a test file, test module, or test function (`!in_test`). |
| `test`, `in_test` | Line IS inside a test context (`in_test`). |
| `async_fn`, `async`, `async_function` | Line is inside an async function and outside tests (`in_async_fn && !in_test`). |
| `sync_fn`, `sync`, `sync_function` | Line is inside a synchronous function and outside tests (`in_fn && !in_async_fn && !in_test`). |
| `fn`, `function` | Line is inside any function and outside tests (`in_fn && !in_test`). |

{% hint style="warning" %}
Any unrecognized `ast_scope` string falls through to `true` (no filtering). Always verify your scope spelling against the table above.
{% endhint %}

### Contextual Lookback (`not_preceded_within_lines`)

When you need a **local** guard instead of file-wide suppression (`must_not_contain`), use `not_preceded_within_lines`:

```yaml
conditions:
  regex_patterns:
    - "execute_raw\\("
  not_preceded_within_lines:
    lines: 5
    patterns:
      - "verify_csrf\\("
      - "^\\s*if\\s+is_authorized"
```

- It inspects strictly preceding lines `idx.saturating_sub(win.lines)..idx` (never the triggered line itself).
- Each line in that window is tested against **both** `eval_lines` and `raw_lines`, matching if **any** pattern succeeds either as a compiled regex or as a substring `.contains(pat)`.
- It applies **only** in `match_mode: line_by_line`.

## Embedded Unit Tests (`test_cases`)

Every `PluginRule` can bundle self-contained unit tests (`RuleTestCase`):

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Descriptive test case label. |
| `file_name` | `string` | Virtual file path (exercises `file_extensions`, path globs, and `ast_scope`). |
| `code` | `string` | Snippet passed to `audit_file(file_name, code)`. |
| `should_trigger` | `bool` | `true` if `rule.id` must fire; `false` if the snippet must remain clean. |

`PluginEngine::run_test_suite()` runs all `test_cases` across all loaded plugins (including disabled manifests loaded from disk) and returns a `PluginTestReport` (`total_tests`, `passed`, `failed`, `failures`). Note that `POST /api/plugins/upsert` executes `run_test_suite()` in memory before writing to disk and rejects failing rules with **HTTP 422 Unprocessable Entity**.

## Declarative SSA Taint Rules

Plugins can extend AetherScope's inter-procedural SSA taint engine (`crates/core-graph/src/dataflow/types.rs`) without writing Rust code.

{% content-ref url="../core/ssa-dataflow-taint.md" %}
[SSA Dataflow & Taint Engine](../core/ssa-dataflow-taint.md)
{% endcontent-ref %}

### 📝 `taint_sources` (`TaintSourceRule`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `string` | Required | Unique source rule identifier. |
| `source_kind` | `SourceKind` | `Custom("custom")` | `HttpQueryParam`, `HttpBodyParam`, `HttpHeader`, `HttpCookie`, `WebSocketPayload`, `FileSystemRead`, `DatabaseRead`, `EnvironmentVar`, `FunctionArgument`, or `Custom(string)` (accepts PascalCase or `snake_case`). |
| `cwe` | `string` | `""` | Target CWE (converted to `"*"` internally if empty). |
| `patterns` | `string[]` | `[]` | Substring/wildcard patterns (`*` wildcard segments supported via `pattern_matches_line`). |
| `language` | `string` | `None` | Optional language/extension filter (`*`/`all`/`any` or normalized language name). |
| `description` | `string` | `""` | Human-readable source description. |

### 📝 `taint_sinks` (`TaintSinkRule`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `string` | Required | Sink rule name. |
| `rule_id` | `string` | `""` | Emitted finding ID (falls back to `name` if empty). |
| `sink_kind` | `SinkKind` | `Custom("custom")` | `SqlExecution`, `CommandExecution`, `HtmlRender`, `FileAccess`, `SsrfNetworkRequest`, `Deserialization`, `CodeEval`, `LdapQuery`, or `Custom(string)`. |
| `cwe` | `string` | `""` | Associated CWE (e.g., `"CWE-78"`, `"CWE-89"`). |
| `severity` | `string` | `"HIGH"` | Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `patterns` | `string[]` | `[]` | Call/token patterns with `*` wildcard support. |
| `language` | `string` | `None` | Optional language filter. |
| `description` | `string` | `""` | Finding description when tainted data reaches this sink. |

### 📝 `sanitizers` (`SanitizerRule`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `string` | Required | Sanitizer rule name. |
| `target_cwes` | `string[]` | `[]` | CWEs neutralized (supports YAML/JSON alias `neutralizes_cwes`). |
| `patterns` | `string[]` | `[]` | Function, method, type-cast, or regex patterns. |
| `match_kind` | `SanitizerMatchKind` | `ExactName` | `ExactName` (`exact_name`), `MethodCall` (`method_call`), `TypeCast` (`type_cast`), or `RegexPattern` (`regex_pattern`). |
| `language` | `string` | `None` | Optional language filter. |
| `neutralizes_all` | `bool` | `false` | When `true`, neutralizes all taint CWEs regardless of `target_cwes`. |

## CLI Selection (`--plugins`) & Profiles

Pass `--plugins <spec>` to `aether-engine` (`crates/security-linter/src/plugin.rs`) to control plugin selection:

- **Default (omitted) or `--plugins default` / `--plugins auto` / `--plugins all`**: Runs all built-in SAST rules plus all enabled `.aether/plugins/` manifests.
- **`--plugins <selector1>,<selector2>` (`PluginSelection::Select`)**:
  - `profile:<name>` matches `manifest.profile` or any entry in `manifest.tags` (case-insensitive).
  - Bare `<name>` matches `manifest.name` or `manifest.folder_alias` (the folder name under `.aether/plugins/`, case-insensitive).
  - If any selector fails to match an enabled plugin (or `BUILTIN_PACK_NAMES`), `load_with_selection` errors and `aether-engine` exits with code `1`.

{% hint style="danger" %}
**Verified Codebase Caveat (`PluginSelection::Select`)**: In `ProjectScanner::scan_project_with_exclusions` (`crates/ast-scanner/src/scanner.rs`), `run_builtin_sast` is set to `!matches!(self.plugin_selection, PluginSelection::Select(_))`. Passing `--plugins <selector>` **disables all built-in SAST rules** and runs only the matching `.aether/plugins/` manifests. Although `BUILTIN_PACK_NAMES` (34 built-in aliases such as `builtin-rust`, `web3`, `python`, `epic`) and `SecurityLinter::audit_file_selected` exist in `security-linter`, `audit_file_selected` is not currently wired into `ProjectScanner` or `desktop-shell`.
{% endhint %}

## Worked Examples & Studio Authoring

You can author plugins directly in YAML or interactively inside `PluginsModal` (`G` -> **Règle DSL v2**, **Taint SSA**, and **Bac à Sable** tabs).

{% tabs %}
{% tab title="SAST Rule (.aether/plugins/example-custom-auth/plugin.yaml)" %}
{% code title=".aether/plugins/example-custom-auth/plugin.yaml" overflow="wrap" %}
```yaml
name: example-custom-auth
version: 1.0.0
author: Security Team
description: 'Custom security plugin: example-custom-auth'
enabled: true
rules:
- id: CUSTOM-EXAMPLE-CUSTOM-AUTH-001
  cwe_id: CWE-287 / AUTH-BYPASS
  name: Exemple de règle personnalisée anti-bypass
  category: Custom / Security
  severity: HIGH
  description: Détection d'un contournement d'authentification ou fonction non protégée
  remediation: Appliquez le middleware de vérification d'autorisation avant d'exécuter l'action.
  file_extensions:
  - .rs
  - .py
  - .ts
  match_mode: line_by_line
  conditions:
    must_contain: []
    must_not_contain:
    - verify_token
    - is_authenticated
    regex_patterns:
    - fn\s+admin_\w+\s*\(
    - def\s+admin_\w+\s*\(
    forbidden_tokens: []
    check_literals: false
  test_cases:
  - name: Fonction admin sans vérification (Vulnérable)
    code: pub fn admin_delete_user() { database.delete(); }
    file_name: admin.rs
    should_trigger: true
  - name: Fonction admin sécurisée (Pass)
    code: pub fn admin_delete_user() { if is_authenticated() { database.delete(); } }
    file_name: admin.rs
    should_trigger: false
```
{% endcode %}
{% endtab %}

{% tab title="SAST + SSA Taint (.aether/plugins/majestic-injections/plugin.yaml)" %}
{% code title=".aether/plugins/majestic-injections/plugin.yaml" overflow="wrap" %}
```yaml
name: "majestic-injections"
version: "1.0.0"
author: "AetherScope Security Lab"
description: "Detects POSIX Argument Smuggling (CWE-88), Fileless ESM Import (CWE-94), and PHP Phar Wrappers (CWE-98)."
enabled: true
profile: "strict"
tags: ["injection", "rce", "posix", "esm", "php"]

taint_sources:
  - name: "http_req_query"
    source_kind: "HttpQueryParam"
    cwe: "CWE-20"
    patterns: ["req.query", "$_GET", "Query("]
    description: "Untrusted external HTTP query parameter"
  - name: "cli_repo_url_arg"
    source_kind: "FunctionArgument"
    cwe: "CWE-88"
    patterns: ["repo_url", "user_arg", "untrusted_input"]
    description: "External function argument forwarded to subprocess"

taint_sinks:
  - name: "posix_command_spawn"
    rule_id: "TAINT-SINK-POSIX-CMD"
    sink_kind: "CommandExecution"
    cwe: "CWE-78"
    severity: "CRITICAL"
    patterns: ["Command::new", "child_process.exec", "os.system"]
    description: "OS process execution reached by unsanitized source"

sanitizers:
  - name: "strict_allowlist_guard"
    target_cwes: ["CWE-78", "CWE-88", "CWE-89", "CWE-22", "CWE-79"]
    patterns: ["sanitize_arg", "PathGuard::validate", "htmlspecialchars", "bind_param"]
    match_kind: "ExactName"
    neutralizes_all: false

rules:
  - id: "PLUGIN-INJ-POSIX-FLAG-SMUGGLING"
    cwe_id: "CWE-88 / POSIX-ARGUMENT-INJECTION-RCE"
    name: "POSIX Executable Flag Smuggling Without '--' Delimiter"
    category: "Code & File Injection"
    severity: "CRITICAL"
    description: "Executing git, tar, find, rg, or ssh with dynamic input without '--'."
    remediation: "Always insert '--' before user-controlled arguments."
    file_extensions: [".rs", ".ts", ".js", ".py"]
    match_mode: line_by_line
    conditions:
      check_literals: true
      regex_patterns:
        - "(?:Command::new|execFile|spawn)\\s*\\(\\s*['\"](?:git|tar|find|rg|ssh|scp|rsync)['\"]"
      must_not_contain:
        - "\"--\""
        - "'--'"
    test_cases:
      - name: "git clone without '--' (Vulnerable)"
        file_name: "src/git_service.rs"
        code: |
          pub fn clone_repo(repo_url: &str) {
              std::process::Command::new("git").arg("clone").arg(repo_url).status().unwrap();
          }
        should_trigger: true
```
{% endcode %}
{% endtab %}
{% endtabs %}

### 💡 Quick Verification Commands

```bash
# Run all embedded test_cases under .aether/plugins/
aether-plugin-tool test .aether/plugins

# Audit a target directory using only the strict profile plugins
aether-engine -p . --audit-only --plugins profile:strict
```

{% content-ref url="semgrep-and-community-bundle.md" %}
[Semgrep Importer & Community Bundle](semgrep-and-community-bundle.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[Plugin, MCP & Runner CLIs](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
