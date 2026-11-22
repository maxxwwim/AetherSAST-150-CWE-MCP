# SSA Dataflow & Taint Engine

The SSA Dataflow & Taint Engine tracks tainted user inputs from sources to dangerous sinks across functions, verifying exploitability and neutralizing false positives when every path is sanitized.

## Overview

Pattern-based SAST rules detect dangerous sinks in isolation, whereas the Static Single Assignment (SSA) dataflow engine models how untrusted data propagates through variable reassignments, binary expressions, and function calls. When `aether-engine` builds a `DataflowGraph`, `execute_track_dataflow` checks every CWE-compatible `(source, sink)` pair and updates `CveAnomalyRecord.is_reachable` and `SymbolBubble.has_security_violation`.

{% hint style="warning" %}
During a full `ProjectScanner` run (`crates/ast-scanner/src/scanner.rs`), `TaintExtractor::extract_multi_with_rules` executes automatically **only when loaded plugins declare at least one taint rule** (`has_taint_rules = !taint_rules.is_empty()`). Standalone calls (`TaintExtractor::extract_from_source`, `TaintExtractor::extract_multi`, and `TaintExtractor::enrich_aether_graph`) always populate `DataflowGraph` using built-in HTTP sources, built-in sinks, and `SanitizerRule::default_catalog()`.
{% endhint %}

## SSA & Dataflow Graph Model

### `SsaVar` and `DataflowGraph`

Every variable assignment receives a monotonically increasing SSA version inside its enclosing function scope (`crates/core-graph/src/dataflow/types.rs` and `graph.rs`):

* **`SsaVar`**: Stores `name`, `version`, `func_scope`, `line`, and `file_path`. `display_id()` formats `"{name}#{version}"`, while `scoped_id()` formats `"{func_scope}::{name}#{version}"` (falling back to `display_id()` when `func_scope` is empty).
* **`DataflowGraph`**: Holds `nodes: HashMap<String, SsaVar>`, `edges: Vec<DataflowEdge>`, `sources: Vec<TaintSource>`, `sinks: Vec<TaintSink>`, and `sanitizers: Vec<SanitizerRule>`. Calling `DataflowGraph::new()` automatically pre-loads all 56 entries of `SanitizerRule::default_catalog()`.

### `DataflowEdge` and the 6 `TaintStepKind` Variants

Each `DataflowEdge` connects `from_var: SsaVar` to `to_var: SsaVar` with `step_kind: TaintStepKind`, `line`, `is_sanitizer`, `sanitizer_name`, `file_path`, and optional `code_snippet`.

| `TaintStepKind` Variant | Payload Fields | Purpose |
| :--- | :--- | :--- |
| `DirectAssignment` | — | Tracks direct assignments such as `x = y` (`x#2 <- y#1`) |
| `BinaryExpression` | — | Propagates taint across concatenations or expressions (`q = "SELECT " + id`) |
| `CallArgumentPassing` | `caller_function`, `callee_function`, `arg_index`, `param_name` | Binds caller argument SSA version to callee parameter version `0` |
| `CallReturnPassing` | `caller_function`, `callee_function` | Binds callee `return_var` back to caller assignment target `lhs_var` |
| `SanitizerCall` | `sanitizer_name`, `cwe_targeted` | Marks an edge where data passes through a sanitizer function or cast |
| `PhiJoin` | — | Defined in `core-graph` for control-flow join points (`taint_extractor.rs` currently emits the 5 variants above) |

`TaintStepKind` also provides `Custom(String)` for domain-specific propagation annotations.

### `TaintSource`, `TaintSink`, and `TaintFlowTrace`

* **`TaintSource`** (`var`, `source_kind: SourceKind`, `cwe`, `file_path`, `line`, `description`): Classifies inputs across `HttpQueryParam`, `HttpBodyParam`, `HttpHeader`, `HttpCookie`, `WebSocketPayload`, `FileSystemRead`, `DatabaseRead`, `EnvironmentVar`, `FunctionArgument`, and `Custom(String)`.
* **`TaintSink`** (`var`, `sink_kind: SinkKind`, `cwe`, `rule_id`, `severity` defaulting to `"HIGH"`, `file_path`, `line`, `description`): Classifies sinks across `SqlExecution`, `CommandExecution`, `HtmlRender`, `FileAccess`, `SsrfNetworkRequest`, `Deserialization`, `CodeEval`, `LdapQuery`, and `Custom(String)`.
* **`TaintFlowTrace`**: Outputs `source`, `sink`, 1-based `steps: Vec<TaintStep>`, `is_sanitized: bool`, `applied_sanitizers: Vec<String>`, and `is_vulnerable: bool` (`!is_sanitized`).

## 2-Pass `TaintExtractor` Across 6 Languages

`TaintExtractor` (`crates/ast-scanner/src/taint_extractor.rs`) performs line-based, cross-file SSA extraction across 6 languages: **PHP** (`.php`, `.phtml`), **JavaScript/TypeScript** (`.js`, `.ts`, `.jsx`, `.tsx`), **Python** (`.py`), **Rust** (`.rs`), **Zig** (`.zig`), and **C#** (`.cs`).

```text
Source Files ──▶ Pass 1: extract_file_intra (SSA versions, HTTP sources, built-in/plugin sinks, sanitizers)
                        │
                        ▼
                 Pass 2: link_inter_procedural (CallArgumentPassing + CallReturnPassing, remove shortcuts)
                        │
                        ▼
                 execute_track_dataflow (DFS max_depth=32 + all-paths sanitizer check)
```

### Pass 1: Intra-Procedural Extraction (`extract_file_intra`)

1. Registers function declarations and initializes each parameter at SSA version `0` inside `scope_versions`.
2. Increments `scope_versions` on every left-hand-side reassignment, emitting `DirectAssignment`, `BinaryExpression`, or `SanitizerCall` edges.
3. Records `CallSite` records and function `return_var` values for inter-procedural resolution.
4. Registers built-in HTTP sources (all tagged with `cwe: "*"`) and built-in sinks alongside any plugin-defined sources/sinks:

| Category | Built-in Patterns Detected | Classification / CWE |
| :--- | :--- | :--- |
| **HTTP Query Sources** | `$_GET`, `req.query`, `request.args` | `SourceKind::HttpQueryParam` (`*`) |
| **HTTP Body Sources** | `$_POST`, `req.body`, `request.form` | `SourceKind::HttpBodyParam` (`*`) |
| **HTTP Header/Cookie Sources** | `$_REQUEST`, `$_COOKIE`, `req.params` | `SourceKind::HttpHeader` (`*`) |
| **SQL Injection Sinks** | `query(`, `execute(`, `mysqli_query(`, `->query(`, `->execute(`, `raw_query(` | `CWE-89-SQL-INJECTION` (`CRITICAL`) |
| **Command Injection Sinks** | `system(`, `exec(` (excluding `->exec(` / `::exec(`), `passthru(`, `shell_exec(`, `popen(`, `child_process.exec(`, `Command::new(`, `Process.Start(`, `std.process.Child.run(` | `CWE-78-COMMAND-INJECTION` (`CRITICAL`) |
| **XSS Sinks** | `echo `, `print `, `innerHTML =`, `res.send(`, `Response.Write(` | `CWE-79-XSS` (`HIGH`) |
| **Path Traversal Sinks** | `file_get_contents(`, `readfile(`, `include `, `require `, `fs.readFile(`, `File.Open(`, `File.ReadAllText(`, `std.fs.cwd().openFile(`, `open(` | `CWE-22-PATH-TRAVERSAL` (`HIGH`) |

### Pass 2: Inter-Procedural Linking (`link_inter_procedural`)

Pass 2 wires caller arguments (`arg_vars`) to callee parameters (version `0`) via `TaintStepKind::CallArgumentPassing` and links the callee's `return_var` back to the caller's `lhs_var` via `TaintStepKind::CallReturnPassing`. Crucially, it removes any same-line direct `arg -> lhs_var` shortcut edge created in Pass 1 so that sanitization inside the callee function is never bypassed.

## Taint Propagation & Sanitizer Neutralization (`execute_track_dataflow`)

### Bounded CWE Matching and DFS (`max_depth = 32`)

For each `(source, sink)` pair, `execute_track_dataflow` (`crates/core-graph/src/dataflow/engine.rs`) first verifies compatibility with `cwe_matches(&source.cwe, &sink.cwe)`. `cwe_matches` returns `true` when either CWE string is empty or `"*"`, matches case-insensitively, or matches on token boundaries (`contains_cwe_bounded` ensures `"CWE-8"` never falsely matches `"CWE-89"`).

If `source.var.scoped_id() == sink.var.scoped_id()`, the engine immediately emits a vulnerable trivial trace (`is_sanitized = false`). Otherwise, `find_paths_dfs` enumerates all simple paths up to `max_depth = 32` using a `visited_nodes` set for cycle detection.

### All-Paths Sanitization Invariant

{% hint style="danger" %}
**Security Invariant**: If **even one** reachable path from source to sink lacks an effective sanitizer, `execute_track_dataflow` selects the shortest unsanitized path and marks the trace **vulnerable** (`is_sanitized = false`, `is_vulnerable = true`). A finding is neutralized (`is_sanitized = true`, `is_vulnerable = false`) **only when every reachable path** passes through an effective sanitizer matching the sink's CWE.
{% endhint %}

When `AetherGraph::compute_dataflow_taint` propagates these traces back to `SymbolBubble` nodes, any bubble whose `cve_anomalies` all become `is_reachable == false` has `has_security_violation` cleared to `false`.

### 🎮 Signature / Endpoint

```rust
pub fn execute_track_dataflow(dfg: &DataflowGraph) -> Vec<TaintFlowTrace>
```

### 📝 Arguments / Parameters

| Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `dfg` | `&DataflowGraph` | Yes | Dataflow graph containing SSA variables, edges, sources, sinks, and sanitizer rules (`default_catalog()` + plugin rules). |

### 💎 Return Value / Response

| Type | Field | Description |
| :--- | :--- | :--- |
| `Vec<TaintFlowTrace>` | `is_vulnerable`, `is_sanitized`, `applied_sanitizers`, `steps` | One trace per reachable `(source, sink)` pair; `is_vulnerable` is `!is_sanitized`. |

### 💡 Example

```rust
use ast_scanner::TaintExtractor;
use core_graph::dataflow::execute_track_dataflow;

let php = r#"
<?php
function safe_query($raw) {
    $clean = intval($raw);
    return $clean;
}
$id = $_GET['id'];
$safe_id = safe_query($id);
$res = mysqli_query($conn, $safe_id);
"#;

let dfg = TaintExtractor::extract_from_source("index.php", php);
let traces = execute_track_dataflow(&dfg);
assert!(traces.iter().all(|t| t.is_sanitized && !t.is_vulnerable));
```

## Complete `SanitizerRule::default_catalog()` (56 Rules)

`DataflowGraph::new()` loads 56 built-in `SanitizerRule` definitions (`crates/core-graph/src/dataflow/types.rs`) grouped by target CWE and match kind (`ExactName`, `MethodCall`, `TypeCast`):

| Target CWE | Count | Rules & `SanitizerMatchKind` |
| :--- | :--- | :--- |
| **CWE-89 (SQL Injection)** | 23 | `intval` (`ExactName`), `floatval` (`ExactName`), `(int)` (`TypeCast`), `(float)` (`TypeCast`), `clean_sql` (`ExactName`), `prepare` (`MethodCall`), `pdo_prepare` (`ExactName`), `mysqli_real_escape_string` (`ExactName`), `addslashes` (`ExactName`), `bind_param` (`MethodCall`), `bindValue` (`MethodCall`), `PDO::quote` (`MethodCall`), `mysql.escape` (`MethodCall`), `sqlstring.escape` (`MethodCall`), `escapeId` (`ExactName`), `parseInt` (`ExactName`), `Number` (`ExactName`), `psycopg2.sql.Identifier` (`MethodCall`), `psycopg2.sql.Literal` (`MethodCall`), `sqlx::query!` (`MethodCall`), `FromSqlInterpolated` (`MethodCall`), `Parameters.AddWithValue` (`MethodCall`), plus shared `sanitize_input` (`CWE-79`, `CWE-89`, `ExactName`) |
| **CWE-78 (Command Injection)** | 6 | `escapeshellarg` (`ExactName`), `escapeshellcmd` (`ExactName`), `shlex.quote` (`MethodCall`), `shell-escape` (`ExactName`), `execFile` (`ExactName`), `ArgumentList.Add` (`MethodCall`) |
| **CWE-79 (XSS)** | 15 (+1 shared) | `htmlspecialchars` (`ExactName`), `htmlentities` (`ExactName`), `strip_tags` (`ExactName`), `DOMPurify.sanitize` (`MethodCall`), `sanitizeHtml` (`ExactName`), `escape_html` (`ExactName`), `escapeHtml` (`ExactName`), `encodeURIComponent` (`ExactName`), `validator.escape` (`MethodCall`), `html.escape` (`MethodCall`), `bleach.clean` (`MethodCall`), `markupsafe.escape` (`MethodCall`), `HtmlEncoder.Default.Encode` (`MethodCall`), `WebUtility.HtmlEncode` (`MethodCall`), `HttpUtility.HtmlEncode` (`MethodCall`), plus shared `sanitize_input` (`CWE-79`, `CWE-89`, `ExactName`) |
| **CWE-22 (Path Traversal)** | 7 | `basename` (`ExactName`), `sanitize_path` (`ExactName`), `realpath` (`ExactName`), `Path::canonicalize` (`MethodCall`), `path.basename` (`MethodCall`), `os.path.basename` (`MethodCall`), `Path.GetFileName` (`MethodCall`) |
| **CWE-170 / CWE-843 (Zig Memory)** | 3 | `dupeZ` (`CWE-170`, `MethodCall`), `bytesAsValue` (`CWE-843`, `MethodCall`), `bytesAsSlice` (`CWE-843`, `MethodCall`) |
| **Wildcard (`*`, `neutralizes_all = true`)** | 2 | `sanitize` (`ExactName`), `clean` (`ExactName`) |

## Plugin Integration (`PluginManifest` Taint Rules)

YAML plugins under `.aether/plugins/` can extend the dataflow engine using `taint_sources`, `taint_sinks`, and `sanitizers` fields on `PluginManifest`. `PluginEngine::collect_taint_rules()` aggregates all active manifests into a `TaintRuleSet`, enabling `has_taint_rules` in `ProjectScanner` and emitting `CveAnomalyRecord` + `AffiliationEdge::new_cve_violation` entries whenever an unsanitized path reaches a plugin sink.

{% code title=".aether/plugins/custom-taint/plugin.yaml" overflow="wrap" %}
```yaml
name: custom-ssrf-taint
version: "1.0.0"
taint_sources:
  - name: req.query.webhook
    patterns: ["req.query.webhook"]
    source_kind: HttpQueryParam
    cwe: CWE-918
taint_sinks:
  - name: axios.get
    patterns: ["axios.get("]
    sink_kind: SsrfNetworkRequest
    cwe: CWE-918
    rule_id: PLUGIN_SSRF_TAINT
    severity: HIGH
sanitizers:
  - name: validateAllowlistUrl
    target_cwes: ["CWE-918"]
    patterns: ["validateAllowlistUrl("]
    match_kind: ExactName
```
{% endcode %}

{% content-ref url="./graph-engine.md" %}
[Spatial Graph Engine](./graph-engine.md)
{% endcontent-ref %}

{% content-ref url="./cwe-sast-engine.md" %}
[CWE & SAST Engine](./cwe-sast-engine.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}
