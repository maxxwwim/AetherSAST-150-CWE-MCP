# Moteur Dataflow SSA & Taint

Le moteur Dataflow SSA & Taint suit les entrées utilisateur non fiables des sources jusqu'aux puits dangereux à travers les fonctions, vérifie l'exploitabilité et neutralise les faux positifs lorsque chaque chemin est assaini.

## Vue d'ensemble

Les règles SAST par motifs détectent les puits dangereux de manière isolée, tandis que le moteur dataflow Static Single Assignment (SSA) modélise la propagation des données non fiables à travers les réaffectations, expressions binaires et appels de fonction. Lorsqu'`aether-engine` construit un `DataflowGraph`, `execute_track_dataflow` évalue chaque paire `(source, sink)` compatible par CWE et met à jour `CveAnomalyRecord.is_reachable` ainsi que `SymbolBubble.has_security_violation`.

{% hint style="warning" %}
Lors d'un scan complet `ProjectScanner` (`crates/ast-scanner/src/scanner.rs`), `TaintExtractor::extract_multi_with_rules` s'exécute automatiquement **uniquement lorsque les plugins chargés déclarent au moins une règle de taint** (`has_taint_rules = !taint_rules.is_empty()`). Les appels autonomes (`TaintExtractor::extract_from_source`, `TaintExtractor::extract_multi` et `TaintExtractor::enrich_aether_graph`) alimentent toujours `DataflowGraph` avec les sources HTTP intégrées, les puits intégrés et `SanitizerRule::default_catalog()`.
{% endhint %}

## Modèle SSA et graphe Dataflow

### `SsaVar` et `DataflowGraph`

Chaque affectation de variable reçoit une version SSA strictement croissante dans sa portée de fonction (`crates/core-graph/src/dataflow/types.rs` et `graph.rs`) :

* **`SsaVar`** : Stocke `name`, `version`, `func_scope`, `line` et `file_path`. `display_id()` produit `"{name}#{version}"`, tandis que `scoped_id()` produit `"{func_scope}::{name}#{version}"` (ou `display_id()` si `func_scope` est vide).
* **`DataflowGraph`** : Contient `nodes: HashMap<String, SsaVar>`, `edges: Vec<DataflowEdge>`, `sources: Vec<TaintSource>`, `sinks: Vec<TaintSink>` et `sanitizers: Vec<SanitizerRule>`. `DataflowGraph::new()` précharge automatiquement les 56 règles de `SanitizerRule::default_catalog()`.

### `DataflowEdge` et les 6 variantes `TaintStepKind`

Chaque `DataflowEdge` relie `from_var: SsaVar` à `to_var: SsaVar` avec `step_kind: TaintStepKind`, `line`, `is_sanitizer`, `sanitizer_name`, `file_path` et un champ optionnel `code_snippet`.

| Variante `TaintStepKind` | Champs associés | Rôle |
| :--- | :--- | :--- |
| `DirectAssignment` | — | Suit les affectations directes telles que `x = y` (`x#2 <- y#1`) |
| `BinaryExpression` | — | Propage le taint à travers les concaténations ou expressions (`q = "SELECT " + id`) |
| `CallArgumentPassing` | `caller_function`, `callee_function`, `arg_index`, `param_name` | Relie la version SSA de l'argument appelant au paramètre `0` de l'appelé |
| `CallReturnPassing` | `caller_function`, `callee_function` | Relie `return_var` de l'appelé à la cible d'affectation `lhs_var` de l'appelant |
| `SanitizerCall` | `sanitizer_name`, `cwe_targeted` | Marque une arête passant par une fonction ou un transtypage d'assainissement |
| `PhiJoin` | — | Défini dans `core-graph` pour les points de jonction de contrôle (`taint_extractor.rs` émet actuellement les 5 variantes ci-dessus) |

`TaintStepKind` propose également `Custom(String)` pour les annotations de propagation personnalisées.

### `TaintSource`, `TaintSink` et `TaintFlowTrace`

* **`TaintSource`** (`var`, `source_kind: SourceKind`, `cwe`, `file_path`, `line`, `description`) : Classe les entrées parmi `HttpQueryParam`, `HttpBodyParam`, `HttpHeader`, `HttpCookie`, `WebSocketPayload`, `FileSystemRead`, `DatabaseRead`, `EnvironmentVar`, `FunctionArgument` et `Custom(String)`.
* **`TaintSink`** (`var`, `sink_kind: SinkKind`, `cwe`, `rule_id`, `severity` par défaut `"HIGH"`, `file_path`, `line`, `description`) : Classe les puits parmi `SqlExecution`, `CommandExecution`, `HtmlRender`, `FileAccess`, `SsrfNetworkRequest`, `Deserialization`, `CodeEval`, `LdapQuery` et `Custom(String)`.
* **`TaintFlowTrace`** : Produit `source`, `sink`, `steps: Vec<TaintStep>` indexés à partir de 1, `is_sanitized: bool`, `applied_sanitizers: Vec<String>` et `is_vulnerable: bool` (`!is_sanitized`).

## `TaintExtractor` en 2 passes sur 6 langages

`TaintExtractor` (`crates/ast-scanner/src/taint_extractor.rs`) effectue une extraction SSA inter-fichiers basée sur les lignes pour 6 langages : **PHP** (`.php`, `.phtml`), **JavaScript/TypeScript** (`.js`, `.ts`, `.jsx`, `.tsx`), **Python** (`.py`), **Rust** (`.rs`), **Zig** (`.zig`) et **C#** (`.cs`).

```text
Fichiers source ──▶ Passe 1 : extract_file_intra (versions SSA, sources HTTP, puits intégrés/plugins, sanitizers)
                        │
                        ▼
                 Passe 2 : link_inter_procedural (CallArgumentPassing + CallReturnPassing, suppression des raccourcis)
                        │
                        ▼
                 execute_track_dataflow (DFS max_depth=32 + invariant d'assainissement sur tous les chemins)
```

### Passe 1 : Extraction intra-procédurale (`extract_file_intra`)

1. Enregistre les déclarations de fonctions et initialise chaque paramètre à la version SSA `0` dans `scope_versions`.
2. Incrémente `scope_versions` à chaque réaffectation à gauche, en émettant des arêtes `DirectAssignment`, `BinaryExpression` ou `SanitizerCall`.
3. Enregistre les `CallSite` et les variables de retour `return_var` pour la résolution inter-procédurale.
4. Enregistre les sources HTTP intégrées (toutes marquées `cwe: "*"`) et les puits intégrés en plus des règles issues des plugins :

| Catégorie | Motifs intégrés détectés | Classification / CWE |
| :--- | :--- | :--- |
| **Sources HTTP Query** | `$_GET`, `req.query`, `request.args` | `SourceKind::HttpQueryParam` (`*`) |
| **Sources HTTP Body** | `$_POST`, `req.body`, `request.form` | `SourceKind::HttpBodyParam` (`*`) |
| **Sources HTTP Header/Cookie** | `$_REQUEST`, `$_COOKIE`, `req.params` | `SourceKind::HttpHeader` (`*`) |
| **Puits Injection SQL** | `query(`, `execute(`, `mysqli_query(`, `->query(`, `->execute(`, `raw_query(` | `CWE-89-SQL-INJECTION` (`CRITICAL`) |
| **Puits Injection de commande** | `system(`, `exec(` (hors `->exec(` / `::exec(`), `passthru(`, `shell_exec(`, `popen(`, `child_process.exec(`, `Command::new(`, `Process.Start(`, `std.process.Child.run(` | `CWE-78-COMMAND-INJECTION` (`CRITICAL`) |
| **Puits XSS** | `echo `, `print `, `innerHTML =`, `res.send(`, `Response.Write(` | `CWE-79-XSS` (`HIGH`) |
| **Puits Traversée de chemin** | `file_get_contents(`, `readfile(`, `include `, `require `, `fs.readFile(`, `File.Open(`, `File.ReadAllText(`, `std.fs.cwd().openFile(`, `open(` | `CWE-22-PATH-TRAVERSAL` (`HIGH`) |

### Passe 2 : Liaison inter-procédurale (`link_inter_procedural`)

La passe 2 relie les arguments appelants (`arg_vars`) aux paramètres de la fonction appelée (version `0`) via `TaintStepKind::CallArgumentPassing`, puis relie le `return_var` de la fonction appelée au `lhs_var` appelant via `TaintStepKind::CallReturnPassing`. Elle supprime également les arêtes raccourcies directes `arg -> lhs_var` générées sur la même ligne en passe 1 afin que l'assainissement interne à l'appelé reste préservé.

## Propagation du taint et neutralisation (`execute_track_dataflow`)

### Correspondance CWE bornée et DFS (`max_depth = 32`)

Pour chaque paire `(source, sink)`, `execute_track_dataflow` (`crates/core-graph/src/dataflow/engine.rs`) vérifie d'abord la compatibilité via `cwe_matches(&source.cwe, &sink.cwe)`. `cwe_matches` retourne `true` si l'une des chaînes est vide ou `"*"`, correspond sans tenir compte de la casse, ou correspond sur frontière de jeton (`contains_cwe_bounded` empêche `"CWE-8"` de correspondre à `"CWE-89"`).

Si `source.var.scoped_id() == sink.var.scoped_id()`, le moteur émet immédiatement une trace triviale vulnérable (`is_sanitized = false`). Sinon, `find_paths_dfs` énumère tous les chemins simples jusqu'à `max_depth = 32` avec détection de cycles via `visited_nodes`.

### Invariant d'assainissement sur tous les chemins

{% hint style="danger" %}
**Invariant de sécurité** : Si **un seul** chemin joignable de la source au puits est dépourvu de sanitizer efficace, `execute_track_dataflow` retient le chemin non assaini le plus court et marque la trace **vulnérable** (`is_sanitized = false`, `is_vulnerable = true`). Une alerte n'est neutralisée (`is_sanitized = true`, `is_vulnerable = false`) **que lorsque tous les chemins joignables** traversent un sanitizer effectif pour le CWE du puits.
{% endhint %}

Lorsque `AetherGraph::compute_dataflow_taint` propage ces traces aux nœuds `SymbolBubble`, toute bulle dont tous les `cve_anomalies` deviennent `is_reachable == false` voit `has_security_violation` repasser à `false`.

### 🎮 Signature / Endpoint

```rust
pub fn execute_track_dataflow(dfg: &DataflowGraph) -> Vec<TaintFlowTrace>
```

### 📝 Arguments / Paramètres

| Nom | Type | Requis | Description |
| :--- | :--- | :--- | :--- |
| `dfg` | `&DataflowGraph` | Oui | Graphe dataflow contenant variables SSA, arêtes, sources, puits et règles de sanitizers (`default_catalog()` + règles de plugins). |

### 💎 Valeur de retour / Réponse

| Type | Champ | Description |
| :--- | :--- | :--- |
| `Vec<TaintFlowTrace>` | `is_vulnerable`, `is_sanitized`, `applied_sanitizers`, `steps` | Une trace par paire `(source, sink)` joignable ; `is_vulnerable` vaut `!is_sanitized`. |

### 💡 Exemple

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

## Catalogue complet `SanitizerRule::default_catalog()` (56 règles)

`DataflowGraph::new()` charge 56 définitions `SanitizerRule` intégrées (`crates/core-graph/src/dataflow/types.rs`) regroupées par CWE cible et type de correspondance (`ExactName`, `MethodCall`, `TypeCast`) :

| CWE cible | Nombre | Règles et `SanitizerMatchKind` |
| :--- | :--- | :--- |
| **CWE-89 (Injection SQL)** | 23 | `intval` (`ExactName`), `floatval` (`ExactName`), `(int)` (`TypeCast`), `(float)` (`TypeCast`), `clean_sql` (`ExactName`), `prepare` (`MethodCall`), `pdo_prepare` (`ExactName`), `mysqli_real_escape_string` (`ExactName`), `addslashes` (`ExactName`), `bind_param` (`MethodCall`), `bindValue` (`MethodCall`), `PDO::quote` (`MethodCall`), `mysql.escape` (`MethodCall`), `sqlstring.escape` (`MethodCall`), `escapeId` (`ExactName`), `parseInt` (`ExactName`), `Number` (`ExactName`), `psycopg2.sql.Identifier` (`MethodCall`), `psycopg2.sql.Literal` (`MethodCall`), `sqlx::query!` (`MethodCall`), `FromSqlInterpolated` (`MethodCall`), `Parameters.AddWithValue` (`MethodCall`), plus la règle partagée `sanitize_input` (`CWE-79`, `CWE-89`, `ExactName`) |
| **CWE-78 (Injection de commande)** | 6 | `escapeshellarg` (`ExactName`), `escapeshellcmd` (`ExactName`), `shlex.quote` (`MethodCall`), `shell-escape` (`ExactName`), `execFile` (`ExactName`), `ArgumentList.Add` (`MethodCall`) |
| **CWE-79 (XSS)** | 15 (+1 partagée) | `htmlspecialchars` (`ExactName`), `htmlentities` (`ExactName`), `strip_tags` (`ExactName`), `DOMPurify.sanitize` (`MethodCall`), `sanitizeHtml` (`ExactName`), `escape_html` (`ExactName`), `escapeHtml` (`ExactName`), `encodeURIComponent` (`ExactName`), `validator.escape` (`MethodCall`), `html.escape` (`MethodCall`), `bleach.clean` (`MethodCall`), `markupsafe.escape` (`MethodCall`), `HtmlEncoder.Default.Encode` (`MethodCall`), `WebUtility.HtmlEncode` (`MethodCall`), `HttpUtility.HtmlEncode` (`MethodCall`), plus la règle partagée `sanitize_input` (`CWE-79`, `CWE-89`, `ExactName`) |
| **CWE-22 (Traversée de chemin)** | 7 | `basename` (`ExactName`), `sanitize_path` (`ExactName`), `realpath` (`ExactName`), `Path::canonicalize` (`MethodCall`), `path.basename` (`MethodCall`), `os.path.basename` (`MethodCall`), `Path.GetFileName` (`MethodCall`) |
| **CWE-170 / CWE-843 (Mémoire Zig)** | 3 | `dupeZ` (`CWE-170`, `MethodCall`), `bytesAsValue` (`CWE-843`, `MethodCall`), `bytesAsSlice` (`CWE-843`, `MethodCall`) |
| **Joker (`*`, `neutralizes_all = true`)** | 2 | `sanitize` (`ExactName`), `clean` (`ExactName`) |

## Intégration des plugins (règles de taint `PluginManifest`)

Les plugins YAML placés sous `.aether/plugins/` étendent le moteur dataflow via les champs `taint_sources`, `taint_sinks` et `sanitizers` de `PluginManifest`. `PluginEngine::collect_taint_rules()` agrège tous les manifestes actifs dans un `TaintRuleSet`, active `has_taint_rules` dans `ProjectScanner` et génère des entrées `CveAnomalyRecord` + `AffiliationEdge::new_cve_violation` dès qu'un flux non assaini atteint un puits déclaré par un plugin.

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
[Moteur de graphe spatial](./graph-engine.md)
{% endcontent-ref %}

{% content-ref url="./cwe-sast-engine.md" %}
[Moteur CWE & SAST](./cwe-sast-engine.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[DSL déclaratif SAST & Taint v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}
