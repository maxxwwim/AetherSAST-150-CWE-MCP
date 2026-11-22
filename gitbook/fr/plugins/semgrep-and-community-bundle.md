# Importateur Semgrep & Bundle Communautaire

Importez des règles Semgrep YAML existantes dans des manifestes `PluginManifest` AetherScope ou déployez le Bundle Communautaire embarqué de 24 règles OWASP/CWE 100 % hors-ligne.

## Bundle Communautaire hors-ligne (`CommunityBundle`)

AetherScope compile `crates/security-linter/rules/community_owasp_cwe.yaml` directement dans le binaire via `include_str!` (`crates/security-linter/src/community_bundle.rs`). Aucun accès réseau n'est requis en environnement air-gapped.

Lors du dépliage via `CommunityBundle::unpack_to_directory`, `SemgrepImporter` convertit les **24** règles Semgrep embarquées (`0` règle taint ; toutes sont des règles SAST par motifs) vers `<target_dir>/community/plugin.yaml` avec `name: "community"`.

### Déployer le Bundle Communautaire

{% tabs %}
{% tab title="CLI (aether-engine)" %}
```bash
# Déploie vers <project_root>/.aether/plugins/community/plugin.yaml
aether-engine -p . --update-rules
```
{% endtab %}

{% tab title="CLI (aether-plugin-tool)" %}
```bash
# Déploiement immédiat hors-ligne
aether-plugin-tool init-bundle .aether/plugins

# Ou tentative en ligne avec repli automatique sur le bundle embarqué
aether-plugin-tool download-semgrep-rules --output .aether/plugins
aether-plugin-tool download-semgrep-rules --offline --output .aether/plugins
```
{% endtab %}

{% tab title="API REST & Interface Cockpit" %}
```bash
# Route HTTP locale (protégée par LocalGuard sur localhost)
curl -X POST http://127.0.0.1:3030/api/plugins/init_bundle
```

Dans le Cockpit (`G`), ouvrez l'onglet **Catalogue SAST** et cliquez sur **Déployer (24)**.
{% endtab %}
{% endtabs %}

### Catalogue exact des 24 règles communautaires

Comme `SemgrepImporter::convert_rule` associe Semgrep `ERROR` -> `CRITICAL` et `WARNING` -> `HIGH`, le fichier `community/plugin.yaml` généré contient **17 règles `CRITICAL`** et **7 règles `HIGH`** couvrant 11 langages :

| # | ID de règle | Sévérité Semgrep brute | Sévérité importée | CWE | Langages ciblés |
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

## Fonctionnement de la traduction `SemgrepImporter`

`SemgrepImporter` (`crates/security-linter/src/semgrep_importer.rs`) transforme un `SemgrepRuleFile` (`rules: Vec<SemgrepRuleDef>`) en `PluginManifest` natif (`author: "AetherScope Semgrep Importer"`, `name: "[Semgrep] <rule.id>"`, `category` par défaut `"Semgrep / Imported"`).

### Correspondance Sévérité, CWE & Langages

| Entrée Semgrep | Sortie AetherScope |
|---|---|
| `severity` : `ERROR` / `CRITICAL` | `CRITICAL` |
| `severity` : `WARNING` / `HIGH` / inconnu | `HIGH` |
| `severity` : `INFO` / `MEDIUM` | `MEDIUM` |
| `severity` : `LOW` | `LOW` |
| `metadata.cwe` : `"CWE-89: SQL Injection"` | `"CWE-89 / SQL-INJECTION"` |
| `metadata.cwe` : `89` (entier) | `"CWE-89 / GENERAL"` |
| `metadata.cwe` : `"Deserialization"` (texte) | `"CWE-699 / DESERIALIZATION"` |
| `metadata.cwe` : absent / vide | `"CWE-699 / GENERAL"` |

`languages_to_extensions` trie et déduplique les extensions générées (repli sur `[".rs"]` si `languages` est vide) :
- `rust|rs` -> `[".rs"]`, `python|py` -> `[".py"]`, `javascript|js` -> `[".js", ".jsx", ".mjs", ".cjs"]`, `typescript|ts` -> `[".ts", ".tsx"]`
- `php` -> `[".php", ".phtml"]`, `c` -> `[".c", ".h"]`, `cpp|c++` -> `[".cpp", ".cc", ".hpp", ".h"]`, `solidity|sol` -> `[".sol"]`
- `zig` -> `[".zig"]`, `csharp|cs|c#` -> `[".cs"]`, `go|golang` -> `[".go"]`, `java` -> `[".java"]`, `ruby|rb` -> `[".rb"]`, `json` -> `[".json"]`, `yaml|yml` -> `[".yaml", ".yml"]`

### Traduction des motifs, métavariables et `pattern-not`

- **Métavariables (`$VAR`)** : `$` suivi d'une majuscule ASCII ou `_` (ex. `$X`, `$QUERY`, `$_TMP`) est compilé en `([^,;\)\s]+?)`. Deux occurrences d'une même métavariable n'imposent **pas** d'égalité par rétro-référence.
- **`$` littéral (PHP/JS)** : `$` non suivi d'une majuscule ou `_` (comme `$this` ou `$user`) est échappé en `\$`.
- **Ellipses (`...`)** : `, ...)` devient `(?:\s*,\s*.*?)?`, `(..., ` devient `(?:.*?\s*,\s*)?`, et `...` isolé devient `.*?`.
- **Détection automatique des littéraux** : Si un motif `pattern` ou `pattern-either` contient `"` ou `'`, `conditions.check_literals` passe automatiquement à `true` pour que `AuditContext` ne masque pas les chaînes.
- **Motifs multi-lignes** : Si un motif contient `\n`, `(?s)` est préfixé à la regex et `match_mode` passe à `whole_file` (sinon `line_by_line`).
- **`pattern-regex`** : Copié tel quel dans `conditions.regex_patterns` et validé via `Regex::new`.
- **`pattern-not`** : `extract_not_clause_strings` extrait les jetons identifiants vers `conditions.must_not_contain` (en ignorant les guillemets, les métavariables `$`, les fragments majuscules courts et les jetons déjà présents dans le `pattern` principal).

### Constructions Semgrep supportées vs non supportées

| Construction | Statut | Notes |
|---|---|---|
| `rules[].id`, `languages`, `severity`, `message` | Supporté | Mappé directement sur `PluginRule`. |
| `metadata.{cwe, category, confidence}` | Supporté | `cwe` accepte chaîne unique, liste (prend le premier élément) ou entier. |
| `pattern`, `pattern-either`, `pattern-regex`, `pattern-not` | Supporté | `pattern-either` accepte chaînes simples ou objets `{ pattern / pattern-regex }`. |
| `patterns` (ET logique), `pattern-inside`, `pattern-not-inside`, `pattern-not-regex` | Non supporté | Ignoré lors de la désérialisation YAML ; à affiner manuellement en DSL v2. |
| `metavariable-regex`, `metavariable-comparison`, `mode: taint`, `fix`, `paths` | Non supporté | Utilisez plutôt `taint_sources` / `taint_sinks` / `in_path_matching` de `sast-taint-dsl.md`. |

## Exemple concret : YAML Semgrep vers `PluginManifest`

Voici le résultat exact produit dans `.aether/plugins/imported/sample-semgrep/plugin.yaml` :

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

Remarquez que `jwt-none-algorithm` active automatiquement `check_literals: true` grâce à la chaîne `'none'`, tandis que `python-deserialization-pickle` conserve `check_literals: false` et extrait `safe_loader` depuis `pattern-not` vers `must_not_contain`.

## Workflow CLI `aether-plugin-tool`

Le binaire compagnon `aether-plugin-tool` (`crates/security-linter/src/bin/aether_plugin_tool.rs`) gère l'initialisation, l'import Semgrep, le listage, les tests unitaires et les analyses autonomes :

```bash
# 1. Créer un squelette de plugin avec 2 tests unitaires embarqués
aether-plugin-tool init my-org-rules .aether/plugins

# 2. Importer un fichier ou dossier Semgrep YAML vers .aether/plugins/imported/
aether-plugin-tool import-semgrep --input ./semgrep-rules --output .aether/plugins/imported

# 3. Déployer le Bundle Communautaire de 24 règles hors-ligne
aether-plugin-tool init-bundle .aether/plugins

# 4. Lister les plugins chargés, identifiants CWE, sévérités et extensions
aether-plugin-tool list .aether/plugins

# 5. Exécuter tous les test_cases embarqués (code de sortie 1 en cas d'échec)
aether-plugin-tool test .aether/plugins

# 6. Lancer une analyse par plugins seuls et exporter un catalogue Markdown
aether-plugin-tool scan .aether/plugins ./src
aether-plugin-tool export .aether/plugins PLUGIN_CATALOG.md
```

{% hint style="info" %}
Dans l'interface du Cockpit (`G`), vous pouvez aussi importer des règles via l'onglet **Import Semgrep** (`POST /api/plugins/import_semgrep`) ou déposer un fichier Semgrep `.yaml`/`.yml` directement dans **Catalogue SAST** : `PluginsModal` détecte `pattern-either:`, `pattern:` ou `languages:` et vous redirige automatiquement vers l'importateur Semgrep.
{% endhint %}

{% content-ref url="sast-taint-dsl.md" %}
[DSL Déclaratif SAST & Taint v2](sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[CLIs Plugins, MCP & Runner](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
