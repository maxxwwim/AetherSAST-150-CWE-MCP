# DSL Déclaratif SAST & Taint v2

Rédigez des règles SAST déclaratives, des gardes basées sur la portée AST, des tests unitaires bloquants et des sources, puits (`sinks`) et assainisseurs (`sanitizers`) SSA inter-procéduraux en YAML ou JSON dans `.aether/plugins/`.

## Ordre du pipeline d'évaluation

Lorsque `PluginEngine::audit_file_with_context` analyse un fichier (`crates/security-linter/src/plugin.rs`), chaque règle d'un plugin actif passe par sept étapes déterministes :

1. **Filtre d'extension (`file_extensions`)** : Suffixes en minuscules testés via `lower_path.ends_with(ext)`. Une liste vide cible tous les fichiers non-Markdown (`ast-scanner` ignore le SAST sur `.md`).
2. **Globs d'exclusion (`not_in_path_matching`)** : Compilés via `glob_to_regex` (`(?i)^...$`). Évalués **avant** `in_path_matching` ; si le chemin est exclu, la règle ignore le fichier même s'il correspond aussi à `in_path_matching`.
3. **Globs d'inclusion (`in_path_matching`)** : Si non vide, le chemin normalisé doit correspondre à au moins un glob.
4. **Mode littéraux (`check_literals`)** : `false` (défaut) utilise `AuditContext::default_masked()` (chaînes et commentaires remplacés par des espaces en conservant les numéros de lignes) ; `true` analyse le source brut (`ctx.raw`).
5. **`must_contain` sur fichier complet** : Toutes les sous-chaînes listées doivent apparaître dans `eval_content`, sinon la règle ignore le fichier.
6. **`must_not_contain` sur fichier complet** : Si **une seule** sous-chaîne listée apparaît n'importe où dans `eval_content`, toute la règle est neutralisée pour ce fichier.
7. **Exécution selon `match_mode`** : Exécute `whole_file` (émet à la ligne `1`) ou `line_by_line` (vérifie `ast_scope`, `forbidden_tokens` / `regex_patterns` / repli `must_contain`, puis `not_preceded_within_lines`).

{% hint style="info" %}
Chaque alerte émise par un plugin préfixe automatiquement `rule.description` par `[Plugin: <plugin.name>] ` et déduplique `(rule.id, line_number)` par fichier.
{% endhint %}

## Schéma du manifeste (`PluginManifest`)

Placez chaque pack dans `.aether/plugins/<pack-name>/plugin.yaml` (ou `.yml` / `.json`). `PluginEngine` renseigne automatiquement `folder_alias` avec le nom du répertoire parent immédiat.

### 📝 Champs de `PluginManifest`

| Champ | Type | Requis | Défaut | Description |
|---|---|---|---|---|
| `name` | `string` | Oui | `""` | Nom affiché et cible de sélecteur `--plugins`. |
| `version` | `string` | Oui | `"1.0.0"` | Chaîne de version Semver. |
| `author` | `string` | Non | `None` | Métadonnée d'auteur optionnelle. |
| `description` | `string` | Non | `None` | Résumé optionnel affiché dans `PluginsModal` et `aether-plugin-tool list`. |
| `enabled` | `bool` | Non | `true` | Active/désactive l'exécution et contribue au condensat BLAKE3 `config_digest()`. |
| `profile` | `string` | Non | `None` | Correspond sans sensibilité à la casse à `--plugins profile:<name>`. |
| `tags` | `string[]` | Non | `[]` | Également reconnus sans sensibilité à la casse par `--plugins profile:<tag>`. |
| `taint_sources` | `TaintSourceRule[]` | Non | `[]` | Sources SSA déclaratives. |
| `taint_sinks` | `TaintSinkRule[]` | Non | `[]` | Puits (`sinks`) SSA déclaratifs. |
| `sanitizers` | `SanitizerRule[]` | Non | `[]` | Assainisseurs (`sanitizers`) SSA déclaratifs. |
| `rules` | `PluginRule[]` | Non | `[]` | Règles SAST par motifs. |

## Schéma des règles (`PluginRule` & `RuleConditions`)

### 📝 Champs de `PluginRule`

| Champ | Type | Requis | Défaut | Description |
|---|---|---|---|---|
| `id` | `string` | Oui | `""` | Identifiant unique de règle (ex. `PLUGIN-INJ-POSIX-FLAG-SMUGGLING`). |
| `cwe_id` | `string` | Oui | `""` | Classification CWE (ex. `CWE-88 / POSIX-ARGUMENT-INJECTION-RCE`). |
| `name` | `string` | Oui | `""` | Titre lisible de la règle. |
| `category` | `string` | Non | `"Plugin / Security"` | Catégorie affichée dans les rapports et l'UI. |
| `severity` | `string` | Oui | `""` | Valeurs attendues : `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING`. |
| `description` | `string` | Oui | `""` | Message d'alerte émis lors d'une détection. |
| `remediation` | `string` | Oui | `""` | Conseil de correction affiché dans l'Inspecteur et SARIF. |
| `file_extensions` | `string[]` | Non | `[]` | Suffixes en minuscules (`".rs"`, `".py"`) ; vide = tous fichiers non-Markdown. |
| `match_mode` | `string` | Non | `"line_by_line"` | `line_by_line` ou `whole_file` (`MatchMode`, sérialisé en `snake_case`). |
| `conditions` | `RuleConditions` | Non | `{}` | Prédicats de détection, portées et globs de chemins. |
| `test_cases` | `RuleTestCase[]` | Non | `[]` | Tests unitaires embarqués exécutés par `run_test_suite()` et `/api/plugins/upsert`. |

### 📝 Champs de `RuleConditions`

| Champ | Type | Défaut | Sémantique |
|---|---|---|---|
| `must_contain` | `string[]` | `[]` | TOUTES les sous-chaînes doivent exister dans `eval_content` (fichier entier). Sert aussi de déclencheur ligne/fichier **uniquement** si `forbidden_tokens` et `regex_patterns` sont tous deux vides. |
| `must_not_contain` | `string[]` | `[]` | Évalué sur le **fichier complet** (`eval_content`). Si UNE seule entrée est présente n'importe où dans le fichier, la règle n'émet aucune alerte sur ce fichier. |
| `forbidden_tokens` | `string[]` | `[]` | Déclencheurs par sous-chaîne (OU logique), évalués avant `regex_patterns`. |
| `regex_patterns` | `string[]` | `[]` | Déclencheurs `regex::Regex` Rust (OU logique). Validés avant sauvegarde dans `/api/plugins/upsert`. |
| `check_literals` | `bool` | `false` | `false` : utilise `AuditContext::default_masked()` (chaînes/commentaires masqués). `true` : analyse le source brut avec littéraux et commentaires. |
| `not_preceded_within_lines` | `object` | `None` | `{ patterns: string[], lines: usize }`. Actif uniquement en mode `line_by_line` quand `lines > 0` et `idx > 0`. |
| `in_path_matching` | `string[]` | `[]` | Globs de chemins requis (`glob_to_regex`). |
| `not_in_path_matching` | `string[]` | `[]` | Globs de chemins exclus. Évalués **avant** `in_path_matching`. |
| `ast_scope` | `string` | `None` | Filtre lexical/AST par ligne actif uniquement en mode `line_by_line`. |

### Globs de chemins (`glob_to_regex`)

`glob_to_regex` normalise `\` en `/`, retire `./` et `/` initiaux, puis compile une regex insensible à la casse `(?i)^...$` :

- `**/` devient `(?:.*/)?` (zéro ou plusieurs segments de dossiers).
- `**` en fin de motif devient `.*`.
- `*` devient `[^/]*` (joker sur un segment unique).
- `?` devient `[^/]` (un caractère hors slash).
- Les métacaractères regex (`.+^$()[]{}|\`) sont échappés automatiquement.

### Valeurs et détection `ast_scope`

En mode `line_by_line`, `compute_line_ast_scopes` suit les fichiers de test (`/tests/`, `/test/`, `tests/...`, `test/...`, `_test.rs`, `_tests.rs`, `.spec.`, `.test.`), l'indentation Python (`def ` / `async def ` / `test_*`) et les blocs à accolades (`#[cfg(test)]`, `mod tests {`, `#[test]`, `#[tokio::test...]`, `#[rstest...]`, `async fn `, `async function`, `fn `, `function `).

| Valeurs `ast_scope` acceptées (insensible à la casse) | Condition appliquée |
|---|---|
| `outside_test`, `non_test`, `prod`, `production` | La ligne N'EST PAS dans un fichier, module ou fonction de test (`!in_test`). |
| `test`, `in_test` | La ligne EST dans un contexte de test (`in_test`). |
| `async_fn`, `async`, `async_function` | La ligne est dans une fonction asynchrone hors tests (`in_async_fn && !in_test`). |
| `sync_fn`, `sync`, `sync_function` | La ligne est dans une fonction synchrone hors tests (`in_fn && !in_async_fn && !in_test`). |
| `fn`, `function` | La ligne est dans une fonction quelconque hors tests (`in_fn && !in_test`). |

{% hint style="warning" %}
Toute valeur `ast_scope` non reconnue est évaluée à `true` (aucun filtrage). Vérifiez toujours l'orthographe exacte dans le tableau ci-dessus.
{% endhint %}

### Fenêtre contextuelle (`not_preceded_within_lines`)

Lorsque vous souhaitez une garde **locale** plutôt qu'une suppression sur tout le fichier (`must_not_contain`), utilisez `not_preceded_within_lines` :

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

- Inspecte les lignes strictement précédentes `idx.saturating_sub(win.lines)..idx` (jamais la ligne déclenchée elle-même).
- Chaque ligne de la fenêtre est testée sur `eval_lines` **et** `raw_lines` ; la garde bloque l'alerte si un motif correspond soit en regex compilée, soit par sous-chaîne `.contains(pat)`.
- S'applique **uniquement** en `match_mode: line_by_line`.

## Tests unitaires embarqués (`test_cases`)

Chaque `PluginRule` peut intégrer des tests unitaires autonomes (`RuleTestCase`) :

| Champ | Type | Description |
|---|---|---|
| `name` | `string` | Libellé descriptif du cas de test. |
| `file_name` | `string` | Chemin virtuel (teste `file_extensions`, globs de chemins et `ast_scope`). |
| `code` | `string` | Extrait passé à `audit_file(file_name, code)`. |
| `should_trigger` | `bool` | `true` si `rule.id` doit se déclencher ; `false` si le snippet doit rester sain. |

`PluginEngine::run_test_suite()` exécute tous les `test_cases` de tous les plugins chargés (y compris les manifestes désactivés présents sur disque) et retourne un `PluginTestReport` (`total_tests`, `passed`, `failed`, `failures`). Notez que `POST /api/plugins/upsert` exécute `run_test_suite()` en mémoire avant écriture sur disque et rejette toute règle en échec avec **HTTP 422 Unprocessable Entity**.

## Règles SSA Taint déclaratives

Les plugins peuvent étendre le moteur de taint SSA inter-procédural d'AetherScope (`crates/core-graph/src/dataflow/types.rs`) sans écrire de code Rust.

{% content-ref url="../core/ssa-dataflow-taint.md" %}
[Moteur Dataflow SSA & Taint](../core/ssa-dataflow-taint.md)
{% endcontent-ref %}

### 📝 `taint_sources` (`TaintSourceRule`)

| Champ | Type | Défaut | Notes |
|---|---|---|---|
| `name` | `string` | Requis | Identifiant unique de source. |
| `source_kind` | `SourceKind` | `Custom("custom")` | `HttpQueryParam`, `HttpBodyParam`, `HttpHeader`, `HttpCookie`, `WebSocketPayload`, `FileSystemRead`, `DatabaseRead`, `EnvironmentVar`, `FunctionArgument` ou `Custom(string)` (accepte PascalCase ou `snake_case`). |
| `cwe` | `string` | `""` | CWE ciblé (converti en `"*"` en interne si vide). |
| `patterns` | `string[]` | `[]` | Motifs avec support du joker `*` via `pattern_matches_line`. |
| `language` | `string` | `None` | Filtre optionnel par langage/extension (`*`/`all`/`any` ou nom normalisé). |
| `description` | `string` | `""` | Description lisible de la source. |

### 📝 `taint_sinks` (`TaintSinkRule`)

| Champ | Type | Défaut | Notes |
|---|---|---|---|
| `name` | `string` | Requis | Nom du puits (`sink`). |
| `rule_id` | `string` | `""` | ID d'alerte émis (repli sur `name` si vide). |
| `sink_kind` | `SinkKind` | `Custom("custom")` | `SqlExecution`, `CommandExecution`, `HtmlRender`, `FileAccess`, `SsrfNetworkRequest`, `Deserialization`, `CodeEval`, `LdapQuery` ou `Custom(string)`. |
| `cwe` | `string` | `""` | CWE associé (ex. `"CWE-78"`, `"CWE-89"`). |
| `severity` | `string` | `"HIGH"` | Sévérité (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `patterns` | `string[]` | `[]` | Motifs d'appels/jetons avec support du joker `*`. |
| `language` | `string` | `None` | Filtre optionnel par langage. |
| `description` | `string` | `""` | Description de l'alerte lorsqu'une donnée souillée atteint ce puits. |

### 📝 `sanitizers` (`SanitizerRule`)

| Champ | Type | Défaut | Notes |
|---|---|---|---|
| `name` | `string` | Requis | Nom de l'assainisseur (`sanitizer`). |
| `target_cwes` | `string[]` | `[]` | CWE neutralisés (supporte l'alias YAML/JSON `neutralizes_cwes`). |
| `patterns` | `string[]` | `[]` | Motifs de fonction, méthode, cast de type ou regex. |
| `match_kind` | `SanitizerMatchKind` | `ExactName` | `ExactName` (`exact_name`), `MethodCall` (`method_call`), `TypeCast` (`type_cast`) ou `RegexPattern` (`regex_pattern`). |
| `language` | `string` | `None` | Filtre optionnel par langage. |
| `neutralizes_all` | `bool` | `false` | À `true`, neutralise tous les CWE quel que soit `target_cwes`. |

## Sélection CLI (`--plugins`) et Profils

Passez `--plugins <spec>` à `aether-engine` (`crates/security-linter/src/plugin.rs`) pour piloter la sélection de plugins :

- **Défaut (omis) ou `--plugins default` / `--plugins auto` / `--plugins all`** : Exécute toutes les règles SAST natives ainsi que tous les manifestes actifs de `.aether/plugins/`.
- **`--plugins <selector1>,<selector2>` (`PluginSelection::Select`)** :
  - `profile:<name>` correspond à `manifest.profile` ou à toute entrée de `manifest.tags` (insensible à la casse).
  - `<name>` seul correspond à `manifest.name` ou `manifest.folder_alias` (le nom du dossier sous `.aether/plugins/`, insensible à la casse).
  - Si un sélecteur ne correspond ni à un plugin actif ni à `BUILTIN_PACK_NAMES`, `load_with_selection` échoue et `aether-engine` quitte avec le code `1`.

{% hint style="danger" %}
**Point vérifié dans le code (`PluginSelection::Select`)** : Dans `ProjectScanner::scan_project_with_exclusions` (`crates/ast-scanner/src/scanner.rs`), `run_builtin_sast` vaut `!matches!(self.plugin_selection, PluginSelection::Select(_))`. Passer `--plugins <selector>` **désactive toutes les règles SAST natives** et n'exécute que les manifestes correspondants de `.aether/plugins/`. Bien que `BUILTIN_PACK_NAMES` (34 alias intégrés tels que `builtin-rust`, `web3`, `python`, `epic`) et `SecurityLinter::audit_file_selected` existent dans `security-linter`, `audit_file_selected` n'est actuellement pas branché dans `ProjectScanner` ni dans `desktop-shell`.
{% endhint %}

## Exemples concrets et édition dans le Studio

Vous pouvez rédiger vos plugins directement en YAML ou de façon interactive dans `PluginsModal` (`G` -> onglets **Règle DSL v2**, **Taint SSA** et **Bac à Sable**).

{% tabs %}
{% tab title="Règle SAST (.aether/plugins/example-custom-auth/plugin.yaml)" %}
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

{% tab title="SAST + Taint SSA (.aether/plugins/majestic-injections/plugin.yaml)" %}
{% code title=".aether/plugins/majestic-injections/plugin.yaml" overflow="wrap" %}
```yaml
name: "majestic-injections"
version: "1.0.0"
author: "AetherScope Security Lab"
description: "Détecte l'Argument Smuggling POSIX (CWE-88), l'import ESM fileless (CWE-94) et les wrappers PHP phar:// (CWE-98)."
enabled: true
profile: "strict"
tags: ["injection", "rce", "posix", "esm", "php"]

taint_sources:
  - name: "http_req_query"
    source_kind: "HttpQueryParam"
    cwe: "CWE-20"
    patterns: ["req.query", "$_GET", "Query("]
    description: "Paramètre HTTP Query externe non fiable"
  - name: "cli_repo_url_arg"
    source_kind: "FunctionArgument"
    cwe: "CWE-88"
    patterns: ["repo_url", "user_arg", "untrusted_input"]
    description: "Argument fonction externe transmis à un sous-processus"

taint_sinks:
  - name: "posix_command_spawn"
    rule_id: "TAINT-SINK-POSIX-CMD"
    sink_kind: "CommandExecution"
    cwe: "CWE-78"
    severity: "CRITICAL"
    patterns: ["Command::new", "child_process.exec", "os.system"]
    description: "Exécution de processus système atteinte par une source non assainie"

sanitizers:
  - name: "strict_allowlist_guard"
    target_cwes: ["CWE-78", "CWE-88", "CWE-89", "CWE-22", "CWE-79"]
    patterns: ["sanitize_arg", "PathGuard::validate", "htmlspecialchars", "bind_param"]
    match_kind: "ExactName"
    neutralizes_all: false

rules:
  - id: "PLUGIN-INJ-POSIX-FLAG-SMUGGLING"
    cwe_id: "CWE-88 / POSIX-ARGUMENT-INJECTION-RCE"
    name: "Smuggling de Drapeaux Exécutables POSIX sans Délimiteur '--'"
    category: "Code & File Injection"
    severity: "CRITICAL"
    description: "Exécution de git, tar, find, rg ou ssh avec un argument dynamique non précédé du séparateur '--'."
    remediation: "Insérer systématiquement l'argument séparateur '--' avant toute valeur utilisateur."
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
      - name: "Exécution git clone sans '--' (Vulnérable)"
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

### 💡 Commandes de vérification rapide

```bash
# Exécuter tous les test_cases embarqués sous .aether/plugins/
aether-plugin-tool test .aether/plugins

# Auditer un répertoire cible avec uniquement les plugins du profil strict
aether-engine -p . --audit-only --plugins profile:strict
```

{% content-ref url="semgrep-and-community-bundle.md" %}
[Importateur Semgrep & Bundle Communautaire](semgrep-and-community-bundle.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[CLIs Plugins, MCP & Runner](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
