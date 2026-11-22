# Moteur SAST et CWE

Analysez des arborescences polyglottes et des lockfiles en temps réel grâce à 223 détecteurs natifs de sécurité, 24 règles Semgrep OWASP/CWE embarquées (247 règles au total), un masquage lexical double passe et la corrélation de vulnérabilités OSV atteignables.

## Architecture et répartition des règles

La crate `security-linter` exécute une analyse statique déterministe couplée aux contrats architecturaux EARS et à l'analyse de composition logicielle atteignable (SCA). Toutes les règles natives sont enregistrées via `SecurityLinter::get_supported_cve_rules()` dans sept modules Rust, complétés par un pack communautaire Semgrep embarqué.

| Module source / Ressource | Point d'entrée Rust | Règles | Portée principale |
|---|---|---:|---|
| `crates/security-linter/src/linter.rs` | `SecurityLinter::get_supported_cve_rules()` | **101** | Rust/Réseau (14 dont 1 L1), L1/Web3/Crypto (34), MMO/Concurrence (5), SAST/Injection (17), Architecture/Frontières (7), Front-End/DOM (13), C/C++ FFI & Réseau (11) |
| `crates/security-linter/src/rules.rs` | `AdvancedDefiRules::definitions()` | **6** | Invariants DeFi (`DEFI-ASYMMETRIC-ROUNDING`, `DEFI-STALE-CACHE-AFTER-CALL`, `EVC-HOOK-BYPASS`) et coupe-circuits d'oracles |
| `crates/security-linter/src/deep_rules.rs` | `DeepSecurityRules::definitions()` | **27** | ZK-SNARKs, réentrance en lecture seule DeFi, VM à modèle de comptes, sûreté Rust/LLVM/ABI/Unwind/Mmap, Wasm, Rollups L2, ERC-4337, `CVE-INJ-*` |
| `crates/security-linter/src/php_rules.rs` | `PhpSecurityRules::definitions()` | **26** | PHP 8.x & Sécurité Web (SQLi, RCE, `unserialize`, LFI/RFI, `phar://`/`php://filter`, SSTI, XXE, type juggling) |
| `crates/security-linter/src/zig_rules.rs` | `ZigSecurityRules::definitions()` | **15** | Allocateurs Zig, UAF, `@ptrCast`, `@setRuntimeSafety(false)`, interop C-ABI, SIMD `@Vector`, TLS, PRNG |
| `crates/security-linter/src/csharp_rules.rs` | `CSharpSecurityRules::definitions()` | **20** | C# / .NET / ASP.NET Core / EF Core (`BinaryFormatter`, SQLi, `Process.Start`, `Path.Combine`, `stackalloc`, réflexion) |
| `crates/security-linter/src/epic_novel_rules.rs` | `EpicNovelRules::definitions()` | **28** | Détecteurs sémantiques hors CWE `AETHER-*`, Unicode Trojan Source et portes dérobées RCE / compile-time furtives |
| **Sous-total natif** | `SecurityLinter::get_supported_cve_rules()` | **223** | **223** `rule_id` uniques, **52** chaînes de catégorie, **84** identifiants `CWE-NNN` distincts (**88** au total avec le pack communautaire) |
| `crates/security-linter/rules/community_owasp_cwe.yaml` | `CommunityBundle::load_embedded_manifest()` | **24** | Pack Semgrep OWASP Top 10 & CWE Top 25 embarqué (`22` identifiants `CWE-NNN` distincts) |
| **Total général** | Règles natives + Pack communautaire embarqué | **247** | Déployé vers `.aether/plugins/community/plugin.yaml` via `--update-rules` ou `aether-plugin-tool init-bundle` |

Sur les **223 règles natives**, les sévérités se répartissent en **134 `CRITICAL`**, **83 `HIGH`**, **4 `MEDIUM`** et **2 `WARNING`** (`RULE_MAX_LINES` et `RULE_MAX_FILES`).

{% hint style="info" %}
**Note sur le comptage v2.6.0 :** D'anciens fichiers du dépôt (`crates/security-linter/README.md`, `CWE_CATALOG.md` et `cwe/README.md`) mentionnent encore `222 + 24 = 246` règles issues de la v2.5.1. L'inspection directe de `crates/security-linter/src/` prouve que `aether-engine` v2.6.0 embarque **223 règles natives + 24 règles communautaires = 247 règles au total**.
{% endhint %}

## API `SecurityLinter` et modèle de violation

Chaque détecteur natif et chaque règle de contrat de dossier émet une structure `LinterViolation`, tandis que `CveRuleDef` décrit les métadonnées et l'éligibilité aux fichiers.

### 📝 Structures `LinterViolation` & `CveRuleDef`

| Structure | Champ | Type | Description |
|---|---|---|---|
| `LinterViolation` | `file_path` | `String` | Chemin relatif ou normalisé du fichier audité. |
| `LinterViolation` | `line_number` | `usize` | Numéro de ligne (indexé à partir de 1) de l'anomalie. |
| `LinterViolation` | `rule_id` | `String` | Identifiant unique de la règle (ex. `CVE-RUST-ASYNC-MUTEX` ou `AETHER-RUST-EPHEMERAL-LOCK-DROP`). |
| `LinterViolation` | `cve_id` | `String` | Étiquette CWE / taxonomie (ex. `CWE-667 / ASYNC-DEADLOCK`). |
| `LinterViolation` | `severity` | `String` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"` ou `"WARNING"` (les plugins personnalisés peuvent aussi émettre `"LOW"`). |
| `LinterViolation` | `message` | `String` | Résumé lisible de la détection. |
| `LinterViolation` | `transmitted_data` | `Option<String>` | Extrait ou paramètre détecté optionnel (`skip_serializing_if = "Option::is_none"`). |
| `LinterViolation` | `transmitted_type` | `Option<String>` | Descripteur optionnel du type de puits ou de donnée (`skip_serializing_if = "Option::is_none"`). |
| `LinterViolation` | `remediation` | `String` | Recommandation de correction affichée dans le Cockpit, le CLI et SARIF. |
| `CveRuleDef` | `rule_id` | `String` | Identifiant unique renvoyé par `get_supported_cve_rules()`. |
| `CveRuleDef` | `cve_id` | `String` | Chaîne CWE ou taxonomie `AETHER-*` associée. |
| `CveRuleDef` | `name` | `String` | Titre de la règle. |
| `CveRuleDef` | `category` | `String` | Chaîne de regroupement (52 valeurs distinctes dans le catalogue natif). |
| `CveRuleDef` | `severity` | `String` | Sévérité de la règle (`CRITICAL`, `HIGH`, `MEDIUM` ou `WARNING`). |
| `CveRuleDef` | `description` | `String` | Explication détaillée de la vulnérabilité. |
| `CveRuleDef` | `default_enabled` | `bool` | Activation par défaut (`true` pour les 223 règles natives). |

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

### 📝 Arguments / Paramètres

| Méthode | Paramètre | Type | Description |
|---|---|---|---|
| `audit_file` | `file_path` | `&str` | Chemin utilisé pour le routage par langage/extension et l'exclusion des tests. |
| `audit_file` | `content` | `&str` | Contenu source brut en UTF-8 du fichier. |
| `audit_file` | `contract` | `Option<&ReadmeContract>` | Contrat EARS optionnel du dossier parent (en-tête YAML de `README.md`). |
| `audit_file_with_context` | `ctx` | `&AuditContext<'_>` | Contexte de masquage partagé (`OnceLock`) réutilisé entre `SecurityLinter` et `PluginEngine`. |
| `audit_file_selected` | `selection` | `&PluginSelection` | Sélecteur `--plugins` parsé (`Default`, `Auto`, `All` ou `Select(Vec<String>)`). |
| `audit_file_with_plugins` | `plugin_engine` | `&mut PluginEngine` | Exécute les règles natives plus les règles YAML/JSON actives de `.aether/plugins/`. |

### 💎 Valeur de retour / Réponse

| Méthode | Type de retour | Sémantique |
|---|---|---|
| `get_supported_cve_rules` | `Vec<CveRuleDef>` | Renvoie les **223** définitions natives ; chacune expose `.target_file_types()` et `.matches_file(path)`. |
| `audit_file*` | `Vec<LinterViolation>` | Renvoie toutes les violations vérifiées en double passe pour le fichier. |

### 💡 Exemple

```rust
use security_linter::lexer::AuditContext;
use security_linter::linter::SecurityLinter;

let source = "pub async fn handler(lock: &std::sync::Mutex<u64>) { let _g = lock.lock(); foo().await; }";
let ctx = AuditContext::new("src/server.rs", source);
let violations = SecurityLinter::audit_file_with_context(&ctx, None);
assert!(violations.iter().any(|v| v.rule_id == "CVE-RUST-ASYNC-MUTEX"));
```

## Masquage lexical double passe (`AuditContext`)

Pour éviter que les règles heuristiques ne se déclenchent sur des commentaires, des docstrings, des messages d'erreur ou des littéraux de chaîne, `crates/security-linter/src/lexer.rs` implémente un masqueur lexical sans regex partagé entre `SecurityLinter` et `PluginEngine`.

### Variantes `Lang` et correspondance d'extensions

| Variante `Lang` | Extensions ciblées | Règles lexicales gérées |
|---|---|---|
| `Lang::Rust` | `.rs` | Commentaires ligne `//`, blocs imbriqués `/* ... */`, chaînes brutes (`r"..."`, `r#"..."#`, `br#"..."#`), littéraux `char` vs durées de vie `'a` |
| `Lang::Python` | `.py` | Commentaires `#`, guillemets simples/doubles, chaînes triples (`"""..."""`, `'''...'''`) |
| `Lang::Zig` | `.zig` | Commentaires `//`, littéraux multilignes `\\`, littéraux `char`, chaînes entre guillemets doubles |
| `Lang::CSharp` | `.cs` | `//`, `/* */`, chaînes verbatim (`@"..."`, `$@"..."`, `@$"..."` avec `""`), chaînes interpolées `$"..."`, littéraux `char` |
| `Lang::Php` | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps` | Commentaires `//`, `/* */`, `#`, chaînes à guillemets simples et doubles |
| `Lang::CLike` | `.js`, `.ts`, `.tsx`, `.jsx`, `.mjs`, `.cjs`, `.sol`, `.circom`, `.c`, `.cpp`, `.cc`, `.h`, `.hpp`, `.java` | `//`, `/* */`, `'`, `"`, backticks `` ` `` |

### `mask_literals` vs `mask_comments_only` et `LITERAL_AWARE_RULES`

`AuditContext<'a>` calcule `masked_literals` et `masked_comments` paresseusement au plus une fois par fichier via `std::sync::OnceLock<String>`, en préservant les délimiteurs, `\r` et `\n` afin de conserver les numéros de lignes exacts :

1. **`mask_literals(src, lang)`** : Remplace l'intérieur des commentaires et des littéraux de chaîne par `' '`.
2. **`mask_comments_only(src, lang)`** : Remplace uniquement les commentaires par `' '`, tout en conservant le contenu des chaînes.
3. **`AuditContext::default_masked()`** : Renvoie `masked_comments()` pour `Lang::Python` et `Lang::Php` (car les règles Python/PHP inspectent des requêtes SQL, superglobales et en-têtes dans les chaînes), `masked_literals()` pour `Rust`, `CLike`, `Zig` et `CSharp`, et `raw` lorsque `lang` vaut `None`.

Dans `SecurityLinter::audit_file_with_context`, le moteur exécute d'abord `audit_file_raw` sur `ctx.raw`. Si `ctx.lang.is_some()` et que des détections brutes existent, il lance une seconde passe sur `ctx.default_masked()` et ne conserve une violation **que si** :
- le couple `(rule_id, line_number)` se déclenche aussi sur la passe masquée, **ou**
- `rule_id` figure dans **`LITERAL_AWARE_RULES`** (`linter.rs:1080-1155`, **74 règles** sensibles aux littéraux, dont `SAST_HARDCODED_SECRET`, `SAST_RAW_SQL_INJECTION`, `CVE-WEB3-AUTH-BYPASS-MOCK`, `SAST_DIRECT_ENV_ACCESS`, les 5 règles de contrat `RULE_*`, `CVE-DB-REDIS-UNAUTH-KEYS-DOS`, `CVE-RUST-COMMAND-INJECTION-SHELL`, `CVE-CPP-NET-FORMAT-STRING-LOGGING`, `CVE-INJ-*`, les 26 règles `CVE-PHP-*`, les 20 règles `CVE-CS-*`, 4 règles `CVE-ZIG-*` et 8 règles `AETHER-*`).

### Filtrage des tests et exemptions de portée

- **Auto-exclusion (`is_linter_catalog`)** : Ignore les fichiers catalogue de `security-linter/src/` (`linter.rs`, `rules.rs`, `deep_rules.rs`, `epic_novel_rules.rs`, `php_rules.rs`, `zig_rules.rs`, `csharp_rules.rs`, `lexer.rs`) pour éviter tout auto-déclenchement.
- **Exclusion des tests, fixtures et outils (`is_test_file`)** : Ignore `/test/`, `/tests/`, `/testing/`, `/testsuite/`, `/pytest/`, `integration-tests`, `test-loop-tests`, `test-utils`, `testlib`, `test-contracts`, `runtime-params-estimator`, `adversarial`, `/benches/`, `/benchmarks/`, `/examples/`, `/fixtures/`, `/testdata/`, `/genesis-tools/`, `/devtools/`, `/buildtools/`, `/tools/`, `debug_scripts`, `/mock`, `/fuzz/`, `/certora/`, `/script/`, `/scripts/`, `tests.rs`, `test.rs`, `testing.rs`, `test_utils.rs`, `bench.rs`, `benches.rs`, `build.rs`, `*_test.rs`, `*_tests.rs`, `*.pb.rs`, `*.generated.rs`, `*_generated.rs`, `test_*`, `*.t.sol` et `*.s.sol`.
- **Exception `build.rs` dans `epic_novel_rules.rs`** : `EpicNovelRules::audit_file` lève explicitement l'exclusion `is_test_file` pour `build.rs` (`is_test_file && !is_build_script`) afin que `AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR`, `AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR`, `AETHER-RUST-FILELESS-WX-MEMFD-RCE`, `AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE` et `AETHER-STEALTH-UNICODE-TROJAN-SOURCE` auditent bien les scripts de compilation.
- **Suppression des tests inline Rust (`strip_rust_inline_tests`)** : Tronque les fichiers `.rs` dès le premier `#[cfg(test)]`, `#[cfg(all(test...))]`, `mod tests {` ou `mod test {`, et ignore les blocs `#[test]`, `#[tokio::test...]` et `#[cfg(feature = "test_features"...)]`.
- **Nuance pour les tests inline Zig** : `ast-scanner` définit `strip_zig_inline_tests` pour l'extraction AST (`analyze_zig`), mais `SecurityLinter` et `zig_rules.rs` ne suppriment **pas** les blocs `test "..." { ... }` inline dans les fichiers `.zig` de production (seuls les chemins correspondant à `is_test_file` sont ignorés).
- **Exemption des interfaces et types (`is_interface_or_types`)** : Ignore `/interface`, `interface.sol`, `.d.ts`, `I[A-Z]*.sol`, `I[A-Z]*.java`, `/types/`, les fichiers Solidity `interface` sans `contract` et les interfaces Java. Une surcharge explicite `file_max_lines` dans `README.md` continue toutefois d'appliquer `RULE_MAX_LINES`.

## Pipeline SCA OSV atteignable (`sca/*`)

En complément de l'analyse du code source, `security-linter` parse les lockfiles de dépendances, interroge `api.osv.dev` (avec cache BLAKE3 hors ligne) et détermine si les fonctions vulnérables sont réellement atteignables depuis vos points d'entrée.

```text
Lockfiles (Cargo.lock / package-lock.json / composer.lock)
   │  sca/lockfile.rs :: scan_project_lockfiles()
   ▼
Requête OSV (cache d'abord -> curl https://api.osv.dev/v1/query sauf --offline-sca)
   │  sca/cache.rs    :: .aether/cache/osv/<blake3_hex>.json
   ▼
Attachement des puits au graphe (dep::<pkg>::<fn> -> «Vulnerable Dependency»)
   │  sca/cross_ref.rs :: cross_reference_reachability()
   ▼
BFS inverse d'atteignabilité (core_graph::reachability::compute_reachability)
   └─► is_reachable = true/false + plus court exploit_path[]
```

### Lockfiles pris en charge

`scan_project_lockfiles` (`crates/security-linter/src/sca/lockfile.rs:287-322`) inspecte la racine du projet et ses sous-dossiers directs de niveau 1 (en ignorant `target`, `node_modules` et `.git`) pour **exactement trois formats de lockfile** :

| Lockfile | Fonction de parsing | Formats pris en charge | Écosystème OSV |
|---|---|---|---|
| `Cargo.lock` | `parse_cargo_lock_content` | Blocs TOML <code>&#91;&#91;package&#93;&#93;</code> avec `source` `registry+` ou `git+` | `crates.io` |
| `package-lock.json` | `parse_package_lock_content` | Lockfiles npm **v1** (`dependencies` récursif) et **v2 / v3** (`packages` plat), avec suivi du drapeau `dev` | `npm` |
| `composer.lock` | `parse_composer_lock_content` | Sections `"packages"` (`is_dev: false`) et `"packages-dev"` (`is_dev: true`), avec retrait du préfixe `v` | `Packagist` |

{% hint style="warning" %}
**Lockfiles non pris en charge (`pnpm-lock.yaml`, `requirements.txt`) :** `sca/lockfile.rs` ne parse **que** `Cargo.lock`, `package-lock.json` et `composer.lock`. Les fichiers `pnpm-lock.yaml` et `requirements.txt` ne sont **pas** analysés par le moteur SCA (tout autre format passé à `parse_lockfile_path` renvoie `Err("Unsupported lockfile type")`).
{% endhint %}

### Cache BLAKE3 déterministe et atteignabilité

- **Chemin et clé de cache (`sca/cache.rs`)** : Stocké dans `<project_root>/.aether/cache/osv/<blake3_hex>.json`, où `<blake3_hex>` vaut `blake3::hash("{ecosystem}:{package}:{version}".as_bytes()).to_hex()`.
- **Pré-remplissage du cache** : `OsvCache::get` lit `OsvCacheEntry` (`cache_version: 1`) et tolère aussi des fichiers JSON bruts `{"vulns": [...]}` (`OsvQueryResponse`) ou `Vec<OsvVulnerability>` pour alimenter des environnements isolés.
- **Mode en ligne vs hors ligne (`sca/osv.rs`)** : En mode en ligne, le moteur exécute `curl -sSL --max-time 5 -X POST -H "Content-Type: application/json" -d <payload> https://api.osv.dev/v1/query` et retombe proprement sur une liste vide en cas d'échec réseau. Avec `--offline-sca`, tout défaut de cache renvoie vide sans aucun trafic réseau.
- **Corrélation sur le graphe d'appels (`sca/cross_ref.rs`)** : Crée ou rattache les nœuds puits (`dep::<pkg>::<fn>`, `crate::<pkg>::<fn>` ou `dep::<pkg>`) avec le stéréotype `"«Vulnerable Dependency»"` et l'ID `SCA-<advisory_id>`, relie les appels correspondants dans `metadata.methods[*].calls` via `EdgeType::Call`, puis appelle `core_graph::reachability::compute_reachability(graph)` pour remplir `is_reachable`, le plus court `exploit_path`, `reachable_count` et `unreachable_count`.

### Options CLI SCA et règles

{% tabs %}
{% tab title="SAST complet + SCA atteignable" %}
```bash
# Exécuter le SAST natif + plugins avec résolution OSV en ligne et atteignabilité
aether-engine --path . --audit-only --sca --format sarif --output results.sarif
```
{% endtab %}
{% tab title="SCA hors ligne (Air-Gapped)" %}
```bash
# Forcer une analyse 100 % hors ligne via le cache .aether/cache/osv/
aether-engine --path . --audit-only --sca --offline-sca
```
{% endtab %}
{% tab title="Porte SCA seule & Pack communautaire" %}
```bash
# Auditer uniquement les lockfiles et échouer seulement sur des CVE HIGH+ atteignables
aether-engine --path . --sca-only --fail-on HIGH

# Décompresser les 24 règles Semgrep embarquées dans .aether/plugins/community/plugin.yaml
aether-engine --path . --update-rules
```
{% endtab %}
{% endtabs %}

## Sortie SARIF v2.1.0 et portes qualité CI/CD

`crates/security-linter/src/sarif.rs` sérialise les détections au standard OASIS SARIF v2.1.0 pour GitHub Code Scanning et vos pipelines CI :

- **`$schema`** : `https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json` (`version: "2.1.0"`).
- **`tool.driver`** : `name: "AetherScope"`, `version: "2.6.0"` (`env!("CARGO_PKG_VERSION")`), `informationUri: "https://github.com/aether-engine"`.
- **Correspondance des sévérités (`severity_to_sarif_level`)** : `CRITICAL` / `HIGH` -> `"error"`, `MEDIUM` -> `"warning"`, `LOW` / `WARNING` / `INFO` / `NOTE` -> `"note"`.
- **URI et extraits** : `normalize_sarif_uri_with_root` supprime le préfixe Windows `\\?\`, convertit `\` en `/`, retire `project_root`, positionne `uriBaseId: "%SRCROOT%"`, borne `startLine >= 1` et expose `is_reachable`, `exploit_path`, `cveId`, `remediation`, `transmittedData` et `transmittedType` dans `properties`.
- **Liens d'aide (`cwe_to_help_uri`)** : Pointe les règles `CWE-NNN` vers `https://cwe.mitre.org/data/definitions/<NNN>.html` et les détecteurs `AETHER-*` vers `https://github.com/aether-engine/blob/main/CWE_CATALOG.md#<lowercase_rule_id>`.

### Formats CLI et sémantique de `--fail-on`

| Option | Valeurs acceptées | Comportement |
|---|---|---|
| `--format` | `text` (défaut), `markdown`, `sarif` | `sarif` génère du JSON SARIF v2.1.0 (vers `-o/--output` ou stdout). `text` et `markdown` écrivent tous deux `.aether/LIVE_AUDIT.md`, affichent un résumé console et copient vers `-o/--output` si fourni. |
| `-o`, `--output` | `<PATH>` | Chemin cible du JSON SARIF ou de la copie de `LIVE_AUDIT.md` (crée les dossiers parents). |
| `--fail-on` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING` | Quitte avec le code **`1`** si des détections atteignent ou dépassent le seuil (`HIGH` couvre `CRITICAL\|HIGH` ; `MEDIUM` couvre `CRITICAL\|HIGH\|MEDIUM` ; `LOW\|WARNING` couvre les cinq niveaux). |

{% hint style="warning" %}
**Il n'existe pas d'option `--format json` :** `crates/desktop-shell/src/main.rs` distingue uniquement `--format sarif` du mode non-SARIF (`text` / `markdown`). Notez également deux subtilités de `--fail-on` : sous `--audit-only`, les détections taint marquées `taint_trace.is_sanitized == true` sont **ignorées** par la porte d'échec ; sous `--sca-only`, **seules** les vulnérabilités `is_reachable == true` peuvent déclencher le code de sortie `1`.
{% endhint %}

### 💡 Exemple : workflow GitHub Actions SARIF

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

## Suppression, filtrage et sélecteurs `--plugins`

{% hint style="danger" %}
**Les commentaires inline `// aether-ignore` et `# aether-ignore` ne sont PAS implémentés :** Ajouter `// aether-ignore`, `# aether-ignore`, `# noqa` ou `// nolint` dans votre code source n'a aucun effet dans `aether-engine` v2.6.0. Utilisez les mécanismes pris en charge ci-dessous.
{% endhint %}

1. **`.aether/settings.json` (`SettingsPayload`)** :
   - `active_cve_rules` : Liste blanche optionnelle de `rule_id` natifs. Les règles de contrat (`BLAKE3_TAMPERED`, `RULE_MAX_LINES`, `RULE_MAX_FILES`, `RULE_FORBIDDEN_FUNCTION`, `RULE_FORBIDDEN_EXTENSION`) et les règles plugins/taint restent actives sauf si `active_cve_rules` vaut `[]`.
   - `ignored_cwes` : Correspondances par sous-chaîne insensibles à la casse testées sur `rule_id` et `cve_id` (ex. `"CWE-89"` ou `"CVE-RUST-PANIC-DOS"`).
   - `exclusions` : Exclusions de dossiers ou chemins transmises à `ProjectScanner::scan_project_with_exclusions`.
   - **Avertissement de portée** : `apply_settings_filters_to_graph` s'applique dans le Cockpit, le serveur HTTP (`POST /api/settings`) et le `FileWatcher` — il n'est **pas** appliqué lors des exécutions CLI headless `aether-engine --audit-only`.
2. **Annotations `// SAFETY:` (fenêtre `[-6..+4]` lignes)** :
   - Placer `// SAFETY:`, `// SAFE:` ou `/* SAFETY:` entre 6 lignes au-dessus et 4 lignes en dessous d'un bloc `unsafe` ou `std::mem::transmute` supprime `CVE-RUST-UNSAFE-MEM` et `CVE-RUST-TRANSMUTE-SIZE-MISMATCH`.
3. **Contrats de dossier EARS (en-tête YAML `README.md`)** :
   - Configurez `security_rules.no_raw_sql`, `security_rules.no_env_access`, `forbidden_imports`, `forbidden_functions`, `allowed_extensions` / `forbidden_extensions` et `file_max_lines`.
4. **Sélecteurs CLI `--plugins`** :
   - `default` (omis) : exécute les **223** règles natives et tous les manifestes actifs de `.aether/plugins/`.
   - `auto` ou `all` : exécute toutes les règles natives et les manifestes `.aether/plugins/` correspondants.
   - `<pack1>,<pack2>,profile:<name>` : filtre les règles natives via les alias de packs intégrés (`rust`, `rust-l1`, `web3`, `solidity`, `defi`, `python`, `js`, `ts`, `php`, `zig`, `csharp`, `dotnet`, `cpp`, `deep`, `epic`, `novel`, `architecture`, `core`) et filtre les plugins locaux par `name`, `folder_alias`, `profile` ou `tags`. Un sélecteur invalide quitte avec le code `1`.

{% code title=".aether/settings.json" overflow="wrap" %}
```json
{
  "exclusions": ["vendor/", "legacy-fixtures/"],
  "ignored_cwes": ["CVE-RUST-PANIC-DOS", "CWE-829"],
  "active_cve_rules": null
}
```
{% endcode %}

## Guides associés

{% content-ref url="cwe-catalog-reference.md" %}
[Référence du catalogue CWE et des règles](cwe-catalog-reference.md)
{% endcontent-ref %}

{% content-ref url="ssa-dataflow-taint.md" %}
[Flux de données SSA et analyse de taint](ssa-dataflow-taint.md)
{% endcontent-ref %}

{% content-ref url="blake3-governance.md" %}
[Gouvernance BLAKE3 et contrats EARS](blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[DSL déclaratif SAST et Taint v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../console/aether-engine-cli.md" %}
[Référence CLI aether-engine](../console/aether-engine-cli.md)
{% endcontent-ref %}
