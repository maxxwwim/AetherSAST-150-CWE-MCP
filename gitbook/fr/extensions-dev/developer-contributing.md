# Guide développeur et contribution

Ce guide présente le workspace hexagonal `aether-engine` `2.6.0`, les suites de tests Rust et Svelte 5, ainsi que l'ajout de règles SAST, d'extracteurs AST et de plugins visuels WebGL 2.

## Architecture du workspace (7 crates + runner exclu)

Le `Cargo.toml` racine (`version = "2.6.0"`, `edition = "2021"`, `license = "PolyForm-Noncommercial-1.0.0"`) structure `aether-engine` en 7 crates workspace plus un crate binaire autonome exclu (`apps/aethercraft/runner`).

| Crate / Chemin | Couche | Rôle et binaires | Dépendances principales |
| :--- | :--- | :--- | :--- |
| `crates/core-graph` | `domain` | Modèle de graphe pur (`AetherGraph`, `SymbolBubble`, `AffiliationEdge`, layouts, reachability) — zéro I/O | `serde`, `serde_json`, `bitflags`, `rayon` |
| `crates/security-linter` | `domain` | 223 règles SAST natives, DSL déclaratif v2, SCA OSV, contrats EARS/BLAKE3 ; binaire `aether-plugin-tool` | `core-graph`, `serde`, `serde_json`, `serde_yaml`, `blake3`, `regex` |
| `crates/arch-templates` | `utility` | Templates multi-stack `ArchScaffolder` (`PureRust`..`ClassicMvc`) | `core-graph`, `serde`, `serde_json`, `toml`, `blake3` |
| `crates/ast-scanner` | `action` | Scanner AST polyglotte, parcours Rayon, cache BLAKE3 `.aether/cache/ast/` | `core-graph`, `security-linter`, `walkdir`, `rayon`, `regex`, `toml` |
| `crates/obsidian-vault` | `application` | Détecteur de coffre Obsidian et scanner Markdown de notes/wikilinks/tags | `core-graph`, `serde`, `serde_yaml`, `regex`, `walkdir`, `rayon`, `thiserror` |
| `crates/ai-file-bridge` | `action` | `FileWatcherBridge`, `TaskManager`, `HandshakePacker`, `AuditWriter`, `PatchVerifier` | `core-graph`, `security-linter`, `notify`, `tokio`, `chrono`, `colored` |
| `crates/desktop-shell` | `ui` | Serveur REST Axum, `LocalGuard`, shell desktop Wry/Tao WebView2, serveur MCP ; binaires `aether-engine`, `aetherscope-mcp` | Les 6 crates frères + `axum`, `tokio`, `clap`, `wry`, `tao`, `rfd` |
| `apps/aethercraft/runner` *(exclu)* | `standalone` | Binaire autonome `aether-mc-runner` (`v1.0.0`) avec sa propre table `[workspace]` | `tokio`, `serde`, `blake3`, `clap`, `reqwest`, `sha2`, `anyhow` |

{% hint style="danger" %}
Chaque dossier sous `crates/` possède un `README.md` scellé en BLAKE3 dans `aether.lock.toml`. Si vous modifiez un contrat `crates/*/README.md`, re-signez-le via le Cockpit ou `POST /api/contracts/sign` afin qu'`ast-scanner` ne lève pas une violation `CRITICAL` `BLAKE3_TAMPERED`.
{% endhint %}

## Compilation et exécution des suites de tests

{% tabs %}
{% tab title="Workspace Rust & E2E V3" %}
```bash
# Exécuter tous les tests unitaires et d'intégration du workspace
cargo test --workspace

# Exécuter les 4 suites E2E V3 (44 tests au total dans ces 4 fichiers)
cargo test -p desktop-shell --test e2e_r1_semgrep --test e2e_r2_dataflow_ssa --test e2e_r3_reachable_sca --test e2e_tier3_tier4_scenarios

# Exécuter chaque suite E2E séparément avec logs stdout
cargo test -p desktop-shell --test e2e_r1_semgrep -- --nocapture             # 12 tests
cargo test -p desktop-shell --test e2e_r2_dataflow_ssa -- --nocapture        # 14 tests
cargo test -p desktop-shell --test e2e_r3_reachable_sca -- --nocapture       # 12 tests
cargo test -p desktop-shell --test e2e_tier3_tier4_scenarios -- --nocapture  # 6 tests

# Vérifier le runner AetherCraft exclu du workspace
cargo check --manifest-path apps/aethercraft/runner/Cargo.toml
```
{% endtab %}
{% tab title="UI Svelte 5 (crates/desktop-shell/ui)" %}
```bash
cd crates/desktop-shell/ui

# Vérifier le typage des templates Svelte 5 et des configs TypeScript
npm run check

# Compiler le bundle UI de production (dist/)
npm run build

# Exécuter les 3 scripts de tests comportementaux et adversariaux
npm test
```
{% endtab %}
{% endtabs %}

`npm test` dans `crates/desktop-shell/ui/package.json` exécute séquentiellement 3 scripts :

1. `node verify_header_bindings.mjs` — vérifie la mise en page à deux lignes de `HeaderDeck.svelte`, les liaisons Omnibox/`SearchDropdownPanel`, Dual-Vision, LoD, les modes de vision et les déclencheurs `BountyModal`.
2. `node empirical_stress_test.mjs` — teste `tokenizeLine` de `BountyModal` contre les attaques ReDoS/XSS ainsi que le filtrage par jokers.
3. `node adversarial_challenge_m4.mjs` — banc Vite SSR vérifiant `use:portal` sur `SearchDropdownPanel`, `RadarMinimap`, le basculement audio mute, le sandbox PoC dry-run et la sûreté XSS/échelle de l'export d'audit.

{% hint style="info" %}
`TEST_INFRA.md` mentionne un objectif initial de `60+` tests (`15/15/18/12`) sur les 4 fichiers E2E V3 ; le nombre réel de fonctions `#[test]` implémentées dans ces 4 fichiers est de `44` (`12 + 14 + 12 + 6`), en plus de 15 autres suites d'intégration dans `crates/desktop-shell/tests/` (telles que `e2e_prod_plugins_dsl.rs` et `e2e_prod_cache_perf.rs`).
{% endhint %}

## Étendre les règles SAST et de taint

### Option A : `plugin.yaml` déclaratif (sans recompilation)

Pour des règles de sécurité sur mesure, des politiques d'équipe ou des migrations Semgrep, placez un pack sous `.aether/plugins/<pack-name>/plugin.yaml`. `FileWatcherBridge` recharge automatiquement vos modifications, et `aether-plugin-tool` permet d'initialiser et de tester vos packs en ligne de commande :

```bash
aether-plugin-tool init my-org-rules .aether/plugins
aether-plugin-tool test .aether/plugins
aether-plugin-tool scan .aether/plugins ./src
```

Les règles déclaratives (`PluginManifest` / `PluginRule` / `RuleConditions` dans `crates/security-linter/src/plugin.rs`) prennent en charge `match_mode` (`line_by_line` | `whole_file`), `ast_scope` (`outside_test`, `test`, `async_fn`, `sync_fn`, `fn`), `not_preceded_within_lines`, `in_path_matching` / `not_in_path_matching`, `check_literals`, les `test_cases` intégrés et les sélecteurs `--plugins` (`default`, `auto`, `all`, noms de packs ou `profile:<name>`).

### Option B : Modules de règles Rust natifs

Lorsque vous avez besoin de motifs compilés en Rust, ajoutez vos règles dans l'un des modules dédiés sous `crates/security-linter/src/` (`rules.rs` `AdvancedDefiRules`, `deep_rules.rs` `DeepSecurityRules`, `php_rules.rs` `PhpSecurityRules`, `zig_rules.rs` `ZigSecurityRules`, `csharp_rules.rs` `CSharpSecurityRules`, `epic_novel_rules.rs` `EpicNovelRules`), chacun exposant `::definitions() -> Vec<CveRuleDef>` et `::audit_file(...) -> Vec<LinterViolation>` :

1. Enregistrez les définitions dans `SecurityLinter::get_supported_cve_rules()`, le mapping d'extensions dans `get_file_types_for_cwe()` et l'exécution dans `audit_file_raw()` (`crates/security-linter/src/linter.rs`).
2. Tenez compte du **masquage lexical à double passe** : `audit_file_with_context` exécute `audit_file_raw` sur le code brut ET sur `ctx.default_masked()` (commentaires et littéraux chaînes masqués). Ajoutez votre `rule_id` à `SecurityLinter::LITERAL_AWARE_RULES` si la règle doit inspecter des littéraux chaînes (par exemple secrets codés en dur ou requêtes SQL).
3. Gardez à l'esprit que `strip_rust_inline_tests` tronque les fichiers `.rs` à partir de `#[cfg(test)]` / `mod tests {`, et que `security-linter/src/` est exclu de l'auto-analyse (`reflexive exclusion`).

## Ajouter un nouvel extracteur AST de langage

Pour ajouter la prise en charge AST native d'un nouveau langage dans `crates/ast-scanner/src/scanner.rs` et `crates/security-linter/src/lexer.rs` :

1. **Autorisez l'extension** : ajoutez l'extension en minuscules dans `ProjectScanner::scan_project_with_exclusions` (`scanner.rs`). Notez que les fichiers `> 1_500_000` octets sont ignorés et que les workspaces Rust élaguent `.c`/`.h`/`.cpp`/`.py`.
2. **Dispatchez dans `analyze_file_with_content`** : ajoutez une branche `match` pour votre extension appelant `analyze_<lang>(rel_path, content)`.
3. **Implémentez `analyze_<lang>`** : utilisez `static_regex!` pour extraire imports, classes/structs, fonctions/méthodes, appels `RawCall`, routes et événements WebSocket. Construisez des nœuds `SymbolBubble` via `detect_galaxy`, `detect_layer`, `folder_from_rel_path` et `compute_complexity`, puis retournez `FileAnalysis` afin que `resolve_graph_edges` relie automatiquement les arêtes `contains`, `imports`, `calls`, `inherits` et `network`.
4. **Ajoutez le masquage lexical dans `lexer.rs`** : si le langage emploie des délimiteurs de commentaires ou chaînes non-C, ajoutez une variante `Lang` et un mapping `Lang::from_path` pour préserver la précision SAST.
5. **Parallélisme Rayon et cache BLAKE3 automatiques** : une fois relié à `analyze_file_with_content`, votre extracteur bénéficie automatiquement de `par_iter()` sous Rayon et du cache BLAKE3 `.aether/cache/ast/`.

## Développer des plugins visuels WebGL 2

Les packs visuels résident dans `.aether/plugins/visuals/<pack-name>/` avec un manifest `visual-plugin.yaml` (ou `.yml`/`.json`) accompagné des shaders optionnels `backdrop.glsl` et `node_sdf.glsl`.

* **5 packs intégrés** (`crates/desktop-shell/ui/src/engine/visualPlugins.ts`) : `obsidian-nebula`, `cyber-pcb`, `architect-blueprint`, `deep-biolum` et `matrix-phosphor` *(note : `docs/WEBGL_VISUAL_PLUGINS_SPEC.md` mentionne 3 packs, alors que le moteur en embarque 5)*.
* **Points d'extension actifs (M1 + M2)** : `palette`, `overlay` (`membrane_style` : `organic_12lobe` | `hex_hull` | `rect_blueprint` | `none` ; `edge_style` : `bezier` | `straight` | `orthogonal_pcb`), `shaders.uniforms`, `backdrop.glsl` (`vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec)`), `node_sdf.glsl` (`void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha)`), watchdog FPS (`> 33 ms` pendant 2s) et rechargement à chaud par `FileWatcherBridge` sur `.glsl`.
* **Feuille de route uniquement (M3 — non implémenté)** : expressions `VisionLens`, `postprocess.glsl`, préréglages `physics` et génération de thèmes par MCP.

### Garde-fous GLSL anti-DoS et `PathGuard`

Rust (`crates/desktop-shell/src/visual_plugin_routes.rs`) et TypeScript (`visualPlugins.ts`) valident tous deux les shaders GLSL avant compilation :

* **Taille maximale** : `32 Ko` (`32 * 1024` octets) et aucun octet nul `\0`.
* **Directives préprocesseur interdites** : `#version`, `#extension`, `#pragma` (injectés par l'hôte).
* **Sûreté des boucles** : `while (...)` et `do { ... } while` sont rejetés ; chaque `for (...)` doit comporter 3 clauses séparées par `;` avec une condition non vide et une borne numérique `<= 128` (`MAX_FOR_LOOP_BOUND`).
* **Contrat et confinement des chemins** : le shader doit définir `aetherBackdrop` ou `aetherNodeSurface`, et son nom doit être un simple fichier `.glsl` sans `/`, `\`, `..` ni `:`.

{% content-ref url="../architecture-overview.md" %}
[Vue d'ensemble de l'architecture](../architecture-overview.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[DSL déclaratif SAST & Taint v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[Plugins visuels WebGL 2](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[CLI aether-plugin-tool, aetherscope-mcp et aether-mc-runner](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}
