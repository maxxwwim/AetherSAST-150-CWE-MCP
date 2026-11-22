# API REST : Paramètres, Bounty, Surface & Plugins

Pilotez les paramètres du moteur, le périmètre Bug Bounty, les audits réseau black-box, les plugins SAST/Taint déclaratifs et les packs visuels WebGL 2 via l'API HTTP locale Axum (`127.0.0.1:3030`).

Chaque route de cette page est protégée globalement par `LocalGuard` (validation `Host`, `Origin` et `Sec-Fetch-Site`), et les mutations de plugins appliquent un confinement strict des chemins dans `.aether/plugins/`.

{% hint style="info" %}
**Client Frontend (`AetherApiClient`)** : Tous les endpoints ci-dessous disposent de méthodes typées correspondantes sur `AetherApiClient` dans `crates/desktop-shell/ui/src/lib/api.ts`. Hors de la webview du Cockpit, envoyez vos requêtes vers `http://127.0.0.1:3030` avec un en-tête `Host: 127.0.0.1:3030` conforme et sans en-tête `Origin` cross-origin.
{% endhint %}

---

## Paramètres & Politiques de sécurité

Configurez les exclusions de dossiers, les règles CWE/SAST actives, les CWE ignorés, les options d'affichage et le mode basse mémoire dans `.aether/settings.json`.

### `GET /api/settings` & `POST /api/settings`

Récupérez la configuration active du projet ainsi que le catalogue complet des règles CVE/SAST, ou appliquez une mise à jour partielle avec ré-analyse optionnelle du graphe.

#### 🎮 Endpoint

```http
GET  http://127.0.0.1:3030/api/settings
POST http://127.0.0.1:3030/api/settings
```

* **Client TypeScript** : `api.getSettings()` et `api.saveSettings(payload)` (`api.ts`)
* **Persistance** : `.aether/settings.json`

#### 📝 Paramètres

`GET /api/settings` ne requiert aucun paramètre. Pour `POST /api/settings`, envoyez un objet JSON `SettingsPayload` complet ou partiel :

| Nom | Type | Requis | Description |
|---|---|---|---|
| `exclusions` | `string[]` | Non | Dossiers ou motifs d'exclusion. Un tableau vide `[]` conserve les exclusions existantes sauf si `rescan: true` est également fourni. |
| `active_cve_rules` | `string[] \| null` | Non | Liste d'autorisation des ID de règles natives actives. Lorsqu'elle n'est pas vide, `apply_settings_filters_to_graph` préserve `BLAKE3_TAMPERED` et les règles de plugins personnalisés ; un tableau vide explicite `[]` masque toutes les alertes. |
| `ignored_cwes` | `string[] \| null` | Non | Identifiants CWE à ignorer sur le graphe (par exemple `["CWE-798"]`). |
| `show_alerts` | `boolean \| null` | Non | Affiche ou masque les indicateurs d'alertes SAST/CWE dans le Cockpit 3D. |
| `show_cwe_bubbles` | `boolean \| null` | Non | Affiche ou masque les bulles satellites CWE autour des symboles concernés. |
| `show_cwe_titles` | `boolean \| null` | Non | Affiche ou masque les libellés des bulles CWE. |
| `show_folder_titles` | `boolean \| null` | Non | Affiche ou masque les noms des membranes de dossiers dans la scène WebGL. |
| `show_file_titles` | `boolean \| null` | Non | Affiche ou masque les noms de fichiers dans la scène WebGL. |
| `low_memory_mode` | `boolean \| null` | Non | Active le mode d'économie mémoire pour les grands dépôts. |
| `active_visual_plugin` | `string \| null` | Non | Slug du pack visuel actif (par défaut `"obsidian-nebula"`). |
| `ui_settings` | `object \| null` | Non | Objet JSON libre conservant les préférences d'interface du Cockpit. |
| `rescan` | `boolean \| null` | Non | Force une ré-analyse `ProjectScanner` complète et incrémente `graph_version`. |

{% hint style="warning" %}
**Fusion partielle sécurisée** : `POST /api/settings` fusionne les champs `Option` fournis dans `AppState` avant d'écrire `.aether/settings.json`, évitant ainsi qu'un appel partiel (comme l'ajout d'un CWE dans `ignored_cwes`) n'écrase vos options d'affichage UI. Une ré-analyse du graphe se déclenche automatiquement si `rescan: true`, si des `exclusions` non vides ont changé, si `active_cve_rules` a changé ou si `ignored_cwes` a changé.
{% endhint %}

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` (présent sur `POST /api/settings`). |
| `200 OK` | `exclusions` | `string[]` | Motifs d'exclusion actifs. |
| `200 OK` | `active_cve_rules` | `string[]` | Règles natives actives (par défaut tout le catalogue sur `GET` si non défini). |
| `200 OK` | `ignored_cwes` | `string[]` | Identifiants CWE actuellement ignorés. |
| `200 OK` | `cve_catalogue` | `CveRuleDef[]` | Catalogue natif complet retourné par `SecurityLinter::get_supported_cve_rules()`. |
| `200 OK` | `mcp_binary_path` | `string \| null` | (`GET` uniquement) Chemin résolu vers `aetherscope-mcp(.exe)` à côté de l'exécutable actif. |
| `200 OK` | `show_*` / `low_memory_mode` / `active_visual_plugin` / `ui_settings` | mixte | (`GET` uniquement) Options d'affichage et préférences UI persistées. |
| `200 OK` | `total_nodes` / `total_edges` | `number` | (`POST` uniquement) Nombre de nœuds et d'arêtes du graphe après ré-analyse éventuelle. |

#### 💡 Exemple

{% tabs %}
{% tab title="curl" %}
```bash
# Lire la configuration actuelle, le catalogue et mcp_binary_path
curl -s http://127.0.0.1:3030/api/settings

# Ignorer CWE-798, activer le mode basse mémoire et relancer une analyse
curl -s -X POST http://127.0.0.1:3030/api/settings \
  -H "Content-Type: application/json" \
  -d '{"ignored_cwes":["CWE-798"],"low_memory_mode":true,"rescan":true}'
```
{% endtab %}
{% tab title="Réponse JSON (POST 200)" %}
```json
{
  "status": "ok",
  "exclusions": [],
  "active_cve_rules": ["CWE-89-SQLI", "CWE-78-CMD-INJ"],
  "ignored_cwes": ["CWE-798"],
  "cve_catalogue": [
    {
      "rule_id": "CWE-89-SQLI",
      "cwe_id": "CWE-89",
      "name": "SQL Injection"
    }
  ],
  "total_nodes": 412,
  "total_edges": 1084
}
```
{% endtab %}
{% endtabs %}

---

## Périmètre Bug Bounty & Scan de Surface

Définissez les dossiers inclus dans votre périmètre d'audit et lancez des scans réseau/Web black-box à 4 niveaux.

### `GET /api/bounty/scope` & `POST /api/bounty/scope`

Consultez ou mettez à jour la configuration du périmètre Bug Bounty PoC persistée dans `.aether/bounty_scope.json`, ou déclenchez le recommandeur IA par dossier (`compute_scope_recommendations`).

#### 🎮 Endpoint

```http
GET  http://127.0.0.1:3030/api/bounty/scope
POST http://127.0.0.1:3030/api/bounty/scope
```

* **Client TypeScript** : `api.getBountyScope()` et `api.updateBountyScope(payload)` (`api.ts`)
* **Persistance** : `.aether/bounty_scope.json`

#### 📝 Paramètres

`GET /api/bounty/scope` n'accepte aucun paramètre. Si `.aether/bounty_scope.json` n'existe pas encore, il génère automatiquement des recommandations (`mode: "ai_recommended"`).

Pour `POST /api/bounty/scope` :

| Nom | Type | Requis | Description |
|---|---|---|---|
| `action` | `string` | Non | `"set"` (par défaut) pour enregistrer des listes personnalisées, ou `"auto_recommend"` pour calculer et sauvegarder le périmètre recommandé par l'IA. |
| `in_scope` | `string[]` | Non | Préfixes de dossiers inclus dans le périmètre (utilisé avec `action: "set"`). |
| `out_of_scope` | `string[]` | Non | Préfixes de dossiers exclus du périmètre (utilisé avec `action: "set"`). |
| `mode` | `string` | Non | Mode enregistré (`"manual"` par défaut pour `"set"`, `"mcp_synced"` ou `"ai_recommended"`). |
| `updated_by` | `string` | Non | Auteur de la modification (`"User / MCP"` par défaut pour `"set"`, `"AetherScope AI Recommender"` pour `"auto_recommend"`). |
| `rationale` | `string` | Non | Justification textuelle sauvegardée avec la configuration. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `scope` | `BountyScopeConfig` | `{ in_scope, out_of_scope, mode, updated_by?, rationale?, timestamp }`. |
| `200 OK` | `recommendations` | `FolderScopeRecommendation[]` | Scores et compteurs par dossier (`folder`, `status`, `critical_count`, `high_count`, `total_violations`, `entrypoints_count`, `score`, `reason`). |

#### 💡 Exemple

```bash
# Calculer et enregistrer automatiquement le périmètre recommandé
curl -s -X POST http://127.0.0.1:3030/api/bounty/scope \
  -H "Content-Type: application/json" \
  -d '{"action":"auto_recommend","updated_by":"AppSec"}'
```

---

### `POST /api/surface_scan`

Exécute un audit de surface d'attaque réseau et Web black-box non destructif à 4 niveaux sur une cible et enregistre un événement de télémétrie (`"Scan Surface (<grade>)"`).

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/surface_scan
```

* **Client TypeScript** : `api.surfaceScan(req)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `target` | `string` | **Oui** | Hôte, IP, `host:port` ou URL `http(s)://` complète. |
| `scan_level` | `integer` | Non | Profondeur d'audit de `1` à `4` (bornée à `1..=4`, défaut `4`). |
| `check_dns` | `boolean` | Non | Active la résolution DNS et la classification IP (défaut `true`). |
| `check_ports` | `boolean` | Non | Active le sondage TCP des ports et bannières (défaut `scan_level >= 2`). |
| `check_headers` | `boolean` | Non | Active l'audit des en-têtes de sécurité HTTP (défaut `true`). |
| `check_endpoints` | `boolean` | Non | Active les sondes `robots.txt` / `security.txt` et `OPTIONS` (défaut `scan_level >= 2`). |
| `check_web_forms` | `boolean` | Non | Active l'extraction HTML des formulaires, ancres DOM et routes JS (défaut `scan_level >= 3`). |
| `check_sensitive_files` | `boolean` | Non | Active les sondes Niveau 4 CWE-538 avec masquage `******** [MASQUÉ]` (défaut `scan_level >= 4`). |
| `custom_ports` | `string` | Non | Ports TCP supplémentaires séparés par virgules, espaces ou points-virgules. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `security_score` / `grade` | `integer` / `string` | Score de posture `0..100` et note (`A+` à `F`). |
| `200 OK` | `impact_matrix` | `ImpactVisibilityMatrix` | Estimation de paquets envoyés et compteurs de surface détectée. |
| `200 OK` | `open_ports` / `headers_audit` | `array` | Résultats des ports/bannières TCP et verdicts des en-têtes HTTP. |
| `200 OK` | `web_discovery` / `exposed_artifacts` | `object \| null` / `array` | Formulaires, routes, ressources JS et sondes CWE-538 masquées. |
| `200 OK` | `trust_zones` / `boundary_weaknesses` / `findings` | `array` | 4 zones de confiance, sondes frontière Côté 1 vers AST Côté 2 et alertes CWE. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/surface_scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://127.0.0.1:3030","scan_level":4}'
```

{% content-ref url="./surface-scanner.md" %}
[Scanner de Surface d'Attaque Réseau](./surface-scanner.md)
{% endcontent-ref %}

---

## Routes des Plugins SAST & Taint (`/api/plugins/*`)

Les 7 endpoints de plugins gèrent les règles de sécurité déclaratives YAML/JSON et les configurations de taint SSA stockées sous `.aether/plugins/`.

### Confinement & Pipeline de mutation

Chaque mutation `/api/plugins/*` applique les garde-fous de sécurité définis dans `crates/desktop-shell/src/plugin_routes.rs` :

* **`sanitize_plugin_slug`** : Limite le nom à 64 caractères, rejette `\0`, `/`, `\`, `..`, `:` et `.`, convertit les espaces en `-`, met en minuscules `[a-z0-9_-]` et supprime les `-`/`_` en début ou fin de chaîne.
* **`resolve_confined_plugin_file`** : Vérifie l'existence de `.aether/plugins` (`404` sinon), rejette les traversées, chemins absolus, UNC ou lettres de lecteur (`400`), restreint les extensions à `.yaml`, `.yml` ou `.json` (`400`), bloque les chemins sensibles via `SecretGuard::is_secret_path` (`403`) et valide l'inclusion canonique dans `.aether/plugins` (`403` si évasion, `404` si absent).
* **`collect_plugin_files`** : Parcourt récursivement `.aether/plugins` en excluant explicitement le sous-dossier `visuals` et tout fichier nommé `visual-plugin.*`.
* **`rescan_after_plugin_mutation`** : Relance `ProjectScanner::scan_project_with_exclusions`, réapplique `apply_settings_filters_to_graph`, écrit `.aether/LIVE_AUDIT.md`, met à jour `code_graph` et—hors mode `vault`—met à jour `graph`, vide `ui_graph_cache` et incrémente `graph_version`.

---

### `GET /api/plugins`

Liste tous les plugins SAST/Taint présents dans `.aether/plugins/`, les compteurs de règles actives et de taint, ainsi que l'état d'installation du bundle communautaire de 24 règles.

#### 🎮 Endpoint

```http
GET http://127.0.0.1:3030/api/plugins
```

* **Client TypeScript** : `api.getPlugins()` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| — | — | — | Aucun paramètre de requête ni corps JSON requis. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugins_dir` | `string` | Chemin vers `.aether/plugins`. |
| `200 OK` | `community_bundle_installed` | `boolean` | `true` si le bundle communautaire est installé sur disque. |
| `200 OK` | `community_bundle_rules_count` | `integer` | Nombre fixe de règles du bundle embarqué (`24`). |
| `200 OK` | `total_plugins` / `enabled_plugins` | `integer` | Nombre total de manifestes et de plugins activés. |
| `200 OK` | `total_active_rules` | `integer` | Nombre total de règles actives parmi les plugins activés. |
| `200 OK` | `total_taint_sources` / `total_taint_sinks` / `total_sanitizers` | `integer` | Totaux issus des plugins activés. |
| `200 OK` | `plugins` | `PluginEntryInfo[]` | Métadonnées complètes, résumés de règles et définitions de taint pour chaque fichier plugin. |

#### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/plugins
```

---

### `POST /api/plugins/toggle`

Active ou désactive un fichier plugin sur disque tout en préservant son format d'origine (`.json` ou `.yaml`/`.yml`), puis relance l'analyse du projet.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/toggle
```

* **Client TypeScript** : `api.togglePlugin(relPath, enabled)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `rel_path` | `string` | **Oui** | Chemin relatif dans `.aether/plugins/` (par exemple `"custom-guard/plugin.yaml"`). |
| `enabled` | `boolean` | **Oui** | Nouvel état d'activation persisté dans le manifeste. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugin` / `enabled` | `string` / `boolean` | `rel_path` mis à jour et nouvel état `enabled`. |
| `200 OK` | `total_nodes` / `total_edges` | `integer` | Compteurs du graphe après `rescan_after_plugin_mutation`. |
| `200 OK` | `inventory` | `PluginsInventoryResponse` | Inventaire mis à jour. |
| `400` / `403` / `404` / `500` | `error` | `string` | Chemin/extension invalide, rejet `SecretGuard`/évasion, fichier manquant ou erreur I/O. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/toggle \
  -H "Content-Type: application/json" \
  -d '{"rel_path":"custom-guard/plugin.yaml","enabled":true}'
```

---

### `POST /api/plugins/test`

Exécute les `test_cases` embarqués via `PluginEngine::run_test_suite()` sur l'ensemble des plugins ou sur un fichier ciblé.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/test
```

* **Client TypeScript** : `api.testPlugins(relPath?)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `rel_path` | `string \| null` | Non | Chemin relatif optionnel dans `.aether/plugins/`. Lorsqu'il est fourni et non vide, seul ce fichier est chargé et `enabled` est forcé à `true` en mémoire afin de tester un plugin même désactivé. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"passed"` (si `failed == 0`) ou `"failed"`. |
| `200 OK` | `total_tests` / `passed` / `failed` | `integer` | Compteurs globaux des tests unitaires. |
| `200 OK` | `failures` | `string[]` | Détails de chaque cas de test en échec. |
| `400` / `403` / `404` / `500` | `error` | `string` | Erreur de confinement ou de parsing sur `rel_path`. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/test \
  -H "Content-Type: application/json" \
  -d '{"rel_path":"custom-guard/plugin.yaml"}'
```

---

### `POST /api/plugins/init_bundle`

Déploie le bundle communautaire Semgrep OWASP/CWE embarqué (24 règles via `CommunityBundle::unpack_to_directory`) vers `.aether/plugins/community/plugin.yaml` et ré-analyse le projet.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/init_bundle
```

* **Client TypeScript** : `api.initCommunityPluginBundle()` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| — | — | — | Aucun corps requis (requête POST vide). |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `path` | `string` | Chemin du manifeste écrit (`.aether/plugins/community/plugin.yaml`). |
| `200 OK` | `total_nodes` / `total_edges` | `integer` | Compteurs du graphe après ré-analyse. |
| `200 OK` | `inventory` | `PluginsInventoryResponse` | Inventaire mis à jour. |
| `500` | `error` | `string` | Erreur d'écriture disque. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/init_bundle
```

---

### `POST /api/plugins/import_semgrep`

Convertit un fichier YAML Semgrep en `PluginManifest` AetherScope via `SemgrepImporter`, l'enregistre dans `.aether/plugins/imported/<slug>/plugin.yaml` et relance l'analyse.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/import_semgrep
```

* **Client TypeScript** : `api.importSemgrepPlugin(pluginName, yamlContent)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `plugin_name` | `string` | **Oui** | Nom du plugin assaini via `sanitize_plugin_slug` vers `<slug>`. |
| `yaml_content` | `string` | **Oui** | Contenu YAML Semgrep brut comportant une liste `rules` non vide. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugin` | `string` | `<slug>` assaini du plugin. |
| `200 OK` | `rules_imported` | `integer` | Nombre de règles converties. |
| `200 OK` | `rel_path` | `string` | Chemin relatif `"imported/<slug>/plugin.yaml"`. |
| `200 OK` | `total_nodes` / `total_edges` / `inventory` | mixte | Totaux du graphe après analyse et inventaire mis à jour. |
| `400` / `500` | `error` | `string` | Slug invalide, YAML Semgrep invalide ou sans règles, ou erreur d'écriture. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/import_semgrep \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"semgrep-demo","yaml_content":"rules:\n  - id: demo-eval\n    languages: [javascript]\n    severity: ERROR\n    message: Avoid eval\n    pattern: eval($X)\n"}'
```

---

### `POST /api/plugins/upsert`

Crée ou met à jour une règle SAST déclarative et/ou une configuration de taint SSA dans `.aether/plugins/<slug>/plugin.yaml` (ou `.aether/plugins/imported/<slug>/plugin.yaml` s'il y existe déjà), avec certification automatique par tests unitaires.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/upsert
```

* **Client TypeScript** : `api.upsertPluginRule(payload)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `plugin_name` | `string` | **Oui** | Nom du plugin cible, assaini via `sanitize_plugin_slug`. |
| `profile` / `tags` / `plugin_description` | `string` / `string[]` / `string` | Non | Profil, tags et description au niveau du manifeste. |
| `rule_id` | `string` | Conditionnel | ID de la règle. Requis sauf en **mode taint uniquement** (`rule_id` vide avec `taint_sources`, `taint_sinks` ou `sanitizers` fournis, enregistré sous `TAINT-SSA-CONFIG`). |
| `cwe_id` | `string` | Conditionnel | Identifiant CWE (requis hors mode taint uniquement). |
| `file_extensions` | `string[]` | Conditionnel | Extensions cibles comme `[".rs", ".ts"]` (non vide hors mode taint uniquement). |
| `name` / `category` / `severity` | `string` | Non | Libellé de la règle, catégorie (`"Custom / Security"` par défaut) et sévérité (`"HIGH"` par défaut, mise en majuscules). |
| `description` / `remediation` | `string` | Non | Description de la faille et conseil de remédiation. |
| `match_mode` | `string` | Non | `"line_by_line"` (défaut) ou `"whole_file"`. |
| `must_contain` / `must_not_contain` | `string[]` | Non | Préconditions et exclusions textuelles. |
| `regex_patterns` / `forbidden_tokens` | `string[]` | Non | Expressions régulières (validées via `validate_regexes()`) et jetons interdits. |
| `check_literals` | `boolean` | Non | Inclure les littéraux et commentaires lors de l'analyse (défaut `false`). |
| `not_preceded_within_lines` | `object` | Non | Fenêtre de garde `{ "patterns": string[], "lines": integer }`. |
| `in_path_matching` / `not_in_path_matching` | `string[]` | Non | Globs d'inclusion et d'exclusion de chemins. |
| `ast_scope` | `string` | Non | Filtre de portée AST (ex. `"outside_test"`, `"test"`, `"async_fn"`, `"sync_fn"`, `"fn"`). |
| `test_cases` | `RuleTestCase[]` | Non | Cas de tests positifs/négatifs. Lors de la mise à jour d'un `rule_id` existant avec un tableau `test_cases` vide, les tests existants sont conservés. |
| `taint_sources` / `taint_sinks` / `sanitizers` | `array` | Non | Listes `TaintSourceRule[]`, `TaintSinkRule[]` et `SanitizerRule[]` fusionnées dans le manifeste. |

{% hint style="danger" %}
**Porte de certification `422`** : Avant toute écriture sur disque, le serveur clone le manifeste candidat, force `enabled = true`, compile les expressions régulières et exécute `PluginEngine::run_test_suite()`. Si `report.failed > 0`, l'opération échoue sans modifier le disque et retourne **`422 Unprocessable Entity`** (`"<N> unit test(s) failed — plugin was NOT modified"`).
{% endhint %}

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `plugin` / `rule_id` | `string` | Slug assaini et ID de règle enregistré (ou `"TAINT-SSA-CONFIG"`). |
| `200 OK` | `tests_passed` | `integer` | Nombre de tests unitaires validés. |
| `200 OK` | `total_nodes` / `total_edges` / `inventory` | mixte | Totaux du graphe après ré-analyse et inventaire mis à jour. |
| `422` | `status` / `message` / `total_tests` / `passed` / `failed` / `failures` | mixte | Détails d'échec de la porte de certification ; aucune modification sur disque. |
| `400` / `500` | `error` | `string` | Slug invalide, champs requis manquants, regex invalide ou erreur d'écriture. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/upsert \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_name": "custom-guard",
    "rule_id": "CUSTOM-EXEC",
    "cwe_id": "CWE-78",
    "name": "Block danger_exec",
    "severity": "CRITICAL",
    "description": "Unsafe command execution",
    "remediation": "Use an explicit command allowlist",
    "file_extensions": [".rs"],
    "regex_patterns": ["danger_exec\\s*\\("],
    "test_cases": [
      {
        "name": "vuln",
        "file_name": "src/app.rs",
        "code": "danger_exec();",
        "should_trigger": true
      }
    ]
  }'
```

---

### `POST /api/plugins/delete`

Supprime un fichier plugin confiné dans `.aether/plugins/`, nettoie son dossier parent s'il devient vide et déclenche une ré-analyse du projet.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/plugins/delete
```

* **Client TypeScript** : `api.deletePlugin(relPath)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `rel_path` | `string` | **Oui** | Chemin relatif du plugin dans `.aether/plugins/` à supprimer. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `deleted` | `string` | `rel_path` supprimé. |
| `200 OK` | `total_nodes` / `total_edges` / `inventory` | mixte | Totaux du graphe après ré-analyse et inventaire mis à jour. |
| `400` / `403` / `404` / `500` | `error` | `string` | Validation de chemin, rejet `SecretGuard`/évasion, fichier absent ou erreur de suppression. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/plugins/delete \
  -H "Content-Type: application/json" \
  -d '{"rel_path":"custom-guard/plugin.yaml"}'
```

---

## Routes des Plugins Visuels WebGL 2 (`/api/visual_plugins/*`)

Les 4 endpoints de plugins visuels gèrent les palettes personnalisées, les géométries d'overlay, les uniforms et les hooks de shaders GLSL ES 3.00 stockés dans `.aether/plugins/visuals/<slug>/`.

### Validation GLSL anti-DoS & Packs intégrés

Les hooks de shaders personnalisés (`backdrop.glsl` et `node_sdf.glsl`) sont validés côté serveur par `validate_glsl_hook` (`visual_plugin_routes.rs`) et côté client dans `ui/src/engine/visualPlugins.ts` :

* **Taille et encodage** : Maximum `32 * 1024` octets (`32 Ko`, `MAX_GLSL_BYTES`), aucun octet nul `\0`.
* **Directives réservées** : Suppression des commentaires `//` et `/* ... */`, puis rejet de `#version`, `#extension` et `#pragma`.
* **Boucles anti-TDR** : Rejet de `while (` et `do {` ; chaque boucle `for (init; cond; step)` doit comporter 3 segments séparés par `;`, une condition non vide et toute constante numérique de `cond` `<= 128` (`MAX_FOR_LOOP_BOUND`).
* **Points d'entrée contractuels** :
  * `backdrop.glsl` doit déclarer `vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec)`
  * `node_sdf.glsl` doit déclarer `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha)`

{% hint style="info" %}
**Packs intégrés vs. Packs sur disque** : Les 5 packs intégrés (`obsidian-nebula`, `cyber-pcb`, `architect-blueprint`, `deep-biolum`, `matrix-phosphor`) sont définis côté client dans `crates/desktop-shell/ui/src/engine/visualPlugins.ts`. `GET /api/visual_plugins` énumère uniquement les packs personnalisés présents sur disque dans `.aether/plugins/visuals/` (`builtin: false`).
{% endhint %}

---

### `GET /api/visual_plugins`

Liste tous les packs visuels personnalisés présents dans `.aether/plugins/visuals/` avec leurs sources GLSL résolues, uniforms, avertissements de validation et identifiant actif.

#### 🎮 Endpoint

```http
GET http://127.0.0.1:3030/api/visual_plugins
```

* **Client TypeScript** : `api.getVisualPlugins()` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| — | — | — | Aucun paramètre requis. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `visuals_dir` | `string` | Chemin vers `.aether/plugins/visuals`. |
| `200 OK` | `active_visual_plugin` | `string` | Slug du thème actif (`"obsidian-nebula"` par défaut). |
| `200 OK` | `visual_version` | `integer` | Compteur monotone incrémenté lors des mutations visuelles. |
| `200 OK` | `plugins` | `VisualPluginResolved[]` | Liste contenant `schema_version`, `id`, `name`, `version`, `author`, `description`, `enabled`, `builtin` (`false`), `rel_dir` (`"visuals/<folder>"`), `palette`, `overlay`, `uniforms`, `backdrop_glsl`, `node_sdf_glsl` et `validation_warnings`. |

#### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/visual_plugins
```

---

### `POST /api/visual_plugins/activate`

Active un pack visuel intégré ou personnalisé par son identifiant, sauvegarde `active_visual_plugin` dans `.aether/settings.json` et incrémente `visual_version`.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/visual_plugins/activate
```

* **Client TypeScript** : `api.activateVisualPlugin(id)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `id` | `string` | **Oui** | Identifiant du pack intégré ou personnalisé, assaini via `sanitize_plugin_slug`. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `active_visual_plugin` | `string` | Slug actif assaini. |
| `200 OK` | `visual_version` | `integer` | `visual_version` incrémenté. |
| `400` | `error` | `string` | Identifiant `id` invalide. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/visual_plugins/activate \
  -H "Content-Type: application/json" \
  -d '{"id":"obsidian-nebula"}'
```

---

### `POST /api/visual_plugins/upsert`

Crée ou met à jour un pack visuel personnalisé dans `.aether/plugins/visuals/<slug>/` en écrivant `visual-plugin.yaml` ainsi que les hooks optionnels `backdrop.glsl` et `node_sdf.glsl` après validation anti-DoS.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/visual_plugins/upsert
```

* **Client TypeScript** : `api.upsertVisualPlugin(payload)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `id` | `string` | **Oui** | Identifiant du pack assaini via `sanitize_plugin_slug`. |
| `name` | `string` | **Oui** | Nom d'affichage non vide du pack. |
| `version` | `string` | Non | Chaîne de version (`"1.0.0"` par défaut). |
| `author` / `description` | `string` | Non | Métadonnées optionnelles du pack. |
| `palette` | `VisualPaletteConfig` | Non | `{ background: string[], layers: Record<string, string>, severities: Record<string, string>, contract_warning?: string }`. |
| `overlay` | `VisualOverlayConfig` | Non | `{ membrane_style?: "organic_12lobe" \| "hex_hull" \| "rect_blueprint" \| "none", edge_style?: "bezier" \| "straight" \| "orthogonal_pcb", edge_pulse_speed?: number, membrane_breath_amp?: number, label_font?: string }`. |
| `uniforms` | `Record<string, number>` | Non | Uniforms flottants personnalisés exposés aux shaders GLSL. |
| `backdrop_glsl` | `string \| null` | Non | Shader de fond validé par `validate_glsl_hook(..., "aetherBackdrop")`. |
| `node_sdf_glsl` | `string \| null` | Non | Shader de nœud validé par `validate_glsl_hook(..., "aetherNodeSurface")`. |
| `activate` | `boolean` | Non | Active automatiquement ce pack et met à jour `.aether/settings.json` (`false` par défaut). |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `id` | `string` | Slug assaini du pack. |
| `200 OK` | `visual_version` | `integer` | `visual_version` incrémenté. |
| `200 OK` | `inventory` | `VisualPluginsInventoryResponse` | Inventaire mis à jour des plugins visuels. |
| `400` / `403` / `500` | `error` | `string` | Slug invalide, `name` vide, échec contrat/anti-DoS GLSL, rejet `SecretGuard` ou erreur I/O. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/visual_plugins/upsert \
  -H "Content-Type: application/json" \
  -d '{
    "id": "neon-grid",
    "name": "Neon Grid",
    "palette": { "background": ["#040a0f", "#06b6d4"] },
    "overlay": { "membrane_style": "hex_hull", "edge_style": "orthogonal_pcb" },
    "uniforms": { "grid_scale": 0.5 },
    "backdrop_glsl": "vec3 aetherBackdrop(vec2 uv, vec2 cam, float z, float t) { return u_theme_colors[0]; }",
    "activate": true
  }'
```

---

### `POST /api/visual_plugins/delete`

Supprime le répertoire d'un pack visuel personnalisé sous `.aether/plugins/visuals/<slug>/`. Si ce pack était actif, `active_visual_plugin` revient automatiquement à `"obsidian-nebula"` en mémoire et dans `.aether/settings.json`.

#### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/visual_plugins/delete
```

* **Client TypeScript** : `api.deleteVisualPlugin(id)` (`api.ts`)

#### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `id` | `string` | **Oui** | Identifiant du pack personnalisé assaini via `sanitize_plugin_slug`. |

#### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` | `string` | `"ok"` |
| `200 OK` | `deleted` | `string` | Slug du pack supprimé. |
| `200 OK` | `visual_version` | `integer` | `visual_version` incrémenté. |
| `200 OK` | `inventory` | `VisualPluginsInventoryResponse` | Inventaire mis à jour des plugins visuels. |
| `400` / `403` / `404` / `500` | `error` | `string` | Slug invalide, évasion de confinement, dossier introuvable ou erreur de suppression. |

#### 💡 Exemple

```bash
curl -s -X POST http://127.0.0.1:3030/api/visual_plugins/delete \
  -H "Content-Type: application/json" \
  -d '{"id":"neon-grid"}'
```

---

## Guides associés

{% content-ref url="./rest-api-overview.md" %}
[Vue d'ensemble de l'API REST & Client](./rest-api-overview.md)
{% endcontent-ref %}

{% content-ref url="./rest-api-ide-contracts-ai.md" %}
[API REST : IDE, Contrats, IA & Tâches](./rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[DSL SAST & Taint déclaratif v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[Plugins visuels WebGL 2](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité & Garde-fous](../core/security-confinement.md)
{% endcontent-ref %}
