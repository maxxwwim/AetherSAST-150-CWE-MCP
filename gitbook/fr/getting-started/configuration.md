# Configuration

Référence complète des schémas pour `aether.lock.toml`, `.aether/settings.json`, les contrats EARS `README.md`, les variables d'environnement et les artefacts générés.

## 1. `aether.lock.toml` (Fichier de verrouillage cryptographique)

`aether.lock.toml` se trouve à `<project_root>/aether.lock.toml` et stocke le `ProjectManifest` (`crates/core-graph/src/manifest.rs`) ainsi que les empreintes BLAKE3 de chaque contrat `README.md` scellé.

| Champ | Type / Valeurs | Défaut | Description |
|---|---|---|---|
| `version` | `u32` | `2` | Version du schéma du fichier de verrouillage. |
| `project_id` | `string` | Nom du projet | Identifiant du workspace verrouillé. |
| `stack_type` | `PureRust` \| `PurePythonUv` \| `PureNodePnpm` \| `HybridMmoWeb3` \| `RobloxLuau` \| `MinecraftServer` \| `ClassicMvc` | — | Modèle d'architecture logicielle du projet. |
| `topology_mode` | `MonorepoLocal` \| `Dissociated` | — | Topologie monorepo locale ou client/serveur dissociée. |
| `[galaxies.<key>]` | Carte `GalaxyManifest` | `{}` | Chaque entrée définit `path`, `role`, `remote_sync` (`false`), `remote_endpoint` optionnel et `readme_blake3` (hash hex BLAKE3 de 64 caractères). |
| `[guardrails]` | `GuardrailSettings` | Tous à `true` | `block_forbidden_imports`, `enforce_ears_syntax`, `sast_strict_mode`, `require_signature_on_contract_change`. |

{% code title="aether.lock.toml (extrait de la racine du dépôt)" overflow="wrap" %}
```toml
version = 2
project_id = "aether-engine"
stack_type = "PureRust"
topology_mode = "MonorepoLocal"

[galaxies.root]
path = "."
role = "Signed contract for root"
remote_sync = false
readme_blake3 = "4cd3d091d0a2fa74ac1223a4d41c845d1070a91135b14c720558ac07d15b55ca"

[galaxies."crates/core-graph"]
path = "./crates/core-graph"
role = "Signed contract for crates/core-graph"
remote_sync = false
readme_blake3 = "3c742885f331dd19d743f6dec53b9bcb383a15a8eae6d209d6f995e3ad12aab2"

[guardrails]
block_forbidden_imports = true
enforce_ears_syntax = true
sast_strict_mode = true
require_signature_on_contract_change = true
```
{% endcode %}

{% hint style="danger" %}
Modifier un fichier `README.md` scellé sans re-signer `aether.lock.toml` (via `POST /api/contracts/sign`, `POST /api/contracts/update`, `POST /api/save_doc` ou l'Inspecteur du Cockpit) déclenche **`BLAKE3_TAMPERED`** (`CWE-353`, `CRITICAL`) et provoque le rejet des patchs dans `PatchVerifier`.
{% endhint %}

## 2. `.aether/settings.json` (`SettingsPayload` et `CockpitSettings`)

Enregistré dans `<project_root>/.aether/settings.json` via `GET/POST /api/settings`. `POST /api/settings` applique une **fusion partielle** dans `AppState` : modifier une seule clé (comme `ignored_cwes` ou `active_visual_plugin`) conserve intactes toutes les autres options.

| Champ | Type | Persisté ? | Défaut / Comportement |
|---|---|---|---|
| `exclusions` | `string[]` | Oui | Chemins, dossiers ou jokers `*` exclus de `ProjectScanner` (défaut UI : `["vendor", "var", "cache", "tests", "*.spec.*", "*.test.*"]`). |
| `active_cve_rules` | `string[] \| null` | Oui | `null` active toutes les règles natives (`GET /api/settings` développe `null` en liste complète d'IDs). Note : `BLAKE3_TAMPERED`, `RULE_MAX_LINES`, `RULE_MAX_FILES`, `RULE_FORBIDDEN_FUNCTION`, `RULE_FORBIDDEN_EXTENSION` et les règles de plugins restent actives sauf si la liste vaut `[]`. |
| `ignored_cwes` | `string[] \| null` | Oui | Filtres insensibles à la casse (correspondance exacte ou sous-chaîne) appliqués sur `rule_id` et `cve_id`. |
| `show_alerts` | `bool \| null` | Oui | Défaut UI `true` — affiche les balises et halos d'alerte de sécurité. |
| `show_cwe_bubbles` | `bool \| null` | Oui | Défaut UI `true` — affiche les nœuds porteurs de vulnérabilités SAST. |
| `show_cwe_titles` | `bool \| null` | Oui | Défaut UI `true` — affiche les pastilles CWE et budgets de lignes. |
| `show_folder_titles` | `bool \| null` | Oui | Défaut UI `true` — affiche les titres de dossiers et modules. |
| `show_file_titles` | `bool \| null` | Oui | Défaut UI `true` — affiche les libellés de fichiers et symboles. |
| `low_memory_mode` | `bool \| null` | Oui | Défaut UI `false` (activé automatiquement au-delà de `2 500` nœuds) ; verrouille le DPR à `1x` et désactive les effets `shadowBlur` coûteux. |
| `active_visual_plugin` | `string \| null` | Oui | Repli UI `"obsidian-nebula"`. Mémorise l'identifiant du pack visuel WebGL 2 actif. |
| `ui_settings` | `object \| null` | Oui | Contient `CockpitSettings` (`maxLabelLength: 18`, `hideBubbleLabelsOver20: true`, `clusterLabelThreshold: 20`, `lazyReadmes: true`, `fpsLimit: "120"`, `soundEnabled: true`, `showFolderBadges: true`, `showFolderMembranes: true`, `aiAutoCam: true`, `aiTrail: true`, `showAiLines: true`, `showAiNames: true`, `aiCustomPrompt: ""`, `mcpBinaryPath`, ainsi que les bascules UI reflétées). |
| `cve_catalogue` | `CveRuleDef[] \| null` | **Non** | Champ calculé au runtime renvoyé par `GET/POST /api/settings`, effacé avant écriture sur disque. |
| `mcp_binary_path` | `string \| null` | **Non** | Chemin résolu au runtime vers l'exécutable compagnon `aetherscope-mcp`, effacé avant écriture sur disque. |
| `rescan` | `bool \| null` | **Non** | Drapeau de requête uniquement sur `POST /api/settings` déclenchant un re-scan immédiat à `true`. |

## 3. Frontmatter YAML `README.md` et contrats EARS

Chaque fichier `README.md` de dossier peut déclarer un contrat structurel et de sécurité analysé par `ReadmeContract::parse` (`crates/security-linter/src/contract.rs`) :

| Clé | Type | Défaut | Application |
|---|---|---|---|
| `id` | `string` | Chemin de dossier normalisé | Obligatoire dès qu'un bloc frontmatter YAML est présent. |
| `layer` | `string` | `"utility"` (upsert : `"domain"`) | Couche architecturale (`domain`, `application`, `infrastructure`, etc.). |
| `max_lines_per_file` | `usize` | `300` (`.java` : `10 000`, `.sol` : `600`) | Émet `RULE_MAX_LINES` (`WARNING`) en cas de dépassement. |
| `file_max_lines` | `map<string, usize>` | `{}` | Surcharges par fichier selon le chemin complet, relatif au dossier ou le nom de fichier. |
| `allowed_imports` | `string[]` | `[]` | Guide architectural injecté dans `<aether_handshake>` et `ACTIVE_TARGET.md`. |
| `forbidden_imports` | `string[]` | `[]` | Appliqué activement sur les instructions `use`/`import`/`from` ; émet `RULE_FORBIDDEN_IMPORT` (`CRITICAL`). |
| `forbidden_functions` | `string[]` | `[]` | Interdit des appels ou macros (ex. `println!`) tout en ignorant les définitions (`RULE_FORBIDDEN_FUNCTION`). |
| `allowed_extensions` | `string[]` | `[]` (tout autoriser) | Liste blanche d'extensions dans le dossier (`README.md` et fichiers sans extension comme `LICENSE` exemptés ; émet `RULE_FORBIDDEN_EXTENSION`). |
| `forbidden_extensions` | `string[]` | `[]` | Liste noire d'extensions, y compris les suffixes composés comme `d.ts` (`RULE_FORBIDDEN_EXTENSION`). |
| `max_files_per_folder` | `usize \| null` | `null` | Plafonne le nombre de fichiers du dossier (`0` via `/api/contracts/update` supprime la limite) ; émet `RULE_MAX_FILES`. |
| `security_rules` | `SecurityRules` | Tous à `false` | Booléens : `no_raw_sql`, `no_env_access` (applique `SAST_DIRECT_ENV_ACCESS` / `CWE-15`), `untrusted_client_input`, `deterministic_only`. |

Dans le corps Markdown, toute ligne contenant `WHEN <déclencheur> THE SYSTEM SHALL <exigence>` (insensible à la casse) est extraite en tant qu'`EarsRequirement`, et les signatures `pub fn` / `export function` / `def` dans les blocs de code sont collectées dans `exported_signatures`.

{% code title="crates/core-graph/README.md (exemple de contrat)" overflow="wrap" %}
```markdown
---
id: core-graph
layer: domain
max_lines_per_file: 800
allowed_imports: ["serde::*", "serde_json::*", "toml::*", "bitflags::*", "thiserror::*", "std::*"]
forbidden_imports: ["ast_scanner::*", "security_linter::*", "ai_file_bridge::*", "arch_templates::*", "desktop_shell::*", "axum::*", "tokio::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
  deterministic_only: true
---

- WHEN a graph layout is computed THE SYSTEM SHALL execute deterministically without runtime I/O or network calls.
```
{% endcode %}

## 4. Variables d'environnement

| Variable | Composant | Défaut | Rôle |
|---|---|---|---|
| `AETHER_AGENT_ID` | `aetherscope-mcp` / `--mcp` | `mcp-agent-<pid % 10000>` | Surcharge l'identifiant d'agent MCP (priorité au drapeau CLI `--agent-id`). |
| `AETHER_AGENT_NAME` | `aetherscope-mcp` / `--mcp` | `IA MCP #<pid % 1000>` | Surcharge le nom affiché dans le HUD (priorité au drapeau CLI `--agent-name`). |
| `AETHER_AGENT_COLOR` | `aetherscope-mcp` / `--mcp` | Hash FNV-1a sur palette de 12 couleurs | Surcharge la couleur d'essaim dans le HUD (priorité au drapeau CLI `--color`). |
| `AETHER_RCON_HOST` | Control Plane AetherCraft | `"127.0.0.1"` | Hôte RCON du serveur Minecraft (`rcon_service.py`). |
| `AETHER_RCON_PORT` | Control Plane AetherCraft | `25575` | Port TCP RCON du serveur Minecraft. |
| `AETHER_RCON_PASSWORD` | Control Plane AetherCraft | `"aether2026"` | Mot de passe RCON du serveur Minecraft. |

{% hint style="warning" %}
**`RUST_LOG` est sans effet :** `aether-engine` et `aetherscope-mcp` n'utilisent ni `env_logger` ni `tracing-subscriber`. Ne vous appuyez pas sur `RUST_LOG` pour obtenir des journaux de débogage.
{% endhint %}

## 5. Artefacts générés et journaux de diagnostic

| Emplacement | Artefact | Rôle |
|---|---|---|
| `.aether/` | `settings.json` | Configuration persistée (`SettingsPayload` et `CockpitSettings`). |
| `.aether/` | `LIVE_AUDIT.md` | Rapport temps réel des violations SAST et d'architecture (`AuditWriter::write_live_audit`). |
| `.aether/` | `ACTIVE_TARGET.md` | Contexte complet du symbole inspecté, liaisons, contrats, tâches et commandes MCP. |
| `.aether/` | `CHAT_INBOX.md` | Boîte de dialogue bidirectionnelle IA (`PENDING_AI_RESPONSE` / `ANSWERED`). |
| `.aether/` | `ai_telemetry_cache.json` | Cache de télémétrie d'essaim (jusqu'à 250 événements, TTL 300 s). |
| `.aether/` | `bounty_scope.json` | Périmètre bug bounty (`in_scope`, `out_of_scope`, `mode`, `rationale`). |
| `.aether/` | `tasks/<task_id>/{task.json,README.md}` & `TASKS_SUMMARY.md` | Suivi des tâches et tableau de bord synchronisé (`TaskManager`). |
| `.aether/` | `plugins/` & `plugins/visuals/` | Plugins YAML SAST/Taint et thèmes visuels GLSL WebGL 2. |
| `.aether/` | `cache/ast/` & `cache/osv/` | Cache AST incrémental BLAKE3 et cache hors ligne des avis OSV.dev. |
| Racine projet | `AETHER_AI_RULES.md`, `BENCHMARK.md`, `aetherscope_viewer.html` | Règles maîtresses IA, rapport `--benchmark` et export HTML `/api/export`. |
| Répertoire courant (CWD) | `desktop-shell-panic.log`, `desktop-shell-error.log`, `server-error.log` | Journaux de panique, d'erreur `real_main()` et de démarrage serveur/watcher. |

## Étapes suivantes

{% content-ref url="../core/blake3-governance.md" %}
[Gouvernance BLAKE3 et contrats EARS](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="best-practices.md" %}
[Conseils en or](best-practices.md)
{% endcontent-ref %}
