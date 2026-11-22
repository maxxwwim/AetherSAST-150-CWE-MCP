# Cryptographie BLAKE3 & Gouvernance EARS

`aether-engine` combine le hachage cryptographique BLAKE3 et les contrats EARS par dossier (`README.md`) pour sceller les frontières architecturales, accélérer les scans incrémentaux et vérifier les correctifs IA en temps réel.

## Vue d'ensemble

Chaque couche critique d'intégrité, de mise en cache et de gouvernance dans `aether-engine` repose sur **BLAKE3** (empreintes hexadécimales minuscules de `64` caractères) associé à la syntaxe **EARS** (*Easy Approach to Requirements Syntax*). Les fichiers `README.md` des dossiers servent de contrats architecturaux vivants scellés dans `aether.lock.toml`, tandis que les empreintes par fichier et par plugin garantissent une invalidation déterministe du cache et des audits SCA hors ligne fiables.

## Les 5 mécanismes BLAKE3

| # | Mécanisme | Stockage / Champ | Formule d'entrée exacte | Consommateur / Comportement en erreur |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Scellement des contrats** | `aether.lock.toml` (`[galaxies.*].readme_blake3`) | Octets UTF-8 bruts de `README.md` | Vérifié par `ProjectScanner` et `PatchVerifier` (`<50ms`) ; divergence -> `BLAKE3_TAMPERED` (`CRITICAL`, `CWE-353`) |
| **2** | **Empreinte par fichier source** | `SymbolMetadata.file_blake3_hash` | Octets UTF-8 bruts de chaque fichier source scanné | Identifie les sources d'un scan à l'autre (tronquée à 16 caractères hex dans les payloads UI compacts) |
| **3** | **Cache disque AST+SAST** | `.aether/cache/ast/<key>.json` | `"v1\|{rel_path}\|{file_hash}\|{contract_sig}\|{plugin_digest}"` | Réutilise `CachedFileScan` via écriture atomique `.tmp_*` + `fs::rename` si source, contrat et plugins concordent |
| **4** | **Digest de configuration plugins** | `PluginEngine::config_digest()` en mémoire | `"aether-plugin-engine-v2:"` + `selection.canonical_key()` + `"\|"` + JSON des `PluginManifest` actifs | Transmis comme `plugin_digest` au mécanisme 3, invalidant le cache AST dès qu'un plugin ou `--plugins` change |
| **5** | **Cache OSV SCA hors ligne** | `.aether/cache/osv/<hash>.json` | `"{ecosystem}:{package}:{version}"` | Consulté avant tout appel réseau ; `--offline-sca` retourne vide sans ouvrir aucun socket en cas de cache miss |

### 1. Scellement `ReadmeContract` dans `aether.lock.toml`

`ReadmeContract::parse` et `ReadmeContract::compute_blake3_hex` (`crates/security-linter/src/contract.rs`) calculent un digest BLAKE3 de 64 caractères sur les octets UTF-8 bruts de chaque `README.md`. Lorsqu'`aether.lock.toml` est présent à la racine du projet :

* **Vérification lors du scan complet (`ast-scanner`)** : Charge les entrées `[galaxies.<key>]` indexées par `path` normalisé et `gal_key`. Tout `README.md` scellé dont `contract.verify_lock(expected_hash)` retourne `false` passe `node.metadata.lock_verified = Some(false)`, `node.has_security_violation = true`, émet une anomalie `BLAKE3_TAMPERED` (`CWE-353 / BLAKE3-INTEGRITY`, `CRITICAL`) et ajoute une arête de violation en boucle.
* **Vérification par le pare-feu IA (`PatchVerifier`)** : Rejette tout correctif IA modifiant un fichier `*readme.md` scellé dont l'empreinte diverge d'`aether.lock.toml` (`PatchVerdict::Rejected`).

### 2. Empreinte par fichier source (`file_blake3_hash`)

Pendant le scan (`crates/ast-scanner/src/scanner.rs`), chaque fichier non ignoré est haché dans `CachedFileScan.file_hash` et propagé vers `SymbolBubble.metadata.file_blake3_hash`. Lorsque le transport UI compact s'active (`> 3 000` nœuds ou `> 20 000` arêtes), `blake3_hash` et `file_blake3_hash` sont tronqués à 16 caractères hexadécimaux.

### 3. Cache disque incrémental AST+SAST (`.aether/cache/ast/`)

Lorsque `ProjectScanner.use_cache` vaut `true` (par défaut), `ast-scanner` met en cache la structure `CachedFileScan` de chaque fichier (`nodes`, `calls`, `routes_*`, `ws_*`, `violations`) dans `.aether/cache/ast/<entry_key>.json` :

```text
contract_sig = "{folder_path}:{blake3_hash}:{effective_max_lines}"   # ou "none"
entry_key    = blake3("v1|{rel_path}|{file_hash}|{contract_sig}|{plugin_digest}")
```

Pour éviter toute lecture partielle entre threads `rayon` parallèles, l'écriture passe par `.tmp_{entry_key}_{pid}_{rayon_thread_idx}.json` puis une promotion atomique via `std::fs::rename` (avec repli en écriture directe + nettoyage si le renommage échoue).

### 4. Invalidation par `PluginEngine::config_digest()`

`PluginEngine::config_digest()` (`crates/security-linter/src/plugin.rs`) hache `"aether-plugin-engine-v2:"`, `selection.canonical_key()` (`"default"`, `"auto"`, `"all"` ou `"select:<sorted_csv>"`) et la sérialisation JSON de chaque `PluginManifest` activé. Modifier une règle ou basculer `--plugins` génère immédiatement un nouvel `entry_key` sans lecture de cache périmé.

### 5. Cache OSV SCA hors ligne (`.aether/cache/osv/`)

Le scanner SCA atteignable OSV (`crates/security-linter/src/sca/cache.rs` et `osv.rs`) hache `"{ecosystem}:{package}:{version}"` en BLAKE3 pour cibler `.aether/cache/osv/<hash>.json`. Il lit des objets structurés `OsvCacheEntry` (`cache_version: 1`, `key`, `ecosystem`, `package`, `version`, `queried_at`, `vulns`) et accepte aussi des réponses brutes `OsvQueryResponse` (`{"vulns": [...]}`) ou des tableaux `Vec<OsvVulnerability>` pour l'amorçage manuel en environnement isolé. Avec `--offline-sca`, un cache miss retourne `Ok(Vec::new())` sans exécuter `curl` ni ouvrir de socket réseau.

{% hint style="info" %}
**Précision sur le runner AetherCraft (`sha2::Sha256`)** : Bien que `apps/aethercraft/runner/Cargo.toml` déclare `blake3 = "1.5"` dans ses dépendances, `apps/aethercraft/runner/src/installer.rs` vérifie les artefacts `.jar` téléchargés exclusivement avec `sha2::Sha256` (et non BLAKE3) afin de correspondre à l'API PaperMC et au champ `sha256` de `.aether-manifest.json`. Consultez [AetherCraft](../extensions-dev/aethercraft.md) pour plus de détails.
{% endhint %}

## Contrats architecturaux EARS (`README.md`)

Un fichier `README.md` devient un contrat architectural grâce à son frontmatter YAML (`ReadmeFrontmatter`) et ses exigences EARS dans le corps Markdown.

{% code title="crates/example-domain/README.md" overflow="wrap" %}
````markdown
---
id: example-domain
layer: domain
max_lines_per_file: 300
file_max_lines:
  large_state_machine.rs: 550
allowed_imports:
  - core_graph
forbidden_imports:
  - desktop_shell::*
  - reqwest::*
forbidden_functions:
  - eval
  - unwrap
allowed_extensions:
  - rs
  - md
max_files_per_folder: 20
security_rules:
  no_raw_sql: true
  no_env_access: true
  untrusted_client_input: false
  deterministic_only: true
---

# Contrat du domaine d'exemple

WHEN an external request enters the domain module, THE SYSTEM SHALL validate all identifiers before persistence.

```rust
pub fn validate_order_id(id: &str) -> Result<(), DomainError>
```
````
{% endcode %}

### `ReadmeFrontmatter`, `SecurityRules` et extraction EARS

* **Valeurs par défaut du frontmatter** : Si un `README.md` omet le frontmatter YAML, `ReadmeContract::parse` applique `id = folder_path.replace(['/', '\\'], "-")`, `layer = "utility"`, `max_lines_per_file = 300`, des listes vides d'imports/extensions/fonctions et tous les drapeaux `SecurityRules` à `false` (`upsert_contract_content` utilise `layer = "domain"` lors de la création d'un nouveau contrat).
* **Extraction EARS** : Scanne les lignes du corps Markdown (insensible à la casse) pour `WHEN ... THE SYSTEM SHALL ...` (en exigeant `THE SYSTEM SHALL` après `WHEN `), produisant `EarsRequirement { raw, trigger, system_shall }`.
* **Signatures exportées** : Collecte les lignes situées dans les blocs de code clôturés commençant par `pub fn `, `export function ` ou `def `.

### Règles de contrat appliquées

| ID de règle | CVE / Catégorie | Sévérité | Logique d'application et exemptions |
| :--- | :--- | :--- | :--- |
| `BLAKE3_TAMPERED` | `CWE-353 / BLAKE3-INTEGRITY` | `CRITICAL` | Déclenchée lorsqu'un `README.md` diverge de son empreinte dans `aether.lock.toml` (`ProjectScanner` et `PatchVerifier`). |
| `RULE_MAX_LINES` | `CONTRACT / ARCH-BUDGET-EXCEEDED` | `WARNING` | Applique `file_max_lines` en priorité, sinon `max_lines_per_file` personnalisé (`!= 300`), sinon les défauts par langage : `.java` (`10_000`), `.sol` (`600`), autres (`300`). Les fichiers de test et interfaces/types (`.d.ts`, `I*.java`, `I*.sol`, `/types/`) sont exemptés sauf surcharge explicite `file_max_lines`. |
| `RULE_FORBIDDEN_IMPORT` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `CRITICAL` | Inspecte les lignes commençant par `use `, `import ` ou `from ` face à chaque motif de `forbidden_imports` (en retirant `*` et `:` finaux). |
| `RULE_FORBIDDEN_FUNCTION` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `CRITICAL` | Détecte les appels à `forbidden_functions` (ou `macro!`) hors déclarations (`fn`, `def`, `function`). |
| `SAST_DIRECT_ENV_ACCESS` | `CWE-15 / DIRECT-ENV-ACCESS` | `HIGH` | Active si `security_rules.no_env_access == true` **ou** si le chemin contient `"domain"` (hors fichiers de test) ; détecte `std::env::var`, `process.env` et `os.environ`. |

Les contrats peuvent également restreindre les types de fichiers via `allowed_extensions` / `forbidden_extensions` (`README.md` est toujours exempté) ainsi que la densité du dossier via `max_files_per_folder`.

## Structure d'`aether.lock.toml` et endpoints associés

Le fichier de verrouillage racine (`aether.lock.toml`) enregistre `version = 2`, `project_id`, `stack_type`, `topology_mode`, les entrées `[galaxies.<key>]` et `[guardrails]`.

{% code title="aether.lock.toml (extrait)" overflow="wrap" %}
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

[guardrails]
block_forbidden_imports = true
enforce_ears_syntax = true
sast_strict_mode = true
require_signature_on_contract_change = true
```
{% endcode %}

{% hint style="warning" %}
**Nuance sur `GuardrailSettings`** : `GuardrailSettings` (`block_forbidden_imports`, `enforce_ears_syntax`, `sast_strict_mode`, `require_signature_on_contract_change`) est parsé et persisté dans `aether.lock.toml` via `core-graph/src/manifest.rs`. Toutefois, `ProjectScanner` et `PatchVerifier` ne lisent que les empreintes `[galaxies.*]` et appliquent `RULE_FORBIDDEN_IMPORT`, `RULE_MAX_LINES`, les règles SAST et la vérification BLAKE3 inconditionnellement dès que des contrats existent : passer les booléens `[guardrails]` à `false` ne désactive pas les contrôles SAST.
{% endhint %}

### API de signature et de mise à jour des contrats

{% tabs %}
{% tab title="POST /api/contracts/sign" %}
### 🎮 Signature / Endpoint

```http
POST /api/contracts/sign
Content-Type: application/json
```

### 📝 Arguments / Paramètres

| Nom | Type | Requis | Description |
| :--- | :--- | :--- | :--- |
| `project_path` | `string \| null` | Non | Surcharge de la racine du projet (par défaut `AppState.project_root`). |
| `folder` | `string \| null` | Non | Dossier cible optionnel ; signe tous les `README.md` non cachés du projet si omis. |

### 💎 Valeur de retour / Réponse

| Champ | Type | Description |
| :--- | :--- | :--- |
| `status` | `string` | `"ok"` en cas de succès. |
| `signed_count` / `lock_path` | `number` / `string` | Nombre de contrats scellés et chemin vers `aether.lock.toml` (`SignContractsResponse`). |

### 💡 Exemple

```bash
curl -X POST http://127.0.0.1:3030/api/contracts/sign \
  -H "Content-Type: application/json" \
  -d '{}'
```
{% endtab %}

{% tab title="POST /api/contracts/update" %}
### 🎮 Signature / Endpoint

```http
POST /api/contracts/update
Content-Type: application/json
```

### 📝 Arguments / Paramètres

| Nom | Type | Requis | Description |
| :--- | :--- | :--- | :--- |
| `folder` | `string \| null` | Non | Dossier cible du contrat (crée au besoin un `README.md` héritant du contrat parent le plus proche). |
| `file_path` | `string \| null` | Non | Chemin de fichier ciblé pour une surcharge `file_max_lines`. |
| `max_lines_per_file` | `number \| null` | Non | Met à jour le budget de lignes du dossier. |
| `file_max_lines` | `number \| null` | Non | Définit une surcharge de budget de lignes par fichier. |
| `clear_file_override` | `boolean` | Non | Supprime la surcharge `file_max_lines` de `file_path`. |
| `allowed_imports` / `forbidden_imports` | `string[] \| null` | Non | Remplace les listes d'imports autorisés ou interdits dans le frontmatter. |

### 💎 Valeur de retour / Réponse

| Champ | Type | Description |
| :--- | :--- | :--- |
| `contract_path` | `string` | Chemin du contrat `README.md` mis à jour. |
| `blake3_hash` / `file_blake3_hash` | `string` | Nouveau digest BLAKE3 (64 hex) scellé dans `aether.lock.toml`. |
| `effective_max_lines` | `number` | Budget de lignes effectif résolu pour le fichier cible. |
| `graph` | `UiGraphPayload` | `AetherGraph` actualisé après rescan automatique. |

### 💡 Exemple

```bash
curl -X POST http://127.0.0.1:3030/api/contracts/update \
  -H "Content-Type: application/json" \
  -d '{"folder":"crates/core-graph","max_lines_per_file":400}'
```
{% endtab %}
{% endtabs %}

{% content-ref url="./graph-engine.md" %}
[Moteur de graphe spatial](./graph-engine.md)
{% endcontent-ref %}

{% content-ref url="./improvements-and-workflows.md" %}
[Améliorations, workflows & Pare-feu IA](./improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../getting-started/configuration.md" %}
[Configuration & environnement](../getting-started/configuration.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[API REST : IDE, contrats, IA et tâches](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}
