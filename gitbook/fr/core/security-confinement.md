# Confinement de sécurité et garde-fous

`aether-engine` isole le trafic HTTP local, les lectures et écritures disque, les manifestes de plugins, les shaders GLSL et les secrets grâce à quatre barrières complémentaires : `LocalGuard`, `PathGuard`, `SecretGuard` et `SecretMasker`.

## Architecture de défense en profondeur

Chaque requête reçue par le serveur Axum local (`127.0.0.1:3030`) traverse quatre contrôles — réseau, chemin, fichier sensible et caviardage de contenu — avant d'accéder au disque ou de renvoyer des données vers l'interface ou un agent IA.

```text
Requête HTTP / MCP
   │
   ├─► 1. LocalGuard        ──► Écoute loopback + Host / Origin / Sec-Fetch-Site (403 si refus)
   ├─► 2. PathGuard         ──► Contrôle lexical CWE-22 + profondeur <= 32 + canonicalize (400 / 403 / 413)
   ├─► 3. SecretGuard       ──► Bloque .env, .ssh, clés, chemins système (PROHIBITED / 403)
   └─► 4. SecretMasker      ──► Bloque l'écriture (contains_secret) & masque lectures / MCP / XML
```

## `LocalGuard` : pare-feu loopback et en-têtes

Le serveur desktop (`crates/desktop-shell/src/main.rs`) écoute exclusivement sur `127.0.0.1:<port>` sans couche CORS permissive et enveloppe l'ensemble du routeur Axum dans `axum::middleware::from_fn_with_state` exécutant `local_guard::enforce_local_only` (`crates/desktop-shell/src/local_guard.rs`).

`LocalGuard::is_allowed(host, origin, sec_fetch_site)` vérifie trois en-têtes face aux trois autorités locales autorisées (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`) :

| En-tête | Règle de validation | Menace bloquée |
| :--- | :--- | :--- |
| `Host` | **Obligatoire.** Doit correspondre (insensible à la casse) à l'une des 3 autorités avec le port exact (ex. `127.0.0.1:3030`). | DNS rebinding (`evil.com:3030`) et scan inter-ports |
| `Origin` | **Vérifié si présent.** Doit égaler `http://<autorité_autorisée>` (insensible à la casse). Rejette les origines distantes et `"null"`. | CSRF navigateur cross-origin ; les clients TCP hors navigateur (`aetherscope-mcp`) omettent `Origin` et passent |
| `Sec-Fetch-Site` | **Vérifié si présent.** En minuscules, doit valoir `"same-origin"` ou `"none"`. | Rejette les requêtes navigateur `"cross-site"` et `"same-site"` |

Tout échec renvoie `403 Forbidden` avec le corps texte `"AetherScope: requête refusée (origine non locale)"`.

{% hint style="warning" %}
Si vous testez l'API REST avec `curl` ou un script sur un port personnalisé, veillez à ce que l'en-tête `Host` corresponde à `127.0.0.1:<port>` et n'envoyez ni `Origin` externe ni `Sec-Fetch-Site: cross-site`.
{% endhint %}

## `PathGuard` / `TargetJail` (confinement CWE-22)

`PathGuard` (`crates/obsidian-vault/src/confinement.rs`, aliasé en `pub type TargetJail = PathGuard`) applique la validation lexicale, le confinement canonique à la racine, la défense contre l'évasion par liens symboliques et le plafonnement de taille pour l'IDE, le coffre Obsidian et l'export.

### Limites cœur et liste blanche d'extensions

* **`DEFAULT_MAX_FILE_SIZE`** : `10 * 1024 * 1024` octets (`10 Mo`) par lecture en mémoire (`SecurityError::FileTooLarge`).
* **`MAX_PATH_DEPTH`** : `32` segments de chemin (`SecurityError::DepthExceeded`).
* **`ALLOWED_RAW_EXTENSIONS` (15 extensions)** : `png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `markdown`, `txt`, `csv`.

### Validation lexicale et défense contre les symlinks

1. **Contrôles lexicaux** (`validate_lexical_path` / `validate_client_relative_path`) : Rejette les chaînes vides ou blanches, les octets nuls (`\0`), les schémas d'URL (`://`), les chemins UNC (`\\`, `//`, `\\?\`), les lettres de lecteur Windows (`C:`, `:/`, `:\`), les `/` ou `\` initiaux (`Path::is_absolute()`), la remontée `..` (`Component::ParentDir`) et toute profondeur supérieure à `32` segments.
2. **Canonicalisation et symlinks** (`resolve_and_verify` / `resolve_write_target`) : Inspecte `fs::symlink_metadata` (bloquant les symlinks si `allow_internal_symlinks` vaut `false`), canonicalise la cible (ou le dossier ancêtre existant le plus proche lors d'une écriture) et vérifie `canonical_target.starts_with(&self.canonical_root)`. Un lien sortant déclenche `SecurityError::SymlinkEscape` ; un chemin hors racine déclenche `SecurityError::PathEscapesRoot`.
3. **Contrôle fichier régulier et taille** (`read_to_string` / `read_bytes`) : Vérifie `metadata.is_file()` et `metadata.len() <= max_file_size`.

### Correspondance HTTP et écriture atomique `/api/save_file`

`security_error_to_status_and_json` (`crates/desktop-shell/src/main.rs`) traduit les variantes `SecurityError` en codes HTTP stricts :

| Code HTTP | Variantes `SecurityError` |
| :--- | :--- |
| `400 Bad Request` | `NullByteDetected`, `PathTraversal`, `UncPathProhibited`, `DriveLetterProhibited`, `AbsolutePathsProhibited`, `UrlSchemeProhibited`, `InvalidPrefix`, `DepthExceeded`, `ExtensionNotAllowed`, `NotAFile` |
| `403 Forbidden` | `SensitiveFileProhibited`, `PathEscapesRoot`, `SymlinkEscape`, `SymlinksDisabled` |
| `404 Not Found` | `IoError` lorsque `source.kind() == ErrorKind::NotFound` |
| `413 Payload Too Large` | `FileTooLarge` |
| `500 Internal Server Error` | Autres `IoError` ou échec de canonicalisation racine |

`AppState::save_file` (`crates/desktop-shell/src/api_routes.rs`, derrière `POST /api/save_file`) acquiert `self.file_save_lock.lock().await`, valide le chemin via `PathGuard::validate_client_relative_path`, `SecretGuard::is_secret_path`, `PathGuard::validate_not_sensitive` et `guard.resolve_write_target`, écrit dans un fichier temporaire frère `.{nom}.tmp.{pid}_{seq}_{nanos}` puis le promeut atomiquement via `std::fs::rename` (avec 20 tentatives progressives contre les verrous Windows et repli sur écriture directe en cas de blocage persistant).

## Confinement des plugins et des shaders visuels

Les plugins SAST et les packs visuels WebGL 2 situés sous `.aether/plugins/` appliquent des garde-fous dédiés sur les chemins et le code GLSL.

{% tabs %}
{% tab title="Plugins SAST (plugin_routes.rs)" %}
* **`sanitize_plugin_slug`** : Plafonne le slug à `64` caractères ; rejette les chaînes vides, `\0`, `/`, `\`, `..`, `:`, `.` et tout caractère hors alphanumérique ASCII, `-`, `_` ou espace (converti en `-`).
* **`push_normal_rel_path`** : Rejette les chemins vides, `\0`, `/` initial, `//`, `:`, `..` et tout segment autre que `Component::Normal`.
* **`resolve_confined_plugin_file`** : Confine la résolution dans `<project_root>/.aether/plugins`, n'autorise que `.yaml`, `.yml` et `.json`, vérifie `SecretGuard::is_secret_path`, canonicalise dossier et cible, et exige `canon_target.starts_with(&canon_plugins) && canon_target.is_file()`.
{% endtab %}

{% tab title="Plugins visuels (visual_plugin_routes.rs)" %}
* **Confinement des fichiers (`read_confined_glsl`)** : N'accepte qu'un nom de fichier `.glsl` simple dans `.aether/plugins/visuals/<slug>/` (sans `/`, `\`, `..`, `:` ni `\0`), applique `SecretGuard::is_secret_path` sur le dossier et vérifie l'appartenance après `fs::canonicalize`.
* **Garde GLSL anti-DoS (`validate_glsl_hook`)** : Impose `MAX_GLSL_BYTES = 32 * 1024` (`32 Ko`), supprime les commentaires, rejette `\0`, interdit `#version`, `#extension` et `#pragma`, interdit les boucles `while (...)` et `do { ... }`, plafonne les bornes de boucles `for` à `MAX_FOR_LOOP_BOUND = 128` (rejetant les boucles non bornées) et exige la fonction contractuelle `aetherBackdrop` ou `aetherNodeSurface`.
{% endtab %}
{% endtabs %}

## `SecretGuard` : blocage des chemins sensibles

`SecretGuard::is_secret_path` (`crates/security-linter/src/secret_guard.rs`, reproduit dans `crates/obsidian-vault/src/confinement.rs`) normalise les séparateurs en `/` et contrôle chemins complets, segments, préfixes et extensions sans tenir compte de la casse :

| Catégorie | Motifs bloqués |
| :--- | :--- |
| **Chemins système** | `etc/passwd`, `etc/shadow`, `etc/sudoers`, `windows/system32`, `system32/config`, `win.ini`, `system.ini` |
| **Fichiers d'environnement** | `.env`, `.env.*`, `*.env`, `.envrc`, `.envrc.*` |
| **Dossiers sensibles** | `.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets`, `.secrets`, `credentials`, `.credentials` |
| **Noms de fichiers exacts** | `credentials`, `secrets`, `secret`, `service-account.json`, `service_account.json`, `master.key`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `authorized_keys`, `known_hosts`, `passwd`, `shadow`, `sudoers`, `sam`, `system` |
| **Préfixes de fichiers** | `credentials.*`, `secrets.*`, `secret.*`, `service-account.*`, `service_account.*`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*` |
| **Extensions sensibles** | `.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`, `.kdbx`, `.der`, `.crt`, `.cer`, `.jks`, `.keystore` |

### Points d'application

`SecretGuard::is_secret_path` est appliqué sur toutes les frontières Rust, HTTP et MCP manipulant des fichiers :

* **Pare-feu IA** : `PatchVerifier::verify_patch_internal` (`patch_verifier.rs`) émet `PROHIBITED_SECRET_FILE_MODIFICATION` (`CWE-538`, `CRITICAL`).
* **Routes IDE et arborescence** : `AppState::save_file` et `list_project_files` (`api_routes.rs`), ainsi que `/api/save_doc`, `/api/ai/target`, `/api/ai/create_file` et `/api/file_content` (`main.rs`).
* **Routes plugins** : `resolve_confined_plugin_file` (`plugin_routes.rs`) et `resolve_confined_visual_dir` (`visual_plugin_routes.rs`).
* **Outils MCP** : `aetherscope_get_active_target`, `aetherscope_search_symbols`, `aetherscope_scan_with_plugins` et `aetherscope_verify_patch` (`mcp.rs`).

## `SecretMasker` : 12 familles de secrets et caviardage

Lorsque des fichiers sources ou de configuration non secrets contiennent des jetons en ligne, `SecretMasker` (`crates/security-linter/src/secret_masker.rs`) détecte et caviarde **12 familles d'expressions régulières** via `SecretMasker::contains_secret` et `SecretMasker::mask_text` :

| # | Famille de secret | Motif de détection | Remplacement caviardé |
| :--- | :--- | :--- | :--- |
| 1 | **Blocs de clés privées** | `(?s)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----` | `[PRIVATE_KEY_BLOCK_REDACTED]` |
| 2 | **Clés OpenAI / Anthropic / Gemini** | `\bsk-[a-zA-Z0-9_-]{20,}\b` | `sk-***[REDACTED]***` |
| 3 | **PAT GitHub classique** | `\bghp_[a-zA-Z0-9]{36}\b` | `ghp_***[REDACTED]***` |
| 4 | **PAT GitHub granulaire** | `\bgithub_pat_[a-zA-Z0-9_]{50,}\b` | `github_pat_***[REDACTED]***` |
| 5 | **Jetons GitHub OAuth / Server / Refresh** | `\bgh[ousr]_[a-zA-Z0-9]{36}\b` | `gh***[REDACTED]***` |
| 6 | **Identifiants AWS Access Key** | `\bAKIA[0-9A-Z]{16}\b` | `AKIA***[REDACTED]***` |
| 7 | **Clés Stripe Live** | `\b(sk_live\|rk_live)_[0-9a-zA-Z]{24,}\b` | `${1}_***[REDACTED]***` |
| 8 | **Jetons Slack** | `\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b` | `xox-***[REDACTED]***` |
| 9 | **JSON Web Tokens (JWT)** | `\bey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b` | `ey***[JWT_REDACTED]***` |
| 10 | **URI base de données avec mot de passe** | `([a-zA-Z0-9+]+://[^:/\s@]+):([^@\s/]+)@` | `${1}:***@` |
| 11 | **Affectations secrètes entre guillemets** | `(?i)\b((?:api_key\|api_secret\|secret_key\|secret\|password\|passwd\|auth_token\|access_token\|private_key)\s*[:=]\s*["'])([^"'\r\n]{4,})(["'])` | `${1}******** [REDACTED]${3}` |
| 12 | **Affectations secrètes sans guillemets** | `(?i)\b((?:api_key\|api_secret\|secret_key\|secret\|password\|passwd\|auth_token\|access_token)\s*=\s*)([^\s"';]{4,})` | `${1}******** [REDACTED]` |

### Rejet en écriture vs masquage en lecture

* **Rejet en écriture (`SecretMasker::contains_secret`)** : `POST /api/save_doc` et `POST /api/ai/create_file` (`crates/desktop-shell/src/main.rs`) rejettent avec `403 Forbidden` tout contenu correspondant à l'une des 12 familles.
* **Masquage en lecture sur `/api/file_content`** : Le handler Rust applique `SecretMasker::mask_text` par défaut (`raw` vaut `false`), garantissant aux appelants HTTP sans paramètre une sortie caviardée. Dans l'interface Cockpit, `api.getFileContent(path, raw = true)` (`crates/desktop-shell/ui/src/lib/api.ts`) passe `&raw=true` afin que l'IDE intégré et le studio Bounty chargent fidèlement les fichiers non secrets (`SecretGuard::is_secret_path` continue de bloquer les fichiers sensibles en `403`).
* **Handshakes IA et outils MCP** : `POST /api/ai/target` masque le XML `<aether_handshake>` via `SecretMasker::mask_text`, et `mcp.rs` caviarde les sorties de `aetherscope_get_active_target`, `aetherscope_search_symbols` et `aetherscope_scan_with_plugins`.
* **Caviardage CWE-538 du scanner de surface (`surface_probes.rs`)** : Lors des scans boîte noire de niveau 4, `probe_sensitive_artifacts` teste des chemins tels que `/.env` et `/.env.local`, écarte les réponses HTML Soft-404, n'extrait que les noms de clés en majuscules (`<= 48` caractères) et masque chaque valeur sous la forme `KEY=******** [MASQUÉ]` (5 clés max dans `redacted_preview`) sans jamais stocker de secret brut.

{% content-ref url="./improvements-and-workflows.md" %}
[Améliorations IA et pare-feu de patch](./improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-overview.md" %}
[Vue d'ensemble de l'API REST](../api-mcp/rest-api-overview.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/surface-scanner.md" %}
[Scanner de surface d'attaque réseau](../api-mcp/surface-scanner.md)
{% endcontent-ref %}

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[Plugins visuels WebGL 2](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}
