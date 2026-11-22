# Security Confinement & Guardrails

`aether-engine` isolates local HTTP traffic, filesystem reads and writes, plugin manifests, GLSL shaders, and secret material through four composable defense layers: `LocalGuard`, `PathGuard`, `SecretGuard`, and `SecretMasker`.

## Defense-in-Depth Architecture

Every request entering the local Axum server (`127.0.0.1:3030`) passes through network, path, secret-path, and content-redaction boundaries before touching disk or returning data to the UI or an AI agent.

```text
HTTP / MCP Request
   │
   ├─► 1. LocalGuard        ──► Loopback bind + Host / Origin / Sec-Fetch-Site (403 on mismatch)
   ├─► 2. PathGuard         ──► Lexical CWE-22 + Depth <= 32 + Symlink canonicalize (400 / 403 / 413)
   ├─► 3. SecretGuard       ──► Blocks .env, .ssh, keys, system paths (PROHIBITED / 403)
   └─► 4. SecretMasker      ──► Blocks writes (contains_secret) & redacts reads / MCP / XML
```

## `LocalGuard`: Loopback & Header Firewall

The desktop server (`crates/desktop-shell/src/main.rs`) binds exclusively to `127.0.0.1:<port>` with **no** permissive CORS layer and wraps the entire Axum router in `axum::middleware::from_fn_with_state` running `local_guard::enforce_local_only` (`crates/desktop-shell/src/local_guard.rs`).

`LocalGuard::is_allowed(host, origin, sec_fetch_site)` enforces three header checks against the server's three allowed authorities (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`):

| Header | Validation Rule | Threat Mitigated |
| :--- | :--- | :--- |
| `Host` | **Required.** Must case-insensitively match one of the 3 authorities with the exact port (e.g., `127.0.0.1:3030`). | DNS rebinding (`evil.com:3030`) and cross-port probing |
| `Origin` | **Checked if present.** Must case-insensitively equal `http://<allowed_authority>`. Rejects remote origins and `"null"`. | Cross-origin browser CSRF; non-browser TCP clients (`aetherscope-mcp`) omit `Origin` and pass |
| `Sec-Fetch-Site` | **Checked if present.** Lowercased value must be `"same-origin"` or `"none"`. | Rejects `"cross-site"` and `"same-site"` browser fetch requests |

Any failed check returns `403 Forbidden` with the plain-text body `"AetherScope: requête refusée (origine non locale)"`.

{% hint style="warning" %}
If you test the REST API with `curl` or a script on a custom port, ensure the `Host` header matches `127.0.0.1:<port>` and avoid sending a forged `Origin` or `Sec-Fetch-Site: cross-site` header.
{% endhint %}

## `PathGuard` / `TargetJail` (CWE-22 Confinement)

`PathGuard` (`crates/obsidian-vault/src/confinement.rs`, aliased as `pub type TargetJail = PathGuard`) enforces lexical validation, canonical root confinement, symlink escape checks, and read-size limits across IDE, vault, and export endpoints.

### Core Limits & Extension Whitelist

* **`DEFAULT_MAX_FILE_SIZE`**: `10 * 1024 * 1024` bytes (`10 MB`) per read into memory (`SecurityError::FileTooLarge`).
* **`MAX_PATH_DEPTH`**: `32` path components (`SecurityError::DepthExceeded`).
* **`ALLOWED_RAW_EXTENSIONS` (15 extensions)**: `png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `markdown`, `txt`, `csv`.

### Lexical Validation & Symlink Defense

1. **Lexical checks** (`validate_lexical_path` / `validate_client_relative_path`): Rejects empty or whitespace-only paths, null bytes (`\0`), URL schemes (`://`), UNC paths (`\\`, `//`, `\\?\`), Windows drive letters (`C:`, `:/`, `:\`), leading `/` or `\` (`Path::is_absolute()`), `..` (`Component::ParentDir`), and paths deeper than `32` segments.
2. **Canonicalization & symlink check** (`resolve_and_verify` / `resolve_write_target`): Inspects `fs::symlink_metadata` (blocking symlinks if `allow_internal_symlinks` is `false`), canonicalizes the target (or nearest existing ancestor directory for new writes), and asserts `canonical_target.starts_with(&self.canonical_root)`. Escaping symlinks raise `SecurityError::SymlinkEscape`; out-of-root paths raise `SecurityError::PathEscapesRoot`.
3. **Regular-file & size check** (`read_to_string` / `read_bytes`): Confirms `metadata.is_file()` and `metadata.len() <= max_file_size`.

### HTTP Status Mapping & Atomic `/api/save_file`

`security_error_to_status_and_json` (`crates/desktop-shell/src/main.rs`) translates `SecurityError` variants to strict HTTP status codes:

| HTTP Status | `SecurityError` Variants |
| :--- | :--- |
| `400 Bad Request` | `NullByteDetected`, `PathTraversal`, `UncPathProhibited`, `DriveLetterProhibited`, `AbsolutePathsProhibited`, `UrlSchemeProhibited`, `InvalidPrefix`, `DepthExceeded`, `ExtensionNotAllowed`, `NotAFile` |
| `403 Forbidden` | `SensitiveFileProhibited`, `PathEscapesRoot`, `SymlinkEscape`, `SymlinksDisabled` |
| `404 Not Found` | `IoError` when `source.kind() == ErrorKind::NotFound` |
| `413 Payload Too Large` | `FileTooLarge` |
| `500 Internal Server Error` | Other `IoError` or root canonicalization failures |

`AppState::save_file` (`crates/desktop-shell/src/api_routes.rs`, backing `POST /api/save_file`) acquires `self.file_save_lock.lock().await`, validates the relative path via `PathGuard::validate_client_relative_path`, `SecretGuard::is_secret_path`, `PathGuard::validate_not_sensitive`, and `guard.resolve_write_target`, writes to a sibling temporary file `.{filename}.tmp.{pid}_{seq}_{nanos}`, and atomically promotes it via `std::fs::rename` (with a 20-step backoff retry for Windows handle contention and a 10-step direct-write fallback if rename stays locked).

## Plugin & Visual Plugin Confinement

Both SAST plugins and WebGL 2 visual plugins under `.aether/plugins/` enforce dedicated path and AST/GLSL guards.

{% tabs %}
{% tab title="SAST Plugins (plugin_routes.rs)" %}
* **`sanitize_plugin_slug`**: Caps slugs at `64` characters; rejects empty strings, `\0`, `/`, `\`, `..`, `:`, `.`, and any character outside ASCII alphanumeric, `-`, `_`, or space (mapped to `-`).
* **`push_normal_rel_path`**: Rejects empty paths, `\0`, leading `/`, `//`, `:`, `..`, and any non-`Component::Normal` segment.
* **`resolve_confined_plugin_file`**: Confines resolution strictly inside `<project_root>/.aether/plugins`, allows only `.yaml`, `.yml`, and `.json` extensions, runs `SecretGuard::is_secret_path`, canonicalizes both directory and target, and requires `canon_target.starts_with(&canon_plugins) && canon_target.is_file()`.
{% endtab %}

{% tab title="Visual Plugins (visual_plugin_routes.rs)" %}
* **Path confinement (`read_confined_glsl`)**: Allows only a single `.glsl` filename inside the sanitized pack directory under `.aether/plugins/visuals/<slug>/` (rejecting `/`, `\`, `..`, `:`, `\0`), runs `SecretGuard::is_secret_path` on the directory, and verifies `fs::canonicalize` containment.
* **Anti-DoS GLSL guard (`validate_glsl_hook`)**: Enforces `MAX_GLSL_BYTES = 32 * 1024` (`32 KB`), strips comments, rejects `\0`, forbids `#version`, `#extension`, and `#pragma`, forbids `while (...)` and `do { ... }` loops, caps `for` loop bounds at `MAX_FOR_LOOP_BOUND = 128` (rejecting unbounded loops), and requires the contract function `aetherBackdrop` or `aetherNodeSurface`.
{% endtab %}
{% endtabs %}

## `SecretGuard`: Blocked Sensitive Paths

`SecretGuard::is_secret_path` (`crates/security-linter/src/secret_guard.rs`, mirrored in `crates/obsidian-vault/src/confinement.rs`) normalizes backslashes to `/` and checks full paths, components, prefixes, and extensions case-insensitively:

| Category | Blocked Patterns |
| :--- | :--- |
| **System Paths** | `etc/passwd`, `etc/shadow`, `etc/sudoers`, `windows/system32`, `system32/config`, `win.ini`, `system.ini` |
| **Environment Files** | `.env`, `.env.*`, `*.env`, `.envrc`, `.envrc.*` |
| **Sensitive Directories** | `.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets`, `.secrets`, `credentials`, `.credentials` |
| **Exact Filenames** | `credentials`, `secrets`, `secret`, `service-account.json`, `service_account.json`, `master.key`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `authorized_keys`, `known_hosts`, `passwd`, `shadow`, `sudoers`, `sam`, `system` |
| **Filename Prefixes** | `credentials.*`, `secrets.*`, `secret.*`, `service-account.*`, `service_account.*`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*` |
| **Sensitive Extensions** | `.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`, `.kdbx`, `.der`, `.crt`, `.cer`, `.jks`, `.keystore` |

### Enforcement Points

`SecretGuard::is_secret_path` is enforced across every file-touching Rust, HTTP, and MCP boundary:

* **AI Patch Firewall**: `PatchVerifier::verify_patch_internal` (`patch_verifier.rs`) emits `PROHIBITED_SECRET_FILE_MODIFICATION` (`CWE-538`, `CRITICAL`).
* **IDE & File Tree Routes**: `AppState::save_file` and `list_project_files` (`api_routes.rs`), plus `/api/save_doc`, `/api/ai/target`, `/api/ai/create_file`, and `/api/file_content` (`main.rs`).
* **Plugin Routes**: `resolve_confined_plugin_file` (`plugin_routes.rs`) and `resolve_confined_visual_dir` (`visual_plugin_routes.rs`).
* **MCP Server Tools**: `aetherscope_get_active_target`, `aetherscope_search_symbols`, `aetherscope_scan_with_plugins`, and `aetherscope_verify_patch` (`mcp.rs`).

## `SecretMasker`: 12 Secret Families & Redaction

When non-secret source or config files contain inline tokens, `SecretMasker` (`crates/security-linter/src/secret_masker.rs`) detects and redacts **12 regex families** via `SecretMasker::contains_secret` and `SecretMasker::mask_text`:

| # | Secret Family | Detection Pattern | Redacted Replacement |
| :--- | :--- | :--- | :--- |
| 1 | **Private Key Blocks** | `(?s)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----` | `[PRIVATE_KEY_BLOCK_REDACTED]` |
| 2 | **OpenAI / Anthropic / Gemini** | `\bsk-[a-zA-Z0-9_-]{20,}\b` | `sk-***[REDACTED]***` |
| 3 | **GitHub Classic PAT** | `\bghp_[a-zA-Z0-9]{36}\b` | `ghp_***[REDACTED]***` |
| 4 | **GitHub Fine-Grained PAT** | `\bgithub_pat_[a-zA-Z0-9_]{50,}\b` | `github_pat_***[REDACTED]***` |
| 5 | **GitHub OAuth / Server / Refresh** | `\bgh[ousr]_[a-zA-Z0-9]{36}\b` | `gh***[REDACTED]***` |
| 6 | **AWS Access Key IDs** | `\bAKIA[0-9A-Z]{16}\b` | `AKIA***[REDACTED]***` |
| 7 | **Stripe Live Keys** | `\b(sk_live\|rk_live)_[0-9a-zA-Z]{24,}\b` | `${1}_***[REDACTED]***` |
| 8 | **Slack Tokens** | `\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b` | `xox-***[REDACTED]***` |
| 9 | **JSON Web Tokens (JWT)** | `\bey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b` | `ey***[JWT_REDACTED]***` |
| 10 | **Database URI Credentials** | `([a-zA-Z0-9+]+://[^:/\s@]+):([^@\s/]+)@` | `${1}:***@` |
| 11 | **Quoted Secret Assignments** | `(?i)\b((?:api_key\|api_secret\|secret_key\|secret\|password\|passwd\|auth_token\|access_token\|private_key)\s*[:=]\s*["'])([^"'\r\n]{4,})(["'])` | `${1}******** [REDACTED]${3}` |
| 12 | **Unquoted Secret Assignments** | `(?i)\b((?:api_key\|api_secret\|secret_key\|secret\|password\|passwd\|auth_token\|access_token)\s*=\s*)([^\s"';]{4,})` | `${1}******** [REDACTED]` |

### Write Rejection vs. Read Masking

* **Write rejection (`SecretMasker::contains_secret`)**: `POST /api/save_doc` and `POST /api/ai/create_file` (`crates/desktop-shell/src/main.rs`) reject payloads containing any of the 12 secret families with `403 Forbidden`.
* **Read masking on `/api/file_content`**: The Rust handler applies `SecretMasker::mask_text` by default (`raw` defaults to `false`), so unparameterized HTTP callers always receive redacted secrets. In the Cockpit UI, `api.getFileContent(path, raw = true)` (`crates/desktop-shell/ui/src/lib/api.ts`) passes `&raw=true` so the integrated IDE and Bounty code viewer can edit valid non-secret files without corrupting source literals (`SecretGuard::is_secret_path` still blocks secret files with `403`).
* **AI Handshakes & MCP Tools**: `POST /api/ai/target` masks the generated `<aether_handshake>` XML via `SecretMasker::mask_text`, and `mcp.rs` masks outputs from `aetherscope_get_active_target`, `aetherscope_search_symbols`, and `aetherscope_scan_with_plugins`.
* **Surface Scanner CWE-538 Redaction (`surface_probes.rs`)**: During Level 4 black-box scans, `probe_sensitive_artifacts` checks endpoints such as `/.env` and `/.env.local`, filters out SPA Soft-404 HTML responses, extracts only uppercase environment key names (`<= 48` chars), and masks every value as `KEY=******** [MASQUÉ]` (capped at 5 preview entries) without ever storing raw secret values.

{% content-ref url="./improvements-and-workflows.md" %}
[AI Improvements & Patch Firewall](./improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-overview.md" %}
[REST API Overview](../api-mcp/rest-api-overview.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/surface-scanner.md" %}
[Network Attack Surface Scanner](../api-mcp/surface-scanner.md)
{% endcontent-ref %}

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[WebGL 2 Visual Plugins](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}
