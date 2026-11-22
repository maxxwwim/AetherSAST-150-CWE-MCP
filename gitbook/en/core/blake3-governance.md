# BLAKE3 Cryptography & EARS Governance

`aether-engine` combines BLAKE3 cryptographic hashing with EARS folder contracts (`README.md`) to seal architectural boundaries, accelerate incremental scans, and verify AI patches in real time.

## Overview

Every critical integrity, caching, and governance layer in `aether-engine` uses **BLAKE3** (`64`-character lowercase hexadecimal digests) paired with Easy Approach to Requirements Syntax (**EARS**) contracts. Folder `README.md` files act as living architectural contracts sealed in `aether.lock.toml`, while per-file and plugin digests guarantee deterministic cache invalidation across codebases and air-gapped dependency audits.

## The 5 BLAKE3 Mechanisms

| # | Mechanism | Storage / Field | Exact Input Formula | Consumer / Failure Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Contract Sealing** | `aether.lock.toml` (`[galaxies.*].readme_blake3`) | Raw UTF-8 bytes of `README.md` | Checked by `ProjectScanner` & `<50ms` `PatchVerifier`; mismatch emits `CRITICAL` `BLAKE3_TAMPERED` (`CWE-353`) |
| **2** | **Per-File Source Digest** | `SymbolMetadata.file_blake3_hash` | Raw UTF-8 bytes of each scanned source file | Tracks source identity across scans (truncated to 16 hex chars in compact UI payloads) |
| **3** | **Incremental AST+SAST Cache** | `.aether/cache/ast/<key>.json` | `"v1\|{rel_path}\|{file_hash}\|{contract_sig}\|{plugin_digest}"` | Reuses `CachedFileScan` via atomic `.tmp_*` + `fs::rename` write when source, contract, and plugins match |
| **4** | **Plugin Config Digest** | In-memory `PluginEngine::config_digest()` | `"aether-plugin-engine-v2:"` + `selection.canonical_key()` + `"\|"` + enabled `PluginManifest` JSONs | Passed as `plugin_digest` into Mechanism 3, invalidating AST cache whenever `--plugins` or manifests change |
| **5** | **Air-Gapped OSV SCA Cache** | `.aether/cache/osv/<hash>.json` | `"{ecosystem}:{package}:{version}"` | Checked before network queries; `--offline-sca` returns empty on cache miss without opening any socket |

### 1. `ReadmeContract` Sealing in `aether.lock.toml`

`ReadmeContract::parse` and `ReadmeContract::compute_blake3_hex` (`crates/security-linter/src/contract.rs`) compute a 64-character BLAKE3 digest over the raw UTF-8 bytes of each `README.md`. When `aether.lock.toml` exists at the project root:

* **Full Scan Verification (`ast-scanner`)**: Loads `[galaxies.<key>]` entries indexed by normalized `path` and `gal_key`. Any sealed `README.md` where `contract.verify_lock(expected_hash)` returns `false` sets `node.metadata.lock_verified = Some(false)`, `node.has_security_violation = true`, emits a `BLAKE3_TAMPERED` (`CWE-353 / BLAKE3-INTEGRITY`, `CRITICAL`) anomaly, and attaches a self-loop violation edge.
* **AI Firewall Verification (`PatchVerifier`)**: Rejects any AI patch modifying a sealed `*readme.md` file whose digest diverges from `aether.lock.toml` (`PatchVerdict::Rejected`).

### 2. Per-File Source Digest (`file_blake3_hash`)

During scanning (`crates/ast-scanner/src/scanner.rs`), every non-skipped source file is hashed into `CachedFileScan.file_hash` and propagated to `SymbolBubble.metadata.file_blake3_hash`. When compact UI transport activates (`> 3,000` nodes or `> 20,000` edges), `blake3_hash` and `file_blake3_hash` are truncated to 16 hex characters.

### 3. Incremental AST+SAST Disk Cache (`.aether/cache/ast/`)

When `ProjectScanner.use_cache` is `true` (default), `ast-scanner` caches each file's parsed `CachedFileScan` (`nodes`, `calls`, `routes_*`, `ws_*`, `violations`) under `.aether/cache/ast/<entry_key>.json`:

```text
contract_sig = "{folder_path}:{blake3_hash}:{effective_max_lines}"   # or "none"
entry_key    = blake3("v1|{rel_path}|{file_hash}|{contract_sig}|{plugin_digest}")
```

To prevent torn reads across parallel `rayon` threads, writes go to `.tmp_{entry_key}_{pid}_{rayon_thread_idx}.json` and are promoted atomically via `std::fs::rename` (with direct-write + cleanup fallback if rename fails).

### 4. `PluginEngine::config_digest()` Cache Invalidation

`PluginEngine::config_digest()` (`crates/security-linter/src/plugin.rs`) hashes `"aether-plugin-engine-v2:"`, `selection.canonical_key()` (`"default"`, `"auto"`, `"all"`, or `"select:<sorted_csv>"`), and the JSON serialization of every enabled `PluginManifest`. Changing a rule file or switching `--plugins` automatically produces a new `entry_key` without stale cache hits.

### 5. Air-Gapped OSV SCA Cache (`.aether/cache/osv/`)

The Reachable OSV SCA scanner (`crates/security-linter/src/sca/cache.rs` & `osv.rs`) hashes `"{ecosystem}:{package}:{version}"` with BLAKE3 to locate `.aether/cache/osv/<hash>.json`. It reads structured `OsvCacheEntry` objects (`cache_version: 1`, `key`, `ecosystem`, `package`, `version`, `queried_at`, `vulns`) and also accepts raw `OsvQueryResponse` (`{"vulns": [...]}`) or `Vec<OsvVulnerability>` arrays for manual air-gap seeding. With `--offline-sca`, a cache miss immediately returns `Ok(Vec::new())` with zero network sockets or `curl` invocations.

{% hint style="info" %}
**AetherCraft Runner Caveat (`sha2::Sha256`)**: Although `apps/aethercraft/runner/Cargo.toml` declares `blake3 = "1.5"` in its dependencies, `apps/aethercraft/runner/src/installer.rs` verifies downloaded server `.jar` artifacts exclusively with `sha2::Sha256` (not BLAKE3) to match the PaperMC API and the `.aether-manifest.json` `sha256` field. See [AetherCraft](../extensions-dev/aethercraft.md) for details.
{% endhint %}

## EARS Architectural Contracts (`README.md`)

A folder `README.md` becomes an architectural contract through YAML frontmatter (`ReadmeFrontmatter`) and EARS requirement statements in the Markdown body.

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

# Example Domain Contract

WHEN an external request enters the domain module, THE SYSTEM SHALL validate all identifiers before persistence.

```rust
pub fn validate_order_id(id: &str) -> Result<(), DomainError>
```
````
{% endcode %}

### `ReadmeFrontmatter`, `SecurityRules`, and EARS Parsing

* **Frontmatter defaults**: If a `README.md` omits YAML frontmatter, `ReadmeContract::parse` falls back to `id = folder_path.replace(['/', '\\'], "-")`, `layer = "utility"`, `max_lines_per_file = 300`, empty import/extension/function lists, and all `SecurityRules` flags `false` (`upsert_contract_content` uses `layer = "domain"` when creating a new contract).
* **EARS extraction**: Scans Markdown body lines case-insensitively for `WHEN ... THE SYSTEM SHALL ...` (requiring `THE SYSTEM SHALL` after `WHEN `), storing `EarsRequirement { raw, trigger, system_shall }`.
* **Exported signatures**: Collects lines inside fenced code blocks starting with `pub fn `, `export function `, or `def `.

### Enforced Contract Rules

| Rule ID | CVE / Category | Severity | Enforcement Logic & Exemptions |
| :--- | :--- | :--- | :--- |
| `BLAKE3_TAMPERED` | `CWE-353 / BLAKE3-INTEGRITY` | `CRITICAL` | Triggered when a `README.md` digest differs from `aether.lock.toml` (`ProjectScanner` and `PatchVerifier`). |
| `RULE_MAX_LINES` | `CONTRACT / ARCH-BUDGET-EXCEEDED` | `WARNING` | Uses `file_max_lines` override first, else custom `max_lines_per_file` (`!= 300`), else language defaults: `.java` (`10_000`), `.sol` (`600`), others (`300`). Test files and interfaces/types (`.d.ts`, `I*.java`, `I*.sol`, `/types/`) are exempt unless an explicit `file_max_lines` override exists. |
| `RULE_FORBIDDEN_IMPORT` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `CRITICAL` | Scans lines starting with `use `, `import `, or `from ` against each `forbidden_imports` pattern (stripping trailing `*` and `:`). |
| `RULE_FORBIDDEN_FUNCTION` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `CRITICAL` | Detects calls to `forbidden_functions` (or `macro!`) outside declarations (`fn`, `def`, `function`). |
| `SAST_DIRECT_ENV_ACCESS` | `CWE-15 / DIRECT-ENV-ACCESS` | `HIGH` | Active when `security_rules.no_env_access == true` **or** file path contains `"domain"` (excluding test files); flags `std::env::var`, `process.env`, and `os.environ`. |

Contracts can also restrict file types via `allowed_extensions` / `forbidden_extensions` (`README.md` is always exempt) and folder density via `max_files_per_folder`.

## `aether.lock.toml` Structure & Endpoints

The workspace lockfile (`aether.lock.toml`) records `version = 2`, `project_id`, `stack_type`, `topology_mode`, `[galaxies.<key>]` contract entries, and `[guardrails]`.

{% code title="aether.lock.toml (excerpt)" overflow="wrap" %}
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
**`GuardrailSettings` Nuance**: `GuardrailSettings` (`block_forbidden_imports`, `enforce_ears_syntax`, `sast_strict_mode`, `require_signature_on_contract_change`) is parsed and persisted in `aether.lock.toml` via `core-graph/src/manifest.rs`. However, `ProjectScanner` and `PatchVerifier` read only `[galaxies.*]` hashes from `aether.lock.toml` and enforce `RULE_FORBIDDEN_IMPORT`, `RULE_MAX_LINES`, SAST rules, and BLAKE3 verification unconditionally whenever contracts exist—setting `[guardrails]` booleans to `false` does not disable SAST checks.
{% endhint %}

### Contract Signing & Updating API

{% tabs %}
{% tab title="POST /api/contracts/sign" %}
### 🎮 Signature / Endpoint

```http
POST /api/contracts/sign
Content-Type: application/json
```

### 📝 Arguments / Parameters

| Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `project_path` | `string \| null` | No | Workspace root override (defaults to active `AppState.project_root`). |
| `folder` | `string \| null` | No | Optional folder scope; signs all non-hidden `README.md` contracts in the project when omitted. |

### 💎 Return Value / Response

| Field | Type | Description |
| :--- | :--- | :--- |
| `status` | `string` | `"ok"` on completion. |
| `signed_count` / `lock_path` | `number` / `string` | Number of sealed contracts and updated `aether.lock.toml` path (`SignContractsResponse`). |

### 💡 Example

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

### 📝 Arguments / Parameters

| Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `folder` | `string \| null` | No | Target contract folder (creates a subfolder `README.md` inheriting from the nearest parent contract if needed). |
| `file_path` | `string \| null` | No | Target file path for `file_max_lines` overrides. |
| `max_lines_per_file` | `number \| null` | No | Updates folder-wide line budget. |
| `file_max_lines` | `number \| null` | No | Sets a per-file line budget override. |
| `clear_file_override` | `boolean` | No | Removes the `file_max_lines` override for `file_path`. |
| `allowed_imports` / `forbidden_imports` | `string[] \| null` | No | Replaces import boundary lists in frontmatter. |

### 💎 Return Value / Response

| Field | Type | Description |
| :--- | :--- | :--- |
| `contract_path` | `string` | Path to the updated `README.md` contract. |
| `blake3_hash` / `file_blake3_hash` | `string` | New 64-hex BLAKE3 digest sealed into `aether.lock.toml`. |
| `effective_max_lines` | `number` | Resolved line budget for the target file. |
| `graph` | `UiGraphPayload` | Refreshed `AetherGraph` after automatic rescan. |

### 💡 Example

```bash
curl -X POST http://127.0.0.1:3030/api/contracts/update \
  -H "Content-Type: application/json" \
  -d '{"folder":"crates/core-graph","max_lines_per_file":400}'
```
{% endtab %}
{% endtabs %}

{% content-ref url="./graph-engine.md" %}
[Spatial Graph Engine](./graph-engine.md)
{% endcontent-ref %}

{% content-ref url="./improvements-and-workflows.md" %}
[Improvements, Enhancements & AI Firewall](./improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../getting-started/configuration.md" %}
[Configuration & Environment](../getting-started/configuration.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[REST API: IDE, Contracts, AI & Tasks](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}
