# Golden Best Practices

Actionable field tips (*Conseils en or*) grounded in `aether-engine` internals to keep contracts sealed, AI edits safe, SAST signals crisp, and large repositories fast.

## 1. EARS Contract & BLAKE3 Lock Hygiene

* **Respect line budgets before splitting files artificially**: Default `max_lines_per_file` is `300` lines (`.java`: `10,000`, `.sol`: `600`). When a single cohesive file legitimately needs more room, set a targeted entry in `file_max_lines` inside that folder's `README.md` instead of inflating the whole folder budget. Note that `RULE_MAX_LINES` emits a `WARNING` (it does not block `PatchVerifier`), and test/mock/interface/`.d.ts` files are exempt unless explicitly listed in `file_max_lines`.
* **Use `forbidden_imports` for hard boundaries and `allowed_imports` for AI guidance**: `SecurityLinter` actively blocks `use`/`import`/`from` lines matching `forbidden_imports` with `RULE_FORBIDDEN_IMPORT` (`CRITICAL`, which rejects patches in `PatchVerifier`), while `allowed_imports` populates `<aether_handshake>` and `.aether/ACTIVE_TARGET.md` to guide AI agents.
* **Write verifiable EARS clauses**: Add `- WHEN <trigger> THE SYSTEM SHALL <behavior>` statements in `README.md` so both human reviewers and AI handshakes share crisp behavioral invariants.
* **Never hand-edit a sealed `README.md` without re-sealing**: Modifying a locked `README.md` without updating `aether.lock.toml` triggers `BLAKE3_TAMPERED` (`CWE-353`, `CRITICAL`). Always re-seal via `POST /api/contracts/update`, `POST /api/contracts/sign`, `POST /api/save_doc` on `README.md`, or the Cockpit Inspector's 1-click sign action.

{% hint style="success" %}
**Tip:** Passing `max_files_per_folder: 0` to `POST /api/contracts/update` clears an existing folder file-count limit cleanly while keeping `aether.lock.toml` sealed.
{% endhint %}

## 2. AI Surgical Workflow & `<50ms` Firewall

Follow the closed-loop workflow documented in `AETHER_AI_RULES.md`:

1. **Read `AETHER_AI_RULES.md` first**: Automatically maintained at the project root on startup/audit and appended to `GET /api/ai/system_prompt`.
2. **Start with `aetherscope_get_graph_summary`**: Get the graph health, active violations, and `.aether/tasks/` queue in a single MCP call.
3. **Lock your target with `aetherscope_get_active_target`**: Generates `.aether/ACTIVE_TARGET.md` and returns `<aether_handshake version="2.1">` XML (incoming/outgoing categorized liaisons capped at 4 per group, contract rules, active tasks, and `[AETHER_ACK]` confirmation).
4. **Keep pure domain functions small and track tasks**: Aim for `< 35` lines for pure domain functions and record progress with `aetherscope_manage_tasks` (`.aether/tasks/` + `TASKS_SUMMARY.md`).
5. **Certify every edit with `aetherscope_verify_patch`**: Runs `PatchVerifier` in `< 50 ms` against `SecretGuard`, `BLAKE3_TAMPERED`, `RULE_MAX_LINES`, SAST + `RULE_FORBIDDEN_IMPORT`, and reverse-BFS `compute_reachability` exploit paths.

{% hint style="info" %}
`PatchVerifier` rejects (`[PATCH_REJECTED]`) any patch with `CRITICAL`, `HIGH`, `RULE_FORBIDDEN_IMPORT`, `BLAKE3_TAMPERED`, or `FILE_NOT_FOUND`. `RULE_MAX_LINES` (`WARNING`) is reported without blocking delivery.
{% endhint %}

## 3. Security, SAST & Reachable SCA Hygiene

* **Never touch sensitive paths or embed tokens**: `SecretGuard` blocks `.env*`, `.git`, `.ssh`, `.aws`, `.kube`, `.docker`, `id_rsa*`, `.pem`/`.key`/`.p12`/`.pfx` files across scanners, `PatchVerifier`, MCP, and REST endpoints. `SecretMasker` redacts 12 secret families on reads and returns `403 FORBIDDEN` on `/api/save_doc` or `/api/ai/create_file` if a token is detected.
* **Trust dual-pass lexical masking (`AuditContext`)**: Strings and comments are masked per language before non-literal rules run, Rust inline `#[cfg(test)]` / `mod tests` blocks are truncated, and custom YAML plugins default to `check_literals: false`. Avoid suppressing real rules just because a term appears in a comment—that is already filtered out.
* **Separate `ignored_cwes` from `--plugins`**:
  * Use `ignored_cwes` in `.aether/settings.json` for **post-scan UI/graph suppression** (case-insensitive substring/exact match on `rule_id` or `cve_id`). Note that `BLAKE3_TAMPERED` and `RULE_MAX_LINES` remain protected against accidental suppression by `active_cve_rules`.
  * Use `--plugins <SPEC>` (`default`, `auto`, `all`, pack names, or `profile:<name>`) for **scan-time rule selection** in CLI and CI runs.
* **Gate CI on Reachable SCA and unsanitized taint**: Run `--sca` (or `--offline-sca` with `.aether/cache/osv/` in air-gapped CI) alongside `--fail-on HIGH|CRITICAL`. In `--sca-only`, `--fail-on` evaluates **only reachable** vulnerabilities (`is_reachable == true`), and in `--audit-only`, `--fail-on` automatically skips taint findings marked `is_sanitized == true`.

## 4. Performance & Large-Repo Hygiene

* **Trim noise with `exclusions`**: Beyond built-in exclusions (`.git`, `node_modules`, `target`, `dist`, `vendor`, files `> 1.5 MB`, `.d.ts`, `*.min.js`), add generated assets or fixture folders to `exclusions` in `.aether/settings.json`.
* **Keep `.aether/cache/ast/` intact**: Each file entry is keyed by BLAKE3(`v1|<rel_path>|<file_hash>|<contract_sig>|<plugin_digest>`), skipping redundant parsing and linting on unchanged files.
* **Understand large-graph thresholds**:
  * **UI auto-eco (`> 2,500` nodes)**: `graphState.svelte.ts` automatically activates `lowMemoryMode` (`dpr = 1`, reduced badges, no heavy `shadowBlur`).
  * **Backend compaction (`> 3,000` nodes or `> 20,000` edges)**: `GET /api/graph` switches to indexed `edges_compact` and strips `raw_content`. Always append `?full=1` if your script needs full uncompacted JSON.
* **Windows WebView2 heap**: On Windows, `aether-engine` automatically passes `--js-flags=--max-old-space-size=4096` to WebView2 so large multi-module graphs stay responsive.

## Next Steps

{% content-ref url="../core/improvements-and-workflows.md" %}
[AI Improvements & Patch Firewall](../core/improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../extensions-dev/benchmark-and-performance.md" %}
[Benchmark & Performance Tuning](../extensions-dev/benchmark-and-performance.md)
{% endcontent-ref %}
