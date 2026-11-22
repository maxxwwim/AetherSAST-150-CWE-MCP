# Obsidian Vault & Dual-Vision Engine

The `crates/obsidian-vault` engine classifies workspaces into code, knowledge vaults, or mixed repositories and lets you switch live (`Alt+V`) between AST code graphs and Obsidian note galaxies.

---

## 4-Stage Project Classification

At startup (`execute_project_pipeline`), AetherScope calls `detect_project_type(root)` (`crates/obsidian-vault/src/detector.rs`) to execute a deterministic 4-stage pipeline:

1. **`.obsidian/` Proximity (`find_obsidian_dir`)**: Checks `root/.obsidian`, prioritized documentation folders (`docs`, `notes`, `vault`, `doc`, `wiki`, `documentation`, `kb`, `knowledge`), and a bounded `WalkDir` (`min_depth(1).max_depth(2)`).
2. **Pruned File Counting**: Walks non-hidden, non-ignored directories (pruning `target`, `node_modules`, `.git`, `.obsidian`, `bin`, `obj`, `dist`, `build`, `.turbo`, `.next`, `vendor`, `.cargo`, `.idea`, `.vscode`, `.venv`, `venv`, plus `.min.js`, `.bundle.js`, `.d.ts`, `build.rs`). Counts `code_files_count` across 28 source extensions vs. `markdown_files_count` (`.md`, `.markdown`), queuing up to `max_syntax_sample_files = 10` paths.
3. **Bounded Syntax Sampling (`sample_syntax_markers`)**: Reads up to `65,536` bytes (`64 KB`) per sampled Markdown file and counts wikilinks, transclusions, nested `#tag/subtag` markers (ignoring `#` headings), and YAML frontmatter keys (`tags:`, `tag:`, `aliases:`, `alias:`).
4. **Deterministic Classification (`classify_project`)**: Assigns one of three `DetectedProjectType` variants:

| Condition | Classification | Default View | Supported Views |
|---|---|---|---|
| `.obsidian/` found & `code_files_count == 0` (or `<= 1` with `>= 10` `.md` files) | `PureObsidianVault` | `vault-notes` | `["vault-notes", "code"]` |
| `.obsidian/` found & multiple code files | `Mixed` | `code` | `["code", "vault-notes"]` |
| No `.obsidian/`, syntax markers `> 0` & `code_files_count == 0` | `PureObsidianVault` | `vault-notes` | `["vault-notes", "code"]` |
| No `.obsidian/`, syntax markers `> 0` & `code_files_count > 0` (`>= 1` `.md`) | `Mixed` | `code` | `["code", "vault-notes"]` |
| No `.obsidian/`, 0 syntax markers & `code_files_count == 0` with `>= 3` `.md` | `PureObsidianVault` | `vault-notes` | `["vault-notes", "code"]` |
| Otherwise | `PureCode` | `code` | `["code"]` |

{% hint style="info" %}
AetherScope inspects `GET /api/project/status` to return the full `ProjectDetectionReport` (`project_type`, `has_obsidian_dir`, `obsidian_dir_path`, `code_files_count`, `markdown_files_count`, `obsidian_syntax_markers_count`).
{% endhint %}

---

## Markdown Parser & Vault Graph Builder

`scan_obsidian_vault(root)` (`crates/obsidian-vault/src/lib.rs`) reads notes in parallel with `rayon::par_iter()` through `PathGuard` and transforms them via `parse_markdown` and `build_vault_graph`.

### Markdown Syntax Extraction (`parser.rs`)

Before scanning links or tags, `mask_markdown_content` blanks out HTML comments (`<!-- ... -->`), fenced code blocks, and inline code spans while preserving line breaks so `(line, col)` offsets remain exact.

| Construct | Syntax Pattern | Extracted Fields |
|---|---|---|
| YAML Frontmatter | `title`, `tags: [kb, security]`, `aliases: [SysArch]` | Note title, tags, aliases, custom attributes |
| Wikilink / Alias / Heading | <code>&#91;&#91;Folder/TargetNote&#93;&#93;</code>, <code>&#91;&#91;TargetNote&#124;Alias&#93;&#93;</code>, <code>&#91;&#91;TargetNote&#35;Heading&#93;&#93;</code> | `target`, optional `label` and `anchor` |
| Self-Anchor / Block Ref | <code>&#91;&#91;&#35;SelfHeading&#93;&#93;</code>, <code>&#91;&#91;TargetNote&#35;^blockid&#93;&#93;</code> | `is_self_anchor`, `is_block_ref`, `block_id` |
| Media / Note Transclusion | <code>&#33;&#91;&#91;assets/diagram.png&#124;400x300&#93;&#93;</code> | `target`, `is_media`, optional `WxH` dimensions |
| Nested / Unicode Tags | <code>&#35;kb/architecture</code>, <code>&#35;sécurité</code> | `TagOccurrence` (`is_nested()`, `segments()`) |
| Escaped Brackets | `\[\[not-a-link\]\]` | Ignored by parser (not treated as a link) |

- **Title Resolution**: Uses frontmatter `title` first, then the first Markdown `# Heading`, then the filename stem.
- **20 Supported Media Extensions (`TransclusionTarget::MEDIA_EXTENSIONS`)**: `png`, `jpg`, `jpeg`, `gif`, `bmp`, `svg`, `webp`, `ico`, `pdf`, `mp3`, `wav`, `m4a`, `ogg`, `3gp`, `flac`, `mp4`, `webm`, `ogv`, `mov`, `mkv`.
- **Target Resolution Order (`VaultIndex::resolve_target`)**: Self heading (`note::<source_rel>`) → exact path from vault root → relative to source parent folder → shortest-path stem match (tie-broken by folder distance) → frontmatter `aliases`/`title` → attachment filename → unresolved `ghost::<clean>`.

### Note, Attachment & Ghost Bubbles (`graph_builder.rs`)

| Stereotype | Node ID Pattern | `symbol_type` | Color RGBA | Radius & Metadata |
|---|---|---|---|---|
| `«Note»` | `note::<rel_path>` | `note` | Purple `[0.55, 0.36, 0.96, 1.0]` | `((lines.sqrt() * 1.5 + 8.0).clamp(8.0, 32.0))`, boosted by `in_degree.sqrt() * 2.0` up to `48.0`; headings in `metadata.methods`, frontmatter/tags in `metadata.attributes` |
| `«Attachment»` | `attachment::<rel_path>` | `attachment` | Cyan `[0.20, 0.70, 0.85, 1.0]` | Fixed `10.0` (`folder = parent` or `"assets"`) |
| `«GhostNote»` | `ghost::<clean>` | `ghost_note` | Grey `[0.45, 0.45, 0.50, 0.6]` | Fixed `8.0` (`folder = "ghosts"`, `line_number = 0`) |

Edges map wikilinks to `EdgeType::Documents` (`relation: "links_to"`, initial weight `1.0`, `+0.5` per duplicate link) and transclusions to `EdgeType::Render` (`relation: "embeds"`, initial weight `1.5`, `+0.5` per duplicate embed). Nodes are positioned by `core_graph::layout::compute_obsidian_layout` (a mass-aware golden-angle folder galaxy).

---

## Dual-Vision Switching & Mixed-Project Behavior

When a workspace is classified as `Mixed` (for example, a Rust/TypeScript project containing an Obsidian knowledge base in `docs/` or `notes/`):

1. **Parallel Startup Scan**: `execute_project_pipeline` runs `ProjectScanner::scan_project_with_exclusions` and `scan_obsidian_vault` simultaneously via `tokio::join!`, caching both `state.code_graph` and `state.vault_graph`.
2. **Instant `Alt+V` Toggle**: Pressing `Alt+V` (or clicking the **AST** / **Vault** pill in `HeaderDeck.svelte` Zone D or the `Vue` menu) calls `POST /api/view_mode` with `{ "mode": "code" }` or `{ "mode": "vault-notes" }`.
3. **HeaderDeck Mode Indicator**: The `Graph` pill in `HeaderDeck.svelte` shifts between sky-blue (`Orbit` icon) in `code` mode and emerald (`BookOpen` icon) in `vault-notes` mode, displaying a compact `AST` / `Vault` toggle pill whenever `cockpitState.isMixedProject` is `true`.
4. **Live Markdown Hot-Reload**: Editing any `.md` file triggers `FileWatcherBridge` (`100 ms` watcher poll, `30 ms` `desktop-shell` loop, `100 ms` quiet-window debounce / `500 ms` max batch), which re-runs `scan_obsidian_vault`, updates `state.vault_graph`, and pushes a live refresh over SSE (`/api/graph/events`) if `vault-notes` is active.

In standalone HTML exports (`DualGraphBundle`), `Alt+V` and the HeaderDeck pill switch offline between `code` and `vault` without a backend server.

---

## PathGuard / TargetJail & Raw Media Confinement

All vault reads and `/api/raw_file` media streaming pass through `PathGuard` (`TargetJail` type alias in `crates/obsidian-vault/src/confinement.rs`):

- **CWE-22 Traversal Defense**: Rejects `\0` null bytes, URL schemes (`://`), UNC paths (`\\`, `//`), Windows drive letters, absolute paths, `..` parent traversal, path depth `> 32` (`MAX_PATH_DEPTH`), and symlink escapes outside `canonical_root`.
- **Sensitive Path & Size Limits**: Blocks `.env*`, `.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets/`, `credentials/`, private keys/certificates, and files exceeding `10 MB` (`DEFAULT_MAX_FILE_SIZE`).
- **Raw Media Whitelist (`ALLOWED_RAW_EXTENSIONS`)**: `GET /api/raw_file` serves only `png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `markdown`, `txt`, and `csv` with matching `Content-Type` headers so `DocReaderDrawer` can safely preview embedded vault images.

---

## Related Pages

{% content-ref url="./webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](./webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="./integrated-ide.md" %}
[Full-Screen Multi-Tab IDE](./integrated-ide.md)
{% endcontent-ref %}

{% content-ref url="./standalone-viewer.md" %}
[Standalone HTML Viewer & GitHub Pages](./standalone-viewer.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}
