# Coffre Obsidian et moteur Dual-Vision

Le moteur `crates/obsidian-vault` classe chaque espace de travail en dépôt de code, coffre de connaissances ou projet mixte, et vous permet de basculer à chaud (`Alt+V`) entre le graphe AST et la galaxie de notes Obsidian.

---

## Classification du projet en 4 étapes

Au démarrage (`execute_project_pipeline`), AetherScope exécute `detect_project_type(root)` (`crates/obsidian-vault/src/detector.rs`) selon un pipeline déterministe en 4 étapes :

1. **Proximité de `.obsidian/` (`find_obsidian_dir`)** : Recherche `.obsidian` à la racine, dans les sous-dossiers documentaires prioritaires (`docs`, `notes`, `vault`, `doc`, `wiki`, `documentation`, `kb`, `knowledge`), puis via un `WalkDir` borné (`min_depth(1).max_depth(2)`).
2. **Comptage filtré des fichiers** : Parcourt les dossiers non cachés et non ignorés (en excluant `target`, `node_modules`, `.git`, `.obsidian`, `bin`, `obj`, `dist`, `build`, `.turbo`, `.next`, `vendor`, `.cargo`, `.idea`, `.vscode`, `.venv`, `venv`, ainsi que `.min.js`, `.bundle.js`, `.d.ts`, `build.rs`). Compte `code_files_count` sur 28 extensions sources face à `markdown_files_count` (`.md`, `.markdown`) en collectant jusqu'à `max_syntax_sample_files = 10` fichiers.
3. **Échantillonnage syntaxique borné (`sample_syntax_markers`)** : Lit jusqu'à `65 536` octets (`64 Ko`) par fichier Markdown échantillonné et dénombre les liens wiki, transclusions, étiquettes imbriquées `#tag/subtag` (hors titres `#`) et clés YAML (`tags:`, `tag:`, `aliases:`, `alias:`).
4. **Classification déterministe (`classify_project`)** : Attribue l'un des trois types `DetectedProjectType` :

| Condition | Classification | Vue par défaut | Vues supportées |
|---|---|---|---|
| `.obsidian/` trouvé & `code_files_count == 0` (ou `<= 1` avec `>= 10` `.md`) | `PureObsidianVault` | `vault-notes` | `["vault-notes", "code"]` |
| `.obsidian/` trouvé & plusieurs fichiers de code | `Mixed` | `code` | `["code", "vault-notes"]` |
| Sans `.obsidian/`, marqueurs `> 0` & `code_files_count == 0` | `PureObsidianVault` | `vault-notes` | `["vault-notes", "code"]` |
| Sans `.obsidian/`, marqueurs `> 0` & `code_files_count > 0` (`>= 1` `.md`) | `Mixed` | `code` | `["code", "vault-notes"]` |
| Sans `.obsidian/`, 0 marqueur & `code_files_count == 0` avec `>= 3` `.md` | `PureObsidianVault` | `vault-notes` | `["vault-notes", "code"]` |
| Autres cas | `PureCode` | `code` | `["code"]` |

{% hint style="info" %}
Interrogez `GET /api/project/status` pour obtenir le rapport complet `ProjectDetectionReport` (`project_type`, `has_obsidian_dir`, `obsidian_dir_path`, `code_files_count`, `markdown_files_count`, `obsidian_syntax_markers_count`).
{% endhint %}

---

## Analyseur Markdown et construction du graphe

`scan_obsidian_vault(root)` (`crates/obsidian-vault/src/lib.rs`) lit les notes en parallèle via `rayon::par_iter()` et `PathGuard`, puis les transforme avec `parse_markdown` et `build_vault_graph`.

### Extraction de la syntaxe Markdown (`parser.rs`)

Avant d'analyser les liens ou les étiquettes, `mask_markdown_content` remplace les commentaires HTML (`<!-- ... -->`), les blocs de code et le code en ligne par des espaces tout en conservant les sauts de ligne pour préserver les coordonnées `(line, col)`.

| Construct | Motif syntaxique | Champs extraits |
|---|---|---|
| Frontmatter YAML | `title`, `tags: [kb, security]`, `aliases: [SysArch]` | Titre de note, étiquettes, alias, attributs personnalisés |
| Lien wiki / Alias / Titre | <code>&#91;&#91;Folder/TargetNote&#93;&#93;</code>, <code>&#91;&#91;TargetNote&#124;Alias&#93;&#93;</code>, <code>&#91;&#91;TargetNote&#35;Heading&#93;&#93;</code> | `target`, `label` et `anchor` optionnels |
| Ancre locale / Bloc | <code>&#91;&#91;&#35;SelfHeading&#93;&#93;</code>, <code>&#91;&#91;TargetNote&#35;^blockid&#93;&#93;</code> | `is_self_anchor`, `is_block_ref`, `block_id` |
| Transclusion média / note | <code>&#33;&#91;&#91;assets/diagram.png&#124;400x300&#93;&#93;</code> | `target`, `is_media`, dimensions `LxH` optionnelles |
| Étiquettes imbriquées / Unicode | <code>&#35;kb/architecture</code>, <code>&#35;sécurité</code> | `TagOccurrence` (`is_nested()`, `segments()`) |
| Crochets échappés | `\[\[not-a-link\]\]` | Ignorés par l'analyseur (non traités comme liens) |

- **Résolution du titre** : Utilise `title` dans le frontmatter en priorité, puis le premier titre `# Heading`, puis le nom du fichier.
- **20 extensions médias (`TransclusionTarget::MEDIA_EXTENSIONS`)** : `png`, `jpg`, `jpeg`, `gif`, `bmp`, `svg`, `webp`, `ico`, `pdf`, `mp3`, `wav`, `m4a`, `ogg`, `3gp`, `flac`, `mp4`, `webm`, `ogv`, `mov`, `mkv`.
- **Ordre de résolution (`VaultIndex::resolve_target`)** : Ancre locale (`note::<source_rel>`) → chemin exact depuis la racine → chemin relatif au dossier parent → correspondance la plus courte par nom (départagée par distance de dossiers) → `aliases`/`title` du frontmatter → fichier joint → note fantôme `ghost::<clean>`.

### Bulles Note, Attachment et GhostNote (`graph_builder.rs`)

| Stéréotype | Motif d'ID | `symbol_type` | Couleur RGBA | Rayon et métadonnées |
|---|---|---|---|---|
| `«Note»` | `note::<rel_path>` | `note` | Violet `[0.55, 0.36, 0.96, 1.0]` | `((lines.sqrt() * 1.5 + 8.0).clamp(8.0, 32.0))`, amplifié par `in_degree.sqrt() * 2.0` jusqu'à `48.0` ; titres dans `metadata.methods`, attributs/tags dans `metadata.attributes` |
| `«Attachment»` | `attachment::<rel_path>` | `attachment` | Cyan `[0.20, 0.70, 0.85, 1.0]` | Fixe `10.0` (`folder = parent` ou `"assets"`) |
| `«GhostNote»` | `ghost::<clean>` | `ghost_note` | Gris `[0.45, 0.45, 0.50, 0.6]` | Fixe `8.0` (`folder = "ghosts"`, `line_number = 0`) |

Les liens wiki deviennent des arêtes `EdgeType::Documents` (`relation: "links_to"`, poids initial `1.0`, `+0.5` par lien répété) et les transclusions deviennent `EdgeType::Render` (`relation: "embeds"`, poids initial `1.5`, `+0.5` par intégration répétée). Le placement spatial est calculé par `core_graph::layout::compute_obsidian_layout` (galaxie de dossiers à angle d'or pondérée par la masse).

---

## Bascule Dual-Vision et comportement sur projet mixte

Lorsqu'un espace de travail est classé `Mixed` (par exemple un projet Rust/TypeScript contenant une base Obsidian dans `docs/` ou `notes/`) :

1. **Analyse parallèle au démarrage** : `execute_project_pipeline` lance `ProjectScanner::scan_project_with_exclusions` et `scan_obsidian_vault` en parallèle via `tokio::join!`, en mettant en cache `state.code_graph` et `state.vault_graph`.
2. **Bascule instantanée `Alt+V`** : Appuyer sur `Alt+V` (ou cliquer sur la pilule **AST** / **Vault** dans la Zone D de `HeaderDeck.svelte` ou dans le menu `Vue`) appelle `POST /api/view_mode` avec `{ "mode": "code" }` ou `{ "mode": "vault-notes" }`.
3. **Indicateur de mode dans `HeaderDeck`** : Le bouton `Graph` de `HeaderDeck.svelte` passe du bleu ciel (icône `Orbit`) en mode `code` à l'émeraude (icône `BookOpen`) en mode `vault-notes`, et affiche la pilule de bascule `AST` / `Vault` dès que `cockpitState.isMixedProject` vaut `true`.
4. **Rechargement à chaud des notes** : Toute modification d'un fichier `.md` déclenche `FileWatcherBridge` (scrutation `100 ms`, boucle `desktop-shell` `30 ms`, anti-rebond `100 ms` / lot max `500 ms`), qui relance `scan_obsidian_vault`, met à jour `state.vault_graph` et diffuse la mise à jour via SSE (`/api/graph/events`) si la vue `vault-notes` est active.

Dans les exports HTML autonomes (`DualGraphBundle`), `Alt+V` et la pilule de `HeaderDeck` basculent également hors-ligne entre `code` et `vault` sans serveur backend.

---

## Confinement PathGuard / TargetJail et médias bruts

Toutes les lectures du coffre et le streaming média `/api/raw_file` passent par `PathGuard` (alias `TargetJail` dans `crates/obsidian-vault/src/confinement.rs`) :

- **Protection CWE-22** : Rejette les octets nuls (`\0`), schémas d'URL (`://`), chemins UNC (`\\`, `//`), lettres de lecteur Windows, chemins absolus, traversées `..`, profondeurs `> 32` (`MAX_PATH_DEPTH`) et évasions par liens symboliques hors de `canonical_root`.
- **Chemins sensibles et limites de taille** : Bloque `.env*`, `.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets/`, `credentials/`, clés/certificats privés et fichiers dépassant `10 Mo` (`DEFAULT_MAX_FILE_SIZE`).
- **Liste blanche média (`ALLOWED_RAW_EXTENSIONS`)** : `GET /api/raw_file` sert uniquement `png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`, `ico`, `bmp`, `tiff`, `pdf`, `json`, `md`, `markdown`, `txt` et `csv` avec l'en-tête `Content-Type` adapté pour que `DocReaderDrawer` affiche les images intégrées en toute sécurité.

---

## Pages associées

{% content-ref url="./webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](./webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="./integrated-ide.md" %}
[IDE multi-onglets plein écran](./integrated-ide.md)
{% endcontent-ref %}

{% content-ref url="./standalone-viewer.md" %}
[Visionneuse HTML autonome et GitHub Pages](./standalone-viewer.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité et garde-fous](../core/security-confinement.md)
{% endcontent-ref %}
