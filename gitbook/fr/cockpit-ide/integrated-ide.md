# IDE multi-onglets plein écran

AetherScope intègre un éditeur de code multi-onglets (`IdeView.svelte`) couplé directement au graphe de symboles AST, à l'inspecteur de remédiation CWE et au moteur de gouvernance BLAKE3.

---

## DOM résident et bascule instantanée

Dans `crates/desktop-shell/ui/src/App.svelte`, le canevas WebGL 2 (`AetherCanvas`) et `<IdeView />` restent montés simultanément dans le DOM et basculent par CSS (`class:hidden={cockpitState.viewMode !== 'ide'}`). Passer du graphe spatial à l'IDE ne démonte jamais l'éditeur : vos onglets ouverts, positions de curseur et tampons non enregistrés sont intégralement préservés.

### 🎮 Raccourcis de vue et de tiroirs

| Raccourci | Action | Notes |
|---|---|---|
| `Alt+1` | Basculer vers la vue Graphe adaptative (`code` ou `vault-notes`) | Restaure `lastGraphMode` |
| `Alt+2` / `Alt+3` | Basculer vers l'IDE plein écran | Envoie `POST /api/view_mode` (`{ mode: "ide" }`) |
| `Alt+V` | Basculer `code` ↔ `vault-notes` | Actif uniquement sur les projets `Mixed` |
| `N` | Ouvrir/fermer `CreateFileModal` | Créer ou importer un fichier dans le graphe |
| `M` | Ouvrir/fermer `DocReaderDrawer` (`Docs & EARS`) | S'ancre à droite en mode IDE |
| `I` | Ouvrir/fermer `InspectorDrawer` | Ouvre l'inspecteur de symboles et CWE à 5 onglets |

Les raccourcis globaux à une touche sont désactivés lorsque le focus se trouve dans un `<input>`, `<textarea>`, `<select>` ou élément `contentEditable`. Cliquer sur un symbole dans le graphe WebGL (`selectSymbol`) précharge `file_path` et `line_number` dans `CockpitState` (`ideActiveFile`, `ideTargetLine`, `ideTargetTick`), si bien qu'appuyer sur `Alt+2` saute immédiatement sur sa déclaration.

Vous pouvez également basculer de vue depuis les pilules de la **Zone D** (`Graph` | `AST`/`Vault` | `IDE`) ou le menu `Vue` de `HeaderDeck.svelte`.

---

## Espace à 3 volets redimensionnables et mode Zen

`IdeView.svelte` organise l'interface en trois volets ajustables :

1. **Barre latérale gauche (`<aside>`)** : Largeur par défaut `320px` (redimensionnable de `180px` à `45%` de la fenêtre ; un double-clic sur le séparateur réinitialise à `320px`), rétractable en rail d'icônes de `42px`. Quatre modes disponibles :
   - `Fichiers` (`IdeFileTree`)
   - `Symboles` (`IdeSymbolHierarchy`)
   - `Docs & EARS` (`IdeDocSidebar`)
   - `Double` (`split`, par défaut) : vue scindée verticale `IdeFileTree` + `IdeSymbolHierarchy` avec séparateur horizontal (`splitRatio = 50%`, borné `15%`–`85%`, double-clic pour réinitialiser).
2. **Éditeur central (`<main>`)** : `<IdeEditor />` occupant tout l'espace horizontal restant.
3. **Volet droit Docs & EARS ancré** : Affiché lorsque `cockpitState.isDocPanelOpen && !cockpitState.ideZenMode`. Rend `<DocReaderDrawer embedded={true} />` sur `520px` par défaut (`320px` à `60vw` ; `wideMode` passe à `760px` ; double-clic réinitialise à `520px`).

Activer le **Mode Zen** (`ideZenMode` via le bouton `Plein Écran` / `Restaurer` de l'éditeur) masque les deux barres latérales pour laisser `<IdeEditor />` occuper tout l'écran.

---

## Éditeur multi-onglets, raccourcis et coloration syntaxique

`IdeEditor.svelte` gère un dictionnaire en mémoire `buffers: Record<string, FileBuffer>` conservant `{ content, savedContent, cursorLine, cursorCol }` pour chaque fichier ouvert.

- **Chargement non masqué** : L'ouverture d'un fichier appelle `GET /api/file_content?path=<rel>&raw=true` afin que `SecretMasker` n'altère pas le code éditable en mémoire (les fichiers sensibles tels que `.env` ou les clés privées restent bloqués par `SecretGuard`).
- **Suivi des modifications non enregistrées** : Chaque onglet suit `content !== savedContent`, affichant un point ambre sur les onglets modifiés, un bouton `Enregistrer` ambre pulsant et `● Modifications non enregistrées` dans la barre d'état.
- **Gestion des onglets** : Alternez la largeur des onglets entre `'auto'` (`max-w-[210px]`), `'compact'` (`130px`) et `'expanded'` (`320px`), fermez un onglet ou cliquez sur `Tout fermer`.
- **Saut à la ligne et surbrillance** : Lorsque `ideTargetTick` / `ideTargetLine` change, l'éditeur borne la ligne dans `[1, lineCount]`, défile vers `(safeLine - 5) * 21` px en mode Édition (ou via `scrollIntoView({ behavior: 'smooth', block: 'center' })` en mode Coloré) et déclenche un flash bleu ciel de `2500 ms` sur la ligne cible.
- **Modes Édition et Aperçu coloré** : Basculez entre `Éditer` (`<textarea>` interactive avec gouttière synchronisée) et `Coloré` (coloration syntaxique via `tokenizeCodeLine` pour `rust`, `typescript`, `javascript`, `python`, `json`, `toml`, `markdown`, `svelte` et `text`).

### 🎮 Raccourcis clavier de l'éditeur

| Raccourci | Comportement |
|---|---|
| `Ctrl+S` / `Cmd+S` | Enregistre le tampon actif de façon atomique via `POST /api/save_file` et affiche `Enregistré sur disque` pendant 3 s |
| `Ctrl+F` / `Cmd+F` | Ouvre la recherche insensible à la casse dans le fichier (`Enter` suivant, `Shift+Enter` précédent, `Escape` fermer) |
| `Tab` | Insère 4 espaces (`'    '`) à la sélection courante et met à jour le curseur |

---

## Arborescence, hiérarchie de symboles et barre Docs

### `IdeFileTree.svelte`

- **Source en direct et repli hors-ligne** : Interroge `GET /api/files` lorsque le serveur local est connecté, et se replie sur `fallbackFromGraph()` (reconstitution depuis `cockpitState.graph.nodes`) en mode autonome/hors-ligne.
- **Couleurs déterministes par branche (`palette.ts`)** : `getFolderColor` attribue des teintes HSL cohérentes via `BRANCH_HUES` (`desktop-shell: 196°`, `core-graph: 255°`, `security-linter: 38°`, `ast-scanner: 158°`, `ai-file-bridge: 178°`, `arch-templates: 282°`, `aethercraft: 335°`, `obsidian-vault: 168°`, etc.) avec décalage subtil pour les sous-dossiers.
- **Agrégation d'anomalies et filtrage** : Les fichiers portant des vulnérabilités CWE/CVE affichent un point d'alerte `#ef4444` et agrègent les compteurs `ShieldAlert` jusqu'aux dossiers parents. Saisir un texte dans `searchFilter` filtre sans sensibilité à la casse et déplie automatiquement les dossiers correspondants.

### `IdeSymbolHierarchy.svelte` et `IdeDocSidebar.svelte`

- **`IdeSymbolHierarchy.svelte`** : Liste les symboles AST du fichier actif triés par `line_number`, avec badges de type (`Function`, `Struct`, `Endpoint`, `Contract`, `Method`, `Symbol`), badges CWE et `methods` imbriquées. Cliquer sur un symbole positionne l'éditeur, notifie `POST /api/ai/target` (`action_type: 'IDE Navigation'`) et centre la caméra WebGL.
- **`IdeDocSidebar.svelte`** : Affiche la carte **Contrat Cible Active** (badge `BLAKE3 Scellé / Modifié`, budget `{loc} / {max_lines_limit || 300} L`, bouton `Inspecter`), la liste des documents Markdown du projet (README en tête avec icône cadenas BLAKE3) et un bouton `Blueprint`.

---

## Création de fichiers IA et import local

Appuyez sur `N` (ou utilisez `Fichier -> Nouveau fichier IA` / `Importer un fichier…`) pour ouvrir `CreateFileModal.svelte` :

- **Import de fichier local** : Lit un fichier local via `<input type="file">` (`file.text()`) et conserve son chemin relatif (ou le préfixe par `imported/`).
- **4 modèles architecturaux rapides** : `+ UI` (`src/ui/panel_widget.ts`), `+ Domain` (`src/domain/model_entity.rs`), `+ Service` (`src/services/service_handler.rs`) et `+ Doc` (`docs/SPECIFICATION.md`).
- **Synchronisation immédiate** : La validation appelle `POST /api/ai/create_file`, met à jour `cockpitState.setGraph(res.graph)`, incrémente `filterVersion`, recadre la caméra et sélectionne le nouveau symbole.

---

## InspectorDrawer et DocReaderDrawer : remédiation CWE et scellement de contrats

### `InspectorDrawer.svelte` (Raccourci `I`)

Largeur par défaut `396px` (redimensionnable `280px`–`70vw`), offrant une barre d'actions rapides (`Ouvrir dans l'IDE`, `Doc / Source`, `Prompt IA`) et **5 onglets** :

| Onglet | Capacités |
|---|---|
| `Débrief` | Badge de contrat EARS et BLAKE3 (`file_blake3_hash`), docstrings AST extraites, alertes sécurité vs dépassement de lignes et scellement de budget en 1 clic |
| `UML` | `classDiagram` Mermaid copiable et Mini-DAG SVG interactif |
| `Flux` | Arêtes entrantes et sortantes filtrables par relation |
| `CVE` | Filtres par portée (`Cible`/`Projet`), texte et langage (`ALL`, `Rust`, `Solidity`, `TS/JS`, `Python`, `C#`, `Zig`), affichant `transmitted_data`, **`🛡️ remediation`**, `Préparer PoC` (`BountyModal`) et `Ignorer` (`POST /api/settings`) |
| `Tâches` | Tâches du projet associées au symbole actif |

**Scellement du budget de lignes en 1 clic** : Dans `Débrief`, sélectionnez un préréglage (`200`, `300`, `500`, `800`, `1500`) ou une limite personnalisée (`10..50000`) et cliquez sur `📄 Sceller Fichier` (`file_max_lines`), `📁 Sceller Dossier` (`max_lines_per_file`) ou `↺ Hériter` (`clear_file_override: true`) via `POST /api/contracts/update`.

### `DocReaderDrawer.svelte` (Raccourci `M`)

Ancré à droite en mode IDE (ou flottant à gauche en vue Graphe), `DocReaderDrawer` fournit :

- **Signature globale BLAKE3 en 1 clic** : Le bouton `Signer` appelle `POST /api/contracts/sign` pour parcourir tous les contrats `README.md` et sceller leurs empreintes BLAKE3 dans `aether.lock.toml`.
- **Scellement de budget** : Mêmes contrôles en 1 clic (préréglages `200`, `300`, `500`, `800`, `1500`, `3000`) via `POST /api/contracts/update`.
- **Édition Markdown et sauvegarde automatique (1,5 s)** : Toute modification déclenche `POST /api/save_doc` après un délai de `1500 ms`. Enregistrer un `README.md` re-signe automatiquement son empreinte BLAKE3 dans `aether.lock.toml` et relance `ProjectScanner`.

---

## Endpoints REST backend pour l'IDE et les contrats

Toutes les routes ci-dessous s'exécutent sur `127.0.0.1:3030` derrière `LocalGuard` (vérification `Host`/`Origin`/`Sec-Fetch-Site`), `PathGuard` (confinement CWE-22), `SecretGuard` (blocage de `.env*`, `.ssh`, `.git`, clés privées) et `SecretMasker::contains_secret`.

| Endpoint | Comportement et garanties de sécurité |
|---|---|
| `GET /api/files` | Parcourt `project_root` via `WalkDir` en excluant `.git`, `node_modules`, `target`, `dist`, `.aether`, `.gemini` et les chemins secrets |
| `GET /api/file_content?path=<rel>&raw=<bool>` | Lit jusqu'à `10 Mo` (`DEFAULT_MAX_FILE_SIZE`) avec 20 tentatives sur verrous Windows ; masque les secrets sauf si `raw=true` |
| `POST /api/save_file` | Sérialisé par `file_save_lock` ; écrit un fichier temporaire voisin `.{filename}.tmp.{pid}_{seq}_{nanos}` puis exécute un `fs::rename` atomique avec 20 réessais exponentiels |
| `POST /api/save_doc` | Écrit le Markdown en sécurité ; s'il s'agit d'un `README.md`, re-signe BLAKE3 et rafraîchit le graphe automatiquement |
| `POST /api/ai/create_file` | Bloque les chemins sensibles et secrets intégrés (`SecretMasker::contains_secret`), écrit le fichier et retourne l'`AetherGraph` mis à jour |
| `POST /api/contracts/sign` | Recalcule et signe les empreintes BLAKE3 des `README.md` dans `aether.lock.toml`, puis réanalyse le workspace |
| `POST /api/contracts/update` | Met à jour `max_lines_per_file`, `file_max_lines`, `allowed_imports` ou `forbidden_imports` dans le `README.md` le plus proche, re-signe BLAKE3 et réanalyse |

Les traversées invalides (`..`, lettres de lecteur, chemins UNC, profondeur `> 32`) retournent `400 Bad Request` ; les fuites de secrets ou évasions hors racine retournent `403 Forbidden` ; les fichiers dépassant `10 Mo` retournent `413 Payload Too Large`.

---

## Pages associées

{% content-ref url="./webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](./webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../core/blake3-governance.md" %}
[Cryptographie BLAKE3 et gouvernance EARS](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité et garde-fous](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[API REST : IDE, Contrats et IA](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}
