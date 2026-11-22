# Raccourcis du Cockpit, palette de commandes et assistants UI

Le Cockpit WebGL 2 et l'IDE intégré d'AetherScope mettent à disposition des raccourcis clavier, une Omnibox `Ctrl+K`, des contrôles souris/tactiles et des assistants pour agents IA afin de naviguer sans quitter le clavier.

{% hint style="info" %}
Les raccourcis globaux à touche unique, avec `Alt` ou `Ctrl+0` dans `App.svelte` sont automatiquement désactivés lorsque le focus se trouve dans un élément `<input>`, `<textarea>`, `<select>` ou `contentEditable`. Les raccourcis à touche unique exigent également l'absence de `Ctrl`, `Meta` et `Alt`.
{% endhint %}

---

## Omnibox et palette de commandes (`Ctrl+K` / `Cmd+K`)

La combinaison `Ctrl+K` (ou `Cmd+K` sur macOS) ouvre les interfaces de recherche rapide d'AetherScope sur les nœuds, les flux d'appels et les fichiers :

- **Omnibox d'en-tête et `SearchDropdownPanel` (`z-[70]`)** : Donne le focus au champ de recherche supérieur et ouvre un panneau portail à 4 onglets (`Tout`, `Fonctions & Symboles`, `Appels & Flux`, `Fichiers & Dossiers`) affichant jusqu'à **60** résultats classés par pertinence. Prend en charge `ArrowDown`, `ArrowUp`, `Enter` (sélectionne le symbole/dossier, centre la caméra et ouvre `InspectorDrawer`) et `Escape`.
- **Palette rapide de symboles `CommandPalette` (`z-50`)** : Filtre `graph.nodes` par `name` ou `file_path` (15 nœuds à vide, jusqu'à 20 correspondances filtrées) et se ferme par clic sur l'arrière-plan, bouton de fermeture ou `Escape`.

{% hint style="warning" %}
`HeaderDeck.svelte` et `CommandPalette.svelte` écoutent tous deux `Ctrl+K` / `Cmd+K` (`e.key === 'k'`). Comme `SearchDropdownPanel` s'affiche dans un portail `z-[70]` au-dessus de `CommandPalette` (`z-50`), il prend la priorité visuelle. De plus, `CommandPalette` ne lie que `Escape` et le clic souris : utilisez l'Omnibox d'en-tête (`SearchDropdownPanel`) pour naviguer au clavier avec `ArrowUp`/`ArrowDown`/`Enter`.
{% endhint %}

---

## Raccourcis globaux du Cockpit

### Changement de vue et Dual-Vision

| Raccourci | Condition | Action |
|---|---|---|
| `Alt+1` | Hors champs de saisie | Bascule vers la vue Graphe Spatial (AST Code ou coffre Obsidian selon le projet). |
| `Alt+2` / `Alt+3` | Hors champs de saisie | Bascule vers l'IDE multi-onglets plein écran (`IdeView`). |
| `Alt+V` | `isMixedProject == true` | Alterne entre les vues Code AST et Notes Obsidian dans les projets Dual-Vision. |

### Caméra et zoom

| Raccourci | Condition | Action |
|---|---|---|
| `Ctrl+0` / `Cmd+0` | Hors champs de saisie | Recadre la caméra sur l'ensemble du graphe (`requestCameraFit`). |
| `F` | Sans modificateur, hors saisie | Recadre la caméra sur le graphe actif. |
| `+` / `=` / `NumpadAdd` | Sans modificateur, hors saisie | Zoome avant (`1.28×`). |
| `-` / `_` / `NumpadSubtract` | Sans modificateur, hors saisie | Zoome arrière (`0.78×`). |
| `0` / `Numpad0` | Sans modificateur, hors saisie | Réinitialise le zoom à `1.0` (`100%`). |

### Continuum spatial LoD (`Z-1`..`Z-4`) et modes de vision

| Raccourci | Catégorie | Action |
|---|---|---|
| `1` | Disposition spatiale | Active `Z-1` (Galaxie Fichiers, `lodLevel = 1`). |
| `2` | Disposition spatiale | Active `Z-2` (Architecture Modules, `lodLevel = 2`). |
| `3` | Disposition spatiale | Active `Z-3` (Flux DAG d'exécution, `lodLevel = 3`). |
| `4` | Disposition spatiale | Active `Z-4` (Matrice UML & Classes ; conserve le `lodLevel` courant, contrairement au menu `Vue` qui fixe `lodLevel = 3`). |
| `V` | Mode de vision | Active le mode de vision `standard`. |
| `X` | Mode de vision | Active/désactive le mode de vision `xray`. |
| `H` | Mode de vision | Active/désactive le mode `heatmap` (chaleur CWE/complexité). |
| `D` | Mode de vision | Active/désactive le mode `deadcode`. |

### Moteur, tiroirs et fenêtres modales

| Raccourci | Portée | Action |
|---|---|---|
| `P` | Physique | Met en pause ou reprend la simulation de forces du Web Worker. |
| `R` | Minimap | Affiche ou masque la `RadarMinimap` en bas à droite (ignoré dans `<input>`/`<textarea>`). |
| `I` | Tiroir | Ouvre ou ferme le tiroir latéral `InspectorDrawer`. |
| `M` | Panneau | Ouvre ou ferme le panneau Documentation, EARS et BLAKE3. |
| `N` | Modale | Ouvre ou ferme `CreateFileModal` (nouveau fichier assisté par IA). |
| `S` | Modale | Ouvre ou ferme `SettingsModal`. |
| `B` | Modale | Ouvre ou ferme `BountyModal` (workflow Bug Bounty en 4 étapes). |
| `G` | Modale | Ouvre ou ferme `PluginsModal` (plugins SAST et visuels GLSL). |
| `U` | Modale | Ouvre ou ferme `SurfaceScannerModal` (scanner de surface d'attaque réseau). |
| `C` | Tiroir | Lié à la fois dans `App.svelte` et `AiChatDrawer.svelte` (voir l'avertissement ci-dessous). |

{% hint style="warning" %}
`App.svelte` et le composant permanent `AiChatDrawer.svelte` attachent chacun un écouteur `window` sur la touche `C`, ce qui inverse `isChatOpen` deux fois lors d'une même pression. Utilisez plutôt le bouton **Chat IA** dans la barre d'accès rapide supérieure ou la pastille flottante pour ouvrir ou fermer le tiroir IA de façon fiable.
{% endhint %}

---

## Menus d'en-tête et barre d'accès rapide

`HeaderDeck.svelte` propose sept menus de style bureau (`Fichier`, `Vue`, `Affichage`, `Sécurité`, `Plugins`, `IA`, `Outils`) ainsi qu'une barre d'accès rapide :

- **Navigation dans les menus** : Cliquer ouvre un menu ; survoler les menus voisins bascule immédiatement tant qu'un menu est ouvert, `Escape` ou un clic extérieur le ferme, et les entrées `keepOpen` (niveaux LoD, modes de vision, `P`, `R`, mode Éco, WebAudio) restent ouvertes pour enchaîner les réglages.
- **Analyseur chemin/URL intégré** : Saisir un chemin local dans la barre du menu `Fichier` lance un scan AST/SAST, tandis qu'une cible `http://`, `https://`, `localhost` ou IP ouvre automatiquement `SurfaceScannerModal`.
- **Barre d'accès rapide** : Bascule entre Graphe / Coffre / IDE, affiche les compteurs de nœuds et d'arêtes en direct, et offre un accès en 1 clic à Recadrer (`F`), Physique (`P`), Violations CWE, Plugins (`G`), Chat IA (`C`), Inspecteur (`I`), Audio Mute/Unmute et Paramètres (`S`).

---

## Contrôles souris et tactiles du canevas WebGL et du Radar

| Interaction | Composant | Comportement |
|---|---|---|
| `Molette` / `Shift+Molette` | `AetherCanvas` | Zoom centré sur le curseur de `0.0001` (`0.01%`) à `12.0` (`1200%`). Maintenir `Shift` double presque la vitesse de zoom (`0.0042` contre `0.0022`). |
| Boutons `+` / `-` (`Shift+Clic`) | `AetherCanvas` | Un clic normal zoome de `1.28×` / `0.78×` ; `Shift+Clic` applique un zoom rapide `1.85×` / `0.45×`. |
| Glisser sur nœud vs vide | `AetherCanvas` | Glisser une bulle la déplace dans le moteur physique ; glisser dans le vide déplace la caméra. |
| Clic / Double-clic | `AetherCanvas` | Un clic sélectionne un symbole ou dossier avec retour WebAudio spatialisé ; un double-clic focalise le symbole ou le centroïde du dossier et ouvre le panneau Doc. |
| Tactile à deux doigts | `AetherCanvas` | Pincement pour zoomer et déplacement panoramique à deux doigts. |
| Clic sur le Radar | `RadarMinimap` | Téléporte instantanément `engine.camera` vers la coordonnée cliquée sur la minimap 130×108. |

---

## Raccourcis de l'IDE intégré et des panneaux

### Raccourcis de `IdeEditor.svelte`

| Raccourci | Contexte | Action |
|---|---|---|
| `Ctrl+S` / `Cmd+S` | Zone d'édition | Enregistre atomiquement le fichier actif via `POST /api/save_file`. |
| `Ctrl+F` / `Cmd+F` | Zone d'édition | Ouvre et donne le focus à la barre de recherche interne au fichier. |
| `Tab` | Zone d'édition | Insère 4 espaces (`'    '`) à la position du curseur. |
| `Enter` / `Shift+Enter` / `Escape` | Barre de recherche | Passe à l'occurrence suivante, précédente, ou ferme la recherche et rend le focus à l'éditeur. |
| `Enter` | Barre d'onglets | Active l'onglet focalisé. |

### Navigation arborescente, dataflow et hiérarchie

Appuyer sur `Enter` ou `Space` active les éléments interactifs dans `IdeFileTree` (ouvre le fichier), `IdeSymbolHierarchy` (saute au symbole/méthode), `StepCodeDataPanel` (saute au nœud SSA amont/aval), `InspectorDrawer` (saute au symbole source/cible) et `SynthesisHud` (déplie/replie les accordéons Modules/Couches/Liens).

---

## Modales et boutons CLI du tiroir Chat IA

- **Fermeture des modales** : `Escape` ferme `BountyModal`, `CreateFileModal`, `IgnoredCweModal`, `PluginsModal`, `ProjectHubModal`, `PromptGeneratorModal`, `SettingsModal`, `SurfaceScannerModal` et `TasksModal` (remarque : `McpControlModal` se ferme via son bouton `×`).
- **Touches de soumission** : `Enter` (sans `Shift`) envoie un message dans `AiChatDrawer` ; `Enter` lance également un scan dans `SurfaceScannerModal` et sélectionne une tâche dans `TasksModal`.
- **Boutons assistants `Agents & MCP` (`Gemini CLI`, `Claude Code`, `Config MCP`)** : Dans l'onglet `Agents & MCP` d'`AiChatDrawer`, `Config MCP` ouvre `McpControlModal`, tandis que `Gemini CLI` et `Claude Code` appellent `launchAgentCli(tool)` :

{% code title="Requêtes envoyées par les boutons Gemini CLI et Claude Code" overflow="wrap" %}
```json
// 1. POST /api/ai/launch_cli
{
  "tool": "gemini",
  "project_path": "<chemin_projet_actif>",
  "prompt": "Analyse <symbole_ou_dossier_actif> dans AetherScope (<project_path>) via MCP aetherscope_get_active_target."
}

// 2. POST /api/ai/telemetry (met à jour la caméra 3D et le badge d'essaim)
{
  "target": "<symbole_ou_dossier_actif>",
  "agent_name": "Agent GEMINI",
  "status": "Session CLI lancée sur <symbole_ou_dossier_actif>"
}
```
{% endcode %}

{% hint style="info" %}
`POST /api/ai/launch_cli` fonctionne selon le modèle zéro-shell d'AetherScope : il enregistre la télémétrie et renvoie `{ "status": "ok", "message": "Terminal CLI <tool> initialisé", ... }` sans lancer de processus terminal OS externe.
{% endhint %}

---

## Pages connexes

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[Cockpit spatial WebGL 2](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/integrated-ide.md" %}
[IDE multi-onglets plein écran](../cockpit-ide/integrated-ide.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/obsidian-dual-vision.md" %}
[Coffre Obsidian et moteur Dual-Vision](../cockpit-ide/obsidian-dual-vision.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[API REST : IDE, Contrats, IA, Chat et Tâches](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}
