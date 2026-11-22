# Cockpit Spatial WebGL 2

Le cockpit spatial d'AetherScope restitue votre base de code ou votre coffre de connaissances jusqu'à 120 FPS grâce à un pipeline SDF instancié WebGL 2, une surcouche Canvas 2D en 7 passes et un moteur physique Web Worker hors-thread.

---

## Vue d'ensemble de l'architecture

Le moteur de rendu (`AetherEngine` dans `crates/desktop-shell/ui/src/engine/engine.ts`) sépare la géométrie massive des annotations dynamiques via deux canvas superposés et un worker en arrière-plan :

- **Canvas WebGL 2 (`webgl2`)** : Initialisé avec `alpha: false`, `antialias: true`, `powerPreference: 'high-performance'` et `preserveDrawingBuffer: false`. Il dessine le fond galactique procédural (Passe 0) et les bulles SDF instanciées (Passe 1).
- **Canvas de surcouche 2D (`lineCtx`)** : Couche transparente (`alpha: true`) synchronisée sur les mêmes dimensions logiques. Elle trace les décors de disposition, les membranes à 12 lobes, les arêtes routées, les étiquettes, les badges Git, les balises CWE et les orbites laser des agents IA (Passe 2).
- **Physique hors-thread (`PhysicsController` + `physics.worker.js`)** : Calcule l'attraction par ressorts de Hooke, la répulsion de Coulomb/Verlet et les enveloppes de clusters à 12 secteurs en dehors du thread UI.

Le ratio de pixels (`dpr`) est plafonné à `Math.min(window.devicePixelRatio || 1, 2)` et forcé à `1` lorsque `lowMemoryMode` est activé.

---

## Pipeline SDF instancié à 12 flottants

Chaque nœud du graphe est compacté dans un tampon d'instances de 12 flottants (`INSTANCE_FLOATS = 12` dans `shaders.ts`, pas de **48 octets**) et dessiné en un seul appel `gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, nodes.length)`.

### 🎮 Disposition du tampon d'instances

| Location | Offset flottant | Offset octets | Attribut | Sémantique |
|---|---|---|---|---|
| `0` | — | — | `a_quad_pos` (`vec2`) | Quad unitaire par sommet `[-1,-1, 1,-1, -1,1, 1,1]` (`divisor = 0`) |
| `1` | `0..1` | `0` | `a_node_pos` (`vec2`) | Coordonnées monde `(x, y)` |
| `2` | `2` | `8` | `a_radius` (`float`) | Rayon de base multiplié par les facteurs de focus, d'alerte et de LoD |
| `3` | `3..6` | `12` | `a_color` (`vec4`) | Couleur RGBA active (couche, dossier, sévérité ou mode de vision) |
| `4` | `7` | `28` | `a_is_file` (`float`) | `0.0` fonction/méthode, `1.0` fichier, `2.0` classe/struct/trait, `3.0` endpoint/formulaire |
| `5` | `8` | `32` | `a_birth_time` (`float`) | Horodatage (ms) pilotant l'animation d'apparition de 300 ms |
| `6` | `9` | `36` | `a_git_status` (`float`) | `0` propre, `1` modifié, `2` nouveau fichier, `3` violation, `4` doc/texte, `5` nouveau dossier |
| `7` | `10` | `40` | `a_metric0` (`float`) | Complexité/degré normalisé `[0..1]` : `max(cc / 24, (in + out) / 28)` |
| `8` | `11` | `44` | `a_metric1` (`float`) | Chaleur sécurité/focus `[0..1]` : `1.0` alerte, `0.85` focus, `0.5` budget de lignes, `0.0` normal |

### Dézoom infini et mouvement organique

Les bornes de zoom couvrent cinq ordres de grandeur, de `MIN_GALAXY_ZOOM = 0.0001` (`0.01%`) à `MAX_GALAXY_ZOOM = 12.0` (`1200%`). Pour garantir que les nœuds ne disparaissent jamais lorsque vous dézoomez sur de vastes monorepos, le vertex shader (`vsSource` dans `shaders.ts`) impose un rayon minimal à l'écran :

- `zoom_factor = clamp(1.0 / sqrt(clamp(u_zoom, 0.0001, 12.0)), 0.85, 6.0)`
- `min_px = (a_is_file > 0.5) ? 2.6 : 1.8`
- `screen_r = max(min_px, actual_r * u_zoom)`

Chaque nœud dispose également d'une courbe de naissance cubique de 300 ms avec un rebond respiratoire de `0.12`, d'une phase déterministe `v_phase` dérivée de `gl_InstanceID`, et d'une micro-dérive organique de `±1.5` unités monde (`buoy_x`, `buoy_y`).

### Palettes par défaut (`palette.ts`)

| Catégorie | Clés et couleurs hexadécimales par défaut |
|---|---|
| **Couches architecturales** | `ui` `#38bdf8`, `action` `#a855f7`, `domain` `#10b981`, `database` `#f59e0b`, `config` `#64748b`, `utility` `#ec4899`, `docs` `#6366f1`, `default` `#94a3b8` |
| **Sévérités SAST** | `CRITICAL` `#f44336`, `HIGH` `#ff6b00`, `MEDIUM` `#ffc107`, `LOW` `#4caf50` |
| **Budget de contrat** | `CONTRACT_WARNING_COLOR` `#fbbf24` (appliquée lors d'un dépassement `RULE_MAX_LINES`) |
| **Teintes de dossiers (`BRANCH_HUES`)** | Teintes HSL déterministes au LoD ≤ 2 (`desktop-shell: 196`, `core-graph: 255`, `security-linter: 38`, `ast-scanner: 158`, `ai-file-bridge: 178`, `arch-templates: 282`, `aethercraft: 335`, `obsidian-vault: 168`, etc.) |

---

## Surcouche Canvas 2D en 7 passes

Une fois les rendus WebGL 2 terminés, `AetherEngine.render` exécute sept passes séquentielles sur `lineCtx` :

1. **`renderLayoutScenery`** : Dessine les guides d'arrière-plan selon la disposition active — `Z-1` (3 bandes horizontales : UI, Domain, Services/Infra), `Z-2` (cosmos épuré), `Z-3` (4 couloirs DAG verticaux : `INGESTION`, `TRANSFORM`, `SECURITY / TAINT`, `SINK / EXPORT`) et `Z-4` (grille blueprint UML de 48 px).
2. **`renderMembranes`** : Synchronise les enveloppes radiales à 12 lobes (`syncLiveClusterEnvelopes`) et trace les frontières de modules en style `organic_12lobe` (spline quadratique fermée + cortex interne à `0.88 * baseR`), `hex_hull`, `rect_blueprint` ou `none`, ainsi que jusqu'à `42` badges de dossiers (`24` en mode éco) teintés par l'état Git ou sécurité.
3. **`renderEdges`** : Trace jusqu'à `48` arêtes incidentes de focus (avec chevrons directionnels, impulsions et badges `➔ APPEL`, `← APPEL`, `IMPORT`, `EXTENDS`, `MEMBRE`, `DATA`, `NET`, `WS`, `FORM`, `SAST`, `MAX LIGNES`) ainsi que les arêtes d'arrière-plan regroupées par `Path2D` (`900..2600` max) selon le routage `bezier`, `straight` ou `orthogonal_pcb` (45°/90°).
4. **`renderLabels`** : Affiche les noms des nœuds à partir de `zoom >= 0.30` (tronqués à `maxLabelLength`, `18` par défaut), en masquant les libellés dans les clusters denses (`> clusterLabelThreshold`, `20` par défaut).
5. **`renderGitDiffBadges`** : Dessine les anneaux d'état (jusqu'à `64`) et les pilules (jusqu'à `8`/`16`) : `MODIF`, `DOC`, `+FICHIER`, `+DOSSIER`.
6. **`renderSecurityBeacons`** : Trace les anneaux pulsants colorés par sévérité (jusqu'à `260`) et les pilules CWE anti-collision (jusqu'à `14`/`24`/`42`, avec pastille `+N` ou compteur `loc/maxLim L`).
7. **`renderAiAgentOverlay`** : Affiche les agents IA connectés (ping `< 5 min`) avec une `DISTINCT_PALETTE` à 16 couleurs, des traînées de navigation en pointillés, des orbites inclinées en 3D (`TILT_ALPHA = 0.610865`, `INCLINATION_PSI = 0.436332`), des faisceaux laser double passe et des icônes (`✨` Claude, `⚡` Gemini, `🎯` Cursor, `🪐` Antigravity, `🤖` par défaut).

---

## Physique hors-thread et solveur de membranes à 12 lobes

`PhysicsController` (`physics.ts`) délègue l'état du graphe à `physics.worker.js` via un Web Worker ES module (ou via une URL `Blob` en mémoire lorsque `window.__PHYSICS_WORKER_CODE__` est injecté dans les exports HTML autonomes). Pour éviter le coût du clonage structuré sur les grands graphes, `sendGraph` échantillonne au maximum `3000` arêtes par pas régulier.

### 🎮 Protocole de messages du Worker

| Direction | Type de message | Charge utile / Rôle |
|---|---|---|
| Main → Worker | `INIT` | Envoie `{ nodes, edges, depth }` avec les `layouts` précalculés (`obsidian`, `system`, `flow`, `classes`) |
| Main → Worker | `STEP` | Avance d'un pas de simulation selon `{ zoom }` |
| Main → Worker | `WAKE` | Réactive le solveur pour `{ steps }` itérations (`100` par défaut) |
| Main → Worker | `SET_DEPTH` | Change la profondeur cible (`1..4`) et réveille le solveur |
| Main → Worker | `DRAG` / `DRAG_END` | Fixe le nœud déplacé `{ id, x, y }` ou relâche la prise |
| Worker → Main | `UPDATE` | Transfert zero-copy `[positions.buffer]` (`Float32Array`), métadonnées `clusters` (toutes les 12 images) et indicateur `isSleeping` |
| Worker → Main | `IDLE` | Signale que le worker est en veille ou en pause |

### Forces de simulation (`stepWorkerPhysics`)

1. **Attraction de disposition** : Attire chaque nœud vers ses coordonnées dans `n.layouts.{obsidian|system|flow|classes}` (`0.035`/`0.045` à `depth = 1`, `0.18` à `depth > 1`).
2. **Ressorts de Hooke** : Applique les forces élastiques (`restLen = 110` pour `contains`, `185` sinon, raideur `0.012`, bornée `[-4.5, 4.5]`), plafonnées à `2500` arêtes lorsque `nodes.length > 1000`.
3. **Enveloppes de clusters à 12 secteurs** : `computeFolderClusters` suit les ancres lissées `folderAnchors` et calcule des multiplicateurs radiaux lissés en 2 passes dans `[0.82..1.48]`.
4. **Répulsion de Coulomb et Verlet** : À `depth === 1`, applique un écart minimal intra-dossier (`125` classe-classe, `115` impliquant un fichier, `98` classe-fonction, `84` fonction-fonction, `78` autre) ainsi qu'une répulsion inter-clusters (`safeClusterDist = rA + rB + max(220, sqrt(cA + cB) * 34)`). À `depth > 1`, utilise une répulsion globale (`115`/`92`/`76`/`68`).
5. **Amortissement et mise en veille** : Applique une friction de `0.76` (`d = 1`) ou `0.70` (`d > 1`) avec une zone morte `< 0.08`, puis met automatiquement le worker en veille dès que `physicsCooldown <= 0` ou que le graphe est stabilisé.

Appuyez sur `P` ou cliquez sur le bouton Lecture/Pause du canevas pour figer ou relancer `physics.step(...)` à tout moment.

---

## Modes de vision et niveaux de détail (LOD)

Basculez entre quatre filtres analytiques (`VisionModesDeck.svelte`, `VisionModeHuds.svelte` et `engine.ts`) sans relancer d'analyse du projet.

| ID du mode | Libellé UI | Raccourci | Comportement visuel et shader | Surcouche HUD (`VisionModeHuds.svelte`) |
|---|---|---|---|---|
| `standard` | `Cosmos Standard` | `V` | Colore par dossier (`lod <= 2`) ou par couche (`lod 3`) ; alertes en couleur `CRITICAL`/`HIGH` et `RULE_MAX_LINES` en `#fbbf24` (`r × 1.12–1.18`) ; membranes visibles | Canevas épuré + barre LOD `N1..N4` |
| `xray` | `Tunnel X-Ray` | `X` | Isole `activeSymbol` (`#ffffff`) et ses voisins directs à 1 saut (`activeNeighbors`) ; masque les membranes ; atténue le reste (`alpha = 0.07`, `r × 0.55`) | HUD **Tunnel X-Ray** : symbole actif, compteurs `ENTRANTS` / `SORTANTS` / `TOTAL`, bouton **Snapshot** PNG |
| `heatmap` | `Heatmap Complexité` | `H` | Colore chaque nœud selon `cyclomatic_complexity` : `>= 15` `CRITICAL`, `>= 8` `HIGH`, `>= 4` `MEDIUM`, `< 4` `LOW` | HUD **Heatmap Complexité Cyclomatique** : moyenne du projet, nombre de hotspots (`CC >= 10`), top-8 cliquable, bouton **Audit Architecture IA (Hotspots)** |
| `deadcode` | `Code Mort` | `D` | Met en évidence les symboles orphelins (`is_orphan` ou `in_degree === 0 && out_degree === 0`) en rouge `CRITICAL` (`r × 1.35`) ; atténue les nœuds reliés (`alpha = 0.08`, `r × 0.55`) | HUD **Audit Dead Code & Orphelins** : total de symboles morts, LOC économisables, top-12 cliquable, bouton **Générer Prompt Nettoyage IA** |

La barre **LOD / Layout** en bas à gauche (`N1..N4`, raccourcis `1`–`4`) change de topologie spatiale :

- `1` (`N1` / `Z-1`, `lodLevel = 1`) : Architecture & Modules
- `2` (`N2` / `Z-2`, `lodLevel = 2`) : Fichiers & Classes
- `3` (`N3` / `Z-3`, `lodLevel = 3`) : Fonctions & Méthodes
- `4` (`N4` / `Z-4`, `lodLevel = 3`) : Micro-Flux Complet

---

## RadarMinimap, picking et contrôles caméra

### RadarMinimap (`RadarMinimap.svelte`)

Affichez ou masquez la `RadarMinimap` en bas à droite (canevas `130x108` dans un conteneur `w-36 h-36`) avec la touche `R` ou le bouton du pied de page (mémorisé dans `localStorage` sous `aetherscope_show_radar`). Elle se décale automatiquement vers la gauche à l'ouverture du panneau Chat (`420px`) ou Inspecteur (`412px`), et se masque sur mobile (`< 640px`) lorsqu'un tiroir est ouvert.

Toutes les trois images (`requestAnimationFrame`), la minicarte dessine :
- Les anneaux radar cyan concentriques (`r = 32, 58`) et le réticule.
- Tous les nœuds sous forme de carrés `2x2` (`#38bdf8` pour `activeSymbol`, gris ardoise sinon).
- Le rectangle du viewport caméra actif et le niveau de zoom (`zoom.toFixed(2)x`, ou `(zoom * 100).toFixed(2)%` sous `0.01`).
- Les traînées de navigation et balises pulsantes des agents IA actifs (ping `< 5 min`).

Cliquez n'importe où sur le radar pour téléporter `engine.camera.targetX` / `targetY` directement aux coordonnées monde correspondantes.

### Picking, tactile et navigation caméra

- **Lissage caméra** : Interpole `(x, y, zoom)` de manière exponentielle (`1 - Math.exp(-14.0 * dt / 1000)`).
- **Zoom centré sur le curseur** : La molette et `+`/`-` (`Shift` multiplie le pas de zoom de `1.28x`/`0.78x` à `1.85x`/`0.45x`) conservent le point monde sous le pointeur.
- **Cadrage et réinitialisation** : Appuyez sur `F` ou `Ctrl+0` / `Cmd+0` pour cadrer tout le graphe ; appuyez sur `0` pour réinitialiser le zoom à `1.00x`.
- **Picking (`pickNode`)** : Utilise `hitPx = Math.max(13, visualR + 8)` avec un biais de priorité (`0.65` nœud actif, `0.8` fichier/classe, `1.0` autres). Cliquer dans l'espace vide d'une membrane appelle `findFolderAt` et sélectionne le cluster.
- **Glisser et pincement** : Un déplacement `>= 6px` sur un nœud appelle `physics.drag(id, x, y)` ; un glisser sur le fond déplace la caméra ; deux doigts déclenchent le zoom/panoramique tactile ; un double-clic centre la caméra (`targetZoom >= 0.85`).
- **Capture PNG** : Déclenche `captureSnapshot()` pour fusionner `canvas` et `lineCanvas` dans `${projet}_snapshot_${timestamp}.png`.

---

## Watchdog FPS et hot-swap des shaders

Les plugins visuels WebGL 2 compilent de façon atomique via `swapNodeShader` et `swapBackdropShader` (`shaders.ts`) : le nouveau `WebGLProgram` est compilé et lié avant la destruction de l'ancien programme. En cas d'erreur de compilation, l'ancien programme reste actif et `formatGlslError` soustrait `lineOffset` afin que les numéros de ligne correspondent à votre extrait GLSL.

{% hint style="warning" %}
**Watchdog FPS GPU automatique** : Si un shader personnalisé provoque des temps d'image `dt > 40 ms` (`< 25 FPS`) soutenus pendant `2800 ms` sur des graphes de moins de `25 000` nœuds, `AetherEngine` réactive automatiquement les shaders natifs (`null`) et signale l'erreur dans `visualPluginError`. Vous pouvez également plafonner la cadence via `settings.fpsLimit` (`'60'`, `'120'` ou `'unlimited'`).
{% endhint %}

---

## Signaux audio spatiaux WebAudio procéduraux

`playSpatialTone(enabled, kind, panX)` (`crates/desktop-shell/ui/src/lib/sound.ts`) génère des retours sonores procéduraux sans aucun fichier audio externe via `AudioContext` et un `StereoPannerNode` borné à `[-0.9, 0.9]` selon la position horizontale du clic (`(sx / logicalWidth) * 2 - 1`).

| Signal (`kind`) | Forme d'onde | Balayage fréquentiel | Durée | Gain crête | Déclencheurs actifs |
|---|---|---|---|---|---|
| `select` | `triangle` | `440 Hz` → `660 Hz` | `0.11 s` | `0.04` | Clic sur un nœud sain dans `AetherEngine`, `BountyModal`, `SurfaceScannerModal` |
| `alert` | `sawtooth` | `320 Hz` → `190 Hz` | `0.20 s` | `0.03` | Clic sur un nœud portant `has_security_violation` ou `anomalies.length > 0` |
| `success` | `sine` | `523.25` → `659.25` → `783.99 Hz` (Do5–Mi5–Sol5) | `0.24 s` | `0.035` | Téléchargement de capture PNG (`captureSnapshot`), scans `SurfaceScannerModal` |
| `action` | `sine` | `540 Hz` → `420 Hz` | `0.08 s` | `0.028` | Clic sur une membrane de dossier, boutons d'outils du canevas, réactivation audio |
| `hover` | `sine` | `620 Hz` → `760 Hz` | `0.05 s` | `0.014` | Défini dans `sound.ts` (non invoqué par les composants UI actuellement) |

Activez ou coupez le son à tout moment via `cockpitState.toggleSound()` dans `HeaderDeck`, le pied de page du canevas ou `SettingsModal` (sauvegardé dans `localStorage` et `/api/settings`).

---

## Pages associées

{% content-ref url="../plugins/webgl-visual-plugins.md" %}
[Plugins visuels WebGL 2](../plugins/webgl-visual-plugins.md)
{% endcontent-ref %}

{% content-ref url="./integrated-ide.md" %}
[IDE multi-onglets plein écran](./integrated-ide.md)
{% endcontent-ref %}

{% content-ref url="../console/cockpit-shortcuts-and-palette.md" %}
[Raccourcis du cockpit et palette de commandes](../console/cockpit-shortcuts-and-palette.md)
{% endcontent-ref %}

{% content-ref url="../core/graph-engine.md" %}
[Moteur de graphe spatial](../core/graph-engine.md)
{% endcontent-ref %}
