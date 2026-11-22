# Plugins Visuels WebGL 2

Personnalisez les palettes, membranes, arêtes et shaders GLSL ES 3.00 d'arrière-plan et de nœuds SDF du Cockpit AetherScope via des packs confinés sous `.aether/plugins/visuals/`.

{% hint style="warning" %}
**Implémenté (M1 + M2) vs Feuille de route uniquement (M3)** :
- **Implémenté** : Palettes déclaratives, styles d'overlay, 5 packs intégrés, VBO d'instances SDF à 12 floats, hooks GLSL ES 3.00 `backdrop.glsl` (`aetherBackdrop`) & `node_sdf.glsl` (`aetherNodeSurface`), double validateur anti-DoS Rust + TS, hot-swap atomique, watchdog FPS, Studio WebGL dans `PluginsModal` et rechargement à chaud `.glsl`.
- **Feuille de route uniquement (NON implémenté dans le code)** : DSL d'expressions `VisionLens` (`vision_lenses`), passe FBO hors-écran `postprocess.glsl`, bloc YAML `physics` (notez que `membrane_breath_amp` se trouve actuellement sous `overlay`, pas sous `physics`), et outil MCP de génération de thèmes (`docs/WEBGL_VISUAL_PLUGINS_SPEC.md`).
{% endhint %}

## Structure d'un pack et découverte

Placez vos packs visuels personnalisés dans `.aether/plugins/visuals/<pack-slug>/` :

```text
.aether/plugins/visuals/my-theme/
├── visual-plugin.yaml        # Accepte aussi visual-plugin.yml ou visual-plugin.json
├── backdrop.glsl             # Hook GLSL ES 3.00 optionnel : aetherBackdrop(...)
└── node_sdf.glsl             # Hook GLSL ES 3.00 optionnel : aetherNodeSurface(...)
```

`visual_plugin_routes.rs` analyse `visual-plugin.yaml`, `visual-plugin.yml` ou `visual-plugin.json` via `serde_yaml` (avec repli `serde_json`), valide chaque fichier `.glsl` référencé via `read_confined_glsl` et expose l'inventaire sur `GET /api/visual_plugins`. `PluginEngine` ignore `visuals/` et `visual-plugin.*` afin que les packs visuels n'interfèrent jamais avec l'analyse SAST.

## Schéma du manifeste (`VisualPluginManifest`)

### 📝 Champs principaux et sous-configurations

| Section / Champ | Type | Défaut | Description |
|---|---|---|---|
| `schema_version` | `u32` | `1` | Version du schéma de manifeste. |
| `id` | `string` | Requis | Slug unique du pack (`<= 64` caractères, confiné via `sanitize_plugin_slug`). |
| `name` | `string` | Requis | Nom affiché dans le Studio WebGL et le menu de l'en-tête. |
| `version` | `string` | `"1.0.0"` | Chaîne Semver. |
| `author` / `description` | `string` | `None` | Métadonnées optionnelles. |
| `enabled` | `bool` | `true` | Active ou désactive le pack dans l'inventaire. |
| `palette.background` | `string[]` | `[]` | Jusqu'à 4 couleurs hex `#RGB`/`#RRGGBB` mappées sur `u_theme_colors[0..3]`. |
| `palette.layers` | `map<string, string>` | `{}` | Surcharges pour `ui`, `action`, `domain`, `database`, `config`, `utility`, `docs`, `default`. |
| `palette.severities` | `map<string, string>` | `{}` | Surcharges pour `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `palette.contract_warning` | `string` | `None` | Surcharge de la couleur d'avertissement de contrat `RULE_MAX_LINES` (défaut `#fbbf24`). |
| `overlay.membrane_style` | `string` | `None` | `organic_12lobe`, `hex_hull`, `rect_blueprint` ou `none`. |
| `overlay.edge_style` | `string` | `None` | `bezier`, `straight` ou `orthogonal_pcb`. |
| `overlay.edge_pulse_speed` | `f32` | `None` | Multiplicateur de vitesse d'impulsion sur les arêtes Canvas 2D. |
| `overlay.membrane_breath_amp` | `f32` | `None` | Amplitude de respiration des membranes (`0.0` désactive l'effet). |
| `overlay.label_font` | `string` | `None` | Surcharge optionnelle de police pour les étiquettes Canvas 2D. |
| `shaders.backdrop` | `string` | `None` | Nom de fichier `.glsl` relatif dans le pack (ex. `"backdrop.glsl"`). |
| `shaders.node_sdf` | `string` | `None` | Nom de fichier `.glsl` relatif dans le pack (ex. `"node_sdf.glsl"`). |
| `shaders.uniforms` | `map<string, f32>` | `{}` | Compactés dans `u_params` (`grid_scale`, `glow_sharpness`, `star_density`, `nebula_speed`, défaut `1.0` chacun). |

## Les 5 packs intégrés

Bien que `docs/WEBGL_VISUAL_PLUGINS_SPEC.md` mentionne 3 packs dans son résumé M1, le registre frontend (`BUILTIN_VISUAL_PLUGINS` dans `crates/desktop-shell/ui/src/engine/visualPlugins.ts`) embarque **5 packs intégrés**, disponibles en mode Live comme en mode démo hors-ligne :

| `id` du pack | Nom affiché | `membrane_style` | `edge_style` | `u_theme_colors[0..3]` | `u_params` (`grid, glow, stars, speed`) | GLSL custom |
|---|---|---|---|---|---|---|
| `obsidian-nebula` | `Obsidian Nebula (Natif)` | `organic_12lobe` | `bezier` | `#04050b`, `#0b304f`, `#2e104d`, `#3d1030` | `1.0, 1.0, 1.0, 1.0` | Shaders natifs (`null`) |
| `cyber-pcb` | `Cyber-PCB Neon Blueprint` | `hex_hull` | `orthogonal_pcb` | `#03080e`, `#083344`, `#06b6d4`, `#22d3ee` | `1.0, 1.4, 0.0, 1.2` | Backdrop + node SDF custom |
| `architect-blueprint` | `CAD Architect Blueprint` | `rect_blueprint` | `straight` | `#071a33`, `#154273`, `#60a5fa`, `#bae6fd` | `1.0, 1.2, 0.0, 0.6` | Backdrop + node SDF custom |
| `deep-biolum` | `Abyssal Bioluminescence` | `organic_12lobe` | `bezier` | `#020c14`, `#062a3a`, `#0ea5e9`, `#2dd4bf` | `1.0, 1.0, 0.5, 1.0` | Backdrop + node SDF custom |
| `matrix-phosphor` | `Phosphor CRT Oscilloscope` | `hex_hull` | `orthogonal_pcb` | `#020904`, `#0b3b1c`, `#10b981`, `#4ade80` | `1.0, 1.3, 0.0, 1.2` | Backdrop + node SDF custom |

Le thème actif par défaut est `obsidian-nebula` ; supprimer un pack personnalisé actif via `POST /api/visual_plugins/delete` rebascule automatiquement vers `obsidian-nebula`.

## Contrats de hooks GLSL ES 3.00

AetherScope gère `#version 300 es`, la caméra, le plancher de taille subpixel (`1.8px–2.6px` minimum) et `void main()`. Vos fichiers `.glsl` fournissent uniquement les fonctions contractuelles.

### 🎮 `backdrop.glsl` (`aetherBackdrop`)

```glsl
vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec)
```

Uniforms et fonctions utilitaires fournis par l'hôte dans `backdrop.glsl` :
- `u_resolution` (`vec2` taille du drawingBuffer), `u_camera_pos` (`vec2`), `u_zoom` (`float`), `u_time` (`float` en ms ; `timeSec = u_time * 0.001`)
- `u_theme_colors[4]` (`vec3[4]` issus de `palette.background`)
- `u_params` (`vec4` : `x = grid_scale`, `y = glow_sharpness`, `z = star_density`, `w = nebula_speed`)
- `float aetherHash21(vec2 p)` et `float aetherNoise2(vec2 p)`

### 🎮 `node_sdf.glsl` (`aetherNodeSurface` & `NodeCtx`)

```glsl
void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha)
```

Chaque champ de `NodeCtx` est rempli par `NODE_HOST_FOOTER` à partir du tampon d'instances WebGL 2 à 12 floats (`shaders.ts`) :

```glsl
struct NodeCtx {
  vec2 uv;          // Coordonnées locales du quad dans [-1.0, 1.0]
  float r;          // length(v_uv) ; l'hôte rejette si r > 1.0
  float angle;      // atan(v_uv.y, v_uv.x)
  vec4 color;       // RGBA résolu (mode de vision / couche / sévérité)
  float kind;       // 0.0=Func/Method, 1.0=File, 2.0=Class/Struct, 3.0=Endpoint/Form
  float time;       // v_time * 0.001 (secondes)
  float phase;      // Phase déterministe par instance dans [0, 2*PI)
  float gitStatus;  // 0=clean, 1=modif, 2=new_file, 3=violation, 4=text/doc, 5=new_folder
  float metric0;    // [0..1] max(cyclomatic_complexity/24.0, (in_degree+out_degree)/28.0)
  float metric1;    // [0..1] 1.0=alerte sécurité, 0.85=focus/survol, 0.5=lines_exceeded, 0.0=normal
};
```

{% hint style="info" %}
**Halos Git diff et sécurité immuables** : `NODE_HOST_FOOTER` superpose systématiquement l'anneau d'état (`r = 0.86`) et le halo externe par-dessus le rendu de `aetherNodeSurface` dès que `v_git_status > 0.5` (`1.0` ambre modifié, `2.0` vert nouveau fichier, `3.0` rouge violation sécurité, `4.0` cyan doc, `5.0` violet nouveau dossier), ainsi que le fondu d'apparition de 300 ms. Aucun shader custom ne peut masquer ces indicateurs critiques.
{% endhint %}

## Validateur GLSL anti-DoS, Swap atomique et Watchdog FPS

Pour éviter tout blocage du pilote GPU (TDR) et déni de service par shader, chaque hook subit une validation statique identique côté backend Rust (`validate_glsl_hook` dans `visual_plugin_routes.rs`) et frontend TypeScript (`validateGlslHookClient` dans `visualPlugins.ts`) :

| Règle de garde | Limite / Comportement |
|---|---|
| Taille maximale | `32 Ko` (`32 768` octets) par fichier `.glsl`. |
| Octet nul | Rejette tout caractère `\0`. |
| Suppression des commentaires | Retire `//...` et `/*...*/` avant les vérifications structurelles. |
| Directives interdites | Rejette `#version`, `#extension` et `#pragma` (gérés par l'en-tête hôte). |
| Boucles non bornées | Rejette `while (` et `do {` (insensible à la casse). |
| Boucles `for` bornées | Chaque `for (init; cond; step)` doit contenir 3 segments séparés par `;`, une condition non vide, et tout littéral numérique de `cond` doit être `<= 128`. |
| Symbole contractuel | Le code doit définir `aetherBackdrop` (`backdrop.glsl`) ou `aetherNodeSurface` (`node_sdf.glsl`). |

### Swap atomique et ré-indexation des lignes d'erreur

Dans `shaders.ts`, `swapBackdropShader` et `swapNodeShader` compilent et lient un nouveau `WebGLProgram` **avant** de détruire le programme actif. En cas d'échec de compilation, l'ancien shader reste actif sans coupure et `formatGlslError` soustrait le `lineOffset` de l'en-tête hôte aux erreurs `ERROR: col:line:` afin d'afficher le numéro de ligne exact de votre extrait.

### Watchdog FPS

Dans `AetherEngine` (`crates/desktop-shell/ui/src/engine/engine.ts`), lorsqu'un shader backdrop ou node personnalisé est actif et que `nodes.length < 25000`, les images dépassant `40 ms` (`< 25 FPS`) s'accumulent dans `slowShaderMs`. Si cette lenteur persiste `>= 2800 ms` (`2,8 s`), `AetherEngine` rebascule automatiquement les deux shaders sur `null` (natifs) et affiche `visualPluginError` dans l'interface.

## Studio WebGL (`PluginsModal`), Rechargement à chaud et API REST

Ouvrez `PluginsModal` (`G`) puis l'onglet **Studio WebGL** (`visuals`) pour :
- Activer l'un des 5 packs intégrés ou un pack personnalisé, importer/exporter des packs `.json`, ou cliquer sur **Reset Natif** (`obsidian-nebula`).
- Ajuster les 4 sélecteurs de fond (`u_theme_colors[0..3]`), `membrane_style`, `edge_style`, les surcharges optionnelles des 7 couches et 4 sévérités, et les 4 curseurs d'uniforms (`grid_scale`, `glow_sharpness`, `star_density`, `nebula_speed`).
- Éditer `backdrop.glsl` et `node_sdf.glsl` à partir des modèles intégrés, tester instantanément sur GPU (**Tester en direct (Hot-Swap)** sans écriture disque), ou enregistrer dans `.aether/plugins/visuals/<id>/` via `POST /api/visual_plugins/upsert`.

Toute modification sous `.aether/plugins/visuals/` ou d'un fichier `.glsl` déclenche `FileWatcherBridge` (scrutation `100 ms`, boucle `desktop-shell` `30 ms`, anti-rebond `100 ms` / lot max `500 ms`) pour incrémenter `visual_plugins_version` sans relancer d'analyse AST/SAST.

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-security-plugins.md" %}
[API REST : Paramètres, Bounty, Surface & Plugins](../api-mcp/rest-api-security-plugins.md)
{% endcontent-ref %}
