# Démarrage rapide

Lancez `aether-engine` en mode Cockpit Desktop, navigateur headless, audit CLI SAST/SARIF/SCA ou serveur MCP, puis explorez l'interface WebGL 2.

{% tabs %}
{% tab title="GUI Desktop" %}

### 1. Ouvrir le Cockpit Desktop

Depuis la racine de n'importe quel dépôt, démarrez la fenêtre native `tao`/`wry` :

```powershell
aether-engine -p .
```

Sous Windows, vous disposez également de deux lanceurs batch fournis :

* **`Start-Cockpit.bat`** : Sélectionne le binaire `aether-engine.exe` le plus récent (`target\release\` -> dossier courant -> `%LOCALAPPDATA%\AetherScope\bin\`), libère le port `3030`, synchronise les binaires et ouvre la fenêtre GUI.
* **`AetherScope-Launcher.bat`** : Menu interactif à 9 choix couvrant le Cockpit GUI (`[1]`), le test MCP stdio (`[2]`), le serveur `--no-gui` (`[3]`), `setup-mcp.ps1` (`[4]`), le scan SAST `--audit-only` (`[5]`), le panneau Flask AetherCraft sur le port `5000` (`[6]`), la libération du port `3030` (`[7]`), `install.ps1` (`[8]`) et la sortie (`[9]`).

{% endtab %}
{% tab title="Headless + Navigateur" %}

### 1. Démarrer le serveur HTTP headless

Lancez le serveur Axum (`127.0.0.1:3030`) et `FileWatcherBridge` sans ouvrir de fenêtre native :

```bash
aether-engine --no-gui --port 3030 --path .
```

Ouvrez ensuite `http://127.0.0.1:3030` dans votre navigateur. `LocalGuard` restreint l'accès aux hôtes loopback (`127.0.0.1`, `localhost`, `[::1]`).

{% endtab %}
{% tab title="Audit CLI, SARIF et SCA" %}

### 1. Exécuter des commandes d'audit et de benchmark

```bash
# Générer .aether/LIVE_AUDIT.md (et actualiser un Cockpit actif sur le port 3030)
aether-engine --path . --audit-only

# Exporter un rapport SARIF v2.1.0 et faire échouer la CI dès HIGH ou CRITICAL
aether-engine --path . --audit-only --format sarif -o results.sarif --fail-on HIGH

# Combiner SAST + SCA atteignable OSV.dev (ou mode hors ligne sur cache local)
aether-engine --path . --audit-only --sca
aether-engine --path . --audit-only --offline-sca
aether-engine --path . --sca-only --offline-sca --fail-on CRITICAL

# Filtrer les packs/profils de plugins ou décompacter les 24 règles Semgrep
aether-engine --path . --audit-only --plugins auto
aether-engine --path . --update-rules

# Mesurer le débit d'analyse et la RAM max -> génère BENCHMARK.md
aether-engine --path . --benchmark
```

{% hint style="warning" %}
**Attention à la redirection stdout sous Windows :** `aether-engine.exe` est compilé avec `#![windows_subsystem = "windows"]` et se rattache à la console parente via `AttachConsole(0xFFFF_FFFF)`. Dans un sous-shell non interactif ou redirigé, la sortie stdout (comme `--help`) peut sembler vide bien que la commande réussisse. Utilisez `-o results.sarif` ou consultez `.aether/LIVE_AUDIT.md` / `BENCHMARK.md` pour une sortie déterministe.
{% endhint %}

{% endtab %}
{% tab title="MCP (Agents IA)" %}

### 1. Connecter un agent IA et suivre le workflow en 3 appels

Configurez votre client IA avec `setup-mcp.ps1` (ou lancez `aetherscope-mcp --port 3030 --path .` / `aether-engine --mcp`). Si le port `3030` n'écoute pas encore, `aetherscope-mcp` démarre automatiquement `aether-engine --no-gui`.

Appliquez le workflow chirurgical en 3 appels défini dans `AETHER_AI_RULES.md` :

1. **Inspecter l'état global (`aetherscope_get_graph_summary`)** :
   ```json
   { "rescan": true, "include_tasks": true, "severity": "all" }
   ```
2. **Verrouiller une cible (`aetherscope_get_active_target`)** pour générer `.aether/ACTIVE_TARGET.md` et recevoir `<aether_handshake version="2.1">` :
   ```json
   { "symbol_id": "<id_symbole_cible>", "trace_direction": "both", "action": "Inspection" }
   ```
3. **Certifier chaque modification (`aetherscope_verify_patch`)** via le pare-feu `<50ms` `PatchVerifier` :
   ```json
   {
     "files_modified": ["crates/core-graph/src/layout.rs"],
     "task_id": "fix-layout-edge",
     "status": "done",
     "progress": 100
   }
   ```

{% endtab %}
{% endtabs %}

## Raccourcis essentiels de navigation du Cockpit

Une fois le Cockpit WebGL 2 ouvert, utilisez ces raccourcis clavier vérifiés (`App.svelte`, `HeaderDeck.svelte`, `VisionModesDeck.svelte`) :

| Raccourci | Action |
|---|---|
| `Alt+1` | Basculer vers la vue **Graphe** (AST Code ou Coffre Obsidian) |
| `Alt+2` / `Alt+3` | Basculer vers l'**IDE multi-onglets plein écran** |
| `Alt+V` | Alterner entre **AST Code** et **Coffre Obsidian** sur les projets `Mixed` |
| `1` / `2` / `3` / `4` | Choisir la disposition spatiale : `Z-1` Galaxie Fichiers, `Z-2` Modules 7 couches, `Z-3` DAG d'exécution, `Z-4` Matrice UML |
| `V` / `X` / `H` / `D` | Choisir le mode de vision : **Standard** (`V`), **Focus X-Ray** (`X`), **Heatmap complexité** (`H`), **Code mort** (`D`) |
| `Ctrl+K` / `Cmd+K` | Ouvrir la **Palette de commandes** et activer la recherche Omnibox du HeaderDeck |
| `F` / `0` / `+` / `-` | Ajuster la caméra (`F`), réinitialiser le zoom (`0` / `Ctrl+0`), zoomer (`+`/`=`), dézoomer (`-`/`_`) |
| `P` / `R` | Mettre en pause/reprendre la physique (`P`), afficher/masquer le Radar Minimap (`R`) |
| `G` / `I` / `C` / `N` | Ouvrir **Plugins & Studio WebGL** (`G`), **Inspecteur** (`I`), **Chat IA** (`C`), **Créer un fichier** (`N`) |
| `S` / `B` / `U` / `M` | Ouvrir **Paramètres** (`S`), **Bug Bounty** (`B`), **Scanner de surface** (`U`), **Lecteur de docs** (`M`) |

## Étapes suivantes

{% content-ref url="configuration.md" %}
[Configuration](configuration.md)
{% endcontent-ref %}

{% content-ref url="best-practices.md" %}
[Conseils en or](best-practices.md)
{% endcontent-ref %}

{% content-ref url="../console/aether-engine-cli.md" %}
[Référence CLI aether-engine](../console/aether-engine-cli.md)
{% endcontent-ref %}
