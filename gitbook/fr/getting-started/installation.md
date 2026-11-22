# Installation

Installez `aether-engine` (`2.6.0`) depuis l'archive Windows précompilée, compilez depuis les sources avec Cargo et npm, puis configurez vos clients MCP.

## Prérequis système

| Prérequis | Utilité | Détails |
|---|---|---|
| **Rust 1.80+ (édition 2021)** | Compilation depuis les sources (`cargo build` / `cargo install`) | Déclaré dans le `Cargo.toml` racine (`edition = "2021"`). |
| **Outils de compilation C++** | Compilation native Rust | MSVC Build Tools sous Windows ; `build-essential` sous Linux. |
| **Node.js et npm** | Recompilation de l'interface Svelte 5 / Vite 8 | Requis uniquement si vous modifiez `crates/desktop-shell/ui/`. Le fichier `crates/desktop-shell/dist/index.html` est déjà compilé et embarqué. |
| **WebView2 Runtime** | Mode GUI Desktop sous Windows | Préinstallé sur Windows 10/11 (`tao 0.28` + `wry 0.42`). |
| **Python 3 + Java 21+** | Extension AetherCraft uniquement | Dépendances Python `flask>=3.0.0`, `requests>=2.31.0` pour le `control-plane` ; Java 21+ dans le `PATH` pour `aether-mc-runner`. |

{% tabs %}
{% tab title="Archive précompilée (Windows x64)" %}

## Option 1 : Release Windows précompilée (`v2.6.0`)

Extrayez `releases/aetherscope-v2.6.0-windows-x64.zip` dans un dossier dédié.

<details>
<summary>Contenu vérifié de <code>releases/aetherscope-v2.6.0-windows-x64.zip</code></summary>

* Binaires : `aether-engine.exe`, `aetherscope-mcp.exe`, `aether-plugin-tool.exe`
* Scripts et manifestes : `install.ps1`, `setup-mcp.ps1`, `Start-Cockpit.bat`, `AetherScope-Launcher.bat`, `mcp.json`
* Visionneuse autonome : `index.html`
* Documentation : `README.md`, `README.fr.md`, `CHANGELOG.md`, `CWE_CATALOG.md`, `AETHER_AI_RULES.md`, `BENCHMARK.md`

</details>

{% hint style="info" %}
`aether-mc-runner.exe` n'est **pas** inclus dans `aetherscope-v2.6.0-windows-x64.zip`. Compilez-le séparément avec `--manifest-path apps/aethercraft/runner/Cargo.toml` si vous utilisez AetherCraft.
{% endhint %}

### Exécuter `install.ps1`

Depuis le dossier extrait (ou la racine du dépôt après `cargo build --release`), exécutez `install.ps1` pour installer les binaires dans `%LOCALAPPDATA%\AetherScope\bin`, mettre à jour votre `PATH` utilisateur, créer le raccourci Bureau (`AetherScope V2.lnk`) et enregistrer vos clients MCP :

```powershell
# Installation par défaut (%LOCALAPPDATA%\AetherScope, PATH, raccourci et MCP)
.\install.ps1

# Dossier personnalisé sans configuration MCP ni raccourci Bureau
.\install.ps1 -InstallDir "C:\Tools\AetherScope" -SkipMcp -SkipShortcut
```

| Paramètre | Valeur par défaut | Comportement |
|---|---|---|
| `-InstallDir` | `"$env:LOCALAPPDATA\AetherScope"` | Dossier cible (`bin\` reçoit les exécutables ; la racine reçoit les `.bat` et `setup-mcp.ps1`). |
| `-SkipMcp` | `$false` | Ignore l'exécution automatique de `setup-mcp.ps1`. |
| `-SkipShortcut` | `$false` | Ignore la création de `AetherScope V2.lnk` sur le Bureau. |

`install.ps1` recherche d'abord les binaires dans `target\release\` puis dans le dossier du script. Il arrête tout processus `aether-engine` actif, copie `aether-engine.exe`, `aetherscope-mcp.exe`, `aether-mc-runner.exe` et `aether-plugin-tool.exe` (s'ils existent), puis ajoute `<InstallDir>\bin` à votre `PATH` utilisateur.

{% endtab %}
{% tab title="Compilation source (Cargo et npm)" %}

## Option 2 : Compiler depuis les sources (Windows / Linux / macOS)

### 1. Recompiler l'interface Frontend (optionnel)

Nécessaire uniquement si vous modifiez des fichiers dans `crates/desktop-shell/ui/` :

```bash
cd crates/desktop-shell/ui
npm ci
npm run build
cd ../../..
```

`npm run build` génère le bundle HTML autonome dans `crates/desktop-shell/dist/index.html`, embarqué ensuite dans le binaire Rust par `viewer.rs` via `include_str!`.

### 2. Compiler les binaires du workspace Rust

```bash
# Compiler aether-engine, aetherscope-mcp et aether-plugin-tool en mode release
cargo build --release

# Ou compiler uniquement l'outil CLI de plugins
cargo build --release -p security-linter --bin aether-plugin-tool
```

### 3. Installer directement dans le `PATH` Cargo

```bash
cargo install --path crates/desktop-shell --bin aether-engine --locked
cargo install --path crates/desktop-shell --bin aetherscope-mcp --locked
cargo install --path crates/security-linter --bin aether-plugin-tool --locked
```

### 4. Compiler le runner AetherCraft (optionnel)

Comme `apps/aethercraft/runner` est exclu du workspace Cargo principal, passez explicitement `--manifest-path` :

```bash
cargo build --release --manifest-path apps/aethercraft/runner/Cargo.toml
```

{% endtab %}
{% endtabs %}

## Configurer les clients IA avec `setup-mcp.ps1`

`setup-mcp.ps1` localise `aetherscope-mcp.exe` (dossier du script, `target\release\`, puis `%LOCALAPPDATA%\AetherScope\bin\`) et enregistre `mcpServers.aetherscope` dans vos clients IA compatibles :

```powershell
# Enregistrer le serveur MCP sur le port 3030 par défaut
.\setup-mcp.ps1

# Enregistrer le serveur MCP sur un port loopback personnalisé
.\setup-mcp.ps1 -Port 3040
```

Le script met à jour (ou crée si nécessaire) ces trois fichiers de configuration :

* **Claude Desktop :** `%APPDATA%\Claude\claude_desktop_config.json`
* **Antigravity / Gemini :** `%USERPROFILE%\.gemini\config\mcp_config.json`
* **Cursor :** `%USERPROFILE%\.cursor\mcp.json`

{% code title="Entrée mcpServers générée" overflow="wrap" %}
```json
{
  "mcpServers": {
    "aetherscope": {
      "command": "C:\\Users\\<vous>\\AppData\\Local\\AetherScope\\bin\\aetherscope-mcp.exe",
      "args": ["--port", "3030"]
    }
  }
}
```
{% endcode %}

{% hint style="warning" %}
**Note sur les bannières héritées des scripts :** Bien que `Cargo.toml`, `ui/package.json`, `mcp.json` et l'archive `v2.6.0` affichent tous la version canonique **`2.6.0`**, les scripts (`install.ps1`, `setup-mcp.ps1`, `Start-Cockpit.bat`, `AetherScope-Launcher.bat`) et `mcp_main.rs` impriment encore `V2.4` dans leurs bannières console, et `.github/workflows/aetherscope-sarif.yml` utilise la clé de cache `aether-engine-v2.5.1`. Il s'agit uniquement d'un libellé cosmétique sans impact sur l'exécution `2.6.0`.
{% endhint %}

## Étapes suivantes

{% content-ref url="quickstart.md" %}
[Démarrage rapide](quickstart.md)
{% endcontent-ref %}

{% content-ref url="configuration.md" %}
[Configuration](configuration.md)
{% endcontent-ref %}
