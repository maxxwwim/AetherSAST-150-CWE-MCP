# Lanceurs, installeurs et workflows CI/CD

AetherScope inclut des lanceurs batch Windows, des scripts PowerShell d'installation et de déploiement ainsi que des workflows GitHub Actions pour automatiser le démarrage local, l'enregistrement MCP, la publication WebGL autonome et les contrôles SARIF en CI.

{% hint style="info" %}
La version canonique du workspace dans `Cargo.toml`, `mcp.json` et `ui/package.json` est `2.6.0`. Plusieurs bannières batch/PowerShell ainsi que la clé de cache binaire GitHub Actions affichent encore d'anciens libellés `V2.4` ou `v2.5.1` issus de versions précédentes.
{% endhint %}

---

## Centre de contrôle interactif (`AetherScope-Launcher.bat`)

`AetherScope-Launcher.bat` est un menu Windows interactif à 9 options (`chcp 65001`) qui localise les binaires, libère le port `3030`, synchronise les exécutables et démarre chaque mode d'AetherScope.

### Résolution des binaires et `:SYNC_BINARIES`

Avant de lancer les modes GUI ou headless, le script recherche `aether-engine.exe` (quitte avec le code `1` s'il est introuvable), `aetherscope-mcp.exe` et `aether-mc-runner.exe` selon un ordre de priorité strict :

1. `%SCRIPT_DIR%target\release\`
2. `%REPO_DIR%target\release\` (répertoire dépôt de repli)
3. `%SCRIPT_DIR%`
4. `%REPO_DIR%`
5. `%LOCALAPPDATA%\AetherScope\bin\`

Pour les options `[1]` et `[3]`, `:SYNC_BINARIES` arrête `aether-engine.exe`, tue tout PID `LISTENING` sur le port `3030` via `netstat -aon`, copie les binaires à jour dans `%LOCALAPPDATA%\AetherScope\bin\` si ce dossier existe, puis copie `aether-engine.exe` dans `%SCRIPT_DIR%` lorsqu'il s'exécute depuis un dépôt source (`Cargo.toml` présent).

### Options du menu (`[1]`–`[9]`)

Appuyer simplement sur **Entrée** sélectionne l'option `[1]` par défaut.

| Option | Action du menu | Commande / comportement sous-jacent |
|---|---|---|
| `[1]` (défaut) | Lancer le Cockpit Spatial | Exécute `:SYNC_BINARIES`, démarre `aether-engine.exe` (`http://127.0.0.1:3030`), patiente 2 s et quitte avec `0`. |
| `[2]` | Tester le serveur MCP stdio | Exécute `"%MCP_EXE%" --port 3030` de manière interactive dans la console (`Ctrl+C` pour arrêter). |
| `[3]` | Lancer le serveur headless | Exécute `:SYNC_BINARIES` et maintient `"%ENGINE_EXE%" --no-gui` bloquant dans la console (`http://127.0.0.1:3030`). |
| `[4]` | Configurer les clients IA | Exécute `powershell -NoProfile -ExecutionPolicy Bypass -File setup-mcp.ps1`. |
| `[5]` | Scanner et synchroniser un projet (SAST) | Demande `SCAN_PATH` (`. ` par défaut), exécute `"%ENGINE_EXE%" --path "%SCAN_PATH%" --audit-only` et génère `.aether\LIVE_AUDIT.md`. |
| `[6]` | Lancer le Cockpit Minecraft AetherCraft | Ouvre `http://127.0.0.1:5000` et exécute `python apps\aethercraft\control-plane\app.py`. |
| `[7]` | Libérer le port `3030` | Tue de force `aether-engine.exe`, `aetherscope-mcp.exe` et tout PID en écoute sur `:3030`. |
| `[8]` | Installer / mettre à jour sous Windows | Exécute `powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1`. |
| `[9]` | Quitter | Ferme le lanceur proprement avec le code `0`. |

---

## Lancement en un clic (`Start-Cockpit.bat`)

`Start-Cockpit.bat` fournit un raccourci non interactif pour ouvrir immédiatement le Cockpit desktop sans afficher le menu du lanceur.

- Résout `aether-engine.exe` et `aetherscope-mcp.exe` selon le même ordre de priorité à 5 niveaux que `AetherScope-Launcher.bat`.
- Arrête de force `aether-engine.exe` et tout PID en écoute sur le port `3030`, synchronise les binaires vers `%LOCALAPPDATA%\AetherScope\bin\` et `%SCRIPT_DIR%`, lance `"%ENGINE_EXE%"` puis quitte avec `0`.

{% hint style="warning" %}
Contrairement à l'option `[7]` d'`AetherScope-Launcher.bat`, `Start-Cockpit.bat` ne tue **pas** les processus `aetherscope-mcp.exe` : vos sessions MCP stdio ouvertes dans votre IDE restent ainsi actives lors du redémarrage du Cockpit.
{% endhint %}

---

## Installeur Windows (`install.ps1`)

`install.ps1` installe les binaires compilés d'AetherScope, les ajoute à votre variable `PATH` utilisateur Windows, crée un raccourci Bureau et enregistre le serveur MCP auprès des clients IA détectés.

### 🎮 Signature

```powershell
.\install.ps1 [-InstallDir <String>] [-SkipMcp] [-SkipShortcut]
```

### 📝 Paramètres

| Paramètre | Type | Défaut | Description |
|---|---|---|---|
| `-InstallDir` | `String` | `$env:LOCALAPPDATA\AetherScope` | Dossier racine d'installation (`bin\` contient les exécutables ; la racine contient les scripts). |
| `-SkipMcp` | `Switch` | `$false` | Ignore l'exécution automatique de `setup-mcp.ps1` en fin d'installation. |
| `-SkipShortcut` | `Switch` | `$false` | Ignore la création du raccourci `AetherScope V2.lnk` sur le Bureau Windows. |

### Arborescence installée et effets de bord

- **Binaires copiés dans `$InstallDir\bin\`** : `aether-engine.exe` (obligatoire ; quitte avec `1` s'il est absent de `target\release` et du répertoire du script), `aetherscope-mcp.exe` (protégé par `try/catch` si un IDE le verrouille), `aether-mc-runner.exe` et `aether-plugin-tool.exe`.
- **Scripts copiés dans `$InstallDir\`** : `AetherScope-Launcher.bat`, `Start-Cockpit.bat` et `setup-mcp.ps1`.
- **`PATH` utilisateur et raccourci** : Ajoute `$InstallDir\bin` à la variable d'environnement `User` `PATH` si absent, et crée `Bureau\AetherScope V2.lnk` ciblant `Start-Cockpit.bat` (ou `aether-engine.exe` en secours).

### 💡 Exemples

{% tabs %}
{% tab title="Installation standard" %}
{% code title="Installer binaires, PATH, raccourci Bureau et configurations MCP" overflow="wrap" %}
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```
{% endcode %}
{% endtab %}

{% tab title="Dossier personnalisé (sans raccourci)" %}
{% code title="Installer dans D:\Tools\AetherScope sans raccourci Bureau ni configuration MCP" overflow="wrap" %}
```powershell
.\install.ps1 -InstallDir "D:\Tools\AetherScope" -SkipShortcut -SkipMcp
```
{% endcode %}
{% endtab %}
{% endtabs %}

---

## Configurateur MCP automatique (`setup-mcp.ps1`)

`setup-mcp.ps1` localise `aetherscope-mcp.exe` (dans le dossier du script, `target\release` ou `%LOCALAPPDATA%\AetherScope\bin`) et crée ou met à jour l'entrée `mcpServers.aetherscope` en UTF-8 dans les clients IA pris en charge.

### 🎮 Signature

```powershell
.\setup-mcp.ps1 [-Port <String>]
```

### 📝 Fichiers de configuration ciblés

| Client IA | Chemin JSON ciblé |
|---|---|
| **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Antigravity / Gemini CLI** | `%USERPROFILE%\.gemini\config\mcp_config.json` |
| **Cursor** | `%USERPROFILE%\.cursor\mcp.json` |

### 💡 Bloc JSON généré

{% code title="Entrée mcpServers.aetherscope injectée" overflow="wrap" %}
```json
{
  "mcpServers": {
    "aetherscope": {
      "command": "C:\\Users\\<User>\\AppData\\Local\\AetherScope\\bin\\aetherscope-mcp.exe",
      "args": ["--port", "3030"]
    }
  }
}
```
{% endcode %}

---

## Déploiement GitHub Pages autonome (`deploy-gh-pages.ps1`)

`deploy-gh-pages.ps1` compile le frontend Svelte 5, exporte le graphe autonome du dépôt dans `docs/index.html` et publie la démo statique sur la branche `gh-pages` :

1. Exécute `npm run build` dans `crates/desktop-shell/ui` pour produire `crates/desktop-shell/dist/`.
2. Exécute `cargo test -p desktop-shell --bin aether-engine viewer::tests::test_export_docs_index_html`, qui scanne le dépôt et embarque `window.__AETHERSCOPE_DATA__` et `window.__AETHERSCOPE_DUAL_GRAPH__` dans `docs/index.html`.
3. Copie `crates/desktop-shell/dist/*` dans `%TEMP%\aether-gh-pages`, remplace `index.html` par `docs/index.html`, ajoute un fichier `.nojekyll` vide, initialise un dépôt Git temporaire et pousse de force sur `gh-pages`.

{% hint style="danger" %}
`deploy-gh-pages.ps1` exécute `git push origin gh-pages --force` depuis un commit temporaire vers le dépôt distant codé en dur (`https://github.com/maxxwwim/AetherSAST-150-CWE-MCP.git`). Vérifiez l'URL du remote avant toute exécution sur un fork.
{% endhint %}

---

## Workflows GitHub Actions (`.github/workflows/`)

Les deux workflows GitHub Actions fournis utilisent actuellement uniquement le déclencheur manuel `on: workflow_dispatch:`, les déclencheurs automatiques `push`, `pull_request` et `schedule` étant commentés afin d'éviter des exécutions CI non souhaitées.

{% tabs %}
{% tab title="aetherscope-sarif.yml (Porte CI SAST)" %}
S'exécute sur `ubuntu-24.04` avec les permissions `contents: read` et `security-events: write` :

1. Récupère le dépôt avec `fetch-depth: 0`.
2. Restaure ou compile `~/.cargo/bin/aether-engine` via `cargo install --path crates/desktop-shell --bin aether-engine --locked` (la clé de cache utilise `${{ runner.os }}-aether-engine-v2.5.1`).
3. Exécute la porte SAST :
   `aether-engine --path . --audit-only --format sarif --output results.sarif --fail-on HIGH`
4. Envoie `results.sarif` (`if: always()`) vers GitHub Code Scanning via `github/codeql-action/upload-sarif@v3` (`category: aetherscope-sast`).
{% endtab %}

{% tab title="deploy-pages.yml (Build GitHub Pages)" %}
Exécute un pipeline en deux jobs sur `ubuntu-latest` avec `contents: read`, `pages: write` et `id-token: write` :

1. **Job `build`** : Récupère le dépôt, configure Node.js `22` avec cache npm, exécute `npm ci` et `npm run build` dans `crates/desktop-shell/ui`, crée `crates/desktop-shell/dist/.nojekyll` et publie l'artefact via `actions/upload-pages-artifact@v3`.
2. **Job `deploy`** : Déploie l'artefact vers l'environnement `github-pages` via `actions/deploy-pages@v4`.
{% endtab %}
{% endtabs %}

---

## Pages connexes

{% content-ref url="aether-engine-cli.md" %}
[CLI aether-engine](aether-engine-cli.md)
{% endcontent-ref %}

{% content-ref url="plugin-and-mcp-clis.md" %}
[CLI Plugins, MCP et Runner](plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="../getting-started/installation.md" %}
[Installation](../getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/standalone-viewer.md" %}
[Visionneuse HTML autonome et GitHub Pages](../cockpit-ide/standalone-viewer.md)
{% endcontent-ref %}
