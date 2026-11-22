# CLI Plugins, MCP et Runner

En complément de `aether-engine`, le dépôt fournit trois binaires Rust spécialisés pour la gestion des plugins SAST, l'orchestration MCP stdio autonome et le provisionnement supervisé de serveurs Minecraft.

---

## Vue d'ensemble des binaires compagnons

| Binaire | Crate / Manifeste | Version | Invocation | Rôle principal |
|---|---|---|---|---|
| `aether-plugin-tool` | `crates/security-linter` | `2.6.0` | `cargo run -p security-linter --bin aether-plugin-tool -- <CMD>` | Créer, importer, tester, lister, exporter et exécuter des plugins SAST YAML/JSON. |
| `aetherscope-mcp` | `crates/desktop-shell` | `2.6.0` | `cargo run -p desktop-shell --bin aetherscope-mcp -- [OPTIONS]` | Pont MCP stdio JSON-RPC 2.0 dédié avec démarrage automatique du backend. |
| `aether-mc-runner` | `apps/aethercraft/runner` | `1.0.0` | `cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- <CMD>` | Installeur AetherCraft autonome, vérificateur SHA-256 et superviseur Java. |

{% content-ref url="aether-engine-cli.md" %}
[CLI aether-engine](aether-engine-cli.md)
{% endcontent-ref %}

---

## aether-plugin-tool

`aether-plugin-tool` gère les packs de règles SAST déclaratifs stockés sous `.aether/plugins/`. L'exécuter sans argument affiche l'aide et quitte avec le code `0` ; une sous-commande ou option inconnue (comme `--version`) écrit une erreur sur `stderr` et quitte avec le code `1`.

### 🎮 Résumé des sous-commandes

| Sous-commande et alias | Arguments et options | Valeurs par défaut | Codes de sortie et comportement |
|---|---|---|---|
| `help`, `--help`, `-h` | Aucun | — | Affiche l'aide CLI sur `stdout` et quitte avec `0`. |
| `download-semgrep-rules`, `update-rules` | `-o`/`--output <DIR>`, `-u`/`--url <URL>`, `--offline`, `<DIR>` positionnel, `--help` | `dir` : `.aether/plugins`, `url` : `template.yaml` Semgrep, `offline` : `false` | Télécharge via `curl -sSL --max-time 5` ; bascule automatiquement sur le `CommunityBundle` intégré (24 règles). Quitte `1` uniquement si l'écriture disque échoue. |
| `init-bundle` | `[output_dir]` | `.aether/plugins` | Déploie le pack OWASP/CWE intégré (24 règles) vers `<output_dir>/community/plugin.yaml`. Quitte `1` en cas d'erreur d'écriture. |
| `import-semgrep` | `-i`/`--input <PATH>` (ou `<PATH>` positionnel), `-o`/`--output <DIR>`, `--help` | `output` : `.aether/plugins/imported` | Traduit les fichiers Semgrep `.yaml`/`.yml` en `<output>/<stem>/plugin.yaml`. Quitte `0` si aucun YAML n'est trouvé ; `1` si l'entrée est absente. |
| `test` | `[plugins_dir]` | `.aether/plugins` | Exécute `PluginEngine::run_test_suite()` sur les manifestes (hors `visuals/`). Quitte `1` si `failed > 0` ou erreur de chargement. |
| `scan` | `<plugins_dir> <target_path>` | Les deux requis | Analyse un fichier ou une arborescence (ignore `target`, `.git`, `node_modules`, `zig-cache`, `zig-out`, `bin`, `obj`). **Quitte `0` même avec des violations.** |
| `list` | `[plugins_dir]` | `.aether/plugins` | Liste les plugins chargés, identifiants de règles, CWE, sévérités et extensions ciblées. Quitte `1` en cas d'erreur de chargement. |
| `init` | `<plugin_name> [output_dir]` | `output_dir` : `.aether/plugins` | Génère `<output_dir>/<plugin_name>/plugin.yaml` avec `CUSTOM-<NAME>-001` (`CWE-287`, `HIGH`) et 2 `test_cases` valides. |
| `export` | `[plugins_dir] [out.md]` | `.aether/plugins`, `PLUGIN_CATALOG.md` | Génère un catalogue Markdown tabulaire pour tous les plugins actifs. Quitte `1` en cas d'erreur de lecture ou d'écriture. |

### 📝 Options clés et cas limites

- **Repli hors ligne (`download-semgrep-rules` / `update-rules`)** : Sans `--offline`, `aether-plugin-tool` exécute `curl -sSL --max-time 5` sur `-u <URL>` (par défaut `https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/template.yaml`). Si `curl` échoue, expire ou renvoie un YAML Semgrep vide/invalide, il déploie automatiquement le `CommunityBundle` intégré de 24 règles OWASP/CWE.
- **Arguments positionnels** : Dans `download-semgrep-rules`, tout argument ne commençant pas par `-` écrase `output_dir`. Dans `import-semgrep`, le premier argument sans tiret définit `input_path` si `--input` est omis ; une option en fin de ligne sans valeur suivante est ignorée silencieusement.
- **Absence de seuil bloquant dans `scan`** : `aether-plugin-tool scan` retourne toujours `0` en fin de parcours, même si des failles sont affichées. Utilisez `aether-engine --audit-only --fail-on <SEVERITY>` pour bloquer une pipeline CI.

### 💡 Exemples

{% tabs %}
{% tab title="Créer et tester un plugin" %}
{% code title="Générer un manifeste de plugin et exécuter ses tests unitaires intégrés" overflow="wrap" %}
```bash
aether-plugin-tool init my-auth-guard .aether/plugins
aether-plugin-tool test .aether/plugins
```
{% endcode %}
{% endtab %}

{% tab title="Importer Semgrep et scanner" %}
{% code title="Convertir des règles YAML Semgrep, exporter le catalogue et scanner src/" overflow="wrap" %}
```bash
aether-plugin-tool import-semgrep --input ./semgrep-rules --output .aether/plugins/imported
aether-plugin-tool export .aether/plugins PLUGIN_CATALOG.md
aether-plugin-tool scan .aether/plugins ./src
```
{% endcode %}
{% endtab %}

{% tab title="Bundle communautaire hors ligne" %}
{% code title="Déployer le pack OWASP/CWE intégré de 24 règles sans accès réseau" overflow="wrap" %}
```bash
aether-plugin-tool update-rules --offline --output .aether/plugins
# Commande directe équivalente :
aether-plugin-tool init-bundle .aether/plugins
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[DSL déclaratif SAST & Taint v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../plugins/semgrep-and-community-bundle.md" %}
[Importateur Semgrep et bundle communautaire](../plugins/semgrep-and-community-bundle.md)
{% endcontent-ref %}

---

## aetherscope-mcp

`aetherscope-mcp` expose le graphe, l'audit SAST, les contrats, les tâches et l'essaim multi-agents d'AetherScope via **JSON-RPC 2.0 (`protocolVersion: "2024-11-05"`)** sur `stdin`/`stdout` pour Claude Desktop, Antigravity, Gemini CLI et Cursor.

### 🎮 Commande

```bash
aetherscope-mcp [OPTIONS]
```

### 📝 Arguments, options et variables d'environnement

| Option / Variable d'env | Court | Défaut | Description |
|---|---|---|---|
| `-p`, `--path <PATH>` | `-p` | `"."` | Répertoire racine du projet ou coffre Obsidian transmis au backend ou au mode hors ligne. |
| `--port <PORT>` | — | `3030` | Port du backend Axum (`127.0.0.1:<port>`) sondé et utilisé par le pont HTTP. |
| `--mcp` | — | `false` | Accepté par symétrie CLI avec `aether-engine --mcp` ; `aetherscope-mcp` démarre toujours en stdio MCP. |
| `--agent-id <AGENT_ID>` / `AETHER_AGENT_ID` | — | `mcp-agent-<pid % 10000>` | Identifiant explicite de l'agent affiché dans la télémétrie 3D et le chat. |
| `--agent-name <AGENT_NAME>` / `AETHER_AGENT_NAME` | — | `IA MCP #<pid % 10000>` | Nom d'affichage de la session IA connectée. |
| `--color <COLOR>` / `AETHER_AGENT_COLOR` | — | Couleur calculée par hash | Couleur hexadécimale (`#38bdf8`..`#e879f9`) issue de la palette de 12 couleurs `MCP_AGENT_PALETTE`. |
| `-h`, `--help` / `-V`, `--version` | `-h`, `-V` | — | Affiche l'aide CLI ou la version du workspace (`2.6.0`). |

{% hint style="info" %}
`aetherscope-mcp --version` et le champ JSON-RPC `initialize` `serverInfo.version` retournent la version canonique `2.6.0`, alors que la bannière `--help` affiche encore l'ancienne chaîne `"AetherScope V2.4 - Dedicated MCP Server for AI Agents"` (et `smithery.yaml` indique `"2.5.1"`).
{% endhint %}

### Ordre de priorité de l'identité d'agent

`aetherscope-mcp` résout l'identité de chaque session selon une hiérarchie à 5 niveaux :

1. **Arguments JSON par appel d'outil** : `agent_id` (alias : `agent`, `caller`, `author`, `sender`, `role`), `agent_name` (alias : `name`) et `color`.
2. **Options CLI** : `--agent-id`, `--agent-name`, `--color`.
3. **Variables d'environnement** : `AETHER_AGENT_ID`, `AETHER_AGENT_NAME`, `AETHER_AGENT_COLOR`.
4. **Champ `initialize` `params.clientInfo.name`** : Utilisé uniquement si ni les options CLI ni les variables d'environnement n'ont fixé d'identité explicite.
5. **Valeurs par défaut basées sur le PID** : `mcp-agent-<pid % 10000>` et sélection déterministe FNV-1a (`#38bdf8` si vide).

### Cycle d'auto-démarrage et discipline du transport

- **Sonde et démarrage automatique du backend** : Au lancement, `aetherscope-mcp` sonde `127.0.0.1:<port>` pendant 150 ms. Si rien ne répond, il cherche `aether-engine.exe` dans le même dossier que `current_exe()`, lance `aether-engine.exe --no-gui --port <port> --path <path>` et sonde jusqu'à **1,5 s** (`10 × 150 ms`).
- **Mode de repli AST hors ligne** : Si aucun backend n'est joignable, les outils de lecture et d'analyse basculent automatiquement vers un scan AST/Vault/TaskManager direct et mémorisent la télémétrie dans `.aether/ai_telemetry_cache.json`.
- **Cadrage stdio** : Lit le JSON délimité par retour à la ligne sur `stdin` (en retirant les espaces et le BOM UTF-8 `\u{feff}`), n'écrit **que** des réponses JSON-RPC sur une seule ligne vers `stdout`, et dirige tous les journaux de diagnostic vers `stderr`.
- **Erreurs JSON-RPC** : Retourne `-32700` sur JSON invalide, `-32601` pour une méthode inconnue, `-32602` pour une URI de ressource ou un prompt inconnu, et `isError: true` dans le résultat d'outil pour les refus `PathGuard`/`SecretGuard`.

{% hint style="warning" %}
Le démarrage automatique recherche spécifiquement `aether-engine.exe` à côté de `aetherscope-mcp`. Sous Linux ou macOS, lancez le backend séparément avec `aether-engine --no-gui` ou configurez votre client MCP pour invoquer directement `aether-engine --mcp` afin de démarrer le serveur Axum dans le même processus.
{% endhint %}

### 💡 Exemples

{% tabs %}
{% tab title="mcp.json" %}
{% code title="Entrée standard de client MCP avec identité d'essaim explicite" overflow="wrap" %}
```json
{
  "mcpServers": {
    "aetherscope": {
      "command": "aetherscope-mcp",
      "args": ["--port", "3030", "--path", ".", "--agent-id", "claude-sec", "--agent-name", "Claude Security"]
    }
  }
}
```
{% endcode %}
{% endtab %}

{% tab title="Lancement CLI & Variables d'env" %}
{% code title="Démarrer le pont MCP autonome avec identité définie par environnement" overflow="wrap" %}
```bash
AETHER_AGENT_ID="auditor-1" AETHER_AGENT_COLOR="#34d399" aetherscope-mcp --path /chemin/vers/depot --port 3030
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}

---

## aether-mc-runner

`aether-mc-runner` (`v1.0.0`) est l'installeur et superviseur Rust/Tokio autonome pour les serveurs Minecraft AetherCraft. Comme `apps/aethercraft/runner` est exclu du workspace Cargo racine, compilez-le ou exécutez-le avec `--manifest-path apps/aethercraft/runner/Cargo.toml`.

### 🎮 Sous-commandes et options

| Sous-commande | Options courtes / longues | Requis | Défaut | Description |
|---|---|---|---|---|
| `install` | `-m`, `--manifest <MANIFEST>`<br>`-d`, `--dir <DIR>` | Manifest : **Oui**<br>Dir : Non | `./instances/<server_id>` | Charge un manifeste local ou `http(s)://` (timeout 10 s), télécharge le JAR `core` et `plugins_and_mods`, vérifie `Sha256`, écrit `configs` et sauvegarde `.aether-manifest.json`. |
| `run` | `-d`, `--dir <DIR>` | **Oui** | Aucun | Lit `<dir>/.aether-manifest.json`, vérifie `java -version` et `<core.target_jar>`, puis lance `java` avec les `jvm_flags` filtrés et `-jar <target_jar> nogui`. |
| `install-and-run` | `-m`, `--manifest <MANIFEST>`<br>`-d`, `--dir <DIR>` | Manifest : **Oui**<br>Dir : Non | `./instances/<server_id>` | Enchaîne `install` puis `run` immédiatement. |
| `doctor` | Aucune | — | — | Vérifie `java -version` dans le `PATH` et teste `https://api.papermc.io/v2/projects` (timeout 5 s). Affiche des avertissements si indisponible et quitte avec `0`. |

### Sécurité et préfixes de journaux supervisés

- **Intégrité SHA-256 des artefacts** : Lorsque `sha256` dans le manifeste est non vide, `AetherInstaller` compare le condensat SHA-256 en streaming (insensible à la casse) et **supprime le fichier téléchargé** en cas de divergence. Si `sha256` est vide, il affiche les 8 premiers caractères hexadécimaux et poursuit.
- **Protections CWE-22 et anti-injection** : Rejette `..`, `/` initial ou `\` initial dans `core.target_jar`, les chemins/noms d'artefacts et les clés `configs`. Filtre `runtime.jvm_flags` pour n'accepter que les options commençant par `-` sans métacaractères shell (`;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `\r`, `\n`), en appelant `java` directement sans shell.
- **Préfixes de sortie supervisée** :

| Préfixe de log | Flux | Condition de déclenchement |
|---|---|---|
| `[MC-WARN]` | `stdout` | La ligne contient `WARN`. |
| `[MC-ERR]` | `stdout` | La ligne contient `ERROR`. |
| `✨ [MC-READY]` | `stdout` | La ligne contient `Done (`. |
| `[MC]` | `stdout` | Toute autre ligne `stdout` émise par la JVM. |
| `[MC-STDERR]` | `stderr` | Toute ligne `stderr` émise par la JVM. |

### 💡 Exemple

{% code title="Provisionner et démarrer une instance PaperMC via un manifeste AetherCraft" overflow="wrap" %}
```bash
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- doctor
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- install-and-run \
  --manifest http://127.0.0.1:5000/api/v1/servers/my-smp/manifest \
  --dir ./instances/my-smp
```
{% endcode %}

{% content-ref url="../extensions-dev/aethercraft.md" %}
[Plateforme Minecraft AetherCraft](../extensions-dev/aethercraft.md)
{% endcontent-ref %}
