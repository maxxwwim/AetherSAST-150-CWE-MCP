# CLI aether-engine

Le binaire `aether-engine` (`v2.6.0`) est le point d'entrée principal pour le Cockpit desktop AetherScope, le serveur Axum headless, l'auditeur de sécurité SAST/SCA, le banc de performance et le serveur MCP stdio.

---

## Modes d'exécution et priorité

Lorsque vous exécutez `aether-engine`, `real_main()` évalue les options dans un ordre de priorité strict afin que les flux CI/CD, MCP et GUI restent déterministes :

1. **`--update-rules`** : Déploie hors ligne le bundle communautaire Semgrep intégré (24 règles) dans `<path>/.aether/plugins/community/plugin.yaml`. Quitte immédiatement sauf si `--audit-only`, `--port` ou `--mcp` est également fourni sans `--no-gui`.
2. **`--benchmark`** : Exécute le banc de performance en 4 phases, affiche les métriques mémoire et débit, écrit `<path>/BENCHMARK.md`, puis quitte.
3. **`--mcp`** : Démarre la boucle JSON-RPC 2.0 MCP sur `stdin`/`stdout`. Si aucun backend n'écoute sur `127.0.0.1:<port>` (sonde TCP de 150 ms), il lance le serveur Axum et `FileWatcherBridge` en arrière-plan et attend 350 ms.
4. **`--sca-only`** : Exécute l'analyse autonome des dépendances sur les lockfiles pris en charge avec atteignabilité par graphe d'appels, affiche le rapport dans le terminal, évalue `--fail-on`, puis quitte.
5. **Audit SAST headless (`run_audit_cli`)** : Déclenché automatiquement dès que `--audit-only`, `--format sarif`, `--fail-on`, `--sca` ou `--offline-sca` est présent. Exécute l'analyse AST + CWE + plugins + SCA optionnel, génère les rapports, évalue `--fail-on` et synchronise tout Cockpit actif sur `127.0.0.1:<port>`.
6. **Serveur + Cockpit Desktop / `--no-gui`** : Démarre le serveur REST Axum (`127.0.0.1:<port>`) et `FileWatcherBridge` (scrutation `100 ms`, boucle `30 ms`, anti-rebond `100 ms` / lot max `500 ms`). Avec `--no-gui`, le serveur reste headless indéfiniment ; sinon, une fenêtre WebView2 native maximisée (`1280×800`, `tao` + `wry`) s'ouvre avec les DevTools activés.

{% hint style="warning" %}
Passer `--format markdown` ou `--format text` seul ne déclenche **pas** d'audit headless : ajoutez `--audit-only` si aucun autre déclencheur (`--fail-on`, `--sca`, `--offline-sca`) n'est présent. De même, combiner `--update-rules` avec `--no-gui` quitte immédiatement après l'hydratation des règles sans démarrer le serveur HTTP.
{% endhint %}

---

## Référence des options

### 🎮 Commande

```bash
aether-engine [OPTIONS]
```

### 📝 Arguments et options

`aether-engine` analyse toutes les options avec `clap` (`2.6.0`), incluant `-h`/`--help` et `-V`/`--version`.

| Court | Long | Type | Défaut | Description | Cas limites |
|---|---|---|---|---|---|
| `-p` | `--path <PATH>` | `String` | `"."` | Répertoire cible du projet ou coffre Obsidian. Nettoie guillemets/espaces et retire le préfixe Windows `\\?\`. | Une chaîne vide `""` équivaut au répertoire courant. |
| — | `--port <PORT>` | `u16` | `3030` | Port TCP local pour Axum (`127.0.0.1:<port>`), `LocalGuard`, l'URL WebView2, le pont `--mcp` et la synchro Cockpit. | Si le port est déjà occupé en mode GUI/`--no-gui`, `server-error.log` enregistre l'erreur tout en laissant la fenêtre ouverte. |
| — | `--audit-only` | `bool` | `false` | Exécute l'audit SAST en ligne de commande et quitte sans fenêtre ni serveur HTTP. | Impliqué automatiquement par `--format sarif`, `--fail-on`, `--sca` ou `--offline-sca`. |
| — | `--no-gui` | `bool` | `false` | Maintient le backend Axum et `FileWatcherBridge` en mode headless sans ouvrir de fenêtre desktop. | Quitte prématurément après l'hydratation si combiné avec `--update-rules`. |
| — | `--mcp` | `bool` | `false` | Entre dans la boucle stdio JSON-RPC 2.0 MCP en démarrant automatiquement le backend dans le même processus si `<port>` est fermé. | Évalué après `--update-rules` et `--benchmark`, avant `--sca-only` et `--audit-only`. |
| — | `--format <FORMAT>` | `String` | `"text"` | Format du rapport d'audit : `"text"`, `"markdown"` ou `"sarif"` (comparaison insensible à la casse pour `"sarif"`). | `"text"` et `"markdown"` exécutent exactement la même branche écrivant `.aether/LIVE_AUDIT.md`. |
| `-o` | `--output <OUTPUT>` | `Option<String>` | `None` | Chemin de destination pour le JSON SARIF ou une copie de `.aether/LIVE_AUDIT.md` (crée les dossiers parents). | Ignoré par `--sca-only` et `--benchmark`. |
| — | `--fail-on <SEVERITY>` | `Option<String>` | `None` | Seuil bloquant CI/CD (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING` ou correspondance exacte). | Quitte avec le code `1` si dépassé ; ignore les traces SSA assainies (`is_sanitized == true`). |
| — | `--benchmark` | `bool` | `false` | Exécute le banc de performance en 4 phases et écrit `<path>/BENCHMARK.md`. | Prend en compte `--plugins` ; ignore `--sca` et `--fail-on`. |
| — | `--update-rules` | `bool` | `false` | Déploie hors ligne le bundle communautaire de 24 règles OWASP/CWE dans `<path>/.aether/plugins/community/plugin.yaml`. | 100 % hors ligne (`include_str!`) ; aucun accès réseau requis. |
| — | `--sca` | `bool` | `false` | Active l'analyse SCA atteignable OSV (`Cargo.lock`, `package-lock.json`, `composer.lock`) pendant l'audit SAST. | Revient silencieusement à 0 vulnérabilité par dépendance en cas d'échec `curl`/réseau. |
| — | `--offline-sca` | `bool` | `false` | Force une analyse SCA 100 % hors ligne lisant uniquement `<path>/.aether/cache/osv/<blake3>.json`. | Les dépendances absentes du cache retournent `0` vulnérabilité sans appeler `curl`. |
| — | `--sca-only` | `bool` | `false` | Exécute uniquement le scan SCA avec atteignabilité par graphe d'appels et affiche le rapport dans le terminal. | N'écrit ni `LIVE_AUDIT.md`, ni SARIF, ni `-o`, et ignore `--plugins`. |
| — | `--plugins <SPEC>` | `Option<String>` | `None` | Sélectionne les packs/profils SAST actifs : `"default"`, `"auto"`, `"all"`, noms de packs/dossiers ou `profile:<name>`. | Quitte avec le code `1` si la syntaxe est vide ou si un pack/profil est inconnu. |

{% hint style="info" %}
Sous Windows, `aether-engine` est compilé avec `#![windows_subsystem = "windows"]` afin d'éviter l'ouverture d'une console lors d'un double-clic, tout en appelant `AttachConsole(0xFFFF_FFFF)` au démarrage pour conserver les sorties `stdout`/`stderr` dans PowerShell et `cmd.exe`. La fenêtre WebView2 native relève aussi la limite du tas V8 via `--js-flags=--max-old-space-size=4096` et consigne les erreurs fatales dans `desktop-shell-panic.log`, `desktop-shell-error.log` et `server-error.log` du répertoire courant.
{% endhint %}

---

## Formats de sortie et synchronisation Cockpit

Les audits SAST headless (`run_audit_cli`) produisent des rapports Markdown lisibles ou du JSON SARIF v2.1.0, puis synchronisent automatiquement toute instance Cockpit active.

{% tabs %}
{% tab title="text / markdown (Par défaut)" %}
Les modes `--format text` et `--format markdown` écrivent tous deux un rapport horodaté dans `<path>/.aether/LIVE_AUDIT.md` et affichent un résumé d'une ligne sur `stdout` (nombre de nœuds, flux, violations et fichiers audités).

- Si `-o <fichier>` est fourni et que `.aether/LIVE_AUDIT.md` existe, `aether-engine` crée les répertoires parents manquants et y copie `LIVE_AUDIT.md`.
- Les projets conformes (ou ne contenant que des avis `RULE_MAX_LINES`) affichent `ARCH_OK` dans `.aether/LIVE_AUDIT.md`.
{% endtab %}

{% tab title="sarif (SARIF v2.1.0)" %}
L'option `--format sarif` génère un document **SARIF v2.1.0** formaté (`tool.driver.name = "AetherScope"`, `version = "2.6.0"`).

- **Destination** : Écrit dans `-o <fichier>` si spécifié (en créant les répertoires parents), ou affiche le JSON complet sur `stdout`.
- **Correspondance des sévérités** : `CRITICAL` / `HIGH` deviennent `"error"`, `MEDIUM` devient `"warning"`, et `LOW` / `WARNING` / `INFO` / `NOTE` deviennent `"note"`.
- **Normalisation des chemins et lignes** : Supprime le préfixe Windows `\\?\`, convertit `\` en `/`, définit `uriBaseId: "%SRCROOT%"`, borne la ligne `0` à `1`, et injecte `cveId`, `remediation`, `is_reachable` et `exploit_path` dans `result.properties`.
- **Liens documentaires (`helpUri`)** : Pointe les entrées `CWE-<chiffres>` vers les définitions MITRE CWE, les règles `AETHER-*` vers `CWE_CATALOG.md`, et les autres règles par identifiant en minuscules.
{% endtab %}
{% endtabs %}

### Synchronisation en direct du Cockpit (`POST /api/analyze`)

Si `run_audit_cli` se termine sans interruption par `--fail-on`, il sonde `127.0.0.1:<port>` avec un timeout TCP de 150 ms :

- **Cockpit détecté** : Envoie `POST http://127.0.0.1:<port>/api/analyze` avec `{"path": "<project_root>"}` pour actualiser instantanément le graphe WebGL 3D et le serveur MCP avec votre dernier scan CLI.
- **Aucun Cockpit actif** : Affiche un message informatif et quitte avec le code `0`.

---

## Codes de sortie et seuils bloquants (`--fail-on`)

### 💎 Codes de sortie

| Code de sortie | Conditions de déclenchement | Sortie et effets de bord |
|---|---|---|
| `0` | Fin normale de `--update-rules`, `--benchmark`, `--mcp`, `--sca-only`, `run_audit_cli` (sans dépassement `--fail-on`), ou fermeture de la GUI. | Écrit les fichiers demandés et lance la synchronisation Cockpit après `run_audit_cli`. |
| `1` | Sélecteur `--plugins` invalide, erreur d'exécution/I/O sur `--benchmark`, ou dépassement du seuil `--fail-on` dans `run_audit_cli` / `--sca-only`. | Affiche les diagnostics `❌` (ainsi que jusqu'à 5 violations d'exemple) sur `stderr`. Les rapports (`LIVE_AUDIT.md` / SARIF / `-o`) sont écrits **avant** la sortie `1`, tandis que la synchro Cockpit est ignorée. |
| `2` / Non nul | Erreur de syntaxe `clap` (`Args::parse()` quitte avec `2`) ou erreur fatale retournée par `real_main()`. | Les erreurs d'exécution écrivent `desktop-shell-error.log` dans le répertoire de travail courant. |

### Règles de correspondance `--fail-on`

| Mode | Résultats évalués | Correspondance des seuils |
|---|---|---|
| `run_audit_cli` (SAST + `--sca`) | Toutes les anomalies actives du graphe **sauf** les traces de taint SSA assainies (`taint_trace.is_sanitized == true`). | `CRITICAL` -> `CRITICAL`<br>`HIGH` -> `CRITICAL`, `HIGH`<br>`MEDIUM` -> `CRITICAL`, `HIGH`, `MEDIUM`<br>`LOW` / `WARNING` -> `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `WARNING`<br>Autre valeur -> correspondance exacte insensible à la casse |
| `--sca-only` (SCA uniquement) | **Uniquement** les vulnérabilités atteignables (`is_reachable == true`) ; les CVE non atteignables ne bloquent jamais la CI. | `CRITICAL` -> `CRITICAL`<br>`HIGH` -> `CRITICAL`, `HIGH`<br>`MEDIUM` -> `CRITICAL`, `HIGH`, `MEDIUM`<br>Autres valeurs -> ignorées (non bloquantes) |

{% hint style="success" %}
Les flux de données SSA assainis (`is_sanitized == true`) sont automatiquement exclus des seuils `--fail-on` lors des audits SAST, ce qui évite les faux blocages en CI lorsqu'une entrée utilisateur passe par un assainisseur reconnu.
{% endhint %}

---

## Sélection des plugins (`--plugins`)

Utilisez `--plugins <SPEC>` pour choisir quels manifestes locaux `.aether/plugins/` et packs intégrés s'exécutent pendant vos audits ou benchmarks :

- **`default`** (comportement par défaut sans `--plugins`) : Exécute toutes les règles SAST natives ainsi que chaque plugin YAML/JSON avec `enabled: true` dans `<path>/.aether/plugins/` (hors `visuals/` et `visual-plugin.*`).
- **`auto` / `all`** : Exécute toutes les règles SAST natives ainsi que tous les plugins locaux activés.
- **Liste séparée par des virgules (`Select`)** : Accepte, sans sensibilité à la casse, le champ `name` d'un plugin, l'alias du dossier parent (`folder_alias`), `profile:<name>` (correspondant à `profile` ou à un élément de `tags`), ou l'un des 34 noms de packs intégrés ci-dessous.

<details>
<summary>Afficher les 34 identifiants de packs intégrés reconnus par --plugins</summary>

| Famille de règles | Identifiants acceptés |
|---|---|
| **Rust** | `builtin-rust`, `rust`, `rust-l1` |
| **Web3 / Solidity / DeFi** | `builtin-web3`, `web3`, `solidity`, `defi` |
| **Python** | `builtin-python`, `python`, `py` |
| **JavaScript / TypeScript** | `builtin-javascript`, `javascript`, `js`, `typescript`, `ts` |
| **PHP** | `builtin-php`, `php` |
| **Zig** | `builtin-zig`, `zig` |
| **C# / .NET** | `builtin-csharp`, `csharp`, `cs`, `dotnet` |
| **C / C++** | `builtin-cpp`, `cpp`, `c` |
| **Deep (Injection / VM / Wasm)** | `builtin-deep`, `deep` |
| **Epic / Novel (`AETHER-*`)** | `builtin-epic`, `epic`, `novel` |
| **Architecture & Core (`RULE_*`, `SAST_*`, `BLAKE3_TAMPERED`)** | `architecture`, `arch`, `core` |

</details>

{% hint style="warning" %}
Dans `ProjectScanner` (utilisé par `--audit-only`, `--format sarif` et le serveur Cockpit), passer une liste `--plugins <spec>` (`PluginSelection::Select`) désactive les règles SAST natives intégrées et n'exécute que les manifestes `.aether/plugins/` correspondants. En mode `--benchmark`, `SecurityLinter::audit_file_selected` filtre également les règles natives selon les packs intégrés demandés.
{% endhint %}

---

## Analyse de composition logicielle (`--sca`, `--offline-sca`, `--sca-only`)

AetherScope recherche les dépendances dans `<path>` et ses sous-répertoires directs de niveau 1 sur trois formats de lockfiles (en ignorant `target`, `node_modules` et `.git`) :

- **`Cargo.lock`** : Écosystème `crates.io` (inclut les sources `registry+` et `git+`).
- **`package-lock.json`** : Écosystème `npm` (prend en charge `dependencies` imbriqué v1 et `packages` plat v2/v3).
- **`composer.lock`** : Écosystème `Packagist` (`packages` et `packages-dev`, en retirant le préfixe `v`).

Pour chaque dépendance, `ScaEngine` consulte le cache disque BLAKE3 dans `<path>/.aether/cache/osv/<blake3>.json` (calculé depuis `"{ecosystem}:{package}:{version}"`). Sauf si `--offline-sca` est activé, les absences du cache interrogent `https://api.osv.dev/v1/query` via `curl -sSL --max-time 5` et stockent la réponse localement.

Les CVE détectées sont rattachées à des nœuds `«Vulnerable Dependency»`, reliées par des arêtes `EdgeType::Call` depuis les appelants applicatifs correspondants, puis tracées par BFS inversé (`compute_reachability`) afin de distinguer les chemins exploitables atteignables du code mort.

---

## Benchmark et mise à jour hors ligne (`--benchmark`, `--update-rules`)

### `--benchmark`

Exécute un banc de performance en 4 phases sur votre espace de travail :

1. **Découverte et lexing** : Collecte les fichiers sources, mesure le nombre de lignes (LOC) et masque les littéraux (`mask_literals`).
2. **AST et graphe** : Construit l'AST parallèle Rayon et le graphe d'affiliation (`ProjectScanner::scan_project`).
3. **Évaluation CWE et plugins** : Évalue les règles SAST natives et plugins sur `available_parallelism()` threads.
4. **Atteignabilité et dispositions** : Calcule l'atteignabilité par BFS inversé et les quatre dispositions spatiales (`Z-1`..`Z-4`).

La commande affiche les durées de chaque phase, le pic mémoire RSS (`K32GetProcessMemoryInfo` sous Windows ou `/proc/self/status` sous Unix) et le débit en LOC/s sur `stdout`, puis génère `<path>/BENCHMARK.md`.

### `--update-rules`

Extrait le pack communautaire Semgrep intégré (24 règles OWASP/CWE) directement depuis le binaire vers `<path>/.aether/plugins/community/plugin.yaml`, sans aucune requête réseau.

---

## Exemples courants

{% tabs %}
{% tab title="Porte CI/CD SARIF" %}
{% code title="Exécuter un audit SAST + SCA headless et bloquer sur HIGH ou CRITICAL" overflow="wrap" %}
```bash
aether-engine --path . --audit-only --sca --format sarif --output results.sarif --fail-on HIGH
```
{% endcode %}
{% endtab %}

{% tab title="SCA hors ligne" %}
{% code title="Exécuter le scan SCA autonome strictement depuis le cache BLAKE3 local" overflow="wrap" %}
```bash
aether-engine --path . --sca-only --offline-sca --fail-on CRITICAL
```
{% endcode %}
{% endtab %}

{% tab title="Profil de plugins" %}
{% code title="Hydrater les règles communautaires puis exécuter uniquement le profil owasp" overflow="wrap" %}
```bash
aether-engine --path . --update-rules
aether-engine --path . --audit-only --plugins profile:owasp
```
{% endcode %}
{% endtab %}

{% tab title="Serveur headless & Synchro" %}
{% code title="Démarrer le backend Axum headless sur le port 3030 puis synchroniser un scan CLI" overflow="wrap" %}
```bash
aether-engine --path . --no-gui --port 3030
# Dans un second terminal :
aether-engine --path . --audit-only --port 3030
```
{% endcode %}
{% endtab %}

{% tab title="Benchmark" %}
{% code title="Mesurer les performances AST, SAST et layouts dans BENCHMARK.md" overflow="wrap" %}
```bash
aether-engine --path . --benchmark --plugins default
```
{% endcode %}
{% endtab %}
{% endtabs %}

---

## Pages connexes

{% content-ref url="plugin-and-mcp-clis.md" %}
[CLI Plugins, MCP et Runner](plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="launchers-and-scripts.md" %}
[Lanceurs, installeurs et workflows CI/CD](launchers-and-scripts.md)
{% endcontent-ref %}

{% content-ref url="../core/cwe-sast-engine.md" %}
[Moteur CWE et SAST](../core/cwe-sast-engine.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[DSL déclaratif SAST & Taint v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}

{% content-ref url="../extensions-dev/benchmark-and-performance.md" %}
[Benchmark et optimisation des performances](../extensions-dev/benchmark-and-performance.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}
