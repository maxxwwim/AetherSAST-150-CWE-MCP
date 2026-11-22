# Dépannage et FAQ

Ce guide vous aide à diagnostiquer et résoudre les incidents courants d'`aether-engine` sous Windows, Linux et macOS : démarrage WebView2, conflits sur le port `3030`, erreurs `403` de `LocalGuard`, alertes `BLAKE3_TAMPERED`, cache SCA hors-ligne et écarts de libellés de version.

## Lancement desktop, console Windows et journaux d'erreur

Sous Windows, `crates/desktop-shell/src/main.rs` utilise `#![windows_subsystem = "windows"]` afin qu'un double-clic sur `aether-engine.exe` n'ouvre pas de fenêtre console superflue. Lors d'un lancement depuis PowerShell ou `cmd.exe`, il appelle `AttachConsole(0xFFFF_FFFF)` (`ATTACH_PARENT_PROCESS`) pour rattacher les sorties au terminal parent.

En cas d'échec du shell desktop ou du serveur HTTP, consultez les journaux générés dans votre **répertoire de travail courant (CWD)** :

| Fichier journal (dans le CWD) | Déclencheur | Cause habituelle |
| :--- | :--- | :--- |
| `desktop-shell-panic.log` | Hook de panique (`PANIC: {:?}`) | Panique d'exécution inattendue au démarrage ou pendant l'analyse. |
| `desktop-shell-error.log` | Erreur de `real_main()` (`MAIN ERROR: {:?}`) | Runtime WebView2 manquant/corrompu ou échec de création de la fenêtre Tao. |
| `server-error.log` | Erreur de `run_server_and_watcher()` (`SERVER ERROR: {:?}`) | Échec de `TcpListener::bind("127.0.0.1:<port>")` car le port `3030` est déjà occupé. |

{% hint style="info" %}
Sous Windows, `aether-engine` transmet `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --js-flags=--max-old-space-size=4096` à WebView2 (`main.rs`). Si la fenêtre embarquée ne s'ouvre toujours pas, vérifiez l'installation du Microsoft Edge WebView2 Runtime dans `desktop-shell-error.log`, ou démarrez en mode navigateur headless avec `--no-gui`.
{% endhint %}

## Conflits sur le port 3030

`aether-engine` et `aetherscope-mcp` utilisent tous deux le port `3030` par défaut (`127.0.0.1:3030`). Si une autre instance tourne encore en arrière-plan, `server-error.log` signale une erreur de liaison réseau.

{% tabs %}
{% tab title="Utiliser un autre port" %}
```bash
# Démarrer sur un port alternatif (par exemple 3040)
aether-engine --path . --port 3040
```
{% endtab %}
{% tab title="Scripts de nettoyage Windows" %}
```bat
:: L'option [7] de AetherScope-Launcher.bat exécute :KILL_PORT :
:: 1. taskkill /F /IM aether-engine.exe
:: 2. taskkill /F /IM aetherscope-mcp.exe
:: 3. Termine chaque PID en écoute sur :3030 via netstat -aon

:: Start-Cockpit.bat libère également aether-engine.exe et :3030 automatiquement avant le lancement.
```
{% endtab %}
{% endtabs %}

## Erreurs 403 Forbidden de LocalGuard

`LocalGuard` (`crates/desktop-shell/src/local_guard.rs`) protège l'ensemble du routeur Axum et renvoie `403 Forbidden` avec le message texte `"AetherScope: requête refusée (origine non locale)"` dès qu'un de ces trois contrôles échoue :

| En-tête vérifié | Valeurs autorisées | Cause fréquente d'un `403 Forbidden` |
| :--- | :--- | :--- |
| `Host` | `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` | Port manquant (ex. `Host: localhost` sans `:3030`), mauvais port ou nom d'hôte non loopback. |
| `Origin` *(si présent)* | `http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>` | Origine `https://`, site externe ou `Origin: null` lors de l'ouverture d'un fichier HTML local via `file://`. |
| `Sec-Fetch-Site` *(si présent)* | `"same-origin"` ou `"none"` | Requête envoyée avec `"cross-site"` ou `"same-site"` depuis un autre port local (utilisez le proxy Vite ou `http://127.0.0.1:3030`). |

{% hint style="warning" %}
Lorsque vous appelez `/api/*` depuis `curl` ou un script, ne fournissez pas d'en-tête `Origin` discordant et conservez `:3030` dans `Host`. Dans le navigateur, ouvrez directement `http://127.0.0.1:3030` (ou le serveur de dev Vite qui proxifie `/api` vers `http://127.0.0.1:3030`) plutôt qu'un fichier HTML ouvert en `file://`.
{% endhint %}

## Violations BLAKE3_TAMPERED

Lorsqu'un `README.md` existe et que `aether.lock.toml` enregistre une empreinte `readme_blake3` pour ce dossier, `ast-scanner` compare `blake3(README.md)` au fichier verrou. En cas de divergence, il émet une alerte `CRITICAL` `CWE-353 / BLAKE3-INTEGRITY` (`rule_id: "BLAKE3_TAMPERED"`).

{% hint style="danger" %}
`BLAKE3_TAMPERED` est explicitement exempté (`exempt_blake3` dans `main.rs`) du filtrage standard `active_cve_rules` afin qu'aucune altération de contrat ne soit masquée par un profil de règles.
{% endhint %}

Validez toute mise à jour légitime d'un contrat `README.md` via l'une de ces 3 méthodes :

1. **Doc Reader Drawer** : cliquez sur **Signer** (`api.signContracts({ project_path, folder })`) pour recalculer et sceller l'empreinte dans `aether.lock.toml`.
2. **Inspector Drawer** : ajustez les règles du dossier ou du fichier et cliquez sur **🔒 Sceller BLAKE3** (`POST /api/contracts/update`), ce qui met à jour le frontmatter et re-signe automatiquement `aether.lock.toml`.
3. **API REST** : appelez directement `POST http://127.0.0.1:3030/api/contracts/sign` :

```bash
curl -s -X POST "http://127.0.0.1:3030/api/contracts/sign" \
  -H "Content-Type: application/json" \
  -d '{"project_path": ".", "folder": "server"}'
```

## Cache SCA OSV hors-ligne et scans air-gapped

L'analyse Reachable Dependency SCA (`--sca`, `--sca-only`) interroge `https://api.osv.dev/v1/query` avec un timeout de 5 secondes (`curl --max-time 5`) et met les réponses en cache dans `<project_root>/.aether/cache/osv/<blake3_hex>.json`.

* **Formule de clé de cache** : `blake3("{ecosystem}:{package}:{version}")` (64 caractères hexadécimaux en minuscules).
* **Écosystèmes normalisés** : `"cargo" | "rust" | "crates.io"` -> `"crates.io"`, `"npm" | "node" | "javascript" | "typescript"` -> `"npm"`, `"packagist" | "composer" | "php"` -> `"Packagist"`.
* **Comportement air-gapped (`--offline-sca`)** : consulte uniquement `.aether/cache/osv/` et renvoie `Ok(Vec::new())` en cas d'absence dans le cache, sans jamais exécuter `curl`.
* **Pré-remplissage du cache** : chaque fichier `<blake3>.json` accepte un wrapper `OsvCacheEntry`, un `OsvQueryResponse` (`{"vulns": [...]}`) ou un tableau JSON brut `Vec<OsvVulnerability>`.

## Repli sur le port 3333 dans McpControlModal en mode autonome

`AetherApiClient` (`crates/desktop-shell/ui/src/lib/api.ts`) utilise par défaut `baseUrl = ''` (appels relatifs `/api/*` sur la même origine). En revanche, `McpControlModal.svelte` calcule ainsi le port affiché dans les extraits JSON MCP et `curl` générés :

```ts
const serverPort = $derived(
  typeof window !== 'undefined' && window.location.port ? window.location.port : '3333'
);
```

Lorsque vous ouvrez le Cockpit sur `http://127.0.0.1:3030`, `window.location.port` vaut `'3030'` et les extraits affichent `3030`. Lorsque vous ouvrez un export HTML autonome via `file://` ou une origine sans port (`window.location.port === ''`), `McpControlModal` se replie sur `'3333'`. Remplacez toujours `3333` par `3030` (ou votre `--port` personnalisé) lorsque vous copiez des extraits depuis un export autonome.

## FAQ : Pourquoi certains fichiers affichent-ils v2.5.1, V2.4 ou V2.1 au lieu de 2.6.0 ?

La version canonique du workspace `aether-engine` est **`2.6.0`**, déclarée dans le `Cargo.toml` racine, `mcp.json`, le `README.md` racine, `crates/desktop-shell/ui/package.json` ainsi que dans `serverInfo.version` d'`aetherscope-mcp` (`env!("CARGO_PKG_VERSION")`).

Quelques manifests secondaires, lanceurs batch et bannières internes conservent toutefois des libellés historiques issus de versions antérieures :

| Libellé historique | Emplacements dans le code | Remarque |
| :--- | :--- | :--- |
| `2.5.1` | `smithery.yaml`, `crates/README.md`, `crates/desktop-shell/README.md` | En-têtes de README des crates et métadonnées Smithery issus de la v2.5.1. |
| `V2.4` | `AetherScope-Launcher.bat`, `Start-Cockpit.bat`, `crates/desktop-shell/src/mcp_main.rs` (`about`) | Bannières des lanceurs Windows et description de `aetherscope-mcp --help`. |
| `V2.1` / `V2` | `crates/desktop-shell/src/benchmark.rs`, `BENCHMARK.md`, `crates/desktop-shell/src/main.rs` (`{"status":"ok","engine":"aether-v2"}`) | Identifiant moteur de deuxième génération conservé par compatibilité. |

{% content-ref url="../getting-started/installation.md" %}
[Installation](../getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="../core/blake3-governance.md" %}
[Cryptographie BLAKE3 et gouvernance EARS](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité et garde-fous](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="benchmark-and-performance.md" %}
[Benchmark et optimisation des performances](benchmark-and-performance.md)
{% endcontent-ref %}
