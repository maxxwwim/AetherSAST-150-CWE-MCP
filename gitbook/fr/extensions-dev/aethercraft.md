# Plateforme Minecraft AetherCraft

AetherCraft (`apps/aethercraft/`) associe un Control Plane Python Flask sur le port `5000` à un runner autonome en Rust (`aether-mc-runner` `v1.0.0`) pour configurer, vérifier, déployer et superviser des serveurs Minecraft Paper/Purpur à partir de manifests JSON immuables.

## Vue d'ensemble

AetherCraft sépare l'orchestration serveur de l'exécution native en deux couches :

1. **Control Plane (`apps/aethercraft/control-plane/app.py`)** : sert la boutique joueurs, le marché des minerais, les classements, la file RCON et le générateur de manifests `/admin` sur `0.0.0.0:5000`.
2. **Runner Rust (`apps/aethercraft/runner/`)** : crate Cargo indépendant (`exclude = [ "apps/aethercraft/runner" ]` dans le `Cargo.toml` racine) compilé en `aether-mc-runner` (`v1.0.0`) pour télécharger les JARs, vérifier les empreintes SHA-256, appliquer les contrôles CWE-22, écrire les configurations et superviser le processus `java`.

{% hint style="info" %}
`apps/aethercraft/runner/Cargo.toml` déclare une table `[workspace]` vide : lancer `cargo test --workspace` à la racine du dépôt ne compile ni ne teste `aether-mc-runner`. Utilisez explicitement `--manifest-path apps/aethercraft/runner/Cargo.toml`.
{% endhint %}

## Lancer AetherCraft

Vous pouvez démarrer le Control Plane et le runner depuis le lanceur Windows (`AetherScope-Launcher.bat` option `[6]`) ou manuellement via Python et Cargo.

{% tabs %}
{% tab title="Control Plane (Flask)" %}
```bash
# Installer les dépendances Flask et Requests
pip install -r apps/aethercraft/control-plane/requirements.txt

# Démarrer le Control Plane sur http://127.0.0.1:5000
python apps/aethercraft/control-plane/app.py
```
{% endtab %}
{% tab title="Runner Rust (aether-mc-runner)" %}
```bash
# Vérifier Java 21+ et la connectivité à l'API PaperMC
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- doctor

# Installer et lancer une instance depuis un manifest du Control Plane
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- install-and-run \
  --manifest http://127.0.0.1:5000/api/v1/servers/default/manifest
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
L'exécution de `install.ps1` copie `aether-mc-runner.exe` (s'il est compilé dans `target\release\`) vers `%LOCALAPPDATA%\AetherScope\bin\`. `AetherScope-Launcher.bat` vérifie ce dossier en plus de `target\release\` et de la racine du dépôt avant d'ouvrir `http://127.0.0.1:5000`.
{% endhint %}

## Routes web du Control Plane (Port 5000)

L'application Flask génère des templates HTML (`templates/*.html`) enrichis par des fragments HTMX et injecte `server_status` globalement via `@app.context_processor`.

| Route(s) | Méthode | Template / Comportement | Description |
| :--- | :--- | :--- | :--- |
| `/` | `GET` | `index.html` (`200`) | Portail d'accueil AetherCraft et présentation de l'état du serveur. |
| `/boutique` | `GET` | `shop.html` (`200`) | Catalogue boutique (`13` articles dans `items`, `pets`, `keys`, `grades`) ; filtrable via `?cat=all\|items\|pets\|keys\|grades`. |
| `/animaux`, `/pets` | `GET` | Redirection `302` | Redirige vers `/boutique?cat=pets`. |
| `/objets`, `/items` | `GET` | Redirection `302` | Redirige vers `/boutique?cat=items`. |
| `/grades` | `GET` | Redirection `302` | Redirige vers `/boutique?cat=grades`. |
| `/caisses`, `/crates`, `/cles` | `GET` | Redirection `302` | Redirige vers `/boutique?cat=keys`. |
| `/shop` | `GET` | Redirection `302` | Redirige vers `/boutique`. |
| `/marche`, `/marche/`, `/marche-minerais`, `/bourse`, `/hdv` | `GET` | `marche.html` (`200`) | Bourse aux minerais affichant `6` minerais statiques (`netherite`, `diamond`, `emerald`, `gold`, `amethyst`, `iron`). |
| `/joueurs` | `GET` | `players.html` (`200`) | Classements (`top_rich`, `top_hours`) et fiche joueur par défaut (`AetherKnight`) avec rendus `mc-heads.net`. |
| `/admin` | `GET` | `admin.html` (`200`) | Cockpit générateur de manifests serveur et historique des commandes en mémoire (`ORDERS_HISTORY`). |
| `/favicon.ico` | `GET` | `204 No Content` | Réponse vide pour l'icône. |

### Pipeline Boutique et livraison RCON

Lorsqu'un utilisateur valide son panier via `POST /api/store/checkout`, `store_service.py` assainit le pseudo Minecraft via `sanitize_minecraft_username` (suppression de tout caractère hors `[a-zA-Z0-9_]`, repli sur `"Steve"` sous `3` caractères, troncature à `16` caractères pour bloquer toute injection CWE-78/CWE-89).

`RconClient` (`services/rcon_service.py`) se connecte ensuite en TCP via le protocole binaire RCON Valve/Minecraft (`SERVERDATA_AUTH = 3`, `SERVERDATA_EXECCOMMAND = 2`, timeout 3 secondes) :

* **Variables d'environnement** : `AETHER_RCON_HOST` (`127.0.0.1`), `AETHER_RCON_PORT` (`25575`), `AETHER_RCON_PASSWORD` (`aether2026`).
* **Repli hors-ligne** : si le serveur Minecraft est injoignable, `dispatch_order_commands` renvoie `"QUEUED_PENDING_SERVER"` et ajoute les commandes sous verrou `threading.Lock()` dans `apps/aethercraft/control-plane/.aether_pending_deliveries.json`.

## Endpoints API du Control Plane

### Panier Boutique et Checkout (Partiels HTMX)

#### 🎮 Endpoint

```http
POST /api/store/cart/add
POST /api/store/cart/remove
POST /api/store/cart/clear
POST /api/store/checkout
```

#### 📝 Paramètres

| Endpoint | Paramètre formulaire (`application/x-www-form-urlencoded`) | Type | Défaut | Description |
| :--- | :--- | :--- | :--- | :--- |
| `/api/store/cart/add` | `item_id` | `string` | — | Identifiant d'article du catalogue (par exemple `item_elytra_celestial`, `rank_aether`). |
| `/api/store/cart/remove` | `item_id` | `string` | — | Retire le premier article correspondant de `session["cart"]`. |
| `/api/store/cart/clear` | *(aucun)* | — | — | Vide `session["cart"]`. |
| `/api/store/checkout` | `username` | `string` | `"Steve"` | Pseudo Minecraft cible (assaini sur 3–16 caractères alphanumériques/`_`). |

#### 💎 Réponse

| Statut | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `text/html` | Fragment `partials/cart.html` rendu avec `cart`, `cart_total` et (après checkout) `order_success`. |

#### 💡 Exemple

```bash
curl -s -c cookies.txt -b cookies.txt -X POST "http://127.0.0.1:5000/api/store/cart/add" \
  -d "item_id=rank_vip"

curl -s -c cookies.txt -b cookies.txt -X POST "http://127.0.0.1:5000/api/store/checkout" \
  -d "username=AetherKnight"
```

### Recherche de joueur (`POST /api/players/search`)

#### 🎮 Endpoint

```http
POST http://127.0.0.1:5000/api/players/search
```

#### 📝 Paramètres

| Paramètre | Source | Type | Défaut | Description |
| :--- | :--- | :--- | :--- | :--- |
| `username` | Formulaire | `string` | `"Steve"` | Recherche insensible à la casse dans `MOCK_PLAYERS` (`AetherKnight`, `PixelSorceress`, `VortexCrafter`, `ShadowRanger`, `Notch`), ou profil dynamique par défaut. |

#### 💎 Réponse

| Statut | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `text/html` | Fragment `partials/player_card.html` rendu avec grade, heures jouées, solde, ratio K/D et avatars `mc-heads.net`. |

#### 💡 Exemple

```bash
curl -s -X POST "http://127.0.0.1:5000/api/players/search" \
  -d "username=AetherKnight"
```

### Générer un Manifest Serveur (`POST /api/v1/servers/generate`)

#### 🎮 Endpoint

```http
POST http://127.0.0.1:5000/api/v1/servers/generate
```

#### 📝 Paramètres

| Paramètre | Source | Type | Défaut | Description |
| :--- | :--- | :--- | :--- | :--- |
| `name` | Formulaire | `string` | `"Serveur Minecraft"` | Nom affiché servant à dériver `server_id` (`srv_<slug>_<6hex>`). |
| `core_type` | Formulaire | `string` | `"paper"` | Moteur serveur (`"paper"` interroge `api.papermc.io` avec timeout 5s et repli sur build `118` ; `"purpur"` utilise le build `2300`). |
| `mc_version` | Formulaire | `string` | `"1.21.1"` | Version Minecraft (`"1.21.1"` ou `"1.20.4"`). |
| `ram_gb` | Formulaire | `integer` | `4` | Mémoire RAM en Go (génère `-Xms{ram_gb}G` / `-Xmx{ram_gb}G` plus 15 flags Aikar G1GC). |
| `port` | Formulaire | `integer` | `25565` | Port d'écoute écrit dans `server.properties`. |
| `difficulty` | Formulaire | `string` | `"normal"` | Difficulté du monde (`"hard"`, `"normal"`, `"easy"`). |
| `plugins` | Formulaire (multi) | `string[]` | `[]` | Toute combinaison de `"chunky"`, `"spark"`, `"luckperms"`. |

#### 💎 Réponse

| Statut | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `text/html` | Carte HTML contenant l'URL du manifest (`/api/v1/servers/{server_id}/manifest`) et la commande `cargo run ... -- install-and-run --manifest ...` prête à copier. |

#### 💡 Exemple

```bash
curl -s -X POST "http://127.0.0.1:5000/api/v1/servers/generate" \
  -d "name=Survival+One" \
  -d "core_type=paper" \
  -d "mc_version=1.21.1" \
  -d "ram_gb=6" \
  -d "plugins=chunky" \
  -d "plugins=spark"
```

### Récupérer un Manifest Serveur (`GET /api/v1/servers/<server_id>/manifest`)

#### 🎮 Endpoint

```http
GET http://127.0.0.1:5000/api/v1/servers/{server_id}/manifest
```

#### 📝 Paramètres

| Paramètre | Source | Type | Requis | Description |
| :--- | :--- | :--- | :--- | :--- |
| `server_id` | Chemin | `string` | Oui | Identifiant retourné par `/api/v1/servers/generate`. S'il est absent de `MANIFEST_STORE`, l'endpoint génère et met en cache un manifest Paper `1.21.1` par défaut (`4G` RAM, `chunky` + `spark`, `hard`). |

#### 💎 Réponse

| Statut | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `application/json` | JSON Aether MC Manifest v1.0 complet incluant `runtime`, `core`, `plugins_and_mods` et `configs` (`eula.txt`, `server.properties` et le datapack en 5 fichiers `world/datapacks/aether_sanctuary/`). |

#### 💡 Exemple

```bash
curl -s "http://127.0.0.1:5000/api/v1/servers/default/manifest"
```

### Ping et santé serveur (`GET /api/v1/server/ping`, `GET /api/v1/health`)

#### 🎮 Endpoint

```http
GET http://127.0.0.1:5000/api/v1/server/ping
GET http://127.0.0.1:5000/api/v1/health
```

#### 📝 Paramètres

| Paramètre | Type | Requis | Description |
| :--- | :--- | :--- | :--- |
| *(aucun)* | — | — | Les deux endpoints ne prennent aucun paramètre de requête ni de corps. |

#### 💎 Réponse

| Endpoint | Statut | Champs retournés |
| :--- | :--- | :--- |
| `/api/v1/server/ping` | `200 OK` JSON | `status`, `ip`, `port`, `local_ip`, `motd`, `version`, `players_online`, `players_max`, `ping_ms`, `tps`, `runner_cmd`. |
| `/api/v1/health` | `200 OK` JSON | `{"status": "ok", "service": "aether-mc-control-plane", "modules": ["store", "players", "server_creator"]}`. |

#### 💡 Exemple

```bash
curl -s "http://127.0.0.1:5000/api/v1/health"
```

## Spécification du Manifest Aether MC (v1.0)

`docs/AETHER_MC_MANIFEST_SPEC.md` et `apps/aethercraft/runner/src/manifest.rs` définissent le contrat JSON v1.0 consommé par `aether-mc-runner` :

{% code title="test_manifest.json (extrait v1.0)" overflow="wrap" %}
```json
{
  "version": "1.0",
  "server_id": "test_mc_srv",
  "name": "Test Server Aether",
  "runtime": {
    "java_major_version": 21,
    "vendor": "adoptium",
    "heap_min": "2G",
    "heap_max": "2G",
    "jvm_flags": ["-Xms2G", "-Xmx2G"]
  },
  "core": {
    "type": "paper",
    "mc_version": "1.21.1",
    "build": 118,
    "target_jar": "paper-server.jar",
    "download_url": "https://api.papermc.io/v2/projects/paper/versions/1.21.1/builds/118/downloads/paper-1.21.1-118.jar",
    "sha256": ""
  },
  "plugins_and_mods": [
    {
      "name": "Chunky.jar",
      "target_dir": "plugins",
      "download_url": "https://cdn.modrinth.com/data/fALzjamp/versions/R1Kxvd8Z/Chunky-1.4.28.jar",
      "sha256": ""
    }
  ],
  "configs": {
    "eula.txt": "eula=true\n",
    "server.properties": "server-port=25565\nmotd=Aether Test Server\n"
  }
}
```
{% endcode %}

Lorsque `AetherInstaller::install` (`apps/aethercraft/runner/src/installer.rs`) applique un manifest, il garantit :

* **Contrôles anti-traversée CWE-22** : rejette `..`, `/` initial ou `\` initial dans `core.target_jar` et les clés de `configs`, et rejette `..` dans `artifact.name` et `artifact.target_dir`.
* **Vérification SHA-256 en streaming** : hache les téléchargements bloc par bloc via `sha2::Sha256`. Si `sha256` est renseigné et ne correspond pas (hexadécimal insensible à la casse), le fichier téléchargé est immédiatement supprimé et l'installation échoue. Si `sha256` vaut `""`, le runner affiche les 8 premiers caractères hexadécimaux et continue.
* **Persistance du manifest** : sérialise le manifest appliqué dans `<instance_dir>/.aether-manifest.json` afin que les exécutions suivantes via `aether-mc-runner run --dir <dir>` fonctionnent hors-ligne.

{% hint style="info" %}
Bien que `apps/aethercraft/runner/Cargo.toml` déclare `blake3 = "1.5"` dans ses dépendances, `installer.rs` utilise exclusivement `sha2::Sha256` pour correspondre à l'API PaperMC et au champ `sha256` du manifest.
{% endhint %}

## Supervision par le runner Rust (`aether-mc-runner`)

`aether-mc-runner` expose 4 sous-commandes (`install`, `run`, `install-and-run`, `doctor`) détaillées dans la référence CLI. Durant `AetherRunner::run` (`apps/aethercraft/runner/src/runner.rs`) :

1. Vérifie la présence de Java via `java -version` et contrôle l'existence de `<instance_dir>/<core.target_jar>`.
2. Filtre `manifest.runtime.jvm_flags` afin de ne transmettre à `tokio::process::Command::new("java")` (sans interpréteur shell) que les flags commençant par `-` et exempts de métacaractères shell (`; | & \` $ > < \r \n`).
3. Étiquette en temps réel `stdout` (`[MC-WARN]` si `WARN`, `[MC-ERR]` si `ERROR`, `✨ [MC-READY]` si `Done (`, sinon `[MC]`) et `stderr` (`[MC-STDERR]`).

{% hint style="warning" %}
`runner.rs` transmet `manifest.runtime.jvm_flags` directement à `java` sans synthétiser `-Xms`/`-Xmx` à partir de `heap_min`/`heap_max`. Incluez toujours `-Xms` et `-Xmx` dans `jvm_flags` (le générateur Flask le fait automatiquement).
{% endhint %}

## Notes d'implémentation et limitations

* **Stockage volatil en mémoire** : `MANIFEST_STORE` et `ORDERS_HISTORY` résident en mémoire Python et sont réinitialisés au redémarrage de `app.py`. Seules les livraisons RCON en attente persistent dans `.aether_pending_deliveries.json`.
* **Vidage manuel de la file RCON** : `rcon_service.flush_pending_queue()` permet de vider `.aether_pending_deliveries.json` lorsque RCON redevient joignable, mais `app.py` ne l'appelle ni automatiquement ni via une route dédiée.
* **Statut serveur simulé** : `server_status_service.py` renvoie un nombre de joueurs simulé (`118`–`142`) et un ping aléatoire (`18`–`34 ms`) plutôt que d'interroger un socket Minecraft réel.
* **Fichiers hérités non câblés** : les dataclasses de `models/*.py` et `templates/dashboard.html` restent présents pour référence sans être utilisés par `app.py`.
* **Validation des chemins d'artefacts** : dans `installer.rs`, `plugins_and_mods` vérifie `.contains("..")` sans vérifier `/` ou `\` en tête ; conservez des valeurs strictement relatives pour `target_dir` et `name` dans vos manifests personnalisés.

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[CLI aether-plugin-tool, aetherscope-mcp et aether-mc-runner](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="../console/launchers-and-scripts.md" %}
[Lanceurs, installateurs et workflows CI/CD](../console/launchers-and-scripts.md)
{% endcontent-ref %}

{% content-ref url="arch-scaffolder.md" %}
[Scaffolder d'Architecture Multi-Stack](arch-scaffolder.md)
{% endcontent-ref %}
