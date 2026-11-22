# AetherCraft Minecraft Platform

AetherCraft (`apps/aethercraft/`) pairs a Python Flask Control Plane on port `5000` with a standalone Rust server runner (`aether-mc-runner` `v1.0.0`) to configure, verify, deploy, and supervise Paper/Purpur Minecraft instances from immutable JSON manifests.

## Overview

AetherCraft separates server orchestration from native process execution across two tiers:

1. **Control Plane (`apps/aethercraft/control-plane/app.py`)**: Serves the player storefront, mineral market, leaderboards, RCON delivery queue, and `/admin` manifest generator on `0.0.0.0:5000`.
2. **Rust Runner (`apps/aethercraft/runner/`)**: An independent Cargo crate (`exclude = [ "apps/aethercraft/runner" ]` in root `Cargo.toml`) compiled into `aether-mc-runner` (`v1.0.0`) to download JARs, verify SHA-256 digests, enforce CWE-22 path checks, write config files, and supervise the `java` process.

{% hint style="info" %}
`apps/aethercraft/runner/Cargo.toml` defines an empty `[workspace]` table, so running `cargo test --workspace` at the repository root does not build or test `aether-mc-runner`. Use `--manifest-path apps/aethercraft/runner/Cargo.toml` explicitly.
{% endhint %}

## Launching AetherCraft

You can start the Control Plane and runner either from the Windows launcher (`AetherScope-Launcher.bat` option `[6]`) or manually via Python and Cargo.

{% tabs %}
{% tab title="Control Plane (Flask)" %}
```bash
# Install Flask & Requests dependencies
pip install -r apps/aethercraft/control-plane/requirements.txt

# Start the Control Plane on http://127.0.0.1:5000
python apps/aethercraft/control-plane/app.py
```
{% endtab %}
{% tab title="Rust Runner (aether-mc-runner)" %}
```bash
# Check Java 21+ and PaperMC API connectivity
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- doctor

# Install and launch an instance from a Control Plane manifest
cargo run --manifest-path apps/aethercraft/runner/Cargo.toml -- install-and-run \
  --manifest http://127.0.0.1:5000/api/v1/servers/default/manifest
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Running `install.ps1` copies `aether-mc-runner.exe` (when built in `target\release\`) into `%LOCALAPPDATA%\AetherScope\bin\`. `AetherScope-Launcher.bat` checks that folder alongside `target\release\` and the repo root before opening `http://127.0.0.1:5000`.
{% endhint %}

## Control Plane Web Routes (Port 5000)

The Flask application renders HTML templates (`templates/*.html`) with HTMX fragments and injects `server_status` globally via `@app.context_processor`.

| Route(s) | Method | Template / Behavior | Description |
| :--- | :--- | :--- | :--- |
| `/` | `GET` | `index.html` (`200`) | Main AetherCraft landing portal and server status showcase. |
| `/boutique` | `GET` | `shop.html` (`200`) | Store catalog (`13` items across `items`, `pets`, `keys`, `grades`); filters via `?cat=all\|items\|pets\|keys\|grades`. |
| `/animaux`, `/pets` | `GET` | `302` redirect | Redirects to `/boutique?cat=pets`. |
| `/objets`, `/items` | `GET` | `302` redirect | Redirects to `/boutique?cat=items`. |
| `/grades` | `GET` | `302` redirect | Redirects to `/boutique?cat=grades`. |
| `/caisses`, `/crates`, `/cles` | `GET` | `302` redirect | Redirects to `/boutique?cat=keys`. |
| `/shop` | `GET` | `302` redirect | Redirects to `/boutique`. |
| `/marche`, `/marche/`, `/marche-minerais`, `/bourse`, `/hdv` | `GET` | `marche.html` (`200`) | Mineral exchange displaying `6` static minerals (`netherite`, `diamond`, `emerald`, `gold`, `amethyst`, `iron`). |
| `/joueurs` | `GET` | `players.html` (`200`) | Leaderboards (`top_rich`, `top_hours`) and default player card (`AetherKnight`) with `mc-heads.net` renders. |
| `/admin` | `GET` | `admin.html` (`200`) | Server manifest generator cockpit and recent in-memory order history (`ORDERS_HISTORY`). |
| `/favicon.ico` | `GET` | `204 No Content` | Empty icon response. |

### Store & RCON Delivery Pipeline

When a user checks out via `POST /api/store/checkout`, `store_service.py` sanitizes the Minecraft username with `sanitize_minecraft_username` (stripping everything outside `[a-zA-Z0-9_]`, falling back to `"Steve"` if under `3` characters, and truncating to `16` characters to prevent CWE-78/CWE-89 command injection).

`RconClient` (`services/rcon_service.py`) then connects over TCP using the binary Valve/Minecraft RCON protocol (`SERVERDATA_AUTH = 3`, `SERVERDATA_EXECCOMMAND = 2`, 3-second timeout):

* **Environment variables**: `AETHER_RCON_HOST` (`127.0.0.1`), `AETHER_RCON_PORT` (`25575`), `AETHER_RCON_PASSWORD` (`aether2026`).
* **Offline fallback**: If the Minecraft server is unreachable, `dispatch_order_commands` returns `"QUEUED_PENDING_SERVER"` and appends the commands under a `threading.Lock()` to `apps/aethercraft/control-plane/.aether_pending_deliveries.json`.

## Control Plane API Endpoints

### Store Cart & Checkout (HTMX Partials)

#### 🎮 Endpoint

```http
POST /api/store/cart/add
POST /api/store/cart/remove
POST /api/store/cart/clear
POST /api/store/checkout
```

#### 📝 Parameters

| Endpoint | Form Parameter (`application/x-www-form-urlencoded`) | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `/api/store/cart/add` | `item_id` | `string` | — | Catalog item ID (for example `item_elytra_celestial`, `rank_aether`). |
| `/api/store/cart/remove` | `item_id` | `string` | — | Removes the first matching item from `session["cart"]`. |
| `/api/store/cart/clear` | *(none)* | — | — | Empties `session["cart"]`. |
| `/api/store/checkout` | `username` | `string` | `"Steve"` | Target Minecraft player name (sanitized to 3–16 alphanumeric/`_` chars). |

#### 💎 Response

| Status | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `text/html` | Rendered `partials/cart.html` fragment with updated `cart`, `cart_total`, and (on checkout) `order_success`. |

#### 💡 Example

```bash
curl -s -c cookies.txt -b cookies.txt -X POST "http://127.0.0.1:5000/api/store/cart/add" \
  -d "item_id=rank_vip"

curl -s -c cookies.txt -b cookies.txt -X POST "http://127.0.0.1:5000/api/store/checkout" \
  -d "username=AetherKnight"
```

### Player Search (`POST /api/players/search`)

#### 🎮 Endpoint

```http
POST http://127.0.0.1:5000/api/players/search
```

#### 📝 Parameters

| Parameter | Source | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `username` | Form data | `string` | `"Steve"` | Case-insensitive lookup in `MOCK_PLAYERS` (`AetherKnight`, `PixelSorceress`, `VortexCrafter`, `ShadowRanger`, `Notch`), or dynamic fallback profile. |

#### 💎 Response

| Status | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `text/html` | Rendered `partials/player_card.html` fragment with rank, hours played, balance, K/D, and `mc-heads.net` avatar URLs. |

#### 💡 Example

```bash
curl -s -X POST "http://127.0.0.1:5000/api/players/search" \
  -d "username=AetherKnight"
```

### Generate Server Manifest (`POST /api/v1/servers/generate`)

#### 🎮 Endpoint

```http
POST http://127.0.0.1:5000/api/v1/servers/generate
```

#### 📝 Parameters

| Parameter | Source | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `name` | Form data | `string` | `"Serveur Minecraft"` | Display name used to derive `server_id` (`srv_<slug>_<6hex>`). |
| `core_type` | Form data | `string` | `"paper"` | Server core (`"paper"` queries `api.papermc.io` with 5s timeout and falls back to build `118`; `"purpur"` uses build `2300`). |
| `mc_version` | Form data | `string` | `"1.21.1"` | Minecraft version (`"1.21.1"` or `"1.20.4"`). |
| `ram_gb` | Form data | `integer` | `4` | Heap allocation in GB (used to generate `-Xms{ram_gb}G` / `-Xmx{ram_gb}G` plus 15 Aikar G1GC flags). |
| `port` | Form data | `integer` | `25565` | Server listen port written into `server.properties`. |
| `difficulty` | Form data | `string` | `"normal"` | World difficulty (`"hard"`, `"normal"`, `"easy"`). |
| `plugins` | Form data (multi) | `string[]` | `[]` | Any combination of `"chunky"`, `"spark"`, `"luckperms"`. |

#### 💎 Response

| Status | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `text/html` | HTML summary card containing the manifest URL (`/api/v1/servers/{server_id}/manifest`) and copyable `cargo run ... -- install-and-run --manifest ...` command. |

#### 💡 Example

```bash
curl -s -X POST "http://127.0.0.1:5000/api/v1/servers/generate" \
  -d "name=Survival+One" \
  -d "core_type=paper" \
  -d "mc_version=1.21.1" \
  -d "ram_gb=6" \
  -d "plugins=chunky" \
  -d "plugins=spark"
```

### Retrieve Server Manifest (`GET /api/v1/servers/<server_id>/manifest`)

#### 🎮 Endpoint

```http
GET http://127.0.0.1:5000/api/v1/servers/{server_id}/manifest
```

#### 📝 Parameters

| Parameter | Source | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `server_id` | Path | `string` | Yes | Identifier returned by `/api/v1/servers/generate`. If absent from `MANIFEST_STORE`, the endpoint auto-generates and caches a default Paper `1.21.1` manifest (`4G` RAM, `chunky` + `spark`, `hard`). |

#### 💎 Response

| Status | Content-Type | Description |
| :--- | :--- | :--- |
| `200 OK` | `application/json` | Full Aether MC Manifest v1.0 JSON including `runtime`, `core`, `plugins_and_mods`, and `configs` (`eula.txt`, `server.properties`, and the 5-file `world/datapacks/aether_sanctuary/` datapack). |

#### 💡 Example

```bash
curl -s "http://127.0.0.1:5000/api/v1/servers/default/manifest"
```

### Server Ping & Health (`GET /api/v1/server/ping`, `GET /api/v1/health`)

#### 🎮 Endpoint

```http
GET http://127.0.0.1:5000/api/v1/server/ping
GET http://127.0.0.1:5000/api/v1/health
```

#### 📝 Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| *(none)* | — | — | Both endpoints take no query or body parameters. |

#### 💎 Response

| Endpoint | Status | Payload Fields |
| :--- | :--- | :--- |
| `/api/v1/server/ping` | `200 OK` JSON | `status`, `ip`, `port`, `local_ip`, `motd`, `version`, `players_online`, `players_max`, `ping_ms`, `tps`, `runner_cmd`. |
| `/api/v1/health` | `200 OK` JSON | `{"status": "ok", "service": "aether-mc-control-plane", "modules": ["store", "players", "server_creator"]}`. |

#### 💡 Example

```bash
curl -s "http://127.0.0.1:5000/api/v1/health"
```

## Aether MC Manifest Specification (v1.0)

Both `docs/AETHER_MC_MANIFEST_SPEC.md` and `apps/aethercraft/runner/src/manifest.rs` define the v1.0 JSON contract consumed by `aether-mc-runner`:

{% code title="test_manifest.json (v1.0 excerpt)" overflow="wrap" %}
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

When `AetherInstaller::install` (`apps/aethercraft/runner/src/installer.rs`) processes a manifest, it enforces:

* **CWE-22 path traversal checks**: Rejects `..`, leading `/`, or leading `\` in `core.target_jar` and `configs` keys, and rejects `..` in `artifact.name` and `artifact.target_dir`.
* **Streaming SHA-256 verification**: Streams downloads chunk-by-chunk through `sha2::Sha256`. If `sha256` is non-empty and does not match (case-insensitive hex), the downloaded file is deleted immediately and installation aborts. If `sha256` is `""`, the runner logs the first 8 hex characters and proceeds.
* **Manifest persistence**: Serializes the applied manifest to `<instance_dir>/.aether-manifest.json` so subsequent `aether-mc-runner run --dir <dir>` calls can work offline.

{% hint style="info" %}
Although `apps/aethercraft/runner/Cargo.toml` lists `blake3 = "1.5"` in its dependencies, `installer.rs` exclusively uses `sha2::Sha256` to match the PaperMC API and the manifest's `sha256` field.
{% endhint %}

## Rust Runner Supervision (`aether-mc-runner`)

`aether-mc-runner` exposes 4 subcommands (`install`, `run`, `install-and-run`, `doctor`) documented in full in the CLI reference. During `AetherRunner::run` (`apps/aethercraft/runner/src/runner.rs`):

1. Verifies Java availability via `java -version` and checks that `<instance_dir>/<core.target_jar>` exists.
2. Filters `manifest.runtime.jvm_flags` so only flags starting with `-` and free of shell metacharacters (`; | & \` $ > < \r \n`) are passed directly to `tokio::process::Command::new("java")` (no shell wrapper).
3. Streams and tags `stdout` lines in real time: `[MC-WARN]` (contains `WARN`), `[MC-ERR]` (contains `ERROR`), `✨ [MC-READY]` (contains `Done (`), or `[MC]`, and tags `stderr` lines as `[MC-STDERR]`.

{% hint style="warning" %}
`runner.rs` passes `manifest.runtime.jvm_flags` directly to `java` rather than synthesizing `-Xms`/`-Xmx` from `heap_min`/`heap_max`. Always include `-Xms` and `-Xmx` inside `jvm_flags` (the Flask generator does this automatically).
{% endhint %}

## Known Implementation Notes

* **Volatile in-memory stores**: `MANIFEST_STORE` and `ORDERS_HISTORY` live in Python process memory and reset when `app.py` restarts. Only pending RCON deliveries persist in `.aether_pending_deliveries.json`.
* **Manual queue flush**: `rcon_service.flush_pending_queue()` exists to drain `.aether_pending_deliveries.json` once RCON comes online, but `app.py` does not schedule or expose a route for it automatically.
* **Simulated live ping**: `server_status_service.py` returns simulated player counts (`118`–`142`) and ping (`18`–`34 ms`) rather than querying a live Minecraft socket.
* **Legacy/unused control-plane files**: `models/*.py` dataclasses and `templates/dashboard.html` remain in the directory for reference and are not invoked by `app.py`.
* **Artifact path validation**: In `installer.rs`, `plugins_and_mods` checks `.contains("..")` without checking leading `/` or `\`; keep `target_dir` and `name` strictly relative in custom manifests.

{% content-ref url="../console/plugin-and-mcp-clis.md" %}
[aether-plugin-tool, aetherscope-mcp & aether-mc-runner CLIs](../console/plugin-and-mcp-clis.md)
{% endcontent-ref %}

{% content-ref url="../console/launchers-and-scripts.md" %}
[Launchers, Installers & CI/CD Workflows](../console/launchers-and-scripts.md)
{% endcontent-ref %}

{% content-ref url="arch-scaffolder.md" %}
[Multi-Stack Architecture Scaffolder](arch-scaffolder.md)
{% endcontent-ref %}
