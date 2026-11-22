# Scanner de Surface d'Attaque Réseau

Auditez vos endpoints HTTP/TCP actifs avec un scanner black-box non destructif à 4 niveaux (`POST /api/surface_scan`) qui note la posture de sécurité (`0–100`, `A+`–`F`), masque les secrets CWE-538 exposés (`******** [MASQUÉ]`) et relie les vecteurs externes aux symboles AST locaux.

Implémenté dans `crates/desktop-shell/src/surface_scanner.rs` et `surface_probes.rs`, le scanner associe une reconnaissance externe **Côté 1** à une corrélation AST **Côté 2** directement dans `SurfaceScannerModal.svelte`.

{% hint style="success" %}
**Non destructif par conception** : Le scanner n'émet que des verbes HTTP en lecture seule (`GET`, `HEAD`, `OPTIONS`) et des sondes de bannières TCP légères. Aucune requête mutante (`POST`, `PUT`, `DELETE`) ni aucun payload de fuzzing SQLi/XSS n'est envoyé.
{% endhint %}

---

## Endpoint API (`POST /api/surface_scan`)

Déclenchez un scan de surface via l'API Axum locale (`127.0.0.1:3030`) ou depuis la modale Surface Scanner du Cockpit.

### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/surface_scan
```

* **Client TypeScript** : `api.surfaceScan(req)` (`crates/desktop-shell/ui/src/lib/api.ts`)
* **Protection** : `LocalGuard` (validation `Host`, `Origin` et `Sec-Fetch-Site`)
* **Effet de télémétrie** : Met à jour `state.telemetry` avec l'action `"Scan Surface (<grade>)"` et les compteurs (`Score`, `IP(s)`, `open_ports`, `findings`).

### 📝 Paramètres

| Nom | Type | Requis | Description |
|---|---|---|---|
| `target` | `string` | **Oui** | Nom d'hôte, IPv4/IPv6 (`[::1]:port`), `host:port`, `host/path` ou URL `http(s)://`. Le schéma passe automatiquement à `https` si omis sur les ports `443` ou `8443`. |
| `scan_level` | `integer` | Non | Profondeur `1..=4` (bornée à `1..=4`, défaut `4`). |
| `check_dns` | `boolean` | Non | Active la résolution DNS et la classification IP (défaut `true`). |
| `check_ports` | `boolean` | Non | Active le scan des ports TCP et la capture de bannières (défaut `scan_level >= 2`). |
| `check_headers` | `boolean` | Non | Active l'audit des en-têtes de sécurité HTTP (défaut `true`). |
| `check_endpoints` | `boolean` | Non | Active les sondes `/.well-known/security.txt`, `/robots.txt` et `OPTIONS` (défaut `scan_level >= 2`). |
| `check_web_forms` | `boolean` | Non | Active l'extraction des formulaires HTML, du DOM et des routes JS (défaut `scan_level >= 3`). Remarque : la découverte HTML s'exécute également dès que HTTP retourne un corps non vide (`check_web_forms \|\| !body.is_empty()`). |
| `check_sensitive_files` | `boolean` | Non | Active les sondes Niveau 4 CWE-538 sur les artefacts sensibles (défaut `scan_level >= 4`). |
| `custom_ports` | `string` | Non | Ports TCP supplémentaires séparés par virgules, espaces ou points-virgules. |

### 💎 Réponse

| Statut | Champ | Type | Description |
|---|---|---|---|
| `200 OK` | `status` / `target_raw` / `host` / `scheme` / `primary_port` | mixte | Statut du scan et composantes analysées de la cible. |
| `200 OK` | `target_classification` / `resolved_ips` / `dns_latency_ms` | mixte | Classification réseau (`Loopback`, `RFC 1918`, `Link-Local`, `Public`, `IPv6`) et latence DNS. |
| `200 OK` | `scan_duration_ms` / `security_score` / `grade` / `http_status` | mixte | Durée totale, score (`0..100`), note (`A+`..`F`) et ligne de statut HTTP initiale. |
| `200 OK` | `impact_matrix` | `ImpactVisibilityMatrix` | Métadonnées du niveau, estimation de paquets et compteurs de surface. |
| `200 OK` | `tech_stack` / `open_ports` / `headers_audit` / `raw_headers` | mixte | Technologies détectées, ports/bannières TCP, 6 contrôles d'en-têtes et en-têtes bruts. |
| `200 OK` | `web_discovery` | `WebArchitectureDiscovery \| null` | Formulaires `<form>`, routes, scripts externes, `web_files`, `directories`, `html_links` et `path_tree`. |
| `200 OK` | `exposed_artifacts` | `ExposedArtifactProbe[]` | Résultats des 8 vérifications Niveau 4 CWE-538 avec aperçus masqués. |
| `200 OK` | `trust_zones` / `verification_suite` | array | 4 couloirs `TrustZoneSummary` et 3 commandes `curl` de non-régression CI. |
| `200 OK` | `boundary_weaknesses` / `findings` | array | Sondes frontière Côté 1 vers AST Côté 2 (`BoundaryWeaknessProbe`) et alertes CWE. |

### 💡 Exemple

{% tabs %}
{% tab title="curl (Auto-Scan)" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/surface_scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://127.0.0.1:3030","scan_level":4,"custom_ports":"3333"}'
```
{% endtab %}
{% tab title="Réponse JSON (Extrait)" %}
```json
{
  "status": "ok",
  "host": "127.0.0.1",
  "scheme": "http",
  "primary_port": 3030,
  "target_classification": "Loopback (127.0.0.0/8)",
  "security_score": 92,
  "grade": "A+",
  "impact_matrix": {
    "scan_level": 4,
    "packets_sent_estimate": "~35-45 paquets TCP/HTTP"
  },
  "trust_zones": [
    { "zone_id": 1, "posture": "WARN" },
    { "zone_id": 2, "posture": "PASS" },
    { "zone_id": 3, "posture": "PASS" },
    { "zone_id": 4, "posture": "PASS" }
  ]
}
```
{% endtab %}
{% endtabs %}

---

## Les 4 Niveaux Progressifs de Scan

Chaque niveau élargit la surface sondée et l'empreinte réseau (`ImpactVisibilityMatrix`) :

| Niveau | Nom | Empreinte estimée | Modules actifs par défaut |
|---|---|---|---|
| **1** | Furtif & Empreinte Passive | `~2–3 paquets TCP` | Classification DNS/IP + 6 en-têtes de sécurité HTTP (scan de ports désactivé par défaut ; si activé manuellement, sonde uniquement `[primary_port]` sans bannières). |
| **2** | Services, Bannières & Versions | `~12–18 paquets TCP` | Niveau 1 + 10 ports TCP + capture de bannières + empreinte technologique + sonde `OPTIONS` + `robots.txt` & `security.txt`. |
| **3** | Black-Box Complet & Web/Forms | `~25–35 paquets TCP/HTTP` | Niveau 2 + 15 ports TCP + `/api/health` + `<form>`/regroupement SPA + extraction DOM/JS/API + test d'indexation de répertoires (`CWE-548`). |
| **4** | Audit d'Exposition (CWE-538 Masqué) | `~35–45 paquets TCP/HTTP` | Niveau 3 + 8 sondes d'artefacts sensibles (`/.env`, `/.git/HEAD`, etc.) avec filtrage Anti-Soft-404 et masquage des valeurs. |

### Niveau 1 — Classification DNS & En-têtes de sécurité HTTP

* **Classification DNS & IP** : Résout les hôtes via `tokio::net::lookup_host` (timeout `1500 ms`) en `Loopback 127.0.0.0/8`, `RFC 1918 Private`, `Link-Local / Cloud Metadata 169.254.0.0/16`, `Surface WAN / IP Publique`, `::1` ou `Surface IPv6`. Émet `SURFACE-DNS-UNRESOLVED` (`CWE-706`, `HIGH`) en cas d'échec ou `SURFACE-DNS-REBIND-PRIVATE-IP` (`CWE-350`, `HIGH`) si un nom non local pointe vers une IP privée ou loopback.
* **Audit des en-têtes HTTP** : Sonde les ports candidats `[primary_port, 443, 80, 3030, 8080, 3000, 5000, 8000]` (arrêt dès la première réponse) et vérifie 6 contrôles :
  1. `Content-Security-Policy` (`CWE-693`)
  2. `X-Content-Type-Options` (`CWE-16`)
  3. `X-Frame-Options` / CSP `frame-ancestors` (`CWE-1021`)
  4. `Strict-Transport-Security` (`CWE-319` — `WARN` sur loopback/privé, `FAIL` + alerte sur cible distante)
  5. `Access-Control-Allow-Origin` (`CWE-942` — détecte la réflexion de `https://scanner-probe.aetherscope.local` ou `*` avec `Access-Control-Allow-Credentials: true`)
  6. Fuite de version `Server` / `X-Powered-By` (`CWE-200`)

### Niveau 2 — Ports, Bannières & Empreinte Technologique

* **Ports TCP sondés** : `[22, 80, 443, 3000, 3030, 5000, 5432, 6379, 8080, 8443]` plus `primary_port` et `custom_ports`.
* **Capture de bannières** : Envoie `HEAD / HTTP/1.1` (`User-Agent: AetherScope-ServiceScanner/2.0`) sur `[80, 3000, 3030, 5000, 8000, 8080, 9200]` et `PING\r\n` sur `6379` (Redis), lit jusqu'à `512` octets et tronque la bannière à `90` caractères.
* **Bases & Ports en clair exposés (`CWE-284`)** : Émet `SURFACE-EXPOSED-DATA-PORT-<port>` avec une sévérité `CRITICAL` (`6379`, `27017`, `9200`, `23`) ou `HIGH` (`5432`, `3306`, `21`).
* **Empreinte technologique** : Corrèle les en-têtes HTTP, cookies de session (`PHPSESSID`, `laravel_session`, `connect.sid`, `JSESSIONID`, `csrftoken`), signatures DOM (`AetherScope V2`, Next.js `/_next/static`, Vue `data-v-`, Angular `ng-version`, WordPress `wp-content/`), `<meta name="generator">` et bannières TCP.

### Niveau 3 — Architecture Web, Formulaires & Routes JS

* **Liste de ports étendue** : Ajoute `21`, `3306`, `8000`, `9200` et `27017` (15 ports standards + `primary_port` + `custom_ports`).
* **Formulaires & Champs** : Extrait `<form>`, `<input>`, `<textarea>`, `<select>` et `<button>`, regroupe les champs SPA isolés hors `<form>` en jusqu'à 7 formulaires SPA synthétiques et classe chaque champ (Anti-CSRF, Secret/Auth, File Upload, Email/User, Target/Path/URL, Prompt/SAST, Hidden, UI Selector, User Input). Signale les `POST` sans jeton CSRF (`CWE-352`), les mots de passe en `GET` (`CWE-598`), les mots de passe sur `http://` non loopback (`CWE-319`) et les `<script>` externes sans SRI `integrity=` (`CWE-353`).
* **Routes, Ressources & Directory Listing** : Sonde `/api/health`, extrait `<a href>`, `<area href>`, `<link href>`, `<iframe src>`, `<img src>`, les ancres DOM `id="..."`, les appels JS `fetch()`/`axios` (`/api/*`, `/v1/*`, `/v2/*`, `/graphql`, `/auth/*`, `/ws*`), jusqu'à 5 scripts inline `> 256` octets, jusqu'à 6 ressources locales `.js`/`.css`/`.html`/`.json`, les clés `JSON.stringify({...})` (max 20 par fichier), `//# sourceMappingURL=` (`CWE-540`), un `path_tree` plafonné à `90` nœuds et une sonde `GET <first_dir>` contre l'indexation de répertoires (`CWE-548`).

### Niveau 4 — Sondes d'Artefacts Sensibles (`CWE-538`) & Masquage

Le niveau 4 sonde **8 chemins fixes** avec **protection Anti-Soft-404** (toute réponse HTTP `200` débutant par `<!doctype`, `<html` ou `Content-Type: text/html`—hors `/server-status`—est classée `"200 Soft-404 (Protégé / Fallback SPA)"` avec `exposed: false`) :

| Chemin | Sévérité | Règle de détection & Masquage |
|---|---|---|
| `/.env` | `CRITICAL` | Recherche des lignes `KEY=VALUE` en majuscules ; masque strictement les valeurs en `KEY=******** [MASQUÉ]` (max 5 clés affichées). |
| `/.env.local` | `CRITICAL` | Même masquage strict `KEY=******** [MASQUÉ]`. |
| `/.git/HEAD` | `CRITICAL` | Vérifie `ref: refs/` ou un SHA-1 hexadécimal de 40 caractères ; extrait les 48 premiers caractères sans télécharger d'objets Git. |
| `/docker-compose.yml` | `HIGH` | Vérifie `services:` + (`image:` ou `build:`) en masquant les variables d'environnement. |
| `/actuator/health` | `MEDIUM` | Vérifie `"status"` avec `"up"` ou `"down"`. |
| `/server-status` | `HIGH` | Vérifie `"apache server status"` ou `"server version:"` (exempté du filtre HTML Soft-404). |
| `/openapi.json` | `INFO` | Vérifie (`"openapi"` ou `"swagger"`) + `"paths"`. |
| `/swagger.json` | `INFO` | Vérifie (`"openapi"` ou `"swagger"`) + `"paths"`. |

Les artefacts exposés de niveau supérieur à `INFO` génèrent des alertes `SURFACE-EXPOSED-ARTIFACT-*` (`CWE-538`).

---

## Timeouts & Particularités de Transport

| Phase de sonde | Timeout / Limite | Détails d'implémentation |
|---|---|---|
| DNS `lookup_host` | `1500 ms` | Timeout asynchrone Tokio par scan. |
| Connexion port TCP | `360 ms` | Sondage parallèle dans `probe_single_port`. |
| Bannière TCP (écriture / lecture) | `250 ms` HTTP / `200 ms` Redis ; `280 ms` lecture (`512 o`) | Tronque l'aperçu de bannière à `90` caractères. |
| Sonde HTTP/1.1 TCP brute | `1100 ms` connect ; `700 ms` write ; `450 ms`/bloc, `2800 ms` total (`3,5 Mo` max) | Envoie d'abord `Origin: https://scanner-probe.aetherscope.local` ; réessaie sans `Origin` sur `403` pour permettre l'auto-scan `LocalGuard`. |
| Sonde HTTPS / Redirections | `4200 ms` timeout Tokio | Appelle `curl -sSi -L --max-redirs 4 -k -m 4` (`curl` requis dans le `PATH` ; `-k` autorise l'inspection des certificats auto-signés). |

{% hint style="warning" %}
**TLS auto-signé & Dépendance `curl`** : Les cibles HTTPS (`https://`, ports `443`/`8443` ou redirections `30x`) utilisent le binaire `curl` avec `-k` afin de pouvoir auditer les en-têtes et le DOM même avec un certificat auto-signé local.
{% endhint %}

---

## Score de Posture, Zones de Confiance & Lien AST Côté 1 -> Côté 2

### Score de posture & Barème

À partir de `100`, chaque alerte applique une pénalité selon sa sévérité (plancher à `0`) :
* `CRITICAL` : `-28` | `HIGH` : `-16` | `MEDIUM` : `-8` | `LOW` : `-4` | `INFO` : `0`

| Intervalle de score | `92–100` | `84–91` | `74–83` | `60–73` | `45–59` | `0–44` |
|---|---|---|---|---|---|---|
| **Note (Grade)** | `A+` | `A` | `B` | `C` | `D` | `F` |

### 4 Zones de Confiance & Suite de Vérification Défensive

Chaque scan synthétise la posture sur 4 couloirs `TrustZoneSummary` (`trust_zones`) et génère 3 commandes `curl` de vérification CI (`verification_suite` : `VERIFY-HEADERS-POSTURE`, `VERIFY-CORS-ISOLATION`, `VERIFY-DOTFILES-BLOCKED`) :
1. **Zone 1 — Client & Fichiers (`.html`/`.js`)** : CSP & Anti-Clickjacking.
2. **Zone 2 — Entrées & Formulaires (`«Form»`)** : Validation CSRF & transport des secrets.
3. **Zone 3 — Passerelle, Dossiers & API** : Isolation CORS & HSTS.
4. **Zone 4 — Services TCP & Fichiers (`.env`/`.git`)** : Dotfiles CWE-538 & bannières de versions.

### Corrélation Frontière Côté 1 -> Côté 2 AST

Le backend génère jusqu'à 7 catégories de `BoundaryWeaknessProbe` reliant un vecteur externe **Côté 1** (`ROBUSTE`, `FAIBLESSE` ou `EXPOSÉ`) à une cible AST **Côté 2** accompagnée de spécifications `positive_test_spec` et `negative_test_spec` :
* `WEAKNESS-CORS-ORIGIN` (`CWE-942`) -> `Middleware CORS / CorsLayer`
* `WEAKNESS-HTTP-VERBS` (`CWE-650`, Niveau 2+) -> `Routeur HTTP / Table des Routes AST`
* `WEAKNESS-COOKIE-FLAGS` (`CWE-1004`) -> `Gestionnaire de Session / Auth Cookie Builder`
* `WEAKNESS-DIR-LISTING` (`CWE-548`, Niveau 3+) -> `ServeDir / Static File Handler`
* `WEAKNESS-FORM-<index>` (`CWE-352` / `CWE-20`, max 4 formulaires) -> `Handler AST <action>`
* `WEAKNESS-JSON-CONTRACT-<path>` (`CWE-20 / CWE-88`, max 5 fichiers JS/HTML) -> `Struct DTO / Deserializer & Sink AST`
* `WEAKNESS-SENSITIVE-ARTIFACTS` (`CWE-538`, Niveau 4) -> `Filtre de routage statique / Isolation des dotfiles`

Dans l'interface du Cockpit (`SurfaceScannerModal.svelte`), `astBridgeItems` met en correspondance les `web_files` et `routes` découverts avec `cockpitState.graph.nodes` pour téléporter la caméra 3D (**Caméra 3D ➔**) directement sur le handler backend, comparer les scans avec une baseline `localStorage` (`aetherscope_surface_baseline_v2`), explorer le graphe en arcs SVG (`ARC_DIAGRAM` / `TIERED_ARCS`) et envoyer des prompts de durcissement au Copilote IA.

---

## Guides associés

{% content-ref url="./rest-api-security-plugins.md" %}
[API REST : Paramètres, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Confinement de sécurité & Garde-fous](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="../core/cwe-sast-engine.md" %}
[Moteur CWE & SAST](../core/cwe-sast-engine.md)
{% endcontent-ref %}
