# Network Attack Surface Scanner

Audit live HTTP/TCP endpoints with a non-destructive 4-level black-box scanner (`POST /api/surface_scan`) that scores security posture (`0–100`, `A+`–`F`), redacts exposed CWE-538 secrets (`******** [MASQUÉ]`), and links external vectors back to local AST symbols.

Implemented in `crates/desktop-shell/src/surface_scanner.rs` and `surface_probes.rs`, the scanner pairs an external **Side-1** black-box reconnaissance pass with **Side-2** AST handler correlation inside `SurfaceScannerModal.svelte`.

{% hint style="success" %}
**Non-Destructive by Design**: The scanner emits only read-only HTTP verbs (`GET`, `HEAD`, `OPTIONS`) and lightweight TCP banner probes. It never sends mutating requests (`POST`, `PUT`, `DELETE`) or SQLi/XSS fuzzing payloads.
{% endhint %}

---

## API Endpoint (`POST /api/surface_scan`)

Trigger a surface scan over the local Axum API (`127.0.0.1:3030`) or directly from the Cockpit Surface Scanner modal.

### 🎮 Endpoint

```http
POST http://127.0.0.1:3030/api/surface_scan
```

* **TypeScript Client**: `api.surfaceScan(req)` (`crates/desktop-shell/ui/src/lib/api.ts`)
* **Protection**: `LocalGuard` (`Host`, `Origin`, and `Sec-Fetch-Site` validation)
* **Telemetry Side Effect**: Updates `state.telemetry` with action `"Scan Surface (<grade>)"` and summary counts (`Score`, `IP(s)`, `open_ports`, `findings`).

### 📝 Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | **Yes** | Hostname, IPv4/IPv6 (`[::1]:port`), `host:port`, `host/path`, or `http(s)://` URL. Schemes auto-upgrade to `https` when omitted on ports `443` or `8443`. |
| `scan_level` | `integer` | No | Depth `1..=4` (clamped to `1..=4`, default `4`). |
| `check_dns` | `boolean` | No | Enable DNS resolution and IP classification (default `true`). |
| `check_ports` | `boolean` | No | Enable TCP port scan and banner grabbing (default `scan_level >= 2`). |
| `check_headers` | `boolean` | No | Enable HTTP security header audit (default `true`). |
| `check_endpoints` | `boolean` | No | Enable `/.well-known/security.txt`, `/robots.txt`, and `OPTIONS` probing (default `scan_level >= 2`). |
| `check_web_forms` | `boolean` | No | Enable HTML form, DOM, and JS route extraction (default `scan_level >= 3`). Note: HTML discovery also runs whenever HTTP returns a non-empty body (`check_web_forms \|\| !body.is_empty()`). |
| `check_sensitive_files` | `boolean` | No | Enable Level 4 CWE-538 artifact probes (default `scan_level >= 4`). |
| `custom_ports` | `string` | No | Additional TCP ports separated by commas, spaces, or semicolons. |

### 💎 Response

| Status | Field | Type | Description |
|---|---|---|---|
| `200 OK` | `status` / `target_raw` / `host` / `scheme` / `primary_port` | mixed | Scan status and parsed target components. |
| `200 OK` | `target_classification` / `resolved_ips` / `dns_latency_ms` | mixed | Network classification (`Loopback`, `RFC 1918`, `Link-Local`, `Public`, `IPv6`) and DNS metrics. |
| `200 OK` | `scan_duration_ms` / `security_score` / `grade` / `http_status` | mixed | Total elapsed time, score (`0..100`), grade (`A+`..`F`), and initial HTTP status line. |
| `200 OK` | `impact_matrix` | `ImpactVisibilityMatrix` | Level metadata, packet footprint estimate, and discovered surface counts. |
| `200 OK` | `tech_stack` / `open_ports` / `headers_audit` / `raw_headers` | mixed | Fingerprinted stack, TCP ports/banners, 6 header audits, and raw response headers. |
| `200 OK` | `web_discovery` | `WebArchitectureDiscovery \| null` | Extracted `<form>`s, routes, external scripts, `web_files`, `directories`, `html_links`, and `path_tree`. |
| `200 OK` | `exposed_artifacts` | `ExposedArtifactProbe[]` | Results for the 8 Level 4 CWE-538 checks with redacted previews. |
| `200 OK` | `trust_zones` / `verification_suite` | array | 4 `TrustZoneSummary` swimlanes and 3 copy-pasteable `curl` CI checks. |
| `200 OK` | `boundary_weaknesses` / `findings` | array | Side-1 to Side-2 `BoundaryWeaknessProbe` cards and CWE findings. |

### 💡 Example

{% tabs %}
{% tab title="curl (Self-Scan)" %}
```bash
curl -s -X POST http://127.0.0.1:3030/api/surface_scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://127.0.0.1:3030","scan_level":4,"custom_ports":"3333"}'
```
{% endtab %}
{% tab title="JSON Response (Excerpt)" %}
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

## The 4 Progressive Scan Levels

Each level expands the probe surface and network footprint (`ImpactVisibilityMatrix`):

| Level | Name | Est. Footprint | Default Modules Active |
|---|---|---|---|
| **1** | Stealth & Passive Footprint | `~2–3 TCP packets` | DNS/IP classification + 6 HTTP security headers (port scan off by default; if enabled, probes only `[primary_port]` without banners). |
| **2** | Services, Banners & Versions | `~12–18 TCP packets` | Level 1 + 10 TCP ports + banner grabbing + tech fingerprinting + `OPTIONS` verb check + `robots.txt` & `security.txt`. |
| **3** | Full Black-Box Web & Forms | `~25–35 TCP/HTTP packets` | Level 2 + 15 TCP ports + `/api/health` + `<form>`/SPA grouping + DOM/JS/API route extraction + directory listing (`CWE-548`). |
| **4** | Exposure Audit (CWE-538 Masked) | `~35–45 TCP/HTTP packets` | Level 3 + 8 sensitive root artifact probes (`/.env`, `/.git/HEAD`, etc.) with Anti-Soft-404 filtering and value redaction. |

### Level 1 — DNS Classification & HTTP Security Headers

* **DNS & IP Classification**: Resolves hostnames via `tokio::net::lookup_host` (`1500 ms` timeout) into `Loopback 127.0.0.0/8`, `RFC 1918 Private`, `Link-Local / Cloud Metadata 169.254.0.0/16`, `Surface WAN / IP Publique`, `::1`, or `Surface IPv6`. Emits `SURFACE-DNS-UNRESOLVED` (`CWE-706`, `HIGH`) on resolution failure or `SURFACE-DNS-REBIND-PRIVATE-IP` (`CWE-350`, `HIGH`) when a non-local hostname resolves to a private/loopback IP.
* **HTTP Header Audit**: Probes candidate ports `[primary_port, 443, 80, 3030, 8080, 3000, 5000, 8000]` (stopping on first response) and evaluates 6 controls:
  1. `Content-Security-Policy` (`CWE-693`)
  2. `X-Content-Type-Options` (`CWE-16`)
  3. `X-Frame-Options` / CSP `frame-ancestors` (`CWE-1021`)
  4. `Strict-Transport-Security` (`CWE-319` — `WARN` on loopback/private, `FAIL` + finding on remote targets)
  5. `Access-Control-Allow-Origin` (`CWE-942` — detects reflection of `https://scanner-probe.aetherscope.local` or `*` paired with `Access-Control-Allow-Credentials: true`)
  6. `Server` / `X-Powered-By` version disclosure (`CWE-200`)

### Level 2 — Ports, Banners & Stack Fingerprinting

* **TCP Ports Probed**: `[22, 80, 443, 3000, 3030, 5000, 5432, 6379, 8080, 8443]` plus `primary_port` and `custom_ports`.
* **Banner Grabbing**: Sends `HEAD / HTTP/1.1` (`User-Agent: AetherScope-ServiceScanner/2.0`) on `[80, 3000, 3030, 5000, 8000, 8080, 9200]` and `PING\r\n` on `6379` (Redis), reading up to `512` bytes and truncating banners to `90` characters.
* **Exposed Datastores & Cleartext Ports (`CWE-284`)**: Emits `SURFACE-EXPOSED-DATA-PORT-<port>` with severity `CRITICAL` (`6379`, `27017`, `9200`, `23`) or `HIGH` (`5432`, `3306`, `21`).
* **Technology Fingerprinting**: Correlates HTTP headers, session cookies (`PHPSESSID`, `laravel_session`, `connect.sid`, `JSESSIONID`, `csrftoken`), DOM markers (`AetherScope V2`, Next.js `/_next/static`, Vue `data-v-`, Angular `ng-version`, WordPress `wp-content/`), `<meta name="generator">`, and port banners.

### Level 3 — Web Architecture, Forms & JS Routes

* **Expanded TCP Port List**: Adds `21`, `3306`, `8000`, `9200`, and `27017` (15 standard ports + `primary_port` + `custom_ports`).
* **Forms & Inputs**: Extracts `<form>`, `<input>`, `<textarea>`, `<select>`, and `<button>` elements, groups standalone SPA inputs outside `<form>` into up to 7 synthetic SPA form groups, and classifies fields (Anti-CSRF, Secret/Auth, File Upload, Email/User, Target/Path/URL, Prompt/SAST, Hidden, UI Selector, User Input). Flags `POST` forms lacking CSRF tokens (`CWE-352`), passwords in `GET` (`CWE-598`), passwords over non-loopback `http://` (`CWE-319`), and external `<script>` tags without SRI `integrity=` (`CWE-353`).
* **Routes, Assets & Directory Listing**: Probes `/api/health`, extracts `<a href>`, `<area href>`, `<link href>`, `<iframe src>`, `<img src>`, DOM `id="..."` anchors, JS `fetch()`/`axios` `/api/*`, `/v1/*`, `/v2/*`, `/graphql`, `/auth/*`, `/ws*` calls, up to 5 inline scripts `> 256` bytes, up to 6 local `.js`/`.css`/`.html`/`.json` assets, `JSON.stringify({...})` payload keys (up to 20 per asset), `//# sourceMappingURL=` (`CWE-540`), a `path_tree` capped at `90` nodes, and runs a `GET <first_dir>` directory listing check (`CWE-548`).

### Level 4 — Sensitive Artifact Probes (`CWE-538`) & Redaction

Level 4 probes **8 fixed paths** while applying **Anti-Soft-404 protection** (HTTP `200` responses starting with `<!doctype`, `<html`, or `Content-Type: text/html`—except `/server-status`—are marked `"200 Soft-404 (Protégé / Fallback SPA)"` with `exposed: false`):

| Path | Risk Level | Detection Rule & Redaction Behavior |
|---|---|---|
| `/.env` | `CRITICAL` | Requires uppercase `KEY=VALUE` lines; values are strictly redacted to `KEY=******** [MASQUÉ]` (max 5 keys previewed). |
| `/.env.local` | `CRITICAL` | Same `KEY=******** [MASQUÉ]` redaction. |
| `/.git/HEAD` | `CRITICAL` | Matches `ref: refs/` or 40-char hex SHA-1; previews first 48 chars without downloading Git objects. |
| `/docker-compose.yml` | `HIGH` | Matches `services:` + (`image:` or `build:`); hides environment values. |
| `/actuator/health` | `MEDIUM` | Matches `"status"` with `"up"` or `"down"`. |
| `/server-status` | `HIGH` | Matches `"apache server status"` or `"server version:"` (exempt from HTML fallback skip). |
| `/openapi.json` | `INFO` | Matches (`"openapi"` or `"swagger"`) + `"paths"`. |
| `/swagger.json` | `INFO` | Matches (`"openapi"` or `"swagger"`) + `"paths"`. |

Exposed findings with risk above `INFO` emit `SURFACE-EXPOSED-ARTIFACT-*` (`CWE-538`).

---

## Timeouts & Transport Quirks

| Probe Phase | Timeout / Limit | Implementation Notes |
|---|---|---|
| DNS `lookup_host` | `1500 ms` | Tokio async timeout per target scan. |
| TCP Port Connect | `360 ms` | Parallel port probing in `probe_single_port`. |
| TCP Banner Write / Read | `250 ms` HTTP / `200 ms` Redis; `280 ms` read (`512 B`) | Truncates extracted banner preview to `90` characters. |
| Plain HTTP/1.1 TCP Probe | `1100 ms` connect; `700 ms` write; `450 ms`/chunk, `2800 ms` total (`3.5 MB` cap) | Sends `Origin: https://scanner-probe.aetherscope.local` first; retries without `Origin` on `403` so `LocalGuard` self-scans succeed. |
| HTTPS / Redirect Probe | `4200 ms` Tokio timeout | Shells out to `curl -sSi -L --max-redirs 4 -k -m 4` (`curl` must be in `PATH`; uses `-k` for self-signed TLS inspection). |

{% hint style="warning" %}
**Self-Signed TLS & `curl` Requirement**: HTTPS targets (`https://`, ports `443`/`8443`, or `30x` redirects) invoke the external `curl` binary with `-k` so local self-signed certificates can still be audited for headers and DOM structure.
{% endhint %}

---

## Posture Score, Trust Zones & Side-1 -> Side-2 AST Linking

### Posture Score & Grade Formula

Starting from `100`, each finding deducts a severity penalty (clamped to `0`):
* `CRITICAL`: `-28` | `HIGH`: `-16` | `MEDIUM`: `-8` | `LOW`: `-4` | `INFO`: `0`

| Score Range | `92–100` | `84–91` | `74–83` | `60–73` | `45–59` | `0–44` |
|---|---|---|---|---|---|---|
| **Grade** | `A+` | `A` | `B` | `C` | `D` | `F` |

### 4 Trust Zones & Defensive Verification Suite

Every scan summarizes posture across 4 Trust Zone swimlanes (`trust_zones`) and outputs 3 reproducible `curl` CI checks (`verification_suite`: `VERIFY-HEADERS-POSTURE`, `VERIFY-CORS-ISOLATION`, `VERIFY-DOTFILES-BLOCKED`):
1. **Zone 1 — Client & Files (`.html`/`.js`)**: CSP & Anti-Clickjacking.
2. **Zone 2 — Inputs & Forms (`«Form»`)**: CSRF validation & secret transport.
3. **Zone 3 — Gateway, Directories & API**: CORS isolation & HSTS.
4. **Zone 4 — TCP Services & Dotfiles (`.env`/`.git`)**: CWE-538 exposure & version banners.

### Side-1 -> Side-2 AST Boundary Correlation

The backend generates up to 7 `BoundaryWeaknessProbe` categories pairing an external **Side-1** vector (`ROBUSTE`, `FAIBLESSE`, or `EXPOSÉ`) with a local **Side-2** AST handler target plus ready-to-run `positive_test_spec` and `negative_test_spec` contracts:
* `WEAKNESS-CORS-ORIGIN` (`CWE-942`) -> `Middleware CORS / CorsLayer`
* `WEAKNESS-HTTP-VERBS` (`CWE-650`, Level 2+) -> `Routeur HTTP / Table des Routes AST`
* `WEAKNESS-COOKIE-FLAGS` (`CWE-1004`) -> `Gestionnaire de Session / Auth Cookie Builder`
* `WEAKNESS-DIR-LISTING` (`CWE-548`, Level 3+) -> `ServeDir / Static File Handler`
* `WEAKNESS-FORM-<index>` (`CWE-352` / `CWE-20`, up to 4 forms) -> `Handler AST <action>`
* `WEAKNESS-JSON-CONTRACT-<path>` (`CWE-20 / CWE-88`, up to 5 JS/HTML assets) -> `Struct DTO / Deserializer & Sink AST`
* `WEAKNESS-SENSITIVE-ARTIFACTS` (`CWE-538`, Level 4) -> `Static routing filter / Dotfile isolation`

In the Cockpit UI (`SurfaceScannerModal.svelte`), `astBridgeItems` matches discovered `web_files` and `routes` directly against `cockpitState.graph.nodes` so you can click **Caméra 3D ➔** to jump to the backend handler, compare runs against a `localStorage` baseline (`aetherscope_surface_baseline_v2`), inspect the SVG Arched Call Graph (`ARC_DIAGRAM` / `TIERED_ARCS`), and send Side-1/Side-2 hardening prompts directly to the AI Copilot.

---

## Related Guides

{% content-ref url="./rest-api-security-plugins.md" %}
[REST API: Settings, Bounty, Surface & Plugins](./rest-api-security-plugins.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../core/security-confinement.md" %}
[Security Confinement & Guardrails](../core/security-confinement.md)
{% endcontent-ref %}

{% content-ref url="../core/cwe-sast-engine.md" %}
[CWE & SAST Engine](../core/cwe-sast-engine.md)
{% endcontent-ref %}
