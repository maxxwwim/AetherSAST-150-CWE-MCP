# Moteur de graphe spatial

Le moteur de graphe spatial transforme des arborescences polyglottes en un `AetherGraph` interactif doté de 4 dispositions mathématiques, d'une analyse d'accessibilité par BFS inverse et d'un transport WebGL compact.

## Vue d'ensemble

Lorsqu'`aether-engine` analyse un dépôt, `ast-scanner` (`ProjectScanner`) parse les fichiers en parallèle avec `rayon` et construit un `AetherGraph` unifié défini dans `core-graph`. Chaque fichier, classe, point d'entrée, contrat et fonction devient un nœud `SymbolBubble` relié par des arêtes typées `AffiliationEdge`.

Avant de transmettre le graphe au cockpit desktop ou aux clients API headless, le moteur exécute quatre étapes déterministes :

1. **Extraction polyglotte** : Analyse 11 langages/formats (32 extensions de fichiers) tout en respectant `SecretGuard`, les limites de taille et les exclusions projet.
2. **Liaison inter-fichiers et galaxies** : Résout les imports, appels, ponts HTTP `NetworkRPC`, sockets `RealtimeWS` et violations `[CROSS_GALAXY_VIOLATION]`.
3. **Calcul des 4 dispositions** : Calcule les coordonnées déterministes `Z-1` à `Z-4` dans `LayoutPositions` via `compute_all_layouts`.
4. **Accessibilité et code mort** : Exécute un BFS inverse `compute_reachability` depuis les puits SAST/CWE vers les points d'entrée et marque les symboles inaccessibles hors UI/docs.

{% hint style="info" %}
Tous les types centraux du graphe résident dans `crates/core-graph/src/` (`graph.rs`, `bubble.rs`, `edge.rs`, `layout.rs`, `reachability.rs`), tandis que le scan et la résolution d'arêtes s'exécutent dans `crates/ast-scanner/src/scanner.rs`.
{% endhint %}

## Modèle de données du graphe

### `AetherGraph` et `GraphStats`

`AetherGraph` est le conteneur racine renvoyé par `ProjectScanner::scan_project` et sérialisé par `/api/graph` et `/api/export`.

| Structure | Champs clés | Rôle |
| :--- | :--- | :--- |
| `AetherGraph` | `project_name`, `project_path`, `generated_at`, `system_prompt`, `nodes`, `edges`, `stats`, `dataflow_graph` | Charge utile racine du graphe ; `system_prompt` provient de `AETHER_AI_RULES.md` et `dataflow_graph` contient l'état SSA optionnel. |
| `GraphStats` | `total_nodes`, `total_edges`, `files_scanned`, `rpc_count`, `realtime_count`, `violation_count`, `dead_code_count`, `elapsed_ms`, `layers`, `relations`, `sides` | Compteurs de télémétrie agrégés et cartes de distribution calculés par `AetherGraph::compute_stats()`. |

### `SymbolKind`, `SymbolBubble` et `SymbolMetadata`

Chaque nœud de `AetherGraph.nodes` est un `SymbolBubble` dont la couleur et le rayon par défaut dérivent directement de la variante `SymbolKind` (`crates/core-graph/src/bubble.rs`).

| Variante `SymbolKind` | ID numérique | Stéréotype | `symbol_type` | Couleur par défaut (RGBA) | Rayon par défaut |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Function` | `0` | `«Function»` | `function` | `[0.22, 0.74, 0.97, 1.0]` | `5.0` |
| `File` | `1` | `«File»` | `file` | `[0.63, 0.52, 0.95, 1.0]` | `14.0` |
| `ClassOrStruct` | `2` | `«Class»` | `class` | `[0.13, 0.77, 0.36, 1.0]` | `10.0` |
| `FormOrEndpoint` | `3` | `«Endpoint»` | `endpoint` | `[0.96, 0.62, 0.13, 1.0]` | `9.0` |
| `Contract` | `4` | `«Contract»` | `contract` | `[0.94, 0.27, 0.27, 1.0]` | `12.0` |

Chaque `SymbolBubble` porte sa classification architecturale (`galaxy` : `"contracts"`, `"client"`, `"server"`, `"data-nodes"` ou `"core"` ; `layer` : `"ui"`, `"action"`, `"domain"`, `"database"`, `"utility"`, `"config"` ou `"docs"`), sa connectivité (`in_degree`, `out_degree`, `stage_idx`), ses métriques (`complexity`, `lines_count`, `is_dead_code`, `has_security_violation`), sa position (`x`, `y`, `layouts`, `birth_time`) et `metadata: SymbolMetadata`.

`SymbolMetadata` stocke les détails AST et de gouvernance de chaque symbole :

* **Source et hachage** : `lines`, `file_type`, `raw_content`, `blake3_hash` (empreinte du contrat), `file_blake3_hash` (empreinte du fichier source), `lock_verified`.
* **Structure AST** : `methods: Vec<AstMethod>` (`name`, `args`, `returns`, `is_async`, `calls`, `docstring`) et `attributes: Vec<AstAttribute>` (`name`, `type`).
* **Gouvernance et alertes** : `ears_count`, `contract_folder`, `max_lines_limit`, `file_max_lines_override`, `violations` et `cve_anomalies: Vec<CveAnomalyRecord>` (`rule_id`, `cve_id`, `severity`, `line_number`, `file_path`, `message`, `transmitted_data`, `transmitted_type`, `remediation`, `is_reachable`, `exploit_path`, `taint_trace`).

### `AffiliationEdge`, `EdgeType` et `FilterAffiliation`

Les arêtes utilisent des drapeaux binaires `u32` (`FilterAffiliation`) afin que le cockpit WebGL et l'analyse d'accessibilité filtrent les relations en O(1) par masque binaire.

| Drapeau `FilterAffiliation` | Masque binaire | Valeur | Rôle visuel / sémantique |
| :--- | :--- | :--- | :--- |
| `PHYSICAL` | `1 << 0` | `1` | Topologie et imports directs de fichiers |
| `NETWORK_RPC` | `1 << 1` | `2` | Appel Formulaire/Fetch vers route serveur (laser orange) |
| `REALTIME_WS` | `1 << 2` | `4` | Paquet WebSocket ou appel Web3 on-chain (laser cyan) |
| `SEMANTIC` | `1 << 3` | `8` | Conventions de rôles et stéréotypes |
| `SECURITY_VIOLATES` | `1 << 4` | `16` | Violation de contrat, CVE ou inter-galaxies (rouge clignotant) |
| `DATABASE_QUERY` | `1 << 5` | `32` | Persistance DB et requêtes SQL (laser émeraude) |

`EdgeType` associe chaque relation à une chaîne `relation` canonique et un poids `weight` par défaut (`1.0` standard, `1.5` avertissement, `2.0` `NetworkRPC`, `2.5` `RealtimeWS`, `3.0` violation CVE) :

| Variante `EdgeType` | `relation` | `FilterAffiliation` typique |
| :--- | :--- | :--- |
| `Contains` | `"contains"` | `PHYSICAL` |
| `Import` | `"imports"` | `PHYSICAL` |
| `Call` | `"calls"` | `SEMANTIC` |
| `Render` | `"renders"` | `PHYSICAL` / `SEMANTIC` |
| `Inherit` | `"inherits"` | `SEMANTIC` |
| `Network` | `"network"` | `NETWORK_RPC` |
| `NetworkRPC` | `"submits"` | `NETWORK_RPC \| PHYSICAL` |
| `RealtimeWS` | `"realtime"` | `REALTIME_WS \| PHYSICAL` |
| `ContractBinding` | `"binds"` | `SEMANTIC` |
| `IllegalCrossGalaxy` | `"violates"` (ou `"warns"`) | `SECURITY_VIOLATES` |
| `Documents` | `"documents"` | `SEMANTIC` |
| `DatabaseQuery` | `"queries"` | `DATABASE_QUERY` |

### `CategorizedLiaisons`

Pour garder les handshakes IA et les panneaux d'inspection lisibles, `CategorizedLiaisons::from_edges` classe les arêtes entrantes et sortantes en 8 catégories `LiaisonCategory` et les formate via `to_compact_markdown(prefix, max_per_category)` :

| `LiaisonCategory` | Badge | Vecteur `CategorizedLiaisons` | Logique de correspondance |
| :--- | :--- | :--- | :--- |
| `FormSubmit` | `📝` | `form_submits` | `EdgeType::NetworkRPC` ou `relation == "submits"` |
| `NetworkHttp` | `🌐` | `network_http` | `EdgeType::Network` ou filtre `NETWORK_RPC` |
| `RealtimeWs` | `⚡` | `realtime_ws` | `EdgeType::RealtimeWS` ou filtre `REALTIME_WS` |
| `DatabaseQuery` | `🗄️` | `database_queries` | `EdgeType::DatabaseQuery` ou filtre `DATABASE_QUERY` |
| `SecurityAlert` | `🚨` | `violations` | `EdgeType::IllegalCrossGalaxy` ou filtre `SECURITY_VIOLATES` |
| `InternalCall` | `📦` | `internal_calls` | `Call` / `Import` / `Render` / `Inherit` / `Contains` internes |
| `ExternalDep` | `🏛️` | `external_deps` | `ContractBinding` ou cibles externes `std::` / `api::` / `crate::` |
| `Documentation` | `📖` | `internal_calls` (rendu) | `EdgeType::Documents` |

## `ProjectScanner` polyglotte et règles de filtrage

`ProjectScanner::scan_project_with_exclusions` découvre récursivement les fichiers candidats et exécute 11 analyseurs de langages/formats couvrant 32 extensions en parallèle.

| Analyseur | Extensions prises en charge | Comportement d'extraction clé |
| :--- | :--- | :--- |
| Rust | `rs` | Supprime les blocs inline `#[cfg(test)]` avant l'extraction des symboles et imports |
| TypeScript / JavaScript | `ts`, `tsx`, `js`, `jsx`, `mjs`, `cjs` | Extrait composants, fonctions, imports, appels `fetch`/routes et événements WebSocket |
| Python | `py` | Extrait classes, fonctions, imports et routes Flask/FastAPI |
| C / C++ | `cpp`, `hpp`, `cc`, `hh`, `cxx`, `hxx`, `c`, `h`, `inl` | Extrait fonctions, structs/classes et directives `#include` |
| Solidity / Yul | `sol`, `yul` | Extrait contrats, fonctions, modifiers et variables d'état |
| Markdown (Contrats) | `md` (`README.md` uniquement) | Parse le frontmatter YAML et les règles EARS ; conserve `raw_content` jusqu'à `32 768` octets |
| PHP | `php`, `phtml`, `php3`, `php4`, `php5`, `php7`, `phps` | Extrait classes, fonctions, inclusions et superglobales HTTP |
| Java | `java` | Extrait classes, méthodes, imports et annotations |
| Lua / Luau | `lua`, `luau` | Extrait modules, fonctions et événements distants Roblox |
| Zig | `zig` | Supprime les blocs `test` inline avant l'extraction des symboles |
| C# | `cs` | Extrait espaces de noms, classes, méthodes et attributs |

### Règles de filtrage et d'exclusion du scanner

Avant de parser un fichier, `ProjectScanner` applique des filtres déterministes de sécurité et de bruit (`crates/ast-scanner/src/scanner.rs`) :

* **Plafond de 1,5 Mo** : Les fichiers dont `meta.len() > 1_500_000` octets sont ignorés pour éviter les pics mémoire.
* **Blocage `SecretGuard`** : Tout chemin détecté par `SecretGuard::is_secret_path` (`.env*`, `.git`, `.ssh`, `.pem`, `.key`, credentials) est immédiatement ignoré.
* **Ignorer les `.md` hors README** : Tous les fichiers `.md` sauf `readme.md` (insensible à la casse) sont ignorés par `ast-scanner`.
* **Exclusion `.c/.h/.cpp/.py` dans un projet Rust** : Lorsque la racine contient `Cargo.toml`, `Cargo.lock`, `crates/` ou des manifestes `Cargo.toml` Tauri/workspace, `ast-scanner` ignore les fichiers `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx`, `.inl` et `.py` afin d'éviter d'analyser des bindings natifs vendored ou des scripts utilitaires.
* **Fichiers générés et de test** : Ignore `*.min.js`, `*.bundle.js`, `*.d.ts`, `build.rs`, `test.rs`, `tests.rs`, `temp_*`, `test_*`, `*_test.rs`, `*_tests.rs` et `*_check.rs`.
* **Dossiers exclus** : Ignore les dossiers commençant par `.`, `target`, `node_modules`, `dist`, `build`, `docs`, `doc`, `vendor`, `WebView2`, `*.tmp`, les chaînes d'outils et les `custom_exclusions` configurées.

### Liaison inter-fichiers et détection de type de projet

Lors de `resolve_graph_edges`, `ProjectScanner` relie les appels inter-fichiers, matérialise des nœuds `FormOrEndpoint` `api::<callee>` pour les appels réseau non résolus, connecte `routes_called` à `routes_declared` (`NetworkRPC` par correspondance de sous-chaîne normalisée en minuscules), connecte `ws_emits` à `ws_handlers` (`RealtimeWS`) et émet `IllegalCrossGalaxy` (`[CROSS_GALAXY_VIOLATION]`) lorsque `client` importe `server`/`data-nodes` ou que `contracts` importe `client`/`server`.

En parallèle du scan de code, `crates/obsidian-vault/src/detector.rs` exécute `detect_project_type` (échantillonnage jusqu'à `10` fichiers `.md` de `65 536` octets chacun, recherche `.obsidian/` jusqu'à la profondeur `2` et comptage sur 28 extensions de code) pour classer le projet en `PureObsidianVault`, `PureCode` ou `Mixed`.

{% content-ref url="../cockpit-ide/obsidian-dual-vision.md" %}
[Coffre Obsidian & Mode Dual-Vision](../cockpit-ide/obsidian-dual-vision.md)
{% endcontent-ref %}

## Les 4 dispositions mathématiques (`Z-1` à `Z-4`)

`compute_all_layouts` (`crates/core-graph/src/layout.rs`) précalcule quatre espaces de coordonnées pour chaque `SymbolBubble` afin que le changement de vue dans le cockpit soit instantané.

| Disposition | Champ | Modèle mathématique et constantes exactes | Cas d'usage optimal |
| :--- | :--- | :--- | :--- |
| **Z-1 Galaxie Obsidian** | `layouts.obsidian` | Grappes hiérarchiques par branche et dossier. Rayon de dossier : `((n.sqrt() * 95.0) + 90.0).clamp(150.0, 950.0)`. Sous-dossiers déployés en éventail (`sub_angle_spread = 0.68`). Dans chaque dossier, spirale de Fermat avec `r0 = 48.0`, `GOLDEN_ANGLE = 2.399_963_229_728_653` rad (~`137,507764°`) et `dist = 48.0 + ((i + 0.6) / n).sqrt() * (radius - 48.0)`. | Exploration spatiale par défaut selon la topologie des dossiers |
| **Z-2 Architecture Système** | `layouts.system` | 7 colonnes X par couche : `docs` (`-1050.0`), `ui` (`-760.0`), `config` (`-530.0`), `action` (`-300.0`), `domain` (`260.0`), `utility` (`540.0`), `database` (`820.0`), repli `0.0`. Sous-grille : `95.0` (X) × `105.0` (Y). | Inspection des frontières d'architecture en couches |
| **Z-3 Flux d'exécution DAG** | `layouts.flow` | 4 colonnes horizontales `stage_idx` (`(stage_idx - 1.5) * 560.0`, plaçant les étapes à `-840.0`, `-280.0`, `280.0`, `840.0`). Sous-grille : `90.0` (X) × `100.0` (Y). | Suivi du flux d'exécution des points d'entrée vers la persistance |
| **Z-4 Grille Classes UML** | `layouts.classes` | Grille matricielle centrée avec `cols = ((total_nodes * 1.4).sqrt().ceil()).max(2)` et espacement `380.0` (X) × `210.0` (Y). | Navigation uniforme dans les classes, structs et contrats |

Dans **Z-3 Flux d'exécution DAG**, `ProjectScanner` attribue `stage_idx` (`0..3`) de manière déterministe selon les degrés et couches :
* `stage_idx = 0` (**Entrypoint**) : `in_degree == 0 && out_degree > 0`
* `stage_idx = 1` (**Coordinator**) : `out_degree > 0 && in_degree > 0`
* `stage_idx = 3` (**Persistence**) : `layer == "database"` ou `name` contenant `"model"` (insensible à la casse)
* `stage_idx = 2` (**Processing**) : tous les autres nœuds

## Accessibilité par BFS inverse et détection de code mort

### BFS inverse (`compute_reachability`)

`compute_reachability` (`crates/core-graph/src/reachability.rs`) détermine si les détections SAST/CWE sont réellement joignables depuis un point d'entrée externe plutôt qu'isolées dans du code interne :

1. **Prédicat de source (`is_source_node`)** : Sélectionne les nœuds dont `kind == SymbolKind::FormOrEndpoint`, `stereotype` contient `"Endpoint"` ou `"Form"`, ou `id.starts_with("api::")`.
2. **Masque d'arêtes autorisé** : Construit une liste d'adjacence inverse `incoming_adj` uniquement sur les arêtes sans boucle dont `filters` recouvre `FilterAffiliation::NETWORK_RPC | FilterAffiliation::REALTIME_WS | FilterAffiliation::SEMANTIC`.
3. **Remontée et reconstruction du chemin** : Depuis chaque nœud contenant `cve_anomalies`, le BFS remonte `incoming_adj` jusqu'au premier `is_source_node`, reconstruit le chemin direct `exploit_path` (`Endpoint -> ... -> Sink`) et positionne `is_reachable = true`.
4. **Délégation au taint SSA** : Si une anomalie embarque `taint_trace: Some(trace)` issu du moteur SSA, `is_reachable` suit `trace.is_vulnerable && !trace.is_sanitized` et `exploit_path` utilise `trace.traversed_scoped_variables()`.

### Heuristique de code mort

Dans `AetherGraph::compute_stats()` (`crates/core-graph/src/graph.rs`), tout symbole vérifiant `layer != "ui" && layer != "docs" && in_degree == 0` reçoit `is_dead_code = true` et incrémente `stats.dead_code_count`.

## Charge utile UI compacte (`ui_payload` et `decodeCompactGraph`)

Les grands monorépôts génèrent des centaines de milliers d'arêtes qui alourdissent la sérialisation JSON et la mémoire WebView2. `ui_payload::build_payload` (`crates/desktop-shell/src/api_routes.rs`) active automatiquement la compaction dès que `nodes.len() > 3_000` (`COMPACT_NODE_THRESHOLD`) ou `edges.len() > 20_000` (`COMPACT_EDGE_THRESHOLD`).

* **Toujours appliqué** : Supprime `metadata.raw_content`, vide `metadata.violations` lorsque `cve_anomalies` est non vide et omet `system_prompt` ainsi que `dataflow_graph`.
* **Lorsque `compact == true`** : Tronque `node.docstring` à `240` caractères, tronque `blake3_hash` et `file_blake3_hash` à `16` caractères hexadécimaux, limite `AstMethod.calls` à `8` entrées (`docstring` à `160` caractères) et remplace `edges` (`[]`) par `edges_compact: CompactEdges`.

{% code title="Format filaire CompactEdges et décodage client" overflow="wrap" %}
```json
{
  "nodes": [ { "id": "src/main.rs::main", "name": "main", "..." : "..." } ],
  "edges": [],
  "edges_compact": {
    "ids": ["api::/api/analyze"],
    "rels": ["submits", "calls"],
    "types": ["NetworkRPC", "Call"],
    "src": [0],
    "dst": [1],
    "rel": [0],
    "typ": [0],
    "extra": {
      "0": { "label": "/api/analyze", "weight": 2.0 }
    }
  }
}
```
{% endcode %}

Côté TypeScript (`crates/desktop-shell/ui/src/lib/graphCodec.ts`), `decodeCompactGraph(g)` résout les indices `< nodes.length` directement vers les références de chaînes `node.id` existantes (et `>= nodes.length` vers `edges_compact.ids`), fusionne les champs épars `extra[i]` via `Object.assign` et supprime `edges_compact` avant de renvoyer un `AetherGraph` standard.

### 🎮 Signature / Endpoint

```http
GET /api/graph
Host: 127.0.0.1:3030
```

### 📝 Arguments / Paramètres

| Nom | Type | Requis | Description |
| :--- | :--- | :--- | :--- |
| `Host` | `Header (string)` | Oui | Doit correspondre à `127.0.0.1:<port>`, `localhost:<port>` ou `[::1]:<port>` (`LocalGuard`). |

### 💎 Valeur de retour / Réponse

| Statut / Champ | Type | Description |
| :--- | :--- | :--- |
| `200 OK` (`nodes`, `stats`) | `UiGraphPayload` | JSON `AetherGraph` complet ou compacté (`raw_content`, `system_prompt`, `dataflow_graph` omis). |
| `edges_compact` | `CompactEdges \| null` | Présent uniquement lorsque `nodes.len() > 3_000` ou `edges.len() > 20_000`. |

### 💡 Exemple

```bash
curl -s http://127.0.0.1:3030/api/graph | jq '{nodes: (.nodes | length), compact: (.edges_compact != null), stats: .stats}'
```

{% content-ref url="./ssa-dataflow-taint.md" %}
[Moteur Dataflow SSA & Taint](./ssa-dataflow-taint.md)
{% endcontent-ref %}

{% content-ref url="./blake3-governance.md" %}
[Cryptographie BLAKE3 & Gouvernance EARS](./blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-workspace-graph.md" %}
[API REST : Espace de travail, fichiers et graphe](../api-mcp/rest-api-workspace-graph.md)
{% endcontent-ref %}
