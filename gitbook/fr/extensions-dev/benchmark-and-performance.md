# Benchmark et optimisation des performances

`aether-engine` combine le parallélisme natif Rust/Rayon, un cache AST incrémental BLAKE3, un format réseau compact pour les graphes et un niveau de détail WebGL 2 adaptatif (`low_memory_mode`) afin d'analyser de vastes dépôts tout en gardant le Cockpit 3D fluide.

## Exécuter le benchmark intégré (`--benchmark`)

Passez `--benchmark` pour mesurer le lexing, la construction de l'AST, l'évaluation SAST, le débit et le pic mémoire sur n'importe quel répertoire, éventuellement filtré par `--plugins`.

{% tabs %}
{% tab title="PowerShell (Windows)" %}
```powershell
# Lancer un benchmark complet sur le dépôt courant et générer BENCHMARK.md
.\aether-engine.exe --path . --benchmark

# Benchmarker avec un profil de plugins spécifique
.\aether-engine.exe --path C:\Projects\target-repo --benchmark --plugins default
```
{% endtab %}
{% tab title="bash (Linux / macOS)" %}
```bash
# Lancer un benchmark complet sur le dépôt courant et générer BENCHMARK.md
./aether-engine --path . --benchmark

# Benchmarker avec un sélecteur de plugins spécifique
./aether-engine --path /path/to/repo --benchmark --plugins profile:web3
```
{% endtab %}
{% endtabs %}

### Phases mesurées et `BenchmarkMetrics`

`benchmark_project_with_plugins` (`crates/desktop-shell/src/benchmark.rs`) exécute 4 phases chronométrées et renseigne `BenchmarkMetrics` :

1. **Découverte, comptage LOC et masquage lexical (`lexing_time_ms`)** : parcourt les fichiers sources (en ignorant `.git`, `target`, `.agents`, `node_modules`, `dist`, `.gemini`, `vendor`, `.idea`, `.vscode`, `.aether` et les Markdown autres que `README.md`), compte les lignes et exécute `Lang::from_path` + `mask_literals`.
2. **Construction AST parallèle sous Rayon (`ast_time_ms`)** : exécute `ProjectScanner::scan_project` sur l'ensemble des cœurs CPU.
3. **Évaluation SAST CWE (`cwe_time_ms`)** : répartit les fichiers sur `std::thread::available_parallelism().unwrap_or(4)` threads scopés et évalue `SecurityLinter::audit_file_selected` ainsi que les plugins déclaratifs actifs.
4. **Reachability et layouts (`total_time_ms`, `throughput_loc_s`, `peak_rss_mb`)** : finalise `compute_reachability` et `compute_all_layouts`, puis mesure le pic RSS :
   * **Windows** : `K32GetProcessMemoryInfo` (`peak_working_set_size`).
   * **Unix/Linux** : première ligne correspondante `VmHWM:`, `VmPeak:` ou `VmRSS:` dans `/proc/self/status`.

### Mesures de référence (`BENCHMARK.md`)

L'exécution de `aether-engine --benchmark` écrit `<project_root>/BENCHMARK.md`. Lors de l'exécution enregistrée dans le dépôt (`2026-11-18 10:50:23 UTC`), `aether-engine` a mesuré :

| Métrique | Valeur enregistrée (`BENCHMARK.md`) |
| :--- | :--- |
| **Fichiers analysés** | `157` fichiers |
| **Lignes de code (LOC)** | `89 843` lignes |
| **Temps Lexing & Masquage** | `151.45 ms` |
| **Temps Construction AST (Rayon)** | `104.36 ms` |
| **Temps Évaluation Règles CWE** | `462.45 ms` |
| **Temps Total d'Exécution** | **`723.28 ms`** |
| **Débit Global** | **`124 216 LOC/s`** |
| **Pic Mémoire RAM (Peak RSS)** | **`25.74 MB`** |
| **Violations & Anomalies** | `44` anomalies |

## Format de graphe compact (`UiGraphPayload`)

Lorsqu'il sert de grands graphes via HTTP (`GET /api/graph`), `crates/desktop-shell/src/api_routes.rs` réduit automatiquement la taille JSON et les allocations mémoire JavaScript.

```rust
pub const COMPACT_NODE_THRESHOLD: usize = 3_000;
pub const COMPACT_EDGE_THRESHOLD: usize = 20_000;

pub fn needs_compaction(g: &AetherGraph) -> bool {
    g.nodes.len() > COMPACT_NODE_THRESHOLD || g.edges.len() > COMPACT_EDGE_THRESHOLD
}
```

* **Toujours retiré des payloads UI** : `n.metadata.raw_content` est mis à `None`, `n.metadata.violations` est vidé dès que `cve_anomalies` n'est pas vide, et `system_prompt` / `dataflow_graph` sont omis.
* **Mode compact (`> 3 000` nœuds OU `> 20 000` arêtes)** :
  * Tronque `docstring` à `240` octets, `blake3_hash` et `file_blake3_hash` à `16` caractères, `m.calls` à `8` entrées et `m.docstring` à `160` octets.
  * Vide `graph.edges` et sérialise `edges_compact: CompactEdges` (`ids`, `rels`, `types`, `src`, `dst`, `rel`, `typ`, plus la table éparse `extra: HashMap<u32, CompactEdgeExtra>` pour les anomalies, le taint, les libellés ou `weight != 1.0`).
* **Cache serveur et contournement `?full=1`** : `AppState::ui_graph_cache` met en cache les octets JSON sérialisés par clé `(graph_version, nodes.len(), edges.len())`. Ajoutez `?full=1` (ou `?full=true`) à `/api/graph` lorsque des outils externes ou exports nécessitent le `AetherGraph` complet.
* **Décodeur UI sans duplication** : `decodeCompactGraph` (`crates/desktop-shell/ui/src/lib/graphCodec.ts`) reconstruit `edges` sur place en pointant `source` et `target` directement vers les références de chaînes `nodes[i].id` existantes, puis supprime `edges_compact`.

## Mode Basse Consommation (`low_memory_mode`)

Vous pouvez activer le mode basse consommation manuellement dans **Settings** (**« ⚡ Mode Petite Config & Basse Consommation RAM »**, persisté via `low_memory_mode: true` dans `<project_root>/.aether/settings.json`), ou laisser l'interface le déclencher automatiquement.

| Déclencheur / Composant | Seuil / Paramètre | Optimisation appliquée |
| :--- | :--- | :--- |
| `graphState.svelte.ts` (`isLowMemoryMode`) | `settings.lowMemoryMode` OU `nodes.length > 2 500` | Tronque `docstring` à `240` caractères et supprime `meta.raw_content` sur les fichiers non texte. |
| `graphState.svelte.ts` (chargement initial) | `normalizedNodes.length > 2 500` | Passe automatiquement `lodLevel = 1` et `settings.lowMemoryMode = true`. |
| `engine.ts` (DPR Canvas / WebGL) | `isLowMemoryMode == true` | Force `dpr = 1` au lieu de `Math.min(devicePixelRatio, 2)`. |
| `engine.ts` (`isDenseProject`) | `clusters.size > 45` OU `isLowMemoryMode` | Remplace les dégradés radiaux par des aplats, désactive `shadowBlur`, ignore la bicouche et le noyau LoD 2 hors sélection, plafonne les badges de dossier à `24` (vs `42`). |
| `engine.ts` (`isHuge` / `isEco`) | `edges.length > 3 500` OU `nodes.length > 2 200` | Plafonne les arêtes rendues à `900` (`zoom < 0.25`) ou `1 400` (`zoom >= 0.25`) et désactive les reflets en diamant. |

## Cache AST incrémental BLAKE3 et élagage du scanner

`ProjectScanner` (`crates/ast-scanner/src/scanner.rs`) accélère les analyses répétées grâce à un cache persistant et à des filtres intelligents :

* **Emplacement du cache AST** : `<project_root>/.aether/cache/ast/<entry_key>.json` (`use_cache = true` par défaut).
* **Formule de clé de cache** :
  ```text
  entry_key = BLAKE3("v1|" + rel_path + "|" + file_hash + "|" + contract_sig + "|" + plugin_digest)
  ```
  Les entrées sont écrites atomiquement via `.tmp_<entry_key>_<pid>_<rayon_tid>.json` suivi de `fs::rename`. Lorsque des règles de taint déclaratives sont actives (`has_taint_rules`), le contenu brut est conservé brièvement pour les passes SSA multi-fichiers `TaintExtractor`, puis immédiatement libéré.
* **Plafond de 1,5 Mo** : les fichiers dépassant strictement `1_500_000` octets sont ignorés avant l'analyse.
* **Élagage des projets Rust** : lorsque `Cargo.toml`, `Cargo.lock`, `crates/` ou des sous-manifests courants existent, le scanner ignore les fichiers `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx`, `.inl` et `.py`.
* **Exclusions intégrées et personnalisées** : ignore les segments cachés `.`, les chemins `WebView2`/`.tmp`, `114` répertoires intégrés (`node_modules`, `target`, `dist`, `vendor`, `docs`, etc.), les chemins sensibles `SecretGuard`, `.min.js`/`.bundle.js`/`.d.ts`, `*_test.rs`/`*_tests.rs`/`*_check.rs` et les Markdown autres que `README.md`. Ajoutez vos propres motifs (y compris avec jokers `*`) sous `exclusions` dans `.aether/settings.json`.

## Configuration du tas V8 WebView2

Sous Windows, `crates/desktop-shell/src/main.rs` configure l'instance WebView2 embarquée avec des arguments Chromium/V8 supplémentaires :

```text
--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --js-flags=--max-old-space-size=4096
```

L'option `--max-old-space-size=4096` porte la limite du tas JavaScript V8 de ~1,4–2 Go par défaut à 4 Go, évitant les pauses de garbage collection et les crashs mémoire sur les graphes spatiaux très denses.

{% hint style="success" %}
Pour obtenir les meilleures performances sur des monorepos polyglottes dépassant 100k LOC, conservez `.aether/cache/ast/` entre deux exécutions, excluez les dossiers de bundles générés dans `.aether/settings.json` et exécutez vos audits CI en mode headless via `--no-gui` ou `--audit-only`.
{% endhint %}

{% content-ref url="../core/graph-engine.md" %}
[Moteur de graphe spatial](../core/graph-engine.md)
{% endcontent-ref %}

{% content-ref url="../core/blake3-governance.md" %}
[Cryptographie BLAKE3 et gouvernance EARS](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[Cockpit Spatial WebGL 2](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="troubleshooting-faq.md" %}
[Dépannage et FAQ](troubleshooting-faq.md)
{% endcontent-ref %}
