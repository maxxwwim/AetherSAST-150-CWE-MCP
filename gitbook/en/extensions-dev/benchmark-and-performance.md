# Benchmark & Performance Tuning

`aether-engine` combines native Rust/Rayon parallelism, BLAKE3 incremental AST caching, compact wire-format graph compaction, and adaptive WebGL 2 Level-of-Detail (`low_memory_mode`) to scan large repositories and keep the 3D Cockpit responsive.

## Running the Built-in Benchmark (`--benchmark`)

Pass `--benchmark` to measure lexing, AST construction, SAST evaluation, throughput, and peak memory usage on any project directory, optionally filtered by `--plugins`.

{% tabs %}
{% tab title="PowerShell (Windows)" %}
```powershell
# Run full benchmark on the current repository and write BENCHMARK.md
.\aether-engine.exe --path . --benchmark

# Benchmark with a specific plugin profile
.\aether-engine.exe --path C:\Projects\target-repo --benchmark --plugins default
```
{% endtab %}
{% tab title="bash (Linux / macOS)" %}
```bash
# Run full benchmark on the current repository and write BENCHMARK.md
./aether-engine --path . --benchmark

# Benchmark with a specific plugin selector
./aether-engine --path /path/to/repo --benchmark --plugins profile:web3
```
{% endtab %}
{% endtabs %}

### Measured Phases & `BenchmarkMetrics`

`benchmark_project_with_plugins` (`crates/desktop-shell/src/benchmark.rs`) executes 4 timed stages and records `BenchmarkMetrics`:

1. **File Discovery, LOC Counting & Lexical Masking (`lexing_time_ms`)**: Walks source files (skipping `.git`, `target`, `.agents`, `node_modules`, `dist`, `.gemini`, `vendor`, `.idea`, `.vscode`, `.aether`, and non-`README.md` Markdown), counts lines, and runs `Lang::from_path` + `mask_literals`.
2. **Parallel Rayon AST Construction (`ast_time_ms`)**: Runs `ProjectScanner::scan_project` across CPU cores.
3. **CWE SAST Evaluation (`cwe_time_ms`)**: Chunks files across `std::thread::available_parallelism().unwrap_or(4)` scoped threads and evaluates `SecurityLinter::audit_file_selected` plus active declarative plugins.
4. **Reachability & Layouts (`total_time_ms`, `throughput_loc_s`, `peak_rss_mb`)**: Finalizes `compute_reachability` and `compute_all_layouts`, then samples Peak RSS:
   * **Windows**: `K32GetProcessMemoryInfo` (`peak_working_set_size`).
   * **Unix/Linux**: First matching `VmHWM:`, `VmPeak:`, or `VmRSS:` line from `/proc/self/status`.

### Baseline Measurements (`BENCHMARK.md`)

Running `aether-engine --benchmark` writes `<project_root>/BENCHMARK.md`. In the repository's recorded run (`2026-11-18 10:50:23 UTC`), `aether-engine` measured:

| Metric | Recorded Value (`BENCHMARK.md`) |
| :--- | :--- |
| **Files analyzed** | `157` files |
| **Lines of code (LOC)** | `89,843` lines |
| **Lexing & masking time** | `151.45 ms` |
| **AST construction time (Rayon)** | `104.36 ms` |
| **CWE rules evaluation time** | `462.45 ms` |
| **Total execution time** | **`723.28 ms`** |
| **Overall throughput** | **`124,216 LOC/s`** |
| **Peak RAM (Peak RSS)** | **`25.74 MB`** |
| **Violations & findings** | `44` anomalies |

## Compact Graph Wire Format (`UiGraphPayload`)

When serving large graphs over HTTP (`GET /api/graph`), `crates/desktop-shell/src/api_routes.rs` reduces JSON payload size and JavaScript memory allocation automatically.

```rust
pub const COMPACT_NODE_THRESHOLD: usize = 3_000;
pub const COMPACT_EDGE_THRESHOLD: usize = 20_000;

pub fn needs_compaction(g: &AetherGraph) -> bool {
    g.nodes.len() > COMPACT_NODE_THRESHOLD || g.edges.len() > COMPACT_EDGE_THRESHOLD
}
```

* **Always stripped on UI payloads**: `n.metadata.raw_content` is set to `None`, `n.metadata.violations` is cleared whenever `cve_anomalies` is non-empty, and `system_prompt` / `dataflow_graph` are omitted.
* **Compact mode (`> 3,000` nodes OR `> 20,000` edges)**:
  * Truncates node `docstring` to `240` bytes, `blake3_hash` and `file_blake3_hash` to `16` characters, `m.calls` to `8` entries, and `m.docstring` to `160` bytes.
  * Empties `graph.edges` and serializes `edges_compact: CompactEdges` (`ids`, `rels`, `types`, `src`, `dst`, `rel`, `typ`, and sparse `extra: HashMap<u32, CompactEdgeExtra>` for anomalies, taint, labels, or `weight != 1.0`).
* **Server cache & `?full=1` bypass**: `AppState::ui_graph_cache` caches the serialized JSON bytes keyed by `(graph_version, nodes.len(), edges.len())`. Append `?full=1` (or `?full=true`) to `/api/graph` when external tools or exports require the unstripped `AetherGraph`.
* **Zero-duplication UI decoder**: `decodeCompactGraph` (`crates/desktop-shell/ui/src/lib/graphCodec.ts`) reconstructs `edges` in-place by pointing `source` and `target` directly at existing `nodes[i].id` string references, then deletes `edges_compact`.

## Low-Memory Mode (`low_memory_mode`)

You can enable low-memory mode manually in **Settings** (**"⚡ Mode Petite Config & Basse Consommation RAM"**, persisted as `low_memory_mode: true` in `<project_root>/.aether/settings.json`), or let the UI activate it automatically.

| Trigger / Component | Threshold / Setting | Applied Optimization |
| :--- | :--- | :--- |
| `graphState.svelte.ts` (`isLowMemoryMode`) | `settings.lowMemoryMode` OR `nodes.length > 2,500` | Truncates `docstring` to `240` chars and drops `meta.raw_content` on non-text files. |
| `graphState.svelte.ts` (initial load) | `normalizedNodes.length > 2,500` | Sets `lodLevel = 1` and enables `settings.lowMemoryMode = true` automatically. |
| `engine.ts` (Canvas / WebGL DPR) | `isLowMemoryMode == true` | Forces `dpr = 1` instead of `Math.min(devicePixelRatio, 2)`. |
| `engine.ts` (`isDenseProject`) | `clusters.size > 45` OR `isLowMemoryMode` | Replaces radial gradients with flat fills, disables `shadowBlur`, skips phospholipid bilayer & LoD 2 nucleus on unselected nodes, caps folder pills at `24` (vs `42`). |
| `engine.ts` (`isHuge` / `isEco`) | `edges.length > 3,500` OR `nodes.length > 2,200` | Caps rendered edges at `900` (`zoom < 0.25`) or `1,400` (`zoom >= 0.25`) and disables diamond cross spark glints. |

## Incremental BLAKE3 AST Cache & Scanner Pruning

`ProjectScanner` (`crates/ast-scanner/src/scanner.rs`) speeds up repeated scans using a persistent cache and smart file filters:

* **AST Cache Location**: `<project_root>/.aether/cache/ast/<entry_key>.json` (`use_cache = true` by default).
* **Cache Key Formula**:
  ```text
  entry_key = BLAKE3("v1|" + rel_path + "|" + file_hash + "|" + contract_sig + "|" + plugin_digest)
  ```
  Cache files are written atomically via `.tmp_<entry_key>_<pid>_<rayon_tid>.json` and `fs::rename`. When declarative taint rules are active (`has_taint_rules`), raw content is retained briefly for multi-file SSA `TaintExtractor` passes and immediately dropped afterward.
* **1.5 MB File Size Cap**: Files strictly larger than `1_500_000` bytes are skipped before parsing.
* **Rust-Project Pruning**: When `Cargo.toml`, `Cargo.lock`, `crates/`, or common workspace sub-manifests exist, the scanner skips `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx`, `.inl`, and `.py` files.
* **Built-in & Custom Exclusions**: Skips hidden `.` segments, `WebView2`/`.tmp` paths, `114` built-in directories (`node_modules`, `target`, `dist`, `vendor`, `docs`, etc.), `SecretGuard` sensitive paths, `.min.js`/`.bundle.js`/`.d.ts`, `*_test.rs`/`*_tests.rs`/`*_check.rs`, and non-`README.md` Markdown files. Add custom patterns (including `*` wildcards) under `exclusions` in `.aether/settings.json`.

## WebView2 V8 Heap Configuration

On Windows, `crates/desktop-shell/src/main.rs` configures the embedded WebView2 instance with extra Chromium/V8 flags:

```text
--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --js-flags=--max-old-space-size=4096
```

Raising `--max-old-space-size=4096` extends the V8 JavaScript heap ceiling from the ~1.4–2 GB default to 4 GB, preventing garbage-collection stutters and out-of-memory crashes when rendering dense spatial graphs.

{% hint style="success" %}
For maximum performance on multi-language monorepos exceeding 100k LOC, keep `.aether/cache/ast/` intact between runs, exclude generated bundle folders in `.aether/settings.json`, and run headless CI audits with `--no-gui` or `--audit-only`.
{% endhint %}

{% content-ref url="../core/graph-engine.md" %}
[Spatial Graph Engine](../core/graph-engine.md)
{% endcontent-ref %}

{% content-ref url="../core/blake3-governance.md" %}
[BLAKE3 Cryptography & EARS Governance](../core/blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="../cockpit-ide/webgl-cockpit.md" %}
[WebGL 2 Spatial Cockpit](../cockpit-ide/webgl-cockpit.md)
{% endcontent-ref %}

{% content-ref url="troubleshooting-faq.md" %}
[Troubleshooting & FAQ](troubleshooting-faq.md)
{% endcontent-ref %}
