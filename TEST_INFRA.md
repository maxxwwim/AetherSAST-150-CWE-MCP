# Test Infrastructure Specification: AetherEngine SAST & SCA V3.0 (R1, R2, R3)

- **Version**: 3.0.0 (SAST, SSA Taint Tracking & Reachable SCA Track)
- **Status**: ACTIVE / TEST_INFRASTRUCTURE_SPECIFIED
- **Target Project Workspace**: `c:\Users\1234\Desktop\Projets\aether-engine`
- **Architect Working Directory**: `c:\Users\1234\Desktop\Projets\aether-engine\.agents\teamwork\teamwork_test_writer_v3_e2e_1\`
- **Test Locations**:
  1. `crates/desktop-shell/tests/e2e_r1_semgrep.rs` (R1: Community Rules, Downloader & Hot-Reload)
  2. `crates/desktop-shell/tests/e2e_r2_dataflow_ssa.rs` (R2: True Dataflow & SSA Taint Tracking)
  3. `crates/desktop-shell/tests/e2e_r3_reachable_sca.rs` (R3: Reachable SCA & OSV.dev Integration)
  4. `crates/desktop-shell/tests/e2e_tier3_tier4_scenarios.rs` (Tiers 3 & 4: Cross-Feature & Real-World Polyglot Projects)
- **Test Runner Framework**: Cargo native test harness (`cargo test`)
- **Authoritative Requirements**: `ORIGINAL_REQUEST.md` and `PROJECT.md`

---

## 1. Executive Summary & Test Philosophy

This test infrastructure establishes the comprehensive, opaque-box, 4-tier automated test harness for AetherScope V3.0. It rigorously validates the three major core requirements:
1. **R1: Semgrep Community Rules & Downloader**: Pre-embedded offline bundle execution in `.aether/plugins/`, `aether-plugin-tool download-semgrep-rules` CLI, native AST/regex conversion, and file-watcher hot-reload detection without requiring any Cloud account.
2. **R2: True Dataflow & SSA Taint Tracking**: Variable def-use SSA versioning (`SsaVar`), unsanitized Source->Sink variable identifier propagation with exact step-by-step trace (`TaintFlowTrace`), sanitizer neutralization logic preventing alert emission at Sink, and inter-procedural propagation across function calls and returns.
3. **R3: Reachable SCA & OSV.dev**: Multi-ecosystem lockfile parsing (`Cargo.lock`, `package-lock.json` v1/v2/v3, `composer.lock`), public OSV.dev integration with persistent local BLAKE3 disk caching in `.aether/cache/osv/` ensuring 100% offline air-gapped repeatability, and call-graph reachability cross-referencing differentiating reachable endpoints from dead dependencies.

### Core Testing Principles:
- **Opaque-Box Requirement-Driven**: Tests assert purely against documented contracts, inputs, outputs, CLI interfaces, and observable anomalies. They do not rely on private internal helper hacks.
- **Independence & Isolation**: Every test creates an isolated temporary directory (using standard library `tempfile` / system temp directory drop-guards) and never mutates global state or depends on test run order.
- **Progressive Testability**: Each milestone feature is tested independently, and cross-feature interactions are stratified in dedicated higher-tier suites.
- **Adversarial Verification**: Edge cases, malformed payloads, cyclic graphs, offline network cutoffs, and escaping integrity are systematically covered.

---

## 2. Feature Inventory Matrix

| ID | Feature Name | Requirement | Primary Module | Acceptance Criteria |
|:---|:---|:---:|:---|:---|
| **F1** | `F1_SEMGREP_OSS_COMMUNITY_BUNDLE` | R1 | `crates/security-linter/src/community_bundle.rs` | Canonical OWASP Top 10 & CWE Top 25 YAML embedded via `include_str!`, unpacks to `.aether/plugins/community/plugin.yaml` with 100% offline air-gapped readiness. |
| **F2** | `F2_SEMGREP_CLI_DOWNLOADER` | R1 | `crates/security-linter/src/bin/aether_plugin_tool.rs` | CLI subcommand `download-semgrep-rules` (and `init-bundle`) synchronizes rules without Cloud account, with graceful offline fallback. |
| **F3** | `F3_SEMGREP_HOT_RELOAD_INTEGRATION` | R1 | `crates/ai-file-bridge/src/watcher.rs` & `ast-scanner` | Watcher whitelists `.aether/plugins/` and `.yaml`/`.yml` extensions; scanner evaluates active plugins during project audit. |
| **F4** | `F4_SSA_DATAFLOW_CORE_MODEL` | R2 | `crates/core-graph/src/dataflow.rs` | Core models: `SsaVar`, `TaintSource`, `TaintSink`, `TaintStep`, `TaintFlowTrace`, `SanitizerRule`, `DataflowGraph`, `DataflowEdge`. |
| **F5** | `F5_SSA_INTRA_INTER_PROCEDURAL_TRACKING` | R2 | `crates/core-graph/src/dataflow.rs` & `ast-scanner` | SSA variable versioning across intra-procedural def-use and inter-procedural argument passing and return value propagation. |
| **F6** | `F6_SANITIZER_NEUTRALIZATION_ENGINE` | R2 | `crates/security-linter/src/sanitizer_catalog.rs` | Catalog of sanitizers per CWE family. When taint passes through a sanitizer, `is_sanitized = true` and alert at Sink is neutralized. Unsanitized flows emit alerts with exact variable traces. |
| **F7** | `F7_SCA_LOCKFILE_PARSERS` | R3 | `crates/security-linter/src/sca/lockfile.rs` | Robust parsing of `Cargo.lock` (TOML), `package-lock.json` (JSON v1/v2/v3), and `composer.lock` (JSON) into unified `DependencyPackage` list. |
| **F8** | `F8_OSV_CLIENT_AND_OFFLINE_CACHE` | R3 | `crates/security-linter/src/sca/osv.rs` & `cache.rs` | OSV.dev query mapping (`crates.io`, `npm`, `Packagist`), persistent disk cache keyed by `BLAKE3(ecosystem:package:version)` in `.aether/cache/osv/`. |
| **F9** | `F9_SCA_CALLGRAPH_REACHABILITY` | R3 | `crates/security-linter/src/sca/cross_ref.rs` & `core-graph` | Materialization of dependency bubbles and call edges; reachability BFS marks endpoint-called vulnerabilities `is_reachable = true` and uncalled dependencies `is_reachable = false`. |
| **F10** | `F10_SCA_CLI_FLAGS` | R3 | `crates/desktop-shell/src/main.rs` | Flags `--sca`, `--offline-sca`, `--sca-only` enable SCA execution and report generation. |
| **F11** | `F11_CROSS_FEATURE_AND_REALWORLD` | R1+R2+R3 | All Workspace Crates | End-to-end integration: SCA vulnerability chained with SSA dataflow, Semgrep rule alerts feeding into reachability graph, multi-crate polyglot scenarios. |

---

## 3. The 4-Tier Testing Methodology

```
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 4: Real-World Polyglot Application Scenarios                     │
│ - Multi-crate Rust workspace + Node.js/TS client + PHP microservice     │
│ - Endpoints calling vulnerable dependencies vs uncalled dependencies   │
│ - Tainted user input traversing 4 function hops with sanitizers        │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 3: Cross-Feature Interactions & Combinations                     │
│ - SCA vulnerable crate argument flows into SSA-tracked SQL sink        │
│ - Semgrep custom plugin rule detects source; SSA engine tracks trace   │
│ - Hot-reloaded plugin alters reachability and anomaly severity         │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 2: Boundary, Precision & Corner Cases                             │
│ - Empty lockfiles, truncated JSON/TOML, cyclic recursive calls         │
│ - Re-assigned SSA versions ($x#0 vs $x#1 vs $x#2) in branch joins     │
│ - Nested sanitizers, partial sanitizers, wrong-CWE sanitizers          │
│ - Air-gapped / 100% offline network failure fallback to disk cache    │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 1: Core Feature Verification & Interface Contracts (>=5 per feat) │
│ - F1: Community bundle load, manifest validation, unpack to disk       │
│ - F2: CLI downloader, offline flag, init-bundle command                │
│ - F3: Watcher directory whitelist, extension filter, scanner plugins   │
│ - F4: SsaVar equality, hashing, DataflowGraph construction             │
│ - F5: Intra-procedural def-use, inter-procedural call arg & return    │
│ - F6: Sanitizer catalog lookup, neutralization, unsanitized trace      │
│ - F7: Cargo.lock, package-lock v1, package-lock v2/v3, composer.lock   │
│ - F8: OSV query format, BLAKE3 cache hit, offline retrieval            │
│ - F9: Reachable endpoint -> dep sink vs dead dependency unreachable   │
│ - F10: CLI flags --sca, --offline-sca, --sca-only                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Authoritative Expected Output Derivation & Mathematical Models

### 4.1 SSA Variable Def-Use & Taint Tracking Formalism
- **SSA Indexing**: In each function scope $F$, variable definitions are numbered monotonically:
  $$\text{def}(x) \implies x_{\text{ver}}, \quad \text{ver} = \max(\text{history}(x)) + 1$$
  Every assignment creates a new `SsaVar { name, version, func_scope, line }`.
- **Taint Propagation Relation**: Directed edge $E = (u, v)$ in `DataflowGraph` exists if:
  1. **Direct Assignment**: $v := \text{expr}(\dots, u, \dots)$
  2. **Inter-Procedural Call**: Caller passes argument $u$ into formal parameter $v_0$ of Callee:
     $$\text{Caller::Arg}_i(u) \xrightarrow{\text{CallPass}} \text{Callee::Param}_i(v_0)$$
  3. **Inter-Procedural Return**: Callee returns $r$, assigned to Caller variable $w$:
     $$\text{Callee::Return}(r) \xrightarrow{\text{CallRet}} \text{Caller::LHS}(w)$$
- **Sanitizer Neutralization Invariant**:
  Given a taint trace path $P = (v_{\text{source}}, \dots, v_{\text{sink}})$ for target vulnerability class $\text{CWE}$:
  $$\text{is\_sanitized}(P) \iff \exists \text{ step } (a \to b) \in P \text{ s.t. } \text{SanitizerMatch}(\text{step}, \text{CWE})$$
  - If $\text{is\_sanitized}(P) == \text{true}$:
    $$\text{Alert emitted at Sink} = \mathbf{FALSE}$$
  - If $\text{is\_sanitized}(P) == \text{false}$:
    $$\text{Alert emitted at Sink} = \mathbf{TRUE}, \quad \text{with } \text{trace} = [v_{\text{source}}, \dots, v_{\text{sink}}]$$

### 4.2 SCA Reachability & Dependency Graph Formalism
- **Dependency Materialization**: For every vulnerable package $P$ with advisory CVE:
  A node $N_{\text{dep}}$ is materialized in `AetherGraph` with `kind = SymbolKind::Function` or `ClassOrStruct` and `metadata.cve_anomalies = [Record]`.
- **Call-Graph Edge**: If user project code symbol $S_{\text{code}}$ imports or calls $P::\text{func}$, an edge $E = (S_{\text{code}}, N_{\text{dep}})$ is registered with `FilterAffiliation::SEMANTIC`.
- **Reachability Criterion**:
  $$\text{Reachable}(N_{\text{dep}}) \iff \exists \text{ path } S_{\text{entry}} \rightsquigarrow N_{\text{dep}} \text{ in } G_{\text{semantic}}$$
  where $S_{\text{entry}}$ satisfies `is_source_node` (`kind == FormOrEndpoint` or stereotype `Endpoint`/`Form` or `api::`).
  - If path exists: `anom.is_reachable = true`, `exploit_path = [S_entry, ..., N_dep]`.
  - If no path exists (dead dependency or uncalled function): `anom.is_reachable = false`, `exploit_path = []`.

### 4.3 OSV.dev BLAKE3 Cache Key Determinism
- Cache key string:
  $$\text{Key} = \text{BLAKE3}\Big(\text{ecosystem} \parallel ":" \parallel \text{package\_name} \parallel ":" \parallel \text{version}\Big)$$
- Disk path:
  $$.aether/cache/osv/\{\text{Key}\}.json$$
- Guarantees 100% offline air-gapped repeatability without network access.

---

## 5. Test Suite Architecture & Implementation Plan

### 5.1 Test File Breakdown

| Test Suite File | Features Covered | Minimum Test Count | Key Scenarios |
|:---|:---|:---:|:---|
| `crates/desktop-shell/tests/e2e_r1_semgrep.rs` | F1, F2, F3 | 15 | Embedded bundle unpack, manifest validation, CLI downloader, offline fallback, pattern metavariable regex translation, `.aether/plugins/` watcher detection, hot-reload scan |
| `crates/desktop-shell/tests/e2e_r2_dataflow_ssa.rs` | F4, F5, F6 | 15 | SsaVar models, intra-procedural def-use, inter-procedural call argument & return tracking, sanitizer catalog per CWE, neutralization of alert, unsanitized full trace |
| `crates/desktop-shell/tests/e2e_r3_reachable_sca.rs` | F7, F8, F9, F10 | 18 | Cargo.lock TOML, package-lock v1/v2/v3 JSON, composer.lock JSON, OSV client query payload, BLAKE3 cache read/write, callgraph reachability distinction, CLI flags |
| `crates/desktop-shell/tests/e2e_tier3_tier4_scenarios.rs` | F11 (T3+T4) | 12 | SCA vulnerability fed into SSA taint tracking, Semgrep plugin findings in reachability graph, multi-crate polyglot real-world project |
| **TOTAL** | **Full V3 E2E Suite** | **60+** | **Exhaustive coverage of R1, R2, R3 across all 4 tiers** |

---

## 6. Execution Commands & Verification Protocol

```powershell
# 1. Run R1 Semgrep Community Rules & Hot-Reload E2E Suite
cargo test -p desktop-shell --test e2e_r1_semgrep -- --nocapture

# 2. Run R2 True Dataflow & SSA Taint Tracking E2E Suite
cargo test -p desktop-shell --test e2e_r2_dataflow_ssa -- --nocapture

# 3. Run R3 Reachable SCA & OSV.dev E2E Suite
cargo test -p desktop-shell --test e2e_r3_reachable_sca -- --nocapture

# 4. Run Tier 3 & Tier 4 Cross-Feature and Polyglot Scenarios Suite
cargo test -p desktop-shell --test e2e_tier3_tier4_scenarios -- --nocapture

# 5. Run Full V3 E2E Test Suite
cargo test -p desktop-shell --test e2e_r1_semgrep --test e2e_r2_dataflow_ssa --test e2e_r3_reachable_sca --test e2e_tier3_tier4_scenarios

# 6. Run Entire Workspace Regression & Unit Suites
cargo test --workspace
```

---

## 7. Defect Escalation Protocol

When any test detects a contract deviation, implementation bug, or regression:
1. **Never modify implementation code**: The Test Writer adheres strictly to test code ownership.
2. **Document the exact defect**:
   - Failing test name and scenario.
   - Expected behavior derived from `ORIGINAL_REQUEST.md` / `PROJECT.md`.
   - Actual observed behavior, stdout/stderr, or error code.
3. **Escalate to implementing worker**:
   - R1 defects $\to$ `teamwork_worker_v3_m1_1`
   - R2 defects $\to$ `teamwork_worker_v3_m2_1`
   - R3 defects $\to$ `teamwork_worker_v3_m3_1` / orchestrator
4. Record defects in `TEST_READY.md` and working directory `handoff.md`.
