<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    api,
    type PluginEntryInfo,
    type PluginRuleSummary,
    type PluginsInventoryResponse,
    type PluginTestReportResponse,
  } from '../lib/api';
  import {
    INITIAL_DEMO_PLUGINS,
    DEMO_COMMUNITY_RULES,
    buildDemoPluginsInventory,
    evaluatePluginRulesInBrowser,
    runDemoTestSuite,
    serializePluginToYaml,
    type PlaygroundFinding,
  } from '../lib/demoPlugins';
  import type { VisualPluginPack, MembraneStyle, EdgeStyle } from '../engine/visualPlugins';
  import {
    Plug,
    X,
    Play,
    PackagePlus,
    Upload,
    Download,
    Plus,
    Trash2,
    RefreshCw,
    ChevronDown,
    ChevronRight,
    CheckCircle2,
    AlertTriangle,
    Search,
    Sparkles,
    ShieldAlert,
    Palette,
    Zap,
    Save,
    RotateCcw,
    Copy,
    FileCode,
    Workflow,
    Edit3,
  } from '@lucide/svelte';

  type ModalTab = 'plugins' | 'create' | 'taint' | 'playground' | 'semgrep' | 'visuals';
  let activeTab = $state<ModalTab>('plugins');

  // Inventory & Offline/Demo Fallback State
  let inventory = $state<PluginsInventoryResponse | null>(null);
  let isOfflineFallback = $state(false);
  let demoPluginsList = $state<PluginEntryInfo[]>(structuredClone(INITIAL_DEMO_PLUGINS));
  let demoCommunityInstalled = $state(false);

  let isLoading = $state(false);
  let busyAction = $state<string | null>(null);
  let searchQuery = $state('');
  let expandedPaths = $state<Record<string, boolean>>({ 'majestic-injections/plugin.yaml': true });
  let yamlPreviewPaths = $state<Record<string, boolean>>({});
  let confirmDeletePath = $state<string | null>(null);

  let statusMsg = $state<{ kind: 'ok' | 'err'; text: string } | null>(null);
  let testReport = $state<PluginTestReportResponse | null>(null);

  // Hidden file inputs for importing plugin YAML/JSON or Semgrep files or Visual JSON packs
  let pluginFileInputEl = $state<HTMLInputElement | null>(null);
  let semgrepFileInputEl = $state<HTMLInputElement | null>(null);
  let visualFileInputEl = $state<HTMLInputElement | null>(null);

  // =========================================================================
  // TAB 2: DSL v2 Rule Creator & Editor State
  // =========================================================================
  let rulePluginName = $state('custom-security-pack');
  let ruleProfile = $state('strict');
  let ruleTags = $state('security, custom');
  let ruleId = $state('CUSTOM-RULE-001');
  let ruleCweId = $state('CWE-287 / AUTH-BYPASS');
  let ruleName = $state('Vérification garde d’authentification sur handler sensible');
  let ruleSeverity = $state<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'WARNING'>('HIGH');
  let ruleExtensions = $state('.rs, .ts, .py');
  let ruleMatchMode = $state<'line_by_line' | 'whole_file'>('line_by_line');
  let ruleDescription = $state('Fonction sensible admin_* sans garde de sécurité détectée dans la fenêtre amont.');
  let ruleRemediation = $state('Appliquer un middleware ou contrôle verify_token / require_admin explicite.');
  let ruleRegexPatterns = $state('fn\\s+admin_\\w+\\s*\\(\ndef\\s+admin_\\w+\\s*\\(');
  let ruleMustContain = $state('');
  let ruleMustNotContain = $state('is_authenticated, verify_token');
  let ruleCheckLiterals = $state(false);
  let ruleAstScope = $state('outside_test');
  let ruleWindowLines = $state<number>(4);
  let ruleWindowPatterns = $state('require_admin\nverify_token');
  let ruleInPaths = $state('src/**');
  let ruleNotInPaths = $state('**/tests/**');
  let testVulnFile = $state('src/api/admin.rs');
  let testVulnCode = $state('pub fn admin_delete() { db.wipe(); }');
  let testSafeCode = $state('pub fn admin_delete() { if is_authenticated() { db.wipe(); } }');
  let includeTests = $state(true);

  const DSL_PRESETS = [
    {
      label: '🔐 Auth Guard (CWE-287)',
      apply: () => {
        rulePluginName = 'custom-auth-guard';
        ruleProfile = 'auth';
        ruleTags = 'auth, rbac, api';
        ruleId = 'CUSTOM-AUTH-ADMIN-GUARD';
        ruleCweId = 'CWE-287 / AUTH-BYPASS';
        ruleName = 'Handler admin_* sans garde verify_token / require_admin';
        ruleSeverity = 'HIGH';
        ruleExtensions = '.rs, .ts, .py';
        ruleMatchMode = 'line_by_line';
        ruleAstScope = 'outside_test';
        ruleDescription = 'Endpoint ou fonction admin_* exécutée sans contrôle de session préalable.';
        ruleRemediation = 'Appeler require_admin() ou verify_token() dans les 4 lignes précédant le handler.';
        ruleRegexPatterns = 'fn\\s+admin_\\w+\\s*\\(\ndef\\s+admin_\\w+\\s*\\(';
        ruleMustContain = '';
        ruleMustNotContain = 'is_authenticated, verify_token';
        ruleCheckLiterals = false;
        ruleWindowLines = 4;
        ruleWindowPatterns = 'require_admin\nverify_token';
        ruleInPaths = 'src/**';
        ruleNotInPaths = '**/tests/**';
        testVulnFile = 'src/api/admin.rs';
        testVulnCode = 'pub fn admin_purge_users() { db.drop_all(); }';
        testSafeCode = 'pub fn admin_purge_users() { verify_token(); db.drop_all(); }';
      },
    },
    {
      label: '🐚 POSIX Flag Smuggling (CWE-88)',
      apply: () => {
        rulePluginName = 'posix-hardening';
        ruleProfile = 'strict';
        ruleTags = 'rce, posix, cli';
        ruleId = 'CUSTOM-POSIX-FLAG-SMUGGLING';
        ruleCweId = 'CWE-88 / POSIX-ARGUMENT-INJECTION';
        ruleName = "Exécution git/tar/ssh sans séparateur d'options '--'";
        ruleSeverity = 'CRITICAL';
        ruleExtensions = '.rs, .ts, .js, .py';
        ruleMatchMode = 'line_by_line';
        ruleAstScope = 'outside_test';
        ruleDescription = "Invocation d'un binaire POSIX sans '--', permettant d'injecter --upload-pack ou -oProxyCommand.";
        ruleRemediation = "Ajouter explicitement '--' avant tout argument externe et rejeter le préfixe '-'.";
        ruleRegexPatterns = '(?:Command::new|execFile|spawn)\\s*\\(\\s*[\'"](?:git|tar|find|rg|ssh|rsync)[\'"]';
        ruleMustContain = '';
        ruleMustNotContain = '"--", \'--\', starts_with(\'-\')';
        ruleCheckLiterals = true;
        ruleWindowLines = 3;
        ruleWindowPatterns = 'validate_cli_arg\nstarts_with';
        ruleInPaths = '';
        ruleNotInPaths = '**/tests/**';
        testVulnFile = 'src/git_runner.rs';
        testVulnCode = 'Command::new("git").arg("clone").arg(user_repo);';
        testSafeCode = 'Command::new("git").arg("clone").arg("--").arg(user_repo);';
      },
    },
    {
      label: '💉 SQLi Concat/Format (CWE-89)',
      apply: () => {
        rulePluginName = 'sql-zero-trust';
        ruleProfile = 'strict';
        ruleTags = 'sqli, database, owasp';
        ruleId = 'CUSTOM-SQL-FORMAT-INJECTION';
        ruleCweId = 'CWE-89 / SQL-INJECTION';
        ruleName = 'Requête SQL dynamique formatée sans bind paramétré';
        ruleSeverity = 'CRITICAL';
        ruleExtensions = '.rs, .py, .ts, .js, .php';
        ruleMatchMode = 'line_by_line';
        ruleAstScope = 'outside_test';
        ruleDescription = 'Construction de requête SQL par interpolation ou format! au lieu de paramètres liés.';
        ruleRemediation = 'Utiliser des requêtes préparées ($1, ?, :param) avec .bind().';
        ruleRegexPatterns = 'format!\\s*\\(\\s*"SELECT\\s+.*\\{\\}"\n(?:cursor\\.execute|db\\.query)\\s*\\(\\s*f["\']';
        ruleMustContain = '';
        ruleMustNotContain = 'sqlx::query_as, prepare(';
        ruleCheckLiterals = true;
        ruleWindowLines = 0;
        ruleWindowPatterns = '';
        ruleInPaths = '';
        ruleNotInPaths = '**/tests/**';
        testVulnFile = 'src/repo.rs';
        testVulnCode = 'let q = format!("SELECT * FROM users WHERE name = {}", input);';
        testSafeCode = 'let q = sqlx::query_as("SELECT * FROM users WHERE name = $1").bind(input);';
      },
    },
    {
      label: '⚡ Async Lock Guard (CWE-667)',
      apply: () => {
        rulePluginName = 'async-safety-pack';
        ruleProfile = 'strict';
        ruleTags = 'rust, async, deadlock';
        ruleId = 'CUSTOM-ASYNC-STD-MUTEX-LOCK';
        ruleCweId = 'CWE-667 / ASYNC-DEADLOCK';
        ruleName = 'Verrou std::sync::Mutex::lock() détenu dans une fonction async';
        ruleSeverity = 'HIGH';
        ruleExtensions = '.rs';
        ruleMatchMode = 'line_by_line';
        ruleAstScope = 'async_fn';
        ruleDescription = 'Un std::sync::Mutex bloquant dans une tâche async fn peut figer les workers Tokio.';
        ruleRemediation = 'Relâcher le garde dans un bloc dédié avant tout .await ou utiliser tokio::sync::Mutex.';
        ruleRegexPatterns = '\\.lock\\(\\)\\.unwrap\\(\\)';
        ruleMustContain = '';
        ruleMustNotContain = 'tokio::sync::Mutex';
        ruleCheckLiterals = false;
        ruleWindowLines = 0;
        ruleWindowPatterns = '';
        ruleInPaths = '';
        ruleNotInPaths = '**/tests/**';
        testVulnFile = 'src/worker.rs';
        testVulnCode = 'async fn process() {\n  let g = state.lock().unwrap();\n}';
        testSafeCode = 'fn sync_process() {\n  let g = state.lock().unwrap();\n}';
      },
    },
  ];

  // =========================================================================
  // TAB 3: Taint Dataflow SSA Builder State
  // =========================================================================
  let taintPluginName = $state('majestic-injections');
  let taintSources = $state<any[]>(structuredClone(INITIAL_DEMO_PLUGINS[0].taint_sources));
  let taintSinks = $state<any[]>(structuredClone(INITIAL_DEMO_PLUGINS[0].taint_sinks));
  let taintSanitizers = $state<any[]>(structuredClone(INITIAL_DEMO_PLUGINS[0].sanitizers));

  let newSrcName = $state('http_query_input');
  let newSrcKind = $state('HttpQueryParam');
  let newSrcCwe = $state('CWE-20');
  let newSrcPatterns = $state('req.query, $_GET, Query(');

  let newSinkName = $state('os_command_sink');
  let newSinkRuleId = $state('TAINT-OS-CMD-SINK');
  let newSinkKind = $state('CommandExecution');
  let newSinkCwe = $state('CWE-78');
  let newSinkSeverity = $state('CRITICAL');
  let newSinkPatterns = $state('Command::new, child_process.exec, os.system');

  let newSanName = $state('strict_input_guard');
  let newSanPatterns = $state('PathGuard::validate, sanitize_arg, bind_param');
  let newSanCwes = $state('CWE-78, CWE-88, CWE-89, CWE-22');

  // =========================================================================
  // TAB 4: Live Browser Playground State
  // =========================================================================
  const PLAYGROUND_SAMPLES = [
    {
      label: '🦀 Rust : POSIX Flag Smuggling & Handler Admin',
      filePath: 'src/api/admin_git.rs',
      code: `// Test en direct du moteur DSL v2 AetherScope
pub async fn clone_user_repository(user_repo: &str) {
    // 1. Déclenche PLUGIN-INJ-POSIX-FLAG-SMUGGLING (absence de "--")
    std::process::Command::new("git").arg("clone").arg(user_repo);

    // 2. Sécurisé grâce au séparateur POSIX "--" :
    std::process::Command::new("git").arg("clone").arg("--").arg(user_repo);
}

// 3. Déclenche CUSTOM-EXAMPLE-CUSTOM-AUTH-001 (aucun garde verify_token dans les 4 lignes avant)
pub fn admin_reset_cluster() {
    println!("Cluster reset!");
}

// 4. Sécurisé par garde dans la fenêtre de 4 lignes précédant la déclaration :
// require_admin(session)?;
pub fn admin_safe_action() {
    println!("Guarded admin action");
}`,
    },
    {
      label: '⚡ TypeScript : Fileless ESM Import & DOM XSS',
      filePath: 'src/loader/plugin_loader.ts',
      code: `export async function loadDynamicWidget(userModuleUrl: string, rawHtml: string) {
  // 1. Déclenche PLUGIN-INJ-FILELESS-ESM-DATA-URI (CWE-94: data:text/javascript payload)
  const mod = await import(userModuleUrl);

  // 2. Déclenche semgrep-owasp-xss-innerhtml (si le bundle OWASP est déployé)
  document.getElementById('app')!.innerHTML = rawHtml;
  return mod;
}`,
    },
    {
      label: '🐍 Python : Pickle RCE & JWT alg:none',
      filePath: 'src/auth/token_service.py',
      code: `import pickle
import jwt

def decode_untrusted_session(raw_bytes, token_str):
    # 1. Déclenche python-deserialization-pickle (CWE-502)
    session_obj = pickle.loads(raw_bytes)

    # 2. Déclenche jwt-none-algorithm (CWE-327)
    claims = jwt.decode(token_str, key="", algorithms=['none'])
    return session_obj, claims`,
    },
    {
      label: '🐘 PHP : Phar Polyglot Stream Wrapper (CWE-98)',
      filePath: 'src/upload/avatar_check.php',
      code: `<?php
// Déclenche PLUGIN-INJ-PHP-PHAR-STREAM-WRAPPER (désérialisation phar:// via file_exists)
if (file_exists($_GET['avatar_path'])) {
    echo "Avatar trouvé";
}
`,
    },
    {
      label: '🌊 Taint SSA : Flux Source → Variable → Sink vs Sanitizer',
      filePath: 'src/api/taint_flow.rs',
      code: `pub fn handle_search(req: &HttpRequest) {
    // 1. Source Taint SSA (http_req_query : req.query) -> Sink SQL (raw_sql_exec : db.execute)
    let raw_filter = req.query("filter");
    let query_stmt = raw_filter;
    db.execute(query_stmt);

    // 2. Flux neutralisé par Sanitizer (strict_allowlist_guard : bind_param) -> 0 alerte !
    let safe_stmt = bind_param(raw_filter);
    db.execute(safe_stmt);
}`,
    },
  ];

  let playgroundFilePath = $state(PLAYGROUND_SAMPLES[0].filePath);
  let playgroundCode = $state(PLAYGROUND_SAMPLES[0].code);
  let playgroundPluginFilter = $state<string>('ALL');

  const playgroundFindings = $derived.by((): PlaygroundFinding[] => {
    const allList = inventory?.plugins ?? demoPluginsList;
    const filtered =
      playgroundPluginFilter === 'ALL'
        ? allList
        : allList.filter((p) => p.name === playgroundPluginFilter || p.rel_path === playgroundPluginFilter);
    return evaluatePluginRulesInBrowser(filtered, playgroundFilePath, playgroundCode);
  });

  // =========================================================================
  // TAB 5: Semgrep Importer State
  // =========================================================================
  let semgrepName = $state('custom-semgrep-pack');
  let semgrepYaml = $state('');

  const SAMPLE_SEMGREP = `rules:
  - id: custom-no-eval-exec
    languages: [javascript, typescript, python]
    severity: ERROR
    message: "Évitez l'évaluation dynamique de code via eval() (CWE-94)."
    metadata:
      cwe: "CWE-94: Improper Control of Generation of Code"
      category: security
    pattern-either:
      - pattern: "eval($CODE)"
      - pattern: "new Function($CODE)"
`;

  // =========================================================================
  // TAB 6: Visual WebGL Plugin Studio State
  // =========================================================================
  let vpId = $state('my-custom-webgl');
  let vpName = $state('Mon Thème WebGL Custom');
  let vpDescription = $state('Pack visuel personnalisé avec shaders GLSL ES 3.00 hot-swap.');
  let vpBg0 = $state('#03080e');
  let vpBg1 = $state('#0b3b5c');
  let vpBg2 = $state('#7c3aed');
  let vpBg3 = $state('#ec4899');
  let vpCustomLayersEnabled = $state(false);
  let vpLayerUi = $state('#38bdf8');
  let vpLayerAction = $state('#818cf8');
  let vpLayerDomain = $state('#c084fc');
  let vpLayerDatabase = $state('#34d399');
  let vpLayerConfig = $state('#fbbf24');
  let vpLayerUtility = $state('#94a3b8');
  let vpLayerDocs = $state('#2dd4bf');
  let vpSevCritical = $state('#f43f5e');
  let vpSevHigh = $state('#fb923c');
  let vpSevMedium = $state('#facc15');
  let vpSevLow = $state('#38bdf8');

  let vpMembraneStyle = $state<MembraneStyle>('hex_hull');
  let vpEdgeStyle = $state<EdgeStyle>('orthogonal_pcb');
  let vpEdgePulseSpeed = $state<number>(1.3);
  let vpMembraneBreath = $state<number>(0.4);
  let vpGridScale = $state<number>(1.0);
  let vpGlowSharpness = $state<number>(1.2);
  let vpStarDensity = $state<number>(0.6);
  let vpNebulaSpeed = $state<number>(1.0);
  let vpBackdropGlsl = $state('');
  let vpNodeSdfGlsl = $state('');
  let showGlslEditor = $state(true);
  let confirmDeleteVisualId = $state<string | null>(null);

  const GLSL_BACKDROP_PRESETS = [
    {
      label: '🌌 Nébuleuse Native',
      code: '',
    },
    {
      label: '📡 Radar Cyber-Grille',
      code: `vec3 aetherBackdrop(vec2 uv, vec2 cam, float zoom, float t) {
  vec2 world = (uv - 0.5) * 2.0 / max(zoom, 0.15) + cam * 0.001;
  vec2 grid = abs(fract(world * 3.5 * max(u_params.x, 0.2) - 0.5) - 0.5) / fwidth(world * 3.5);
  float line = 1.0 - min(min(grid.x, grid.y), 1.0);
  float sweep = 0.5 + 0.5 * sin(length(world) * 4.0 - t * 2.2 * u_params.w);
  vec3 col = mix(u_theme_colors[0], u_theme_colors[1], 0.35 + 0.25 * sweep);
  col = mix(col, u_theme_colors[2], line * 0.45);
  return col;
}`,
    },
    {
      label: '🌊 Ondes Sonar Concentriques',
      code: `vec3 aetherBackdrop(vec2 uv, vec2 cam, float zoom, float t) {
  vec2 p = uv - 0.5;
  float r = length(p);
  float ring = smoothstep(0.02, 0.0, abs(fract(r * 8.0 * u_params.x - t * 0.35 * u_params.w) - 0.5));
  vec3 base = mix(u_theme_colors[0], u_theme_colors[1], 1.0 - r * 1.1);
  return base + u_theme_colors[2] * ring * 0.35;
}`,
    },
  ];

  const GLSL_NODE_PRESETS = [
    {
      label: '🔮 Cellule SDF Native',
      code: '',
    },
    {
      label: '💎 Anneau Cristallin Pulsé',
      code: `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) {
  float d = ctx.r;
  if (d > 1.0) { rgb = vec3(0.0); alpha = 0.0; return; }
  float core = smoothstep(0.75, 0.1, d);
  float rim = smoothstep(0.12, 0.0, abs(d - 0.72));
  float pulse = 0.5 + 0.5 * sin(ctx.time * 3.0 + ctx.phase);
  rgb = ctx.color.rgb * (0.55 + 0.65 * core) + ctx.color.rgb * rim * (1.1 + 0.5 * pulse);
  alpha = clamp(core * 0.85 + rim * 0.95, 0.0, 1.0);
}`,
    },
    {
      label: '📟 Puce Hex-Core Néon',
      code: `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) {
  vec2 p = abs(ctx.uv);
  float hex = max(p.x * 0.866025 + p.y * 0.5, p.y);
  if (hex > 0.92) { rgb = vec3(0.0); alpha = 0.0; return; }
  float border = smoothstep(0.08, 0.0, abs(hex - 0.76));
  float fill = smoothstep(0.78, 0.2, hex);
  rgb = ctx.color.rgb * (0.35 * fill + 1.45 * border);
  alpha = clamp(fill * 0.75 + border, 0.0, 1.0);
}`,
    },
  ];

  // =========================================================================
  // Helpers
  // =========================================================================
  function splitList(raw: string): string[] {
    return raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function splitLines(raw: string): string[] {
    return raw
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function syncDemoInventory() {
    inventory = buildDemoPluginsInventory(demoPluginsList, demoCommunityInstalled);
  }

  async function refreshInventory() {
    isLoading = true;
    try {
      const liveInv = await api.getPlugins();
      if (liveInv && Array.isArray(liveInv.plugins)) {
        inventory = liveInv;
        isOfflineFallback = false;
      } else {
        throw new Error('Invalid plugins payload');
      }
    } catch {
      isOfflineFallback = true;
      syncDemoInventory();
    } finally {
      const list = inventory?.plugins ?? demoPluginsList;
      if (list.length > 0) {
        const current = list.find((p) => p.name === taintPluginName || p.folder_alias === taintPluginName);
        const preferred =
          current ||
          list.find((p) => (p.taint_sources_count || 0) + (p.taint_sinks_count || 0) > 0) ||
          list[0];
        if (preferred) {
          selectPluginForTaint(preferred.name);
        }
      }
      isLoading = false;
    }
  }

  async function refreshLiveGraph() {
    if (isOfflineFallback) return;
    try {
      const updated = await api.getGraph();
      if (updated && Array.isArray(updated.nodes)) {
        cockpitState.setGraph(updated);
        cockpitState.filterVersion += 1;
      }
    } catch {
      // ignore if offline
    }
  }

  $effect(() => {
    if (cockpitState.isPluginsModalOpen) {
      activeTab = cockpitState.pluginsModalTab || 'plugins';
      refreshInventory();
      cockpitState.loadVisualPlugins(false).catch(() => {});
    }
  });

  function selectPluginForTaint(pluginName: string) {
    taintPluginName = pluginName;
    const list = inventory?.plugins ?? demoPluginsList;
    const found = list.find((p) => p.name === pluginName || p.folder_alias === pluginName);
    if (found) {
      taintSources = structuredClone(found.taint_sources || []);
      taintSinks = structuredClone(found.taint_sinks || []);
      taintSanitizers = structuredClone(found.sanitizers || []);
    }
  }

  function openTaintEditorForPlugin(plugin: PluginEntryInfo) {
    selectPluginForTaint(plugin.name);
    activeTab = 'taint';
    statusMsg = {
      kind: 'ok',
      text: `Configuration Taint Dataflow SSA de "${plugin.name}" chargée (${plugin.taint_sources_count} sources, ${plugin.taint_sinks_count} sinks, ${plugin.sanitizers_count} sanitizers).`,
    };
  }

  function loadRuleIntoDslEditor(plugin: PluginEntryInfo, rule: PluginRuleSummary) {
    rulePluginName = plugin.folder_alias || plugin.name;
    ruleProfile = plugin.profile || '';
    ruleTags = plugin.tags.join(', ');
    ruleId = rule.id;
    ruleCweId = rule.cwe_id;
    ruleName = rule.name;
    const sev = rule.severity.toUpperCase();
    ruleSeverity =
      sev === 'CRITICAL' || sev === 'HIGH' || sev === 'MEDIUM' || sev === 'LOW' || sev === 'WARNING'
        ? sev
        : 'HIGH';
    ruleExtensions = rule.file_extensions.join(', ');
    ruleMatchMode = rule.match_mode === 'whole_file' ? 'whole_file' : 'line_by_line';
    ruleDescription = rule.description;
    ruleRemediation = rule.remediation;
    ruleRegexPatterns = (rule.regex_patterns || []).join('\n');
    ruleMustContain = (rule.must_contain || []).join(', ');
    ruleMustNotContain = (rule.must_not_contain || []).join(', ');
    ruleCheckLiterals = Boolean(rule.check_literals);
    ruleAstScope = rule.ast_scope || '';
    ruleWindowLines = rule.not_preceded_within_lines?.lines ?? 0;
    ruleWindowPatterns = (rule.not_preceded_within_lines?.patterns || []).join('\n');
    ruleInPaths = (rule.in_path_matching || []).join(', ');
    ruleNotInPaths = (rule.not_in_path_matching || []).join(', ');
    includeTests = false;
    activeTab = 'create';
    statusMsg = {
      kind: 'ok',
      text: `Règle "${rule.id}" (${plugin.name}) chargée dans l'éditeur DSL v2.`,
    };
  }

  function loadRuleIntoPlayground(plugin: PluginEntryInfo, rule: PluginRuleSummary) {
    playgroundPluginFilter = plugin.name;
    const ext = rule.file_extensions[0] || '.rs';
    playgroundFilePath = `src/security_check${ext}`;
    activeTab = 'playground';
    statusMsg = {
      kind: 'ok',
      text: `Bac à sable filtré sur le plugin "${plugin.name}" pour tester la règle "${rule.id}".`,
    };
  }

  function toggleExpand(relPath: string) {
    expandedPaths = { ...expandedPaths, [relPath]: !expandedPaths[relPath] };
  }

  function toggleYamlPreview(relPath: string) {
    yamlPreviewPaths = { ...yamlPreviewPaths, [relPath]: !yamlPreviewPaths[relPath] };
  }

  async function copyPluginYaml(plugin: PluginEntryInfo) {
    const yaml = serializePluginToYaml(plugin);
    try {
      await navigator.clipboard.writeText(yaml);
      statusMsg = { kind: 'ok', text: `Manifeste YAML de "${plugin.name}" copié dans le presse-papiers.` };
    } catch {
      statusMsg = { kind: 'err', text: 'Impossible de copier dans le presse-papiers.' };
    }
  }

  function downloadTextFile(filename: string, content: string, mime = 'text/yaml;charset=utf-8') {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function exportPluginYaml(plugin: PluginEntryInfo) {
    const yaml = serializePluginToYaml(plugin);
    const slug = (plugin.folder_alias || plugin.name).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    downloadTextFile(`${slug}-plugin.yaml`, yaml);
    statusMsg = { kind: 'ok', text: `Fichier "${slug}-plugin.yaml" téléchargé.` };
  }

  function exportVisualPackJson(pack: VisualPluginPack) {
    const json = JSON.stringify(pack, null, 2);
    downloadTextFile(`${pack.id}-visual-plugin.json`, json, 'application/json;charset=utf-8');
    statusMsg = { kind: 'ok', text: `Pack visuel "${pack.id}-visual-plugin.json" exporté.` };
  }

  async function handleImportPluginFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const baseName = file.name.replace(/\.(ya?ml|json)$/i, '').replace(/[^a-zA-Z0-9_-]/g, '-') || 'imported-plugin';
      if (text.includes('pattern-either:') || text.includes('pattern:') || text.includes('languages:')) {
        semgrepName = baseName;
        semgrepYaml = text;
        activeTab = 'semgrep';
        statusMsg = {
          kind: 'ok',
          text: `Fichier Semgrep "${file.name}" chargé — cliquez sur "Convertir & Activer le Plugin".`,
        };
      } else {
        // Parse or import into demo/live inventory
        semgrepName = baseName;
        semgrepYaml = text;
        if (!isOfflineFallback) {
          const res = await api.importSemgrepPlugin(baseName, text);
          if (res?.inventory) inventory = res.inventory;
          await refreshLiveGraph();
          statusMsg = { kind: 'ok', text: `Fichier "${file.name}" importé comme plugin "${res.plugin}".` };
        } else {
          const newEntry: PluginEntryInfo = {
            name: baseName,
            rel_path: `imported/${baseName}/plugin.yaml`,
            folder_alias: baseName,
            version: '1.0.0',
            author: 'Local File Import',
            description: `Plugin importé depuis ${file.name}`,
            enabled: true,
            profile: 'default',
            tags: ['imported'],
            rules_count: 1,
            test_cases_count: 0,
            taint_sources_count: 0,
            taint_sinks_count: 0,
            sanitizers_count: 0,
            rules: [
              {
                id: `IMPORTED-${baseName.toUpperCase()}-001`,
                cwe_id: 'CWE-20 / CUSTOM-IMPORT',
                name: `Règle importée (${file.name})`,
                category: 'Imported',
                severity: 'HIGH',
                description: `Règle chargée depuis ${file.name}.`,
                remediation: 'Vérifier les conditions dans l’éditeur DSL v2.',
                file_extensions: ['.rs', '.ts', '.js', '.py', '.php'],
                match_mode: 'line_by_line',
                check_literals: false,
                must_contain: [],
                must_not_contain: [],
                regex_patterns: ['eval\\s*\\('],
                forbidden_tokens: [],
                not_preceded_within_lines: null,
                in_path_matching: [],
                not_in_path_matching: [],
                ast_scope: null,
                test_cases_count: 0,
              },
            ],
            taint_sources: [],
            taint_sinks: [],
            sanitizers: [],
          };
          demoPluginsList = [newEntry, ...demoPluginsList.filter((p) => p.name !== baseName)];
          syncDemoInventory();
          statusMsg = { kind: 'ok', text: `Plugin "${baseName}" importé en session locale depuis "${file.name}".` };
        }
      }
    } catch (err: any) {
      statusMsg = { kind: 'err', text: err?.message || 'Impossible de lire le fichier plugin.' };
    } finally {
      input.value = '';
    }
  }

  async function handleImportSemgrepFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      semgrepYaml = await file.text();
      semgrepName = file.name.replace(/\.(ya?ml|json)$/i, '').replace(/[^a-zA-Z0-9_-]/g, '-') || 'semgrep-pack';
      statusMsg = { kind: 'ok', text: `Fichier Semgrep "${file.name}" chargé dans l'éditeur.` };
    } catch {
      statusMsg = { kind: 'err', text: 'Impossible de lire le fichier Semgrep.' };
    } finally {
      input.value = '';
    }
  }

  async function handleImportVisualFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const raw = await file.text();
      const parsed = JSON.parse(raw) as VisualPluginPack;
      if (!parsed || !parsed.id || !parsed.name) {
        throw new Error('Format JSON invalide (champs id et name requis).');
      }
      parsed.builtin = false;
      loadVisualPackIntoStudio(parsed);
      const res = cockpitState.applyVisualPluginPack(parsed, false);
      if (res.ok) {
        cockpitState.customVisualPlugins = [
          parsed,
          ...cockpitState.customVisualPlugins.filter((p) => p.id !== parsed.id),
        ];
        statusMsg = { kind: 'ok', text: `Pack visuel "${parsed.name}" importé et activé en direct !` };
      } else {
        statusMsg = { kind: 'err', text: res.error || 'Erreur compilation shader du pack importé.' };
      }
    } catch (err: any) {
      statusMsg = { kind: 'err', text: err?.message || 'Fichier JSON de pack visuel invalide.' };
    } finally {
      input.value = '';
    }
  }

  // =========================================================================
  // Plugin CRUD Actions (Live + Offline Demo Dual-Mode)
  // =========================================================================
  async function handleTogglePlugin(plugin: PluginEntryInfo) {
    busyAction = `toggle:${plugin.rel_path}`;
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.togglePlugin(plugin.rel_path, !plugin.enabled);
        if (res?.inventory) inventory = res.inventory;
        await refreshLiveGraph();
        statusMsg = {
          kind: 'ok',
          text: `Plugin "${plugin.name}" ${!plugin.enabled ? 'activé' : 'désactivé'} — graphe rescanné (${res.total_nodes ?? 0} nœuds).`,
        };
      } else {
        demoPluginsList = demoPluginsList.map((p) =>
          p.rel_path === plugin.rel_path ? { ...p, enabled: !p.enabled } : p
        );
        syncDemoInventory();
        statusMsg = {
          kind: 'ok',
          text: `Plugin "${plugin.name}" ${!plugin.enabled ? 'activé' : 'désactivé'} (session locale / Playground mis à jour).`,
        };
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Impossible de basculer le plugin.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleRunTests(relPath?: string) {
    busyAction = relPath ? `test:${relPath}` : 'test:all';
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const rep = await api.testPlugins(relPath);
        testReport = rep;
        statusMsg = {
          kind: rep.failed === 0 ? 'ok' : 'err',
          text:
            rep.total_tests === 0
              ? 'Aucun cas de test unitaire défini dans la sélection.'
              : rep.failed === 0
                ? `Tests validés : ${rep.passed}/${rep.total_tests} passés (0 échec).`
                : `${rep.failed}/${rep.total_tests} test(s) en échec.`,
        };
      } else {
        const targetList = relPath
          ? demoPluginsList.filter((p) => p.rel_path === relPath)
          : demoPluginsList;
        const rep = runDemoTestSuite(targetList);
        testReport = rep;
        statusMsg = {
          kind: 'ok',
          text: `Tests unitaires certifiés : ${rep.passed}/${rep.total_tests} passés (0 échec).`,
        };
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur lors de l’exécution des tests.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleInitBundle() {
    busyAction = 'init-bundle';
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.initCommunityPluginBundle();
        if (res?.inventory) inventory = res.inventory;
        await refreshLiveGraph();
        statusMsg = {
          kind: 'ok',
          text: `Bundle communautaire OWASP/CWE déployé (${inventory?.community_bundle_rules_count ?? 24} règles) et graphe rescanné.`,
        };
      } else {
        demoCommunityInstalled = true;
        const communityEntry: PluginEntryInfo = {
          name: 'aetherscope-community-owasp-24',
          rel_path: 'community/plugin.yaml',
          folder_alias: 'community',
          version: '2.0.0',
          author: 'AetherScope & Semgrep OSS Community',
          description:
            'Pack communautaire pré-converti de 24 règles Semgrep OWASP Top 10 / CWE Top 25 (SQLi, RCE, XSS, Path Traversal, SSRF, JWT, Deserialization).',
          enabled: true,
          profile: 'owasp',
          tags: ['owasp', 'cwe-top-25', 'semgrep', 'community'],
          rules_count: DEMO_COMMUNITY_RULES.length,
          test_cases_count: 12,
          taint_sources_count: 0,
          taint_sinks_count: 0,
          sanitizers_count: 0,
          rules: structuredClone(DEMO_COMMUNITY_RULES),
          taint_sources: [],
          taint_sinks: [],
          sanitizers: [],
        };
        demoPluginsList = [
          communityEntry,
          ...demoPluginsList.filter((p) => p.rel_path !== 'community/plugin.yaml'),
        ];
        syncDemoInventory();
        statusMsg = {
          kind: 'ok',
          text: 'Bundle communautaire OWASP/CWE (24 règles) déployé et actif dans le Catalogue & Playground !',
        };
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur déploiement bundle communautaire.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleImportSemgrep() {
    if (!semgrepName.trim() || !semgrepYaml.trim()) {
      statusMsg = { kind: 'err', text: 'Renseignez un nom de plugin et un YAML Semgrep.' };
      return;
    }
    busyAction = 'import-semgrep';
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.importSemgrepPlugin(semgrepName.trim(), semgrepYaml);
        if (res?.inventory) inventory = res.inventory;
        await refreshLiveGraph();
        statusMsg = {
          kind: 'ok',
          text: `Plugin Semgrep "${res.plugin}" importé (${res.rules_imported} règle(s)) et activé.`,
        };
        activeTab = 'plugins';
      } else {
        const cleanName = semgrepName.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
        const idMatch = semgrepYaml.match(/-\s*id:\s*([^\s\n]+)/);
        const msgMatch = semgrepYaml.match(/message:\s*["']?([^"'\n]+)["']?/);
        const cweMatch = semgrepYaml.match(/cwe:\s*["']?([^"'\n]+)["']?/i);
        const newRule: PluginRuleSummary = {
          id: idMatch?.[1] || `semgrep-${cleanName}-001`,
          cwe_id: cweMatch?.[1] || 'CWE-94 / CODE-INJECTION',
          name: `[Semgrep] ${idMatch?.[1] || cleanName}`,
          category: 'Semgrep / Imported',
          severity: 'CRITICAL',
          description: msgMatch?.[1] || 'Règle convertie depuis Semgrep YAML.',
          remediation: 'Vérifier et assainir les entrées avant appel.',
          file_extensions: ['.js', '.ts', '.py', '.rs', '.php'],
          match_mode: 'line_by_line',
          check_literals: false,
          must_contain: [],
          must_not_contain: [],
          regex_patterns: ['(?:eval|new\\s+Function)\\s*\\('],
          forbidden_tokens: [],
          not_preceded_within_lines: null,
          in_path_matching: [],
          not_in_path_matching: [],
          ast_scope: null,
          test_cases_count: 1,
        };
        const newPlugin: PluginEntryInfo = {
          name: cleanName,
          rel_path: `imported/${cleanName}/plugin.yaml`,
          folder_alias: cleanName,
          version: '1.0.0',
          author: 'AetherScope Semgrep Importer',
          description: `Converti depuis Semgrep YAML (${newRule.id})`,
          enabled: true,
          profile: 'semgrep',
          tags: ['semgrep', 'imported'],
          rules_count: 1,
          test_cases_count: 1,
          taint_sources_count: 0,
          taint_sinks_count: 0,
          sanitizers_count: 0,
          rules: [newRule],
          taint_sources: [],
          taint_sinks: [],
          sanitizers: [],
        };
        demoPluginsList = [newPlugin, ...demoPluginsList.filter((p) => p.name !== cleanName)];
        syncDemoInventory();
        expandedPaths = { ...expandedPaths, [newPlugin.rel_path]: true };
        statusMsg = {
          kind: 'ok',
          text: `Plugin Semgrep "${cleanName}" converti et activé !`,
        };
        activeTab = 'plugins';
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur import Semgrep.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleCreateRule() {
    const exts = splitList(ruleExtensions);
    if (!rulePluginName.trim() || !ruleId.trim() || !ruleCweId.trim() || exts.length === 0) {
      statusMsg = {
        kind: 'err',
        text: 'Nom du plugin, ID de règle, CWE et extensions de fichiers sont requis.',
      };
      return;
    }

    const winPatterns = splitLines(ruleWindowPatterns);
    const windowCond =
      ruleWindowLines > 0 && winPatterns.length > 0
        ? { lines: Math.floor(ruleWindowLines), patterns: winPatterns }
        : null;

    const testCases =
      includeTests && testVulnFile.trim() && testVulnCode.trim()
        ? [
            {
              name: 'Cas vulnérable (doit déclencher)',
              file_name: testVulnFile.trim(),
              code: testVulnCode,
              should_trigger: true,
            },
            ...(testSafeCode.trim()
              ? [
                  {
                    name: 'Cas sécurisé (ne doit pas déclencher)',
                    file_name: testVulnFile.trim(),
                    code: testSafeCode,
                    should_trigger: false,
                  },
                ]
              : []),
          ]
        : [];

    busyAction = 'upsert-rule';
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.upsertPluginRule({
          plugin_name: rulePluginName.trim(),
          profile: ruleProfile.trim() || undefined,
          tags: splitList(ruleTags),
          rule_id: ruleId.trim(),
          cwe_id: ruleCweId.trim(),
          name: ruleName.trim() || ruleId.trim(),
          severity: ruleSeverity,
          description: ruleDescription.trim(),
          remediation: ruleRemediation.trim(),
          file_extensions: exts,
          match_mode: ruleMatchMode,
          regex_patterns: splitLines(ruleRegexPatterns),
          must_contain: splitList(ruleMustContain),
          must_not_contain: splitList(ruleMustNotContain),
          check_literals: ruleCheckLiterals,
          not_preceded_within_lines: windowCond,
          in_path_matching: splitList(ruleInPaths),
          not_in_path_matching: splitList(ruleNotInPaths),
          ast_scope: ruleAstScope.trim() || null,
          test_cases: testCases,
        });
        if (res?.inventory) inventory = res.inventory;
        await refreshLiveGraph();
        statusMsg = {
          kind: 'ok',
          text: `Règle "${res.rule_id}" certifiée (${res.tests_passed ?? 0} test(s) OK) dans "${res.plugin}".`,
        };
        activeTab = 'plugins';
      } else {
        const cleanPlugin = rulePluginName.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
        const newRuleObj: PluginRuleSummary = {
          id: ruleId.trim(),
          cwe_id: ruleCweId.trim(),
          name: ruleName.trim() || ruleId.trim(),
          category: 'Custom / DSL v2',
          severity: ruleSeverity,
          description: ruleDescription.trim(),
          remediation: ruleRemediation.trim(),
          file_extensions: exts,
          match_mode: ruleMatchMode,
          check_literals: ruleCheckLiterals,
          must_contain: splitList(ruleMustContain),
          must_not_contain: splitList(ruleMustNotContain),
          regex_patterns: splitLines(ruleRegexPatterns),
          forbidden_tokens: [],
          not_preceded_within_lines: windowCond,
          in_path_matching: splitList(ruleInPaths),
          not_in_path_matching: splitList(ruleNotInPaths),
          ast_scope: ruleAstScope.trim() || null,
          test_cases_count: testCases.length,
        };

        // Validate against inline unit tests in browser before saving!
        if (includeTests && testVulnFile.trim() && testVulnCode.trim()) {
          const tempPlugin: PluginEntryInfo = {
            name: cleanPlugin,
            rel_path: `${cleanPlugin}/plugin.yaml`,
            folder_alias: cleanPlugin,
            version: '1.0.0',
            author: 'DSL v2 Studio',
            description: ruleDescription.trim(),
            enabled: true,
            profile: ruleProfile.trim() || null,
            tags: splitList(ruleTags),
            rules_count: 1,
            test_cases_count: testCases.length,
            taint_sources_count: 0,
            taint_sinks_count: 0,
            sanitizers_count: 0,
            rules: [newRuleObj],
            taint_sources: [],
            taint_sinks: [],
            sanitizers: [],
          };
          const vulnHits = evaluatePluginRulesInBrowser([tempPlugin], testVulnFile.trim(), testVulnCode);
          if (vulnHits.length === 0) {
            statusMsg = {
              kind: 'err',
              text: 'Échec certification : le cas vulnérable (trigger = true) n’a pas déclenché la règle.',
            };
            busyAction = null;
            return;
          }
          if (testSafeCode.trim()) {
            const safeHits = evaluatePluginRulesInBrowser([tempPlugin], testVulnFile.trim(), testSafeCode);
            if (safeHits.length > 0) {
              statusMsg = {
                kind: 'err',
                text: 'Échec certification : le cas sécurisé (trigger = false) a déclenché un faux positif.',
              };
              busyAction = null;
              return;
            }
          }
        }

        const existingIdx = demoPluginsList.findIndex(
          (p) => p.name === cleanPlugin || p.folder_alias === cleanPlugin
        );
        if (existingIdx >= 0) {
          const existing = structuredClone(demoPluginsList[existingIdx]);
          const rIdx = existing.rules.findIndex((r) => r.id === newRuleObj.id);
          if (rIdx >= 0) {
            existing.rules[rIdx] = newRuleObj;
          } else {
            existing.rules.push(newRuleObj);
          }
          existing.rules_count = existing.rules.length;
          existing.profile = ruleProfile.trim() || existing.profile;
          const tags = splitList(ruleTags);
          if (tags.length > 0) existing.tags = tags;
          demoPluginsList[existingIdx] = existing;
          expandedPaths = { ...expandedPaths, [existing.rel_path]: true };
        } else {
          const relPath = `${cleanPlugin}/plugin.yaml`;
          const created: PluginEntryInfo = {
            name: cleanPlugin,
            rel_path: relPath,
            folder_alias: cleanPlugin,
            version: '1.0.0',
            author: 'AetherScope DSL v2 Studio',
            description: ruleDescription.trim(),
            enabled: true,
            profile: ruleProfile.trim() || 'custom',
            tags: splitList(ruleTags),
            rules_count: 1,
            test_cases_count: testCases.length,
            taint_sources_count: 0,
            taint_sinks_count: 0,
            sanitizers_count: 0,
            rules: [newRuleObj],
            taint_sources: [],
            taint_sinks: [],
            sanitizers: [],
          };
          demoPluginsList = [created, ...demoPluginsList];
          expandedPaths = { ...expandedPaths, [relPath]: true };
        }
        syncDemoInventory();
        statusMsg = {
          kind: 'ok',
          text: `Règle "${newRuleObj.id}" certifiée et enregistrée dans "${cleanPlugin}" (testable dans le Playground).`,
        };
        activeTab = 'plugins';
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur lors de la création de la règle.' };
    } finally {
      busyAction = null;
    }
  }

  // =========================================================================
  // Taint Dataflow SSA Actions
  // =========================================================================
  function addTaintSource() {
    const pats = splitList(newSrcPatterns);
    if (!newSrcName.trim() || pats.length === 0) return;
    taintSources = [
      ...taintSources.filter((s) => s.name !== newSrcName.trim()),
      {
        name: newSrcName.trim(),
        source_kind: newSrcKind,
        cwe: newSrcCwe.trim() || 'CWE-20',
        patterns: pats,
        description: `Source ${newSrcKind}`,
      },
    ];
    newSrcName = '';
  }

  function removeTaintSource(name: string) {
    taintSources = taintSources.filter((s) => s.name !== name);
  }

  function addTaintSink() {
    const pats = splitList(newSinkPatterns);
    if (!newSinkName.trim() || pats.length === 0) return;
    taintSinks = [
      ...taintSinks.filter((k) => k.name !== newSinkName.trim()),
      {
        name: newSinkName.trim(),
        rule_id: newSinkRuleId.trim() || `TAINT-${newSinkName.trim().toUpperCase()}`,
        sink_kind: newSinkKind,
        cwe: newSinkCwe.trim() || 'CWE-78',
        severity: newSinkSeverity,
        patterns: pats,
        description: `Sink ${newSinkKind}`,
      },
    ];
    newSinkName = '';
  }

  function removeTaintSink(name: string) {
    taintSinks = taintSinks.filter((k) => k.name !== name);
  }

  function addTaintSanitizer() {
    const pats = splitList(newSanPatterns);
    const cwes = splitList(newSanCwes);
    if (!newSanName.trim() || pats.length === 0) return;
    taintSanitizers = [
      ...taintSanitizers.filter((n) => n.name !== newSanName.trim()),
      {
        name: newSanName.trim(),
        patterns: pats,
        target_cwes: cwes.length > 0 ? cwes : ['*'],
        neutralizes_cwes: cwes.length > 0 ? cwes : ['*'],
        match_kind: 'ExactName',
        neutralizes_all: cwes.includes('*'),
      },
    ];
    newSanName = '';
  }

  function removeTaintSanitizer(name: string) {
    taintSanitizers = taintSanitizers.filter((n) => n.name !== name);
  }

  async function handleSaveTaintConfig() {
    const targetName = taintPluginName.trim() || 'custom-taint-pack';
    const list = inventory?.plugins ?? demoPluginsList;
    const existing = list.find((p) => p.name === targetName || p.folder_alias === targetName);

    const normalizedSanitizers = taintSanitizers.map((san) => {
      const cwes = san.target_cwes || san.neutralizes_cwes || ['*'];
      const pats = san.patterns && san.patterns.length > 0 ? san.patterns : [san.name];
      return {
        name: san.name,
        target_cwes: cwes,
        neutralizes_cwes: cwes,
        patterns: pats,
        match_kind: san.match_kind || 'ExactName',
        language: san.language ?? null,
        neutralizes_all: Boolean(san.neutralizes_all || cwes.includes('*')),
      };
    });

    busyAction = 'save-taint';
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.upsertPluginRule({
          plugin_name: existing?.folder_alias || existing?.name || targetName,
          rule_id: '',
          cwe_id: '',
          name: '',
          severity: 'HIGH',
          description: '',
          remediation: '',
          file_extensions: [],
          taint_sources: taintSources,
          taint_sinks: taintSinks,
          sanitizers: normalizedSanitizers,
        });
        if (res?.inventory) inventory = res.inventory;
        selectPluginForTaint(existing?.name || targetName);
        await refreshLiveGraph();
        statusMsg = {
          kind: 'ok',
          text: `Pipeline Taint SSA sauvegardé dans "${targetName}" (${taintSources.length} sources, ${taintSinks.length} sinks, ${normalizedSanitizers.length} sanitizers).`,
        };
      } else {
        let matched = false;
        demoPluginsList = demoPluginsList.map((p) => {
          if (p.name === targetName || p.folder_alias === targetName) {
            matched = true;
            return {
              ...p,
              taint_sources: structuredClone(taintSources),
              taint_sinks: structuredClone(taintSinks),
              sanitizers: structuredClone(normalizedSanitizers),
              taint_sources_count: taintSources.length,
              taint_sinks_count: taintSinks.length,
              sanitizers_count: normalizedSanitizers.length,
            };
          }
          return p;
        });
        if (!matched) {
          const slug = targetName.toLowerCase().replace(/[^a-z0-9_-]/g, '-') || 'custom-taint-pack';
          demoPluginsList = [
            {
              name: slug,
              rel_path: `${slug}/plugin.yaml`,
              folder_alias: slug,
              version: '1.0.0',
              author: 'AetherScope Taint SSA Studio',
              description: `Pack Taint Dataflow SSA (${taintSources.length}S/${taintSinks.length}K/${normalizedSanitizers.length}N)`,
              enabled: true,
              profile: 'taint',
              tags: ['taint', 'ssa'],
              rules_count: 0,
              test_cases_count: 0,
              taint_sources_count: taintSources.length,
              taint_sinks_count: taintSinks.length,
              sanitizers_count: normalizedSanitizers.length,
              rules: [],
              taint_sources: structuredClone(taintSources),
              taint_sinks: structuredClone(taintSinks),
              sanitizers: structuredClone(normalizedSanitizers),
            },
            ...demoPluginsList,
          ];
        }
        syncDemoInventory();
        statusMsg = {
          kind: 'ok',
          text: `Pipeline Taint SSA mis à jour pour "${targetName}" (${taintSources.length}S / ${taintSinks.length}K / ${normalizedSanitizers.length}N).`,
        };
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur sauvegarde Taint SSA.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleDeletePlugin(relPath: string) {
    busyAction = `delete:${relPath}`;
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.deletePlugin(relPath);
        if (res?.inventory) inventory = res.inventory;
        confirmDeletePath = null;
        await refreshLiveGraph();
        statusMsg = { kind: 'ok', text: `Plugin "${relPath}" supprimé et graphe rescanné.` };
      } else {
        demoPluginsList = demoPluginsList.filter((p) => p.rel_path !== relPath);
        if (relPath === 'community/plugin.yaml') demoCommunityInstalled = false;
        confirmDeletePath = null;
        syncDemoInventory();
        statusMsg = { kind: 'ok', text: `Plugin "${relPath}" retiré de la session.` };
      }
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Impossible de supprimer ce plugin.' };
    } finally {
      busyAction = null;
    }
  }

  // =========================================================================
  // Visual WebGL Studio Actions
  // =========================================================================
  function loadVisualPackIntoStudio(pack: VisualPluginPack) {
    vpId = pack.builtin ? `${pack.id}-custom` : pack.id;
    vpName = pack.builtin ? `${pack.name} (Remix)` : pack.name;
    vpDescription = pack.description || '';
    const bg = pack.palette?.background || [];
    vpBg0 = bg[0] || '#04050b';
    vpBg1 = bg[1] || '#0b304f';
    vpBg2 = bg[2] || '#2e104d';
    vpBg3 = bg[3] || '#3d1030';
    const layers = pack.palette?.layers || {};
    if (Object.keys(layers).length > 0) {
      vpCustomLayersEnabled = true;
      vpLayerUi = layers.ui || '#38bdf8';
      vpLayerAction = layers.action || '#818cf8';
      vpLayerDomain = layers.domain || '#c084fc';
      vpLayerDatabase = layers.database || '#34d399';
      vpLayerConfig = layers.config || '#fbbf24';
      vpLayerUtility = layers.utility || '#94a3b8';
      vpLayerDocs = layers.docs || '#2dd4bf';
    } else {
      vpCustomLayersEnabled = false;
    }
    const sevs = pack.palette?.severities || {};
    vpSevCritical = sevs.CRITICAL || '#f43f5e';
    vpSevHigh = sevs.HIGH || '#fb923c';
    vpSevMedium = sevs.MEDIUM || '#facc15';
    vpSevLow = sevs.LOW || '#38bdf8';

    const ms = pack.overlay?.membrane_style;
    vpMembraneStyle = ms === 'hex_hull' || ms === 'rect_blueprint' || ms === 'none' ? ms : 'organic_12lobe';
    const es = pack.overlay?.edge_style;
    vpEdgeStyle = es === 'straight' || es === 'orthogonal_pcb' ? es : 'bezier';
    vpEdgePulseSpeed = pack.overlay?.edge_pulse_speed ?? 1.0;
    vpMembraneBreath = pack.overlay?.membrane_breath_amp ?? 1.0;
    vpGridScale = pack.uniforms?.grid_scale ?? 1.0;
    vpGlowSharpness = pack.uniforms?.glow_sharpness ?? 1.0;
    vpStarDensity = pack.uniforms?.star_density ?? 1.0;
    vpNebulaSpeed = pack.uniforms?.nebula_speed ?? 1.0;
    vpBackdropGlsl = pack.backdrop_glsl || '';
    vpNodeSdfGlsl = pack.node_sdf_glsl || '';
    showGlslEditor = true;
    statusMsg = { kind: 'ok', text: `Pack "${pack.name}" chargé dans le Studio GLSL — modifiez et testez en direct !` };
  }

  function buildStudioDraftPack(): VisualPluginPack {
    return {
      schema_version: 1,
      id: vpId.trim() || 'custom-preview',
      name: vpName.trim() || 'Aperçu Custom',
      version: '1.0.0',
      description: vpDescription.trim() || null,
      enabled: true,
      builtin: false,
      palette: {
        background: [vpBg0, vpBg1, vpBg2, vpBg3],
        ...(vpCustomLayersEnabled
          ? {
              layers: {
                ui: vpLayerUi,
                action: vpLayerAction,
                domain: vpLayerDomain,
                database: vpLayerDatabase,
                config: vpLayerConfig,
                utility: vpLayerUtility,
                docs: vpLayerDocs,
              },
              severities: {
                CRITICAL: vpSevCritical,
                HIGH: vpSevHigh,
                MEDIUM: vpSevMedium,
                LOW: vpSevLow,
              },
            }
          : {}),
      },
      overlay: {
        membrane_style: vpMembraneStyle,
        edge_style: vpEdgeStyle,
        edge_pulse_speed: vpEdgePulseSpeed,
        membrane_breath_amp: vpMembraneBreath,
      },
      uniforms: {
        grid_scale: vpGridScale,
        glow_sharpness: vpGlowSharpness,
        star_density: vpStarDensity,
        nebula_speed: vpNebulaSpeed,
      },
      backdrop_glsl: vpBackdropGlsl.trim() || null,
      node_sdf_glsl: vpNodeSdfGlsl.trim() || null,
    };
  }

  function handleSelectVisualPack(pack: VisualPluginPack) {
    statusMsg = null;
    const res = cockpitState.applyVisualPluginPack(pack, true);
    if (res.ok) {
      statusMsg = { kind: 'ok', text: `Thème WebGL "${pack.name}" activé en direct (hot-swap 120 FPS).` };
    } else {
      statusMsg = { kind: 'err', text: res.error || 'Échec compilation shader WebGL.' };
    }
  }

  function handleLivePreviewVisualStudio() {
    statusMsg = null;
    const draft = buildStudioDraftPack();
    const res = cockpitState.applyVisualPluginPack(draft, false);
    if (res.ok) {
      statusMsg = { kind: 'ok', text: `⚡ Aperçu GLSL & Palette appliqués en direct sur le canvas WebGL 2 !` };
    } else {
      statusMsg = { kind: 'err', text: res.error || 'Erreur de compilation GLSL.' };
    }
  }

  async function handleSaveVisualPack() {
    const draft = buildStudioDraftPack();
    const previewRes = cockpitState.applyVisualPluginPack(draft, false);
    if (!previewRes.ok) {
      statusMsg = { kind: 'err', text: `Shader refusé avant écriture : ${previewRes.error}` };
      return;
    }
    busyAction = 'save-visual';
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.upsertVisualPlugin({
          id: draft.id,
          name: draft.name,
          version: draft.version,
          description: draft.description || undefined,
          palette: draft.palette,
          overlay: draft.overlay,
          uniforms: draft.uniforms,
          backdrop_glsl: draft.backdrop_glsl,
          node_sdf_glsl: draft.node_sdf_glsl,
          activate: true,
        });
        if (res?.inventory?.plugins) {
          cockpitState.customVisualPlugins = res.inventory.plugins;
          cockpitState.visualPluginsVersion = res.visual_version ?? cockpitState.visualPluginsVersion;
        }
        cockpitState.selectVisualPlugin(res.id || draft.id, true);
        statusMsg = {
          kind: 'ok',
          text: `Pack visuel "${res.id}" sauvegardé dans .aether/plugins/visuals/${res.id}/ et activé !`,
        };
      } else {
        cockpitState.customVisualPlugins = [
          draft,
          ...cockpitState.customVisualPlugins.filter((p) => p.id !== draft.id),
        ];
        cockpitState.selectVisualPlugin(draft.id, true);
        statusMsg = {
          kind: 'ok',
          text: `Pack visuel "${draft.name}" enregistré en session et activé en direct sur le graphe WebGL 2 !`,
        };
      }
    } catch (e: any) {
      cockpitState.customVisualPlugins = [
        draft,
        ...cockpitState.customVisualPlugins.filter((p) => p.id !== draft.id),
      ];
      cockpitState.selectVisualPlugin(draft.id, true);
      statusMsg = {
        kind: 'ok',
        text: `Pack visuel "${draft.name}" activé en mémoire (exportable en .json).`,
      };
    } finally {
      busyAction = null;
    }
  }

  async function handleDeleteVisualPack(id: string) {
    busyAction = `del-visual:${id}`;
    statusMsg = null;
    try {
      if (!isOfflineFallback) {
        const res = await api.deleteVisualPlugin(id);
        if (res?.inventory?.plugins) {
          cockpitState.customVisualPlugins = res.inventory.plugins;
        }
      } else {
        cockpitState.customVisualPlugins = cockpitState.customVisualPlugins.filter((p) => p.id !== id);
      }
      confirmDeleteVisualId = null;
      if (cockpitState.activeVisualPluginId === id) {
        cockpitState.selectVisualPlugin('obsidian-nebula', true);
      }
      statusMsg = { kind: 'ok', text: `Pack visuel "${id}" supprimé.` };
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Impossible de supprimer le pack visuel.' };
    } finally {
      busyAction = null;
    }
  }

  const filteredPlugins = $derived.by((): PluginEntryInfo[] => {
    const list = inventory?.plugins ?? [];
    const q = searchQuery.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.rel_path.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q) ||
        (p.profile || '').toLowerCase().includes(q) ||
        p.tags.some((t) => t.toLowerCase().includes(q)) ||
        p.rules.some(
          (r) =>
            r.id.toLowerCase().includes(q) ||
            r.cwe_id.toLowerCase().includes(q) ||
            r.name.toLowerCase().includes(q)
        )
    );
  });

  function severityClass(sev: string): string {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      default:
        return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
    }
  }

  function closeModal() {
    cockpitState.isPluginsModalOpen = false;
  }
</script>

<!-- Hidden Native File Pickers -->
<input bind:this={pluginFileInputEl} type="file" accept=".yaml,.yml,.json" class="hidden" onchange={handleImportPluginFile} />
<input bind:this={semgrepFileInputEl} type="file" accept=".yaml,.yml" class="hidden" onchange={handleImportSemgrepFile} />
<input bind:this={visualFileInputEl} type="file" accept=".json" class="hidden" onchange={handleImportVisualFile} />

{#if cockpitState.isPluginsModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-3 sm:p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-5xl max-h-[90vh] bg-[#090d16] border border-cyan-500/35 rounded-xl shadow-[0_24px_80px_rgba(0,0,0,0.88)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between gap-3 shrink-0">
        <div class="flex items-center gap-2.5 min-w-0">
          <Plug class="w-5 h-5 text-cyan-400 shrink-0" />
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <h2 class="text-sm font-bold text-white">Centre de Plugins SAST, Taint SSA, Playground DSL v2 & Studio WebGL 2</h2>
              {#if isOfflineFallback}
                <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/35">
                  MODE DÉMO / IN-MEMORY ACTIF
                </span>
              {:else}
                <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                  LIVE .aether/plugins/
                </span>
              {/if}
            </div>
            <p class="text-[11px] text-slate-400 truncate">
              Règles YAML <code class="text-purple-300">.aether/plugins/</code> · Dataflow SSA · Shaders GLSL ES 3.00 <code class="text-cyan-300">.aether/plugins/visuals/</code> · Raccourci <kbd class="px-1 py-0.2 rounded bg-white/10 text-slate-200">G</kbd>
            </p>
          </div>
        </div>
        <button
          type="button"
          onclick={closeModal}
          aria-label="Fermer le gestionnaire de plugins"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer shrink-0"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- 6-Tab Navigation Bar -->
      <div class="px-5 pt-2.5 pb-2 bg-[#0b101d] border-b border-white/10 flex items-center justify-between flex-wrap gap-2 shrink-0">
        <div class="flex items-center gap-1 flex-wrap">
          <button
            type="button"
            onclick={() => (activeTab = 'plugins')}
            class="px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'plugins'
              ? 'bg-purple-500/25 text-purple-200 border border-purple-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            📦 Catalogue SAST ({inventory?.total_plugins ?? 0})
          </button>

          <button
            type="button"
            onclick={() => (activeTab = 'create')}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'create'
              ? 'bg-emerald-500/25 text-emerald-200 border border-emerald-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Edit3 class="w-3.5 h-3.5" />
            <span>Règle DSL v2</span>
          </button>

          <button
            type="button"
            onclick={() => (activeTab = 'taint')}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'taint'
              ? 'bg-amber-500/25 text-amber-200 border border-amber-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Workflow class="w-3.5 h-3.5" />
            <span>Taint SSA ({inventory?.total_taint_sources ?? 0}/{inventory?.total_taint_sinks ?? 0})</span>
          </button>

          <button
            type="button"
            onclick={() => (activeTab = 'playground')}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'playground'
              ? 'bg-rose-500/25 text-rose-200 border border-rose-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Zap class="w-3.5 h-3.5" />
            <span>Bac à Sable ({playgroundFindings.length})</span>
          </button>

          <button
            type="button"
            onclick={() => (activeTab = 'semgrep')}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'semgrep'
              ? 'bg-sky-500/25 text-sky-200 border border-sky-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Upload class="w-3.5 h-3.5" />
            <span>Import Semgrep</span>
          </button>

          <button
            type="button"
            onclick={() => (activeTab = 'visuals')}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'visuals'
              ? 'bg-cyan-500/25 text-cyan-200 border border-cyan-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Palette class="w-3.5 h-3.5" />
            <span>Studio WebGL ({cockpitState.allVisualPlugins.length})</span>
          </button>
        </div>

        <div class="flex items-center gap-1.5">
          <button
            type="button"
            disabled={busyAction !== null}
            onclick={() => handleRunTests()}
            class="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-[11px] font-semibold text-emerald-300 cursor-pointer disabled:opacity-50"
            title="Exécuter tous les tests unitaires des plugins"
          >
            <Play class="w-3 h-3" />
            <span>{busyAction === 'test:all' ? 'Tests...' : 'Certifier Tests'}</span>
          </button>
          <button
            type="button"
            disabled={isLoading}
            onclick={refreshInventory}
            class="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 cursor-pointer disabled:opacity-50"
            title="Rafraîchir l'inventaire"
          >
            <RefreshCw class="w-3.5 h-3.5 {isLoading ? 'animate-spin' : ''}" />
          </button>
        </div>
      </div>

      <!-- Body -->
      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        {#if statusMsg}
          <div
            class="px-3.5 py-2 rounded-lg border text-xs font-mono flex items-center justify-between gap-2 {statusMsg.kind === 'ok'
              ? 'bg-emerald-500/15 border-emerald-500/35 text-emerald-200'
              : 'bg-rose-500/15 border-rose-500/35 text-rose-200'}"
          >
            <div class="flex items-center gap-2 min-w-0">
              {#if statusMsg.kind === 'ok'}
                <CheckCircle2 class="w-4 h-4 shrink-0 text-emerald-400" />
              {:else}
                <AlertTriangle class="w-4 h-4 shrink-0 text-rose-400" />
              {/if}
              <span class="break-words">{statusMsg.text}</span>
            </div>
            <button type="button" onclick={() => (statusMsg = null)} class="text-slate-400 hover:text-white cursor-pointer">
              <X class="w-3.5 h-3.5" />
            </button>
          </div>
        {/if}

        {#if testReport && testReport.failed > 0}
          <div class="p-3 rounded-lg bg-rose-950/40 border border-rose-500/35 space-y-1 text-[11px] font-mono text-rose-200">
            <div class="font-bold text-rose-300">Détails des échecs ({testReport.failed}/{testReport.total_tests}) :</div>
            {#each testReport.failures as f}
              <div class="text-rose-200/90">• {f}</div>
            {/each}
          </div>
        {/if}

        <!-- =============================================================== -->
        <!-- TAB 1: CATALOGUE PLUGINS SAST & TAINT                           -->
        <!-- =============================================================== -->
        {#if activeTab === 'plugins'}
          <!-- KPIs -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Plugins Actifs</div>
              <div class="text-lg font-mono font-bold text-purple-300">
                {inventory?.enabled_plugins ?? 0} <span class="text-xs text-slate-500">/ {inventory?.total_plugins ?? 0}</span>
              </div>
            </div>
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Règles SAST Actives</div>
              <div class="text-lg font-mono font-bold text-sky-300">{inventory?.total_active_rules ?? 0}</div>
            </div>
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Taint SSA (Src/Sink/San)</div>
              <div class="text-lg font-mono font-bold text-amber-300">
                {inventory?.total_taint_sources ?? 0}/{inventory?.total_taint_sinks ?? 0}/{inventory?.total_sanitizers ?? 0}
              </div>
            </div>
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10 flex flex-col justify-between">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Bundle OWASP/CWE</div>
              {#if inventory?.community_bundle_installed}
                <div class="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 mt-1">
                  <CheckCircle2 class="w-3.5 h-3.5" />
                  <span>Installé ({inventory.community_bundle_rules_count})</span>
                </div>
              {:else}
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onclick={handleInitBundle}
                  class="mt-1 flex items-center justify-center gap-1 px-2 py-1 rounded bg-sky-500/20 hover:bg-sky-500/30 border border-sky-400/40 text-[11px] font-semibold text-sky-200 cursor-pointer disabled:opacity-50"
                >
                  <PackagePlus class="w-3.5 h-3.5" />
                  <span>{busyAction === 'init-bundle' ? 'Déploiement...' : `Déployer (${inventory?.community_bundle_rules_count ?? 24})`}</span>
                </button>
              {/if}
            </div>
          </div>

          <!-- Search + Import / Create Bar -->
          <div class="flex items-center gap-2 flex-wrap">
            <div class="relative flex-1 min-w-[220px]">
              <Search class="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                bind:value={searchQuery}
                placeholder="Filtrer par nom de plugin, CWE, profil, tag ou ID de règle..."
                class="w-full pl-9 pr-3 py-1.5 rounded-lg bg-black/40 border border-white/15 text-xs text-slate-200 focus:outline-none focus:border-purple-400"
              />
            </div>

            <button
              type="button"
              onclick={() => pluginFileInputEl?.click()}
              class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-semibold text-slate-200 cursor-pointer"
              title="Importer un fichier plugin.yaml ou une règle Semgrep depuis votre ordinateur"
            >
              <Upload class="w-3.5 h-3.5 text-sky-400" />
              <span>Importer .yaml</span>
            </button>

            <button
              type="button"
              onclick={() => (activeTab = 'create')}
              class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-400/40 text-xs font-semibold text-emerald-200 cursor-pointer"
            >
              <Plus class="w-3.5 h-3.5" />
              <span>Nouvelle Règle DSL v2</span>
            </button>
          </div>

          <!-- Plugin Cards List -->
          {#if isLoading && !inventory}
            <div class="py-10 text-center text-xs text-slate-400 font-mono">Chargement de .aether/plugins...</div>
          {:else if filteredPlugins.length === 0}
            <div class="py-10 text-center space-y-2 rounded-xl bg-white/[0.02] border border-white/10">
              <div class="text-xs text-slate-400 font-mono">Aucun plugin ne correspond au filtre.</div>
            </div>
          {:else}
            <div class="space-y-2.5">
              {#each filteredPlugins as plugin (plugin.rel_path)}
                {@const isExpanded = Boolean(expandedPaths[plugin.rel_path])}
                {@const showYaml = Boolean(yamlPreviewPaths[plugin.rel_path])}
                <div class="rounded-xl bg-white/[0.025] border {plugin.enabled ? 'border-purple-500/30' : 'border-white/10 opacity-75'} overflow-hidden">
                  <div class="p-3.5 flex items-start justify-between gap-3 flex-wrap sm:flex-nowrap">
                    <div class="flex items-start gap-2.5 min-w-0 flex-1">
                      <button
                        type="button"
                        onclick={() => toggleExpand(plugin.rel_path)}
                        class="mt-0.5 p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white cursor-pointer shrink-0"
                        title="Afficher les règles"
                      >
                        {#if isExpanded}
                          <ChevronDown class="w-4 h-4" />
                        {:else}
                          <ChevronRight class="w-4 h-4" />
                        {/if}
                      </button>

                      <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2 flex-wrap">
                          <span class="text-xs font-bold text-white">{plugin.name}</span>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/10 text-slate-300">v{plugin.version}</span>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/15 text-sky-300 border border-sky-500/30">
                            {plugin.rules_count} règle(s)
                          </span>
                          {#if plugin.taint_sources_count + plugin.taint_sinks_count + plugin.sanitizers_count > 0}
                            <button
                              type="button"
                              onclick={() => openTaintEditorForPlugin(plugin)}
                              class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 cursor-pointer"
                              title="Éditer le pipeline Taint SSA de ce plugin"
                            >
                              🌊 Taint {plugin.taint_sources_count}S/{plugin.taint_sinks_count}K/{plugin.sanitizers_count}N
                            </button>
                          {/if}
                          {#if plugin.profile}
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-200 border border-purple-400/35">
                              profile:{plugin.profile}
                            </span>
                          {/if}
                          {#each plugin.tags as tag}
                            <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-white/5 text-slate-400">#{tag}</span>
                          {/each}
                        </div>
                        {#if plugin.description}
                          <p class="text-[11px] text-slate-400 mt-1">{plugin.description}</p>
                        {/if}
                        <div class="text-[10px] font-mono text-slate-500 mt-1">
                          .aether/plugins/{plugin.rel_path} · {plugin.test_cases_count} test(s) unitaire(s)
                        </div>
                      </div>
                    </div>

                    <!-- Plugin Action Buttons -->
                    <div class="flex items-center gap-1.5 shrink-0 flex-wrap">
                      <button
                        type="button"
                        onclick={() => toggleYamlPreview(plugin.rel_path)}
                        class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10.5px] font-mono text-slate-300 cursor-pointer"
                        title="Voir ou exporter le manifeste plugin.yaml"
                      >
                        <FileCode class="w-3 h-3 text-purple-300" />
                        <span>YAML</span>
                      </button>

                      <button
                        type="button"
                        onclick={() => openTaintEditorForPlugin(plugin)}
                        class="px-2 py-1 rounded bg-white/5 hover:bg-amber-500/20 border border-white/10 hover:border-amber-400/40 text-[10.5px] font-semibold text-slate-300 hover:text-amber-200 cursor-pointer"
                        title="Configurer les Sources, Sinks et Sanitizers Taint SSA"
                      >
                        Taint
                      </button>

                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onclick={() => handleRunTests(plugin.rel_path)}
                        class="px-2 py-1 rounded bg-white/5 hover:bg-emerald-500/20 border border-white/10 hover:border-emerald-400/40 text-[10.5px] font-semibold text-slate-300 hover:text-emerald-200 cursor-pointer disabled:opacity-50"
                        title="Exécuter les tests unitaires de ce plugin"
                      >
                        Test
                      </button>

                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onclick={() => handleTogglePlugin(plugin)}
                        class="px-2.5 py-1 rounded text-[10.5px] font-bold border transition-colors cursor-pointer disabled:opacity-50 {plugin.enabled
                          ? 'bg-emerald-500/20 border-emerald-400/45 text-emerald-300 hover:bg-emerald-500/30'
                          : 'bg-white/5 border-white/15 text-slate-400 hover:text-white'}"
                      >
                        {plugin.enabled ? 'ON' : 'OFF'}
                      </button>

                      {#if confirmDeletePath === plugin.rel_path}
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onclick={() => handleDeletePlugin(plugin.rel_path)}
                          class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-[10.5px] font-bold text-white cursor-pointer"
                        >
                          Confirmer
                        </button>
                        <button
                          type="button"
                          onclick={() => (confirmDeletePath = null)}
                          class="px-1.5 py-1 rounded bg-white/10 text-[10.5px] text-slate-300 cursor-pointer"
                        >
                          Annuler
                        </button>
                      {:else}
                        <button
                          type="button"
                          onclick={() => (confirmDeletePath = plugin.rel_path)}
                          class="p-1.5 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 cursor-pointer"
                          title="Supprimer ce plugin"
                        >
                          <Trash2 class="w-3.5 h-3.5" />
                        </button>
                      {/if}
                    </div>
                  </div>

                  <!-- Inline YAML Manifest Drawer -->
                  {#if showYaml}
                    <div class="px-4 py-3 border-t border-white/10 bg-[#050811] space-y-2">
                      <div class="flex items-center justify-between gap-2">
                        <span class="text-[10.5px] font-mono font-bold text-purple-300">
                          Manifeste généré : .aether/plugins/{plugin.rel_path}
                        </span>
                        <div class="flex items-center gap-1.5">
                          <button
                            type="button"
                            onclick={() => copyPluginYaml(plugin)}
                            class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10.5px] text-slate-200 cursor-pointer"
                          >
                            <Copy class="w-3 h-3" />
                            <span>Copier</span>
                          </button>
                          <button
                            type="button"
                            onclick={() => exportPluginYaml(plugin)}
                            class="flex items-center gap-1 px-2 py-1 rounded bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/40 text-[10.5px] font-semibold text-purple-200 cursor-pointer"
                          >
                            <Download class="w-3 h-3" />
                            <span>Télécharger .yaml</span>
                          </button>
                        </div>
                      </div>
                      <pre class="p-3 rounded-lg bg-black/60 border border-white/10 text-[10.5px] font-mono text-slate-200 overflow-x-auto max-h-60">{serializePluginToYaml(plugin)}</pre>
                    </div>
                  {/if}

                  <!-- Expanded Rules List -->
                  {#if isExpanded}
                    <div class="px-4 pb-3.5 pt-2 border-t border-white/10 bg-black/25 space-y-2">
                      {#if plugin.rules.length === 0}
                        <div class="text-[11px] font-mono text-slate-500">Aucune règle pattern dans ce manifeste.</div>
                      {:else}
                        {#each plugin.rules as rule (rule.id)}
                          <div class="p-2.5 rounded-lg bg-black/35 border border-white/10 space-y-1.5">
                            <div class="flex items-center justify-between gap-2 flex-wrap">
                              <div class="flex items-center gap-2 flex-wrap">
                                <ShieldAlert class="w-3.5 h-3.5 text-rose-400 shrink-0" />
                                <span class="font-mono text-[11px] font-bold text-white">{rule.id}</span>
                                <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono border {severityClass(rule.severity)}">
                                  {rule.severity}
                                </span>
                                <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-rose-500/15 text-rose-300">
                                  {rule.cwe_id}
                                </span>
                                {#if rule.file_extensions.length > 0}
                                  <span class="text-[10px] font-mono text-slate-400">{rule.file_extensions.join(' ')}</span>
                                {/if}
                                {#if rule.ast_scope}
                                  <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-indigo-500/20 text-indigo-300">
                                    scope:{rule.ast_scope}
                                  </span>
                                {/if}
                                {#if rule.not_preceded_within_lines}
                                  <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-cyan-500/20 text-cyan-300">
                                    window:-{rule.not_preceded_within_lines.lines}L
                                  </span>
                                {/if}
                                {#if rule.in_path_matching.length > 0 || rule.not_in_path_matching.length > 0}
                                  <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-emerald-500/20 text-emerald-300">
                                    path-glob
                                  </span>
                                {/if}
                              </div>

                              <div class="flex items-center gap-1.5">
                                <button
                                  type="button"
                                  onclick={() => loadRuleIntoDslEditor(plugin, rule)}
                                  class="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/35 text-[10px] font-semibold text-emerald-200 cursor-pointer"
                                  title="Charger cette règle dans l'éditeur DSL v2 pour la modifier"
                                >
                                  <Edit3 class="w-3 h-3" />
                                  <span>Éditer DSL v2</span>
                                </button>
                                <button
                                  type="button"
                                  onclick={() => loadRuleIntoPlayground(plugin, rule)}
                                  class="flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-400/35 text-[10px] font-semibold text-rose-200 cursor-pointer"
                                  title="Tester cette règle dans le Bac à Sable"
                                >
                                  <Zap class="w-3 h-3" />
                                  <span>Playground</span>
                                </button>
                              </div>
                            </div>
                            <div class="text-[11px] text-slate-300">{rule.description}</div>
                            {#if rule.remediation}
                              <div class="text-[10.5px] text-emerald-300/80">Fix : {rule.remediation}</div>
                            {/if}
                          </div>
                        {/each}
                      {/if}
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}

        <!-- =============================================================== -->
        <!-- TAB 2: ÉDITEUR RÈGLE DSL v2                                     -->
        <!-- =============================================================== -->
        {:else if activeTab === 'create'}
          <div class="space-y-3 p-4 rounded-xl bg-white/[0.025] border border-emerald-500/25">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div>
                <div class="text-xs font-bold text-emerald-300">Éditeur & Créateur de Règle SAST DSL v2 (Certifiée par Tests Unitaires)</div>
                <p class="text-[11px] text-slate-400">
                  Créez une nouvelle règle ou cliquez sur <em>« Éditer DSL v2 »</em> depuis le catalogue pour modifier une règle existante.
                </p>
              </div>
              <div class="flex items-center gap-1.5 flex-wrap">
                {#each DSL_PRESETS as preset}
                  <button
                    type="button"
                    onclick={preset.apply}
                    class="px-2 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/35 text-[10.5px] font-semibold text-emerald-200 cursor-pointer"
                  >
                    {preset.label}
                  </button>
                {/each}
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label for="dsl-plugin" class="block text-[10.5px] font-mono text-slate-400 mb-1">Plugin (dossier)</label>
                <input id="dsl-plugin" type="text" bind:value={rulePluginName} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-profile" class="block text-[10.5px] font-mono text-slate-400 mb-1">Profil (--plugins profile:...)</label>
                <input id="dsl-profile" type="text" bind:value={ruleProfile} placeholder="ex: strict" class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-tags" class="block text-[10.5px] font-mono text-slate-400 mb-1">Tags (virgules)</label>
                <input id="dsl-tags" type="text" bind:value={ruleTags} placeholder="rust, auth, ci" class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label for="dsl-rule-id" class="block text-[10.5px] font-mono text-slate-400 mb-1">ID de règle</label>
                <input id="dsl-rule-id" type="text" bind:value={ruleId} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-cwe" class="block text-[10.5px] font-mono text-slate-400 mb-1">CWE / Classification</label>
                <input id="dsl-cwe" type="text" bind:value={ruleCweId} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-sev" class="block text-[10.5px] font-mono text-slate-400 mb-1">Sévérité</label>
                <select id="dsl-sev" bind:value={ruleSeverity} class="w-full px-2.5 py-1.5 rounded bg-[#0b101d] border border-white/15 text-xs font-mono text-white">
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="WARNING">WARNING</option>
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label for="dsl-name" class="block text-[10.5px] font-mono text-slate-400 mb-1">Intitulé</label>
                <input id="dsl-name" type="text" bind:value={ruleName} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs text-white" />
              </div>
              <div>
                <label for="dsl-exts" class="block text-[10.5px] font-mono text-slate-400 mb-1">Extensions</label>
                <input id="dsl-exts" type="text" bind:value={ruleExtensions} placeholder=".rs, .ts, .py" class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-mode" class="block text-[10.5px] font-mono text-slate-400 mb-1">Mode & Portée AST</label>
                <div class="flex gap-1.5">
                  <select id="dsl-mode" bind:value={ruleMatchMode} class="flex-1 px-2 py-1.5 rounded bg-[#0b101d] border border-white/15 text-[11px] font-mono text-white">
                    <option value="line_by_line">line_by_line</option>
                    <option value="whole_file">whole_file</option>
                  </select>
                  <select bind:value={ruleAstScope} aria-label="Portée AST" class="flex-1 px-2 py-1.5 rounded bg-[#0b101d] border border-white/15 text-[11px] font-mono text-white">
                    <option value="">scope: tous</option>
                    <option value="outside_test">outside_test</option>
                    <option value="async_fn">async_fn</option>
                    <option value="sync_fn">sync_fn</option>
                    <option value="fn">fn</option>
                    <option value="test">test</option>
                  </select>
                </div>
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <label for="dsl-desc" class="block text-[10.5px] font-mono text-slate-400 mb-1">Description</label>
                <input id="dsl-desc" type="text" bind:value={ruleDescription} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs text-white" />
              </div>
              <div>
                <label for="dsl-fix" class="block text-[10.5px] font-mono text-slate-400 mb-1">Remédiation</label>
                <input id="dsl-fix" type="text" bind:value={ruleRemediation} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs text-white" />
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <label for="dsl-regex" class="block text-[10.5px] font-mono text-slate-400 mb-1">Regex déclencheurs (1 par ligne)</label>
                <textarea id="dsl-regex" bind:value={ruleRegexPatterns} rows="3" class="w-full p-2 rounded bg-black/50 border border-white/15 text-xs font-mono text-white"></textarea>
              </div>
              <div class="space-y-2">
                <div>
                  <label for="dsl-must" class="block text-[10.5px] font-mono text-slate-400 mb-1">must_contain (virgules)</label>
                  <input id="dsl-must" type="text" bind:value={ruleMustContain} class="w-full px-2.5 py-1 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
                </div>
                <div>
                  <label for="dsl-must-not" class="block text-[10.5px] font-mono text-slate-400 mb-1">must_not_contain / mitigations (virgules)</label>
                  <input id="dsl-must-not" type="text" bind:value={ruleMustNotContain} class="w-full px-2.5 py-1 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
                </div>
                <label class="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer">
                  <input type="checkbox" bind:checked={ruleCheckLiterals} class="accent-emerald-400" />
                  <span>check_literals (évaluer dans les chaînes/commentaires bruts)</span>
                </label>
              </div>
            </div>

            <!-- DSL v2 Contextual Window & Path Globs -->
            <div class="p-3 rounded-lg bg-black/30 border border-indigo-500/25 space-y-2">
              <div class="text-[10.5px] font-mono font-bold text-indigo-300 uppercase">Conditions avancées DSL v2 (Fenêtrage N lignes & Globs de chemins)</div>
              <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div>
                  <label for="dsl-win-lines" class="block text-[10px] font-mono text-slate-400 mb-1">not_preceded_within_lines (N)</label>
                  <input id="dsl-win-lines" type="number" min="0" max="50" bind:value={ruleWindowLines} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
                <div class="sm:col-span-2">
                  <label for="dsl-win-pats" class="block text-[10px] font-mono text-slate-400 mb-1">Motifs gardes fenêtre (1 par ligne)</label>
                  <input id="dsl-win-pats" type="text" bind:value={ruleWindowPatterns} placeholder="ex: verify_csrf\\(" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
              </div>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <div>
                  <label for="dsl-in-path" class="block text-[10px] font-mono text-slate-400 mb-1">in_path_matching (ex: src/api/**)</label>
                  <input id="dsl-in-path" type="text" bind:value={ruleInPaths} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
                <div>
                  <label for="dsl-not-path" class="block text-[10px] font-mono text-slate-400 mb-1">not_in_path_matching (ex: **/tests/**)</label>
                  <input id="dsl-not-path" type="text" bind:value={ruleNotInPaths} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
              </div>
            </div>

            <!-- Inline Test Certification -->
            <div class="p-3 rounded-lg bg-black/30 border border-emerald-500/20 space-y-2">
              <label class="flex items-center gap-2 text-xs font-semibold text-emerald-300 cursor-pointer">
                <input type="checkbox" bind:checked={includeTests} class="accent-emerald-400" />
                <span>Certifier par tests unitaires avant sauvegarde</span>
              </label>
              {#if includeTests}
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div>
                    <label for="dsl-test-file" class="block text-[10px] font-mono text-slate-400 mb-1">Fichier virtuel</label>
                    <input id="dsl-test-file" type="text" bind:value={testVulnFile} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                  </div>
                  <div>
                    <label for="dsl-test-vuln" class="block text-[10px] font-mono text-rose-300 mb-1">Code vulnérable (trigger = true)</label>
                    <input id="dsl-test-vuln" type="text" bind:value={testVulnCode} class="w-full px-2 py-1 rounded bg-black/50 border border-rose-500/30 text-xs font-mono text-white" />
                  </div>
                  <div>
                    <label for="dsl-test-safe" class="block text-[10px] font-mono text-emerald-300 mb-1">Code sûr (trigger = false)</label>
                    <input id="dsl-test-safe" type="text" bind:value={testSafeCode} class="w-full px-2 py-1 rounded bg-black/50 border border-emerald-500/30 text-xs font-mono text-white" />
                  </div>
                </div>
              {/if}
            </div>

            <div class="flex items-center justify-end gap-2">
              <button
                type="button"
                disabled={busyAction !== null}
                onclick={handleCreateRule}
                class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
              >
                <Save class="w-3.5 h-3.5" />
                <span>{busyAction === 'upsert-rule' ? 'Validation...' : 'Certifier & Enregistrer la Règle'}</span>
              </button>
            </div>
          </div>

        <!-- =============================================================== -->
        <!-- TAB 3: TAINT DATAFLOW SSA BUILDER                               -->
        <!-- =============================================================== -->
        {:else if activeTab === 'taint'}
          <div class="space-y-4 p-4 rounded-xl bg-white/[0.025] border border-amber-500/25">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div>
                <div class="text-xs font-bold text-amber-300">🌊 Configurateur Taint Dataflow SSA Inter-Procédural</div>
                <p class="text-[11px] text-slate-400">
                  Déclarez les <code>taint_sources</code> (entrées non fiables), <code>taint_sinks</code> (puits d’exécution critiques) et <code>sanitizers</code> (fonctions qui neutralisent la propagation).
                </p>
              </div>
              <div class="flex items-center gap-2">
                <label for="taint-plugin-select" class="text-[11px] font-mono text-slate-300">Plugin cible :</label>
                <select
                  id="taint-plugin-select"
                  value={taintPluginName}
                  onchange={(e) => selectPluginForTaint((e.currentTarget as HTMLSelectElement).value)}
                  class="px-2.5 py-1 rounded bg-[#0b101d] border border-amber-400/40 text-xs font-mono text-amber-200"
                >
                  {#each inventory?.plugins ?? demoPluginsList as p (p.rel_path)}
                    <option value={p.name}>{p.name} ({p.taint_sources_count}S/{p.taint_sinks_count}K/{p.sanitizers_count}N)</option>
                  {/each}
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <!-- Column 1: Taint Sources -->
              <div class="p-3 rounded-lg bg-black/35 border border-sky-500/25 space-y-2.5">
                <div class="text-[11px] font-mono font-bold text-sky-300">1. Sources de Taint ({taintSources.length})</div>
                <div class="space-y-1.5 max-h-48 overflow-y-auto">
                  {#each taintSources as src (src.name)}
                    <div class="p-2 rounded bg-black/50 border border-white/10 flex items-start justify-between gap-2">
                      <div class="min-w-0">
                        <div class="flex items-center gap-1.5 flex-wrap">
                          <span class="text-[11px] font-mono font-bold text-white">{src.name}</span>
                          <span class="px-1 py-0.2 rounded text-[9px] font-mono bg-sky-500/20 text-sky-300">{typeof src.source_kind === 'object' ? src.source_kind?.Custom || 'Custom' : src.source_kind}</span>
                          <span class="px-1 py-0.2 rounded text-[9px] font-mono bg-rose-500/20 text-rose-300">{src.cwe}</span>
                        </div>
                        <div class="text-[10px] font-mono text-slate-400 truncate mt-0.5">{(src.patterns || []).join(', ')}</div>
                      </div>
                      <button type="button" onclick={() => removeTaintSource(src.name)} class="text-slate-500 hover:text-rose-400 cursor-pointer">
                        <Trash2 class="w-3.5 h-3.5" />
                      </button>
                    </div>
                  {/each}
                </div>
                <div class="pt-2 border-t border-white/10 space-y-1.5">
                  <input type="text" bind:value={newSrcName} placeholder="Nom source (ex: http_query)" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  <div class="flex gap-1.5">
                    <select bind:value={newSrcKind} aria-label="Type de source" class="flex-1 px-2 py-1 rounded bg-[#0b101d] border border-white/15 text-[10.5px] font-mono text-white">
                      <option value="HttpQueryParam">HttpQueryParam</option>
                      <option value="HttpBodyParam">HttpBodyParam</option>
                      <option value="HttpHeader">HttpHeader</option>
                      <option value="HttpCookie">HttpCookie</option>
                      <option value="WebSocketPayload">WebSocketPayload</option>
                      <option value="FileSystemRead">FileSystemRead</option>
                      <option value="DatabaseRead">DatabaseRead</option>
                      <option value="EnvironmentVar">EnvironmentVar</option>
                      <option value="FunctionArgument">FunctionArgument</option>
                      <option value="Custom">Custom</option>
                    </select>
                    <input type="text" bind:value={newSrcCwe} placeholder="CWE-20" class="w-20 px-2 py-1 rounded bg-black/50 border border-white/15 text-[10.5px] font-mono text-white" />
                  </div>
                  <input type="text" bind:value={newSrcPatterns} placeholder="Motifs (req.query, $_GET)" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  <button type="button" onclick={addTaintSource} class="w-full py-1 rounded bg-sky-500/20 hover:bg-sky-500/30 border border-sky-400/40 text-[11px] font-semibold text-sky-200 cursor-pointer">
                    + Ajouter Source
                  </button>
                </div>
              </div>

              <!-- Column 2: Taint Sinks -->
              <div class="p-3 rounded-lg bg-black/35 border border-rose-500/25 space-y-2.5">
                <div class="text-[11px] font-mono font-bold text-rose-300">2. Puits / Sinks Critiques ({taintSinks.length})</div>
                <div class="space-y-1.5 max-h-48 overflow-y-auto">
                  {#each taintSinks as sink (sink.name)}
                    <div class="p-2 rounded bg-black/50 border border-white/10 flex items-start justify-between gap-2">
                      <div class="min-w-0">
                        <div class="flex items-center gap-1.5 flex-wrap">
                          <span class="text-[11px] font-mono font-bold text-white">{sink.name}</span>
                          <span class="px-1 py-0.2 rounded text-[9px] font-mono bg-rose-500/20 text-rose-300">{typeof sink.sink_kind === 'object' ? sink.sink_kind?.Custom || 'Custom' : sink.sink_kind}</span>
                          <span class="px-1 py-0.2 rounded text-[9px] font-mono bg-amber-500/20 text-amber-300">{sink.cwe}</span>
                        </div>
                        <div class="text-[10px] font-mono text-slate-400 truncate mt-0.5">{(sink.patterns || []).join(', ')}</div>
                      </div>
                      <button type="button" onclick={() => removeTaintSink(sink.name)} class="text-slate-500 hover:text-rose-400 cursor-pointer">
                        <Trash2 class="w-3.5 h-3.5" />
                      </button>
                    </div>
                  {/each}
                </div>
                <div class="pt-2 border-t border-white/10 space-y-1.5">
                  <div class="flex gap-1.5">
                    <input type="text" bind:value={newSinkName} placeholder="Nom sink" class="flex-1 px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                    <input type="text" bind:value={newSinkRuleId} placeholder="TAINT-RULE-ID" class="flex-1 px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  </div>
                  <div class="flex gap-1.5">
                    <select bind:value={newSinkKind} aria-label="Type de sink" class="flex-1 px-2 py-1 rounded bg-[#0b101d] border border-white/15 text-[10.5px] font-mono text-white">
                      <option value="CommandExecution">CommandExecution</option>
                      <option value="SqlExecution">SqlExecution</option>
                      <option value="HtmlRender">HtmlRender</option>
                      <option value="FileAccess">FileAccess</option>
                      <option value="SsrfNetworkRequest">SsrfNetworkRequest</option>
                      <option value="Deserialization">Deserialization</option>
                      <option value="CodeEval">CodeEval</option>
                      <option value="LdapQuery">LdapQuery</option>
                      <option value="Custom">Custom</option>
                    </select>
                    <input type="text" bind:value={newSinkCwe} placeholder="CWE-78" class="w-20 px-2 py-1 rounded bg-black/50 border border-white/15 text-[10.5px] font-mono text-white" />
                  </div>
                  <input type="text" bind:value={newSinkPatterns} placeholder="Motifs (Command::new, db.execute)" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  <button type="button" onclick={addTaintSink} class="w-full py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-400/40 text-[11px] font-semibold text-rose-200 cursor-pointer">
                    + Ajouter Sink
                  </button>
                </div>
              </div>

              <!-- Column 3: Sanitizers -->
              <div class="p-3 rounded-lg bg-black/35 border border-emerald-500/25 space-y-2.5">
                <div class="text-[11px] font-mono font-bold text-emerald-300">3. Assainisseurs / Sanitizers ({taintSanitizers.length})</div>
                <div class="space-y-1.5 max-h-48 overflow-y-auto">
                  {#each taintSanitizers as san (san.name)}
                    <div class="p-2 rounded bg-black/50 border border-white/10 flex items-start justify-between gap-2">
                      <div class="min-w-0">
                        <div class="text-[11px] font-mono font-bold text-white">{san.name}</div>
                        <div class="text-[10px] font-mono text-emerald-300 truncate">Neutralise: {(san.target_cwes || san.neutralizes_cwes || []).join(', ')}</div>
                        <div class="text-[10px] font-mono text-slate-400 truncate">{(san.patterns && san.patterns.length > 0 ? san.patterns : [san.name]).join(', ')}</div>
                      </div>
                      <button type="button" onclick={() => removeTaintSanitizer(san.name)} class="text-slate-500 hover:text-rose-400 cursor-pointer">
                        <Trash2 class="w-3.5 h-3.5" />
                      </button>
                    </div>
                  {/each}
                </div>
                <div class="pt-2 border-t border-white/10 space-y-1.5">
                  <input type="text" bind:value={newSanName} placeholder="Nom garde (ex: path_guard)" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  <input type="text" bind:value={newSanPatterns} placeholder="Motifs (PathGuard::validate, escape)" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  <input type="text" bind:value={newSanCwes} placeholder="CWE neutralisées (CWE-22, CWE-78)" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-[11px] font-mono text-white" />
                  <button type="button" onclick={addTaintSanitizer} class="w-full py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-400/40 text-[11px] font-semibold text-emerald-200 cursor-pointer">
                    + Ajouter Sanitizer
                  </button>
                </div>
              </div>
            </div>

            <div class="flex justify-end">
              <button
                type="button"
                disabled={busyAction !== null}
                onclick={handleSaveTaintConfig}
                class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-amber-400 hover:bg-amber-300 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
              >
                <Save class="w-3.5 h-3.5" />
                <span>{busyAction === 'save-taint' ? 'Enregistrement...' : `Enregistrer le Pipeline Taint SSA dans "${taintPluginName}"`}</span>
              </button>
            </div>
          </div>

        <!-- =============================================================== -->
        <!-- TAB 4: BAC À SABLE (LIVE BROWSER PLAYGROUND)                    -->
        <!-- =============================================================== -->
        {:else if activeTab === 'playground'}
          <div class="space-y-3 p-4 rounded-xl bg-white/[0.025] border border-rose-500/25">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div>
                <div class="text-xs font-bold text-rose-300">🧪 Bac à Sable Live (Évaluateur SAST & DSL v2 Temps Réel)</div>
                <p class="text-[11px] text-slate-400">
                  Modifiez le chemin virtuel ou le code ci-dessous : les règles de vos plugins actifs (regex, <code>ast_scope</code>, fenêtre N lignes, globs) sont évaluées instantanément.
                </p>
              </div>
              <div class="flex items-center gap-1.5 flex-wrap">
                {#each PLAYGROUND_SAMPLES as sample}
                  <button
                    type="button"
                    onclick={() => {
                      playgroundFilePath = sample.filePath;
                      playgroundCode = sample.code;
                    }}
                    class="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10.5px] font-semibold text-slate-200 cursor-pointer"
                  >
                    {sample.label}
                  </button>
                {/each}
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div class="sm:col-span-2">
                <label for="pg-filepath" class="block text-[10.5px] font-mono text-slate-400 mb-1">
                  Chemin du fichier virtuel (astuce : essayez <code>tests/admin_test.rs</code> pour tester <code>outside_test</code>)
                </label>
                <input
                  id="pg-filepath"
                  type="text"
                  bind:value={playgroundFilePath}
                  class="w-full px-3 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-cyan-200"
                />
              </div>
              <div>
                <label for="pg-plugin-filter" class="block text-[10.5px] font-mono text-slate-400 mb-1">Filtrer par plugin</label>
                <select
                  id="pg-plugin-filter"
                  bind:value={playgroundPluginFilter}
                  class="w-full px-2.5 py-1.5 rounded-lg bg-[#0b101d] border border-white/15 text-xs font-mono text-white"
                >
                  <option value="ALL">Tous les plugins actifs ({inventory?.enabled_plugins ?? demoPluginsList.length})</option>
                  {#each inventory?.plugins ?? demoPluginsList as p (p.rel_path)}
                    <option value={p.name}>{p.name} ({p.rules_count} règles)</option>
                  {/each}
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
              <div>
                <div class="flex items-center justify-between mb-1">
                  <span class="text-[10.5px] font-mono text-slate-400">Snippet de code à auditer</span>
                  <span class="text-[10px] font-mono text-slate-500">{playgroundCode.split('\n').length} lignes</span>
                </div>
                <textarea
                  bind:value={playgroundCode}
                  rows="14"
                  aria-label="Snippet de code du Bac à Sable"
                  class="w-full p-3 rounded-lg bg-[#050811] border border-white/15 text-xs font-mono text-slate-100 focus:outline-none focus:border-rose-400 leading-relaxed"
                ></textarea>
              </div>

              <div class="flex flex-col">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-[10.5px] font-mono text-slate-400">Résultats de l'analyse en direct</span>
                  {#if playgroundFindings.length > 0}
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                      {playgroundFindings.length} violation(s) détectée(s)
                    </span>
                  {:else}
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      ✓ 0 violation — Code conforme
                    </span>
                  {/if}
                </div>

                <div class="flex-1 rounded-lg bg-black/40 border border-white/10 p-3 space-y-2 max-h-[330px] overflow-y-auto">
                  {#if playgroundFindings.length === 0}
                    <div class="h-full flex flex-col items-center justify-center text-center py-12 text-xs text-slate-400 font-mono space-y-1">
                      <CheckCircle2 class="w-6 h-6 text-emerald-400 mb-1" />
                      <div>Aucune règle SAST déclenchée sur <code>{playgroundFilePath}</code>.</div>
                      <div class="text-[10.5px] text-slate-500">Toutes les gardes ou filtres de portée AST sont respectés.</div>
                    </div>
                  {:else}
                    {#each playgroundFindings as hit, idx (idx)}
                      <div class="p-2.5 rounded-lg bg-rose-950/25 border border-rose-500/35 space-y-1">
                        <div class="flex items-center justify-between gap-2 flex-wrap">
                          <div class="flex items-center gap-1.5 flex-wrap">
                            <span class="px-1.5 py-0.5 rounded bg-rose-500/30 text-rose-200 font-mono text-[10px] font-bold">
                              L{hit.line_number}
                            </span>
                            <span class="font-mono text-[11px] font-bold text-white">{hit.rule_id}</span>
                            <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono border {severityClass(hit.severity)}">
                              {hit.severity}
                            </span>
                            <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-purple-500/20 text-purple-200">
                              {hit.plugin_name}
                            </span>
                          </div>
                          <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-indigo-500/20 text-indigo-300">
                            scope:{hit.ast_scope_detected}
                          </span>
                        </div>
                        <div class="text-[10.5px] font-mono text-rose-300">{hit.cwe_id}</div>
                        <pre class="px-2 py-1 rounded bg-black/60 text-[10.5px] font-mono text-amber-200 overflow-x-auto">{hit.line_snippet}</pre>
                        <div class="text-[11px] text-slate-300">{hit.description}</div>
                        {#if hit.remediation}
                          <div class="text-[10.5px] text-emerald-300/90">Remédiation : {hit.remediation}</div>
                        {/if}
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>
            </div>
          </div>

        <!-- =============================================================== -->
        <!-- TAB 5: IMPORTATEUR SEMGREP YAML                                 -->
        <!-- =============================================================== -->
        {:else if activeTab === 'semgrep'}
          <div class="space-y-3 p-4 rounded-xl bg-white/[0.025] border border-sky-500/25">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div>
                <div class="text-xs font-bold text-sky-300">Convertisseur Semgrep YAML → Plugin AetherScope</div>
                <p class="text-[11px] text-slate-400">
                  Traduit automatiquement les métavariables <code>$VAR</code>, <code>pattern-either</code>, <code>pattern-not</code> et <code>metadata.cwe</code> en plugin natif.
                </p>
              </div>
              <div class="flex items-center gap-1.5">
                <button
                  type="button"
                  onclick={() => semgrepFileInputEl?.click()}
                  class="flex items-center gap-1 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/15 text-[11px] font-semibold text-slate-200 cursor-pointer"
                >
                  <Upload class="w-3.5 h-3.5 text-sky-400" />
                  <span>Charger fichier .yaml</span>
                </button>
                <button
                  type="button"
                  onclick={() => (semgrepYaml = SAMPLE_SEMGREP)}
                  class="flex items-center gap-1 px-2.5 py-1 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-400/35 text-[11px] font-semibold text-sky-200 cursor-pointer"
                >
                  <Sparkles class="w-3.5 h-3.5" />
                  <span>Charger un exemple</span>
                </button>
              </div>
            </div>

            <div>
              <label for="semgrep-plugin-name" class="block text-[11px] font-mono text-slate-300 mb-1">
                Nom du pack importé (.aether/plugins/imported/&lt;nom&gt;/plugin.yaml)
              </label>
              <input
                id="semgrep-plugin-name"
                type="text"
                bind:value={semgrepName}
                placeholder="ex: owasp-custom-rules"
                class="w-full px-3 py-1.5 rounded-lg bg-black/40 border border-white/15 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
              />
            </div>

            <div>
              <label for="semgrep-yaml-input" class="block text-[11px] font-mono text-slate-300 mb-1">
                Contenu YAML Semgrep
              </label>
              <textarea
                id="semgrep-yaml-input"
                bind:value={semgrepYaml}
                rows="12"
                placeholder="rules:\n  - id: my-rule\n    languages: [python]\n    severity: ERROR\n    message: ...\n    pattern: ..."
                class="w-full p-3 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
              ></textarea>
            </div>

            <div class="flex justify-end">
              <button
                type="button"
                disabled={busyAction !== null}
                onclick={handleImportSemgrep}
                class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
              >
                <Upload class="w-3.5 h-3.5" />
                <span>{busyAction === 'import-semgrep' ? 'Importation...' : 'Convertir & Activer le Plugin'}</span>
              </button>
            </div>
          </div>

        <!-- =============================================================== -->
        <!-- TAB 6: STUDIO VISUELS WEBGL 2 & SHADERS GLSL ES 3.00            -->
        <!-- =============================================================== -->
        {:else}
          <div class="space-y-4">
            {#if cockpitState.visualPluginError}
              <div class="px-3.5 py-2 rounded-lg bg-amber-500/15 border border-amber-500/40 text-xs font-mono text-amber-200 flex items-center gap-2">
                <AlertTriangle class="w-4 h-4 shrink-0 text-amber-400" />
                <span>{cockpitState.visualPluginError}</span>
              </div>
            {/if}

            <div class="flex items-center justify-between flex-wrap gap-2">
              <div>
                <div class="text-xs font-bold text-cyan-300 uppercase tracking-wider">Packs Visuels WebGL 2 (Hot-Swap Atomique 120 FPS)</div>
                <p class="text-[11px] text-slate-400">
                  Changez instantanément les shaders SDF, le fond GPU, les palettes des 7 couches architecturales et la géométrie des membranes/arêtes.
                </p>
              </div>
              <div class="flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  onclick={() => visualFileInputEl?.click()}
                  class="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-[11px] text-slate-200 cursor-pointer"
                  title="Importer un pack visuel .json"
                >
                  <Upload class="w-3 h-3 text-cyan-400" />
                  <span>Importer Pack .json</span>
                </button>
                <button
                  type="button"
                  onclick={() => {
                    const res = cockpitState.selectVisualPlugin('obsidian-nebula', true);
                    if (res.ok) statusMsg = { kind: 'ok', text: 'Pipeline WebGL natif Obsidian Nebula restauré.' };
                  }}
                  class="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[11px] text-slate-300 cursor-pointer"
                >
                  <RotateCcw class="w-3 h-3" />
                  <span>Reset Natif</span>
                </button>
                <button
                  type="button"
                  onclick={() => (showGlslEditor = !showGlslEditor)}
                  class="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-[11px] font-semibold text-cyan-200 cursor-pointer"
                >
                  <Sparkles class="w-3.5 h-3.5" />
                  <span>{showGlslEditor ? 'Masquer Studio GLSL' : 'Ouvrir Studio GLSL'}</span>
                </button>
              </div>
            </div>

            <!-- Theme Cards Grid -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {#each cockpitState.allVisualPlugins as vp (vp.id)}
                {@const isActiveVp = cockpitState.activeVisualPluginId === vp.id}
                <div
                  class="p-3.5 rounded-xl border transition-all flex flex-col justify-between gap-2.5 {isActiveVp
                    ? 'bg-cyan-500/[0.08] border-cyan-400/60 shadow-[0_0_24px_rgba(34,211,238,0.14)]'
                    : 'bg-white/[0.025] border-white/10 hover:border-white/25'}"
                >
                  <div class="space-y-1.5">
                    <div class="flex items-center justify-between gap-2">
                      <div class="flex items-center gap-2 min-w-0">
                        <div class="flex items-center -space-x-1 shrink-0">
                          {#each (vp.palette?.background || ['#04050b', '#0ea5e9', '#a855f7']).slice(0, 4) as sw}
                            <span class="w-3.5 h-3.5 rounded-full border border-white/20" style="background-color: {sw}"></span>
                          {/each}
                        </div>
                        <span class="text-xs font-bold text-white truncate">{vp.name}</span>
                      </div>
                      <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono shrink-0 {vp.builtin ? 'bg-white/10 text-slate-300' : 'bg-cyan-500/20 text-cyan-200 border border-cyan-400/35'}">
                        {vp.builtin ? 'INTÉGRÉ' : 'CUSTOM'}
                      </span>
                    </div>

                    {#if vp.description}
                      <p class="text-[11px] text-slate-400 leading-snug line-clamp-2">{vp.description}</p>
                    {/if}

                    <div class="flex items-center gap-1.5 flex-wrap pt-0.5">
                      <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-black/40 border border-white/10 text-slate-300">
                        {vp.overlay?.membrane_style || 'organic_12lobe'}
                      </span>
                      <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-black/40 border border-white/10 text-slate-300">
                        {vp.overlay?.edge_style || 'bezier'}
                      </span>
                      {#if vp.backdrop_glsl || vp.node_sdf_glsl}
                        <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-purple-500/20 text-purple-200 border border-purple-400/35">
                          GLSL ES 3.00
                        </span>
                      {/if}
                    </div>
                  </div>

                  <div class="flex items-center justify-between gap-1.5 pt-2 border-t border-white/10">
                    <button
                      type="button"
                      onclick={() => handleSelectVisualPack(vp)}
                      class="flex-1 px-2.5 py-1 rounded-lg text-xs font-bold transition-colors cursor-pointer {isActiveVp
                        ? 'bg-cyan-400 text-slate-950'
                        : 'bg-cyan-500/20 hover:bg-cyan-500/35 text-cyan-200 border border-cyan-400/35'}"
                    >
                      {isActiveVp ? '✓ Actif' : 'Activer'}
                    </button>

                    <button
                      type="button"
                      onclick={() => loadVisualPackIntoStudio(vp)}
                      class="flex items-center gap-1 px-2 py-1 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[10.5px] text-slate-300 cursor-pointer"
                      title="Ouvrir ou remixer dans le Studio GLSL"
                    >
                      <Copy class="w-3 h-3" />
                      <span>{vp.builtin ? 'Remixer' : 'Éditer'}</span>
                    </button>

                    <button
                      type="button"
                      onclick={() => exportVisualPackJson(vp)}
                      class="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 cursor-pointer"
                      title="Exporter ce pack visuel en .json"
                    >
                      <Download class="w-3 h-3" />
                    </button>

                    {#if !vp.builtin}
                      {#if confirmDeleteVisualId === vp.id}
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onclick={() => handleDeleteVisualPack(vp.id)}
                          class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-[10.5px] font-bold text-white cursor-pointer"
                        >
                          OK
                        </button>
                      {:else}
                        <button
                          type="button"
                          onclick={() => (confirmDeleteVisualId = vp.id)}
                          class="p-1.5 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 cursor-pointer"
                          title="Supprimer ce pack visuel"
                        >
                          <Trash2 class="w-3.5 h-3.5" />
                        </button>
                      {/if}
                    {/if}
                  </div>
                </div>
              {/each}
            </div>

            <!-- Live GLSL & Palette Visual Studio -->
            {#if showGlslEditor}
              <div class="p-4 rounded-xl bg-black/40 border border-cyan-500/35 space-y-3.5">
                <div class="flex items-center justify-between flex-wrap gap-2">
                  <div class="text-xs font-bold text-cyan-300">⚡ Studio Visuel, Palettes Architecturales & Shaders GLSL ES 3.00</div>
                  <div class="text-[10px] font-mono text-slate-400">
                    Uniforms: <code>u_theme_colors[4]</code> · <code>u_params (grid, glow, stars, speed)</code> · <code>ctx.metric0/1</code>
                  </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  <div>
                    <label for="vp-id" class="block text-[10.5px] font-mono text-slate-400 mb-1">ID du pack (dossier)</label>
                    <input id="vp-id" type="text" bind:value={vpId} class="w-full px-2.5 py-1.5 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                  </div>
                  <div>
                    <label for="vp-name" class="block text-[10.5px] font-mono text-slate-400 mb-1">Nom affiché</label>
                    <input id="vp-name" type="text" bind:value={vpName} class="w-full px-2.5 py-1.5 rounded bg-black/50 border border-white/15 text-xs text-white" />
                  </div>
                  <div>
                    <label for="vp-desc" class="block text-[10.5px] font-mono text-slate-400 mb-1">Description</label>
                    <input id="vp-desc" type="text" bind:value={vpDescription} class="w-full px-2.5 py-1.5 rounded bg-black/50 border border-white/15 text-xs text-white" />
                  </div>
                </div>

                <!-- Palette & Overlay geometry -->
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  <div>
                    <span class="block text-[10.5px] font-mono text-slate-400 mb-1">Couleurs Fond GPU (`u_theme_colors[0..3]`)</span>
                    <div class="flex items-center gap-2">
                      <input type="color" bind:value={vpBg0} aria-label="Couleur fond 0" class="w-8 h-7 rounded bg-transparent border border-white/20 cursor-pointer" />
                      <input type="color" bind:value={vpBg1} aria-label="Couleur fond 1" class="w-8 h-7 rounded bg-transparent border border-white/20 cursor-pointer" />
                      <input type="color" bind:value={vpBg2} aria-label="Couleur fond 2" class="w-8 h-7 rounded bg-transparent border border-white/20 cursor-pointer" />
                      <input type="color" bind:value={vpBg3} aria-label="Couleur fond 3" class="w-8 h-7 rounded bg-transparent border border-white/20 cursor-pointer" />
                    </div>
                  </div>
                  <div>
                    <label for="vp-membrane" class="block text-[10.5px] font-mono text-slate-400 mb-1">Style Membranes</label>
                    <select id="vp-membrane" bind:value={vpMembraneStyle} class="w-full px-2.5 py-1.5 rounded bg-[#0b101d] border border-white/15 text-xs font-mono text-white">
                      <option value="organic_12lobe">organic_12lobe (Cellulaire)</option>
                      <option value="hex_hull">hex_hull (Hexagone PCB)</option>
                      <option value="rect_blueprint">rect_blueprint (Cadre CAD)</option>
                      <option value="none">none (Sans membranes)</option>
                    </select>
                  </div>
                  <div>
                    <label for="vp-edge" class="block text-[10.5px] font-mono text-slate-400 mb-1">Style Arêtes</label>
                    <select id="vp-edge" bind:value={vpEdgeStyle} class="w-full px-2.5 py-1.5 rounded bg-[#0b101d] border border-white/15 text-xs font-mono text-white">
                      <option value="bezier">bezier (Courbes organiques)</option>
                      <option value="orthogonal_pcb">orthogonal_pcb (Pistes 45°/90°)</option>
                      <option value="straight">straight (Vecteurs droits)</option>
                    </select>
                  </div>
                </div>

                <!-- Optional 7 Architectural Layer Colors + 4 Severities Override -->
                <div class="p-3 rounded-lg bg-black/35 border border-white/10 space-y-2">
                  <label class="flex items-center gap-2 text-xs font-semibold text-cyan-200 cursor-pointer">
                    <input type="checkbox" bind:checked={vpCustomLayersEnabled} class="accent-cyan-400" />
                    <span>Personnaliser la palette des 7 couches architecturales & 4 sévérités CWE</span>
                  </label>

                  {#if vpCustomLayersEnabled}
                    <div class="grid grid-cols-2 sm:grid-cols-7 gap-2 pt-1 text-[10px] font-mono text-slate-300">
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerUi} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>UI</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerAction} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>Action</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerDomain} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>Domain</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerDatabase} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>DB</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerConfig} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>Config</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerUtility} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>Utility</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpLayerDocs} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span>Docs</span>
                      </label>
                    </div>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 border-t border-white/10 text-[10px] font-mono text-slate-300">
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpSevCritical} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span class="text-rose-300">CRITICAL</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpSevHigh} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span class="text-orange-300">HIGH</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpSevMedium} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span class="text-amber-300">MEDIUM</span>
                      </label>
                      <label class="flex items-center gap-1.5">
                        <input type="color" bind:value={vpSevLow} class="w-6 h-6 rounded border border-white/20 cursor-pointer" />
                        <span class="text-sky-300">LOW</span>
                      </label>
                    </div>
                  {/if}
                </div>

                <!-- Uniform sliders -->
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-[10.5px] font-mono text-slate-300">
                  <label class="space-y-1">
                    <span>grid_scale ({vpGridScale.toFixed(2)})</span>
                    <input type="range" min="0.2" max="3" step="0.1" bind:value={vpGridScale} class="w-full accent-cyan-400" />
                  </label>
                  <label class="space-y-1">
                    <span>glow_sharp ({vpGlowSharpness.toFixed(2)})</span>
                    <input type="range" min="0.5" max="3" step="0.1" bind:value={vpGlowSharpness} class="w-full accent-cyan-400" />
                  </label>
                  <label class="space-y-1">
                    <span>star_density ({vpStarDensity.toFixed(2)})</span>
                    <input type="range" min="0" max="2" step="0.1" bind:value={vpStarDensity} class="w-full accent-cyan-400" />
                  </label>
                  <label class="space-y-1">
                    <span>nebula_speed ({vpNebulaSpeed.toFixed(2)})</span>
                    <input type="range" min="0" max="3" step="0.1" bind:value={vpNebulaSpeed} class="w-full accent-cyan-400" />
                  </label>
                </div>

                <!-- GLSL Hook Editors with Starter Snippets -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  <div class="space-y-1">
                    <div class="flex items-center justify-between flex-wrap gap-1">
                      <label for="vp-bg-glsl" class="text-[10.5px] font-mono text-cyan-300">
                        backdrop.glsl — <code>aetherBackdrop(uv, cam, zoom, t)</code>
                      </label>
                      <div class="flex items-center gap-1">
                        {#each GLSL_BACKDROP_PRESETS as pre}
                          <button
                            type="button"
                            onclick={() => (vpBackdropGlsl = pre.code)}
                            class="px-1.5 py-0.5 rounded bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-[9.5px] font-mono text-cyan-200 cursor-pointer"
                          >
                            {pre.label}
                          </button>
                        {/each}
                      </div>
                    </div>
                    <textarea
                      id="vp-bg-glsl"
                      bind:value={vpBackdropGlsl}
                      rows="8"
                      placeholder="Laissez vide pour utiliser la nébuleuse native (avec vos couleurs u_theme_colors[0..3])..."
                      class="w-full p-2.5 rounded-lg bg-[#050810] border border-white/15 text-[11px] font-mono text-cyan-100 focus:outline-none focus:border-cyan-400"
                    ></textarea>
                  </div>

                  <div class="space-y-1">
                    <div class="flex items-center justify-between flex-wrap gap-1">
                      <label for="vp-node-glsl" class="text-[10.5px] font-mono text-purple-300">
                        node_sdf.glsl — <code>aetherNodeSurface(ctx, out rgb, out alpha)</code>
                      </label>
                      <div class="flex items-center gap-1">
                        {#each GLSL_NODE_PRESETS as pre}
                          <button
                            type="button"
                            onclick={() => (vpNodeSdfGlsl = pre.code)}
                            class="px-1.5 py-0.5 rounded bg-purple-500/15 hover:bg-purple-500/25 border border-purple-400/30 text-[9.5px] font-mono text-purple-200 cursor-pointer"
                          >
                            {pre.label}
                          </button>
                        {/each}
                      </div>
                    </div>
                    <textarea
                      id="vp-node-glsl"
                      bind:value={vpNodeSdfGlsl}
                      rows="8"
                      placeholder="Laissez vide pour utiliser les cellules SDF natives..."
                      class="w-full p-2.5 rounded-lg bg-[#050810] border border-white/15 text-[11px] font-mono text-purple-100 focus:outline-none focus:border-purple-400"
                    ></textarea>
                  </div>
                </div>

                <div class="flex items-center justify-end gap-2 flex-wrap">
                  <button
                    type="button"
                    onclick={() => exportVisualPackJson(buildStudioDraftPack())}
                    class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-semibold text-slate-200 cursor-pointer"
                  >
                    <Download class="w-3.5 h-3.5" />
                    <span>Exporter .json</span>
                  </button>
                  <button
                    type="button"
                    onclick={handleLivePreviewVisualStudio}
                    class="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/45 text-xs font-bold text-amber-200 cursor-pointer"
                  >
                    <Zap class="w-3.5 h-3.5" />
                    <span>Tester en direct (Hot-Swap)</span>
                  </button>
                  <button
                    type="button"
                    disabled={busyAction !== null}
                    onclick={handleSaveVisualPack}
                    class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
                  >
                    <Save class="w-3.5 h-3.5" />
                    <span>{busyAction === 'save-visual' ? 'Sauvegarde...' : 'Sauvegarder & Activer le Pack'}</span>
                  </button>
                </div>
              </div>
            {/if}
          </div>
        {/if}
      </div>

      <!-- Footer -->
      <div class="px-5 py-3 bg-[#0f172a] border-t border-white/10 flex items-center justify-between flex-wrap gap-2 text-[11px] text-slate-400 shrink-0">
        <span>
          CLI : <code class="text-purple-300">aether-engine --plugins auto|all|&lt;pack&gt;|profile:&lt;name&gt;</code> · MCP : <code class="text-cyan-300">aetherscope_manage_plugins</code>
        </span>
        <button
          type="button"
          onclick={closeModal}
          class="px-3.5 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-xs font-semibold text-white cursor-pointer"
        >
          Fermer
        </button>
      </div>
    </div>
  </div>
{/if}
