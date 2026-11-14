<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../lib/api';
  import { playSpatialTone } from '../lib/sound';
  import { cockpitState } from '../state/graphState.svelte';
  import type { CveAnomalyRecord, SymbolBubble } from '../types/graph';
  import {
    BOUNTY_PRESETS,
    buildBugBountyMarkdownReport,
    buildCodeViewerLines,
    buildCurlCommand,
    buildStep1ScopePrompt,
    buildStep2TargetFunctionsPrompt,
    buildStep3DataCodePrompt,
    buildStep4ContextualTargetPrompt,
    buildTargetDataDirection,
    extractFileFunctions,
    getTargetEndpoint,
    getTargetMethod,
    matchesWildcardPattern,
    normalizeFolderKey,
    parsePatternLines,
    pathsMatch,
    type BountyPresetId,
    type BountyStep,
    type DataFlowNode,
    type DryRunResult,
    type FileFunctionItem,
    type FolderRecommendation,
    type ProjectFolderStat,
    type PromptFormat,
    type ScopePromptConfig,
    type ScopePromptMission,
  } from './bounty/bountyEngine';
  import StepCodeDataPanel from './bounty/StepCodeDataPanel.svelte';
  import StepPromptsPocPanel from './bounty/StepPromptsPocPanel.svelte';
  import StepScopePanel from './bounty/StepScopePanel.svelte';
  import StepTargetsFunctionsPanel from './bounty/StepTargetsFunctionsPanel.svelte';
  import {
    CheckCircle2,
    Code2,
    Download,
    Eye,
    Layers,
    Lock,
    Radar,
    Save,
    ShieldAlert,
    Sparkles,
    X,
  } from '@lucide/svelte';

  let currentStep = $state<BountyStep>(1);
  let selectedAnomaly = $state<CveAnomalyRecord | null>(null);
  let selectedSymbol = $state<SymbolBubble | null>(null);
  let activeFunction = $state<FileFunctionItem | null>(null);

  let rawFileContent = $state('');
  let codeViewMode = $state<'excerpt' | 'full'>('excerpt');
  let snippetLoading = $state(false);
  let snippetFileError = $state('');
  const fileCache = new Map<string, string>();
  let fileFetchSeq = 0;

  let filterSeverity = $state<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  let filterReachableOnly = $state(false);
  let cveSearchQuery = $state('');

  let promptFormat = $state<PromptFormat>('target_prompt');
  let reportRenderMode = $state<'formatted' | 'raw'>('formatted');

  let activePreset = $state<BountyPresetId | null>('auto');
  let showWildcardEditor = $state(false);
  let inScopePatternsText = $state('src/*\ncrates/*');
  let outScopePatternsText = $state('tests/*\nfixtures/*\nmocks/*');
  let excludedFolders = $state<Record<string, boolean>>({});
  let recommendations = $state<FolderRecommendation[]>([]);
  let scopeModeLabel = $state('Permissive / Audit Complet');
  let scopeUpdatedBy = $state('UI Scope Matrix');
  let scopeRationale = $state('');
  let syncedNotice = $state('');
  let copiedKey = $state<string | null>(null);
  let sentToMcp = $state(false);

  let lockedSingleFolder = $state<string>('ALL');
  let folderSearchQuery = $state('');
  let isolateScopeIn3DGraph = $state(false);

  let scopePromptMission = $state<ScopePromptMission>('audit_strict');
  let strictFolderBoundary = $state(true);
  let includeTopTargetsInPrompt = $state(true);
  let requireNonDestructivePoc = $state(true);
  let requireEarsInvariant = $state(true);
  let customScopeInstructions = $state('');

  let isDryRunning = $state(false);
  let dryRunResult = $state<DryRunResult | null>(null);
  let dryRunActiveTab = $state<'response' | 'headers' | 'ast'>('response');

  const STEPS: { id: BountyStep; num: string; label: string; desc: string }[] = [
    { id: 1, num: '01', label: 'Scope & Dossiers', desc: 'Périmètre & RoE' },
    { id: 2, num: '02', label: 'Cibles & Fonctions', desc: 'CVE, AST & Appels' },
    { id: 3, num: '03', label: 'Code & Direction Data', desc: 'Pipeline SVG & SSA' },
    { id: 4, num: '04', label: 'Prompts & PoC Studio', desc: 'Prompts, cURL & Dry-Run' },
  ];

  // Aggregate folders across graph nodes & anomalies
  const projectFolders = $derived.by((): ProjectFolderStat[] => {
    const stats = new Map<string, ProjectFolderStat>();
    const ensure = (folder: string) => {
      let entry = stats.get(folder);
      if (!entry) {
        entry = { folder, count: 0, critCount: 0, highCount: 0, nodeCount: 0 };
        stats.set(folder, entry);
      }
      return entry;
    };

    for (const n of cockpitState.graph.nodes) {
      const f = normalizeFolderKey(n.file_path, n.folder);
      ensure(f).nodeCount += 1;
    }

    for (const v of cockpitState.allViolations) {
      const f = normalizeFolderKey(v.file_path);
      const item = ensure(f);
      item.count += 1;
      const sev = (v.severity || '').toUpperCase();
      if (sev === 'CRITICAL') item.critCount += 1;
      else if (sev === 'HIGH') item.highCount += 1;
    }

    return Array.from(stats.values()).sort((a, b) => {
      if (b.critCount !== a.critCount) return b.critCount - a.critCount;
      if (b.count !== a.count) return b.count - a.count;
      if (b.nodeCount !== a.nodeCount) return b.nodeCount - a.nodeCount;
      return a.folder.localeCompare(b.folder);
    });
  });

  const filteredProjectFolders = $derived.by(() => {
    const q = folderSearchQuery.trim().toLowerCase();
    if (!q) return projectFolders;
    return projectFolders.filter((f) => f.folder.toLowerCase().includes(q));
  });

  const recByFolder = $derived.by(() => {
    const map = new Map<string, FolderRecommendation>();
    for (const r of recommendations) {
      map.set(normalizeFolderKey(r.folder, r.folder), r);
    }
    return map;
  });

  const inScopeFoldersList = $derived.by(() => {
    if (lockedSingleFolder !== 'ALL') return [lockedSingleFolder];
    return projectFolders.filter((f) => !excludedFolders[f.folder]).map((f) => f.folder);
  });

  const outScopeFoldersList = $derived.by(() => {
    if (lockedSingleFolder !== 'ALL') {
      return projectFolders.filter((f) => f.folder !== lockedSingleFolder).map((f) => f.folder);
    }
    return projectFolders.filter((f) => excludedFolders[f.folder]).map((f) => f.folder);
  });

  const parsedOutPatterns = $derived(parsePatternLines(outScopePatternsText));

  function isPathInActiveScope(filePath?: string): boolean {
    if (!filePath) return lockedSingleFolder === 'ALL';
    const folder = normalizeFolderKey(filePath);
    if (lockedSingleFolder !== 'ALL') {
      return folder === lockedSingleFolder;
    }
    if (excludedFolders[folder]) return false;
    if (parsedOutPatterns.some((pat) => matchesWildcardPattern(filePath, pat))) {
      return false;
    }
    return true;
  }

  const inScopeNodes = $derived.by(() => {
    return cockpitState.graph.nodes.filter((n) => isPathInActiveScope(n.file_path));
  });

  const filteredTargets = $derived.by(() => {
    const q = cveSearchQuery.trim().toLowerCase();
    const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return cockpitState.allViolations
      .filter((v) => isPathInActiveScope(v.file_path))
      .filter((v) => {
        if (filterSeverity === 'ALL') return true;
        return (v.severity || '').toUpperCase() === filterSeverity;
      })
      .filter((v) => !filterReachableOnly || v.is_reachable !== false)
      .filter((v) => {
        if (!q) return true;
        return (
          (v.cve_id || '').toLowerCase().includes(q) ||
          (v.cwe_class || '').toLowerCase().includes(q) ||
          (v.file_path || '').toLowerCase().includes(q) ||
          (v.title || '').toLowerCase().includes(q) ||
          (v.message || '').toLowerCase().includes(q)
        );
      })
      .sort((a, b) => {
        const ra = sevOrder[(a.severity || '').toUpperCase()] ?? 4;
        const rb = sevOrder[(b.severity || '').toUpperCase()] ?? 4;
        if (ra !== rb) return ra - rb;
        return (a.file_path || '').localeCompare(b.file_path || '');
      });
  });

  const criticalCount = $derived(
    filteredTargets.filter((v) => (v.severity || '').toUpperCase() === 'CRITICAL').length
  );

  const activeFilePath = $derived(
    selectedAnomaly?.file_path || selectedSymbol?.file_path || ''
  );

  const targetLine = $derived(
    selectedAnomaly?.line_number || activeFunction?.line || selectedSymbol?.line_number || 1
  );

  const fileFunctions = $derived.by(() => {
    if (!activeFilePath) return [];
    return extractFileFunctions(
      cockpitState.graph.nodes,
      activeFilePath,
      rawFileContent,
      selectedAnomaly?.line_number || selectedSymbol?.line_number || 1,
      selectedAnomaly
    );
  });

  const codeLines = $derived.by(() => {
    return buildCodeViewerLines(
      rawFileContent,
      selectedAnomaly?.line_number || activeFunction?.line || selectedSymbol?.line_number || 1,
      activeFunction,
      selectedAnomaly,
      codeViewMode
    );
  });

  const dataDirection = $derived.by(() => {
    return buildTargetDataDirection(
      selectedAnomaly,
      selectedSymbol,
      activeFunction,
      cockpitState.graph
    );
  });

  const presetLabel = $derived(
    activePreset ? BOUNTY_PRESETS[activePreset].label : 'Scope Personnalisé'
  );

  const scopePromptCfg = $derived<ScopePromptConfig>({
    projectName: cockpitState.graph.project_name || 'AetherEngine',
    projectPath: cockpitState.graph.project_path || '.',
    presetLabel,
    scopeModeLabel,
    lockedSingleFolder,
    inFolders: inScopeFoldersList,
    outFolders: outScopeFoldersList,
    inScopePatternsText,
    outScopePatternsText,
    mission: scopePromptMission,
    strictFolderBoundary,
    filterReachableOnly,
    includeTopTargetsInPrompt,
    requireNonDestructivePoc,
    requireEarsInvariant,
    customScopeInstructions,
    filteredTargets,
    selectedAnomaly,
  });

  const step1Prompt = $derived(buildStep1ScopePrompt(scopePromptCfg));
  const step2Prompt = $derived(
    buildStep2TargetFunctionsPrompt(
      selectedAnomaly,
      selectedSymbol,
      fileFunctions,
      activeFunction,
      inScopeFoldersList
    )
  );
  const step3Prompt = $derived(
    buildStep3DataCodePrompt(
      selectedAnomaly,
      selectedSymbol,
      activeFunction,
      codeLines,
      dataDirection
    )
  );
  const step4TargetPrompt = $derived(
    buildStep4ContextualTargetPrompt(
      selectedAnomaly,
      selectedSymbol,
      activeFunction,
      codeLines,
      dataDirection,
      scopePromptCfg
    )
  );

  const activeRecommendation = $derived.by(() => {
    if (!selectedAnomaly) return undefined;
    return recByFolder.get(normalizeFolderKey(selectedAnomaly.file_path));
  });

  function showSyncedToast(msg: string) {
    syncedNotice = msg;
    setTimeout(() => {
      if (syncedNotice === msg) syncedNotice = '';
    }, 3200);
  }

  async function loadTargetFileContent(filePath: string) {
    if (!filePath) {
      rawFileContent = '';
      snippetFileError = '';
      return;
    }
    const cached = fileCache.get(filePath);
    if (cached !== undefined) {
      rawFileContent = cached;
      snippetFileError = '';
      return;
    }

    const seq = ++fileFetchSeq;
    snippetLoading = true;
    snippetFileError = '';
    try {
      const res = await api.getFileContent(filePath);
      if (seq !== fileFetchSeq) return;
      const content = res?.content || '';
      fileCache.set(filePath, content);
      rawFileContent = content;
    } catch (e) {
      if (seq !== fileFetchSeq) return;
      rawFileContent = '';
      snippetFileError = `Impossible de lire ${filePath} (${e instanceof Error ? e.message : String(e)})`;
    } finally {
      if (seq === fileFetchSeq) snippetLoading = false;
    }
  }

  async function loadServerScope() {
    try {
      const cfg = await api.getBountyScope();
      if (!cfg?.scope) return;
      if (Array.isArray(cfg.scope.in_scope) && cfg.scope.in_scope.length > 0) {
        inScopePatternsText = cfg.scope.in_scope.join('\n');
      }
      if (Array.isArray(cfg.scope.out_of_scope)) {
        outScopePatternsText = cfg.scope.out_of_scope.join('\n');
        cockpitState.bountyOutOfScopePatterns = cfg.scope.out_of_scope;
        cockpitState.filterVersion += 1;
      }
      if (Array.isArray(cfg.recommendations)) {
        recommendations = cfg.recommendations;
      }
      if (cfg.scope.mode) scopeModeLabel = cfg.scope.mode;
      if (cfg.scope.updated_by) scopeUpdatedBy = cfg.scope.updated_by;
      if (cfg.scope.rationale) scopeRationale = cfg.scope.rationale;
    } catch {
      // Backend optional in offline viewer mode
    }
  }

  function sync3DGraphIsolation(enabled: boolean) {
    if (enabled) {
      const nextDisabled: Record<string, boolean> = {};
      for (const f of outScopeFoldersList) {
        nextDisabled[f] = true;
      }
      cockpitState.disabledModules = nextDisabled;
      cockpitState.filterVersion += 1;
    } else {
      cockpitState.setAllModules(true);
    }
  }

  function toggleIsolateScopeIn3DGraph() {
    isolateScopeIn3DGraph = !isolateScopeIn3DGraph;
    sync3DGraphIsolation(isolateScopeIn3DGraph);
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    showSyncedToast(
      isolateScopeIn3DGraph
        ? '🌐 Graphe 3D isolé sur le périmètre In-Scope'
        : '🌐 Graphe 3D restauré (tous modules)'
    );
  }

  async function syncOutScopeToScanner(author = 'UI Scope Matrix') {
    const outList = Array.from(
      new Set([
        ...outScopeFoldersList.map((f) => `${f}/*`),
        ...parsePatternLines(outScopePatternsText),
      ])
    );
    const inList = Array.from(
      new Set([
        ...inScopeFoldersList.map((f) => `${f}/*`),
        ...parsePatternLines(inScopePatternsText),
      ])
    );

    cockpitState.bountyOutOfScopePatterns = outList;
    cockpitState.filterVersion += 1;
    if (isolateScopeIn3DGraph) {
      sync3DGraphIsolation(true);
    }

    try {
      await api.updateBountyScope({
        action: 'set',
        in_scope: inList,
        out_of_scope: outList,
        mode: lockedSingleFolder !== 'ALL' ? `Strict (${lockedSingleFolder})` : scopeModeLabel,
        updated_by: author,
        rationale:
          scopeRationale ||
          `Synchronisation Scope (${inScopeFoldersList.length} In-Scope, ${outScopeFoldersList.length} exclus)`,
      });
      showSyncedToast('Scope synchronisé avec le scanner Rust & MCP');
    } catch {
      showSyncedToast('Scope appliqué localement (hors-ligne)');
    }
  }

  function applyBountyPreset(id: BountyPresetId) {
    const preset = BOUNTY_PRESETS[id];
    activePreset = id;
    lockedSingleFolder = 'ALL';
    inScopePatternsText = preset.inScope.join('\n');
    outScopePatternsText = preset.outScope.join('\n');
    scopeModeLabel = `Preset ${preset.label}`;
    scopeRationale = preset.rationale;

    const nextExcluded: Record<string, boolean> = {};
    for (const pf of projectFolders) {
      const samplePath = `${pf.folder}/lib.rs`;
      const isOut = preset.outScope.some((pat) => matchesWildcardPattern(samplePath, pat));
      if (isOut) nextExcluded[pf.folder] = true;
    }
    excludedFolders = nextExcluded;

    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    void syncOutScopeToScanner(`Preset: ${preset.label}`);
  }

  function applyAiRecommendedScope() {
    activePreset = 'auto';
    lockedSingleFolder = 'ALL';
    const nextExcluded: Record<string, boolean> = {};
    if (recommendations.length > 0) {
      for (const rec of recommendations) {
        const key = normalizeFolderKey(rec.folder, rec.folder);
        if (rec.status === 'OUT_OF_SCOPE' || rec.total_violations === 0) {
          nextExcluded[key] = true;
        }
      }
    } else {
      for (const pf of projectFolders) {
        if (pf.count === 0 && /(test|bench|mock|doc|script|fixture|example)/i.test(pf.folder)) {
          nextExcluded[pf.folder] = true;
        }
      }
    }
    excludedFolders = nextExcluded;
    scopeModeLabel = 'IA Auto-Scope Strict';
    scopeRationale = 'Dossiers recommandés automatiquement par ratio de vulnérabilités et entrypoints.';
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    void syncOutScopeToScanner('IA Auto-Scope');
  }

  function lockToSingleFolder(folder: string) {
    lockedSingleFolder = lockedSingleFolder === folder ? 'ALL' : folder;
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    void syncOutScopeToScanner(
      lockedSingleFolder === 'ALL' ? 'Unlock Folder' : `Lock: ${lockedSingleFolder}`
    );
  }

  function isolateOnlyFolderInMatrix(folder: string) {
    lockedSingleFolder = folder;
    const nextExcluded: Record<string, boolean> = {};
    for (const pf of projectFolders) {
      if (pf.folder !== folder) nextExcluded[pf.folder] = true;
    }
    excludedFolders = nextExcluded;
    if (!isolateScopeIn3DGraph) isolateScopeIn3DGraph = true;
    sync3DGraphIsolation(true);
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    void syncOutScopeToScanner(`Focus Dossier: ${folder}`);
  }

  function setAllFoldersScope(includeAll: boolean) {
    lockedSingleFolder = 'ALL';
    if (includeAll) {
      excludedFolders = {};
    } else {
      const nextExcluded: Record<string, boolean> = {};
      for (const pf of projectFolders) nextExcluded[pf.folder] = true;
      excludedFolders = nextExcluded;
    }
    void syncOutScopeToScanner(includeAll ? 'Include All' : 'Exclude All');
  }

  function toggleFolderScope(folder: string) {
    if (lockedSingleFolder !== 'ALL') {
      lockedSingleFolder = 'ALL';
    }
    excludedFolders = {
      ...excludedFolders,
      [folder]: !excludedFolders[folder],
    };
    void syncOutScopeToScanner('Folder Matrix Toggle');
  }

  function pickDefaultFunctionForFile(
    fns: FileFunctionItem[],
    lineHint: number,
    symbolHint: SymbolBubble | null
  ): FileFunctionItem | null {
    if (fns.length === 0) return null;
    const containing = fns.find((f) => lineHint > 0 && lineHint >= f.line && lineHint <= f.endLine);
    if (containing) return containing;
    if (symbolHint) {
      const byName = fns.find((f) => f.name === symbolHint.name);
      if (byName) return byName;
    }
    const tainted = fns.find((f) => f.isTaintTouched || f.hasAnomaly);
    return tainted || fns[0];
  }

  function selectAnomalyTarget(a: CveAnomalyRecord, jumpToStep?: BountyStep) {
    selectedAnomaly = a;
    const matchedNode = cockpitState.graph.nodes.find((n) => pathsMatch(n.file_path, a.file_path));
    if (matchedNode) selectedSymbol = matchedNode;
    activeFunction = null;
    dryRunResult = null;
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    if (jumpToStep) currentStep = jumpToStep;
  }

  function selectSymbolTarget(s: SymbolBubble, jumpToStep?: BountyStep) {
    selectedSymbol = s;
    const nodeAnom =
      cockpitState.allViolations.find((v) => pathsMatch(v.file_path, s.file_path)) || null;
    selectedAnomaly = nodeAnom;
    activeFunction = null;
    dryRunResult = null;
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    if (jumpToStep) currentStep = jumpToStep;
  }

  function selectFunctionItem(fn: FileFunctionItem, jumpToStep?: BountyStep) {
    activeFunction = fn;
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    if (jumpToStep) currentStep = jumpToStep;
  }

  function handleJumpToDataNode(node: DataFlowNode) {
    const resolved =
      (node.symbolId && cockpitState.graph.nodes.find((n) => n.id === node.symbolId)) ||
      cockpitState.graph.nodes.find(
        (n) => pathsMatch(n.file_path, node.filePath) && Math.abs((n.line_number || 0) - node.line) <= 3
      ) ||
      cockpitState.graph.nodes.find((n) => pathsMatch(n.file_path, node.filePath)) ||
      null;

    const vuln =
      cockpitState.allViolations.find(
        (v) =>
          pathsMatch(v.file_path, node.filePath) &&
          Math.abs((v.line_number || 0) - node.line) <= 5
      ) ||
      cockpitState.allViolations.find((v) => pathsMatch(v.file_path, node.filePath)) ||
      null;

    if (vuln) selectedAnomaly = vuln;
    if (resolved) selectedSymbol = resolved;
    activeFunction = null;
    dryRunResult = null;
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
  }

  function focusActiveTargetIn3DGraph() {
    const candidate =
      selectedSymbol ||
      (selectedAnomaly
        ? cockpitState.graph.nodes.find((n) => pathsMatch(n.file_path, selectedAnomaly?.file_path))
        : null);
    if (candidate) {
      cockpitState.selectSymbol(candidate.id, true);
      cockpitState.requestFocusSymbol(candidate.id);
      playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    }
  }

  async function executePocDryRun() {
    if (!selectedAnomaly || isDryRunning) return;
    isDryRunning = true;
    dryRunActiveTab = 'response';
    const method = getTargetMethod(selectedAnomaly);
    const endpoint = getTargetEndpoint(selectedAnomaly);
    const param = selectedAnomaly.transmitted_data || 'payload';
    const cveSlug = (selectedAnomaly.cve_id || 'vuln').toLowerCase().replace(/[^a-z0-9]/g, '_');
    const vectorValue = `aether_poc_${cveSlug}_test_vector`;
    const targetUrl =
      method === 'POST'
        ? `http://localhost:3030${endpoint}`
        : `http://localhost:3030${endpoint}?${encodeURIComponent(param)}=${encodeURIComponent(vectorValue)}`;

    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'AetherScope-BugBounty-PoC/2.4',
      'X-Bounty-Scope': 'In-Scope-Validated',
    };
    const requestPayload = method === 'POST' ? { [param]: vectorValue } : { queryParam: vectorValue };

    const started = performance.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(targetUrl, {
        method,
        headers: requestHeaders,
        body: method === 'POST' ? JSON.stringify(requestPayload) : undefined,
        signal: controller.signal,
      });
      clearTimeout(timer);

      const latencyMs = Math.max(1, Math.round(performance.now() - started));
      const responseBody = await res.text();
      const responseHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        responseHeaders[k] = v;
      });

      const reproduced = res.status >= 500 || responseBody.includes(vectorValue);
      dryRunResult = {
        mode: 'live_http',
        statusCode: res.status,
        statusText: res.statusText || 'OK',
        latencyMs,
        verdict: reproduced ? 'vulnerability_reproduced' : 'target_defended',
        verdictMessage: reproduced
          ? 'Serveur local atteint : anomalie / réflexion reproduite.'
          : 'Requête HTTP exécutée : aucune panique 5xx détectée.',
        targetUrl,
        method,
        requestHeaders,
        requestPayload,
        responseHeaders,
        responseBody: responseBody || '(Corps de réponse vide)',
      };
    } catch {
      const latencyMs = Math.max(2, Math.round(performance.now() - started));
      const sev = (selectedAnomaly.severity || '').toUpperCase();
      const isCritOrHigh = sev === 'CRITICAL' || sev === 'HIGH';
      dryRunResult = {
        mode: 'sandbox_ast',
        statusCode: isCritOrHigh ? 500 : 200,
        statusText: isCritOrHigh
          ? 'Simulated Unhandled Exception / Sink Reached'
          : 'Simulated 200 OK',
        latencyMs,
        verdict: isCritOrHigh && !dataDirection.isSanitized ? 'vulnerability_reproduced' : 'target_defended',
        verdictMessage:
          isCritOrHigh && !dataDirection.isSanitized
            ? 'Serveur HTTP inactif — Bascule Sandbox AST : flux tainté non assaini atteint le sink.'
            : 'Serveur HTTP inactif — Bascule Sandbox AST : barrière ou sévérité modérée simulée.',
        targetUrl,
        method,
        requestHeaders,
        requestPayload,
        responseHeaders: {
          'x-aether-sandbox': 'ast-dataflow-v2.4',
          'content-type': 'application/json',
        },
        responseBody: JSON.stringify(
          {
            simulation: 'sandbox_ast',
            cve_id: selectedAnomaly.cve_id,
            cwe_class: selectedAnomaly.cwe_class || 'CWE',
            taint_chain: dataDirection.taintSummary,
            sink: `${selectedAnomaly.file_path}:${selectedAnomaly.line_number || 1}`,
            injected_param: param,
            sanitizer_detected: dataDirection.isSanitized,
          },
          null,
          2
        ),
        astDetails: {
          taintChain: dataDirection.taintSummary,
          sinkRule: `${selectedAnomaly.cve_id} (${selectedAnomaly.cwe_class || 'CWE'})`,
          sanitizerDetected: dataDirection.isSanitized,
          confidence: selectedAnomaly.taint_trace?.is_vulnerable
            ? 0.94
            : selectedAnomaly.severity === 'CRITICAL'
              ? 0.91
              : 0.78,
        },
      };
    } finally {
      isDryRunning = false;
      playSpatialTone(cockpitState.settings.soundEnabled, 'select');
    }
  }

  async function copyText(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      copiedKey = key;
      playSpatialTone(cockpitState.settings.soundEnabled, 'select');
      setTimeout(() => {
        if (copiedKey === key) copiedKey = null;
      }, 2200);
    } catch {
      // Clipboard fallback ignored if denied
    }
  }

  function downloadFile(filename: string, content: string, mime = 'text/plain;charset=utf-8') {
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

  function downloadScopePromptMd() {
    downloadFile('aether_scope_prompt.md', step1Prompt, 'text/markdown;charset=utf-8');
    showSyncedToast('Prompt Scope exporté (.md)');
  }

  function downloadReportMd() {
    if (!selectedAnomaly) return;
    const md = buildBugBountyMarkdownReport(selectedAnomaly, {
      presetLabel,
      recReason: activeRecommendation?.reason,
      snippetLines: codeLines,
      dataDirection,
    });
    const slug = (selectedAnomaly.cve_id || 'bounty').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    downloadFile(`bounty_report_${slug}.md`, md, 'text/markdown;charset=utf-8');
    showSyncedToast(`Rapport ${selectedAnomaly.cve_id} téléchargé`);
  }

  function downloadScopeJson() {
    const payload = {
      project: cockpitState.graph.project_name || 'AetherEngine',
      preset: activePreset,
      mode: scopeModeLabel,
      locked_folder: lockedSingleFolder,
      in_scope_folders: inScopeFoldersList,
      out_of_scope_folders: outScopeFoldersList,
      in_scope_patterns: parsePatternLines(inScopePatternsText),
      out_of_scope_patterns: parsePatternLines(outScopePatternsText),
      selected_target: selectedAnomaly
        ? {
            cve_id: selectedAnomaly.cve_id,
            cwe_class: selectedAnomaly.cwe_class,
            severity: selectedAnomaly.severity,
            file_path: selectedAnomaly.file_path,
            line_number: selectedAnomaly.line_number,
            data_direction: dataDirection.taintSummary,
          }
        : null,
    };
    downloadFile('aether_bounty_scope.json', JSON.stringify(payload, null, 2), 'application/json');
    showSyncedToast('Configuration Scope JSON téléchargée');
  }

  async function saveReportToWorkspace() {
    if (!selectedAnomaly) return;
    const projectPath = cockpitState.graph.project_path || '.';
    const md = buildBugBountyMarkdownReport(selectedAnomaly, {
      presetLabel,
      recReason: activeRecommendation?.reason,
      snippetLines: codeLines,
      dataDirection,
    });
    const slug = (selectedAnomaly.cve_id || 'bounty').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    const relPath = `.aether/bounty_reports/report_${slug}.md`;
    try {
      await api.createFile({
        project_path: projectPath,
        file_path: relPath,
        content: md,
      });
      playSpatialTone(cockpitState.settings.soundEnabled, 'select');
      showSyncedToast(`Sauvegardé dans ${relPath}`);
    } catch (e) {
      showSyncedToast(
        `Échec sauvegarde : ${e instanceof Error ? e.message : String(e)}`
      );
    }
  }

  async function sendPromptToMcpChat(promptText: string, targetSymbol?: string) {
    try {
      await api.sendChatMessage(promptText, 'user', targetSymbol);
      sentToMcp = true;
      playSpatialTone(cockpitState.settings.soundEnabled, 'select');
      showSyncedToast('Prompt transmis au Copilote IA MCP');
      setTimeout(() => {
        sentToMcp = false;
      }, 2600);
    } catch (e) {
      showSyncedToast(`Erreur Chat MCP : ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  async function sendScopePromptToMcpChat() {
    await sendPromptToMcpChat(step1Prompt, inScopeFoldersList[0] || undefined);
  }

  async function sendPocMissionToMcpChat() {
    if (!selectedAnomaly) {
      await sendPromptToMcpChat(step4TargetPrompt, selectedSymbol?.file_path);
      return;
    }
    const curl = buildCurlCommand(selectedAnomaly);
    const msg = `${step4TargetPrompt}\n\n### Commande cURL\n\`\`\`bash\n${curl}\n\`\`\``;
    await sendPromptToMcpChat(msg, selectedAnomaly.file_path);
  }

  function closeModal() {
    cockpitState.isBountyModalOpen = false;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && cockpitState.isBountyModalOpen) {
      e.preventDefault();
      closeModal();
    }
  }

  // Hydrate modal target & server scope when opened
  $effect(() => {
    if (!cockpitState.isBountyModalOpen) return;

    untrack(() => {
      void loadServerScope();
      const activeNode = cockpitState.activeSymbol;
      if (activeNode) {
        selectedSymbol = activeNode;
        const matchedVuln =
          cockpitState.allViolations.find((v) => pathsMatch(v.file_path, activeNode.file_path)) ||
          null;
        selectedAnomaly = matchedVuln;
        if (matchedVuln) currentStep = 2;
      } else if (!selectedAnomaly && filteredTargets.length > 0) {
        selectedAnomaly = filteredTargets[0];
      }
    });
  });

  // Load real source code whenever target file changes while modal is open
  $effect(() => {
    if (!cockpitState.isBountyModalOpen) return;
    const fp = activeFilePath;
    if (!fp) {
      rawFileContent = '';
      snippetFileError = '';
      return;
    }
    untrack(() => {
      void loadTargetFileContent(fp);
    });
  });

  // Auto-select most relevant function for newly loaded file/target
  $effect(() => {
    if (!cockpitState.isBountyModalOpen) return;
    const fns = fileFunctions;
    if (fns.length === 0) return;
    const lineHint = selectedAnomaly?.line_number || selectedSymbol?.line_number || 1;
    const symHint = selectedSymbol;
    const currentFn = untrack(() => activeFunction);
    const stillValid = currentFn && fns.some((f) => f.id === currentFn.id);
    if (!stillValid) {
      activeFunction = pickDefaultFunctionForFile(fns, lineHint, symHint);
    }
  });
</script>

<svelte:window onkeydown={handleKeydown} />

{#if cockpitState.isBountyModalOpen}
  <!-- Backdrop -->
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-2 sm:p-4"
    onclick={closeModal}
  >
    <!-- Studio Modal Shell -->
    <div
      class="w-full max-w-[1440px] h-[93vh] rounded-2xl border border-amber-500/35 bg-[#070a12] shadow-2xl shadow-amber-950/30 flex flex-col overflow-hidden"
      onclick={(e) => e.stopPropagation()}
    >
      <!-- 1. Top Studio Header -->
      <header class="px-4 py-2.5 border-b border-white/10 bg-gradient-to-r from-[#0d1323] via-[#0a0f1d] to-[#120d18] flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div class="flex flex-wrap items-center gap-2.5 min-w-0">
          <div class="w-8 h-8 rounded-xl bg-gradient-to-br from-amber-500/30 to-rose-500/30 border border-amber-400/50 flex items-center justify-center shrink-0">
            <Radar class="w-4 h-4 text-amber-300" />
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-extrabold font-mono tracking-tight text-white">
                Scope PoC · Bug Bounty Studio
              </h2>
              <span class="px-1.5 py-0.5 rounded bg-emerald-500/20 border border-emerald-400/30 text-emerald-300 text-[10px] font-mono font-bold">
                {inScopeFoldersList.length} dossiers In-Scope
              </span>
              {#if lockedSingleFolder !== 'ALL'}
                <span class="flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyan-500/20 border border-cyan-400/40 text-cyan-200 text-[10px] font-mono font-bold">
                  <Lock class="w-3 h-3" />
                  <span>{lockedSingleFolder}</span>
                </span>
              {/if}
            </div>
            <p class="text-[10.5px] font-mono text-slate-400 truncate max-w-[540px]">
              {#if selectedAnomaly}
                Cible : <span class="text-amber-300 font-bold">{selectedAnomaly.cve_id}</span>
                <span class="text-slate-500">·</span>
                <span class="text-rose-300">{selectedAnomaly.cwe_class || 'CWE'}</span>
                <span class="text-slate-500">·</span>
                <span class="text-cyan-300">{selectedAnomaly.file_path}:{selectedAnomaly.line_number || 1}</span>
              {:else if selectedSymbol}
                Symbole : <span class="text-sky-300 font-bold">{selectedSymbol.name}</span>
                <span class="text-slate-500">·</span>
                <span class="text-cyan-300">{selectedSymbol.file_path}</span>
              {:else}
                Orchestration multi-étapes : Scope, Fonctions AST, Code Source, Direction Data & PoC
              {/if}
            </p>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-1.5 shrink-0">
          {#if syncedNotice}
            <span class="flex items-center gap-1 px-2 py-1 rounded-lg bg-emerald-500/20 border border-emerald-400/40 text-emerald-200 text-[10.5px] font-mono">
              <CheckCircle2 class="w-3.5 h-3.5" />
              <span>{syncedNotice}</span>
            </span>
          {/if}

          <button
            type="button"
            onclick={toggleIsolateScopeIn3DGraph}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-mono border cursor-pointer {isolateScopeIn3DGraph
              ? 'bg-emerald-500/25 border-emerald-400/50 text-emerald-200 font-bold'
              : 'bg-white/5 hover:bg-white/10 border-white/15 text-slate-200'}"
            title="Isoler uniquement les dossiers In-Scope dans la scène 3D"
          >
            <Eye class="w-3.5 h-3.5" />
            <span>Isoler 3D</span>
          </button>

          {#if selectedAnomaly}
            <button
              type="button"
              onclick={saveReportToWorkspace}
              class="hidden sm:flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/40 text-emerald-200 text-[11px] font-mono cursor-pointer"
            >
              <Save class="w-3.5 h-3.5" />
              <span>Sauver .aether/</span>
            </button>

            <button
              type="button"
              onclick={downloadReportMd}
              class="hidden sm:flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/40 text-amber-200 text-[11px] font-mono font-bold cursor-pointer"
            >
              <Download class="w-3.5 h-3.5" />
              <span>Rapport .md</span>
            </button>
          {/if}

          <button
            type="button"
            onclick={closeModal}
            class="p-1.5 rounded-lg bg-white/5 hover:bg-rose-500/25 border border-white/10 hover:border-rose-400/50 text-slate-300 hover:text-white cursor-pointer"
            aria-label="Fermer Scope PoC Studio"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </header>

      <!-- 2. 4-Step Horizontal Stepper + Persistent Target Quick-Bar -->
      <div class="px-4 py-2 border-b border-white/10 bg-[#090d18] flex flex-wrap items-center justify-between gap-2 shrink-0">
        <nav class="flex flex-wrap items-center gap-1.5" aria-label="Étapes Scope PoC">
          {#each STEPS as step}
            {@const isActive = currentStep === step.id}
            <button
              type="button"
              onclick={() => {
                currentStep = step.id;
                playSpatialTone(cockpitState.settings.soundEnabled, 'select');
              }}
              class="group flex items-center gap-2 px-3 py-1.5 rounded-xl border text-left transition-all cursor-pointer {isActive
                ? 'bg-gradient-to-r from-amber-500/20 to-cyan-500/15 border-amber-400/60 shadow-sm shadow-amber-500/10'
                : 'bg-white/[0.03] hover:bg-white/[0.08] border-white/10 text-slate-400 hover:text-slate-200'}"
            >
              <span
                class="w-5 h-5 rounded-md flex items-center justify-center text-[10px] font-extrabold font-mono {isActive
                  ? 'bg-amber-500 text-slate-950'
                  : 'bg-white/10 text-slate-300'}"
              >
                {step.num}
              </span>
              <div class="leading-tight">
                <div class="text-[11px] font-bold font-mono {isActive ? 'text-white' : ''}">
                  {step.label}
                </div>
                <div class="text-[9.5px] font-mono text-slate-400 hidden xl:block">
                  {#if step.id === 1}
                    {inScopeFoldersList.length} dossiers · {filteredTargets.length} CVE
                  {:else if step.id === 2}
                    {filteredTargets.length} cibles · {fileFunctions.length} fonctions
                  {:else if step.id === 3}
                    🌊 {dataDirection.upstream.length} IN → {dataDirection.downstream.length} OUT
                  {:else}
                    ⚡ 8 formats & Dry-Run
                  {/if}
                </div>
              </div>
            </button>
          {/each}
        </nav>

        <!-- Persistent Target Quick-Switcher (Usable across Steps 2-4) -->
        <div class="flex items-center gap-2 min-w-0 max-w-full sm:max-w-[430px]">
          <div class="flex items-center gap-1 text-[10px] font-mono text-amber-300 shrink-0">
            <ShieldAlert class="w-3.5 h-3.5" />
            <span class="hidden md:inline">Cible :</span>
          </div>
          <select
            class="flex-1 min-w-[200px] max-w-[380px] bg-black/50 border border-white/15 rounded-lg px-2.5 py-1 text-[11px] font-mono text-slate-100 focus:outline-none focus:border-amber-400"
            value={selectedAnomaly ? `${selectedAnomaly.cve_id}::${selectedAnomaly.file_path}:${selectedAnomaly.line_number}` : ''}
            onchange={(e) => {
              const val = e.currentTarget.value;
              const match = filteredTargets.find(
                (t) => `${t.cve_id}::${t.file_path}:${t.line_number}` === val
              );
              if (match) selectAnomalyTarget(match);
            }}
          >
            {#if filteredTargets.length === 0}
              <option value="">Aucune CVE dans le scope actif ({inScopeFoldersList.length} dossiers)</option>
            {:else}
              {#if !selectedAnomaly}
                <option value="">-- Sélectionner parmi {filteredTargets.length} CVE --</option>
              {/if}
              {#each filteredTargets as t}
                <option value={`${t.cve_id}::${t.file_path}:${t.line_number}`}>
                  [{t.severity}] {t.cve_id} ({t.cwe_class || 'CWE'}) · {t.file_path}:{t.line_number || 1}
                </option>
              {/each}
            {/if}
          </select>

          {#if activeFunction}
            <button
              type="button"
              onclick={() => (currentStep = 3)}
              class="hidden lg:flex items-center gap-1 px-2 py-1 rounded-lg bg-sky-500/15 border border-sky-400/35 text-sky-200 text-[10px] font-mono shrink-0 cursor-pointer hover:bg-sky-500/25"
              title="Inspecter la fonction active et son flux de données (Étape 3)"
            >
              <Code2 class="w-3 h-3" />
              <span class="truncate max-w-[110px]">{activeFunction.name}()</span>
            </button>
          {/if}
        </div>
      </div>

      <!-- 3. Active Step Viewport -->
      <main class="flex-1 min-h-0 flex flex-col overflow-hidden">
        {#if currentStep === 1}
          <StepScopePanel
            {projectFolders}
            {filteredProjectFolders}
            {inScopeFoldersList}
            {outScopeFoldersList}
            {recByFolder}
            {excludedFolders}
            {lockedSingleFolder}
            bind:folderSearchQuery
            bind:showWildcardEditor
            bind:inScopePatternsText
            bind:outScopePatternsText
            {activePreset}
            {scopeModeLabel}
            {scopeUpdatedBy}
            {scopeRationale}
            {isolateScopeIn3DGraph}
            bind:scopePromptMission
            bind:strictFolderBoundary
            bind:includeTopTargetsInPrompt
            bind:requireNonDestructivePoc
            bind:requireEarsInvariant
            bind:customScopeInstructions
            filteredTargetsCount={filteredTargets.length}
            {step1Prompt}
            {copiedKey}
            {sentToMcp}
            onApplyPreset={applyBountyPreset}
            onApplyAiRecommended={applyAiRecommendedScope}
            onSyncOutScope={syncOutScopeToScanner}
            onToggleIsolate3D={toggleIsolateScopeIn3DGraph}
            onLockSingleFolder={lockToSingleFolder}
            onIsolateOnlyFolder={isolateOnlyFolderInMatrix}
            onSetAllFoldersScope={setAllFoldersScope}
            onToggleFolderScope={toggleFolderScope}
            onCopyText={copyText}
            onSendScopePrompt={sendScopePromptToMcpChat}
            onDownloadScopePrompt={downloadScopePromptMd}
            onGoNextStep={() => (currentStep = 2)}
          />
        {:else if currentStep === 2}
          <StepTargetsFunctionsPanel
            {filteredTargets}
            {inScopeNodes}
            {selectedAnomaly}
            {selectedSymbol}
            bind:filterSeverity
            bind:filterReachableOnly
            bind:cveSearchQuery
            {criticalCount}
            {fileFunctions}
            {activeFunction}
            {lockedSingleFolder}
            {step2Prompt}
            {copiedKey}
            {sentToMcp}
            onSelectAnomaly={(a) => selectAnomalyTarget(a)}
            onSelectSymbol={(s) => selectSymbolTarget(s)}
            onSelectFunction={(fn) => selectFunctionItem(fn)}
            onInspectFunctionCodeData={(fn) => selectFunctionItem(fn, 3)}
            onFocusInGraph={focusActiveTargetIn3DGraph}
            onUnlockFolder={() => {
              lockedSingleFolder = 'ALL';
              void syncOutScopeToScanner('Unlock Folder');
            }}
            onCopyText={copyText}
            onSendPromptToChat={sendPromptToMcpChat}
            onGoPrevStep={() => (currentStep = 1)}
            onGoNextStep={() => (currentStep = 3)}
          />
        {:else if currentStep === 3}
          <StepCodeDataPanel
            {selectedAnomaly}
            {selectedSymbol}
            {fileFunctions}
            {activeFunction}
            {codeLines}
            bind:codeViewMode
            {snippetLoading}
            {snippetFileError}
            {dataDirection}
            {step3Prompt}
            {copiedKey}
            {sentToMcp}
            onSelectFunction={(fn) => selectFunctionItem(fn)}
            onToggleCodeViewMode={(mode) => (codeViewMode = mode)}
            onJumpToDataNode={handleJumpToDataNode}
            onFocusInGraph={focusActiveTargetIn3DGraph}
            onCopyText={copyText}
            onSendPromptToChat={sendPromptToMcpChat}
            onGoPrevStep={() => (currentStep = 2)}
            onGoNextStep={() => (currentStep = 4)}
          />
        {:else}
          <StepPromptsPocPanel
            {selectedAnomaly}
            {selectedSymbol}
            {activeFunction}
            {codeLines}
            {dataDirection}
            bind:promptFormat
            bind:reportRenderMode
            {step1Prompt}
            {step4TargetPrompt}
            {activePreset}
            {presetLabel}
            {scopeModeLabel}
            {inScopeFoldersList}
            {outScopeFoldersList}
            {lockedSingleFolder}
            {activeRecommendation}
            {isDryRunning}
            {dryRunResult}
            bind:dryRunActiveTab
            {copiedKey}
            {sentToMcp}
            onGoStep2={() => (currentStep = 2)}
            onGoPrevStep={() => (currentStep = 3)}
            onExecuteDryRun={executePocDryRun}
            onCopyText={copyText}
            onSendPromptToChat={sendPromptToMcpChat}
            onSendPocMissionToMcp={sendPocMissionToMcpChat}
            onSaveReportToWorkspace={saveReportToWorkspace}
            onDownloadReportMd={downloadReportMd}
            onDownloadScopeJson={downloadScopeJson}
          />
        {/if}
      </main>
    </div>
  </div>
{/if}
