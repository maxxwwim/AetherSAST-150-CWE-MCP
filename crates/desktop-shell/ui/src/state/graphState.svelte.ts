import type { AetherGraph, SymbolBubble, TaskItem, CveAnomalyRecord, GitStatusResponse, GitFileChange, EditActivityKind } from '../types/graph';
import { playSpatialTone } from '../lib/sound';
import { api } from '../lib/api';

export function isLinesExceededAnomaly(a?: Partial<CveAnomalyRecord> | null): boolean {
  if (!a) return false;
  const rule = String(a.rule_id || '').toUpperCase();
  const cve = String(a.cve_id || a.cwe_class || '').toUpperCase();
  const msg = String(a.message || a.description || '').toUpperCase();
  const sev = String(a.severity || '').toUpperCase();
  return (
    rule === 'RULE_MAX_LINES' ||
    cve.includes('ARCH-BUDGET-EXCEEDED') ||
    cve.includes('CWE-1075') ||
    msg.includes('RULE_MAX_LINES') ||
    msg.includes('MAXIMUM LINE LIMIT') ||
    sev === 'WARNING'
  );
}

export function getNodeAlertKind(n?: SymbolBubble | null): 'security' | 'lines_exceeded' | 'none' {
  if (!n) return 'none';
  if (n.has_security_violation) return 'security';
  const list = [
    ...(n.anomalies || []),
    ...(n.violations || []),
    ...(n.metadata?.cve_anomalies || []),
  ];
  let hasLines = false;
  for (const a of list) {
    if (isLinesExceededAnomaly(a)) {
      hasLines = true;
    } else {
      return 'security';
    }
  }
  const strViolations = n.metadata?.violations || [];
  for (const v of strViolations) {
    const up = String(v || '').toUpperCase();
    if (up.includes('RULE_MAX_LINES') || up.includes('ARCH-BUDGET-EXCEEDED') || up.includes('MAXIMUM LINE LIMIT')) {
      hasLines = true;
    } else {
      return 'security';
    }
  }
  if (hasLines) return 'lines_exceeded';
  const maxLimit = n.metadata?.max_lines_limit;
  if (maxLimit && maxLimit > 0 && (n.loc || n.metadata?.lines || 0) > maxLimit) {
    return 'lines_exceeded';
  }
  return 'none';
}

export function isTextOrDocFile(path?: string, layer?: string, kind?: string): boolean {
  const l = String(layer || '').toLowerCase();
  const k = String(kind || '').toLowerCase();
  if (l === 'docs' || k === 'note' || k === 'doc' || k === 'markdown') return true;
  const p = String(path || '').toLowerCase().trim();
  return (
    p.endsWith('.md') ||
    p.endsWith('.txt') ||
    p.endsWith('.rst') ||
    p.endsWith('.adoc') ||
    p.endsWith('.toml') ||
    p.endsWith('.json') ||
    p.endsWith('.yaml') ||
    p.endsWith('.yml') ||
    p.endsWith('.ears') ||
    p.endsWith('.ini') ||
    p.endsWith('.env')
  );
}

export interface CockpitSettings {
  maxLabelLength: number;
  hideBubbleLabelsOver20: boolean;
  clusterLabelThreshold: number;
  lazyReadmes: boolean;
  fpsLimit: '60' | '120' | 'unlimited';
  soundEnabled: boolean;
  showFolderBadges: boolean;
  showFolderMembranes: boolean;
  aiAutoCam: boolean;
  aiTrail: boolean;
  aiCustomPrompt: string;
  exclusions: string[];
  activeCveRules: string[];
  ignoredCwes: string[];
  mcpBinaryPath: string;
}

const DEFAULT_SETTINGS: CockpitSettings = {
  maxLabelLength: 18,
  hideBubbleLabelsOver20: true,
  clusterLabelThreshold: 20,
  lazyReadmes: true,
  fpsLimit: '120',
  soundEnabled: true,
  showFolderBadges: true,
  showFolderMembranes: true,
  aiAutoCam: true,
  aiTrail: true,
  aiCustomPrompt: '',
  exclusions: ['tests', '*.spec.*', '*.test.*'],
  activeCveRules: [],
  ignoredCwes: [],
  mcpBinaryPath: 'aetherscope-mcp.exe',
};

function loadSavedSettings(): CockpitSettings {
  try {
    const raw = typeof localStorage !== 'undefined' ? localStorage.getItem('aetherscope_settings') : null;
    if (raw) {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
    }
  } catch {
    // ignore invalid localStorage
  }
  return { ...DEFAULT_SETTINGS };
}

function loadSavedRadar(): boolean {
  try {
    if (typeof localStorage !== 'undefined') {
      const val = localStorage.getItem('aetherscope_show_radar');
      if (val !== null) return val === 'true';
    }
  } catch {
    // ignore localStorage errors
  }
  return true;
}

export function normalizeEdgeRelation(raw?: string): string {
  const r = String(raw || 'calls').toLowerCase().trim();
  if (r === 'realtime_ws' || r === 'realtimews') return 'realtime';
  if (r === 'security_violation' || r === 'security_violates' || r === 'violation') return 'violates';
  return r;
}

export class CockpitState {
  graph = $state.raw<AetherGraph>({
    project_name: 'AetherScope',
    nodes: [],
    edges: [],
    clusters: {},
    anomalies_count: 0,
    critical_count: 0,
  });

  activeSymbol = $state.raw<SymbolBubble | null>(null);
  hoveredSymbol = $state.raw<SymbolBubble | null>(null);
  hoverScreenPos = $state<{ x: number; y: number }>({ x: 0, y: 0 });
  selectedFolder = $state<string | null>(null);
  activeTab = $state<'debrief' | 'uml' | 'relations' | 'cve' | 'tasks'>('debrief');
  lodLevel = $state<1 | 2 | 3>(1);
  activeLayout = $state<'Z-1' | 'Z-2' | 'Z-3' | 'Z-4'>('Z-2');
  visionMode = $state<'standard' | 'xray' | 'heatmap' | 'deadcode'>('standard');
  viewMode = $state<'code' | 'vault'>('code');
  docMode = $state<'library' | 'folder' | 'symbol' | 'system'>('library');
  docSelectedPath = $state<string | null>(null);
  searchQuery = $state('');
  tasks = $state<TaskItem[]>([]);
  settings = $state<CockpitSettings>(loadSavedSettings());
  cveCatalogue = $state.raw<any[]>([]);
  fitRequestTick = $state(0);
  focusTargetId = $state<string | null>(null);
  focusRequestTick = $state(0);
  disabledLayers = $state<Record<string, boolean>>({});
  disabledRelations = $state<Record<string, boolean>>({});
  disabledModules = $state<Record<string, boolean>>({});
  pipelineHighlight = $state(false);
  filterVersion = $state(0);

  // Modals & Panels Visibility
  isInspectorOpen = $state(false);
  isDocPanelOpen = $state(false);
  isSynthesisOpen = $state(false);
  isCommandPaletteOpen = $state(false);
  isHubModalOpen = $state(false);
  isBountyModalOpen = $state(false);
  isGameServersModalOpen = $state(false);
  isSettingsModalOpen = $state(false);
  isPromptModalOpen = $state(false);
  promptModalTab = $state<'context' | 'master' | 'sysprompt' | 'mcp'>('context');
  isSurfaceScannerOpen = $state(false);
  isTasksModalOpen = $state(false);
  isCreateFileModalOpen = $state(false);
  isIgnoredCweModalOpen = $state(false);
  isChatOpen = $state(false);
  isMcpModalOpen = $state(false);
  showRadar = $state(loadSavedRadar());
  physicsPaused = $state(false);
  snapshotRequestTick = $state(0);
  graphVersion = $state(0);
  liveConnected = $state(false);
  bountyOutOfScopePatterns = $state<string[]>([]);
  isScanningProject = $state(false);
  scanningTargetPath = $state('');
  gitStatus = $state<GitStatusResponse | null>(null);
  folderEdits = $state<Record<string, { kind: EditActivityKind; count: number; lastTs: number; label: string }>>({});
  private lastGitSignature = '';
  private prevGitFileStates = new Map<string, string>();
  private knownTrackedFolders = new Set<string>();
  engine: any = null;

  // Live Multi-Agent AI Swarm, MCP & Copilot Telemetry
  activeAgents = $state<{
    agentId: string;
    agentName: string;
    color: string;
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
  }[]>([]);
  agentTrails = $state<Record<string, {
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    x?: number;
    y?: number;
  }[]>>({});
  aiTelemetry = $state<{
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    agentName?: string;
    agentId?: string;
    color?: string;
  } | null>(null);
  aiTrail = $state<{
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    agentName?: string;
    color?: string;
    x?: number;
    y?: number;
  }[]>([]);
  aiChatMessages = $state<{
    id: string;
    sender: string;
    text: string;
    target_symbol?: string | null;
    timestamp: number;
    agent_id?: string | null;
    agent_name?: string | null;
    recipient?: string | null;
    color?: string | null;
  }[]>([]);
  aiAgentStatus = $state<'ready' | 'thinking' | 'idle'>('ready');
  mcpConnected = $state(true);
  lastTelemetryTs = $state(0);

  private resolveAgentColor(agentId: string, customColor?: string): string {
    if (customColor) return customColor;
    const palette = ['#c084fc', '#38bdf8', '#34d399', '#f59e0b', '#f472b6', '#a3e635'];
    let hash = 0;
    for (let i = 0; i < agentId.length; i++) {
      hash = (hash * 31 + agentId.charCodeAt(i)) >>> 0;
    }
    return palette[hash % palette.length];
  }

  resolveTargetNode(target: string): SymbolBubble | undefined {
    const tLower = target.toLowerCase();
    return this.graph.nodes.find(
      (n) =>
        n.name.toLowerCase() === tLower ||
        n.id.toLowerCase() === tLower ||
        (n.file_path && n.file_path.toLowerCase().includes(tLower))
    );
  }

  recordAiTelemetry(
    ev: { target: string; action: string; details: string; timestamp: number; agent_id?: string; agent_name?: string; color?: string },
    agentsList?: { target: string; action: string; details: string; timestamp: number; agent_id?: string; agent_name?: string; color?: string }[]
  ) {
    const incoming = agentsList && agentsList.length > 0 ? agentsList : ev?.target ? [ev] : [];
    if (incoming.length === 0) return;

    let anyNew = false;
    let latestAutoFocusId: string | null = null;
    const nextTrails = { ...this.agentTrails };
    const nextActive: typeof this.activeAgents = [];
    const mergedGlobalTrail = [...this.aiTrail];

    for (const item of incoming) {
      if (!item?.target) continue;
      const agentId = item.agent_id || item.agent_name || (
        item.action?.toLowerCase().includes('claude') ? 'claude-mcp'
          : item.action?.toLowerCase().includes('gemini') ? 'gemini-mcp'
            : item.action?.toLowerCase().includes('cursor') ? 'cursor-mcp'
              : 'primary-agent'
      );
      const agentName = item.agent_name || agentId;
      const color = this.resolveAgentColor(agentId, item.color);
      const hit = this.resolveTargetNode(item.target);

      nextActive.push({
        agentId,
        agentName,
        color,
        target: item.target,
        action: item.action || 'Inspection',
        details: item.details || '',
        timestamp: item.timestamp,
        nodeId: hit?.id,
      });

      const prevAgentTrail = nextTrails[agentId] || [];
      if (!prevAgentTrail.some((p) => p.timestamp === item.timestamp && p.target === item.target)) {
        anyNew = true;
        if (hit && incoming.length === 1) {
          latestAutoFocusId = hit.id;
        }
        nextTrails[agentId] = [
          ...prevAgentTrail,
          {
            target: item.target,
            action: item.action || 'Inspection',
            details: item.details || '',
            timestamp: item.timestamp,
            nodeId: hit?.id,
            x: hit?.x,
            y: hit?.y,
          },
        ].slice(-18);

        if (!mergedGlobalTrail.some((p) => p.timestamp === item.timestamp && p.target === item.target && p.agentName === agentName)) {
          mergedGlobalTrail.push({
            target: item.target,
            action: item.action || 'Inspection',
            details: item.details || '',
            timestamp: item.timestamp,
            nodeId: hit?.id,
            agentName,
            color,
            x: hit?.x,
            y: hit?.y,
          });
        }
      }
    }

    this.activeAgents = nextActive.sort((a, b) => b.timestamp - a.timestamp);
    this.agentTrails = nextTrails;
    this.aiTrail = mergedGlobalTrail.slice(-36);

    const head = this.activeAgents[0];
    if (head) {
      this.aiTelemetry = {
        target: head.target,
        action: head.action,
        details: head.details,
        timestamp: head.timestamp,
        nodeId: head.nodeId,
        agentName: head.agentName,
        agentId: head.agentId,
        color: head.color,
      };
      this.lastTelemetryTs = head.timestamp;
    }

    if (anyNew && latestAutoFocusId && this.settings.aiAutoCam) {
      this.requestFocusSymbol(latestAutoFocusId);
    }
  }

  clearAiTrail() {
    this.aiTrail = [];
    this.agentTrails = {};
    this.activeAgents = [];
    this.aiTelemetry = null;
  }

  saveLocalSettings() {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('aetherscope_settings', JSON.stringify(this.settings));
      }
    } catch {
      // ignore storage quota errors
    }
  }

  toggleSound(): boolean {
    this.settings.soundEnabled = !this.settings.soundEnabled;
    this.saveLocalSettings();
    if (this.settings.soundEnabled) {
      playSpatialTone(true, 'action');
    }
    return this.settings.soundEnabled;
  }

  toggleRadar(): boolean {
    this.showRadar = !this.showRadar;
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('aetherscope_show_radar', String(this.showRadar));
      }
    } catch {
      // ignore storage quota errors
    }
    return this.showRadar;
  }

  requestCameraFit() {
    this.fitRequestTick += 1;
  }

  requestFocusSymbol(symbolId: string) {
    this.focusTargetId = symbolId;
    this.focusRequestTick += 1;
  }

  toggleLayer(layer: string) {
    this.disabledLayers = {
      ...this.disabledLayers,
      [layer]: !this.disabledLayers[layer],
    };
    this.filterVersion += 1;
  }

  setAllLayers(enableAll: boolean) {
    if (enableAll) {
      this.disabledLayers = {};
    } else {
      const next: Record<string, boolean> = {};
      for (const l of ['ui', 'action', 'domain', 'database', 'config', 'utility', 'docs']) {
        next[l] = true;
      }
      this.disabledLayers = next;
    }
    this.filterVersion += 1;
  }

  toggleModule(folder: string) {
    this.disabledModules = {
      ...this.disabledModules,
      [folder]: !this.disabledModules[folder],
    };
    this.filterVersion += 1;
  }

  setAllModules(enableAll: boolean) {
    if (enableAll) {
      this.disabledModules = {};
    } else {
      const next: Record<string, boolean> = {};
      for (const n of this.graph.nodes) {
        next[n.folder || n.cluster_id || 'root'] = true;
      }
      this.disabledModules = next;
    }
    this.filterVersion += 1;
  }

  toggleRelation(category: string) {
    const key = normalizeEdgeRelation(category);
    this.disabledRelations = {
      ...this.disabledRelations,
      [key]: !this.disabledRelations[key],
    };
    this.filterVersion += 1;
  }

  setAllRelations(enableAll: boolean, keys: string[] = []) {
    if (enableAll) {
      this.disabledRelations = {};
    } else {
      const next: Record<string, boolean> = {};
      for (const k of keys) next[normalizeEdgeRelation(k)] = true;
      this.disabledRelations = next;
    }
    this.filterVersion += 1;
  }

  togglePipelineHighlight() {
    this.pipelineHighlight = !this.pipelineHighlight;
    this.filterVersion += 1;
  }

  resetFilters() {
    this.disabledLayers = {};
    this.disabledRelations = {};
    this.disabledModules = {};
    this.pipelineHighlight = false;
    this.filterVersion += 1;
  }

  openDoc(mode?: 'library' | 'folder' | 'symbol' | 'system', filePath?: string) {
    if (filePath) {
      this.docSelectedPath = filePath;
    }
    if (mode) this.docMode = mode;
    else if (filePath) this.docMode = 'library';
    else if (this.activeSymbol) this.docMode = 'symbol';
    else if (this.selectedFolder) this.docMode = 'folder';
    else this.docMode = 'library';
    this.isDocPanelOpen = true;
  }

  openPromptModal(tab: 'context' | 'master' | 'sysprompt' | 'mcp' = 'context') {
    this.promptModalTab = tab;
    this.isPromptModalOpen = true;
  }

  requestSnapshot() {
    this.snapshotRequestTick += 1;
  }

  togglePhysicsPaused() {
    this.physicsPaused = !this.physicsPaused;
  }

  isCweIgnored(ruleId?: string, cveId?: string): boolean {
    const ignored = this.settings.ignoredCwes;
    if (!ignored || ignored.length === 0) return false;
    const r = String(ruleId || '').toUpperCase().trim();
    const c = String(cveId || '').toUpperCase().trim();
    return ignored.some((item) => {
      const ig = item.toUpperCase().trim();
      return Boolean(ig) && (ig === r || ig === c || (r && r.includes(ig)) || (c && c.includes(ig)));
    });
  }

  ignoreCweRule(ruleOrCve: string) {
    const token = ruleOrCve.trim();
    if (!token) return;
    if (!this.settings.ignoredCwes.includes(token)) {
      this.settings.ignoredCwes = [...this.settings.ignoredCwes, token];
      this.saveLocalSettings();
      this.filterVersion += 1;
    }
  }

  unignoreCweRule(ruleOrCve: string) {
    this.settings.ignoredCwes = this.settings.ignoredCwes.filter((r) => r !== ruleOrCve);
    this.saveLocalSettings();
    this.filterVersion += 1;
  }

  restoreAllCweRules() {
    this.settings.ignoredCwes = [];
    this.saveLocalSettings();
    this.filterVersion += 1;
  }

  // Derived computed states
  filteredNodes = $derived(
    this.searchQuery.trim() === ''
      ? this.graph.nodes
      : this.graph.nodes.filter(
          (n) =>
            n.name.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
            n.file_path.toLowerCase().includes(this.searchQuery.toLowerCase()) ||
            String(n.kind).toLowerCase().includes(this.searchQuery.toLowerCase())
        )
  );

  rawViolations = $derived.by(() => {
    const list: CveAnomalyRecord[] = [];
    for (const node of this.graph.nodes) {
      if (node.anomalies && node.anomalies.length > 0) {
        list.push(...node.anomalies);
      }
      if (node.violations && node.violations.length > 0) {
        list.push(...node.violations);
      }
    }
    return list;
  });

  allViolations = $derived(
    this.rawViolations.filter((v) => !this.isCweIgnored(v.rule_id, v.cve_id))
  );

  criticalViolations = $derived(
    this.allViolations.filter((v) => v.severity === 'CRITICAL')
  );

  orphanNodes = $derived(
    this.graph.nodes.filter((n) => n.is_orphan || (n.in_degree === 0 && n.out_degree === 0))
  );

  hotspotNodes = $derived(
    this.graph.nodes.filter((n) => n.cyclomatic_complexity >= 10)
  );

  private recomputeFolderEdits(nodes: SymbolBubble[]) {
    const map: Record<string, {
      modif: number;
      text: number;
      new_file: number;
      new_folder: number;
      violation: number;
      lastTs: number;
    }> = {};

    for (const n of nodes) {
      const ek = n.edit_kind || (
        n.git_status === 'violation' ? 'violation'
          : n.git_status === 'new_folder' ? 'new_folder'
            : n.git_status === 'untracked' ? 'new_file'
              : n.git_status === 'text' ? 'text'
                : n.git_status === 'modified' ? 'modif'
                  : 'none'
      );
      if (ek === 'none') continue;
      const folder = n.folder || n.cluster_id || 'root';
      if (!map[folder]) {
        map[folder] = { modif: 0, text: 0, new_file: 0, new_folder: 0, violation: 0, lastTs: 0 };
      }
      map[folder][ek] += 1;
      if ((n.last_edit_ts || 0) > map[folder].lastTs) {
        map[folder].lastTs = n.last_edit_ts || 0;
      }
    }

    const next: Record<string, { kind: EditActivityKind; count: number; lastTs: number; label: string }> = {};
    for (const [folder, counts] of Object.entries(map)) {
      const total = counts.violation + counts.new_folder + counts.new_file + counts.text + counts.modif;
      if (total === 0) continue;
      let kind: EditActivityKind = 'modif';
      let label = `✏️ MODIF (${counts.modif})`;
      if (counts.violation > 0) {
        kind = 'violation';
        label = `🚨 FAILLE (${counts.violation})`;
      } else if (counts.new_folder > 0) {
        kind = 'new_folder';
        label = `📁✨ NOUVEAU DOSSIER`;
      } else if (counts.new_file > 0) {
        kind = 'new_file';
        label = `✨ +FICHIER (${counts.new_file})`;
      } else if (counts.text > 0 && counts.modif === 0) {
        kind = 'text';
        label = `📝 TEXTE/DOC (${counts.text})`;
      } else if (counts.text > 0 && counts.modif > 0) {
        kind = 'modif';
        label = `✏️ CODE (${counts.modif}) · 📝 DOC (${counts.text})`;
      }
      next[folder] = { kind, count: total, lastTs: counts.lastTs, label };
    }
    this.folderEdits = next;
  }

  // Actions
  setGraph(g: AetherGraph, isIncremental = false) {
    const rawNodes = Array.isArray(g?.nodes) ? g.nodes : [];
    const prevNodes = this.graph.nodes || [];
    const isSameProject = prevNodes.length > 0 && (!g?.project_name || g.project_name === this.graph.project_name);
    const incremental = isIncremental || isSameProject;

    const prevMap = new Map<string, SymbolBubble>();
    const prevFolders = new Set<string>();
    const folderSums = new Map<string, { sx: number; sy: number; count: number }>();

    if (incremental) {
      for (const pn of prevNodes) {
        prevMap.set(pn.id, pn);
        const f = pn.folder || pn.cluster_id || 'root';
        prevFolders.add(f);
        if (Number.isFinite(pn.x) && Number.isFinite(pn.y)) {
          const cur = folderSums.get(f) || { sx: 0, sy: 0, count: 0 };
          cur.sx += pn.x;
          cur.sy += pn.y;
          cur.count += 1;
          folderSums.set(f, cur);
        }
      }
    }

    const nowTs = typeof performance !== 'undefined' ? performance.now() : Date.now();

    const normalizedNodes = rawNodes.map((rawNode) => {
      const meta = rawNode.metadata || {};
      const methods = (rawNode.methods && rawNode.methods.length > 0 ? rawNode.methods : meta.methods || []).map((m) => ({
        ...m,
        signature:
          m.signature ||
          `${m.is_async ? 'async ' : ''}${m.name}(${m.args || ''})${m.returns ? ` -> ${m.returns}` : ''}`,
        visibility: m.visibility || '+',
        line: m.line ?? rawNode.line_number ?? 1,
      }));
      const attributes = (rawNode.attributes && rawNode.attributes.length > 0
        ? rawNode.attributes
        : meta.attributes || []
      ).map((a) => ({
        ...a,
        attr_type: a.attr_type || a.type || 'any',
        visibility: a.visibility || '+',
      }));
      const rawAnomalies =
        rawNode.anomalies && rawNode.anomalies.length > 0 ? rawNode.anomalies : meta.cve_anomalies || [];
      let anomalies = rawAnomalies.map((a) => ({
        ...a,
        cwe_class: a.cwe_class || a.cve_id || a.rule_id || 'CWE',
        title: a.title || a.rule_id || a.cve_id || 'Security Alert',
        description: a.description || a.message || '',
      }));
      if (anomalies.length === 0 && meta.violations && meta.violations.length > 0) {
        anomalies = meta.violations.map((msg) => {
          const isMaxLines =
            msg.includes('RULE_MAX_LINES') ||
            msg.includes('ARCH-BUDGET-EXCEEDED') ||
            msg.includes('maximum line limit');
          return {
            rule_id: isMaxLines ? 'RULE_MAX_LINES' : 'SAST-VIOLATION',
            cve_id: isMaxLines ? 'CWE-1075 / ARCH-BUDGET-EXCEEDED' : 'CWE-SAST',
            cwe_class: isMaxLines ? 'CWE-1075 / ARCH-BUDGET-EXCEEDED' : 'CWE-SAST',
            severity: isMaxLines ? 'WARNING' : 'HIGH',
            title: isMaxLines ? 'Dépassement Budget Lignes' : 'Violation SAST / Contrat',
            description: msg,
            message: msg,
            remediation: isMaxLines
              ? 'Découper le fichier ou ajuster la limite max_lines dans le contrat BLAKE3.'
              : 'Inspecter la source et sceller les entrées/sorties.',
            file_path: rawNode.file_path,
            line_number: rawNode.line_number || 1,
          };
        });
      }

      const folder = rawNode.folder || rawNode.cluster_id || 'root';
      const loc = rawNode.loc || rawNode.lines_count || meta.lines || 1;
      const cc = rawNode.cyclomatic_complexity || rawNode.complexity || 1;
      const isText = isTextOrDocFile(rawNode.file_path, rawNode.layer, String(rawNode.kind));

      let nodeGitStatus: SymbolBubble['git_status'] = rawNode.git_status;
      let editKind: EditActivityKind = rawNode.edit_kind || 'none';
      let lastEditTs = rawNode.last_edit_ts || 0;
      let birthTime = rawNode.birth_time;
      let posX = rawNode.x;
      let posY = rawNode.y;

      const prev = incremental ? prevMap.get(rawNode.id) : undefined;
      if (prev) {
        // Preserve live physics coordinates & birth_time so navigation never jumps or resets!
        if (Number.isFinite(prev.x)) posX = prev.x;
        if (Number.isFinite(prev.y)) posY = prev.y;
        birthTime = prev.birth_time;
        nodeGitStatus = prev.git_status || nodeGitStatus;
        editKind = prev.edit_kind || editKind;
        lastEditTs = prev.last_edit_ts || 0;

        // Detect live AST modification on this node
        const locChanged = loc !== prev.loc;
        const ccChanged = cc !== prev.cyclomatic_complexity;
        const docChanged = (rawNode.docstring || '') !== (prev.docstring || '');
        const methodsChanged = methods.length !== (prev.methods?.length || 0);
        const anomChanged = anomalies.length !== (prev.anomalies?.length || 0);
        const secAnomCount = anomalies.filter((a) => !isLinesExceededAnomaly(a)).length;
        const prevSecAnomCount = (prev.anomalies || []).filter((a) => !isLinesExceededAnomaly(a)).length;

        if (locChanged || ccChanged || docChanged || methodsChanged || anomChanged) {
          lastEditTs = nowTs;
          if (secAnomCount > prevSecAnomCount || Boolean(rawNode.has_security_violation && !prev.has_security_violation)) {
            editKind = 'violation';
            nodeGitStatus = 'violation';
          } else if (isText || (docChanged && !locChanged && !ccChanged)) {
            editKind = 'text';
            nodeGitStatus = 'text';
          } else {
            editKind = 'modif';
            nodeGitStatus = 'modified';
          }
        }
      } else if (incremental) {
        // Brand new node created during live session!
        birthTime = nowTs;
        lastEditTs = nowTs;
        const isNewFolder = !prevFolders.has(folder) && !this.knownTrackedFolders.has(folder);
        if (isNewFolder) {
          editKind = 'new_folder';
          nodeGitStatus = 'new_folder';
        } else if (isText) {
          editKind = 'text';
          nodeGitStatus = 'text';
        } else {
          editKind = 'new_file';
          nodeGitStatus = 'untracked';
        }
        // Spawn inside parent folder cell centroid if available
        const fCenter = folderSums.get(folder);
        if (fCenter && fCenter.count > 0) {
          posX = fCenter.sx / fCenter.count + (Math.random() - 0.5) * 42;
          posY = fCenter.sy / fCenter.count + (Math.random() - 0.5) * 42;
        }
      } else {
        this.knownTrackedFolders.add(folder);
      }

      if ((!nodeGitStatus || nodeGitStatus === 'clean') && this.gitStatus && Array.isArray(this.gitStatus.files)) {
        const cleanPath = (p: string) => p.replace(/\\/g, '/').toLowerCase().trim();
        const np = cleanPath(rawNode.file_path || '');
        const match = this.gitStatus.files.find((f) => {
          const fp = cleanPath(f.path);
          return np === fp || np.endsWith(fp) || fp.endsWith(np);
        });
        if (match) {
          const isViolation = match.has_security_violation || match.ears_violation || Boolean(rawNode.has_security_violation);
          if (isViolation) {
            nodeGitStatus = 'violation';
            editKind = 'violation';
          } else if (match.status === 'untracked' || match.status === 'added') {
            if (!this.knownTrackedFolders.has(folder) && incremental) {
              nodeGitStatus = 'new_folder';
              editKind = 'new_folder';
            } else if (isText) {
              nodeGitStatus = 'text';
              editKind = 'text';
            } else {
              nodeGitStatus = 'untracked';
              editKind = 'new_file';
            }
          } else if (isText) {
            nodeGitStatus = 'text';
            editKind = 'text';
          } else {
            nodeGitStatus = 'modified';
            editKind = 'modif';
          }
        }
      }

      return {
        ...rawNode,
        x: posX,
        y: posY,
        birth_time: birthTime,
        git_status: nodeGitStatus || 'clean',
        edit_kind: editKind,
        last_edit_ts: lastEditTs,
        folder,
        cluster_id: rawNode.cluster_id || folder,
        loc,
        cyclomatic_complexity: cc,
        is_orphan: Boolean(
          rawNode.is_orphan ?? rawNode.is_dead_code ?? (rawNode.in_degree === 0 && rawNode.out_degree === 0)
        ),
        methods,
        attributes,
        anomalies,
      };
    });

    this.recomputeFolderEdits(normalizedNodes);

    this.graph = {
      ...g,
      nodes: normalizedNodes,
      edges: Array.isArray(g?.edges) ? g.edges : [],
      clusters: g?.clusters || {},
    };
    if (normalizedNodes.length > 0 && !this.activeSymbol) {
      this.activeSymbol = normalizedNodes[0];
    } else if (this.activeSymbol) {
      const updatedActive = normalizedNodes.find((n) => n.id === this.activeSymbol?.id);
      if (updatedActive) this.activeSymbol = updatedActive;
    }
    if (this.engine) {
      this.engine.syncGraphToEngine(!incremental);
    }
  }

  async fetchGitStatus(forceRefresh = false): Promise<GitStatusResponse | null> {
    try {
      const data: GitStatusResponse = typeof (api as any).getGitStatus === 'function'
        ? await (api as any).getGitStatus()
        : await (await fetch('/api/git/status')).json();

      if (!data) return null;

      const cleanPath = (p: string) => p.replace(/\\/g, '/').toLowerCase().trim();
      const files = Array.isArray(data.files) ? data.files : [];
      const sig = files
        .map((f) => `${cleanPath(f.path)}:${f.status}:${f.has_security_violation ? 1 : 0}:${f.cwe_count}:${f.ears_violation ? 1 : 0}`)
        .sort()
        .join('|');

      // Zero re-init if Git status hasn't changed!
      if (!forceRefresh && this.lastGitSignature !== '' && sig === this.lastGitSignature) {
        return data;
      }

      const isInitialGitLoad = this.lastGitSignature === '';
      this.lastGitSignature = sig;
      this.gitStatus = data;

      const gitMap = new Map<string, GitFileChange>();
      const newlyChangedPaths = new Set<string>();
      for (const f of files) {
        const cp = cleanPath(f.path);
        gitMap.set(cp, f);
        const stateToken = `${f.status}:${f.cwe_count}:${f.ears_violation ? 1 : 0}`;
        if (!isInitialGitLoad && this.prevGitFileStates.get(cp) !== stateToken) {
          newlyChangedPaths.add(cp);
        }
      }
      this.prevGitFileStates.clear();
      for (const [cp, f] of gitMap.entries()) {
        this.prevGitFileStates.set(cp, `${f.status}:${f.cwe_count}:${f.ears_violation ? 1 : 0}`);
      }

      // Identify folders that have at least one clean (already tracked) file
      const trackedFolders = new Set<string>(this.knownTrackedFolders);
      for (const n of this.graph.nodes) {
        const np = cleanPath(n.file_path || '');
        const m = gitMap.get(np);
        if (!m || (m.status !== 'untracked' && m.status !== 'added')) {
          trackedFolders.add(n.folder || n.cluster_id || 'root');
        }
      }

      const nowTs = typeof performance !== 'undefined' ? performance.now() : Date.now();

      for (const n of this.graph.nodes) {
        const nodePath = cleanPath(n.file_path || '');
        let match = gitMap.get(nodePath);
        let matchedKey = nodePath;
        if (!match && nodePath) {
          for (const [fPath, f] of gitMap.entries()) {
            if (nodePath.endsWith(fPath) || fPath.endsWith(nodePath)) {
              match = f;
              matchedKey = fPath;
              break;
            }
          }
        }

        const folder = n.folder || n.cluster_id || 'root';
        const isText = isTextOrDocFile(n.file_path, n.layer, String(n.kind));

        if (match) {
          const isViolation = match.has_security_violation || match.ears_violation || Boolean(n.has_security_violation);
          if (isViolation) {
            n.git_status = 'violation';
            n.edit_kind = 'violation';
          } else if (match.status === 'untracked' || match.status === 'added') {
            if (!trackedFolders.has(folder)) {
              n.git_status = 'new_folder';
              n.edit_kind = 'new_folder';
            } else if (isText) {
              n.git_status = 'text';
              n.edit_kind = 'text';
            } else {
              n.git_status = 'untracked';
              n.edit_kind = 'new_file';
            }
          } else if (isText) {
            n.git_status = 'text';
            n.edit_kind = 'text';
          } else {
            n.git_status = 'modified';
            n.edit_kind = 'modif';
          }

          if (newlyChangedPaths.has(matchedKey) || (!n.last_edit_ts && !isInitialGitLoad)) {
            n.last_edit_ts = nowTs;
          }
        } else {
          n.git_status = 'clean';
          n.edit_kind = 'none';
        }
      }

      this.recomputeFolderEdits(this.graph.nodes);

      // Update WebGL instance attributes in-place WITHOUT resetting camera, positions, or physics!
      if (this.engine && typeof this.engine.updateGitAndEditHighlights === 'function') {
        this.engine.updateGitAndEditHighlights();
      }
      return data;
    } catch {
      return null;
    }
  }

  selectSymbol(symbolId: string, focusCamera = false) {
    const found = this.graph.nodes.find((n) => n.id === symbolId);
    if (found) {
      this.activeSymbol = found;
      this.selectedFolder = found.folder || found.cluster_id || null;
      this.isInspectorOpen = true;
      if (this.docMode !== 'system') {
        this.docMode = 'symbol';
      }
      if (focusCamera) {
        this.requestFocusSymbol(symbolId);
      }
    }
  }

  selectFolder(folderName: string, openDoc = false) {
    this.selectedFolder = folderName;
    this.activeSymbol = null;
    this.isInspectorOpen = true;
    if (openDoc) {
      this.docMode = 'folder';
      this.isDocPanelOpen = true;
    } else if (this.docMode !== 'system') {
      this.docMode = 'folder';
    }
  }

  clearSelection() {
    this.activeSymbol = null;
    this.selectedFolder = null;
  }

  toggleInspector() {
    this.isInspectorOpen = !this.isInspectorOpen;
  }

  toggleDocPanel() {
    if (!this.isDocPanelOpen) {
      this.docMode = this.activeSymbol ? 'symbol' : this.selectedFolder ? 'folder' : 'library';
    }
    this.isDocPanelOpen = !this.isDocPanelOpen;
  }
}

export const cockpitState = new CockpitState();
