import type { AetherGraph, SymbolBubble, TaskItem, CveAnomalyRecord } from '../types/graph';

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
  isChatOpen = $state(false);
  isMcpModalOpen = $state(false);

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

  private resolveTargetNode(target: string): SymbolBubble | undefined {
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

  allViolations = $derived.by(() => {
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

  criticalViolations = $derived(
    this.allViolations.filter((v) => v.severity === 'CRITICAL')
  );

  orphanNodes = $derived(
    this.graph.nodes.filter((n) => n.is_orphan || (n.in_degree === 0 && n.out_degree === 0))
  );

  hotspotNodes = $derived(
    this.graph.nodes.filter((n) => n.cyclomatic_complexity >= 10)
  );

  // Actions
  setGraph(g: AetherGraph) {
    const rawNodes = Array.isArray(g?.nodes) ? g.nodes : [];
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
        anomalies = meta.violations.map((msg) => ({
          rule_id: 'SAST-VIOLATION',
          cve_id: 'CWE-SAST',
          cwe_class: 'CWE-SAST',
          severity: 'HIGH',
          title: 'Violation SAST / Contrat',
          description: msg,
          message: msg,
          remediation: 'Inspecter la source et sceller les entrées/sorties.',
          file_path: rawNode.file_path,
          line_number: rawNode.line_number || 1,
        }));
      }

      return {
        ...rawNode,
        folder: rawNode.folder || rawNode.cluster_id || 'root',
        cluster_id: rawNode.cluster_id || rawNode.folder || 'root',
        loc: rawNode.loc || rawNode.lines_count || meta.lines || 1,
        cyclomatic_complexity: rawNode.cyclomatic_complexity || rawNode.complexity || 1,
        is_orphan: Boolean(
          rawNode.is_orphan ?? rawNode.is_dead_code ?? (rawNode.in_degree === 0 && rawNode.out_degree === 0)
        ),
        methods,
        attributes,
        anomalies,
      };
    });

    this.graph = {
      ...g,
      nodes: normalizedNodes,
      edges: Array.isArray(g?.edges) ? g.edges : [],
      clusters: g?.clusters || {},
    };
    if (normalizedNodes.length > 0 && !this.activeSymbol) {
      this.activeSymbol = normalizedNodes[0];
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
