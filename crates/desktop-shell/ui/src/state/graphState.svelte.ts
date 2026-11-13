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
  selectedFolder = $state<string | null>(null);
  activeTab = $state<'debrief' | 'uml' | 'relations' | 'cve' | 'tasks'>('debrief');
  lodLevel = $state<1 | 2 | 3>(1);
  activeLayout = $state<'Z-1' | 'Z-2' | 'Z-3' | 'Z-4'>('Z-2');
  visionMode = $state<'standard' | 'xray' | 'heatmap' | 'deadcode'>('standard');
  viewMode = $state<'code' | 'vault'>('code');
  docMode = $state<'system' | 'symbol' | 'folder'>('system');
  searchQuery = $state('');
  tasks = $state<TaskItem[]>([]);
  settings = $state<CockpitSettings>(loadSavedSettings());
  cveCatalogue = $state.raw<any[]>([]);
  fitRequestTick = $state(0);
  focusTargetId = $state<string | null>(null);
  focusRequestTick = $state(0);
  disabledLayers = $state<Record<string, boolean>>({});
  disabledRelations = $state<Record<string, boolean>>({});
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

  toggleRelation(category: string) {
    this.disabledRelations = {
      ...this.disabledRelations,
      [category]: !this.disabledRelations[category],
    };
    this.filterVersion += 1;
  }

  resetFilters() {
    this.disabledLayers = {};
    this.disabledRelations = {};
    this.filterVersion += 1;
  }

  openDoc(mode?: 'system' | 'symbol' | 'folder') {
    if (mode) this.docMode = mode;
    else if (this.activeSymbol) this.docMode = 'symbol';
    else if (this.selectedFolder) this.docMode = 'folder';
    else this.docMode = 'system';
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
      const anomalies = rawAnomalies.map((a) => ({
        ...a,
        cwe_class: a.cwe_class || a.cve_id || a.rule_id || 'CWE',
        title: a.title || a.rule_id || a.cve_id || 'Security Alert',
        description: a.description || a.message || '',
      }));

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
      this.docMode = this.activeSymbol ? 'symbol' : this.selectedFolder ? 'folder' : 'system';
    }
    this.isDocPanelOpen = !this.isDocPanelOpen;
  }
}

export const cockpitState = new CockpitState();
