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
  searchQuery = $state('');
  tasks = $state<TaskItem[]>([]);
  settings = $state<CockpitSettings>(loadSavedSettings());
  cveCatalogue = $state.raw<any[]>([]);
  fitRequestTick = $state(0);

  // Modals & Panels Visibility
  isInspectorOpen = $state(false);
  isDocPanelOpen = $state(false);
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
    this.graph = g;
    if (g.nodes.length > 0 && !this.activeSymbol) {
      this.activeSymbol = g.nodes[0];
    }
  }

  selectSymbol(symbolId: string) {
    const found = this.graph.nodes.find((n) => n.id === symbolId);
    if (found) {
      this.activeSymbol = found;
      this.isInspectorOpen = true;
    }
  }

  toggleInspector() {
    this.isInspectorOpen = !this.isInspectorOpen;
  }

  toggleDocPanel() {
    this.isDocPanelOpen = !this.isDocPanelOpen;
  }
}

export const cockpitState = new CockpitState();
