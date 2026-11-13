import type { AetherGraph, SymbolBubble, TaskItem, CveAnomalyRecord } from '../types/graph';

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
  activeTab = $state<'debrief' | 'uml' | 'relations' | 'cve' | 'tasks'>('debrief');
  lodLevel = $state<1 | 2 | 3>(1);
  activeLayout = $state<'Z-1' | 'Z-2' | 'Z-3' | 'Z-4'>('Z-2');
  visionMode = $state<'standard' | 'xray' | 'heatmap' | 'deadcode'>('standard');
  searchQuery = $state('');
  tasks = $state<TaskItem[]>([]);

  // Modals & Panels Visibility
  isInspectorOpen = $state(false);
  isDocPanelOpen = $state(false);
  isCommandPaletteOpen = $state(false);
  isHubModalOpen = $state(false);
  isBountyModalOpen = $state(false);
  isGameServersModalOpen = $state(false);
  isSettingsModalOpen = $state(false);

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
