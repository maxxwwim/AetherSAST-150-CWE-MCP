import type { AetherGraph, AffiliationEdge, SymbolBubble, TaskItem, CveAnomalyRecord, GitStatusResponse, GitFileChange, EditActivityKind } from '../types/graph';
import { playSpatialTone } from '../lib/sound';
import { api } from '../lib/api';
import { decodeCompactGraph } from '../lib/graphCodec';

export function isLinesExceededAnomaly(a?: Partial<CveAnomalyRecord> | null): boolean {
  if (!a) return false;
  const rule = String(a.rule_id || '').toUpperCase();
  const cve = String(a.cve_id || a.cwe_class || '').toUpperCase();
  const msg = String(a.message || a.description || a.title || '').toUpperCase();
  const sev = String(a.severity || '').toUpperCase();
  return (
    rule === 'RULE_MAX_LINES' ||
    rule.includes('MAX_LINES') ||
    rule.includes('LINE_LIMIT') ||
    rule.includes('LINE_BUDGET') ||
    cve.includes('ARCH-BUDGET') ||
    cve.includes('CONTRACT-BUDGET') ||
    cve.includes('CONTRACT / ARCH-BUDGET') ||
    cve.includes('CWE-1075') ||
    cve === 'CONTRACT_BUDGET' ||
    msg.includes('RULE_MAX_LINES') ||
    msg.includes('MAXIMUM LINE LIMIT') ||
    msg.includes('EXCEEDS CONTRACT MAXIMUM LINE') ||
    msg.includes('BUDGET DE LIGNES') ||
    msg.includes('BUDGET LIGNES') ||
    (sev === 'WARNING' &&
      (rule.includes('LINE') ||
        cve.includes('BUDGET') ||
        cve.includes('CONTRACT') ||
        msg.includes('LINE') ||
        msg.includes('BUDGET')))
  );
}

export function getNodeAlertKind(n?: SymbolBubble | null): 'security' | 'lines_exceeded' | 'none' {
  if (!n) return 'none';
  const list = [
    ...(n.anomalies || []),
    ...(n.violations || []),
    ...(n.metadata?.cve_anomalies || []),
  ];
  const strViolations = n.metadata?.violations || [];

  let hasLines = false;
  let hasRealSecurity = false;

  for (const a of list) {
    if (isLinesExceededAnomaly(a)) {
      hasLines = true;
    } else {
      hasRealSecurity = true;
      break;
    }
  }

  if (!hasRealSecurity) {
    for (const v of strViolations) {
      const up = String(v || '').toUpperCase();
      if (
        up.includes('RULE_MAX_LINES') ||
        up.includes('ARCH-BUDGET-EXCEEDED') ||
        up.includes('MAXIMUM LINE LIMIT') ||
        up.includes('BUDGET LIGNES') ||
        up.includes('EXCEEDS CONTRACT MAXIMUM LINE')
      ) {
        hasLines = true;
      } else {
        hasRealSecurity = true;
        break;
      }
    }
  }

  if (hasRealSecurity) return 'security';

  const maxLimit = n.metadata?.max_lines_limit;
  const currentLoc = n.loc || n.metadata?.lines || 0;
  if (maxLimit && maxLimit > 0 && currentLoc > maxLimit) {
    hasLines = true;
  }

  if (hasLines) return 'lines_exceeded';

  if (n.has_security_violation) {
    return 'security';
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

/**
 * Agrège un chemin de dossier en module architectural haut niveau (ex. "src/Core", "classes/order").
 * Évite d'exploser en milliers de micro-cellules pour chaque sous-sous-dossier dans les gros projets.
 */
export function getArchitecturalModule(folderPath?: string): string {
  if (!folderPath || folderPath === 'root') return 'root';
  const clean = folderPath.replace(/\\/g, '/').replace(/^\.\//, '').trim();
  const parts = clean.split('/').filter(Boolean);
  if (parts.length <= 1) return clean;
  return parts.slice(0, 2).join('/');
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
  showAlerts: boolean;
  showCweBubbles: boolean;
  showCweTitles: boolean;
  showFolderTitles: boolean;
  showFileTitles: boolean;
  lowMemoryMode: boolean;
}

const EMPTY_METHODS: any[] = Object.freeze([]);
const EMPTY_ATTRIBUTES: any[] = Object.freeze([]);
const EMPTY_ANOMALIES: any[] = Object.freeze([]);

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
  exclusions: ['vendor', 'var', 'cache', 'tests', '*.spec.*', '*.test.*'],
  activeCveRules: [],
  ignoredCwes: [],
  mcpBinaryPath: 'aetherscope-mcp.exe',
  showAlerts: true,
  showCweBubbles: true,
  showCweTitles: true,
  showFolderTitles: true,
  showFileTitles: true,
  lowMemoryMode: false,
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

interface SavedAiCache {
  activeAgents: {
    agentId: string;
    agentName: string;
    color: string;
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    prevX?: number;
    prevY?: number;
    targetX?: number;
    targetY?: number;
    moveStartTs?: number;
  }[];
  agentTrails: Record<string, {
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    x?: number;
    y?: number;
  }[]>;
  aiTrail: {
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    agentName?: string;
    color?: string;
    x?: number;
    y?: number;
  }[];
}

function loadSavedAiCache(): SavedAiCache {
  try {
    if (typeof localStorage !== 'undefined') {
      const raw = localStorage.getItem('aetherscope_ai_cache');
      if (raw) {
        const parsed = JSON.parse(raw);
        return {
          activeAgents: Array.isArray(parsed.activeAgents) ? parsed.activeAgents : [],
          agentTrails: parsed.agentTrails && typeof parsed.agentTrails === 'object' ? parsed.agentTrails : {},
          aiTrail: Array.isArray(parsed.aiTrail) ? parsed.aiTrail : [],
        };
      }
    }
  } catch {
    // ignore
  }
  return { activeAgents: [], agentTrails: {}, aiTrail: [] };
}

const INITIAL_AI_CACHE = loadSavedAiCache();

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
  isDemoMode = $state(false);
  bountyOutOfScopePatterns = $state<string[]>([]);
  isScanningProject = $state(false);
  scanningTargetPath = $state('');
  gitStatus = $state<GitStatusResponse | null>(null);
  folderEdits = $state<Record<string, { kind: EditActivityKind; count: number; lastTs: number; label: string }>>({});
  private lastGitSignature = '';
  private prevGitFileStates = new Map<string, string>();
  private knownTrackedFolders = new Set<string>();
  nodeById = new Map<string, SymbolBubble>();
  engine: any = null;

  getNodeById(id: string | null | undefined): SymbolBubble | undefined {
    if (!id) return undefined;
    return this.nodeById.get(id);
  }

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
    prevX?: number;
    prevY?: number;
    targetX?: number;
    targetY?: number;
    moveStartTs?: number;
  }[]>(INITIAL_AI_CACHE.activeAgents);
  agentTrails = $state<Record<string, {
    target: string;
    action: string;
    details: string;
    timestamp: number;
    nodeId?: string;
    x?: number;
    y?: number;
  }[]>>(INITIAL_AI_CACHE.agentTrails);
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
  }[]>(INITIAL_AI_CACHE.aiTrail);
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

  saveLocalAiCache() {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(
          'aetherscope_ai_cache',
          JSON.stringify({
            activeAgents: this.activeAgents,
            agentTrails: this.agentTrails,
            aiTrail: this.aiTrail,
          })
        );
      }
    } catch {
      // ignore
    }
  }

  resolveAgentColor(agentId?: string, customColor?: string, agentName?: string, indexOffset = 0): string {
    if (customColor && customColor.trim()) return customColor.trim();
    const palette = [
      '#38bdf8', // Cyan (Sky)
      '#f97316', // Orange (Fire)
      '#c084fc', // Purple (Cosmic)
      '#34d399', // Emerald (Bio)
      '#f43f5e', // Rose (Neon)
      '#eab308', // Amber (Solar)
      '#a855f7', // Violet
      '#06b6d4', // Bright Turquoise
      '#ec4899', // Hot Pink
      '#84cc16', // Toxic Lime
      '#6366f1', // Indigo
      '#14b8a6', // Teal
      '#fb923c', // Tangerine
      '#e879f9', // Fuchsia
      '#10b981', // Green
      '#3b82f6', // Electric Blue
    ];
    const key = (agentId || agentName || 'primary-agent').trim().toLowerCase();
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
    }
    return palette[(hash + indexOffset) % palette.length];
  }

  resolveTargetNode(target: string): SymbolBubble | undefined {
    if (!target) return undefined;
    let clean = target.trim();
    clean = clean.replace(/^(?:file|note|symbol)::+/i, '');
    clean = clean.replace(/:\d+(?::\d+)?$/, '');
    clean = clean.replace(/\\/g, '/').trim();
    if (!clean) return undefined;

    // Fast O(1) direct ID hit
    const fastHit = this.nodeById.get(clean);
    if (fastHit) return fastHit;

    const tLower = clean.toLowerCase();
    const baseNameLower = tLower.split('/').pop() || tLower;

    // 1. Exact ID or name match
    let hit = this.graph.nodes.find(
      (n) => n.id.toLowerCase() === tLower || n.name.toLowerCase() === tLower
    );
    if (hit) return hit;

    // 2. Exact match on basename
    hit = this.graph.nodes.find(
      (n) => n.name.toLowerCase() === baseNameLower
    );
    if (hit) return hit;

    // 2b. Exact or partial match with :: converted to / or _
    const slashClean = clean.replace(/::/g, '/').toLowerCase();
    hit = this.graph.nodes.find((n) => {
      const np = (n.file_path || '').replace(/\\/g, '/').toLowerCase();
      return np === slashClean || np.endsWith('/' + slashClean) || np.includes(slashClean) || slashClean.includes(np);
    });
    if (hit) return hit;

    // 3. File path ends with or equals
    hit = this.graph.nodes.find((n) => {
      const np = (n.file_path || '').replace(/\\/g, '/').toLowerCase();
      return np === tLower || np.endsWith('/' + tLower) || np.endsWith(tLower);
    });
    if (hit) return hit;

    // 4. File path contains
    hit = this.graph.nodes.find((n) => {
      const np = (n.file_path || '').replace(/\\/g, '/').toLowerCase();
      return np.includes(tLower) || (baseNameLower.length > 2 && np.includes(baseNameLower));
    });
    if (hit) return hit;

    // 5. Folder match
    hit = this.graph.nodes.find((n) => {
      const f = (n.folder || '').replace(/\\/g, '/').toLowerCase();
      return f === tLower || f.endsWith('/' + tLower) || tLower.includes(f);
    });
    return hit;
  }

  syncTelemetryCoordinates() {
    let changed = false;
    for (const ag of this.activeAgents) {
      const hit = this.resolveTargetNode(ag.target);
      if (hit) {
        ag.nodeId = hit.id;
        if (ag.targetX !== hit.x || ag.targetY !== hit.y) {
          ag.prevX = ag.targetX ?? hit.x;
          ag.prevY = ag.targetY ?? hit.y;
          ag.targetX = hit.x;
          ag.targetY = hit.y;
          ag.moveStartTs = typeof performance !== 'undefined' ? performance.now() : Date.now();
          changed = true;
        }
      }
    }
    for (const trail of Object.values(this.agentTrails)) {
      for (const p of trail) {
        const hit = this.resolveTargetNode(p.target);
        if (hit && (p.x !== hit.x || p.y !== hit.y || p.nodeId !== hit.id)) {
          p.nodeId = hit.id;
          p.x = hit.x;
          p.y = hit.y;
          changed = true;
        }
      }
    }
    for (const p of this.aiTrail) {
      const hit = this.resolveTargetNode(p.target);
      if (hit && (p.x !== hit.x || p.y !== hit.y || p.nodeId !== hit.id)) {
        p.nodeId = hit.id;
        p.x = hit.x;
        p.y = hit.y;
        changed = true;
      }
    }
    if (changed) {
      this.saveLocalAiCache();
    }
  }

  syncTaskAgentsToTelemetry(tasks: TaskItem[]) {
    if (!tasks || tasks.length === 0) return;
    const taskAgents: { target: string; action: string; details: string; timestamp: number; agent_id?: string; agent_name?: string; color?: string }[] = [];
    for (const t of tasks) {
      if (t.status === 'done' || t.status === 'cancelled') continue;
      const target = t.target_symbol || t.target_file;
      if (!target) continue;
      const agentId = t.agent_id || (t.agent_name ? t.agent_name.toLowerCase().replace(/\s+/g, '-') : t.author ? t.author.toLowerCase().replace(/\s+/g, '-') : `task-agent-${t.id}`);
      const agentName = t.agent_name || (t.author && t.author !== 'model' ? t.author : `Agent (${t.title.slice(0, 16)})`);
      taskAgents.push({
        target,
        action: `Mission: ${t.kind}`,
        details: `${t.title} (${t.progress || 0}%)`,
        timestamp: Date.now(),
        agent_id: agentId,
        agent_name: agentName,
        color: t.color,
      });
    }
    if (taskAgents.length > 0) {
      this.recordAiTelemetry(taskAgents[0], taskAgents);
    }
  }

  recordAiTelemetry(
    ev: { target: string; action: string; details: string; timestamp: number; agent_id?: string; agent_name?: string; color?: string },
    agentsList?: { target: string; action: string; details: string; timestamp: number; agent_id?: string; agent_name?: string; color?: string }[],
    historyList?: { target: string; action: string; details: string; timestamp: number; agent_id?: string; agent_name?: string; color?: string }[]
  ) {
    const incoming = agentsList && agentsList.length > 0 ? agentsList : ev?.target ? [ev] : [];
    if (incoming.length === 0 && (!historyList || historyList.length === 0)) return;

    let anyNew = false;
    let latestAutoFocusId: string | null = null;
    const nextTrails = { ...this.agentTrails };
    const mergedGlobalTrail = [...this.aiTrail];

    // Seed activeMap with all existing active agents so none are discarded!
    const activeMap = new Map<string, (typeof this.activeAgents)[0]>();
    for (const ag of this.activeAgents) {
      activeMap.set(ag.agentId, ag);
    }

    // Reconstruct history if provided from backend cache
    if (historyList && historyList.length > 0) {
      const chronological = [...historyList].sort((a, b) => a.timestamp - b.timestamp);
      for (const hist of chronological) {
        if (!hist?.target) continue;
        const normTs = hist.timestamp < 1e11 ? hist.timestamp * 1000 : hist.timestamp;
        const aid = hist.agent_id || hist.agent_name || 'primary-agent';
        const aname = hist.agent_name || aid;
        const color = this.resolveAgentColor(aid, hist.color, aname);
        const hit = this.resolveTargetNode(hist.target);

        const curAgentTrail = nextTrails[aid] || [];
        if (!curAgentTrail.some((p) => Math.abs(p.timestamp - normTs) <= 1000 && p.target === hist.target)) {
          nextTrails[aid] = [
            ...curAgentTrail,
            {
              target: hist.target,
              action: hist.action || 'Inspection',
              details: hist.details || '',
              timestamp: normTs,
              nodeId: hit?.id,
              x: hit?.x,
              y: hit?.y,
            },
          ].slice(-32);
        }

        if (!mergedGlobalTrail.some((p) => Math.abs(p.timestamp - normTs) <= 1000 && p.target === hist.target && p.agentName === aname)) {
          mergedGlobalTrail.push({
            target: hist.target,
            action: hist.action || 'Inspection',
            details: hist.details || '',
            timestamp: normTs,
            nodeId: hit?.id,
            agentName: aname,
            color,
            x: hit?.x,
            y: hit?.y,
          });
        }
      }
    }

    for (const item of incoming) {
      if (!item?.target) continue;
      const normTs = item.timestamp < 1e11 ? item.timestamp * 1000 : item.timestamp;
      const agentId = item.agent_id || item.agent_name || (
        item.action?.toLowerCase().includes('claude') ? 'claude-mcp'
          : item.action?.toLowerCase().includes('gemini') ? 'gemini-mcp'
            : item.action?.toLowerCase().includes('cursor') ? 'cursor-mcp'
              : 'primary-agent'
      );
      const agentName = item.agent_name || agentId;
      const color = this.resolveAgentColor(agentId, item.color, agentName);
      const hit = this.resolveTargetNode(item.target);

      const existingActive = activeMap.get(agentId) || this.activeAgents.find((a) => a.agentId === agentId);
      let prevX = existingActive?.targetX;
      let prevY = existingActive?.targetY;
      let targetX = hit?.x;
      let targetY = hit?.y;
      let moveStartTs = (prevX !== undefined && targetX !== undefined && (prevX !== targetX || prevY !== targetY))
        ? (typeof performance !== 'undefined' ? performance.now() : Date.now())
        : existingActive?.moveStartTs;

      activeMap.set(agentId, {
        agentId,
        agentName,
        color,
        target: item.target,
        action: item.action || 'Inspection',
        details: item.details || '',
        timestamp: normTs,
        nodeId: hit?.id,
        prevX,
        prevY,
        targetX,
        targetY,
        moveStartTs,
      });

      const prevAgentTrail = nextTrails[agentId] || [];
      if (!prevAgentTrail.some((p) => Math.abs(p.timestamp - normTs) <= 1000 && p.target === item.target)) {
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
            timestamp: normTs,
            nodeId: hit?.id,
            x: hit?.x,
            y: hit?.y,
          },
        ].slice(-32);

        if (!mergedGlobalTrail.some((p) => Math.abs(p.timestamp - normTs) <= 1000 && p.target === item.target && p.agentName === agentName)) {
          mergedGlobalTrail.push({
            target: item.target,
            action: item.action || 'Inspection',
            details: item.details || '',
            timestamp: normTs,
            nodeId: hit?.id,
            agentName,
            color,
            x: hit?.x,
            y: hit?.y,
          });
        }
      }
    }

    const sortedActive = Array.from(activeMap.values()).sort((a, b) => b.timestamp - a.timestamp);
    // Guarantee 100% unique, distinct color per active agent ("une couleur par IA")
    const usedColors = new Set<string>();
    for (let i = 0; i < sortedActive.length; i++) {
      const ag = sortedActive[i];
      let c = ag.color;
      if (!c || usedColors.has(c)) {
        c = this.resolveAgentColor(ag.agentId, undefined, ag.agentName, i);
      }
      usedColors.add(c);
      ag.color = c;
    }

    this.activeAgents = sortedActive;
    this.agentTrails = nextTrails;
    this.aiTrail = mergedGlobalTrail.slice(-64);
    this.saveLocalAiCache();

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
    this.saveLocalAiCache();
  }

  saveLocalSettings(syncBackend = true) {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('aetherscope_settings', JSON.stringify(this.settings));
      }
    } catch {
      // ignore storage quota errors
    }
    if (syncBackend && typeof window !== 'undefined') {
      this.syncSettingsToBackend();
    }
  }

  private _syncTimer: any = null;
  syncSettingsToBackend() {
    if (this._syncTimer) clearTimeout(this._syncTimer);
    this._syncTimer = setTimeout(async () => {
      try {
        await api.saveSettings({
          exclusions: this.settings.exclusions,
          active_cve_rules: this.settings.activeCveRules.length > 0 ? this.settings.activeCveRules : undefined,
          ignored_cwes: this.settings.ignoredCwes,
          show_alerts: this.settings.showAlerts,
          show_cwe_bubbles: this.settings.showCweBubbles,
          show_cwe_titles: this.settings.showCweTitles,
          show_folder_titles: this.settings.showFolderTitles,
          show_file_titles: this.settings.showFileTitles,
          ui_settings: this.settings as any,
        });
      } catch {
        // standalone offline mode
      }
    }, 250);
  }

  toggleAlerts(): boolean {
    this.settings.showAlerts = !this.settings.showAlerts;
    this.saveLocalSettings();
    this.filterVersion += 1;
    return this.settings.showAlerts;
  }

  toggleCweBubbles(): boolean {
    this.settings.showCweBubbles = !this.settings.showCweBubbles;
    this.saveLocalSettings();
    this.filterVersion += 1;
    return this.settings.showCweBubbles;
  }

  toggleCweTitles(): boolean {
    this.settings.showCweTitles = !this.settings.showCweTitles;
    this.saveLocalSettings();
    this.filterVersion += 1;
    return this.settings.showCweTitles;
  }

  toggleFolderTitles(): boolean {
    this.settings.showFolderTitles = !this.settings.showFolderTitles;
    this.settings.showFolderBadges = this.settings.showFolderTitles;
    this.saveLocalSettings();
    this.filterVersion += 1;
    return this.settings.showFolderTitles;
  }

  toggleFolderMembranes(): boolean {
    this.settings.showFolderMembranes = !this.settings.showFolderMembranes;
    this.saveLocalSettings();
    this.filterVersion += 1;
    if (this.engine) {
      this.engine.handleResize();
    }
    return this.settings.showFolderMembranes;
  }

  toggleFileTitles(): boolean {
    this.settings.showFileTitles = !this.settings.showFileTitles;
    this.saveLocalSettings();
    this.filterVersion += 1;
    return this.settings.showFileTitles;
  }

  get isLowMemoryMode(): boolean {
    return Boolean(this.settings.lowMemoryMode || (this.graph.nodes && this.graph.nodes.length > 2500));
  }

  /**
   * Index d'adjacence nœud -> positions d'arêtes, construit une seule fois par graphe.
   * Remplace les balayages O(E) (250k arêtes) faits à chaque frame / survol.
   * Champ volontairement non réactif (pas de proxy Svelte sur 500k entrées).
   */
  edgeIndex: Map<string, number[]> = new Map();

  private buildEdgeIndex(edges: AffiliationEdge[]) {
    const idx = new Map<string, number[]>();
    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      let a = idx.get(e.source);
      if (!a) {
        a = [];
        idx.set(e.source, a);
      }
      a.push(i);
      if (e.target !== e.source) {
        let b = idx.get(e.target);
        if (!b) {
          b = [];
          idx.set(e.target, b);
        }
        b.push(i);
      }
    }
    this.edgeIndex = idx;
  }

  /** Arêtes incidentes à un nœud en O(degré) au lieu de O(E). */
  incidentEdges(id: string | null | undefined): AffiliationEdge[] {
    if (!id) return [];
    const positions = this.edgeIndex.get(id);
    if (!positions || positions.length === 0) return [];
    const edges = this.graph.edges;
    const out: AffiliationEdge[] = new Array(positions.length);
    for (let i = 0; i < positions.length; i++) out[i] = edges[positions[i]];
    return out;
  }

  toggleLowMemoryMode(): boolean {
    this.settings.lowMemoryMode = !this.settings.lowMemoryMode;
    this.saveLocalSettings();
    this.filterVersion += 1;
    if (this.engine) {
      this.engine.handleResize();
    }
    return this.settings.lowMemoryMode;
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
    if (typeof window !== 'undefined' && window.innerWidth < 940) {
      this.isInspectorOpen = false;
    }
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
  setGraph(gIn: AetherGraph, isIncremental = false) {
    const g = decodeCompactGraph(gIn);
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

    const isHuge = rawNodes.length > 2500 || this.settings.lowMemoryMode;

    const normalizedNodes = rawNodes.map((rawNode) => {
      const meta = rawNode.metadata || {};
      const rawM = (rawNode.methods && rawNode.methods.length > 0) ? rawNode.methods : meta.methods;
      const methods = (rawM && rawM.length > 0)
        ? rawM.map((m) => ({
            ...m,
            signature:
              m.signature ||
              `${m.is_async ? 'async ' : ''}${m.name}(${m.args || ''})${m.returns ? ` -> ${m.returns}` : ''}`,
            visibility: m.visibility || '+',
            line: m.line ?? rawNode.line_number ?? 1,
          }))
        : EMPTY_METHODS;

      const rawA = (rawNode.attributes && rawNode.attributes.length > 0) ? rawNode.attributes : meta.attributes;
      const attributes = (rawA && rawA.length > 0)
        ? rawA.map((a) => ({
            ...a,
            attr_type: a.attr_type || a.type || 'any',
            visibility: a.visibility || '+',
          }))
        : EMPTY_ATTRIBUTES;

      const rawAnomalies =
        rawNode.anomalies && rawNode.anomalies.length > 0 ? rawNode.anomalies : meta.cve_anomalies;
      let anomalies = EMPTY_ANOMALIES;
      if (rawAnomalies && rawAnomalies.length > 0) {
        anomalies = rawAnomalies.map((a) => {
          const isMax = isLinesExceededAnomaly(a);
          return {
            ...a,
            cve_id: isMax ? 'CONTRACT / ARCH-BUDGET-EXCEEDED' : a.cve_id || a.cwe_class || 'CWE',
            cwe_class: isMax ? 'CONTRACT_BUDGET' : a.cwe_class || a.cve_id || 'CWE',
            title: isMax ? 'Dépassement Budget Lignes' : a.title || a.rule_id || a.cve_id || 'Security Alert',
            description: a.description || a.message || '',
          };
        });
      } else if (meta.violations && meta.violations.length > 0) {
        anomalies = meta.violations.map((msg) => {
          const isMaxLines =
            msg.includes('RULE_MAX_LINES') ||
            msg.includes('ARCH-BUDGET-EXCEEDED') ||
            msg.includes('CONTRACT') ||
            msg.includes('maximum line limit') ||
            msg.includes('BUDGET LIGNES');
          return {
            rule_id: isMaxLines ? 'RULE_MAX_LINES' : 'SAST-VIOLATION',
            cve_id: isMaxLines ? 'CONTRACT / ARCH-BUDGET-EXCEEDED' : 'CWE-SAST',
            cwe_class: isMaxLines ? 'CONTRACT_BUDGET' : 'CWE-SAST',
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

      const prelimAlertKind = getNodeAlertKind({
        ...rawNode,
        loc,
        anomalies,
        metadata: meta,
      });
      const isPureLinesWarn = prelimAlertKind === 'lines_exceeded';
      const effectiveHasSec = isPureLinesWarn ? false : Boolean(rawNode.has_security_violation);

      // Heap Optimization: Prune excessive metadata strings on massive graphs (>2500 nodes)
      let docstring = rawNode.docstring || '';
      if (isHuge && docstring.length > 240) {
        docstring = docstring.slice(0, 240) + '...';
      }
      if (isHuge && meta.raw_content && !isText) {
        delete meta.raw_content;
      }

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
          if (secAnomCount > prevSecAnomCount || Boolean(effectiveHasSec && !prev.has_security_violation)) {
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
          const isViolation =
            (match.has_security_violation || match.ears_violation || effectiveHasSec) && !isPureLinesWarn;
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
        has_security_violation: effectiveHasSec,
        docstring,
        x: posX,
        y: posY,
        birth_time: birthTime,
        git_status: nodeGitStatus || 'clean',
        edit_kind: editKind,
        last_edit_ts: lastEditTs,
        folder,
        cluster_id: rawNode.cluster_id || getArchitecturalModule(folder),
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

    if (g && Array.isArray(g.nodes)) {
      g.nodes.length = 0; // Free raw JSON objects from memory
    }

    this.nodeById.clear();
    for (let i = 0; i < normalizedNodes.length; i++) {
      const n = normalizedNodes[i];
      this.nodeById.set(n.id, n);
    }

    const normalizedEdges = Array.isArray(g?.edges) ? g.edges : [];
    this.buildEdgeIndex(normalizedEdges);

    this.graph = {
      ...g,
      nodes: normalizedNodes,
      edges: normalizedEdges,
      clusters: g?.clusters || {},
    };
    this.syncTelemetryCoordinates();
    if (normalizedNodes.length > 2500 && !incremental) {
      this.lodLevel = 1;
      this.settings.lowMemoryMode = true;
    }
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
          const isLines = getNodeAlertKind(n) === 'lines_exceeded';
          const isViolation =
            (match.has_security_violation || match.ears_violation || Boolean(n.has_security_violation)) && !isLines;
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
      if (typeof window !== 'undefined' && window.innerWidth < 940) {
        this.isDocPanelOpen = false;
      }
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
      if (typeof window !== 'undefined' && window.innerWidth < 940) {
        this.isInspectorOpen = false;
      }
    } else {
      if (typeof window !== 'undefined' && window.innerWidth < 940) {
        this.isDocPanelOpen = false;
      }
      if (this.docMode !== 'system') {
        this.docMode = 'folder';
      }
    }
  }

  clearSelection() {
    this.activeSymbol = null;
    this.selectedFolder = null;
  }

  toggleInspector() {
    this.isInspectorOpen = !this.isInspectorOpen;
    if (this.isInspectorOpen && typeof window !== 'undefined' && window.innerWidth < 940) {
      this.isDocPanelOpen = false;
    }
  }

  toggleDocPanel() {
    if (!this.isDocPanelOpen) {
      this.docMode = this.activeSymbol ? 'symbol' : this.selectedFolder ? 'folder' : 'library';
      if (typeof window !== 'undefined' && window.innerWidth < 940) {
        this.isInspectorOpen = false;
      }
    }
    this.isDocPanelOpen = !this.isDocPanelOpen;
  }
}

export const cockpitState = new CockpitState();
