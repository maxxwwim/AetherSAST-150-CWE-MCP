// =========================================================================
// AETHERSCOPE V2 — HIGH-PERFORMANCE WEBGL 2 ENGINE (engine.ts)
// 120 FPS Celestial Spatial Graph Engine, Cellular Membranes & Laser Optics
// =========================================================================

import {
  INSTANCE_FLOATS,
  initShaderPipeline,
  initBackdropPipeline,
  swapNodeShader,
  swapBackdropShader,
  type ShaderPipeline,
  type BackdropPipeline
} from './shaders';
import {
  resolveThemeColorsArray,
  resolveUniformParamsVec4,
  type VisualPluginPack,
  type MembraneStyle,
  type EdgeStyle
} from './visualPlugins';
import { PhysicsController, type FolderClusterEntry } from './physics';
import {
  getLayerRgba,
  getFolderColor,
  formatFolderLabel,
  applyPaletteOverride,
  SEVERITY_COLORS,
  CONTRACT_WARNING_COLOR,
  type RgbaColor
} from './palette';
import { normalizeEdgeRelation, getNodeAlertKind, isLinesExceededAnomaly, formatCweShortId, type CockpitState } from '../state/graphState.svelte';
import { playSpatialTone } from '../lib/sound';
import type { SymbolBubble, CveAnomalyRecord } from '../types/graph';

// Precomputed 12-sector trigonometric tables for C1-continuous cellular membranes
const _COS12 = new Float32Array(12);
const _SIN12 = new Float32Array(12);
for (let i = 0; i < 12; i++) {
  const a = (i / 12) * Math.PI * 2;
  _COS12[i] = Math.cos(a);
  _SIN12[i] = Math.sin(a);
}

// Infinite Galaxy Dezoom & Cellular Precision Zoom Bounds
export const MIN_GALAXY_ZOOM = 0.0001;
export const MAX_GALAXY_ZOOM = 12.0;

export class AetherEngine {
  private gl: WebGL2RenderingContext;
  private lineCtx: CanvasRenderingContext2D;
  private pipeline: ShaderPipeline;
  private backdropPipeline: BackdropPipeline;
  private physics: PhysicsController;

  private animationFrameId: number | null = null;
  private isDestroyed = false;

  // Logical CSS viewport dimensions (independent of devicePixelRatio)
  public logicalWidth = 800;
  public logicalHeight = 600;
  private dpr = 1;

  // Pointer tracking & multi-touch pinch
  private activePointers = new Map<number, { x: number; y: number }>();
  private initialPinchDist = 0;
  private initialPinchZoom = 1;
  private initialPinchCenter = { x: 0, y: 0 };
  private initialPinchFocalWorld = { x: 0, y: 0 };
  private resizeObserver: ResizeObserver | null = null;
  private dprMediaQuery: MediaQueryList | null = null;
  private dprListener: (() => void) | null = null;
  private pointerMoveHandler: ((e: PointerEvent) => void) | null = null;
  private pointerUpHandler: ((e: PointerEvent) => void) | null = null;

  // Camera & viewport
  public camera = {
    x: 0,
    y: 0,
    zoom: 0.65,
    targetX: 0,
    targetY: 0,
    targetZoom: 0.65
  };
  private time = 0;

  // FPS telemetry
  private fpsFrames = 0;
  private fpsLastTime = performance.now();
  public onFps?: (fps: number) => void;

  // Instance Buffer management
  private instanceData: Float32Array = new Float32Array(0);
  private nodeMap = new Map<string, SymbolBubble>();
  private clusters = new Map<string, FolderClusterEntry>();
  private activeNeighbors = new Set<string>();
  private lastVisionMode = 'standard';
  private lastActiveSymbolId: string | null = null;
  private lastLodLevel = 1;
  private lastActiveLayout: string = 'Z-2';
  private lastFitTick = 0;
  private lastFocusTick = 0;
  private lastSnapshotTick = 0;
  private lastFilterVersion = 0;
  private hoveredNodeId: string | null = null;
  private hoveredFolder: string | null = null;
  private selectedFolder: string | null = null;
  private hasInitialCameraFit = false;
  private folderPillBounds: { folder: string; x: number; y: number; w: number; h: number }[] = [];
  private labelBounds: { x: number; y: number; w: number; h: number }[] = [];
  private anomalyNodeIndices: number[] = [];
  private fileAnomaliesByPath = new Map<string, CveAnomalyRecord[]>();
  private agentSmoothPositions = new Map<string, { x: number; y: number }>();

  // Visual Plugin Runtime State (M1 + M2)
  private themeColors: Float32Array = resolveThemeColorsArray();
  private uniformParams: [number, number, number, number] = [1.0, 1.0, 1.0, 1.0];
  private membraneStyle: MembraneStyle = 'organic_12lobe';
  private edgeStyle: EdgeStyle = 'bezier';
  private edgePulseSpeed = 1.0;
  private membraneBreathAmp = 1.0;
  private slowShaderMs = 0;
  private contextLostHandler: ((e: Event) => void) | null = null;

  // Mouse interaction state
  private isDragging = false;
  private isDraggingNode = false;
  private draggedNodeId: string | null = null;
  private dragStartX = 0;
  private dragStartY = 0;
  private pointerDownX = 0;
  private pointerDownY = 0;
  private pointerDownHitId: string | null = null;
  private pointerDownOnCanvas = false;
  private resizeHandler = () => this.handleResize();

  constructor(
    private canvas: HTMLCanvasElement,
    private lineCanvas: HTMLCanvasElement,
    private state: CockpitState
  ) {
    const gl = canvas.getContext('webgl2', {
      alpha: false,
      antialias: true,
      powerPreference: 'high-performance',
      preserveDrawingBuffer: false
    });
    if (!gl) throw new Error('WebGL 2 not supported by browser hardware');
    this.gl = gl;

    const lineCtx = lineCanvas.getContext('2d', { alpha: true });
    if (!lineCtx) throw new Error('Failed to get 2D overlay context');
    this.lineCtx = lineCtx;

    this.backdropPipeline = initBackdropPipeline(this.gl);
    this.pipeline = initShaderPipeline(this.gl);
    this.physics = new PhysicsController();

    this.contextLostHandler = (e: Event) => {
      e.preventDefault();
      this.state.visualPluginError = 'Contexte WebGL interrompu par le GPU — repli de sécurité activé.';
    };
    this.canvas.addEventListener('webglcontextlost', this.contextLostHandler);

    this.setupPhysicsListener();
    this.handleResize();
    this.setupMouseEvents();

    this.state.engine = this;

    // Apply currently selected visual plugin pack immediately if non-default
    const initialPack = this.state.activeVisualPluginPack;
    if (initialPack && initialPack.id !== 'obsidian-nebula') {
      this.applyVisualPlugin(initialPack);
    }

    if (this.state.graph.nodes.length > 0) {
      this.syncGraphToEngine();
    }
  }

  /**
   * Applies a VisualPluginPack atomically (palette, overlay geometry, uniforms & GLSL hot-swap).
   * If a custom GLSL shader fails compilation, the previous WebGLProgram remains intact.
   */
  public applyVisualPlugin(pack: VisualPluginPack | null): { ok: boolean; error?: string } {
    this.slowShaderMs = 0;
    const isDefault = !pack || pack.id === 'obsidian-nebula';

    const bgRes = swapBackdropShader(this.gl, this.backdropPipeline, isDefault ? null : pack?.backdrop_glsl);
    if (!bgRes.ok) {
      return { ok: false, error: `backdrop.glsl : ${bgRes.error}` };
    }
    const nodeRes = swapNodeShader(this.gl, this.pipeline, isDefault ? null : pack?.node_sdf_glsl);
    if (!nodeRes.ok) {
      return { ok: false, error: `node_sdf.glsl : ${nodeRes.error}` };
    }

    this.themeColors = resolveThemeColorsArray(pack?.palette?.background);
    this.uniformParams = resolveUniformParamsVec4(pack?.uniforms);
    applyPaletteOverride(isDefault ? null : pack?.palette);

    const mStyle = pack?.overlay?.membrane_style;
    this.membraneStyle =
      mStyle === 'hex_hull' || mStyle === 'rect_blueprint' || mStyle === 'none' || mStyle === 'organic_12lobe'
        ? mStyle
        : 'organic_12lobe';

    const eStyle = pack?.overlay?.edge_style;
    this.edgeStyle =
      eStyle === 'straight' || eStyle === 'orthogonal_pcb' || eStyle === 'bezier'
        ? eStyle
        : 'bezier';

    this.edgePulseSpeed =
      typeof pack?.overlay?.edge_pulse_speed === 'number' && Number.isFinite(pack.overlay.edge_pulse_speed)
        ? Math.max(0.1, Math.min(5.0, pack.overlay.edge_pulse_speed))
        : 1.0;

    this.membraneBreathAmp =
      typeof pack?.overlay?.membrane_breath_amp === 'number' && Number.isFinite(pack.overlay.membrane_breath_amp)
        ? Math.max(0.0, Math.min(2.5, pack.overlay.membrane_breath_amp))
        : 1.0;

    this.refreshVisionColors(true);
    return { ok: true };
  }

  private setupPhysicsListener() {
    this.physics.onUpdate = (positions: Float32Array, rawClusters?: Record<string, any>) => {
      const nodes = this.state.graph.nodes;
      const count = Math.min(nodes.length, Math.floor(positions.length / 2));

      for (let i = 0; i < count; i++) {
        nodes[i].x = positions[i * 2];
        nodes[i].y = positions[i * 2 + 1];

        if (this.instanceData.length >= (i + 1) * INSTANCE_FLOATS) {
          this.instanceData[i * INSTANCE_FLOATS + 0] = nodes[i].x;
          this.instanceData[i * INSTANCE_FLOATS + 1] = nodes[i].y;
        }
      }

      if (rawClusters) {
        for (const k in rawClusters) {
          const cl = rawClusters[k];
          let entry = this.clusters.get(k);
          if (!entry) {
            entry = {
              cx: cl.cx,
              cy: cl.cy,
              sumX: cl.sumX,
              sumY: cl.sumY,
              count: cl.count,
              computedRadius: cl.computedRadius,
              naturalRadius: cl.naturalRadius,
              lobeProfile: new Float32Array(cl.lobeProfile || 12)
            };
            this.clusters.set(k, entry);
          } else {
            // Keep count synced, but preserve live 60/120 FPS smoothed geometry from syncLiveClusterEnvelopes
            entry.count = cl.count;
          }
        }
      }

      this.uploadInstanceSubData();
    };
  }

  private uploadInstanceSubData() {
    if (this.instanceData.length === 0) return;
    const { gl, pipeline } = this;
    gl.bindBuffer(gl.ARRAY_BUFFER, pipeline.instanceVbo);
    gl.bufferSubData(gl.ARRAY_BUFFER, 0, this.instanceData);
    gl.bindBuffer(gl.ARRAY_BUFFER, null);
  }

  private classifyNode(n: SymbolBubble): { shaderType: number; baseRadius: number; isFunction: boolean; isClass: boolean; isFile: boolean } {
    const kind = String(n.kind || n.symbol_type || '').toLowerCase();
    const isFunc =
      kind === 'function' ||
      kind === 'method' ||
      n.stereotype === '«Function»' ||
      n.stereotype === '«Method»';
    const isFile = Boolean(n.is_file || kind === 'file' || n.stereotype === '«File»');
    const isClass = Boolean(n.is_class || kind === 'class' || kind === 'struct' || kind === 'interface' || kind === 'trait' || n.stereotype === '«Class»');
    const isForm = Boolean(n.is_form || kind === 'endpoint' || n.stereotype === '«Endpoint»' || n.stereotype === '«Form»');

    if (isFunc) return { shaderType: 0.0, baseRadius: 4.6, isFunction: true, isClass: false, isFile: false };
    if (isFile) return { shaderType: 1.0, baseRadius: 13.0, isFunction: false, isClass: false, isFile: true };
    if (isClass) return { shaderType: 2.0, baseRadius: 14.5, isFunction: false, isClass: true, isFile: false };
    if (isForm) return { shaderType: 3.0, baseRadius: 12.0, isFunction: false, isClass: false, isFile: false };
    return { shaderType: 1.0, baseRadius: 9.5, isFunction: false, isClass: false, isFile: false };
  }

  private seedInitialClusters(nodes: SymbolBubble[]) {
    const buckets = new Map<string, SymbolBubble[]>();
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const folder = n.cluster_id || n.folder || 'root';
      let list = buckets.get(folder);
      if (!list) {
        list = [];
        buckets.set(folder, list);
      }
      list.push(n);
    }

    buckets.forEach((list, folder) => {
      let sumX = 0, sumY = 0;
      for (const n of list) {
        sumX += n.x || 0;
        sumY += n.y || 0;
      }
      const cx = sumX / list.length;
      const cy = sumY / list.length;
      let maxDist = 0;
      const sectorDist = new Float32Array(12);
      for (const n of list) {
        const dx = (n.x || 0) - cx;
        const dy = (n.y || 0) - cy;
        const d = Math.hypot(dx, dy);
        if (d > maxDist) maxDist = d;
        const angle = (Math.atan2(dy, dx) + Math.PI * 2) % (Math.PI * 2);
        const sec = Math.floor((angle / (Math.PI * 2)) * 12) % 12;
        if (d > sectorDist[sec]) sectorDist[sec] = d;
      }
      const baseR = Math.max(72, Math.sqrt(list.length) * 38, maxDist + 42);
      const lobeProfile = new Float32Array(12);
      for (let i = 0; i < 12; i++) {
        lobeProfile[i] = Math.max(0.86, Math.min(1.22, sectorDist[i] > 0 ? (sectorDist[i] + 44) / baseR : 0.94));
      }
      this.clusters.set(folder, {
        cx,
        cy,
        sumX,
        sumY,
        count: list.length,
        computedRadius: baseR,
        naturalRadius: baseR,
        lobeProfile
      });
    });
  }

  private getNodeGitShaderVal(n: SymbolBubble): number {
    const ek = n.edit_kind;
    if (ek === 'violation' || n.git_status === 'violation') return 3.0;
    if (ek === 'new_folder' || n.git_status === 'new_folder') return 5.0;
    if (ek === 'new_file' || n.git_status === 'untracked') return 2.0;
    if (ek === 'text' || n.git_status === 'text') return 4.0;
    if (ek === 'modif' || n.git_status === 'modified') return 1.0;
    return 0.0;
  }

  public updateGitAndEditHighlights() {
    const nodes = this.state.graph.nodes;
    if (!nodes || this.instanceData.length < nodes.length * INSTANCE_FLOATS) return;

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const offset = i * INSTANCE_FLOATS;
      if (typeof n.birth_time === 'number') {
        this.instanceData[offset + 8] = n.birth_time;
      }
      this.instanceData[offset + 9] = this.getNodeGitShaderVal(n);
    }

    this.refreshVisionColors(false);
    this.uploadInstanceSubData();
  }

  public syncGraphToEngine(resetCamera = false) {
    const nodes = this.state.graph.nodes;
    this.nodeMap.clear();
    this.clusters.clear();

    const floatCount = nodes.length * INSTANCE_FLOATS;
    if (this.instanceData.length !== floatCount) {
      this.instanceData = new Float32Array(floatCount);
    }

    const defaultBirthStamp = Math.max(0, performance.now() - 320);
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!Number.isFinite(n.x)) n.x = (Math.random() - 0.5) * 800;
      if (!Number.isFinite(n.y)) n.y = (Math.random() - 0.5) * 800;
      if (typeof n.birth_time !== 'number') {
        n.birth_time = resetCamera || !this.hasInitialCameraFit ? Math.max(0, performance.now() - 16) : defaultBirthStamp;
      }
      this.nodeMap.set(n.id, n);

      const offset = i * INSTANCE_FLOATS;
      const { shaderType, baseRadius } = this.classifyNode(n);

      this.instanceData[offset + 0] = n.x;
      this.instanceData[offset + 1] = n.y;
      this.instanceData[offset + 2] = baseRadius;
      this.instanceData[offset + 7] = shaderType;
      this.instanceData[offset + 8] = n.birth_time;
      this.instanceData[offset + 9] = this.getNodeGitShaderVal(n);
      this.instanceData[offset + 10] = 0.0;
      this.instanceData[offset + 11] = 0.0;
    }

    this.rebuildAnomalyIndex(nodes);

    this.seedInitialClusters(nodes);
    this.refreshVisionColors(false);
    if (resetCamera || !this.hasInitialCameraFit) {
      this.hasInitialCameraFit = true;
      this.fitCameraToGraph(true);
    }

    const { gl, pipeline } = this;
    gl.bindBuffer(gl.ARRAY_BUFFER, pipeline.instanceVbo);
    gl.bufferData(gl.ARRAY_BUFFER, this.instanceData, gl.DYNAMIC_DRAW);
    gl.bindBuffer(gl.ARRAY_BUFFER, null);

    this.physics.sendGraph(nodes, this.state.graph.edges, this.state.lodLevel);
  }

  public fitCameraToGraph(immediate = false) {
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return;

    let minX = Infinity, maxX = -Infinity;
    let minY = Infinity, maxY = -Infinity;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) continue;
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    }
    if (!Number.isFinite(minX)) return;

    this.clusters.forEach((cl) => {
      const r = cl.computedRadius || 100;
      if (cl.cx - r < minX) minX = cl.cx - r;
      if (cl.cx + r > maxX) maxX = cl.cx + r;
      if (cl.cy - r < minY) minY = cl.cy - r;
      if (cl.cy + r > maxY) maxY = cl.cy + r;
    });

    const spanX = Math.max(400, maxX - minX);
    const spanY = Math.max(400, maxY - minY);
    const fitZoom = Math.max(
      MIN_GALAXY_ZOOM,
      Math.min(1.15, Math.min(this.logicalWidth / (spanX + 240), this.logicalHeight / (spanY + 240)))
    );

    this.camera.targetX = (minX + maxX) * 0.5;
    this.camera.targetY = (minY + maxY) * 0.5;
    this.camera.targetZoom = fitZoom;
    if (immediate) {
      this.camera.x = this.camera.targetX;
      this.camera.y = this.camera.targetY;
      this.camera.zoom = this.camera.targetZoom;
    }
  }

  private isAnomalyIgnored = (ruleId?: string, cveId?: string) => this.state.isCweIgnored(ruleId, cveId);

  private rebuildAnomalyIndex(nodes: SymbolBubble[]) {
    this.anomalyNodeIndices = [];
    this.fileAnomaliesByPath.clear();

    // First collect real structured anomalies from child symbols by file_path
    const byFile = new Map<string, CveAnomalyRecord[]>();
    const seenByFile = new Map<string, Set<string>>();
    const addToFile = (fp: string | undefined, list: CveAnomalyRecord[] | undefined) => {
      if (!fp || !list || list.length === 0) return;
      const keyPath = fp.replace(/\\/g, '/').toLowerCase();
      let arr = byFile.get(keyPath);
      let seen = seenByFile.get(keyPath);
      if (!arr) {
        arr = [];
        seen = new Set<string>();
        byFile.set(keyPath, arr);
        seenByFile.set(keyPath, seen);
      }
      for (const a of list) {
        if (this.isAnomalyIgnored(a.rule_id, a.cve_id)) continue;
        const k = `${a.line_number || 0}|${String(a.rule_id || a.cve_id || '').toUpperCase()}`;
        if (!seen!.has(k)) {
          seen!.add(k);
          arr.push(a);
        }
      }
    };

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!n.is_file) addToFile(n.file_path, n.anomalies);
    }
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.is_file) addToFile(n.file_path, n.anomalies);
    }
    this.fileAnomaliesByPath = byFile;

    for (let i = 0; i < nodes.length; i++) {
      if (getNodeAlertKind(nodes[i], this.isAnomalyIgnored) !== 'none') {
        this.anomalyNodeIndices.push(i);
      }
    }
  }

  private getEffectiveAnomalies(n: SymbolBubble): CveAnomalyRecord[] {
    if (n.is_file && n.file_path) {
      const keyPath = n.file_path.replace(/\\/g, '/').toLowerCase();
      const aggregated = this.fileAnomaliesByPath.get(keyPath);
      if (aggregated && aggregated.length > 0) return aggregated;
    }
    return (n.anomalies || []).filter((a) => !this.isAnomalyIgnored(a.rule_id, a.cve_id));
  }

  public refreshVisionColors(upload = true) {
    const nodes = this.state.graph.nodes;
    if (!nodes || this.instanceData.length < nodes.length * INSTANCE_FLOATS) return;

    const filterChanged = this.lastFilterVersion !== this.state.filterVersion;
    const mode = this.state.visionMode;
    const activeId = this.state.activeSymbol?.id || null;
    const lod = this.state.lodLevel;
    const disabledLayers = this.state.disabledLayers;
    this.lastVisionMode = mode;
    this.lastActiveSymbolId = activeId;
    this.lastLodLevel = lod;
    this.lastFilterVersion = this.state.filterVersion;

    if (filterChanged) {
      this.rebuildAnomalyIndex(nodes);
    }

    this.activeNeighbors.clear();
    if (mode === 'xray' && activeId) {
      this.activeNeighbors.add(activeId);
      const inc = this.state.incidentEdges(activeId);
      for (let i = 0; i < inc.length; i++) {
        const e = inc[i];
        if (e.source === activeId) this.activeNeighbors.add(e.target);
        if (e.target === activeId) this.activeNeighbors.add(e.source);
      }
    }

    const isHugeProject = nodes.length > 2500;
    const showAlerts = this.state.settings.showAlerts;
    const showCweBubbles = this.state.settings.showCweBubbles;

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const offset = i * INSTANCE_FLOATS;
      const { baseRadius, isFunction } = this.classifyNode(n);
      const folder = n.cluster_id || n.folder || 'root';
      let col: RgbaColor = lod <= 2 ? getFolderColor(folder) : getLayerRgba(n.layer);
      let alpha = 1.0;
      let r = baseRadius;

      const isFocus = n.id === activeId || n.id === this.hoveredNodeId;
      if (n.id === activeId) r *= 1.65;
      else if (n.id === this.hoveredNodeId) r *= 1.35;

      const alertKind = getNodeAlertKind(n, this.isAnomalyIgnored);
      const isSecurityAlert = alertKind === 'security';
      const isLinesAlert = alertKind === 'lines_exceeded';

      // --- LoD BUBBLE FILTERING & SMART COLLAPSE ---
      if (lod === 1 && isFunction && !isSecurityAlert && !isFocus) {
        r = 0.0;
        alpha = 0.0;
      } else if (lod === 2 && isFunction && !isSecurityAlert && !isFocus) {
        const cc = n.cyclomatic_complexity || 1;
        if (isHugeProject && cc < 5) {
          r = 0.0;
          alpha = 0.0;
        }
      }

      if (mode === 'heatmap') {
        const cc = n.cyclomatic_complexity || 1;
        if (cc >= 15) col = SEVERITY_COLORS.CRITICAL;
        else if (cc >= 8) col = SEVERITY_COLORS.HIGH;
        else if (cc >= 4) col = SEVERITY_COLORS.MEDIUM;
        else col = SEVERITY_COLORS.LOW;
      } else if (mode === 'deadcode') {
        const isOrphan = n.is_orphan || (n.in_degree === 0 && n.out_degree === 0);
        if (isOrphan) {
          col = SEVERITY_COLORS.CRITICAL;
          r *= 1.35;
        } else {
          alpha = 0.08;
          r *= 0.55;
        }
      } else if (mode === 'xray' && activeId) {
        if (!this.activeNeighbors.has(n.id)) {
          alpha = 0.07;
          r *= 0.55;
        } else if (n.id === activeId) {
          col = { r: 1.0, g: 1.0, b: 1.0, a: 1.0 };
        }
      }

      if (!showCweBubbles && isSecurityAlert) {
        alpha = 0.0;
        r = 0.0;
      } else if (showAlerts) {
        if (isSecurityAlert && mode === 'standard') {
          const eff = this.getEffectiveAnomalies(n).filter((a) => !isLinesExceededAnomaly(a));
          const hasCritical = eff.some((a) => String(a.severity || '').toUpperCase() === 'CRITICAL');
          const hasHigh = eff.some((a) => String(a.severity || '').toUpperCase() === 'HIGH');
          col = hasCritical ? SEVERITY_COLORS.CRITICAL : hasHigh ? SEVERITY_COLORS.HIGH : SEVERITY_COLORS.CRITICAL;
          r *= n.is_file ? 1.18 : 1.12;
        } else if (isLinesAlert && mode === 'standard') {
          col = CONTRACT_WARNING_COLOR;
          r *= 1.12;
        }
      }

      if (disabledLayers[n.layer || 'utility'] || this.state.disabledModules[folder]) {
        alpha = 0.035;
        r *= 0.42;
      }

      let gitStatusVal = this.getNodeGitShaderVal(n);
      if (gitStatusVal === 3.0 && (!showAlerts || !showCweBubbles)) {
        gitStatusVal = 0.0;
      }

      // Normalized GPU plugin metrics: metric0 = complexity/degree [0..1], metric1 = security/focus heat [0..1]
      const deg = (n.in_degree || 0) + (n.out_degree || 0);
      const cc = n.cyclomatic_complexity || 1;
      const metric0 = Math.max(0.0, Math.min(1.0, Math.max(cc / 24.0, deg / 28.0)));
      const metric1 = isSecurityAlert ? 1.0 : isFocus ? 0.85 : isLinesAlert ? 0.5 : 0.0;

      this.instanceData[offset + 2] = r;
      this.instanceData[offset + 3] = col.r;
      this.instanceData[offset + 4] = col.g;
      this.instanceData[offset + 5] = col.b;
      this.instanceData[offset + 6] = alpha;
      this.instanceData[offset + 9] = gitStatusVal;
      this.instanceData[offset + 10] = metric0;
      this.instanceData[offset + 11] = metric1;
    }

    if (upload) {
      this.uploadInstanceSubData();
    }
  }

  public handleResize() {
    this.dpr = this.state.isLowMemoryMode ? 1 : Math.min(window.devicePixelRatio || 1, 2);
    const rect = this.canvas.getBoundingClientRect();
    this.logicalWidth = Math.max(1, rect.width || this.canvas.clientWidth || window.innerWidth);
    this.logicalHeight = Math.max(1, rect.height || this.canvas.clientHeight || (window.innerHeight - 78));

    const newW = Math.floor(this.logicalWidth * this.dpr);
    const newH = Math.floor(this.logicalHeight * this.dpr);

    if (this.canvas.width !== newW || this.canvas.height !== newH) {
      this.canvas.width = newW;
      this.canvas.height = newH;
      this.gl.viewport(0, 0, newW, newH);
    }

    if (this.lineCanvas.width !== newW || this.lineCanvas.height !== newH) {
      this.lineCanvas.width = newW;
      this.lineCanvas.height = newH;
      this.lineCtx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    }
  }

  public zoomAtScreenPoint(factor: number, sx: number, sy: number) {
    const clampedZoom = Math.max(MIN_GALAXY_ZOOM, Math.min(MAX_GALAXY_ZOOM, this.camera.targetZoom * factor));
    const focalWorld = this.screenToWorld(sx, sy);
    this.camera.targetZoom = clampedZoom;
    this.camera.targetX = focalWorld.x - (sx - this.logicalWidth / 2) / clampedZoom;
    this.camera.targetY = focalWorld.y - (sy - this.logicalHeight / 2) / clampedZoom;
    this.physics.wake(60);
  }

  public zoomIn(factor = 1.28) {
    this.zoomAtScreenPoint(factor, this.logicalWidth / 2, this.logicalHeight / 2);
  }

  public zoomOut(factor = 0.78) {
    this.zoomAtScreenPoint(factor, this.logicalWidth / 2, this.logicalHeight / 2);
  }

  public resetZoom() {
    this.camera.targetZoom = 1.0;
    this.physics.wake(60);
  }

  private getCanvasLocalCoords(clientX: number, clientY: number) {
    const rect = this.canvas.getBoundingClientRect();
    return {
      sx: clientX - rect.left,
      sy: clientY - rect.top
    };
  }

  public screenToWorld(sx: number, sy: number) {
    return {
      x: this.camera.x + (sx - this.logicalWidth / 2) / this.camera.zoom,
      y: this.camera.y + (sy - this.logicalHeight / 2) / this.camera.zoom
    };
  }

  public worldToScreen(wx: number, wy: number) {
    return {
      x: (wx - this.camera.x) * this.camera.zoom + this.logicalWidth / 2,
      y: (wy - this.camera.y) * this.camera.zoom + this.logicalHeight / 2
    };
  }

  private getNodeScreenRadius(n: SymbolBubble, activeId: string | null): number {
    const zoom = this.camera.zoom;
    const zoomFactor = Math.max(0.85, Math.min(6.0, 1.0 / Math.sqrt(Math.max(MIN_GALAXY_ZOOM, Math.min(MAX_GALAXY_ZOOM, zoom)))));
    const { baseRadius, shaderType } = this.classifyNode(n);
    const scaleMult = n.id === activeId ? 1.65 : n.id === this.hoveredNodeId ? 1.35 : 1.0;
    const rawR = baseRadius * scaleMult * 2.85 * zoomFactor * zoom;
    return Math.max(shaderType > 0.5 ? 2.6 : 1.8, rawR);
  }

  private pickNode(sx: number, sy: number): SymbolBubble | null {
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return null;

    const activeId = this.state.activeSymbol?.id || null;
    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const isXray = this.state.visionMode === 'xray' && this.activeNeighbors.size > 0;

    let bestNode: SymbolBubble | null = null;
    let bestScore = Infinity;

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (disabledLayers[n.layer || 'utility']) continue;
      if (disabledModules[n.folder || n.cluster_id || 'root']) continue;
      if (!this.state.settings.showCweBubbles && getNodeAlertKind(n, this.isAnomalyIgnored) === 'security') continue;
      if (isXray && !this.activeNeighbors.has(n.id)) continue;

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -60 || p.x > this.logicalWidth + 60 || p.y < -60 || p.y > this.logicalHeight + 60) {
        continue;
      }

      const visualR = this.getNodeScreenRadius(n, activeId);
      const hitPx = Math.max(13, visualR + 8);
      const d = Math.hypot(p.x - sx, p.y - sy);
      if (d <= hitPx) {
        const priorityBias = n.id === activeId ? 0.65 : n.is_file || n.is_class ? 0.8 : 1.0;
        const score = d * priorityBias;
        if (score < bestScore) {
          bestScore = score;
          bestNode = n;
        }
      }
    }
    return bestNode;
  }

  public focusSymbol(symbolId: string) {
    const node = this.nodeMap.get(symbolId);
    if (!node) return;
    this.camera.targetX = node.x;
    this.camera.targetY = node.y;
    if (this.camera.targetZoom < 0.72) {
      this.camera.targetZoom = 0.85;
    }
    this.physics.wake(30);
  }

  private setupMouseEvents() {
    window.addEventListener('resize', this.resizeHandler);

    if (typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(() => this.handleResize());
      this.resizeObserver.observe(this.canvas);
      if (this.canvas.parentElement) {
        this.resizeObserver.observe(this.canvas.parentElement);
      }
    }

    const setupDprListener = () => {
      if (typeof window === 'undefined' || !window.matchMedia) return;
      this.dprMediaQuery = window.matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`);
      this.dprListener = () => {
        this.handleResize();
        setupDprListener();
      };
      this.dprMediaQuery.addEventListener('change', this.dprListener, { once: true });
    };
    setupDprListener();

    this.canvas.addEventListener('wheel', (e: WheelEvent) => {
      e.preventDefault();
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      const normalizedDelta = e.deltaMode === 1 ? e.deltaY * 24 : e.deltaMode === 2 ? e.deltaY * 400 : e.deltaY;
      const speed = e.shiftKey ? 0.0042 : 0.0022;
      const zoomFactor = Math.exp(-normalizedDelta * speed);
      this.zoomAtScreenPoint(zoomFactor, sx, sy);
    }, { passive: false });

    this.canvas.addEventListener('pointerdown', (e: PointerEvent) => {
      try {
        this.canvas.setPointerCapture?.(e.pointerId);
      } catch {
        // ignore
      }
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      this.activePointers.set(e.pointerId, { x: sx, y: sy });

      if (this.activePointers.size === 1) {
        if (e.button !== 0 && e.pointerType === 'mouse') return;
        this.dragStartX = sx;
        this.dragStartY = sy;
        this.pointerDownX = sx;
        this.pointerDownY = sy;
        this.pointerDownOnCanvas = true;
        const hit = this.pickNode(sx, sy);
        this.pointerDownHitId = hit ? hit.id : null;
      } else if (this.activePointers.size === 2) {
        if (this.isDraggingNode && this.draggedNodeId) {
          this.physics.dragEnd();
        }
        this.isDragging = false;
        this.isDraggingNode = false;
        this.draggedNodeId = null;
        this.pointerDownOnCanvas = false;
        this.pointerDownHitId = null;

        const pts = Array.from(this.activePointers.values());
        this.initialPinchDist = Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
        this.initialPinchZoom = this.camera.targetZoom;
        this.initialPinchCenter = { x: (pts[0].x + pts[1].x) / 2, y: (pts[0].y + pts[1].y) / 2 };
        this.initialPinchFocalWorld = this.screenToWorld(this.initialPinchCenter.x, this.initialPinchCenter.y);
      }
    });

    this.canvas.addEventListener('dblclick', (e: MouseEvent) => {
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      const hit = this.pickNode(sx, sy);
      if (hit) {
        this.selectedFolder = hit.folder || hit.cluster_id || null;
        this.state.selectSymbol(hit.id, true);
        this.refreshVisionColors(true);
        return;
      }
      const folder = this.findFolderAt(sx, sy);
      if (folder) {
        this.selectedFolder = folder;
        const cl = this.clusters.get(folder);
        if (cl) {
          this.camera.targetX = cl.cx;
          this.camera.targetY = cl.cy;
          if (this.camera.targetZoom < 0.55) this.camera.targetZoom = 0.65;
        }
        this.state.selectFolder(folder, true);
      }
    });

    this.pointerMoveHandler = (e: PointerEvent) => {
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      if (this.activePointers.has(e.pointerId)) {
        this.activePointers.set(e.pointerId, { x: sx, y: sy });
      }

      if (this.activePointers.size >= 2) {
        const pts = Array.from(this.activePointers.values());
        const currentDist = Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
        const currentCenter = { x: (pts[0].x + pts[1].x) / 2, y: (pts[0].y + pts[1].y) / 2 };

        if (this.initialPinchDist > 8 && currentDist > 8) {
          const scale = currentDist / this.initialPinchDist;
          const newTargetZoom = Math.max(MIN_GALAXY_ZOOM, Math.min(MAX_GALAXY_ZOOM, this.initialPinchZoom * scale));
          this.camera.targetZoom = newTargetZoom;

          const panDx = (currentCenter.x - this.initialPinchCenter.x) / newTargetZoom;
          const panDy = (currentCenter.y - this.initialPinchCenter.y) / newTargetZoom;

          this.camera.targetX = this.initialPinchFocalWorld.x - (this.initialPinchCenter.x - this.logicalWidth / 2) / newTargetZoom - panDx;
          this.camera.targetY = this.initialPinchFocalWorld.y - (this.initialPinchCenter.y - this.logicalHeight / 2) / newTargetZoom - panDy;
          this.physics.wake(30);
        }
        return;
      }

      if (this.pointerDownOnCanvas && !this.isDraggingNode && !this.isDragging) {
        if (Math.hypot(sx - this.pointerDownX, sy - this.pointerDownY) >= 6) {
          if (this.pointerDownHitId) {
            this.isDraggingNode = true;
            this.draggedNodeId = this.pointerDownHitId;
            const world = this.screenToWorld(sx, sy);
            this.physics.drag(this.pointerDownHitId, world.x, world.y);
          } else {
            this.isDragging = true;
          }
        }
      }

      if (this.isDraggingNode && this.draggedNodeId) {
        const world = this.screenToWorld(sx, sy);
        this.physics.drag(this.draggedNodeId, world.x, world.y);
        const node = this.nodeMap.get(this.draggedNodeId);
        if (node) {
          node.x = world.x;
          node.y = world.y;
        }
      } else if (this.isDragging) {
        const dx = (sx - this.dragStartX) / this.camera.zoom;
        const dy = (sy - this.dragStartY) / this.camera.zoom;
        this.camera.x -= dx;
        this.camera.y -= dy;
        this.camera.targetX = this.camera.x;
        this.camera.targetY = this.camera.y;
        this.dragStartX = sx;
        this.dragStartY = sy;
      } else if (e.target === this.canvas) {
        const hit = this.pickNode(sx, sy);
        const prevHov = this.hoveredNodeId;
        this.hoveredNodeId = hit ? hit.id : null;
        this.state.hoveredSymbol = hit;
        this.state.hoverScreenPos = { x: e.clientX, y: e.clientY };
        this.hoveredFolder = hit ? (hit.folder || hit.cluster_id || 'root') : this.findFolderAt(sx, sy);
        this.canvas.style.cursor = hit || this.hoveredFolder ? 'pointer' : 'grab';
        if (prevHov !== this.hoveredNodeId) {
          this.refreshVisionColors(true);
        }
      } else {
        if (this.hoveredNodeId !== null) {
          this.hoveredNodeId = null;
          this.state.hoveredSymbol = null;
          this.refreshVisionColors(true);
        }
      }
    };
    window.addEventListener('pointermove', this.pointerMoveHandler);

    this.canvas.addEventListener('pointerleave', () => {
      if (this.hoveredNodeId !== null || this.state.hoveredSymbol !== null) {
        this.hoveredNodeId = null;
        this.state.hoveredSymbol = null;
        this.refreshVisionColors(true);
      }
    });

    this.pointerUpHandler = (e: PointerEvent) => {
      try {
        if (this.canvas.hasPointerCapture?.(e.pointerId)) {
          this.canvas.releasePointerCapture?.(e.pointerId);
        }
      } catch {
        // ignore
      }
      this.activePointers.delete(e.pointerId);

      if (this.activePointers.size === 1) {
        const remaining = Array.from(this.activePointers.values())[0];
        this.dragStartX = remaining.x;
        this.dragStartY = remaining.y;
        this.pointerDownX = remaining.x;
        this.pointerDownY = remaining.y;
        this.isDragging = false;
        this.pointerDownOnCanvas = false;
      } else if (this.activePointers.size === 0) {
        this.initialPinchDist = 0;
      }

      if (!this.pointerDownOnCanvas && !this.isDraggingNode && !this.isDragging) return;
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      const wasDownOnCanvas = this.pointerDownOnCanvas;
      const downHitId = this.pointerDownHitId;

      if (this.isDraggingNode) {
        this.isDraggingNode = false;
        this.draggedNodeId = null;
        this.physics.dragEnd();
      }
      if (this.isDragging) {
        this.isDragging = false;
      }
      this.pointerDownOnCanvas = false;
      this.pointerDownHitId = null;

      const dist = Math.hypot(sx - this.pointerDownX, sy - this.pointerDownY);
      if (wasDownOnCanvas && dist < 7) {
        const hit = this.pickNode(sx, sy) || (downHitId ? this.nodeMap.get(downHitId) || null : null);
        if (hit) {
          this.selectedFolder = hit.folder || hit.cluster_id || null;
          this.state.selectSymbol(hit.id, false);
          const pan = (sx / Math.max(1, this.logicalWidth)) * 2 - 1;
          playSpatialTone(
            this.state.settings.soundEnabled,
            hit.has_security_violation || (hit.anomalies && hit.anomalies.length > 0) ? 'alert' : 'select',
            pan
          );
          this.refreshVisionColors(true);
        } else {
          const folder = this.findFolderAt(sx, sy);
          this.selectedFolder = folder;
          if (folder) {
            this.state.selectFolder(folder, false);
            const pan = (sx / Math.max(1, this.logicalWidth)) * 2 - 1;
            playSpatialTone(this.state.settings.soundEnabled, 'action', pan);
          } else {
            this.state.clearSelection();
          }
          this.refreshVisionColors(true);
        }
      }
    };

    window.addEventListener('pointerup', this.pointerUpHandler);
    window.addEventListener('pointercancel', this.pointerUpHandler);
  }

  private findFolderAt(sx: number, sy: number): string | null {
    for (let i = this.folderPillBounds.length - 1; i >= 0; i--) {
      const b = this.folderPillBounds[i];
      if (sx >= b.x && sx <= b.x + b.w && sy >= b.y && sy <= b.y + b.h) {
        return b.folder;
      }
    }
    const world = this.screenToWorld(sx, sy);
    let best: string | null = null;
    let bestR = Infinity;
    this.clusters.forEach((cl, folder) => {
      const r = cl.computedRadius || 100;
      const dist = Math.hypot(world.x - cl.cx, world.y - cl.cy);
      if (dist <= r && r < bestR) {
        best = folder;
        bestR = r;
      }
    });
    return best;
  }

  public start() {
    let lastTime = performance.now();
    let lastRenderTime = 0;
    const loop = (now: number) => {
      if (this.isDestroyed) return;
      this.animationFrameId = requestAnimationFrame(loop);

      const fpsLimit = this.state.settings.fpsLimit;
      const targetInterval = fpsLimit === '60' ? (1000 / 60) : (fpsLimit === '120' ? (1000 / 120) : 0);
      if (targetInterval > 0 && lastRenderTime > 0 && (now - lastRenderTime) < (targetInterval - 1.0)) {
        return;
      }
      const dt = lastRenderTime > 0 ? (now - lastRenderTime) : (now - lastTime);
      lastTime = now;
      lastRenderTime = now;
      this.time += dt;

      // Track FPS every 500ms
      this.fpsFrames++;
      if (now - this.fpsLastTime >= 500) {
        const fps = Math.round((this.fpsFrames * 1000) / (now - this.fpsLastTime));
        this.onFps?.(fps);
        this.fpsFrames = 0;
        this.fpsLastTime = now;
      }

      if (this.lastFitTick !== this.state.fitRequestTick) {
        this.lastFitTick = this.state.fitRequestTick;
        this.fitCameraToGraph(false);
      }

      if (this.lastFocusTick !== this.state.focusRequestTick) {
        this.lastFocusTick = this.state.focusRequestTick;
        if (this.state.focusTargetId) {
          this.focusSymbol(this.state.focusTargetId);
        }
      }

      this.selectedFolder = this.state.selectedFolder;

      const activeLayout = this.state.activeLayout;
      const targetDepth = activeLayout === 'Z-4' ? 4 : (parseInt(activeLayout.replace('Z-', ''), 10) || this.state.lodLevel);

      if (this.lastLodLevel !== this.state.lodLevel || this.lastActiveLayout !== activeLayout) {
        this.lastActiveLayout = activeLayout;
        this.lastLodLevel = this.state.lodLevel;
        this.physics.setDepth(targetDepth);
        this.physics.wake(140);
        this.refreshVisionColors(true);
      } else if (
        this.lastVisionMode !== this.state.visionMode ||
        this.lastActiveSymbolId !== (this.state.activeSymbol?.id || null) ||
        this.lastFilterVersion !== this.state.filterVersion
      ) {
        this.refreshVisionColors(true);
      }

      this.updateCamera(dt);
      if (!this.state.physicsPaused) {
        this.physics.step(this.camera.zoom);
      }
      this.render(now, dt);

      if (this.lastSnapshotTick !== this.state.snapshotRequestTick) {
        this.lastSnapshotTick = this.state.snapshotRequestTick;
        this.captureSnapshot();
      }
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  private updateCamera(dt: number) {
    const factor = 1 - Math.exp(-14.0 * (dt / 1000));
    this.camera.x += (this.camera.targetX - this.camera.x) * factor;
    this.camera.y += (this.camera.targetY - this.camera.y) * factor;
    this.camera.zoom += (this.camera.targetZoom - this.camera.zoom) * factor;
  }

  private render(now: number, dt = 16.6) {
    const { gl, pipeline, backdropPipeline } = this;
    const nodes = this.state.graph.nodes;

    // GPU FPS Watchdog: if a custom GLSL plugin causes sustained <25 FPS on normal graphs, auto-fallback to native shaders
    if ((pipeline.isCustom || backdropPipeline.isCustom) && (!nodes || nodes.length < 25000)) {
      if (dt > 40) {
        this.slowShaderMs += dt;
        if (this.slowShaderMs >= 2800) {
          swapBackdropShader(gl, backdropPipeline, null);
          swapNodeShader(gl, pipeline, null);
          this.slowShaderMs = 0;
          this.state.visualPluginError =
            'Watchdog FPS : shader GLSL custom trop lent (<25 FPS soutenu) — repli automatique sur les shaders natifs.';
        }
      } else {
        this.slowShaderMs = Math.max(0, this.slowShaderMs - dt * 0.5);
      }
    }

    // 0. Backdrop WebGL 2 Pass (Native Nebula or Custom Visual Plugin GLSL)
    gl.clearColor(this.themeColors[0], this.themeColors[1], this.themeColors[2], 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.disable(gl.BLEND);
    gl.useProgram(backdropPipeline.program);
    if (backdropPipeline.uniforms.uRes) gl.uniform2f(backdropPipeline.uniforms.uRes, this.gl.drawingBufferWidth, this.gl.drawingBufferHeight);
    if (backdropPipeline.uniforms.uCam) gl.uniform2f(backdropPipeline.uniforms.uCam, this.camera.x, this.camera.y);
    if (backdropPipeline.uniforms.uZoom) gl.uniform1f(backdropPipeline.uniforms.uZoom, this.camera.zoom);
    if (backdropPipeline.uniforms.uTime) gl.uniform1f(backdropPipeline.uniforms.uTime, now);
    if (backdropPipeline.uniforms.uThemeColors) gl.uniform3fv(backdropPipeline.uniforms.uThemeColors, this.themeColors);
    if (backdropPipeline.uniforms.uParams) {
      gl.uniform4f(
        backdropPipeline.uniforms.uParams,
        this.uniformParams[0],
        this.uniformParams[1],
        this.uniformParams[2],
        this.uniformParams[3]
      );
    }
    gl.bindVertexArray(backdropPipeline.vao);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    gl.bindVertexArray(null);

    // 1. WebGL 2 Instanced Living Celestial Bubbles (uRes in logical CSS pixels)
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    gl.useProgram(pipeline.program);
    if (pipeline.uniforms.uRes) gl.uniform2f(pipeline.uniforms.uRes, this.logicalWidth, this.logicalHeight);
    if (pipeline.uniforms.uCam) gl.uniform2f(pipeline.uniforms.uCam, this.camera.x, this.camera.y);
    if (pipeline.uniforms.uZoom) gl.uniform1f(pipeline.uniforms.uZoom, this.camera.zoom);
    if (pipeline.uniforms.uTime) gl.uniform1f(pipeline.uniforms.uTime, now);
    if (pipeline.uniforms.uThemeColors) gl.uniform3fv(pipeline.uniforms.uThemeColors, this.themeColors);
    if (pipeline.uniforms.uParams) {
      gl.uniform4f(
        pipeline.uniforms.uParams,
        this.uniformParams[0],
        this.uniformParams[1],
        this.uniformParams[2],
        this.uniformParams[3]
      );
    }

    if (nodes && nodes.length > 0) {
      gl.bindVertexArray(pipeline.vao);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, nodes.length);
      gl.bindVertexArray(null);
    }

    // 2. 2D Overlay Canvas (Thematic Layout Scenery, Cellular Membranes, Edges, Security Beacons, Labels)
    const ctx = this.lineCtx;
    ctx.clearRect(0, 0, this.logicalWidth, this.logicalHeight);

    this.renderLayoutScenery(ctx);
    this.renderMembranes(ctx, now);
    this.renderEdges(ctx, now);
    this.renderLabels(ctx);
    this.renderGitDiffBadges(ctx, now);
    this.renderSecurityBeacons(ctx, now);
    this.renderAiAgentOverlay(ctx, now, dt);
  }

  private captureSnapshot() {
    try {
      const exportCanvas = document.createElement('canvas');
      exportCanvas.width = this.canvas.width;
      exportCanvas.height = this.canvas.height;
      const ectx = exportCanvas.getContext('2d');
      if (!ectx) return;
      ectx.drawImage(this.canvas, 0, 0);
      ectx.drawImage(this.lineCanvas, 0, 0);
      const url = exportCanvas.toDataURL('image/png');
      const a = document.createElement('a');
      a.href = url;
      const proj = (this.state.graph.project_name || 'aetherscope').replace(/[^a-zA-Z0-9_-]/g, '_');
      a.download = `${proj}_snapshot_${Date.now()}.png`;
      a.click();
      playSpatialTone(this.state.settings.soundEnabled, 'success', 0);
    } catch {
      // ignore security errors if tainted
    }
  }

  private renderLayoutScenery(ctx: CanvasRenderingContext2D) {
    const layout = this.state.activeLayout;
    if (layout === 'Z-2') return; // Standard Galaxy cosmos uses pure nebula

    const w = this.logicalWidth;
    const h = this.logicalHeight;
    ctx.save();

    if (layout === 'Z-1') {
      // System Architecture Horizontal Layers (UI -> Domain -> Service -> Persistence/Infra)
      const bands = [
        { label: 'COUCHE PRÉSENTATION / UI', color: 'rgba(56, 189, 248, 0.05)', stroke: 'rgba(56, 189, 248, 0.22)' },
        { label: 'COUCHE DOMAINE / MÉTIER', color: 'rgba(168, 85, 247, 0.05)', stroke: 'rgba(168, 85, 247, 0.22)' },
        { label: 'COUCHE SERVICES & INFRASTRUCTURE', color: 'rgba(16, 185, 129, 0.045)', stroke: 'rgba(16, 185, 129, 0.22)' },
      ];
      const bandH = h / bands.length;
      ctx.font = '700 10px ui-monospace, "SF Mono", Consolas, monospace';
      for (let i = 0; i < bands.length; i++) {
        const y = i * bandH;
        ctx.fillStyle = bands[i].color;
        ctx.fillRect(0, y + 4, w, bandH - 8);
        ctx.strokeStyle = bands[i].stroke;
        ctx.setLineDash([6, 6]);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y + 4);
        ctx.lineTo(w, y + 4);
        ctx.stroke();
        ctx.fillStyle = bands[i].stroke.replace('0.22', '0.68');
        ctx.fillText(bands[i].label, 16, y + 20);
      }
      ctx.setLineDash([]);
    } else if (layout === 'Z-3') {
      // DAG Pipeline Horizontal Flow Lanes
      const lanes = 4;
      const laneW = w / lanes;
      const labels = ['INGESTION', 'TRANSFORM', 'SECURITY / TAINT', 'SINK / EXPORT'];
      ctx.font = '700 10px ui-monospace, "SF Mono", Consolas, monospace';
      for (let i = 0; i < lanes; i++) {
        const x = i * laneW;
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.16)';
        ctx.setLineDash([4, 8]);
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
        ctx.fillStyle = 'rgba(125, 211, 252, 0.52)';
        ctx.fillText(`⟶ ${labels[i]}`, x + 12, 22);
      }
      ctx.setLineDash([]);
    } else if (layout === 'Z-4') {
      // UML Matrix Technical Blueprint Grid
      const step = 48;
      ctx.strokeStyle = 'rgba(99, 102, 241, 0.08)';
      ctx.lineWidth = 1;
      for (let gx = (-(this.camera.x * this.camera.zoom) % step + step) % step; gx < w; gx += step) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, h);
        ctx.stroke();
      }
      for (let gy = (-(this.camera.y * this.camera.zoom) % step + step) % step; gy < h; gy += step) {
        ctx.beginPath();
        ctx.moveTo(0, gy);
        ctx.lineTo(w, gy);
        ctx.stroke();
      }
      ctx.font = '700 10px ui-monospace, "SF Mono", Consolas, monospace';
      ctx.fillStyle = 'rgba(165, 180, 252, 0.55)';
      ctx.fillText('MATRICE UML & RELATIONS STRUCTURELLES', 16, 22);
    }

    ctx.restore();
  }

  private renderGitDiffBadges(ctx: CanvasRenderingContext2D, now: number) {
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return;
    const gitFiles = this.state.gitStatus?.files;
    const hasEdits = Boolean((gitFiles && gitFiles.length > 0) || (this.state.folderEdits && Object.keys(this.state.folderEdits).length > 0));
    if (!hasEdits) return;

    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const zoom = this.camera.zoom;
    const activeId = this.state.activeSymbol?.id || null;
    const W = this.logicalWidth;
    const H = this.logicalHeight;

    ctx.save();
    ctx.font = '600 9.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';

    const placed: { x: number; y: number; w: number; h: number }[] = this.folderPillBounds.map((b) => ({
      x: b.x - 3,
      y: b.y - 3,
      w: b.w + 6,
      h: b.h + 6,
    }));
    const collides = (x: number, y: number, w: number, h: number) => {
      for (const r of placed) {
        if (x < r.x + r.w + 3 && x + w + 3 > r.x && y < r.y + r.h + 3 && y + h + 3 > r.y) return true;
      }
      return false;
    };

    let drawnRings = 0;
    let drawnPills = 0;
    const maxPills = zoom < 0.25 ? 8 : 16;

    for (let i = 0; i < nodes.length && drawnRings < 64; i++) {
      const n = nodes[i];
      const ek = n.edit_kind || (
        n.git_status === 'violation' ? 'violation'
          : n.git_status === 'new_folder' ? 'new_folder'
            : n.git_status === 'untracked' ? 'new_file'
              : n.git_status === 'text' ? 'text'
                : n.git_status === 'modified' ? 'modif'
                  : 'none'
      );
      if (ek === 'none') continue;
      if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;

      const isFocus = n.id === this.hoveredNodeId || n.id === activeId;
      // Only show git-diff indicators on file nodes or focused/hovered symbol (prevents 60+ stacked child-symbol overlays)
      if (!n.is_file && !isFocus) continue;

      // Never draw redundant "FAILLE ÉDIT" boxes: security nodes are rendered cleanly by renderSecurityBeacons
      if (ek === 'violation') continue;

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -60 || p.x > W + 60 || p.y < -60 || p.y > H + 60) continue;

      let badgeText = '';
      let accentHex = '#facc15';
      let strokeColor = 'rgba(250, 204, 21, 0.72)';
      let textColor = '#fef08a';

      if (ek === 'modif') {
        badgeText = 'MODIF';
        accentHex = '#facc15';
        strokeColor = 'rgba(250, 204, 21, 0.72)';
        textColor = '#fef08a';
      } else if (ek === 'text') {
        badgeText = 'DOC';
        accentHex = '#22d3ee';
        strokeColor = 'rgba(34, 211, 238, 0.72)';
        textColor = '#a5f3fc';
      } else if (ek === 'new_file') {
        badgeText = '+FICHIER';
        accentHex = '#34d399';
        strokeColor = 'rgba(52, 211, 153, 0.75)';
        textColor = '#a7f3d0';
      } else if (ek === 'new_folder') {
        badgeText = '+DOSSIER';
        accentHex = '#c084fc';
        strokeColor = 'rgba(192, 132, 252, 0.75)';
        textColor = '#e9d5ff';
      } else {
        continue;
      }

      const visR = this.getNodeScreenRadius(n, activeId);
      const ringR = Math.max(5.5, Math.min(22, visR * 0.58 + 3));
      const isRecent = Boolean(n.last_edit_ts && now - n.last_edit_ts < 15000);

      // Subtle, crisp git status ring (zero heavy shadowBlur blotches)
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = isRecent || isFocus ? 1.5 : 1.05;
      ctx.stroke();
      drawnRings++;

      if (!isFocus && !isRecent && zoom < 0.35) continue;
      if (drawnPills >= maxPills && !isFocus) continue;

      const padX = 6;
      const dotW = 8;
      const pillH = 16;
      const tw = Math.ceil(ctx.measureText(badgeText).width) + padX * 2 + dotW;
      const bx = Math.max(4, Math.min(W - tw - 4, Math.round(p.x - tw * 0.5)));
      const by = Math.round(p.y + ringR + 5);

      if (by + pillH > H - 28 || (!isFocus && collides(bx, by, tw, pillH))) continue;
      placed.push({ x: bx, y: by, w: tw, h: pillH });
      drawnPills++;

      ctx.fillStyle = 'rgba(10, 14, 24, 0.90)';
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 1.0;
      ctx.beginPath();
      ctx.roundRect(bx, by, tw, pillH, pillH / 2);
      ctx.fill();
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(bx + padX + 2, by + pillH / 2, 2.3, 0, Math.PI * 2);
      ctx.fillStyle = accentHex;
      ctx.fill();

      ctx.fillStyle = textColor;
      ctx.fillText(badgeText, bx + padX + dotW, by + pillH / 2 + 0.5);
    }

    ctx.restore();
  }

  private renderSecurityBeacons(ctx: CanvasRenderingContext2D, now: number) {
    if (!this.state.settings.showAlerts) return;
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return;
    const anomalyIndices = this.anomalyNodeIndices;
    if (anomalyIndices.length === 0) return;

    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const zoom = this.camera.zoom;
    const showTitles = this.state.settings.showCweTitles;
    const activeId = this.state.activeSymbol?.id || null;
    const W = this.logicalWidth;
    const H = this.logicalHeight;

    type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LINES';
    type Beacon = {
      x: number;
      y: number;
      ringR: number;
      sev: SeverityLevel;
      code: string;
      extraCount: number;
      prio: number;
      isFocus: boolean;
    };
    const beacons: Beacon[] = [];

    // ---- Passe 1 : anneaux fins proportionnels à la bulle (pas de pâté rouge au dézoom)
    ctx.save();
    let rings = 0;
    for (let k = 0; k < anomalyIndices.length && rings < 260; k++) {
      const i = anomalyIndices[k];
      const n = nodes[i];
      if (!n) continue;
      if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;

      const alertKind = getNodeAlertKind(n, this.isAnomalyIgnored);
      if (alertKind === 'none') continue;
      if (!this.state.settings.showCweBubbles && alertKind === 'security') continue;

      const isFocus = n.id === this.hoveredNodeId || n.id === activeId;
      // En vue macro/méso (zoom < 0.55), agréger par fichier évite d'empiler 30 anneaux de sous-fonctions
      if (!n.is_file && !isFocus && zoom < 0.55) continue;

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -50 || p.x > W + 50 || p.y < -50 || p.y > H + 50) continue;

      const isLinesWarn = alertKind === 'lines_exceeded';
      const effAnom = this.getEffectiveAnomalies(n);
      const secAnoms = effAnom.filter((a) => !isLinesExceededAnomaly(a));

      let sev: SeverityLevel = isLinesWarn ? 'LINES' : 'HIGH';
      if (!isLinesWarn) {
        if (secAnoms.some((a) => String(a.severity || '').toUpperCase() === 'CRITICAL')) sev = 'CRITICAL';
        else if (secAnoms.some((a) => String(a.severity || '').toUpperCase() === 'HIGH')) sev = 'HIGH';
        else if (secAnoms.length > 0) sev = 'MEDIUM';
        else sev = 'CRITICAL';
      }

      const visR = this.getNodeScreenRadius(n, activeId);
      const breath = 0.5 + 0.5 * Math.sin(now * 0.0018 + i * 0.55);
      const ringR = Math.max(5.5, Math.min(24, visR * 0.56 + 3.2)) + (isFocus ? breath * 2.0 : breath * 0.8);

      const rgb =
        sev === 'LINES' ? '245, 158, 11'
          : sev === 'CRITICAL' ? '244, 63, 94'
            : sev === 'HIGH' ? '251, 146, 60'
              : '250, 204, 21';

      // Aura externe très légère (ne sature plus jamais en bloc rouge opaque)
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR + 3, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${rgb}, ${(isFocus ? 0.14 : 0.055).toFixed(3)})`;
      ctx.fill();

      // Anneau net
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${rgb}, ${(isFocus ? 0.92 : 0.62 + breath * 0.18).toFixed(2)})`;
      ctx.lineWidth = isFocus ? 1.8 : 1.15;
      ctx.stroke();
      rings++;

      if (showTitles && (isFocus || n.is_file || zoom >= 0.55)) {
        let code: string;
        let extraCount = 0;
        let prio = 0;
        if (isLinesWarn) {
          const maxLim = n.metadata?.max_lines_limit || 300;
          const curLoc = n.loc || n.metadata?.lines || 0;
          code = curLoc > 0 ? `${curLoc}/${maxLim} L` : 'Max L';
          prio = 1;
        } else {
          // Prioriser la faille la plus critique et compter les CWE de sécurité réelles
          const rankSev = (s?: string) => {
            const u = String(s || '').toUpperCase();
            return u === 'CRITICAL' ? 3 : u === 'HIGH' ? 2 : 1;
          };
          const sortedSec = [...secAnoms].sort((a, b) => rankSev(b.severity) - rankSev(a.severity));
          const primary = sortedSec[0];
          code = primary ? formatCweShortId(primary.cve_id, primary.rule_id) : 'CWE';
          extraCount = Math.max(0, sortedSec.length - 1);
          prio = sev === 'CRITICAL' ? 4 : sev === 'HIGH' ? 3 : 2;
        }
        if (n.is_file) prio += 0.5;
        beacons.push({ x: p.x, y: p.y, ringR, sev, code, extraCount, prio, isFocus });
      }
    }

    // ---- Passe 2 : pastilles CWE compactes, verre dépoli sombre, anti-collision avec dossiers + labels
    if (beacons.length > 0) {
      beacons.sort((a, b) => Number(b.isFocus) - Number(a.isFocus) || b.prio - a.prio || b.extraCount - a.extraCount);

      const fontPx = Math.min(11.5, Math.max(9.5, 9.8 + (zoom - 0.3) * 1.4));
      const mainFont = `700 ${fontPx.toFixed(1)}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`;
      const countFont = `700 ${Math.max(8.5, fontPx - 1.2).toFixed(1)}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`;
      ctx.textBaseline = 'middle';
      ctx.textAlign = 'left';

      const pillH = Math.round(fontPx + 8);
      const padL = 7;
      const padR = 7;
      const dotArea = 9;

      // Pré-remplit les zones occupées par les badges de dossiers et les labels de fichiers
      const placed: { x: number; y: number; w: number; h: number }[] = [
        ...this.folderPillBounds.map((b) => ({ x: b.x - 2, y: b.y - 2, w: b.w + 4, h: b.h + 4 })),
        ...this.labelBounds.map((b) => ({ x: b.x - 1, y: b.y - 1, w: b.w + 2, h: b.h + 2 })),
      ];
      const hit = (x: number, y: number, w: number, h: number) => {
        for (const r of placed) {
          if (x < r.x + r.w + 4 && x + w + 4 > r.x && y < r.y + r.h + 4 && y + h + 4 > r.y) return true;
        }
        return false;
      };

      const maxPills = zoom < 0.12 ? 14 : zoom < 0.35 ? 24 : 42;
      let drawnPills = 0;

      for (const b of beacons) {
        if (drawnPills >= maxPills && !b.isFocus) break;

        ctx.font = mainFont;
        const codeW = Math.ceil(ctx.measureText(b.code).width);
        let extraText = '';
        let extraChipW = 0;
        if (b.extraCount > 0) {
          extraText = `+${b.extraCount}`;
          ctx.font = countFont;
          extraChipW = Math.ceil(ctx.measureText(extraText).width) + 9;
        }
        const tw = padL + dotArea + codeW + (extraChipW > 0 ? 5 + extraChipW : 0) + padR;
        const baseY = Math.round(b.y - b.ringR - pillH - 6);
        const centerBx = Math.round(b.x - tw / 2);

        // Positions candidates autour de la bulle : dessus, haut-droite, haut-gauche, étage +1, droite, gauche, dessous
        const candidates: [number, number][] = [
          [centerBx, baseY],
          [Math.round(b.x + b.ringR + 6), Math.round(b.y - pillH - 2)],
          [Math.round(b.x - b.ringR - tw - 6), Math.round(b.y - pillH - 2)],
          [centerBx, baseY - (pillH + 5)],
          [Math.round(b.x + b.ringR + 6), Math.round(b.y - pillH / 2)],
          [Math.round(b.x - b.ringR - tw - 6), Math.round(b.y - pillH / 2)],
          [centerBx, Math.round(b.y + b.ringR + 6)],
        ];

        let bx = centerBx;
        let by = baseY;
        let ok = false;
        for (const [cxRaw, cy] of candidates) {
          const cx = Math.max(6, Math.min(W - tw - 6, cxRaw));
          if (cy < 54 || cy + pillH > H - 32) continue;
          if (!hit(cx, cy, tw, pillH)) {
            bx = cx;
            by = cy;
            ok = true;
            break;
          }
        }
        if (!ok) {
          if (!b.isFocus) continue;
          bx = Math.max(6, Math.min(W - tw - 6, centerBx));
          by = Math.max(54, Math.min(H - pillH - 32, baseY));
        }

        placed.push({ x: bx, y: by, w: tw, h: pillH });
        drawnPills++;

        const palette =
          b.sev === 'LINES'
            ? { accent: '#f59e0b', border: 'rgba(245, 158, 11, 0.72)', bg: 'rgba(18, 14, 8, 0.90)', text: '#fde68a', chipBg: 'rgba(245, 158, 11, 0.22)', chipTxt: '#fcd34d' }
            : b.sev === 'CRITICAL'
              ? { accent: '#f43f5e', border: 'rgba(244, 63, 94, 0.78)', bg: 'rgba(17, 10, 16, 0.92)', text: '#ffe4e6', chipBg: 'rgba(244, 63, 94, 0.24)', chipTxt: '#fda4af' }
              : b.sev === 'HIGH'
                ? { accent: '#fb923c', border: 'rgba(251, 146, 60, 0.78)', bg: 'rgba(18, 12, 10, 0.92)', text: '#ffedd5', chipBg: 'rgba(251, 146, 60, 0.24)', chipTxt: '#fdba74' }
                : { accent: '#facc15', border: 'rgba(250, 204, 21, 0.72)', bg: 'rgba(17, 15, 9, 0.90)', text: '#fef9c3', chipBg: 'rgba(250, 204, 21, 0.20)', chipTxt: '#fde047' };

        // Fin trait connecteur vers la bulle
        const pillCx = bx + tw / 2;
        const pillCy = by + pillH / 2;
        const dx = b.x - pillCx;
        const dy = b.y - pillCy;
        const d = Math.hypot(dx, dy) || 1;
        if (d > b.ringR + pillH * 0.6) {
          const anchorX = Math.max(bx + 4, Math.min(bx + tw - 4, b.x));
          const anchorY = by + pillH < b.y ? by + pillH : by > b.y ? by : pillCy;
          ctx.beginPath();
          ctx.moveTo(anchorX, anchorY);
          ctx.lineTo(b.x - (dx / d) * b.ringR, b.y - (dy / d) * b.ringR);
          ctx.strokeStyle = palette.border;
          ctx.globalAlpha = 0.42;
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.globalAlpha = 1.0;
        }

        // Corps de la pastille (sombre verre dépoli, bord net 1px, zéro flou baveux)
        ctx.fillStyle = palette.bg;
        ctx.strokeStyle = b.isFocus ? palette.accent : palette.border;
        ctx.lineWidth = b.isFocus ? 1.5 : 1.0;
        ctx.beginPath();
        ctx.roundRect(bx, by, tw, pillH, 6);
        ctx.fill();
        ctx.stroke();

        // Point de gravité net
        ctx.beginPath();
        ctx.arc(bx + padL + 2.5, by + pillH / 2, 2.7, 0, Math.PI * 2);
        ctx.fillStyle = palette.accent;
        ctx.fill();

        // Identifiant CWE clair (ex: CWE-88, PATH-008, CWE-1075)
        ctx.font = mainFont;
        ctx.fillStyle = palette.text;
        ctx.fillText(b.code, bx + padL + dotArea, by + pillH / 2 + 0.5);

        // Mini-badge compteur (+N) sur la droite si plusieurs failles
        if (extraChipW > 0) {
          const chipX = bx + padL + dotArea + codeW + 5;
          const chipH = pillH - 5;
          const chipY = by + 2.5;
          ctx.fillStyle = palette.chipBg;
          ctx.beginPath();
          ctx.roundRect(chipX, chipY, extraChipW, chipH, 4);
          ctx.fill();

          ctx.font = countFont;
          ctx.fillStyle = palette.chipTxt;
          ctx.fillText(extraText, chipX + 4.5, by + pillH / 2 + 0.5);
        }
      }
    }
    ctx.restore();
  }

  private renderAiAgentOverlay(ctx: CanvasRenderingContext2D, now: number, dt = 16.6) {
    const rawAgents = this.state.activeAgents;
    const trails = this.state.agentTrails;
    if (!rawAgents || rawAgents.length === 0) return;
    // Only render agents that pinged within the last 5 minutes
    const agents = rawAgents.filter((ag) => !this.state.isAgentInactive(ag));
    if (agents.length === 0) return;

    // Prune stale agent positions to prevent memory leaks over time
    if (this.agentSmoothPositions.size > 40) {
      const activeIds = new Set(agents.map((a) => a.agentId));
      for (const k of this.agentSmoothPositions.keys()) {
        if (!activeIds.has(k)) {
          this.agentSmoothPositions.delete(k);
        }
      }
    }

    ctx.save();
    const zoom = this.camera.zoom;
    const safeDt = Math.min(Math.max(dt || 16.6, 1.0), 50.0);

    // Palette of vibrant neon colors guaranteed to be visually distinct
    const DISTINCT_PALETTE = [
      '#38bdf8', // Sky Cyan
      '#f97316', // Neon Orange
      '#c084fc', // Cosmic Purple
      '#34d399', // Emerald Mint
      '#f43f5e', // Hot Coral Rose
      '#eab308', // Solar Amber
      '#a855f7', // Electric Violet
      '#06b6d4', // Bright Turquoise
      '#ec4899', // Hyper Pink
      '#84cc16', // Toxic Lime
      '#6366f1', // Ultra Indigo
      '#14b8a6', // Deep Teal
      '#fb923c', // Tangerine
      '#e879f9', // Orchid Fuchsia
      '#10b981', // Spring Green
      '#3b82f6', // Cobalt Blue
    ];

    // Pre-pass: Resolve target bubble and assign unique color for each agent
    interface ActiveAgentVisual {
      ag: (typeof agents)[0];
      targetNode: SymbolBubble;
      agColor: string;
      agNameLower: string;
      agentCleanName: string;
    }

    const resolvedList: ActiveAgentVisual[] = [];
    const agentsByNode = new Map<string, number>();
    const assignedColors = new Set<string>();

    for (let idx = 0; idx < agents.length; idx++) {
      const ag = agents[idx];
      let targetNode: SymbolBubble | undefined;
      if (ag.nodeId) {
        targetNode = this.nodeMap.get(ag.nodeId);
      }
      if (!targetNode && ag.target) {
        targetNode = this.state.resolveTargetNode(ag.target);
        if (targetNode) ag.nodeId = targetNode.id;
      }
      if (!targetNode && this.state.activeSymbol) {
        targetNode = this.state.activeSymbol;
      }
      if (!targetNode) continue;

      let agColor = ag.color;
      if (!agColor || assignedColors.has(agColor)) {
        agColor = DISTINCT_PALETTE[idx % DISTINCT_PALETTE.length];
      }
      assignedColors.add(agColor);

      const agNameLower = (ag.agentName || ag.agentId || '').toLowerCase();
      const agentCleanName = ag.agentName || ag.agentId || 'Agent';

      resolvedList.push({ ag, targetNode, agColor, agNameLower, agentCleanName });
      agentsByNode.set(targetNode.id, (agentsByNode.get(targetNode.id) || 0) + 1);
    }

    if (resolvedList.length === 0) {
      ctx.restore();
      return;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. RENDER INTER-BUBBLE NAVIGATION TRAJECTORIES (LIGNES D'IA)
    // ─────────────────────────────────────────────────────────────────────────
    if (this.state.settings.showAiLines && this.state.settings.aiTrail) {
      for (let idx = 0; idx < resolvedList.length; idx++) {
        const { ag, targetNode, agColor } = resolvedList[idx];
        const agTrail = trails[ag.agentId] || [];

        const validPoints: { s: { x: number; y: number }; wx: number; wy: number }[] = [];

        for (const pt of agTrail) {
          let node = pt.nodeId ? this.nodeMap.get(pt.nodeId) : null;
          if (!node && pt.target) {
            node = this.state.resolveTargetNode(pt.target);
            if (node) pt.nodeId = node.id;
          }
          const wx = node ? node.x : pt.x;
          const wy = node ? node.y : pt.y;
          if (wx == null || wy == null) continue;
          validPoints.push({ s: this.worldToScreen(wx, wy), wx, wy });
        }

        // Connect the trail directly to the current target bubble if not already the final point
        const lastPt = validPoints[validPoints.length - 1];
        if (!lastPt || Math.hypot(lastPt.wx - targetNode.x, lastPt.wy - targetNode.y) > 1.0) {
          validPoints.push({
            s: this.worldToScreen(targetNode.x, targetNode.y),
            wx: targetNode.x,
            wy: targetNode.y,
          });
        }

        if (validPoints.length > 1) {
          // Pass 1: Subtle diffused glow path
          ctx.beginPath();
          ctx.moveTo(validPoints[0].s.x, validPoints[0].s.y);
          for (let i = 1; i < validPoints.length; i++) {
            ctx.lineTo(validPoints[i].s.x, validPoints[i].s.y);
          }
          ctx.strokeStyle = agColor;
          ctx.lineWidth = Math.max(1.5, 2.2 * Math.sqrt(zoom));
          ctx.globalAlpha = 0.12;
          ctx.stroke();

          // Pass 2: Lightweight dashed trajectory core
          ctx.beginPath();
          ctx.moveTo(validPoints[0].s.x, validPoints[0].s.y);
          for (let i = 1; i < validPoints.length; i++) {
            ctx.lineTo(validPoints[i].s.x, validPoints[i].s.y);
          }
          ctx.setLineDash([6, 6]);
          ctx.lineDashOffset = -(now * 0.015 + idx * 3);
          ctx.strokeStyle = agColor;
          ctx.globalAlpha = 0.48;
          ctx.lineWidth = Math.max(1.0, 1.3 * Math.sqrt(zoom));
          ctx.stroke();
          ctx.setLineDash([]);

          // Pass 3: Subtle waypoint dots
          for (let i = 0; i < validPoints.length; i++) {
            const wp = validPoints[i];
            const isLatest = i === validPoints.length - 1;
            const wpRadius = isLatest ? 3.2 : 2.0;

            ctx.beginPath();
            ctx.arc(wp.s.x, wp.s.y, wpRadius, 0, Math.PI * 2);
            ctx.fillStyle = isLatest ? '#ffffff' : agColor;
            ctx.globalAlpha = isLatest ? 0.85 : 0.45;
            ctx.fill();
          }
          ctx.globalAlpha = 1.0;
        }
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. RENDER MULTI-AGENT ORBITS ON THE BUBBLE SIMULTANEOUSLY
    // ─────────────────────────────────────────────────────────────────────────
    const nodeAgentCounter = new Map<string, number>();

    // 3D inclined celestial orbit constants base:
    const TILT_ALPHA = 0.610865;   // ~35°
    const INCLINATION_PSI = 0.436332; // ~25°
    const omega = 0.0018;

    for (let idx = 0; idx < resolvedList.length; idx++) {
      const { ag, targetNode, agColor, agNameLower, agentCleanName } = resolvedList[idx];

      const totalOnNode = agentsByNode.get(targetNode.id) || 1;
      const subIdx = nodeAgentCounter.get(targetNode.id) || 0;
      nodeAgentCounter.set(targetNode.id, subIdx + 1);

      // Phase spacing: uniformly distribute agents around this bubble
      const phiAgent = (subIdx / totalOnNode) * (Math.PI * 2);

      // Tiered radius per agent on the same bubble so they have distinct orbital shells
      const { baseRadius } = this.classifyNode(targetNode);
      const orbitR = (baseRadius * 2.5 + 24.0) + (subIdx * 14.0);

      // Distinct 3D orbital plane tilt and inclination per agent on this bubble
      const tiltAlpha = TILT_ALPHA + (subIdx * (Math.PI / Math.max(2, totalOnNode * 2)));
      const inclinationPsi = INCLINATION_PSI + (subIdx * (Math.PI / Math.max(1, totalOnNode)));
      const cosAlpha = Math.cos(tiltAlpha);
      const cosPsi = Math.cos(inclinationPsi);
      const sinPsi = Math.sin(inclinationPsi);

      // Alternating orbital revolution direction and speed
      const dir = (subIdx % 2 === 0 ? 1 : -0.85);
      const agentOmega = omega + (subIdx * 0.0002);
      const theta = (now * agentOmega * dir) + phiAgent;

      // Smooth camera anchor position with continuous LERP (safeguarded against frame drops)
      let smooth = this.agentSmoothPositions.get(ag.agentId);
      if (!smooth) {
        smooth = { x: targetNode.x, y: targetNode.y };
        this.agentSmoothPositions.set(ag.agentId, smooth);
      } else {
        const lerpFactor = 1.0 - Math.exp(-14.0 * (safeDt / 1000));
        smooth.x += (targetNode.x - smooth.x) * lerpFactor;
        smooth.y += (targetNode.y - smooth.y) * lerpFactor;
      }
      const anchorX = smooth.x;
      const anchorY = smooth.y;

      // ───────────────────────────────────────────────────────────────────────
      // A. DRAW ORBITAL TRAJECTORY RING ON THE BUBBLE (LIGNES D'IA)
      // ───────────────────────────────────────────────────────────────────────
      if (this.state.settings.showAiLines) {
        ctx.beginPath();
        const ORBIT_SAMPLES = 12; // Lightweight sampling (eliminated heavy 28-sample matrix loop)
        for (let s = 0; s <= ORBIT_SAMPLES; s++) {
          const a = (s / ORBIT_SAMPLES) * Math.PI * 2;
          const xP = orbitR * Math.cos(a);
          const yP = orbitR * Math.sin(a) * cosAlpha;
          const xR = xP * cosPsi - yP * sinPsi;
          const yR = xP * sinPsi + yP * cosPsi;
          const p = this.worldToScreen(anchorX + xR, anchorY + yR);
          if (s === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        }
        ctx.strokeStyle = agColor;
        ctx.lineWidth = Math.max(1.0, 1.4 * Math.sqrt(zoom));
        ctx.globalAlpha = 0.35;
        ctx.stroke();
      }

      // Current avatar 3D position in orbit
      const xPlane = orbitR * Math.cos(theta);
      const yPlane = orbitR * Math.sin(theta) * cosAlpha;
      const xRot = xPlane * cosPsi - yPlane * sinPsi;
      const yRot = xPlane * sinPsi + yPlane * cosPsi;

      const xOrbWorld = anchorX + xRot;
      const yOrbWorld = anchorY + yRot;

      const pOrb = this.worldToScreen(xOrbWorld, yOrbWorld);
      const pNode = this.worldToScreen(anchorX, anchorY);

      // Screen culling
      if (
        pOrb.x < -140 || pOrb.x > this.logicalWidth + 140 ||
        pOrb.y < -140 || pOrb.y > this.logicalHeight + 140
      ) {
        continue;
      }

      // Calculate target bubble surface intersection
      const targetR = this.getNodeScreenRadius(targetNode, this.state.activeSymbol?.id || null);
      const dx = pNode.x - pOrb.x;
      const dy = pNode.y - pOrb.y;
      const len = Math.hypot(dx, dy) || 1;
      const impactDist = Math.max(0, targetR * 0.45);
      const pImpact = {
        x: pNode.x - (dx / len) * impactDist,
        y: pNode.y - (dy / len) * impactDist,
      };

      // ───────────────────────────────────────────────────────────────────────
      // B. CONNECTING LASER BEAM FROM AVATAR TO BUBBLE SURFACE (LIGNES D'IA)
      // ───────────────────────────────────────────────────────────────────────
      if (this.state.settings.showAiLines) {
        // Pass 1: Diffused colored glow aura
        ctx.beginPath();
        ctx.moveTo(pOrb.x, pOrb.y);
        ctx.lineTo(pImpact.x, pImpact.y);
        ctx.strokeStyle = agColor;
        ctx.lineWidth = Math.max(1.5, 2.5 * Math.sqrt(zoom));
        ctx.globalAlpha = 0.30;
        ctx.stroke();

        // Pass 2: Inner white laser core
        ctx.beginPath();
        ctx.moveTo(pOrb.x, pOrb.y);
        ctx.lineTo(pImpact.x, pImpact.y);
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.0;
        ctx.globalAlpha = 0.85;
        ctx.stroke();

        // Pass 3: Concentric circular scanning reticle on bubble surface (fast, zero matrix rotate churn)
        const reticleRadius = Math.max(4, Math.min(10, 5 * Math.sqrt(Math.max(0.3, zoom))));
        ctx.beginPath();
        ctx.arc(pImpact.x, pImpact.y, reticleRadius, 0, Math.PI * 2);
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.0;
        ctx.globalAlpha = 0.80;
        ctx.stroke();
      }

      // ───────────────────────────────────────────────────────────────────────
      // C. STELLAR AVATAR ORB AT (pOrb.x, pOrb.y) (LIGHTWEIGHT, ZERO MATRIX STACK CHURN)
      // ───────────────────────────────────────────────────────────────────────
      // Fast lightweight vector circles (eliminated rotating accretion ellipse matrix transforms)
      ctx.beginPath();
      ctx.arc(pOrb.x, pOrb.y, 8, 0, Math.PI * 2);
      ctx.fillStyle = agColor;
      ctx.globalAlpha = 0.35;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(pOrb.x, pOrb.y, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.globalAlpha = 0.95;
      ctx.fill();

      // ───────────────────────────────────────────────────────────────────────
      // D. STATIC & SLEEK BILLBOARD BADGE (MASQUABLE & DISPARAÎT APRÈS 5 MIN D'INACTIVITÉ)
      // ───────────────────────────────────────────────────────────────────────
      const isInactive = this.state.isAgentInactive(ag);
      if (this.state.settings.showAiNames && !isInactive && zoom >= 0.22) {
        const agentIcon = agNameLower.includes('claude') ? '✨'
          : agNameLower.includes('gemini') ? '⚡'
          : agNameLower.includes('cursor') ? '🎯'
          : agNameLower.includes('antigravity') ? '🪐'
          : '🤖';
        const shortName = agentCleanName.length > 14 ? agentCleanName.slice(0, 12) + '…' : agentCleanName;
        const tagText = `${agentIcon} ${shortName}`;

        ctx.font = '600 9px ui-sans-serif, system-ui, -apple-system, sans-serif';
        const tw = ctx.measureText(tagText).width + 10;
        const badgeH = 15;

        // FIXED ANCHOR TO NODE (pNode), NOT MOVING WITH THE ORBITING CELL (pOrb)
        const badgeX = pNode.x;
        const badgeY = pNode.y - targetR - 8 - (subIdx * (badgeH + 3));

        // Compact glassmorphic pill badge
        ctx.fillStyle = 'rgba(10, 14, 26, 0.92)';
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.0;
        ctx.globalAlpha = 0.92;
        ctx.beginPath();
        ctx.roundRect(badgeX - tw * 0.5, badgeY - badgeH * 0.5, tw, badgeH, 4);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = '#f8fafc';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(tagText, badgeX, badgeY + 0.5);
      }
    }

    ctx.restore();
  }

  private traceMembraneSpline(
    ctx: CanvasRenderingContext2D,
    cx: number,
    cy: number,
    radius: number,
    lobeProfile: Float32Array | undefined,
    breathPhase: number,
    phaseShift: number
  ): number {
    if (this.membraneStyle === 'hex_hull') {
      const r = radius * (1.0 + 0.012 * this.membraneBreathAmp * Math.sin(breathPhase + phaseShift));
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = (i / 6) * Math.PI * 2 - Math.PI / 6;
        const px = cx + Math.cos(a) * r;
        const py = cy + Math.sin(a) * r;
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      return cy - r;
    }

    if (this.membraneStyle === 'rect_blueprint') {
      const r = radius * 0.96;
      const chamfer = Math.min(18, r * 0.18);
      const x0 = cx - r;
      const y0 = cy - r;
      const x1 = cx + r;
      const y1 = cy + r;
      ctx.beginPath();
      ctx.moveTo(x0 + chamfer, y0);
      ctx.lineTo(x1 - chamfer, y0);
      ctx.lineTo(x1, y0 + chamfer);
      ctx.lineTo(x1, y1 - chamfer);
      ctx.lineTo(x1 - chamfer, y1);
      ctx.lineTo(x0 + chamfer, y1);
      ctx.lineTo(x0, y1 - chamfer);
      ctx.lineTo(x0, y0 + chamfer);
      ctx.closePath();
      return y0;
    }

    const ptsX = new Float32Array(12);
    const ptsY = new Float32Array(12);
    const amp = this.membraneBreathAmp;

    // Respiration cellulaire ultra-fluide & ondulation amiboïde continue (C∞ sur le cercle fermé)
    const globalBreath = 1.0 + 0.022 * amp * Math.sin(breathPhase + phaseShift);

    for (let i = 0; i < 12; i++) {
      const prof = lobeProfile && lobeProfile[i] ? lobeProfile[i] : 1.0;
      const waveMode2 = 0.014 * amp * Math.sin(breathPhase * 0.72 + (i * Math.PI) / 3 + phaseShift);
      const waveMode3 = 0.006 * amp * Math.cos(breathPhase * 0.44 - (i * Math.PI) / 2 - phaseShift * 0.5);

      const harmonic = globalBreath + waveMode2 + waveMode3;
      const r = radius * prof * harmonic;
      ptsX[i] = cx + _COS12[i] * r;
      ptsY[i] = cy + _SIN12[i] * r;
    }

    ctx.beginPath();
    ctx.moveTo((ptsX[11] + ptsX[0]) * 0.5, (ptsY[11] + ptsY[0]) * 0.5);
    for (let i = 0; i < 12; i++) {
      const next = (i + 1) % 12;
      ctx.quadraticCurveTo(ptsX[i], ptsY[i], (ptsX[i] + ptsX[next]) * 0.5, (ptsY[i] + ptsY[next]) * 0.5);
    }
    ctx.closePath();
    return ptsY[9] ?? cy - radius;
  }

  private syncLiveClusterEnvelopes() {
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return;

    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const grouped = new Map<string, SymbolBubble[]>();

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) continue;
      if (disabledLayers[n.layer || 'utility']) continue;
      const folder = n.cluster_id || n.folder || 'root';
      if (disabledModules[folder]) continue;
      let list = grouped.get(folder);
      if (!list) {
        list = [];
        grouped.set(folder, list);
      }
      list.push(n);
    }

    // Remove clusters with 0 currently visible nodes
    for (const k of Array.from(this.clusters.keys())) {
      if (!grouped.has(k)) this.clusters.delete(k);
    }

    const TWO_PI = Math.PI * 2;
    const padding = 36 / Math.sqrt(Math.max(0.2, Math.min(2.0, this.camera.zoom)));

    grouped.forEach((list, folder) => {
      let sumX = 0;
      let sumY = 0;
      for (let i = 0; i < list.length; i++) {
        sumX += list[i].x;
        sumY += list[i].y;
      }
      const cx = sumX / list.length;
      const cy = sumY / list.length;

      let maxDist = 0;
      const rawSectors = new Float32Array(12);
      for (let i = 0; i < list.length; i++) {
        const nd = list[i];
        const dx = nd.x - cx;
        const dy = nd.y - cy;
        const nodePad = nd.is_file || nd.is_class ? 24 : 15;
        const d = Math.hypot(dx, dy) + nodePad;
        if (d > maxDist) maxDist = d;
        let ang = Math.atan2(dy, dx);
        if (ang < 0) ang += TWO_PI;
        const sIdx = Math.round((ang / TWO_PI) * 12) % 12;
        if (d > rawSectors[sIdx]) rawSectors[sIdx] = d;
        const prev = (sIdx + 11) % 12;
        const next = (sIdx + 1) % 12;
        if (d * 0.90 > rawSectors[prev]) rawSectors[prev] = d * 0.90;
        if (d * 0.90 > rawSectors[next]) rawSectors[next] = d * 0.90;
      }

      const minBaseR = Math.max(54, Math.sqrt(list.length) * 32);
      const baseR = Math.max(minBaseR, maxDist + padding);

      const rawLobes = new Float32Array(12);
      for (let s = 0; s < 12; s++) {
        const neededR = rawSectors[s] > 0 ? rawSectors[s] + padding : baseR * 0.88;
        rawLobes[s] = Math.max(0.84, Math.min(1.45, neededR / baseR));
      }

      let entry = this.clusters.get(folder);
      if (!entry) {
        const initialLobes = new Float32Array(12);
        for (let s = 0; s < 12; s++) {
          const prev = rawLobes[(s + 11) % 12];
          const next = rawLobes[(s + 1) % 12];
          initialLobes[s] = (prev * 0.25 + rawLobes[s] * 0.50 + next * 0.25) * 1.06;
        }
        entry = {
          cx,
          cy,
          sumX,
          sumY,
          count: list.length,
          computedRadius: baseR,
          naturalRadius: baseR,
          lobeProfile: initialLobes,
        };
        this.clusters.set(folder, entry);
      } else {
        // Adaptive temporal smoothing: fast catchup on layout transitions (N1 <-> N2 <-> N3), silky when settled
        const dist = Math.hypot(cx - entry.cx, cy - entry.cy);
        const alpha = dist > 400 ? 0.40 : (dist > 100 ? 0.24 : 0.14);
        entry.cx += (cx - entry.cx) * alpha;
        entry.cy += (cy - entry.cy) * alpha;
        entry.sumX = sumX;
        entry.sumY = sumY;
        entry.count = list.length;
        entry.computedRadius += (baseR - entry.computedRadius) * alpha;
        entry.naturalRadius += (baseR - entry.naturalRadius) * alpha;
        if (entry.lobeProfile.length !== 12) entry.lobeProfile = new Float32Array(12);
        for (let s = 0; s < 12; s++) {
          const prev = rawLobes[(s + 11) % 12];
          const next = rawLobes[(s + 1) % 12];
          const targetLobe = (prev * 0.25 + rawLobes[s] * 0.50 + next * 0.25) * 1.06;
          entry.lobeProfile[s] = entry.lobeProfile[s]
            ? entry.lobeProfile[s] + (targetLobe - entry.lobeProfile[s]) * alpha
            : targetLobe;
        }
      }
    });
  }

  private renderMembranes(ctx: CanvasRenderingContext2D, now: number) {
    this.folderPillBounds = [];
    this.syncLiveClusterEnvelopes();
    if (!this.state.settings.showFolderMembranes || this.membraneStyle === 'none' || this.state.visionMode === 'xray' || this.clusters.size === 0) return;

    ctx.save();
    // Horloge respiratoire maîtresse apaisée, ultra-fluide et douce (~9.6s par cycle)
    const breathPhase = now * 0.00065;
    const isDenseProject = this.clusters.size > 45 || this.state.isLowMemoryMode;
    const badges: {
      folder: string;
      label: string;
      count: number;
      cx: number;
      topY: number;
      rgb: string;
      sel: boolean;
      editLabel?: string;
      editHex?: string;
    }[] = [];

    this.clusters.forEach((cl, folder) => {
      if (cl.count <= 0 || this.state.disabledModules[folder]) return;
      const isSel = folder === this.selectedFolder || folder === this.hoveredFolder;
      const folderEdit = this.state.folderEdits?.[folder];
      const isEditedCell = Boolean(folderEdit && folderEdit.count > 0);

      // Skip micro-clusters (less than 3 nodes) on dense views to eliminate cell clutter
      if (cl.count < 3 && !isSel && !isEditedCell) return;

      const center = this.worldToScreen(cl.cx, cl.cy);
      const rawR = (cl.computedRadius || 100) * this.camera.zoom;
      const baseR = Math.max(5.5, rawR);

      if (
        center.x + baseR < -60 ||
        center.x - baseR > this.logicalWidth + 60 ||
        center.y + baseR < -60 ||
        center.y - baseR > this.logicalHeight + 60
      ) {
        return;
      }
      if (baseR < 14 && !isSel && !isEditedCell) return;

      const col = getFolderColor(folder);
      let rR = Math.round(col.r * 255);
      let rG = Math.round(col.g * 255);
      let rB = Math.round(col.b * 255);
      let lR = Math.min(255, rR + 85);
      let lG = Math.min(255, rG + 85);
      let lB = Math.min(255, rB + 100);
      const folderPhase = (rR * 0.03 + rG * 0.07) % 6.28;

      let editHex: string | undefined;
      if (folderEdit && folderEdit.count > 0) {
        if (folderEdit.kind === 'violation') {
          rR = 239; rG = 68; rB = 68;
          lR = 252; lG = 165; lB = 165;
          editHex = '#ef4444';
        } else if (folderEdit.kind === 'new_folder') {
          rR = 192; rG = 132; rB = 252;
          lR = 233; lG = 213; lB = 255;
          editHex = '#c084fc';
        } else if (folderEdit.kind === 'new_file') {
          rR = 16; rG = 185; rB = 129;
          lR = 110; lG = 231; lB = 183;
          editHex = '#34d399';
        } else if (folderEdit.kind === 'text') {
          rR = 34; rG = 211; rB = 238;
          lR = 165; lG = 243; lB = 252;
          editHex = '#22d3ee';
        } else {
          rR = 250; rG = 204; rB = 21;
          lR = 254; lG = 240; lB = 138;
          editHex = '#facc15';
        }
      }

      // Respiration synchronisée et harmonieuse des cellules modifiées (sans à-coup)
      const cellPulse = isEditedCell ? 0.5 + 0.5 * Math.sin(breathPhase + folderPhase) : 0;

      // 1. Living Outer Cytoplasmic Membrane (high-perf flat fill for dense clusters)
      const topCrestY = this.traceMembraneSpline(ctx, center.x, center.y, baseR, cl.lobeProfile, breathPhase, folderPhase);
      const isTiny = baseR < 20;

      if (isDenseProject || isTiny) {
        const innerAlpha = isEditedCell ? 0.18 : isSel ? 0.16 : 0.065;
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${innerAlpha})`;
        ctx.fill();
      } else {
        const grad = ctx.createRadialGradient(center.x, center.y, Math.max(4, baseR * 0.15), center.x, center.y, Math.max(12, baseR * 1.15));
        const bioPulse = 0.5 + 0.5 * Math.sin(breathPhase + folderPhase);
        const innerAlpha = isEditedCell ? (0.16 + cellPulse * 0.035) : isSel ? 0.16 : (0.075 + 0.010 * bioPulse);
        const midAlpha = isEditedCell ? (0.10 + cellPulse * 0.02) : isSel ? 0.10 : (0.040 + 0.005 * bioPulse);
        grad.addColorStop(0, `rgba(${rR}, ${rG}, ${rB}, ${innerAlpha.toFixed(3)})`);
        grad.addColorStop(0.7, `rgba(${rR}, ${rG}, ${rB}, ${midAlpha.toFixed(3)})`);
        grad.addColorStop(1, `rgba(${rR}, ${rG}, ${rB}, 0.015)`);
        ctx.fillStyle = grad;
        ctx.fill();
      }

      ctx.save();
      if (isEditedCell && editHex && !isDenseProject) {
        ctx.shadowColor = editHex;
        ctx.shadowBlur = 10 + cellPulse * 3;
      }
      ctx.lineWidth = Math.min(3.4, Math.max(1.2, isEditedCell ? 2.3 : isSel ? 2.4 : 1.5));
      ctx.strokeStyle = isSel
        ? 'rgba(56, 189, 248, 0.90)'
        : isEditedCell
          ? `rgba(${lR}, ${lG}, ${lB}, ${(0.76 + cellPulse * 0.12).toFixed(2)})`
          : `rgba(${lR}, ${lG}, ${lB}, 0.44)`;
      ctx.stroke();
      ctx.restore();

      // 2. Living Inner Phospholipid Bilayer Cortex (cohérence de phase harmonique douce)
      if (baseR >= 26 && (!isDenseProject || isSel || isEditedCell)) {
        this.traceMembraneSpline(ctx, center.x, center.y, baseR * 0.88, cl.lobeProfile, breathPhase, folderPhase + 0.35);
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${isEditedCell ? 0.065 : isSel ? 0.05 : 0.022})`;
        ctx.fill();
        ctx.lineWidth = isEditedCell ? 1.2 : 0.9;
        ctx.strokeStyle = `rgba(${lR}, ${lG}, ${lB}, ${isEditedCell ? 0.48 : isSel ? 0.35 : 0.18})`;
        ctx.stroke();
      }

      // 3. LoD 2 Nucleus Core (cohérence de phase harmonique douce)
      if ((this.state.lodLevel === 2 || isSel || isEditedCell) && baseR >= 45 && (!isDenseProject || isSel || isEditedCell)) {
        const nucR = Math.max(12, baseR * 0.20);
        this.traceMembraneSpline(ctx, center.x, center.y, nucR, undefined, breathPhase, folderPhase + 0.60);
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${isEditedCell ? 0.22 : isSel ? 0.20 : 0.10})`;
        ctx.fill();
        ctx.lineWidth = 1.0;
        ctx.strokeStyle = `rgba(${lR}, ${lG}, ${lB}, ${isEditedCell ? 0.55 : 0.30})`;
        ctx.stroke();
      }

      if (isSel || isEditedCell || (this.state.settings.showFolderBadges && this.state.settings.showFolderTitles && cl.count >= 3 && rawR >= 9)) {
        badges.push({
          folder,
          label: formatFolderLabel(folder),
          count: cl.count,
          cx: center.x,
          topY: topCrestY,
          rgb: `${lR}, ${lG}, ${lB}`,
          sel: isSel,
          editLabel: folderEdit?.label,
          editHex,
        });
      }
    });

    badges.sort((a, b) => {
      if (a.sel !== b.sel) return a.sel ? -1 : 1;
      if (Boolean(a.editHex) !== Boolean(b.editHex)) return a.editHex ? -1 : 1;
      return b.count - a.count;
    });
    this.renderFolderBadges(ctx, badges);
    ctx.restore();
  }

  private renderFolderBadges(
    ctx: CanvasRenderingContext2D,
    badges: {
      folder: string;
      label: string;
      count: number;
      cx: number;
      topY: number;
      rgb: string;
      sel: boolean;
      editLabel?: string;
      editHex?: string;
    }[]
  ) {
    if (badges.length === 0) return;
    ctx.font = '600 11px ui-sans-serif, system-ui, -apple-system, sans-serif';
    ctx.textBaseline = 'middle';

    const maxDraw = this.state.isLowMemoryMode ? Math.min(badges.length, 24) : Math.min(badges.length, 42);
    for (let i = 0; i < maxDraw; i++) {
      const b = badges[i];
      const text = b.editLabel ? `${b.label} · ${b.editLabel}` : `${b.label}`;
      const countText = `${b.count}`;
      const textW = ctx.measureText(text).width;
      const countW = ctx.measureText(countText).width;
      const pillW = textW + countW + 26;
      const pillH = 20;
      const pillX = b.cx - pillW * 0.5;
      const pillY = b.topY - pillH - 8;
      if (
        !b.sel &&
        !b.editHex &&
        this.folderPillBounds.some(
          (p) => Math.abs(p.x + p.w * 0.5 - b.cx) < (p.w + pillW) * 0.48 && Math.abs(p.y - pillY) < 22
        )
      ) {
        continue;
      }
      this.folderPillBounds.push({ folder: b.folder, x: pillX, y: pillY, w: pillW, h: pillH });

      const strokeCol = b.sel ? '#38bdf8' : b.editHex ? b.editHex : `rgba(${b.rgb}, 0.55)`;

      // Tether line from cellular crest to pill badge
      ctx.beginPath();
      ctx.moveTo(b.cx, b.topY);
      ctx.lineTo(b.cx, pillY + pillH);
      ctx.strokeStyle = strokeCol;
      ctx.lineWidth = b.editHex ? 1.3 : 1.0;
      ctx.stroke();

      ctx.save();
      if (b.editHex) {
        ctx.shadowColor = b.editHex;
        ctx.shadowBlur = 8;
      }
      ctx.fillStyle = b.sel ? 'rgba(12, 74, 110, 0.92)' : b.editHex ? 'rgba(15, 19, 32, 0.94)' : 'rgba(11, 14, 23, 0.86)';
      ctx.strokeStyle = strokeCol;
      ctx.lineWidth = b.editHex ? 1.3 : 1.0;
      ctx.beginPath();
      ctx.roundRect(pillX, pillY, pillW, pillH, 6);
      ctx.fill();
      ctx.stroke();
      ctx.restore();

      ctx.fillStyle = b.editHex ? '#ffffff' : '#e2e8f0';
      ctx.textAlign = 'left';
      ctx.fillText(text, pillX + 8, pillY + pillH * 0.5);

      ctx.fillStyle = b.editHex || `rgba(${b.rgb}, 0.95)`;
      ctx.textAlign = 'right';
      ctx.fillText(countText, pillX + pillW - 7, pillY + pillH * 0.5);
    }
  }

  private getRelationVisual(rel: string, isViolation: boolean, isDbTarget: boolean, isIncoming: boolean) {
    if (rel === 'warns') return { color: '#f97316', dashed: true, tag: 'MAX LIGNES' };
    if (isViolation) return { color: '#f87171', dashed: false, tag: 'SAST' };
    if (rel === 'submits') return { color: '#ff7a18', dashed: false, tag: 'FORM' };
    if (rel === 'network') return { color: '#22d3ee', dashed: false, tag: 'NET' };
    if (rel === 'realtime') return { color: '#34d399', dashed: false, tag: 'WS' };
    if (rel === 'queries' || isDbTarget) return { color: '#c084fc', dashed: false, tag: 'DATA' };
    if (rel === 'imports' || rel === 'inherits' || rel === 'contains') {
      const tag = rel === 'inherits' ? 'EXTENDS' : rel === 'contains' ? 'MEMBRE' : 'IMPORT';
      return { color: '#fbbf24', dashed: true, tag };
    }
    return isIncoming
      ? { color: '#34d399', dashed: false, tag: '← APPEL' }
      : { color: '#38bdf8', dashed: false, tag: '➔ APPEL' };
  }

  private drawEdgeArrow(
    ctx: CanvasRenderingContext2D,
    tipX: number,
    tipY: number,
    angle: number,
    size: number,
    fillColor: string,
    alpha = 0.85
  ) {
    const spread = 0.42;
    ctx.save();
    ctx.globalAlpha = alpha;
    ctx.beginPath();
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(tipX - Math.cos(angle - spread) * size, tipY - Math.sin(angle - spread) * size);
    ctx.lineTo(tipX - Math.cos(angle) * size * 0.66, tipY - Math.sin(angle) * size * 0.66);
    ctx.lineTo(tipX - Math.cos(angle + spread) * size, tipY - Math.sin(angle + spread) * size);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
    ctx.restore();
  }

  private isSmallFunctionCulled(n: SymbolBubble, activeId: string | null): boolean {
    if (n.id === activeId || n.id === this.hoveredNodeId) return false;
    const alertKind = getNodeAlertKind(n, this.isAnomalyIgnored);
    if (alertKind === 'security' || alertKind === 'lines_exceeded') return false;
    const { isFunction } = this.classifyNode(n);
    if (!isFunction) return false;

    const lod = this.state.lodLevel;
    if (lod === 1) return true;
    if (lod === 2) {
      const cc = n.cyclomatic_complexity || 1;
      const isHugeProject = this.state.graph.nodes.length > 1500;
      if (isHugeProject && cc < 5) return true;
    }
    return false;
  }

  private renderEdges(ctx: CanvasRenderingContext2D, now: number) {
    const edges = this.state.graph.edges;
    if (!edges || edges.length === 0) return;

    const isEco = this.state.isLowMemoryMode;
    const activeId = this.state.activeSymbol?.id || null;
    const focusId = this.hoveredNodeId || activeId;
    const isHoverFocus = Boolean(this.hoveredNodeId);
    const isXray = this.state.visionMode === 'xray' && this.state.activeSymbol;
    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const disabledRelations = this.state.disabledRelations;
    const pipe = this.state.pipelineHighlight;
    const zoom = this.camera.zoom;

    const pCalls = new Path2D();
    const pImports = new Path2D();
    const pQueries = new Path2D();
    const pViolates = new Path2D();
    const pWarns = new Path2D();
    const pRealtime = new Path2D();
    const pNetwork = new Path2D();
    const pSubmits = new Path2D();
    let hasCalls = false, hasImports = false, hasQueries = false, hasViolates = false, hasWarns = false, hasRealtime = false, hasNetwork = false, hasSubmits = false;
    const pulseParticles: { x: number; y: number; color: string }[] = [];
    const midChevrons: { x: number; y: number; angle: number; color: string }[] = [];
    const functionStars = new Map<string, { x: number; y: number; colorRgb: { r: number; g: number; b: number } }>();
    const focusEdges: {
      sourceNode: SymbolBubble;
      targetNode: SymbolBubble;
      p1: { x: number; y: number };
      p2: { x: number; y: number };
      cx: number | null;
      cy: number | null;
      rel: string;
      isViolation: boolean;
      isIncoming: boolean;
    }[] = [];

    const isHuge = edges.length > 3500 || this.state.graph.nodes.length > 2200;
    const edgeCap = isHuge
      ? (zoom < 0.25 ? (isEco ? 900 : 1400) : (isEco ? 1400 : 2200))
      : 2600;

    // 1. Process incident edges for the focused/hovered node directly (O(deg) via index)
    if (focusId) {
      const incident = this.state.incidentEdges(focusId);
      const maxFocusEdges = 48;
      // Prioritize semantic calls/imports/data/security edges before structural `contains`
      const orderedIncident = incident.length > maxFocusEdges
        ? [...incident].sort((a, b) => {
            const ra = normalizeEdgeRelation(a.relation || a.edge_type) === 'contains' ? 1 : 0;
            const rb = normalizeEdgeRelation(b.relation || b.edge_type) === 'contains' ? 1 : 0;
            return ra - rb;
          })
        : incident;
      for (let k = 0; k < orderedIncident.length && focusEdges.length < maxFocusEdges; k++) {
        const e = orderedIncident[k];
        const s = this.nodeMap.get(e.source);
        const t = this.nodeMap.get(e.target);
        if (!s || !t) continue;
        if (!this.state.settings.showCweBubbles && (getNodeAlertKind(s, this.isAnomalyIgnored) === 'security' || getNodeAlertKind(t, this.isAnomalyIgnored) === 'security')) continue;
        if (disabledLayers[s.layer || 'utility'] || disabledLayers[t.layer || 'utility']) continue;
        if (disabledModules[s.folder || s.cluster_id || 'root'] || disabledModules[t.folder || t.cluster_id || 'root']) continue;

        const rel = normalizeEdgeRelation(e.relation || e.edge_type);
        if (disabledRelations[rel]) continue;

        const p1 = this.worldToScreen(s.x, s.y);
        const p2 = this.worldToScreen(t.x, t.y);
        const sFolder = s.folder || s.cluster_id;
        const tFolder = t.folder || t.cluster_id;
        const isCross = Boolean(sFolder && tFolder && sFolder !== tFolder);
        const isCurved = isCross && rel !== 'contains';
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const cx = isCurved ? (p1.x + p2.x) * 0.5 - dy * 0.13 : null;
        const cy = isCurved ? (p1.y + p2.y) * 0.5 + dx * 0.13 : null;

        const isWarnEdge =
          rel === 'warns' ||
          e.severity === 'WARNING' ||
          Boolean(e.cve_id && e.cve_id.includes('ARCH-BUDGET-EXCEEDED'));
        const isViolEdge = !isWarnEdge && (rel === 'violates' || Boolean(e.cve_id));

        focusEdges.push({
          sourceNode: s,
          targetNode: t,
          p1,
          p2,
          cx,
          cy,
          rel: isWarnEdge ? 'warns' : rel,
          isViolation: isViolEdge,
          isIncoming: e.target === focusId && e.source !== focusId,
        });

        if (this.isSmallFunctionCulled(s, activeId) && !functionStars.has(s.id)) {
          const col = getFolderColor(sFolder || 'root');
          functionStars.set(s.id, {
            x: p1.x,
            y: p1.y,
            colorRgb: { r: Math.round(col.r * 255), g: Math.round(col.g * 255), b: Math.round(col.b * 255) },
          });
        }
        if (this.isSmallFunctionCulled(t, activeId) && !functionStars.has(t.id)) {
          const col = getFolderColor(tFolder || 'root');
          functionStars.set(t.id, {
            x: p2.x,
            y: p2.y,
            colorRgb: { r: Math.round(col.r * 255), g: Math.round(col.g * 255), b: Math.round(col.b * 255) },
          });
        }
      }
    }

    // 2. Sample background edges up to edgeCap (never starve semantic calls/imports behind `contains`)
    const maxBackground = edgeCap;
    let drawnCount = 0;
    const stride = isHuge ? Math.max(1, Math.floor(edges.length / (edgeCap * 2))) : 1;

    for (let i = 0; i < edges.length && drawnCount < maxBackground; i += stride) {
      const e = edges[i];
      if (focusId && (e.source === focusId || e.target === focusId)) continue;
      if (isXray && e.source !== activeId && e.target !== activeId) continue;

      const rel = normalizeEdgeRelation(e.relation || e.edge_type);
      if (disabledRelations[rel]) continue;
      // At zoomed-out macro views, skip internal file->symbol `contains` spokes so `calls` and `imports` stay 100% visible
      if (rel === 'contains' && zoom < 0.35) continue;

      const s = this.nodeMap.get(e.source);
      const t = this.nodeMap.get(e.target);
      if (!s || !t) continue;
      if (!this.state.settings.showCweBubbles && (getNodeAlertKind(s, this.isAnomalyIgnored) === 'security' || getNodeAlertKind(t, this.isAnomalyIgnored) === 'security')) continue;
      if (disabledLayers[s.layer || 'utility'] || disabledLayers[t.layer || 'utility']) continue;
      if (disabledModules[s.folder || s.cluster_id || 'root'] || disabledModules[t.folder || t.cluster_id || 'root']) continue;

      const p1 = this.worldToScreen(s.x, s.y);
      const p2 = this.worldToScreen(t.x, t.y);
      if (
        Math.max(p1.x, p2.x) < -60 ||
        Math.min(p1.x, p2.x) > this.logicalWidth + 60 ||
        Math.max(p1.y, p2.y) < -60 ||
        Math.min(p1.y, p2.y) > this.logicalHeight + 60
      ) {
        continue;
      }
      drawnCount++;

      const sFolder = s.folder || s.cluster_id;
      const tFolder = t.folder || t.cluster_id;

      if (this.isSmallFunctionCulled(s, activeId) && !functionStars.has(s.id)) {
        const col = getFolderColor(sFolder || 'root');
        functionStars.set(s.id, {
          x: p1.x,
          y: p1.y,
          colorRgb: { r: Math.round(col.r * 255), g: Math.round(col.g * 255), b: Math.round(col.b * 255) },
        });
      }
      if (this.isSmallFunctionCulled(t, activeId) && !functionStars.has(t.id)) {
        const col = getFolderColor(tFolder || 'root');
        functionStars.set(t.id, {
          x: p2.x,
          y: p2.y,
          colorRgb: { r: Math.round(col.r * 255), g: Math.round(col.g * 255), b: Math.round(col.b * 255) },
        });
      }

      const isCross = Boolean(sFolder && tFolder && sFolder !== tFolder);
      const isCurved = isCross && rel !== 'contains';
      const dx = p2.x - p1.x;
      const dy = p2.y - p1.y;
      const dist = Math.hypot(dx, dy);
      const cx = isCurved ? (p1.x + p2.x) * 0.5 - dy * 0.14 : null;
      const cy = isCurved ? (p1.y + p2.y) * 0.5 + dx * 0.14 : null;

      const isWarnEdge =
        rel === 'warns' ||
        e.severity === 'WARNING' ||
        Boolean(e.cve_id && e.cve_id.includes('ARCH-BUDGET-EXCEEDED'));
      const isViolEdge = !isWarnEdge && (rel === 'violates' || Boolean(e.cve_id));

      let targetPath = pCalls;
      if (isWarnEdge) { targetPath = pWarns; hasWarns = true; }
      else if (isViolEdge) { targetPath = pViolates; hasViolates = true; }
      else if (rel === 'submits') { targetPath = pSubmits; hasSubmits = true; }
      else if (rel === 'network') { targetPath = pNetwork; hasNetwork = true; }
      else if (rel === 'realtime') { targetPath = pRealtime; hasRealtime = true; }
      else if (rel === 'queries' || t.layer === 'database') { targetPath = pQueries; hasQueries = true; }
      else if (rel === 'imports' || rel === 'contains' || rel === 'inherits') { targetPath = pImports; hasImports = true; }
      else { hasCalls = true; }

      targetPath.moveTo(p1.x, p1.y);
      if (this.edgeStyle === 'orthogonal_pcb') {
        const adx = Math.abs(dx);
        const ady = Math.abs(dy);
        if (adx >= ady) {
          const diag = Math.min(ady, adx * 0.45);
          const sx = dx >= 0 ? 1 : -1;
          const sy = dy >= 0 ? 1 : -1;
          const elbowX = p1.x + sx * (adx - diag) * 0.5;
          targetPath.lineTo(elbowX, p1.y);
          targetPath.lineTo(elbowX + sx * diag, p1.y + sy * diag);
          targetPath.lineTo(p2.x, p2.y);
        } else {
          const diag = Math.min(adx, ady * 0.45);
          const sx = dx >= 0 ? 1 : -1;
          const sy = dy >= 0 ? 1 : -1;
          const elbowY = p1.y + sy * (ady - diag) * 0.5;
          targetPath.lineTo(p1.x, elbowY);
          targetPath.lineTo(p1.x + sx * diag, elbowY + sy * diag);
          targetPath.lineTo(p2.x, p2.y);
        }
        if (pulseParticles.length < 28 && (isXray || pipe || i % 9 === 0)) {
          const u = ((now * 0.00028 * this.edgePulseSpeed + i * 0.17) % 1 + 1) % 1;
          pulseParticles.push({
            x: p1.x + dx * u,
            y: p1.y + dy * u,
            color: isWarnEdge ? '#fb923c' : isViolEdge ? '#f87171' : rel === 'realtime' ? '#34d399' : rel === 'queries' ? '#c084fc' : rel === 'imports' ? '#fbbf24' : '#38bdf8',
          });
        }
      } else if (this.edgeStyle === 'bezier' && isCurved && cx !== null && cy !== null) {
        targetPath.quadraticCurveTo(cx, cy, p2.x, p2.y);

        if (pulseParticles.length < 28 && (isXray || pipe || i % 9 === 0)) {
          const u = ((now * 0.00028 * this.edgePulseSpeed + i * 0.17) % 1 + 1) % 1;
          const inv = 1 - u;
          pulseParticles.push({
            x: inv * inv * p1.x + 2 * inv * u * cx + u * u * p2.x,
            y: inv * inv * p1.y + 2 * inv * u * cy + u * u * p2.y,
            color: isWarnEdge ? '#fb923c' : isViolEdge ? '#f87171' : rel === 'realtime' ? '#34d399' : rel === 'queries' ? '#c084fc' : rel === 'imports' ? '#fbbf24' : '#38bdf8',
          });
        }
      } else {
        targetPath.lineTo(p2.x, p2.y);
      }

      // Directional chevrons on visible call, import & data links (always visible across zoom levels so direction is clear)
      if (rel !== 'contains' && dist >= 34 && midChevrons.length < 150 && (isCross || zoom >= 0.30)) {
        const u = 0.62;
        const inv = 1 - u;
        const mx = isCurved && cx !== null && cy !== null
          ? inv * inv * p1.x + 2 * inv * u * cx + u * u * p2.x
          : p1.x + dx * u;
        const my = isCurved && cx !== null && cy !== null
          ? inv * inv * p1.y + 2 * inv * u * cy + u * u * p2.y
          : p1.y + dy * u;
        // True curve tangent at u for accurate arrow orientation
        const tx = isCurved && cx !== null ? 2 * inv * (cx - p1.x) + 2 * u * (p2.x - cx) : dx;
        const ty = isCurved && cy !== null ? 2 * inv * (cy - p1.y) + 2 * u * (p2.y - cy) : dy;
        midChevrons.push({
          x: mx,
          y: my,
          angle: Math.atan2(ty, tx),
          color: isViolEdge
            ? 'rgba(248, 113, 113, 0.78)'
            : isWarnEdge
              ? 'rgba(251, 146, 60, 0.75)'
              : rel === 'imports' || rel === 'inherits'
                ? 'rgba(251, 191, 36, 0.72)'
                : rel === 'queries'
                  ? 'rgba(192, 132, 252, 0.75)'
                  : rel === 'realtime'
                    ? 'rgba(52, 211, 153, 0.75)'
                    : 'rgba(56, 189, 248, 0.72)',
        });
      }
    }

    ctx.save();
    ctx.lineCap = 'round';
    const w = Math.max(0.75, Math.min(1.65, 1.0 * Math.sqrt(zoom)));
    const zoomFade = zoom < 0.06 ? Math.max(0.58, zoom * 10.0) : 1.0;
    const bgDim = (isHoverFocus && focusEdges.length > 0 ? 0.45 : 1.0) * zoomFade;

    if (hasImports) {
      ctx.lineWidth = Math.max(0.8, w * 0.9);
      ctx.setLineDash([5, 4]);
      ctx.strokeStyle = `rgba(251, 191, 36, ${(pipe ? 0.12 : 0.28) * bgDim})`;
      ctx.stroke(pImports);
      ctx.setLineDash([]);
    }
    if (hasCalls) {
      ctx.lineWidth = Math.max(0.9, w);
      ctx.strokeStyle = `rgba(56, 189, 248, ${(isXray ? 0.62 : pipe ? 0.12 : 0.32) * bgDim})`;
      ctx.stroke(pCalls);
    }
    if (hasSubmits) {
      ctx.lineWidth = pipe ? w * 1.9 : w * 1.25;
      ctx.strokeStyle = `rgba(255, 107, 0, ${(pipe ? 0.85 : 0.48) * bgDim})`;
      ctx.stroke(pSubmits);
    }
    if (hasNetwork) {
      ctx.lineWidth = pipe ? w * 1.9 : w * 1.25;
      ctx.strokeStyle = `rgba(0, 200, 255, ${(pipe ? 0.88 : 0.48) * bgDim})`;
      ctx.stroke(pNetwork);
    }
    if (hasQueries) {
      ctx.lineWidth = pipe ? w * 1.9 : w * 1.2;
      ctx.strokeStyle = `rgba(168, 85, 247, ${(pipe ? 0.88 : 0.46) * bgDim})`;
      ctx.stroke(pQueries);
    }
    if (hasRealtime) {
      ctx.lineWidth = pipe ? w * 1.9 : w * 1.25;
      ctx.strokeStyle = `rgba(52, 211, 153, ${(pipe ? 0.90 : 0.50) * bgDim})`;
      ctx.stroke(pRealtime);
    }
    if (hasWarns) {
      ctx.lineWidth = w * 1.25;
      ctx.setLineDash([5, 4]);
      ctx.strokeStyle = `rgba(249, 115, 22, ${0.55 * bgDim})`;
      ctx.stroke(pWarns);
      ctx.setLineDash([]);
    }
    if (hasViolates) {
      ctx.lineWidth = w * 1.3;
      ctx.strokeStyle = `rgba(239, 68, 68, ${0.58 * bgDim})`;
      ctx.stroke(pViolates);
    }
    for (let i = 0; i < midChevrons.length; i++) {
      const ch = midChevrons[i];
      this.drawEdgeArrow(ctx, ch.x, ch.y, ch.angle, 5.8, ch.color, 0.82);
    }
    if (pulseParticles.length > 0) {
      ctx.save();
      ctx.globalAlpha = isXray || pipe ? 0.85 : 0.72;
      for (let i = 0; i < pulseParticles.length; i++) {
        const pt = pulseParticles[i];
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, isXray || pipe ? 2.2 : 1.7, 0, Math.PI * 2);
        ctx.fillStyle = pt.color;
        ctx.fill();
      }
      ctx.restore();
    }

    // Highlighted directional links, arrowheads & relation badges (`➔ APPEL`, `← APPEL`, `IMPORT`) for hovered or active node
    if (focusEdges.length > 0) {
      const showPillLabels = focusEdges.length <= 28;
      const placedTagBoxes: { x: number; y: number; w: number; h: number }[] = [];
      const neighborSet = new Map<string, { node: SymbolBubble; p: { x: number; y: number }; color: string }>();

      for (let i = 0; i < focusEdges.length; i++) {
        const fe = focusEdges[i];
        const dist = Math.hypot(fe.p2.x - fe.p1.x, fe.p2.y - fe.p1.y);
        if (dist < 4) continue;

        const meta = this.getRelationVisual(fe.rel, fe.isViolation, fe.targetNode.layer === 'database', fe.isIncoming);
        const tangentX = fe.cx !== null ? fe.p2.x - fe.cx : fe.p2.x - fe.p1.x;
        const tangentY = fe.cy !== null ? fe.p2.y - fe.cy : fe.p2.y - fe.p1.y;
        const tLen = Math.hypot(tangentX, tangentY) || 1;
        const angle = Math.atan2(tangentY, tangentX);

        const targetR = this.getNodeScreenRadius(fe.targetNode, activeId);
        const tipOffset = Math.min(dist * 0.45, Math.max(7, targetR * 0.42 + 4));
        const tipX = fe.p2.x - (tangentX / tLen) * tipOffset;
        const tipY = fe.p2.y - (tangentY / tLen) * tipOffset;

        ctx.save();
        ctx.globalAlpha = isHoverFocus ? 0.90 : 0.74;
        ctx.strokeStyle = meta.color;
        ctx.lineWidth = isHoverFocus ? Math.max(1.4, w * 1.45) : Math.max(1.15, w * 1.2);
        if (isHoverFocus) {
          ctx.shadowColor = meta.color;
          ctx.shadowBlur = 5;
        }
        if (meta.dashed) ctx.setLineDash([5, 4]);
        ctx.beginPath();
        ctx.moveTo(fe.p1.x, fe.p1.y);
        if (this.edgeStyle === 'orthogonal_pcb') {
          const fdx = fe.p2.x - fe.p1.x;
          const fdy = fe.p2.y - fe.p1.y;
          const adx = Math.abs(fdx);
          const ady = Math.abs(fdy);
          const sx = fdx >= 0 ? 1 : -1;
          const sy = fdy >= 0 ? 1 : -1;
          if (adx >= ady) {
            const diag = Math.min(ady, adx * 0.45);
            const ex = fe.p1.x + sx * (adx - diag) * 0.5;
            ctx.lineTo(ex, fe.p1.y);
            ctx.lineTo(ex + sx * diag, fe.p1.y + sy * diag);
            ctx.lineTo(fe.p2.x, fe.p2.y);
          } else {
            const diag = Math.min(adx, ady * 0.45);
            const ey = fe.p1.y + sy * (ady - diag) * 0.5;
            ctx.lineTo(fe.p1.x, ey);
            ctx.lineTo(fe.p1.x + sx * diag, ey + sy * diag);
            ctx.lineTo(fe.p2.x, fe.p2.y);
          }
        } else if (this.edgeStyle === 'bezier' && fe.cx !== null && fe.cy !== null) {
          ctx.quadraticCurveTo(fe.cx, fe.cy, fe.p2.x, fe.p2.y);
        } else {
          ctx.lineTo(fe.p2.x, fe.p2.y);
        }
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.restore();

        // Crisp directional arrowhead pointing caller -> callee / importer -> imported
        this.drawEdgeArrow(ctx, tipX, tipY, angle, isHoverFocus ? 8.5 : 7.2, meta.color, isHoverFocus ? 0.95 : 0.85);

        // Flow bead traveling in call/import direction (source -> target)
        const u = ((now * 0.00072 + i * 0.21) % 1 + 1) % 1;
        const inv = 1 - u;
        const bx = fe.cx !== null && fe.cy !== null
          ? inv * inv * fe.p1.x + 2 * inv * u * fe.cx + u * u * fe.p2.x
          : fe.p1.x + (fe.p2.x - fe.p1.x) * u;
        const by = fe.cx !== null && fe.cy !== null
          ? inv * inv * fe.p1.y + 2 * inv * u * fe.cy + u * u * fe.p2.y
          : fe.p1.y + (fe.p2.y - fe.p1.y) * u;
        ctx.save();
        ctx.globalAlpha = isHoverFocus ? 0.92 : 0.78;
        ctx.beginPath();
        ctx.arc(bx, by, isHoverFocus ? 2.3 : 1.9, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.fill();
        ctx.restore();

        if (fe.sourceNode.id !== focusId && !neighborSet.has(fe.sourceNode.id)) {
          neighborSet.set(fe.sourceNode.id, { node: fe.sourceNode, p: fe.p1, color: meta.color });
        }
        if (fe.targetNode.id !== focusId && !neighborSet.has(fe.targetNode.id)) {
          neighborSet.set(fe.targetNode.id, { node: fe.targetNode, p: fe.p2, color: meta.color });
        }

        if (showPillLabels && fe.rel !== 'contains' && dist >= 58) {
          const mx = fe.cx !== null && fe.cy !== null
            ? 0.25 * fe.p1.x + 0.5 * fe.cx + 0.25 * fe.p2.x
            : (fe.p1.x + fe.p2.x) * 0.5;
          const my = fe.cx !== null && fe.cy !== null
            ? 0.25 * fe.p1.y + 0.5 * fe.cy + 0.25 * fe.p2.y
            : (fe.p1.y + fe.p2.y) * 0.5;
          ctx.font = '700 8.5px ui-monospace, monospace';
          const tw = ctx.measureText(meta.tag).width + 8;
          const th = 14;
          const tx = mx - tw * 0.5;
          const ty = my - 7;
          const overlaps = placedTagBoxes.some(
            (b) => tx < b.x + b.w + 3 && tx + tw + 3 > b.x && ty < b.y + b.h + 2 && ty + th + 2 > b.y
          );
          if (!overlaps) {
            placedTagBoxes.push({ x: tx, y: ty, w: tw, h: th });
            ctx.fillStyle = 'rgba(7, 10, 18, 0.90)';
            ctx.beginPath();
            ctx.roundRect(tx, ty, tw, th, 4);
            ctx.fill();
            ctx.strokeStyle = meta.color;
            ctx.lineWidth = 0.85;
            ctx.stroke();
            ctx.fillStyle = meta.color;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(meta.tag, mx, my + 0.5);
          }
        }
      }

      // Ring & label connected peers on hover even if overall zoom hides normal labels
      if (isHoverFocus) {
        ctx.font = '600 9.5px ui-monospace, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        for (const item of neighborSet.values()) {
          ctx.beginPath();
          ctx.arc(item.p.x, item.p.y, Math.max(9, this.getNodeScreenRadius(item.node, activeId) * 0.55 + 4), 0, Math.PI * 2);
          ctx.strokeStyle = item.color;
          ctx.lineWidth = 1.4;
          ctx.stroke();
          if (zoom < 0.55) {
            ctx.fillStyle = item.color;
            ctx.fillText(item.node.name, item.p.x, item.p.y - 12);
          }
        }
      }
    }

    // 3. Luminous micro-stars / glowing bubbles for small functions at edge endpoints (no lines in void)
    if (functionStars.size > 0) {
      const starR = Math.max(1.8, Math.min(2.8, 1.8 * Math.sqrt(zoom)));

      for (const star of functionStars.values()) {
        const { x, y, colorRgb } = star;

        // Outer soft glowing halo (diffuse nebula around the micro-bubble)
        ctx.beginPath();
        ctx.arc(x, y, starR * 2.3, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${colorRgb.r}, ${colorRgb.g}, ${colorRgb.b}, 0.28)`;
        ctx.fill();

        // Inner glowing core
        ctx.beginPath();
        ctx.arc(x, y, starR, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${Math.min(255, colorRgb.r + 90)}, ${Math.min(255, colorRgb.g + 90)}, ${Math.min(255, colorRgb.b + 90)}, 0.95)`;
        ctx.fill();

        // Brilliant central stellar spark
        ctx.beginPath();
        ctx.arc(x, y, starR * 0.45, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.fill();

        // Subtle diamond cross spark glint when zoomed in
        if (!isEco && zoom >= 0.75) {
          const sparkLen = starR * 2.0;
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.45)';
          ctx.lineWidth = 0.75;
          ctx.beginPath();
          ctx.moveTo(x - sparkLen, y);
          ctx.lineTo(x + sparkLen, y);
          ctx.moveTo(x, y - sparkLen);
          ctx.lineTo(x, y + sparkLen);
          ctx.stroke();
        }
      }
    }

    ctx.restore();
  }

  private renderLabels(ctx: CanvasRenderingContext2D) {
    this.labelBounds = [];
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return;
    const zoom = this.camera.zoom;
    const isXray = this.state.visionMode === 'xray' && this.activeNeighbors.size > 0;
    const activeId = this.state.activeSymbol?.id;
    const focusId = activeId || this.hoveredNodeId;

    // Fast exit if zoomed out and no node is hovered or active
    if (!focusId && zoom < 0.30) return;

    const maxLen = this.state.settings.maxLabelLength || 18;
    const hideDense = this.state.settings.hideBubbleLabelsOver20;
    const denseLimit = this.state.settings.clusterLabelThreshold || 20;

    ctx.save();
    ctx.font = '500 10.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textAlign = 'center';

    let drawn = 0;
    const isHuge = nodes.length > 2000;
    const maxDraw = isHuge ? 85 : 220;
    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    for (let i = 0; i < nodes.length && drawn < maxDraw; i++) {
      const n = nodes[i];
      if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;
      const isFocus = n.id === activeId || n.id === this.hoveredNodeId;
      if (!this.state.settings.showFileTitles && !isFocus) continue;
      if (!this.state.settings.showCweBubbles && getNodeAlertKind(n, this.isAnomalyIgnored) === 'security') continue;
      if (isXray && !this.activeNeighbors.has(n.id)) continue;
      if (!isFocus && zoom < 0.30) continue;
      if (!isFocus && zoom < 0.55 && !n.is_file && !n.is_class) continue;

      if (!isFocus && hideDense) {
        const cl = this.clusters.get(n.folder || n.cluster_id || 'root');
        if (cl && cl.count > denseLimit) continue;
      }

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -40 || p.x > this.logicalWidth + 40 || p.y < -20 || p.y > this.logicalHeight + 20) {
        continue;
      }

      const rawName = n.name || '';
      const displayName = !isFocus && rawName.length > maxLen ? rawName.slice(0, maxLen - 2) + '..' : rawName;
      const ly = p.y + Math.max(14, 22 * zoom);
      const tw = ctx.measureText(displayName).width;
      ctx.fillStyle = isFocus ? '#38bdf8' : 'rgba(226, 232, 240, 0.88)';
      ctx.fillText(displayName, p.x, ly);
      this.labelBounds.push({ x: p.x - tw * 0.5, y: ly - 10, w: tw, h: 13 });
      drawn++;
    }
    ctx.restore();
  }

  public destroy() {
    this.isDestroyed = true;
    if (this.state.engine === this) {
      this.state.engine = null;
    }
    window.removeEventListener('resize', this.resizeHandler);
    if (this.pointerMoveHandler) {
      window.removeEventListener('pointermove', this.pointerMoveHandler);
      this.pointerMoveHandler = null;
    }
    if (this.pointerUpHandler) {
      window.removeEventListener('pointerup', this.pointerUpHandler);
      window.removeEventListener('pointercancel', this.pointerUpHandler);
      this.pointerUpHandler = null;
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    if (this.dprMediaQuery && this.dprListener) {
      this.dprMediaQuery.removeEventListener('change', this.dprListener);
      this.dprMediaQuery = null;
      this.dprListener = null;
    }
    if (this.contextLostHandler) {
      this.canvas.removeEventListener('webglcontextlost', this.contextLostHandler);
      this.contextLostHandler = null;
    }
    if (this.animationFrameId !== null) {
      cancelAnimationFrame(this.animationFrameId);
    }
    this.physics.destroy();
  }
}
