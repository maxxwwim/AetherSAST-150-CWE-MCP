// =========================================================================
// AETHERSCOPE V2 — HIGH-PERFORMANCE WEBGL 2 ENGINE (engine.ts)
// 120 FPS Celestial Spatial Graph Engine, Cellular Membranes & Laser Optics
// =========================================================================

import {
  initShaderPipeline,
  initBackdropPipeline,
  type ShaderPipeline,
  type BackdropPipeline
} from './shaders';
import { PhysicsController, type FolderClusterEntry } from './physics';
import { getLayerRgba, getFolderColor, formatFolderLabel, SEVERITY_COLORS, type RgbaColor } from './palette';
import { normalizeEdgeRelation, getNodeAlertKind, isLinesExceededAnomaly, type CockpitState } from '../state/graphState.svelte';
import { playSpatialTone } from '../lib/sound';
import type { SymbolBubble } from '../types/graph';

// Precomputed 12-sector trigonometric tables for C1-continuous cellular membranes
const _COS12 = new Float32Array(12);
const _SIN12 = new Float32Array(12);
for (let i = 0; i < 12; i++) {
  const a = (i / 12) * Math.PI * 2;
  _COS12[i] = Math.cos(a);
  _SIN12[i] = Math.sin(a);
}

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
  private lastFitTick = 0;
  private lastFocusTick = 0;
  private lastSnapshotTick = 0;
  private lastFilterVersion = 0;
  private hoveredNodeId: string | null = null;
  private hoveredFolder: string | null = null;
  private selectedFolder: string | null = null;
  private hasInitialCameraFit = false;
  private folderPillBounds: { folder: string; x: number; y: number; w: number; h: number }[] = [];

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

    this.setupPhysicsListener();
    this.handleResize();
    this.setupMouseEvents();

    this.state.engine = this;

    if (this.state.graph.nodes.length > 0) {
      this.syncGraphToEngine();
    }
  }

  private setupPhysicsListener() {
    this.physics.onUpdate = (positions: Float32Array, rawClusters?: Record<string, any>) => {
      const nodes = this.state.graph.nodes;
      const count = Math.min(nodes.length, Math.floor(positions.length / 2));

      for (let i = 0; i < count; i++) {
        nodes[i].x = positions[i * 2];
        nodes[i].y = positions[i * 2 + 1];

        if (this.instanceData.length >= (i + 1) * 10) {
          this.instanceData[i * 10 + 0] = nodes[i].x;
          this.instanceData[i * 10 + 1] = nodes[i].y;
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
            entry.cx = cl.cx;
            entry.cy = cl.cy;
            entry.sumX = cl.sumX;
            entry.sumY = cl.sumY;
            entry.count = cl.count;
            entry.computedRadius = cl.computedRadius;
            entry.naturalRadius = cl.naturalRadius;
            if (cl.lobeProfile) {
              if (entry.lobeProfile.length !== 12) {
                entry.lobeProfile = new Float32Array(cl.lobeProfile);
              } else {
                entry.lobeProfile.set(cl.lobeProfile);
              }
            }
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

  private classifyNode(n: SymbolBubble): { shaderType: number; baseRadius: number } {
    const kind = String(n.kind || n.symbol_type || '').toLowerCase();
    const isFunc =
      kind === 'function' ||
      kind === 'method' ||
      n.stereotype === '«Function»' ||
      n.stereotype === '«Method»';
    if (isFunc) return { shaderType: 0.0, baseRadius: 4.6 };
    if (n.is_file || kind === 'file') return { shaderType: 1.0, baseRadius: 13.0 };
    if (n.is_class || kind === 'class' || kind === 'struct' || kind === 'interface' || kind === 'trait') {
      return { shaderType: 2.0, baseRadius: 14.5 };
    }
    if (n.is_form || kind === 'endpoint' || n.stereotype === '«Endpoint»' || n.stereotype === '«Form»') {
      return { shaderType: 3.0, baseRadius: 12.0 };
    }
    return { shaderType: 1.0, baseRadius: 9.5 };
  }

  private seedInitialClusters(nodes: SymbolBubble[]) {
    const buckets = new Map<string, SymbolBubble[]>();
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const folder = n.folder || n.cluster_id || 'root';
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
    if (!nodes || this.instanceData.length < nodes.length * 10) return;

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const offset = i * 10;
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

    const floatCount = nodes.length * 10;
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

      const offset = i * 10;
      const { shaderType, baseRadius } = this.classifyNode(n);

      this.instanceData[offset + 0] = n.x;
      this.instanceData[offset + 1] = n.y;
      this.instanceData[offset + 2] = baseRadius;
      this.instanceData[offset + 7] = shaderType;
      this.instanceData[offset + 8] = n.birth_time;
      this.instanceData[offset + 9] = this.getNodeGitShaderVal(n);
    }

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

    const spanX = Math.max(400, maxX - minX);
    const spanY = Math.max(400, maxY - minY);
    const fitZoom = Math.max(
      0.04,
      Math.min(1.1, Math.min(this.logicalWidth / (spanX + 240), this.logicalHeight / (spanY + 240)))
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

  public refreshVisionColors(upload = true) {
    const nodes = this.state.graph.nodes;
    if (!nodes || this.instanceData.length < nodes.length * 10) return;

    const mode = this.state.visionMode;
    const activeId = this.state.activeSymbol?.id || null;
    const lod = this.state.lodLevel;
    const disabledLayers = this.state.disabledLayers;
    this.lastVisionMode = mode;
    this.lastActiveSymbolId = activeId;
    this.lastLodLevel = lod;
    this.lastFilterVersion = this.state.filterVersion;

    this.activeNeighbors.clear();
    if (mode === 'xray' && activeId) {
      this.activeNeighbors.add(activeId);
      for (const e of this.state.graph.edges) {
        if (e.source === activeId) this.activeNeighbors.add(e.target);
        if (e.target === activeId) this.activeNeighbors.add(e.source);
      }
    }

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const offset = i * 10;
      const { baseRadius } = this.classifyNode(n);
      const folder = n.folder || n.cluster_id || 'root';
      let col: RgbaColor = lod <= 2 ? getFolderColor(folder) : getLayerRgba(n.layer);
      let alpha = 1.0;
      let r = baseRadius;

      if (n.id === activeId) r *= 1.65;
      else if (n.id === this.hoveredNodeId) r *= 1.35;

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

      const alertKind = getNodeAlertKind(n);
      if (alertKind === 'security' && mode === 'standard') {
        col = SEVERITY_COLORS.CRITICAL;
        r *= 1.3;
      } else if (alertKind === 'lines_exceeded' && mode === 'standard') {
        col = SEVERITY_COLORS.HIGH;
        r *= 1.18;
      }

      if (disabledLayers[n.layer || 'utility'] || this.state.disabledModules[folder]) {
        alpha = 0.035;
        r *= 0.42;
      }

      let gitStatusVal = 0.0;
      if (n.git_status === 'modified') gitStatusVal = 1.0;
      else if (n.git_status === 'untracked') gitStatusVal = 2.0;
      else if (n.git_status === 'violation') gitStatusVal = 3.0;

      this.instanceData[offset + 2] = r;
      this.instanceData[offset + 3] = col.r;
      this.instanceData[offset + 4] = col.g;
      this.instanceData[offset + 5] = col.b;
      this.instanceData[offset + 6] = alpha;
      this.instanceData[offset + 9] = gitStatusVal;
    }

    if (upload) {
      this.uploadInstanceSubData();
    }
  }

  public handleResize() {
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
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
    const clampedZoom = Math.max(0.04, Math.min(5.0, this.camera.targetZoom * factor));
    const focalWorld = this.screenToWorld(sx, sy);
    this.camera.targetZoom = clampedZoom;
    this.camera.targetX = focalWorld.x - (sx - this.logicalWidth / 2) / clampedZoom;
    this.camera.targetY = focalWorld.y - (sy - this.logicalHeight / 2) / clampedZoom;
    this.physics.wake(60);
  }

  public zoomIn(factor = 1.25) {
    this.zoomAtScreenPoint(factor, this.logicalWidth / 2, this.logicalHeight / 2);
  }

  public zoomOut(factor = 0.8) {
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
    const zoomFactor = Math.max(0.85, Math.min(4.5, 1.0 / Math.sqrt(Math.max(0.001, Math.min(5.0, zoom)))));
    const { baseRadius } = this.classifyNode(n);
    const scaleMult = n.id === activeId ? 1.65 : n.id === this.hoveredNodeId ? 1.35 : 1.0;
    const rawR = baseRadius * scaleMult * 2.85 * zoomFactor * zoom;
    return Math.max(2.0, rawR);
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
      const zoomFactor = Math.exp(-normalizedDelta * 0.0018);
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
          const newTargetZoom = Math.max(0.04, Math.min(5.0, this.initialPinchZoom * scale));
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
    const loop = (now: number) => {
      if (this.isDestroyed) return;
      const dt = now - lastTime;
      lastTime = now;
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

      if (this.lastLodLevel !== this.state.lodLevel) {
        this.physics.setDepth(this.state.lodLevel);
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
      this.render(now);

      if (this.lastSnapshotTick !== this.state.snapshotRequestTick) {
        this.lastSnapshotTick = this.state.snapshotRequestTick;
        this.captureSnapshot();
      }

      this.animationFrameId = requestAnimationFrame(loop);
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  private updateCamera(dt: number) {
    const factor = 1 - Math.exp(-14.0 * (dt / 1000));
    this.camera.x += (this.camera.targetX - this.camera.x) * factor;
    this.camera.y += (this.camera.targetY - this.camera.y) * factor;
    this.camera.zoom += (this.camera.targetZoom - this.camera.zoom) * factor;
  }

  private render(now: number) {
    const { gl, pipeline, backdropPipeline } = this;

    // 0. Cosmic Space, Ethereal Nebula & Parallax Stellar Starfield Backdrop
    gl.clearColor(0.018, 0.024, 0.048, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.disable(gl.BLEND);
    gl.useProgram(backdropPipeline.program);
    gl.uniform2f(backdropPipeline.uniforms.uRes, this.gl.drawingBufferWidth, this.gl.drawingBufferHeight);
    gl.uniform2f(backdropPipeline.uniforms.uCam, this.camera.x, this.camera.y);
    gl.uniform1f(backdropPipeline.uniforms.uZoom, this.camera.zoom);
    gl.uniform1f(backdropPipeline.uniforms.uTime, now);
    gl.bindVertexArray(backdropPipeline.vao);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    gl.bindVertexArray(null);

    // 1. WebGL 2 Instanced Living Celestial Bubbles (uRes in logical CSS pixels)
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    gl.useProgram(pipeline.program);
    gl.uniform2f(pipeline.uniforms.uRes, this.logicalWidth, this.logicalHeight);
    gl.uniform2f(pipeline.uniforms.uCam, this.camera.x, this.camera.y);
    gl.uniform1f(pipeline.uniforms.uZoom, this.camera.zoom);
    gl.uniform1f(pipeline.uniforms.uTime, now);

    const nodes = this.state.graph.nodes;
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
    this.renderGitDiffBadges(ctx, now);
    this.renderSecurityBeacons(ctx, now);
    this.renderAiAgentOverlay(ctx, now);
    this.renderLabels(ctx);
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

    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const zoom = this.camera.zoom;

    ctx.save();
    ctx.font = '700 9.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'center';

    let drawn = 0;
    for (let i = 0; i < nodes.length && drawn < 96; i++) {
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

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -80 || p.x > this.logicalWidth + 80 || p.y < -80 || p.y > this.logicalHeight + 80) continue;

      let badgeText = '';
      let ringHex = '#facc15';
      let strokeColor = '';
      let fillColor = '';
      let textColor = '';

      if (ek === 'modif') {
        badgeText = n.is_file ? '✏️ FICHIER MODIFIÉ' : '✏️ MODIF';
        ringHex = '#facc15';
        strokeColor = 'rgba(250, 204, 21, 0.95)';
        fillColor = 'rgba(38, 28, 6, 0.92)';
        textColor = '#fef08a';
      } else if (ek === 'text') {
        badgeText = '📝 TEXTE / DOC';
        ringHex = '#22d3ee';
        strokeColor = 'rgba(34, 211, 238, 0.95)';
        fillColor = 'rgba(6, 32, 44, 0.92)';
        textColor = '#a5f3fc';
      } else if (ek === 'new_file') {
        badgeText = n.is_file ? '✨ NOUVEAU FICHIER' : '✨ +SYMBOLE';
        ringHex = '#34d399';
        strokeColor = 'rgba(52, 211, 153, 0.95)';
        fillColor = 'rgba(6, 36, 24, 0.92)';
        textColor = '#a7f3d0';
      } else if (ek === 'new_folder') {
        badgeText = '📁✨ +DOSSIER';
        ringHex = '#c084fc';
        strokeColor = 'rgba(192, 132, 252, 0.95)';
        fillColor = 'rgba(32, 12, 48, 0.92)';
        textColor = '#e9d5ff';
      } else if (ek === 'violation') {
        badgeText = '🚨 FAILLE ÉDIT';
        ringHex = '#ef4444';
        strokeColor = 'rgba(239, 68, 68, 0.95)';
        fillColor = 'rgba(45, 10, 10, 0.95)';
        textColor = '#fecaca';
      } else {
        continue;
      }

      const baseR = n.is_file || n.is_class ? 16 : 11;
      const screenR = Math.max(10, baseR * Math.sqrt(Math.max(0.22, zoom)));
      const pulse = 0.5 + 0.5 * Math.sin(now * 0.0008 + i * 0.7);
      const isRecent = Boolean(n.last_edit_ts && now - n.last_edit_ts < 15000);

      // 1. Calm, Steady Bioluminescent Bubble Corona Ring (no rapid spinning or strobing)
      ctx.save();
      ctx.beginPath();
      ctx.arc(p.x, p.y, screenR + 5 + pulse * 1.2, 0, Math.PI * 2);
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = isRecent ? 2.0 : 1.4;
      ctx.shadowColor = ringHex;
      ctx.shadowBlur = isRecent ? 10 : 6;
      ctx.globalAlpha = isRecent ? 0.88 : 0.70;
      ctx.stroke();
      ctx.restore();

      const isFocus = n.id === this.hoveredNodeId || n.id === this.state.activeSymbol?.id;
      if (!isFocus && !isRecent && zoom < 0.28 && !n.is_file) {
        drawn++;
        continue;
      }

      const tw = ctx.measureText(badgeText).width + 10;
      const hasSec = Boolean(n.has_security_violation || (n.anomalies && n.anomalies.length > 0) || (n.violations && n.violations.length > 0));
      const by = hasSec ? p.y + screenR + 6 : p.y - screenR - 18;
      const bx = p.x - tw * 0.5;

      ctx.fillStyle = fillColor;
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 1.1;
      ctx.shadowColor = ringHex;
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.roundRect(bx, by, tw, 15, 4);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = textColor;
      ctx.shadowBlur = 0;
      ctx.fillText(badgeText, p.x, by + 7.5);

      drawn++;
    }

    ctx.restore();
  }

  private renderSecurityBeacons(ctx: CanvasRenderingContext2D, now: number) {
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return;

    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const zoom = this.camera.zoom;

    ctx.save();
    ctx.font = '700 9.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textBaseline = 'middle';

    let drawn = 0;
    for (let i = 0; i < nodes.length && drawn < 48; i++) {
      const n = nodes[i];
      if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;
      const alertKind = getNodeAlertKind(n);
      if (alertKind === 'none') continue;
      const isLinesWarn = alertKind === 'lines_exceeded';
      const anom = n.anomalies || [];

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -50 || p.x > this.logicalWidth + 50 || p.y < -50 || p.y > this.logicalHeight + 50) continue;

      // Calm, slow breathing aura (crimson for security, orange for exceeded lines)
      const gentleBreath = 0.5 + 0.5 * Math.sin(now * 0.0014 + i * 0.45);
      const baseR = n.is_file || n.is_class ? 16 : 11;
      const ringR = Math.max(11, baseR * Math.sqrt(Math.max(0.25, zoom)) + gentleBreath * 2.0);

      // Soft ambient outer halo
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR + 4, 0, Math.PI * 2);
      ctx.fillStyle = isLinesWarn
        ? `rgba(249, 115, 22, ${(0.07 + gentleBreath * 0.05).toFixed(3)})`
        : `rgba(239, 68, 68, ${(0.06 + gentleBreath * 0.05).toFixed(3)})`;
      ctx.fill();

      // Steady inner ring
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
      ctx.strokeStyle = isLinesWarn
        ? `rgba(251, 146, 60, ${(0.62 + gentleBreath * 0.24).toFixed(2)})`
        : `rgba(248, 113, 113, ${(0.52 + gentleBreath * 0.24).toFixed(2)})`;
      ctx.lineWidth = 1.35;
      ctx.stroke();

      // Alert pill on files, focused/hovered nodes, or when zoomed in (steady position, legible)
      const isFocus = n.id === this.hoveredNodeId || n.id === this.state.activeSymbol?.id;
      if (isFocus || n.is_file || zoom >= 0.42) {
        let shortTag: string;
        if (isLinesWarn) {
          const maxLim = n.metadata?.max_lines_limit || 300;
          const curLoc = n.loc || n.metadata?.lines || 0;
          shortTag = curLoc > 0 ? `⚠️ ${curLoc}/${maxLim} L` : '⚠️ LIGNES MAX';
        } else {
          const primary = anom.find((a) => !isLinesExceededAnomaly(a)) || anom[0];
          const tagText = primary ? `🚨 ${primary.cve_id || primary.rule_id || 'CWE'}` : '🚨 SAST CWE';
          shortTag = tagText.length > 18 ? tagText.slice(0, 17) + '…' : tagText;
        }
        const tw = ctx.measureText(shortTag).width + 10;
        const fixedOffset = Math.max(12, baseR * Math.sqrt(Math.max(0.25, zoom)) + 4);
        const bx = p.x - tw * 0.5;
        const by = p.y - fixedOffset - 16;

        ctx.fillStyle = isLinesWarn ? 'rgba(124, 45, 18, 0.92)' : 'rgba(127, 29, 29, 0.90)';
        ctx.strokeStyle = isLinesWarn ? 'rgba(251, 146, 60, 0.88)' : 'rgba(248, 113, 113, 0.85)';
        ctx.lineWidth = 1.0;
        ctx.beginPath();
        ctx.roundRect(bx, by, tw, 15, 4);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = isLinesWarn ? '#fed7aa' : '#fecaca';
        ctx.textAlign = 'center';
        ctx.fillText(shortTag, p.x, by + 7.5);
      }
      drawn++;
    }
    ctx.restore();
  }

  private renderAiAgentOverlay(ctx: CanvasRenderingContext2D, now: number) {
    const agents = this.state.activeAgents;
    const trails = this.state.agentTrails;
    if (!agents || agents.length === 0) return;

    ctx.save();
    const zoom = this.camera.zoom;

    // Count agents per target node for orbital distribution
    const agentsByNode = new Map<string, number>();
    agents.forEach((ag) => {
      const targetId = ag.nodeId;
      if (targetId) {
        agentsByNode.set(targetId, (agentsByNode.get(targetId) || 0) + 1);
      }
    });

    const nodeAgentCounter = new Map<string, number>();

    // 3D inclined celestial orbit constants:
    // Tilt alpha = 35° (0.6108 rad), inclination psi = 25° (0.4363 rad)
    const TILT_ALPHA = 0.610865;
    const INCLINATION_PSI = 0.436332;
    const cosAlpha = Math.cos(TILT_ALPHA);
    const cosPsi = Math.cos(INCLINATION_PSI);
    const sinPsi = Math.sin(INCLINATION_PSI);
    const omega = 0.0018;

    for (let idx = 0; idx < agents.length; idx++) {
      const ag = agents[idx];
      let agColor = ag.color || '#c084fc';
      const agNameLower = (ag.agentName || ag.agentId || '').toLowerCase();
      if (agNameLower.includes('claude')) agColor = '#f97316';
      else if (agNameLower.includes('gemini')) agColor = '#38bdf8';
      else if (agNameLower.includes('cursor')) agColor = '#10b981';

      // 1. Trail path rendering
      const agTrail = trails[ag.agentId] || [];
      if (this.state.settings.aiTrail && agTrail.length > 1) {
        ctx.beginPath();
        let started = false;
        for (const pt of agTrail) {
          const node = pt.nodeId ? this.nodeMap.get(pt.nodeId) : null;
          const wx = node ? node.x : pt.x;
          const wy = node ? node.y : pt.y;
          if (wx == null || wy == null) continue;
          const s = this.worldToScreen(wx, wy);
          if (!started) {
            ctx.moveTo(s.x, s.y);
            started = true;
          } else {
            ctx.lineTo(s.x, s.y);
          }
        }
        ctx.setLineDash([6, 5]);
        ctx.lineDashOffset = -(now * 0.018);
        ctx.strokeStyle = agColor;
        ctx.globalAlpha = 0.55;
        ctx.lineWidth = Math.max(1.2, 1.8 * Math.sqrt(zoom));
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1.0;
      }

      // 2. Resolve target bubble position in world space (X_N, Y_N)
      let targetNode: SymbolBubble | undefined;
      if (ag.nodeId) {
        targetNode = this.nodeMap.get(ag.nodeId);
      }
      if (!targetNode && ag.target) {
        targetNode = this.state.resolveTargetNode(ag.target);
      }
      if (!targetNode) continue;

      const totalOnNode = agentsByNode.get(targetNode.id) || 1;
      const subIdx = nodeAgentCounter.get(targetNode.id) || 0;
      nodeAgentCounter.set(targetNode.id, subIdx + 1);

      // Phase spacing for agents orbiting the same node
      const phiAgent = (subIdx / totalOnNode) * (Math.PI * 2) + (idx * 0.618);
      const theta = (now * omega) + phiAgent;

      // 3. Orbit radius in world space: R_orbit = R_node * 2.85 + 24.0
      const { baseRadius } = this.classifyNode(targetNode);
      const orbitR = baseRadius * 2.85 + 24.0;

      // 3D celestial coordinates calculation in world space:
      // In orbital plane: x_plane = R * cos(theta), y_plane = R * sin(theta)
      // Tilt alpha = 35° around X-axis: x1 = x_plane, y1 = y_plane * cos(alpha)
      // Inclination psi = 25° in (x, y) plane:
      // x_rot = x1 * cos(psi) - y1 * sin(psi)
      // y_rot = x1 * sin(psi) + y1 * cos(psi)
      const xPlane = orbitR * Math.cos(theta);
      const yPlane = orbitR * Math.sin(theta) * cosAlpha;
      const xRot = xPlane * cosPsi - yPlane * sinPsi;
      const yRot = xPlane * sinPsi + yPlane * cosPsi;

      const xOrbWorld = targetNode.x + xRot;
      const yOrbWorld = targetNode.y + yRot;

      // 4. Smoothly project to screen coordinates using worldToScreen
      const pOrb = this.worldToScreen(xOrbWorld, yOrbWorld);
      const pNode = this.worldToScreen(targetNode.x, targetNode.y);

      // Culling
      if (
        pOrb.x < -120 || pOrb.x > this.logicalWidth + 120 ||
        pOrb.y < -120 || pOrb.y > this.logicalHeight + 120
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
        y: pNode.y - (dy / len) * impactDist
      };

      // 5. Multi-Pass Connecting Laser Beam from avatar to target bubble surface:
      // Pass 1: Diffused colored glow aura (lineWidth = 3.5 * Math.sqrt(zoom), globalAlpha = 0.35)
      ctx.beginPath();
      ctx.moveTo(pOrb.x, pOrb.y);
      ctx.lineTo(pImpact.x, pImpact.y);
      ctx.strokeStyle = agColor;
      ctx.lineWidth = Math.max(1.8, 3.5 * Math.sqrt(zoom));
      ctx.shadowColor = agColor;
      ctx.shadowBlur = 10;
      ctx.globalAlpha = 0.35;
      ctx.stroke();

      // Pass 2: High-intensity inner white laser core (lineWidth = 1.2, globalAlpha = 0.95)
      ctx.beginPath();
      ctx.moveTo(pOrb.x, pOrb.y);
      ctx.lineTo(pImpact.x, pImpact.y);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.2;
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = 4;
      ctx.globalAlpha = 0.95;
      ctx.stroke();

      // Pass 3: 3 traveling photon beads animated along the vector
      ctx.shadowColor = agColor;
      ctx.shadowBlur = 6;
      for (let b = 0; b < 3; b++) {
        const u = ((now * 0.0024 + b * 0.333) % 1.0 + 1.0) % 1.0;
        const bx = pOrb.x + (pImpact.x - pOrb.x) * u;
        const by = pOrb.y + (pImpact.y - pOrb.y) * u;
        ctx.beginPath();
        ctx.arc(bx, by, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.globalAlpha = 0.95;
        ctx.fill();
      }

      // Pass 4: Concentric circular scanning reticle on bubble surface with animated rotation
      const reticleAngle = now * 0.0035 + idx;
      const reticleRadius = Math.max(5, Math.min(14, 6 * Math.sqrt(Math.max(0.3, zoom))));
      ctx.save();
      ctx.translate(pImpact.x, pImpact.y);
      ctx.rotate(reticleAngle);

      ctx.beginPath();
      ctx.arc(0, 0, reticleRadius, 0, Math.PI * 2);
      ctx.strokeStyle = agColor;
      ctx.lineWidth = 1.2;
      ctx.globalAlpha = 0.85;
      ctx.shadowColor = agColor;
      ctx.shadowBlur = 5;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(0, 0, reticleRadius + 3.5, 0, Math.PI * 1.3);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.0;
      ctx.globalAlpha = 0.75;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(0, 0, reticleRadius + 3.5, Math.PI * 1.5, Math.PI * 1.8);
      ctx.strokeStyle = agColor;
      ctx.lineWidth = 1.0;
      ctx.stroke();
      ctx.restore();

      // 6. Stellar Avatar Orb at (pOrb.x, pOrb.y):
      // Layer 2: Colored luminous corona (radius 9px, glowing radial gradient)
      const coronaGrad = ctx.createRadialGradient(pOrb.x, pOrb.y, 1, pOrb.x, pOrb.y, 16);
      coronaGrad.addColorStop(0, '#ffffff');
      coronaGrad.addColorStop(0.35, agColor);
      coronaGrad.addColorStop(0.70, `${agColor}55`);
      coronaGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = coronaGrad;
      ctx.globalAlpha = 0.90;
      ctx.beginPath();
      ctx.arc(pOrb.x, pOrb.y, 16, 0, Math.PI * 2);
      ctx.fill();

      // Layer 3: Spinning accretion ring / halo with animated rotation angle
      const haloR = 9.0 + Math.sin(now * 0.0032 + idx) * 1.5;
      ctx.save();
      ctx.translate(pOrb.x, pOrb.y);
      ctx.rotate(now * 0.003 + idx * 1.2);
      ctx.beginPath();
      ctx.ellipse(0, 0, haloR, haloR * 0.45, 0, 0, Math.PI * 2);
      ctx.strokeStyle = agColor;
      ctx.lineWidth = 1.4;
      ctx.shadowColor = agColor;
      ctx.shadowBlur = 8;
      ctx.globalAlpha = 0.90;
      ctx.stroke();
      ctx.restore();

      // Layer 1: White-hot core nucleus (radius 4.5px, #ffffff)
      ctx.beginPath();
      ctx.arc(pOrb.x, pOrb.y, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = 8;
      ctx.globalAlpha = 1.0;
      ctx.fill();

      // 7. Billboard Badge floating above cursor (pOrb.x, pOrb.y - 18)
      const agentIcon = agNameLower.includes('claude') ? '✨'
        : agNameLower.includes('gemini') ? '⚡'
        : agNameLower.includes('cursor') ? '🎯'
        : '🤖';
      const agentCleanName = ag.agentName || ag.agentId || 'Agent';
      const actionText = ag.action || 'Auditing AST';
      const tagText = `${agentIcon} ${agentCleanName} · ${actionText}`;

      ctx.font = '600 10px ui-sans-serif, system-ui, -apple-system, sans-serif';
      const tw = ctx.measureText(tagText).width + 16;
      const badgeH = 19;
      const badgeY = pOrb.y - 18;

      // Glassmorphic pill badge
      ctx.fillStyle = 'rgba(10, 14, 26, 0.90)';
      ctx.strokeStyle = agColor;
      ctx.lineWidth = 1.1;
      ctx.shadowColor = agColor;
      ctx.shadowBlur = 6;
      ctx.globalAlpha = 0.95;
      ctx.beginPath();
      ctx.roundRect(pOrb.x - tw * 0.5, badgeY - badgeH * 0.5, tw, badgeH, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#f8fafc';
      ctx.shadowBlur = 0;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(tagText, pOrb.x, badgeY + 0.5);
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
    const ptsX = new Float32Array(12);
    const ptsY = new Float32Array(12);
    for (let i = 0; i < 12; i++) {
      const prof = lobeProfile && lobeProfile[i] ? lobeProfile[i] : 1.0;
      // Ondulation amiboïde organique fluide (membrane lipidique vivante)
      const harmonic =
        1.0 +
        0.034 * Math.sin(breathPhase * 1.35 + phaseShift + i * 1.57) +
        0.018 * Math.cos(breathPhase * 0.90 - phaseShift * 0.75 + i * 2.62);
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
      const folder = n.folder || n.cluster_id || 'root';
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
        // Exponential temporal smoothing prevents any frame-to-frame jitter or snapping
        const alpha = 0.12;
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
    if (!this.state.settings.showFolderMembranes || this.state.visionMode === 'xray' || this.clusters.size === 0) return;

    ctx.save();
    const breathPhase = now * 0.00075;
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
      const center = this.worldToScreen(cl.cx, cl.cy);
      const baseR = (cl.computedRadius || 100) * this.camera.zoom;

      if (
        center.x + baseR < -60 ||
        center.x - baseR > this.logicalWidth + 60 ||
        center.y + baseR < -60 ||
        center.y - baseR > this.logicalHeight + 60
      ) {
        return;
      }

      const col = getFolderColor(folder);
      let rR = Math.round(col.r * 255);
      let rG = Math.round(col.g * 255);
      let rB = Math.round(col.b * 255);
      let lR = Math.min(255, rR + 85);
      let lG = Math.min(255, rG + 85);
      let lB = Math.min(255, rB + 100);
      const isSel = folder === this.selectedFolder || folder === this.hoveredFolder;
      const folderPhase = (rR * 0.03 + rG * 0.07) % 6.28;

      const folderEdit = this.state.folderEdits?.[folder];
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

      const isEditedCell = Boolean(folderEdit && folderEdit.count > 0);
      const cellPulse = isEditedCell ? 0.5 + 0.5 * Math.sin(now * 0.00075 + folderPhase) : 0;

      // 1. Living Outer Cytoplasmic Membrane with soft radial gradient (illuminated when edited)
      const topCrestY = this.traceMembraneSpline(ctx, center.x, center.y, baseR, cl.lobeProfile, breathPhase, folderPhase);
      const grad = ctx.createRadialGradient(center.x, center.y, Math.max(4, baseR * 0.15), center.x, center.y, Math.max(12, baseR * 1.15));
      const bioPulse = 0.5 + 0.5 * Math.sin(now * 0.0012 + folderPhase);
      const innerAlpha = isEditedCell ? (0.16 + cellPulse * 0.04) : isSel ? 0.16 : (0.075 + 0.022 * bioPulse);
      const midAlpha = isEditedCell ? (0.10 + cellPulse * 0.025) : isSel ? 0.10 : 0.04;
      grad.addColorStop(0, `rgba(${rR}, ${rG}, ${rB}, ${innerAlpha.toFixed(3)})`);
      grad.addColorStop(0.7, `rgba(${rR}, ${rG}, ${rB}, ${midAlpha.toFixed(3)})`);
      grad.addColorStop(1, `rgba(${rR}, ${rG}, ${rB}, 0.015)`);
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.save();
      if (isEditedCell && editHex) {
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

      // 2. Living Inner Phospholipid Bilayer Cortex (breathing out-of-phase)
      if (baseR >= 26) {
        this.traceMembraneSpline(ctx, center.x, center.y, baseR * 0.88, cl.lobeProfile, breathPhase * 0.88, folderPhase + 2.1);
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${isEditedCell ? 0.065 : isSel ? 0.05 : 0.022})`;
        ctx.fill();
        ctx.lineWidth = isEditedCell ? 1.2 : 0.9;
        ctx.strokeStyle = `rgba(${lR}, ${lG}, ${lB}, ${isEditedCell ? 0.48 : isSel ? 0.35 : 0.18})`;
        ctx.stroke();
      }

      // 3. LoD 2 Nucleus Core
      if ((this.state.lodLevel === 2 || isSel || isEditedCell) && baseR >= 45) {
        const nucR = Math.max(12, baseR * 0.20);
        this.traceMembraneSpline(ctx, center.x, center.y, nucR, undefined, breathPhase * 1.25, 1.1);
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${isEditedCell ? 0.22 : isSel ? 0.20 : 0.10})`;
        ctx.fill();
        ctx.lineWidth = 1.0;
        ctx.strokeStyle = `rgba(${lR}, ${lG}, ${lB}, ${isEditedCell ? 0.55 : 0.30})`;
        ctx.stroke();
      }

      if (isSel || isEditedCell || (this.state.settings.showFolderBadges && cl.count >= 4 && baseR >= 34)) {
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

    const maxDraw = Math.min(badges.length, 36);
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
    fillColor: string
  ) {
    const spread = 0.44;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(tipX - Math.cos(angle - spread) * size, tipY - Math.sin(angle - spread) * size);
    ctx.lineTo(tipX - Math.cos(angle + spread) * size * 0.72, tipY - Math.sin(angle + spread) * size * 0.72);
    ctx.lineTo(tipX - Math.cos(angle + spread) * size, tipY - Math.sin(angle + spread) * size);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.shadowColor = fillColor;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.restore();
  }

  private renderEdges(ctx: CanvasRenderingContext2D, now: number) {
    const edges = this.state.graph.edges;
    if (!edges || edges.length === 0) return;

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

    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      const isIncident = Boolean(focusId && (e.source === focusId || e.target === focusId));
      if (!isIncident && i >= 2200) continue;
      if (isXray && e.source !== activeId && e.target !== activeId && !isIncident) continue;

      const s = this.nodeMap.get(e.source);
      const t = this.nodeMap.get(e.target);
      if (!s || !t) continue;
      if (disabledLayers[s.layer || 'utility'] || disabledLayers[t.layer || 'utility']) continue;
      if (disabledModules[s.folder || s.cluster_id || 'root'] || disabledModules[t.folder || t.cluster_id || 'root']) continue;

      const rel = normalizeEdgeRelation(e.relation || e.edge_type);
      if (disabledRelations[rel]) continue;

      const p1 = this.worldToScreen(s.x, s.y);
      const p2 = this.worldToScreen(t.x, t.y);
      if (
        !isIncident &&
        (Math.max(p1.x, p2.x) < -60 ||
          Math.min(p1.x, p2.x) > this.logicalWidth + 60 ||
          Math.max(p1.y, p2.y) < -60 ||
          Math.min(p1.y, p2.y) > this.logicalHeight + 60)
      ) {
        continue;
      }

      const sFolder = s.folder || s.cluster_id;
      const tFolder = t.folder || t.cluster_id;
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

      if (isIncident && focusEdges.length < 64) {
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
      }

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
      if (isCurved && cx !== null && cy !== null) {
        targetPath.quadraticCurveTo(cx, cy, p2.x, p2.y);

        if (pulseParticles.length < 48 && (isXray || pipe || i % 7 === 0)) {
          const u = ((now * 0.00032 + i * 0.17) % 1 + 1) % 1;
          const inv = 1 - u;
          pulseParticles.push({
            x: inv * inv * p1.x + 2 * inv * u * cx + u * u * p2.x,
            y: inv * inv * p1.y + 2 * inv * u * cy + u * u * p2.y,
            color: isWarnEdge ? '#fb923c' : isViolEdge ? '#f87171' : rel === 'realtime' ? '#34d399' : rel === 'queries' ? '#c084fc' : '#38bdf8',
          });
        }
      } else {
        targetPath.lineTo(p2.x, p2.y);
      }

      // Subtle mid-edge directional chevrons on visible non-focus call/data edges when zoomed in
      if (!focusId && zoom >= 1.15 && dist >= 44 && midChevrons.length < 180) {
        const mx = isCurved && cx !== null && cy !== null ? 0.25 * p1.x + 0.5 * cx + 0.25 * p2.x : (p1.x + p2.x) * 0.5;
        const my = isCurved && cx !== null && cy !== null ? 0.25 * p1.y + 0.5 * cy + 0.25 * p2.y : (p1.y + p2.y) * 0.5;
        midChevrons.push({
          x: mx,
          y: my,
          angle: Math.atan2(dy, dx),
          color: rel === 'imports' ? 'rgba(251, 191, 36, 0.55)' : rel === 'queries' ? 'rgba(192, 132, 252, 0.65)' : 'rgba(56, 189, 248, 0.55)',
        });
      }
    }

    ctx.save();
    ctx.lineCap = 'round';
    const w = Math.max(0.75, Math.min(2.0, 1.15 * Math.sqrt(zoom)));
    const zoomFade = zoom < 0.08 ? Math.max(0.12, zoom * 12.5) : 1.0;
    const bgDim = (isHoverFocus && focusEdges.length > 0 ? 0.45 : 1.0) * zoomFade;

    if (hasImports) {
      ctx.lineWidth = w * 0.85;
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = `rgba(245, 158, 11, ${(pipe ? 0.08 : 0.16) * bgDim})`;
      ctx.stroke(pImports);
      ctx.setLineDash([]);
    }
    if (hasCalls) {
      ctx.lineWidth = w;
      ctx.strokeStyle = `rgba(56, 189, 248, ${(isXray ? 0.58 : pipe ? 0.08 : 0.19) * bgDim})`;
      ctx.stroke(pCalls);
    }
    if (hasSubmits) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.4;
      ctx.strokeStyle = `rgba(255, 107, 0, ${(pipe ? 0.85 : 0.45) * bgDim})`;
      ctx.stroke(pSubmits);
    }
    if (hasNetwork) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.4;
      ctx.strokeStyle = `rgba(0, 200, 255, ${(pipe ? 0.88 : 0.45) * bgDim})`;
      ctx.stroke(pNetwork);
    }
    if (hasQueries) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.3;
      ctx.strokeStyle = `rgba(168, 85, 247, ${(pipe ? 0.88 : 0.45) * bgDim})`;
      ctx.stroke(pQueries);
    }
    if (hasRealtime) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.35;
      ctx.strokeStyle = `rgba(52, 211, 153, ${(pipe ? 0.90 : 0.48) * bgDim})`;
      ctx.stroke(pRealtime);
    }
    if (hasWarns) {
      ctx.lineWidth = w * 1.45;
      ctx.setLineDash([5, 4]);
      ctx.strokeStyle = `rgba(249, 115, 22, ${0.68 * bgDim})`;
      ctx.stroke(pWarns);
      ctx.setLineDash([]);
    }
    if (hasViolates) {
      ctx.lineWidth = w * 1.55;
      ctx.strokeStyle = `rgba(239, 68, 68, ${0.65 * bgDim})`;
      ctx.stroke(pViolates);
    }
    for (let i = 0; i < midChevrons.length; i++) {
      const ch = midChevrons[i];
      this.drawEdgeArrow(ctx, ch.x, ch.y, ch.angle, 6.5, ch.color);
    }
    for (let i = 0; i < pulseParticles.length; i++) {
      const pt = pulseParticles[i];
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, isXray || pipe ? 2.6 : 1.9, 0, Math.PI * 2);
      ctx.fillStyle = pt.color;
      ctx.fill();
    }

    // Highlighted directional links, arrowheads & relation badges for hovered or active node
    if (focusEdges.length > 0) {
      const showPillLabels = isHoverFocus && focusEdges.length <= 16;
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
        const tipOffset = Math.min(dist * 0.45, Math.max(8, targetR * 0.42 + 5));
        const tipX = fe.p2.x - (tangentX / tLen) * tipOffset;
        const tipY = fe.p2.y - (tangentY / tLen) * tipOffset;

        ctx.save();
        ctx.strokeStyle = meta.color;
        ctx.lineWidth = isHoverFocus ? Math.max(1.8, w * 1.75) : Math.max(1.4, w * 1.35);
        ctx.shadowColor = meta.color;
        ctx.shadowBlur = isHoverFocus ? 10 : 5;
        if (meta.dashed) ctx.setLineDash([6, 4]);
        ctx.beginPath();
        ctx.moveTo(fe.p1.x, fe.p1.y);
        if (fe.cx !== null && fe.cy !== null) {
          ctx.quadraticCurveTo(fe.cx, fe.cy, fe.p2.x, fe.p2.y);
        } else {
          ctx.lineTo(fe.p2.x, fe.p2.y);
        }
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.restore();

        // Directional arrowhead pointing caller -> callee / importer -> imported / source -> data
        this.drawEdgeArrow(ctx, tipX, tipY, angle, isHoverFocus ? 10.5 : 8.5, meta.color);

        // Animated flow bead traveling strictly in call direction (source -> target)
        const u = ((now * 0.00095 + i * 0.21) % 1 + 1) % 1;
        const inv = 1 - u;
        const bx = fe.cx !== null && fe.cy !== null
          ? inv * inv * fe.p1.x + 2 * inv * u * fe.cx + u * u * fe.p2.x
          : fe.p1.x + (fe.p2.x - fe.p1.x) * u;
        const by = fe.cx !== null && fe.cy !== null
          ? inv * inv * fe.p1.y + 2 * inv * u * fe.cy + u * u * fe.p2.y
          : fe.p1.y + (fe.p2.y - fe.p1.y) * u;
        ctx.beginPath();
        ctx.arc(bx, by, 3.0, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.fill();

        if (fe.sourceNode.id !== focusId && !neighborSet.has(fe.sourceNode.id)) {
          neighborSet.set(fe.sourceNode.id, { node: fe.sourceNode, p: fe.p1, color: meta.color });
        }
        if (fe.targetNode.id !== focusId && !neighborSet.has(fe.targetNode.id)) {
          neighborSet.set(fe.targetNode.id, { node: fe.targetNode, p: fe.p2, color: meta.color });
        }

        if (showPillLabels && dist >= 72) {
          const mx = fe.cx !== null && fe.cy !== null
            ? 0.25 * fe.p1.x + 0.5 * fe.cx + 0.25 * fe.p2.x
            : (fe.p1.x + fe.p2.x) * 0.5;
          const my = fe.cx !== null && fe.cy !== null
            ? 0.25 * fe.p1.y + 0.5 * fe.cy + 0.25 * fe.p2.y
            : (fe.p1.y + fe.p2.y) * 0.5;
          ctx.font = '700 8.5px ui-monospace, monospace';
          const tw = ctx.measureText(meta.tag).width + 8;
          ctx.fillStyle = 'rgba(7, 10, 18, 0.88)';
          ctx.beginPath();
          ctx.roundRect(mx - tw * 0.5, my - 7, tw, 14, 4);
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

    ctx.restore();
  }

  private renderLabels(ctx: CanvasRenderingContext2D) {
    const nodes = this.state.graph.nodes;
    const zoom = this.camera.zoom;
    const isXray = this.state.visionMode === 'xray' && this.activeNeighbors.size > 0;
    const activeId = this.state.activeSymbol?.id;
    const maxLen = this.state.settings.maxLabelLength || 18;
    const hideDense = this.state.settings.hideBubbleLabelsOver20;
    const denseLimit = this.state.settings.clusterLabelThreshold || 20;

    ctx.save();
    ctx.font = '500 10.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textAlign = 'center';

    let drawn = 0;
    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    for (let i = 0; i < nodes.length && drawn < 220; i++) {
      const n = nodes[i];
      if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;
      const isFocus = n.id === activeId || n.id === this.hoveredNodeId;
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
      ctx.fillStyle = isFocus ? '#38bdf8' : 'rgba(226, 232, 240, 0.88)';
      ctx.fillText(displayName, p.x, p.y + Math.max(14, 22 * zoom));
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
    if (this.animationFrameId !== null) {
      cancelAnimationFrame(this.animationFrameId);
    }
    this.physics.destroy();
  }
}
