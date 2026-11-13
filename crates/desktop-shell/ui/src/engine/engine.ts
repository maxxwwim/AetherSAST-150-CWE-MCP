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
import { normalizeEdgeRelation, type CockpitState } from '../state/graphState.svelte';
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
  private logicalWidth = 800;
  private logicalHeight = 600;
  private dpr = 1;

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
  private lastFilterVersion = 0;
  private hoveredNodeId: string | null = null;
  private hoveredFolder: string | null = null;
  private selectedFolder: string | null = null;
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

        if (this.instanceData.length >= (i + 1) * 9) {
          this.instanceData[i * 9 + 0] = nodes[i].x;
          this.instanceData[i * 9 + 1] = nodes[i].y;
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

  public syncGraphToEngine() {
    const nodes = this.state.graph.nodes;
    this.nodeMap.clear();
    this.clusters.clear();

    const floatCount = nodes.length * 9;
    if (this.instanceData.length !== floatCount) {
      this.instanceData = new Float32Array(floatCount);
    }

    const birthStamp = Math.max(0, performance.now() - 16);
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!Number.isFinite(n.x)) n.x = (Math.random() - 0.5) * 800;
      if (!Number.isFinite(n.y)) n.y = (Math.random() - 0.5) * 800;
      this.nodeMap.set(n.id, n);

      const offset = i * 9;
      const { shaderType, baseRadius } = this.classifyNode(n);

      this.instanceData[offset + 0] = n.x;
      this.instanceData[offset + 1] = n.y;
      this.instanceData[offset + 2] = baseRadius;
      this.instanceData[offset + 7] = shaderType;
      this.instanceData[offset + 8] = birthStamp;
    }

    this.seedInitialClusters(nodes);
    this.refreshVisionColors(false);
    this.fitCameraToGraph(true);

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
      0.06,
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
    if (!nodes || this.instanceData.length < nodes.length * 9) return;

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
      const offset = i * 9;
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

      const hasVuln =
        n.has_security_violation ||
        (n.anomalies && n.anomalies.length > 0) ||
        (n.violations && n.violations.length > 0);
      if (hasVuln && mode === 'standard') {
        col = SEVERITY_COLORS.CRITICAL;
        r *= 1.3;
      }

      if (disabledLayers[n.layer || 'utility'] || this.state.disabledModules[folder]) {
        alpha = 0.035;
        r *= 0.42;
      }

      this.instanceData[offset + 2] = r;
      this.instanceData[offset + 3] = col.r;
      this.instanceData[offset + 4] = col.g;
      this.instanceData[offset + 5] = col.b;
      this.instanceData[offset + 6] = alpha;
    }

    if (upload) {
      this.uploadInstanceSubData();
    }
  }

  public handleResize() {
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.logicalWidth = this.canvas.clientWidth || window.innerWidth;
    this.logicalHeight = this.canvas.clientHeight || (window.innerHeight - 44);

    this.canvas.width = Math.floor(this.logicalWidth * this.dpr);
    this.canvas.height = Math.floor(this.logicalHeight * this.dpr);
    this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);

    this.lineCanvas.width = Math.floor(this.logicalWidth * this.dpr);
    this.lineCanvas.height = Math.floor(this.logicalHeight * this.dpr);
    this.lineCtx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
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

  private pickNode(sx: number, sy: number): SymbolBubble | null {
    const nodes = this.state.graph.nodes;
    if (!nodes || nodes.length === 0) return null;

    const zoom = this.camera.zoom;
    const zoomFactor = Math.max(0.85, Math.min(2.5, 1.0 / Math.sqrt(Math.max(0.08, Math.min(3.5, zoom)))));
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

      const { baseRadius } = this.classifyNode(n);
      const scaleMult = n.id === activeId ? 1.65 : n.id === this.hoveredNodeId ? 1.35 : 1.0;
      const visualR = baseRadius * scaleMult * 2.8 * zoomFactor * zoom;
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

    this.canvas.addEventListener('wheel', (e: WheelEvent) => {
      e.preventDefault();
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      const newZoom = Math.max(0.06, Math.min(3.5, this.camera.targetZoom * zoomFactor));

      const mouseWorldBefore = this.screenToWorld(sx, sy);
      this.camera.targetZoom = newZoom;
      this.camera.zoom = newZoom;

      const mouseWorldAfter = this.screenToWorld(sx, sy);
      this.camera.targetX += mouseWorldBefore.x - mouseWorldAfter.x;
      this.camera.targetY += mouseWorldBefore.y - mouseWorldAfter.y;
      this.camera.x = this.camera.targetX;
      this.camera.y = this.camera.targetY;

      this.physics.wake(60);
    }, { passive: false });

    this.canvas.addEventListener('pointerdown', (e: PointerEvent) => {
      if (e.button !== 0) return;
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      this.dragStartX = sx;
      this.dragStartY = sy;
      this.pointerDownX = sx;
      this.pointerDownY = sy;
      this.pointerDownOnCanvas = true;
      const hit = this.pickNode(sx, sy);
      this.pointerDownHitId = hit ? hit.id : null;
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

    window.addEventListener('pointermove', (e: PointerEvent) => {
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);

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
    });

    this.canvas.addEventListener('pointerleave', () => {
      if (this.hoveredNodeId !== null || this.state.hoveredSymbol !== null) {
        this.hoveredNodeId = null;
        this.state.hoveredSymbol = null;
        this.refreshVisionColors(true);
      }
    });

    window.addEventListener('pointerup', (e: PointerEvent) => {
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
          this.refreshVisionColors(true);
        } else {
          const folder = this.findFolderAt(sx, sy);
          this.selectedFolder = folder;
          if (folder) {
            this.state.selectFolder(folder, false);
          } else {
            this.state.clearSelection();
          }
          this.refreshVisionColors(true);
        }
      }
    });
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
      this.physics.step(this.camera.zoom);
      this.render(now);
      this.animationFrameId = requestAnimationFrame(loop);
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  private updateCamera(dt: number) {
    const factor = Math.min(1.0, (dt / 1000) * 10.0);
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

    // 2. 2D Overlay Canvas (Cellular Membranes, Edges, Security Beacons, Labels)
    const ctx = this.lineCtx;
    ctx.clearRect(0, 0, this.logicalWidth, this.logicalHeight);

    this.renderMembranes(ctx, now);
    this.renderEdges(ctx, now);
    this.renderSecurityBeacons(ctx, now);
    this.renderAiAgentOverlay(ctx, now);
    this.renderLabels(ctx);
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
      const anom = n.anomalies || [];
      const hasSec = Boolean(n.has_security_violation || anom.length > 0 || (n.violations && n.violations.length > 0));
      if (!hasSec) continue;

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -50 || p.x > this.logicalWidth + 50 || p.y < -50 || p.y > this.logicalHeight + 50) continue;

      // Calm, slow breathing crimson aura (no rapid strobe or jitter)
      const gentleBreath = 0.5 + 0.5 * Math.sin(now * 0.0014 + i * 0.45);
      const baseR = n.is_file || n.is_class ? 16 : 11;
      const ringR = Math.max(11, baseR * Math.sqrt(Math.max(0.25, zoom)) + gentleBreath * 2.0);

      // Soft ambient outer halo
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR + 4, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(239, 68, 68, ${(0.06 + gentleBreath * 0.05).toFixed(3)})`;
      ctx.fill();

      // Steady inner crimson ring
      ctx.beginPath();
      ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(248, 113, 113, ${(0.52 + gentleBreath * 0.24).toFixed(2)})`;
      ctx.lineWidth = 1.35;
      ctx.stroke();

      // Alert pill on files, focused/hovered nodes, or when zoomed in (steady position, legible)
      const isFocus = n.id === this.hoveredNodeId || n.id === this.state.activeSymbol?.id;
      if (isFocus || n.is_file || zoom >= 0.42) {
        const primary = anom[0];
        const tagText = primary ? `🚨 ${primary.cve_id || primary.rule_id || 'CWE'}` : '🚨 SAST CWE';
        const shortTag = tagText.length > 18 ? tagText.slice(0, 17) + '…' : tagText;
        const tw = ctx.measureText(shortTag).width + 10;
        const fixedOffset = Math.max(12, baseR * Math.sqrt(Math.max(0.25, zoom)) + 4);
        const bx = p.x - tw * 0.5;
        const by = p.y - fixedOffset - 16;

        ctx.fillStyle = 'rgba(127, 29, 29, 0.90)';
        ctx.strokeStyle = 'rgba(248, 113, 113, 0.85)';
        ctx.lineWidth = 1.0;
        ctx.beginPath();
        ctx.roundRect(bx, by, tw, 15, 4);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = '#fecaca';
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
    ctx.font = '700 10px ui-sans-serif, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    const nodeBadgeStack = new Map<string, number>();

    for (let idx = 0; idx < agents.length; idx++) {
      const ag = agents[idx];
      const agColor = ag.color || '#c084fc';
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
        ctx.globalAlpha = 0.65;
        ctx.lineWidth = 1.7;
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1.0;
      }

      if (ag.nodeId) {
        const targetNode = this.nodeMap.get(ag.nodeId);
        if (targetNode) {
          const p = this.worldToScreen(targetNode.x, targetNode.y);
          const stackIdx = nodeBadgeStack.get(ag.nodeId) || 0;
          nodeBadgeStack.set(ag.nodeId, stackIdx + 1);

          const r = 19 + stackIdx * 6 + Math.sin(now * 0.0018 + idx) * 2.2;
          ctx.beginPath();
          ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
          ctx.strokeStyle = agColor;
          ctx.globalAlpha = 0.85;
          ctx.lineWidth = 1.7;
          ctx.stroke();
          ctx.globalAlpha = 1.0;

          const label = `🤖 ${ag.agentName}: ${ag.action || 'Focus'}`;
          const tw = ctx.measureText(label).width + 12;
          const badgeY = p.y + 24 + stackIdx * 21;
          ctx.fillStyle = 'rgba(11, 14, 24, 0.92)';
          ctx.strokeStyle = agColor;
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.roundRect(p.x - tw * 0.5, badgeY, tw, 18, 6);
          ctx.fill();
          ctx.stroke();
          ctx.fillStyle = '#f8fafc';
          ctx.fillText(label, p.x, badgeY + 9);
        }
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
    const ptsX = new Float32Array(12);
    const ptsY = new Float32Array(12);
    for (let i = 0; i < 12; i++) {
      const prof = lobeProfile && lobeProfile[i] ? lobeProfile[i] : 1.0;
      const harmonic =
        1.0 +
        0.042 * Math.sin(breathPhase + phaseShift + i * 1.618) +
        0.024 * Math.cos(breathPhase * 0.62 - phaseShift * 0.7 + i * 2.51);
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

  private renderMembranes(ctx: CanvasRenderingContext2D, now: number) {
    this.folderPillBounds = [];
    if (!this.state.settings.showFolderMembranes || this.state.visionMode === 'xray' || this.clusters.size === 0) return;

    ctx.save();
    const breathPhase = now * 0.00095;
    const badges: { folder: string; label: string; count: number; cx: number; topY: number; rgb: string; sel: boolean }[] = [];

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
      const rR = Math.round(col.r * 255);
      const rG = Math.round(col.g * 255);
      const rB = Math.round(col.b * 255);
      const lR = Math.min(255, rR + 85);
      const lG = Math.min(255, rG + 85);
      const lB = Math.min(255, rB + 100);
      const isSel = folder === this.selectedFolder || folder === this.hoveredFolder;
      const folderPhase = (rR * 0.03 + rG * 0.07) % 6.28;

      // 1. Living Outer Cytoplasmic Membrane with soft radial gradient
      const topCrestY = this.traceMembraneSpline(ctx, center.x, center.y, baseR, cl.lobeProfile, breathPhase, folderPhase);
      const grad = ctx.createRadialGradient(center.x, center.y, Math.max(4, baseR * 0.15), center.x, center.y, Math.max(12, baseR * 1.15));
      grad.addColorStop(0, `rgba(${rR}, ${rG}, ${rB}, ${isSel ? 0.16 : 0.085})`);
      grad.addColorStop(0.7, `rgba(${rR}, ${rG}, ${rB}, ${isSel ? 0.10 : 0.04})`);
      grad.addColorStop(1, `rgba(${rR}, ${rG}, ${rB}, 0.01)`);
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.lineWidth = Math.min(3.5, Math.max(1.1, isSel ? 2.4 : 1.5));
      ctx.strokeStyle = isSel ? 'rgba(56, 189, 248, 0.85)' : `rgba(${lR}, ${lG}, ${lB}, 0.44)`;
      ctx.stroke();

      // 2. Living Inner Phospholipid Bilayer Cortex (breathing out-of-phase)
      if (baseR >= 26) {
        this.traceMembraneSpline(ctx, center.x, center.y, baseR * 0.88, cl.lobeProfile, breathPhase * 0.88, folderPhase + 2.1);
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${isSel ? 0.05 : 0.022})`;
        ctx.fill();
        ctx.lineWidth = 0.9;
        ctx.strokeStyle = `rgba(${lR}, ${lG}, ${lB}, ${isSel ? 0.35 : 0.18})`;
        ctx.stroke();
      }

      // 3. LoD 2 Nucleus Core
      if ((this.state.lodLevel === 2 || isSel) && baseR >= 45) {
        const nucR = Math.max(12, baseR * 0.20);
        this.traceMembraneSpline(ctx, center.x, center.y, nucR, undefined, breathPhase * 1.25, 1.1);
        ctx.fillStyle = `rgba(${rR}, ${rG}, ${rB}, ${isSel ? 0.20 : 0.10})`;
        ctx.fill();
        ctx.lineWidth = 1.0;
        ctx.strokeStyle = `rgba(${lR}, ${lG}, ${lB}, 0.30)`;
        ctx.stroke();
      }

      if (isSel || (this.state.settings.showFolderBadges && cl.count >= 4 && baseR >= 34)) {
        badges.push({
          folder,
          label: formatFolderLabel(folder),
          count: cl.count,
          cx: center.x,
          topY: topCrestY,
          rgb: `${lR}, ${lG}, ${lB}`,
          sel: isSel
        });
      }
    });

    this.renderFolderBadges(ctx, badges);
    ctx.restore();
  }

  private renderFolderBadges(
    ctx: CanvasRenderingContext2D,
    badges: { folder: string; label: string; count: number; cx: number; topY: number; rgb: string; sel: boolean }[]
  ) {
    if (badges.length === 0) return;
    ctx.font = '600 11px ui-sans-serif, system-ui, -apple-system, sans-serif';
    ctx.textBaseline = 'middle';

    const maxDraw = Math.min(badges.length, 32);
    for (let i = 0; i < maxDraw; i++) {
      const b = badges[i];
      const text = `${b.label}`;
      const countText = `${b.count}`;
      const textW = ctx.measureText(text).width;
      const countW = ctx.measureText(countText).width;
      const pillW = textW + countW + 26;
      const pillH = 20;
      const pillX = b.cx - pillW * 0.5;
      const pillY = b.topY - pillH - 8;
      this.folderPillBounds.push({ folder: b.folder, x: pillX, y: pillY, w: pillW, h: pillH });

      // Tether line from cellular crest to pill badge
      ctx.beginPath();
      ctx.moveTo(b.cx, b.topY);
      ctx.lineTo(b.cx, pillY + pillH);
      ctx.strokeStyle = b.sel ? '#38bdf8' : `rgba(${b.rgb}, 0.55)`;
      ctx.lineWidth = 1.0;
      ctx.stroke();

      ctx.fillStyle = b.sel ? 'rgba(12, 74, 110, 0.92)' : 'rgba(11, 14, 23, 0.86)';
      ctx.strokeStyle = b.sel ? '#38bdf8' : `rgba(${b.rgb}, 0.55)`;
      ctx.beginPath();
      ctx.roundRect(pillX, pillY, pillW, pillH, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#e2e8f0';
      ctx.textAlign = 'left';
      ctx.fillText(text, pillX + 8, pillY + pillH * 0.5);

      ctx.fillStyle = `rgba(${b.rgb}, 0.95)`;
      ctx.textAlign = 'right';
      ctx.fillText(countText, pillX + pillW - 7, pillY + pillH * 0.5);
    }
  }

  private renderEdges(ctx: CanvasRenderingContext2D, now: number) {
    const edges = this.state.graph.edges;
    if (!edges || edges.length === 0) return;

    const isXray = this.state.visionMode === 'xray' && this.state.activeSymbol;
    const activeId = this.state.activeSymbol?.id;
    const disabledLayers = this.state.disabledLayers;
    const disabledModules = this.state.disabledModules;
    const disabledRelations = this.state.disabledRelations;
    const pipe = this.state.pipelineHighlight;

    const pCalls = new Path2D();
    const pImports = new Path2D();
    const pQueries = new Path2D();
    const pViolates = new Path2D();
    const pRealtime = new Path2D();
    const pNetwork = new Path2D();
    const pSubmits = new Path2D();
    let hasCalls = false, hasImports = false, hasQueries = false, hasViolates = false, hasRealtime = false, hasNetwork = false, hasSubmits = false;
    const pulseParticles: { x: number; y: number; color: string }[] = [];

    const maxDraw = Math.min(edges.length, 1800);
    for (let i = 0; i < maxDraw; i++) {
      const e = edges[i];
      if (isXray && e.source !== activeId && e.target !== activeId) continue;

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
        Math.max(p1.x, p2.x) < -40 ||
        Math.min(p1.x, p2.x) > this.logicalWidth + 40 ||
        Math.max(p1.y, p2.y) < -40 ||
        Math.min(p1.y, p2.y) > this.logicalHeight + 40
      ) {
        continue;
      }

      const sFolder = s.folder || s.cluster_id;
      const tFolder = t.folder || t.cluster_id;
      const isCross = sFolder && tFolder && sFolder !== tFolder;

      let targetPath = pCalls;
      if (rel === 'violates' || e.cve_id) { targetPath = pViolates; hasViolates = true; }
      else if (rel === 'submits') { targetPath = pSubmits; hasSubmits = true; }
      else if (rel === 'network') { targetPath = pNetwork; hasNetwork = true; }
      else if (rel === 'realtime') { targetPath = pRealtime; hasRealtime = true; }
      else if (rel === 'queries' || t.layer === 'database') { targetPath = pQueries; hasQueries = true; }
      else if (rel === 'imports' || rel === 'contains' || rel === 'inherits') { targetPath = pImports; hasImports = true; }
      else { hasCalls = true; }

      targetPath.moveTo(p1.x, p1.y);
      if (isCross && rel !== 'contains') {
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const cx = (p1.x + p2.x) * 0.5 - dy * 0.14;
        const cy = (p1.y + p2.y) * 0.5 + dx * 0.14;
        targetPath.quadraticCurveTo(cx, cy, p2.x, p2.y);

        // Living synaptic vesicles drifting along active connections
        if (pulseParticles.length < 48 && (isXray || pipe || i % 7 === 0)) {
          const u = ((now * 0.00032 + i * 0.17) % 1 + 1) % 1;
          const inv = 1 - u;
          pulseParticles.push({
            x: inv * inv * p1.x + 2 * inv * u * cx + u * u * p2.x,
            y: inv * inv * p1.y + 2 * inv * u * cy + u * u * p2.y,
            color: rel === 'violates' ? '#f87171' : rel === 'realtime' ? '#34d399' : rel === 'queries' ? '#c084fc' : '#38bdf8',
          });
        }
      } else {
        targetPath.lineTo(p2.x, p2.y);
      }
    }

    ctx.save();
    ctx.lineCap = 'round';
    const w = Math.max(0.75, Math.min(2.0, 1.15 * Math.sqrt(this.camera.zoom)));

    if (hasImports) {
      ctx.lineWidth = w * 0.85;
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = pipe ? 'rgba(245, 158, 11, 0.08)' : 'rgba(245, 158, 11, 0.16)';
      ctx.stroke(pImports);
      ctx.setLineDash([]);
    }
    if (hasCalls) {
      ctx.lineWidth = w;
      ctx.strokeStyle = isXray ? 'rgba(56, 189, 248, 0.58)' : (pipe ? 'rgba(56, 189, 248, 0.08)' : 'rgba(56, 189, 248, 0.18)');
      ctx.stroke(pCalls);
    }
    if (hasSubmits) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.4;
      ctx.strokeStyle = pipe ? 'rgba(255, 107, 0, 0.85)' : 'rgba(255, 107, 0, 0.45)';
      ctx.stroke(pSubmits);
    }
    if (hasNetwork) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.4;
      ctx.strokeStyle = pipe ? 'rgba(0, 200, 255, 0.88)' : 'rgba(0, 200, 255, 0.45)';
      ctx.stroke(pNetwork);
    }
    if (hasQueries) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.3;
      ctx.strokeStyle = pipe ? 'rgba(168, 85, 247, 0.88)' : 'rgba(168, 85, 247, 0.45)';
      ctx.stroke(pQueries);
    }
    if (hasRealtime) {
      ctx.lineWidth = pipe ? w * 2.1 : w * 1.35;
      ctx.strokeStyle = pipe ? 'rgba(52, 211, 153, 0.90)' : 'rgba(52, 211, 153, 0.48)';
      ctx.stroke(pRealtime);
    }
    if (hasViolates) {
      ctx.lineWidth = w * 1.55;
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.65)';
      ctx.stroke(pViolates);
    }
    for (let i = 0; i < pulseParticles.length; i++) {
      const pt = pulseParticles[i];
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, isXray || pipe ? 2.6 : 1.9, 0, Math.PI * 2);
      ctx.fillStyle = pt.color;
      ctx.fill();
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
    window.removeEventListener('resize', this.resizeHandler);
    if (this.animationFrameId !== null) {
      cancelAnimationFrame(this.animationFrameId);
    }
    this.physics.destroy();
  }
}
