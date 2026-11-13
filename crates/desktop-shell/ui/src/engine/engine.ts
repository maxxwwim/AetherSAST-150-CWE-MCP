// =========================================================================
// AETHERSCOPE V2 — HIGH-PERFORMANCE WEBGL 2 ENGINE (engine.ts)
// 120 FPS Celestial Spatial Graph Engine, Cellular Membranes & Laser Optics
// =========================================================================

import { initShaderPipeline, type ShaderPipeline } from './shaders';
import { PhysicsController, type FolderClusterEntry } from './physics';
import { getLayerRgba, SEVERITY_COLORS } from './palette';
import type { CockpitState } from '../state/graphState.svelte';
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

  // Mouse interaction state
  private isDragging = false;
  private isDraggingNode = false;
  private draggedNodeId: string | null = null;
  private dragStartX = 0;
  private dragStartY = 0;
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

  public syncGraphToEngine() {
    const nodes = this.state.graph.nodes;
    this.nodeMap.clear();
    this.clusters.clear();

    const floatCount = nodes.length * 9;
    if (this.instanceData.length !== floatCount) {
      this.instanceData = new Float32Array(floatCount);
    }

    const now = performance.now();
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      this.nodeMap.set(n.id, n);

      const offset = i * 9;
      const isFile = n.kind === 'File' ? 1.0 : n.kind === 'Class' ? 2.0 : n.kind === 'Endpoint' ? 3.0 : 0.0;
      const radius = isFile > 0.5 ? 24.0 : 16.0;

      this.instanceData[offset + 0] = n.x || (Math.random() - 0.5) * 800;
      this.instanceData[offset + 1] = n.y || (Math.random() - 0.5) * 800;
      this.instanceData[offset + 2] = radius;
      this.instanceData[offset + 7] = isFile;
      this.instanceData[offset + 8] = now;
    }

    this.refreshVisionColors(false);

    const { gl, pipeline } = this;
    gl.bindBuffer(gl.ARRAY_BUFFER, pipeline.instanceVbo);
    gl.bufferData(gl.ARRAY_BUFFER, this.instanceData, gl.DYNAMIC_DRAW);
    gl.bindBuffer(gl.ARRAY_BUFFER, null);

    this.physics.sendGraph(nodes, this.state.graph.edges);
  }

  public refreshVisionColors(upload = true) {
    const nodes = this.state.graph.nodes;
    if (!nodes || this.instanceData.length < nodes.length * 9) return;

    const mode = this.state.visionMode;
    const activeId = this.state.activeSymbol?.id || null;
    this.lastVisionMode = mode;
    this.lastActiveSymbolId = activeId;

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
      let col = getLayerRgba(n.layer);
      let alpha = 1.0;

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
        } else {
          alpha = 0.12;
        }
      } else if (mode === 'xray' && activeId) {
        if (!this.activeNeighbors.has(n.id)) {
          alpha = 0.08;
        }
      }

      if (n.anomalies && n.anomalies.length > 0 && mode === 'standard') {
        col = SEVERITY_COLORS.CRITICAL;
      }

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
    const world = this.screenToWorld(sx, sy);
    const nodes = this.state.graph.nodes;
    const hitRadius = 28 / this.camera.zoom;
    const hitRadius2 = hitRadius * hitRadius;

    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = n.x - world.x;
      const dy = n.y - world.y;
      if (dx * dx + dy * dy <= hitRadius2) {
        return n;
      }
    }
    return null;
  }

  private setupMouseEvents() {
    window.addEventListener('resize', this.resizeHandler);

    this.canvas.addEventListener('wheel', (e: WheelEvent) => {
      e.preventDefault();
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      const newZoom = Math.max(0.12, Math.min(3.2, this.camera.targetZoom * zoomFactor));

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
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      this.dragStartX = sx;
      this.dragStartY = sy;

      const hit = this.pickNode(sx, sy);
      if (hit) {
        this.isDraggingNode = true;
        this.draggedNodeId = hit.id;
        const world = this.screenToWorld(sx, sy);
        this.physics.drag(hit.id, world.x, world.y);
      } else {
        this.isDragging = true;
      }
    });

    window.addEventListener('pointermove', (e: PointerEvent) => {
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);

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
      }
    });

    window.addEventListener('pointerup', (e: PointerEvent) => {
      const { sx, sy } = this.getCanvasLocalCoords(e.clientX, e.clientY);
      const wasDraggingNode = this.isDraggingNode;

      if (this.isDraggingNode) {
        this.isDraggingNode = false;
        this.draggedNodeId = null;
        this.physics.dragEnd();
      }
      if (this.isDragging) {
        this.isDragging = false;
      }

      const dist = Math.hypot(sx - this.dragStartX, sy - this.dragStartY);
      if (dist < 4 && (wasDraggingNode || e.target === this.canvas)) {
        const hit = this.pickNode(sx, sy);
        if (hit) {
          this.state.selectSymbol(hit.id);
        }
      }
    });
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

      if (
        this.lastVisionMode !== this.state.visionMode ||
        this.lastActiveSymbolId !== (this.state.activeSymbol?.id || null)
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
    const { gl, pipeline } = this;

    // 1. WebGL 2 Instanced Celestial Nodes (uRes in logical CSS pixels)
    gl.clearColor(0.027, 0.035, 0.055, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);
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

    // 2. 2D Overlay Canvas (Cellular Membranes, Edges, Labels)
    const ctx = this.lineCtx;
    ctx.clearRect(0, 0, this.logicalWidth, this.logicalHeight);

    this.renderMembranes(ctx, now);
    this.renderEdges(ctx);
    this.renderLabels(ctx);
  }

  private renderMembranes(ctx: CanvasRenderingContext2D, now: number) {
    if (this.state.visionMode === 'xray' || this.clusters.size === 0) return;

    ctx.save();
    const breathPhase = now * 0.0012;
    const ptsX = new Float32Array(12);
    const ptsY = new Float32Array(12);

    this.clusters.forEach((cl) => {
      if (cl.count <= 0) return;
      const center = this.worldToScreen(cl.cx, cl.cy);
      const baseR = (cl.computedRadius || 100) * this.camera.zoom;

      if (
        center.x + baseR < -40 ||
        center.x - baseR > this.logicalWidth + 40 ||
        center.y + baseR < -40 ||
        center.y - baseR > this.logicalHeight + 40
      ) {
        return;
      }

      for (let i = 0; i < 12; i++) {
        const prof = cl.lobeProfile && cl.lobeProfile[i] ? cl.lobeProfile[i] : 1.0;
        const harmonic = 1.0 + 0.035 * Math.sin(breathPhase + i * 1.618);
        const r = baseR * prof * harmonic;
        ptsX[i] = center.x + _COS12[i] * r;
        ptsY[i] = center.y + _SIN12[i] * r;
      }

      ctx.beginPath();
      const startMidX = (ptsX[11] + ptsX[0]) * 0.5;
      const startMidY = (ptsY[11] + ptsY[0]) * 0.5;
      ctx.moveTo(startMidX, startMidY);
      for (let i = 0; i < 12; i++) {
        const next = (i + 1) % 12;
        const midX = (ptsX[i] + ptsX[next]) * 0.5;
        const midY = (ptsY[i] + ptsY[next]) * 0.5;
        ctx.quadraticCurveTo(ptsX[i], ptsY[i], midX, midY);
      }
      ctx.closePath();

      ctx.fillStyle = 'rgba(56, 189, 248, 0.035)';
      ctx.fill();
      ctx.lineWidth = Math.max(0.8, 1.3 * this.camera.zoom);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.22)';
      ctx.stroke();
    });

    ctx.restore();
  }

  private renderEdges(ctx: CanvasRenderingContext2D) {
    const edges = this.state.graph.edges;
    if (!edges || edges.length === 0) return;

    ctx.save();
    ctx.lineWidth = Math.max(0.8, 1.2 * this.camera.zoom);
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.22)';
    ctx.beginPath();

    const isXray = this.state.visionMode === 'xray' && this.state.activeSymbol;
    const activeId = this.state.activeSymbol?.id;

    const maxDraw = Math.min(edges.length, 1200);
    for (let i = 0; i < maxDraw; i++) {
      const e = edges[i];
      if (isXray && e.source !== activeId && e.target !== activeId) continue;

      const s = this.nodeMap.get(e.source);
      const t = this.nodeMap.get(e.target);
      if (!s || !t) continue;

      const p1 = this.worldToScreen(s.x, s.y);
      const p2 = this.worldToScreen(t.x, t.y);

      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
    }
    ctx.stroke();
    ctx.restore();
  }

  private renderLabels(ctx: CanvasRenderingContext2D) {
    if (this.camera.zoom < 0.45) return;

    const nodes = this.state.graph.nodes;
    ctx.save();
    ctx.font = '10px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.fillStyle = 'rgba(226, 232, 240, 0.85)';

    const isXray = this.state.visionMode === 'xray' && this.activeNeighbors.size > 0;
    const maxLabels = Math.min(nodes.length, 300);

    for (let i = 0; i < maxLabels; i++) {
      const n = nodes[i];
      if (isXray && !this.activeNeighbors.has(n.id)) continue;

      const p = this.worldToScreen(n.x, n.y);
      if (p.x < -40 || p.x > this.logicalWidth + 40 || p.y < -20 || p.y > this.logicalHeight + 20) {
        continue;
      }
      ctx.fillText(n.name, p.x, p.y + 24 * this.camera.zoom);
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
