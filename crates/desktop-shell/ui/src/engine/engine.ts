// =========================================================================
// AETHERSCOPE V2 — HIGH-PERFORMANCE WEBGL 2 ENGINE (engine.ts)
// 120 FPS Celestial Spatial Graph Engine, Cellular Membranes & Laser Optics
// =========================================================================

import { initShaderPipeline, type ShaderPipeline } from './shaders';
import { PhysicsController } from './physics';
import { getLayerRgba } from './palette';
import type { CockpitState } from '../state/graphState.svelte';
import type { SymbolBubble } from '../types/graph';

export class AetherEngine {
  private gl: WebGL2RenderingContext;
  private lineCtx: CanvasRenderingContext2D;
  private pipeline: ShaderPipeline;
  private physics: PhysicsController;

  private animationFrameId: number | null = null;
  private isDestroyed = false;

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

  // Instance Buffer management
  private instanceData: Float32Array = new Float32Array(0);
  private instanceCapacity = 0;
  private nodeMap = new Map<string, SymbolBubble>();

  // Mouse interaction state
  private isDragging = false;
  private isDraggingNode = false;
  private draggedNodeId: string | null = null;
  private dragStartX = 0;
  private dragStartY = 0;
  private mouseScreenX = 0;
  private mouseScreenY = 0;

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

    // Check if graph already loaded
    if (this.state.graph.nodes.length > 0) {
      this.syncGraphToEngine();
    }
  }

  private setupPhysicsListener() {
    this.physics.onUpdate = (positions: Float32Array) => {
      const nodes = this.state.graph.nodes;
      const count = Math.min(nodes.length, Math.floor(positions.length / 2));

      for (let i = 0; i < count; i++) {
        nodes[i].x = positions[i * 2];
        nodes[i].y = positions[i * 2 + 1];

        // Update instance data positions
        if (this.instanceData.length >= (i + 1) * 9) {
          this.instanceData[i * 9 + 0] = nodes[i].x;
          this.instanceData[i * 9 + 1] = nodes[i].y;
        }
      }

      // Fast upload to GPU via bufferSubData
      const { gl, pipeline } = this;
      gl.bindBuffer(gl.ARRAY_BUFFER, pipeline.instanceVbo);
      gl.bufferSubData(gl.ARRAY_BUFFER, 0, this.instanceData);
      gl.bindBuffer(gl.ARRAY_BUFFER, null);
    };
  }

  public syncGraphToEngine() {
    const nodes = this.state.graph.nodes;
    this.nodeMap.clear();

    const floatCount = nodes.length * 9;
    if (this.instanceData.length !== floatCount) {
      this.instanceData = new Float32Array(floatCount);
    }

    const now = performance.now();
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      this.nodeMap.set(n.id, n);

      const offset = i * 9;
      const col = getLayerRgba(n.layer);
      const isFile = n.kind === 'File' ? 1.0 : n.kind === 'Class' ? 2.0 : n.kind === 'Endpoint' ? 3.0 : 0.0;
      const radius = isFile > 0.5 ? 24.0 : 16.0;

      this.instanceData[offset + 0] = n.x || (Math.random() - 0.5) * 800;
      this.instanceData[offset + 1] = n.y || (Math.random() - 0.5) * 800;
      this.instanceData[offset + 2] = radius;
      this.instanceData[offset + 3] = col.r;
      this.instanceData[offset + 4] = col.g;
      this.instanceData[offset + 5] = col.b;
      this.instanceData[offset + 6] = col.a;
      this.instanceData[offset + 7] = isFile;
      this.instanceData[offset + 8] = now;
    }

    // Allocate / Upload VBO
    const { gl, pipeline } = this;
    gl.bindBuffer(gl.ARRAY_BUFFER, pipeline.instanceVbo);
    gl.bufferData(gl.ARRAY_BUFFER, this.instanceData, gl.DYNAMIC_DRAW);
    this.instanceCapacity = this.instanceData.byteLength;
    gl.bindBuffer(gl.ARRAY_BUFFER, null);

    // Send to Web Worker
    this.physics.sendGraph(nodes, this.state.graph.edges);
  }

  public handleResize() {
    const w = this.canvas.clientWidth || window.innerWidth;
    const h = this.canvas.clientHeight || (window.innerHeight - 44);

    this.canvas.width = w * window.devicePixelRatio;
    this.canvas.height = h * window.devicePixelRatio;
    this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);

    this.lineCanvas.width = w;
    this.lineCanvas.height = h;
  }

  public screenToWorld(sx: number, sy: number) {
    const w = this.lineCanvas.width;
    const h = this.lineCanvas.height;
    return {
      x: this.camera.x + (sx - w / 2) / this.camera.zoom,
      y: this.camera.y + (sy - h / 2) / this.camera.zoom
    };
  }

  public worldToScreen(wx: number, wy: number) {
    const w = this.lineCanvas.width;
    const h = this.lineCanvas.height;
    return {
      x: (wx - this.camera.x) * this.camera.zoom + w / 2,
      y: (wy - this.camera.y) * this.camera.zoom + h / 2
    };
  }

  private pickNode(sx: number, sy: number): SymbolBubble | null {
    const world = this.screenToWorld(sx, sy);
    const nodes = this.state.graph.nodes;
    const hitRadius = 28 / this.camera.zoom;

    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = n.x - world.x;
      const dy = n.y - world.y;
      if (dx * dx + dy * dy <= hitRadius * hitRadius) {
        return n;
      }
    }
    return null;
  }

  private setupMouseEvents() {
    window.addEventListener('resize', () => this.handleResize());

    // Wheel Zoom
    this.canvas.addEventListener('wheel', (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.15 : 0.87;
      const newZoom = Math.max(0.12, Math.min(3.2, this.camera.targetZoom * zoomFactor));

      // Zoom towards cursor
      const mouseWorldBefore = this.screenToWorld(e.clientX, e.clientY);
      this.camera.targetZoom = newZoom;
      this.camera.zoom = newZoom;

      const mouseWorldAfter = this.screenToWorld(e.clientX, e.clientY);
      this.camera.targetX += mouseWorldBefore.x - mouseWorldAfter.x;
      this.camera.targetY += mouseWorldBefore.y - mouseWorldAfter.y;
      this.camera.x = this.camera.targetX;
      this.camera.y = this.camera.targetY;

      this.physics.wake(60);
    }, { passive: false });

    // Pointer Down
    this.canvas.addEventListener('pointerdown', (e: PointerEvent) => {
      this.dragStartX = e.clientX;
      this.dragStartY = e.clientY;

      const hit = this.pickNode(e.clientX, e.clientY);
      if (hit) {
        this.isDraggingNode = true;
        this.draggedNodeId = hit.id;
        const world = this.screenToWorld(e.clientX, e.clientY);
        this.physics.drag(hit.id, world.x, world.y);
      } else {
        this.isDragging = true;
      }
    });

    // Pointer Move
    window.addEventListener('pointermove', (e: PointerEvent) => {
      this.mouseScreenX = e.clientX;
      this.mouseScreenY = e.clientY;

      if (this.isDraggingNode && this.draggedNodeId) {
        const world = this.screenToWorld(e.clientX, e.clientY);
        this.physics.drag(this.draggedNodeId, world.x, world.y);
        const node = this.nodeMap.get(this.draggedNodeId);
        if (node) {
          node.x = world.x;
          node.y = world.y;
        }
      } else if (this.isDragging) {
        const dx = (e.clientX - this.dragStartX) / this.camera.zoom;
        const dy = (e.clientY - this.dragStartY) / this.camera.zoom;
        this.camera.x -= dx;
        this.camera.y -= dy;
        this.camera.targetX = this.camera.x;
        this.camera.targetY = this.camera.y;
        this.dragStartX = e.clientX;
        this.dragStartY = e.clientY;
      }
    });

    // Pointer Up
    window.addEventListener('pointerup', (e: PointerEvent) => {
      if (this.isDraggingNode) {
        this.isDraggingNode = false;
        this.draggedNodeId = null;
        this.physics.dragEnd();
      }
      if (this.isDragging) {
        this.isDragging = false;
      }

      // Check click without drag for selection
      const dist = Math.hypot(e.clientX - this.dragStartX, e.clientY - this.dragStartY);
      if (dist < 4) {
        const hit = this.pickNode(e.clientX, e.clientY);
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

    // 1. WebGL 2 Instanced Background & Celestial Nodes
    gl.clearColor(0.027, 0.035, 0.055, 1.0); // #07090e
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    gl.useProgram(pipeline.program);
    gl.uniform2f(pipeline.uniforms.uRes, this.canvas.width, this.canvas.height);
    gl.uniform2f(pipeline.uniforms.uCam, this.camera.x, this.camera.y);
    gl.uniform1f(pipeline.uniforms.uZoom, this.camera.zoom);
    gl.uniform1f(pipeline.uniforms.uTime, now);

    const nodes = this.state.graph.nodes;
    if (nodes && nodes.length > 0) {
      gl.bindVertexArray(pipeline.vao);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, nodes.length);
      gl.bindVertexArray(null);
    }

    // 2. 2D Overlay Canvas (Edges, Labels)
    const ctx = this.lineCtx;
    ctx.clearRect(0, 0, this.lineCanvas.width, this.lineCanvas.height);

    this.renderEdges(ctx);
    this.renderLabels(ctx);
  }

  private renderEdges(ctx: CanvasRenderingContext2D) {
    const edges = this.state.graph.edges;
    if (!edges || edges.length === 0) return;

    ctx.save();
    ctx.lineWidth = Math.max(0.8, 1.2 * this.camera.zoom);
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.22)'; // Cyan flow
    ctx.beginPath();

    const maxDraw = Math.min(edges.length, 1200);
    for (let i = 0; i < maxDraw; i++) {
      const e = edges[i];
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
    if (this.camera.zoom < 0.45) return; // LoD label culling when zoomed out

    const nodes = this.state.graph.nodes;
    ctx.save();
    ctx.font = '10px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.fillStyle = 'rgba(226, 232, 240, 0.85)';

    const maxLabels = Math.min(nodes.length, 300);
    for (let i = 0; i < maxLabels; i++) {
      const n = nodes[i];
      const p = this.worldToScreen(n.x, n.y);

      // Viewport frustum check
      if (p.x < -40 || p.x > this.lineCanvas.width + 40 || p.y < -20 || p.y > this.lineCanvas.height + 20) {
        continue;
      }
      ctx.fillText(n.name, p.x, p.y + 24 * this.camera.zoom);
    }
    ctx.restore();
  }

  public destroy() {
    this.isDestroyed = true;
    if (this.animationFrameId !== null) {
      cancelAnimationFrame(this.animationFrameId);
    }
    this.physics.destroy();
  }
}
