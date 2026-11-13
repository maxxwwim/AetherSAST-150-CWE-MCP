// =========================================================================
// AETHERSCOPE V2 — OFF-THREAD PHYSICS CONTROLLER (physics.ts)
// Offloads O(N^2) Coulomb/Hooke & 12-Lobe Cellular Membranes to Web Worker
// =========================================================================

import type { SymbolBubble, AffiliationEdge } from '../types/graph';

export interface FolderClusterEntry {
  cx: number;
  cy: number;
  sumX: number;
  sumY: number;
  count: number;
  computedRadius: number;
  naturalRadius: number;
  lobeProfile: Float32Array;
  nodes?: SymbolBubble[];
}

export class PhysicsController {
  private worker: Worker | null = null;
  private isBusy = false;
  private isSleeping = false;

  public onUpdate?: (positions: Float32Array, clusters: Record<string, any>, isSleeping: boolean) => void;

  constructor() {
    this.initWorker();
  }

  private initWorker() {
    if (typeof Worker === 'undefined') return;
    try {
      if (typeof window !== 'undefined' && (window as any).__PHYSICS_WORKER_CODE__) {
        const blob = new Blob([(window as any).__PHYSICS_WORKER_CODE__], { type: 'application/javascript' });
        this.worker = new Worker(URL.createObjectURL(blob));
      } else {
        // Standard Vite worker instantiation
        this.worker = new Worker(new URL('./physics.worker.js', import.meta.url), { type: 'module' });
      }

      this.worker.onmessage = (e: MessageEvent) => {
        const { type, positions, clusters, isSleeping } = e.data;
        if (type === 'UPDATE' && positions) {
          this.isBusy = false;
          this.isSleeping = Boolean(isSleeping);
          if (this.onUpdate) {
            this.onUpdate(positions, clusters, this.isSleeping);
          }
        } else if (type === 'IDLE') {
          this.isBusy = false;
        }
      };

      this.worker.onerror = (err) => {
        console.warn('[AetherScope] Physics Worker error, running headless:', err);
      };
    } catch (e) {
      console.warn('[AetherScope] Failed to initialize Web Worker:', e);
      this.worker = null;
    }
  }

  public sendGraph(nodes: SymbolBubble[], edges: AffiliationEdge[], depth = 1) {
    if (!this.worker || nodes.length === 0) return;
    this.isSleeping = false;
    this.worker.postMessage({
      type: 'INIT',
      payload: {
        nodes: nodes.map((n) => ({
          id: n.id,
          name: n.name,
          x: n.x || 0,
          y: n.y || 0,
          vx: 0,
          vy: 0,
          folder: (n as any).folder || 'root',
          layer: n.layer || 'domain',
          loc: n.loc || 10,
          is_file: n.kind === 'File'
        })),
        edges: edges.map((e) => ({
          source: e.source,
          target: e.target,
          type: e.edge_type
        })),
        depth
      }
    });
  }

  public step(zoom: number) {
    if (!this.worker || this.isBusy || this.isSleeping) return;
    this.isBusy = true;
    this.worker.postMessage({
      type: 'STEP',
      payload: { zoom }
    });
  }

  public wake(steps = 100) {
    this.isSleeping = false;
    if (this.worker) {
      this.worker.postMessage({ type: 'WAKE', payload: { steps } });
    }
  }

  public setDepth(depth: number) {
    this.isSleeping = false;
    if (this.worker) {
      this.worker.postMessage({ type: 'SET_DEPTH', payload: { depth } });
    }
  }

  public drag(id: string, x: number, y: number) {
    this.isSleeping = false;
    if (this.worker) {
      this.worker.postMessage({ type: 'DRAG', payload: { id, x, y } });
    }
  }

  public dragEnd() {
    this.isSleeping = false;
    if (this.worker) {
      this.worker.postMessage({ type: 'DRAG_END' });
    }
  }

  public destroy() {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
  }
}
