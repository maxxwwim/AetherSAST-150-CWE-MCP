<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { AetherEngine } from '../engine/engine';
  import RadarMinimap from './RadarMinimap.svelte';
  import { onMount } from 'svelte';

  let canvasEl: HTMLCanvasElement;
  let lineCanvasEl: HTMLCanvasElement;
  let engine = $state<AetherEngine | null>(null);
  let fps = $state(120);

  onMount(() => {
    if (canvasEl && lineCanvasEl) {
      engine = new AetherEngine(canvasEl, lineCanvasEl, cockpitState);
      engine.onFps = (val) => {
        fps = val;
      };
      engine.start();
    }

    return () => {
      engine?.destroy();
      engine = null;
    };
  });

  $effect(() => {
    if (engine && cockpitState.graph.nodes.length > 0) {
      engine.syncGraphToEngine();
    }
  });
</script>

<div class="relative w-full h-[calc(100vh-44px)] overflow-hidden bg-[#07090e]">
  <!-- WebGL 2 Instanced Celestial Canvas -->
  <canvas
    bind:this={canvasEl}
    id="aether-canvas"
    class="w-full h-full block absolute top-0 left-0 z-10"
  ></canvas>

  <!-- 2D Overlay Canvas (Membranes, Lines, Lasers & Starfield) -->
  <canvas
    bind:this={lineCanvasEl}
    id="line-canvas"
    class="w-full h-full block absolute top-0 left-0 z-20 pointer-events-none"
  ></canvas>

  <!-- Radar Minimap -->
  <RadarMinimap {engine} />

  <!-- Bottom Telemetry Status Bar -->
  <footer
    class="absolute bottom-0 left-0 right-0 h-7 px-3 bg-[#080a0f]/90 backdrop-blur-md border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-slate-400 select-none z-30"
  >
    <div class="flex items-center gap-3">
      <span class="flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        <span class="text-slate-300 font-semibold">{cockpitState.graph.nodes.length}</span> Nœuds
      </span>
      <span class="text-slate-600">·</span>
      <span class="flex items-center gap-1">
        <span class="text-slate-300 font-semibold">{cockpitState.graph.edges.length}</span> Flux
      </span>
      <span class="text-slate-600">·</span>
      <span class="flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full {cockpitState.allViolations.length > 0 ? 'bg-rose-400' : 'bg-emerald-400'}"></span>
        <span class="text-slate-300 font-semibold">{cockpitState.allViolations.length}</span> Failles
      </span>
      <span class="text-slate-600">·</span>
      <span class="text-sky-400 font-semibold">Layout {cockpitState.activeLayout}</span>
    </div>

    <div class="flex items-center gap-3 text-[10px]">
      <span class="text-emerald-400 font-bold">{fps} FPS (WebGL 2)</span>
      <span class="text-slate-600">·</span>
      <span class="text-purple-400 font-semibold">MCP Zero-Shell</span>
    </div>
  </footer>
</div>
