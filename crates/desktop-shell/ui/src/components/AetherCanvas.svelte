<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { AetherEngine } from '../engine/engine';
  import RadarMinimap from './RadarMinimap.svelte';
  import { onMount } from 'svelte';
  import { Volume2, VolumeX } from '@lucide/svelte';

  let canvasEl: HTMLCanvasElement;
  let lineCanvasEl: HTMLCanvasElement;
  let engine = $state<AetherEngine | null>(null);
  let fps = $state(120);

  function handleKeydown(e: KeyboardEvent) {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
    if (e.key === 'r' || e.key === 'R') {
      if (!e.ctrlKey && !e.metaKey && !e.altKey) {
        cockpitState.toggleRadar();
      }
    }
  }

  onMount(() => {
    if (canvasEl && lineCanvasEl) {
      engine = new AetherEngine(canvasEl, lineCanvasEl, cockpitState);
      engine.onFps = (val) => {
        fps = val;
      };
      engine.start();
      if (cockpitState.graph.nodes.length > 0) {
        engine.syncGraphToEngine(true);
      }
    }

    return () => {
      engine?.destroy();
      engine = null;
    };
  });
</script>

<svelte:window onkeydown={handleKeydown} />

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

    <div class="flex items-center gap-2.5 text-[10px]">
      <!-- Radar Minimap Toggle -->
      <button
        type="button"
        onclick={() => cockpitState.toggleRadar()}
        class="flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors cursor-pointer {cockpitState.showRadar ? 'text-cyan-300 bg-cyan-950/40 border border-cyan-500/30' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5 border border-transparent'}"
        title="Afficher / Masquer le Radar Minimap (R)"
      >
        <span>🧭</span>
        <span>Radar {cockpitState.showRadar ? 'ON' : 'OFF'}</span>
      </button>

      <!-- Audio Mute/Unmute Toggle -->
      <button
        type="button"
        onclick={() => cockpitState.toggleSound()}
        class="flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors cursor-pointer {cockpitState.settings.soundEnabled ? 'text-sky-300 hover:text-sky-100 hover:bg-white/5' : 'text-slate-500 hover:text-slate-400 hover:bg-white/5'}"
        title={cockpitState.settings.soundEnabled ? "Couper l'audio WebAudio (Mute)" : "Activer l'audio WebAudio (Unmute)"}
      >
        {#if cockpitState.settings.soundEnabled}
          <Volume2 class="w-3 h-3 text-sky-400" />
          <span class="text-[9.5px]">Audio</span>
        {:else}
          <VolumeX class="w-3 h-3 text-slate-500" />
          <span class="text-[9.5px]">Mute</span>
        {/if}
      </button>

      <span class="text-slate-600">·</span>
      <span class="text-emerald-400 font-bold">{fps} FPS (WebGL 2)</span>
      <span class="text-slate-600">·</span>
      <span class="text-purple-400 font-semibold">MCP Zero-Shell</span>
    </div>
  </footer>
</div>
