<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { AetherEngine } from '../engine/engine';
  import RadarMinimap from './RadarMinimap.svelte';
  import { onMount } from 'svelte';
  import { Volume2, VolumeX, Plus, Minus, Maximize2, Play, Pause } from '@lucide/svelte';
  import { playSpatialTone } from '../lib/sound';

  let containerEl: HTMLDivElement;
  let canvasEl: HTMLCanvasElement;
  let lineCanvasEl: HTMLCanvasElement;
  let engine = $state.raw<AetherEngine | null>(null);
  let fps = $state(120);
  let zoomPercent = $state(100);
  let resizeObserver: ResizeObserver | null = null;

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
        if (engine) {
          zoomPercent = Math.round(engine.camera.zoom * 100);
        }
      };
      engine.start();
      if (cockpitState.graph.nodes.length > 0) {
        engine.syncGraphToEngine(true);
      }
    }

    if (containerEl && typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(() => {
        engine?.handleResize();
      });
      resizeObserver.observe(containerEl);
    }

    return () => {
      resizeObserver?.disconnect();
      resizeObserver = null;
      engine?.destroy();
      engine = null;
    };
  });
</script>

<svelte:window onkeydown={handleKeydown} />

<div bind:this={containerEl} class="relative w-full h-full min-h-0 overflow-hidden bg-[#07090e]">
  <!-- WebGL 2 Instanced Celestial Canvas -->
  <canvas
    bind:this={canvasEl}
    id="aether-canvas"
    class="w-full h-full block absolute top-0 left-0 z-10 touch-none"
    style="touch-action: none;"
  ></canvas>

  <!-- 2D Overlay Canvas (Membranes, Lines, Lasers & Starfield) -->
  <canvas
    bind:this={lineCanvasEl}
    id="line-canvas"
    class="w-full h-full block absolute top-0 left-0 z-20 pointer-events-none touch-none"
    style="touch-action: none;"
  ></canvas>

  <!-- Floating Canvas Navigation & Zoom Toolbar HUD -->
  <div
    role="toolbar"
    aria-label="Contrôles de navigation et zoom"
    class="absolute z-30 flex items-center p-1 bg-[#090d16]/92 backdrop-blur-md border border-white/10 rounded-xl shadow-2xl gap-1 transition-all pointer-events-auto {cockpitState.showRadar ? 'bottom-48 sm:bottom-10 right-4 sm:right-[172px]' : 'bottom-10 right-4'}"
  >
    <!-- Zoom In -->
    <button
      type="button"
      onclick={() => {
        engine?.zoomIn();
        if (engine) zoomPercent = Math.round(engine.camera.targetZoom * 100);
        playSpatialTone(cockpitState.settings.soundEnabled, 'action', 0);
      }}
      title="Zoom avant (+)"
      aria-label="Zoom avant"
      class="flex items-center justify-center min-w-[44px] min-h-[44px] sm:min-w-[32px] sm:min-h-[32px] rounded-lg text-slate-300 hover:text-white hover:bg-white/10 active:scale-90 active:bg-sky-500/30 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-sky-400"
    >
      <Plus class="w-4 h-4" />
    </button>

    <!-- Reset Zoom 100% -->
    <button
      type="button"
      onclick={() => {
        engine?.resetZoom();
        zoomPercent = 100;
        playSpatialTone(cockpitState.settings.soundEnabled, 'action', 0);
      }}
      title="Réinitialiser le zoom (1:1 / 100%)"
      aria-label="Réinitialiser le zoom à 1:1"
      class="flex items-center justify-center min-w-[44px] min-h-[44px] sm:min-w-[42px] sm:min-h-[32px] px-1.5 rounded-lg text-xs font-mono font-bold text-sky-400 hover:text-sky-300 hover:bg-white/10 active:scale-90 active:bg-sky-500/30 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-sky-400"
    >
      {zoomPercent}%
    </button>

    <!-- Zoom Out -->
    <button
      type="button"
      onclick={() => {
        engine?.zoomOut();
        if (engine) zoomPercent = Math.round(engine.camera.targetZoom * 100);
        playSpatialTone(cockpitState.settings.soundEnabled, 'action', 0);
      }}
      title="Zoom arrière (-)"
      aria-label="Zoom arrière"
      class="flex items-center justify-center min-w-[44px] min-h-[44px] sm:min-w-[32px] sm:min-h-[32px] rounded-lg text-slate-300 hover:text-white hover:bg-white/10 active:scale-90 active:bg-sky-500/30 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-sky-400"
    >
      <Minus class="w-4 h-4" />
    </button>

    <!-- Fit to screen -->
    <button
      type="button"
      onclick={() => {
        cockpitState.requestCameraFit();
        playSpatialTone(cockpitState.settings.soundEnabled, 'action', 0);
      }}
      title="Recadrer la vue sur le graphe (F)"
      aria-label="Recadrer la vue sur le graphe"
      class="flex items-center justify-center min-w-[44px] min-h-[44px] sm:min-w-[32px] sm:min-h-[32px] rounded-lg text-slate-300 hover:text-white hover:bg-white/10 active:scale-90 active:bg-sky-500/30 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-sky-400"
    >
      <Maximize2 class="w-4 h-4" />
    </button>

    <!-- Physics Pause / Play -->
    <button
      type="button"
      onclick={() => {
        cockpitState.togglePhysicsPaused();
        playSpatialTone(cockpitState.settings.soundEnabled, 'action', 0);
      }}
      title={cockpitState.physicsPaused ? 'Reprendre la simulation physique (P)' : 'Mettre en pause la gravité/physique (P)'}
      aria-label={cockpitState.physicsPaused ? 'Reprendre la simulation physique' : 'Mettre en pause la gravité/physique'}
      class="flex items-center justify-center min-w-[44px] min-h-[44px] sm:min-w-[32px] sm:min-h-[32px] rounded-lg {cockpitState.physicsPaused ? 'bg-amber-500/25 text-amber-300' : 'text-slate-300 hover:text-white hover:bg-white/10'} active:scale-90 transition-all cursor-pointer focus-visible:ring-2 focus-visible:ring-sky-400"
    >
      {#if cockpitState.physicsPaused}
        <Play class="w-4 h-4" />
      {:else}
        <Pause class="w-4 h-4" />
      {/if}
    </button>
  </div>

  <!-- Radar Minimap -->
  <RadarMinimap {engine} />

  <!-- Bottom Telemetry Status Bar -->
  <footer
    class="absolute bottom-0 left-0 right-0 h-7 px-2 sm:px-3 bg-[#080a0f]/90 backdrop-blur-md border-t border-white/5 flex items-center justify-between text-[10px] sm:text-[11px] font-mono text-slate-400 select-none z-30 overflow-x-auto scrollbar-none"
  >
    <div class="flex items-center gap-2 sm:gap-3 shrink-0">
      <span class="flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        <span class="text-slate-300 font-semibold">{cockpitState.graph.nodes.length}</span> <span class="hidden xs:inline">Nœuds</span>
      </span>
      <span class="text-slate-600">·</span>
      <span class="flex items-center gap-1">
        <span class="text-slate-300 font-semibold">{cockpitState.graph.edges.length}</span> <span class="hidden xs:inline">Flux</span>
      </span>
      <span class="text-slate-600">·</span>
      <span class="flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full {cockpitState.allViolations.length > 0 ? 'bg-rose-400' : 'bg-emerald-400'}"></span>
        <span class="text-slate-300 font-semibold">{cockpitState.allViolations.length}</span> <span class="hidden xs:inline">Failles</span>
      </span>
      <span class="hidden sm:inline text-slate-600">·</span>
      <span class="hidden sm:inline text-sky-400 font-semibold">Layout {cockpitState.activeLayout}</span>
    </div>

    <div class="flex items-center gap-1.5 sm:gap-2.5 text-[9.5px] sm:text-[10px] shrink-0">
      <!-- Radar Minimap Toggle -->
      <button
        type="button"
        onclick={() => cockpitState.toggleRadar()}
        class="flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors cursor-pointer {cockpitState.showRadar ? 'text-cyan-300 bg-cyan-950/40 border border-cyan-500/30' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5 border border-transparent'}"
        title="Afficher / Masquer le Radar Minimap (R)"
        aria-label="Afficher ou masquer le radar minimap"
      >
        <span>🧭</span>
        <span class="hidden sm:inline">Radar {cockpitState.showRadar ? 'ON' : 'OFF'}</span>
      </button>

      <!-- Audio Mute/Unmute Toggle -->
      <button
        type="button"
        onclick={() => cockpitState.toggleSound()}
        class="flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors cursor-pointer {cockpitState.settings.soundEnabled ? 'text-sky-300 hover:text-sky-100 hover:bg-white/5' : 'text-slate-500 hover:text-slate-400 hover:bg-white/5'}"
        title={cockpitState.settings.soundEnabled ? "Couper l'audio WebAudio (Mute)" : "Activer l'audio WebAudio (Unmute)"}
        aria-label={cockpitState.settings.soundEnabled ? "Couper l'audio WebAudio" : "Activer l'audio WebAudio"}
      >
        {#if cockpitState.settings.soundEnabled}
          <Volume2 class="w-3 h-3 text-sky-400" />
          <span class="hidden sm:inline text-[9.5px]">Audio</span>
        {:else}
          <VolumeX class="w-3 h-3 text-slate-500" />
          <span class="hidden sm:inline text-[9.5px]">Mute</span>
        {/if}
      </button>

      <span class="text-slate-600">·</span>
      <span class="text-emerald-400 font-bold">{fps} FPS<span class="hidden sm:inline"> (WebGL 2)</span></span>
      <span class="hidden sm:inline text-slate-600">·</span>
      <span class="hidden sm:inline text-purple-400 font-semibold">MCP Zero-Shell</span>
    </div>
  </footer>
</div>
