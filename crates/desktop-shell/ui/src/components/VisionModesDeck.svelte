<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    Eye,
    Radio,
    Flame,
    Skull,
    ShieldAlert,
    Sparkles,
    Grid,
    SlidersHorizontal,
    X
  } from '@lucide/svelte';

  let isOpen = $state(false);

  function setVision(mode: 'standard' | 'xray' | 'heatmap' | 'deadcode') {
    cockpitState.visionMode = mode;
  }
</script>

<!-- Floating Vision & Display Pill (Bottom Center-Left) -->
<div class="absolute bottom-10 left-4 z-30 select-none flex flex-col items-start gap-1.5 pointer-events-auto">
  {#if isOpen}
    <div
      class="p-2 bg-[#0c0f17]/95 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl flex flex-col gap-2 min-w-[220px] text-xs"
    >
      <div class="flex items-center justify-between px-1 text-[10px] font-mono uppercase text-slate-400">
        <span>Modes de Vision</span>
        <button
          onclick={() => (isOpen = false)}
          class="p-0.5 rounded text-slate-400 hover:text-white"
        >
          <X class="w-3.5 h-3.5" />
        </button>
      </div>

      <!-- Vision Modes List -->
      <div class="flex flex-col gap-0.5">
        <button
          onclick={() => setVision('standard')}
          class="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white/[0.06] text-left transition-colors {cockpitState.visionMode === 'standard' ? 'bg-sky-500/15 text-sky-400 font-semibold' : 'text-slate-300'}"
        >
          <Eye class="w-3.5 h-3.5 text-sky-400" />
          <span>🌌 Cosmos Standard</span>
        </button>

        <button
          onclick={() => setVision('xray')}
          class="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white/[0.06] text-left transition-colors {cockpitState.visionMode === 'xray' ? 'bg-purple-500/15 text-purple-400 font-semibold' : 'text-slate-300'}"
        >
          <Radio class="w-3.5 h-3.5 text-purple-400" />
          <span>🔦 Tunnel X-Ray</span>
        </button>

        <button
          onclick={() => setVision('heatmap')}
          class="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white/[0.06] text-left transition-colors {cockpitState.visionMode === 'heatmap' ? 'bg-amber-500/15 text-amber-400 font-semibold' : 'text-slate-300'}"
        >
          <Flame class="w-3.5 h-3.5 text-amber-400" />
          <span>🌡️ Heatmap Complexité</span>
        </button>

        <button
          onclick={() => setVision('deadcode')}
          class="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white/[0.06] text-left transition-colors {cockpitState.visionMode === 'deadcode' ? 'bg-rose-500/15 text-rose-400 font-semibold' : 'text-slate-300'}"
        >
          <Skull class="w-3.5 h-3.5 text-rose-400" />
          <span>💀 Code Mort ({cockpitState.orphanNodes.length})</span>
        </button>
      </div>

      <div class="h-px bg-white/10 my-0.5"></div>

      <!-- Quick Stats -->
      <div class="px-1 text-[10px] font-mono text-slate-500 flex items-center justify-between">
        <span>Failles In-Scope :</span>
        <span class="text-rose-400 font-bold">{cockpitState.allViolations.length}</span>
      </div>
    </div>
  {/if}

  <!-- Toggle Trigger Button -->
  <button
    onclick={() => (isOpen = !isOpen)}
    class="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#0c0f17]/90 hover:bg-white/10 backdrop-blur-md border border-white/10 text-xs font-medium text-slate-200 hover:text-white shadow-xl transition-all cursor-pointer"
  >
    <SlidersHorizontal class="w-3.5 h-3.5 text-sky-400" />
    <span class="capitalize font-mono text-[11px]">Vision : {cockpitState.visionMode}</span>
  </button>
</div>
