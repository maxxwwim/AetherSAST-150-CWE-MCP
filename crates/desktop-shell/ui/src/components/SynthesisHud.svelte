<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    SlidersHorizontal,
    Layers,
    GitBranch,
    RotateCcw,
    BookOpen,
    ChevronRight,
    X
  } from '@lucide/svelte';

  const LAYERS: { id: string; label: string; color: string }[] = [
    { id: 'ui', label: 'UI', color: 'bg-sky-400' },
    { id: 'action', label: 'Actions', color: 'bg-emerald-400' },
    { id: 'domain', label: 'Domain', color: 'bg-indigo-400' },
    { id: 'database', label: 'Database', color: 'bg-purple-400' },
    { id: 'config', label: 'Config', color: 'bg-amber-400' },
    { id: 'utility', label: 'Utils', color: 'bg-slate-400' },
    { id: 'docs', label: 'Docs', color: 'bg-teal-400' },
  ];

  const RELATIONS: { id: string; label: string; color: string }[] = [
    { id: 'calls', label: 'Appels', color: 'text-sky-300 border-sky-500/35' },
    { id: 'imports', label: 'Imports', color: 'text-emerald-300 border-emerald-500/35' },
    { id: 'queries', label: 'Requêtes DB', color: 'text-purple-300 border-purple-500/35' },
    { id: 'violations', label: 'Failles CWE', color: 'text-rose-300 border-rose-500/35' },
  ];

  const rightOffset = $derived(cockpitState.isInspectorOpen ? 'right-[408px]' : 'right-3');
</script>

<!-- Floating Right-Side Synthesis & Quick Dock HUD -->
<div class="absolute top-3 {rightOffset} z-30 flex flex-col items-end gap-2 pointer-events-auto transition-all">
  <div class="flex items-center gap-1.5">
    <button
      type="button"
      onclick={() => (cockpitState.isSynthesisOpen = !cockpitState.isSynthesisOpen)}
      class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#0b0f19]/90 hover:bg-white/10 backdrop-blur-md border border-white/15 text-[11px] font-medium text-slate-200 shadow-xl cursor-pointer transition-colors"
      title="Afficher / Masquer la Synthèse des Couches & Flux"
    >
      <SlidersHorizontal class="w-3.5 h-3.5 text-sky-400" />
      <span>Synthèse & Filtres</span>
    </button>

    {#if !cockpitState.isInspectorOpen}
      <button
        type="button"
        onclick={() => {
          cockpitState.activeTab = 'uml';
          cockpitState.isInspectorOpen = true;
        }}
        class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 backdrop-blur-md border border-indigo-500/40 text-[11px] font-semibold text-indigo-200 shadow-xl cursor-pointer transition-colors"
        title="Ouvrir l'Inspecteur UML & Flux sur la droite"
      >
        <GitBranch class="w-3.5 h-3.5 text-indigo-300" />
        <span>UML & Liens</span>
        <ChevronRight class="w-3 h-3" />
      </button>
    {/if}
  </div>

  {#if cockpitState.isSynthesisOpen}
    <div class="w-72 p-3 rounded-xl bg-[#0b0e17]/95 backdrop-blur-xl border border-white/15 shadow-2xl space-y-3 text-xs select-none">
      <div class="flex items-center justify-between border-b border-white/10 pb-2">
        <span class="text-[11px] font-bold text-white flex items-center gap-1.5">
          <Layers class="w-3.5 h-3.5 text-sky-400" /> Architecture & Liens
        </span>
        <div class="flex items-center gap-1">
          <button
            type="button"
            onclick={() => cockpitState.resetFilters()}
            class="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-white/5 cursor-pointer"
            title="Tout réactiver"
          >
            <RotateCcw class="w-3 h-3" />
          </button>
          <button
            type="button"
            onclick={() => (cockpitState.isSynthesisOpen = false)}
            class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
          >
            <X class="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <!-- Layers Filter -->
      <div class="space-y-1.5">
        <div class="text-[10px] font-mono uppercase text-slate-400">Couches Architecturales</div>
        <div class="flex flex-wrap gap-1.5">
          {#each LAYERS as layer}
            {@const off = Boolean(cockpitState.disabledLayers[layer.id])}
            <button
              type="button"
              onclick={() => cockpitState.toggleLayer(layer.id)}
              class="flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-mono border cursor-pointer transition-all {off ? 'bg-black/30 border-white/5 text-slate-500 opacity-50' : 'bg-white/[0.06] border-white/15 text-slate-100'}"
            >
              <span class="w-2 h-2 rounded-full {layer.color}"></span>
              {layer.label}
            </button>
          {/each}
        </div>
      </div>

      <!-- Relations Filter -->
      <div class="space-y-1.5">
        <div class="text-[10px] font-mono uppercase text-slate-400">Liens & Flux Optiques</div>
        <div class="grid grid-cols-2 gap-1.5">
          {#each RELATIONS as rel}
            {@const off = Boolean(cockpitState.disabledRelations[rel.id])}
            <button
              type="button"
              onclick={() => cockpitState.toggleRelation(rel.id)}
              class="px-2 py-1 rounded-md text-[10px] font-mono border text-center cursor-pointer transition-all {off ? 'bg-black/30 border-white/5 text-slate-500 opacity-50' : `bg-white/[0.04] ${rel.color}`}"
            >
              {rel.label}
            </button>
          {/each}
        </div>
      </div>

      <!-- Quick Shortcuts -->
      <div class="pt-2 border-t border-white/10 flex gap-1.5">
        <button
          type="button"
          onclick={() => cockpitState.openDoc()}
          class="flex-1 flex items-center justify-center gap-1 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 text-[10px] font-semibold cursor-pointer"
        >
          <BookOpen class="w-3 h-3" /> Docs
        </button>
        <button
          type="button"
          onclick={() => cockpitState.requestCameraFit()}
          class="flex-1 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/35 text-sky-300 text-[10px] font-semibold cursor-pointer"
        >
          Recentrer Vue
        </button>
      </div>
    </div>
  {/if}
</div>
