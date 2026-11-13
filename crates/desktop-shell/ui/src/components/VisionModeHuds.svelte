<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { Eye, Flame, Ghost, X, Camera, Sparkles, Layers } from 'lucide-svelte';

  const xrayStats = $derived.by(() => {
    const active = cockpitState.activeSymbol;
    if (!active) return { up: 0, down: 0, total: 0, name: 'Aucun nœud sélectionné' };
    let up = 0;
    let down = 0;
    for (const e of cockpitState.graph.edges) {
      if (e.target === active.id) up++;
      if (e.source === active.id) down++;
    }
    return { up, down, total: up + down, name: active.name };
  });

  const deadcodeStats = $derived.by(() => {
    const list = cockpitState.orphanNodes.slice(0, 12);
    const totalLoc = cockpitState.orphanNodes.reduce((acc, n) => acc + (n.loc || 1), 0);
    return { count: cockpitState.orphanNodes.length, loc: totalLoc, list };
  });

  const heatmapStats = $derived.by(() => {
    const hotspots = [...cockpitState.graph.nodes]
      .sort((a, b) => (b.cyclomatic_complexity || 1) - (a.cyclomatic_complexity || 1))
      .slice(0, 8);
    const avg =
      cockpitState.graph.nodes.length > 0
        ? (
            cockpitState.graph.nodes.reduce((acc, n) => acc + (n.cyclomatic_complexity || 1), 0) /
            cockpitState.graph.nodes.length
          ).toFixed(1)
        : '1.0';
    return { avg, hotspots };
  });

  const depthLabels: Record<1 | 2 | 3 | 4, { tag: string; title: string }> = {
    1: { tag: 'N1', title: 'Architecture & Modules' },
    2: { tag: 'N2', title: 'Fichiers & Classes' },
    3: { tag: 'N3', title: 'Fonctions & Méthodes' },
    4: { tag: 'N4', title: 'Micro-Flux Complet' },
  };
</script>

<!-- X-RAY HUD -->
{#if cockpitState.visionMode === 'xray'}
  <div class="fixed left-1/2 -translate-x-1/2 bottom-12 z-30 w-[340px] max-w-[92vw] rounded-xl border border-purple-500/45 bg-[#0c0a1d]/92 backdrop-blur-md shadow-[0_12px_36px_rgba(168,85,247,0.28)] p-3 text-xs text-slate-200">
    <div class="flex items-center justify-between gap-2 pb-2 border-b border-purple-500/20">
      <div class="flex items-center gap-1.5 font-bold text-purple-300">
        <Eye class="w-4 h-4" />
        <span>Tunnel X-Ray</span>
      </div>
      <div class="flex items-center gap-1">
        <button
          type="button"
          onclick={() => cockpitState.requestSnapshot()}
          class="flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/35 text-[10px] text-purple-200 cursor-pointer"
          title="Capture PNG"
        >
          <Camera class="w-3 h-3" /> Snapshot
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.visionMode = 'standard')}
          class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
          aria-label="Quitter X-Ray"
        >
          <X class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
    <div class="mt-2 flex items-center justify-between">
      <span class="font-mono text-white font-semibold truncate">{xrayStats.name}</span>
      <span class="text-[10px] font-mono text-purple-300">{xrayStats.total} liens</span>
    </div>
    <div class="mt-2 grid grid-cols-3 gap-1.5 text-center font-mono">
      <div class="p-1.5 rounded bg-black/40 border border-white/10">
        <div class="text-[9px] text-slate-400">ENTRANTS</div>
        <div class="text-sm font-bold text-purple-300">{xrayStats.up}</div>
      </div>
      <div class="p-1.5 rounded bg-black/40 border border-white/10">
        <div class="text-[9px] text-slate-400">SORTANTS</div>
        <div class="text-sm font-bold text-sky-300">{xrayStats.down}</div>
      </div>
      <div class="p-1.5 rounded bg-black/40 border border-white/10">
        <div class="text-[9px] text-slate-400">TOTAL</div>
        <div class="text-sm font-bold text-white">{xrayStats.total}</div>
      </div>
    </div>
  </div>
{/if}

<!-- DEADCODE HUD -->
{#if cockpitState.visionMode === 'deadcode'}
  <div class="fixed left-1/2 -translate-x-1/2 bottom-12 z-30 w-[370px] max-w-[92vw] rounded-xl border border-rose-500/45 bg-[#150910]/92 backdrop-blur-md shadow-[0_12px_36px_rgba(244,63,94,0.28)] p-3 text-xs text-slate-200">
    <div class="flex items-center justify-between gap-2 pb-2 border-b border-rose-500/20">
      <div class="flex items-center gap-1.5 font-bold text-rose-300">
        <Ghost class="w-4 h-4" />
        <span>Audit Dead Code & Orphelins</span>
      </div>
      <button
        type="button"
        onclick={() => (cockpitState.visionMode = 'standard')}
        class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
        aria-label="Quitter Dead Code"
      >
        <X class="w-3.5 h-3.5" />
      </button>
    </div>
    <div class="mt-2 grid grid-cols-2 gap-2 font-mono">
      <div class="p-2 rounded bg-black/40 border border-rose-500/20">
        <div class="text-[9px] text-slate-400">SYMBOLES MORTS</div>
        <div class="text-base font-black text-rose-400">{deadcodeStats.count}</div>
      </div>
      <div class="p-2 rounded bg-black/40 border border-rose-500/20">
        <div class="text-[9px] text-slate-400">LOC ÉCONOMISABLES</div>
        <div class="text-base font-black text-amber-300">~{deadcodeStats.loc}</div>
      </div>
    </div>
    {#if deadcodeStats.list.length > 0}
      <div class="mt-2 max-h-24 overflow-y-auto space-y-1 pr-1">
        {#each deadcodeStats.list as n}
          <button
            type="button"
            onclick={() => cockpitState.selectSymbol(n.id, true)}
            class="w-full flex items-center justify-between px-2 py-1 rounded bg-white/[0.04] hover:bg-rose-500/15 text-[10px] font-mono text-left cursor-pointer"
          >
            <span class="truncate text-slate-100">{n.name}</span>
            <span class="text-slate-400 shrink-0 ml-2">{n.loc} LOC</span>
          </button>
        {/each}
      </div>
    {/if}
    <button
      type="button"
      onclick={() => cockpitState.openPromptModal('context')}
      class="mt-2.5 w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-rose-500/25 hover:bg-rose-500/35 border border-rose-500/40 text-[11px] font-semibold text-rose-200 cursor-pointer"
    >
      <Sparkles class="w-3.5 h-3.5" /> Générer Prompt Nettoyage IA
    </button>
  </div>
{/if}

<!-- HEATMAP HUD -->
{#if cockpitState.visionMode === 'heatmap'}
  <div class="fixed left-1/2 -translate-x-1/2 bottom-12 z-30 w-[370px] max-w-[92vw] rounded-xl border border-amber-500/45 bg-[#161006]/92 backdrop-blur-md shadow-[0_12px_36px_rgba(245,158,11,0.28)] p-3 text-xs text-slate-200">
    <div class="flex items-center justify-between gap-2 pb-2 border-b border-amber-500/20">
      <div class="flex items-center gap-1.5 font-bold text-amber-300">
        <Flame class="w-4 h-4" />
        <span>Heatmap Complexité Cyclomatique</span>
      </div>
      <button
        type="button"
        onclick={() => (cockpitState.visionMode = 'standard')}
        class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
        aria-label="Quitter Heatmap"
      >
        <X class="w-3.5 h-3.5" />
      </button>
    </div>
    <div class="mt-2 flex items-center justify-between text-[11px] font-mono">
      <span class="text-slate-400">Moyenne projet : <strong class="text-amber-300">{heatmapStats.avg}</strong></span>
      <span class="text-rose-300">{cockpitState.hotspotNodes.length} hotspots (&ge;10)</span>
    </div>
    <div class="mt-2 max-h-24 overflow-y-auto space-y-1 pr-1">
      {#each heatmapStats.hotspots as n}
        <button
          type="button"
          onclick={() => cockpitState.selectSymbol(n.id, true)}
          class="w-full flex items-center justify-between px-2 py-1 rounded bg-white/[0.04] hover:bg-amber-500/15 text-[10px] font-mono text-left cursor-pointer"
        >
          <span class="truncate text-slate-100">{n.name}</span>
          <span class="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold shrink-0 ml-2">
            CC {n.cyclomatic_complexity || 1}
          </span>
        </button>
      {/each}
    </div>
    <button
      type="button"
      onclick={() => cockpitState.openPromptModal('master')}
      class="mt-2.5 w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-amber-500/25 hover:bg-amber-500/35 border border-amber-500/40 text-[11px] font-semibold text-amber-200 cursor-pointer"
    >
      <Sparkles class="w-3.5 h-3.5" /> Audit Architecture IA (Hotspots)
    </button>
  </div>
{/if}

<!-- DEPTH / LOD SELECTOR BAR (N1..N4) -->
<div class="fixed left-48 bottom-9 z-20 hidden md:flex items-center gap-1 px-2 py-1 rounded-full bg-[#0a0d16]/85 border border-white/10 backdrop-blur-md text-[10px] font-mono text-slate-300">
  <Layers class="w-3 h-3 text-sky-400 mr-0.5" />
  {#each ([1, 2, 3, 4] as const) as d}
    {@const active = (d === 4 ? 'Z-4' : d === 3 ? 'Z-3' : d === 2 ? 'Z-2' : 'Z-1') === cockpitState.activeLayout}
    <button
      type="button"
      title={depthLabels[d].title}
      onclick={() => {
        cockpitState.lodLevel = d === 1 ? 1 : d === 2 ? 2 : 3;
        cockpitState.activeLayout = (`Z-${d}`) as 'Z-1' | 'Z-2' | 'Z-3' | 'Z-4';
      }}
      class="px-1.5 py-0.5 rounded-full transition-colors cursor-pointer {active ? 'bg-sky-500/25 text-sky-200 font-bold border border-sky-400/40' : 'text-slate-400 hover:text-white'}"
    >
      {depthLabels[d].tag}
    </button>
  {/each}
</div>
