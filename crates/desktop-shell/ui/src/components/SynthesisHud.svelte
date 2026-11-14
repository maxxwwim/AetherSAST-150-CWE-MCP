<script lang="ts">
  import { cockpitState, normalizeEdgeRelation } from '../state/graphState.svelte';
  import { getFolderColor, formatFolderLabel } from '../engine/palette';
  import {
    SlidersHorizontal,
    Layers,
    GitBranch,
    FolderOpen,
    ShieldAlert,
    BookOpen,
    ChevronDown,
    ChevronRight,
    Zap,
    RotateCcw,
    X,
    Search,
    Eye,
    EyeOff
  } from '@lucide/svelte';

  const LAYER_META: Record<string, { label: string; hex: string }> = {
    ui: { label: 'UI', hex: '#ec4899' },
    action: { label: 'ACTION', hex: '#38bdf8' },
    domain: { label: 'DOMAIN', hex: '#f59e0b' },
    database: { label: 'DATABASE', hex: '#818cf8' },
    config: { label: 'CONFIG', hex: '#94a3b8' },
    utility: { label: 'UTILITY', hex: '#c084fc' },
    docs: { label: 'DOCS', hex: '#10b981' },
  };

  const RELATION_META: Record<string, { label: string; color: string; dashed?: boolean; order: number }> = {
    submits: { label: 'Soumissions UI (submits)', color: '#ff6b00', order: 1 },
    network: { label: 'Appels Réseau (network)', color: '#00c8ff', order: 2 },
    realtime: { label: 'Temps Réel WS (realtime)', color: '#34d399', order: 3 },
    queries: { label: 'Requêtes DB (queries)', color: '#a855f7', order: 4 },
    calls: { label: 'Appels AST (calls)', color: '#38bdf8', order: 5 },
    renders: { label: 'Rendu UI (renders)', color: '#f472b6', order: 6 },
    imports: { label: 'Imports Modules (imports)', color: '#fbbf24', dashed: true, order: 7 },
    contains: { label: 'Contient (contains)', color: '#64748b', dashed: true, order: 8 },
    inherits: { label: 'Héritage (inherits)', color: '#fb923c', order: 9 },
    warns: { label: 'Budget Lignes (warns)', color: '#f97316', dashed: true, order: 10 },
    violates: { label: 'Violations CWE (violates)', color: '#ef4444', order: 11 },
    documents: { label: 'Doc -> Code (documents)', color: '#10b981', dashed: true, order: 12 },
    binds: { label: 'Contrats (binds)', color: '#818cf8', order: 13 },
  };

  let moduleFilter = $state('');
  let openAcc = $state({
    modules: true,
    layers: true,
    links: true,
    cve: true,
  });

  // Live module counts from graph nodes
  const moduleEntries = $derived.by(() => {
    const map = new Map<string, number>();
    for (const n of cockpitState.graph.nodes) {
      const f = n.folder || n.cluster_id || 'root';
      map.set(f, (map.get(f) || 0) + 1);
    }
    const q = moduleFilter.trim().toLowerCase();
    return Array.from(map.entries())
      .filter(([folder]) => !q || folder.toLowerCase().includes(q))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([folder, count]) => {
        const col = getFolderColor(folder);
        const rgb = `rgb(${Math.round(col.r * 255)}, ${Math.round(col.g * 255)}, ${Math.round(col.b * 255)})`;
        return { folder, shortName: formatFolderLabel(folder), count, rgb };
      });
  });

  // Live layer counts from graph nodes
  const layerEntries = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const key of Object.keys(LAYER_META)) counts.set(key, 0);
    for (const n of cockpitState.graph.nodes) {
      const l = (n.layer || 'utility').toLowerCase();
      counts.set(l, (counts.get(l) || 0) + 1);
    }
    return Array.from(counts.entries()).map(([id, count]) => ({
      id,
      count,
      meta: LAYER_META[id] || { label: id.toUpperCase(), hex: '#38bdf8' },
    }));
  });

  // Live normalized relation typology counts from graph edges
  const relationEntries = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const k of ['submits', 'network', 'realtime', 'queries', 'calls', 'renders', 'imports', 'contains', 'inherits', 'violates', 'documents', 'binds']) {
      counts.set(k, 0);
    }
    for (const e of cockpitState.graph.edges) {
      const norm = normalizeEdgeRelation(e.relation || e.edge_type);
      counts.set(norm, (counts.get(norm) || 0) + 1);
    }
    return Array.from(counts.entries())
      .filter(([k, count]) => count > 0 || (RELATION_META[k] && RELATION_META[k].order <= 10))
      .sort((a, b) => {
        const oa = RELATION_META[a[0]]?.order ?? 99;
        const ob = RELATION_META[b[0]]?.order ?? 99;
        if (oa !== ob) return oa - ob;
        return b[1] - a[1];
      })
      .map(([id, count]) => ({
        id,
        count,
        meta: RELATION_META[id] || { label: `Liaison ${id}`, color: '#38bdf8', order: 99 },
      }));
  });

  const rightOffset = $derived(cockpitState.isInspectorOpen ? 'right-[408px]' : 'right-3');
</script>

<!-- Floating Right-Side Synthesis & Multi-Layer Dock -->
<div class="absolute top-3 {rightOffset} z-30 flex flex-col items-end gap-2 pointer-events-auto transition-all">
  <div class="flex items-center gap-1.5">
    <button
      type="button"
      onclick={() => (cockpitState.isSynthesisOpen = !cockpitState.isSynthesisOpen)}
      class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#0b0f19]/92 hover:bg-white/10 backdrop-blur-md border border-sky-500/30 text-[11px] font-medium text-slate-100 shadow-xl cursor-pointer transition-colors"
      title="Ouvrir / Fermer le menu Synthèse Multi-Couches & Liens"
    >
      <SlidersHorizontal class="w-3.5 h-3.5 text-sky-400" />
      <span>Synthèse</span>
      <span class="px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 font-mono text-[10px]">
        {cockpitState.graph.edges.length} flux
      </span>
    </button>

    {#if !cockpitState.isInspectorOpen}
      <button
        type="button"
        onclick={() => {
          cockpitState.activeTab = 'uml';
          cockpitState.isInspectorOpen = true;
        }}
        class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 backdrop-blur-md border border-indigo-500/40 text-[11px] font-semibold text-indigo-200 shadow-xl cursor-pointer transition-colors"
        title="Ouvrir l'Inspecteur UML, Fonctions & Liens à droite"
      >
        <GitBranch class="w-3.5 h-3.5 text-indigo-300" />
        <span>UML & Liens</span>
        <ChevronRight class="w-3 h-3" />
      </button>
    {/if}
  </div>

  {#if cockpitState.isSynthesisOpen}
    <div class="w-[340px] max-h-[calc(100vh-110px)] flex flex-col rounded-xl bg-[#0a0d16]/96 backdrop-blur-xl border border-white/15 shadow-2xl text-xs select-none overflow-hidden">
      <!-- Header -->
      <div class="px-3.5 py-2.5 bg-[#0f172a]/80 border-b border-white/10 flex items-center justify-between">
        <div>
          <div class="text-xs font-bold text-white flex items-center gap-1.5">
            <span>🪐</span> Synthèse Multi-Couches
          </div>
          <div class="text-[10px] font-mono text-slate-400">
            {cockpitState.graph.nodes.length} symboles • {cockpitState.graph.edges.length} flux • {cockpitState.allViolations.length} CWE
          </div>
        </div>
        <div class="flex items-center gap-1">
          <button
            type="button"
            onclick={() => cockpitState.resetFilters()}
            class="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-white/5 cursor-pointer"
            title="Tout réinitialiser"
          >
            <RotateCcw class="w-3.5 h-3.5" />
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

      <div class="flex-1 overflow-y-auto p-3 space-y-2.5">
        <!-- 1. Modules & Dossiers -->
        <div class="rounded-lg border border-white/10 bg-white/[0.02] overflow-hidden">
          <div
            class="px-2.5 py-2 flex items-center justify-between bg-white/[0.03] cursor-pointer"
            onclick={() => (openAcc.modules = !openAcc.modules)}
            onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (openAcc.modules = !openAcc.modules)}
            role="button"
            tabindex="0"
          >
            <div class="flex items-center gap-1.5 font-semibold text-slate-200 text-[11px]">
              <ChevronDown class="w-3.5 h-3.5 transition-transform {openAcc.modules ? '' : '-rotate-90'}" />
              <FolderOpen class="w-3.5 h-3.5 text-amber-400" />
              <span>Modules & Dossiers ({moduleEntries.length})</span>
            </div>
            <div class="flex items-center gap-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="none">
              <button
                type="button"
                onclick={() => cockpitState.setAllModules(true)}
                class="px-1.5 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 text-sky-300 text-[9.5px] font-mono cursor-pointer"
              >
                Tout ON
              </button>
              <button
                type="button"
                onclick={() => cockpitState.setAllModules(false)}
                class="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-slate-400 text-[9.5px] font-mono cursor-pointer"
              >
                OFF
              </button>
            </div>
          </div>

          {#if openAcc.modules}
            <div class="p-2 space-y-1.5">
              <div class="relative">
                <Search class="w-3 h-3 text-slate-500 absolute left-2 top-2" />
                <input
                  type="text"
                  bind:value={moduleFilter}
                  placeholder="Filtrer un dossier..."
                  class="w-full pl-6 pr-2 py-1 rounded bg-black/40 border border-white/10 text-[10.5px] text-slate-200 focus:outline-none focus:border-sky-500/50"
                />
              </div>
              <div class="max-h-36 overflow-y-auto space-y-1 pr-0.5">
                {#each moduleEntries as mod}
                  {@const off = Boolean(cockpitState.disabledModules[mod.folder])}
                  <div class="flex items-center gap-1">
                    <button
                      type="button"
                      onclick={() => cockpitState.toggleModule(mod.folder)}
                      class="flex-1 flex items-center justify-between px-2 py-1 rounded text-[10.5px] font-mono border cursor-pointer transition-all min-w-0 {off ? 'bg-black/30 border-white/5 text-slate-500 opacity-55' : 'bg-white/[0.04] border-white/10 text-slate-100 hover:bg-white/[0.08]'}"
                    >
                      <span class="flex items-center gap-1.5 truncate">
                        {#if off}<EyeOff class="w-3 h-3 text-slate-500 shrink-0" />{:else}<Eye class="w-3 h-3 text-sky-400 shrink-0" />{/if}
                        <span class="w-2 h-2 rounded-full shrink-0" style="background:{mod.rgb};"></span>
                        <span class="truncate" title={mod.folder}>{mod.shortName}</span>
                      </span>
                      <span class="text-[9.5px] text-slate-400 ml-1 shrink-0">{mod.count}</span>
                    </button>
                    <button
                      type="button"
                      onclick={() => cockpitState.selectFolder(mod.folder, true)}
                      title="Ouvrir README / Doc du module"
                      class="p-1 rounded bg-emerald-500/10 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 cursor-pointer shrink-0"
                    >
                      <BookOpen class="w-3 h-3" />
                    </button>
                  </div>
                {/each}
              </div>
            </div>
          {/if}
        </div>

        <!-- 2. Couches Architecturales -->
        <div class="rounded-lg border border-white/10 bg-white/[0.02] overflow-hidden">
          <div
            class="px-2.5 py-2 flex items-center justify-between bg-white/[0.03] cursor-pointer"
            onclick={() => (openAcc.layers = !openAcc.layers)}
            onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (openAcc.layers = !openAcc.layers)}
            role="button"
            tabindex="0"
          >
            <div class="flex items-center gap-1.5 font-semibold text-slate-200 text-[11px]">
              <ChevronDown class="w-3.5 h-3.5 transition-transform {openAcc.layers ? '' : '-rotate-90'}" />
              <Layers class="w-3.5 h-3.5 text-sky-400" />
              <span>Couches Architecturales</span>
            </div>
            <div class="flex items-center gap-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="none">
              <button
                type="button"
                onclick={() => cockpitState.setAllLayers(true)}
                class="px-1.5 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 text-sky-300 text-[9.5px] font-mono cursor-pointer"
              >
                Tout ON
              </button>
              <button
                type="button"
                onclick={() => cockpitState.setAllLayers(false)}
                class="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-slate-400 text-[9.5px] font-mono cursor-pointer"
              >
                OFF
              </button>
            </div>
          </div>

          {#if openAcc.layers}
            <div class="p-2 flex flex-wrap gap-1.5">
              {#each layerEntries as item}
                {@const off = Boolean(cockpitState.disabledLayers[item.id])}
                <button
                  type="button"
                  onclick={() => cockpitState.toggleLayer(item.id)}
                  style="border-color:{off ? 'rgba(255,255,255,0.08)' : item.meta.hex}; color:{off ? '#64748b' : item.meta.hex}; background:{off ? 'transparent' : `${item.meta.hex}1a`};"
                  class="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold border cursor-pointer transition-all {off ? 'opacity-45 line-through' : ''}"
                >
                  {item.meta.label} ({item.count})
                </button>
              {/each}
            </div>
          {/if}
        </div>

        <!-- 3. Pipeline & Typologie des Liens -->
        <div class="rounded-lg border border-white/10 bg-white/[0.02] overflow-hidden">
          <div
            class="px-2.5 py-2 flex items-center justify-between bg-white/[0.03] cursor-pointer"
            onclick={() => (openAcc.links = !openAcc.links)}
            onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (openAcc.links = !openAcc.links)}
            role="button"
            tabindex="0"
          >
            <div class="flex items-center gap-1.5 font-semibold text-slate-200 text-[11px]">
              <ChevronDown class="w-3.5 h-3.5 transition-transform {openAcc.links ? '' : '-rotate-90'}" />
              <GitBranch class="w-3.5 h-3.5 text-purple-400" />
              <span>Typologie des Liens ({relationEntries.length})</span>
            </div>
            <div class="flex items-center gap-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="none">
              <button
                type="button"
                onclick={() => cockpitState.setAllRelations(true)}
                class="px-1.5 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 text-sky-300 text-[9.5px] font-mono cursor-pointer"
              >
                Tout ON
              </button>
              <button
                type="button"
                onclick={() => cockpitState.setAllRelations(false, relationEntries.map((r) => r.id))}
                class="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-slate-400 text-[9.5px] font-mono cursor-pointer"
              >
                OFF
              </button>
            </div>
          </div>

          {#if openAcc.links}
            <div class="p-2 space-y-1.5">
              <button
                type="button"
                onclick={() => cockpitState.togglePipelineHighlight()}
                class="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg border text-[10.5px] font-semibold cursor-pointer transition-all {cockpitState.pipelineHighlight ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200 shadow-sm' : 'bg-sky-500/10 border-sky-500/30 text-sky-300 hover:bg-sky-500/15'}"
              >
                <span class="flex items-center gap-1.5">
                  <Zap class="w-3.5 h-3.5 text-cyan-300" />
                  <span>Traçabilité (Submit➔Net➔WS➔DB)</span>
                </span>
                <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-black/40 border border-cyan-500/40">
                  {cockpitState.pipelineHighlight ? 'ON' : 'OFF'}
                </span>
              </button>

              <div class="max-h-48 overflow-y-auto space-y-1 pr-0.5">
                {#each relationEntries as rel}
                  {@const off = Boolean(cockpitState.disabledRelations[rel.id])}
                  <button
                    type="button"
                    onclick={() => cockpitState.toggleRelation(rel.id)}
                    class="w-full flex items-center justify-between gap-2 px-2 py-1 rounded text-[10.5px] border cursor-pointer transition-all {off ? 'bg-black/30 border-white/5 text-slate-500 opacity-50' : 'bg-white/[0.03] border-white/10 text-slate-200 hover:bg-white/[0.07]'}"
                  >
                    <span class="flex items-center gap-2 min-w-0">
                      <span
                        class="w-4 h-0.5 shrink-0 rounded-full"
                        style="background:{rel.meta.color}; {rel.meta.dashed ? `border-top:2px dashed ${rel.meta.color}; background:transparent;` : ''}"
                      ></span>
                      <span class="truncate">{rel.meta.label}</span>
                    </span>
                    <span class="flex items-center gap-1.5 shrink-0 font-mono text-[9.5px]">
                      <span class="text-slate-400">({rel.count})</span>
                      <span class="px-1 rounded {off ? 'bg-slate-800 text-slate-400' : 'bg-emerald-500/20 text-emerald-300'}">
                        {off ? 'OFF' : 'ON'}
                      </span>
                    </span>
                  </button>
                {/each}
              </div>
            </div>
          {/if}
        </div>

        <!-- 4. Sécurité CWE -->
        <div class="rounded-lg border border-rose-500/30 bg-rose-500/5 p-2 space-y-1.5">
          <div class="flex items-center justify-between text-[11px] font-semibold text-rose-300">
            <span class="flex items-center gap-1.5">
              <ShieldAlert class="w-3.5 h-3.5 text-rose-400" />
              Zero-Day & CWE Anomalies
            </span>
            <span class="px-1.5 py-0.5 rounded bg-rose-500/25 text-rose-200 font-mono text-[10px] font-bold">
              {cockpitState.allViolations.length}
            </span>
          </div>
          <div class="flex gap-1.5">
            <button
              type="button"
              onclick={() => {
                cockpitState.activeTab = 'cve';
                cockpitState.isInspectorOpen = true;
              }}
              class="flex-1 py-1.5 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-[10px] font-semibold cursor-pointer"
            >
              🚨 Ouvrir Audit CWE
            </button>
            <button
              type="button"
              onclick={() => (cockpitState.isBountyModalOpen = true)}
              class="flex-1 py-1.5 rounded bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/35 text-amber-200 text-[10px] font-semibold cursor-pointer"
            >
              🎯 Scope PoC
            </button>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>
