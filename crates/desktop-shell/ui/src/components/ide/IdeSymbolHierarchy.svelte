<script lang="ts">
  import { cockpitState } from '../../state/graphState.svelte';
  import { api } from '../../lib/api';
  import type { SymbolBubble } from '../../types/graph';
  import {
    Code2,
    Layers,
    Box,
    Zap,
    CornerDownRight,
    Search,
    X,
    ShieldAlert,
    FileCode,
    Sparkles
  } from '@lucide/svelte';

  let symbolSearch = $state('');

  // Active file path normalized
  let activeFile = $derived(cockpitState.ideActiveFile ? cockpitState.ideActiveFile.replace(/\\/g, '/') : null);

  // AST symbols filtered by current active file
  let fileSymbols = $derived.by(() => {
    if (!activeFile) return [];

    const nodes = cockpitState.graph.nodes.filter((n) => {
      if (!n.file_path) return false;
      const norm = n.file_path.replace(/\\/g, '/');
      // Exclude generic File container nodes unless it is the only node
      const isFileNode = n.is_file || n.kind === 1 || n.id.startsWith('file::');
      return norm === activeFile && !isFileNode;
    });

    // Sort by line_number ascending
    nodes.sort((a, b) => (a.line_number || 0) - (b.line_number || 0));

    if (!symbolSearch.trim()) {
      return nodes;
    }

    const q = symbolSearch.trim().toLowerCase();
    return nodes.filter(
      (n) => n.name.toLowerCase().includes(q) || (n.kind && String(n.kind).toLowerCase().includes(q))
    );
  });

  function getKindBadge(kind: any): { label: string; cls: string; Icon: any } {
    const kStr = String(kind).toLowerCase();
    if (kStr === '0' || kStr.includes('func') || kStr.includes('fn')) {
      return { label: 'Function', cls: 'bg-purple-500/20 text-purple-300 border-purple-500/30', Icon: Code2 };
    }
    if (kStr === '2' || kStr.includes('struct') || kStr.includes('class') || kStr.includes('type')) {
      return { label: 'Struct', cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30', Icon: Box };
    }
    if (kStr === '3' || kStr.includes('endpoint') || kStr.includes('form') || kStr.includes('route')) {
      return { label: 'Endpoint', cls: 'bg-amber-500/20 text-amber-300 border-amber-500/30', Icon: Zap };
    }
    if (kStr === '4' || kStr.includes('contract')) {
      return { label: 'Contract', cls: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30', Icon: Layers };
    }
    if (kStr.includes('method')) {
      return { label: 'Method', cls: 'bg-sky-500/20 text-sky-300 border-sky-500/30', Icon: CornerDownRight };
    }
    return { label: 'Symbol', cls: 'bg-slate-500/20 text-slate-300 border-slate-500/30', Icon: FileCode };
  }

  function handleSelectSymbol(sym: SymbolBubble, lineOverride?: number) {
    cockpitState.activeSymbol = sym;
    const line = lineOverride || sym.line_number || 1;
    cockpitState.ideTargetLine = line;

    // Trigger AI active target update and WebGL camera focus
    api.setAiTarget(sym.id, 'IDE Navigation').catch((err) => {
      console.warn('Erreur AI Target:', err);
    });
    cockpitState.requestFocusSymbol(sym.id);
  }
</script>

<div class="w-full h-full flex flex-col bg-[#070a14] border-r border-white/10 select-none text-xs">
  <!-- Header Bar -->
  <div class="h-9 px-3 border-b border-white/10 flex items-center justify-between bg-black/30 shrink-0">
    <div class="flex items-center gap-2">
      <span class="font-bold uppercase tracking-wider text-[10px] text-slate-300 font-mono">Symboles AST</span>
      {#if activeFile}
        <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/5 text-slate-400 border border-white/5">
          {fileSymbols.length}
        </span>
      {/if}
    </div>
    {#if activeFile}
      <span class="text-[9.5px] font-mono text-slate-500 truncate max-w-[140px]" title={activeFile}>
        {activeFile.split('/').pop()}
      </span>
    {/if}
  </div>

  <!-- Search Filter Input -->
  <div class="p-2 border-b border-white/5 shrink-0 bg-black/20">
    <div class="relative flex items-center">
      <Search class="w-3.5 h-3.5 text-slate-500 absolute left-2 pointer-events-none" />
      <input
        type="text"
        bind:value={symbolSearch}
        placeholder="Filtrer les symboles..."
        class="w-full pl-7 pr-6 py-1 rounded bg-white/[0.04] border border-white/10 text-slate-200 placeholder-slate-500 text-[11px] font-mono focus:outline-none focus:border-sky-500/50 transition-colors"
      />
      {#if symbolSearch}
        <button
          onclick={() => (symbolSearch = '')}
          class="absolute right-1.5 p-0.5 rounded text-slate-400 hover:text-white cursor-pointer"
          title="Effacer le filtre"
        >
          <X class="w-3 h-3" />
        </button>
      {/if}
    </div>
  </div>

  <!-- Symbol List Container -->
  <div class="flex-1 overflow-y-auto overflow-x-hidden p-2 space-y-1 font-mono text-[11.5px] scrollbar-thin">
    {#if !activeFile}
      <div class="py-12 px-4 text-center text-slate-500 text-[11px] flex flex-col items-center gap-2">
        <FileCode class="w-6 h-6 text-slate-600" />
        <span>Ouvrez un fichier source pour inspecter sa structure AST.</span>
      </div>
    {:else if fileSymbols.length === 0}
      <div class="py-12 px-4 text-center text-slate-500 text-[11px] flex flex-col items-center gap-2">
        <Sparkles class="w-5 h-5 text-slate-600" />
        {#if symbolSearch}
          <span>Aucun symbole correspondant à "{symbolSearch}".</span>
        {:else}
          <span>Aucun symbole AST détecté pour ce fichier.</span>
        {/if}
      </div>
    {:else}
      {#each fileSymbols as sym (sym.id)}
        {@const badge = getKindBadge(sym.kind)}
        {@const isSelected = cockpitState.activeSymbol?.id === sym.id}
        {@const hasAnomaly = sym.has_security_violation || (sym.anomalies && sym.anomalies.length > 0) || (sym.metadata?.cve_anomalies && sym.metadata.cve_anomalies.length > 0)}
        {@const anomalyCount = (sym.anomalies?.length || 0) + (sym.metadata?.cve_anomalies?.length || 0) || (sym.has_security_violation ? 1 : 0)}

        <div
          role="button"
          tabindex="0"
          onclick={() => handleSelectSymbol(sym)}
          onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') handleSelectSymbol(sym); }}
          class="w-full flex items-center justify-between p-1.5 rounded transition-colors group cursor-pointer text-left
            {isSelected ? 'bg-sky-500/20 text-sky-200 border-l-2 border-sky-400 font-semibold' : 'text-slate-300 hover:bg-white/[0.04] hover:text-white'}"
          title="{sym.name} (Ligne {sym.line_number || 1})"
        >
          <div class="flex items-center gap-1.5 min-w-0 flex-1">
            <span class="px-1 py-0.2 rounded text-[9px] font-semibold border {badge.cls} shrink-0">
              {badge.label}
            </span>
            <span class="truncate">{sym.name}</span>
          </div>

          <div class="flex items-center gap-1.5 shrink-0 ml-1">
            {#if hasAnomaly}
              <span
                class="flex items-center gap-0.5 px-1 py-0.2 text-[9px] rounded font-mono bg-rose-500/20 border border-rose-500/30 text-rose-300"
                title="{anomalyCount} anomalie(s) de sécurité CWE"
              >
                <ShieldAlert class="w-2.5 h-2.5 text-rose-400" />
                <span>CWE</span>
              </span>
            {/if}

            <span class="px-1.5 py-0.2 rounded text-[9.5px] font-mono bg-white/5 border border-white/10 text-slate-400">
              L{sym.line_number || 1}
            </span>
          </div>
        </div>

        <!-- Render Inner Methods if present on struct/class -->
        {#if sym.methods && sym.methods.length > 0}
          <div class="pl-4 space-y-0.5 border-l border-white/5 ml-2 mt-0.5">
            {#each sym.methods as m (m.name)}
              {@const methodLine = m.line || sym.line_number || 1}
              <div
                role="button"
                tabindex="0"
                onclick={() => handleSelectSymbol(sym, methodLine)}
                onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') handleSelectSymbol(sym, methodLine); }}
                class="flex items-center justify-between py-0.5 px-1 rounded text-slate-400 hover:text-sky-200 hover:bg-white/[0.03] cursor-pointer text-[10.5px]"
                title="{sym.name}::{m.name} (L{methodLine})"
              >
                <div class="flex items-center gap-1 min-w-0">
                  <CornerDownRight class="w-2.5 h-2.5 text-sky-400/70 shrink-0" />
                  <span class="truncate">{m.name}()</span>
                </div>
                <span class="text-[9px] font-mono text-slate-600">L{methodLine}</span>
              </div>
            {/each}
          </div>
        {/if}
      {/each}
    {/if}
  </div>
</div>
