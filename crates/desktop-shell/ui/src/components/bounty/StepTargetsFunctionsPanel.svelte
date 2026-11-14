<script lang="ts">
  import type { CveAnomalyRecord, SymbolBubble } from '../../types/graph';
  import {
    getTargetEndpoint,
    getTargetMethod,
    type FileFunctionItem,
  } from './bountyEngine';
  import {
    Check,
    Code2,
    Copy,
    ExternalLink,
    FileCode2,
    GitBranch,
    Layers,
    Search,
    Send,
    ShieldAlert,
  } from '@lucide/svelte';

  interface Props {
    filteredTargets: CveAnomalyRecord[];
    inScopeNodes: SymbolBubble[];
    selectedAnomaly: CveAnomalyRecord | null;
    selectedSymbol: SymbolBubble | null;
    filterSeverity: 'ALL' | 'CRITICAL' | 'HIGH';
    filterReachableOnly: boolean;
    cveSearchQuery: string;
    criticalCount: number;
    fileFunctions: FileFunctionItem[];
    activeFunction: FileFunctionItem | null;
    lockedSingleFolder: string;
    step2Prompt: string;
    copiedKey: string | null;
    sentToMcp: boolean;
    onSelectAnomaly: (a: CveAnomalyRecord) => void;
    onSelectSymbol: (s: SymbolBubble) => void;
    onSelectFunction: (fn: FileFunctionItem) => void;
    onInspectFunctionCodeData: (fn: FileFunctionItem) => void;
    onFocusInGraph: () => void;
    onUnlockFolder: () => void;
    onCopyText: (text: string, key: string) => void;
    onSendPromptToChat: (prompt: string, target: string) => void;
    onGoPrevStep: () => void;
    onGoNextStep: () => void;
  }

  let {
    filteredTargets,
    inScopeNodes,
    selectedAnomaly,
    selectedSymbol,
    filterSeverity = $bindable(),
    filterReachableOnly = $bindable(),
    cveSearchQuery = $bindable(),
    criticalCount,
    fileFunctions,
    activeFunction,
    lockedSingleFolder,
    step2Prompt,
    copiedKey,
    sentToMcp,
    onSelectAnomaly,
    onSelectSymbol,
    onSelectFunction,
    onInspectFunctionCodeData,
    onFocusInGraph,
    onUnlockFolder,
    onCopyText,
    onSendPromptToChat,
    onGoPrevStep,
    onGoNextStep,
  }: Props = $props();

  let targetSourceTab = $state<'vulns' | 'symbols'>('vulns');
  let functionFilterQuery = $state('');

  const filteredFunctions = $derived.by(() => {
    const q = functionFilterQuery.trim().toLowerCase();
    if (!q) return fileFunctions;
    return fileFunctions.filter(
      (f) =>
        f.name.toLowerCase().includes(q) ||
        f.signature.toLowerCase().includes(q) ||
        f.calls.some((c) => c.toLowerCase().includes(q))
    );
  });

  const filteredSymbols = $derived.by(() => {
    const q = cveSearchQuery.trim().toLowerCase();
    const list = inScopeNodes.filter((n) => {
      if (!q) return true;
      return (
        n.name.toLowerCase().includes(q) ||
        n.file_path.toLowerCase().includes(q) ||
        String(n.kind).toLowerCase().includes(q)
      );
    });
    return list.slice(0, 80);
  });

  const activeFilePath = $derived(
    selectedAnomaly?.file_path || selectedSymbol?.file_path || 'Aucun fichier'
  );
</script>

<div class="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden bg-[#080b12]">
  <!-- Left Pane: Targets & Symbols Selector (5 cols) -->
  <div class="lg:col-span-5 border-b lg:border-b-0 lg:border-r border-white/10 flex flex-col overflow-hidden bg-black/30">
    <div class="p-3 border-b border-white/10 space-y-2 shrink-0">
      <div class="grid grid-cols-2 gap-1 p-0.5 rounded-lg bg-black/50 border border-white/10 text-[11px] font-mono">
        <button
          type="button"
          onclick={() => (targetSourceTab = 'vulns')}
          class="py-1.5 px-2 rounded-md flex items-center justify-center gap-1.5 cursor-pointer {targetSourceTab === 'vulns'
            ? 'bg-rose-500/25 text-rose-200 border border-rose-500/40 font-bold'
            : 'text-slate-400 hover:text-white'}"
        >
          <span>🎯 Vulnérabilités</span>
          <span class="px-1.5 rounded bg-black/40 text-[10px]">{filteredTargets.length}</span>
        </button>
        <button
          type="button"
          onclick={() => (targetSourceTab = 'symbols')}
          class="py-1.5 px-2 rounded-md flex items-center justify-center gap-1.5 cursor-pointer {targetSourceTab === 'symbols'
            ? 'bg-sky-500/25 text-sky-200 border border-sky-500/40 font-bold'
            : 'text-slate-400 hover:text-white'}"
        >
          <span>⚡ Symboles AST</span>
          <span class="px-1.5 rounded bg-black/40 text-[10px]">{inScopeNodes.length}</span>
        </button>
      </div>

      {#if targetSourceTab === 'vulns'}
        <div class="flex items-center gap-1 text-[10.5px] font-mono">
          <button
            type="button"
            onclick={() => (filterSeverity = 'ALL')}
            class="flex-1 py-1 rounded text-center cursor-pointer {filterSeverity === 'ALL'
              ? 'bg-white/10 text-white font-bold'
              : 'text-slate-400 hover:text-white'}"
          >
            Tous ({filteredTargets.length})
          </button>
          <button
            type="button"
            onclick={() => (filterSeverity = 'CRITICAL')}
            class="flex-1 py-1 rounded text-center cursor-pointer {filterSeverity === 'CRITICAL'
              ? 'bg-rose-500/20 text-rose-300 font-bold'
              : 'text-slate-400 hover:text-white'}"
          >
            Critique ({criticalCount})
          </button>
          <button
            type="button"
            onclick={() => (filterSeverity = 'HIGH')}
            class="flex-1 py-1 rounded text-center cursor-pointer {filterSeverity === 'HIGH'
              ? 'bg-orange-500/20 text-orange-300 font-bold'
              : 'text-slate-400 hover:text-white'}"
          >
            Élevé
          </button>
        </div>
      {/if}

      <div class="flex items-center gap-1.5">
        <div class="relative flex-1">
          <Search class="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
          <input
            type="text"
            bind:value={cveSearchQuery}
            placeholder="Filtrer CWE, fichier, fonction, paramètre..."
            class="w-full pl-8 pr-2.5 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-rose-400/50"
          />
        </div>
        {#if targetSourceTab === 'vulns'}
          <button
            type="button"
            onclick={() => (filterReachableOnly = !filterReachableOnly)}
            class="px-2.5 py-1.5 rounded-lg text-[10px] font-mono border cursor-pointer shrink-0 {filterReachableOnly
              ? 'bg-emerald-500/25 border-emerald-400 text-emerald-200 font-bold'
              : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
          >
            🟢 Reachable
          </button>
        {/if}
      </div>
    </div>

    <!-- Scrollable List -->
    <div class="flex-1 overflow-y-auto p-2.5 space-y-1.5 scrollbar-thin">
      {#if targetSourceTab === 'vulns'}
        {#each filteredTargets as a}
          {@const isSelected =
            selectedAnomaly?.cve_id === a.cve_id &&
            selectedAnomaly?.line_number === a.line_number &&
            selectedAnomaly?.file_path === a.file_path}
          {@const method = getTargetMethod(a)}
          <button
            type="button"
            onclick={() => onSelectAnomaly(a)}
            class="w-full text-left p-2.5 rounded-xl border transition-all cursor-pointer {isSelected
              ? 'bg-rose-500/15 border-rose-500/55 shadow-md text-white ring-1 ring-rose-400/30'
              : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.05]'}"
          >
            <div class="flex items-center justify-between gap-1 text-[10px] font-mono">
              <div class="flex items-center gap-1.5 flex-wrap">
                <span
                  class="px-1.5 py-0.5 rounded font-bold {a.severity === 'CRITICAL'
                    ? 'bg-rose-500/25 text-rose-300 border border-rose-500/40'
                    : 'bg-amber-500/25 text-amber-300 border border-amber-500/40'}"
                >
                  {a.severity}
                </span>
                <span class="px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-200 border border-sky-500/30 font-semibold">
                  {a.cwe_class || a.cve_id}
                </span>
                <span class="px-1.5 py-0.5 rounded bg-white/10 text-slate-300 font-bold text-[9px]">
                  {method}
                </span>
                {#if a.taint_trace || (a.exploit_path && a.exploit_path.length > 0)}
                  <span class="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-200 border border-cyan-500/35 text-[9px]">
                    🌊 Flux Taint
                  </span>
                {/if}
              </div>
              <span class="text-[9.5px] font-bold shrink-0 {a.is_reachable !== false ? 'text-emerald-400' : 'text-amber-400'}">
                {a.is_reachable !== false ? '🟢 Reachable' : '🟡 Internal'}
              </span>
            </div>

            <div class="text-xs font-semibold truncate mt-1 text-slate-100">
              {a.title || a.message || a.cve_id}
            </div>

            <div class="flex items-center justify-between gap-1 mt-1 text-[9.5px] font-mono text-slate-400">
              <span class="truncate flex-1">{a.file_path}:{a.line_number || 1}</span>
              {#if a.transmitted_data}
                <span class="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-200 border border-purple-500/30 shrink-0">
                  📦 {a.transmitted_data}
                </span>
              {/if}
            </div>
          </button>
        {/each}

        {#if filteredTargets.length === 0}
          <div class="py-12 px-4 text-center text-xs text-slate-400 font-mono space-y-2.5">
            <ShieldAlert class="w-8 h-8 text-slate-600 mx-auto" />
            <div>Aucune vulnérabilité In-Scope avec ces filtres.</div>
            <div class="flex items-center justify-center gap-2 flex-wrap">
              {#if lockedSingleFolder !== 'ALL'}
                <button
                  type="button"
                  onclick={onUnlockFolder}
                  class="px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 text-[11px] cursor-pointer"
                >
                  🌐 Lever le verrou ({lockedSingleFolder})
                </button>
              {/if}
              <button
                type="button"
                onclick={() => (targetSourceTab = 'symbols')}
                class="px-3 py-1.5 rounded-lg bg-sky-500/20 border border-sky-500/40 text-sky-200 text-[11px] cursor-pointer"
              >
                ⚡ Parcourir les Symboles AST
              </button>
            </div>
          </div>
        {/if}
      {:else}
        {#each filteredSymbols as sym (sym.id)}
          {@const isSelected = selectedSymbol?.id === sym.id && !selectedAnomaly}
          <button
            type="button"
            onclick={() => onSelectSymbol(sym)}
            class="w-full text-left p-2.5 rounded-xl border transition-all cursor-pointer {isSelected
              ? 'bg-sky-500/15 border-sky-400/55 text-white ring-1 ring-sky-400/30'
              : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.05]'}"
          >
            <div class="flex items-center justify-between gap-2 text-[10px] font-mono">
              <div class="flex items-center gap-1.5">
                <span class="px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-200 border border-sky-500/30">
                  {sym.stereotype || sym.kind}
                </span>
                <span class="px-1.5 py-0.5 rounded bg-white/10 text-slate-300 uppercase">
                  {sym.layer}
                </span>
              </div>
              <span class="text-slate-400">
                {sym.methods?.length || 0} fn · ⬅️{sym.in_degree} ➡️{sym.out_degree}
              </span>
            </div>
            <div class="text-xs font-bold text-white truncate mt-1">
              {sym.has_security_violation ? '🚨 ' : ''}{sym.name}
            </div>
            <div class="text-[9.5px] font-mono text-slate-400 truncate mt-0.5">
              {sym.file_path}:{sym.line_number || 1}
            </div>
          </button>
        {/each}
      {/if}
    </div>
  </div>

  <!-- Right Pane: Target Functions Explorer + Step 2 Prompt (7 cols) -->
  <div class="lg:col-span-7 flex flex-col p-4 gap-3 overflow-hidden">
    <!-- Target Summary Strip -->
    <div class="p-3 rounded-xl bg-gradient-to-r from-[#0e1524] via-[#0b101b] to-indigo-950/20 border border-sky-500/25 flex items-center justify-between gap-3 flex-wrap shrink-0">
      <div class="min-w-0">
        <div class="flex items-center gap-2 flex-wrap text-[10px] font-mono">
          <span class="px-2 py-0.5 rounded bg-sky-500/20 border border-sky-500/40 text-sky-200 font-bold">
            STEP 2 · FONCTIONS & STRUCTURE
          </span>
          {#if selectedAnomaly}
            <span class="px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-200 font-bold">
              {selectedAnomaly.severity} · {selectedAnomaly.cve_id}
            </span>
            <span class="px-2 py-0.5 rounded bg-white/10 text-slate-300">
              {getTargetMethod(selectedAnomaly)} {getTargetEndpoint(selectedAnomaly)}
            </span>
          {:else if selectedSymbol}
            <span class="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 font-bold">
              {selectedSymbol.name} ({selectedSymbol.layer})
            </span>
          {/if}
        </div>
        <div class="text-xs font-mono text-slate-300 truncate mt-1 flex items-center gap-1.5">
          <FileCode2 class="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <span class="truncate">{activeFilePath}</span>
        </div>
      </div>

      <button
        type="button"
        onclick={onFocusInGraph}
        class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/35 text-xs font-mono text-sky-200 cursor-pointer shrink-0"
      >
        <ExternalLink class="w-3.5 h-3.5" />
        <span>Cibler 3D</span>
      </button>
    </div>

    <!-- Functions Explorer Header & Filter -->
    <div class="flex items-center justify-between gap-2 flex-wrap shrink-0">
      <div class="flex items-center gap-2 text-xs font-mono">
        <Layers class="w-4 h-4 text-purple-400" />
        <span class="font-bold text-white">Fonctions du fichier ({filteredFunctions.length})</span>
        {#if activeFunction}
          <span class="px-2 py-0.5 rounded bg-purple-500/20 border border-purple-400/40 text-purple-200 text-[10px]">
            Active : {activeFunction.name}() L{activeFunction.line}
          </span>
        {/if}
      </div>

      <div class="relative w-60">
        <Search class="w-3 h-3 text-slate-500 absolute left-2.5 top-2" />
        <input
          type="text"
          bind:value={functionFilterQuery}
          placeholder="Filtrer fonction ou appel..."
          class="w-full pl-7 pr-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/10 text-[10.5px] font-mono text-slate-200 focus:outline-none focus:border-purple-400/50"
        />
      </div>
    </div>

    <!-- Functions List -->
    <div class="flex-1 min-h-[180px] overflow-y-auto space-y-1.5 pr-1 scrollbar-thin">
      {#if filteredFunctions.length === 0}
        <div class="py-10 text-center text-xs font-mono text-slate-500 border border-dashed border-white/10 rounded-xl">
          Aucune fonction détaillée extraite pour <code class="text-slate-300">{activeFilePath}</code>.
          Passez au Step 3 pour inspecter le code brut et les flux du graphe.
        </div>
      {:else}
        {#each filteredFunctions as fn (fn.id)}
          {@const isActive = activeFunction?.id === fn.id}
          <div
            class="p-2.5 rounded-xl border transition-all {isActive
              ? 'bg-purple-500/15 border-purple-400/55 ring-1 ring-purple-400/30'
              : fn.isTargetLineInside
                ? 'bg-rose-950/20 border-rose-500/35 hover:border-rose-400/60'
                : 'bg-white/[0.025] border-white/10 hover:border-sky-500/35'}"
          >
            <div class="flex items-start justify-between gap-2">
              <button
                type="button"
                onclick={() => onSelectFunction(fn)}
                class="flex-1 min-w-0 text-left cursor-pointer"
              >
                <div class="flex items-center gap-1.5 flex-wrap font-mono text-[10px]">
                  <span class="px-1.5 py-0.5 rounded bg-white/10 text-slate-300">
                    {fn.visibility} {fn.isAsync ? 'async' : ''}
                  </span>
                  <span class="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
                    L{fn.line}–L{fn.endLine} ({fn.loc} LOC)
                  </span>
                  {#if fn.complexity > 1}
                    <span class="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                      CC {fn.complexity}
                    </span>
                  {/if}
                  {#if fn.isTargetLineInside}
                    <span class="px-1.5 py-0.5 rounded bg-rose-500/30 text-rose-100 border border-rose-400/50 font-bold">
                      🎯 CONTIENT LA FAILLE
                    </span>
                  {/if}
                  {#each fn.taintRoles as role}
                    <span
                      class="px-1.5 py-0.5 rounded font-bold border {role === 'SOURCE'
                        ? 'bg-emerald-500/20 text-emerald-200 border-emerald-400/40'
                        : role === 'SINK'
                          ? 'bg-rose-500/25 text-rose-200 border-rose-400/50'
                          : 'bg-amber-500/20 text-amber-200 border-amber-400/40'}"
                    >
                      {role}
                    </span>
                  {/each}
                </div>

                <div class="font-mono text-xs font-bold text-white mt-1.5 break-all">
                  {fn.signature}
                </div>

                {#if fn.docstring}
                  <p class="text-[11px] text-slate-400 mt-1 line-clamp-2">{fn.docstring}</p>
                {/if}

                {#if fn.calls.length > 0}
                  <div class="flex flex-wrap items-center gap-1 mt-1.5 text-[9.5px] font-mono">
                    <GitBranch class="w-3 h-3 text-cyan-400 shrink-0" />
                    <span class="text-slate-400">Appelle :</span>
                    {#each fn.calls.slice(0, 8) as c}
                      <span class="px-1.5 py-0.5 rounded bg-cyan-950/50 border border-cyan-500/25 text-cyan-200">
                        {c}
                      </span>
                    {/each}
                  </div>
                {/if}
              </button>

              <button
                type="button"
                onclick={() => onInspectFunctionCodeData(fn)}
                class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 border border-sky-400/40 text-sky-200 text-[10.5px] font-mono font-bold shrink-0 cursor-pointer"
                title="Ouvrir le Step 3 centré sur cette fonction"
              >
                <Code2 class="w-3.5 h-3.5" />
                <span>Code & Data</span>
              </button>
            </div>
          </div>
        {/each}
      {/if}
    </div>

    <!-- Step 2 Contextual Prompt Card -->
    <div class="rounded-xl bg-[#05070f] border border-purple-500/30 overflow-hidden shrink-0">
      <div class="px-3 py-1.5 bg-purple-950/25 border-b border-purple-500/20 flex items-center justify-between gap-2 text-[11px] font-mono">
        <span class="text-purple-200 font-bold">📜 Prompt Step 2 — Reconnaissance Fonctions & Cible</span>
        <div class="flex items-center gap-1.5">
          <button
            type="button"
            onclick={() => onCopyText(step2Prompt, 'step2_prompt')}
            class="flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500 hover:bg-purple-400 text-slate-950 font-bold text-[10px] cursor-pointer"
          >
            {#if copiedKey === 'step2_prompt'}
              <Check class="w-3 h-3" />
              <span>Copié !</span>
            {:else}
              <Copy class="w-3 h-3" />
              <span>Copier Prompt Step 2</span>
            {/if}
          </button>
          <button
            type="button"
            onclick={() => onSendPromptToChat(step2Prompt, activeFilePath)}
            class="flex items-center gap-1 px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-white text-[10px] cursor-pointer"
          >
            <Send class="w-3 h-3" />
            <span>{sentToMcp ? 'Envoyé !' : 'Chat MCP'}</span>
          </button>
        </div>
      </div>
      <pre class="p-2.5 font-mono text-[10px] leading-relaxed text-purple-100/90 whitespace-pre-wrap max-h-[115px] overflow-y-auto scrollbar-thin select-text">{step2Prompt}</pre>
    </div>

    <!-- Footer Step Navigation -->
    <div class="flex items-center justify-between pt-1 shrink-0">
      <button
        type="button"
        onclick={onGoPrevStep}
        class="px-3.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-slate-200 text-xs font-mono cursor-pointer"
      >
        ← Étape 1 : Scope
      </button>
      <button
        type="button"
        onclick={onGoNextStep}
        class="px-4 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-cyan-400 hover:from-sky-400 hover:to-cyan-300 text-slate-950 text-xs font-extrabold font-mono shadow-lg shadow-sky-500/20 cursor-pointer"
      >
        Étape 3 : Code & Direction Data ➔
      </button>
    </div>
  </div>
</div>
