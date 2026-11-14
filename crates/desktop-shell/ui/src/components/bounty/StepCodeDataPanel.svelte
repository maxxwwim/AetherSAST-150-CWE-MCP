<script lang="ts">
  import type { CveAnomalyRecord, SymbolBubble } from '../../types/graph';
  import {
    tokenizeLine,
    type CodeViewerLine,
    type DataFlowNode,
    type FileFunctionItem,
    type TargetDataDirection,
  } from './bountyEngine';
  import {
    ArrowLeft,
    ArrowRight,
    Check,
    Code2,
    Copy,
    ExternalLink,
    GitBranch,
    Layers,
    Send,
    ShieldAlert,
    ShieldCheck,
  } from '@lucide/svelte';

  interface Props {
    selectedAnomaly: CveAnomalyRecord | null;
    selectedSymbol: SymbolBubble | null;
    fileFunctions: FileFunctionItem[];
    activeFunction: FileFunctionItem | null;
    codeLines: CodeViewerLine[];
    codeViewMode: 'excerpt' | 'full';
    snippetLoading: boolean;
    snippetFileError: string;
    dataDirection: TargetDataDirection;
    step3Prompt: string;
    copiedKey: string | null;
    sentToMcp: boolean;
    onSelectFunction: (fn: FileFunctionItem) => void;
    onToggleCodeViewMode: (mode: 'excerpt' | 'full') => void;
    onJumpToDataNode: (node: DataFlowNode) => void;
    onFocusInGraph: () => void;
    onCopyText: (text: string, key: string) => void;
    onSendPromptToChat: (prompt: string, target: string) => void;
    onGoPrevStep: () => void;
    onGoNextStep: () => void;
  }

  let {
    selectedAnomaly,
    selectedSymbol,
    fileFunctions,
    activeFunction,
    codeLines,
    codeViewMode = $bindable(),
    snippetLoading,
    snippetFileError,
    dataDirection,
    step3Prompt,
    copiedKey,
    sentToMcp,
    onSelectFunction,
    onToggleCodeViewMode,
    onJumpToDataNode,
    onFocusInGraph,
    onCopyText,
    onSendPromptToChat,
    onGoPrevStep,
    onGoNextStep,
  }: Props = $props();

  let layoutMode = $state<'split' | 'code' | 'data'>('split');
  let dataSubTab = $state<'pipeline' | 'steps' | 'table'>('pipeline');
  let codeScrollEl = $state<HTMLDivElement | null>(null);

  const activeFilePath = $derived(
    selectedAnomaly?.file_path || selectedSymbol?.file_path || dataDirection.targetNode.filePath || 'unknown'
  );
  const targetLine = $derived(
    selectedAnomaly?.line_number || activeFunction?.line || selectedSymbol?.line_number || 1
  );

  function truncateSvg(str: string, maxLen: number): string {
    if (!str) return '';
    return str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : str;
  }

  function handleFunctionJump(fn: FileFunctionItem) {
    onSelectFunction(fn);
    setTimeout(() => {
      if (!codeScrollEl) return;
      const lineEl = codeScrollEl.querySelector(`[data-line="${fn.line}"]`);
      if (lineEl) {
        lineEl.scrollIntoView({ block: 'center', behavior: 'smooth' });
      }
    }, 30);
  }

  const svgUpstream = $derived(dataDirection.upstream.slice(0, 5));
  const svgDownstream = $derived(dataDirection.downstream.slice(0, 5));
  const svgRows = $derived(Math.max(1, svgUpstream.length, svgDownstream.length));
  const svgHeight = $derived(Math.max(210, svgRows * 52 + 30));
  const svgCenterY = $derived(Math.round(svgHeight / 2));

  function copyVisibleCode() {
    const text = codeLines.map((l) => `${String(l.num).padStart(4, ' ')} | ${l.text}`).join('\n');
    onCopyText(text, 'step3_code');
  }
</script>

<div class="flex-1 flex flex-col overflow-hidden bg-[#080b12]">
  <!-- Top Sub-Bar: Active Target + Layout Switcher + Data Summary -->
  <div class="px-4 py-2 border-b border-white/10 bg-[#0b101b] flex items-center justify-between gap-2 flex-wrap shrink-0">
    <div class="flex items-center gap-2 min-w-0 flex-wrap font-mono text-[10.5px]">
      <span class="px-2 py-0.5 rounded bg-cyan-500/20 border border-cyan-400/40 text-cyan-200 font-bold">
        STEP 3 · CODE & DIRECTION DATA
      </span>
      <span class="text-slate-200 font-semibold truncate max-w-[300px]" title={activeFilePath}>
        {activeFilePath}:{targetLine}
      </span>
      {#if activeFunction}
        <span class="px-2 py-0.5 rounded bg-purple-500/20 border border-purple-400/40 text-purple-200">
          ƒ {activeFunction.name}()
        </span>
      {/if}
      {#if selectedAnomaly?.transmitted_data}
        <span class="px-2 py-0.5 rounded bg-amber-500/20 border border-amber-400/40 text-amber-200">
          📦 {selectedAnomaly.transmitted_data}
        </span>
      {/if}
    </div>

    <div class="flex items-center gap-1.5 font-mono text-[10.5px]">
      <div class="flex p-0.5 rounded-lg bg-black/50 border border-white/10">
        <button
          type="button"
          onclick={() => (layoutMode = 'split')}
          class="px-2.5 py-1 rounded-md cursor-pointer {layoutMode === 'split'
            ? 'bg-sky-500/25 text-sky-200 font-bold'
            : 'text-slate-400 hover:text-white'}"
        >
          Split Code + Data
        </button>
        <button
          type="button"
          onclick={() => (layoutMode = 'code')}
          class="px-2.5 py-1 rounded-md cursor-pointer {layoutMode === 'code'
            ? 'bg-rose-500/25 text-rose-200 font-bold'
            : 'text-slate-400 hover:text-white'}"
        >
          Code & Fonctions
        </button>
        <button
          type="button"
          onclick={() => (layoutMode = 'data')}
          class="px-2.5 py-1 rounded-md cursor-pointer {layoutMode === 'data'
            ? 'bg-cyan-500/25 text-cyan-200 font-bold'
            : 'text-slate-400 hover:text-white'}"
        >
          Direction Data
        </button>
      </div>

      <button
        type="button"
        onclick={onFocusInGraph}
        class="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/5 hover:bg-sky-500/20 border border-white/15 text-sky-200 cursor-pointer"
      >
        <ExternalLink class="w-3 h-3" />
        <span class="hidden sm:inline">Graphe 3D</span>
      </button>
    </div>
  </div>

  <!-- Main Workspace Area -->
  <div class="flex-1 grid grid-cols-1 {layoutMode === 'split' ? 'lg:grid-cols-12' : ''} overflow-hidden">
    <!-- LEFT: CODE SOURCE & FUNCTIONS JUMP -->
    {#if layoutMode === 'split' || layoutMode === 'code'}
      <div
        class="{layoutMode === 'split' ? 'lg:col-span-6 border-b lg:border-b-0 lg:border-r border-white/10' : ''} flex flex-col overflow-hidden bg-[#060810]"
      >
        <!-- Code Header + Mode Switcher -->
        <div class="px-3.5 py-2 bg-[#0c101b] border-b border-white/10 flex items-center justify-between gap-2 flex-wrap shrink-0">
          <div class="flex items-center gap-2 text-xs font-mono">
            <Code2 class="w-4 h-4 text-rose-400" />
            <span class="font-bold text-slate-100">Source & Fonctions</span>
            <span class="text-[10px] text-slate-400">({codeLines.length} L affichées)</span>
          </div>
          <div class="flex items-center gap-1.5 font-mono text-[10px]">
            <div class="flex p-0.5 rounded bg-black/50 border border-white/10">
              <button
                type="button"
                onclick={() => onToggleCodeViewMode('excerpt')}
                class="px-2 py-0.5 rounded cursor-pointer {codeViewMode === 'excerpt'
                  ? 'bg-rose-500/25 text-rose-200 font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                Extrait ciblé
              </button>
              <button
                type="button"
                onclick={() => onToggleCodeViewMode('full')}
                class="px-2 py-0.5 rounded cursor-pointer {codeViewMode === 'full'
                  ? 'bg-sky-500/25 text-sky-200 font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                Fichier complet
              </button>
            </div>
            <button
              type="button"
              onclick={copyVisibleCode}
              class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/15 border border-white/10 text-slate-200 cursor-pointer"
            >
              {#if copiedKey === 'step3_code'}
                <Check class="w-3 h-3 text-emerald-400" />
                <span>Copié</span>
              {:else}
                <Copy class="w-3 h-3" />
                <span>Code</span>
              {/if}
            </button>
          </div>
        </div>

        <!-- Function Jump Pills Strip -->
        {#if fileFunctions.length > 0}
          <div class="px-3 py-1.5 bg-[#080c16] border-b border-white/10 flex items-center gap-1.5 overflow-x-auto scrollbar-thin shrink-0">
            <span class="text-[9.5px] font-mono text-slate-400 shrink-0 flex items-center gap-1">
              <Layers class="w-3 h-3 text-purple-400" /> Fonctions :
            </span>
            {#each fileFunctions as fn (fn.id)}
              {@const isSel = activeFunction?.id === fn.id}
              <button
                type="button"
                onclick={() => handleFunctionJump(fn)}
                class="px-2 py-0.5 rounded-md text-[10px] font-mono border shrink-0 transition-colors cursor-pointer {isSel
                  ? 'bg-purple-500/30 border-purple-400/70 text-white font-bold'
                  : fn.isTargetLineInside
                    ? 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                    : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
                title={fn.signature}
              >
                {fn.isTargetLineInside ? '🎯 ' : 'ƒ '}{fn.name}() <span class="opacity-65">L{fn.line}</span>
              </button>
            {/each}
          </div>
        {/if}

        <!-- Active Function Signature Banner -->
        {#if activeFunction}
          <div class="px-3.5 py-1.5 bg-purple-950/20 border-b border-purple-500/20 flex items-center justify-between gap-2 text-[10.5px] font-mono shrink-0">
            <span class="text-purple-200 truncate">{activeFunction.signature}</span>
            <span class="text-slate-400 shrink-0">L{activeFunction.line}–L{activeFunction.endLine}</span>
          </div>
        {/if}

        <!-- Highlighted Code Body -->
        <div
          bind:this={codeScrollEl}
          class="flex-1 overflow-auto p-2.5 font-mono text-[11px] leading-relaxed bg-[#04060c] scrollbar-thin select-text"
        >
          {#if snippetLoading}
            <div class="p-4 text-slate-400">Chargement du code source...</div>
          {:else if codeLines.length > 0}
            {#each codeLines as ln (ln.num)}
              <div
                data-line={ln.num}
                class="flex items-start px-2 py-0.5 rounded {ln.isFaulty
                  ? 'bg-rose-500/25 border-l-3 border-rose-400 text-rose-100 font-bold'
                  : ln.isTaintStep
                    ? 'bg-amber-500/15 border-l-2 border-amber-400/80'
                    : ln.isInActiveFunction
                      ? 'bg-purple-500/[0.07] border-l-2 border-purple-400/50'
                      : 'text-slate-300 hover:bg-white/[0.03]'}"
              >
                <span
                  class="w-10 shrink-0 select-none text-right pr-3 {ln.isFaulty
                    ? 'text-rose-300 font-bold'
                    : ln.isInActiveFunction
                      ? 'text-purple-300'
                      : 'text-slate-500'}"
                >
                  {ln.num}
                </span>
                <span class="whitespace-pre flex-1">
                  {#each tokenizeLine(ln.text) as tok}
                    <span class={tok.cls}>{tok.text}</span>
                  {/each}
                </span>
                {#if ln.isFaulty}
                  <span class="ml-2 px-2 py-0.5 rounded bg-rose-500/45 text-[9px] text-white shrink-0 font-bold">
                    ◄ {selectedAnomaly?.cve_id || 'CIBLE'} (Sink)
                  </span>
                {:else if ln.taintLabel}
                  <span class="ml-2 px-1.5 py-0.5 rounded bg-amber-500/30 text-[9px] text-amber-100 shrink-0">
                    {ln.taintLabel}
                  </span>
                {/if}
              </div>
            {/each}
          {:else}
            <div class="p-4 text-slate-500">{snippetFileError || 'Code source indisponible sur disque.'}</div>
          {/if}
        </div>
      </div>
    {/if}

    <!-- RIGHT: DATA DIRECTION VISUALIZATION & PROMPT STEP 3 -->
    {#if layoutMode === 'split' || layoutMode === 'data'}
      <div
        class="{layoutMode === 'split' ? 'lg:col-span-6' : ''} flex flex-col overflow-hidden bg-[#080c16]"
      >
        <!-- Data Direction Summary Header -->
        <div class="px-3.5 py-2 bg-[#0c1220] border-b border-white/10 space-y-1.5 shrink-0">
          <div class="flex items-center justify-between gap-2 flex-wrap">
            <div class="flex items-center gap-2 text-xs font-mono">
              <GitBranch class="w-4 h-4 text-cyan-400" />
              <span class="font-bold text-white">Direction de la Data</span>
              <span
                class="px-2 py-0.5 rounded text-[9.5px] font-bold border {dataDirection.isSanitized
                  ? 'bg-emerald-500/20 text-emerald-200 border-emerald-400/40'
                  : 'bg-rose-500/20 text-rose-200 border-rose-400/40'}"
              >
                {dataDirection.isSanitized ? '🛡️ Sanitizer détecté' : '🚨 Flux non assaini'}
              </span>
            </div>

            <div class="flex p-0.5 rounded-lg bg-black/50 border border-white/10 text-[10px] font-mono">
              <button
                type="button"
                onclick={() => (dataSubTab = 'pipeline')}
                class="px-2 py-0.5 rounded cursor-pointer {dataSubTab === 'pipeline'
                  ? 'bg-cyan-500/25 text-cyan-200 font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                🌊 Pipeline SVG
              </button>
              <button
                type="button"
                onclick={() => (dataSubTab = 'steps')}
                class="px-2 py-0.5 rounded cursor-pointer {dataSubTab === 'steps'
                  ? 'bg-amber-500/25 text-amber-200 font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                🧬 Étapes ({dataDirection.coreSteps.length})
              </button>
              <button
                type="button"
                onclick={() => (dataSubTab = 'table')}
                class="px-2 py-0.5 rounded cursor-pointer {dataSubTab === 'table'
                  ? 'bg-purple-500/25 text-purple-200 font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                📊 Variables ({dataDirection.dataVars.length})
              </button>
            </div>
          </div>

          <div class="px-2.5 py-1 rounded-lg bg-black/45 border border-cyan-500/25 text-[10.5px] font-mono text-cyan-200 truncate" title={dataDirection.taintSummary}>
            {dataDirection.taintSummary}
          </div>
        </div>

        <!-- Data Direction Content Area -->
        <div class="flex-1 overflow-y-auto p-3 space-y-3 scrollbar-thin">
          {#if dataSubTab === 'pipeline'}
            <!-- Directional Legend -->
            <div class="grid grid-cols-3 gap-2 text-[10px] font-mono text-center">
              <div class="px-2 py-1 rounded-lg bg-emerald-950/35 border border-emerald-500/30 text-emerald-300 font-bold flex items-center justify-center gap-1">
                <ArrowRight class="w-3 h-3" />
                <span>ENTRANT ({dataDirection.upstream.length})</span>
              </div>
              <div class="px-2 py-1 rounded-lg bg-sky-950/35 border border-sky-500/35 text-sky-200 font-bold">
                🎯 CIBLE ({dataDirection.targetNode.label})
              </div>
              <div class="px-2 py-1 rounded-lg bg-rose-950/35 border border-rose-500/30 text-rose-300 font-bold flex items-center justify-center gap-1">
                <span>SORTANT ({dataDirection.downstream.length})</span>
                <ArrowRight class="w-3 h-3" />
              </div>
            </div>

            <!-- Interactive SVG Directional Flow Graph -->
            <div class="rounded-xl border border-cyan-500/25 bg-[#050811] p-2 overflow-x-auto">
              <svg viewBox="0 0 660 {svgHeight}" class="w-full min-w-[500px] font-mono">
                <defs>
                  <marker id="bounty-arrow-in" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M 0 1 L 9 5 L 0 9 z" fill="#34d399" />
                  </marker>
                  <marker id="bounty-arrow-out" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                    <path d="M 0 1 L 9 5 L 0 9 z" fill="#fb7185" />
                  </marker>
                </defs>

                <!-- Upstream Nodes (Left -> Center) -->
                {#each svgUpstream as up, idx}
                  {@const startY = Math.round((svgHeight - svgUpstream.length * 48) / 2) + idx * 48 + 4}
                  {@const midY = startY + 19}
                  <g
                    class="cursor-pointer"
                    onclick={() => onJumpToDataNode(up)}
                    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && onJumpToDataNode(up)}
                    role="button"
                    tabindex="0"
                  >
                    <path
                      d="M 184 {midY} C 218 {midY}, 218 {svgCenterY}, 248 {svgCenterY}"
                      fill="none"
                      stroke="#34d399"
                      stroke-width="1.6"
                      marker-end="url(#bounty-arrow-in)"
                    />
                    <rect x="190" y={Math.round((midY + svgCenterY) / 2) - 10} width="54" height="14" rx="4" fill="#06281e" stroke="#10b981" stroke-width="0.7" />
                    <text x="217" y={Math.round((midY + svgCenterY) / 2)} fill="#6ee7b7" font-size="8" text-anchor="middle">
                      {truncateSvg(up.transmittedData || up.relation || 'in', 9)}
                    </text>

                    <rect x="8" y={startY} width="176" height="38" rx="7" fill="#091916" stroke="#10b981" stroke-width="1.2" />
                    <text x="16" y={startY + 15} fill="#ecfdf5" font-size="10" font-weight="bold">
                      📥 {truncateSvg(up.label, 20)}
                    </text>
                    <text x="16" y={startY + 29} fill="#6ee7b7" font-size="8">
                      {truncateSvg(up.sublabel, 27)}
                    </text>
                  </g>
                {/each}

                <!-- Center Target Node -->
                <rect
                  x="252"
                  y={svgCenterY - 34}
                  width="156"
                  height="68"
                  rx="10"
                  fill="#0c1c34"
                  stroke="#38bdf8"
                  stroke-width="2"
                />
                <text x="330" y={svgCenterY - 11} fill="#ffffff" font-size="11" font-weight="bold" text-anchor="middle">
                  {truncateSvg(dataDirection.targetNode.label, 19)}
                </text>
                <text x="330" y={svgCenterY + 5} fill="#7dd3fc" font-size="8.5" text-anchor="middle">
                  [{dataDirection.targetNode.layer.toUpperCase()}] · L{dataDirection.targetNode.line}
                </text>
                <text x="330" y={svgCenterY + 20} fill="#fbbf24" font-size="8.5" text-anchor="middle">
                  {truncateSvg(dataDirection.targetNode.transmittedData ? `📦 ${dataDirection.targetNode.transmittedData}` : 'Taint Transit', 22)}
                </text>

                <!-- Downstream Nodes (Center -> Right) -->
                {#each svgDownstream as down, idx}
                  {@const startY = Math.round((svgHeight - svgDownstream.length * 48) / 2) + idx * 48 + 4}
                  {@const midY = startY + 19}
                  <g
                    class="cursor-pointer"
                    onclick={() => onJumpToDataNode(down)}
                    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && onJumpToDataNode(down)}
                    role="button"
                    tabindex="0"
                  >
                    <path
                      d="M 408 {svgCenterY} C 438 {svgCenterY}, 438 {midY}, 472 {midY}"
                      fill="none"
                      stroke={down.kind === 'sink' ? '#fb7185' : '#38bdf8'}
                      stroke-width="1.6"
                      marker-end="url(#bounty-arrow-out)"
                    />
                    <rect x="415" y={Math.round((midY + svgCenterY) / 2) - 10} width="54" height="14" rx="4" fill="#2a0b16" stroke="#f43f5e" stroke-width="0.7" />
                    <text x="442" y={Math.round((midY + svgCenterY) / 2)} fill="#fda4af" font-size="8" text-anchor="middle">
                      {truncateSvg(down.relation || down.transmittedData || 'out', 9)}
                    </text>

                    <rect
                      x="476"
                      y={startY}
                      width="176"
                      height="38"
                      rx="7"
                      fill={down.kind === 'sink' ? '#240b15' : '#0b162a'}
                      stroke={down.kind === 'sink' ? '#f43f5e' : '#38bdf8'}
                      stroke-width="1.2"
                    />
                    <text x="484" y={startY + 15} fill="#fff1f2" font-size="10" font-weight="bold">
                      {down.kind === 'sink' ? '🚨 ' : '📤 '}{truncateSvg(down.label, 20)}
                    </text>
                    <text x="484" y={startY + 29} fill={down.kind === 'sink' ? '#fda4af' : '#7dd3fc'} font-size="8">
                      {truncateSvg(down.sublabel, 27)}
                    </text>
                  </g>
                {/each}
              </svg>
            </div>

            <!-- Interactive Upstream / Downstream Lists -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              <div class="p-2.5 rounded-xl bg-emerald-950/15 border border-emerald-500/25 space-y-1.5">
                <div class="text-[10px] font-mono uppercase text-emerald-300 font-bold flex items-center gap-1">
                  <ArrowLeft class="w-3 h-3" /> Entrées / Sources Amont ({dataDirection.upstream.length})
                </div>
                {#each dataDirection.upstream as u (u.id)}
                  <button
                    type="button"
                    onclick={() => onJumpToDataNode(u)}
                    class="w-full text-left p-2 rounded-lg bg-black/40 hover:bg-emerald-500/15 border border-white/10 transition-colors cursor-pointer"
                  >
                    <div class="flex items-center justify-between gap-1 text-[11px] font-mono">
                      <span class="font-bold text-emerald-200 truncate">{u.label}</span>
                      <span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[9px] shrink-0">
                        {u.relation || 'IN'}
                      </span>
                    </div>
                    <div class="text-[9.5px] font-mono text-slate-400 truncate mt-0.5">{u.sublabel}</div>
                    {#if u.transmittedData}
                      <div class="text-[9.5px] font-mono text-amber-300 mt-0.5">📦 {u.transmittedData}</div>
                    {/if}
                  </button>
                {/each}
              </div>

              <div class="p-2.5 rounded-xl bg-rose-950/15 border border-rose-500/25 space-y-1.5">
                <div class="text-[10px] font-mono uppercase text-rose-300 font-bold flex items-center gap-1">
                  <ArrowRight class="w-3 h-3" /> Sorties / Sinks Aval ({dataDirection.downstream.length})
                </div>
                {#each dataDirection.downstream as d (d.id)}
                  <button
                    type="button"
                    onclick={() => onJumpToDataNode(d)}
                    class="w-full text-left p-2 rounded-lg bg-black/40 hover:bg-rose-500/15 border border-white/10 transition-colors cursor-pointer"
                  >
                    <div class="flex items-center justify-between gap-1 text-[11px] font-mono">
                      <span class="font-bold text-rose-200 truncate">{d.label}</span>
                      <span class="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[9px] shrink-0">
                        {d.relation || 'OUT'}
                      </span>
                    </div>
                    <div class="text-[9.5px] font-mono text-slate-400 truncate mt-0.5">{d.sublabel}</div>
                    {#if d.transmittedData}
                      <div class="text-[9.5px] font-mono text-amber-300 mt-0.5">📦 {d.transmittedData}</div>
                    {/if}
                  </button>
                {/each}
              </div>
            </div>
          {:else if dataSubTab === 'steps'}
            {#if dataDirection.coreSteps.length === 0}
              <div class="p-6 text-center text-xs font-mono text-slate-400 border border-dashed border-white/10 rounded-xl">
                Aucune étape SSA intermédiaire enregistrée — le flux passe directement des entrées amont vers la cible et le sink.
              </div>
            {:else}
              <div class="space-y-2">
                {#each dataDirection.coreSteps as st, idx (st.id)}
                  <div class="p-2.5 rounded-xl bg-black/40 border border-amber-500/25 space-y-1 font-mono">
                    <div class="flex items-center justify-between gap-2 text-[10.5px]">
                      <span class="font-bold text-amber-200">
                        Step {idx + 1} · {st.label}
                      </span>
                      <span
                        class="px-1.5 py-0.5 rounded text-[9px] font-bold {st.isSanitized
                          ? 'bg-emerald-500/25 text-emerald-200'
                          : 'bg-rose-500/25 text-rose-200'}"
                      >
                        {st.isSanitized ? `🛡️ ${st.sanitizerName || 'Sanitized'}` : '⚠️ Non filtré'}
                      </span>
                    </div>
                    <div class="text-[10px] text-slate-400">{st.sublabel}</div>
                    {#if st.transmittedData}
                      <div class="text-[10.5px] text-cyan-200">➔ {st.transmittedData}</div>
                    {/if}
                    {#if st.codeSnippet}
                      <pre class="p-1.5 rounded bg-[#04060c] text-[10px] text-slate-300 overflow-x-auto">{st.codeSnippet}</pre>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          {:else}
            <!-- Variables & Direction Table -->
            <div class="rounded-xl border border-white/10 overflow-hidden bg-black/30">
              <table class="w-full text-left font-mono text-[10.5px]">
                <thead class="bg-white/5 text-slate-300 border-b border-white/10">
                  <tr>
                    <th class="px-2.5 py-2">Direction</th>
                    <th class="px-2.5 py-2">Donnée / Variable</th>
                    <th class="px-2.5 py-2">Origine ➔ Destination</th>
                    <th class="px-2.5 py-2">Ligne</th>
                    <th class="px-2.5 py-2">État</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-white/5">
                  {#each dataDirection.dataVars as dv}
                    <tr class="hover:bg-white/[0.03]">
                      <td class="px-2.5 py-1.5">
                        <span
                          class="px-1.5 py-0.5 rounded text-[9px] font-bold {dv.direction === 'IN'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : dv.direction === 'OUT'
                              ? 'bg-rose-500/20 text-rose-300'
                              : 'bg-amber-500/20 text-amber-300'}"
                        >
                          {dv.direction === 'IN' ? '⬅️ ENTRANT' : dv.direction === 'OUT' ? '➡️ SORTANT' : '⚡ TRANSIT'}
                        </span>
                      </td>
                      <td class="px-2.5 py-1.5 text-amber-200 font-bold">{dv.name}</td>
                      <td class="px-2.5 py-1.5 text-slate-300">{dv.origin} ➔ {dv.destination}</td>
                      <td class="px-2.5 py-1.5 text-sky-300">L{dv.line}</td>
                      <td class="px-2.5 py-1.5">
                        {#if dv.sanitized}
                          <span class="text-emerald-400 flex items-center gap-1"><ShieldCheck class="w-3 h-3" /> Safe</span>
                        {:else}
                          <span class="text-rose-400 flex items-center gap-1"><ShieldAlert class="w-3 h-3" /> Exposé</span>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}

          <!-- Step 3 Contextual Prompt Preview -->
          <div class="rounded-xl bg-[#05070f] border border-cyan-500/30 overflow-hidden">
            <div class="px-3 py-1.5 bg-cyan-950/25 border-b border-cyan-500/20 flex items-center justify-between gap-2 text-[11px] font-mono">
              <span class="text-cyan-200 font-bold">📜 Prompt Step 3 — Code, Fonction & Direction Data</span>
              <div class="flex items-center gap-1.5">
                <button
                  type="button"
                  onclick={() => onCopyText(step3Prompt, 'step3_prompt')}
                  class="flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-[10px] cursor-pointer"
                >
                  {#if copiedKey === 'step3_prompt'}
                    <Check class="w-3 h-3" />
                    <span>Copié !</span>
                  {:else}
                    <Copy class="w-3 h-3" />
                    <span>Copier Prompt Step 3</span>
                  {/if}
                </button>
                <button
                  type="button"
                  onclick={() => onSendPromptToChat(step3Prompt, activeFilePath)}
                  class="flex items-center gap-1 px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-white text-[10px] cursor-pointer"
                >
                  <Send class="w-3 h-3" />
                  <span>{sentToMcp ? 'Envoyé !' : 'Chat MCP'}</span>
                </button>
              </div>
            </div>
            <pre class="p-2.5 font-mono text-[10px] leading-relaxed text-cyan-100/90 whitespace-pre-wrap max-h-[125px] overflow-y-auto scrollbar-thin select-text">{step3Prompt}</pre>
          </div>
        </div>
      </div>
    {/if}
  </div>

  <!-- Step 3 Bottom Navigation -->
  <div class="px-4 py-2.5 border-t border-white/10 bg-[#0b101b] flex items-center justify-between gap-2 shrink-0">
    <button
      type="button"
      onclick={onGoPrevStep}
      class="px-3.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-slate-200 text-xs font-mono cursor-pointer"
    >
      ← Étape 2 : Cibles & Fonctions
    </button>
    <button
      type="button"
      onclick={onGoNextStep}
      class="px-4 py-2 rounded-xl bg-gradient-to-r from-rose-500 to-amber-500 hover:from-rose-400 hover:to-amber-400 text-white text-xs font-extrabold font-mono shadow-lg shadow-rose-500/20 cursor-pointer"
    >
      Étape 4 : Prompts & PoC Studio ➔
    </button>
  </div>
</div>
