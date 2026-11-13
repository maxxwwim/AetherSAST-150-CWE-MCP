<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import type { AffiliationEdge, CveAnomalyRecord, SymbolBubble, TaskItem } from '../types/graph';
  import {
    X,
    FileCode2,
    FolderOpen,
    GitBranch,
    ArrowRight,
    ArrowLeft,
    ShieldAlert,
    Bug,
    Sparkles,
    BookOpen,
    Crosshair,
    CheckCircle2,
    Clock,
    Play,
    RefreshCw,
    Lock,
    Search,
    Layers
  } from '@lucide/svelte';

  const symbol = $derived(cockpitState.activeSymbol);
  const selectedFolder = $derived(cockpitState.selectedFolder);

  const nodeMap = $derived.by(() => {
    const map = new Map<string, SymbolBubble>();
    for (const n of cockpitState.graph.nodes) {
      map.set(n.id, n);
    }
    return map;
  });

  const folderNodes = $derived.by(() => {
    if (!selectedFolder) return [] as SymbolBubble[];
    return cockpitState.graph.nodes.filter((n) => (n.folder || n.cluster_id || 'root') === selectedFolder);
  });

  const isFolderMode = $derived(!symbol && Boolean(selectedFolder));

  // Symbol incident edges
  const incomingEdges = $derived.by(() => {
    const edges = cockpitState.graph.edges;
    if (symbol) {
      return edges.filter((e) => e.target === symbol.id);
    }
    if (selectedFolder) {
      return edges.filter((e) => {
        const s = nodeMap.get(e.source);
        const t = nodeMap.get(e.target);
        return s && t && (s.folder || s.cluster_id || 'root') !== selectedFolder && (t.folder || t.cluster_id || 'root') === selectedFolder;
      });
    }
    return [] as AffiliationEdge[];
  });

  const outgoingEdges = $derived.by(() => {
    const edges = cockpitState.graph.edges;
    if (symbol) {
      return edges.filter((e) => e.source === symbol.id);
    }
    if (selectedFolder) {
      return edges.filter((e) => {
        const s = nodeMap.get(e.source);
        const t = nodeMap.get(e.target);
        return s && t && (s.folder || s.cluster_id || 'root') === selectedFolder && (t.folder || t.cluster_id || 'root') !== selectedFolder;
      });
    }
    return [] as AffiliationEdge[];
  });

  const siblingSymbols = $derived.by(() => {
    if (!symbol?.file_path) return [] as SymbolBubble[];
    return cockpitState.graph.nodes
      .filter((n) => n.file_path === symbol.file_path && n.id !== symbol.id)
      .slice(0, 24);
  });

  const folderFiles = $derived.by(() => folderNodes.filter((n) => n.is_file || n.kind === 'File'));
  const folderClasses = $derived.by(() => folderNodes.filter((n) => n.is_class || n.kind === 'Class' || n.kind === 'Struct'));
  const folderTotalLoc = $derived.by(() => folderNodes.reduce((acc, n) => acc + (n.loc || n.lines_count || 0), 0));

  // Relations filter inside Flux tab
  let relationQuery = $state('');
  const filteredIncoming = $derived.by(() => {
    const q = relationQuery.trim().toLowerCase();
    const list = incomingEdges;
    if (!q) return list;
    return list.filter((e) => {
      const n = nodeMap.get(e.source);
      return (
        e.source.toLowerCase().includes(q) ||
        (n?.name || '').toLowerCase().includes(q) ||
        (e.relation || '').toLowerCase().includes(q)
      );
    });
  });

  const filteredOutgoing = $derived.by(() => {
    const q = relationQuery.trim().toLowerCase();
    const list = outgoingEdges;
    if (!q) return list;
    return list.filter((e) => {
      const n = nodeMap.get(e.target);
      return (
        e.target.toLowerCase().includes(q) ||
        (n?.name || '').toLowerCase().includes(q) ||
        (e.relation || '').toLowerCase().includes(q)
      );
    });
  });

  // Mini-DAG top callers & callees
  const miniInNodes = $derived.by(() => {
    const seen = new Set<string>();
    const res: { id: string; label: string; rel: string }[] = [];
    for (const e of incomingEdges) {
      if (seen.has(e.source)) continue;
      seen.add(e.source);
      const n = nodeMap.get(e.source);
      res.push({
        id: e.source,
        label: n?.name || e.source.split('::').pop()?.replace('file::', '') || e.source,
        rel: e.relation || 'calls',
      });
      if (res.length >= 4) break;
    }
    return res;
  });

  const miniOutNodes = $derived.by(() => {
    const seen = new Set<string>();
    const res: { id: string; label: string; rel: string }[] = [];
    for (const e of outgoingEdges) {
      if (seen.has(e.target)) continue;
      seen.add(e.target);
      const n = nodeMap.get(e.target);
      res.push({
        id: e.target,
        label: n?.name || e.target.split('::').pop()?.replace('file::', '') || e.target,
        rel: e.relation || 'calls',
      });
      if (res.length >= 4) break;
    }
    return res;
  });

  // CVE tab filtering
  let cveScope = $state<'target' | 'project'>('target');
  const activeAnomalies = $derived.by(() => {
    if (symbol?.anomalies && symbol.anomalies.length > 0) return symbol.anomalies;
    if (isFolderMode) {
      const list: CveAnomalyRecord[] = [];
      for (const n of folderNodes) {
        if (n.anomalies) list.push(...n.anomalies);
      }
      return list;
    }
    return [] as CveAnomalyRecord[];
  });

  const displayedCves = $derived.by(() => {
    if (cveScope === 'target' && activeAnomalies.length > 0) return activeAnomalies;
    return cockpitState.allViolations.slice(0, 80);
  });

  // Tasks tab live sync
  let tasksLoading = $state(false);
  let tasksError = $state('');

  async function refreshTasks() {
    tasksLoading = true;
    tasksError = '';
    try {
      const list = await api.getTasks();
      cockpitState.tasks = Array.isArray(list) ? list : [];
    } catch (e: any) {
      tasksError = String(e?.message || e || 'Erreur /api/tasks');
    } finally {
      tasksLoading = false;
    }
  }

  async function setTaskStatus(task: TaskItem, status: 'pending' | 'in_progress' | 'done') {
    const progress = status === 'done' ? 100 : status === 'in_progress' ? 50 : 0;
    try {
      await api.updateTask(task.id, status, progress, `MAJ statut -> ${status}`);
      await refreshTasks();
    } catch (e) {
      console.error('Task update failed', e);
    }
  }

  $effect(() => {
    if (cockpitState.isInspectorOpen && cockpitState.activeTab === 'tasks') {
      refreshTasks();
    }
  });

  function jumpToSymbol(id: string) {
    cockpitState.selectSymbol(id, true);
  }

  function truncateSvg(str: string, max = 12): string {
    return str.length > max ? str.slice(0, max - 1) + '…' : str;
  }

  function formatRelColor(rel?: string): string {
    const r = (rel || '').toLowerCase();
    if (r.includes('violat')) return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
    if (r === 'queries') return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
    if (r.includes('import')) return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    return 'bg-sky-500/15 text-sky-300 border-sky-500/35';
  }
</script>

{#if cockpitState.isInspectorOpen}
  <aside
    class="absolute top-0 right-0 bottom-7 w-[396px] max-w-[92vw] bg-[#0b0e17]/95 backdrop-blur-xl border-l border-white/10 flex flex-col z-40 select-none shadow-[-16px_0_48px_rgba(0,0,0,0.6)]"
  >
    <!-- Drawer Header -->
    <div class="px-3.5 py-2.5 border-b border-white/10 bg-[#0f172a]/70 flex items-start justify-between gap-2">
      <div class="min-w-0 flex-1">
        {#if symbol}
          <div class="flex items-center gap-1.5 flex-wrap">
            <span class="px-1.5 py-0.5 text-[10px] font-mono rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
              {symbol.stereotype || `«${symbol.kind}»`}
            </span>
            <button
              type="button"
              onclick={() => cockpitState.selectFolder(symbol.folder || symbol.cluster_id || 'root')}
              class="px-1.5 py-0.5 text-[10px] font-mono rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 cursor-pointer flex items-center gap-1"
              title="Inspecter tout le dossier"
            >
              <FolderOpen class="w-2.5 h-2.5" />
              {symbol.folder || symbol.cluster_id || 'root'}
            </button>
          </div>
          <h2 class="text-sm font-bold text-white truncate mt-1" title={symbol.name}>{symbol.name}</h2>
          <p class="text-[10px] font-mono text-slate-400 truncate" title={symbol.file_path}>
            {symbol.file_path}{symbol.line_number ? `:${symbol.line_number}` : ''}
          </p>
        {:else if isFolderMode}
          <div class="flex items-center gap-1.5">
            <span class="px-1.5 py-0.5 text-[10px] font-mono rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
              «Module / Dossier»
            </span>
            <span class="text-[10px] font-mono text-slate-400">{folderNodes.length} entités</span>
          </div>
          <h2 class="text-sm font-bold text-white truncate mt-1">📁 {selectedFolder}</h2>
          <p class="text-[10px] font-mono text-slate-400 truncate">
            {folderFiles.length} fichiers • {folderClasses.length} classes • {folderTotalLoc} LOC
          </p>
        {:else}
          <div class="text-xs font-semibold text-slate-300">Inspecteur Spatial</div>
          <p class="text-[11px] text-slate-400">Cliquez une bulle ou un dossier du graphe.</p>
        {/if}
      </div>

      <div class="flex items-center gap-1 shrink-0">
        {#if symbol}
          <button
            type="button"
            onclick={() => cockpitState.requestFocusSymbol(symbol.id)}
            title="Centrer la caméra sur ce symbole"
            class="p-1.5 rounded bg-white/5 hover:bg-sky-500/20 text-slate-300 hover:text-sky-300 border border-white/10 cursor-pointer"
          >
            <Crosshair class="w-3.5 h-3.5" />
          </button>
        {/if}
        <button
          type="button"
          onclick={() => (cockpitState.isInspectorOpen = false)}
          aria-label="Fermer l'inspecteur"
          class="p-1.5 rounded bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white border border-white/10 cursor-pointer"
        >
          <X class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>

    <!-- Quick Action Strip -->
    {#if symbol || isFolderMode}
      <div class="px-3 py-1.5 border-b border-white/5 bg-black/25 flex items-center gap-1.5 text-[11px]">
        <button
          type="button"
          onclick={() => cockpitState.openDoc(symbol ? 'symbol' : 'folder')}
          class="flex-1 flex items-center justify-center gap-1.5 py-1 px-2 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 font-medium cursor-pointer transition-colors"
        >
          <BookOpen class="w-3.5 h-3.5" />
          <span>Doc / Source</span>
        </button>
        {#if symbol}
          <button
            type="button"
            onclick={() => cockpitState.openPromptModal('context')}
            class="flex-1 flex items-center justify-center gap-1.5 py-1 px-2 rounded bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/35 text-purple-300 font-medium cursor-pointer transition-colors"
          >
            <Sparkles class="w-3.5 h-3.5" />
            <span>Prompt IA</span>
          </button>
        {/if}
      </div>
    {/if}

    <!-- Tabs -->
    <div class="flex border-b border-white/10 bg-[#0d111a] text-[11px] font-medium px-1">
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'debrief')}
        class="flex-1 py-2 px-1.5 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'debrief' ? 'border-sky-400 text-sky-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Débrief
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'uml')}
        class="flex-1 py-2 px-1.5 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'uml' ? 'border-indigo-400 text-indigo-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        UML
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'relations')}
        class="flex-1 py-2 px-1.5 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'relations' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Flux ({incomingEdges.length + outgoingEdges.length})
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'cve')}
        class="flex-1 py-2 px-1.5 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'cve' ? 'border-rose-400 text-rose-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        CVE ({activeAnomalies.length || cockpitState.allViolations.length})
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'tasks')}
        class="flex-1 py-2 px-1.5 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'tasks' ? 'border-emerald-400 text-emerald-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Tâches
      </button>
    </div>

    <!-- Tab Body -->
    <div class="flex-1 overflow-y-auto p-3.5 space-y-3 text-xs select-text">
      {#if cockpitState.activeTab === 'debrief'}
        {#if symbol}
          <!-- Symbol badges -->
          <div class="flex flex-wrap gap-1.5 items-center">
            <span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-white/5 border border-white/10 text-slate-300">
              Couche: {symbol.layer}
            </span>
            {#if symbol.metadata?.blake3_hash}
              <span class="px-2 py-0.5 rounded-full text-[10px] font-mono flex items-center gap-1 {symbol.metadata.lock_verified ? 'bg-emerald-500/15 border border-emerald-500/40 text-emerald-300' : 'bg-amber-500/15 border border-amber-500/40 text-amber-300'}">
                <Lock class="w-2.5 h-2.5" />
                BLAKE3 {symbol.metadata.lock_verified ? 'Scellé' : 'Modifié'} ({symbol.metadata.ears_count || 0} EARS)
              </span>
            {/if}
          </div>

          <!-- KPI grid -->
          <div class="grid grid-cols-2 gap-2">
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Lignes (LOC)</div>
              <div class="text-base font-bold text-white font-mono">{symbol.loc || 1}</div>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Complexité</div>
              <div class="text-base font-bold font-mono {(symbol.cyclomatic_complexity || 1) >= 10 ? 'text-amber-400' : 'text-sky-300'}">
                {symbol.cyclomatic_complexity || 1}
              </div>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Appels Entrants</div>
              <div class="text-base font-bold text-cyan-300 font-mono">{incomingEdges.length || symbol.in_degree}</div>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Appels Sortants</div>
              <div class="text-base font-bold text-purple-300 font-mono">{outgoingEdges.length || symbol.out_degree}</div>
            </div>
          </div>

          {#if symbol.docstring}
            <div class="p-2.5 rounded-lg bg-slate-900/80 border border-white/10">
              <div class="text-[10px] font-mono uppercase text-emerald-400 mb-1">Spécification / Docstring</div>
              <p class="text-[11px] text-slate-200 whitespace-pre-wrap leading-relaxed">{symbol.docstring}</p>
            </div>
          {/if}

          {#if siblingSymbols.length > 0}
            <div>
              <div class="text-[10px] font-mono uppercase text-slate-400 mb-1.5">
                Symboles liés dans ce fichier ({siblingSymbols.length})
              </div>
              <div class="space-y-1 max-h-48 overflow-y-auto pr-1">
                {#each siblingSymbols as sub}
                  <button
                    type="button"
                    onclick={() => jumpToSymbol(sub.id)}
                    class="w-full flex items-center justify-between px-2.5 py-1.5 rounded bg-white/[0.03] hover:bg-sky-500/15 border border-white/5 hover:border-sky-500/35 text-left cursor-pointer transition-colors"
                  >
                    <span class="truncate font-mono text-[11px] text-slate-200">
                      {sub.is_class ? '🏛️' : '⚡'} {sub.name}
                    </span>
                    <span class="text-[10px] text-sky-400 shrink-0 ml-2">{sub.stereotype || sub.kind}</span>
                  </button>
                {/each}
              </div>
            </div>
          {/if}
        {:else if isFolderMode}
          <div class="grid grid-cols-2 gap-2">
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Fichiers</div>
              <div class="text-base font-bold text-white font-mono">{folderFiles.length}</div>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Classes / Structs</div>
              <div class="text-base font-bold text-indigo-300 font-mono">{folderClasses.length}</div>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">LOC Cumulés</div>
              <div class="text-base font-bold text-sky-300 font-mono">{folderTotalLoc}</div>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] text-slate-400 uppercase font-mono">Alertes SAST</div>
              <div class="text-base font-bold text-rose-400 font-mono">{activeAnomalies.length}</div>
            </div>
          </div>

          <div>
            <div class="text-[10px] font-mono uppercase text-slate-400 mb-1.5">
              Contenu du dossier ({folderNodes.length})
            </div>
            <div class="space-y-1 max-h-72 overflow-y-auto pr-1">
              {#each folderNodes.slice(0, 40) as item}
                <button
                  type="button"
                  onclick={() => jumpToSymbol(item.id)}
                  class="w-full flex items-center justify-between px-2.5 py-1.5 rounded bg-white/[0.03] hover:bg-sky-500/15 border border-white/5 hover:border-sky-500/35 text-left cursor-pointer"
                >
                  <span class="truncate font-mono text-[11px] text-slate-200">
                    {item.is_file ? '📄' : item.is_class ? '🏛️' : '⚡'} {item.name}
                  </span>
                  <span class="text-[10px] text-slate-400 shrink-0 ml-2">{item.layer}</span>
                </button>
              {/each}
            </div>
          </div>
        {:else}
          <div class="py-12 text-center text-slate-400 space-y-2">
            <Layers class="w-8 h-8 text-sky-400/60 mx-auto" />
            <p class="font-medium text-slate-300">Aucune entité sélectionnée</p>
            <p class="text-[11px]">Cliquez sur une bulle lumineuse ou une membrane de dossier dans le graphe.</p>
          </div>
        {/if}

      {:else if cockpitState.activeTab === 'uml'}
        {#if symbol || isFolderMode}
          <!-- UML Structured Card -->
          <div class="rounded-xl border border-indigo-500/35 bg-[#090d16] overflow-hidden shadow-lg">
            <!-- Stereotype & Name Compartment -->
            <div class="px-3.5 py-2.5 bg-indigo-950/50 border-b border-indigo-500/30 text-center">
              <div class="text-[10px] font-mono text-indigo-300">
                {symbol ? (symbol.stereotype || `«${symbol.kind}»`) : '«Module / Dossier»'}
              </div>
              <div class="text-sm font-bold text-white truncate">
                {symbol ? symbol.name : `📁 ${selectedFolder}`}
              </div>
            </div>

            <!-- Attributes / Properties Compartment -->
            <div class="px-3 py-2 border-b border-indigo-500/20 space-y-1 font-mono text-[11px]">
              <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-1">Attributs & Métadonnées</div>
              {#if symbol?.attributes && symbol.attributes.length > 0}
                {#each symbol.attributes as attr}
                  <div class="flex items-center justify-between gap-2 text-slate-200">
                    <span class="truncate"><span class="text-emerald-400">{attr.visibility || '+'}</span> {attr.name}</span>
                    <span class="text-[10px] text-sky-300 shrink-0">: {attr.attr_type || attr.type || 'any'}</span>
                  </div>
                {/each}
              {:else if symbol}
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> layer</span>
                  <span class="text-sky-300">: {symbol.layer}</span>
                </div>
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> lines_count</span>
                  <span class="text-sky-300">: {symbol.loc || 1}</span>
                </div>
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> complexity</span>
                  <span class="text-amber-300">: {symbol.cyclomatic_complexity || 1}</span>
                </div>
              {:else}
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> fichiers</span>
                  <span class="text-sky-300">: {folderFiles.length}</span>
                </div>
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> classes</span>
                  <span class="text-sky-300">: {folderClasses.length}</span>
                </div>
              {/if}
            </div>

            <!-- Methods / Operations Compartment -->
            <div class="px-3 py-2 space-y-1 font-mono text-[11px]">
              <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-1">
                {symbol ? 'Méthodes & Opérations' : 'Fichiers du Module'}
              </div>
              {#if symbol?.methods && symbol.methods.length > 0}
                {#each symbol.methods.slice(0, 20) as m}
                  <div class="flex items-center justify-between gap-2 text-slate-200">
                    <span class="truncate"><span class="text-purple-400">{m.visibility || '+'}</span> {m.signature || `${m.name}()`}</span>
                    {#if m.returns}
                      <span class="text-[10px] text-emerald-300 shrink-0">{m.returns}</span>
                    {/if}
                  </div>
                {/each}
              {:else if symbol && siblingSymbols.length > 0}
                {#each siblingSymbols.slice(0, 8) as sub}
                  <button
                    type="button"
                    onclick={() => jumpToSymbol(sub.id)}
                    class="w-full flex items-center justify-between text-left hover:text-sky-300 text-slate-300 cursor-pointer"
                  >
                    <span class="truncate"><span class="text-purple-400">+</span> {sub.name}()</span>
                    <span class="text-[10px] text-slate-500 shrink-0">{sub.stereotype || sub.kind}</span>
                  </button>
                {/each}
              {:else if isFolderMode}
                {#each folderFiles.slice(0, 10) as f}
                  <button
                    type="button"
                    onclick={() => jumpToSymbol(f.id)}
                    class="w-full flex items-center justify-between text-left hover:text-sky-300 text-slate-300 cursor-pointer"
                  >
                    <span class="truncate"><span class="text-sky-400">+</span> {f.name}</span>
                    <span class="text-[10px] text-slate-500 shrink-0">{f.layer}</span>
                  </button>
                {/each}
              {:else}
                <div class="text-slate-500 italic">
                  + flux_entrants: {incomingEdges.length} • flux_sortants: {outgoingEdges.length}
                </div>
              {/if}
            </div>
          </div>

          <!-- Interactive SVG Mini-DAG -->
          <div class="rounded-xl border border-white/10 bg-[#070a12] p-2.5">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[10px] font-mono uppercase text-sky-400 flex items-center gap-1">
                <GitBranch class="w-3 h-3" /> Mini-DAG Interactif
              </span>
              <span class="text-[10px] text-slate-500">Cliquer pour naviguer</span>
            </div>
            <svg viewBox="0 0 360 132" class="w-full h-32 font-mono text-[9px]">
              <defs>
                <marker id="uml-arrow-in" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
                  <path d="M 0 1 L 9 5 L 0 9 z" fill="#c084fc" />
                </marker>
                <marker id="uml-arrow-out" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">
                  <path d="M 0 1 L 9 5 L 0 9 z" fill="#38bdf8" />
                </marker>
              </defs>

              <!-- Inbound nodes (Left) -->
              {#if miniInNodes.length > 0}
                {#each miniInNodes as src, idx}
                  {@const y = (132 - miniInNodes.length * 28) / 2 + idx * 28 + 2}
                  <g
                    class="cursor-pointer"
                    onclick={() => jumpToSymbol(src.id)}
                    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && jumpToSymbol(src.id)}
                    role="button"
                    tabindex="0"
                  >
                    <path d="M 96 {y + 11} L 128 66" fill="none" stroke="#c084fc" stroke-width="1.2" stroke-dasharray="3,2" marker-end="url(#uml-arrow-in)" />
                    <rect x="6" y={y} width="90" height="22" rx="4" fill="#0f172a" stroke="#a855f7" stroke-width="1" />
                    <text x="51" y={y + 14} fill="#e2e8f0" text-anchor="middle">{truncateSvg(src.label, 12)}</text>
                  </g>
                {/each}
              {:else}
                <text x="50" y="68" fill="#64748b" font-style="italic" text-anchor="middle">[Entrée]</text>
              {/if}

              <!-- Center Node -->
              <rect x="130" y="42" width="100" height="48" rx="6" fill="#0c192c" stroke="#38bdf8" stroke-width="1.8" />
              <text x="180" y="62" fill="#ffffff" font-weight="bold" font-size="10" text-anchor="middle">
                {truncateSvg(symbol ? symbol.name : selectedFolder || 'Root', 13)}
              </text>
              <text x="180" y="77" fill="#38bdf8" font-size="8" text-anchor="middle">
                {truncateSvg(symbol ? (symbol.stereotype || symbol.kind) : 'Folder', 14)}
              </text>

              <!-- Outbound nodes (Right) -->
              {#if miniOutNodes.length > 0}
                {#each miniOutNodes as tgt, idx}
                  {@const y = (132 - miniOutNodes.length * 28) / 2 + idx * 28 + 2}
                  <g
                    class="cursor-pointer"
                    onclick={() => jumpToSymbol(tgt.id)}
                    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && jumpToSymbol(tgt.id)}
                    role="button"
                    tabindex="0"
                  >
                    <path d="M 230 66 L 262 {y + 11}" fill="none" stroke="#38bdf8" stroke-width="1.2" marker-end="url(#uml-arrow-out)" />
                    <rect x="264" y={y} width="90" height="22" rx="4" fill="#0f172a" stroke="#38bdf8" stroke-width="1" />
                    <text x="309" y={y + 14} fill="#e2e8f0" text-anchor="middle">{truncateSvg(tgt.label, 12)}</text>
                  </g>
                {/each}
              {:else}
                <text x="310" y="68" fill="#64748b" font-style="italic" text-anchor="middle">[Feuille]</text>
              {/if}
            </svg>
          </div>
        {:else}
          <p class="text-slate-400 text-center py-8">Sélectionnez un symbole ou un dossier pour afficher son diagramme UML.</p>
        {/if}

      {:else if cockpitState.activeTab === 'relations'}
        <!-- Relation Filter -->
        <div class="relative">
          <Search class="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            bind:value={relationQuery}
            placeholder="Filtrer les flux entrants / sortants..."
            class="w-full pl-8 pr-2.5 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-sky-500/50"
          />
        </div>

        <!-- Inbound Callers -->
        <div class="space-y-1.5">
          <div class="flex items-center justify-between text-[10px] font-mono uppercase text-purple-300">
            <span class="flex items-center gap-1"><ArrowRight class="w-3 h-3" /> Flux Entrants ({filteredIncoming.length})</span>
          </div>
          {#if filteredIncoming.length === 0}
            <p class="text-[11px] text-slate-500 italic">Aucun appelant entrant.</p>
          {:else}
            <div class="space-y-1 max-h-56 overflow-y-auto pr-1">
              {#each filteredIncoming as edge}
                {@const src = nodeMap.get(edge.source)}
                <button
                  type="button"
                  onclick={() => jumpToSymbol(edge.source)}
                  class="w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-white/[0.03] hover:bg-purple-500/15 border border-white/5 hover:border-purple-500/40 text-left cursor-pointer transition-colors"
                >
                  <div class="min-w-0">
                    <div class="text-[11px] font-mono text-slate-100 truncate">
                      {src?.name || edge.source.replace('file::', '')}
                    </div>
                    {#if src?.file_path}
                      <div class="text-[9px] text-slate-500 truncate">{src.file_path}</div>
                    {/if}
                  </div>
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-mono border shrink-0 {formatRelColor(edge.relation)}">
                    {edge.relation || edge.edge_type || 'calls'}
                  </span>
                </button>
              {/each}
            </div>
          {/if}
        </div>

        <!-- Outbound Callees -->
        <div class="space-y-1.5 pt-2 border-t border-white/10">
          <div class="flex items-center justify-between text-[10px] font-mono uppercase text-sky-300">
            <span class="flex items-center gap-1"><ArrowLeft class="w-3 h-3" /> Flux Sortants ({filteredOutgoing.length})</span>
          </div>
          {#if filteredOutgoing.length === 0}
            <p class="text-[11px] text-slate-500 italic">Aucune dépendance sortante.</p>
          {:else}
            <div class="space-y-1 max-h-56 overflow-y-auto pr-1">
              {#each filteredOutgoing as edge}
                {@const tgt = nodeMap.get(edge.target)}
                <button
                  type="button"
                  onclick={() => jumpToSymbol(edge.target)}
                  class="w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-white/[0.03] hover:bg-sky-500/15 border border-white/5 hover:border-sky-500/40 text-left cursor-pointer transition-colors"
                >
                  <div class="min-w-0">
                    <div class="text-[11px] font-mono text-slate-100 truncate">
                      {tgt?.name || edge.target.replace('file::', '')}
                    </div>
                    {#if tgt?.file_path}
                      <div class="text-[9px] text-slate-500 truncate">{tgt.file_path}</div>
                    {/if}
                  </div>
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-mono border shrink-0 {formatRelColor(edge.relation)}">
                    {edge.relation || edge.edge_type || 'calls'}
                  </span>
                </button>
              {/each}
            </div>
          {/if}
        </div>

      {:else if cockpitState.activeTab === 'cve'}
        {#if activeAnomalies.length > 0}
          <div class="flex gap-1.5 p-1 rounded-lg bg-black/30 border border-white/10 text-[10px]">
            <button
              type="button"
              onclick={() => (cveScope = 'target')}
              class="flex-1 py-1 rounded cursor-pointer font-semibold {cveScope === 'target' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400'}"
            >
              Cible ({activeAnomalies.length})
            </button>
            <button
              type="button"
              onclick={() => (cveScope = 'project')}
              class="flex-1 py-1 rounded cursor-pointer font-semibold {cveScope === 'project' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400'}"
            >
              Projet ({cockpitState.allViolations.length})
            </button>
          </div>
        {/if}

        {#if displayedCves.length === 0}
          <div class="py-10 text-center text-emerald-400 space-y-1.5">
            <ShieldAlert class="w-8 h-8 mx-auto opacity-80" />
            <p class="font-semibold">Aucune vulnérabilité SAST détectée</p>
          </div>
        {:else}
          <div class="space-y-2">
            {#each displayedCves as cve}
              <div class="p-2.5 rounded-lg bg-rose-500/5 border border-rose-500/25 space-y-1.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    {cve.cve_id || cve.rule_id}
                  </span>
                  <span class="text-[10px] font-mono text-slate-400">
                    {cve.severity} • L{cve.line_number}
                  </span>
                </div>
                <div class="text-[11px] font-semibold text-white">{cve.title || cve.rule_id}</div>
                <p class="text-[11px] text-slate-300 leading-snug">{cve.description || cve.message}</p>
                <div class="text-[10px] font-mono text-slate-500 truncate">{cve.file_path}</div>
                <div class="flex gap-1.5 pt-1">
                  <button
                    type="button"
                    onclick={() => (cockpitState.isBountyModalOpen = true)}
                    class="flex items-center gap-1 px-2 py-1 rounded bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/35 text-amber-300 text-[10px] font-medium cursor-pointer"
                  >
                    <Bug class="w-3 h-3" /> Préparer PoC
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {/if}

      {:else if cockpitState.activeTab === 'tasks'}
        <div class="flex items-center justify-between">
          <span class="text-[10px] font-mono uppercase text-slate-400">
            Tâches Actives ({cockpitState.tasks.length})
          </span>
          <button
            type="button"
            onclick={refreshTasks}
            class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] text-slate-300 cursor-pointer"
          >
            <RefreshCw class="w-3 h-3 {tasksLoading ? 'animate-spin' : ''}" />
            Actualiser
          </button>
        </div>

        {#if tasksError}
          <p class="text-[11px] text-rose-400">{tasksError}</p>
        {:else if cockpitState.tasks.length === 0}
          <div class="py-10 text-center text-slate-400 space-y-1.5">
            <Clock class="w-7 h-7 mx-auto opacity-60" />
            <p>Aucune tâche active dans le workspace.</p>
          </div>
        {:else}
          <div class="space-y-2">
            {#each cockpitState.tasks as task}
              <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/10 space-y-1.5">
                <div class="flex items-start justify-between gap-2">
                  <div class="font-semibold text-white text-[11px]">{task.title}</div>
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-mono uppercase {task.status === 'done' ? 'bg-emerald-500/20 text-emerald-300' : task.status === 'in_progress' ? 'bg-sky-500/20 text-sky-300' : 'bg-slate-700/60 text-slate-300'}">
                    {task.status}
                  </span>
                </div>
                {#if task.target_symbol}
                  <button
                    type="button"
                    onclick={() => task.target_symbol && jumpToSymbol(task.target_symbol)}
                    class="text-[10px] font-mono text-sky-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <FileCode2 class="w-3 h-3" /> {task.target_symbol}
                  </button>
                {/if}
                <div class="w-full h-1.5 rounded bg-black/40 overflow-hidden">
                  <div class="h-full bg-emerald-400 transition-all" style="width: {task.progress || 0}%"></div>
                </div>
                <div class="flex gap-1.5 pt-0.5">
                  {#if task.status !== 'in_progress'}
                    <button
                      type="button"
                      onclick={() => setTaskStatus(task, 'in_progress')}
                      class="flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-300 text-[10px] cursor-pointer"
                    >
                      <Play class="w-2.5 h-2.5" /> Démarrer
                    </button>
                  {/if}
                  {#if task.status !== 'done'}
                    <button
                      type="button"
                      onclick={() => setTaskStatus(task, 'done')}
                      class="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-[10px] cursor-pointer"
                    >
                      <CheckCircle2 class="w-2.5 h-2.5" /> Terminer
                    </button>
                  {/if}
                </div>
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    </div>
  </aside>
{/if}
