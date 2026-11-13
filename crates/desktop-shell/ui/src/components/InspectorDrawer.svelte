<script lang="ts">
  import { cockpitState, normalizeEdgeRelation } from '../state/graphState.svelte';
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
    Layers,
    Copy,
    Check,
    Radio
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

  // Symbol or Folder incident edges
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
      .slice(0, 32);
  });

  const folderFiles = $derived.by(() => folderNodes.filter((n) => n.is_file || n.kind === 'File'));
  const folderClasses = $derived.by(() => folderNodes.filter((n) => n.is_class || n.kind === 'Class' || n.kind === 'Struct'));
  const folderTotalLoc = $derived.by(() => folderNodes.reduce((acc, n) => acc + (n.loc || n.lines_count || 0), 0));

  // Lazy AST comment extraction when active symbol has no preloaded docstring
  let lazyAstComment = $state('');
  let lazyLoadedForId = $state('');

  $effect(() => {
    const sym = cockpitState.activeSymbol;
    if (!sym || sym.docstring || !sym.file_path || sym.is_file) {
      lazyAstComment = '';
      lazyLoadedForId = sym?.id || '';
      return;
    }
    if (lazyLoadedForId === sym.id) return;
    lazyLoadedForId = sym.id;
    api
      .getFileContent(sym.file_path)
      .then((res) => {
        if (res?.status !== 'ok' || !res.content || !sym.line_number) return;
        const lines = String(res.content).split('\n');
        const idx = Math.min(lines.length - 1, sym.line_number - 1);
        const out: string[] = [];
        for (let i = idx - 1; i >= 0 && i >= idx - 25; i--) {
          const t = lines[i].trim();
          if (!t) {
            if (out.length > 0) break;
            continue;
          }
          if (t.startsWith('#[') || t.startsWith('#![')) continue;
          if (t.startsWith('///') || t.startsWith('//!')) out.push(t.slice(3).trim());
          else if (t.startsWith('//')) out.push(t.slice(2).trim());
          else if (t.startsWith('*') || t.startsWith('/**') || t.startsWith('*/')) {
            const c = t.replace(/^\/?\*+\/?/, '').trim();
            if (c) out.push(c);
          } else if (t.startsWith('#')) out.push(t.slice(1).trim());
          else break;
        }
        lazyAstComment = out.reverse().join('\n');
      })
      .catch(() => {});
  });

  // Rich reconstructed signature for Functions / Methods / Classes
  const fullDeclaration = $derived.by(() => {
    if (!symbol) return '';
    if (symbol.methods && symbol.methods.length > 0 && !symbol.is_class && !symbol.is_file) {
      const m = symbol.methods[0];
      return `${m.is_async ? 'async ' : ''}fn ${m.name}(${m.args || ''})${m.returns ? ` -> ${m.returns}` : ''}`;
    }
    if (symbol.is_class) {
      return `${symbol.stereotype || 'class'} ${symbol.name}  // ${symbol.attributes?.length || 0} attributs, ${symbol.methods?.length || 0} méthodes`;
    }
    if (!symbol.is_file) {
      return `${symbol.stereotype || symbol.kind} ${symbol.name}()  // L${symbol.line_number || 1}`;
    }
    return '';
  });

  // Security alerts attached to active target, child symbols in the same file, or folder
  const activeAnomalies = $derived.by(() => {
    const out: CveAnomalyRecord[] = [];
    const seen = new Set<string>();
    const pushAll = (list?: CveAnomalyRecord[]) => {
      if (!list) return;
      for (const a of list) {
        const key = `${a.rule_id}:${a.line_number}:${a.message}`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push(a);
        }
      }
    };
    if (symbol) {
      pushAll(symbol.anomalies);
      if (symbol.is_file && symbol.file_path) {
        for (const n of cockpitState.graph.nodes) {
          if (n.file_path === symbol.file_path) pushAll(n.anomalies);
        }
        for (const e of outgoingEdges) {
          const child = nodeMap.get(e.target);
          if (child) pushAll(child.anomalies);
        }
      }
      return out;
    }
    if (isFolderMode) {
      for (const n of folderNodes) pushAll(n.anomalies);
      return out;
    }
    return out;
  });

  const hasSecurityAlert = $derived(
    activeAnomalies.length > 0 ||
      Boolean(symbol?.has_security_violation) ||
      (Boolean(symbol?.is_file) && siblingSymbols.some((s) => s.has_security_violation))
  );

  // Relations filter inside Flux tab
  let relationQuery = $state('');
  let relationTypeFilter = $state('all');

  const availableRelTypes = $derived.by(() => {
    const set = new Set<string>();
    for (const e of incomingEdges) set.add(normalizeEdgeRelation(e.relation || e.edge_type));
    for (const e of outgoingEdges) set.add(normalizeEdgeRelation(e.relation || e.edge_type));
    return Array.from(set);
  });

  const filteredIncoming = $derived.by(() => {
    const q = relationQuery.trim().toLowerCase();
    return incomingEdges.filter((e) => {
      const rel = normalizeEdgeRelation(e.relation || e.edge_type);
      if (relationTypeFilter !== 'all' && rel !== relationTypeFilter) return false;
      if (!q) return true;
      const n = nodeMap.get(e.source);
      return (
        e.source.toLowerCase().includes(q) ||
        (n?.name || '').toLowerCase().includes(q) ||
        rel.includes(q)
      );
    });
  });

  const filteredOutgoing = $derived.by(() => {
    const q = relationQuery.trim().toLowerCase();
    return outgoingEdges.filter((e) => {
      const rel = normalizeEdgeRelation(e.relation || e.edge_type);
      if (relationTypeFilter !== 'all' && rel !== relationTypeFilter) return false;
      if (!q) return true;
      const n = nodeMap.get(e.target);
      return (
        e.target.toLowerCase().includes(q) ||
        (n?.name || '').toLowerCase().includes(q) ||
        rel.includes(q)
      );
    });
  });

  // Mini-DAG top callers & callees (up to 5 each, with relation label)
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
        rel: normalizeEdgeRelation(e.relation || e.edge_type),
      });
      if (res.length >= 5) break;
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
        rel: normalizeEdgeRelation(e.relation || e.edge_type),
      });
      if (res.length >= 5) break;
    }
    return res;
  });

  let mermaidCopied = $state(false);
  function copyMermaidDiagram() {
    const centerName = (symbol?.name || selectedFolder || 'Module').replace(/[^A-Za-z0-9_]/g, '_');
    let code = `classDiagram\n  class ${centerName} {\n`;
    if (symbol) {
      for (const a of symbol.attributes || []) {
        code += `    ${a.visibility || '+'}${a.attr_type || 'any'} ${a.name}\n`;
      }
      for (const m of symbol.methods || []) {
        code += `    ${m.visibility || '+'}${m.name}(${m.args || ''}) ${m.returns || ''}\n`;
      }
    }
    code += `  }\n`;
    for (const e of incomingEdges.slice(0, 12)) {
      const s = (nodeMap.get(e.source)?.name || e.source).replace(/[^A-Za-z0-9_]/g, '_');
      code += `  ${s} --> ${centerName} : ${e.relation || 'calls'}\n`;
    }
    for (const e of outgoingEdges.slice(0, 12)) {
      const t = (nodeMap.get(e.target)?.name || e.target).replace(/[^A-Za-z0-9_]/g, '_');
      code += `  ${centerName} --> ${t} : ${e.relation || 'calls'}\n`;
    }
    navigator.clipboard?.writeText(code);
    mermaidCopied = true;
    setTimeout(() => (mermaidCopied = false), 1500);
  }

  // CVE tab scope switcher
  let cveScope = $state<'target' | 'project'>('target');
  const displayedCves = $derived.by(() => {
    if (cveScope === 'target' && activeAnomalies.length > 0) return activeAnomalies;
    return cockpitState.allViolations.slice(0, 100);
  });

  // Tasks live sync
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
    const r = normalizeEdgeRelation(rel);
    if (r === 'violates') return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
    if (r === 'queries') return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
    if (r === 'imports' || r === 'contains') return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    if (r === 'realtime' || r === 'documents') return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
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
            {#if activeAnomalies.length > 0 || symbol.has_security_violation}
              <span class="px-1.5 py-0.5 text-[10px] font-mono font-bold rounded bg-rose-500/25 text-rose-200 border border-rose-500/50 animate-pulse">
                🚨 {activeAnomalies.length || 1} CWE
              </span>
            {/if}
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
            onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'xray' ? 'standard' : 'xray')}
            title="Activer / Couper le Tunnel X-Ray sur ce nœud"
            class="p-1.5 rounded border cursor-pointer {cockpitState.visionMode === 'xray' ? 'bg-purple-500/25 border-purple-500/50 text-purple-200' : 'bg-white/5 hover:bg-purple-500/20 text-slate-300 border-white/10'}"
          >
            <Radio class="w-3.5 h-3.5" />
          </button>
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
        class="flex-1 py-2 px-1 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'debrief' ? 'border-sky-400 text-sky-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Débrief
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'uml')}
        class="flex-1 py-2 px-1 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'uml' ? 'border-indigo-400 text-indigo-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        UML
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'relations')}
        class="flex-1 py-2 px-1 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'relations' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Flux ({incomingEdges.length + outgoingEdges.length})
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'cve')}
        class="flex-1 py-2 px-1 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'cve' ? 'border-rose-400 text-rose-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        CVE ({activeAnomalies.length || cockpitState.allViolations.length})
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.activeTab = 'tasks')}
        class="flex-1 py-2 px-1 border-b-2 transition-colors cursor-pointer {cockpitState.activeTab === 'tasks' ? 'border-emerald-400 text-emerald-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Tâches
      </button>
    </div>

    <!-- Tab Body -->
    <div class="flex-1 overflow-y-auto p-3.5 space-y-3 text-xs select-text">
      {#if cockpitState.activeTab === 'debrief'}
        {#if symbol}
          <!-- Immediate CWE Security Alert Box when clicking a blinking/vulnerable file or function -->
          {#if hasSecurityAlert}
            <div class="p-2.5 rounded-xl bg-rose-950/60 border border-rose-500/60 space-y-2 shadow-lg">
              <div class="flex items-center justify-between gap-2">
                <span class="text-[11px] font-extrabold text-rose-200 flex items-center gap-1.5">
                  <ShieldAlert class="w-4 h-4 text-rose-400" />
                  🚨 ALERTE CWE & SAST ({activeAnomalies.length || 1})
                </span>
                <button
                  type="button"
                  onclick={() => (cockpitState.activeTab = 'cve')}
                  class="px-1.5 py-0.5 rounded bg-rose-500/25 hover:bg-rose-500/40 text-rose-100 text-[9.5px] font-mono cursor-pointer"
                >
                  Détails ➔
                </button>
              </div>
              {#if activeAnomalies.length === 0}
                <div class="p-2 rounded-lg bg-black/45 border border-rose-500/35 space-y-1">
                  <div class="text-[11px] text-rose-100">Violation SAST / CWE détectée dans ce fichier ou l'un de ses symboles.</div>
                  <div class="pt-0.5 flex gap-1.5">
                    <button
                      type="button"
                      onclick={() => (cockpitState.isBountyModalOpen = true)}
                      class="flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 text-[10px] font-semibold cursor-pointer"
                    >
                      <Bug class="w-3 h-3" /> 🧪 PoC Bug Bounty
                    </button>
                  </div>
                </div>
              {/if}
              {#each activeAnomalies.slice(0, 3) as alert}
                <div class="p-2 rounded-lg bg-black/45 border border-rose-500/35 space-y-1">
                  <div class="flex items-center justify-between gap-1.5">
                    <span class="px-1.5 py-0.5 rounded bg-rose-500/30 text-rose-200 font-mono text-[10px] font-bold">
                      {alert.cve_id || alert.rule_id}
                    </span>
                    <span class="text-[9.5px] font-mono text-rose-300">{alert.severity} • L{alert.line_number}</span>
                  </div>
                  <p class="text-[11px] text-slate-200 leading-snug">{alert.description || alert.message}</p>
                  {#if alert.transmitted_data}
                    <div class="text-[10px] font-mono text-amber-300 bg-amber-500/10 px-1.5 py-0.5 rounded">
                      📦 Vecteur : {alert.transmitted_data}
                    </div>
                  {/if}
                  <div class="pt-0.5 flex gap-1.5">
                    <button
                      type="button"
                      onclick={() => (cockpitState.isBountyModalOpen = true)}
                      class="flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 text-[10px] font-semibold cursor-pointer"
                    >
                      <Bug class="w-3 h-3" /> 🧪 PoC Bug Bounty
                    </button>
                  </div>
                </div>
              {/each}
            </div>
          {/if}

          <!-- Layer & BLAKE3 seals -->
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
              <div class="text-[10px] text-slate-400 uppercase font-mono">Complexité McCabe</div>
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

          <!-- Function / Class Declaration & Signature + Docstring -->
          {#if fullDeclaration || symbol.docstring || lazyAstComment}
            <div class="p-2.5 rounded-lg bg-slate-900/85 border border-sky-500/30 space-y-2">
              <div class="text-[10px] font-mono uppercase text-sky-400">⚡ Déclaration & Contrat AST</div>
              {#if fullDeclaration}
                <pre class="p-2 rounded bg-black/55 border border-white/10 font-mono text-[10.5px] text-sky-200 overflow-x-auto whitespace-pre-wrap break-all">{fullDeclaration}</pre>
              {/if}
              {#if symbol.docstring || lazyAstComment}
                <p class="text-[11px] text-slate-200 border-l-2 border-emerald-400/60 pl-2 whitespace-pre-wrap leading-relaxed">
                  {symbol.docstring || lazyAstComment}
                </p>
              {/if}
              {#if symbol.methods?.[0]?.calls && symbol.methods[0].calls.length > 0}
                <div class="flex flex-wrap gap-1 pt-0.5">
                  <span class="text-[9.5px] font-mono text-slate-400">Appels internes :</span>
                  {#each symbol.methods[0].calls.slice(0, 12) as c}
                    <span class="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 font-mono text-[9.5px] text-cyan-300">{c}</span>
                  {/each}
                </div>
              {/if}
            </div>
          {/if}

          <!-- Inline Callers & Callees right in Débrief for fast inspection -->
          {#if !symbol.is_file && (incomingEdges.length > 0 || outgoingEdges.length > 0)}
            <div class="space-y-2">
              {#if incomingEdges.length > 0}
                <div>
                  <div class="text-[10px] font-mono uppercase text-purple-300 mb-1">📥 Appelants ({incomingEdges.length})</div>
                  <div class="space-y-1 max-h-28 overflow-y-auto pr-1">
                    {#each incomingEdges.slice(0, 8) as e}
                      {@const src = nodeMap.get(e.source)}
                      <button
                        type="button"
                        onclick={() => jumpToSymbol(e.source)}
                        class="w-full flex items-center justify-between px-2 py-1 rounded bg-white/[0.03] hover:bg-purple-500/15 border border-white/5 text-left cursor-pointer"
                      >
                        <span class="font-mono text-[10.5px] text-slate-200 truncate">{src?.name || e.source}</span>
                        <span class="text-[9.5px] text-purple-300 shrink-0 ml-2">{e.relation || 'calls'}</span>
                      </button>
                    {/each}
                  </div>
                </div>
              {/if}
              {#if outgoingEdges.length > 0}
                <div>
                  <div class="text-[10px] font-mono uppercase text-sky-300 mb-1">📤 Sous-Appels ({outgoingEdges.length})</div>
                  <div class="space-y-1 max-h-28 overflow-y-auto pr-1">
                    {#each outgoingEdges.slice(0, 8) as e}
                      {@const tgt = nodeMap.get(e.target)}
                      <button
                        type="button"
                        onclick={() => jumpToSymbol(e.target)}
                        class="w-full flex items-center justify-between px-2 py-1 rounded bg-white/[0.03] hover:bg-sky-500/15 border border-white/5 text-left cursor-pointer"
                      >
                        <span class="font-mono text-[10.5px] text-slate-200 truncate">{tgt?.name || e.target}</span>
                        <span class="text-[9.5px] text-sky-300 shrink-0 ml-2">{e.relation || 'calls'}</span>
                      </button>
                    {/each}
                  </div>
                </div>
              {/if}
            </div>
          {/if}

          {#if siblingSymbols.length > 0}
            <div>
              <div class="text-[10px] font-mono uppercase text-slate-400 mb-1.5">
                Symboles contenus / frères dans ce fichier ({siblingSymbols.length})
              </div>
              <div class="space-y-1 max-h-44 overflow-y-auto pr-1">
                {#each siblingSymbols as sub}
                  <button
                    type="button"
                    onclick={() => jumpToSymbol(sub.id)}
                    class="w-full flex items-center justify-between px-2.5 py-1.5 rounded bg-white/[0.03] hover:bg-sky-500/15 border border-white/5 hover:border-sky-500/35 text-left cursor-pointer transition-colors"
                  >
                    <span class="truncate font-mono text-[11px] text-slate-200">
                      {sub.has_security_violation ? '🚨' : sub.is_class ? '🏛️' : '⚡'} {sub.name}
                    </span>
                    <span class="text-[10px] text-sky-400 shrink-0 ml-2">{sub.stereotype || sub.kind}</span>
                  </button>
                {/each}
              </div>
            </div>
          {/if}
        {:else if isFolderMode}
          {#if activeAnomalies.length > 0}
            <div class="p-2.5 rounded-xl bg-rose-950/60 border border-rose-500/50 space-y-1">
              <div class="text-[11px] font-bold text-rose-200">🚨 {activeAnomalies.length} Alerte(s) CWE dans ce dossier</div>
              <button
                type="button"
                onclick={() => (cockpitState.activeTab = 'cve')}
                class="text-[10.5px] text-rose-300 underline cursor-pointer"
              >
                Voir toutes les vulnérabilités ➔
              </button>
            </div>
          {/if}
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
              {#each folderNodes.slice(0, 45) as item}
                <button
                  type="button"
                  onclick={() => jumpToSymbol(item.id)}
                  class="w-full flex items-center justify-between px-2.5 py-1.5 rounded bg-white/[0.03] hover:bg-sky-500/15 border border-white/5 hover:border-sky-500/35 text-left cursor-pointer"
                >
                  <span class="truncate font-mono text-[11px] text-slate-200">
                    {item.has_security_violation ? '🚨' : item.is_file ? '📄' : item.is_class ? '🏛️' : '⚡'} {item.name}
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
          <!-- UML Structured Card + Mermaid Copy -->
          <div class="flex justify-end">
            <button
              type="button"
              onclick={copyMermaidDiagram}
              class="flex items-center gap-1 px-2.5 py-1 rounded-md bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/35 text-indigo-300 text-[10px] font-semibold cursor-pointer"
            >
              {#if mermaidCopied}<Check class="w-3 h-3 text-emerald-400" /><span>Mermaid Copié</span>{:else}<Copy class="w-3 h-3" /><span>📋 Copier Mermaid UML</span>{/if}
            </button>
          </div>

          <div class="rounded-xl border border-indigo-500/35 bg-[#090d16] overflow-hidden shadow-lg">
            <div class="px-3.5 py-2.5 bg-indigo-950/50 border-b border-indigo-500/30 text-center">
              <div class="text-[10px] font-mono text-indigo-300">
                {symbol ? (symbol.stereotype || `«${symbol.kind}»`) : '«Module / Dossier»'}
              </div>
              <div class="text-sm font-bold text-white truncate">
                {symbol ? symbol.name : `📁 ${selectedFolder}`}
              </div>
              {#if symbol?.galaxy}
                <div class="text-[9.5px] font-mono text-slate-400 mt-0.5">
                  galaxy:{symbol.galaxy} • layer:{symbol.layer}
                </div>
              {/if}
            </div>

            <!-- Attributes / Properties Compartment -->
            <div class="px-3 py-2 border-b border-indigo-500/20 space-y-1 font-mono text-[11px]">
              <div class="text-[9px] uppercase tracking-wider text-slate-500 mb-1">Attributs & Signatures</div>
              {#if symbol?.attributes && symbol.attributes.length > 0}
                {#each symbol.attributes as attr}
                  <div class="flex items-center justify-between gap-2 text-slate-200">
                    <span class="truncate"><span class="text-emerald-400">{attr.visibility || '+'}</span> {attr.name}</span>
                    <span class="text-[10px] text-sky-300 shrink-0">: {attr.attr_type || attr.type || 'any'}</span>
                  </div>
                {/each}
              {:else if symbol}
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> file_path</span>
                  <span class="text-sky-300 truncate max-w-[190px]">: {symbol.file_path}</span>
                </div>
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> lines_count / complexity</span>
                  <span class="text-amber-300">: {symbol.loc || 1} LOC / CC {symbol.cyclomatic_complexity || 1}</span>
                </div>
              {:else}
                <div class="flex items-center justify-between text-slate-300">
                  <span><span class="text-emerald-400">+</span> fichiers / classes</span>
                  <span class="text-sky-300">: {folderFiles.length} / {folderClasses.length}</span>
                </div>
              {/if}
            </div>

            <!-- Methods / Operations Compartment -->
            <div class="px-3 py-2 space-y-1.5 font-mono text-[11px]">
              <div class="text-[9px] uppercase tracking-wider text-slate-500">
                {symbol ? 'Opérations, Paramètres & Appels AST' : 'Fichiers du Module'}
              </div>
              {#if symbol?.methods && symbol.methods.length > 0}
                {#each symbol.methods.slice(0, 20) as m}
                  <div class="p-1.5 rounded bg-white/[0.025] border border-white/5 space-y-1">
                    <div class="flex items-center justify-between gap-2 text-slate-100">
                      <span class="truncate">
                        <span class="text-purple-400">{m.visibility || '+'}</span>
                        <span class="text-sky-300">{m.is_async ? 'async ' : ''}</span>{m.name}({m.args || ''})
                      </span>
                      {#if m.returns}
                        <span class="text-[10px] text-emerald-300 shrink-0">-> {m.returns}</span>
                      {/if}
                    </div>
                    {#if m.calls && m.calls.length > 0}
                      <div class="text-[9.5px] text-slate-400 truncate">
                        ↳ appelle : {m.calls.slice(0, 6).join(', ')}
                      </div>
                    {/if}
                  </div>
                {/each}
              {:else if symbol && siblingSymbols.length > 0}
                {#each siblingSymbols.slice(0, 12) as sub}
                  <button
                    type="button"
                    onclick={() => jumpToSymbol(sub.id)}
                    class="w-full flex items-center justify-between text-left hover:text-sky-300 text-slate-300 cursor-pointer py-0.5"
                  >
                    <span class="truncate"><span class="text-purple-400">+</span> {sub.methods?.[0]?.signature || `${sub.name}()`}</span>
                    <span class="text-[10px] text-slate-500 shrink-0 ml-1">{sub.stereotype || sub.kind}</span>
                  </button>
                {/each}
              {:else if isFolderMode}
                {#each folderFiles.slice(0, 12) as f}
                  <button
                    type="button"
                    onclick={() => jumpToSymbol(f.id)}
                    class="w-full flex items-center justify-between text-left hover:text-sky-300 text-slate-300 cursor-pointer py-0.5"
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

          <!-- Interactive SVG Mini-DAG with relation labels -->
          <div class="rounded-xl border border-white/10 bg-[#070a12] p-2.5">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-[10px] font-mono uppercase text-sky-400 flex items-center gap-1">
                <GitBranch class="w-3 h-3" /> Mini-DAG Flux & Relations
              </span>
              <span class="text-[10px] text-slate-500">Entrants ({incomingEdges.length}) • Sortants ({outgoingEdges.length})</span>
            </div>
            <svg viewBox="0 0 360 154" class="w-full h-36 font-mono text-[9px]">
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
                  {@const y = (154 - miniInNodes.length * 29) / 2 + idx * 29 + 3}
                  <g
                    class="cursor-pointer"
                    onclick={() => jumpToSymbol(src.id)}
                    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && jumpToSymbol(src.id)}
                    role="button"
                    tabindex="0"
                  >
                    <path d="M 96 {y + 11} L 128 77" fill="none" stroke={src.rel === 'violates' ? '#ef4444' : '#c084fc'} stroke-width="1.2" stroke-dasharray="3,2" marker-end="url(#uml-arrow-in)" />
                    <text x="112" y={y + 8} fill="#a78bfa" font-size="7" text-anchor="middle">{src.rel}</text>
                    <rect x="4" y={y} width="92" height="22" rx="4" fill="#0f172a" stroke="#a855f7" stroke-width="1" />
                    <text x="50" y={y + 14} fill="#e2e8f0" text-anchor="middle">{truncateSvg(src.label, 12)}</text>
                  </g>
                {/each}
              {:else}
                <text x="50" y="80" fill="#64748b" font-style="italic" text-anchor="middle">[Entrée]</text>
              {/if}

              <!-- Center Node -->
              <rect x="130" y="52" width="100" height="50" rx="6" fill="#0c192c" stroke="#38bdf8" stroke-width="1.8" />
              <text x="180" y="72" fill="#ffffff" font-weight="bold" font-size="10" text-anchor="middle">
                {truncateSvg(symbol ? symbol.name : selectedFolder || 'Root', 13)}
              </text>
              <text x="180" y="88" fill="#38bdf8" font-size="8" text-anchor="middle">
                {truncateSvg(symbol ? (symbol.stereotype || symbol.kind) : 'Folder', 14)}
              </text>

              <!-- Outbound nodes (Right) -->
              {#if miniOutNodes.length > 0}
                {#each miniOutNodes as tgt, idx}
                  {@const y = (154 - miniOutNodes.length * 29) / 2 + idx * 29 + 3}
                  <g
                    class="cursor-pointer"
                    onclick={() => jumpToSymbol(tgt.id)}
                    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && jumpToSymbol(tgt.id)}
                    role="button"
                    tabindex="0"
                  >
                    <path d="M 230 77 L 262 {y + 11}" fill="none" stroke={tgt.rel === 'violates' ? '#ef4444' : '#38bdf8'} stroke-width="1.2" marker-end="url(#uml-arrow-out)" />
                    <text x="246" y={y + 8} fill="#7dd3fc" font-size="7" text-anchor="middle">{tgt.rel}</text>
                    <rect x="264" y={y} width="92" height="22" rx="4" fill="#0f172a" stroke="#38bdf8" stroke-width="1" />
                    <text x="310" y={y + 14} fill="#e2e8f0" text-anchor="middle">{truncateSvg(tgt.label, 12)}</text>
                  </g>
                {/each}
              {:else}
                <text x="310" y="80" fill="#64748b" font-style="italic" text-anchor="middle">[Feuille]</text>
              {/if}
            </svg>
          </div>
        {:else}
          <p class="text-slate-400 text-center py-8">Sélectionnez un symbole ou un dossier pour afficher son diagramme UML.</p>
        {/if}

      {:else if cockpitState.activeTab === 'relations'}
        <!-- Relation Filter & Type Chips -->
        <div class="space-y-2">
          <div class="relative">
            <Search class="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              bind:value={relationQuery}
              placeholder="Filtrer les flux entrants / sortants..."
              class="w-full pl-8 pr-2.5 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-sky-500/50"
            />
          </div>
          {#if availableRelTypes.length > 1}
            <div class="flex flex-wrap gap-1">
              <button
                type="button"
                onclick={() => (relationTypeFilter = 'all')}
                class="px-2 py-0.5 rounded text-[10px] font-mono border cursor-pointer {relationTypeFilter === 'all' ? 'bg-sky-500/20 border-sky-500/40 text-sky-200' : 'bg-white/5 border-white/10 text-slate-400'}"
              >
                Tous
              </button>
              {#each availableRelTypes as rt}
                <button
                  type="button"
                  onclick={() => (relationTypeFilter = rt)}
                  class="px-2 py-0.5 rounded text-[10px] font-mono border cursor-pointer {relationTypeFilter === rt ? formatRelColor(rt) : 'bg-white/5 border-white/10 text-slate-400'}"
                >
                  {rt}
                </button>
              {/each}
            </div>
          {/if}
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
                      {src?.has_security_violation ? '🚨 ' : ''}{src?.name || edge.source.replace('file::', '')}
                    </div>
                    <div class="text-[9.5px] text-slate-400 truncate">
                      {src ? `${src.layer} • ${src.file_path}:${src.line_number || 1}` : edge.source}
                    </div>
                    {#if edge.transmitted_data}
                      <div class="text-[9.5px] font-mono text-amber-300 truncate">📦 {edge.transmitted_data}</div>
                    {/if}
                  </div>
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-mono border shrink-0 {formatRelColor(edge.relation)}">
                    {normalizeEdgeRelation(edge.relation || edge.edge_type)}
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
                      {tgt?.has_security_violation ? '🚨 ' : ''}{tgt?.name || edge.target.replace('file::', '')}
                    </div>
                    <div class="text-[9.5px] text-slate-400 truncate">
                      {tgt ? `${tgt.layer} • ${tgt.file_path}:${tgt.line_number || 1}` : edge.target}
                    </div>
                    {#if edge.transmitted_data}
                      <div class="text-[9.5px] font-mono text-amber-300 truncate">📦 {edge.transmitted_data}</div>
                    {/if}
                  </div>
                  <span class="px-1.5 py-0.5 rounded text-[9px] font-mono border shrink-0 {formatRelColor(edge.relation)}">
                    {normalizeEdgeRelation(edge.relation || edge.edge_type)}
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
                {#if cve.transmitted_data}
                  <div class="text-[10px] font-mono text-amber-300 bg-amber-500/10 px-1.5 py-0.5 rounded">
                    📦 Donnée transmise : {cve.transmitted_data} ({cve.transmitted_type || 'Untyped'})
                  </div>
                {/if}
                {#if cve.remediation}
                  <div class="text-[10px] text-emerald-300/90 bg-emerald-500/10 px-2 py-1 rounded">
                    🛡️ {cve.remediation}
                  </div>
                {/if}
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
