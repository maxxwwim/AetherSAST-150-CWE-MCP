<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    Search,
    Code2,
    Folder,
    FileCode,
    ArrowRight,
    ShieldAlert,
    Flame,
    Cpu,
    Boxes,
    Workflow,
    GitCommit,
    Layers,
    X
  } from '@lucide/svelte';
  import type { SymbolBubble, AffiliationEdge } from '../types/graph';

  interface Props {
    query: string;
    isOpen: boolean;
    onClose: () => void;
    anchorEl?: HTMLElement | null;
  }

  let { query = $bindable(''), isOpen, onClose, anchorEl }: Props = $props();

  type TabCategory = 'all' | 'functions' | 'calls' | 'files';
  let activeTab = $state<TabCategory>('all');
  let selectedIndex = $state(0);
  let panelContainerEl = $state<HTMLDivElement | null>(null);

  // Dynamic portal positioning coordinates
  let coords = $state({ top: 46, left: 16, width: 620 });

  function updatePosition() {
    if (typeof window === 'undefined') return;
    if (anchorEl) {
      const rect = anchorEl.getBoundingClientRect();
      const panelWidth = Math.min(620, Math.max(300, window.innerWidth - 32));
      const idealLeft = rect.left + rect.width / 2 - panelWidth / 2;
      const clampedLeft = Math.max(16, Math.min(window.innerWidth - panelWidth - 16, idealLeft));
      const top = rect.bottom + 6;
      coords = { top, left: clampedLeft, width: panelWidth };
    } else {
      const panelWidth = Math.min(620, Math.max(300, window.innerWidth - 32));
      const left = Math.max(16, (window.innerWidth - panelWidth) / 2);
      coords = { top: 46, left, width: panelWidth };
    }
  }

  $effect(() => {
    if (isOpen) {
      updatePosition();
    }
  });

  function portal(node: HTMLElement) {
    document.body.appendChild(node);
    return {
      destroy() {
        if (node.parentNode) {
          node.parentNode.removeChild(node);
        }
      }
    };
  }

  interface SearchResultItem {
    id: string;
    type: 'symbol' | 'folder' | 'call' | 'file';
    title: string;
    subtitle: string;
    kindBadge?: string;
    complexity?: number;
    violationsCount?: number;
    relationType?: string;
    sourceNode?: string;
    targetNode?: string;
    folderName?: string;
    symbolId?: string;
    filePath?: string;
    score: number;
  }

  // Helper to resolve node names quickly
  const nodeMap = $derived.by(() => {
    const map = new Map<string, SymbolBubble>();
    for (const n of cockpitState.graph.nodes) {
      map.set(n.id, n);
    }
    return map;
  });

  // Extract distinct folders
  const allFolders = $derived.by(() => {
    const folders = new Map<string, { count: number; loc: number }>();
    for (const n of cockpitState.graph.nodes) {
      const f = n.folder || n.cluster_id || 'root';
      const cur = folders.get(f) || { count: 0, loc: 0 };
      cur.count += 1;
      cur.loc += n.loc || 1;
      folders.set(f, cur);
    }
    for (const [clusterName, nodeIds] of Object.entries(cockpitState.graph.clusters || {})) {
      if (!folders.has(clusterName)) {
        folders.set(clusterName, { count: nodeIds.length, loc: nodeIds.length * 20 });
      }
    }
    return Array.from(folders.entries()).map(([name, stat]) => ({
      name,
      count: stat.count,
      loc: stat.loc,
    }));
  });

  // Extract distinct files
  const allFiles = $derived.by(() => {
    const filePaths = new Map<string, { symbolId?: string; symbolCount: number; loc: number }>();
    for (const n of cockpitState.graph.nodes) {
      if (!n.file_path) continue;
      const cur = filePaths.get(n.file_path) || { symbolId: n.id, symbolCount: 0, loc: 0 };
      cur.symbolCount += 1;
      cur.loc += n.loc || 1;
      if (n.is_file) cur.symbolId = n.id;
      filePaths.set(n.file_path, cur);
    }
    return Array.from(filePaths.entries()).map(([filePath, stat]) => ({
      filePath,
      symbolId: stat.symbolId,
      symbolCount: stat.symbolCount,
      loc: stat.loc,
    }));
  });

  // Results computation
  const results = $derived.by((): SearchResultItem[] => {
    const q = (query || '').toLowerCase().trim();
    const items: SearchResultItem[] = [];

    // --- 1. FONCTIONS & SYMBOLES ---
    if (activeTab === 'all' || activeTab === 'functions') {
      for (const n of cockpitState.graph.nodes) {
        const nameLower = (n.name || '').toLowerCase();
        const fileLower = (n.file_path || '').toLowerCase();
        const kindLower = String(n.kind || '').toLowerCase();
        const folderLower = (n.folder || '').toLowerCase();

        let match = false;
        let score = 0;

        if (!q) {
          match = true;
          score = (n.anomalies && n.anomalies.length > 0 ? 50 : 0) + (n.cyclomatic_complexity >= 10 ? 30 : 10);
        } else if (nameLower === q) {
          match = true;
          score = 100;
        } else if (nameLower.startsWith(q)) {
          match = true;
          score = 85;
        } else if (nameLower.includes(q)) {
          match = true;
          score = 70;
        } else if (fileLower.includes(q) || folderLower.includes(q) || kindLower.includes(q)) {
          match = true;
          score = 40;
        } else if (n.anomalies && n.anomalies.some((a) => (a.cve_id || '').toLowerCase().includes(q) || (a.title || '').toLowerCase().includes(q))) {
          match = true;
          score = 75;
        }

        // Search sub-methods
        if (!match && n.methods) {
          for (const m of n.methods) {
            if ((m.name || '').toLowerCase().includes(q)) {
              items.push({
                id: `${n.id}::method::${m.name}`,
                type: 'symbol',
                title: `${n.name}::${m.name}()`,
                subtitle: `${n.file_path || ''}:${m.line || n.line_number || 1}`,
                kindBadge: 'method',
                complexity: 1,
                symbolId: n.id,
                filePath: n.file_path,
                score: 65,
              });
            }
          }
        }

        if (match) {
          const violCount = n.anomalies?.length || n.violations?.length || 0;
          items.push({
            id: n.id,
            type: 'symbol',
            title: n.name,
            subtitle: `${n.file_path || 'symbole'}${n.line_number ? `:${n.line_number}` : ''}${n.folder ? ` (${n.folder})` : ''}`,
            kindBadge: String(n.kind || 'fn'),
            complexity: n.cyclomatic_complexity || 1,
            violationsCount: violCount,
            symbolId: n.id,
            filePath: n.file_path,
            score: score + (violCount > 0 ? 15 : 0),
          });
        }
      }
    }

    // --- 2. APPELS & FLUX (Call Edges) ---
    if (activeTab === 'all' || activeTab === 'calls') {
      const edges = cockpitState.graph.edges || [];
      for (let i = 0; i < edges.length; i++) {
        const e = edges[i];
        const src = nodeMap.get(e.source);
        const tgt = nodeMap.get(e.target);
        const srcName = src?.name || e.source;
        const tgtName = tgt?.name || e.target;
        const rel = e.relation || e.edge_type || 'calls';
        const relLower = rel.toLowerCase();
        const srcLower = srcName.toLowerCase();
        const tgtLower = tgtName.toLowerCase();
        const transData = e.transmitted_data || '';

        let match = false;
        let score = 0;

        if (!q) {
          match = activeTab === 'calls' || i < 20;
          score = 20;
        } else if (srcLower.includes(q) || tgtLower.includes(q) || relLower.includes(q) || transData.toLowerCase().includes(q)) {
          match = true;
          score = 65;
          if (srcLower === q || tgtLower === q) score = 90;
        }

        if (match) {
          items.push({
            id: `edge-${e.source}-${e.target}-${i}`,
            type: 'call',
            title: `${srcName} ➔ ${tgtName}`,
            subtitle: `${rel} · ${src?.file_path || ''} ➔ ${tgt?.file_path || ''}${transData ? ` [${transData}]` : ''}`,
            relationType: rel,
            sourceNode: srcName,
            targetNode: tgtName,
            symbolId: tgt?.id || src?.id,
            score,
          });
        }
      }
    }

    // --- 3. FICHIERS & DOSSIERS ---
    if (activeTab === 'all' || activeTab === 'files') {
      // Folders
      for (const f of allFolders) {
        const fLower = f.name.toLowerCase();
        let match = false;
        let score = 0;

        if (!q) {
          match = activeTab === 'files' || f.name !== 'root';
          score = 30;
        } else if (fLower === q) {
          match = true;
          score = 95;
        } else if (fLower.startsWith(q)) {
          match = true;
          score = 80;
        } else if (fLower.includes(q)) {
          match = true;
          score = 60;
        }

        if (match) {
          items.push({
            id: `folder-${f.name}`,
            type: 'folder',
            title: f.name,
            subtitle: `Dossier architectural · ${f.count} symbole(s) · ~${f.loc} LOC`,
            folderName: f.name,
            kindBadge: 'dossier',
            score,
          });
        }
      }

      // Files
      for (const file of allFiles) {
        const fileLower = file.filePath.toLowerCase();
        let match = false;
        let score = 0;

        if (!q) {
          match = activeTab === 'files';
          score = 25;
        } else if (fileLower.endsWith(q) || fileLower.includes(q)) {
          match = true;
          score = 65;
        }

        if (match) {
          items.push({
            id: `file-${file.filePath}`,
            type: 'file',
            title: file.filePath.split(/[/\\]/).pop() || file.filePath,
            subtitle: `${file.filePath} · ${file.symbolCount} symbole(s)`,
            filePath: file.filePath,
            symbolId: file.symbolId,
            kindBadge: 'fichier',
            score,
          });
        }
      }
    }

    // Sort by relevance score
    items.sort((a, b) => b.score - a.score);
    return items.slice(0, 60);
  });

  // Reset selected index when results change
  $effect(() => {
    if (results.length > 0) {
      if (selectedIndex >= results.length) selectedIndex = 0;
    } else {
      selectedIndex = 0;
    }
  });

  function handleItemClick(item: SearchResultItem) {
    if (item.type === 'symbol' || item.type === 'file') {
      if (item.symbolId) {
        cockpitState.selectSymbol(item.symbolId, true);
        cockpitState.requestFocusSymbol(item.symbolId);
      }
      cockpitState.isInspectorOpen = true;
    } else if (item.type === 'call') {
      if (item.symbolId) {
        cockpitState.selectSymbol(item.symbolId, true);
        cockpitState.requestFocusSymbol(item.symbolId);
      }
      cockpitState.isInspectorOpen = true;
    } else if (item.type === 'folder') {
      if (item.folderName) {
        cockpitState.selectFolder(item.folderName);
        // Focus first node in that folder
        const first = cockpitState.graph.nodes.find((n) => (n.folder || n.cluster_id) === item.folderName);
        if (first) {
          cockpitState.requestFocusSymbol(first.id);
        }
      }
      cockpitState.isInspectorOpen = true;
    }
    onClose();
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (results.length > 0) {
        selectedIndex = (selectedIndex + 1) % results.length;
        scrollSelectedIntoView();
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (results.length > 0) {
        selectedIndex = (selectedIndex - 1 + results.length) % results.length;
        scrollSelectedIntoView();
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (results[selectedIndex]) {
        handleItemClick(results[selectedIndex]);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  }

  function scrollSelectedIntoView() {
    const el = document.getElementById(`search-res-item-${selectedIndex}`);
    el?.scrollIntoView({ block: 'nearest' });
  }
</script>

<svelte:window onkeydown={handleKeyDown} onresize={updatePosition} onscroll={updatePosition} />

<!-- Dropdown Panel Container (Detached Portal fixed directly under Search Input) -->
<div
  use:portal
  bind:this={panelContainerEl}
  style="top: {coords.top}px; left: {coords.left}px; width: {coords.width}px; z-index: 60;"
  class="fixed max-h-[500px] bg-[#0c101d]/98 backdrop-blur-2xl border border-sky-500/35 rounded-xl shadow-[0_20px_60px_rgba(0,0,0,0.85)] flex flex-col overflow-hidden text-slate-100 select-none animate-in fade-in zoom-in-95 duration-100"
  onclick={(e) => e.stopPropagation()}
  onkeydown={(e) => { if (e.key === 'Escape') onClose(); }}
  role="dialog"
  tabindex="-1"
  aria-label="Panneau de recherche complet"
>
  <!-- Category Filter Tabs Header -->
  <div class="px-3 py-2 bg-[#080b14]/90 border-b border-white/10 flex items-center justify-between gap-2 shrink-0">
    <div class="flex items-center gap-1">
      <button
        type="button"
        onclick={() => (activeTab = 'all')}
        class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer {activeTab === 'all' ? 'bg-sky-500/25 border border-sky-400/50 text-sky-200' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
      >
        <span>✨</span>
        <span>Tout</span>
      </button>

      <button
        type="button"
        onclick={() => (activeTab = 'functions')}
        class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer {activeTab === 'functions' ? 'bg-sky-500/25 border border-sky-400/50 text-sky-200' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
      >
        <Code2 class="w-3.5 h-3.5 text-sky-400" />
        <span>Fonctions & Symboles</span>
      </button>

      <button
        type="button"
        onclick={() => (activeTab = 'calls')}
        class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer {activeTab === 'calls' ? 'bg-emerald-500/25 border border-emerald-400/50 text-emerald-200' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
      >
        <Workflow class="w-3.5 h-3.5 text-emerald-400" />
        <span>Appels & Flux</span>
      </button>

      <button
        type="button"
        onclick={() => (activeTab = 'files')}
        class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer {activeTab === 'files' ? 'bg-purple-500/25 border border-purple-400/50 text-purple-200' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
      >
        <Folder class="w-3.5 h-3.5 text-purple-400" />
        <span>Fichiers & Dossiers</span>
      </button>
    </div>

    <div class="flex items-center gap-2 text-[10.5px] font-mono text-slate-400">
      <span class="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
        {results.length} résultat{results.length > 1 ? 's' : ''}
      </span>
      <button
        type="button"
        onclick={onClose}
        class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer transition-colors"
        title="Fermer (Échap)"
      >
        <X class="w-3.5 h-3.5" />
      </button>
    </div>
  </div>

  <!-- Results List -->
  <div class="flex-1 overflow-y-auto p-1.5 space-y-1 max-h-[360px] scrollbar-thin">
    {#each results as item, idx}
      <button
        type="button"
        id={`search-res-item-${idx}`}
        onclick={() => handleItemClick(item)}
        class="w-full flex items-center justify-between gap-3 p-2 rounded-lg text-left transition-all cursor-pointer group {idx === selectedIndex ? 'bg-sky-500/20 border border-sky-400/40 shadow-xs' : 'hover:bg-white/[0.05] border border-transparent'}"
      >
        <!-- Left: Icon + Title + Subtitle -->
        <div class="flex items-center gap-2.5 min-w-0 flex-1">
          <!-- Icon depending on item type -->
          <div class="shrink-0 p-1.5 rounded-md bg-white/[0.04] border border-white/5">
            {#if item.type === 'folder'}
              <Folder class="w-4 h-4 text-purple-400" />
            {:else if item.type === 'file'}
              <FileCode class="w-4 h-4 text-slate-300" />
            {:else if item.type === 'call'}
              <Workflow class="w-4 h-4 text-emerald-400" />
            {:else if item.violationsCount && item.violationsCount > 0}
              <ShieldAlert class="w-4 h-4 text-rose-400" />
            {:else if item.complexity && item.complexity >= 10}
              <Flame class="w-4 h-4 text-amber-400" />
            {:else}
              <Code2 class="w-4 h-4 text-sky-400" />
            {/if}
          </div>

          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="text-xs font-semibold text-slate-100 group-hover:text-white truncate">
                {item.title}
              </span>
              {#if item.kindBadge}
                <span class="text-[9px] font-mono px-1.5 py-0.2 rounded bg-white/10 text-slate-300 border border-white/10 uppercase">
                  {item.kindBadge}
                </span>
              {/if}
            </div>
            <div class="text-[10px] text-slate-400 font-mono truncate mt-0.5">
              {item.subtitle}
            </div>
          </div>
        </div>

        <!-- Right: Badges (Violations, Complexity, Action indicator) -->
        <div class="flex items-center gap-2 shrink-0">
          {#if item.violationsCount && item.violationsCount > 0}
            <span class="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
              <ShieldAlert class="w-3 h-3 text-rose-400" />
              <span>{item.violationsCount} CWE</span>
            </span>
          {/if}

          {#if item.complexity && item.complexity >= 10}
            <span class="flex items-center gap-0.5 text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
              <Flame class="w-3 h-3 text-amber-400" />
              <span>CC {item.complexity}</span>
            </span>
          {/if}

          {#if item.relationType}
            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              {item.relationType}
            </span>
          {/if}

          <span class="text-slate-600 group-hover:text-sky-300 transition-colors text-xs">➔</span>
        </div>
      </button>
    {/each}

    {#if results.length === 0}
      <div class="py-10 text-center text-slate-500 text-xs italic">
        Aucun résultat trouvé pour <strong class="text-slate-300">"{query}"</strong> dans cet onglet.
      </div>
    {/if}
  </div>

  <!-- Footer Help Bar -->
  <div class="px-3 py-1.5 bg-[#070911] border-t border-white/10 flex items-center justify-between text-[10px] font-mono text-slate-400 shrink-0">
    <div class="flex items-center gap-3">
      <span><kbd class="px-1 py-0.5 rounded bg-white/10 text-slate-300">↑↓</kbd> Naviguer</span>
      <span><kbd class="px-1 py-0.5 rounded bg-white/10 text-slate-300">Entrée</kbd> Téléporter & Inspecter</span>
      <span><kbd class="px-1 py-0.5 rounded bg-white/10 text-slate-300">Échap</kbd> Fermer</span>
    </div>
    <div class="text-sky-400 font-semibold">
      Aether Omnibox • La Totale
    </div>
  </div>
</div>
