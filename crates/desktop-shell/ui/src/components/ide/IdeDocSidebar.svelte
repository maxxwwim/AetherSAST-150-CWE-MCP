<script lang="ts">
  import { cockpitState, getNodeAlertKind } from '../../state/graphState.svelte';
  import {
    BookOpen,
    FileText,
    Search,
    X,
    Lock,
    ShieldCheck,
    ShieldAlert,
    ChevronRight,
    Sparkles,
    Layers,
    FileCode2
  } from '@lucide/svelte';

  let docSearch = $state('');

  // Active Symbol & Target resolution
  const symbol = $derived(cockpitState.activeSymbol);
  const activeFile = $derived(cockpitState.ideActiveFile ? cockpitState.ideActiveFile.replace(/\\/g, '/') : '');

  // Extract all markdown doc files in project
  const docFiles = $derived.by(() => {
    const seen = new Set<string>();
    const list: {
      name: string;
      path: string;
      folder: string;
      blake3?: boolean;
      lockVerified?: boolean;
      hasSec?: boolean;
    }[] = [];
    const q = docSearch.trim().toLowerCase();

    for (const n of cockpitState.graph.nodes) {
      const p = n.file_path || '';
      const lower = p.toLowerCase();
      if (!(lower.endsWith('.md') || lower.endsWith('.mdx') || n.layer === 'docs')) continue;
      if (!p || seen.has(p)) continue;
      seen.add(p);

      const folder = n.folder || n.cluster_id || 'root';
      const name = p.split('/').pop() || n.name;
      if (q && !p.toLowerCase().includes(q) && !name.toLowerCase().includes(q) && !folder.toLowerCase().includes(q)) {
        continue;
      }
      list.push({
        name,
        path: p,
        folder,
        blake3: Boolean(n.metadata?.blake3_hash),
        lockVerified: Boolean(n.metadata?.lock_verified),
        hasSec: Boolean(n.has_security_violation),
      });
    }

    return list.sort((a, b) => {
      const aReadme = a.name.toLowerCase().includes('readme') ? -1 : 0;
      const bReadme = b.name.toLowerCase().includes('readme') ? -1 : 0;
      if (aReadme !== bReadme) return aReadme - bReadme;
      return a.path.localeCompare(b.path);
    });
  });

  function openDoc(path: string) {
    cockpitState.docSelectedPath = path;
    cockpitState.docMode = 'library';
    cockpitState.isDocPanelOpen = true;
    cockpitState.openFileInIde(path);
  }

  function openTargetContract() {
    cockpitState.docMode = 'symbol';
    cockpitState.isDocPanelOpen = true;
  }
</script>

<div class="w-full h-full flex flex-col bg-[#070a14] select-none overflow-hidden">
  <!-- Search Input Strip -->
  <div class="p-2 border-b border-white/10 shrink-0 bg-[#090d16]">
    <div class="relative">
      <Search class="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2 pointer-events-none" />
      <input
        type="text"
        bind:value={docSearch}
        placeholder="Filtrer docs & contrats EARS..."
        class="w-full pl-7 pr-6 py-1 bg-white/[0.04] border border-white/10 focus:border-emerald-400 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none transition-colors"
      />
      {#if docSearch}
        <button
          type="button"
          onclick={() => (docSearch = '')}
          class="absolute right-2 top-2 text-slate-500 hover:text-white cursor-pointer"
        >
          <X class="w-3 h-3" />
        </button>
      {/if}
    </div>
  </div>

  <div class="flex-1 overflow-y-auto p-2 space-y-3 font-mono text-xs scrollbar-thin">
    <!-- Active Target EARS Contract Card -->
    {#if symbol || activeFile}
      <div class="p-2.5 rounded-lg bg-gradient-to-br from-emerald-950/30 to-[#080d1a] border border-emerald-500/35 space-y-1.5 shadow-sm">
        <div class="flex items-center justify-between gap-1">
          <span class="text-[10px] font-bold text-emerald-300 uppercase tracking-wider flex items-center gap-1">
            <Lock class="w-3 h-3 text-emerald-400" />
            Contrat Cible Active
          </span>
          {#if symbol?.metadata?.blake3_hash}
            <span class="text-[9px] px-1.5 py-0.2 rounded font-bold {symbol.metadata.lock_verified ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'}">
              BLAKE3 {symbol.metadata.lock_verified ? 'Scellé' : 'Modifié'}
            </span>
          {/if}
        </div>

        <div class="truncate text-[11px] font-bold text-white">
          {symbol ? symbol.name : activeFile.split('/').pop()}
        </div>

        <div class="text-[10px] text-slate-400 truncate">
          {symbol?.file_path || activeFile}
        </div>

        <div class="pt-1 flex items-center justify-between gap-2 border-t border-white/10 text-[10px]">
          <span class="text-slate-400">
            Budget : <strong class="text-emerald-300">{symbol?.loc || 0}</strong> / {symbol?.metadata?.max_lines_limit || 300} L
          </span>
          <button
            type="button"
            onclick={openTargetContract}
            class="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/20 hover:bg-emerald-500/35 border border-emerald-500/40 text-emerald-200 text-[10px] font-semibold transition-colors cursor-pointer"
            title="Inspecter le contrat complet et les invariants EARS dans le volet dédié"
          >
            <span>Inspecter</span>
            <ChevronRight class="w-2.5 h-2.5" />
          </button>
        </div>
      </div>
    {/if}

    <!-- Documentation & Markdown Files Section -->
    <div class="space-y-1">
      <div class="px-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
        <span>Documents & Contrats ({docFiles.length})</span>
        <button
          type="button"
          onclick={() => {
            cockpitState.docMode = 'system';
            cockpitState.isDocPanelOpen = true;
          }}
          class="text-[9.5px] text-purple-400 hover:text-purple-300 cursor-pointer flex items-center gap-0.5"
          title="Consulter le System Prompt & Blueprint IA"
        >
          <Sparkles class="w-2.5 h-2.5" />
          <span>Blueprint</span>
        </button>
      </div>

      {#if docFiles.length === 0}
        <div class="p-3 text-center text-slate-500 text-[11px]">
          {#if docSearch}
            Aucun document ne correspond à "{docSearch}"
          {:else}
            Aucun document Markdown (.md) détecté dans le projet
          {/if}
        </div>
      {:else}
        {#each docFiles as doc}
          {@const isActive = activeFile === doc.path.replace(/\\/g, '/')}
          <button
            type="button"
            onclick={() => openDoc(doc.path)}
            class="w-full text-left p-2 rounded border transition-all cursor-pointer flex items-center justify-between gap-2 group
              {isActive ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200 shadow-sm' : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.06] hover:border-white/10'}"
            title="{doc.path} — Cliquez pour ouvrir dans l'éditeur et afficher le contrat"
          >
            <div class="flex items-center gap-2 min-w-0">
              <FileText class="w-3.5 h-3.5 shrink-0 {isActive ? 'text-emerald-400' : 'text-slate-400 group-hover:text-emerald-300'}" />
              <div class="min-w-0">
                <div class="truncate text-[11px] font-medium {isActive ? 'font-bold text-white' : 'text-slate-200'}">
                  {doc.name}
                </div>
                <div class="text-[9.5px] text-slate-500 truncate font-mono">
                  {doc.path}
                </div>
              </div>
            </div>

            <div class="flex items-center gap-1 shrink-0">
              {#if doc.blake3}
                <Lock class="w-3 h-3 {doc.lockVerified ? 'text-emerald-400' : 'text-amber-400'}" title="Contrat BLAKE3" />
              {/if}
              <ChevronRight class="w-3 h-3 text-slate-600 group-hover:text-slate-300 transition-colors" />
            </div>
          </button>
        {/each}
      {/if}
    </div>
  </div>
</div>
