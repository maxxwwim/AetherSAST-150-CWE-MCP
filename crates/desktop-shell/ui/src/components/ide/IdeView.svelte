<script lang="ts">
  import IdeFileTree from './IdeFileTree.svelte';
  import IdeSymbolHierarchy from './IdeSymbolHierarchy.svelte';
  import IdeEditor from './IdeEditor.svelte';
  import { FolderTree, Code2, Columns2 } from '@lucide/svelte';

  let sidebarMode = $state<'files' | 'symbols' | 'split'>('split');
</script>

<div class="w-full h-full flex bg-[#060810] text-slate-100 overflow-hidden relative">
  <!-- Left Sidebar (~320px width) -->
  <aside class="w-80 shrink-0 h-full border-r border-white/10 flex flex-col bg-[#070a14] z-10">
    <!-- Sidebar Navigation Mode Tabs -->
    <div class="h-9 px-2 bg-[#090d16] border-b border-white/10 flex items-center justify-between gap-1 shrink-0 select-none">
      <div class="flex items-center gap-1 bg-white/[0.04] p-0.5 rounded border border-white/10 text-[11px]">
        <button
          type="button"
          onclick={() => (sidebarMode = 'files')}
          class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
            {sidebarMode === 'files' ? 'bg-sky-500/25 text-sky-200 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Afficher l'arborescence des fichiers du projet"
        >
          <FolderTree class="w-3 h-3 text-sky-400" />
          <span>Fichiers</span>
        </button>

        <button
          type="button"
          onclick={() => (sidebarMode = 'symbols')}
          class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
            {sidebarMode === 'symbols' ? 'bg-purple-500/25 text-purple-200 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Afficher la hiérarchie AST du fichier actif"
        >
          <Code2 class="w-3 h-3 text-purple-400" />
          <span>Symboles</span>
        </button>

        <button
          type="button"
          onclick={() => (sidebarMode = 'split')}
          class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
            {sidebarMode === 'split' ? 'bg-emerald-500/25 text-emerald-200 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Vue scindée (Fichiers + Symboles AST)"
        >
          <Columns2 class="w-3 h-3 text-emerald-400" />
          <span>Double</span>
        </button>
      </div>
    </div>

    <!-- Sidebar Body Content -->
    <div class="flex-1 flex flex-col min-h-0 overflow-hidden">
      {#if sidebarMode === 'files'}
        <div class="flex-1 min-h-0 overflow-hidden">
          <IdeFileTree />
        </div>
      {:else if sidebarMode === 'symbols'}
        <div class="flex-1 min-h-0 overflow-hidden">
          <IdeSymbolHierarchy />
        </div>
      {:else}
        <!-- Split View: Top File Tree, Bottom Symbol Hierarchy -->
        <div class="h-1/2 min-h-0 overflow-hidden border-b border-white/10">
          <IdeFileTree />
        </div>
        <div class="h-1/2 min-h-0 overflow-hidden">
          <IdeSymbolHierarchy />
        </div>
      {/if}
    </div>
  </aside>

  <!-- Main Code Editor Pane -->
  <main class="flex-1 h-full min-w-0 flex flex-col overflow-hidden bg-[#060810]">
    <IdeEditor />
  </main>
</div>
