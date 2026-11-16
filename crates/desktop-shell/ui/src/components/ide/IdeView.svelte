<script lang="ts">
  import IdeFileTree from './IdeFileTree.svelte';
  import IdeSymbolHierarchy from './IdeSymbolHierarchy.svelte';
  import IdeDocSidebar from './IdeDocSidebar.svelte';
  import IdeEditor from './IdeEditor.svelte';
  import DocReaderDrawer from '../DocReaderDrawer.svelte';
  import { cockpitState } from '../../state/graphState.svelte';
  import {
    FolderTree,
    Code2,
    BookOpen,
    Columns2,
    ChevronLeft,
    ChevronRight,
    PanelLeftOpen,
    Maximize2,
    Minimize2
  } from '@lucide/svelte';

  let sidebarMode = $state<'files' | 'symbols' | 'docs' | 'split'>('split');
  let ideDocWide = $state(false);

  // Left Sidebar adjustable width & minimizable state
  let sidebarWidth = $state(320);
  let sidebarCollapsed = $state(false);
  let isResizingSidebar = $state(false);

  // Double View (Split) vertical adjustable ratio
  let splitRatio = $state(50);
  let isResizingSplit = $state(false);
  let splitContainerEl = $state<HTMLElement | null>(null);

  // Right Doc Pane adjustable width
  let docPaneWidth = $state(520);
  let isResizingDoc = $state(false);

  function startSidebarResize(e: PointerEvent) {
    e.preventDefault();
    isResizingSidebar = true;
    const startX = e.clientX;
    const startW = sidebarWidth;

    function onPointerMove(ev: PointerEvent) {
      const delta = ev.clientX - startX;
      sidebarWidth = Math.max(180, Math.min(Math.floor(window.innerWidth * 0.45), startW + delta));
    }

    function onPointerUp() {
      isResizingSidebar = false;
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    }

    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  }

  function startSplitResize(e: PointerEvent) {
    e.preventDefault();
    if (!splitContainerEl) return;
    isResizingSplit = true;
    const rect = splitContainerEl.getBoundingClientRect();

    function onPointerMove(ev: PointerEvent) {
      const relY = ev.clientY - rect.top;
      const pct = Math.round((relY / rect.height) * 100);
      splitRatio = Math.max(15, Math.min(85, pct));
    }

    function onPointerUp() {
      isResizingSplit = false;
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    }

    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  }

  function startDocPaneResize(e: PointerEvent) {
    e.preventDefault();
    isResizingDoc = true;
    const startX = e.clientX;
    const startW = ideDocWide ? 720 : docPaneWidth;

    function onPointerMove(ev: PointerEvent) {
      const delta = startX - ev.clientX;
      docPaneWidth = Math.max(320, Math.min(Math.floor(window.innerWidth * 0.6), startW + delta));
      if (ideDocWide && docPaneWidth < 680) {
        ideDocWide = false;
      }
    }

    function onPointerUp() {
      isResizingDoc = false;
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    }

    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  }
</script>

<div class="w-full h-full flex bg-[#060810] text-slate-100 overflow-hidden relative">
  <!-- Left Sidebar (Adjustable width from 180px to 45% of screen, or minimizable) -->
  <aside
    style="width: {cockpitState.ideZenMode ? 0 : sidebarCollapsed ? 42 : sidebarWidth}px;"
    class="w-80 shrink-0 h-full border-r border-white/10 flex flex-col bg-[#070a14] z-10 transition-[width] duration-75 relative select-none {cockpitState.ideZenMode ? 'hidden' : ''}"
  >
    {#if sidebarCollapsed}
      <!-- Slim Minimized Rail (42px) -->
      <div class="w-full h-full flex flex-col items-center py-2 bg-[#080c16] justify-between">
        <div class="flex flex-col items-center gap-2">
          <button
            type="button"
            onclick={() => (sidebarCollapsed = false)}
            class="p-1.5 rounded hover:bg-white/10 text-sky-400 transition-colors cursor-pointer"
            title="Déplier la barre latérale"
          >
            <ChevronRight class="w-4 h-4" />
          </button>

          <div class="w-5 h-px bg-white/10 my-0.5"></div>

          <button
            type="button"
            onclick={() => { sidebarMode = 'files'; sidebarCollapsed = false; }}
            class="p-1.5 rounded transition-colors cursor-pointer {sidebarMode === 'files' ? 'bg-sky-500/25 text-sky-300' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
            title="Fichiers (déplier)"
          >
            <FolderTree class="w-4 h-4" />
          </button>

          <button
            type="button"
            onclick={() => { sidebarMode = 'symbols'; sidebarCollapsed = false; }}
            class="p-1.5 rounded transition-colors cursor-pointer {sidebarMode === 'symbols' ? 'bg-purple-500/25 text-purple-300' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
            title="Symboles AST (déplier)"
          >
            <Code2 class="w-4 h-4" />
          </button>

          <button
            type="button"
            onclick={() => { sidebarMode = 'docs'; sidebarCollapsed = false; }}
            class="p-1.5 rounded transition-colors cursor-pointer {sidebarMode === 'docs' ? 'bg-emerald-500/25 text-emerald-300' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
            title="Docs & EARS (déplier)"
          >
            <BookOpen class="w-4 h-4" />
          </button>

          <button
            type="button"
            onclick={() => { sidebarMode = 'split'; sidebarCollapsed = false; }}
            class="p-1.5 rounded transition-colors cursor-pointer {sidebarMode === 'split' ? 'bg-sky-500/25 text-sky-300' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
            title="Vue double (déplier)"
          >
            <Columns2 class="w-4 h-4" />
          </button>
        </div>

        <button
          type="button"
          onclick={() => (sidebarCollapsed = false)}
          class="p-1.5 rounded text-slate-500 hover:text-white cursor-pointer"
          title="Agrandir la barre latérale"
        >
          <PanelLeftOpen class="w-4 h-4" />
        </button>
      </div>
    {:else}
      <!-- Expanded Full Sidebar -->
      <div class="h-9 px-2 bg-[#090d16] border-b border-white/10 flex items-center justify-between gap-1 shrink-0 select-none">
        <div class="flex items-center gap-1 bg-white/[0.04] p-0.5 rounded border border-white/10 text-[11px] overflow-x-auto scrollbar-none">
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
            onclick={() => (sidebarMode = 'docs')}
            class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
              {sidebarMode === 'docs' ? 'bg-emerald-500/25 text-emerald-200 font-semibold' : 'text-slate-400 hover:text-white'}"
            title="Afficher la bibliothèque Docs & Contrats EARS"
          >
            <BookOpen class="w-3 h-3 text-emerald-400" />
            <span>Docs & EARS</span>
          </button>

          <button
            type="button"
            onclick={() => (sidebarMode = 'split')}
            class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
              {sidebarMode === 'split' ? 'bg-sky-500/25 text-sky-200 font-semibold' : 'text-slate-400 hover:text-white'}"
            title="Vue scindée (Fichiers + Symboles AST)"
          >
            <Columns2 class="w-3 h-3 text-slate-300" />
            <span>Double</span>
          </button>
        </div>

        <!-- Minimize Sidebar Button -->
        <button
          type="button"
          onclick={() => (sidebarCollapsed = true)}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer shrink-0 transition-colors"
          title="Minimiser la barre latérale"
        >
          <ChevronLeft class="w-3.5 h-3.5" />
        </button>
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
        {:else if sidebarMode === 'docs'}
          <div class="flex-1 min-h-0 overflow-hidden">
            <IdeDocSidebar />
          </div>
        {:else}
          <!-- Split View with Horizontal Draggable Resizer -->
          <div bind:this={splitContainerEl} class="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div style="height: {splitRatio}%;" class="min-h-[40px] overflow-hidden flex flex-col">
              <IdeFileTree />
            </div>

            <!-- Horizontal Split Resizer -->
            <div
              role="separator"
              tabindex="-1"
              aria-orientation="horizontal"
              onpointerdown={startSplitResize}
              ondblclick={() => (splitRatio = 50)}
              class="h-1.5 hover:h-2 -my-0.5 z-20 cursor-row-resize hover:bg-sky-500/60 active:bg-sky-400 transition-colors select-none shrink-0 border-y border-white/10 flex items-center justify-center group"
              title="Glisser pour ajuster la hauteur (double-clic pour 50/50)"
            >
              <div class="w-8 h-0.5 bg-white/20 group-hover:bg-sky-300 rounded-full transition-colors"></div>
            </div>

            <div style="height: {100 - splitRatio}%;" class="min-h-[40px] overflow-hidden flex flex-col">
              <IdeSymbolHierarchy />
            </div>
          </div>
        {/if}
      </div>
    {/if}
  </aside>

  <!-- Left Sidebar Drag Resizer -->
  {#if !sidebarCollapsed && !cockpitState.ideZenMode}
    <div
      role="separator"
      tabindex="-1"
      aria-orientation="vertical"
      aria-valuenow={sidebarWidth}
      onpointerdown={startSidebarResize}
      ondblclick={() => (sidebarWidth = 320)}
      class="w-1.5 hover:w-2 -mr-1 z-20 cursor-col-resize hover:bg-sky-500/60 active:bg-sky-400 transition-colors select-none shrink-0 {isResizingSidebar ? 'bg-sky-500 w-2' : ''}"
      title="Glisser pour ajuster la largeur de la barre latérale (double-clic pour 320px)"
    ></div>
  {/if}

  <!-- Main Code Editor Pane (Flex-1) -->
  <main class="flex-1 h-full min-w-0 flex flex-col overflow-hidden bg-[#060810]">
    <IdeEditor />
  </main>

  <!-- Right Doc Pane Drag Resizer & Container -->
  {#if cockpitState.isDocPanelOpen && !cockpitState.ideZenMode}
    <!-- Resizer Divider Handle -->
    <div
      role="separator"
      tabindex="-1"
      aria-orientation="vertical"
      aria-valuenow={docPaneWidth}
      onpointerdown={startDocPaneResize}
      ondblclick={() => { docPaneWidth = 520; ideDocWide = false; }}
      class="w-1.5 hover:w-2 -ml-1 z-20 cursor-col-resize hover:bg-emerald-500/60 active:bg-emerald-400 transition-colors select-none shrink-0 {isResizingDoc ? 'bg-emerald-500 w-2' : ''}"
      title="Glisser pour ajuster la largeur du volet Docs & EARS (double-clic pour 520px)"
    ></div>

    <!-- Integrated Docked Doc, EARS & Source Panel (Adjustable width) -->
    <div
      style="width: {ideDocWide ? 760 : docPaneWidth}px;"
      class="shrink-0 h-full border-l border-white/10 flex flex-col bg-[#070b14] z-10 overflow-hidden max-w-[60vw] transition-[width] duration-75"
    >
      <DocReaderDrawer embedded={true} bind:wideMode={ideDocWide} />
    </div>
  {/if}
</div>
