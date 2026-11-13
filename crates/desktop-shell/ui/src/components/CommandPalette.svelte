<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { Search, X, Code2, ShieldAlert, Layers } from '@lucide/svelte';

  let query = $state('');

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      cockpitState.isCommandPaletteOpen = false;
    }
  }

  function selectNode(id: string) {
    cockpitState.selectSymbol(id);
    cockpitState.isCommandPaletteOpen = false;
  }

  const results = $derived(
    query.trim() === ''
      ? cockpitState.graph.nodes.slice(0, 15)
      : cockpitState.graph.nodes
          .filter(
            (n) =>
              n.name.toLowerCase().includes(query.toLowerCase()) ||
              n.file_path.toLowerCase().includes(query.toLowerCase())
          )
          .slice(0, 20)
  );
</script>

<svelte:window onkeydown={(e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    cockpitState.isCommandPaletteOpen = !cockpitState.isCommandPaletteOpen;
  }
}} />

{#if cockpitState.isCommandPaletteOpen}
  <div
    class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-start justify-center pt-24 p-4 select-none"
    onclick={() => (cockpitState.isCommandPaletteOpen = false)}
    role="presentation"
  >
    <div
      class="w-full max-w-lg bg-[#0d1117] border border-white/10 rounded-xl shadow-2xl overflow-hidden flex flex-col"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cockpitState.isCommandPaletteOpen = false; }}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <!-- Search Input -->
      <div class="flex items-center px-3 py-2.5 border-b border-white/10 gap-2.5">
        <Search class="w-4 h-4 text-slate-400" />
        <input
          type="text"
          bind:value={query}
          placeholder="Rechercher un symbole, fonction, fichier..."
          class="flex-1 bg-transparent border-none outline-none text-xs text-white placeholder-slate-500 font-mono"
          autofocus
        />
        <button
          onclick={() => (cockpitState.isCommandPaletteOpen = false)}
          class="p-1 rounded text-slate-400 hover:text-white"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Results List -->
      <div class="max-h-80 overflow-y-auto p-1.5 space-y-0.5">
        {#each results as node}
          <button
            onclick={() => selectNode(node.id)}
            class="w-full flex items-center justify-between p-2 rounded-lg hover:bg-white/[0.06] text-left transition-colors group cursor-pointer"
          >
            <div class="flex items-center gap-2 truncate">
              <Code2 class="w-3.5 h-3.5 text-sky-400 group-hover:text-sky-300 shrink-0" />
              <div class="truncate">
                <span class="text-xs font-medium text-slate-200 group-hover:text-white truncate">
                  {node.name}
                </span>
                <span class="block text-[10px] text-slate-500 font-mono truncate">
                  {node.file_path}
                </span>
              </div>
            </div>
            <span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400 shrink-0">
              {node.kind}
            </span>
          </button>
        {/each}
        {#if results.length === 0}
          <div class="py-8 text-center text-xs text-slate-500">
            Aucun résultat pour "{query}"
          </div>
        {/if}
      </div>

      <!-- Footer Help -->
      <div class="px-3 py-1.5 border-t border-white/5 bg-black/30 flex items-center justify-between text-[10px] text-slate-500 font-mono">
        <span>Navigation : ↑ ↓</span>
        <span>Sélection : ↵</span>
        <span>Fermer : Esc</span>
      </div>
    </div>
  </div>
{/if}
