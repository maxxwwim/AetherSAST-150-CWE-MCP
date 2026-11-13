<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { FolderGit2, RefreshCw, Download, X, Layers } from 'lucide-svelte';

  let projectPath = $state(cockpitState.graph.project_path || '.');
  let isBusy = $state(false);
  let feedback = $state<string | null>(null);

  async function rescanProject() {
    isBusy = true;
    feedback = null;
    try {
      const g = await api.analyzeProject(projectPath.trim() || '.', cockpitState.settings.exclusions);
      cockpitState.setGraph(g);
      cockpitState.requestCameraFit();
      feedback = `✅ Rescan terminé : ${g.nodes.length} nœuds · ${g.edges.length} flux`;
    } catch {
      feedback = '❌ Impossible de contacter POST /api/analyze.';
    } finally {
      isBusy = false;
    }
  }

  async function exportStandalone() {
    isBusy = true;
    feedback = null;
    try {
      const res = await api.exportHtml(projectPath.trim() || undefined);
      feedback = `💾 Exporté vers ${res.viewer_path}`;
    } catch {
      feedback = '❌ Échec de export HTML (/api/export).';
    } finally {
      isBusy = false;
    }
  }

  async function switchMode(mode: 'code' | 'vault') {
    cockpitState.viewMode = mode;
    try {
      await api.switchViewMode(mode);
      const g = await api.getGraph();
      cockpitState.setGraph(g);
      cockpitState.requestCameraFit();
      feedback = `🔄 Mode ${mode === 'code' ? 'Code Source' : 'Obsidian Vault'} activé`;
    } catch {
      feedback = `⚠️ Bascule locale en mode ${mode}`;
    }
  }
</script>

{#if cockpitState.isHubModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && (cockpitState.isHubModalOpen = false)}
    onkeydown={(e) => e.key === 'Escape' && (cockpitState.isHubModalOpen = false)}
  >
    <div class="w-full max-w-xl bg-[#090d16] border border-sky-500/35 rounded-xl shadow-[0_24px_80px_rgba(0,0,0,0.85)] overflow-hidden">
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <FolderGit2 class="w-5 h-5 text-sky-400" />
          <div>
            <h2 class="text-sm font-bold text-white">Hub Projet & Workspace</h2>
            <p class="text-[11px] text-slate-400">Re-scanner un dépôt, basculer Code ↔ Vault, ou exporter un viewer HTML</p>
          </div>
        </div>
        <button
          onclick={() => (cockpitState.isHubModalOpen = false)}
          aria-label="Fermer le hub projet"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <div class="p-5 space-y-4">
        <div class="space-y-1.5">
          <label for="hub-project-path" class="text-xs font-semibold text-slate-300">Chemin du Projet / Workspace</label>
          <div class="flex gap-2">
            <input
              id="hub-project-path"
              type="text"
              bind:value={projectPath}
              class="flex-1 px-3 py-2 rounded-lg bg-black/45 border border-white/15 text-xs font-mono text-white focus:outline-none focus:border-sky-400"
            />
            <button
              type="button"
              disabled={isBusy}
              onclick={rescanProject}
              class="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
            >
              <RefreshCw class="w-3.5 h-3.5 {isBusy ? 'animate-spin' : ''}" />
              <span>Analyser</span>
            </button>
          </div>
        </div>

        <div class="p-3.5 rounded-xl bg-white/[0.025] border border-white/10 space-y-2">
          <div class="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
            <Layers class="w-3.5 h-3.5 text-sky-400" />
            <span>Mode de Graphe Dual-Vision</span>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <button
              type="button"
              onclick={() => switchMode('code')}
              class="py-2 rounded-lg border text-xs font-semibold cursor-pointer {cockpitState.viewMode === 'code' ? 'bg-sky-500/20 border-sky-400 text-sky-200' : 'bg-black/30 border-white/10 text-slate-400 hover:text-white'}"
            >
              💻 Code Source & AST
            </button>
            <button
              type="button"
              onclick={() => switchMode('vault')}
              class="py-2 rounded-lg border text-xs font-semibold cursor-pointer {cockpitState.viewMode === 'vault' ? 'bg-emerald-500/20 border-emerald-400 text-emerald-200' : 'bg-black/30 border-white/10 text-slate-400 hover:text-white'}"
            >
              🧠 Obsidian Vault & Notes
            </button>
          </div>
        </div>

        <button
          type="button"
          disabled={isBusy}
          onclick={exportStandalone}
          class="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-semibold text-slate-200 cursor-pointer"
        >
          <Download class="w-4 h-4 text-amber-400" />
          <span>Exporter aetherscope_viewer.html Autonome</span>
        </button>

        {#if feedback}
          <div class="px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-xs font-mono text-sky-200">
            {feedback}
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}
