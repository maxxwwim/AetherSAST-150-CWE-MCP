<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { ShieldOff, X, RotateCcw } from 'lucide-svelte';

  async function persistIgnored() {
    try {
      await api.saveSettings({
        exclusions: cockpitState.settings.exclusions,
        active_cve_rules: cockpitState.settings.activeCveRules,
        ignored_cwes: cockpitState.settings.ignoredCwes,
      });
    } catch {
      // keep local state even when backend is static HTML
    }
  }

  async function handleUnignore(rule: string) {
    cockpitState.unignoreCweRule(rule);
    await persistIgnored();
  }

  async function handleRestoreAll() {
    cockpitState.restoreAllCweRules();
    await persistIgnored();
  }

  function closeModal() {
    cockpitState.isIgnoredCweModalOpen = false;
  }
</script>

{#if cockpitState.isIgnoredCweModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-lg bg-[#090d16] border border-amber-500/40 rounded-xl shadow-2xl flex flex-col overflow-hidden text-slate-100">
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <ShieldOff class="w-5 h-5 text-amber-400" />
          <h2 class="text-sm font-bold text-white">Règles & CWE Ignorées</h2>
          <span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px] font-mono font-bold">
            {cockpitState.settings.ignoredCwes.length}
          </span>
        </div>
        <button
          type="button"
          onclick={closeModal}
          aria-label="Fermer CWE ignorées"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <div class="p-4 space-y-2 max-h-80 overflow-y-auto">
        {#if cockpitState.settings.ignoredCwes.length === 0}
          <div class="py-10 text-center text-xs text-slate-500 font-mono">
            Aucune règle CWE ou alerte masquée actuellement.
          </div>
        {:else}
          {#each cockpitState.settings.ignoredCwes as rule}
            <div class="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/10 text-xs font-mono">
              <span class="text-amber-300 font-bold truncate">{rule}</span>
              <button
                type="button"
                onclick={() => handleUnignore(rule)}
                class="flex items-center gap-1 px-2 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 text-[10px] cursor-pointer"
              >
                <RotateCcw class="w-3 h-3" /> Restaurer
              </button>
            </div>
          {/each}
        {/if}
      </div>

      <div class="px-5 py-3 bg-[#0f172a] border-t border-white/10 flex items-center justify-between">
        <button
          type="button"
          disabled={cockpitState.settings.ignoredCwes.length === 0}
          onclick={handleRestoreAll}
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 disabled:opacity-40 border border-amber-500/35 text-xs font-semibold text-amber-200 cursor-pointer"
        >
          <RotateCcw class="w-3.5 h-3.5" /> Tout Restaurer
        </button>
        <button
          type="button"
          onclick={closeModal}
          class="px-4 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-xs text-white cursor-pointer"
        >
          Fermer
        </button>
      </div>
    </div>
  </div>
{/if}
