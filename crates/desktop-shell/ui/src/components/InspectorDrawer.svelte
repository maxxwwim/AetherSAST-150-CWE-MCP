<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    X,
    FileCode,
    Activity,
    GitBranch,
    ShieldAlert,
    CheckSquare,
    Copy,
    Wand2,
    ExternalLink
  } from '@lucide/svelte';

  const symbol = $derived(cockpitState.activeSymbol);

  function copyPrompt(type: string) {
    if (!symbol) return;
    let prompt = '';
    if (type === 'refactor') {
      prompt = `Refactorise chirurgicalement le symbole \`${symbol.name}\` dans \`${symbol.file_path}\` en optimisant la complexité cyclomatique (${symbol.cyclomatic_complexity}) tout en respectant les invariants EARS.`;
    } else if (type === 'tests') {
      prompt = `Rédige une suite de tests unitaires exhaustive pour le symbole \`${symbol.name}\` dans \`${symbol.file_path}\`.`;
    } else if (type === 'security') {
      prompt = `Effectue un audit de sécurité SAST approfondi du symbole \`${symbol.name}\` dans \`${symbol.file_path}\` en vérifiant l'absence de failles CWE / Zero-Day.`;
    } else if (type === 'doc') {
      prompt = `Génère la documentation d'architecture technique du symbole \`${symbol.name}\` (${symbol.file_path}).`;
    }
    navigator.clipboard.writeText(prompt);
  }
</script>

{#if cockpitState.isInspectorOpen}
  <aside
    class="absolute top-11 right-0 bottom-7 w-96 max-w-[90vw] bg-[#0c0f17]/95 backdrop-blur-xl border-l border-white/10 flex flex-col z-40 select-none shadow-2xl transition-all"
  >
    <!-- Header -->
    <div class="p-3 border-b border-white/10 flex flex-col gap-2">
      <div class="flex items-center justify-between">
        <span class="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-sky-950/80 text-sky-400 border border-sky-500/30">
          «{symbol?.kind || 'Symbole'}» {symbol?.layer || 'Domain'}
        </span>
        <button
          onclick={() => (cockpitState.isInspectorOpen = false)}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <div>
        <h2 class="text-sm font-semibold text-white tracking-tight truncate">
          {symbol?.name || 'Aucun symbole sélectionné'}
        </h2>
        <p class="text-[11px] font-mono text-slate-400 truncate">
          {symbol?.file_path || 'Sélectionnez un nœud sur la galaxie'}
        </p>
      </div>

      <!-- Quick 1-Click Action Buttons -->
      {#if symbol}
        <div class="flex items-center gap-1 pt-1">
          <button
            onclick={() => copyPrompt('refactor')}
            class="flex-1 py-1 px-1.5 rounded bg-white/[0.04] hover:bg-white/10 text-[10px] text-slate-300 border border-white/10 transition-colors truncate"
          >
            Refactor
          </button>
          <button
            onclick={() => copyPrompt('tests')}
            class="flex-1 py-1 px-1.5 rounded bg-white/[0.04] hover:bg-white/10 text-[10px] text-slate-300 border border-white/10 transition-colors truncate"
          >
            Tests
          </button>
          <button
            onclick={() => copyPrompt('security')}
            class="flex-1 py-1 px-1.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-[10px] text-rose-300 border border-rose-500/30 transition-colors truncate"
          >
            Audit
          </button>
          <button
            onclick={() => copyPrompt('doc')}
            class="flex-1 py-1 px-1.5 rounded bg-white/[0.04] hover:bg-white/10 text-[10px] text-slate-300 border border-white/10 transition-colors truncate"
          >
            Doc
          </button>
        </div>
      {/if}
    </div>

    <!-- Segmented Tabs Navigation -->
    <div class="flex items-center px-2 border-b border-white/10 bg-black/20 text-xs">
      <button
        onclick={() => (cockpitState.activeTab = 'debrief')}
        class="py-2 px-2.5 font-medium border-b-2 transition-colors {cockpitState.activeTab === 'debrief' ? 'border-sky-400 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Débrief
      </button>
      <button
        onclick={() => (cockpitState.activeTab = 'uml')}
        class="py-2 px-2.5 font-medium border-b-2 transition-colors {cockpitState.activeTab === 'uml' ? 'border-sky-400 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        UML
      </button>
      <button
        onclick={() => (cockpitState.activeTab = 'relations')}
        class="py-2 px-2.5 font-medium border-b-2 transition-colors {cockpitState.activeTab === 'relations' ? 'border-sky-400 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Flux
      </button>
      <button
        onclick={() => (cockpitState.activeTab = 'cve')}
        class="py-2 px-2.5 font-medium border-b-2 transition-colors {cockpitState.activeTab === 'cve' ? 'border-rose-400 text-rose-400' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        CVE ({cockpitState.allViolations.length})
      </button>
      <button
        onclick={() => (cockpitState.activeTab = 'tasks')}
        class="py-2 px-2.5 font-medium border-b-2 transition-colors {cockpitState.activeTab === 'tasks' ? 'border-sky-400 text-sky-400' : 'border-transparent text-slate-400 hover:text-slate-200'}"
      >
        Tâches
      </button>
    </div>

    <!-- Content Area -->
    <div class="flex-1 p-3 overflow-y-auto space-y-3 text-xs">
      {#if cockpitState.activeTab === 'debrief'}
        {#if symbol}
          <div class="grid grid-cols-2 gap-2">
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span class="text-[10px] text-slate-400">Lignes de code</span>
              <p class="text-base font-mono font-bold text-white">{symbol.loc} LOC</p>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span class="text-[10px] text-slate-400">Complexité</span>
              <p class="text-base font-mono font-bold {symbol.cyclomatic_complexity > 10 ? 'text-amber-400' : 'text-emerald-400'}">
                {symbol.cyclomatic_complexity}
              </p>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span class="text-[10px] text-slate-400">Appelants (In)</span>
              <p class="text-base font-mono font-bold text-sky-400">{symbol.in_degree}</p>
            </div>
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span class="text-[10px] text-slate-400">Dépendances (Out)</span>
              <p class="text-base font-mono font-bold text-indigo-400">{symbol.out_degree}</p>
            </div>
          </div>

          {#if symbol.docstring}
            <div class="p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
              <span class="text-[10px] text-slate-400 font-medium">Docstring & Contrat</span>
              <p class="mt-1 text-[11px] text-slate-300 leading-relaxed font-mono whitespace-pre-wrap">
                {symbol.docstring}
              </p>
            </div>
          {/if}
        {:else}
          <p class="text-slate-500 text-center py-8">Aucun symbole sélectionné</p>
        {/if}

      {:else}
        {#if cockpitState.activeTab === 'cve'}
          <div class="space-y-2">
            {#each cockpitState.allViolations as cve}
              <div class="p-2.5 rounded-lg bg-white/[0.03] border-l-2 border-white/10 {cve.severity === 'CRITICAL' ? 'border-l-rose-500 bg-rose-950/10' : 'border-l-amber-500 bg-amber-950/10'}">
                <div class="flex items-center justify-between gap-1 mb-1">
                  <span class="font-mono font-bold text-[10px] {cve.severity === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'}">
                    [{cve.severity}] {cve.cve_id}
                  </span>
                  <span class="text-[9px] text-slate-400 font-mono">L.{cve.line_number}</span>
                </div>
                <p class="text-[11px] text-slate-200 font-medium leading-snug">{cve.title}</p>
                <p class="mt-1 text-[10px] text-slate-400 leading-relaxed">{cve.description}</p>
                {#if cve.remediation}
                  <div class="mt-2 p-1.5 rounded bg-black/40 border border-white/5 text-[10px] font-mono text-emerald-400">
                    Fix: {cve.remediation}
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <p class="text-slate-500 text-center py-8">Section {cockpitState.activeTab} en cours d'affichage.</p>
        {/if}
      {/if}
    </div>
  </aside>
{/if}
