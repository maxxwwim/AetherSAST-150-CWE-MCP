<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { ShieldAlert, X, Copy, Check, Terminal, ExternalLink } from '@lucide/svelte';
  import type { CveAnomalyRecord } from '../types/graph';

  let selectedAnomaly = $state<CveAnomalyRecord | null>(null);
  let filterSeverity = $state<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  let copied = $state(false);

  const filtered = $derived(
    filterSeverity === 'ALL'
      ? cockpitState.allViolations
      : cockpitState.allViolations.filter((v) => v.severity === filterSeverity)
  );

  function selectAnomaly(a: CveAnomalyRecord) {
    selectedAnomaly = a;
    copied = false;
  }

  function copyBountyPrompt(a: CveAnomalyRecord) {
    const prompt = `# 🎯 Bug Bounty PoC & Exploitation Report — ${a.cve_id}

## Target Architecture:
- File: \`${a.file_path}\`
- Line: \`${a.line_number}\`
- Severity: **${a.severity}**
- Title: ${a.title}

## Description:
${a.description}

## Remediation Roadmap:
${a.remediation}

## Task for AI Auditor:
Rédige un script de preuve de concept (PoC) défensif démontrant l'atteignabilité de cette vulnérabilité sans causer de déni de service, puis fournis un patch minimal conforme aux règles EARS.`;

    navigator.clipboard.writeText(prompt).then(() => {
      copied = true;
      setTimeout(() => (copied = false), 2000);
    });
  }
</script>

{#if cockpitState.isBountyModalOpen}
  <div
    class="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4 select-none"
    onclick={() => (cockpitState.isBountyModalOpen = false)}
    role="presentation"
  >
    <div
      class="w-full max-w-4xl max-h-[85vh] bg-[#0c0f17] border border-rose-500/30 rounded-2xl shadow-2xl overflow-hidden flex flex-col text-slate-100"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cockpitState.isBountyModalOpen = false; }}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <!-- Header -->
      <div class="px-5 py-3.5 border-b border-white/10 flex items-center justify-between bg-rose-950/20">
        <div class="flex items-center gap-2.5">
          <ShieldAlert class="w-5 h-5 text-rose-400" />
          <h2 class="text-sm font-bold tracking-tight text-white">
            Générateur de PoC Bug Bounty & Audit Zero-Day
          </h2>
          <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
            {cockpitState.allViolations.length} Vulnérabilités
          </span>
        </div>
        <button
          onclick={() => (cockpitState.isBountyModalOpen = false)}
          class="p-1 rounded text-slate-400 hover:text-white"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Content Split View -->
      <div class="flex-1 flex overflow-hidden">
        <!-- List Sidebar -->
        <div class="w-80 border-r border-white/10 flex flex-col bg-black/30">
          <!-- Severity Filter Tabs -->
          <div class="flex items-center p-2 gap-1 border-b border-white/10 text-[11px] font-mono">
            <button
              onclick={() => (filterSeverity = 'ALL')}
              class="flex-1 py-1 rounded transition-colors {filterSeverity === 'ALL' ? 'bg-white/10 text-white font-bold' : 'text-slate-400'}"
            >
              Tous ({cockpitState.allViolations.length})
            </button>
            <button
              onclick={() => (filterSeverity = 'CRITICAL')}
              class="flex-1 py-1 rounded transition-colors {filterSeverity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 font-bold' : 'text-slate-400'}"
            >
              Critique ({cockpitState.criticalViolations.length})
            </button>
            <button
              onclick={() => (filterSeverity = 'HIGH')}
              class="flex-1 py-1 rounded transition-colors {filterSeverity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 font-bold' : 'text-slate-400'}"
            >
              Élevé
            </button>
          </div>

          <!-- Anomalies Items -->
          <div class="flex-1 overflow-y-auto p-2 space-y-1">
            {#each filtered as a}
              <button
                onclick={() => selectAnomaly(a)}
                class="w-full text-left p-2 rounded-lg border transition-all cursor-pointer {selectedAnomaly?.cve_id === a.cve_id && selectedAnomaly?.line_number === a.line_number ? 'bg-rose-500/15 border-rose-500/40 text-white' : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.05]'}"
              >
                <div class="flex items-center justify-between text-[10px] font-mono">
                  <span class="font-bold {a.severity === 'CRITICAL' ? 'text-rose-400' : 'text-orange-400'}">{a.cve_id}</span>
                  <span class="text-slate-500">{a.line_number ? `L${a.line_number}` : ''}</span>
                </div>
                <div class="text-xs font-semibold truncate mt-0.5">{a.title}</div>
                <div class="text-[10px] text-slate-500 font-mono truncate">{a.file_path}</div>
              </button>
            {/each}
            {#if filtered.length === 0}
              <div class="py-12 text-center text-xs text-slate-500 font-mono">
                Aucune anomalie détectée
              </div>
            {/if}
          </div>
        </div>

        <!-- Detail Preview -->
        <div class="flex-1 flex flex-col p-4 overflow-y-auto bg-[#0a0d14]">
          {#if selectedAnomaly}
            <div class="flex flex-col gap-4">
              <div class="flex items-start justify-between">
                <div>
                  <span class="text-[10px] font-mono px-2 py-0.5 rounded font-bold {selectedAnomaly.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'}">
                    {selectedAnomaly.severity} · {selectedAnomaly.cwe_class}
                  </span>
                  <h3 class="text-base font-bold text-white mt-1.5">{selectedAnomaly.title}</h3>
                  <p class="text-xs font-mono text-slate-400 mt-0.5">
                    {selectedAnomaly.file_path}:{selectedAnomaly.line_number}
                  </p>
                </div>

                <button
                  onclick={() => selectedAnomaly && copyBountyPrompt(selectedAnomaly)}
                  class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500 hover:bg-rose-600 text-white text-xs font-bold transition-all shadow-lg shadow-rose-500/25 cursor-pointer shrink-0"
                >
                  {#if copied}
                    <Check class="w-3.5 h-3.5" />
                    <span>Copié !</span>
                  {:else}
                    <Copy class="w-3.5 h-3.5" />
                    <span>Copier le Prompt PoC</span>
                  {/if}
                </button>
              </div>

              <!-- Description -->
              <div class="p-3 rounded-lg bg-black/40 border border-white/5 flex flex-col gap-1">
                <span class="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Description de la Faille</span>
                <p class="text-xs text-slate-300 leading-relaxed">{selectedAnomaly.description}</p>
              </div>

              <!-- Remediation -->
              <div class="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/20 flex flex-col gap-1">
                <span class="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">Guide de Remédiation Défensive</span>
                <p class="text-xs text-emerald-200/90 leading-relaxed">{selectedAnomaly.remediation}</p>
              </div>
            </div>
          {:else}
            <div class="h-full flex flex-col items-center justify-center text-center text-slate-500 gap-2">
              <Terminal class="w-8 h-8 text-slate-600" />
              <p class="text-xs font-mono">Sélectionnez une vulnérabilité à gauche pour générer le prompt PoC Bug Bounty.</p>
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
{/if}
