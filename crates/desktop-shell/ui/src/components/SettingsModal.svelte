<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { Settings, ShieldAlert, Cpu, FolderTree, Sparkles, Radar, X, Check, RotateCw } from 'lucide-svelte';

  let exclusionsText = $state(cockpitState.settings.exclusions.join('\n'));
  let cveFilter = $state('');
  let ignoredInput = $state(cockpitState.settings.ignoredCwes.join(', '));
  let isSaving = $state(false);
  let statusMsg = $state<string | null>(null);
  let loadedFromApi = $state(false);

  $effect(() => {
    if (cockpitState.isSettingsModalOpen && !loadedFromApi) {
      loadedFromApi = true;
      api
        .getSettings()
        .then((res) => {
          if (Array.isArray(res.exclusions)) {
            cockpitState.settings.exclusions = res.exclusions;
            exclusionsText = res.exclusions.join('\n');
          }
          if (Array.isArray(res.cve_catalogue)) {
            cockpitState.cveCatalogue = res.cve_catalogue;
          }
          if (Array.isArray(res.active_cve_rules)) {
            cockpitState.settings.activeCveRules = res.active_cve_rules;
          }
          if (Array.isArray(res.ignored_cwes)) {
            cockpitState.settings.ignoredCwes = res.ignored_cwes;
            ignoredInput = res.ignored_cwes.join(', ');
          }
          if (res.mcp_binary_path) {
            cockpitState.settings.mcpBinaryPath = res.mcp_binary_path;
          }
        })
        .catch(() => {
          // keep local defaults when running standalone offline HTML
        });
    }
  });

  const filteredRules = $derived(
    cockpitState.cveCatalogue.filter((r: any) => {
      const q = cveFilter.trim().toLowerCase();
      if (!q) return true;
      return (
        String(r.rule_id || '').toLowerCase().includes(q) ||
        String(r.cve_id || '').toLowerCase().includes(q) ||
        String(r.description || '').toLowerCase().includes(q) ||
        String(r.severity || '').toLowerCase().includes(q)
      );
    })
  );

  const previewName = $derived.by(() => {
    const sample = 'ReservationBookingController';
    const len = cockpitState.settings.maxLabelLength;
    return sample.length > len ? sample.slice(0, len - 2) + '..' : sample;
  });

  function addExclusionPill(pattern: string) {
    const current = exclusionsText
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!current.includes(pattern)) {
      current.push(pattern);
      exclusionsText = current.join('\n');
    }
  }

  function isRuleActive(ruleId: string): boolean {
    if (cockpitState.settings.activeCveRules.length === 0) return true;
    return cockpitState.settings.activeCveRules.includes(ruleId);
  }

  function toggleRule(ruleId: string) {
    if (cockpitState.settings.activeCveRules.length === 0) {
      cockpitState.settings.activeCveRules = cockpitState.cveCatalogue.map((r: any) => r.rule_id);
    }
    if (cockpitState.settings.activeCveRules.includes(ruleId)) {
      cockpitState.settings.activeCveRules = cockpitState.settings.activeCveRules.filter((id) => id !== ruleId);
    } else {
      cockpitState.settings.activeCveRules = [...cockpitState.settings.activeCveRules, ruleId];
    }
  }

  function toggleAllRules(enable: boolean) {
    cockpitState.settings.activeCveRules = enable
      ? cockpitState.cveCatalogue.map((r: any) => r.rule_id)
      : [];
  }

  async function saveAndRescan() {
    isSaving = true;
    statusMsg = null;

    const exclusions = exclusionsText
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const ignoredCwes = ignoredInput
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    cockpitState.settings.exclusions = exclusions;
    cockpitState.settings.ignoredCwes = ignoredCwes;
    cockpitState.saveLocalSettings();

    try {
      const res = await api.saveSettings({
        exclusions,
        active_cve_rules:
          cockpitState.settings.activeCveRules.length > 0 ? cockpitState.settings.activeCveRules : undefined,
        ignored_cwes: ignoredCwes,
      });
      const updated = await api.getGraph();
      cockpitState.setGraph(updated);
      statusMsg = `✅ Enregistré & Rescanné : ${res.total_nodes ?? updated.nodes.length} nœuds, ${res.total_edges ?? updated.edges.length} flux`;
    } catch {
      statusMsg = '💾 Préférences locales enregistrées (mode standalone hors-ligne)';
    } finally {
      isSaving = false;
    }
  }

  function closeModal() {
    cockpitState.isSettingsModalOpen = false;
  }
</script>

{#if cockpitState.isSettingsModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-3xl max-h-[88vh] bg-[#090d16] border border-sky-500/35 rounded-xl shadow-[0_24px_80px_rgba(0,0,0,0.85)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <Settings class="w-5 h-5 text-sky-400" />
          <div>
            <h2 class="text-sm font-bold text-white">Configuration & Préférences AetherScope</h2>
            <p class="text-[11px] text-slate-400">
              Affichage WebGL 2, Exclusions AST, Copilote MCP & Catalogue 120+ Règles CWE Zero-Day
            </p>
          </div>
        </div>
        <button
          onclick={closeModal}
          aria-label="Fermer les paramètres"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Body -->
      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        <!-- 1. Affichage & Labels -->
        <div class="p-4 rounded-xl bg-white/[0.025] border border-white/10 space-y-3">
          <div class="flex items-center gap-2 text-xs font-bold text-sky-300 uppercase tracking-wider">
            <FolderTree class="w-4 h-4" />
            <span>1. Affichage Graphe, Bulles & Labels</span>
          </div>

          <div class="space-y-1.5">
            <div class="flex items-center justify-between text-xs">
              <span class="text-slate-300">Longueur maximale des noms de symboles</span>
              <span class="font-mono font-bold text-sky-400">{cockpitState.settings.maxLabelLength} car.</span>
            </div>
            <input
              type="range"
              min="10"
              max="40"
              step="2"
              bind:value={cockpitState.settings.maxLabelLength}
              class="w-full accent-sky-400 cursor-pointer"
            />
            <div class="text-[11px] font-mono text-slate-400 bg-black/30 px-2.5 py-1.5 rounded border border-white/5">
              Aperçu : <code>ReservationBookingController</code> → <strong class="text-sky-400">{previewName}</strong>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/25 border border-white/5 cursor-pointer">
              <div>
                <div class="text-xs font-semibold text-white">Membranes cellulaires</div>
                <div class="text-[10px] text-slate-400">Contours bicouches des dossiers</div>
              </div>
              <input type="checkbox" bind:checked={cockpitState.settings.showFolderMembranes} class="accent-sky-400 w-4 h-4" />
            </label>

            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/25 border border-white/5 cursor-pointer">
              <div>
                <div class="text-xs font-semibold text-white">Badges dossiers auto</div>
                <div class="text-[10px] text-slate-400">Afficher les pillules au repos</div>
              </div>
              <input type="checkbox" bind:checked={cockpitState.settings.showFolderBadges} class="accent-sky-400 w-4 h-4" />
            </label>

            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/25 border border-white/5 cursor-pointer">
              <div>
                <div class="text-xs font-semibold text-white">Épurer bulles denses</div>
                <div class="text-[10px] text-slate-400">Masquer labels si &gt; {cockpitState.settings.clusterLabelThreshold} nœuds</div>
              </div>
              <input type="checkbox" bind:checked={cockpitState.settings.hideBubbleLabelsOver20} class="accent-sky-400 w-4 h-4" />
            </label>

            <div class="flex items-center justify-between p-2.5 rounded-lg bg-black/25 border border-white/5">
              <span class="text-xs font-semibold text-white">Seuil bulle dense</span>
              <input
                type="number"
                min="5"
                max="100"
                step="5"
                bind:value={cockpitState.settings.clusterLabelThreshold}
                class="w-16 px-2 py-1 rounded bg-slate-900 border border-white/15 text-xs font-mono text-sky-300 text-center"
              />
            </div>
          </div>
        </div>

        <!-- 2. Performance GPU & Lazy Loading -->
        <div class="p-4 rounded-xl bg-white/[0.025] border border-white/10 space-y-3">
          <div class="flex items-center gap-2 text-xs font-bold text-emerald-300 uppercase tracking-wider">
            <Cpu class="w-4 h-4" />
            <span>2. Performance GPU, Mémoire & Audio</span>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/25 border border-white/5 cursor-pointer">
              <span class="text-xs text-slate-200">Lazy-load READMEs</span>
              <input type="checkbox" bind:checked={cockpitState.settings.lazyReadmes} class="accent-emerald-400 w-4 h-4" />
            </label>

            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/25 border border-white/5 cursor-pointer">
              <span class="text-xs text-slate-200">Audio Spatialisé</span>
              <input type="checkbox" bind:checked={cockpitState.settings.soundEnabled} class="accent-emerald-400 w-4 h-4" />
            </label>

            <div class="flex items-center justify-between p-2 rounded-lg bg-black/25 border border-white/5">
              <span class="text-xs text-slate-200">FPS WebGL</span>
              <select
                bind:value={cockpitState.settings.fpsLimit}
                class="bg-slate-900 border border-white/15 rounded px-2 py-1 text-xs text-sky-300 font-mono"
              >
                <option value="60">60 FPS</option>
                <option value="120">120 FPS</option>
                <option value="unlimited">Max</option>
              </select>
            </div>
          </div>
        </div>

        <!-- 3. Exclusions AST -->
        <div class="p-4 rounded-xl bg-white/[0.025] border border-white/10 space-y-2.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-amber-300 uppercase tracking-wider">3. Exclusions Dossiers & Motifs (Scan AST)</span>
            <span class="text-[10px] text-slate-500 font-mono">1 motif par ligne ou virgule</span>
          </div>
          <textarea
            bind:value={exclusionsText}
            rows="3"
            class="w-full rounded-lg bg-black/40 border border-white/15 p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
            placeholder="tests&#10;*.spec.*&#10;dist"
          ></textarea>
          <div class="flex flex-wrap gap-1.5">
            {#each ['tests', '*.spec.*', '*.test.*', 'mocks', 'fixtures', 'dist', 'node_modules', 'target'] as pill}
              <button
                type="button"
                onclick={() => addExclusionPill(pill)}
                class="px-2 py-0.5 rounded bg-white/5 hover:bg-sky-500/20 border border-white/10 text-[10px] font-mono text-slate-300 hover:text-sky-300 cursor-pointer"
              >
                + {pill}
              </button>
            {/each}
          </div>
        </div>

        <!-- 4. Copilote IA & Prompts -->
        <div class="p-4 rounded-xl bg-purple-500/[0.05] border border-purple-500/30 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2 text-xs font-bold text-purple-300 uppercase tracking-wider">
              <Sparkles class="w-4 h-4" />
              <span>4. Copilote IA, Prompts & Pont MCP Zero-Shell</span>
            </div>
            <div class="flex gap-1.5">
              <button
                type="button"
                onclick={() => { closeModal(); cockpitState.openPromptModal('mcp'); }}
                class="px-2.5 py-1 rounded bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-[11px] font-semibold text-purple-200 cursor-pointer"
              >
                🔌 Config MCP
              </button>
              <button
                type="button"
                onclick={() => { closeModal(); cockpitState.openPromptModal('sysprompt'); }}
                class="px-2.5 py-1 rounded bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/40 text-[11px] font-semibold text-sky-200 cursor-pointer"
              >
                📜 Directives Système
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/30 border border-purple-500/20 cursor-pointer">
              <span class="text-xs text-slate-200">Auto-Caméra IA (Focus Live)</span>
              <input type="checkbox" bind:checked={cockpitState.settings.aiAutoCam} class="accent-purple-400 w-4 h-4" />
            </label>
            <label class="flex items-center justify-between p-2.5 rounded-lg bg-black/30 border border-purple-500/20 cursor-pointer">
              <span class="text-xs text-slate-200">Tracé Stellaire & Chemin d'Ariane</span>
              <input type="checkbox" bind:checked={cockpitState.settings.aiTrail} class="accent-purple-400 w-4 h-4" />
            </label>
          </div>

          <div>
            <label for="ai-custom-prompt" class="block text-[11px] font-mono text-purple-300 mb-1">
              INSTRUCTIONS SPÉCIFIQUES COPILOTE (injectées dans le Générateur de Prompt)
            </label>
            <textarea
              id="ai-custom-prompt"
              bind:value={cockpitState.settings.aiCustomPrompt}
              rows="2"
              class="w-full rounded-lg bg-black/40 border border-purple-500/30 p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-400"
              placeholder="Ex: Respect strict de l'architecture hexagonale, aucun I/O dans domain/, tests unitaires complets..."
            ></textarea>
          </div>
        </div>

        <!-- 5. Catalogue SAST 120+ Règles CWE & Ignorées -->
        <div class="p-4 rounded-xl bg-rose-500/[0.04] border border-rose-500/30 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2 text-xs font-bold text-rose-300 uppercase tracking-wider">
              <ShieldAlert class="w-4 h-4" />
              <span>5. Catalogue SAST Zero-Day & CWE ({cockpitState.cveCatalogue.length || '120+'} règles)</span>
            </div>
            <div class="flex gap-1.5">
              <button
                type="button"
                onclick={() => toggleAllRules(true)}
                class="px-2 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-[10px] font-semibold text-sky-300 cursor-pointer"
              >
                Tout Activer
              </button>
              <button
                type="button"
                onclick={() => toggleAllRules(false)}
                class="px-2 py-0.5 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-[10px] font-semibold text-rose-300 cursor-pointer"
              >
                Tout Couper
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input
              type="text"
              bind:value={cveFilter}
              placeholder="Filtrer CWE, règle, sévérité..."
              class="px-3 py-1.5 rounded-lg bg-black/40 border border-white/15 text-xs text-slate-200 focus:outline-none focus:border-rose-400"
            />
            <input
              type="text"
              bind:value={ignoredInput}
              placeholder="CWE / Rule IDs ignorées (ex: CWE-798, RULE_MAX_LINES)"
              class="px-3 py-1.5 rounded-lg bg-black/40 border border-white/15 text-xs font-mono text-slate-200 focus:outline-none focus:border-rose-400"
            />
          </div>

          <div class="max-h-52 overflow-y-auto space-y-1.5 pr-1">
            {#if filteredRules.length === 0}
              <div class="text-xs text-slate-500 text-center py-4 font-mono">
                {cockpitState.cveCatalogue.length === 0
                  ? 'Connectez le serveur Rust local pour charger le catalogue SAST complet.'
                  : 'Aucune règle ne correspond au filtre.'}
              </div>
            {:else}
              {#each filteredRules as rule}
                <label class="flex items-start gap-2.5 p-2 rounded-lg bg-black/30 border border-white/5 hover:border-white/15 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isRuleActive(rule.rule_id)}
                    onchange={() => toggleRule(rule.rule_id)}
                    class="mt-0.5 accent-rose-500"
                  />
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 flex-wrap">
                      <span class="font-mono text-[11px] font-bold text-white">{rule.rule_id}</span>
                      <span class="px-1.5 py-0.2 rounded text-[9px] font-mono bg-rose-500/20 text-rose-300">{rule.cve_id}</span>
                      <span class="text-[9px] font-mono uppercase px-1.5 rounded bg-white/10 text-slate-300">{rule.severity}</span>
                    </div>
                    <p class="text-[11px] text-slate-400 truncate mt-0.5">{rule.description}</p>
                  </div>
                </label>
              {/each}
            {/if}
          </div>
        </div>

        {#if statusMsg}
          <div class="px-3.5 py-2 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-xs text-emerald-200 font-mono">
            {statusMsg}
          </div>
        {/if}
      </div>

      <!-- Footer -->
      <div class="px-5 py-3 bg-[#0f172a] border-t border-white/10 flex items-center justify-between gap-2 shrink-0">
        <button
          type="button"
          onclick={() => { closeModal(); cockpitState.isSurfaceScannerOpen = true; }}
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-xs font-semibold text-emerald-300 cursor-pointer"
        >
          <Radar class="w-3.5 h-3.5" />
          <span>Scanner Domaine / IP...</span>
        </button>

        <div class="flex items-center gap-2">
          <button
            type="button"
            onclick={closeModal}
            class="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs text-slate-300 cursor-pointer"
          >
            Fermer
          </button>
          <button
            type="button"
            disabled={isSaving}
            onclick={saveAndRescan}
            class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-xs font-bold text-slate-950 transition-colors cursor-pointer"
          >
            {#if isSaving}
              <RotateCw class="w-3.5 h-3.5 animate-spin" />
              <span>Re-scan AST...</span>
            {:else}
              <Check class="w-3.5 h-3.5" />
              <span>Enregistrer & Appliquer</span>
            {/if}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
