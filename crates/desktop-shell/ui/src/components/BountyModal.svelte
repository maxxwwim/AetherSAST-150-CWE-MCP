<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { ShieldAlert, X, Copy, Check, Terminal, Radar, Sparkles, Plug, Send } from '@lucide/svelte';
  import type { CveAnomalyRecord } from '../types/graph';

  interface FolderRecommendation {
    folder: string;
    status: string;
    critical_count: number;
    high_count: number;
    total_violations: number;
    entrypoints_count: number;
    score: number;
    reason: string;
  }

  let selectedAnomaly = $state<CveAnomalyRecord | null>(null);
  let filterSeverity = $state<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  let excludedFolders = $state<Record<string, boolean>>({});
  let recommendations = $state<FolderRecommendation[]>([]);
  let scopeModeLabel = $state('ai_recommended');
  let scopeUpdatedBy = $state('AetherScope AI Recommender');
  let scopeRationale = $state('');
  let syncedNotice = $state('');
  let copied = $state(false);
  let sentToMcp = $state(false);

  const projectFolders = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const v of cockpitState.allViolations) {
      const parts = (v.file_path || '').replace(/\\/g, '/').split('/');
      const folder = parts.length > 1 ? parts.slice(0, Math.min(2, parts.length - 1)).join('/') : 'root';
      counts.set(folder, (counts.get(folder) || 0) + 1);
    }
    for (const r of recommendations) {
      if (!counts.has(r.folder)) counts.set(r.folder, r.total_violations);
    }
    return Array.from(counts.entries()).map(([folder, count]) => ({ folder, count }));
  });

  const recByFolder = $derived.by(() => {
    const map = new Map<string, FolderRecommendation>();
    for (const r of recommendations) map.set(r.folder, r);
    return map;
  });

  function folderOf(a: CveAnomalyRecord): string {
    const parts = (a.file_path || '').replace(/\\/g, '/').split('/');
    return parts.length > 1 ? parts.slice(0, Math.min(2, parts.length - 1)).join('/') : 'root';
  }

  async function loadServerScope() {
    try {
      const res = await api.getBountyScope();
      if (res?.recommendations) recommendations = res.recommendations;
      if (res?.scope) {
        scopeModeLabel = res.scope.mode || 'ai_recommended';
        scopeUpdatedBy = res.scope.updated_by || 'Auto';
        scopeRationale = res.scope.rationale || '';
        const next: Record<string, boolean> = {};
        for (const outF of res.scope.out_of_scope || []) {
          next[outF] = true;
        }
        excludedFolders = next;
        cockpitState.bountyOutOfScopePatterns = res.scope.out_of_scope || [];
      }
    } catch {
      // Fallback local
    }
  }

  $effect(() => {
    if (cockpitState.isBountyModalOpen) {
      loadServerScope();
    }
  });

  async function applyAiRecommendedScope() {
    try {
      const res = await api.updateBountyScope({
        action: 'auto_recommend',
        updated_by: 'AetherScope AI Recommender',
      });
      if (res?.recommendations) recommendations = res.recommendations;
      if (res?.scope) {
        scopeModeLabel = res.scope.mode || 'ai_recommended';
        scopeUpdatedBy = res.scope.updated_by || 'AI Recommender';
        scopeRationale = res.scope.rationale || '';
        const next: Record<string, boolean> = {};
        for (const outF of res.scope.out_of_scope || []) next[outF] = true;
        excludedFolders = next;
        cockpitState.bountyOutOfScopePatterns = res.scope.out_of_scope || [];
        syncedNotice = `🤖 Auto-Scope IA appliqué (${res.scope.in_scope?.length || 0} In-Scope · ${res.scope.out_of_scope?.length || 0} Out-Scope)`;
        setTimeout(() => (syncedNotice = ''), 3200);
        return;
      }
    } catch {
      // Fallback local heuristic
    }
    const next: Record<string, boolean> = {};
    for (const { folder } of projectFolders) {
      const rec = recByFolder.get(folder);
      if (rec ? rec.status === 'out_of_scope' : /(test|tests|spec|fixture|mock|bench|docs|target|node_modules)/i.test(folder)) {
        next[folder] = true;
      }
    }
    excludedFolders = next;
  }

  function toggleFolderScope(folder: string) {
    excludedFolders = { ...excludedFolders, [folder]: !excludedFolders[folder] };
  }

  async function syncOutScopeToScanner() {
    const outList = Object.keys(excludedFolders).filter((k) => excludedFolders[k]);
    const inList = projectFolders.map((p) => p.folder).filter((f) => !excludedFolders[f]);
    cockpitState.bountyOutOfScopePatterns = outList;
    try {
      const res = await api.updateBountyScope({
        action: 'set',
        in_scope: inList,
        out_of_scope: outList,
        mode: 'mcp_synced',
        updated_by: 'Cockpit User -> MCP',
        rationale: `Périmètre synchronisé depuis BountyModal (${inList.length} In-Scope, ${outList.length} Out-of-Scope)`,
      });
      if (res?.scope) {
        scopeModeLabel = res.scope.mode;
        scopeUpdatedBy = res.scope.updated_by || 'Cockpit User';
      }
      syncedNotice = `🔌 Synchronisé MCP (.aether/bounty_scope.json) & Surface (${inList.length} In · ${outList.length} Out)`;
    } catch {
      syncedNotice = `${outList.length} dossier(s) exclus synchronisé(s) localement`;
    }
    setTimeout(() => (syncedNotice = ''), 3200);
  }

  const filtered = $derived(
    cockpitState.allViolations.filter((v) => {
      if (filterSeverity !== 'ALL' && v.severity !== filterSeverity) return false;
      if (excludedFolders[folderOf(v)]) return false;
      return true;
    })
  );

  function selectAnomaly(a: CveAnomalyRecord) {
    selectedAnomaly = a;
    copied = false;
    sentToMcp = false;
  }

  function buildMcpBountyPrompt(a: CveAnomalyRecord): string {
    const outList = Object.keys(excludedFolders).filter((k) => excludedFolders[k]);
    const inList = projectFolders.map((p) => p.folder).filter((f) => !excludedFolders[f]);
    const folder = folderOf(a);
    const rec = recByFolder.get(folder);
    return `# 🎯 Bug Bounty PoC & Exploitation Report — ${a.cve_id}

## Target Architecture & Scope MCP:
- File: \`${a.file_path}\` (Dossier: \`${folder}\` — **IN-SCOPE**)
- Line: \`${a.line_number}\`
- Severity: **${a.severity}**
- Title: ${a.title}
- Surface Rationale: ${rec?.reason || 'Module actif In-Scope'}
- Active In-Scope Modules (${inList.length}): ${inList.map((s) => `\`${s}\``).join(', ') || 'All'}
- Excluded Out-of-Scope (${outList.length}): ${outList.map((s) => `\`${s}\``).join(', ') || 'None'}

## Description:
${a.description}

## Remediation Roadmap:
${a.remediation}

## Protocole Agent MCP AetherScope:
1. Vérifier/ajuster le scope PoC : \`aetherscope_search_symbols({"scope_mode": "recommend_scope"})\` ou \`{"scope_mode": "in_scope_only", "cwe_id": "${a.cve_id}"}\`
2. Inspecter le flux d'atteignabilité : \`aetherscope_get_active_target({"symbol_id": "${a.file_path}", "action": "Audit PoC ${a.cve_id}"})\`
3. Rédiger un PoC défensif prouvant l'atteignabilité sans DoS, appliquer le patch EARS, puis certifier avec \`aetherscope_verify_patch\`.`;
  }

  function copyBountyPrompt(a: CveAnomalyRecord) {
    navigator.clipboard.writeText(buildMcpBountyPrompt(a)).then(() => {
      copied = true;
      setTimeout(() => (copied = false), 2000);
    });
  }

  async function sendPocMissionToMcpChat(a?: CveAnomalyRecord | null) {
    const text = a
      ? buildMcpBountyPrompt(a)
      : `🤖 Peux-tu analyser les recommandations In-Scope / Out-of-Scope de ce projet via \`aetherscope_search_symbols({"scope_mode": "recommend_scope"})\`, configurer le périmètre optimal avec \`scope_mode: "configure_scope"\`, et prioriser les PoC sur les CWE critiques In-Scope ?`;
    await api.sendChatMessage(text, 'user', a?.file_path || 'Bug Bounty Scope');
    sentToMcp = true;
    setTimeout(() => (sentToMcp = false), 2500);
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
              Tous ({filtered.length})
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

          <!-- Interactive In-Scope / Out-of-Scope Folder Pills + MCP & AI Recommender -->
          {#if projectFolders.length > 0}
            <div class="p-2 border-b border-white/10 bg-black/20 space-y-1.5">
              <div class="flex items-center justify-between gap-1 text-[9.5px] font-mono text-slate-400">
                <span class="flex items-center gap-1" title="Mode actif : {scopeModeLabel} ({scopeUpdatedBy})">
                  <Plug class="w-2.5 h-2.5 text-sky-400" />
                  SCOPE MCP ({scopeModeLabel === 'mcp_synced' ? 'MCP' : 'IA'})
                </span>
                <div class="flex gap-1">
                  <button
                    type="button"
                    onclick={applyAiRecommendedScope}
                    class="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/30 text-purple-200 cursor-pointer"
                    title="Laisser l'IA / AST configurer automatiquement le In-Scope (surfaces exposées & CWE) et Out-of-Scope (tests/docs)"
                  >
                    <Sparkles class="w-2.5 h-2.5" /> Auto-IA
                  </button>
                  <button
                    type="button"
                    onclick={syncOutScopeToScanner}
                    class="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/30 text-emerald-300 cursor-pointer"
                    title="Synchroniser In-Scope / Out-of-Scope vers MCP (.aether/bounty_scope.json) et Surface Scanner"
                  >
                    <Radar class="w-2.5 h-2.5" /> Sync MCP
                  </button>
                </div>
              </div>
              {#if syncedNotice}
                <div class="text-[9.5px] font-mono text-emerald-300">{syncedNotice}</div>
              {:else if scopeRationale}
                <div class="text-[9px] font-mono text-slate-400 truncate" title={scopeRationale}>
                  💡 {scopeRationale}
                </div>
              {/if}
              <div class="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                {#each projectFolders as item}
                  {@const isOut = Boolean(excludedFolders[item.folder])}
                  {@const rec = recByFolder.get(item.folder)}
                  <button
                    type="button"
                    onclick={() => toggleFolderScope(item.folder)}
                    title="{item.folder} • {rec ? `${rec.status.toUpperCase()} (score ${rec.score}) : ${rec.reason}` : isOut ? 'Out-of-Scope' : 'In-Scope'}"
                    class="px-1.5 py-0.5 rounded text-[9.5px] font-mono border cursor-pointer {isOut ? 'bg-rose-500/15 border-rose-500/35 text-rose-300 line-through' : 'bg-emerald-500/15 border-emerald-500/35 text-emerald-200'}"
                  >
                    {isOut ? '🚫' : '🎯'} {item.folder} ({item.count})
                  </button>
                {/each}
              </div>
              <button
                type="button"
                onclick={() => sendPocMissionToMcpChat(null)}
                class="w-full py-1 px-2 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-200 text-[9.5px] font-mono flex items-center justify-center gap-1 cursor-pointer"
              >
                <Send class="w-2.5 h-2.5" />
                {sentToMcp && !selectedAnomaly ? 'Mission Scope envoyée au Chat MCP !' : 'Demander à l\'Agent MCP de configurer le Scope'}
              </button>
            </div>
          {/if}

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

                <div class="flex items-center gap-1.5 shrink-0">
                  <button
                    onclick={() => selectedAnomaly && sendPocMissionToMcpChat(selectedAnomaly)}
                    class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-purple-600/80 hover:bg-purple-600 border border-purple-400/40 text-white text-xs font-bold transition-all cursor-pointer"
                    title="Envoyer la cible In-Scope et la demande de PoC dans le canal MCP"
                  >
                    <Send class="w-3.5 h-3.5" />
                    <span>{sentToMcp ? 'Envoyé MCP !' : 'Envoyer Agent MCP'}</span>
                  </button>
                  <button
                    onclick={() => selectedAnomaly && copyBountyPrompt(selectedAnomaly)}
                    class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500 hover:bg-rose-600 text-white text-xs font-bold transition-all shadow-lg shadow-rose-500/25 cursor-pointer"
                  >
                    {#if copied}
                      <Check class="w-3.5 h-3.5" />
                      <span>Copié !</span>
                    {:else}
                      <Copy class="w-3.5 h-3.5" />
                      <span>Copier Prompt PoC + MCP</span>
                    {/if}
                  </button>
                </div>
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
