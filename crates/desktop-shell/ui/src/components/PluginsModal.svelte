<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    api,
    type PluginEntryInfo,
    type PluginsInventoryResponse,
    type PluginTestReportResponse,
  } from '../lib/api';
  import {
    Plug,
    X,
    Play,
    PackagePlus,
    Upload,
    Plus,
    Trash2,
    RefreshCw,
    ChevronDown,
    ChevronRight,
    CheckCircle2,
    AlertTriangle,
    Search,
    Sparkles,
    ShieldAlert,
  } from '@lucide/svelte';

  let activeTab = $state<'plugins' | 'semgrep' | 'create'>('plugins');
  let inventory = $state<PluginsInventoryResponse | null>(null);
  let isLoading = $state(false);
  let busyAction = $state<string | null>(null);
  let searchQuery = $state('');
  let expandedPaths = $state<Record<string, boolean>>({});
  let confirmDeletePath = $state<string | null>(null);

  let statusMsg = $state<{ kind: 'ok' | 'err'; text: string } | null>(null);
  let testReport = $state<PluginTestReportResponse | null>(null);

  // Semgrep Importer state
  let semgrepName = $state('custom-semgrep-pack');
  let semgrepYaml = $state('');

  // DSL v2 Rule Creator state
  let rulePluginName = $state('custom-security-pack');
  let ruleProfile = $state('');
  let ruleTags = $state('');
  let ruleId = $state('CUSTOM-RULE-001');
  let ruleCweId = $state('CWE-287 / AUTH-BYPASS');
  let ruleName = $state('Vérification garde d’authentification');
  let ruleSeverity = $state<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'WARNING'>('HIGH');
  let ruleExtensions = $state('.rs, .ts, .py');
  let ruleMatchMode = $state<'line_by_line' | 'whole_file'>('line_by_line');
  let ruleDescription = $state('Fonction sensible sans garde de sécurité détecté.');
  let ruleRemediation = $state('Appliquer un middleware ou contrôle d’autorisation explicite.');
  let ruleRegexPatterns = $state('fn\\s+admin_\\w+\\s*\\(');
  let ruleMustContain = $state('');
  let ruleMustNotContain = $state('is_authenticated, verify_token');
  let ruleCheckLiterals = $state(false);
  let ruleAstScope = $state('');
  let ruleWindowLines = $state<number>(0);
  let ruleWindowPatterns = $state('');
  let ruleInPaths = $state('');
  let ruleNotInPaths = $state('');
  let testVulnFile = $state('src/admin.rs');
  let testVulnCode = $state('pub fn admin_delete() { db.wipe(); }');
  let testSafeCode = $state('pub fn admin_delete() { if is_authenticated() { db.wipe(); } }');
  let includeTests = $state(true);

  const SAMPLE_SEMGREP = `rules:
  - id: custom-no-eval-exec
    languages: [javascript, typescript, python]
    severity: ERROR
    message: "Évitez l'évaluation dynamique de code via eval() (CWE-94)."
    metadata:
      cwe: "CWE-94: Improper Control of Generation of Code"
      category: security
    pattern-either:
      - pattern: "eval($CODE)"
      - pattern: "new Function($CODE)"
`;

  function splitList(raw: string): string[] {
    return raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function splitLines(raw: string): string[] {
    return raw
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function refreshInventory() {
    isLoading = true;
    statusMsg = null;
    try {
      inventory = await api.getPlugins();
    } catch (e: any) {
      inventory = null;
      statusMsg = {
        kind: 'err',
        text: e?.message || 'Serveur Rust local non connecté (gestion plugins disponible en mode live).',
      };
    } finally {
      isLoading = false;
    }
  }

  async function refreshLiveGraph() {
    try {
      const updated = await api.getGraph();
      if (updated && Array.isArray(updated.nodes)) {
        cockpitState.setGraph(updated);
        cockpitState.filterVersion += 1;
      }
    } catch {
      // ignore if offline
    }
  }

  $effect(() => {
    if (cockpitState.isPluginsModalOpen) {
      refreshInventory();
    }
  });

  const filteredPlugins = $derived.by((): PluginEntryInfo[] => {
    const list = inventory?.plugins ?? [];
    const q = searchQuery.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.rel_path.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q) ||
        (p.profile || '').toLowerCase().includes(q) ||
        p.tags.some((t) => t.toLowerCase().includes(q)) ||
        p.rules.some(
          (r) =>
            r.id.toLowerCase().includes(q) ||
            r.cwe_id.toLowerCase().includes(q) ||
            r.name.toLowerCase().includes(q)
        )
    );
  });

  function toggleExpand(relPath: string) {
    expandedPaths = { ...expandedPaths, [relPath]: !expandedPaths[relPath] };
  }

  async function handleTogglePlugin(plugin: PluginEntryInfo) {
    busyAction = `toggle:${plugin.rel_path}`;
    statusMsg = null;
    try {
      const res = await api.togglePlugin(plugin.rel_path, !plugin.enabled);
      if (res?.inventory) inventory = res.inventory;
      await refreshLiveGraph();
      statusMsg = {
        kind: 'ok',
        text: `Plugin "${plugin.name}" ${!plugin.enabled ? 'activé' : 'désactivé'} — graphe rescanné (${res.total_nodes ?? 0} nœuds).`,
      };
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Impossible de basculer le plugin.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleRunTests(relPath?: string) {
    busyAction = relPath ? `test:${relPath}` : 'test:all';
    statusMsg = null;
    try {
      const rep = await api.testPlugins(relPath);
      testReport = rep;
      statusMsg = {
        kind: rep.failed === 0 ? 'ok' : 'err',
        text:
          rep.total_tests === 0
            ? 'Aucun cas de test unitaire défini dans la sélection.'
            : rep.failed === 0
              ? `Tests validés : ${rep.passed}/${rep.total_tests} passés (0 échec).`
              : `${rep.failed}/${rep.total_tests} test(s) en échec.`,
      };
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur lors de l’exécution des tests.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleInitBundle() {
    busyAction = 'init-bundle';
    statusMsg = null;
    try {
      const res = await api.initCommunityPluginBundle();
      if (res?.inventory) inventory = res.inventory;
      await refreshLiveGraph();
      statusMsg = {
        kind: 'ok',
        text: `Bundle communautaire OWASP/CWE déployé (${inventory?.community_bundle_rules_count ?? 24} règles) et graphe rescanné.`,
      };
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur déploiement bundle communautaire.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleImportSemgrep() {
    if (!semgrepName.trim() || !semgrepYaml.trim()) {
      statusMsg = { kind: 'err', text: 'Renseignez un nom de plugin et un YAML Semgrep.' };
      return;
    }
    busyAction = 'import-semgrep';
    statusMsg = null;
    try {
      const res = await api.importSemgrepPlugin(semgrepName.trim(), semgrepYaml);
      if (res?.inventory) inventory = res.inventory;
      await refreshLiveGraph();
      statusMsg = {
        kind: 'ok',
        text: `Plugin Semgrep "${res.plugin}" importé (${res.rules_imported} règle(s)) et activé.`,
      };
      activeTab = 'plugins';
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur import Semgrep.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleCreateRule() {
    const exts = splitList(ruleExtensions);
    if (!rulePluginName.trim() || !ruleId.trim() || !ruleCweId.trim() || exts.length === 0) {
      statusMsg = {
        kind: 'err',
        text: 'Nom du plugin, ID de règle, CWE et extensions de fichiers sont requis.',
      };
      return;
    }

    const winPatterns = splitLines(ruleWindowPatterns);
    const windowCond =
      ruleWindowLines > 0 && winPatterns.length > 0
        ? { lines: Math.floor(ruleWindowLines), patterns: winPatterns }
        : null;

    const testCases =
      includeTests && testVulnFile.trim() && testVulnCode.trim()
        ? [
            {
              name: 'Cas vulnérable (doit déclencher)',
              file_name: testVulnFile.trim(),
              code: testVulnCode,
              should_trigger: true,
            },
            ...(testSafeCode.trim()
              ? [
                  {
                    name: 'Cas sécurisé (ne doit pas déclencher)',
                    file_name: testVulnFile.trim(),
                    code: testSafeCode,
                    should_trigger: false,
                  },
                ]
              : []),
          ]
        : [];

    busyAction = 'upsert-rule';
    statusMsg = null;
    try {
      const res = await api.upsertPluginRule({
        plugin_name: rulePluginName.trim(),
        profile: ruleProfile.trim() || undefined,
        tags: splitList(ruleTags),
        rule_id: ruleId.trim(),
        cwe_id: ruleCweId.trim(),
        name: ruleName.trim() || ruleId.trim(),
        severity: ruleSeverity,
        description: ruleDescription.trim(),
        remediation: ruleRemediation.trim(),
        file_extensions: exts,
        match_mode: ruleMatchMode,
        regex_patterns: splitLines(ruleRegexPatterns),
        must_contain: splitList(ruleMustContain),
        must_not_contain: splitList(ruleMustNotContain),
        check_literals: ruleCheckLiterals,
        not_preceded_within_lines: windowCond,
        in_path_matching: splitList(ruleInPaths),
        not_in_path_matching: splitList(ruleNotInPaths),
        ast_scope: ruleAstScope.trim() || null,
        test_cases: testCases,
      });
      if (res?.inventory) inventory = res.inventory;
      await refreshLiveGraph();
      statusMsg = {
        kind: 'ok',
        text: `Règle "${res.rule_id}" certifiée (${res.tests_passed ?? 0} test(s) OK) dans "${res.plugin}".`,
      };
      activeTab = 'plugins';
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Erreur lors de la création de la règle.' };
    } finally {
      busyAction = null;
    }
  }

  async function handleDeletePlugin(relPath: string) {
    busyAction = `delete:${relPath}`;
    statusMsg = null;
    try {
      const res = await api.deletePlugin(relPath);
      if (res?.inventory) inventory = res.inventory;
      confirmDeletePath = null;
      await refreshLiveGraph();
      statusMsg = { kind: 'ok', text: `Plugin "${relPath}" supprimé et graphe rescanné.` };
    } catch (e: any) {
      statusMsg = { kind: 'err', text: e?.message || 'Impossible de supprimer ce plugin.' };
    } finally {
      busyAction = null;
    }
  }

  function severityClass(sev: string): string {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      default:
        return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
    }
  }

  function closeModal() {
    cockpitState.isPluginsModalOpen = false;
  }
</script>

{#if cockpitState.isPluginsModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-4xl max-h-[88vh] bg-[#090d16] border border-purple-500/35 rounded-xl shadow-[0_24px_80px_rgba(0,0,0,0.85)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <Plug class="w-5 h-5 text-purple-400" />
          <div>
            <h2 class="text-sm font-bold text-white">Gestionnaire de Plugins SAST & Taint (DSL v2)</h2>
            <p class="text-[11px] text-slate-400">
              Règles YAML locales dans <code class="text-purple-300">.aether/plugins/</code> · Import Semgrep · Fenêtrage & Taint SSA · Hot-Reload
            </p>
          </div>
        </div>
        <button
          type="button"
          onclick={closeModal}
          aria-label="Fermer le gestionnaire de plugins"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Tabs Bar -->
      <div class="px-5 pt-3 pb-2 bg-[#0b101d] border-b border-white/10 flex items-center justify-between flex-wrap gap-2 shrink-0">
        <div class="flex items-center gap-1.5">
          <button
            type="button"
            onclick={() => (activeTab = 'plugins')}
            class="px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'plugins'
              ? 'bg-purple-500/25 text-purple-200 border border-purple-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            📦 Plugins ({inventory?.total_plugins ?? 0})
          </button>
          <button
            type="button"
            onclick={() => (activeTab = 'semgrep')}
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'semgrep'
              ? 'bg-sky-500/25 text-sky-200 border border-sky-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Upload class="w-3.5 h-3.5" />
            <span>Importer Semgrep</span>
          </button>
          <button
            type="button"
            onclick={() => (activeTab = 'create')}
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer {activeTab === 'create'
              ? 'bg-emerald-500/25 text-emerald-200 border border-emerald-400/40'
              : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
          >
            <Plus class="w-3.5 h-3.5" />
            <span>Nouvelle Règle DSL v2</span>
          </button>
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            disabled={busyAction !== null}
            onclick={() => handleRunTests()}
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-[11px] font-semibold text-emerald-300 cursor-pointer disabled:opacity-50"
          >
            <Play class="w-3 h-3" />
            <span>{busyAction === 'test:all' ? 'Tests...' : 'Tester tous'}</span>
          </button>
          <button
            type="button"
            disabled={isLoading}
            onclick={refreshInventory}
            class="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 cursor-pointer disabled:opacity-50"
            title="Rafraîchir l'inventaire"
          >
            <RefreshCw class="w-3.5 h-3.5 {isLoading ? 'animate-spin' : ''}" />
          </button>
        </div>
      </div>

      <!-- Body -->
      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        {#if statusMsg}
          <div
            class="px-3.5 py-2 rounded-lg border text-xs font-mono flex items-center gap-2 {statusMsg.kind === 'ok'
              ? 'bg-emerald-500/15 border-emerald-500/35 text-emerald-200'
              : 'bg-rose-500/15 border-rose-500/35 text-rose-200'}"
          >
            {#if statusMsg.kind === 'ok'}
              <CheckCircle2 class="w-4 h-4 shrink-0 text-emerald-400" />
            {:else}
              <AlertTriangle class="w-4 h-4 shrink-0 text-rose-400" />
            {/if}
            <span class="break-words">{statusMsg.text}</span>
          </div>
        {/if}

        {#if testReport && testReport.failed > 0}
          <div class="p-3 rounded-lg bg-rose-950/40 border border-rose-500/35 space-y-1 text-[11px] font-mono text-rose-200">
            <div class="font-bold text-rose-300">Détails des échecs ({testReport.failed}/{testReport.total_tests}) :</div>
            {#each testReport.failures as f}
              <div class="text-rose-200/90">• {f}</div>
            {/each}
          </div>
        {/if}

        {#if activeTab === 'plugins'}
          <!-- KPIs -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Plugins Actifs</div>
              <div class="text-lg font-mono font-bold text-purple-300">
                {inventory?.enabled_plugins ?? 0} <span class="text-xs text-slate-500">/ {inventory?.total_plugins ?? 0}</span>
              </div>
            </div>
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Règles SAST Actives</div>
              <div class="text-lg font-mono font-bold text-sky-300">{inventory?.total_active_rules ?? 0}</div>
            </div>
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Taint SSA (Src/Sink/San)</div>
              <div class="text-lg font-mono font-bold text-amber-300">
                {inventory?.total_taint_sources ?? 0}/{inventory?.total_taint_sinks ?? 0}/{inventory?.total_sanitizers ?? 0}
              </div>
            </div>
            <div class="p-3 rounded-lg bg-white/[0.03] border border-white/10 flex flex-col justify-between">
              <div class="text-[10px] uppercase text-slate-400 font-semibold">Bundle OWASP/CWE</div>
              {#if inventory?.community_bundle_installed}
                <div class="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 mt-1">
                  <CheckCircle2 class="w-3.5 h-3.5" />
                  <span>Installé ({inventory.community_bundle_rules_count})</span>
                </div>
              {:else}
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onclick={handleInitBundle}
                  class="mt-1 flex items-center justify-center gap-1 px-2 py-1 rounded bg-sky-500/20 hover:bg-sky-500/30 border border-sky-400/40 text-[11px] font-semibold text-sky-200 cursor-pointer disabled:opacity-50"
                >
                  <PackagePlus class="w-3.5 h-3.5" />
                  <span>{busyAction === 'init-bundle' ? 'Déploiement...' : `Déployer (${inventory?.community_bundle_rules_count ?? 24})`}</span>
                </button>
              {/if}
            </div>
          </div>

          <!-- Search bar -->
          <div class="relative">
            <Search class="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              bind:value={searchQuery}
              placeholder="Filtrer par nom de plugin, CWE, profil, tag ou ID de règle..."
              class="w-full pl-9 pr-3 py-1.5 rounded-lg bg-black/40 border border-white/15 text-xs text-slate-200 focus:outline-none focus:border-purple-400"
            />
          </div>

          <!-- Plugin list -->
          {#if isLoading && !inventory}
            <div class="py-10 text-center text-xs text-slate-400 font-mono">Chargement de .aether/plugins...</div>
          {:else if filteredPlugins.length === 0}
            <div class="py-10 text-center space-y-2 rounded-xl bg-white/[0.02] border border-white/10">
              <div class="text-xs text-slate-400 font-mono">
                {inventory ? 'Aucun plugin ne correspond au filtre.' : 'Connectez le serveur Rust local pour gérer .aether/plugins.'}
              </div>
            </div>
          {:else}
            <div class="space-y-2.5">
              {#each filteredPlugins as plugin (plugin.rel_path)}
                {@const isExpanded = Boolean(expandedPaths[plugin.rel_path])}
                <div class="rounded-xl bg-white/[0.025] border {plugin.enabled ? 'border-purple-500/30' : 'border-white/10 opacity-75'} overflow-hidden">
                  <div class="p-3.5 flex items-start justify-between gap-3">
                    <div class="flex items-start gap-2.5 min-w-0 flex-1">
                      <button
                        type="button"
                        onclick={() => toggleExpand(plugin.rel_path)}
                        class="mt-0.5 p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white cursor-pointer shrink-0"
                        title="Afficher les règles"
                      >
                        {#if isExpanded}
                          <ChevronDown class="w-4 h-4" />
                        {:else}
                          <ChevronRight class="w-4 h-4" />
                        {/if}
                      </button>

                      <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2 flex-wrap">
                          <span class="text-xs font-bold text-white">{plugin.name}</span>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/10 text-slate-300">v{plugin.version}</span>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/15 text-sky-300 border border-sky-500/30">
                            {plugin.rules_count} règle(s)
                          </span>
                          {#if plugin.taint_sources_count + plugin.taint_sinks_count + plugin.sanitizers_count > 0}
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                              Taint {plugin.taint_sources_count}S/{plugin.taint_sinks_count}K/{plugin.sanitizers_count}N
                            </span>
                          {/if}
                          {#if plugin.profile}
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-200 border border-purple-400/35">
                              profile:{plugin.profile}
                            </span>
                          {/if}
                          {#each plugin.tags as tag}
                            <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-white/5 text-slate-400">#{tag}</span>
                          {/each}
                        </div>
                        {#if plugin.description}
                          <p class="text-[11px] text-slate-400 mt-1">{plugin.description}</p>
                        {/if}
                        <div class="text-[10px] font-mono text-slate-500 mt-1">
                          .aether/plugins/{plugin.rel_path} · {plugin.test_cases_count} test(s) unitaire(s)
                        </div>
                      </div>
                    </div>

                    <!-- Actions -->
                    <div class="flex items-center gap-1.5 shrink-0">
                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onclick={() => handleRunTests(plugin.rel_path)}
                        class="px-2 py-1 rounded bg-white/5 hover:bg-emerald-500/20 border border-white/10 hover:border-emerald-400/40 text-[10.5px] font-semibold text-slate-300 hover:text-emerald-200 cursor-pointer disabled:opacity-50"
                        title="Exécuter les tests unitaires de ce plugin"
                      >
                        Test
                      </button>

                      <button
                        type="button"
                        disabled={busyAction !== null}
                        onclick={() => handleTogglePlugin(plugin)}
                        class="px-2.5 py-1 rounded text-[10.5px] font-bold border transition-colors cursor-pointer disabled:opacity-50 {plugin.enabled
                          ? 'bg-emerald-500/20 border-emerald-400/45 text-emerald-300 hover:bg-emerald-500/30'
                          : 'bg-white/5 border-white/15 text-slate-400 hover:text-white'}"
                      >
                        {plugin.enabled ? 'ON' : 'OFF'}
                      </button>

                      {#if confirmDeletePath === plugin.rel_path}
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onclick={() => handleDeletePlugin(plugin.rel_path)}
                          class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-[10.5px] font-bold text-white cursor-pointer"
                        >
                          Confirmer
                        </button>
                        <button
                          type="button"
                          onclick={() => (confirmDeletePath = null)}
                          class="px-1.5 py-1 rounded bg-white/10 text-[10.5px] text-slate-300 cursor-pointer"
                        >
                          Annuler
                        </button>
                      {:else}
                        <button
                          type="button"
                          onclick={() => (confirmDeletePath = plugin.rel_path)}
                          class="p-1.5 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 cursor-pointer"
                          title="Supprimer ce plugin"
                        >
                          <Trash2 class="w-3.5 h-3.5" />
                        </button>
                      {/if}
                    </div>
                  </div>

                  {#if isExpanded}
                    <div class="px-4 pb-3.5 pt-2 border-t border-white/10 bg-black/25 space-y-2">
                      {#if plugin.rules.length === 0}
                        <div class="text-[11px] font-mono text-slate-500">Aucune règle pattern dans ce manifeste.</div>
                      {:else}
                        {#each plugin.rules as rule (rule.id)}
                          <div class="p-2.5 rounded-lg bg-black/35 border border-white/10 space-y-1">
                            <div class="flex items-center gap-2 flex-wrap">
                              <ShieldAlert class="w-3.5 h-3.5 text-rose-400 shrink-0" />
                              <span class="font-mono text-[11px] font-bold text-white">{rule.id}</span>
                              <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono border {severityClass(rule.severity)}">
                                {rule.severity}
                              </span>
                              <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-rose-500/15 text-rose-300">
                                {rule.cwe_id}
                              </span>
                              {#if rule.file_extensions.length > 0}
                                <span class="text-[10px] font-mono text-slate-400">{rule.file_extensions.join(' ')}</span>
                              {/if}
                              {#if rule.ast_scope}
                                <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-indigo-500/20 text-indigo-300">
                                  scope:{rule.ast_scope}
                                </span>
                              {/if}
                              {#if rule.not_preceded_within_lines}
                                <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-cyan-500/20 text-cyan-300">
                                  window:-{rule.not_preceded_within_lines.lines}L
                                </span>
                              {/if}
                              {#if rule.in_path_matching.length > 0 || rule.not_in_path_matching.length > 0}
                                <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-emerald-500/20 text-emerald-300">
                                  path-glob
                                </span>
                              {/if}
                            </div>
                            <div class="text-[11px] text-slate-300">{rule.description}</div>
                            {#if rule.remediation}
                              <div class="text-[10.5px] text-emerald-300/80">Fix : {rule.remediation}</div>
                            {/if}
                          </div>
                        {/each}
                      {/if}
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        {:else if activeTab === 'semgrep'}
          <div class="space-y-3 p-4 rounded-xl bg-white/[0.025] border border-sky-500/25">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div>
                <div class="text-xs font-bold text-sky-300">Convertisseur Semgrep YAML → Plugin AetherScope</div>
                <p class="text-[11px] text-slate-400">
                  Traduit automatiquement les métavariables <code>$VAR</code>, <code>pattern-either</code>, <code>pattern-not</code> et <code>metadata.cwe</code> en plugin natif.
                </p>
              </div>
              <button
                type="button"
                onclick={() => (semgrepYaml = SAMPLE_SEMGREP)}
                class="flex items-center gap-1 px-2.5 py-1 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-400/35 text-[11px] font-semibold text-sky-200 cursor-pointer"
              >
                <Sparkles class="w-3.5 h-3.5" />
                <span>Charger un exemple</span>
              </button>
            </div>

            <div>
              <label for="semgrep-plugin-name" class="block text-[11px] font-mono text-slate-300 mb-1">
                Nom du pack importé (.aether/plugins/imported/&lt;nom&gt;/plugin.yaml)
              </label>
              <input
                id="semgrep-plugin-name"
                type="text"
                bind:value={semgrepName}
                placeholder="ex: owasp-custom-rules"
                class="w-full px-3 py-1.5 rounded-lg bg-black/40 border border-white/15 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
              />
            </div>

            <div>
              <label for="semgrep-yaml-input" class="block text-[11px] font-mono text-slate-300 mb-1">
                Contenu YAML Semgrep
              </label>
              <textarea
                id="semgrep-yaml-input"
                bind:value={semgrepYaml}
                rows="12"
                placeholder="rules:\n  - id: my-rule\n    languages: [python]\n    severity: ERROR\n    message: ...\n    pattern: ..."
                class="w-full p-3 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
              ></textarea>
            </div>

            <div class="flex justify-end">
              <button
                type="button"
                disabled={busyAction !== null}
                onclick={handleImportSemgrep}
                class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
              >
                <Upload class="w-3.5 h-3.5" />
                <span>{busyAction === 'import-semgrep' ? 'Importation...' : 'Convertir & Activer le Plugin'}</span>
              </button>
            </div>
          </div>
        {:else}
          <!-- DSL v2 Rule Creator -->
          <div class="space-y-3 p-4 rounded-xl bg-white/[0.025] border border-emerald-500/25">
            <div class="text-xs font-bold text-emerald-300">Créer / Mettre à jour une Règle SAST DSL v2 (Certifiée par Tests Unitaires)</div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label for="dsl-plugin" class="block text-[10.5px] font-mono text-slate-400 mb-1">Plugin (dossier)</label>
                <input id="dsl-plugin" type="text" bind:value={rulePluginName} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-profile" class="block text-[10.5px] font-mono text-slate-400 mb-1">Profil (--plugins profile:...)</label>
                <input id="dsl-profile" type="text" bind:value={ruleProfile} placeholder="ex: strict" class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-tags" class="block text-[10.5px] font-mono text-slate-400 mb-1">Tags (virgules)</label>
                <input id="dsl-tags" type="text" bind:value={ruleTags} placeholder="rust, auth, ci" class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label for="dsl-rule-id" class="block text-[10.5px] font-mono text-slate-400 mb-1">ID de règle</label>
                <input id="dsl-rule-id" type="text" bind:value={ruleId} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-cwe" class="block text-[10.5px] font-mono text-slate-400 mb-1">CWE / Classification</label>
                <input id="dsl-cwe" type="text" bind:value={ruleCweId} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-sev" class="block text-[10.5px] font-mono text-slate-400 mb-1">Sévérité</label>
                <select id="dsl-sev" bind:value={ruleSeverity} class="w-full px-2.5 py-1.5 rounded bg-[#0b101d] border border-white/15 text-xs font-mono text-white">
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="WARNING">WARNING</option>
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label for="dsl-name" class="block text-[10.5px] font-mono text-slate-400 mb-1">Intitulé</label>
                <input id="dsl-name" type="text" bind:value={ruleName} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs text-white" />
              </div>
              <div>
                <label for="dsl-exts" class="block text-[10.5px] font-mono text-slate-400 mb-1">Extensions</label>
                <input id="dsl-exts" type="text" bind:value={ruleExtensions} placeholder=".rs, .ts, .py" class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
              </div>
              <div>
                <label for="dsl-mode" class="block text-[10.5px] font-mono text-slate-400 mb-1">Mode & Portée AST</label>
                <div class="flex gap-1.5">
                  <select id="dsl-mode" bind:value={ruleMatchMode} class="flex-1 px-2 py-1.5 rounded bg-[#0b101d] border border-white/15 text-[11px] font-mono text-white">
                    <option value="line_by_line">line_by_line</option>
                    <option value="whole_file">whole_file</option>
                  </select>
                  <select bind:value={ruleAstScope} aria-label="Portée AST" class="flex-1 px-2 py-1.5 rounded bg-[#0b101d] border border-white/15 text-[11px] font-mono text-white">
                    <option value="">scope: tous</option>
                    <option value="outside_test">outside_test</option>
                    <option value="async_fn">async_fn</option>
                    <option value="sync_fn">sync_fn</option>
                    <option value="fn">fn</option>
                    <option value="test">test</option>
                  </select>
                </div>
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <label for="dsl-desc" class="block text-[10.5px] font-mono text-slate-400 mb-1">Description</label>
                <input id="dsl-desc" type="text" bind:value={ruleDescription} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs text-white" />
              </div>
              <div>
                <label for="dsl-fix" class="block text-[10.5px] font-mono text-slate-400 mb-1">Remédiation</label>
                <input id="dsl-fix" type="text" bind:value={ruleRemediation} class="w-full px-2.5 py-1.5 rounded bg-black/40 border border-white/15 text-xs text-white" />
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <label for="dsl-regex" class="block text-[10.5px] font-mono text-slate-400 mb-1">Regex déclencheurs (1 par ligne)</label>
                <textarea id="dsl-regex" bind:value={ruleRegexPatterns} rows="3" class="w-full p-2 rounded bg-black/50 border border-white/15 text-xs font-mono text-white"></textarea>
              </div>
              <div class="space-y-2">
                <div>
                  <label for="dsl-must" class="block text-[10.5px] font-mono text-slate-400 mb-1">must_contain (virgules)</label>
                  <input id="dsl-must" type="text" bind:value={ruleMustContain} class="w-full px-2.5 py-1 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
                </div>
                <div>
                  <label for="dsl-must-not" class="block text-[10.5px] font-mono text-slate-400 mb-1">must_not_contain / mitigations (virgules)</label>
                  <input id="dsl-must-not" type="text" bind:value={ruleMustNotContain} class="w-full px-2.5 py-1 rounded bg-black/40 border border-white/15 text-xs font-mono text-white" />
                </div>
                <label class="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer">
                  <input type="checkbox" bind:checked={ruleCheckLiterals} class="accent-emerald-400" />
                  <span>check_literals (évaluer dans les chaînes/commentaires bruts)</span>
                </label>
              </div>
            </div>

            <!-- DSL v2 Contextual Window & Path Globs -->
            <div class="p-3 rounded-lg bg-black/30 border border-indigo-500/25 space-y-2">
              <div class="text-[10.5px] font-mono font-bold text-indigo-300 uppercase">Conditions avancées DSL v2 (Fenêtrage & Globs)</div>
              <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div>
                  <label for="dsl-win-lines" class="block text-[10px] font-mono text-slate-400 mb-1">not_preceded_within_lines (N)</label>
                  <input id="dsl-win-lines" type="number" min="0" max="50" bind:value={ruleWindowLines} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
                <div class="sm:col-span-2">
                  <label for="dsl-win-pats" class="block text-[10px] font-mono text-slate-400 mb-1">Motifs gardes fenêtre (1 par ligne)</label>
                  <input id="dsl-win-pats" type="text" bind:value={ruleWindowPatterns} placeholder="ex: verify_csrf\\(" class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
              </div>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <div>
                  <label for="dsl-in-path" class="block text-[10px] font-mono text-slate-400 mb-1">in_path_matching (ex: src/api/**)</label>
                  <input id="dsl-in-path" type="text" bind:value={ruleInPaths} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
                <div>
                  <label for="dsl-not-path" class="block text-[10px] font-mono text-slate-400 mb-1">not_in_path_matching (ex: **/generated/**)</label>
                  <input id="dsl-not-path" type="text" bind:value={ruleNotInPaths} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                </div>
              </div>
            </div>

            <!-- Inline Test Certification -->
            <div class="p-3 rounded-lg bg-black/30 border border-emerald-500/20 space-y-2">
              <label class="flex items-center gap-2 text-xs font-semibold text-emerald-300 cursor-pointer">
                <input type="checkbox" bind:checked={includeTests} class="accent-emerald-400" />
                <span>Certifier par tests unitaires avant sauvegarde</span>
              </label>
              {#if includeTests}
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div>
                    <label for="dsl-test-file" class="block text-[10px] font-mono text-slate-400 mb-1">Fichier virtuel</label>
                    <input id="dsl-test-file" type="text" bind:value={testVulnFile} class="w-full px-2 py-1 rounded bg-black/50 border border-white/15 text-xs font-mono text-white" />
                  </div>
                  <div>
                    <label for="dsl-test-vuln" class="block text-[10px] font-mono text-rose-300 mb-1">Code vulnérable (trigger = true)</label>
                    <input id="dsl-test-vuln" type="text" bind:value={testVulnCode} class="w-full px-2 py-1 rounded bg-black/50 border border-rose-500/30 text-xs font-mono text-white" />
                  </div>
                  <div>
                    <label for="dsl-test-safe" class="block text-[10px] font-mono text-emerald-300 mb-1">Code sûr (trigger = false)</label>
                    <input id="dsl-test-safe" type="text" bind:value={testSafeCode} class="w-full px-2 py-1 rounded bg-black/50 border border-emerald-500/30 text-xs font-mono text-white" />
                  </div>
                </div>
              {/if}
            </div>

            <div class="flex justify-end">
              <button
                type="button"
                disabled={busyAction !== null}
                onclick={handleCreateRule}
                class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
              >
                <Plus class="w-3.5 h-3.5" />
                <span>{busyAction === 'upsert-rule' ? 'Validation...' : 'Certifier & Enregistrer la Règle'}</span>
              </button>
            </div>
          </div>
        {/if}
      </div>

      <!-- Footer -->
      <div class="px-5 py-3 bg-[#0f172a] border-t border-white/10 flex items-center justify-between text-[11px] text-slate-400 shrink-0">
        <span>CLI compatible : <code class="text-purple-300">aether-engine --plugins auto|all|&lt;pack&gt;|profile:&lt;name&gt;</code></span>
        <button
          type="button"
          onclick={closeModal}
          class="px-3.5 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-xs font-semibold text-white cursor-pointer"
        >
          Fermer
        </button>
      </div>
    </div>
  </div>
{/if}
