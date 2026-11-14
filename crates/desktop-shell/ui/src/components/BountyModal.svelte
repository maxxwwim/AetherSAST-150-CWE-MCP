<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { ShieldAlert, X, Copy, Check, Terminal, Radar, Sparkles, Plug, Send, Search, Code2, SlidersHorizontal, ExternalLink } from '@lucide/svelte';
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

  type PromptFormat = 'poc_exploit' | 'gold_patch' | 'bounty_report' | 'full_handshake';
  type BountyPresetId = 'immunefi' | 'hackerone' | 'yeswehack' | 'smart_contracts';

  const BOUNTY_PRESETS: Record<BountyPresetId, { label: string; badge: string; inScope: string[]; outScope: string[]; rationale: string }> = {
    immunefi: {
      label: 'Immunefi Web3',
      badge: '⛓️ Web3',
      inScope: ['contracts/*', 'crates/*', 'src/*', '*.sol', '*.rs'],
      outScope: ['tests/*', 'test/*', 'script/*', 'mocks/*', 'docs/*', 'target/*'],
      rationale: 'Preset Immunefi Web3 : Contrats, crates cœur & logique d\'état In-Scope ; tests/mocks/scripts Out-of-Scope.',
    },
    hackerone: {
      label: 'HackerOne API',
      badge: '🌐 API',
      inScope: ['crates/*', 'src/*', 'api/*', 'routes/*', 'controllers/*', 'auth/*'],
      outScope: ['tests/*', '*.spec.*', '*.test.*', 'docs/*', 'fixtures/*', 'benches/*'],
      rationale: 'Preset HackerOne API : Endpoints HTTP/WS, handlers & auth In-Scope ; tests unitaires & docs Out-of-Scope.',
    },
    yeswehack: {
      label: 'YesWeHack SaaS',
      badge: '🛡️ SaaS',
      inScope: ['crates/*', 'src/*', 'app/*', 'server/*', 'ui/src/*'],
      outScope: ['tests/*', 'e2e/*', 'docs/*', 'migrations/*', 'node_modules/*', '*.test.*'],
      rationale: 'Preset YesWeHack SaaS : Application full-stack (backend + frontend UI) In-Scope ; migrations & tests Out-of-Scope.',
    },
    smart_contracts: {
      label: 'Smart Contracts',
      badge: '💎 DeFi',
      inScope: ['contracts/*', 'programs/*', 'pallets/*', 'crates/core*'],
      outScope: ['test/*', 'tests/*', 'bench/*', 'scripts/*', 'audits/*', 'docs/*'],
      rationale: 'Preset Smart Contracts : Protocoles on-chain & moteurs critiques uniquement.',
    },
  };

  let selectedAnomaly = $state<CveAnomalyRecord | null>(null);
  let filterSeverity = $state<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  let cveSearchQuery = $state('');
  let promptFormat = $state<PromptFormat>('poc_exploit');
  let activePreset = $state<BountyPresetId | null>(null);
  let showWildcardEditor = $state(false);
  let inScopePatternsText = $state('');
  let outScopePatternsText = $state('tests/*\n*.test.*\n*.spec.*\ndocs/*');
  let excludedFolders = $state<Record<string, boolean>>({});
  let recommendations = $state<FolderRecommendation[]>([]);
  let scopeModeLabel = $state('ai_recommended');
  let scopeUpdatedBy = $state('AetherScope AI Recommender');
  let scopeRationale = $state('');
  let syncedNotice = $state('');
  let copied = $state(false);
  let sentToMcp = $state(false);

  // Faulty source code snippet state
  let snippetLoading = $state(false);
  let snippetLines = $state<{ num: number; text: string; isFaulty: boolean }[]>([]);
  let snippetFileError = $state('');
  let fileCache = new Map<string, string>();

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

  function parsePatternLines(text: string): string[] {
    return text
      .split(/[\r\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function matchesWildcardPattern(filePath: string, pattern: string): boolean {
    const normPath = (filePath || '').replace(/\\/g, '/').toLowerCase();
    const normPat = (pattern || '').replace(/\\/g, '/').trim().toLowerCase();
    if (!normPat) return false;
    if (!normPat.includes('*')) {
      return normPath === normPat || normPath.startsWith(normPat + '/') || normPath.includes('/' + normPat + '/');
    }
    const regexStr =
      '^' +
      normPat
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*') +
      '$';
    try {
      if (new RegExp(regexStr, 'i').test(normPath)) return true;
      const prefix = normPat.replace(/\/?\*+$/, '');
      if (prefix && (normPath === prefix || normPath.startsWith(prefix + '/'))) return true;
    } catch {
      // ignore invalid regex
    }
    return false;
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
        inScopePatternsText = (res.scope.in_scope || []).join('\n');
        outScopePatternsText = (res.scope.out_of_scope || []).join('\n');
        cockpitState.bountyOutOfScopePatterns = res.scope.out_of_scope || [];
      }
    } catch {
      // Fallback local
    }
  }

  $effect(() => {
    if (cockpitState.isBountyModalOpen) {
      loadServerScope();
      if (!selectedAnomaly && cockpitState.allViolations.length > 0) {
        selectAnomaly(cockpitState.allViolations[0]);
      }
    }
  });

  async function applyBountyPreset(presetId: BountyPresetId) {
    activePreset = presetId;
    const preset = BOUNTY_PRESETS[presetId];
    inScopePatternsText = preset.inScope.join('\n');
    outScopePatternsText = preset.outScope.join('\n');
    scopeRationale = preset.rationale;
    const next: Record<string, boolean> = {};
    for (const { folder } of projectFolders) {
      const isOut = preset.outScope.some((pat) => matchesWildcardPattern(folder, pat));
      if (isOut) next[folder] = true;
    }
    excludedFolders = next;
    await syncOutScopeToScanner(`Preset ${preset.label}`);
  }

  async function applyAiRecommendedScope() {
    activePreset = null;
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
        inScopePatternsText = (res.scope.in_scope || []).join('\n');
        outScopePatternsText = (res.scope.out_of_scope || []).join('\n');
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
    const nextExcluded = !excludedFolders[folder];
    excludedFolders = { ...excludedFolders, [folder]: nextExcluded };
    const outSet = new Set(parsePatternLines(outScopePatternsText));
    const inSet = new Set(parsePatternLines(inScopePatternsText));
    if (nextExcluded) {
      outSet.add(folder);
      inSet.delete(folder);
    } else {
      outSet.delete(folder);
      inSet.add(folder);
    }
    outScopePatternsText = Array.from(outSet).join('\n');
    inScopePatternsText = Array.from(inSet).join('\n');
  }

  async function syncOutScopeToScanner(customAuthor?: string) {
    const folderOutList = Object.keys(excludedFolders).filter((k) => excludedFolders[k]);
    const folderInList = projectFolders.map((p) => p.folder).filter((f) => !excludedFolders[f]);
    const outList = Array.from(new Set([...folderOutList, ...parsePatternLines(outScopePatternsText)]));
    const inList = Array.from(new Set([...folderInList, ...parsePatternLines(inScopePatternsText)]));
    cockpitState.bountyOutOfScopePatterns = outList;
    try {
      const res = await api.updateBountyScope({
        action: 'set',
        in_scope: inList,
        out_of_scope: outList,
        mode: 'mcp_synced',
        updated_by: customAuthor || 'Cockpit User -> MCP',
        rationale: scopeRationale || `Périmètre synchronisé depuis BountyModal (${inList.length} In-Scope, ${outList.length} Out-of-Scope)`,
      });
      if (res?.scope) {
        scopeModeLabel = res.scope.mode;
        scopeUpdatedBy = res.scope.updated_by || 'Cockpit User';
      }
      syncedNotice = `🔌 Synchronisé MCP (.aether/bounty_scope.json) & Surface (${inList.length} In · ${outList.length} Out)`;
    } catch {
      syncedNotice = `${outList.length} règle(s) Out-of-Scope synchronisée(s) localement`;
    }
    setTimeout(() => (syncedNotice = ''), 3200);
  }

  const activeOutWildcards = $derived(parsePatternLines(outScopePatternsText));

  const filtered = $derived(
    cockpitState.allViolations.filter((v) => {
      if (filterSeverity !== 'ALL' && v.severity !== filterSeverity) return false;
      const folder = folderOf(v);
      if (excludedFolders[folder]) return false;
      if (activeOutWildcards.some((pat) => matchesWildcardPattern(v.file_path || '', pat))) return false;
      const q = cveSearchQuery.trim().toLowerCase();
      if (q) {
        const hay = `${v.cve_id} ${v.cwe_class || ''} ${v.title} ${v.file_path} ${v.description || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    })
  );

  async function loadFaultySnippet(a: CveAnomalyRecord) {
    snippetFileError = '';
    snippetLines = [];
    if (!a?.file_path) return;
    snippetLoading = true;
    try {
      let raw = fileCache.get(a.file_path);
      if (raw === undefined) {
        const res = await api.getFileContent(a.file_path);
        if (typeof res?.content === 'string') {
          raw = res.content;
          fileCache.set(a.file_path, res.content);
        }
      }
      if (raw) {
        const allLines = raw.split(/\r?\n/);
        const targetLine = Math.max(1, Number(a.line_number) || 1);
        const startLine = Math.max(1, targetLine - 5);
        const endLine = Math.min(allLines.length, targetLine + 5);
        const extracted: { num: number; text: string; isFaulty: boolean }[] = [];
        for (let ln = startLine; ln <= endLine; ln++) {
          extracted.push({
            num: ln,
            text: allLines[ln - 1] ?? '',
            isFaulty: ln === targetLine,
          });
        }
        snippetLines = extracted;
      } else {
        snippetFileError = 'Extrait source non disponible sur disque';
      }
    } catch {
      snippetFileError = 'Impossible de charger l\'extrait source';
    } finally {
      snippetLoading = false;
    }
  }

  function selectAnomaly(a: CveAnomalyRecord) {
    selectedAnomaly = a;
    copied = false;
    sentToMcp = false;
    loadFaultySnippet(a);
  }

  function focusAnomalyInGraph(a: CveAnomalyRecord) {
    const node = cockpitState.resolveTargetNode(a.file_path);
    if (node) {
      cockpitState.selectSymbol(node.id);
      cockpitState.activeTab = 'cve';
      cockpitState.requestFocusSymbol(node.id);
      cockpitState.isBountyModalOpen = false;
    }
  }

  function buildMcpBountyPrompt(a: CveAnomalyRecord, format: PromptFormat = promptFormat): string {
    const outList = Array.from(new Set([...Object.keys(excludedFolders).filter((k) => excludedFolders[k]), ...parsePatternLines(outScopePatternsText)]));
    const inList = Array.from(new Set([...projectFolders.map((p) => p.folder).filter((f) => !excludedFolders[f]), ...parsePatternLines(inScopePatternsText)]));
    const folder = folderOf(a);
    const rec = recByFolder.get(folder);
    const snippetBlock =
      snippetLines.length > 0
        ? `\n## Extrait Source Vulnérable (${a.file_path}:${a.line_number}):\n\`\`\`\n${snippetLines
            .map((l) => `${l.isFaulty ? '>> ' : '   '}${String(l.num).padStart(4, ' ')} | ${l.text}`)
            .join('\n')}\n\`\`\`\n`
        : '';

    if (format === 'gold_patch') {
      return `# 🛡️ Mission Gold Patch & Contrat EARS — ${a.cve_id} (${a.title})

## Cible In-Scope:
- Fichier : \`${a.file_path}\` (Ligne \`${a.line_number}\`)
- Sévérité : **${a.severity}** · Classe : \`${a.cwe_class}\`
- Diagnostic : ${a.description}
${snippetBlock}
## Exigences EARS & Remédiation:
- ${a.remediation}
- Le correctif DOIT préserver les invariants du module \`${folder}\` et être certifié via \`aetherscope_verify_patch({"symbol_id": "${a.file_path}", "patched_code": "..."})\`.`;
    }

    if (format === 'bounty_report') {
      return `# 🏆 Rapport Bug Bounty (${activePreset ? BOUNTY_PRESETS[activePreset].label : 'HackerOne / Immunefi'}) — ${a.cve_id}

## 1. Executive Summary
- **Asset In-Scope** : \`${a.file_path}\` (L${a.line_number})
- **Vulnerability Type** : ${a.cve_id} — ${a.title} (${a.cwe_class})
- **Severity** : **${a.severity}**
- **Attack Surface Score** : ${rec?.score ?? 'High'} (${rec?.reason || 'Reachable module'})

## 2. Root Cause & Vulnerable Code
${a.description}
${snippetBlock}
## 3. Proof of Concept (Non-Destructive)
1. Target entrypoint in \`${folder}\`.
2. Trigger state/input reaching \`${a.file_path}:${a.line_number}\`.
3. Observe invariant violation without causing DoS.

## 4. Recommended Fix
${a.remediation}`;
    }

    if (format === 'full_handshake') {
      return `# 🤝 Handshake Complet Multi-Agent MCP — ${a.cve_id}

\`\`\`json
{
  "protocol": "aetherscope-mcp-v2.3",
  "mission": "poc_and_ears_patch",
  "target": {
    "cve_id": "${a.cve_id}",
    "cwe_class": "${a.cwe_class}",
    "severity": "${a.severity}",
    "file_path": "${a.file_path}",
    "line_number": ${a.line_number || 1},
    "folder": "${folder}"
  },
  "scope": {
    "mode": "${scopeModeLabel}",
    "preset": "${activePreset || 'auto'}",
    "in_scope": ${JSON.stringify(inList.slice(0, 12))},
    "out_of_scope": ${JSON.stringify(outList.slice(0, 12))}
  },
  "mcp_pipeline": [
    { "tool": "aetherscope_search_symbols", "args": { "scope_mode": "in_scope_only", "cwe_id": "${a.cve_id}" } },
    { "tool": "aetherscope_get_active_target", "args": { "symbol_id": "${a.file_path}", "action": "Audit PoC ${a.cve_id}" } },
    { "tool": "aetherscope_verify_patch", "args": { "symbol_id": "${a.file_path}" } }
  ]
}
\`\`\`
${snippetBlock}`;
    }

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
${snippetBlock}
## Remediation Roadmap:
${a.remediation}

## Protocole Agent MCP AetherScope:
1. Vérifier/ajuster le scope PoC : \`aetherscope_search_symbols({"scope_mode": "recommend_scope"})\` ou \`{"scope_mode": "in_scope_only", "cwe_id": "${a.cve_id}"}\`
2. Inspecter le flux d'atteignabilité : \`aetherscope_get_active_target({"symbol_id": "${a.file_path}", "action": "Audit PoC ${a.cve_id}"})\`
3. Rédiger un PoC défensif prouvant l'atteignabilité sans DoS, appliquer le patch EARS, puis certifier avec \`aetherscope_verify_patch\`.`;
  }

  const activePromptPreview = $derived(selectedAnomaly ? buildMcpBountyPrompt(selectedAnomaly, promptFormat) : '');

  function copyBountyPrompt(a: CveAnomalyRecord) {
    navigator.clipboard.writeText(buildMcpBountyPrompt(a, promptFormat)).then(() => {
      copied = true;
      setTimeout(() => (copied = false), 2000);
    });
  }

  async function sendPocMissionToMcpChat(a?: CveAnomalyRecord | null) {
    const text = a
      ? buildMcpBountyPrompt(a, promptFormat)
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
      class="w-full max-w-5xl max-h-[88vh] bg-[#0c0f17] border border-rose-500/30 rounded-2xl shadow-2xl overflow-hidden flex flex-col text-slate-100"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cockpitState.isBountyModalOpen = false; }}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <!-- Header -->
      <div class="px-5 py-3 border-b border-white/10 flex items-center justify-between bg-rose-950/20">
        <div class="flex items-center gap-2.5 flex-wrap">
          <ShieldAlert class="w-5 h-5 text-rose-400" />
          <h2 class="text-sm font-bold tracking-tight text-white">
            Générateur de PoC Bug Bounty & Audit Zero-Day
          </h2>
          <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
            {filtered.length} / {cockpitState.allViolations.length} In-Scope
          </span>
          <!-- Bug Bounty Program Presets -->
          <div class="flex items-center gap-1 ml-2">
            {#each Object.entries(BOUNTY_PRESETS) as [presetKey, preset]}
              <button
                type="button"
                onclick={() => applyBountyPreset(presetKey as BountyPresetId)}
                title={preset.rationale}
                class="px-2 py-0.5 rounded text-[10px] font-mono border transition-all cursor-pointer {activePreset === presetKey ? 'bg-amber-500/25 border-amber-400/50 text-amber-200 font-bold' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
              >
                {preset.badge} {preset.label}
              </button>
            {/each}
          </div>
        </div>
        <button
          onclick={() => (cockpitState.isBountyModalOpen = false)}
          class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Content Split View -->
      <div class="flex-1 flex overflow-hidden">
        <!-- List Sidebar -->
        <div class="w-88 border-r border-white/10 flex flex-col bg-black/30 shrink-0">
          <!-- Severity Filter Tabs -->
          <div class="flex items-center p-2 gap-1 border-b border-white/10 text-[11px] font-mono">
            <button
              onclick={() => (filterSeverity = 'ALL')}
              class="flex-1 py-1 rounded transition-colors cursor-pointer {filterSeverity === 'ALL' ? 'bg-white/10 text-white font-bold' : 'text-slate-400'}"
            >
              Tous ({filtered.length})
            </button>
            <button
              onclick={() => (filterSeverity = 'CRITICAL')}
              class="flex-1 py-1 rounded transition-colors cursor-pointer {filterSeverity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 font-bold' : 'text-slate-400'}"
            >
              Critique ({cockpitState.criticalViolations.length})
            </button>
            <button
              onclick={() => (filterSeverity = 'HIGH')}
              class="flex-1 py-1 rounded transition-colors cursor-pointer {filterSeverity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 font-bold' : 'text-slate-400'}"
            >
              Élevé
            </button>
          </div>

          <!-- Internal CWE / File Search -->
          <div class="px-2 py-1.5 border-b border-white/10 bg-black/25">
            <div class="relative">
              <Search class="w-3 h-3 text-slate-500 absolute left-2.5 top-2" />
              <input
                type="text"
                bind:value={cveSearchQuery}
                placeholder="Filtrer CWE, titre, fichier..."
                class="w-full pl-7 pr-2 py-1 rounded bg-white/[0.04] border border-white/10 text-[10.5px] font-mono text-slate-200 focus:outline-none focus:border-rose-400/50"
              />
            </div>
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
                    onclick={() => (showWildcardEditor = !showWildcardEditor)}
                    class="flex items-center gap-0.5 px-1.5 py-0.5 rounded border cursor-pointer {showWildcardEditor ? 'bg-sky-500/25 border-sky-400/40 text-sky-200' : 'bg-white/5 hover:bg-white/10 border-white/15 text-slate-300'}"
                    title="Éditer les règles Wildcards In-Scope / Out-of-Scope (*.test.ts, migrations/*, etc.)"
                  >
                    <SlidersHorizontal class="w-2.5 h-2.5" /> Règles
                  </button>
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
                    onclick={() => syncOutScopeToScanner()}
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

              {#if showWildcardEditor}
                <div class="grid grid-cols-2 gap-1.5 pt-1">
                  <div class="flex flex-col gap-0.5">
                    <span class="text-[8.5px] font-mono text-emerald-300 uppercase">🎯 In-Scope Wildcards</span>
                    <textarea
                      bind:value={inScopePatternsText}
                      rows="3"
                      placeholder="crates/*&#10;src/*&#10;*.rs"
                      class="w-full p-1.5 rounded bg-[#050811] border border-emerald-500/30 text-[9.5px] font-mono text-emerald-100 focus:outline-none resize-none"
                    ></textarea>
                  </div>
                  <div class="flex flex-col gap-0.5">
                    <span class="text-[8.5px] font-mono text-rose-300 uppercase">🚫 Out-of-Scope Wildcards</span>
                    <textarea
                      bind:value={outScopePatternsText}
                      rows="3"
                      placeholder="tests/*&#10;*.test.*&#10;docs/*"
                      class="w-full p-1.5 rounded bg-[#050811] border border-rose-500/30 text-[9.5px] font-mono text-rose-100 focus:outline-none resize-none"
                    ></textarea>
                  </div>
                </div>
              {/if}

              <div class="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
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
                class="w-full text-left p-2 rounded-lg border transition-all cursor-pointer {selectedAnomaly?.cve_id === a.cve_id && selectedAnomaly?.line_number === a.line_number && selectedAnomaly?.file_path === a.file_path ? 'bg-rose-500/15 border-rose-500/40 text-white' : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.05]'}"
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
                Aucune anomalie In-Scope détectée
              </div>
            {/if}
          </div>
        </div>

        <!-- Detail Preview -->
        <div class="flex-1 flex flex-col p-4 overflow-y-auto bg-[#0a0d14]">
          {#if selectedAnomaly}
            <div class="flex flex-col gap-3.5">
              <div class="flex items-start justify-between gap-2">
                <div class="min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded font-bold {selectedAnomaly.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'}">
                      {selectedAnomaly.severity} · {selectedAnomaly.cwe_class}
                    </span>
                    <button
                      type="button"
                      onclick={() => selectedAnomaly && focusAnomalyInGraph(selectedAnomaly)}
                      class="flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/35 text-[10px] font-mono text-sky-300 cursor-pointer"
                      title="Téléporter la caméra sur cette bulle dans le graphe"
                    >
                      <ExternalLink class="w-2.5 h-2.5" /> Cibler dans le Graphe
                    </button>
                  </div>
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

              <!-- Prompt / Report Mode Selector -->
              <div class="flex items-center gap-1 p-1 rounded-lg bg-black/40 border border-white/10 text-[10.5px] font-mono">
                <button
                  type="button"
                  onclick={() => (promptFormat = 'poc_exploit')}
                  class="flex-1 py-1 px-2 rounded cursor-pointer transition-colors {promptFormat === 'poc_exploit' ? 'bg-rose-500/25 text-rose-200 border border-rose-500/40 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  🎯 PoC Exploit Défensif
                </button>
                <button
                  type="button"
                  onclick={() => (promptFormat = 'gold_patch')}
                  class="flex-1 py-1 px-2 rounded cursor-pointer transition-colors {promptFormat === 'gold_patch' ? 'bg-emerald-500/25 text-emerald-200 border border-emerald-500/40 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  🛡️ Gold Patch EARS
                </button>
                <button
                  type="button"
                  onclick={() => (promptFormat = 'bounty_report')}
                  class="flex-1 py-1 px-2 rounded cursor-pointer transition-colors {promptFormat === 'bounty_report' ? 'bg-amber-500/25 text-amber-200 border border-amber-500/40 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  🏆 Rapport Bounty
                </button>
                <button
                  type="button"
                  onclick={() => (promptFormat = 'full_handshake')}
                  class="flex-1 py-1 px-2 rounded cursor-pointer transition-colors {promptFormat === 'full_handshake' ? 'bg-purple-500/25 text-purple-200 border border-purple-500/40 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  🤝 Handshake MCP
                </button>
              </div>

              <!-- Faulty Source Code Snippet Preview (line ± 5) -->
              <div class="rounded-lg bg-[#05070d] border border-rose-500/30 overflow-hidden">
                <div class="px-3 py-1.5 bg-rose-950/30 border-b border-rose-500/20 flex items-center justify-between text-[10px] font-mono text-rose-200">
                  <span class="flex items-center gap-1.5">
                    <Code2 class="w-3.5 h-3.5 text-rose-400" />
                    Extrait Code Source Fautif ({selectedAnomaly.file_path} · Ligne {selectedAnomaly.line_number})
                  </span>
                  <span class="text-rose-400/80">Contexte ±5 lignes</span>
                </div>
                {#if snippetLoading}
                  <div class="p-3 text-[11px] font-mono text-slate-400">Chargement de l'extrait source...</div>
                {:else if snippetLines.length > 0}
                  <div class="p-2 font-mono text-[10.5px] overflow-x-auto leading-relaxed">
                    {#each snippetLines as ln}
                      <div
                        class="flex items-center px-2 py-0.5 rounded {ln.isFaulty ? 'bg-rose-500/25 border-l-2 border-rose-400 text-rose-100 font-bold' : 'text-slate-300'}"
                      >
                        <span class="w-10 shrink-0 select-none text-right pr-3 {ln.isFaulty ? 'text-rose-300' : 'text-slate-500'}">{ln.num}</span>
                        <span class="whitespace-pre flex-1">{ln.text}</span>
                        {#if ln.isFaulty}
                          <span class="ml-3 px-1.5 py-0.2 rounded bg-rose-500/40 text-[9px] text-white shrink-0">◄ {selectedAnomaly.cve_id}</span>
                        {/if}
                      </div>
                    {/each}
                  </div>
                {:else}
                  <div class="p-3 text-[11px] font-mono text-slate-500">{snippetFileError || 'Extrait non disponible'}</div>
                {/if}
              </div>

              <!-- Description & Remediation Grid -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="p-3 rounded-lg bg-black/40 border border-white/5 flex flex-col gap-1">
                  <span class="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Description de la Faille</span>
                  <p class="text-xs text-slate-300 leading-relaxed">{selectedAnomaly.description}</p>
                </div>

                <div class="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/20 flex flex-col gap-1">
                  <span class="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">Guide de Remédiation Défensive</span>
                  <p class="text-xs text-emerald-200/90 leading-relaxed">{selectedAnomaly.remediation}</p>
                </div>
              </div>

              <!-- Live Prompt / Handshake Preview -->
              <div class="rounded-lg bg-black/50 border border-white/10 overflow-hidden">
                <div class="px-3 py-1.5 bg-white/[0.03] border-b border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span>Aperçu du Payload ({promptFormat})</span>
                  <span>Prêt pour Presse-Papiers / Canal MCP</span>
                </div>
                <pre class="p-3 text-[10px] font-mono text-slate-300 whitespace-pre-wrap max-h-44 overflow-y-auto leading-relaxed">{activePromptPreview}</pre>
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
