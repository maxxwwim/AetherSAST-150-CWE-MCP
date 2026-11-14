<script lang="ts">
  import type { CveAnomalyRecord, SymbolBubble } from '../../types/graph';
  import {
    buildBugBountyMarkdownReport,
    buildCurlCommand,
    buildExecutablePocScript,
    buildGoldPatchBlock,
    buildMcpHandshakeBlock,
    buildRawHttpRequest,
    getTargetEndpoint,
    getTargetMethod,
    tokenizeLine,
    type BountyPresetId,
    type CodeViewerLine,
    type DryRunResult,
    type FileFunctionItem,
    type FolderRecommendation,
    type PromptFormat,
    type TargetDataDirection,
  } from './bountyEngine';
  import {
    ArrowLeft,
    Bug,
    Check,
    Code2,
    Copy,
    Download,
    Eye,
    FileJson,
    FileText,
    Globe,
    Layers,
    Play,
    Radio,
    RefreshCw,
    Save,
    Send,
    ShieldAlert,
    ShieldCheck,
    Sparkles,
    Terminal,
  } from '@lucide/svelte';

  interface Props {
    selectedAnomaly: CveAnomalyRecord | null;
    selectedSymbol: SymbolBubble | null;
    activeFunction: FileFunctionItem | null;
    codeLines: CodeViewerLine[];
    dataDirection: TargetDataDirection;
    promptFormat: PromptFormat;
    reportRenderMode: 'formatted' | 'raw';
    step1Prompt: string;
    step4TargetPrompt: string;
    activePreset: BountyPresetId | null;
    presetLabel: string;
    scopeModeLabel: string;
    inScopeFoldersList: string[];
    outScopeFoldersList: string[];
    lockedSingleFolder: string;
    activeRecommendation?: FolderRecommendation;
    isDryRunning: boolean;
    dryRunResult: DryRunResult | null;
    dryRunActiveTab: 'response' | 'headers' | 'ast';
    copiedKey: string | null;
    sentToMcp: boolean;
    onGoStep2: () => void;
    onGoPrevStep: () => void;
    onExecuteDryRun: () => void;
    onCopyText: (text: string, key: string) => void;
    onSendPromptToChat: (prompt: string, target: string) => void;
    onSendPocMissionToMcp: () => void;
    onSaveReportToWorkspace: () => void;
    onDownloadReportMd: () => void;
    onDownloadScopeJson: () => void;
  }

  let {
    selectedAnomaly,
    selectedSymbol,
    activeFunction,
    codeLines,
    dataDirection,
    promptFormat = $bindable(),
    reportRenderMode = $bindable(),
    step1Prompt,
    step4TargetPrompt,
    activePreset,
    presetLabel,
    scopeModeLabel,
    inScopeFoldersList,
    outScopeFoldersList,
    lockedSingleFolder,
    activeRecommendation,
    isDryRunning,
    dryRunResult,
    dryRunActiveTab = $bindable(),
    copiedKey,
    sentToMcp,
    onGoStep2,
    onGoPrevStep,
    onExecuteDryRun,
    onCopyText,
    onSendPromptToChat,
    onSendPocMissionToMcp,
    onSaveReportToWorkspace,
    onDownloadReportMd,
    onDownloadScopeJson,
  }: Props = $props();

  const FORMAT_TABS: { id: PromptFormat; label: string; shortLabel: string; requiresAnomaly: boolean }[] = [
    { id: 'target_prompt', label: '⚡ Prompt Cible Complet', shortLabel: 'Prompt Cible', requiresAnomaly: false },
    { id: 'scope_prompt', label: '🧭 Prompt Scope Maître', shortLabel: 'Prompt Scope', requiresAnomaly: false },
    { id: 'poc_code', label: '🧪 PoC Exécutable & Dry-Run', shortLabel: 'PoC & Dry-Run', requiresAnomaly: true },
    { id: 'curl_command', label: '🌐 cURL', shortLabel: 'cURL', requiresAnomaly: true },
    { id: 'raw_http', label: '📡 HTTP Raw', shortLabel: 'HTTP Raw', requiresAnomaly: true },
    { id: 'bounty_report', label: '🏆 Rapport Bounty', shortLabel: 'Rapport', requiresAnomaly: true },
    { id: 'gold_patch', label: '🛡️ Gold Patch EARS', shortLabel: 'Gold Patch', requiresAnomaly: true },
    { id: 'mcp_handshake', label: '🤝 Handshake MCP', shortLabel: 'MCP JSON', requiresAnomaly: true },
  ];

  const activeFilePath = $derived(
    selectedAnomaly?.file_path || selectedSymbol?.file_path || dataDirection.targetNode.filePath || 'unknown'
  );

  const pocScriptData = $derived.by(() => {
    if (!selectedAnomaly) return null;
    return buildExecutablePocScript(selectedAnomaly);
  });

  const activeContentText = $derived.by((): string => {
    if (promptFormat === 'scope_prompt') return step1Prompt;
    if (promptFormat === 'target_prompt') return step4TargetPrompt;
    if (!selectedAnomaly) return '';

    switch (promptFormat) {
      case 'poc_code':
        return pocScriptData?.code || '';
      case 'curl_command':
        return buildCurlCommand(selectedAnomaly);
      case 'raw_http':
        return buildRawHttpRequest(selectedAnomaly);
      case 'bounty_report':
        return buildBugBountyMarkdownReport(selectedAnomaly, {
          presetLabel,
          recReason: activeRecommendation?.reason,
          snippetLines: codeLines,
          dataDirection,
        });
      case 'gold_patch':
        return buildGoldPatchBlock(selectedAnomaly, dataDirection);
      case 'mcp_handshake':
        return buildMcpHandshakeBlock(selectedAnomaly, {
          scopeModeLabel,
          activePreset,
          inList: inScopeFoldersList,
          outList: outScopeFoldersList,
          dataDirection,
        });
      default:
        return step4TargetPrompt;
    }
  });

  const activeFormatMeta = $derived(
    FORMAT_TABS.find((t) => t.id === promptFormat) || FORMAT_TABS[0]
  );

  const isCodeHighlightedFormat = $derived(
    promptFormat === 'poc_code' ||
      promptFormat === 'curl_command' ||
      promptFormat === 'raw_http' ||
      promptFormat === 'mcp_handshake'
  );

  const contentLines = $derived(activeContentText ? activeContentText.split('\n') : []);
  const lineCount = $derived(contentLines.length);
  const charCount = $derived(activeContentText.length);
</script>

<div class="flex flex-col flex-1 min-h-0 overflow-hidden bg-[#060913]">
  <!-- Top Format Switcher + Target Quick Context -->
  <div class="px-4 py-2.5 border-b border-white/10 bg-[#0b101d] flex flex-wrap items-center justify-between gap-2 shrink-0">
    <div class="flex flex-wrap items-center gap-1.5">
      {#each FORMAT_TABS as tab}
        {@const disabledByMissingVuln = tab.requiresAnomaly && !selectedAnomaly}
        <button
          type="button"
          onclick={() => (promptFormat = tab.id)}
          class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono transition-all cursor-pointer border {promptFormat ===
          tab.id
            ? 'bg-gradient-to-r from-amber-500/25 to-rose-500/20 border-amber-400/60 text-amber-200 font-bold shadow-sm shadow-amber-500/10'
            : disabledByMissingVuln
              ? 'bg-white/[0.02] border-white/5 text-slate-500 hover:text-slate-300 hover:border-white/15'
              : 'bg-white/[0.04] border-white/10 text-slate-300 hover:bg-white/10 hover:text-white'}"
          title={disabledByMissingVuln
            ? 'Requiert une vulnérabilité sélectionnée à l’Étape 2'
            : tab.label}
        >
          <span>{tab.label}</span>
          {#if tab.id === 'poc_code' && dryRunResult}
            <span
              class="w-1.5 h-1.5 rounded-full {dryRunResult.verdict === 'vulnerability_reproduced'
                ? 'bg-rose-400 animate-pulse'
                : 'bg-emerald-400'}"
            ></span>
          {/if}
        </button>
      {/each}
    </div>

    <div class="flex items-center gap-2 shrink-0">
      {#if selectedAnomaly}
        <button
          type="button"
          onclick={onExecuteDryRun}
          disabled={isDryRunning}
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 disabled:opacity-50 text-slate-950 font-extrabold text-[11px] font-mono shadow-lg shadow-emerald-500/20 cursor-pointer"
        >
          {#if isDryRunning}
            <RefreshCw class="w-3.5 h-3.5 animate-spin" />
            <span>Dry-Run en cours...</span>
          {:else}
            <Play class="w-3.5 h-3.5" />
            <span>Exécuter PoC / Dry-Run</span>
          {/if}
        </button>
      {/if}
    </div>
  </div>

  <!-- Sub-Context Banner: Active Target / Direction / Perimeter Summary -->
  <div class="px-4 py-1.5 bg-[#080d19] border-b border-white/10 flex flex-wrap items-center justify-between gap-2 text-[10.5px] font-mono shrink-0">
    <div class="flex flex-wrap items-center gap-2 min-w-0">
      {#if selectedAnomaly}
        <span
          class="px-1.5 py-0.5 rounded font-bold {selectedAnomaly.severity === 'CRITICAL'
            ? 'bg-rose-500/25 text-rose-200 border border-rose-500/40'
            : 'bg-amber-500/20 text-amber-200 border border-amber-500/40'}"
        >
          {selectedAnomaly.severity}
        </span>
        <span class="text-white font-bold">{selectedAnomaly.cve_id}</span>
        <span class="text-slate-500">·</span>
        <span class="text-cyan-300 truncate max-w-[300px]" title={activeFilePath}>
          {activeFilePath}:{selectedAnomaly.line_number || 1}
        </span>
      {:else if selectedSymbol}
        <span class="px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-200 border border-sky-400/30 font-bold">
          SYMBOLE AST
        </span>
        <span class="text-white font-bold">{selectedSymbol.name}</span>
        <span class="text-cyan-300 truncate max-w-[300px]">{selectedSymbol.file_path}</span>
      {:else}
        <span class="text-amber-300">Mode Scope Global (aucune cible CVE sélectionnée)</span>
      {/if}

      {#if activeFunction}
        <span class="px-1.5 py-0.5 rounded bg-purple-500/15 border border-purple-400/30 text-purple-200">
          fn {activeFunction.name}()
        </span>
      {/if}

      <span class="hidden lg:inline text-slate-400 truncate max-w-[360px]" title={dataDirection.taintSummary}>
        🌊 {dataDirection.taintSummary}
      </span>
    </div>

    <div class="flex items-center gap-2 text-slate-400 shrink-0">
      <span class="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">
        🔒 {lockedSingleFolder !== 'ALL' ? `Unique: ${lockedSingleFolder}` : `${inScopeFoldersList.length} dossiers`}
      </span>
      {#if activeContentText}
        <span class="text-slate-500">{lineCount} lignes · {charCount} car.</span>
      {/if}
    </div>
  </div>

  <!-- Main Workspace Area -->
  <div class="flex-1 min-h-0 overflow-y-auto scrollbar-thin p-4 space-y-3">
    {#if activeFormatMeta.requiresAnomaly && !selectedAnomaly}
      <!-- Empty state when user jumps to Step 4 without picking a CVE -->
      <div class="rounded-2xl border border-amber-500/30 bg-amber-950/15 p-6 text-center space-y-3 my-4">
        <ShieldAlert class="w-10 h-10 text-amber-400 mx-auto" />
        <div class="space-y-1">
          <h3 class="text-sm font-bold font-mono text-white">
            Aucune vulnérabilité sélectionnée pour "{activeFormatMeta.label}"
          </h3>
          <p class="text-xs text-slate-300 max-w-xl mx-auto">
            Les livrables <code class="text-amber-200">PoC Exécutable</code>, <code class="text-amber-200">cURL</code>,
            <code class="text-amber-200">Rapport Bounty</code> et <code class="text-amber-200">Gold Patch</code> nécessitent une anomalie cible.
            Les onglets <strong class="text-cyan-300">⚡ Prompt Cible Complet</strong> et
            <strong class="text-emerald-300">🧭 Prompt Scope Maître</strong> restent utilisables même sans CVE.
          </p>
        </div>
        <div class="flex flex-wrap items-center justify-center gap-2 pt-2">
          <button
            type="button"
            onclick={onGoStep2}
            class="px-3.5 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs font-mono cursor-pointer"
          >
            🎯 Choisir une Vulnérabilité (Étape 2)
          </button>
          <button
            type="button"
            onclick={() => (promptFormat = 'target_prompt')}
            class="px-3.5 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-200 font-bold text-xs font-mono cursor-pointer"
          >
            ⚡ Voir Prompt Cible Complet
          </button>
          <button
            type="button"
            onclick={() => (promptFormat = 'scope_prompt')}
            class="px-3.5 py-2 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-400/40 text-emerald-200 font-bold text-xs font-mono cursor-pointer"
          >
            🧭 Voir Prompt Scope Maître
          </button>
        </div>
      </div>
    {:else}
      <!-- Action Toolbar above active document -->
      <div class="flex flex-wrap items-center justify-between gap-2 bg-[#0b101d] border border-white/10 rounded-xl px-3 py-2">
        <div class="flex items-center gap-2 min-w-0">
          {#if promptFormat === 'target_prompt'}
            <Sparkles class="w-4 h-4 text-amber-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-amber-200">
              Prompt Contextuel Complet (Scope + Cible + Fonction + Code + Direction Data)
            </span>
          {:else if promptFormat === 'scope_prompt'}
            <Layers class="w-4 h-4 text-emerald-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-emerald-200">
              Prompt Scope Maître ({presetLabel}) — Gouvernance & RoE MCP
            </span>
          {:else if promptFormat === 'poc_code'}
            <Bug class="w-4 h-4 text-rose-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-rose-200">
              Harness PoC Non-Destructif ({selectedAnomaly?.file_path?.endsWith('.rs') ? 'Rust #[test]' : 'Python requests'})
            </span>
          {:else if promptFormat === 'curl_command'}
            <Globe class="w-4 h-4 text-sky-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-sky-200">
              Commande cURL ({getTargetMethod(selectedAnomaly!)} {getTargetEndpoint(selectedAnomaly!)})
            </span>
          {:else if promptFormat === 'raw_http'}
            <Radio class="w-4 h-4 text-cyan-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-cyan-200">Requête HTTP/1.1 Brute (Repeater / Burp)</span>
          {:else if promptFormat === 'bounty_report'}
            <FileText class="w-4 h-4 text-amber-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-amber-200">Rapport Bug Bounty Prêt à Soumettre</span>
          {:else if promptFormat === 'gold_patch'}
            <ShieldCheck class="w-4 h-4 text-emerald-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-emerald-200">Gold Patch & Contrat Formel EARS</span>
          {:else}
            <Terminal class="w-4 h-4 text-purple-400 shrink-0" />
            <span class="text-xs font-bold font-mono text-purple-200">Payload JSON Handshake MCP</span>
          {/if}
        </div>

        <div class="flex flex-wrap items-center gap-1.5">
          {#if promptFormat === 'bounty_report'}
            <div class="inline-flex rounded-lg bg-black/50 border border-white/10 p-0.5 text-[10.5px] font-mono">
              <button
                type="button"
                onclick={() => (reportRenderMode = 'formatted')}
                class="flex items-center gap-1 px-2 py-0.5 rounded cursor-pointer {reportRenderMode === 'formatted'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-300 hover:text-white'}"
              >
                <Eye class="w-3 h-3" />
                <span>Formaté</span>
              </button>
              <button
                type="button"
                onclick={() => (reportRenderMode = 'raw')}
                class="flex items-center gap-1 px-2 py-0.5 rounded cursor-pointer {reportRenderMode === 'raw'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-300 hover:text-white'}"
              >
                <Code2 class="w-3 h-3" />
                <span>Markdown Brut</span>
              </button>
            </div>
          {/if}

          <button
            type="button"
            onclick={() => onCopyText(activeContentText, `step4_${promptFormat}`)}
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-[11px] font-mono cursor-pointer"
          >
            {#if copiedKey === `step4_${promptFormat}`}
              <Check class="w-3.5 h-3.5" />
              <span>Copié !</span>
            {:else}
              <Copy class="w-3.5 h-3.5" />
              <span>Copier</span>
            {/if}
          </button>

          <button
            type="button"
            onclick={() => onSendPromptToChat(activeContentText, activeFilePath)}
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-200 font-bold text-[11px] font-mono cursor-pointer"
          >
            <Send class="w-3.5 h-3.5" />
            <span>{sentToMcp ? 'Envoyé au Chat !' : 'Envoyer au Chat MCP'}</span>
          </button>
        </div>
      </div>

      <!-- Optional Dry-Run CLI Banner when viewing PoC Code -->
      {#if promptFormat === 'poc_code' && pocScriptData}
        <div class="rounded-xl border border-emerald-500/25 bg-emerald-950/15 px-3 py-2 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
          <div class="flex items-center gap-2 min-w-0">
            <Terminal class="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span class="text-slate-400">CLI :</span>
            <code class="text-emerald-200 truncate select-all">{pocScriptData.cli}</code>
          </div>
          <button
            type="button"
            onclick={() => onCopyText(pocScriptData.cli, 'poc_cli')}
            class="px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-slate-200 text-[10px] cursor-pointer"
          >
            {copiedKey === 'poc_cli' ? 'CLI Copiée ✓' : 'Copier CLI'}
          </button>
        </div>
      {/if}

      <!-- Live Dry-Run Telemetry Panel -->
      {#if dryRunResult && (promptFormat === 'poc_code' || promptFormat === 'curl_command' || promptFormat === 'raw_http')}
        <div
          class="rounded-xl border overflow-hidden {dryRunResult.verdict === 'vulnerability_reproduced'
            ? 'border-rose-500/45 bg-rose-950/15'
            : dryRunResult.verdict === 'target_defended'
              ? 'border-emerald-500/40 bg-emerald-950/15'
              : 'border-amber-500/40 bg-amber-950/15'}"
        >
          <div class="px-3 py-2 border-b border-white/10 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
            <div class="flex flex-wrap items-center gap-2">
              <span
                class="px-2 py-0.5 rounded font-bold {dryRunResult.mode === 'live_http'
                  ? 'bg-emerald-500/25 text-emerald-200 border border-emerald-400/40'
                  : 'bg-purple-500/25 text-purple-200 border border-purple-400/40'}"
              >
                {dryRunResult.mode === 'live_http' ? 'LIVE HTTP' : 'SANDBOX AST'}
              </span>
              <span
                class="px-2 py-0.5 rounded font-bold {dryRunResult.statusCode >= 500
                  ? 'bg-rose-500/30 text-rose-200'
                  : 'bg-sky-500/25 text-sky-200'}"
              >
                HTTP {dryRunResult.statusCode} {dryRunResult.statusText}
              </span>
              <span class="text-slate-400">{dryRunResult.latencyMs} ms</span>
              <span class="text-white font-bold">{dryRunResult.verdictMessage}</span>
            </div>

            <div class="inline-flex rounded-lg bg-black/50 border border-white/10 p-0.5 text-[10px]">
              <button
                type="button"
                onclick={() => (dryRunActiveTab = 'response')}
                class="px-2 py-0.5 rounded cursor-pointer {dryRunActiveTab === 'response'
                  ? 'bg-white/20 text-white font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                Corps de Réponse
              </button>
              <button
                type="button"
                onclick={() => (dryRunActiveTab = 'headers')}
                class="px-2 py-0.5 rounded cursor-pointer {dryRunActiveTab === 'headers'
                  ? 'bg-white/20 text-white font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                En-têtes HTTP
              </button>
              <button
                type="button"
                onclick={() => (dryRunActiveTab = 'ast')}
                class="px-2 py-0.5 rounded cursor-pointer {dryRunActiveTab === 'ast'
                  ? 'bg-white/20 text-white font-bold'
                  : 'text-slate-400 hover:text-white'}"
              >
                Trace Taint AST
              </button>
            </div>
          </div>

          <div class="p-3 font-mono text-[11px] bg-[#04070f]">
            {#if dryRunActiveTab === 'response'}
              <pre class="text-slate-200 whitespace-pre-wrap max-h-[180px] overflow-y-auto scrollbar-thin select-text">{dryRunResult.responseBody}</pre>
            {:else if dryRunActiveTab === 'headers'}
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="rounded-lg border border-white/10 bg-black/40 p-2">
                  <div class="text-[10px] text-cyan-300 font-bold mb-1">
                    Requête ({dryRunResult.method} {dryRunResult.targetUrl})
                  </div>
                  <pre class="text-[10px] text-slate-300 whitespace-pre-wrap">{JSON.stringify(
                    { headers: dryRunResult.requestHeaders, payload: dryRunResult.requestPayload },
                    null,
                    2
                  )}</pre>
                </div>
                <div class="rounded-lg border border-white/10 bg-black/40 p-2">
                  <div class="text-[10px] text-amber-300 font-bold mb-1">En-têtes Réponse</div>
                  <pre class="text-[10px] text-slate-300 whitespace-pre-wrap">{JSON.stringify(
                    dryRunResult.responseHeaders,
                    null,
                    2
                  )}</pre>
                </div>
              </div>
            {:else if dryRunResult.astDetails}
              <div class="space-y-1.5 text-slate-200">
                <div>
                  <span class="text-slate-400">Chaîne Taint :</span>
                  <span class="text-cyan-300 font-bold">{dryRunResult.astDetails.taintChain}</span>
                </div>
                <div>
                  <span class="text-slate-400">Règle Sink :</span>
                  <span class="text-amber-300">{dryRunResult.astDetails.sinkRule}</span>
                </div>
                <div class="flex items-center gap-4">
                  <span>
                    <span class="text-slate-400">Sanitizer :</span>
                    {#if dryRunResult.astDetails.sanitizerDetected}
                      <span class="text-emerald-300 font-bold">Oui</span>
                    {:else}
                      <span class="text-rose-300 font-bold">Non détecté</span>
                    {/if}
                  </span>
                  <span>
                    <span class="text-slate-400">Confiance :</span>
                    <span class="text-white font-bold">{Math.round(dryRunResult.astDetails.confidence * 100)}%</span>
                  </span>
                </div>
              </div>
            {:else}
              <div class="text-slate-400">
                Télémetrie HTTP Live capturée sans simulation AST ({dryRunResult.latencyMs} ms).
              </div>
            {/if}
          </div>
        </div>
      {/if}

      <!-- Main Formatted or Code Document Container -->
      {#if promptFormat === 'bounty_report' && reportRenderMode === 'formatted' && selectedAnomaly}
        <!-- Formatted Structured Report View (XSS-safe native Svelte cards) -->
        <div class="rounded-2xl border border-amber-500/30 bg-[#050811] p-4 space-y-4">
          <div class="flex flex-wrap items-start justify-between gap-3 border-b border-white/10 pb-3">
            <div class="space-y-1">
              <div class="flex items-center gap-2 text-xs font-mono">
                <span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-400/40 font-bold">
                  {presetLabel}
                </span>
                <span
                  class="px-2 py-0.5 rounded font-bold {selectedAnomaly.severity === 'CRITICAL'
                    ? 'bg-rose-500/25 text-rose-200 border border-rose-500/40'
                    : 'bg-amber-500/20 text-amber-200 border border-amber-500/40'}"
                >
                  {selectedAnomaly.severity} · CVSS {selectedAnomaly.severity === 'CRITICAL' ? '9.8' : '7.5'}
                </span>
                <span class="text-slate-400">{selectedAnomaly.cwe_class || 'CWE'}</span>
              </div>
              <h3 class="text-base font-bold text-white">
                {selectedAnomaly.cve_id} — {selectedAnomaly.title || selectedAnomaly.message || 'Vulnérabilité In-Scope'}
              </h3>
              <div class="text-[11px] font-mono text-cyan-300">
                📁 {selectedAnomaly.file_path}:{selectedAnomaly.line_number || 1} · Paramètre :
                <span class="text-amber-300 font-bold">{selectedAnomaly.transmitted_data || 'payload'}</span>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div class="rounded-xl border border-white/10 bg-black/30 p-3 space-y-1.5">
              <div class="text-[11px] font-bold font-mono text-slate-200">1. Root Cause & Description</div>
              <p class="text-xs text-slate-300 leading-relaxed">
                {selectedAnomaly.description ||
                  selectedAnomaly.message ||
                  'Validation insuffisante des données non fiables jusqu’au sink critique.'}
              </p>
              <div class="pt-1.5 text-[11px] font-mono text-cyan-200 bg-cyan-950/25 border border-cyan-500/20 rounded-lg px-2.5 py-1.5">
                🌊 Direction Data : {dataDirection.taintSummary}
              </div>
            </div>

            <div class="rounded-xl border border-emerald-500/25 bg-emerald-950/10 p-3 space-y-1.5">
              <div class="text-[11px] font-bold font-mono text-emerald-300 flex items-center gap-1.5">
                <ShieldCheck class="w-3.5 h-3.5" />
                <span>2. Remédiation Gold Standard</span>
              </div>
              <p class="text-xs text-slate-200 leading-relaxed">
                {selectedAnomaly.remediation ||
                  "Appliquer une validation stricte du type et des bornes sur le paramètre d'entrée avant le sink."}
              </p>
              {#if activeRecommendation?.reason}
                <div class="text-[11px] text-amber-200/90 pt-1">
                  <strong>Impact métier :</strong> {activeRecommendation.reason}
                </div>
              {/if}
            </div>
          </div>

          {#if codeLines.length > 0}
            <div class="rounded-xl border border-white/10 bg-[#03050b] overflow-hidden">
              <div class="px-3 py-1.5 border-b border-white/10 text-[10.5px] font-mono text-slate-400">
                Extrait Code Vulnérable ({selectedAnomaly.file_path})
              </div>
              <div class="p-2 font-mono text-[11px] max-h-[200px] overflow-y-auto scrollbar-thin">
                {#each codeLines.slice(0, 35) as line}
                  <div class="flex items-start gap-2 px-1.5 py-0.5 rounded {line.isFaulty ? 'bg-rose-500/15' : ''}">
                    <span class="w-9 text-right shrink-0 select-none text-slate-500">{line.num}</span>
                    <span class="flex-1 whitespace-pre-wrap break-all">
                      {#each tokenizeLine(line.text) as tok}
                        <span class={tok.cls}>{tok.text}</span>
                      {/each}
                    </span>
                  </div>
                {/each}
              </div>
            </div>
          {/if}
        </div>
      {:else if isCodeHighlightedFormat}
        <!-- Syntax-Highlighted Monospace Code View -->
        <div class="rounded-2xl border border-white/10 bg-[#03060d] overflow-hidden shadow-inner">
          <div class="p-3 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-[430px] overflow-y-auto scrollbar-thin select-text">
            {#each contentLines as rawLine, idx}
              <div class="flex items-start gap-3 hover:bg-white/[0.03] px-1 rounded">
                <span class="w-8 text-right text-slate-600 select-none shrink-0">{idx + 1}</span>
                <span class="flex-1 whitespace-pre">
                  {#each tokenizeLine(rawLine) as tok}
                    <span class={tok.cls}>{tok.text}</span>
                  {/each}
                </span>
              </div>
            {/each}
          </div>
        </div>
      {:else}
        <!-- Prompt / Markdown / Gold Patch Clean Reader -->
        <div class="rounded-2xl border border-cyan-500/25 bg-[#040711] overflow-hidden">
          <pre class="p-4 font-mono text-[11.5px] leading-relaxed text-slate-100 whitespace-pre-wrap max-h-[450px] overflow-y-auto scrollbar-thin select-text">{activeContentText}</pre>
        </div>
      {/if}
    {/if}
  </div>

  <!-- Step 4 Bottom Studio Action Bar -->
  <div class="px-4 py-2.5 border-t border-white/10 bg-[#0b101b] flex flex-wrap items-center justify-between gap-2 shrink-0">
    <button
      type="button"
      onclick={onGoPrevStep}
      class="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-slate-200 text-xs font-mono cursor-pointer"
    >
      <ArrowLeft class="w-3.5 h-3.5" />
      <span>Étape 3 : Code & Direction Data</span>
    </button>

    <div class="flex flex-wrap items-center gap-2">
      <button
        type="button"
        onclick={onDownloadScopeJson}
        class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-slate-200 text-xs font-mono cursor-pointer"
      >
        <FileJson class="w-3.5 h-3.5 text-sky-400" />
        <span>Export JSON</span>
      </button>

      {#if selectedAnomaly}
        <button
          type="button"
          onclick={onSaveReportToWorkspace}
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/40 text-emerald-200 text-xs font-mono font-bold cursor-pointer"
        >
          <Save class="w-3.5 h-3.5" />
          <span>Sauver .aether/</span>
        </button>

        <button
          type="button"
          onclick={onDownloadReportMd}
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/40 text-amber-200 text-xs font-mono font-bold cursor-pointer"
        >
          <Download class="w-3.5 h-3.5" />
          <span>Télécharger Rapport .md</span>
        </button>
      {/if}

      <button
        type="button"
        onclick={onSendPocMissionToMcp}
        class="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-sky-500 hover:from-cyan-400 hover:to-sky-400 text-slate-950 font-extrabold text-xs font-mono shadow-lg shadow-cyan-500/20 cursor-pointer"
      >
        <Send class="w-3.5 h-3.5" />
        <span>{sentToMcp ? 'Transmis au Copilote MCP ✓' : 'Transmettre Mission PoC au Copilote MCP'}</span>
      </button>
    </div>
  </div>
</div>
