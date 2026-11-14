<script lang="ts">
  import {
    BOUNTY_PRESETS,
    type BountyPresetId,
    type FolderRecommendation,
    type ProjectFolderStat,
    type ScopePromptMission,
  } from './bountyEngine';
  import {
    Check,
    Copy,
    Download,
    Eye,
    FolderPlus,
    Radar,
    Search,
    Send,
    SlidersHorizontal,
    Sparkles,
  } from '@lucide/svelte';

  interface Props {
    projectFolders: ProjectFolderStat[];
    filteredProjectFolders: ProjectFolderStat[];
    inScopeFoldersList: string[];
    outScopeFoldersList: string[];
    recByFolder: Map<string, FolderRecommendation>;
    excludedFolders: Record<string, boolean>;
    lockedSingleFolder: string;
    folderSearchQuery: string;
    showWildcardEditor: boolean;
    inScopePatternsText: string;
    outScopePatternsText: string;
    activePreset: BountyPresetId | null;
    scopeModeLabel: string;
    scopeUpdatedBy: string;
    scopeRationale: string;
    isolateScopeIn3DGraph: boolean;
    scopePromptMission: ScopePromptMission;
    strictFolderBoundary: boolean;
    includeTopTargetsInPrompt: boolean;
    requireNonDestructivePoc: boolean;
    requireEarsInvariant: boolean;
    customScopeInstructions: string;
    filteredTargetsCount: number;
    step1Prompt: string;
    copiedKey: string | null;
    sentToMcp: boolean;
    onApplyPreset: (id: BountyPresetId) => void;
    onApplyAiRecommended: () => void;
    onSyncOutScope: (author?: string) => void;
    onToggleIsolate3D: () => void;
    onLockSingleFolder: (folder: string) => void;
    onIsolateOnlyFolder: (folder: string) => void;
    onSetAllFoldersScope: (includeAll: boolean) => void;
    onToggleFolderScope: (folder: string) => void;
    onCopyText: (text: string, key: string) => void;
    onSendScopePrompt: () => void;
    onDownloadScopePrompt: () => void;
    onGoNextStep: () => void;
  }

  let {
    projectFolders,
    filteredProjectFolders,
    inScopeFoldersList,
    outScopeFoldersList,
    recByFolder,
    excludedFolders,
    lockedSingleFolder,
    folderSearchQuery = $bindable(),
    showWildcardEditor = $bindable(),
    inScopePatternsText = $bindable(),
    outScopePatternsText = $bindable(),
    activePreset,
    scopeModeLabel,
    scopeUpdatedBy,
    scopeRationale,
    isolateScopeIn3DGraph,
    scopePromptMission = $bindable(),
    strictFolderBoundary = $bindable(),
    includeTopTargetsInPrompt = $bindable(),
    requireNonDestructivePoc = $bindable(),
    requireEarsInvariant = $bindable(),
    customScopeInstructions = $bindable(),
    filteredTargetsCount,
    step1Prompt,
    copiedKey,
    sentToMcp,
    onApplyPreset,
    onApplyAiRecommended,
    onSyncOutScope,
    onToggleIsolate3D,
    onLockSingleFolder,
    onIsolateOnlyFolder,
    onSetAllFoldersScope,
    onToggleFolderScope,
    onCopyText,
    onSendScopePrompt,
    onDownloadScopePrompt,
    onGoNextStep,
  }: Props = $props();
</script>

<div class="flex-1 flex flex-col overflow-hidden bg-[#080b12]">
  <!-- Presets & Scope Telemetry Strip -->
  <div class="px-4 py-2.5 border-b border-white/10 bg-[#0b101b] flex flex-wrap items-center justify-between gap-2 shrink-0">
    <div class="flex flex-wrap items-center gap-1.5">
      <span class="text-[10px] font-mono uppercase tracking-wider text-slate-400 mr-1">
        Presets :
      </span>
      {#each Object.entries(BOUNTY_PRESETS) as [presetKey, preset]}
        <button
          type="button"
          onclick={() => onApplyPreset(presetKey as BountyPresetId)}
          title={preset.rationale}
          class="px-2 py-1 rounded-md text-[10.5px] font-mono border transition-all cursor-pointer {activePreset === presetKey
            ? 'bg-amber-500/25 border-amber-400/60 text-amber-200 font-bold shadow-xs'
            : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
        >
          {preset.badge} {preset.label}
        </button>
      {/each}
    </div>

    <div class="flex items-center gap-1.5 font-mono text-[10.5px]">
      <button
        type="button"
        onclick={onApplyAiRecommended}
        class="flex items-center gap-1 px-2.5 py-1 rounded-md bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/40 text-purple-200 font-semibold cursor-pointer"
      >
        <Sparkles class="w-3.5 h-3.5" />
        <span>Auto-Scope IA</span>
      </button>
      <button
        type="button"
        onclick={() => onSyncOutScope()}
        class="flex items-center gap-1 px-2.5 py-1 rounded-md bg-sky-500/20 hover:bg-sky-500/30 border border-sky-400/40 text-sky-200 font-semibold cursor-pointer"
        title="Enregistrer dans .aether/bounty_scope.json et synchroniser MCP"
      >
        <Radar class="w-3.5 h-3.5" />
        <span>Sync MCP</span>
      </button>
      <button
        type="button"
        onclick={onToggleIsolate3D}
        class="flex items-center gap-1 px-2.5 py-1 rounded-md border transition-colors cursor-pointer {isolateScopeIn3DGraph
          ? 'bg-emerald-500/25 border-emerald-400/60 text-emerald-200 font-bold'
          : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
      >
        <Eye class="w-3.5 h-3.5" />
        <span>{isolateScopeIn3DGraph ? '3D Isolé' : 'Isoler 3D'}</span>
      </button>
    </div>
  </div>

  <!-- Split Workspace: Left Folder Matrix | Right Step 1 Prompt Scope Builder -->
  <div class="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden">
    <!-- Left Column: Folder Scope Limiter & Matrix (5 cols) -->
    <div class="lg:col-span-5 border-b lg:border-b-0 lg:border-r border-white/10 flex flex-col overflow-hidden bg-black/25">
      <div class="p-3 border-b border-white/10 space-y-2.5 shrink-0">
        <!-- Single Folder Lock Bar -->
        <div class="p-2.5 rounded-xl bg-gradient-to-r from-emerald-950/35 via-[#0a111f] to-cyan-950/20 border border-emerald-500/30 space-y-1.5">
          <div class="flex items-center justify-between text-[10.5px] font-mono">
            <span class="text-emerald-300 font-bold flex items-center gap-1">
              <FolderPlus class="w-3.5 h-3.5" />
              <span>Verrou Dossier Unique :</span>
            </span>
            {#if lockedSingleFolder !== 'ALL'}
              <button
                type="button"
                onclick={() => onLockSingleFolder('ALL')}
                class="px-1.5 py-0.5 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-[9.5px] cursor-pointer"
              >
                × Déverrouiller
              </button>
            {/if}
          </div>
          <select
            value={lockedSingleFolder}
            onchange={(e) => onLockSingleFolder((e.currentTarget as HTMLSelectElement).value)}
            aria-label="Limiter le scope à un seul dossier"
            class="w-full px-2.5 py-1.5 rounded-lg bg-[#050811] border border-emerald-500/35 text-[11px] font-mono text-emerald-100 focus:outline-none focus:border-emerald-400 cursor-pointer"
          >
            <option value="ALL">🌐 Multi-dossiers ({inScopeFoldersList.length} / {projectFolders.length} In-Scope)</option>
            {#each projectFolders as item (item.folder)}
              <option value={item.folder}>
                🎯 {item.folder} ({item.count} failles · {item.nodeCount} symboles)
              </option>
            {/each}
          </select>
        </div>

        <!-- Quick Actions + Search + Wildcard Toggle -->
        <div class="flex items-center gap-1.5 text-[10px] font-mono">
          <button
            type="button"
            onclick={() => onSetAllFoldersScope(true)}
            class="flex-1 py-1 px-2 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-200 cursor-pointer"
          >
            ✅ Tout In
          </button>
          <button
            type="button"
            onclick={() => onSetAllFoldersScope(false)}
            class="flex-1 py-1 px-2 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-200 cursor-pointer"
          >
            🧹 Exclure Tests
          </button>
          <button
            type="button"
            onclick={() => (showWildcardEditor = !showWildcardEditor)}
            class="flex items-center gap-1 py-1 px-2.5 rounded border cursor-pointer {showWildcardEditor
              ? 'bg-sky-500/25 border-sky-400/50 text-sky-200 font-bold'
              : 'bg-white/5 border-white/10 text-slate-300'}"
          >
            <SlidersHorizontal class="w-3 h-3" />
            <span>Wildcards</span>
          </button>
        </div>

        <div class="relative">
          <Search class="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
          <input
            type="text"
            bind:value={folderSearchQuery}
            placeholder="Filtrer un dossier (ex: crates/desktop-shell, src...)"
            class="w-full pl-8 pr-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-emerald-400/50"
          />
        </div>

        {#if showWildcardEditor}
          <div class="grid grid-cols-2 gap-2 pt-1">
            <div class="flex flex-col gap-1">
              <span class="text-[9px] font-mono text-emerald-300 uppercase">🎯 In-Scope Wildcards</span>
              <textarea
                bind:value={inScopePatternsText}
                rows="3"
                placeholder="crates/*&#10;src/*&#10;*.rs"
                class="w-full p-1.5 rounded bg-[#050811] border border-emerald-500/30 text-[10px] font-mono text-emerald-100 focus:outline-none resize-none"
              ></textarea>
            </div>
            <div class="flex flex-col gap-1">
              <span class="text-[9px] font-mono text-rose-300 uppercase">🚫 Out-of-Scope Wildcards</span>
              <textarea
                bind:value={outScopePatternsText}
                rows="3"
                placeholder="tests/*&#10;*.test.*&#10;docs/*"
                class="w-full p-1.5 rounded bg-[#050811] border border-rose-500/30 text-[10px] font-mono text-rose-100 focus:outline-none resize-none"
              ></textarea>
            </div>
          </div>
        {/if}
      </div>

      <!-- Folder Matrix List -->
      <div class="flex-1 overflow-y-auto p-2.5 space-y-1.5 scrollbar-thin">
        {#each filteredProjectFolders as item (item.folder)}
          {@const isLockedOnly = lockedSingleFolder === item.folder}
          {@const isOut = lockedSingleFolder !== 'ALL' ? !isLockedOnly : Boolean(excludedFolders[item.folder])}
          {@const rec = recByFolder.get(item.folder)}
          <div
            class="p-2.5 rounded-xl border transition-all flex items-center justify-between gap-2 {isLockedOnly
              ? 'bg-emerald-500/20 border-emerald-400/60 ring-1 ring-emerald-400/30'
              : isOut
                ? 'bg-rose-950/15 border-rose-500/25 opacity-70'
                : 'bg-emerald-950/20 border-emerald-500/30 hover:border-emerald-400/50'}"
          >
            <button
              type="button"
              onclick={() => onToggleFolderScope(item.folder)}
              class="flex-1 min-w-0 text-left cursor-pointer"
            >
              <div class="flex items-center gap-1.5 font-mono text-[11px]">
                <span
                  class="px-1.5 py-0.5 rounded text-[9px] font-bold {isOut
                    ? 'bg-rose-500/25 text-rose-300 border border-rose-500/40'
                    : 'bg-emerald-500/25 text-emerald-200 border border-emerald-500/40'}"
                >
                  {isOut ? '🚫 OUT' : '🎯 IN'}
                </span>
                <span class="font-bold truncate {isOut ? 'text-slate-400 line-through' : 'text-white'}">
                  {item.folder}
                </span>
              </div>
              <div class="flex flex-wrap items-center gap-2 mt-1 text-[9.5px] font-mono text-slate-400">
                <span>{item.nodeCount} symboles</span>
                <span>·</span>
                <span class={item.count > 0 ? 'text-amber-300 font-semibold' : ''}>{item.count} failles</span>
                {#if item.critCount > 0}
                  <span class="text-rose-400 font-bold">({item.critCount} CRIT)</span>
                {/if}
                {#if rec}
                  <span class="text-purple-300">· Score IA {rec.score}</span>
                {/if}
              </div>
            </button>

            <button
              type="button"
              onclick={() => onIsolateOnlyFolder(item.folder)}
              class="px-2.5 py-1 rounded-lg border text-[10px] font-mono shrink-0 transition-colors cursor-pointer {isLockedOnly
                ? 'bg-emerald-500 text-slate-950 font-bold border-emerald-300'
                : 'bg-white/5 hover:bg-emerald-500/25 text-emerald-200 border-emerald-500/30'}"
              title="Limiter tout le Scope exclusivement à ce dossier"
            >
              {isLockedOnly ? '🔒 Isolé' : '🎯 Seul'}
            </button>
          </div>
        {/each}
      </div>
    </div>

    <!-- Right Column: Step 1 Governance & Prompt Scope Preview (7 cols) -->
    <div class="lg:col-span-7 flex flex-col p-4 gap-3 overflow-y-auto scrollbar-thin">
      <!-- Scope Status & Mission Profile -->
      <div class="p-3.5 rounded-xl bg-gradient-to-r from-emerald-950/30 via-[#0d1522] to-sky-950/20 border border-emerald-500/30 space-y-3">
        <div class="flex items-start justify-between gap-2 flex-wrap">
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <span class="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 font-mono text-[10px] font-bold">
                STEP 1 · GOUVERNANCE SCOPE
              </span>
              <span class="text-[10.5px] font-mono text-slate-400">
                Mode: <strong class="text-sky-300">{scopeModeLabel}</strong> · Par: {scopeUpdatedBy}
              </span>
            </div>
            {#if scopeRationale}
              <p class="text-[11px] font-mono text-slate-300 mt-1.5">{scopeRationale}</p>
            {/if}
          </div>
          <div class="flex items-center gap-1.5 font-mono text-[10.5px]">
            <span class="px-2 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-bold">
              {inScopeFoldersList.length} IN
            </span>
            <span class="px-2 py-1 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-300 font-bold">
              {outScopeFoldersList.length} OUT
            </span>
            <span class="px-2 py-1 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-200 font-bold">
              {filteredTargetsCount} cibles
            </span>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-white/10 text-xs font-mono">
          <div class="space-y-1.5">
            <span class="text-[10px] font-bold text-sky-300 uppercase">🎯 Mission du Prompt Step 1</span>
            <div class="grid grid-cols-2 gap-1.5">
              <button
                type="button"
                onclick={() => (scopePromptMission = 'audit_strict')}
                class="px-2.5 py-1.5 rounded-lg text-[10.5px] text-left border cursor-pointer {scopePromptMission === 'audit_strict'
                  ? 'bg-emerald-500/25 border-emerald-400/50 text-emerald-200 font-bold'
                  : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
              >
                🔒 Prison Dossier Strict
              </button>
              <button
                type="button"
                onclick={() => (scopePromptMission = 'poc_batch')}
                class="px-2.5 py-1.5 rounded-lg text-[10.5px] text-left border cursor-pointer {scopePromptMission === 'poc_batch'
                  ? 'bg-rose-500/25 border-rose-400/50 text-rose-200 font-bold'
                  : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
              >
                💥 Validation PoC
              </button>
              <button
                type="button"
                onclick={() => (scopePromptMission = 'patch_ears')}
                class="px-2.5 py-1.5 rounded-lg text-[10.5px] text-left border cursor-pointer {scopePromptMission === 'patch_ears'
                  ? 'bg-sky-500/25 border-sky-400/50 text-sky-200 font-bold'
                  : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
              >
                🛡️ Remédiation EARS
              </button>
              <button
                type="button"
                onclick={() => (scopePromptMission = 'mcp_autonomous')}
                class="px-2.5 py-1.5 rounded-lg text-[10.5px] text-left border cursor-pointer {scopePromptMission === 'mcp_autonomous'
                  ? 'bg-purple-500/25 border-purple-400/50 text-purple-200 font-bold'
                  : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
              >
                🤖 Agent MCP Autonome
              </button>
            </div>
          </div>

          <div class="space-y-1.5">
            <span class="text-[10px] font-bold text-purple-300 uppercase">🛡️ Garde-Fous IA</span>
            <label class="flex items-center gap-2 text-[11px] text-slate-200 cursor-pointer">
              <input type="checkbox" bind:checked={strictFolderBoundary} class="accent-emerald-500 cursor-pointer" />
              <span>Interdire lecture/écriture Hors-Scope</span>
            </label>
            <label class="flex items-center gap-2 text-[11px] text-slate-200 cursor-pointer">
              <input type="checkbox" bind:checked={requireNonDestructivePoc} class="accent-emerald-500 cursor-pointer" />
              <span>Exiger PoC non-destructifs</span>
            </label>
            <label class="flex items-center gap-2 text-[11px] text-slate-200 cursor-pointer">
              <input type="checkbox" bind:checked={includeTopTargetsInPrompt} class="accent-emerald-500 cursor-pointer" />
              <span>Inclure les {filteredTargetsCount} cibles du périmètre</span>
            </label>
            <label class="flex items-center gap-2 text-[11px] text-slate-200 cursor-pointer">
              <input type="checkbox" bind:checked={requireEarsInvariant} class="accent-emerald-500 cursor-pointer" />
              <span>Exiger contrat formel EARS</span>
            </label>
          </div>
        </div>

        <input
          type="text"
          bind:value={customScopeInstructions}
          placeholder="Consigne spécifique opérateur (ex: Focus sur la validation JWT et ne pas modifier les migrations)..."
          class="w-full px-3 py-1.5 rounded-lg bg-[#050811] border border-white/15 text-[11px] font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-400"
        />
      </div>

      <!-- Prompt Step 1 Live Preview -->
      <div class="flex-1 min-h-[220px] rounded-xl bg-[#05070f] border border-emerald-500/30 flex flex-col overflow-hidden">
        <div class="px-3.5 py-2 bg-emerald-950/25 border-b border-emerald-500/20 flex items-center justify-between gap-2 flex-wrap text-xs font-mono">
          <span class="text-emerald-300 font-bold">📜 Prompt Step 1 — Périmètre & Règles d'Engagement</span>
          <div class="flex items-center gap-1.5">
            <button
              type="button"
              onclick={onDownloadScopePrompt}
              class="flex items-center gap-1 px-2 py-1 rounded bg-white/10 hover:bg-white/20 text-slate-200 text-[10.5px] cursor-pointer"
            >
              <Download class="w-3 h-3" />
              <span>.md</span>
            </button>
            <button
              type="button"
              onclick={() => onCopyText(step1Prompt, 'step1_prompt')}
              class="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-[10.5px] cursor-pointer"
            >
              {#if copiedKey === 'step1_prompt'}
                <Check class="w-3 h-3" />
                <span>Copié !</span>
              {:else}
                <Copy class="w-3 h-3" />
                <span>Copier Prompt Step 1</span>
              {/if}
            </button>
            <button
              type="button"
              onclick={onSendScopePrompt}
              class="flex items-center gap-1 px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-500 text-white font-bold text-[10.5px] cursor-pointer"
            >
              <Send class="w-3 h-3" />
              <span>{sentToMcp ? 'Envoyé !' : 'Chat MCP'}</span>
            </button>
          </div>
        </div>
        <pre class="flex-1 p-3.5 font-mono text-[11px] leading-relaxed text-emerald-100/95 whitespace-pre-wrap overflow-y-auto scrollbar-thin bg-[#04060c] select-text">{step1Prompt}</pre>
      </div>

      <!-- Footer Step Navigation -->
      <div class="flex items-center justify-between pt-1 shrink-0">
        <span class="text-[11px] font-mono text-slate-400">
          Périmètre prêt : {inScopeFoldersList.length} dossier(s) In-Scope · {filteredTargetsCount} vulnérabilité(s) active(s)
        </span>
        <button
          type="button"
          onclick={onGoNextStep}
          class="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-sky-500 hover:from-emerald-400 hover:to-sky-400 text-slate-950 text-xs font-extrabold font-mono shadow-lg shadow-emerald-500/20 cursor-pointer"
        >
          Étape 2 : Cibles & Fonctions ➔
        </button>
      </div>
    </div>
  </div>
</div>
