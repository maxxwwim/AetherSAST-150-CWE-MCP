<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import {
    Search,
    Layers,
    ShieldAlert,
    Target,
    Sparkles,
    Radar,
    Settings,
    Eye,
    Flame,
    Ghost,
    Maximize2,
    FileText,
    FolderGit2,
    Bot,
    Plug
  } from '@lucide/svelte';

  function onSearchClick() {
    cockpitState.isCommandPaletteOpen = true;
  }
</script>

<header class="h-11 px-2 border-b border-white/5 bg-[#090b10]/90 backdrop-blur-md flex items-center justify-between gap-2 select-none z-50 overflow-hidden">
  <!-- Left: Brand & Project info -->
  <div class="flex items-center gap-1.5 shrink-0 min-w-0">
    <div class="flex items-center gap-1.5 font-bold text-xs tracking-tight text-white">
      <span class="text-sky-400 text-sm">🪐</span>
      <span class="bg-gradient-to-r from-sky-400 to-indigo-300 bg-clip-text text-transparent font-extrabold tracking-wide">
        AetherScope
      </span>
      <button
        onclick={() => (cockpitState.isHubModalOpen = true)}
        title="Hub Multi-Architectures : Créer Projet (7 Stacks), Analyser, Code/Vault, Export HTML"
        class="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full font-mono bg-sky-950/70 hover:bg-sky-900/80 border border-sky-500/35 text-sky-300 max-w-[140px] truncate cursor-pointer transition-colors"
      >
        <FolderGit2 class="w-3 h-3 shrink-0" />
        <span class="truncate">{cockpitState.graph.project_name || 'Projet'}</span>
        <span class="text-sky-400 font-bold">+</span>
      </button>
    </div>

    <!-- LoD Selector -->
    <div class="hidden md:flex items-center p-0.5 bg-white/[0.03] border border-white/10 rounded-md gap-0.5 text-[11px] font-mono">
      <select
        onchange={(e) => (cockpitState.lodLevel = parseInt(e.currentTarget.value, 10) as 1 | 2 | 3)}
        class="bg-transparent border-none text-sky-300 font-medium text-[11px] focus:outline-none cursor-pointer py-0.5 px-1"
        value={cockpitState.lodLevel}
      >
        <option value={1} class="bg-[#0b0e17] text-white">🌌 Galaxie Fichiers</option>
        <option value={2} class="bg-[#0b0e17] text-white">🌐 Système Multi-Couches</option>
        <option value={3} class="bg-[#0b0e17] text-white">⚙️ Flux DAG</option>
      </select>
      <button
        onclick={() => cockpitState.requestCameraFit()}
        title="Recentrer & Adapter la caméra au graphe"
        class="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-white/10 transition-colors cursor-pointer"
      >
        <Maximize2 class="w-3 h-3" />
      </button>
    </div>
  </div>

  <!-- Center: Omnibox Command Search Trigger -->
  <div class="flex-1 min-w-[110px] max-w-xs lg:max-w-sm mx-1">
    <button
      onclick={onSearchClick}
      class="w-full min-w-0 overflow-hidden flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.07] border border-white/10 text-xs text-slate-400 transition-all group cursor-pointer shadow-xs"
    >
      <div class="flex items-center gap-1.5 min-w-0 flex-1">
        <Search class="w-3.5 h-3.5 shrink-0 text-slate-400 group-hover:text-sky-400 transition-colors" />
        <span class="truncate">Rechercher symboles, CWE...</span>
      </div>
      <kbd class="hidden xl:inline-block shrink-0 px-1.5 py-0.5 text-[10px] font-mono rounded bg-white/10 text-slate-300 border border-white/10">
        ⌘K
      </kbd>
    </button>
  </div>

  <!-- Right: Tooling & Quick Modals -->
  <div class="flex items-center gap-1 shrink-0">
    <!-- Vision Modes -->
    <div class="hidden lg:flex items-center bg-white/[0.03] border border-white/10 rounded-md p-0.5 gap-0.5">
      <button
        onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'xray' ? 'standard' : 'xray')}
        class="p-1 rounded text-slate-400 hover:text-white transition-colors {cockpitState.visionMode === 'xray' ? 'bg-indigo-500/25 text-indigo-300' : ''}"
        title="Mode X-Ray Focus"
      >
        <Eye class="w-3.5 h-3.5" />
      </button>
      <button
        onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'heatmap' ? 'standard' : 'heatmap')}
        class="p-1 rounded text-slate-400 hover:text-white transition-colors {cockpitState.visionMode === 'heatmap' ? 'bg-amber-500/25 text-amber-300' : ''}"
        title="Heatmap Complexité"
      >
        <Flame class="w-3.5 h-3.5" />
      </button>
      <button
        onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'deadcode' ? 'standard' : 'deadcode')}
        class="p-1 rounded text-slate-400 hover:text-white transition-colors {cockpitState.visionMode === 'deadcode' ? 'bg-rose-500/25 text-rose-300' : ''}"
        title="Code Mort & Orphelins"
      >
        <Ghost class="w-3.5 h-3.5" />
      </button>
    </div>

    <!-- MCP IA Bridge & Agents Config -->
    <button
      onclick={() => (cockpitState.isMcpModalOpen = true)}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-sky-500/12 hover:bg-sky-500/22 border border-sky-500/35 text-sky-300 transition-colors shadow-xs cursor-pointer"
      title="Module MCP IA, 10 Outils & Configuration Antigravity / Claude / Cursor"
    >
      <Plug class="w-3.5 h-3.5 text-sky-400" />
      <span class="hidden lg:inline">MCP</span>
    </button>

    <!-- AI Copilot Chat & Live Multi-Agents -->
    <button
      onclick={() => (cockpitState.isChatOpen = !cockpitState.isChatOpen)}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border transition-colors shadow-xs cursor-pointer {cockpitState.isChatOpen ? 'bg-purple-500/30 border-purple-400 text-purple-100' : 'bg-purple-500/12 hover:bg-purple-500/22 border-purple-500/35 text-purple-200'}"
      title="Affichage Multi-Agents IA, Trajectoire & Chat Copilot (C)"
    >
      <Bot class="w-3.5 h-3.5 text-purple-300" />
      <span class="hidden lg:inline">Chat IA</span>
      {#if cockpitState.activeAgents.length > 0}
        <span class="px-1 rounded-full bg-emerald-500/25 border border-emerald-400/40 text-emerald-200 font-mono text-[10px]" title="Agents actifs simultanés">
          {cockpitState.activeAgents.length}
        </span>
      {:else if cockpitState.aiChatMessages.length > 0}
        <span class="px-1 rounded-full bg-purple-400/25 text-purple-100 font-mono text-[10px]">
          {cockpitState.aiChatMessages.length}
        </span>
      {/if}
    </button>

    <!-- Prompt Generator Trigger -->
    <button
      onclick={() => cockpitState.openPromptModal('context')}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-indigo-500/12 hover:bg-indigo-500/22 border border-indigo-500/35 text-indigo-300 transition-colors shadow-xs cursor-pointer"
      title="Générateur de Prompt IA Contextuel & Master Blueprint"
    >
      <Sparkles class="w-3.5 h-3.5 text-indigo-400" />
      <span class="hidden 2xl:inline">Prompts</span>
    </button>

    <!-- Surface Scanner Trigger -->
    <button
      onclick={() => (cockpitState.isSurfaceScannerOpen = true)}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 transition-colors shadow-xs cursor-pointer"
      title="Scanner Surface Domaine / IP (DNS, Ports, Headers, .env)"
    >
      <Radar class="w-3.5 h-3.5 text-emerald-400" />
      <span class="hidden xl:inline">Surface</span>
    </button>

    <!-- Bug Bounty Scope Modal Trigger -->
    <button
      onclick={() => (cockpitState.isBountyModalOpen = true)}
      class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 transition-colors shadow-xs cursor-pointer"
      title="Préparateur de Scope & PoC Bug Bounty"
    >
      <Target class="w-3.5 h-3.5 text-amber-400" />
      <span class="hidden sm:inline">Scope PoC</span>
    </button>

    <!-- SAST / CVE Badge -->
    <button
      onclick={() => {
        cockpitState.activeTab = 'cve';
        cockpitState.isInspectorOpen = true;
      }}
      class="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 transition-colors shadow-xs cursor-pointer"
      title="Audit SAST & Failles CWE"
    >
      <ShieldAlert class="w-3.5 h-3.5 text-rose-400" />
      <span class="font-mono text-[11px] font-bold">{cockpitState.allViolations.length}</span>
    </button>

    <!-- Markdown Doc Reader Button -->
    <button
      onclick={() => cockpitState.toggleDocPanel()}
      class="p-1.5 rounded-md transition-colors border cursor-pointer {cockpitState.isDocPanelOpen ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300' : 'text-slate-400 hover:text-white hover:bg-white/5 border-white/5'}"
      title="Documentation EARS & Contrats BLAKE3"
    >
      <FileText class="w-3.5 h-3.5" />
    </button>

    <!-- Full Settings Modal Trigger -->
    <button
      onclick={() => (cockpitState.isSettingsModalOpen = true)}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-white/[0.04] hover:bg-white/10 border border-white/10 text-slate-200 transition-colors cursor-pointer"
      title="Panneau de Configuration Complet (Affichage, Exclusions, MCP & 120+ Règles CWE)"
    >
      <Settings class="w-3.5 h-3.5 text-sky-400" />
      <span class="hidden lg:inline">Options</span>
    </button>

    <!-- Side Inspector Toggle -->
    <button
      onclick={() => cockpitState.toggleInspector()}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-300 transition-colors shadow-xs"
    >
      <Layers class="w-3.5 h-3.5" />
      <span class="hidden sm:inline">Inspecteur</span>
    </button>
  </div>
</header>
