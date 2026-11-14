<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import SearchDropdownPanel from './SearchDropdownPanel.svelte';
import { generateAuditMarkdown, generateAuditHtml, downloadBlob } from '../lib/auditReport';
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
    FolderOpen,
    FolderTree,
    RefreshCw,
    Bot,
    Plug,
    CheckSquare,
    FilePlus2,
    Camera,
    Pause,
    Play,
    Code2,
    BookOpen,
    Tag,
    Activity,
    X,
    Volume2,
    VolumeX,
    FileDown,
    Download
  } from '@lucide/svelte';

  let folderInput = $state('');
  let isAnalyzingBar = $state(false);

  // Omnibox Search state
  let searchQuery = $state('');
  let isSearchDropdownOpen = $state(false);
  let searchInputEl = $state<HTMLInputElement | null>(null);

  // Global Security Audit Export Dropdown State
  let isAuditMenuOpen = $state(false);

  function exportAuditMarkdown() {
    const md = generateAuditMarkdown(cockpitState);
    const proj = (cockpitState.graph.project_name || 'project').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    downloadBlob(md, `audit-report-${proj}-${Date.now()}.md`, 'text/markdown;charset=utf-8');
    isAuditMenuOpen = false;
  }

  function exportAuditHtml() {
    const html = generateAuditHtml(cockpitState);
    const proj = (cockpitState.graph.project_name || 'project').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    downloadBlob(html, `audit-report-${proj}-${Date.now()}.html`, 'text/html;charset=utf-8');
    isAuditMenuOpen = false;
  }

  $effect(() => {
    const p = cockpitState.graph.project_path;
    if (p) folderInput = p;
  });

  async function analyzeFolderFromBar(e?: Event) {
    e?.preventDefault();
    const target = folderInput.trim() || cockpitState.graph.project_path || '.';
    if (isAnalyzingBar) return;
    isAnalyzingBar = true;
    cockpitState.isScanningProject = true;
    cockpitState.scanningTargetPath = target;
    try {
      const g = await api.analyzeProject(target, cockpitState.settings.exclusions);
      if (g && Array.isArray(g.nodes)) {
        cockpitState.setGraph(g);
        cockpitState.requestCameraFit();
      }
    } finally {
      isAnalyzingBar = false;
      cockpitState.isScanningProject = false;
    }
  }

  async function browseFolderFromBar() {
    if (isAnalyzingBar) return;
    isAnalyzingBar = true;
    try {
      const res = await api.pickProject();
      if (res?.project_path) folderInput = res.project_path;
      if (res?.graph && Array.isArray(res.graph.nodes)) {
        cockpitState.setGraph(res.graph);
        cockpitState.requestCameraFit();
      }
    } catch {
      cockpitState.isHubModalOpen = true;
    } finally {
      isAnalyzingBar = false;
    }
  }

  async function browseWorkspaceFromBar() {
    if (isAnalyzingBar) return;
    try {
      const res = await api.pickWorkspace();
      if (res?.workspace) {
        folderInput = res.workspace;
        analyzeFolderFromBar();
      }
    } catch {
      cockpitState.isHubModalOpen = true;
    }
  }

  async function switchViewMode(mode: 'code' | 'vault') {
    cockpitState.viewMode = mode;
    try {
      await api.switchViewMode(mode);
    } catch (e) {
      console.warn('Erreur bascule viewMode:', e);
    }
  }

  function toggleFolderBadges() {
    cockpitState.settings.showFolderBadges = !cockpitState.settings.showFolderBadges;
    cockpitState.saveLocalSettings();
  }

  function openSearch() {
    isSearchDropdownOpen = true;
  }

  function closeSearch() {
    isSearchDropdownOpen = false;
  }

  function handleSearchKeyDown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      searchInputEl?.focus();
      isSearchDropdownOpen = true;
    }
  }
</script>

<svelte:window onkeydown={handleSearchKeyDown} />

<!-- Backdrop overlay and detached portal search dropdown -->
{#if isSearchDropdownOpen}
  <div
    class="fixed inset-0 z-40 bg-black/20"
    onclick={closeSearch}
    role="presentation"
  ></div>
  <SearchDropdownPanel
    bind:query={searchQuery}
    isOpen={isSearchDropdownOpen}
    anchorEl={searchInputEl}
    onClose={closeSearch}
  />
{/if}

<header class="relative flex flex-col border-b border-white/10 bg-[#090b10]/95 backdrop-blur-md select-none z-50 shrink-0 shadow-lg">
  <!-- ========================================================================= -->
  <!-- LIGNE 1 : BRAND, HUB PROJET, WORKSPACE/CHEMIN, RECHERCHE OMNIBOX & STATS (h-10 / 40px) -->
  <!-- ========================================================================= -->
  <div class="h-10 px-3 flex items-center justify-between gap-2 border-b border-white/5 overflow-x-auto flex-nowrap scrollbar-none">
    <!-- Zone 1-A : Brand & Projet Actif -->
    <div class="flex items-center gap-2 shrink-0">
      <div class="flex items-center gap-1.5 font-bold text-xs tracking-tight text-white shrink-0">
        <span class="text-sky-400 text-sm">🪐</span>
        <span class="bg-gradient-to-r from-sky-400 via-indigo-300 to-purple-300 bg-clip-text text-transparent font-extrabold tracking-wide whitespace-nowrap">
          AetherScope
        </span>
      </div>

      <!-- Bouton Hub Multi-Architectures / Projet Actif -->
      <button
        onclick={() => (cockpitState.isHubModalOpen = true)}
        title="Hub Multi-Architectures : Créer Projet (7 Stacks), Changer de Dépôt, Export HTML"
        class="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-md font-mono bg-sky-950/60 hover:bg-sky-900/80 border border-sky-500/35 text-sky-300 max-w-[140px] xl:max-w-[200px] truncate cursor-pointer transition-colors shadow-xs"
      >
        <FolderGit2 class="w-3.5 h-3.5 shrink-0 text-sky-400" />
        <span class="truncate font-semibold">{cockpitState.graph.project_name || 'Projet'}</span>
        <span
          class="w-1.5 h-1.5 rounded-full shrink-0 {cockpitState.liveConnected ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]' : 'bg-slate-500'}"
          title={cockpitState.liveConnected ? `Watch Temps Réel Actif (v${cockpitState.graphVersion})` : 'Mode Hors-Ligne / Statique'}
        ></span>
        <span class="text-sky-400 font-bold ml-0.5">+</span>
      </button>

      <!-- Barre de saisie de Chemin Projet + Analyser + Parcourir -->
      <form
        onsubmit={analyzeFolderFromBar}
        class="hidden sm:flex items-center rounded-lg bg-white/[0.04] border border-white/10 focus-within:border-sky-400/60 px-1.5 py-0.5 gap-1 shadow-xs"
        title="Chemin du dossier ou workspace actif"
      >
        <button
          type="button"
          onclick={browseFolderFromBar}
          disabled={isAnalyzingBar}
          title="Parcourir un projet unique..."
          class="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-white/10 transition-colors cursor-pointer shrink-0 disabled:opacity-50"
        >
          <FolderOpen class="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onclick={browseWorkspaceFromBar}
          disabled={isAnalyzingBar}
          title="Parcourir le dossier racine Workspace..."
          class="p-1 rounded text-slate-400 hover:text-emerald-300 hover:bg-white/10 transition-colors cursor-pointer shrink-0 disabled:opacity-50"
        >
          <FolderTree class="w-3.5 h-3.5" />
        </button>
        <input
          type="text"
          bind:value={folderInput}
          placeholder="Chemin absolu ou URL..."
          class="w-28 sm:w-36 md:w-52 lg:w-64 xl:w-72 bg-transparent border-none outline-none text-[11px] font-mono text-slate-200 placeholder:text-slate-500 px-1"
        />
        <button
          type="submit"
          disabled={isAnalyzingBar}
          title="Lancer l'analyse AST du dossier"
          class="flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/20 hover:bg-sky-500/35 border border-sky-400/40 text-sky-200 text-[10.5px] font-semibold transition-colors cursor-pointer shrink-0 disabled:opacity-50"
        >
          <RefreshCw class="w-3 h-3 {isAnalyzingBar ? 'animate-spin' : ''}" />
          <span class="hidden md:inline">{isAnalyzingBar ? '...' : 'Analyser'}</span>
        </button>
      </form>
    </div>

    <!-- Zone 1-B : Omnibox Recherche Globale ("La Totale") -->
    <div class="relative flex items-center justify-center flex-1 min-w-[200px] max-w-lg mx-2 z-50">
      <div class="w-full flex items-center justify-between gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] hover:bg-white/[0.07] focus-within:bg-white/[0.08] border border-white/10 focus-within:border-sky-400/60 transition-all shadow-xs group">
        <Search class="w-3.5 h-3.5 shrink-0 text-slate-400 group-focus-within:text-sky-400 transition-colors" />
        <input
          bind:this={searchInputEl}
          type="text"
          bind:value={searchQuery}
          onfocus={openSearch}
          onclick={openSearch}
          placeholder="Rechercher fonctions, appels, fichiers, CWE..."
          class="flex-1 min-w-0 bg-transparent border-none outline-none text-xs text-white placeholder-slate-500 font-mono"
        />
        {#if searchQuery}
          <button
            type="button"
            onclick={() => { searchQuery = ''; searchInputEl?.focus(); }}
            class="text-slate-400 hover:text-white text-xs px-1 cursor-pointer"
            title="Effacer"
          >
            <X class="w-3.5 h-3.5" />
          </button>
        {/if}
        <kbd class="hidden sm:inline-block shrink-0 px-1.5 py-0.5 text-[9.5px] font-mono rounded bg-white/10 text-slate-300 border border-white/10">
          ⌘K
        </kbd>
      </div>
    </div>

    <!-- Zone 1-C : Métriques Globales, Contrôles Moteur & Settings -->
    <div class="flex items-center gap-1.5 shrink-0">
      <!-- Badge Métriques Graphe -->
      <div
        class="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-md bg-white/[0.03] border border-white/10 font-mono text-[11px] text-slate-300"
        title="Nombre de symboles et dépendances dans le graphe"
      >
        <span class="flex items-center gap-1">
          <span class="w-2 h-2 rounded-full bg-sky-400"></span>
          <span>{cockpitState.graph.nodes.length} nœuds</span>
        </span>
        <span class="text-white/20">|</span>
        <span class="text-slate-400">{cockpitState.graph.edges.length} liens</span>
      </div>

      <!-- Contrôles Moteur (Recadrer, Pause Physique, Snapshot) -->
      <div class="flex items-center p-0.5 bg-white/[0.03] border border-white/10 rounded-md gap-0.5 text-[11px]">
        <button
          onclick={() => cockpitState.requestCameraFit()}
          title="Recadrer la vue caméra sur le graphe (F)"
          class="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-white/10 transition-colors cursor-pointer"
        >
          <Maximize2 class="w-3.5 h-3.5" />
        </button>
        <button
          onclick={() => cockpitState.togglePhysicsPaused()}
          title={cockpitState.physicsPaused ? 'Reprendre la simulation physique (P)' : 'Mettre en pause la gravité/physique (P)'}
          class="p-1 rounded transition-colors cursor-pointer {cockpitState.physicsPaused ? 'bg-amber-500/25 text-amber-300' : 'text-slate-400 hover:text-white hover:bg-white/10'}"
        >
          {#if cockpitState.physicsPaused}<Play class="w-3.5 h-3.5" />{:else}<Pause class="w-3.5 h-3.5" />{/if}
        </button>
        <button
          onclick={() => cockpitState.requestSnapshot()}
          title="Capturer un Snapshot PNG haute résolution"
          class="p-1 rounded text-slate-400 hover:text-emerald-300 hover:bg-white/10 transition-colors cursor-pointer"
        >
          <Camera class="w-3.5 h-3.5" />
        </button>
      </div>

      <!-- Bascule Audio 1-Clic Mute / Unmute -->
      <button
        type="button"
        onclick={() => cockpitState.toggleSound()}
        class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-mono transition-colors cursor-pointer border {cockpitState.settings.soundEnabled ? 'bg-sky-500/15 hover:bg-sky-500/25 border-sky-500/35 text-sky-300' : 'bg-white/[0.03] hover:bg-white/[0.07] border-white/10 text-slate-500'}"
        title={cockpitState.settings.soundEnabled ? "Couper l'audio WebAudio (Mute 1-Clic)" : "Activer l'audio WebAudio (Unmute 1-Clic)"}
      >
        {#if cockpitState.settings.soundEnabled}
          <Volume2 class="w-3.5 h-3.5 text-sky-400" />
          <span class="hidden 2xl:inline text-[11px] font-sans">Son ON</span>
        {:else}
          <VolumeX class="w-3.5 h-3.5 text-slate-500" />
          <span class="hidden 2xl:inline text-[11px] font-sans">Mute</span>
        {/if}
      </button>

      <!-- Configuration / Préférences Globales -->
      <button
        onclick={() => (cockpitState.isSettingsModalOpen = true)}
        class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-white/[0.04] hover:bg-white/10 border border-white/10 text-slate-200 transition-colors cursor-pointer shadow-xs"
        title="Préférences Cockpit (Affichage, Exclusions, 120+ Règles CWE) (S)"
      >
        <Settings class="w-3.5 h-3.5 text-sky-400" />
        <span class="hidden xl:inline text-[11px]">Options</span>
      </button>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- LIGNE 2 : CONTINUUM SPATIAL, MODES DE VISION & DÉCLENCHEURS DE MODALES (h-9 / 36px) -->
  <!-- ========================================================================= -->
  <div class="h-9 px-3 flex items-center justify-between gap-2 bg-[#06080e]/95 overflow-x-auto flex-nowrap scrollbar-none text-xs">
    <!-- Zone 2-A : Dual-Vision, LoD & Filtres Visuels -->
    <div class="flex items-center gap-1.5 shrink-0">
      <!-- Bascule Dual-Vision (Code AST vs Obsidian Vault) -->
      <div class="flex items-center bg-white/[0.04] border border-white/10 rounded-md p-0.5 gap-0.5">
        <button
          onclick={() => switchViewMode('code')}
          class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer {cockpitState.viewMode === 'code' ? 'bg-sky-500/25 border border-sky-400/40 text-sky-200' : 'text-slate-400 hover:text-white'}"
          title="Vision 1 : Architecture & AST Code (Alt+1)"
        >
          <Code2 class="w-3 h-3 text-sky-400" />
          <span class="hidden md:inline">Code AST</span>
        </button>
        <button
          onclick={() => switchViewMode('vault')}
          class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer {cockpitState.viewMode === 'vault' ? 'bg-emerald-500/25 border border-emerald-400/40 text-emerald-200' : 'text-slate-400 hover:text-white'}"
          title="Vision 2 : Graphe de Notes & Wikilinks Obsidian (Alt+2)"
        >
          <BookOpen class="w-3 h-3 text-emerald-400" />
          <span class="hidden md:inline">Vault Notes</span>
        </button>
      </div>

      <!-- Sélecteur Niveau de Détail (LoD Continuum) -->
      <div class="flex items-center p-0.5 bg-white/[0.03] border border-white/10 rounded-md gap-0.5 text-[11px] font-mono">
        <select
          onchange={(e) => (cockpitState.lodLevel = parseInt(e.currentTarget.value, 10) as 1 | 2 | 3)}
          class="bg-transparent border-none text-sky-300 font-medium text-[11px] focus:outline-none cursor-pointer py-0.5 px-1.5"
          value={cockpitState.lodLevel}
          title="Continuum Spatial / Niveau de Détail (Touches 1, 2, 3)"
        >
          <option value={1} class="bg-[#0b0e17] text-white">🌌 Z-1 Galaxie Fichiers</option>
          <option value={2} class="bg-[#0b0e17] text-white">🌐 Z-2 Architecture Modules</option>
          <option value={3} class="bg-[#0b0e17] text-white">⚙️ Z-3 Flux DAG d'Exécution</option>
        </select>
      </div>

      <!-- Toggle Badges Noms de Dossiers -->
      <button
        onclick={toggleFolderBadges}
        class="hidden xl:flex items-center gap-1 px-2 py-0.5 rounded-md border text-[11px] font-mono transition-colors cursor-pointer {cockpitState.settings.showFolderBadges ? 'bg-sky-500/15 border-sky-500/30 text-sky-300' : 'bg-white/[0.02] border-white/5 text-slate-500 hover:text-slate-300'}"
        title="Afficher/Masquer automatiquement les étiquettes de dossiers sur le graphe"
      >
        <Tag class="w-3 h-3" />
        <span>Dossiers: <strong>{cockpitState.settings.showFolderBadges ? 'ON' : 'OFF'}</strong></span>
      </button>

      <!-- Modes de Vision Analytiques -->
      <div class="flex items-center bg-white/[0.03] border border-white/10 rounded-md p-0.5 gap-0.5" title="Filtres de Vision Analytique">
        <button
          onclick={() => (cockpitState.visionMode = 'standard')}
          class="px-1.5 py-0.5 rounded text-[10.5px] font-semibold transition-colors {cockpitState.visionMode === 'standard' ? 'bg-sky-500/25 text-sky-300' : 'text-slate-400 hover:text-white'}"
          title="Vision Standard (V)"
        >
          🌌 Standard
        </button>
        <button
          onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'xray' ? 'standard' : 'xray')}
          class="p-1 rounded text-slate-400 hover:text-white transition-colors {cockpitState.visionMode === 'xray' ? 'bg-indigo-500/30 text-indigo-300' : ''}"
          title="Mode X-Ray Focus (X)"
        >
          <Eye class="w-3.5 h-3.5" />
        </button>
        <button
          onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'heatmap' ? 'standard' : 'heatmap')}
          class="p-1 rounded text-slate-400 hover:text-white transition-colors {cockpitState.visionMode === 'heatmap' ? 'bg-amber-500/30 text-amber-300' : ''}"
          title="Heatmap Complexité Cyclomatique (H)"
        >
          <Flame class="w-3.5 h-3.5" />
        </button>
        <button
          onclick={() => (cockpitState.visionMode = cockpitState.visionMode === 'deadcode' ? 'standard' : 'deadcode')}
          class="p-1 rounded text-slate-400 hover:text-white transition-colors {cockpitState.visionMode === 'deadcode' ? 'bg-rose-500/30 text-rose-300' : ''}"
          title="Scanner Code Mort & Orphelins (D)"
        >
          <Ghost class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>

    <!-- Zone 2-B : Actions Sécurité, IA Swarm & Tiroirs / Modales -->
    <div class="flex items-center gap-1.5 shrink-0">
      <!-- Groupe Sécurité & Bug Bounty -->
      <button
        onclick={() => (cockpitState.isBountyModalOpen = true)}
        class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-500/12 hover:bg-amber-500/24 border border-amber-500/35 text-amber-300 transition-colors shadow-xs cursor-pointer"
        title="Générateur de Scope & PoC Bug Bounty / Zero-Day (B)"
      >
        <Target class="w-3.5 h-3.5 text-amber-400" />
        <span class="hidden sm:inline">Scope PoC</span>
      </button>

      <button
        onclick={() => {
          cockpitState.activeTab = 'cve';
          cockpitState.isInspectorOpen = true;
        }}
        class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold bg-rose-500/12 hover:bg-rose-500/24 border border-rose-500/35 text-rose-300 transition-colors shadow-xs cursor-pointer"
        title="Audit SAST & Failles CWE ({cockpitState.allViolations.length} violations détectées)"
      >
        <ShieldAlert class="w-3.5 h-3.5 text-rose-400" />
        <span class="font-mono text-[11px] font-bold">{cockpitState.allViolations.length}</span>
      </button>

      <button
        onclick={() => (cockpitState.isSurfaceScannerOpen = true)}
        class="hidden 2xl:flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 transition-colors shadow-xs cursor-pointer"
        title="Scanner de Surface Domaine / IP (DNS, Ports, Headers, .env)"
      >
        <Radar class="w-3.5 h-3.5 text-emerald-400" />
        <span>Surface</span>
      </button>

      <!-- Menu Déroulant Export Rapport d'Audit Global -->
      <div class="relative">
        <button
          type="button"
          onclick={() => (isAuditMenuOpen = !isAuditMenuOpen)}
          class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 transition-colors shadow-xs cursor-pointer"
          title="Exporter le Rapport Global d'Audit de Sécurité (Markdown / HTML)"
        >
          <FileDown class="w-3.5 h-3.5 text-emerald-400" />
          <span class="hidden sm:inline">Rapport d'Audit</span>
          <span class="text-[9px] text-emerald-400">▾</span>
        </button>

        {#if isAuditMenuOpen}
          <div
            class="fixed inset-0 z-50"
            onclick={() => (isAuditMenuOpen = false)}
            role="presentation"
          ></div>

          <div
            class="absolute top-full left-0 mt-1 w-48 bg-[#0b0f19]/98 border border-emerald-500/35 rounded-lg shadow-2xl p-1 z-50 flex flex-col gap-0.5 text-xs font-mono animate-in fade-in zoom-in-95 duration-100"
          >
            <button
              type="button"
              onclick={exportAuditMarkdown}
              class="flex items-center gap-2 px-2.5 py-1.5 rounded hover:bg-white/10 text-slate-200 hover:text-white transition-colors cursor-pointer text-left"
            >
              <Download class="w-3.5 h-3.5 text-sky-400" />
              <span>Format Markdown (.md)</span>
            </button>
            <button
              type="button"
              onclick={exportAuditHtml}
              class="flex items-center gap-2 px-2.5 py-1.5 rounded hover:bg-white/10 text-slate-200 hover:text-white transition-colors cursor-pointer text-left"
            >
              <Download class="w-3.5 h-3.5 text-emerald-400" />
              <span>Format HTML Dark (.html)</span>
            </button>
          </div>
        {/if}
      </div>

      <div class="h-4 w-px bg-white/10 mx-0.5"></div>

      <!-- Groupe Copilote IA & MCP -->
      <button
        onclick={() => (cockpitState.isMcpModalOpen = true)}
        class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-sky-500/12 hover:bg-sky-500/22 border border-sky-500/35 text-sky-300 transition-colors shadow-xs cursor-pointer"
        title="Module MCP IA (10 Outils & Config Claude / Cursor / Antigravity) (C)"
      >
        <Plug class="w-3.5 h-3.5 text-sky-400" />
        <span class="hidden md:inline">MCP</span>
      </button>

      <button
        onclick={() => (cockpitState.isChatOpen = !cockpitState.isChatOpen)}
        class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border transition-colors shadow-xs cursor-pointer {cockpitState.isChatOpen ? 'bg-purple-500/30 border-purple-400 text-purple-100' : 'bg-purple-500/12 hover:bg-purple-500/22 border-purple-500/35 text-purple-200'}"
        title="Journal Copilot IA, Déplacements & Chat Multi-Agents"
      >
        <Bot class="w-3.5 h-3.5 text-purple-300" />
        <span class="hidden lg:inline">Chat IA</span>
        {#if cockpitState.activeAgents.length > 0}
          <span class="px-1 rounded-full bg-emerald-500/25 border border-emerald-400/40 text-emerald-200 font-mono text-[10px]" title="Agents simultanés">
            {cockpitState.activeAgents.length}
          </span>
        {:else if cockpitState.aiChatMessages.length > 0}
          <span class="px-1 rounded-full bg-purple-400/25 text-purple-100 font-mono text-[10px]">
            {cockpitState.aiChatMessages.length}
          </span>
        {/if}
      </button>

      <button
        onclick={() => cockpitState.openPromptModal('context')}
        class="hidden 2xl:flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-indigo-500/12 hover:bg-indigo-500/22 border border-indigo-500/35 text-indigo-300 transition-colors shadow-xs cursor-pointer"
        title="Générateur de Prompt IA Contextuel & Master Blueprint"
      >
        <Sparkles class="w-3.5 h-3.5 text-indigo-400" />
        <span>Prompts</span>
      </button>

      <div class="h-4 w-px bg-white/10 mx-0.5"></div>

      <!-- Groupe Outils, Documentation & Tiroirs -->
      <button
        onclick={() => (cockpitState.isTasksModalOpen = true)}
        class="p-1 rounded-md transition-colors border cursor-pointer {cockpitState.isTasksModalOpen ? 'bg-indigo-500/25 border-indigo-400 text-indigo-200' : 'text-slate-400 hover:text-white hover:bg-white/5 border-white/5'}"
        title="Tableau des Tâches & Quêtes ({cockpitState.tasks.length})"
      >
        <CheckSquare class="w-3.5 h-3.5" />
      </button>

      <button
        onclick={() => (cockpitState.isCreateFileModalOpen = true)}
        class="p-1 rounded-md transition-colors border cursor-pointer {cockpitState.isCreateFileModalOpen ? 'bg-emerald-500/25 border-emerald-400 text-emerald-200' : 'text-slate-400 hover:text-emerald-300 hover:bg-white/5 border-white/5'}"
        title="Créer un Nouveau Fichier IA & Ré-indexer (N)"
      >
        <FilePlus2 class="w-3.5 h-3.5" />
      </button>

      <button
        onclick={() => cockpitState.toggleDocPanel()}
        class="flex items-center gap-1 px-2 py-1 rounded-md transition-colors border cursor-pointer {cockpitState.isDocPanelOpen ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300' : 'text-slate-400 hover:text-white hover:bg-white/5 border-white/5'}"
        title="Documentation EARS & Contrats BLAKE3 (M)"
      >
        <FileText class="w-3.5 h-3.5" />
        <span class="hidden xl:inline text-[11px]">Doc</span>
      </button>

      <button
        onclick={() => (cockpitState.isSynthesisOpen = !cockpitState.isSynthesisOpen)}
        class="hidden 2xl:flex items-center gap-1 px-2 py-1 rounded-md transition-colors border cursor-pointer {cockpitState.isSynthesisOpen ? 'bg-sky-500/20 border-sky-400 text-sky-200' : 'text-slate-400 hover:text-white hover:bg-white/5 border-white/5'}"
        title="Panneau de Synthèse & Flux Écosystème"
      >
        <Activity class="w-3.5 h-3.5" />
        <span class="text-[11px]">Synthèse</span>
      </button>

      <button
        onclick={() => cockpitState.toggleInspector()}
        class="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold transition-colors shadow-xs cursor-pointer {cockpitState.isInspectorOpen ? 'bg-sky-500/25 border border-sky-400 text-sky-200 shadow-[0_0_10px_rgba(56,189,248,0.3)]' : 'bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-300'}"
        title="Inspecteur Latéral (I)"
      >
        <Layers class="w-3.5 h-3.5" />
        <span class="hidden sm:inline">Inspecteur</span>
      </button>
    </div>
  </div>
</header>
