<script lang="ts">
  import HeaderDeck from './components/HeaderDeck.svelte';
  import AetherCanvas from './components/AetherCanvas.svelte';
  import InspectorDrawer from './components/InspectorDrawer.svelte';
  import CommandPalette from './components/CommandPalette.svelte';
  import VisionModesDeck from './components/VisionModesDeck.svelte';
  import BountyModal from './components/BountyModal.svelte';
  import SettingsModal from './components/SettingsModal.svelte';
  import PromptGeneratorModal from './components/PromptGeneratorModal.svelte';
  import SurfaceScannerModal from './components/SurfaceScannerModal.svelte';
  import DocReaderDrawer from './components/DocReaderDrawer.svelte';
  import ProjectHubModal from './components/ProjectHubModal.svelte';
  import SynthesisHud from './components/SynthesisHud.svelte';
  import CanvasTooltip from './components/CanvasTooltip.svelte';
  import AiChatDrawer from './components/AiChatDrawer.svelte';
  import McpControlModal from './components/McpControlModal.svelte';
  import VisionModeHuds from './components/VisionModeHuds.svelte';
  import TasksModal from './components/TasksModal.svelte';
  import CreateFileModal from './components/CreateFileModal.svelte';
  import IgnoredCweModal from './components/IgnoredCweModal.svelte';
  import IdeView from './components/ide/IdeView.svelte';
  import { cockpitState } from './state/graphState.svelte';
  import { api } from './lib/api';
  import { DEMO_AETHER_GRAPH, DEMO_TASKS, DEMO_GIT_STATUS, DEMO_ACTIVE_AGENTS } from './data/demoGraph';
  import { onMount } from 'svelte';

  function handleGlobalKeydown(e: KeyboardEvent) {
    const target = e.target as HTMLElement | null;
    const tag = target?.tagName?.toLowerCase() || '';
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || target?.isContentEditable) {
      return;
    }

    // Alt+1, Alt+2, and Alt+3 view modes (Code AST vs Obsidian Vault Notes vs IDE)
    if (e.altKey && !e.ctrlKey && !e.metaKey) {
      if (e.key === '1' || e.code === 'Digit1') {
        e.preventDefault();
        cockpitState.viewMode = 'code';
        api.switchViewMode('code').catch(() => {});
        return;
      }
      if (e.key === '2' || e.code === 'Digit2') {
        e.preventDefault();
        cockpitState.viewMode = 'vault';
        api.switchViewMode('vault').catch(() => {});
        return;
      }
      if (e.key === '3' || e.code === 'Digit3') {
        e.preventDefault();
        cockpitState.viewMode = 'ide';
        api.switchViewMode('ide').catch(() => {});
        return;
      }
    }

    // Ctrl+0 or Meta+0 (Zoom reset / Fit camera)
    if ((e.ctrlKey || e.metaKey) && (e.key === '0' || e.code === 'Digit0')) {
      e.preventDefault();
      cockpitState.requestCameraFit();
      return;
    }

    // Guard: ignore single-key hotkeys when Ctrl or Meta or Alt is pressed
    if (e.ctrlKey || e.metaKey || e.altKey) {
      return;
    }

    // Zoom in / out shortcuts (+, -, =, NumpadAdd, NumpadSubtract, 0)
    if (e.key === '+' || e.key === '=' || e.code === 'NumpadAdd') {
      e.preventDefault();
      if (cockpitState.engine) {
        cockpitState.engine.zoomIn();
      } else {
        const canvas = document.getElementById('aether-canvas');
        canvas?.dispatchEvent(new WheelEvent('wheel', { deltaY: -120, clientX: window.innerWidth / 2, clientY: window.innerHeight / 2 }));
      }
      return;
    }
    if (e.key === '-' || e.key === '_' || e.code === 'NumpadSubtract') {
      e.preventDefault();
      if (cockpitState.engine) {
        cockpitState.engine.zoomOut();
      } else {
        const canvas = document.getElementById('aether-canvas');
        canvas?.dispatchEvent(new WheelEvent('wheel', { deltaY: 120, clientX: window.innerWidth / 2, clientY: window.innerHeight / 2 }));
      }
      return;
    }
    if (e.key === '0' || e.code === 'Numpad0') {
      e.preventDefault();
      cockpitState.engine?.resetZoom();
      return;
    }

    const k = e.key.toLowerCase();
    switch (k) {
      case 'x':
        cockpitState.visionMode = cockpitState.visionMode === 'xray' ? 'standard' : 'xray';
        break;
      case 'd':
        cockpitState.visionMode = cockpitState.visionMode === 'deadcode' ? 'standard' : 'deadcode';
        break;
      case 'h':
        cockpitState.visionMode = cockpitState.visionMode === 'heatmap' ? 'standard' : 'heatmap';
        break;
      case 'v':
        cockpitState.visionMode = 'standard';
        break;
      case 'p':
        cockpitState.togglePhysicsPaused();
        break;
      case 'n':
        cockpitState.isCreateFileModalOpen = !cockpitState.isCreateFileModalOpen;
        break;
      case 's':
        cockpitState.isSettingsModalOpen = !cockpitState.isSettingsModalOpen;
        break;
      case 'c':
        cockpitState.isChatOpen = !cockpitState.isChatOpen;
        break;
      case '1':
        cockpitState.lodLevel = 1;
        cockpitState.activeLayout = 'Z-1';
        break;
      case '2':
        cockpitState.lodLevel = 2;
        cockpitState.activeLayout = 'Z-2';
        break;
      case '3':
        cockpitState.lodLevel = 3;
        cockpitState.activeLayout = 'Z-3';
        break;
      case '4':
        cockpitState.activeLayout = 'Z-4';
        break;
      case 'f':
        cockpitState.requestCameraFit();
        break;
      case 'b':
        cockpitState.isBountyModalOpen = !cockpitState.isBountyModalOpen;
        break;
      case 'u':
        cockpitState.isSurfaceScannerOpen = !cockpitState.isSurfaceScannerOpen;
        break;
      case 'm':
        cockpitState.toggleDocPanel();
        break;
      case 'i':
        cockpitState.toggleInspector();
        break;
    }
  }

  onMount(() => {
    let versionTimer: ReturnType<typeof setInterval> | null = null;

    (async () => {
      // Check if data was injected via window.__AETHERSCOPE_DATA__
      const injected = (window as any).__AETHERSCOPE_DATA__;
      if (injected) {
        cockpitState.setGraph(injected);
      } else {
        try {
          const timeoutPromise = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000));
          const g = await Promise.race([api.getGraph(), timeoutPromise]);
          if (g && Array.isArray(g.nodes) && g.nodes.length > 0) {
            cockpitState.setGraph(g);
            cockpitState.liveConnected = true;
          } else {
            throw new Error('Empty graph');
          }
        } catch (e) {
          console.info('AetherScope: Live backend not detected. Booting interactive standalone demo mode (GitHub Pages).');
          cockpitState.isDemoMode = true;
          cockpitState.setGraph(DEMO_AETHER_GRAPH);
          cockpitState.tasks = DEMO_TASKS;
          cockpitState.gitStatus = DEMO_GIT_STATUS;
          cockpitState.activeAgents = DEMO_ACTIVE_AGENTS;
        }
      }

      // Sync saved CWE settings, tasks count & initial Git status from backend if online
      try {
        const [verRes, tasksList, settingsRes] = await Promise.allSettled([
          api.getGraphVersion(),
          api.getTasks(),
          api.getSettings(),
        ]);
        if (verRes.status === 'fulfilled' && typeof verRes.value?.version === 'number') {
          cockpitState.graphVersion = verRes.value.version;
          cockpitState.liveConnected = true;
        }
        if (tasksList.status === 'fulfilled') {
          cockpitState.tasks = tasksList.value;
        }
        if (settingsRes.status === 'fulfilled' && settingsRes.value) {
          const s = settingsRes.value;
          if (Array.isArray(s.ignored_cwes) && s.ignored_cwes.length > 0) {
            cockpitState.settings.ignoredCwes = s.ignored_cwes;
          }
          if (Array.isArray(s.exclusions) && s.exclusions.length > 0) {
            cockpitState.settings.exclusions = s.exclusions;
          }
          if (Array.isArray(s.active_cve_rules) && s.active_cve_rules.length > 0) {
            cockpitState.settings.activeCveRules = s.active_cve_rules;
          }
          if (typeof s.show_alerts === 'boolean') cockpitState.settings.showAlerts = s.show_alerts;
          if (typeof s.show_cwe_bubbles === 'boolean') cockpitState.settings.showCweBubbles = s.show_cwe_bubbles;
          if (typeof s.show_cwe_titles === 'boolean') cockpitState.settings.showCweTitles = s.show_cwe_titles;
          if (typeof s.show_folder_titles === 'boolean') {
            cockpitState.settings.showFolderTitles = s.show_folder_titles;
            cockpitState.settings.showFolderBadges = s.show_folder_titles;
          }
          if (typeof s.show_file_titles === 'boolean') cockpitState.settings.showFileTitles = s.show_file_titles;
          if (s.ui_settings && typeof s.ui_settings === 'object') {
            Object.assign(cockpitState.settings, s.ui_settings);
          }
          cockpitState.saveLocalSettings(false);
        }
        await cockpitState.fetchGitStatus().catch(() => {});
      } catch {
        // standalone offline mode
      }
    })();

    // Live graph version watcher, Git diff, tasks & AI agent telemetry (polls every 2s)
    let tickCount = 0;
    versionTimer = setInterval(async () => {
      tickCount++;
      if (cockpitState.isDemoMode && !cockpitState.liveConnected) {
        if (tickCount % 10 !== 0) return;
      }
      try {
        const res = await api.getGraphVersion();
        cockpitState.liveConnected = true;
        if (cockpitState.isDemoMode) {
          cockpitState.isDemoMode = false;
        }
        if (typeof res?.version === 'number' && cockpitState.graphVersion > 0 && res.version !== cockpitState.graphVersion) {
          cockpitState.graphVersion = res.version;
          const updated = await api.getGraph();
          cockpitState.setGraph(updated, true);
          await cockpitState.fetchGitStatus(true).catch(() => {});
        } else if (typeof res?.version === 'number' && cockpitState.graphVersion === 0) {
          cockpitState.graphVersion = res.version;
        }
      } catch {
        cockpitState.liveConnected = false;
      }

      // Continuous Git diff status poll
      cockpitState.fetchGitStatus().catch(() => {});

      // Continuous AI telemetry poll so agent avatars orbit and animate on WebGL canvas even when AI chat drawer is closed
      try {
        const teleRes = await api.getTelemetry();
        if (teleRes && (teleRes.telemetry || teleRes.agents || teleRes.history)) {
          cockpitState.recordAiTelemetry(teleRes.telemetry as any, teleRes.agents, teleRes.history);
        }
      } catch {
        // offline or quiet telemetry
      }

      // Periodic tasks poll (every 4s) so AI agent tasks appear in UI automatically
      if (tickCount % 2 === 0) {
        try {
          const tasks = await api.getTasks();
          if (Array.isArray(tasks)) {
            cockpitState.tasks = tasks;
            cockpitState.syncTaskAgentsToTelemetry(tasks);
          }
        } catch {
          // offline or quiet tasks
        }
      }
    }, 2000);

    return () => {
      if (versionTimer) clearInterval(versionTimer);
    };
  });
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<div class="w-full h-screen flex flex-col bg-[#07090e] text-slate-100 overflow-hidden font-sans">
  <HeaderDeck />
  <div class="relative flex-1 w-full min-h-0 overflow-hidden">
    <!-- WebGL Canvas & HUD Overlays (Resident in DOM, hidden via CSS in IDE mode) -->
    <div class="w-full h-full relative" class:hidden={cockpitState.viewMode === 'ide'}>
      <AetherCanvas />
      <CanvasTooltip />
      <VisionModesDeck />
      <VisionModeHuds />
      <SynthesisHud />
    </div>

    <!-- Dedicated Full-Screen IDE View (Retains dirty editor state across view switches) -->
    <div class="w-full h-full absolute inset-0 z-10" class:hidden={cockpitState.viewMode !== 'ide'}>
      <IdeView />
    </div>

    <InspectorDrawer />
    <CommandPalette />
    <BountyModal />
    <SettingsModal />
    <PromptGeneratorModal />
    <SurfaceScannerModal />
    <DocReaderDrawer />
    <ProjectHubModal />
    <AiChatDrawer />
    <McpControlModal />
    <TasksModal />
    <CreateFileModal />
    <IgnoredCweModal />

    {#if cockpitState.isScanningProject}
      <div class="fixed inset-0 z-50 bg-[#050811]/80 backdrop-blur-md flex items-center justify-center pointer-events-auto">
        <div class="w-96 max-w-[90vw] p-6 rounded-2xl bg-[#0c111d] border border-sky-500/40 shadow-[0_20px_60px_rgba(14,165,233,0.35)] flex flex-col items-center text-center gap-3">
          <div class="w-10 h-10 rounded-full border-2 border-sky-400 border-t-transparent animate-spin"></div>
          <div class="text-sm font-bold text-white">Analyse AST & Télémétrie SAST en cours...</div>
          <div class="text-[11px] font-mono text-sky-300 truncate max-w-full px-3 py-1 rounded bg-sky-500/10 border border-sky-500/25">
            {cockpitState.scanningTargetPath || cockpitState.graph.project_path || '.'}
          </div>
          <div class="w-full h-1.5 rounded-full bg-white/10 overflow-hidden">
            <div class="h-full w-2/3 bg-gradient-to-r from-sky-500 via-purple-400 to-emerald-400 animate-pulse rounded-full"></div>
          </div>
          <div class="text-[10px] font-mono text-slate-400">
            Extraction Tree-Sitter · Contrats EARS · CWE Top 25 · Enveloppes Cellulaires
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>
