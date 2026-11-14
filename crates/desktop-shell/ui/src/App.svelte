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
  import { cockpitState } from './state/graphState.svelte';
  import { api } from './lib/api';
  import { onMount } from 'svelte';

  onMount(() => {
    let versionTimer: ReturnType<typeof setInterval> | null = null;

    (async () => {
      // Check if data was injected via window.__AETHERSCOPE_DATA__
      const injected = (window as any).__AETHERSCOPE_DATA__;
      if (injected) {
        cockpitState.setGraph(injected);
      } else {
        try {
          const g = await api.getGraph();
          cockpitState.setGraph(g);
          cockpitState.liveConnected = true;
        } catch (e) {
          console.warn('Backend not responding yet:', e);
        }
      }

      // Sync saved CWE settings & tasks count from backend if online
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
          if (Array.isArray(settingsRes.value.ignored_cwes)) {
            cockpitState.settings.ignoredCwes = settingsRes.value.ignored_cwes;
          }
        }
      } catch {
        // standalone offline mode
      }
    })();

    // Live graph version watcher (polls /api/graph/version every 3s)
    versionTimer = setInterval(async () => {
      try {
        const res = await api.getGraphVersion();
        cockpitState.liveConnected = true;
        if (typeof res?.version === 'number' && cockpitState.graphVersion > 0 && res.version !== cockpitState.graphVersion) {
          cockpitState.graphVersion = res.version;
          const updated = await api.getGraph();
          cockpitState.setGraph(updated);
          cockpitState.filterVersion += 1;
        } else if (typeof res?.version === 'number' && cockpitState.graphVersion === 0) {
          cockpitState.graphVersion = res.version;
        }
      } catch {
        cockpitState.liveConnected = false;
      }
    }, 3000);

    return () => {
      if (versionTimer) clearInterval(versionTimer);
    };
  });
</script>

<div class="w-full h-full flex flex-col bg-[#07090e] text-slate-100 overflow-hidden font-sans">
  <HeaderDeck />
  <div class="relative flex-1 w-full h-full overflow-hidden">
    <AetherCanvas />
    <CanvasTooltip />
    <VisionModesDeck />
    <VisionModeHuds />
    <SynthesisHud />
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
