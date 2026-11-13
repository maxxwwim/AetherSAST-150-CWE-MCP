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
  import { cockpitState } from './state/graphState.svelte';
  import { api } from './lib/api';
  import { onMount } from 'svelte';

  onMount(async () => {
    // Check if data was injected via window.__AETHERSCOPE_DATA__
    const injected = (window as any).__AETHERSCOPE_DATA__;
    if (injected) {
      cockpitState.setGraph(injected);
    } else {
      try {
        const g = await api.getGraph();
        cockpitState.setGraph(g);
      } catch (e) {
        console.warn('Backend not responding yet:', e);
      }
    }
  });
</script>

<div class="w-full h-full flex flex-col bg-[#07090e] text-slate-100 overflow-hidden font-sans">
  <HeaderDeck />
  <div class="relative flex-1 w-full h-full overflow-hidden">
    <AetherCanvas />
    <VisionModesDeck />
    <InspectorDrawer />
    <CommandPalette />
    <BountyModal />
    <SettingsModal />
    <PromptGeneratorModal />
    <SurfaceScannerModal />
    <DocReaderDrawer />
    <ProjectHubModal />
  </div>
</div>
