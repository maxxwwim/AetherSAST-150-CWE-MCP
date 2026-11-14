<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { onMount } from 'svelte';
  import type { AetherEngine } from '../engine/engine';

  let { engine }: { engine: AetherEngine | null } = $props();

  let radarCanvas = $state<HTMLCanvasElement | null>(null);
  let animId: number | null = null;

  function renderRadar() {
    if (!radarCanvas || !engine) return;
    const ctx = radarCanvas.getContext('2d');
    if (!ctx) return;

    const w = radarCanvas.width;
    const h = radarCanvas.height;
    ctx.clearRect(0, 0, w, h);

    const nodes = cockpitState.graph.nodes;
    if (nodes.length === 0) return;

    // Calculate bounding box
    let minX = 0, maxX = 0, minY = 0, maxY = 0;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    }

    const span = Math.max(maxX - minX, maxY - minY, 800);
    const scale = (w * 0.74) / span;
    const gCenterX = (minX + maxX) / 2;
    const gCenterY = (minY + maxY) / 2;
    const cx = w / 2;
    const cy = h / 2;

    // 1. Faint circular grid & crosshairs
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.18)';
    ctx.lineWidth = 0.8;
    ctx.beginPath();
    ctx.arc(cx, cy, 32, 0, Math.PI * 2);
    ctx.arc(cx, cy, 58, 0, Math.PI * 2);
    ctx.moveTo(cx, 4); ctx.lineTo(cx, h - 4);
    ctx.moveTo(4, cy); ctx.lineTo(w - 4, cy);
    ctx.stroke();

    // 2. Plot Nodes
    const activeSymbolId = cockpitState.activeSymbol?.id;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const rx = cx + (n.x - gCenterX) * scale;
      const ry = cy + (n.y - gCenterY) * scale;

      ctx.fillStyle = n.id === activeSymbolId ? '#38bdf8' : 'rgba(148, 163, 184, 0.55)';
      ctx.fillRect(rx - 1, ry - 1, 2, 2);
    }

    // 3. Camera Viewport Box
    const cam = engine.camera;
    const vw = Math.min(w * 2.2, (window.innerWidth / cam.zoom) * scale);
    const vh = Math.min(h * 2.2, (window.innerHeight / cam.zoom) * scale);
    const vx = cx + (cam.x - gCenterX) * scale - vw / 2;
    const vy = cy + (cam.y - gCenterY) * scale - vh / 2;

    ctx.strokeStyle = '#38bdf8';
    ctx.lineWidth = 1.2;
    ctx.strokeRect(vx, vy, vw, vh);
  }

  function handleRadarClick(e: MouseEvent) {
    if (!radarCanvas || !engine) return;
    const rect = radarCanvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left - radarCanvas.width / 2;
    const clickY = e.clientY - rect.top - radarCanvas.height / 2;

    const nodes = cockpitState.graph.nodes;
    let minX = 0, maxX = 0, minY = 0, maxY = 0;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.x < minX) minX = n.x; if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y; if (n.y > maxY) maxY = n.y;
    }
    const span = Math.max(maxX - minX, maxY - minY, 800);
    const scale = (radarCanvas.width * 0.74) / span;
    const gCenterX = (minX + maxX) / 2;
    const gCenterY = (minY + maxY) / 2;

    engine.camera.targetX = gCenterX + clickX / scale;
    engine.camera.targetY = gCenterY + clickY / scale;
  }

  const rightOffset = $derived.by(() => {
    if (cockpitState.isChatOpen) return 420;
    if (cockpitState.isInspectorOpen) return 412;
    return 16;
  });

  onMount(() => {
    let frame = 0;
    const loop = () => {
      frame++;
      if (frame % 3 === 0) {
        renderRadar();
      }
      animId = requestAnimationFrame(loop);
    };
    animId = requestAnimationFrame(loop);

    return () => {
      if (animId !== null) cancelAnimationFrame(animId);
    };
  });
</script>

{#if cockpitState.showRadar}
  <div
    style="right: {rightOffset}px;"
    class="absolute bottom-10 w-36 h-36 bg-[#070a12]/85 backdrop-blur-md border border-cyan-500/20 rounded-xl shadow-2xl p-1 z-30 select-none flex flex-col items-center justify-between pointer-events-auto transition-[right] duration-300 ease-in-out"
  >
    <!-- Header / Zoom level indicator -->
    <div class="w-full flex items-center justify-between px-1.5 text-[9px] font-mono text-cyan-400/80">
      <span>RADAR</span>
      <span>{engine ? `${engine.camera.zoom.toFixed(2)}x` : '1.00x'}</span>
    </div>

    <canvas
      bind:this={radarCanvas}
      width={130}
      height={108}
      onclick={handleRadarClick}
      class="cursor-crosshair rounded"
    ></canvas>
  </div>
{/if}
