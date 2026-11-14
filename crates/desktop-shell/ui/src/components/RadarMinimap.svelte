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
    const logW = engine.logicalWidth || (typeof window !== 'undefined' ? window.innerWidth : 800);
    const logH = engine.logicalHeight || (typeof window !== 'undefined' ? window.innerHeight : 600);
    const safeZoom = Math.max(0.0001, cam.zoom);
    const vw = Math.min(w - 4, Math.max(4, (logW / safeZoom) * scale));
    const vh = Math.min(h - 4, Math.max(4, (logH / safeZoom) * scale));
    const vx = Math.max(2, Math.min(w - vw - 2, cx + (cam.x - gCenterX) * scale - vw / 2));
    const vy = Math.max(2, Math.min(h - vh - 2, cy + (cam.y - gCenterY) * scale - vh / 2));

    ctx.strokeStyle = '#38bdf8';
    ctx.lineWidth = 1.2;
    ctx.strokeRect(vx, vy, vw, vh);

    // 4. Plot Multi-Agent AI Trails & Beacons
    const agents = cockpitState.activeAgents;
    const trails = cockpitState.agentTrails;
    const nowTs = Date.now();

    for (let idx = 0; idx < agents.length; idx++) {
      const ag = agents[idx];
      const agColor = ag.color || '#38bdf8';
      const agTrail = trails[ag.agentId] || [];

      // Determine agent current position
      let ax = ag.targetX;
      let ay = ag.targetY;
      if (ax == null || ay == null) {
        const hit = cockpitState.resolveTargetNode(ag.target);
        if (hit) {
          ax = hit.x;
          ay = hit.y;
        }
      }

      // Render trail line on radar (connecting visited bubbles to current position)
      const radarPts: { x: number; y: number }[] = [];
      for (const pt of agTrail) {
        let wx = pt.x;
        let wy = pt.y;
        if (wx == null || wy == null) {
          const hit = cockpitState.resolveTargetNode(pt.target);
          if (hit) {
            wx = hit.x;
            wy = hit.y;
          }
        }
        if (wx != null && wy != null) {
          radarPts.push({ x: cx + (wx - gCenterX) * scale, y: cy + (wy - gCenterY) * scale });
        }
      }
      if (ax != null && ay != null) {
        const curTx = cx + (ax - gCenterX) * scale;
        const curTy = cy + (ay - gCenterY) * scale;
        const last = radarPts[radarPts.length - 1];
        if (!last || Math.hypot(last.x - curTx, last.y - curTy) > 0.5) {
          radarPts.push({ x: curTx, y: curTy });
        }
      }

      if (radarPts.length > 1) {
        ctx.beginPath();
        ctx.moveTo(radarPts[0].x, radarPts[0].y);
        for (let i = 1; i < radarPts.length; i++) {
          ctx.lineTo(radarPts[i].x, radarPts[i].y);
        }
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.2;
        ctx.globalAlpha = 0.65;
        ctx.stroke();
        ctx.globalAlpha = 1.0;
      }

      // Render agent current position beacon
      if (ax != null && ay != null) {
        const arx = cx + (ax - gCenterX) * scale;
        const ary = cy + (ay - gCenterY) * scale;
        const pulseR = 3.5 + Math.sin(nowTs * 0.005 + idx) * 1.5;

        // Outer pulsing beacon ring
        ctx.beginPath();
        ctx.arc(arx, ary, pulseR, 0, Math.PI * 2);
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.0;
        ctx.stroke();

        // Inner glowing dot
        ctx.beginPath();
        ctx.arc(arx, ary, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = agColor;
        ctx.fill();
      }
    }
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
    if (typeof window !== 'undefined' && window.innerWidth < 640) {
      if (cockpitState.isChatOpen || cockpitState.isInspectorOpen) return 16;
    }
    if (cockpitState.isChatOpen) return 420;
    if (cockpitState.isInspectorOpen) return 412;
    return 16;
  });

  const shouldHideOnMobileDrawer = $derived.by(() => {
    return typeof window !== 'undefined' && window.innerWidth < 640 && (cockpitState.isChatOpen || cockpitState.isInspectorOpen);
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

{#if cockpitState.showRadar && !shouldHideOnMobileDrawer}
  <div
    style="right: {rightOffset}px;"
    class="absolute bottom-10 w-36 h-36 bg-[#070a12]/85 backdrop-blur-md border border-cyan-500/20 rounded-xl shadow-2xl p-1 z-30 select-none flex flex-col items-center justify-between pointer-events-auto transition-[right] duration-300 ease-in-out"
  >
    <!-- Header / Zoom level indicator -->
    <div class="w-full flex items-center justify-between px-1.5 text-[9px] font-mono text-cyan-400/80">
      <span>RADAR</span>
      <span>{engine ? (engine.camera.zoom >= 0.01 ? `${engine.camera.zoom.toFixed(2)}x` : `${(engine.camera.zoom * 100).toFixed(2)}%`) : '1.00x'}</span>
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
