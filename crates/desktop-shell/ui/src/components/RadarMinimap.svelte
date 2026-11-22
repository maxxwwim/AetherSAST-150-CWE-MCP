<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { onMount } from 'svelte';
  import type { AetherEngine } from '../engine/engine';
  import type { SymbolBubble } from '../types/graph';

  interface Props {
    engine?: AetherEngine | null;
    mode?: 'global' | 'local';
    embedded?: boolean;
  }

  let {
    engine = null,
    mode = $bindable<'global' | 'local'>('global'),
    embedded = false
  }: Props = $props();

  let radarCanvas = $state<HTMLCanvasElement | null>(null);
  let animId: number | null = null;

  function normPath(p?: string | null): string {
    return String(p || '')
      .replace(/\\/g, '/')
      .replace(/^\.\//, '')
      .trim()
      .toLowerCase();
  }

  const centerNode = $derived.by<SymbolBubble | null>(() => {
    if (cockpitState.activeSymbol) return cockpitState.activeSymbol;
    const activeFile = normPath(cockpitState.ideActiveFile);
    const cursorLine = cockpitState.ideCursorPosition?.line || cockpitState.ideTargetLine || 1;
    const nodes = cockpitState.graph.nodes || [];
    if (activeFile) {
      const fileNodes = nodes.filter((n) => normPath(n.file_path) === activeFile);
      const nonFile = fileNodes
        .filter((n) => !n.is_file && String(n.kind).toLowerCase() !== 'file' && !n.id.startsWith('file::'))
        .sort((a, b) => (a.line_number || 0) - (b.line_number || 0));
      let best: SymbolBubble | null = null;
      for (const s of nonFile) {
        if ((s.line_number || 1) <= cursorLine) {
          best = s;
        }
      }
      if (best) return best;
      if (nonFile.length > 0) return nonFile[0];
      if (fileNodes.length > 0) return fileNodes[0];
    }
    return nodes[0] || null;
  });

  const localTopology = $derived.by(() => {
    const center = centerNode;
    if (!center) {
      return {
        callers: [] as SymbolBubble[],
        callees: [] as SymbolBubble[],
        displayedCallers: [] as SymbolBubble[],
        displayedCallees: [] as SymbolBubble[],
        neighborIds: new Set<string>()
      };
    }

    const incEdges = cockpitState.incidentEdges(center.id);
    const callersMap = new Map<string, SymbolBubble>();
    const calleesMap = new Map<string, SymbolBubble>();
    const neighborIds = new Set<string>([center.id]);

    for (let i = 0; i < incEdges.length; i++) {
      const e = incEdges[i];
      if (!e || e.source === e.target) continue;
      if (e.target === center.id) {
        const srcNode = cockpitState.getNodeById(e.source);
        if (srcNode && srcNode.name && !callersMap.has(srcNode.id)) {
          callersMap.set(srcNode.id, srcNode);
          neighborIds.add(srcNode.id);
        }
      } else if (e.source === center.id) {
        const tgtNode = cockpitState.getNodeById(e.target);
        if (tgtNode && tgtNode.name && !calleesMap.has(tgtNode.id)) {
          calleesMap.set(tgtNode.id, tgtNode);
          neighborIds.add(tgtNode.id);
        }
      }
    }

    const callers = Array.from(callersMap.values());
    const callees = Array.from(calleesMap.values());
    return {
      callers,
      callees,
      displayedCallers: callers.slice(0, 8),
      displayedCallees: callees.slice(0, 8),
      neighborIds
    };
  });

  const localAgents = $derived.by(() => {
    const center = centerNode;
    const activeFile = normPath(cockpitState.ideActiveFile || center?.file_path);
    const neighborIds = localTopology.neighborIds;
    const list: { agentId: string; agentName: string; color: string; action?: string; targetLabel: string }[] = [];

    for (const ag of cockpitState.activeAgents || []) {
      if (!ag || cockpitState.isAgentInactive(ag)) continue;
      const name = String(ag.agentName || '').trim();
      if (!name || name === 'undefined') continue;

      const agTargetNorm = normPath(ag.target);
      const resolved = ag.nodeId ? cockpitState.getNodeById(ag.nodeId) : cockpitState.resolveTargetNode(ag.target);
      const resolvedId = ag.nodeId || resolved?.id || '';
      const resolvedFile = normPath(resolved?.file_path);

      const matchesLocal =
        (resolvedId && neighborIds.has(resolvedId)) ||
        (activeFile && (agTargetNorm === activeFile || agTargetNorm.endsWith('/' + activeFile) || resolvedFile === activeFile));

      if (matchesLocal && resolved) {
        list.push({
          agentId: ag.agentId,
          agentName: name,
          color: ag.color || '#38bdf8',
          action: ag.action,
          targetLabel: resolved.name || ''
        });
      }
    }
    return list;
  });

  function jumpToNeighbor(node: SymbolBubble) {
    if (!node) return;
    cockpitState.selectSymbol(node.id, false);
    if (node.file_path) {
      const targetLine = node.line_number && node.line_number > 0 ? node.line_number : 1;
      cockpitState.openFileInIde(node.file_path, targetLine);
    }
    cockpitState.requestFocusSymbol(node.id);
  }

  function renderRadar() {
    if (!radarCanvas || !engine || mode !== 'global') return;
    const ctx = radarCanvas.getContext('2d');
    if (!ctx) return;

    const w = radarCanvas.width;
    const h = radarCanvas.height;
    ctx.clearRect(0, 0, w, h);

    const nodes = cockpitState.graph.nodes;
    if (nodes.length === 0) return;

    let minX = 0, maxX = 0, minY = 0, maxY = 0;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const nx = Number.isFinite(n.x) ? n.x : 0;
      const ny = Number.isFinite(n.y) ? n.y : 0;
      if (nx < minX) minX = nx;
      if (nx > maxX) maxX = nx;
      if (ny < minY) minY = ny;
      if (ny > maxY) maxY = ny;
    }

    const span = Math.max(maxX - minX, maxY - minY, 800);
    const scale = (w * 0.74) / span;
    const gCenterX = (minX + maxX) / 2;
    const gCenterY = (minY + maxY) / 2;
    const cx = w / 2;
    const cy = h / 2;

    ctx.strokeStyle = 'rgba(56, 189, 248, 0.18)';
    ctx.lineWidth = 0.8;
    ctx.beginPath();
    ctx.arc(cx, cy, 32, 0, Math.PI * 2);
    ctx.arc(cx, cy, 58, 0, Math.PI * 2);
    ctx.moveTo(cx, 4); ctx.lineTo(cx, h - 4);
    ctx.moveTo(4, cy); ctx.lineTo(w - 4, cy);
    ctx.stroke();

    const activeSymbolId = cockpitState.activeSymbol?.id;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const nx = Number.isFinite(n.x) ? n.x : 0;
      const ny = Number.isFinite(n.y) ? n.y : 0;
      const rx = cx + (nx - gCenterX) * scale;
      const ry = cy + (ny - gCenterY) * scale;

      ctx.fillStyle = n.id === activeSymbolId ? '#38bdf8' : 'rgba(148, 163, 184, 0.55)';
      ctx.fillRect(rx - 1, ry - 1, 2, 2);
    }

    const cam = engine.camera;
    const logW = engine.logicalWidth || (typeof window !== 'undefined' ? window.innerWidth : 800);
    const logH = engine.logicalHeight || (typeof window !== 'undefined' ? window.innerHeight : 600);
    const safeZoom = Math.max(0.0001, Number.isFinite(cam.zoom) ? cam.zoom : 1);
    const camX = Number.isFinite(cam.x) ? cam.x : 0;
    const camY = Number.isFinite(cam.y) ? cam.y : 0;
    const vw = Math.min(w - 4, Math.max(4, (logW / safeZoom) * scale));
    const vh = Math.min(h - 4, Math.max(4, (logH / safeZoom) * scale));
    const vx = Math.max(2, Math.min(w - vw - 2, cx + (camX - gCenterX) * scale - vw / 2));
    const vy = Math.max(2, Math.min(h - vh - 2, cy + (camY - gCenterY) * scale - vh / 2));

    ctx.strokeStyle = '#38bdf8';
    ctx.lineWidth = 1.2;
    ctx.strokeRect(vx, vy, vw, vh);

    const agents = cockpitState.activeAgents.filter((ag) => !cockpitState.isAgentInactive(ag));
    const trails = cockpitState.agentTrails;
    const nowTs = Date.now();

    for (let idx = 0; idx < agents.length; idx++) {
      const ag = agents[idx];
      const agColor = ag.color || '#38bdf8';
      const agTrail = trails[ag.agentId] || [];

      let ax = ag.targetX;
      let ay = ag.targetY;
      if (ax == null || ay == null) {
        const hit = cockpitState.resolveTargetNode(ag.target);
        if (hit) {
          ax = hit.x;
          ay = hit.y;
        }
      }

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
        if (wx != null && wy != null && Number.isFinite(wx) && Number.isFinite(wy)) {
          radarPts.push({ x: cx + (wx - gCenterX) * scale, y: cy + (wy - gCenterY) * scale });
        }
      }
      if (ax != null && ay != null && Number.isFinite(ax) && Number.isFinite(ay)) {
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

      if (ax != null && ay != null && Number.isFinite(ax) && Number.isFinite(ay)) {
        const arx = cx + (ax - gCenterX) * scale;
        const ary = cy + (ay - gCenterY) * scale;
        const pulseR = 3.5 + Math.sin(nowTs * 0.005 + idx) * 1.5;

        ctx.beginPath();
        ctx.arc(arx, ary, pulseR, 0, Math.PI * 2);
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.0;
        ctx.stroke();

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
      const nx = Number.isFinite(n.x) ? n.x : 0;
      const ny = Number.isFinite(n.y) ? n.y : 0;
      if (nx < minX) minX = nx; if (nx > maxX) maxX = nx;
      if (ny < minY) minY = ny; if (ny > maxY) maxY = ny;
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

  const zoomLabel = $derived.by(() => {
    if (!engine || !Number.isFinite(engine.camera?.zoom)) return '1.00x';
    const z = engine.camera.zoom;
    return z >= 0.01 ? `${z.toFixed(2)}x` : `${(z * 100).toFixed(2)}%`;
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

{#if mode === 'local' || embedded || (cockpitState.showRadar && !shouldHideOnMobileDrawer)}
  <div
    style={embedded ? '' : `right: ${rightOffset}px;`}
    class="{embedded
      ? 'w-full bg-[#070a12]/95 border border-cyan-500/25 rounded-xl shadow-2xl p-2 select-none flex flex-col gap-1.5'
      : mode === 'local'
        ? 'absolute bottom-10 w-72 bg-[#070a12]/90 backdrop-blur-md border border-cyan-500/25 rounded-xl shadow-2xl p-2 z-30 select-none flex flex-col gap-1.5 pointer-events-auto transition-[right] duration-300 ease-in-out'
        : 'absolute bottom-10 w-40 h-40 bg-[#070a12]/85 backdrop-blur-md border border-cyan-500/20 rounded-xl shadow-2xl p-1.5 z-30 select-none flex flex-col items-center justify-between pointer-events-auto transition-[right] duration-300 ease-in-out'}"
  >
    <!-- Header with Local / Global Mode Switch -->
    <div class="w-full flex items-center justify-between px-1 text-[9.5px] font-mono text-cyan-400/90 shrink-0">
      <span class="font-bold tracking-wider uppercase">
        {mode === 'local' ? 'Constellation PiP' : 'RADAR'}
      </span>
      <div class="flex items-center gap-1">
        <button
          type="button"
          onclick={() => (mode = 'local')}
          class="px-1.5 py-0.2 rounded text-[8.5px] cursor-pointer transition-colors {mode === 'local' ? 'bg-cyan-500/25 text-cyan-200 border border-cyan-400/40 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Mode Constellation Locale (symbole actif & voisins)"
        >
          Local
        </button>
        <button
          type="button"
          onclick={() => (mode = 'global')}
          class="px-1.5 py-0.2 rounded text-[8.5px] cursor-pointer transition-colors {mode === 'global' ? 'bg-cyan-500/25 text-cyan-200 border border-cyan-400/40 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Mode Radar Global"
        >
          Global
        </button>
        {#if mode === 'global'}
          <span class="text-[8.5px] text-cyan-400/70 ml-0.5">{zoomLabel}</span>
        {/if}
      </div>
    </div>

    {#if mode === 'local'}
      {#if !centerNode}
        <div class="py-4 text-center text-[10px] font-mono text-slate-500">
          Aucun symbole actif · 0 appelant · 0 appelé
        </div>
      {:else}
        <!-- Active Center Node Pill -->
        <div class="px-2 py-1 rounded bg-sky-500/15 border border-sky-400/35 flex items-center justify-between gap-1.5 text-[10.5px] font-mono">
          <div class="flex items-center gap-1.5 min-w-0">
            <span class="w-2 h-2 rounded-full bg-sky-400 shrink-0 shadow-[0_0_6px_#38bdf8]"></span>
            <span class="font-bold text-sky-100 truncate" title={centerNode.name}>{centerNode.name}</span>
          </div>
          {#if centerNode.line_number}
            <span class="text-[9px] text-sky-300/80 shrink-0">L{centerNode.line_number}</span>
          {/if}
        </div>

        <!-- Summary Counts (0-neighbor state compliant) -->
        <div class="px-1 flex items-center justify-between text-[9.5px] font-mono text-slate-400">
          <span>{localTopology.callers.length} appelant{localTopology.callers.length > 1 ? 's' : ''}</span>
          <span class="text-slate-600">·</span>
          <span>{localTopology.callees.length} appelé{localTopology.callees.length > 1 ? 's' : ''}</span>
        </div>

        <!-- Active AI Agents targeting local symbols -->
        {#if localAgents.length > 0}
          <div class="flex flex-wrap gap-1 px-0.5">
            {#each localAgents as ag (ag.agentId)}
              <span
                class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono bg-sky-500/15 border border-sky-400/30 text-sky-200"
                style="border-color: {ag.color}66;"
              >
                <span class="w-1.5 h-1.5 rounded-full animate-pulse" style="background-color: {ag.color};"></span>
                <span>{ag.agentName}</span>
              </span>
            {/each}
          </div>
        {/if}

        <!-- Direct Callers & Callees 1-Click Constellation Lists -->
        <div class="grid grid-cols-2 gap-1.5 max-h-40 overflow-y-auto scrollbar-thin text-[10px] font-mono">
          <!-- Incoming Callers -->
          <div class="space-y-0.5 min-w-0">
            <div class="text-[8.5px] uppercase tracking-wider text-amber-300/80 px-1 font-semibold">
              📥 Appelants ({localTopology.callers.length})
            </div>
            {#if localTopology.displayedCallers.length === 0}
              <div class="px-1 py-1 text-[9px] text-slate-600 italic">0 appelant</div>
            {:else}
              {#each localTopology.displayedCallers as caller (caller.id)}
                <button
                  type="button"
                  onclick={() => jumpToNeighbor(caller)}
                  class="w-full text-left px-1.5 py-0.5 rounded bg-white/[0.03] hover:bg-amber-500/20 border border-white/5 hover:border-amber-400/40 text-slate-200 hover:text-amber-200 truncate cursor-pointer transition-colors"
                  title="Sauter vers {caller.name} ({caller.file_path || ''}:{caller.line_number || 1})"
                >
                  ↖ {caller.name}
                </button>
              {/each}
            {/if}
          </div>

          <!-- Outgoing Callees -->
          <div class="space-y-0.5 min-w-0">
            <div class="text-[8.5px] uppercase tracking-wider text-emerald-300/80 px-1 font-semibold">
              📤 Appelés ({localTopology.callees.length})
            </div>
            {#if localTopology.displayedCallees.length === 0}
              <div class="px-1 py-1 text-[9px] text-slate-600 italic">0 appelé</div>
            {:else}
              {#each localTopology.displayedCallees as callee (callee.id)}
                <button
                  type="button"
                  onclick={() => jumpToNeighbor(callee)}
                  class="w-full text-left px-1.5 py-0.5 rounded bg-white/[0.03] hover:bg-emerald-500/20 border border-white/5 hover:border-emerald-400/40 text-slate-200 hover:text-emerald-200 truncate cursor-pointer transition-colors"
                  title="Sauter vers {callee.name} ({callee.file_path || ''}:{callee.line_number || 1})"
                >
                  ↗ {callee.name}
                </button>
              {/each}
            {/if}
          </div>
        </div>
      {/if}
    {:else}
      <canvas
        bind:this={radarCanvas}
        width={130}
        height={108}
        onclick={handleRadarClick}
        class="cursor-crosshair rounded"
      ></canvas>
      {#if !engine && centerNode}
        <div class="text-[9px] font-mono text-slate-400 truncate max-w-full px-1">
          {centerNode.name} ({cockpitState.graph.nodes.length} nœuds)
        </div>
      {/if}
    {/if}
  </div>
{/if}
