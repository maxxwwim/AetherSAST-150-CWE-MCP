import type { SymbolBubble } from '../types/graph';
import type { CockpitState } from '../state/graphState.svelte';

// Palette of vibrant neon colors guaranteed to be visually distinct
const DISTINCT_PALETTE: readonly string[] = [
  '#38bdf8', // Sky Cyan
  '#f97316', // Neon Orange
  '#c084fc', // Cosmic Purple
  '#34d399', // Emerald Mint
  '#f43f5e', // Hot Coral Rose
  '#eab308', // Solar Amber
  '#a855f7', // Electric Violet
  '#06b6d4', // Bright Turquoise
  '#ec4899', // Hyper Pink
  '#84cc16', // Toxic Lime
  '#6366f1', // Ultra Indigo
  '#14b8a6', // Deep Teal
  '#fb923c', // Tangerine
  '#e879f9', // Orchid Fuchsia
  '#10b981', // Spring Green
  '#3b82f6', // Cobalt Blue
];

export interface AgentOverlayContext {
  state: CockpitState;
  nodeMap: ReadonlyMap<string, SymbolBubble>;
  zoom: number;
  logicalWidth: number;
  logicalHeight: number;
  worldToScreen: (wx: number, wy: number) => { x: number; y: number };
  classifyNode: (n: SymbolBubble) => { baseRadius: number };
  getNodeScreenRadius: (n: SymbolBubble, activeId: string | null) => number;
}

export class AgentOverlayRenderer {
  private smoothPositions = new Map<string, { x: number; y: number }>();

  public clear(): void {
    this.smoothPositions.clear();
  }

  public render(
    ctx: CanvasRenderingContext2D,
    now: number,
    dt: number,
    overlay: AgentOverlayContext
  ): void {
    const rawAgents = overlay.state.activeAgents;
    const trails = overlay.state.agentTrails;
    if (!rawAgents || rawAgents.length === 0) return;
    // Only render agents that pinged within the last 5 minutes
    const agents = rawAgents.filter((ag) => !overlay.state.isAgentInactive(ag));
    if (agents.length === 0) return;

    // Prune stale agent positions to prevent memory leaks over time
    if (this.smoothPositions.size > 40) {
      const activeIds = new Set(agents.map((a) => a.agentId));
      for (const k of this.smoothPositions.keys()) {
        if (!activeIds.has(k)) {
          this.smoothPositions.delete(k);
        }
      }
    }

    ctx.save();
    const zoom = overlay.zoom;
    const safeDt = Math.min(Math.max(dt || 16.6, 1.0), 50.0);

    // Pre-pass: Resolve target bubble and assign unique color for each agent
    interface ActiveAgentVisual {
      ag: (typeof agents)[0];
      targetNode: SymbolBubble;
      agColor: string;
      agNameLower: string;
      agentCleanName: string;
    }

    const resolvedList: ActiveAgentVisual[] = [];
    const agentsByNode = new Map<string, number>();
    const assignedColors = new Set<string>();

    for (let idx = 0; idx < agents.length; idx++) {
      const ag = agents[idx];
      let targetNode: SymbolBubble | undefined;
      if (ag.nodeId) {
        targetNode = overlay.nodeMap.get(ag.nodeId);
      }
      if (!targetNode && ag.target) {
        targetNode = overlay.state.resolveTargetNode(ag.target);
        if (targetNode) ag.nodeId = targetNode.id;
      }
      if (!targetNode && overlay.state.activeSymbol) {
        targetNode = overlay.state.activeSymbol;
      }
      if (!targetNode) continue;

      let agColor = ag.color;
      if (!agColor || assignedColors.has(agColor)) {
        agColor = DISTINCT_PALETTE[idx % DISTINCT_PALETTE.length];
      }
      assignedColors.add(agColor);

      const agNameLower = (ag.agentName || ag.agentId || '').toLowerCase();
      const agentCleanName = ag.agentName || ag.agentId || 'Agent';

      resolvedList.push({ ag, targetNode, agColor, agNameLower, agentCleanName });
      agentsByNode.set(targetNode.id, (agentsByNode.get(targetNode.id) || 0) + 1);
    }

    if (resolvedList.length === 0) {
      ctx.restore();
      return;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. RENDER INTER-BUBBLE NAVIGATION TRAJECTORIES (LIGNES D'IA)
    // ─────────────────────────────────────────────────────────────────────────
    if (overlay.state.settings.showAiLines && overlay.state.settings.aiTrail) {
      for (let idx = 0; idx < resolvedList.length; idx++) {
        const { ag, targetNode, agColor } = resolvedList[idx];
        const agTrail = trails[ag.agentId] || [];

        const validPoints: { s: { x: number; y: number }; wx: number; wy: number }[] = [];

        for (const pt of agTrail) {
          let node = pt.nodeId ? overlay.nodeMap.get(pt.nodeId) : null;
          if (!node && pt.target) {
            node = overlay.state.resolveTargetNode(pt.target);
            if (node) pt.nodeId = node.id;
          }
          const wx = node ? node.x : pt.x;
          const wy = node ? node.y : pt.y;
          if (wx == null || wy == null) continue;
          validPoints.push({ s: overlay.worldToScreen(wx, wy), wx, wy });
        }

        // Connect the trail directly to the current target bubble if not already the final point
        const lastPt = validPoints[validPoints.length - 1];
        if (!lastPt || Math.hypot(lastPt.wx - targetNode.x, lastPt.wy - targetNode.y) > 1.0) {
          validPoints.push({
            s: overlay.worldToScreen(targetNode.x, targetNode.y),
            wx: targetNode.x,
            wy: targetNode.y,
          });
        }

        if (validPoints.length > 1) {
          // Pass 1: Subtle diffused glow path
          ctx.beginPath();
          ctx.moveTo(validPoints[0].s.x, validPoints[0].s.y);
          for (let i = 1; i < validPoints.length; i++) {
            ctx.lineTo(validPoints[i].s.x, validPoints[i].s.y);
          }
          ctx.strokeStyle = agColor;
          ctx.lineWidth = Math.max(1.5, 2.2 * Math.sqrt(zoom));
          ctx.globalAlpha = 0.12;
          ctx.stroke();

          // Pass 2: Lightweight dashed trajectory core
          ctx.beginPath();
          ctx.moveTo(validPoints[0].s.x, validPoints[0].s.y);
          for (let i = 1; i < validPoints.length; i++) {
            ctx.lineTo(validPoints[i].s.x, validPoints[i].s.y);
          }
          ctx.setLineDash([6, 6]);
          ctx.lineDashOffset = -(now * 0.015 + idx * 3);
          ctx.strokeStyle = agColor;
          ctx.globalAlpha = 0.48;
          ctx.lineWidth = Math.max(1.0, 1.3 * Math.sqrt(zoom));
          ctx.stroke();
          ctx.setLineDash([]);

          // Pass 3: Subtle waypoint dots
          for (let i = 0; i < validPoints.length; i++) {
            const wp = validPoints[i];
            const isLatest = i === validPoints.length - 1;
            const wpRadius = isLatest ? 3.2 : 2.0;

            ctx.beginPath();
            ctx.arc(wp.s.x, wp.s.y, wpRadius, 0, Math.PI * 2);
            ctx.fillStyle = isLatest ? '#ffffff' : agColor;
            ctx.globalAlpha = isLatest ? 0.85 : 0.45;
            ctx.fill();
          }
          ctx.globalAlpha = 1.0;
        }
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. RENDER MULTI-AGENT ORBITS ON THE BUBBLE SIMULTANEOUSLY
    // ─────────────────────────────────────────────────────────────────────────
    const nodeAgentCounter = new Map<string, number>();

    // 3D inclined celestial orbit constants base:
    const TILT_ALPHA = 0.610865;   // ~35°
    const INCLINATION_PSI = 0.436332; // ~25°
    const omega = 0.0018;

    for (let idx = 0; idx < resolvedList.length; idx++) {
      const { ag, targetNode, agColor, agNameLower, agentCleanName } = resolvedList[idx];

      const totalOnNode = agentsByNode.get(targetNode.id) || 1;
      const subIdx = nodeAgentCounter.get(targetNode.id) || 0;
      nodeAgentCounter.set(targetNode.id, subIdx + 1);

      // Phase spacing: uniformly distribute agents around this bubble
      const phiAgent = (subIdx / totalOnNode) * (Math.PI * 2);

      // Tiered radius per agent on the same bubble so they have distinct orbital shells
      const { baseRadius } = overlay.classifyNode(targetNode);
      const orbitR = (baseRadius * 2.5 + 24.0) + (subIdx * 14.0);

      // Distinct 3D orbital plane tilt and inclination per agent on this bubble
      const tiltAlpha = TILT_ALPHA + (subIdx * (Math.PI / Math.max(2, totalOnNode * 2)));
      const inclinationPsi = INCLINATION_PSI + (subIdx * (Math.PI / Math.max(1, totalOnNode)));
      const cosAlpha = Math.cos(tiltAlpha);
      const cosPsi = Math.cos(inclinationPsi);
      const sinPsi = Math.sin(inclinationPsi);

      // Alternating orbital revolution direction and speed
      const dir = (subIdx % 2 === 0 ? 1 : -0.85);
      const agentOmega = omega + (subIdx * 0.0002);
      const theta = (now * agentOmega * dir) + phiAgent;

      // Smooth camera anchor position with continuous LERP (safeguarded against frame drops)
      let smooth = this.smoothPositions.get(ag.agentId);
      if (!smooth) {
        smooth = { x: targetNode.x, y: targetNode.y };
        this.smoothPositions.set(ag.agentId, smooth);
      } else {
        const lerpFactor = 1.0 - Math.exp(-14.0 * (safeDt / 1000));
        smooth.x += (targetNode.x - smooth.x) * lerpFactor;
        smooth.y += (targetNode.y - smooth.y) * lerpFactor;
      }
      const anchorX = smooth.x;
      const anchorY = smooth.y;

      // ───────────────────────────────────────────────────────────────────────
      // A. DRAW ORBITAL TRAJECTORY RING ON THE BUBBLE (LIGNES D'IA)
      // ───────────────────────────────────────────────────────────────────────
      if (overlay.state.settings.showAiLines) {
        ctx.beginPath();
        const ORBIT_SAMPLES = 12; // Lightweight sampling (eliminated heavy 28-sample matrix loop)
        for (let s = 0; s <= ORBIT_SAMPLES; s++) {
          const a = (s / ORBIT_SAMPLES) * Math.PI * 2;
          const xP = orbitR * Math.cos(a);
          const yP = orbitR * Math.sin(a) * cosAlpha;
          const xR = xP * cosPsi - yP * sinPsi;
          const yR = xP * sinPsi + yP * cosPsi;
          const p = overlay.worldToScreen(anchorX + xR, anchorY + yR);
          if (s === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        }
        ctx.strokeStyle = agColor;
        ctx.lineWidth = Math.max(1.0, 1.4 * Math.sqrt(zoom));
        ctx.globalAlpha = 0.35;
        ctx.stroke();
      }

      // Current avatar 3D position in orbit
      const xPlane = orbitR * Math.cos(theta);
      const yPlane = orbitR * Math.sin(theta) * cosAlpha;
      const xRot = xPlane * cosPsi - yPlane * sinPsi;
      const yRot = xPlane * sinPsi + yPlane * cosPsi;

      const xOrbWorld = anchorX + xRot;
      const yOrbWorld = anchorY + yRot;

      const pOrb = overlay.worldToScreen(xOrbWorld, yOrbWorld);
      const pNode = overlay.worldToScreen(anchorX, anchorY);

      // Screen culling
      if (
        pOrb.x < -140 || pOrb.x > overlay.logicalWidth + 140 ||
        pOrb.y < -140 || pOrb.y > overlay.logicalHeight + 140
      ) {
        continue;
      }

      // Calculate target bubble surface intersection
      const targetR = overlay.getNodeScreenRadius(targetNode, overlay.state.activeSymbol?.id || null);
      const dx = pNode.x - pOrb.x;
      const dy = pNode.y - pOrb.y;
      const len = Math.hypot(dx, dy) || 1;
      const impactDist = Math.max(0, targetR * 0.45);
      const pImpact = {
        x: pNode.x - (dx / len) * impactDist,
        y: pNode.y - (dy / len) * impactDist,
      };

      // ───────────────────────────────────────────────────────────────────────
      // B. CONNECTING LASER BEAM FROM AVATAR TO BUBBLE SURFACE (LIGNES D'IA)
      // ───────────────────────────────────────────────────────────────────────
      if (overlay.state.settings.showAiLines) {
        // Pass 1: Diffused colored glow aura
        ctx.beginPath();
        ctx.moveTo(pOrb.x, pOrb.y);
        ctx.lineTo(pImpact.x, pImpact.y);
        ctx.strokeStyle = agColor;
        ctx.lineWidth = Math.max(1.5, 2.5 * Math.sqrt(zoom));
        ctx.globalAlpha = 0.30;
        ctx.stroke();

        // Pass 2: Inner white laser core
        ctx.beginPath();
        ctx.moveTo(pOrb.x, pOrb.y);
        ctx.lineTo(pImpact.x, pImpact.y);
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.0;
        ctx.globalAlpha = 0.85;
        ctx.stroke();

        // Pass 3: Concentric circular scanning reticle on bubble surface (fast, zero matrix rotate churn)
        const reticleRadius = Math.max(4, Math.min(10, 5 * Math.sqrt(Math.max(0.3, zoom))));
        ctx.beginPath();
        ctx.arc(pImpact.x, pImpact.y, reticleRadius, 0, Math.PI * 2);
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.0;
        ctx.globalAlpha = 0.80;
        ctx.stroke();
      }

      // ───────────────────────────────────────────────────────────────────────
      // C. STELLAR AVATAR ORB AT (pOrb.x, pOrb.y) (LIGHTWEIGHT, ZERO MATRIX STACK CHURN)
      // ───────────────────────────────────────────────────────────────────────
      // Fast lightweight vector circles (eliminated rotating accretion ellipse matrix transforms)
      ctx.beginPath();
      ctx.arc(pOrb.x, pOrb.y, 8, 0, Math.PI * 2);
      ctx.fillStyle = agColor;
      ctx.globalAlpha = 0.35;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(pOrb.x, pOrb.y, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.globalAlpha = 0.95;
      ctx.fill();

      // ───────────────────────────────────────────────────────────────────────
      // D. STATIC & SLEEK BILLBOARD BADGE (MASQUABLE & DISPARAÎT APRÈS 5 MIN D'INACTIVITÉ)
      // ───────────────────────────────────────────────────────────────────────
      const isInactive = overlay.state.isAgentInactive(ag);
      if (overlay.state.settings.showAiNames && !isInactive && zoom >= 0.22) {
        const agentIcon = agNameLower.includes('claude') ? '✨'
          : agNameLower.includes('gemini') ? '⚡'
          : agNameLower.includes('cursor') ? '🎯'
          : agNameLower.includes('antigravity') ? '🪐'
          : '🤖';
        const shortName = agentCleanName.length > 14 ? agentCleanName.slice(0, 12) + '…' : agentCleanName;
        const tagText = `${agentIcon} ${shortName}`;

        ctx.font = '600 9px ui-sans-serif, system-ui, -apple-system, sans-serif';
        const tw = ctx.measureText(tagText).width + 10;
        const badgeH = 15;

        // FIXED ANCHOR TO NODE (pNode), NOT MOVING WITH THE ORBITING CELL (pOrb)
        const badgeX = pNode.x;
        const badgeY = pNode.y - targetR - 8 - (subIdx * (badgeH + 3));

        // Compact glassmorphic pill badge
        ctx.fillStyle = 'rgba(10, 14, 26, 0.92)';
        ctx.strokeStyle = agColor;
        ctx.lineWidth = 1.0;
        ctx.globalAlpha = 0.92;
        ctx.beginPath();
        ctx.roundRect(badgeX - tw * 0.5, badgeY - badgeH * 0.5, tw, badgeH, 4);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = '#f8fafc';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(tagText, badgeX, badgeY + 0.5);
      }
    }

    ctx.restore();
  }
}
