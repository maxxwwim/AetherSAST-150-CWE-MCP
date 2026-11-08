// =========================================================================
// AETHERSCOPE V2 — HIGH-PERFORMANCE OFF-THREAD PHYSICS WORKER
// Offloads O(N^2) Coulomb/Hooke & 12-Lobe Cellular Membranes from UI Thread
// Keeps 120 FPS rock-solid WebGL 2 without altering any visual shaders/rendering
// =========================================================================

let nodes = [];
let edges = [];
let nodeMap = new Map();
let depth = 1;
let activeLayers = new Set(['ui', 'action', 'domain', 'database', 'network', 'external', 'test']);
let hiddenModules = new Set();
let folderAnchors = new Map();
let activeDragId = null;
let physicsRunning = true;
let physicsSleeping = false;
let physicsCooldown = 120;
let isBusy = false;

const SECTORS = 12;
const TWO_PI = Math.PI * 2;

function initGraph(payload) {
  nodes = payload.nodes || [];
  edges = payload.edges || [];
  depth = payload.depth || 1;
  activeDragId = null;
  physicsSleeping = false;
  physicsCooldown = 150;

  nodeMap = new Map();
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    n.vx = n.vx || 0;
    n.vy = n.vy || 0;
    nodeMap.set(n.id, n);
  }

  // Pre-resolve edge pointers in worker
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    e._s = nodeMap.get(e.source);
    e._t = nodeMap.get(e.target);
  }
}

function computeFolderClusters(zoom = 1.0) {
  const folderStats = new Map();
  const comfortPadding = Math.max(48, Math.min(88, 54 / Math.sqrt(zoom || 1)));

  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    if (!activeLayers.has(n.layer)) continue;
    const f = n.folder || 'root';
    if (hiddenModules.has(f)) continue;

    let st = folderStats.get(f);
    if (!st) {
      st = { sumX: 0, sumY: 0, count: 0, minX: Infinity, maxX: -Infinity, minY: Infinity, maxY: -Infinity, nodes: [] };
      folderStats.set(f, st);
    }
    st.sumX += n.x;
    st.sumY += n.y;
    st.count++;
    st.nodes.push(n);
  }

  const exportClusters = {};

  folderStats.forEach((st, folder) => {
    let anchor = folderAnchors.get(folder);
    if (!anchor || !Number.isFinite(anchor.x) || !Number.isFinite(anchor.y)) {
      anchor = { x: st.sumX / st.count, y: st.sumY / st.count };
      folderAnchors.set(folder, anchor);
    }
    const cx = anchor.x;
    const cy = anchor.y;
    st.cx = cx;
    st.cy = cy;
    st.sumX = cx * st.count;
    st.sumY = cy * st.count;

    let maxDist = 0;
    let sumDist = 0;
    const minBaseR = Math.max(110, Math.sqrt(st.count) * 58);
    const rawSectors = new Float32Array(SECTORS);

    for (let ni = 0; ni < st.nodes.length; ni++) {
      const nd = st.nodes[ni];
      const dx = nd.x - cx;
      const dy = nd.y - cy;
      const d = Math.hypot(dx, dy);
      sumDist += d;
      if (d > maxDist) maxDist = d;
      let ang = Math.atan2(dy, dx);
      if (ang < 0) ang += TWO_PI;
      const sIdx = Math.floor((ang / TWO_PI) * SECTORS) % SECTORS;
      if (d > rawSectors[sIdx]) rawSectors[sIdx] = d;

      const prevIdx = (sIdx + SECTORS - 1) % SECTORS;
      const nextIdx = (sIdx + 1) % SECTORS;
      if (d * 0.90 > rawSectors[prevIdx]) rawSectors[prevIdx] = d * 0.90;
      if (d * 0.90 > rawSectors[nextIdx]) rawSectors[nextIdx] = d * 0.90;
    }

    const meanDist = sumDist / Math.max(1, st.count);
    const coreR = Math.max(meanDist * 1.55 + comfortPadding, minBaseR);
    const baseR = Math.max(coreR, maxDist * 0.75 + comfortPadding);
    st.computedRadius = Math.max(baseR, maxDist + comfortPadding * 0.75);
    st.naturalRadius = coreR;

    const lobes = new Float32Array(SECTORS);
    for (let s = 0; s < SECTORS; s++) {
      const neededR = rawSectors[s] > 0 ? (rawSectors[s] + comfortPadding) : (baseR * 0.86);
      const ratio = neededR / st.computedRadius;
      lobes[s] = Math.max(0.76, Math.min(1.42, ratio));
    }

    const smoothed = new Float32Array(SECTORS);
    for (let pass = 0; pass < 2; pass++) {
      const src = pass === 0 ? lobes : smoothed;
      const dst = pass === 0 ? smoothed : lobes;
      for (let s = 0; s < SECTORS; s++) {
        const prev = src[(s + SECTORS - 1) % SECTORS];
        const next = src[(s + 1) % SECTORS];
        dst[s] = prev * 0.25 + src[s] * 0.50 + next * 0.25;
      }
    }
    st.lobeProfile = lobes;

    exportClusters[folder] = {
      cx: st.cx,
      cy: st.cy,
      sumX: st.sumX,
      sumY: st.sumY,
      count: st.count,
      computedRadius: st.computedRadius,
      naturalRadius: st.naturalRadius,
      lobeProfile: Array.from(lobes)
    };
  });

  return { folderStats, exportClusters };
}

function stepWorkerPhysics(zoom = 1.0) {
  if (!physicsRunning || nodes.length === 0 || physicsSleeping) return null;

  const d = depth;
  const isHuge = nodes.length > 1000;
  let totalSpeed = 0;
  let distToTargetSum = 0;
  let targetCount = 0;

  // 1. Pull towards active layout
  const pull = (d === 1) ? (isHuge ? 0.045 : 0.035) : 0.18;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    if (activeDragId && n.id === activeDragId) continue;
    let target = null;
    if (n.layouts) {
      if (d === 1 && n.layouts.obsidian) target = n.layouts.obsidian;
      else if (d === 2 && n.layouts.system) target = n.layouts.system;
      else if (d === 3 && n.layouts.flow) target = n.layouts.flow;
      else if (d === 4 && n.layouts.classes) target = n.layouts.classes;
    }
    if (target) {
      const dx = target.x - n.x;
      const dy = target.y - n.y;
      n.vx = (n.vx || 0) + dx * pull;
      n.vy = (n.vy || 0) + dy * pull;
      distToTargetSum += Math.hypot(dx, dy);
      targetCount++;
    }
  }

  // 2. Hooke Spring Attraction
  const springFactor = (d === 1) ? 1.0 : 0.12;
  const maxEdges = isHuge ? Math.min(edges.length, 2500) : edges.length;
  for (let i = 0; i < maxEdges; i++) {
    const e = edges[i];
    const s = e._s;
    const t = e._t;
    if (!s || !t) continue;
    if (!activeLayers.has(s.layer) || !activeLayers.has(t.layer)) continue;
    if (activeDragId && (s.id === activeDragId || t.id === activeDragId)) continue;

    const dx = t.x - s.x;
    const dy = t.y - s.y;
    const dist = Math.hypot(dx, dy) || 1;
    const restLen = e.relation === 'contains' ? 65 : 160;
    const force = Math.max(-4.5, Math.min(4.5, (dist - restLen) * 0.012)) * springFactor;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;
    s.vx = (s.vx || 0) + fx;
    s.vy = (s.vy || 0) + fy;
    t.vx = (t.vx || 0) - fx;
    t.vy = (t.vy || 0) - fy;
  }

  // 2b. Cellular Membrane Confinement in Obsidian Galaxy View
  let exportClusters = null;
  if (d === 1) {
    const clusterRes = computeFolderClusters(zoom);
    exportClusters = clusterRes.exportClusters;
    const folderStats = clusterRes.folderStats;

    // Intra-cellular node anti-stick & comfort spacing
    folderStats.forEach((st) => {
      if (!st.nodes || st.nodes.length <= 1) return;
      const count = st.nodes.length;
      const innerStep = count > 180 ? 2 : 1;
      const minD = 58; // Distance de confort augmentée : les bulles ne se collent jamais
      const minD2 = minD * minD;

      for (let i = 0; i < count; i++) {
        const na = st.nodes[i];
        for (let j = i + 1; j < count; j += innerStep) {
          const nb = st.nodes[j];
          const bdx = nb.x - na.x;
          const bdy = nb.y - na.y;
          const bdist2 = bdx * bdx + bdy * bdy;
          if (bdist2 < minD2 && bdist2 > 0.0001) {
            const bdist = Math.sqrt(bdist2);
            const overlap = minD - bdist;
            const repulse = Math.min(5.5, overlap * 0.10);
            const pfx = (bdx / bdist) * repulse;
            const pfy = (bdy / bdist) * repulse;
            if (!activeDragId || na.id !== activeDragId) { na.vx = (na.vx || 0) - pfx; na.vy = (na.vy || 0) - pfy; }
            if (!activeDragId || nb.id !== activeDragId) { nb.vx = (nb.vx || 0) + pfx; nb.vy = (nb.vy || 0) + pfy; }

            // Séparation instantanée anti-overlap (Verlet push)
            const pushRatio = 0.28;
            const px = (bdx / bdist) * overlap * pushRatio;
            const py = (bdy / bdist) * overlap * pushRatio;
            if (!activeDragId || na.id !== activeDragId) { na.x -= px; na.y -= py; }
            if (!activeDragId || nb.id !== activeDragId) { nb.x += px; nb.y += py; }
          }
        }
      }
    });

    const clusterList = Array.from(folderStats.values());
    for (let i = 0; i < clusterList.length; i++) {
      clusterList[i]._cfx = 0;
      clusterList[i]._cfy = 0;
    }
    for (let i = 0; i < clusterList.length; i++) {
      const cA = clusterList[i];
      if (!cA.nodes || cA.count === 0) continue;
      const cxA = cA.cx !== undefined ? cA.cx : (cA.sumX / cA.count);
      const cyA = cA.cy !== undefined ? cA.cy : (cA.sumY / cA.count);
      const rA = cA.computedRadius || 120;

      for (let j = i + 1; j < clusterList.length; j++) {
        const cB = clusterList[j];
        if (!cB.nodes || cB.count === 0) continue;
        const cxB = cB.cx !== undefined ? cB.cx : (cB.sumX / cB.count);
        const cyB = cB.cy !== undefined ? cB.cy : (cB.sumY / cB.count);
        const rB = cB.computedRadius || 120;

        const cdx = cxB - cxA;
        const cdy = cyB - cyA;
        const cdist = Math.hypot(cdx, cdy) || 1;
        // Espacement mass-aware : les gros amas d'étoiles sont bien plus espacés
        const massPadding = Math.max(160, Math.sqrt(cA.count + cB.count) * 26);
        const safeClusterDist = rA + rB + massPadding;

        if (cdist < safeClusterDist) {
          const overlap = safeClusterDist - cdist;
          const repulse = Math.min(9.5, overlap * 0.08);
          const rfx = (cdx / cdist) * repulse * 0.8;
          const rfy = (cdy / cdist) * repulse * 0.8;
          cA._cfx -= rfx;
          cA._cfy -= rfy;
          cB._cfx += rfx;
          cB._cfy += rfy;
        }
      }
    }

    for (let i = 0; i < clusterList.length; i++) {
      const c = clusterList[i];
      if (!c.nodes || (c._cfx === 0 && c._cfy === 0)) continue;
      const fx = c._cfx, fy = c._cfy;
      for (let k = 0; k < c.nodes.length; k++) {
        const nd = c.nodes[k];
        if (activeDragId && nd.id === activeDragId) continue;
        nd.vx = (nd.vx || 0) + fx;
        nd.vy = (nd.vy || 0) + fy;
      }
    }
  } else {
    // In Structured Views
    const count = nodes.length;
    const step = count > 500 ? 2 : 1;
    const minD = 48;
    const minD2 = minD * minD;
    for (let i = 0; i < count; i += step) {
      const na = nodes[i];
      for (let j = i + 1; j < Math.min(count, i + 48); j++) {
        const nb = nodes[j];
        const bdx = nb.x - na.x;
        const bdy = nb.y - na.y;
        const bdist2 = bdx * bdx + bdy * bdy;
        if (bdist2 < minD2 && bdist2 > 0.0001) {
          const bdist = Math.sqrt(bdist2);
          const overlap = minD - bdist;
          const repulse = Math.min(4.5, overlap * 0.09);
          const pfx = (bdx / bdist) * repulse;
          const pfy = (bdy / bdist) * repulse;
          if (!activeDragId || na.id !== activeDragId) { na.vx = (na.vx || 0) - pfx; na.vy = (na.vy || 0) - pfy; }
          if (!activeDragId || nb.id !== activeDragId) { nb.vx = (nb.vx || 0) + pfx; nb.vy = (nb.vy || 0) + pfy; }

          const pushRatio = 0.22;
          const px = (bdx / bdist) * overlap * pushRatio;
          const py = (bdy / bdist) * overlap * pushRatio;
          if (!activeDragId || na.id !== activeDragId) { na.x -= px; na.y -= py; }
          if (!activeDragId || nb.id !== activeDragId) { nb.x += px; nb.y += py; }
        }
      }
    }
  }

  // 3. Integration & Friction Damping
  const maxSpeed = (d === 1) ? 3.6 : 18.0;
  const friction = (d === 1) ? 0.82 : 0.74;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    if (activeDragId && n.id === activeDragId) {
      n.vx = 0;
      n.vy = 0;
      continue;
    }
    n.vx = (n.vx || 0) * friction;
    n.vy = (n.vy || 0) * friction;
    const sp = Math.hypot(n.vx, n.vy);
    if (sp > maxSpeed) {
      n.vx = (n.vx / sp) * maxSpeed;
      n.vy = (n.vy / sp) * maxSpeed;
    }
    n.x += n.vx;
    n.y += n.vy;
    totalSpeed += sp;
  }

  // Auto-sleep check
  physicsCooldown--;
  const avgDist = targetCount > 0 ? (distToTargetSum / targetCount) : 0;
  const isRelaxed = (d === 1)
    ? (isHuge ? totalSpeed < 0.80 : totalSpeed < 0.20)
    : (avgDist < 1.8 && totalSpeed < 0.6);

  if (!activeDragId && (physicsCooldown <= 0 || isRelaxed)) {
    physicsSleeping = true;
  }

  // Export positions as Transferable Float32Array (x, y per node)
  const positions = new Float32Array(nodes.length * 2);
  for (let i = 0; i < nodes.length; i++) {
    positions[i * 2] = nodes[i].x;
    positions[i * 2 + 1] = nodes[i].y;
  }

  return {
    positions,
    exportClusters,
    physicsSleeping
  };
}

self.onmessage = function(e) {
  const { type, payload } = e.data;

  if (type === 'INIT') {
    initGraph(payload);
  } else if (type === 'SET_DEPTH') {
    depth = payload.depth || 1;
    physicsSleeping = false;
    physicsCooldown = 150;
  } else if (type === 'SET_LAYERS') {
    if (payload.activeLayers) activeLayers = new Set(payload.activeLayers);
    if (payload.hiddenModules) hiddenModules = new Set(payload.hiddenModules);
    physicsSleeping = false;
    physicsCooldown = 90;
  } else if (type === 'DRAG') {
    activeDragId = payload.id;
    const n = nodeMap.get(payload.id);
    if (n) {
      n.x = payload.x;
      n.y = payload.y;
      n.vx = 0;
      n.vy = 0;
    }
    physicsSleeping = false;
    physicsCooldown = 90;
  } else if (type === 'DRAG_END') {
    activeDragId = null;
    physicsSleeping = false;
    physicsCooldown = 100;
  } else if (type === 'WAKE') {
    physicsCooldown = Math.max(physicsCooldown || 0, payload.steps || 100);
    physicsSleeping = false;
  } else if (type === 'STEP') {
    if (isBusy) return;
    isBusy = true;
    const res = stepWorkerPhysics(payload ? payload.zoom : 1.0);
    isBusy = false;
    if (res) {
      self.postMessage(
        {
          type: 'UPDATE',
          positions: res.positions,
          clusters: res.exportClusters,
          isSleeping: res.physicsSleeping
        },
        [res.positions.buffer]
      );
    } else {
      self.postMessage({ type: 'IDLE' });
    }
  }
};
