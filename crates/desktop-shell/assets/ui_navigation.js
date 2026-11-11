// =========================================================================
// AETHERSCOPE V2 — NAVIGATION & VIEWPORT CONTROLLER (ui_navigation.js)
// Canvas interaction, camera lerp, dragging, zoom, depth, resizers & topbar
// =========================================================================

// --- Node Hover Tooltip Engine ---
const tooltipEl = document.getElementById('node-tooltip');

function safeEscape(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function updateTooltip(node, mouseX, mouseY) {
  if (!tooltipEl) return;
  if (!node) {
    tooltipEl.classList.remove('show');
    return;
  }

  const stEl = document.getElementById('tt-stereo');
  const lyEl = document.getElementById('tt-layer');
  const nmEl = document.getElementById('tt-name');
  const ptEl = document.getElementById('tt-path');
  const tyEl = document.getElementById('tt-type');
  const exEl = document.getElementById('tt-extra');

  if (stEl) stEl.innerText = node.stereotype || (node.is_file ? '«File»' : (node.is_class ? '«Class»' : '«Function»'));
  if (lyEl) {
    lyEl.innerText = (node.layer || 'domain').toUpperCase();
    const pal = state.folderPalettes?.get(node.folder) || [56/255, 189/255, 248/255];
    lyEl.style.color = `rgb(${Math.round(pal[0]*255)}, ${Math.round(pal[1]*255)}, ${Math.round(pal[2]*255)})`;
    lyEl.style.background = `rgba(${Math.round(pal[0]*255)}, ${Math.round(pal[1]*255)}, ${Math.round(pal[2]*255)}, 0.15)`;
    lyEl.style.border = `1px solid rgba(${Math.round(pal[0]*255)}, ${Math.round(pal[1]*255)}, ${Math.round(pal[2]*255)}, 0.4)`;
  }
  if (nmEl) nmEl.innerText = node.name;
  if (ptEl) ptEl.innerText = node.file_path || node.folder || '';
  if (tyEl) tyEl.innerText = node.symbol_type ? `${node.symbol_type.toUpperCase()}` : 'AST NODE';
  if (exEl) {
    const inD = node.in_degree || 0;
    const outD = node.out_degree || 0;
    exEl.innerText = `${inD + outD} flux (${inD}▲ ${outD}▼)`;
  }

  // Signature & Docstring PHPDoc / JSDoc
  const sigBox = document.getElementById('tt-sig-box');
  const sigCode = document.getElementById('tt-sig-code');
  const docBox = document.getElementById('tt-doc-box');
  const docText = document.getElementById('tt-doc-text');
  const locBadge = document.getElementById('tt-loc-badge');

  if (locBadge) {
    const loc = node.lines_count || (node.metadata && node.metadata.lines) || 0;
    locBadge.innerText = loc > 0 ? `${loc} LOC` : '';
    locBadge.style.display = loc > 0 ? 'inline-block' : 'none';
  }

  // Build clean function signature (PHP / TS / Rust style)
  let sig = node.signature || (node.metadata && node.metadata.signature) || '';
  if (!sig && (node.symbol_type === 'function' || node.is_function || node.stereotype === '«Function»' || node.stereotype === '«Method»')) {
    const params = node.parameters || (node.metadata && node.metadata.parameters) || [];
    const retType = node.return_type || (node.metadata && node.metadata.return_type) || '';
    if (params.length > 0) {
      sig = `function ${node.name}(${params.join(', ')})${retType ? ': ' + retType : ''}`;
    } else {
      sig = `function ${node.name}()${retType ? ': ' + retType : ''}`;
    }
  } else if (!sig && (node.is_class || node.stereotype === '«Class»' || node.stereotype === '«Model»' || node.stereotype === '«Service»')) {
    sig = `class ${node.name}`;
  }

  if (sigBox && sigCode) {
    if (sig) {
      sigCode.innerText = sig;
      sigBox.style.display = 'block';
    } else {
      sigBox.style.display = 'none';
    }
  }

  // Docstring PHPDoc / Summary
  const doc = node.docstring || (node.metadata && node.metadata.docstring) || '';
  if (docBox && docText) {
    if (doc && !doc.startsWith('Module source ') && !doc.startsWith('Fichier source ') && !doc.startsWith('Documentation Markdown')) {
      let cleanDoc = doc.replace(/^[\/\*#\s]+/gm, '').trim();
      const summaryMatch = cleanDoc.match(/@summary\s+([^\n@]+)/i);
      if (summaryMatch) {
        cleanDoc = summaryMatch[1].trim();
      } else {
        cleanDoc = cleanDoc.split('\n\n')[0].split('\n')[0].trim();
      }
      docText.innerText = cleanDoc;
      docBox.style.display = 'block';
    } else {
      docBox.style.display = 'none';
    }
  } else if (docBox) {
    docBox.style.display = 'none';
  }

  // CWE Security Alert / Anomalies display in tooltip (R1)
  const cweBox = document.getElementById('tt-cwe-container');
  const anomalies = (node.metadata && node.metadata.cve_anomalies) || [];
  const violations = (node.metadata && node.metadata.violations) || node.violations || [];
  const hasSecurity = Boolean(node.has_security_violation || anomalies.length > 0 || violations.length > 0);

  if (cweBox) {
    if (hasSecurity && (anomalies.length > 0 || violations.length > 0)) {
      let html = '';
      if (anomalies.length > 0) {
        const primary = anomalies[0];
        const sev = (primary.severity || 'CRITICAL').toUpperCase();
        const cweId = primary.cve_id || primary.rule_id || 'CWE-SAST';
        const msg = primary.message || primary.remediation || 'Vulnérabilité de sécurité détectée';
        const count = anomalies.length > 1 ? ` <span class="tt-cwe-count">(+${anomalies.length - 1} autre${anomalies.length > 2 ? 's' : ''})</span>` : '';
        html = `
          <div class="tt-cwe-badge ${sev.toLowerCase()}">
            <span class="tt-cwe-sev">🚨 ${sev}</span>
            <span class="tt-cwe-title">${safeEscape(cweId)}</span>${count}
          </div>
          <div class="tt-cwe-msg">${safeEscape(msg)}</div>
        `;
      } else {
        const v = violations[0];
        html = `
          <div class="tt-cwe-badge critical">
            <span class="tt-cwe-sev">🚨 ALERTE</span>
            <span class="tt-cwe-title">VIOLATION SÉCURITÉ</span>
          </div>
          <div class="tt-cwe-msg">${safeEscape(v)}</div>
        `;
      }
      cweBox.innerHTML = html;
      cweBox.style.display = 'flex';
    } else {
      cweBox.style.display = 'none';
      cweBox.innerHTML = '';
    }
  }

  // Dynamic non-obstructing positioning (R1)
  // Calculate safety clearance using node screen radius so tooltip does not obscure node
  const camZoom = (state.camera && state.camera.zoom) || 1.0;
  const nodeScreenRadius = Math.max(20, (node.radius || 18) * camZoom);
  const clearance = nodeScreenRadius + 20;

  // Render temporarily to accurately measure bounds
  tooltipEl.classList.add('show');
  const ttWidth = tooltipEl.offsetWidth || 340;
  const ttHeight = tooltipEl.offsetHeight || 160;

  // Horizontal position: prefer placing to the right of node, flip to left if edge reached
  let x = mouseX + clearance;
  if (x + ttWidth > window.innerWidth - 14) {
    x = mouseX - clearance - ttWidth;
  }
  // Clamp inside window boundaries
  x = Math.max(12, Math.min(window.innerWidth - ttWidth - 12, x));

  // Vertical position: align near node center or offset vertically to avoid covering labels below
  let y = mouseY - ttHeight * 0.4;
  if (y + ttHeight > window.innerHeight - 14) {
    y = window.innerHeight - ttHeight - 14;
  }
  y = Math.max(12, y);

  tooltipEl.style.left = `${Math.round(x)}px`;
  tooltipEl.style.top = `${Math.round(y)}px`;
}

// --- Inspector & Doc Panel Resizer Drag Engines ---
let isResizingInspector = false;
let resizerStartX = 0;
let resizerStartWidth = 480;

let isResizingDocPanel = false;
let docResizerStartX = 0;
let docResizerStartWidth = 520;

const resizerEl = document.getElementById('inspector-resizer');
const inspectorEl = document.getElementById('inspector');
const docResizerEl = document.getElementById('doc-panel-resizer');
const docPanelEl = document.getElementById('doc-reader-panel');

resizerEl?.addEventListener('mousedown', (e) => {
  isResizingInspector = true;
  resizerStartX = e.clientX;
  resizerStartWidth = inspectorEl ? inspectorEl.offsetWidth : 480;
  resizerEl.classList.add('active');
  document.body.style.cursor = 'ew-resize';
  e.preventDefault();
  e.stopPropagation();
});

docResizerEl?.addEventListener('mousedown', (e) => {
  isResizingDocPanel = true;
  docResizerStartX = e.clientX;
  docResizerStartWidth = docPanelEl ? docPanelEl.offsetWidth : 520;
  docResizerEl.classList.add('active');
  document.body.style.cursor = 'ew-resize';
  e.preventDefault();
  e.stopPropagation();
});

let dragFolderAnchorStart = { x: 0, y: 0 };

// Canvas Mouse Interactions
window.addEventListener('mousedown', (e) => {
  const isInteractive = !!e.target.closest('button, input, select, textarea, .modal-card, .aether-btn, nav, header, #serverbar, #inspector, #doc-reader-panel, .aether-dropdown-menu, #ai-chat-popup, #ai-telemetry-hud, #xray-hud, #deadcode-hud, #heatmap-hud, #radar-container');
  if (isInteractive) return;

  if (state.cameraFlight) state.cameraFlight.active = false;

  // Middle-click (1) = Plateau Pan; Right-click (2) = Smooth Vertical Drag-Zoom
  if (e.button === 1 || e.button === 2) {
    e.preventDefault();
    dragMode = e.button === 2 ? 'right_zoom' : 'plateau';
    state.isPanning = true;
    state.isDraggingCanvas = true;
    mouseDownPos = { x: e.clientX, y: e.clientY };
    dragStart = { x: e.clientX, y: e.clientY };
    document.body.style.cursor = e.button === 2 ? 'ns-resize' : 'grabbing';
    return;
  }

  if (e.button !== 0) return;

  mouseDownPos = { x: e.clientX, y: e.clientY };
  dragStart = { x: e.clientX, y: e.clientY };
  const w = screenToWorld(e.clientX, e.clientY);
  dragMouseStart = { x: w.x, y: w.y };

  const hitNode = findNodeAt(e.clientX, e.clientY);
  const hitFolder = findFolderAt(e.clientX, e.clientY);

  if (hitNode) {
    dragMode = 'node';
    draggedNode = hitNode;
    dragNodeStart = { x: hitNode.x, y: hitNode.y };
    state.draggedNode = hitNode;
    state.physicsSleeping = false;
    state.physicsCooldown = 180;
    document.body.style.cursor = 'grabbing';
  } else if (hitFolder && (hitFolder.isBadge || e.altKey)) {
    dragMode = 'folder';
    draggedFolder = hitFolder.folder;
    dragFolderNodes = (hitFolder.nodes || []).map(n => ({ node: n, startX: n.x, startY: n.y }));
    const anc = state.folderAnchors ? state.folderAnchors.get(hitFolder.folder) : null;
    dragFolderAnchorStart = anc ? { x: anc.x, y: anc.y } : { x: hitFolder.cx, y: hitFolder.cy };
    state.physicsSleeping = false;
    state.physicsCooldown = 180;
    document.body.style.cursor = 'grabbing';
  } else {
    dragMode = 'plateau';
    state.isPanning = true;
    state.isDraggingCanvas = true;
    document.body.style.cursor = 'grabbing';
  }
});

// Canvas Context Menu (allow custom right-click navigation)
window.addEventListener('contextmenu', (e) => {
  const isInteractive = !!e.target.closest('.modal-card, input, textarea, #inspector, #doc-reader-panel, #ai-chat-popup, .aether-dropdown-menu');
  if (!isInteractive) {
    e.preventDefault();
  }
});

window.addEventListener('mousemove', (e) => {
  if (isResizingInspector && inspectorEl) {
    const deltaX = resizerStartX - e.clientX;
    const newWidth = Math.max(320, Math.min(window.innerWidth * 0.85, resizerStartWidth + deltaX));
    inspectorEl.style.width = `${newWidth}px`;
    return;
  }
  if (isResizingDocPanel && docPanelEl) {
    const deltaX = e.clientX - docResizerStartX;
    const newWidth = Math.max(340, Math.min(window.innerWidth * 0.85, docResizerStartWidth + deltaX));
    docPanelEl.style.width = `${newWidth}px`;
    return;
  }

  // Right-click drag-zoom (continuous smooth mouse zoom)
  if (dragMode === 'right_zoom') {
    const dy = e.clientY - dragStart.y;
    dragStart = { x: e.clientX, y: e.clientY };
    if (dy !== 0) {
      const zoomFactor = Math.exp(-dy * 0.0075);
      zoomCameraAroundPoint(zoomFactor, mouseDownPos.x, mouseDownPos.y);
    }
    return;
  }

  // Node Dragging: moves ONLY the dragged bubble inside its stationary folder cell!
  if (dragMode === 'node' && draggedNode) {
    const curWorld = screenToWorld(e.clientX, e.clientY);
    let targetX = dragNodeStart.x + (curWorld.x - dragMouseStart.x);
    let targetY = dragNodeStart.y + (curWorld.y - dragMouseStart.y);

    const fKey = draggedNode.folder || 'root';
    const st = state.folderClusters ? state.folderClusters.get(fKey) : null;
    if (st) {
      const cx = st.cx !== undefined ? st.cx : (st.sumX / st.count);
      const cy = st.cy !== undefined ? st.cy : (st.sumY / st.count);
      const maxR = (st.computedRadius || 130) - 15;
      const d = Math.hypot(targetX - cx, targetY - cy);
      if (d > maxR && maxR > 25) {
        // Soft elastic retention at cell wall: bubble remains peacefully inside its folder cloud
        const over = d - maxR;
        const dampedD = maxR + Math.tanh(over * 0.015) * 25;
        targetX = cx + ((targetX - cx) / d) * dampedD;
        targetY = cy + ((targetY - cy) / d) * dampedD;
      }
    }

    draggedNode.x = targetX;
    draggedNode.y = targetY;
    draggedNode.vx = 0;
    draggedNode.vy = 0;
    if (typeof pinNodeToActiveLayout === 'function') pinNodeToActiveLayout(draggedNode);

    updateFolderClusters();
    state.physicsSleeping = false;
    state.physicsCooldown = 45;
    state.instanceDataDirty = true;
    state.cachedEdgePaths = null;
    document.body.style.cursor = 'grabbing';
    updateTooltip(draggedNode, e.clientX, e.clientY);
  } else if (dragMode === 'folder' && dragFolderNodes) {
    // Folder Dragging: moves the entire folder cloud and all its nodes as a single solid unit
    const curWorld = screenToWorld(e.clientX, e.clientY);
    const dx = curWorld.x - dragMouseStart.x;
    const dy = curWorld.y - dragMouseStart.y;
    for (let i = 0; i < dragFolderNodes.length; i++) {
      const item = dragFolderNodes[i];
      item.node.x = item.startX + dx;
      item.node.y = item.startY + dy;
      item.node.vx = 0;
      item.node.vy = 0;
      if (typeof pinNodeToActiveLayout === 'function') pinNodeToActiveLayout(item.node);
    }
    if (state.folderAnchors && draggedFolder && dragFolderAnchorStart) {
      state.folderAnchors.set(draggedFolder, {
        x: dragFolderAnchorStart.x + dx,
        y: dragFolderAnchorStart.y + dy
      });
    }
    updateFolderClusters();
    state.physicsSleeping = false;
    state.physicsCooldown = 45;
    state.instanceDataDirty = true;
    state.cachedEdgePaths = null;
    document.body.style.cursor = 'grabbing';
  } else if (dragMode === 'plateau') {
    state.camera.targetX -= (e.clientX - dragStart.x) / state.camera.zoom;
    state.camera.targetY -= (e.clientY - dragStart.y) / state.camera.zoom;
    dragStart = { x: e.clientX, y: e.clientY };
    document.body.style.cursor = 'grabbing';
    updateTooltip(null);
  } else {
    const isInteractive = !!e.target.closest('button, input, select, textarea, .modal-card, .aether-btn, nav, header, #serverbar, #inspector, #doc-reader-panel, .aether-dropdown-menu, #ai-chat-popup, #radar-container');
    if (!isInteractive) {
      const hit = findNodeAt(e.clientX, e.clientY);
      if (hit !== state.hoveredNode) {
        state.hoveredNode = hit;
      }
      const hitFolder = hit ? { folder: hit.folder || 'root' } : findFolderAt(e.clientX, e.clientY);
      const nextHovFolder = hitFolder ? hitFolder.folder : null;
      if (nextHovFolder !== state.hoveredFolder) {
        state.hoveredFolder = nextHovFolder;
      }
      canvas.style.cursor = (hit || hitFolder) ? 'pointer' : 'default';
      updateTooltip(hit, e.clientX, e.clientY);
    } else {
      state.hoveredFolder = null;
      updateTooltip(null);
    }
  }
});

window.addEventListener('mouseup', (e) => {
  if (isResizingInspector) {
    isResizingInspector = false;
    resizerEl?.classList.remove('active');
    document.body.style.cursor = '';
  }
  if (isResizingDocPanel) {
    isResizingDocPanel = false;
    docResizerEl?.classList.remove('active');
    document.body.style.cursor = '';
  }
  if (dragMode) {
    const distMoved = Math.hypot(e.clientX - mouseDownPos.x, e.clientY - mouseDownPos.y);
    const isInteractive = !!e.target.closest('button, input, select, textarea, .modal-card, .aether-btn, nav, header, #serverbar, #inspector, #doc-reader-panel, .aether-dropdown-menu, #ai-chat-popup, #radar-container');
    if (distMoved < 6 && !isInteractive && dragMode !== 'right_zoom') {
      const hitNode = findNodeAt(e.clientX, e.clientY);
      if (hitNode) {
        selectNode(hitNode);
      } else {
        const hitFolder = findFolderAt(e.clientX, e.clientY);
        if (hitFolder) {
          selectFolder(hitFolder.folder);
        } else if (state.selectedNode || state.selectedFolder) {
          selectNode(null);
          selectFolder(null);
        }
      }
    }
    dragMode = null;
    draggedNode = null;
    state.draggedNode = null;
    state.isPanning = false;
    state.isDraggingCanvas = false;
    if (typeof dragEndWorker === 'function') dragEndWorker();
    draggedFolder = null;
    dragFolderNodes = null;
    document.body.style.cursor = '';
  }
});

// Topbar 3-Tier Zoom Buttons Event Listeners
document.getElementById('btn-zoom-1')?.addEventListener('click', () => {
  fitView();
  AudioSys.depthSwitch();
  showToast('🔭 Zoom 1 • Vue Macro Globale');
});
document.getElementById('btn-zoom-2')?.addEventListener('click', () => {
  state.camera.targetZoom = 0.55;
  AudioSys.depthSwitch();
  showToast('🪐 Zoom 2 • Entrée dans les Dossiers');
});
document.getElementById('btn-zoom-3')?.addEventListener('click', () => {
  state.camera.targetZoom = 1.25;
  AudioSys.depthSwitch();
  showToast('🔬 Zoom 3 • Microcosme Fichiers & Fonctions');
});

// Cursor-Anchored Invariant Camera Zoom
function zoomCameraAroundPoint(factor, screenX, screenY) {
  const c = state.camera;
  if (!Number.isFinite(c.targetZoom) || c.targetZoom <= 0) c.targetZoom = 0.65;
  if (!Number.isFinite(c.targetX)) c.targetX = 0;
  if (!Number.isFinite(c.targetY)) c.targetY = 0;
  if (!Number.isFinite(c.zoom) || c.zoom <= 0) c.zoom = c.targetZoom;
  if (!Number.isFinite(c.x)) c.x = c.targetX;
  if (!Number.isFinite(c.y)) c.y = c.targetY;

  const minZoom = 0.04;
  const maxZoom = 6.0;
  const newTargetZoom = Math.max(minZoom, Math.min(maxZoom, c.targetZoom * factor));
  if (Math.abs(newTargetZoom - c.targetZoom) < 0.00001) return;

  const cx = (screenX !== undefined && Number.isFinite(screenX)) ? screenX : window.innerWidth / 2;
  const cy = (screenY !== undefined && Number.isFinite(screenY)) ? screenY : window.innerHeight / 2;

  // Invariant point under cursor in TARGET world coordinates
  const worldX = (cx - window.innerWidth / 2) / c.targetZoom + c.targetX;
  const worldY = (cy - window.innerHeight / 2) / c.targetZoom + c.targetY;

  c.targetZoom = newTargetZoom;
  c.targetX = worldX - (cx - window.innerWidth / 2) / newTargetZoom;
  c.targetY = worldY - (cy - window.innerHeight / 2) / newTargetZoom;

  state.physicsSleeping = false;
  state.physicsCooldown = 60;
  if (typeof wakePhysics === 'function') wakePhysics(60);
}

document.getElementById('btn-zoom-in')?.addEventListener('click', () => {
  zoomCameraAroundPoint(1.35);
});
document.getElementById('btn-zoom-out')?.addEventListener('click', () => {
  zoomCameraAroundPoint(0.74);
});

// Double-click on canvas to zoom smoothly towards cursor
const mainCanvas = document.getElementById('aether-canvas') || window;
mainCanvas.addEventListener('dblclick', (e) => {
  if (e.target.closest('button, input, select, textarea, .modal-card, #inspector, #doc-reader-panel, #synthesis-card, #serverbar, header')) return;
  e.preventDefault();
  zoomCameraAroundPoint(e.shiftKey ? 0.65 : 1.55, e.clientX, e.clientY);
});

// Keyboard Zoom Shortcuts
window.addEventListener('keydown', (e) => {
  const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
  if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable) return;
  if (e.key === '+' || e.key === '=') {
    e.preventDefault();
    zoomCameraAroundPoint(1.28);
  } else if (e.key === '-' || e.key === '_') {
    e.preventDefault();
    zoomCameraAroundPoint(0.78);
  } else if (e.key === '0' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    fitView();
  }
});

// Normalized Natural Wheel Zoom (Instant & Smooth)
window.addEventListener('wheel', (e) => {
  if (e.target.closest('.insp-body, #doc-reader-content, .modal-body, .hub-body, .ai-chat-body, #deadcode-quick-list, #heatmap-hotspots, .search-results-list, .topbar-search-results-list, .synth-legend-list, #synthesis-card, .aether-dropdown-menu')) {
    return;
  }
  if (state.cameraFlight) state.cameraFlight.active = false;
  e.preventDefault();
  let dy = e.deltaY;
  if (e.deltaMode === 1) dy *= 32;
  else if (e.deltaMode === 2) dy *= 640;
  if (dy === 0) return;

  const clampedDy = Math.max(-140, Math.min(140, dy));
  const factor = Math.exp(-clampedDy * 0.0022);
  zoomCameraAroundPoint(factor, e.clientX, e.clientY);
}, { passive: false });

// 4D Depth Switcher
const DEPTH_TITLES = {
  1: 'Z-1 • 🌌 Galaxie Fichiers (Obsidian)',
  2: 'Z-2 • 🌐 Architecture Système Multi-Couches',
  3: 'Z-3 • ⚙️ Flux d\'Exécution DAG',
  4: 'Z-4 • 🏛️ Classes & Composants UML'
};

function switchDepth(d) {
  state.depth = d;
  state.folderAnchors = new Map();
  if (typeof setDepthWorker === 'function') setDepthWorker(d);

  // Reset lingering velocities so bubbles smoothly glide toward new targets without chaos
  const nodes = state.data.nodes || [];
  nodes.forEach(n => { n.vx = 0; n.vy = 0; });

  state.physicsSleeping = false;
  state.instanceDataDirty = true;
  if (typeof invalidateEdgePathCache === 'function') invalidateEdgePathCache();
  wakePhysics(240);
  AudioSys.depthSwitch();

  document.querySelectorAll('.depth-btn').forEach(b => {
    b.classList.toggle('active', parseInt(b.getAttribute('data-depth')) === d);
  });
  const el = document.getElementById('depth-title');
  if (el) el.innerText = DEPTH_TITLES[d] || '4D Depth Continuum';

  const depthSelect = document.getElementById('serverbar-depth-select');
  if (depthSelect) depthSelect.value = String(d);

  [1, 2, 3, 4].forEach(level => {
    const btn = document.getElementById(`btn-vision-depth-${level}`);
    if (btn) btn.classList.toggle('active-depth-item', level === d);
  });

  // Smoothly reframe camera to encompass the full new geometric structure
  setTimeout(() => {
    if (typeof fitView === 'function') fitView();
  }, 100);

  showToast(`🚀 Cosmos basculé : ${DEPTH_TITLES[d]}`);
}

document.querySelectorAll('.depth-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const d = parseInt(btn.getAttribute('data-depth'));
    switchDepth(d);
  });
});

document.getElementById('serverbar-depth-select')?.addEventListener('change', (e) => {
  const d = parseInt(e.target.value, 10);
  if (!isNaN(d)) switchDepth(d);
});

// Fit View
function fitView() {
  const nodes = state.data.nodes || [];
  if (nodes.length === 0) return;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  nodes.forEach(n => {
    if (!state.activeLayers.has(n.layer)) return;
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  });
  if (minX === Infinity) return;

  const w = maxX - minX + 220;
  const h = maxY - minY + 220;
  state.camera.targetX = (minX + maxX) / 2;
  state.camera.targetY = (minY + maxY) / 2;
  const zoomX = window.innerWidth / w;
  const zoomY = window.innerHeight / h;
  state.camera.targetZoom = Math.min(1.8, Math.max(0.005, Math.min(zoomX, zoomY) * 0.85));
  showToast('🎯 Vue recentrée sur la galaxie');
}

document.getElementById('btn-fit')?.addEventListener('click', fitView);

// Gravity Toggle
document.getElementById('btn-gravity')?.addEventListener('click', () => {
  state.physicsRunning = !state.physicsRunning;
  if (state.physicsRunning) {
    wakePhysics(120);
  }
  const btn = document.getElementById('btn-gravity');
  if (btn) {
    btn.innerText = state.physicsRunning ? '🌌 Gravité ON' : '⏸️ Gravité PAUSE';
    btn.classList.toggle('primary', state.physicsRunning);
  }
  showToast(state.physicsRunning ? 'Physique quantique active' : 'Simulation en pause');
});

// Universal Desktop Dropdown Menus
const allDropdowns = document.querySelectorAll('.aether-dropdown');
allDropdowns.forEach(dd => {
  const trigger = dd.querySelector('.menu-bar-btn') || dd.querySelector('.aether-btn');
  if (trigger) {
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = dd.classList.contains('open');
      allDropdowns.forEach(d => d.classList.remove('open'));
      if (!isOpen) {
        dd.classList.add('open');
      }
    });
  }
});

window.addEventListener('click', () => {
  allDropdowns.forEach(d => d.classList.remove('open'));
});

document.querySelectorAll('.aether-dropdown-item').forEach(item => {
  item.addEventListener('click', () => {
    allDropdowns.forEach(d => d.classList.remove('open'));
  });
});

// Wire up Desktop Menu Bar Actions
document.getElementById('btn-menu-scaffold-project')?.addEventListener('click', () => {
  if (typeof openHubModal === 'function') openHubModal();
});
document.getElementById('btn-quick-create-project')?.addEventListener('click', () => {
  if (typeof openHubModal === 'function') openHubModal();
});
document.getElementById('btn-serverbar-new-folder')?.addEventListener('click', () => {
  if (typeof openHubModal === 'function') openHubModal();
});

document.getElementById('btn-menu-pick-workspace')?.addEventListener('click', () => {
  document.getElementById('btn-pick-workspace')?.click();
});
document.getElementById('btn-menu-pick-project')?.addEventListener('click', () => {
  document.getElementById('btn-pick-project')?.click();
});
document.getElementById('btn-menu-analyze')?.addEventListener('click', () => {
  document.getElementById('btn-analyze')?.click();
});
document.getElementById('btn-menu-export')?.addEventListener('click', () => {
  document.getElementById('btn-export')?.click();
});

document.getElementById('btn-menu-lod-1')?.addEventListener('click', () => {
  document.getElementById('btn-zoom-1')?.click();
});
document.getElementById('btn-menu-lod-2')?.addEventListener('click', () => {
  document.getElementById('btn-zoom-2')?.click();
});
document.getElementById('btn-menu-lod-3')?.addEventListener('click', () => {
  document.getElementById('btn-zoom-3')?.click();
});
document.getElementById('btn-menu-fit')?.addEventListener('click', () => {
  document.getElementById('btn-fit')?.click();
});

window.fitView = fitView;
window.switchDepth = switchDepth;
window.zoomCameraAroundPoint = zoomCameraAroundPoint;
window.updateTooltip = updateTooltip;


// =========================================================================
// M3: DUAL-VISION CONTROLLER (Code AST vs Obsidian Vault Notes)
// =========================================================================

async function syncProjectStatus() {
  try {
    const status = await window.AetherAPI.fetchProjectStatus();
    state.project_type = status.project_type;
    state.active_view_mode = status.active_view_mode || status.active_view || 'code';
    renderProjectStatusUI(status);
  } catch (err) {
    console.warn('Erreur synchronisation statut projet:', err);
  }
}

function renderProjectStatusUI(status) {
  const btnCode = document.getElementById('btn-view-mode-code');
  const btnVault = document.getElementById('btn-view-mode-vault');
  const menuCode = document.getElementById('btn-menu-view-code');
  const menuVault = document.getElementById('btn-menu-view-vault');
  const badgeCode = document.getElementById('menu-badge-view-code');
  const badgeVault = document.getElementById('menu-badge-view-vault');

  const pType = status.project_type;
  const isPureCode = pType === 'PureCode';
  const isPureVault = pType === 'PureObsidianVault';
  const activeMode = status.active_view_mode || 'code';
  const isCode = activeMode === 'code';

  if (btnVault) {
    btnVault.disabled = isPureCode;
    btnVault.classList.toggle('disabled', isPureCode);
    btnVault.title = isPureCode
      ? 'Aucun coffre Obsidian détecté dans ce projet (PureCode)'
      : 'Vision 2 : Graphe de Notes & Wikilinks Obsidian (Alt+2)';
    btnVault.classList.toggle('active', !isCode && !isPureCode);
  }

  if (btnCode) {
    btnCode.disabled = isPureVault;
    btnCode.classList.toggle('disabled', isPureVault);
    btnCode.title = isPureVault
      ? 'Coffre Obsidian pur (aucun fichier code détecté)'
      : 'Vision 1 : Architecture & AST Code (Alt+1)';
    btnCode.classList.toggle('active', isCode && !isPureVault);
  }

  if (menuVault) {
    menuVault.disabled = isPureCode;
    menuVault.classList.toggle('disabled', isPureCode);
    menuVault.classList.toggle('active-vision-mode', !isCode);
    if (!isCode) menuVault.classList.add('vault');
    else menuVault.classList.remove('vault');
  }

  if (menuCode) {
    menuCode.disabled = isPureVault;
    menuCode.classList.toggle('disabled', isPureVault);
    menuCode.classList.toggle('active-vision-mode', isCode);
  }

  if (badgeCode) {
    badgeCode.innerText = isCode ? 'ACTIF' : (isPureVault ? 'NON DISPO' : 'INACTIF');
    badgeCode.style.color = isCode ? '#38bdf8' : (isPureVault ? '#ef4444' : '#64748b');
  }

  if (badgeVault) {
    badgeVault.innerText = !isCode ? 'ACTIF' : (isPureCode ? 'NON DISPO' : 'INACTIF');
    badgeVault.style.color = !isCode ? '#c084fc' : (isPureCode ? '#ef4444' : '#64748b');
  }
}

async function switchProjectViewMode(requestedMode) {
  const normMode = (requestedMode === 'vault' || requestedMode === 'notes') ? 'vault' : 'code';
  if (state.active_view_mode === normMode) return;

  const btnCode = document.getElementById('btn-view-mode-code');
  const btnVault = document.getElementById('btn-view-mode-vault');
  const activeBtn = normMode === 'vault' ? btnVault : btnCode;

  try {
    if (activeBtn) activeBtn.classList.add('loading-pulse');
    showToast(`⏳ Bascule vers la vision ${normMode === 'vault' ? 'Obsidian Notes' : 'Architecture Code'}...`);

    const newGraph = await window.AetherAPI.switchViewMode(normMode);
    state.active_view_mode = normMode;

    if (window.AudioSys && typeof AudioSys.depthSwitch === 'function') {
      AudioSys.depthSwitch();
    }

    if (typeof applyData === 'function') {
      applyData(newGraph);
    }

    renderProjectStatusUI({
      project_type: state.project_type || 'Mixed',
      active_view_mode: normMode
    });

    const count = (newGraph.nodes || []).length;
    const toastLabel = normMode === 'vault'
      ? `📓 Vision Vault Notes activée (${count} notes & liens)`
      : `💻 Vision Architecture Code activée (${count} symboles)`;
    showToast(toastLabel);
  } catch (err) {
    console.error('Erreur bascule vision:', err);
    showToast(`❌ Erreur bascule vision: ${err.message}`);
  } finally {
    if (activeBtn) activeBtn.classList.remove('loading-pulse');
  }
}

window.switchProjectViewMode = switchProjectViewMode;
window.syncProjectStatus = syncProjectStatus;
window.refreshProjectStatusUi = syncProjectStatus;
window.applyProjectStatusToUi = renderProjectStatusUI;

// Keyboard shortcuts for view switching
window.addEventListener('keydown', (e) => {
  const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
  if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable) return;

  if (e.altKey && (e.key === '1' || e.code === 'Digit1')) {
    e.preventDefault();
    switchProjectViewMode('code');
  } else if (e.altKey && (e.key === '2' || e.code === 'Digit2')) {
    e.preventDefault();
    switchProjectViewMode('vault');
  }
});
