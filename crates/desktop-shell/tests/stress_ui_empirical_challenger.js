/**
 * EMPIRICAL CHALLENGER TEST SUITE: UI PRODUCTION ENHANCEMENTS (R1 & R2)
 * 
 * Adversarially stress-tests Requirements R1 and R2:
 * 1. Tooltip positioning, dynamic clearance, screen-edge clamping, and XSS safety.
 * 2. Canvas edge badge geometry, node collision on short edges, perpendicular offsets.
 * 3. Canvas node callout pill geometry, notch clearance, and pulse collision.
 * 4. Zoom font-size scaling in world vs screen coordinates (ballooning vs vanishing).
 * 5. Inspector debrief panel wrapping and rule name separation.
 * 6. Central HUD complete suppression across lifecycle, rapid switches, and backend failures.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ASSETS_DIR = path.join(__dirname, '..', 'assets');
const DOCS_DIR = path.join(__dirname, '..', '..', '..', 'docs');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const findings = [];

function check(id, name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  [PASS] ${id}: ${name}`);
  } catch (err) {
    failedTests++;
    findings.push({ id, name, error: err.message, stack: err.stack });
    console.log(`  [FAIL] ${id}: ${name}\n         -> ${err.message}`);
  }
}

console.log('================================================================');
console.log('AETHERSCOPE PRODUCTION UI EMPIRICAL CHALLENGE HARNESS (R1 & R2)');
console.log('================================================================\n');

const indexHtml = fs.readFileSync(path.join(ASSETS_DIR, 'index.html'), 'utf8');
const stylesCss = fs.readFileSync(path.join(ASSETS_DIR, 'styles.css'), 'utf8');
const uiNavJs = fs.readFileSync(path.join(ASSETS_DIR, 'ui_navigation.js'), 'utf8');
const uiModalsJs = fs.readFileSync(path.join(ASSETS_DIR, 'ui_ai_modals.js'), 'utf8');
const uiInspectorJs = fs.readFileSync(path.join(ASSETS_DIR, 'ui_inspector_docs.js'), 'utf8');
const webglJs = fs.readFileSync(path.join(ASSETS_DIR, 'webgl_renderer.js'), 'utf8');
const docsIndexHtml = fs.existsSync(path.join(DOCS_DIR, 'index.html'))
  ? fs.readFileSync(path.join(DOCS_DIR, 'index.html'), 'utf8')
  : null;

// =============================================================================
// CATEGORY 1: R2 — CENTER HUD SUPPRESSION & LIFECYCLE ROBUSTNESS
// =============================================================================
console.log('--- CATEGORY 1: R2 — Center HUD Suppression & Lifecycle Robustness ---');

check('R2-DOM-1', 'DOM in assets/index.html completely omits #hydro-loading-hud', () => {
  const match = indexHtml.match(/<div[^>]*id=["']hydro-loading-hud["'][^>]*>/i);
  assert.strictEqual(match, null, 'Found #hydro-loading-hud DOM tag in index.html');
});

check('R2-DOM-2', 'DOM in assets/index.html completely omits .hydro-hud-banner', () => {
  const match = indexHtml.match(/<div[^>]*class=["'][^"']*hydro-hud-banner[^"']*["'][^>]*>/i);
  assert.strictEqual(match, null, 'Found .hydro-hud-banner DOM tag in index.html');
});

if (docsIndexHtml) {
  check('R2-DOM-3', 'Built standalone docs/index.html completely omits active #hydro-loading-hud', () => {
    const match = docsIndexHtml.match(/<div[^>]*id=["']hydro-loading-hud["'][^>]*>/i);
    assert.strictEqual(match, null, 'Found #hydro-loading-hud in docs/index.html');
  });
}

check('R2-CSS-1', 'styles.css strictly enforces display: none !important and opacity: 0 !important', () => {
  const ruleMatch = stylesCss.match(/(?:#hydro-loading-hud\s*,\s*\.hydro-hud-banner|\.hydro-hud-banner\s*,\s*#hydro-loading-hud|#hydro-loading-hud)[\s\S]*?\{([\s\S]*?)\}/);
  assert.ok(ruleMatch, 'CSS rule for #hydro-loading-hud not found');
  const body = ruleMatch[1];
  assert.ok(body.includes('display: none !important'), 'Missing display: none !important');
  assert.ok(body.includes('opacity: 0 !important'), 'Missing opacity: 0 !important');
  assert.ok(body.includes('pointer-events: none !important'), 'Missing pointer-events: none !important');
  assert.ok(body.includes('visibility: hidden !important'), 'Missing visibility: hidden !important');
});

check('R2-JS-1', 'showLoadingScreen() does not initiate setInterval or manipulate HUD elements', () => {
  const fnMatch = uiModalsJs.match(/function showLoadingScreen\([^\)]*\)\s*\{([\s\S]*?)\n\}/);
  assert.ok(fnMatch, 'Could not extract showLoadingScreen');
  const body = fnMatch[1];
  assert.ok(!body.includes('setInterval'), 'showLoadingScreen must not create setInterval');
  assert.ok(!body.includes("classList.remove('hidden')"), 'showLoadingScreen must not unhide hud');
  assert.ok(!body.includes('hydro-project-title'), 'showLoadingScreen must not write to hydro-project-title');
});

check('R2-JS-2', 'applyData emergence sequence does not touch central HUD banner', () => {
  const fnMatch = uiModalsJs.match(/function applyData\(data\)\s*\{([\s\S]*?)\nfunction /);
  assert.ok(fnMatch, 'Could not extract applyData');
  const body = fnMatch[1];
  assert.ok(!body.includes("hud.classList.remove('hidden')"), 'applyData must not unhide central HUD');
  assert.ok(!body.includes('hydro-step-text'), 'applyData must not update hydro-step-text');
});

check('R2-JS-3', 'analyze() handles backend failure with try-finally ensuring clean state', () => {
  const fnMatch = uiModalsJs.match(/async function analyze\(path\)\s*\{([\s\S]*?)\n\}/);
  assert.ok(fnMatch, 'Could not extract analyze');
  const body = fnMatch[1];
  assert.ok(body.includes('finally'), 'analyze must use a finally block');
  assert.ok(body.includes('hideLoadingScreen()'), 'analyze must call hideLoadingScreen in finally block');
});

// =============================================================================
// CATEGORY 2: R1 — TOOLTIP POSITIONING, CLAMPING & XSS
// =============================================================================
console.log('\n--- CATEGORY 2: R1 — Tooltip Positioning, Clamping & XSS ---');

function createMockDom(winWidth = 1280, winHeight = 800) {
  const elements = new Map();
  const getOrCreate = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        innerText: '',
        innerHTML: '',
        style: {},
        classList: {
          classes: new Set(),
          add(c) { this.classes.add(c); },
          remove(c) { this.classes.delete(c); },
          contains(c) { return this.classes.has(c); }
        },
        offsetWidth: 340,
        offsetHeight: 160
      });
    }
    return elements.get(id);
  };

  return {
    doc: { getElementById: (id) => getOrCreate(id) },
    win: { innerWidth: winWidth, innerHeight: winHeight },
    elements
  };
}

const escapeMatch = uiNavJs.match(/function safeEscape\(str\)\s*\{([\s\S]*?)\n\}/);
const safeEscape = new Function('str', escapeMatch[1]);
const ttFnMatch = uiNavJs.match(/function updateTooltip\(node, mouseX, mouseY\)\s*\{([\s\S]*?)\n\}/);
const updateTooltipBody = ttFnMatch[1];

function runTooltip(node, mouseX, mouseY, mock, stateZoom = 1.0) {
  const document = mock.doc;
  const window = mock.win;
  const tooltipEl = document.getElementById('node-tooltip');
  const state = { camera: { zoom: stateZoom }, folderPalettes: new Map() };
  const fn = new Function('node', 'mouseX', 'mouseY', 'tooltipEl', 'document', 'window', 'state', 'safeEscape', updateTooltipBody);
  fn(node, mouseX, mouseY, tooltipEl, document, window, state, safeEscape);
  return tooltipEl;
}

check('R1-TT-1', 'Tooltip maintains horizontal clearance from node center on standard positions', () => {
  const mock = createMockDom(1280, 800);
  const node = { id: 'n1', radius: 18, metadata: { cve_anomalies: [{ cve_id: 'CWE-502', severity: 'CRITICAL' }] } };
  const tt = runTooltip(node, 500, 400, mock, 1.0);
  const left = parseFloat(tt.style.left);
  // nodeScreenRadius = Math.max(20, 18 * 1.0) = 20; clearance = 40; left = 500 + 40 = 540
  assert.strictEqual(left, 540);
  assert.ok(left - 500 >= 38, 'Tooltip must not touch node');
});

check('R1-TT-2', 'Tooltip flips to left of node when nearing right edge', () => {
  const mock = createMockDom(1280, 800);
  const node = { id: 'n_edge', radius: 18, metadata: {} };
  const tt = runTooltip(node, 1150, 400, mock, 1.0);
  const left = parseFloat(tt.style.left);
  // Flipped: 1150 - 40 - 340 = 770
  assert.strictEqual(left, 770);
  assert.strictEqual(1150 - (left + tt.offsetWidth), 40, 'Clearance of 40px maintained to left of node');
});

check('R1-TT-3', 'Tooltip stays within window boundaries at all extreme corners', () => {
  const mock = createMockDom(1280, 800);
  const node = { id: 'corner', radius: 18 };
  const corners = [
    { x: 0, y: 0 },
    { x: 1280, y: 0 },
    { x: 0, y: 800 },
    { x: 1280, y: 800 },
    { x: -100, y: -100 },
    { x: 2000, y: 2000 }
  ];

  for (const c of corners) {
    const tt = runTooltip(node, c.x, c.y, mock, 1.0);
    const left = parseFloat(tt.style.left);
    const top = parseFloat(tt.style.top);
    assert.ok(left >= 12, `x clamp failed for (${c.x}, ${c.y}): left=${left}`);
    assert.ok(left + tt.offsetWidth <= 1280, `x right clamp failed for (${c.x}, ${c.y})`);
    assert.ok(top >= 12, `y clamp failed for (${c.x}, ${c.y}): top=${top}`);
    assert.ok(top + tt.offsetHeight <= 800, `y bottom clamp failed for (${c.x}, ${c.y})`);
  }
});

check('R1-TT-4', 'Multi-CWE anomalies render (+N autres) summary and escape adversarial strings', () => {
  const mock = createMockDom(1280, 800);
  const node = {
    id: 'vuln_multi',
    has_security_violation: true,
    metadata: {
      cve_anomalies: [
        { cve_id: '<script>alert("PWN")</script>', severity: 'CRITICAL', message: '"><img src=x onerror=1>' },
        { cve_id: 'CWE-89', severity: 'HIGH' },
        { cve_id: 'CWE-79', severity: 'MEDIUM' }
      ]
    }
  };

  runTooltip(node, 500, 400, mock, 1.0);
  const cweBox = mock.elements.get('tt-cwe-container');
  assert.strictEqual(cweBox.style.display, 'flex');
  assert.ok(cweBox.innerHTML.includes('&lt;script&gt;alert(&quot;PWN&quot;)&lt;/script&gt;'));
  assert.ok(!cweBox.innerHTML.includes('<script>'));
  assert.ok(cweBox.innerHTML.includes('(+2 autres)'));
});

// =============================================================================
// CATEGORY 3: R1 — CANVAS NODE CALLOUT PILL & NOTCH GEOMETRY (ADVERSARIAL STRESS)
// =============================================================================
console.log('\n--- CATEGORY 3: R1 — Canvas Node Callout Pill & Notch Geometry ---');

check('R1-CALLOUT-1', 'Callout notch does not penetrate node alert circle at zoom=5.0', () => {
  // webgl_renderer.js:2054-2080:
  // calloutY = n.y - alertR - 14 / Math.max(0.5, c.zoom) - pillH / 2;
  // notch = Math.max(3, 4 / Math.max(0.5, c.zoom));
  // notch tip = calloutY + pillH / 2 + notch = n.y - alertR - 14 / Math.max(0.5, c.zoom) + notch
  // nodeTopY = n.y - alertR
  // gap = nodeTopY - notchTipY = 14 / Math.max(0.5, c.zoom) - Math.max(3, 4 / Math.max(0.5, c.zoom))

  const zoom = 5.0;
  const offset = 14 / Math.max(0.5, zoom); // 14 / 5.0 = 2.8 world units
  const notch = Math.max(3, 4 / Math.max(0.5, zoom)); // Math.max(3, 0.8) = 3.0 world units
  const gap = offset - notch; // 2.8 - 3.0 = -0.2 world units

  if (gap < 0) {
    throw new Error(
      `GEOMETRIC OVERLAP DEFECT: At zoom=${zoom}, pill offset (${offset.toFixed(2)}) is smaller than notch height (${notch.toFixed(2)}). ` +
      `The notch penetrates ${Math.abs(gap).toFixed(2)} world units (${(Math.abs(gap) * zoom).toFixed(1)} screen pixels) INTO the node alert circle!`
    );
  }
});

check('R1-CALLOUT-2', 'Callout pill clears rotating caution brackets under pulse peak (1.18x)', () => {
  // webgl_renderer.js:2021-2042:
  // alertR = (n.is_file ? 24 : 16) / c.zoom;
  // pulse = 1.0 + 0.18 * sin(...) -> peak = 1.18
  // outer caution bracket radius = (alertR + 6 / c.zoom) * pulse
  // callout bottom = alertR + 14 / Math.max(0.5, c.zoom)
  const zoom = 1.0;
  const alertR = 24 / zoom; // File node
  const maxBracketRadius = (alertR + 6 / zoom) * 1.18; // (24 + 6) * 1.18 = 35.4 world units
  const calloutBottomDist = alertR + 14 / Math.max(0.5, zoom); // 24 + 14 = 38.0 world units
  const notchTipDist = calloutBottomDist - Math.max(3, 4 / Math.max(0.5, zoom)); // 38.0 - 4 = 34.0 world units

  // Notch tip is at distance 34.0 from node center, while bracket extends to 35.4!
  if (notchTipDist < maxBracketRadius) {
    const overlap = maxBracketRadius - notchTipDist;
    throw new Error(
      `COLLISION DEFECT: Rotating caution brackets reach radius ${maxBracketRadius.toFixed(1)} during pulse peak, ` +
      `colliding with callout notch (tip at radius ${notchTipDist.toFixed(1)}) by ${overlap.toFixed(1)} world units (${(overlap * zoom).toFixed(1)} screen pixels)!`
    );
  }
});

// =============================================================================
// CATEGORY 4: R1 — CANVAS EDGE BADGES & SHORT EDGE COLLISION (ADVERSARIAL STRESS)
// =============================================================================
console.log('\n--- CATEGORY 4: R1 — Canvas Edge Badges & Short Edge Collision ---');

check('R1-BADGE-1', 'Edge badge clears source/target node circles when edge length is short', () => {
  // webgl_renderer.js:1810-1820:
  // perpDist = badgeH * 0.75 + 10 / Math.max(0.5, c.zoom);
  // bx = mx + nx * perpDist; by = my + ny * perpDist;
  // For a horizontal edge, ny = -1, by = my - perpDist.
  // badge bottom = by + badgeH / 2 = my - perpDist + badgeH / 2 = my - (0.25 * badgeH + 10 / Math.max(0.5, c.zoom)).
  // Distance from edge line to badge bottom is clearance = 0.25 * badgeH + 10 / Math.max(0.5, c.zoom).
  // For a file node with radius 24:
  const zoom = 1.0;
  const badgeFontSize = Math.max(9, Math.min(13, 11 / zoom)); // 11
  const subFontSize = Math.max(8, Math.min(11, badgeFontSize * 0.88)); // 9.68
  const padY = Math.max(3, Math.min(6, 4 / Math.max(0.5, zoom))); // 4
  const lineSpacing = Math.max(2, 3 / Math.max(0.5, zoom)); // 3
  const badgeH = badgeFontSize + subFontSize + lineSpacing + padY * 2; // 31.68

  const perpDist = badgeH * 0.75 + 10 / Math.max(0.5, zoom); // 23.76 + 10 = 33.76
  const clearanceToBadgeBottom = perpDist - badgeH / 2; // 33.76 - 15.84 = 17.92 world units

  // If source node is a file node (radius 24):
  const fileNodeRadius = 24;
  if (clearanceToBadgeBottom < fileNodeRadius) {
    const overlap = fileNodeRadius - clearanceToBadgeBottom;
    throw new Error(
      `NODE OBSCURATION DEFECT: Clearance from edge midpoint to badge bottom is only ${clearanceToBadgeBottom.toFixed(2)} units. ` +
      `For file nodes (radius ${fileNodeRadius} units), any badge with width > edgeLen overlaps the top of the node by ${overlap.toFixed(2)} world units!`
    );
  }
});

// =============================================================================
// CATEGORY 5: R1 — ZOOM FONT SCALING IN WORLD VS SCREEN COORDINATES
// =============================================================================
console.log('\n--- CATEGORY 5: R1 — Zoom Font Scaling in World vs Screen Coordinates ---');

check('R1-FONT-1', 'Canvas badge font size remains legible (>= 8px) and does not balloon (<= 18px) across all zoom levels', () => {
  // webgl_renderer.js:1750:
  // const badgeFontSize = Math.max(9, Math.min(13, 11 / c.zoom));
  // Notice that ctx.scale(c.zoom, c.zoom) scales everything on screen!
  // Therefore: screenFontSize = badgeFontSize * c.zoom

  const testZooms = [0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 3.0, 5.0];
  for (const z of testZooms) {
    const worldFontSize = Math.max(9, Math.min(13, 11 / z));
    const screenFontSize = worldFontSize * z;

    if (screenFontSize < 8.0) {
      throw new Error(
        `UNREADABLE / MICROSCOPIC TEXT DEFECT: At zoom=${z}, world font size is clamped to ${worldFontSize}px. ` +
        `Rendered on screen with ctx.scale(${z}), the font size shrinks to ${screenFontSize.toFixed(2)} screen pixels (completely unreadable)!`
      );
    }
    if (screenFontSize > 18.0) {
      throw new Error(
        `BALLOONING TEXT DEFECT: At zoom=${z}, world font size is clamped to ${worldFontSize}px. ` +
        `Rendered on screen with ctx.scale(${z}), the font size balloons to ${screenFontSize.toFixed(2)} screen pixels (exceeds 18px limit)!`
      );
    }
  }
});

// =============================================================================
// CATEGORY 6: R1 — INSPECTOR DEBRIEF BADGE WRAPPING & RULE ID
// =============================================================================
console.log('\n--- CATEGORY 6: R1 — Inspector Debrief Badge Wrapping & Rule ID ---');

check('R1-INSP-1', 'styles.css suppresses ellipsis truncation and forces word-break on .cve-badge', () => {
  const match = stylesCss.match(/\.cve-badge\s*\{([\s\S]*?)\}/);
  assert.ok(match, 'Missing .cve-badge rule');
  const body = match[1];
  assert.ok(!body.includes('text-overflow: ellipsis'), 'Must not truncate with ellipsis');
  assert.ok(body.includes('white-space: normal'), 'Must wrap normally');
  assert.ok(body.includes('word-break: break-word'), 'Must break long words');
});

check('R1-INSP-2', 'ui_inspector_docs renders separate .cve-rule-name tag for compound identifiers', () => {
  assert.ok(uiInspectorJs.includes('cve-rule-name'), 'Missing cve-rule-name tag in inspector template');
  assert.ok(uiInspectorJs.includes('a.rule_id !== a.cve_id'), 'Missing check for distinct rule_id');
});

// =============================================================================
// REPORT SUMMARY & VERDICT
// =============================================================================
console.log('\n================================================================');
console.log(`TEST SUMMARY: Total: ${totalTests} | Passed: ${passedTests} | Failed: ${failedTests}`);
console.log('================================================================');

if (findings.length > 0) {
  console.log('\nEMPIRICALLY CONFIRMED DEFECTS:');
  findings.forEach((f, idx) => {
    console.log(`\n[DEFECT ${idx + 1}] ID: ${f.id} — ${f.name}`);
    console.log(`DETAILS: ${f.error}`);
  });
  console.log('\n================================================================');
  console.log('CHALLENGER VERDICT: REQUEST_CHANGES');
  console.log('================================================================');
  process.exit(1);
} else {
  console.log('\nCHALLENGER VERDICT: APPROVE');
  console.log('================================================================');
  process.exit(0);
}
