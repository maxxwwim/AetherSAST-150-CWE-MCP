import { getFolderColor, formatFolderLabel, type RgbaColor } from '../engine/palette';
import {
  getNodeAlertKind,
  isLinesExceededAnomaly,
  formatCweShortId,
  normalizeEdgeRelation,
  getArchitecturalModule,
  type CockpitState,
} from '../state/graphState.svelte';
import type { CveAnomalyRecord, SymbolBubble } from '../types/graph';

const VIEW_W = 1000;
const VIEW_H = 540;
const PAD_X = 72;
const PAD_Y = 78;
const MAX_RENDERED_BUBBLES = 220;
const MAX_RENDERED_MEMBRANES = 32;
const MAX_RENDERED_EDGES = 150;
const MAX_CWE_PILLS = 18;
const MAX_NODE_LABELS = 26;
const GOLDEN_ANGLE = 2.399963229728653;

type BubbleKind = 'file' | 'class' | 'form' | 'func';
type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LINES' | 'NONE';
type EdgeVisualKind =
  | 'violates'
  | 'warns'
  | 'queries'
  | 'realtime'
  | 'network'
  | 'submits'
  | 'imports'
  | 'calls';

interface PreparedBubble {
  node: SymbolBubble;
  folder: string;
  kind: BubbleKind;
  alert: AlertSeverity;
  cweCode: string;
  cweExtra: number;
  violationCount: number;
  isHotspot: boolean;
  x: number;
  y: number;
  diam: number;
  rgb: [number, number, number];
  lightRgb: [number, number, number];
  priority: number;
}

interface PreparedMembrane {
  folder: string;
  label: string;
  count: number;
  alertCount: number;
  maxSeverity: AlertSeverity;
  cx: number;
  cy: number;
  rx: number;
  ry: number;
  rgb: [number, number, number];
  lightRgb: [number, number, number];
  borderRadius: string;
  breathDelay: number;
}

interface PreparedEdge {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  dist: number;
  angleRad: number;
  kind: EdgeVisualKind;
  priority: number;
}

interface RectBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

const HTML_ESCAPE_RE = /[&<>"']/;

function escapeHtml(str?: string): string {
  if (!str) return '';
  const s = String(str);
  if (!HTML_ESCAPE_RE.test(s)) return s;
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function pct2(val: number): number {
  return Math.round(val * 100) / 100;
}

function pct3(val: number): number {
  return Math.round(val * 1000) / 1000;
}

function normalizePath(p?: string): string {
  if (!p) return '';
  const s = String(p);
  return (s.includes('\\') ? s.replace(/\\/g, '/') : s).toLowerCase().trim();
}

function hashString(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function rgbaToTriplet(col: RgbaColor): [number, number, number] {
  return [
    Math.max(0, Math.min(255, Math.round(col.r * 255))),
    Math.max(0, Math.min(255, Math.round(col.g * 255))),
    Math.max(0, Math.min(255, Math.round(col.b * 255))),
  ];
}

function brightenRgb([r, g, b]: [number, number, number]): [number, number, number] {
  return [Math.min(255, r + 88), Math.min(255, g + 88), Math.min(255, b + 102)];
}

function resolveNodeFolder(n: SymbolBubble, folderCache: Map<string, string>): string {
  const direct = (n.cluster_id || n.folder || '').trim();
  if (direct && direct !== 'root') return direct;
  const rawFp = n.file_path;
  if (rawFp) {
    const cached = folderCache.get(rawFp);
    if (cached !== undefined) return cached;
    const fp = (rawFp.includes('\\') ? rawFp.replace(/\\/g, '/') : rawFp).trim();
    const clean = fp.startsWith('./') ? fp.slice(2) : fp;
    const slash = clean.lastIndexOf('/');
    const resolved =
      slash > 0
        ? getArchitecturalModule(clean.slice(0, slash))
        : direct || (n.layer ? String(n.layer).toLowerCase() : 'root');
    folderCache.set(rawFp, resolved);
    return resolved;
  }
  return direct || (n.layer ? String(n.layer).toLowerCase() : 'root');
}

function classifyBubble(n: SymbolBubble): BubbleKind {
  const kind = String(n.kind || n.symbol_type || '').toLowerCase();
  const isFunc =
    kind === 'function' ||
    kind === 'method' ||
    n.stereotype === '«Function»' ||
    n.stereotype === '«Method»';
  if (isFunc) return 'func';
  if (n.is_file || kind === 'file' || n.stereotype === '«File»') return 'file';
  if (
    n.is_class ||
    kind === 'class' ||
    kind === 'struct' ||
    kind === 'interface' ||
    kind === 'trait' ||
    kind === 'enum' ||
    n.stereotype === '«Class»'
  ) {
    return 'class';
  }
  if (
    n.is_form ||
    kind === 'endpoint' ||
    kind === 'form' ||
    n.stereotype === '«Endpoint»' ||
    n.stereotype === '«Form»'
  ) {
    return 'form';
  }
  return 'file';
}

function severityRank(sev: AlertSeverity): number {
  if (sev === 'CRITICAL') return 4;
  if (sev === 'HIGH') return 3;
  if (sev === 'MEDIUM') return 2;
  if (sev === 'LINES') return 1;
  return 0;
}

function rankAnomalySeverity(sev?: string): number {
  const u = String(sev || '').toUpperCase();
  if (u === 'CRITICAL') return 3;
  if (u === 'HIGH') return 2;
  if (u === 'MEDIUM') return 1;
  return 0;
}

function buildFileViolationMap(
  nodes: SymbolBubble[],
  violations: CveAnomalyRecord[]
): Map<string, CveAnomalyRecord[]> {
  const byNodeId = new Map<string, CveAnomalyRecord[]>();
  if (violations.length === 0 || nodes.length === 0) return byNodeId;

  const violByPath = new Map<string, CveAnomalyRecord[]>();
  for (let i = 0; i < violations.length; i++) {
    const v = violations[i];
    const key = normalizePath(v.file_path);
    if (!key) continue;
    let list = violByPath.get(key);
    if (!list) {
      list = [];
      violByPath.set(key, list);
    }
    list.push(v);
  }
  if (violByPath.size === 0) return byNodeId;

  const primaryNodeByFile = new Map<string, string>();
  const pathCache = new Map<string, string>();
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    const rawFp = n.file_path;
    if (!rawFp) continue;
    let key = pathCache.get(rawFp);
    if (key === undefined) {
      key = normalizePath(rawFp);
      pathCache.set(rawFp, key);
    }
    if (!violByPath.has(key)) continue;
    const prevId = primaryNodeByFile.get(key);
    if (!prevId || n.is_file || n.kind === 'File' || n.kind === 'file') {
      primaryNodeByFile.set(key, n.id);
    }
  }

  for (const [key, list] of violByPath.entries()) {
    const targetNodeId = primaryNodeByFile.get(key);
    if (targetNodeId) byNodeId.set(targetNodeId, list);
  }
  return byNodeId;
}

function resolveBubbleAlert(
  n: SymbolBubble,
  fallbackViolations: CveAnomalyRecord[] | undefined,
  isIgnored?: (ruleId?: string, cveId?: string) => boolean
): { alert: AlertSeverity; cweCode: string; cweExtra: number; violationCount: number } {
  const hasInline =
    (n.anomalies && n.anomalies.length > 0) ||
    (n.violations && n.violations.length > 0) ||
    (n.metadata?.cve_anomalies && n.metadata.cve_anomalies.length > 0);
  if (!hasInline && (!fallbackViolations || fallbackViolations.length === 0)) {
    if (!n.has_security_violation && !(n.metadata?.violations && n.metadata.violations.length > 0)) {
      const maxLim = n.metadata?.max_lines_limit;
      const curLoc = n.loc || n.metadata?.lines || 0;
      if (!maxLim || maxLim <= 0 || curLoc <= maxLim) {
        return { alert: 'NONE', cweCode: '', cweExtra: 0, violationCount: 0 };
      }
    }
  }

  let combined: CveAnomalyRecord[];
  if (hasInline) {
    combined = [];
    if (n.anomalies) combined.push(...n.anomalies);
    if (n.violations) combined.push(...n.violations);
    if (n.metadata?.cve_anomalies) combined.push(...n.metadata.cve_anomalies);
  } else {
    combined = fallbackViolations || [];
  }
  const filtered = isIgnored
    ? combined.filter((a) => !isIgnored(a.rule_id, a.cve_id))
    : combined;

  const secAnoms = filtered.filter((a) => !isLinesExceededAnomaly(a));
  if (secAnoms.length > 0) {
    const sorted = [...secAnoms].sort(
      (a, b) => rankAnomalySeverity(b.severity) - rankAnomalySeverity(a.severity)
    );
    const primary = sorted[0];
    const topSev = String(primary.severity || 'HIGH').toUpperCase();
    const alert: AlertSeverity =
      topSev === 'CRITICAL' ? 'CRITICAL' : topSev === 'HIGH' ? 'HIGH' : 'MEDIUM';
    return {
      alert,
      cweCode: formatCweShortId(primary.cve_id, primary.rule_id),
      cweExtra: Math.max(0, sorted.length - 1),
      violationCount: sorted.length,
    };
  }

  const kind = getNodeAlertKind(n, isIgnored);
  if (kind === 'security') {
    return { alert: 'HIGH', cweCode: 'CWE', cweExtra: 0, violationCount: 1 };
  }
  if (kind === 'lines_exceeded') {
    const lim = n.metadata?.max_lines_limit || 300;
    const loc = n.loc || n.metadata?.lines || 0;
    return {
      alert: 'LINES',
      cweCode: loc > 0 ? `${loc}/${lim}L` : 'MAX L',
      cweExtra: 0,
      violationCount: 1,
    };
  }
  return { alert: 'NONE', cweCode: '', cweExtra: 0, violationCount: 0 };
}

function getAlertRgb(alert: AlertSeverity): [number, number, number] | null {
  if (alert === 'CRITICAL') return [244, 63, 94];
  if (alert === 'HIGH') return [251, 146, 60];
  if (alert === 'MEDIUM') return [250, 204, 21];
  if (alert === 'LINES') return [245, 158, 11];
  return null;
}

function selectAndScoreBubbles(
  nodes: SymbolBubble[],
  violations: CveAnomalyRecord[],
  isIgnored?: (ruleId?: string, cveId?: string) => boolean
): { bubbles: PreparedBubble[]; folderTotals: Map<string, number>; folderAlerts: Map<string, number> } {
  const folderTotals = new Map<string, number>();
  const folderAlerts = new Map<string, number>();
  const folderCache = new Map<string, string>();
  const fallbackByNode = buildFileViolationMap(nodes, violations);
  const all: PreparedBubble[] = [];
  const folderSeen = new Set<string>();

  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    const folder = resolveNodeFolder(n, folderCache);
    folderTotals.set(folder, (folderTotals.get(folder) || 0) + 1);

    const kind = classifyBubble(n);
    const alertInfo = resolveBubbleAlert(n, fallbackByNode.get(n.id), isIgnored);
    if (alertInfo.alert !== 'NONE' && alertInfo.alert !== 'LINES') {
      folderAlerts.set(folder, (folderAlerts.get(folder) || 0) + alertInfo.violationCount);
    }

    const cc = n.cyclomatic_complexity || n.complexity || 1;
    const isHotspot = cc >= 10;
    const deg = (n.in_degree || 0) + (n.out_degree || 0);

    let priority = 0;
    if (alertInfo.alert === 'CRITICAL') priority += 1200;
    else if (alertInfo.alert === 'HIGH') priority += 900;
    else if (alertInfo.alert === 'MEDIUM') priority += 650;
    else if (alertInfo.alert === 'LINES') priority += 420;
    if (isHotspot) priority += 260 + Math.min(80, cc);
    if (kind === 'file') priority += 190;
    else if (kind === 'class' || kind === 'form') priority += 145;
    priority += Math.min(100, deg * 6);
    if (!folderSeen.has(folder) && folderSeen.size < 64) {
      folderSeen.add(folder);
      priority += 320;
    }

    all.push({
      node: n,
      folder,
      kind,
      alert: alertInfo.alert,
      cweCode: alertInfo.cweCode,
      cweExtra: alertInfo.cweExtra,
      violationCount: alertInfo.violationCount,
      isHotspot,
      x: Number.isFinite(n.x) ? n.x : NaN,
      y: Number.isFinite(n.y) ? n.y : NaN,
      diam: 12,
      rgb: [56, 189, 248],
      lightRgb: [144, 255, 255],
      priority,
    });
  }

  let selected = all;
  if (all.length > MAX_RENDERED_BUBBLES) {
    selected = all.sort((a, b) => b.priority - a.priority).slice(0, MAX_RENDERED_BUBBLES);
  }
  for (let i = 0; i < selected.length; i++) {
    const b = selected[i];
    const baseRgb = getAlertRgb(b.alert) || rgbaToTriplet(getFolderColor(b.folder));
    b.rgb = baseRgb;
    b.lightRgb = brightenRgb(baseRgb);
  }
  return { bubbles: selected, folderTotals, folderAlerts };
}

function hasLiveSpatialLayout(bubbles: PreparedBubble[]): boolean {
  if (bubbles.length === 0) return false;
  let valid = 0;
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const b of bubbles) {
    if (Number.isFinite(b.x) && Number.isFinite(b.y)) {
      valid++;
      if (b.x < minX) minX = b.x;
      if (b.x > maxX) maxX = b.x;
      if (b.y < minY) minY = b.y;
      if (b.y > maxY) maxY = b.y;
    }
  }
  if (valid < Math.max(1, bubbles.length * 0.75)) return false;
  if (bubbles.length === 1) return true;
  return maxX - minX > 4 || maxY - minY > 4;
}

function computeSyntheticGalaxyLayout(
  bubbles: PreparedBubble[],
  folderAlerts: Map<string, number>
): void {
  const byFolder = new Map<string, PreparedBubble[]>();
  for (const b of bubbles) {
    let list = byFolder.get(b.folder);
    if (!list) {
      list = [];
      byFolder.set(b.folder, list);
    }
    list.push(b);
  }

  const folders = Array.from(byFolder.entries()).sort((a, b) => {
    const alertDiff = (folderAlerts.get(b[0]) || 0) - (folderAlerts.get(a[0]) || 0);
    if (alertDiff !== 0) return alertDiff;
    if (b[1].length !== a[1].length) return b[1].length - a[1].length;
    return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
  });

  const placed: { cx: number; cy: number; r: number }[] = [];
  const aspectX = 1.62;

  for (let idx = 0; idx < folders.length; idx++) {
    const [, list] = folders[idx];
    const clusterR = Math.max(26, Math.sqrt(list.length) * 14.5 + 16);
    let cx = 0;
    let cy = 0;

    if (idx > 0) {
      let placedOk = false;
      for (let step = 1; step <= 420; step++) {
        const theta = idx * GOLDEN_ANGLE + step * 0.42;
        const rad = 28 + Math.sqrt(step) * 26;
        const candX = Math.cos(theta) * rad * aspectX;
        const candY = Math.sin(theta) * rad;
        let collides = false;
        for (const p of placed) {
          if (Math.hypot(candX - p.cx, candY - p.cy) < clusterR + p.r + 16) {
            collides = true;
            break;
          }
        }
        if (!collides) {
          cx = candX;
          cy = candY;
          placedOk = true;
          break;
        }
      }
      if (!placedOk) {
        const fallbackA = idx * GOLDEN_ANGLE;
        cx = Math.cos(fallbackA) * (160 + idx * 30) * aspectX;
        cy = Math.sin(fallbackA) * (160 + idx * 30);
      }
    }
    placed.push({ cx, cy, r: clusterR });

    const ordered = [...list].sort((a, b) => b.priority - a.priority);
    const orbitMax = Math.max(10, clusterR - 11);
    for (let j = 0; j < ordered.length; j++) {
      const b = ordered[j];
      if (ordered.length === 1) {
        b.x = cx;
        b.y = cy;
      } else {
        const frac = Math.sqrt((j + 0.45) / ordered.length);
        const angle = j * GOLDEN_ANGLE + (idx % 7) * 0.4;
        const dist = j === 0 && ordered.length <= 5 ? 0 : frac * orbitMax;
        b.x = cx + Math.cos(angle) * dist;
        b.y = cy + Math.sin(angle) * dist;
      }
    }
  }
}

function normalizeBubbleCoordinates(bubbles: PreparedBubble[]): void {
  if (bubbles.length === 0) return;

  // Fill any missing coordinate from folder centroid or origin
  const sumByFolder = new Map<string, { sx: number; sy: number; n: number }>();
  for (const b of bubbles) {
    if (Number.isFinite(b.x) && Number.isFinite(b.y)) {
      const cur = sumByFolder.get(b.folder) || { sx: 0, sy: 0, n: 0 };
      cur.sx += b.x;
      cur.sy += b.y;
      cur.n += 1;
      sumByFolder.set(b.folder, cur);
    }
  }
  for (let i = 0; i < bubbles.length; i++) {
    const b = bubbles[i];
    if (!Number.isFinite(b.x) || !Number.isFinite(b.y)) {
      const c = sumByFolder.get(b.folder);
      const a = i * GOLDEN_ANGLE;
      b.x = (c ? c.sx / c.n : 0) + Math.cos(a) * 12;
      b.y = (c ? c.sy / c.n : 0) + Math.sin(a) * 12;
    }
  }

  if (bubbles.length === 1) {
    bubbles[0].x = VIEW_W * 0.5;
    bubbles[0].y = VIEW_H * 0.5;
    return;
  }

  // Soft outlier clamping for very large live graphs with one far-away stray node
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  if (bubbles.length >= 24) {
    const xs = bubbles.map((b) => b.x).sort((a, b) => a - b);
    const ys = bubbles.map((b) => b.y).sort((a, b) => a - b);
    const lo = Math.floor(bubbles.length * 0.02);
    const hi = Math.min(bubbles.length - 1, Math.ceil(bubbles.length * 0.98));
    const coreSpanX = Math.max(1, xs[hi] - xs[lo]);
    const coreSpanY = Math.max(1, ys[hi] - ys[lo]);
    const rawSpanX = xs[xs.length - 1] - xs[0];
    const rawSpanY = ys[ys.length - 1] - ys[0];
    if (rawSpanX > coreSpanX * 4 || rawSpanY > coreSpanY * 4) {
      const clampMinX = xs[lo] - coreSpanX * 0.15;
      const clampMaxX = xs[hi] + coreSpanX * 0.15;
      const clampMinY = ys[lo] - coreSpanY * 0.15;
      const clampMaxY = ys[hi] + coreSpanY * 0.15;
      for (const b of bubbles) {
        b.x = Math.max(clampMinX, Math.min(clampMaxX, b.x));
        b.y = Math.max(clampMinY, Math.min(clampMaxY, b.y));
      }
    }
  }

  for (const b of bubbles) {
    if (b.x < minX) minX = b.x;
    if (b.x > maxX) maxX = b.x;
    if (b.y < minY) minY = b.y;
    if (b.y > maxY) maxY = b.y;
  }

  const usableW = VIEW_W - PAD_X * 2;
  const usableH = VIEW_H - PAD_Y * 2;
  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);
  const scale = Math.min(usableW / spanX, usableH / spanY);
  const cx = (minX + maxX) * 0.5;
  const cy = (minY + maxY) * 0.5;

  for (const b of bubbles) {
    b.x = VIEW_W * 0.5 + (b.x - cx) * scale;
    b.y = VIEW_H * 0.5 + (b.y - cy) * scale;
  }
}

function assignBubbleDiameters(bubbles: PreparedBubble[]): void {
  const count = bubbles.length;
  const densityScale = count <= 25 ? 1.24 : count <= 90 ? 1.0 : count <= 180 ? 0.84 : 0.72;
  for (const b of bubbles) {
    const base =
      b.kind === 'file' ? 18.5 : b.kind === 'class' ? 16.5 : b.kind === 'form' ? 15.5 : 10.5;
    const locBoost = Math.min(3.5, Math.log1p(b.node.loc || 1) * 0.55);
    const alertBoost = b.alert !== 'NONE' ? 1.18 : b.isHotspot ? 1.12 : 1.0;
    b.diam = Math.max(7.2, Math.min(28, (base + locBoost) * densityScale * alertBoost));
  }
}

function buildOrganicBorderRadius(seed: number): string {
  const v = (shift: number) => 46 + ((seed >>> shift) % 9);
  const a = v(0);
  const b = v(4);
  const c = v(8);
  const d = v(12);
  return `${a}% ${100 - a}% ${b}% ${100 - b}% / ${c}% ${d}% ${100 - d}% ${100 - c}%`;
}

function buildMembranes(
  bubbles: PreparedBubble[],
  folderTotals: Map<string, number>,
  folderAlerts: Map<string, number>
): PreparedMembrane[] {
  const groups = new Map<string, PreparedBubble[]>();
  for (const b of bubbles) {
    let list = groups.get(b.folder);
    if (!list) {
      list = [];
      groups.set(b.folder, list);
    }
    list.push(b);
  }

  const membranes: PreparedMembrane[] = [];
  const skipSingletons = groups.size > 24;

  for (const [folder, list] of groups.entries()) {
    const alertCount = folderAlerts.get(folder) || 0;
    if (skipSingletons && list.length < 2 && alertCount === 0) continue;

    let sumX = 0;
    let sumY = 0;
    let maxSeverity: AlertSeverity = 'NONE';
    for (const b of list) {
      sumX += b.x;
      sumY += b.y;
      if (severityRank(b.alert) > severityRank(maxSeverity)) {
        maxSeverity = b.alert;
      }
    }
    const cx = sumX / list.length;
    const cy = sumY / list.length;

    let maxDx = 0;
    let maxDy = 0;
    let maxDist = 0;
    for (const b of list) {
      const pad = b.diam * 0.55 + 11;
      const dx = Math.abs(b.x - cx) + pad;
      const dy = Math.abs(b.y - cy) + pad;
      const dist = Math.hypot(b.x - cx, b.y - cy) + pad;
      if (dx > maxDx) maxDx = dx;
      if (dy > maxDy) maxDy = dy;
      if (dist > maxDist) maxDist = dist;
    }

    const baseR = Math.max(26, Math.min(185, maxDist + 8));
    let rx = Math.max(26, Math.min(205, Math.max(maxDx + 10, baseR * 0.88)));
    let ry = Math.max(24, Math.min(175, Math.max(maxDy + 10, baseR * 0.84)));

    // Keep membranes organically rounded rather than paper-thin slivers
    if (rx > ry * 1.75) ry = rx / 1.75;
    if (ry > rx * 1.65) rx = ry / 1.65;

    const col = rgbaToTriplet(getFolderColor(folder));
    const seed = hashString(folder);
    membranes.push({
      folder,
      label: formatFolderLabel(folder),
      count: folderTotals.get(folder) || list.length,
      alertCount,
      maxSeverity,
      cx,
      cy,
      rx,
      ry,
      rgb: col,
      lightRgb: brightenRgb(col),
      borderRadius: buildOrganicBorderRadius(seed),
      breathDelay: +(((seed % 80) / 10) * -1).toFixed(1),
    });
  }

  membranes.sort((a, b) => {
    const aAlert = a.alertCount > 0 ? 1 : 0;
    const bAlert = b.alertCount > 0 ? 1 : 0;
    if (bAlert !== aAlert) return bAlert - aAlert;
    return b.count - a.count;
  });
  return membranes.slice(0, MAX_RENDERED_MEMBRANES);
}

function classifyEdgeKind(
  rel: string,
  cveId: string | undefined,
  severity: string | undefined,
  targetLayer: string | undefined
): { kind: EdgeVisualKind; priority: number } {
  const isWarn =
    rel === 'warns' ||
    String(severity || '').toUpperCase() === 'WARNING' ||
    Boolean(cveId && cveId.includes('ARCH-BUDGET-EXCEEDED'));
  if (isWarn) return { kind: 'warns', priority: 85 };
  if (rel === 'violates' || Boolean(cveId)) return { kind: 'violates', priority: 110 };
  if (rel === 'submits') return { kind: 'submits', priority: 75 };
  if (rel === 'network') return { kind: 'network', priority: 72 };
  if (rel === 'realtime') return { kind: 'realtime', priority: 70 };
  if (rel === 'queries' || String(targetLayer || '').toLowerCase() === 'database') {
    return { kind: 'queries', priority: 68 };
  }
  if (rel === 'imports' || rel === 'inherits') return { kind: 'imports', priority: 44 };
  if (rel === 'contains') return { kind: 'imports', priority: 12 };
  return { kind: 'calls', priority: 58 };
}

function prepareEdges(
  cockpitState: CockpitState,
  bubbles: PreparedBubble[]
): PreparedEdge[] {
  const rawEdges = cockpitState.graph?.edges || [];
  if (rawEdges.length === 0 || bubbles.length < 2) return [];

  const bubbleMap = new Map<string, PreparedBubble>();
  for (const b of bubbles) bubbleMap.set(b.node.id, b);

  const seen = new Set<string>();
  const edges: PreparedEdge[] = [];

  for (let i = 0; i < rawEdges.length; i++) {
    const e = rawEdges[i];
    if (!e || e.source === e.target) continue;
    const s = bubbleMap.get(e.source);
    const t = bubbleMap.get(e.target);
    if (!s || !t) continue;

    const dx = t.x - s.x;
    const dy = t.y - s.y;
    const dist = Math.hypot(dx, dy);
    if (dist < 6) continue;

    const rel = normalizeEdgeRelation(e.relation || e.edge_type);
    const { kind, priority } = classifyEdgeKind(rel, e.cve_id, e.severity, t.node.layer);
    const dedupKey = `${e.source}|${e.target}|${kind}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const crossBoost = s.folder !== t.folder ? 18 : 0;
    const alertBoost = s.alert !== 'NONE' || t.alert !== 'NONE' ? 14 : 0;

    edges.push({
      x1: s.x,
      y1: s.y,
      x2: t.x,
      y2: t.y,
      dist,
      angleRad: Math.atan2(dy, dx),
      kind,
      priority: priority + crossBoost + alertBoost,
    });
  }

  if (edges.length > MAX_RENDERED_EDGES) {
    edges.sort((a, b) => b.priority - a.priority);
    return edges.slice(0, MAX_RENDERED_EDGES);
  }
  return edges;
}

function rectsCollide(a: RectBox, b: RectBox, gap = 3): boolean {
  return (
    a.x < b.x + b.w + gap &&
    a.x + a.w + gap > b.x &&
    a.y < b.y + b.h + gap &&
    a.y + a.h + gap > b.y
  );
}

function fitsWithoutCollision(cand: RectBox, placed: RectBox[], gap = 3): boolean {
  if (cand.x < 8 || cand.y < 8 || cand.x + cand.w > VIEW_W - 8 || cand.y + cand.h > VIEW_H - 12) {
    return false;
  }
  for (let i = 0; i < placed.length; i++) {
    if (rectsCollide(cand, placed[i], gap)) return false;
  }
  return true;
}

function renderStarsHtml(): string {
  const parts: string[] = [];
  const tints = [
    'rgba(186, 230, 253, 0.82)',
    'rgba(233, 213, 255, 0.78)',
    'rgba(254, 243, 199, 0.72)',
    'rgba(165, 243, 252, 0.88)',
  ];
  for (let i = 0; i < 34; i++) {
    const h = hashString(`aether-star-${i}`);
    const xPct = ((h % 960) / 10 + 2).toFixed(2);
    const yPct = (((h >>> 10) % 940) / 10 + 3).toFixed(2);
    const sizePx = (1.3 + ((h >>> 20) % 18) / 10).toFixed(1);
    const delay = (-(((h >>> 5) % 60) / 10)).toFixed(1);
    const tint = tints[i % tints.length];
    parts.push(
      `<div class="ag-star" style="left:${xPct}%;top:${yPct}%;width:${sizePx}px;height:${sizePx}px;background:${tint};animation-delay:${delay}s;"></div>`
    );
  }
  return parts.join('');
}

function renderMembranesAndPillsHtml(
  membranes: PreparedMembrane[],
  placedBoxes: RectBox[]
): { membranesHtml: string; pillsHtml: string } {
  const memParts: string[] = [];
  const pillParts: string[] = [];

  for (const m of membranes) {
    const [r, g, b] = m.rgb;
    const [lr, lg, lb] = m.lightRgb;
    const isAlert = m.alertCount > 0;
    const leftPct = (((m.cx - m.rx) / VIEW_W) * 100).toFixed(2);
    const topPct = (((m.cy - m.ry) / VIEW_H) * 100).toFixed(2);
    const widthPct = (((m.rx * 2) / VIEW_W) * 100).toFixed(2);
    const heightPct = (((m.ry * 2) / VIEW_H) * 100).toFixed(2);

    const borderCol = isAlert
      ? m.maxSeverity === 'CRITICAL'
        ? 'rgba(244,63,94,0.62)'
        : 'rgba(251,146,60,0.58)'
      : `rgba(${lr},${lg},${lb},0.42)`;

    memParts.push(
      `<div class="ag-membrane${isAlert ? ' ag-membrane-alert' : ''}" style="left:${leftPct}%;top:${topPct}%;width:${widthPct}%;height:${heightPct}%;border-radius:${m.borderRadius};--ag-c:${r},${g},${b};--ag-l:${lr},${lg},${lb};border-color:${borderCol};animation-delay:${m.breathDelay}s;"><div class="ag-membrane-inner" style="border-radius:${m.borderRadius};"></div></div>`
    );

    // Folder pill placement with anti-collision
    const labelStr = m.label || 'root';
    const estW = Math.min(186, Math.max(66, labelStr.length * 6.4 + 34 + (isAlert ? 28 : 0)));
    const estH = 20;
    const crestY = m.cy - m.ry;
    const candidates: [number, number][] = [
      [m.cx - estW * 0.5, crestY - estH - 8],
      [m.cx - estW * 0.5, crestY - estH - 28],
      [m.cx + 8, crestY - estH - 6],
      [m.cx - estW - 8, crestY - estH - 6],
      [m.cx - estW * 0.5, m.cy + m.ry + 6],
    ];

    let chosen: RectBox | null = null;
    for (const [cxRaw, cyRaw] of candidates) {
      const box: RectBox = {
        x: Math.max(8, Math.min(VIEW_W - estW - 8, cxRaw)),
        y: Math.max(8, Math.min(VIEW_H - estH - 12, cyRaw)),
        w: estW,
        h: estH,
      };
      if (fitsWithoutCollision(box, placedBoxes, 4)) {
        chosen = box;
        break;
      }
    }

    if (chosen) {
      placedBoxes.push(chosen);
      const pillCx = chosen.x + chosen.w * 0.5;
      const pLeft = ((pillCx / VIEW_W) * 100).toFixed(2);
      const pTop = ((chosen.y / VIEW_H) * 100).toFixed(2);
      const isBelow = chosen.y > m.cy;
      const alertChip = isAlert
        ? `<span class="ag-fp-alert">${m.alertCount}</span>`
        : '';
      pillParts.push(
        `<div class="ag-folder-pill${isAlert ? ' ag-folder-pill-alert' : ''}${isBelow ? ' ag-folder-pill-below' : ''}" style="left:${pLeft}%;top:${pTop}%;border-color:${borderCol};"><span class="ag-fp-dot" style="background:rgb(${lr},${lg},${lb});"></span><span class="ag-fp-name">${escapeHtml(labelStr)}</span><span class="ag-fp-count" style="color:rgb(${lr},${lg},${lb});">${m.count}</span>${alertChip}</div>`
      );
    }
  }

  return { membranesHtml: memParts.join(''), pillsHtml: pillParts.join('') };
}

function renderEdgesHtml(edges: PreparedEdge[]): string {
  const parts: string[] = [];
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    const leftPct = pct2((e.x1 / VIEW_W) * 100);
    const topPct = pct2((e.y1 / VIEW_H) * 100);
    const widthPct = pct2((e.dist / VIEW_W) * 100);
    const ang = Math.round(e.angleRad * 10000) / 10000;
    const arrowClass = e.dist >= 38 ? ' ag-edge-arrow' : '';
    parts.push(
      `<div class="ag-edge ag-edge-${e.kind}${arrowClass}" style="left:${leftPct}%;top:${topPct}%;width:${widthPct}%;transform:translateY(-50%) rotate(${ang}rad);"></div>`
    );
  }
  return parts.join('');
}

function buildBubbleVisualStyle(b: PreparedBubble): string {
  const [r, g, bl] = b.rgb;
  const [lr, lg, lbl] = b.lightRgb;
  const leftPct = pct2((b.x / VIEW_W) * 100);
  const topPct = pct2((b.y / VIEW_H) * 100);
  const wPct = pct3((b.diam / VIEW_W) * 100);
  const zIndex =
    b.alert !== 'NONE'
      ? 28 + severityRank(b.alert)
      : b.isHotspot
        ? 22
        : b.kind === 'file'
          ? 18
          : b.kind === 'class' || b.kind === 'form'
            ? 14
            : 10;

  return `left:${leftPct}%;top:${topPct}%;width:${wPct}%;z-index:${zIndex};--ag-c:${r},${g},${bl};--ag-l:${lr},${lg},${lbl};`;
}

function renderBubblesHtml(bubbles: PreparedBubble[]): string {
  const parts: string[] = [];
  for (let i = 0; i < bubbles.length; i++) {
    const b = bubbles[i];
    const n = b.node;
    const style = buildBubbleVisualStyle(b);
    const alertLower = b.alert !== 'NONE' ? b.alert.toLowerCase() : '';
    const alertClass = alertLower ? ` ag-alert-${alertLower}` : '';
    const hotspotClass = b.isHotspot ? ' ag-hotspot' : '';
    const tipCls =
      (b.y < 165 ? ' ag-tip-below' : '') +
      (b.x < 190 ? ' ag-tip-left' : b.x > VIEW_W - 190 ? ' ag-tip-right' : '');

    const kindLabel =
      b.kind === 'file'
        ? 'Fichier'
        : b.kind === 'class'
          ? 'Classe / Struct'
          : b.kind === 'form'
            ? 'Endpoint / Form'
            : 'Fonction';
    const cc = n.cyclomatic_complexity || n.complexity || 1;
    const loc = n.loc || n.lines_count || n.metadata?.lines || 1;
    const alertLine = alertLower
      ? `<span class="ag-tip-alert ag-tip-alert-${alertLower}">${escapeHtml(b.cweCode)}${b.cweExtra > 0 ? ` +${b.cweExtra}` : ''} · ${b.alert}</span>`
      : '';

    parts.push(
      `<div class="ag-bubble ag-${b.kind}${alertClass}${hotspotClass}" data-alert="${b.alert}" style="${style}"><span class="ag-tip${tipCls}"><span class="ag-tip-head"><span class="ag-tip-name">${escapeHtml(n.name || n.id)}</span><span class="ag-tip-kind">${kindLabel}</span></span><span class="ag-tip-meta">${escapeHtml(b.folder)} · ${escapeHtml(String(n.layer || 'domain').toUpperCase())} · ${loc} LOC · CC ${cc}</span>${alertLine}</span></div>`
    );
  }
  return parts.join('');
}

function renderCwePillsAndLabelsHtml(
  bubbles: PreparedBubble[],
  placedBoxes: RectBox[],
  folderTotals: Map<string, number>
): { cwePillsHtml: string; nodeLabelsHtml: string } {
  const cweParts: string[] = [];
  const labelParts: string[] = [];

  // 1. Security CWE floating pills (highest severity first)
  const alertBubbles = bubbles
    .filter((b) => b.alert !== 'NONE')
    .sort((a, b) => severityRank(b.alert) - severityRank(a.alert) || b.violationCount - a.violationCount);

  let drawnCwe = 0;
  for (const b of alertBubbles) {
    if (drawnCwe >= MAX_CWE_PILLS) break;
    const extraTxt = b.cweExtra > 0 ? `+${b.cweExtra}` : '';
    const estW = Math.min(130, 24 + b.cweCode.length * 6.5 + (extraTxt ? extraTxt.length * 6 + 10 : 0));
    const estH = 18;
    const r = b.diam * 0.55 + 6;
    const candidates: [number, number][] = [
      [b.x - estW * 0.5, b.y - r - estH - 4],
      [b.x + r + 5, b.y - estH - 2],
      [b.x - r - estW - 5, b.y - estH - 2],
      [b.x - estW * 0.5, b.y + r + 5],
      [b.x + r + 5, b.y - estH * 0.5],
      [b.x - r - estW - 5, b.y - estH * 0.5],
    ];

    let chosen: RectBox | null = null;
    for (const [cxRaw, cyRaw] of candidates) {
      const box: RectBox = {
        x: Math.max(8, Math.min(VIEW_W - estW - 8, cxRaw)),
        y: Math.max(8, Math.min(VIEW_H - estH - 10, cyRaw)),
        w: estW,
        h: estH,
      };
      if (fitsWithoutCollision(box, placedBoxes, 3)) {
        chosen = box;
        break;
      }
    }
    if (!chosen) continue;

    placedBoxes.push(chosen);
    drawnCwe++;
    const pLeft = (((chosen.x + chosen.w * 0.5) / VIEW_W) * 100).toFixed(2);
    const pTop = ((chosen.y / VIEW_H) * 100).toFixed(2);
    const sevCls = b.alert.toLowerCase();
    const extraBadge = extraTxt ? `<span class="ag-cwe-extra">${escapeHtml(extraTxt)}</span>` : '';
    cweParts.push(
      `<div class="ag-cwe-pill ag-cwe-${sevCls}" style="left:${pLeft}%;top:${pTop}%;"><span class="ag-cwe-dot"></span><span class="ag-cwe-code">${escapeHtml(b.cweCode)}</span>${extraBadge}</div>`
    );
  }

  // 2. Prominent structural symbol labels (files, classes, hotspots — hide non-alert clutter in dense clusters > 22)
  const isDenseGraph = bubbles.length > 80;
  const labelCandidates = [...bubbles]
    .filter((b) => {
      if (b.alert !== 'NONE') return true;
      if (isDenseGraph && (folderTotals.get(b.folder) || 0) > 22) return false;
      return b.kind === 'file' || b.kind === 'class' || b.isHotspot;
    })
    .sort((a, b) => b.priority - a.priority);

  let drawnLabels = 0;
  for (const b of labelCandidates) {
    if (drawnLabels >= MAX_NODE_LABELS) break;
    const rawName = b.node.name || b.node.id || '';
    if (!rawName) continue;
    const shortName = rawName.length > 18 ? `${rawName.slice(0, 16)}..` : rawName;
    const estW = shortName.length * 5.6 + 8;
    const estH = 13;
    const box: RectBox = {
      x: b.x - estW * 0.5,
      y: b.y + b.diam * 0.55 + 5,
      w: estW,
      h: estH,
    };
    if (!fitsWithoutCollision(box, placedBoxes, 2)) continue;
    placedBoxes.push(box);
    drawnLabels++;

    const lLeft = ((b.x / VIEW_W) * 100).toFixed(2);
    const lTop = ((box.y / VIEW_H) * 100).toFixed(2);
    const cls = b.alert !== 'NONE' ? 'ag-node-label ag-node-label-alert' : 'ag-node-label';
    labelParts.push(
      `<span class="${cls}" style="left:${lLeft}%;top:${lTop}%;">${escapeHtml(shortName)}</span>`
    );
  }

  return { cwePillsHtml: cweParts.join(''), nodeLabelsHtml: labelParts.join('') };
}

export function getAetherGraphStyles(): string {
  return `
    /* ===================================================================== */
    /* AETHER BUBBLE TOPOLOGICAL GRAPH STAGE (PURE CSS · ZERO-JS · XSS-SAFE) */
    /* ===================================================================== */
    .aether-graph-section { margin-bottom: 32px; }
    .aether-graph-card {
      position: relative;
      background: #060a14;
      border: 1px solid rgba(56, 189, 248, 0.22);
      border-radius: 18px;
      overflow: hidden;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(125, 211, 252, 0.12);
    }
    .ag-toggle-input {
      position: absolute;
      width: 1px;
      height: 1px;
      opacity: 0;
      pointer-events: none;
    }
    .aether-graph-bar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 14px 20px;
      background: linear-gradient(90deg, rgba(12, 18, 36, 0.96) 0%, rgba(15, 23, 42, 0.92) 100%);
      border-bottom: 1px solid rgba(56, 189, 248, 0.14);
    }
    .ag-title-wrap { display: flex; flex-direction: column; gap: 3px; }
    .ag-title {
      font-size: 15px;
      font-weight: 800;
      color: #f8fafc;
      letter-spacing: 0.01em;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .ag-orb-icon {
      display: inline-block;
      width: 13px;
      height: 13px;
      border-radius: 50%;
      flex-shrink: 0;
      background: radial-gradient(circle at 34% 30%, #ffffff 0%, #7dd3fc 36%, #0284c7 76%, rgba(14, 165, 233, 0.25) 100%);
      border: 1px solid rgba(186, 230, 253, 0.92);
      box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.22), 0 0 8px rgba(56, 189, 248, 0.7);
    }
    .ag-orb-icon-sm {
      width: 9px;
      height: 9px;
      box-shadow: 0 0 0 1.5px rgba(56, 189, 248, 0.26), 0 0 6px rgba(56, 189, 248, 0.65);
    }
    .ag-title-pill {
      font-size: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 2px 8px;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.14);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: #7dd3fc;
    }
    .ag-sub {
      font-size: 11px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      color: #94a3b8;
    }
    .ag-controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .ag-ctrl-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 11px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      color: #94a3b8;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid rgba(148, 163, 184, 0.22);
      cursor: pointer;
      user-select: none;
      transition: all 0.18s ease;
    }
    .ag-ctrl-btn:hover { border-color: rgba(125, 211, 252, 0.55); color: #e2e8f0; }

    #ag-tog-membranes:checked ~ .aether-graph-bar label[for="ag-tog-membranes"],
    #ag-tog-edges:checked ~ .aether-graph-bar label[for="ag-tog-edges"],
    #ag-tog-labels:checked ~ .aether-graph-bar label[for="ag-tog-labels"] {
      color: #e0f2fe;
      background: rgba(14, 165, 233, 0.18);
      border-color: rgba(56, 189, 248, 0.58);
      box-shadow: 0 0 12px rgba(56, 189, 248, 0.2);
    }
    #ag-tog-cwe:checked ~ .aether-graph-bar label[for="ag-tog-cwe"] {
      color: #ffe4e6;
      background: rgba(244, 63, 94, 0.24);
      border-color: rgba(244, 63, 94, 0.72);
      box-shadow: 0 0 14px rgba(244, 63, 94, 0.3);
    }

    .aether-viewport {
      position: relative;
      width: 100%;
      aspect-ratio: 1000 / 540;
      min-height: 300px;
      overflow: hidden;
      background:
        radial-gradient(ellipse 62% 52% at 22% 28%, rgba(14, 165, 233, 0.15) 0%, transparent 70%),
        radial-gradient(ellipse 56% 54% at 78% 26%, rgba(139, 92, 246, 0.15) 0%, transparent 72%),
        radial-gradient(ellipse 52% 48% at 54% 80%, rgba(236, 72, 153, 0.10) 0%, transparent 68%),
        radial-gradient(ellipse 75% 75% at 50% 50%, rgba(15, 23, 42, 0.35) 0%, #030610 100%),
        #030610;
    }
    .aether-grid-bg {
      position: absolute;
      inset: 0;
      background-image:
        linear-gradient(to right, rgba(56, 189, 248, 0.045) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(56, 189, 248, 0.045) 1px, transparent 1px);
      background-size: 48px 48px;
      pointer-events: none;
    }
    .aether-hud-corner {
      position: absolute;
      left: 14px;
      bottom: 10px;
      z-index: 4;
      font-size: 9.5px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      letter-spacing: 0.08em;
      color: rgba(125, 211, 252, 0.45);
      pointer-events: none;
    }

    .ag-layer {
      position: absolute;
      inset: 0;
      transition: opacity 0.22s ease;
    }
    .ag-layer-stars { pointer-events: none; z-index: 1; }
    .ag-layer-membranes { pointer-events: none; z-index: 2; }
    .ag-layer-edges { pointer-events: none; z-index: 3; }
    .ag-layer-bubbles { z-index: auto; }
    .ag-layer-labels { pointer-events: none; z-index: 40; }
    .ag-layer-cwe { pointer-events: none; z-index: 45; }

    #ag-tog-membranes:not(:checked) ~ .aether-viewport .ag-layer-membranes,
    #ag-tog-membranes:not(:checked) ~ .aether-viewport .ag-folder-pill { opacity: 0; }
    #ag-tog-edges:not(:checked) ~ .aether-viewport .ag-layer-edges { opacity: 0; }
    #ag-tog-labels:not(:checked) ~ .aether-viewport .ag-layer-labels { opacity: 0; }
    #ag-tog-cwe:checked ~ .aether-viewport .ag-bubble[data-alert="NONE"] { opacity: 0.14; filter: saturate(0.3); }
    #ag-tog-cwe:checked ~ .aether-viewport .ag-edge:not(.ag-edge-violates) { opacity: 0.08; }
    #ag-tog-cwe:checked ~ .aether-viewport .ag-membrane:not(.ag-membrane-alert) { opacity: 0.22; }
    #ag-tog-cwe:checked ~ .aether-viewport .ag-folder-pill:not(.ag-folder-pill-alert) { opacity: 0.26; }
    #ag-tog-cwe:checked ~ .aether-viewport .ag-node-label:not(.ag-node-label-alert) { opacity: 0.14; }

    .ag-star {
      position: absolute;
      border-radius: 50%;
      box-shadow: 0 0 6px rgba(186, 230, 253, 0.55);
      animation: ag-twinkle 4.8s ease-in-out infinite;
    }
    @keyframes ag-twinkle {
      0%, 100% { opacity: 0.28; transform: scale(0.85); }
      50% { opacity: 0.95; transform: scale(1.22); }
    }

    .ag-membrane {
      position: absolute;
      border-width: 1.4px;
      border-style: solid;
      background: radial-gradient(circle at 44% 38%, rgba(var(--ag-c), 0.13) 0%, rgba(var(--ag-c), 0.05) 66%, rgba(var(--ag-c), 0.01) 100%);
      box-shadow: inset 0 0 22px rgba(var(--ag-c), 0.13), 0 0 18px rgba(var(--ag-c), 0.08);
      animation: ag-breathe 9.2s ease-in-out infinite;
      transition: opacity 0.25s ease;
    }
    .ag-membrane-alert {
      background: radial-gradient(circle at 44% 38%, rgba(var(--ag-c), 0.17) 0%, rgba(var(--ag-c), 0.06) 66%, rgba(var(--ag-c), 0.01) 100%);
    }
    .ag-membrane-inner {
      position: absolute;
      inset: 7%;
      border: 1px dashed rgba(var(--ag-l), 0.19);
      opacity: 0.72;
    }
    @keyframes ag-breathe {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.022); }
    }

    .ag-folder-pill {
      position: absolute;
      transform: translateX(-50%);
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 2px 8px;
      border-radius: 7px;
      background: rgba(9, 13, 24, 0.90);
      border: 1px solid rgba(148, 163, 184, 0.4);
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.45);
      font-size: 10px;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      color: #e2e8f0;
      white-space: nowrap;
      transition: opacity 0.22s ease;
    }
    .ag-folder-pill::after {
      content: "";
      position: absolute;
      left: 50%;
      top: 100%;
      width: 1px;
      height: 8px;
      background: inherit;
      border-left: 1px solid rgba(148, 163, 184, 0.45);
    }
    .ag-folder-pill-below::after {
      top: auto;
      bottom: 100%;
    }
    .ag-folder-pill-alert { box-shadow: 0 0 12px rgba(244, 63, 94, 0.28); }
    .ag-fp-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
    .ag-fp-count { font-size: 9.5px; opacity: 0.95; }
    .ag-fp-alert {
      font-size: 9px;
      padding: 0 5px;
      border-radius: 999px;
      background: rgba(244, 63, 94, 0.26);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.55);
    }

    .ag-edge {
      position: absolute;
      height: 0;
      transform-origin: 0 50%;
      border-top: 1.15px solid rgba(56, 189, 248, 0.34);
      transition: opacity 0.22s ease;
    }
    .ag-edge-arrow::after {
      content: "";
      position: absolute;
      left: 62%;
      top: -3.4px;
      width: 0;
      height: 0;
      border-top: 3px solid transparent;
      border-bottom: 3px solid transparent;
      border-left: 5.5px solid currentColor;
      opacity: 0.78;
    }
    .ag-edge-calls { border-top-color: rgba(56, 189, 248, 0.34); color: #38bdf8; }
    .ag-edge-imports { border-top: 1px dashed rgba(251, 191, 36, 0.34); color: #fbbf24; }
    .ag-edge-queries { border-top-color: rgba(192, 132, 252, 0.48); color: #c084fc; }
    .ag-edge-realtime { border-top-color: rgba(52, 211, 153, 0.50); color: #34d399; }
    .ag-edge-network { border-top-color: rgba(34, 211, 238, 0.50); color: #22d3ee; }
    .ag-edge-submits { border-top-color: rgba(255, 122, 24, 0.52); color: #ff7a18; }
    .ag-edge-warns { border-top: 1.2px dashed rgba(249, 115, 22, 0.62); color: #fb923c; }
    .ag-edge-violates {
      border-top: 1.6px solid rgba(244, 63, 94, 0.72);
      color: #f43f5e;
      box-shadow: 0 0 6px rgba(244, 63, 94, 0.38);
    }

    .ag-bubble {
      position: absolute;
      aspect-ratio: 1 / 1;
      border-radius: 50%;
      transform: translate(-50%, -50%);
      cursor: pointer;
      transition: transform 0.16s ease, opacity 0.22s ease, filter 0.22s ease;
    }
    .ag-bubble.ag-file {
      background: radial-gradient(circle at 36% 32%, #ffffff 0%, rgba(var(--ag-l), 0.94) 24%, rgba(var(--ag-c), 0.78) 54%, rgba(var(--ag-c), 0.22) 100%);
      border: 1.4px solid rgba(var(--ag-l), 0.92);
      box-shadow: 0 0 0 2.6px rgba(var(--ag-c), 0.24), 0 0 11px rgba(var(--ag-c), 0.65), inset 0 0 5px rgba(255, 255, 255, 0.45);
    }
    .ag-bubble.ag-class {
      border-radius: 26%;
      background: radial-gradient(circle at 42% 38%, #ffffff 0%, rgba(var(--ag-l), 0.92) 30%, rgba(var(--ag-c), 0.76) 70%, rgba(var(--ag-c), 0.30) 100%);
      border: 1.3px solid rgba(var(--ag-l), 0.95);
      box-shadow: 0 0 10px rgba(var(--ag-c), 0.72), inset 0 0 4px rgba(255, 255, 255, 0.5);
    }
    .ag-bubble.ag-form {
      background: radial-gradient(circle at 40% 35%, #fffbeb 0%, rgba(var(--ag-l), 0.95) 28%, rgba(var(--ag-c), 0.78) 65%, rgba(var(--ag-c), 0.26) 100%);
      border: 1.3px solid rgba(255, 255, 255, 0.85);
      box-shadow: 0 0 0 3px rgba(var(--ag-c), 0.26), 0 0 12px rgba(var(--ag-c), 0.74);
    }
    .ag-bubble.ag-func {
      background: radial-gradient(circle at 40% 36%, #ffffff 0%, rgba(var(--ag-l), 0.96) 36%, rgba(var(--ag-c), 0.62) 72%, rgba(var(--ag-c), 0.08) 100%);
      border: 1px solid rgba(var(--ag-l), 0.72);
      box-shadow: 0 0 8px rgba(var(--ag-c), 0.80), 0 0 16px rgba(var(--ag-c), 0.34);
    }
    .ag-bubble.ag-class::after {
      content: "";
      position: absolute;
      inset: 22%;
      border-radius: 22%;
      border: 1px solid rgba(255, 255, 255, 0.55);
      transform: rotate(45deg);
      pointer-events: none;
    }
    .ag-bubble:hover {
      transform: translate(-50%, -50%) scale(1.42);
      z-index: 95 !important;
    }

    .ag-bubble.ag-form::before,
    .ag-bubble.ag-alert-critical::before,
    .ag-bubble.ag-alert-high::before,
    .ag-bubble.ag-alert-medium::before,
    .ag-bubble.ag-alert-lines::before {
      content: "";
      position: absolute;
      inset: -5px;
      border-radius: 50%;
      pointer-events: none;
    }
    .ag-bubble.ag-form::before {
      border: 1.2px solid rgba(56, 189, 248, 0.68);
      animation: ag-pulse-ring 2.8s ease-out infinite;
    }
    .ag-bubble.ag-alert-critical::before {
      border: 1.6px solid rgba(244, 63, 94, 0.92);
      box-shadow: 0 0 10px rgba(244, 63, 94, 0.55);
      animation: ag-pulse-ring 2.2s ease-out infinite;
    }
    .ag-bubble.ag-alert-high::before {
      border: 1.5px solid rgba(251, 146, 60, 0.88);
      box-shadow: 0 0 8px rgba(251, 146, 60, 0.45);
    }
    .ag-bubble.ag-alert-medium::before {
      border: 1.3px solid rgba(250, 204, 21, 0.82);
    }
    .ag-bubble.ag-alert-lines::before {
      border: 1.4px dashed rgba(245, 158, 11, 0.86);
    }
    @keyframes ag-pulse-ring {
      0% { transform: scale(0.95); opacity: 0.92; }
      70% { transform: scale(1.48); opacity: 0.16; }
      100% { transform: scale(1.55); opacity: 0; }
    }

    .ag-tip {
      position: absolute;
      left: 50%;
      bottom: calc(100% + 10px);
      transform: translateX(-50%) translateY(4px);
      min-width: 195px;
      max-width: 280px;
      padding: 8px 11px;
      border-radius: 10px;
      background: rgba(7, 11, 22, 0.96);
      border: 1px solid rgba(56, 189, 248, 0.45);
      box-shadow: 0 12px 28px rgba(0, 0, 0, 0.72);
      display: flex;
      flex-direction: column;
      gap: 4px;
      opacity: 0;
      visibility: hidden;
      pointer-events: none;
      transition: opacity 0.14s ease, transform 0.14s ease;
      white-space: normal;
      text-align: left;
      z-index: 120;
    }
    .ag-tip.ag-tip-below { bottom: auto; top: calc(100% + 10px); transform: translateX(-50%) translateY(-4px); }
    .ag-tip.ag-tip-left { left: 0; transform: translateX(0) translateY(4px); }
    .ag-tip.ag-tip-right { left: auto; right: 0; transform: translateX(0) translateY(4px); }
    .ag-tip.ag-tip-below.ag-tip-left,
    .ag-tip.ag-tip-below.ag-tip-right { transform: translateX(0) translateY(-4px); }
    .ag-bubble:hover .ag-tip {
      opacity: 1;
      visibility: visible;
      transform: translateX(-50%) translateY(0);
    }
    .ag-bubble:hover .ag-tip.ag-tip-left,
    .ag-bubble:hover .ag-tip.ag-tip-right {
      transform: translateX(0) translateY(0);
    }
    .ag-tip-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .ag-tip-name {
      font-size: 11.5px;
      font-weight: 800;
      color: #f8fafc;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      word-break: break-all;
    }
    .ag-tip-kind {
      font-size: 9.5px;
      font-weight: 700;
      color: #7dd3fc;
      background: rgba(56, 189, 248, 0.15);
      padding: 1px 6px;
      border-radius: 4px;
      white-space: nowrap;
    }
    .ag-tip-meta {
      font-size: 10px;
      color: #94a3b8;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .ag-tip-alert {
      margin-top: 2px;
      font-size: 10px;
      font-weight: 800;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      padding: 2px 6px;
      border-radius: 5px;
      width: fit-content;
    }
    .ag-tip-alert-critical { background: rgba(244, 63, 94, 0.24); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.5); }
    .ag-tip-alert-high { background: rgba(251, 146, 60, 0.24); color: #fdba74; border: 1px solid rgba(251, 146, 60, 0.5); }
    .ag-tip-alert-medium { background: rgba(250, 204, 21, 0.20); color: #fde047; border: 1px solid rgba(250, 204, 21, 0.45); }
    .ag-tip-alert-lines { background: rgba(245, 158, 11, 0.22); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.45); }

    .ag-cwe-pill {
      position: absolute;
      transform: translateX(-50%);
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 7px;
      border-radius: 6px;
      font-size: 9.5px;
      font-weight: 800;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      white-space: nowrap;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.55);
    }
    .ag-cwe-dot { width: 5.5px; height: 5.5px; border-radius: 50%; flex-shrink: 0; }
    .ag-cwe-extra { padding: 0 4px; border-radius: 4px; font-size: 8.5px; }
    .ag-cwe-critical { background: rgba(17, 10, 16, 0.93); border: 1px solid rgba(244, 63, 94, 0.8); color: #ffe4e6; }
    .ag-cwe-critical .ag-cwe-dot { background: #f43f5e; }
    .ag-cwe-critical .ag-cwe-extra { background: rgba(244, 63, 94, 0.25); color: #fda4af; }
    .ag-cwe-high { background: rgba(18, 12, 10, 0.93); border: 1px solid rgba(251, 146, 60, 0.8); color: #ffedd5; }
    .ag-cwe-high .ag-cwe-dot { background: #fb923c; }
    .ag-cwe-high .ag-cwe-extra { background: rgba(251, 146, 60, 0.25); color: #fdba74; }
    .ag-cwe-medium { background: rgba(17, 15, 9, 0.92); border: 1px solid rgba(250, 204, 21, 0.72); color: #fef9c3; }
    .ag-cwe-medium .ag-cwe-dot { background: #facc15; }
    .ag-cwe-medium .ag-cwe-extra { background: rgba(250, 204, 21, 0.22); color: #fde047; }
    .ag-cwe-lines { background: rgba(18, 14, 8, 0.92); border: 1px solid rgba(245, 158, 11, 0.72); color: #fde68a; }
    .ag-cwe-lines .ag-cwe-dot { background: #f59e0b; }

    .ag-node-label {
      position: absolute;
      transform: translateX(-50%);
      padding: 1px 5px;
      border-radius: 4px;
      background: rgba(5, 9, 20, 0.78);
      border: 1px solid rgba(148, 163, 184, 0.14);
      font-size: 9.5px;
      font-weight: 600;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      color: rgba(226, 232, 240, 0.90);
      white-space: nowrap;
      transition: opacity 0.22s ease;
    }
    .ag-node-label-alert {
      color: #fecdd3;
      border-color: rgba(244, 63, 94, 0.35);
      font-weight: 700;
    }

    .ag-empty {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 14px;
      z-index: 6;
      text-align: center;
      padding: 24px;
    }
    .ag-empty-orb {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: radial-gradient(circle at 36% 32%, rgba(125, 211, 252, 0.65), rgba(56, 189, 248, 0.14) 58%, transparent 100%);
      border: 1.5px solid rgba(56, 189, 248, 0.45);
      box-shadow: 0 0 0 8px rgba(56, 189, 248, 0.08), 0 0 28px rgba(56, 189, 248, 0.35);
      animation: ag-breathe 6s ease-in-out infinite;
    }
    .ag-empty-text { font-size: 13px; color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

    .aether-graph-footer {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 11px 20px;
      background: rgba(9, 13, 24, 0.96);
      border-top: 1px solid rgba(255, 255, 255, 0.07);
      font-size: 11px;
      color: #94a3b8;
    }
    .ag-legend { display: flex; flex-wrap: wrap; align-items: center; gap: 14px; }
    .ag-leg-item { display: inline-flex; align-items: center; gap: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10.5px; }
    .ag-leg-orb { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
    .ag-leg-file {
      background: radial-gradient(circle at 35% 35%, #fff, #38bdf8 55%, rgba(56, 189, 248, 0.3));
      border: 1px solid #bae6fd;
      box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.25), 0 0 6px #38bdf8;
    }
    .ag-leg-class {
      border-radius: 28%;
      background: radial-gradient(circle at 40% 35%, #fff, #a855f7 65%);
      border: 1px solid #e9d5ff;
      box-shadow: 0 0 6px #a855f7;
    }
    .ag-leg-func {
      width: 7.5px;
      height: 7.5px;
      background: radial-gradient(circle, #fff 10%, #10b981 70%);
      box-shadow: 0 0 6px #10b981;
    }
    .ag-leg-cwe {
      background: radial-gradient(circle, #fff 10%, #f43f5e 70%);
      box-shadow: 0 0 0 2px rgba(244, 63, 94, 0.75), 0 0 8px #f43f5e;
    }
    .ag-leg-line { display: inline-block; width: 14px; height: 0; border-top: 1.5px solid #38bdf8; }
    .ag-leg-line-imp { border-top: 1.5px dashed #fbbf24; }
    .ag-leg-line-viol { border-top: 2px solid #f43f5e; }
    .ag-hint { font-size: 10.5px; color: #64748b; font-style: italic; }

    @media print {
      .aether-graph-section { break-inside: avoid; page-break-inside: avoid; }
      .aether-graph-card, .aether-viewport, .ag-membrane, .ag-bubble, .ag-cwe-pill, .ag-folder-pill {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }
      .ag-controls { display: none !important; }
    }
  `;
}

/**
 * Generates the self-contained stylized Aether Bubble project graph section (Pure HTML + CSS, zero script/svg/img).
 */
export function renderAetherBubbleGraphHtml(cockpitState: CockpitState): string {
  const nodes = cockpitState.graph?.nodes || [];
  const totalNodes = nodes.length;
  const totalEdges = (cockpitState.graph?.edges || []).length;
  const violations = cockpitState.allViolations || [];
  const isIgnored =
    typeof cockpitState.isCweIgnored === 'function'
      ? (r?: string, c?: string) => cockpitState.isCweIgnored(r, c)
      : undefined;

  const { bubbles, folderTotals, folderAlerts } = selectAndScoreBubbles(nodes, violations, isIgnored);

  if (bubbles.length > 0) {
    if (!hasLiveSpatialLayout(bubbles)) {
      computeSyntheticGalaxyLayout(bubbles, folderAlerts);
    }
    normalizeBubbleCoordinates(bubbles);
    assignBubbleDiameters(bubbles);
  }

  const membranes = buildMembranes(bubbles, folderTotals, folderAlerts);
  const edges = prepareEdges(cockpitState, bubbles);
  const placedBoxes: RectBox[] = [];

  const starsHtml = renderStarsHtml();
  const { membranesHtml, pillsHtml } = renderMembranesAndPillsHtml(membranes, placedBoxes);
  const edgesHtml = renderEdgesHtml(edges);
  const bubblesHtml = renderBubblesHtml(bubbles);
  const { cwePillsHtml, nodeLabelsHtml } = renderCwePillsAndLabelsHtml(bubbles, placedBoxes, folderTotals);

  const alertBubbleCount = bubbles.filter((b) => b.alert !== 'NONE' && b.alert !== 'LINES').length;
  const countLabel =
    totalNodes > bubbles.length
      ? `${bubbles.length} bulles clés affichées / ${totalNodes} symboles`
      : `${totalNodes} ${totalNodes > 1 ? 'bulles' : 'bulle'} AST`;
  const memLabel = `${membranes.length} ${membranes.length > 1 ? 'membranes cellulaires' : 'membrane cellulaire'}`;
  const cweLabel = `${alertBubbleCount} ${alertBubbleCount > 1 ? 'bulles' : 'bulle'} CWE`;

  const stageBody =
    bubbles.length === 0
      ? `<div class="ag-empty"><div class="ag-empty-orb"></div><div class="ag-empty-text">Aucune bulle AST cartographiée dans le périmètre actuel.</div></div>`
      : `<div class="ag-layer ag-layer-membranes">${membranesHtml}</div>
         <div class="ag-layer ag-layer-edges">${edgesHtml}</div>
         <div class="ag-layer ag-layer-bubbles">${bubblesHtml}</div>
         <div class="ag-layer ag-layer-labels">${pillsHtml}${nodeLabelsHtml}</div>
         <div class="ag-layer ag-layer-cwe">${cwePillsHtml}</div>`;

  return `
    <section class="aether-graph-section">
      <div class="aether-graph-card">
        <input type="checkbox" id="ag-tog-membranes" class="ag-toggle-input" checked>
        <input type="checkbox" id="ag-tog-edges" class="ag-toggle-input" checked>
        <input type="checkbox" id="ag-tog-labels" class="ag-toggle-input" checked>
        <input type="checkbox" id="ag-tog-cwe" class="ag-toggle-input">

        <div class="aether-graph-bar">
          <div class="ag-title-wrap">
            <div class="ag-title">
              <span class="ag-orb-icon"></span>
              <span>Topologie Projet — Affichage Aether Bulle</span>
              <span class="ag-title-pill">Aether Bubble</span>
            </div>
            <div class="ag-sub">${countLabel} · ${memLabel} · ${edges.length}/${totalEdges} flux · ${cweLabel}</div>
          </div>
          <div class="ag-controls">
            <label for="ag-tog-membranes" class="ag-ctrl-btn"><span class="ag-orb-icon ag-orb-icon-sm"></span>Membranes</label>
            <label for="ag-tog-edges" class="ag-ctrl-btn">⚡ Flux</label>
            <label for="ag-tog-labels" class="ag-ctrl-btn">🏷️ Labels</label>
            <label for="ag-tog-cwe" class="ag-ctrl-btn">🚨 Focus CWE</label>
          </div>
        </div>

        <div class="aether-viewport">
          <div class="aether-grid-bg"></div>
          <div class="ag-layer ag-layer-stars">${starsHtml}</div>
          ${stageBody}
          <div class="aether-hud-corner">AETHERSCOPE · GALAXIE TOPOLOGIQUE · ${escapeHtml(cockpitState.graph?.project_name || 'PROJET')}</div>
        </div>

        <div class="aether-graph-footer">
          <div class="ag-legend">
            <span class="ag-leg-item"><span class="ag-leg-orb ag-leg-file"></span>Fichier</span>
            <span class="ag-leg-item"><span class="ag-leg-orb ag-leg-class"></span>Classe / Struct</span>
            <span class="ag-leg-item"><span class="ag-leg-orb ag-leg-func"></span>Fonction</span>
            <span class="ag-leg-item"><span class="ag-leg-orb ag-leg-cwe"></span>Alerte CWE</span>
            <span class="ag-leg-item"><span class="ag-leg-line"></span>Appel</span>
            <span class="ag-leg-item"><span class="ag-leg-line ag-leg-line-imp"></span>Import</span>
            <span class="ag-leg-item"><span class="ag-leg-line ag-leg-line-viol"></span>Violation SAST</span>
          </div>
          <span class="ag-hint">Survolez une bulle pour inspecter son module, sa complexité et ses alertes CWE</span>
        </div>
      </div>
    </section>
  `;
}
