import type { SymbolBubble, CveAnomalyRecord } from '../types/graph';
import {
  getNodeAlertKind,
  isLinesExceededAnomaly,
  formatCweShortId,
  type CockpitState,
} from '../state/graphState.svelte';

export interface ScreenRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface BeaconsOverlayContext {
  state: CockpitState;
  zoom: number;
  logicalWidth: number;
  logicalHeight: number;
  hoveredNodeId: string | null;
  folderPillBounds: readonly ScreenRect[];
  labelBounds: readonly ScreenRect[];
  anomalyNodeIndices: readonly number[];
  isAnomalyIgnored: (ruleId?: string, cveId?: string) => boolean;
  getEffectiveAnomalies: (n: SymbolBubble) => CveAnomalyRecord[];
  worldToScreen: (wx: number, wy: number) => { x: number; y: number };
  getNodeScreenRadius: (n: SymbolBubble, activeId: string | null) => number;
}

export function renderGitDiffBadges(
  ctx: CanvasRenderingContext2D,
  now: number,
  overlay: BeaconsOverlayContext
): void {
  const nodes = overlay.state.graph.nodes;
  if (!nodes || nodes.length === 0) return;
  const gitFiles = overlay.state.gitStatus?.files;
  const hasEdits = Boolean(
    (gitFiles && gitFiles.length > 0) ||
    (overlay.state.folderEdits && Object.keys(overlay.state.folderEdits).length > 0)
  );
  if (!hasEdits) return;

  const disabledLayers = overlay.state.disabledLayers;
  const disabledModules = overlay.state.disabledModules;
  const zoom = overlay.zoom;
  const activeId = overlay.state.activeSymbol?.id || null;
  const W = overlay.logicalWidth;
  const H = overlay.logicalHeight;

  ctx.save();
  ctx.font = '600 9.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'left';

  const placed: ScreenRect[] = overlay.folderPillBounds.map((b) => ({
    x: b.x - 3,
    y: b.y - 3,
    w: b.w + 6,
    h: b.h + 6,
  }));
  const collides = (x: number, y: number, w: number, h: number): boolean => {
    for (const r of placed) {
      if (x < r.x + r.w + 3 && x + w + 3 > r.x && y < r.y + r.h + 3 && y + h + 3 > r.y) return true;
    }
    return false;
  };

  let drawnRings = 0;
  let drawnPills = 0;
  const maxPills = zoom < 0.25 ? 8 : 16;

  for (let i = 0; i < nodes.length && drawnRings < 64; i++) {
    const n = nodes[i];
    const ek = n.edit_kind || (
      n.git_status === 'violation' ? 'violation'
        : n.git_status === 'new_folder' ? 'new_folder'
          : n.git_status === 'untracked' ? 'new_file'
            : n.git_status === 'text' ? 'text'
              : n.git_status === 'modified' ? 'modif'
                : 'none'
    );
    if (ek === 'none') continue;
    if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;

    const isFocus = n.id === overlay.hoveredNodeId || n.id === activeId;
    // Only show git-diff indicators on file nodes or focused/hovered symbol (prevents 60+ stacked child-symbol overlays)
    if (!n.is_file && !isFocus) continue;

    // Never draw redundant "FAILLE ÉDIT" boxes: security nodes are rendered cleanly by renderSecurityBeacons
    if (ek === 'violation') continue;

    const p = overlay.worldToScreen(n.x, n.y);
    if (p.x < -60 || p.x > W + 60 || p.y < -60 || p.y > H + 60) continue;

    let badgeText = '';
    let accentHex = '#facc15';
    let strokeColor = 'rgba(250, 204, 21, 0.72)';
    let textColor = '#fef08a';

    if (ek === 'modif') {
      badgeText = 'MODIF';
      accentHex = '#facc15';
      strokeColor = 'rgba(250, 204, 21, 0.72)';
      textColor = '#fef08a';
    } else if (ek === 'text') {
      badgeText = 'DOC';
      accentHex = '#22d3ee';
      strokeColor = 'rgba(34, 211, 238, 0.72)';
      textColor = '#a5f3fc';
    } else if (ek === 'new_file') {
      badgeText = '+FICHIER';
      accentHex = '#34d399';
      strokeColor = 'rgba(52, 211, 153, 0.75)';
      textColor = '#a7f3d0';
    } else if (ek === 'new_folder') {
      badgeText = '+DOSSIER';
      accentHex = '#c084fc';
      strokeColor = 'rgba(192, 132, 252, 0.75)';
      textColor = '#e9d5ff';
    } else {
      continue;
    }

    const visR = overlay.getNodeScreenRadius(n, activeId);
    const ringR = Math.max(5.5, Math.min(22, visR * 0.58 + 3));
    const isRecent = Boolean(n.last_edit_ts && now - n.last_edit_ts < 15000);

    // Subtle, crisp git status ring (zero heavy shadowBlur blotches)
    ctx.beginPath();
    ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = isRecent || isFocus ? 1.5 : 1.05;
    ctx.stroke();
    drawnRings++;

    if (!isFocus && !isRecent && zoom < 0.35) continue;
    if (drawnPills >= maxPills && !isFocus) continue;

    const padX = 6;
    const dotW = 8;
    const pillH = 16;
    const tw = Math.ceil(ctx.measureText(badgeText).width) + padX * 2 + dotW;
    const bx = Math.max(4, Math.min(W - tw - 4, Math.round(p.x - tw * 0.5)));
    const by = Math.round(p.y + ringR + 5);

    if (by + pillH > H - 28 || (!isFocus && collides(bx, by, tw, pillH))) continue;
    placed.push({ x: bx, y: by, w: tw, h: pillH });
    drawnPills++;

    ctx.fillStyle = 'rgba(10, 14, 24, 0.90)';
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 1.0;
    ctx.beginPath();
    ctx.roundRect(bx, by, tw, pillH, pillH / 2);
    ctx.fill();
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(bx + padX + 2, by + pillH / 2, 2.3, 0, Math.PI * 2);
    ctx.fillStyle = accentHex;
    ctx.fill();

    ctx.fillStyle = textColor;
    ctx.fillText(badgeText, bx + padX + dotW, by + pillH / 2 + 0.5);
  }

  ctx.restore();
}

export function renderSecurityBeacons(
  ctx: CanvasRenderingContext2D,
  now: number,
  overlay: BeaconsOverlayContext
): void {
  if (!overlay.state.settings.showAlerts) return;
  const nodes = overlay.state.graph.nodes;
  if (!nodes || nodes.length === 0) return;
  const anomalyIndices = overlay.anomalyNodeIndices;
  if (anomalyIndices.length === 0) return;

  const disabledLayers = overlay.state.disabledLayers;
  const disabledModules = overlay.state.disabledModules;
  const zoom = overlay.zoom;
  const showTitles = overlay.state.settings.showCweTitles;
  const activeId = overlay.state.activeSymbol?.id || null;
  const W = overlay.logicalWidth;
  const H = overlay.logicalHeight;

  type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LINES';
  type Beacon = {
    x: number;
    y: number;
    ringR: number;
    sev: SeverityLevel;
    code: string;
    extraCount: number;
    prio: number;
    isFocus: boolean;
  };
  const beacons: Beacon[] = [];

  // ---- Passe 1 : anneaux fins proportionnels à la bulle (pas de pâté rouge au dézoom)
  ctx.save();
  let rings = 0;
  for (let k = 0; k < anomalyIndices.length && rings < 260; k++) {
    const i = anomalyIndices[k];
    const n = nodes[i];
    if (!n) continue;
    if (disabledLayers[n.layer || 'utility'] || disabledModules[n.folder || n.cluster_id || 'root']) continue;

    const alertKind = getNodeAlertKind(n, overlay.isAnomalyIgnored);
    if (alertKind === 'none') continue;
    if (!overlay.state.settings.showCweBubbles && alertKind === 'security') continue;

    const isFocus = n.id === overlay.hoveredNodeId || n.id === activeId;
    // En vue macro/méso (zoom < 0.55), agréger par fichier évite d'empiler 30 anneaux de sous-fonctions
    if (!n.is_file && !isFocus && zoom < 0.55) continue;

    const p = overlay.worldToScreen(n.x, n.y);
    if (p.x < -50 || p.x > W + 50 || p.y < -50 || p.y > H + 50) continue;

    const isLinesWarn = alertKind === 'lines_exceeded';
    const effAnom = overlay.getEffectiveAnomalies(n);
    const secAnoms = effAnom.filter((a) => !isLinesExceededAnomaly(a));

    let sev: SeverityLevel = isLinesWarn ? 'LINES' : 'HIGH';
    if (!isLinesWarn) {
      if (secAnoms.some((a) => String(a.severity || '').toUpperCase() === 'CRITICAL')) sev = 'CRITICAL';
      else if (secAnoms.some((a) => String(a.severity || '').toUpperCase() === 'HIGH')) sev = 'HIGH';
      else if (secAnoms.length > 0) sev = 'MEDIUM';
      else sev = 'CRITICAL';
    }

    const visR = overlay.getNodeScreenRadius(n, activeId);
    const breath = 0.5 + 0.5 * Math.sin(now * 0.0018 + i * 0.55);
    const ringR = Math.max(5.5, Math.min(24, visR * 0.56 + 3.2)) + (isFocus ? breath * 2.0 : breath * 0.8);

    const rgb =
      sev === 'LINES' ? '245, 158, 11'
        : sev === 'CRITICAL' ? '244, 63, 94'
          : sev === 'HIGH' ? '251, 146, 60'
            : '250, 204, 21';

    // Aura externe très légère (ne sature plus jamais en bloc rouge opaque)
    ctx.beginPath();
    ctx.arc(p.x, p.y, ringR + 3, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${rgb}, ${(isFocus ? 0.14 : 0.055).toFixed(3)})`;
    ctx.fill();

    // Anneau net
    ctx.beginPath();
    ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(${rgb}, ${(isFocus ? 0.92 : 0.62 + breath * 0.18).toFixed(2)})`;
    ctx.lineWidth = isFocus ? 1.8 : 1.15;
    ctx.stroke();
    rings++;

    if (showTitles && (isFocus || n.is_file || zoom >= 0.55)) {
      let code: string;
      let extraCount = 0;
      let prio = 0;
      if (isLinesWarn) {
        const maxLim = n.metadata?.max_lines_limit || 300;
        const curLoc = n.loc || n.metadata?.lines || 0;
        code = curLoc > 0 ? `${curLoc}/${maxLim} L` : 'Max L';
        prio = 1;
      } else {
        // Prioriser la faille la plus critique et compter les CWE de sécurité réelles
        const rankSev = (s?: string) => {
          const u = String(s || '').toUpperCase();
          return u === 'CRITICAL' ? 3 : u === 'HIGH' ? 2 : 1;
        };
        const sortedSec = [...secAnoms].sort((a, b) => rankSev(b.severity) - rankSev(a.severity));
        const primary = sortedSec[0];
        code = primary ? formatCweShortId(primary.cve_id, primary.rule_id) : 'CWE';
        extraCount = Math.max(0, sortedSec.length - 1);
        prio = sev === 'CRITICAL' ? 4 : sev === 'HIGH' ? 3 : 2;
      }
      if (n.is_file) prio += 0.5;
      beacons.push({ x: p.x, y: p.y, ringR, sev, code, extraCount, prio, isFocus });
    }
  }

  // ---- Passe 2 : pastilles CWE compactes, verre dépoli sombre, anti-collision avec dossiers + labels
  if (beacons.length > 0) {
    beacons.sort((a, b) => Number(b.isFocus) - Number(a.isFocus) || b.prio - a.prio || b.extraCount - a.extraCount);

    const fontPx = Math.min(11.5, Math.max(9.5, 9.8 + (zoom - 0.3) * 1.4));
    const mainFont = `700 ${fontPx.toFixed(1)}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`;
    const countFont = `700 ${Math.max(8.5, fontPx - 1.2).toFixed(1)}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`;
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';

    const pillH = Math.round(fontPx + 8);
    const padL = 7;
    const padR = 7;
    const dotArea = 9;

    // Pré-remplit les zones occupées par les badges de dossiers et les labels de fichiers
    const placed: ScreenRect[] = [
      ...overlay.folderPillBounds.map((b) => ({ x: b.x - 2, y: b.y - 2, w: b.w + 4, h: b.h + 4 })),
      ...overlay.labelBounds.map((b) => ({ x: b.x - 1, y: b.y - 1, w: b.w + 2, h: b.h + 2 })),
    ];
    const hit = (x: number, y: number, w: number, h: number): boolean => {
      for (const r of placed) {
        if (x < r.x + r.w + 4 && x + w + 4 > r.x && y < r.y + r.h + 4 && y + h + 4 > r.y) return true;
      }
      return false;
    };

    const maxPills = zoom < 0.12 ? 14 : zoom < 0.35 ? 24 : 42;
    let drawnPills = 0;

    for (const b of beacons) {
      if (drawnPills >= maxPills && !b.isFocus) break;

      ctx.font = mainFont;
      const codeW = Math.ceil(ctx.measureText(b.code).width);
      let extraText = '';
      let extraChipW = 0;
      if (b.extraCount > 0) {
        extraText = `+${b.extraCount}`;
        ctx.font = countFont;
        extraChipW = Math.ceil(ctx.measureText(extraText).width) + 9;
      }
      const tw = padL + dotArea + codeW + (extraChipW > 0 ? 5 + extraChipW : 0) + padR;
      const baseY = Math.round(b.y - b.ringR - pillH - 6);
      const centerBx = Math.round(b.x - tw / 2);

      // Positions candidates autour de la bulle : dessus, haut-droite, haut-gauche, étage +1, droite, gauche, dessous
      const candidates: [number, number][] = [
        [centerBx, baseY],
        [Math.round(b.x + b.ringR + 6), Math.round(b.y - pillH - 2)],
        [Math.round(b.x - b.ringR - tw - 6), Math.round(b.y - pillH - 2)],
        [centerBx, baseY - (pillH + 5)],
        [Math.round(b.x + b.ringR + 6), Math.round(b.y - pillH / 2)],
        [Math.round(b.x - b.ringR - tw - 6), Math.round(b.y - pillH / 2)],
        [centerBx, Math.round(b.y + b.ringR + 6)],
      ];

      let bx = centerBx;
      let by = baseY;
      let ok = false;
      for (const [cxRaw, cy] of candidates) {
        const cx = Math.max(6, Math.min(W - tw - 6, cxRaw));
        if (cy < 54 || cy + pillH > H - 32) continue;
        if (!hit(cx, cy, tw, pillH)) {
          bx = cx;
          by = cy;
          ok = true;
          break;
        }
      }
      if (!ok) {
        if (!b.isFocus) continue;
        bx = Math.max(6, Math.min(W - tw - 6, centerBx));
        by = Math.max(54, Math.min(H - pillH - 32, baseY));
      }

      placed.push({ x: bx, y: by, w: tw, h: pillH });
      drawnPills++;

      const palette =
        b.sev === 'LINES'
          ? { accent: '#f59e0b', border: 'rgba(245, 158, 11, 0.72)', bg: 'rgba(18, 14, 8, 0.90)', text: '#fde68a', chipBg: 'rgba(245, 158, 11, 0.22)', chipTxt: '#fcd34d' }
          : b.sev === 'CRITICAL'
            ? { accent: '#f43f5e', border: 'rgba(244, 63, 94, 0.78)', bg: 'rgba(17, 10, 16, 0.92)', text: '#ffe4e6', chipBg: 'rgba(244, 63, 94, 0.24)', chipTxt: '#fda4af' }
            : b.sev === 'HIGH'
              ? { accent: '#fb923c', border: 'rgba(251, 146, 60, 0.78)', bg: 'rgba(18, 12, 10, 0.92)', text: '#ffedd5', chipBg: 'rgba(251, 146, 60, 0.24)', chipTxt: '#fdba74' }
              : { accent: '#facc15', border: 'rgba(250, 204, 21, 0.72)', bg: 'rgba(17, 15, 9, 0.90)', text: '#fef9c3', chipBg: 'rgba(250, 204, 21, 0.20)', chipTxt: '#fde047' };

      // Fin trait connecteur vers la bulle
      const pillCx = bx + tw / 2;
      const pillCy = by + pillH / 2;
      const dx = b.x - pillCx;
      const dy = b.y - pillCy;
      const d = Math.hypot(dx, dy) || 1;
      if (d > b.ringR + pillH * 0.6) {
        const anchorX = Math.max(bx + 4, Math.min(bx + tw - 4, b.x));
        const anchorY = by + pillH < b.y ? by + pillH : by > b.y ? by : pillCy;
        ctx.beginPath();
        ctx.moveTo(anchorX, anchorY);
        ctx.lineTo(b.x - (dx / d) * b.ringR, b.y - (dy / d) * b.ringR);
        ctx.strokeStyle = palette.border;
        ctx.globalAlpha = 0.42;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.globalAlpha = 1.0;
      }

      // Corps de la pastille (sombre verre dépoli, bord net 1px, zéro flou baveux)
      ctx.fillStyle = palette.bg;
      ctx.strokeStyle = b.isFocus ? palette.accent : palette.border;
      ctx.lineWidth = b.isFocus ? 1.5 : 1.0;
      ctx.beginPath();
      ctx.roundRect(bx, by, tw, pillH, 6);
      ctx.fill();
      ctx.stroke();

      // Point de gravité net
      ctx.beginPath();
      ctx.arc(bx + padL + 2.5, by + pillH / 2, 2.7, 0, Math.PI * 2);
      ctx.fillStyle = palette.accent;
      ctx.fill();

      // Identifiant CWE clair (ex: CWE-88, PATH-008, CWE-1075)
      ctx.font = mainFont;
      ctx.fillStyle = palette.text;
      ctx.fillText(b.code, bx + padL + dotArea, by + pillH / 2 + 0.5);

      // Mini-badge compteur (+N) sur la droite si plusieurs failles
      if (extraChipW > 0) {
        const chipX = bx + padL + dotArea + codeW + 5;
        const chipH = pillH - 5;
        const chipY = by + 2.5;
        ctx.fillStyle = palette.chipBg;
        ctx.beginPath();
        ctx.roundRect(chipX, chipY, extraChipW, chipH, 4);
        ctx.fill();

        ctx.font = countFont;
        ctx.fillStyle = palette.chipTxt;
        ctx.fillText(extraText, chipX + 4.5, by + pillH / 2 + 0.5);
      }
    }
  }
  ctx.restore();
}
