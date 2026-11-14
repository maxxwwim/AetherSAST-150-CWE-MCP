// =========================================================================
// AETHERSCOPE V2 — ARCHITECTURAL COLOR PALETTES & LAYER MAPPING (palette.ts)
// =========================================================================

export interface RgbaColor {
  r: number;
  g: number;
  b: number;
  a: number;
}

export const LAYER_COLORS: Record<string, RgbaColor> = {
  ui: { r: 0.22, g: 0.74, b: 0.97, a: 1.0 },        // #38bdf8 Sky Blue
  action: { r: 0.66, g: 0.33, b: 0.97, a: 1.0 },    // #a855f7 Purple
  domain: { r: 0.06, g: 0.73, b: 0.51, a: 1.0 },    // #10b981 Emerald
  database: { r: 0.96, g: 0.62, b: 0.04, a: 1.0 },  // #f59e0b Amber
  config: { r: 0.39, g: 0.45, b: 0.55, a: 1.0 },    // #64748b Slate
  utility: { r: 0.93, g: 0.28, b: 0.60, a: 1.0 },   // #ec4899 Pink
  docs: { r: 0.39, g: 0.40, b: 0.95, a: 1.0 },      // #6366f1 Indigo
  default: { r: 0.58, g: 0.64, b: 0.72, a: 1.0 }   // #94a3b8 Neutral
};

export const SEVERITY_COLORS: Record<string, RgbaColor> = {
  CRITICAL: { r: 0.96, g: 0.26, b: 0.21, a: 1.0 }, // #f44336 Bright Red
  HIGH: { r: 1.00, g: 0.42, b: 0.00, a: 1.0 },     // #ff6b00 Orange
  MEDIUM: { r: 1.00, g: 0.76, b: 0.03, a: 1.0 },   // #ffc107 Yellow
  LOW: { r: 0.29, g: 0.69, b: 0.31, a: 1.0 }       // #4caf50 Green
};

export const GIT_STATUS_COLORS = {
  clean: '#64748b',
  modified: '#facc15', // Pulsing yellow/amber
  untracked: '#34d399', // Radiant emerald green
  violation: '#ef4444', // Warning crimson red
};

export function getLayerRgba(layer?: string): RgbaColor {
  if (!layer) return LAYER_COLORS.default;
  const key = layer.toLowerCase();
  return LAYER_COLORS[key] || LAYER_COLORS.default;
}

export function parseHexColor(hex: string, alpha = 1.0): RgbaColor {
  let c = hex.replace('#', '');
  if (c.length === 3) {
    c = c.split('').map(x => x + x).join('');
  }
  const num = parseInt(c, 16);
  return {
    r: ((num >> 16) & 255) / 255,
    g: ((num >> 8) & 255) / 255,
    b: (num & 255) / 255,
    a: alpha
  };
}

const BRANCH_HUES: Record<string, number> = {
  'desktop-shell': 196,
  'core-graph': 255,
  'security-linter': 38,
  'ast-scanner': 158,
  'ai-file-bridge': 178,
  'arch-templates': 282,
  'aethercraft': 335,
  'obsidian-vault': 168,
  desktop: 196,
  crates: 220,
  apps: 325,
  docs: 142,
  tests: 48,
  root: 200
};

const folderColorCache = new Map<string, RgbaColor>();

function hslToRgba(h: number, s: number, l: number): RgbaColor {
  const hue = ((h % 360) + 360) % 360;
  const sat = Math.max(0, Math.min(1, s));
  const lum = Math.max(0, Math.min(1, l));
  const c = (1 - Math.abs(2 * lum - 1)) * sat;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = lum - c / 2;
  let r = 0, g = 0, b = 0;
  if (hue < 60) { r = c; g = x; }
  else if (hue < 120) { r = x; g = c; }
  else if (hue < 180) { g = c; b = x; }
  else if (hue < 240) { g = x; b = c; }
  else if (hue < 300) { r = x; b = c; }
  else { r = c; b = x; }
  return { r: +(r + m).toFixed(3), g: +(g + m).toFixed(3), b: +(b + m).toFixed(3), a: 1.0 };
}

/**
 * Computes a deterministic tree-coherent cosmic RGBA hue for a folder path.
 */
export function getFolderColor(folder?: string): RgbaColor {
  const key = !folder || folder === 'root' ? 'root' : folder;
  const cached = folderColorCache.get(key);
  if (cached) return cached;
  if (key === 'root') {
    const rootCol = { r: 0.22, g: 0.78, b: 0.99, a: 1.0 };
    folderColorCache.set(key, rootCol);
    return rootCol;
  }

  const clean = key.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const parts = clean.split('/').filter(Boolean);
  let branchKey = 'root';
  let subDepth = 0;
  let subHash = 0;

  if (parts.length >= 2 && (parts[0] === 'crates' || parts[0] === 'apps' || parts[0] === 'packages')) {
    branchKey = parts[1];
    subDepth = parts.length - 2;
    const subStr = parts.slice(2).join('/');
    for (let i = 0; i < subStr.length; i++) subHash = (subHash * 31 + subStr.charCodeAt(i)) | 0;
  } else if (parts.length >= 1) {
    branchKey = parts[0];
    subDepth = parts.length - 1;
    const subStr = parts.slice(1).join('/');
    for (let i = 0; i < subStr.length; i++) subHash = (subHash * 31 + subStr.charCodeAt(i)) | 0;
  }

  const lowerBranch = branchKey.toLowerCase();
  let baseHue = BRANCH_HUES[lowerBranch];
  if (baseHue === undefined) {
    let hHash = 0;
    for (let i = 0; i < lowerBranch.length; i++) hHash = (hHash * 37 + lowerBranch.charCodeAt(i)) | 0;
    baseHue = Math.abs(hHash * 137.5) % 360;
  }

  const hueShift = ((Math.abs(subHash) % 5) - 2) * 5;
  const finalHue = (baseHue + hueShift + 360) % 360;
  const sat = Math.max(0.70, Math.min(0.96, 0.88 - subDepth * 0.04 + (Math.abs(subHash) % 3) * 0.03));
  const lum = Math.max(0.48, Math.min(0.68, 0.58 + (subDepth % 2 === 1 ? 0.05 : -0.03) + (Math.abs(subHash) % 3) * 0.02));

  const rgba = hslToRgba(finalHue, sat, lum);
  folderColorCache.set(key, rgba);
  return rgba;
}

export function formatFolderLabel(folder?: string): string {
  if (!folder || folder === 'root') return 'root';
  const clean = folder.replace(/\\/g, '/');
  const parts = clean.split('/').filter(Boolean);
  if (parts.length <= 1) {
    return clean.length > 20 ? clean.slice(0, 18) + '…' : clean;
  }
  const last = parts[parts.length - 1];
  const prev = parts[parts.length - 2];
  const shortPath = `${prev}/${last}`;
  if (shortPath.length <= 22) return shortPath;
  return last.length > 20 ? last.slice(0, 18) + '…' : last;
}
