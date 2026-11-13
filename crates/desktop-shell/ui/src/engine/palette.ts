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
