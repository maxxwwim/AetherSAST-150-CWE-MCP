// =========================================================================
// AETHERSCOPE V2 — WEBGL 2 VISUAL PLUGINS ENGINE (visualPlugins.ts)
// Declarative Themes, GLSL ES 3.00 Hook Assemblers, Anti-DoS Validator & Built-in Packs
// =========================================================================

import type { RgbaColor } from './palette';

export type MembraneStyle = 'organic_12lobe' | 'hex_hull' | 'rect_blueprint' | 'none';
export type EdgeStyle = 'bezier' | 'straight' | 'orthogonal_pcb';

export interface VisualPaletteConfig {
  background?: string[];
  layers?: Record<string, string>;
  severities?: Record<string, string>;
  contract_warning?: string;
}

export interface VisualOverlayConfig {
  membrane_style?: MembraneStyle | string;
  edge_style?: EdgeStyle | string;
  edge_pulse_speed?: number;
  membrane_breath_amp?: number;
  label_font?: string;
}

export interface VisualPluginPack {
  schema_version?: number;
  id: string;
  name: string;
  version: string;
  author?: string | null;
  description?: string | null;
  enabled: boolean;
  builtin?: boolean;
  rel_dir?: string;
  palette: VisualPaletteConfig;
  overlay: VisualOverlayConfig;
  uniforms: Record<string, number>;
  backdrop_glsl?: string | null;
  node_sdf_glsl?: string | null;
  validation_warnings?: string[];
}

export const MAX_GLSL_BYTES = 32 * 1024;
const MAX_FOR_BOUND = 128;

export function hexToRgba(hex: string, alpha = 1.0): RgbaColor | null {
  const clean = hex.trim().replace(/^#/, '');
  if (!/^[0-9a-fA-F]{3}$|^[0-9a-fA-F]{6}$/.test(clean)) return null;
  const full =
    clean.length === 3
      ? clean
          .split('')
          .map((c) => c + c)
          .join('')
      : clean;
  const r = parseInt(full.slice(0, 2), 16) / 255;
  const g = parseInt(full.slice(2, 4), 16) / 255;
  const b = parseInt(full.slice(4, 6), 16) / 255;
  return { r: +r.toFixed(4), g: +g.toFixed(4), b: +b.toFixed(4), a: alpha };
}

export function resolveThemeColorsArray(bgHexes?: string[]): Float32Array {
  const defaults: [number, number, number][] = [
    [0.016, 0.020, 0.044],
    [0.045, 0.190, 0.310],
    [0.180, 0.065, 0.300],
    [0.240, 0.065, 0.190],
  ];
  const out = new Float32Array(12);
  for (let i = 0; i < 4; i++) {
    const parsed = bgHexes?.[i] ? hexToRgba(bgHexes[i]) : null;
    if (parsed) {
      out[i * 3 + 0] = parsed.r;
      out[i * 3 + 1] = parsed.g;
      out[i * 3 + 2] = parsed.b;
    } else {
      out[i * 3 + 0] = defaults[i][0];
      out[i * 3 + 1] = defaults[i][1];
      out[i * 3 + 2] = defaults[i][2];
    }
  }
  return out;
}

export function resolveUniformParamsVec4(uniforms?: Record<string, number>): [number, number, number, number] {
  const u = uniforms || {};
  return [
    Number.isFinite(u.grid_scale) ? u.grid_scale : 1.0,
    Number.isFinite(u.glow_sharpness) ? u.glow_sharpness : 1.0,
    Number.isFinite(u.star_density) ? u.star_density : 1.0,
    Number.isFinite(u.nebula_speed) ? u.nebula_speed : 1.0,
  ];
}

/**
 * Client-side GLSL ES 3.00 static anti-DoS validator mirroring Rust `validate_glsl_hook`.
 */
export function validateGlslHookClient(src: string, expectedFn: 'aetherBackdrop' | 'aetherNodeSurface'): string | null {
  if (src.length > MAX_GLSL_BYTES) {
    return `Shader GLSL trop volumineux (${src.length} > ${MAX_GLSL_BYTES} octets).`;
  }
  if (src.includes('\0')) {
    return 'Octet nul interdit dans le shader GLSL.';
  }
  const stripped = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '');

  if (/^\s*#(version|extension|pragma)\b/m.test(stripped)) {
    return 'Directives #version / #extension / #pragma gérées par AetherScope et interdites dans les hooks.';
  }
  if (/\bwhile\s*\(/i.test(stripped) || /\bdo\s*\{/i.test(stripped)) {
    return 'Boucles while / do-while interdites dans les shaders plugins (protection anti-TDR GPU).';
  }

  const forRegex = /\bfor\s*\(([^)]*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = forRegex.exec(stripped)) !== null) {
    const parts = m[1].split(';');
    if (parts.length !== 3 || !parts[1].trim()) {
      return 'Boucle for non bornée interdite dans le shader GLSL.';
    }
    const nums = parts[1].match(/\d+/g) || [];
    for (const n of nums) {
      if (parseInt(n, 10) > MAX_FOR_BOUND) {
        return `Borne de boucle for (${n}) supérieure à la limite de sécurité (${MAX_FOR_BOUND}).`;
      }
    }
  }

  if (!stripped.includes(expectedFn)) {
    return `Le hook GLSL doit définir la fonction contractuelle '${expectedFn}'.`;
  }
  return null;
}

const BACKDROP_HOST_HEADER = `#version 300 es
precision highp float;
in vec2 v_uv;
uniform vec2 u_resolution;
uniform vec2 u_camera_pos;
uniform float u_zoom;
uniform float u_time;
uniform vec3 u_theme_colors[4];
uniform vec4 u_params;
out vec4 fragColor;

float aetherHash21(vec2 p) {
  p = fract(p * vec2(123.34, 456.21));
  p += dot(p, p + 45.32);
  return fract(p.x * p.y);
}

float aetherNoise2(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(aetherHash21(i), aetherHash21(i + vec2(1.0, 0.0)), f.x),
    mix(aetherHash21(i + vec2(0.0, 1.0)), aetherHash21(i + vec2(1.0, 1.0)), f.x),
    f.y
  );
}
`;

const BACKDROP_HOST_FOOTER = `
void main() {
  float minDim = max(1.0, min(u_resolution.x, u_resolution.y));
  vec2 aspectUv = (gl_FragCoord.xy - 0.5 * u_resolution) / minDim;
  float timeSec = u_time * 0.001;
  vec3 rgb = aetherBackdrop(aspectUv, u_camera_pos, u_zoom, timeSec);
  fragColor = vec4(clamp(rgb, 0.0, 1.5), 1.0);
}
`;

export function assembleBackdropFs(hookGlsl: string): { source: string; lineOffset: number } {
  const lineOffset = BACKDROP_HOST_HEADER.split('\n').length - 1;
  return {
    source: `${BACKDROP_HOST_HEADER}\n${hookGlsl}\n${BACKDROP_HOST_FOOTER}`,
    lineOffset,
  };
}

const NODE_HOST_HEADER = `#version 300 es
precision highp float;
in vec2 v_uv;
in vec4 v_color;
in float v_is_file;
in float v_scale;
in float v_spawn_progress;
in float v_time;
in float v_phase;
in float v_git_status;
in float v_metric0;
in float v_metric1;

uniform vec3 u_theme_colors[4];
uniform vec4 u_params;

out vec4 fragColor;

struct NodeCtx {
  vec2 uv;
  float r;
  float angle;
  vec4 color;
  float kind;
  float time;
  float phase;
  float gitStatus;
  float metric0;
  float metric1;
};
`;

const NODE_HOST_FOOTER = `
void main() {
  if (v_spawn_progress <= 0.001) discard;
  float r = length(v_uv);
  if (r > 1.0) discard;

  NodeCtx ctx;
  ctx.uv = v_uv;
  ctx.r = r;
  ctx.angle = atan(v_uv.y, v_uv.x);
  ctx.color = v_color;
  ctx.kind = v_is_file;
  ctx.time = v_time * 0.001;
  ctx.phase = v_phase;
  ctx.gitStatus = v_git_status;
  ctx.metric0 = v_metric0;
  ctx.metric1 = v_metric1;

  vec3 final_rgb = v_color.rgb;
  float alpha = 0.0;
  aetherNodeSurface(ctx, final_rgb, alpha);

  // Preserve Git Diff & Security Violation halos across all custom visual plugins
  if (v_git_status > 0.5) {
    vec3 halo_col = vec3(0.98, 0.80, 0.08);
    float pulse = 0.88 + 0.12 * sin(v_time * 0.00075 + v_phase);
    if (v_git_status > 1.5 && v_git_status < 2.5) {
      halo_col = vec3(0.18, 0.92, 0.52);
    } else if (v_git_status >= 2.5 && v_git_status < 3.5) {
      halo_col = vec3(0.98, 0.22, 0.22);
    } else if (v_git_status >= 3.5 && v_git_status < 4.5) {
      halo_col = vec3(0.13, 0.85, 0.96);
    } else if (v_git_status >= 4.5) {
      halo_col = vec3(0.76, 0.52, 0.99);
    }
    float halo_rim = (1.0 - smoothstep(0.0, 0.095, abs(r - 0.86))) * pulse;
    float halo_glow = (1.0 - smoothstep(0.50, 0.99, r)) * 0.48 * pulse;
    final_rgb = mix(final_rgb, halo_col * 1.18, clamp(halo_rim * 0.85 + halo_glow * 0.45, 0.0, 1.0));
    alpha = max(alpha, clamp(halo_rim * 0.90 + halo_glow * 0.55, 0.0, 1.0));
  }

  if (v_color.a < 0.2) {
    final_rgb *= (v_color.a * 2.5 + 0.08);
  }
  float spawn_alpha = clamp(v_spawn_progress * 1.6, 0.0, 1.0);
  fragColor = vec4(final_rgb, clamp(alpha, 0.0, 1.0) * v_color.a * spawn_alpha);
}
`;

export function assembleNodeFs(hookGlsl: string): { source: string; lineOffset: number } {
  const lineOffset = NODE_HOST_HEADER.split('\n').length - 1;
  return {
    source: `${NODE_HOST_HEADER}\n${hookGlsl}\n${NODE_HOST_FOOTER}`,
    lineOffset,
  };
}

// =========================================================================
// BUILT-IN VISUAL PLUGIN PACKS (Available Live & in Standalone Demo!)
// =========================================================================

const CYBER_PCB_BACKDROP = `vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec) {
  float scale = max(0.08, u_params.x) * (1.0 + clamp(zoom, 0.05, 4.0) * 0.18);
  vec2 p = aspectUv * (14.0 * scale) + worldCam * 0.008;

  // Dual-scale PCB grid lines (minor + major)
  vec2 gMinor = abs(fract(p - 0.5) - 0.5) / max(fwidth(p), vec2(0.002));
  float minorLine = 1.0 - min(min(gMinor.x, gMinor.y), 1.0);

  vec2 pMaj = p * 0.25;
  vec2 gMajor = abs(fract(pMaj - 0.5) - 0.5) / max(fwidth(pMaj), vec2(0.002));
  float majorLine = 1.0 - min(min(gMajor.x, gMajor.y), 1.0);

  // Subtle circuit pad dots at major grid intersections
  vec2 cell = fract(pMaj) - 0.5;
  float viaDot = 1.0 - smoothstep(0.04, 0.09, length(cell));

  // Scanning data bus wave across PCB
  float scan = exp(-abs(sin(pMaj.x * 0.65 - timeSec * 0.45 * u_params.w)) * 18.0) * majorLine;

  vec3 col = u_theme_colors[0];
  col += u_theme_colors[1] * (minorLine * 0.16 + majorLine * 0.36);
  col += u_theme_colors[2] * viaDot * 0.35;
  col += u_theme_colors[3] * scan * 0.65;

  // Soft edge vignette
  float vig = 1.0 - smoothstep(0.45, 1.35, length(aspectUv));
  return col * (0.65 + 0.35 * vig);
}`;

const CYBER_PCB_NODE_SDF = `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) {
  vec2 a = abs(ctx.uv);
  // Octagonal IC microchip silhouette
  float oct = max(max(a.x, a.y), (a.x + a.y) * 0.7071);
  float glowSharp = max(0.5, u_params.y);

  if (ctx.kind < 0.5) {
    // Function: glowing solder via pad
    float pad = 1.0 - smoothstep(0.18, 0.46, ctx.r);
    float ring = 1.0 - smoothstep(0.0, 0.08, abs(ctx.r - 0.48));
    float hole = smoothstep(0.10, 0.16, ctx.r);
    float aura = (1.0 - smoothstep(0.35, 0.96, ctx.r)) * (0.45 + 0.35 * ctx.metric0);
    rgb = ctx.color.rgb * (0.85 + pad * 0.5 + aura) + vec3(0.92, 1.0, 1.0) * ring * 0.8;
    alpha = clamp((pad * hole) + ring * 0.9 + aura * 0.55, 0.0, 1.0);
  } else if (ctx.kind < 1.5) {
    // File: octagonal silicon IC package with metric0 voltage core
    float body = (1.0 - smoothstep(0.54, 0.60, oct)) * 0.85;
    float rim = (1.0 - smoothstep(0.0, 0.055 / glowSharp, abs(oct - 0.58))) * 0.95;
    float innerTrace = (1.0 - smoothstep(0.0, 0.04, abs(oct - 0.36))) * (0.55 + 0.45 * ctx.metric0);
    float corePulse = 0.78 + 0.22 * sin(ctx.time * 2.4 + ctx.phase);
    float core = (1.0 - smoothstep(0.0, 0.24, oct)) * (0.55 + 0.45 * ctx.metric0) * corePulse;
    // Microchip pins along cardinal axes
    float pinMask = step(0.58, oct) * (1.0 - step(0.76, oct));
    float pins = pinMask * (step(0.72, abs(sin(ctx.uv.x * 22.0))) * step(a.x, 0.42) + step(0.72, abs(sin(ctx.uv.y * 22.0))) * step(a.y, 0.42));
    float aura = (1.0 - smoothstep(0.52, 0.98, ctx.r)) * 0.42;
    rgb = ctx.color.rgb * (body * 0.65 + aura * 0.9)
        + mix(ctx.color.rgb, vec3(0.95, 1.0, 1.0), 0.72) * (rim + core * 0.85 + innerTrace * 0.7)
        + u_theme_colors[3] * pins * 0.85;
    alpha = clamp(body * 0.88 + rim + pins * 0.75 + aura * 0.45, 0.0, 1.0);
  } else if (ctx.kind < 2.5) {
    // Class/Struct: crisp diamond bus controller
    float dia = (a.x + a.y) * 0.82;
    float body = (1.0 - smoothstep(0.50, 0.58, dia)) * 0.82;
    float rim = 1.0 - smoothstep(0.0, 0.06, abs(dia - 0.55));
    float core = 1.0 - smoothstep(0.0, 0.22, dia);
    rgb = mix(ctx.color.rgb, vec3(1.0), core * 0.75 + rim * 0.55) + ctx.color.rgb * body * 0.5;
    alpha = clamp(body + rim * 0.95, 0.0, 1.0);
  } else {
    // Endpoint: pulsing telemetry transceiver
    float pulseR = mix(0.45, 0.88, fract(ctx.time * 0.45 + ctx.phase * 0.16));
    float wave = (1.0 - smoothstep(0.0, 0.07, abs(ctx.r - pulseR))) * (1.0 - pulseR * 0.7);
    float body = (1.0 - smoothstep(0.24, 0.50, oct)) * 0.85;
    float rim = 1.0 - smoothstep(0.0, 0.06, abs(oct - 0.48));
    rgb = mix(ctx.color.rgb, vec3(1.0), rim * 0.7 + wave * 0.5) + ctx.color.rgb * body * 0.6;
    alpha = clamp(body + rim * 0.95 + wave * 0.85, 0.0, 1.0);
  }
}`;

const ARCHITECT_BLUEPRINT_BACKDROP = `vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec) {
  float scale = max(0.1, u_params.x) * (1.0 + clamp(zoom, 0.05, 5.0) * 0.12);
  vec2 p = aspectUv * (18.0 * scale) + worldCam * 0.01;

  vec2 g1 = abs(fract(p - 0.5) - 0.5) / max(fwidth(p), vec2(0.002));
  float fine = 1.0 - min(min(g1.x, g1.y), 1.0);

  vec2 p5 = p * 0.2;
  vec2 g5 = abs(fract(p5 - 0.5) - 0.5) / max(fwidth(p5), vec2(0.002));
  float bold = 1.0 - min(min(g5.x, g5.y), 1.0);

  // Subtle paper grain
  float grain = (aetherNoise2(aspectUv * 120.0 + vec2(0.0, timeSec * 0.02)) - 0.5) * 0.025;

  // Drafting crosshairs at origin
  vec2 crossD = abs(aspectUv);
  float axis = (1.0 - smoothstep(0.001, 0.003, min(crossD.x, crossD.y))) * 0.14;

  vec3 col = u_theme_colors[0] + grain;
  col = mix(col, u_theme_colors[1], fine * 0.18);
  col = mix(col, u_theme_colors[2], bold * 0.34 + axis);
  return col;
}`;

const ARCHITECT_BLUEPRINT_NODE_SDF = `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) {
  vec2 a = abs(ctx.uv);
  float stroke = 0.055;
  if (ctx.kind < 0.5) {
    // Function: crisp technical dot with drafting ring
    float core = 1.0 - smoothstep(0.14, 0.24, ctx.r);
    float ring = 1.0 - smoothstep(0.0, stroke, abs(ctx.r - 0.48));
    rgb = mix(ctx.color.rgb, vec3(0.95, 0.98, 1.0), 0.55) * (core + ring);
    alpha = clamp(core * 0.92 + ring * 0.85, 0.0, 1.0);
  } else if (ctx.kind < 1.5) {
    // File: double concentric blueprint caliper circle with crosshairs
    float fill = (1.0 - smoothstep(0.50, 0.58, ctx.r)) * (0.28 + 0.25 * ctx.metric0);
    float outerRing = 1.0 - smoothstep(0.0, stroke, abs(ctx.r - 0.62));
    float innerRing = (1.0 - smoothstep(0.0, stroke * 0.75, abs(ctx.r - 0.38))) * 0.7;
    float ticks = (1.0 - smoothstep(0.0, 0.035, min(a.x, a.y))) * step(0.46, ctx.r) * (1.0 - step(0.76, ctx.r));
    rgb = mix(ctx.color.rgb, vec3(0.94, 0.98, 1.0), outerRing * 0.7 + ticks * 0.8 + innerRing * 0.4);
    alpha = clamp(fill + outerRing * 0.95 + innerRing * 0.7 + ticks * 0.85, 0.0, 1.0);
  } else if (ctx.kind < 2.5) {
    // Class/Struct: architectural framed square module
    float sq = max(a.x, a.y);
    float fill = (1.0 - smoothstep(0.50, 0.56, sq)) * 0.34;
    float frame = 1.0 - smoothstep(0.0, stroke, abs(sq - 0.56));
    float corner = (1.0 - smoothstep(0.0, stroke * 0.8, abs(sq - 0.42))) * 0.55;
    rgb = mix(ctx.color.rgb, vec3(1.0), frame * 0.75 + corner * 0.4);
    alpha = clamp(fill + frame * 0.95 + corner * 0.6, 0.0, 1.0);
  } else {
    // Endpoint: CAD diamond marker
    float dia = a.x + a.y;
    float fill = (1.0 - smoothstep(0.55, 0.62, dia)) * 0.38;
    float rim = 1.0 - smoothstep(0.0, stroke * 1.2, abs(dia - 0.62));
    rgb = mix(ctx.color.rgb, vec3(1.0, 0.96, 0.86), rim * 0.8);
    alpha = clamp(fill + rim * 0.95, 0.0, 1.0);
  }
}`;

const DEEP_BIOLUM_BACKDROP = `vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec) {
  float t = timeSec * 0.35 * u_params.w;
  vec2 p = aspectUv * 2.8 + worldCam * 0.00045;
  // Layered pelagic caustics
  float n1 = aetherNoise2(p * 2.2 + vec2(t * 0.4, -t * 0.25));
  float n2 = aetherNoise2(p * 3.6 + vec2(-t * 0.3, t * 0.35) + n1 * 1.4);
  float caustic = pow(clamp(1.0 - abs(n2 - 0.5) * 2.4, 0.0, 1.0), 3.0);

  // Subtle depth gradient (lighter teal near top, abyssal navy at bottom)
  float depth = clamp(0.55 - aspectUv.y * 0.65, 0.0, 1.0);
  vec3 col = mix(u_theme_colors[0], u_theme_colors[1], depth * 0.65);
  col += u_theme_colors[2] * caustic * 0.42;
  col += u_theme_colors[3] * smoothstep(0.65, 0.95, n1 * n2) * 0.35;
  return col;
}`;

const DEEP_BIOLUM_NODE_SDF = `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) {
  float ripple = 0.045 * sin(ctx.angle * 5.0 + ctx.time * 2.2 + ctx.phase)
               + 0.025 * cos(ctx.angle * 8.0 - ctx.time * 1.6 + ctx.phase * 1.4);
  float rOrg = ctx.r * (1.0 + ripple);
  float pulse = 0.86 + 0.14 * sin(ctx.time * 2.8 + ctx.phase);
  float core = 1.0 - smoothstep(0.0, 0.32 + 0.10 * ctx.metric0, rOrg);
  float bell = (1.0 - smoothstep(0.18, 0.64, rOrg)) * 0.65;
  float rim = (1.0 - smoothstep(0.0, 0.08, abs(rOrg - 0.58))) * 0.92 * pulse;
  float glow = (1.0 - smoothstep(0.28, 0.99, ctx.r)) * (0.58 + 0.28 * ctx.metric0) * pulse;

  rgb = mix(ctx.color.rgb * 0.9, vec3(0.85, 1.0, 0.98), core * 0.82 + rim * 0.45)
      + ctx.color.rgb * (bell * 0.75 + glow * 0.95);
  alpha = clamp(core * 0.95 + bell * 0.70 + rim * 0.92 + glow * 0.60, 0.0, 1.0);
}`;

const MATRIX_PHOSPHOR_BACKDROP = `vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec) {
  vec2 p = aspectUv * (12.0 * max(0.1, u_params.x)) + worldCam * 0.006;
  vec2 g = abs(fract(p - 0.5) - 0.5) / max(fwidth(p), vec2(0.002));
  float grid = 1.0 - min(min(g.x, g.y), 1.0);

  // Subtle CRT scanlines + radial radar sweep
  float scanline = 0.90 + 0.10 * sin(gl_FragCoord.y * 1.5);
  float ang = atan(aspectUv.y, aspectUv.x);
  float sweep = exp(-mod(ang + timeSec * 0.55 * u_params.w, 6.28318) * 3.5) * 0.14;
  float rings = (1.0 - smoothstep(0.0, 0.008, abs(fract(length(aspectUv) * 3.5) - 0.5))) * 0.14;

  vec3 col = u_theme_colors[0];
  col += u_theme_colors[1] * (grid * 0.20 + rings);
  col += u_theme_colors[2] * sweep;
  return col * scanline;
}`;

const MATRIX_PHOSPHOR_NODE_SDF = `void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) {
  float ring = 1.0 - smoothstep(0.0, 0.065, abs(ctx.r - 0.56));
  float inner = 1.0 - smoothstep(0.0, 0.28 + 0.14 * ctx.metric0, ctx.r);
  float halo = (1.0 - smoothstep(0.32, 0.98, ctx.r)) * 0.52;
  vec2 a = abs(ctx.uv);
  float reticle = (1.0 - smoothstep(0.0, 0.04, min(a.x, a.y))) * step(0.56, ctx.r) * (1.0 - step(0.84, ctx.r));
  float phosphor = 0.92 + 0.08 * sin(ctx.time * 12.0 + ctx.phase);
  rgb = (ctx.color.rgb * (inner * 0.9 + halo) + mix(ctx.color.rgb, vec3(0.85, 1.0, 0.88), 0.7) * (ring + reticle * 0.8)) * phosphor;
  alpha = clamp(inner * 0.95 + ring * 0.95 + reticle * 0.75 + halo * 0.5, 0.0, 1.0);
}`;

export const BUILTIN_VISUAL_PLUGINS: VisualPluginPack[] = [
  {
    schema_version: 1,
    id: 'obsidian-nebula',
    name: 'Obsidian Nebula (Natif)',
    version: '2.5.1',
    author: 'AetherScope Core',
    description: 'Nébuleuse cosmique native, cellules bioluminescentes 3D SDF et membranes organiques à 12 lobes.',
    enabled: true,
    builtin: true,
    palette: {
      background: ['#04050b', '#0b304f', '#2e104d', '#3d1030'],
    },
    overlay: {
      membrane_style: 'organic_12lobe',
      edge_style: 'bezier',
      edge_pulse_speed: 1.0,
      membrane_breath_amp: 1.0,
    },
    uniforms: { grid_scale: 1.0, glow_sharpness: 1.0, star_density: 1.0, nebula_speed: 1.0 },
    backdrop_glsl: null,
    node_sdf_glsl: null,
  },
  {
    schema_version: 1,
    id: 'cyber-pcb',
    name: 'Cyber-PCB Neon Blueprint',
    version: '1.0.0',
    author: 'AetherScope Visual Lab',
    description: 'Transforme le graphe AST en carte électronique néon : puces octogonales GLSL, enveloppes hexagonales et pistes PCB 45°/90°.',
    enabled: true,
    builtin: true,
    palette: {
      background: ['#03080e', '#083344', '#06b6d4', '#22d3ee'],
      layers: {
        ui: '#22d3ee',
        action: '#e879f9',
        domain: '#34d399',
        database: '#fbbf24',
        config: '#64748b',
        utility: '#f472b6',
        docs: '#818cf8',
      },
      severities: {
        CRITICAL: '#ff1e56',
        HIGH: '#ff8c00',
        MEDIUM: '#fde047',
        LOW: '#22c55e',
      },
    },
    overlay: {
      membrane_style: 'hex_hull',
      edge_style: 'orthogonal_pcb',
      edge_pulse_speed: 1.6,
      membrane_breath_amp: 0.0,
    },
    uniforms: { grid_scale: 1.0, glow_sharpness: 1.4, star_density: 0.0, nebula_speed: 1.2 },
    backdrop_glsl: CYBER_PCB_BACKDROP,
    node_sdf_glsl: CYBER_PCB_NODE_SDF,
  },
  {
    schema_version: 1,
    id: 'architect-blueprint',
    name: 'CAD Architect Blueprint',
    version: '1.0.0',
    author: 'AetherScope Visual Lab',
    description: 'Plan d’architecte bleu de Prusse : grille millimétrée vectorielle, glyphes techniques CAD, cadres rectangulaires et vecteurs droits.',
    enabled: true,
    builtin: true,
    palette: {
      background: ['#071a33', '#154273', '#60a5fa', '#bae6fd'],
      layers: {
        ui: '#7dd3fc',
        action: '#c4b5fd',
        domain: '#6ee7b7',
        database: '#fcd34d',
        config: '#94a3b8',
        utility: '#f9a8d4',
        docs: '#a5b4fc',
      },
    },
    overlay: {
      membrane_style: 'rect_blueprint',
      edge_style: 'straight',
      edge_pulse_speed: 0.8,
      membrane_breath_amp: 0.0,
    },
    uniforms: { grid_scale: 1.0, glow_sharpness: 1.2, star_density: 0.0, nebula_speed: 0.6 },
    backdrop_glsl: ARCHITECT_BLUEPRINT_BACKDROP,
    node_sdf_glsl: ARCHITECT_BLUEPRINT_NODE_SDF,
  },
  {
    schema_version: 1,
    id: 'deep-biolum',
    name: 'Abyssal Bioluminescence',
    version: '1.0.0',
    author: 'AetherScope Visual Lab',
    description: 'Courants abyssaux caustiques et organismes cellulaires translucides à pulsation bioluminescente.',
    enabled: true,
    builtin: true,
    palette: {
      background: ['#020c14', '#062a3a', '#0ea5e9', '#2dd4bf'],
      layers: {
        ui: '#38bdf8',
        action: '#a78bfa',
        domain: '#2dd4bf',
        database: '#fbbf24',
        config: '#64748b',
        utility: '#f472b6',
        docs: '#818cf8',
      },
    },
    overlay: {
      membrane_style: 'organic_12lobe',
      edge_style: 'bezier',
      edge_pulse_speed: 0.9,
      membrane_breath_amp: 1.25,
    },
    uniforms: { grid_scale: 1.0, glow_sharpness: 1.0, star_density: 0.5, nebula_speed: 1.0 },
    backdrop_glsl: DEEP_BIOLUM_BACKDROP,
    node_sdf_glsl: DEEP_BIOLUM_NODE_SDF,
  },
  {
    schema_version: 1,
    id: 'matrix-phosphor',
    name: 'Phosphor CRT Oscilloscope',
    version: '1.0.0',
    author: 'AetherScope Visual Lab',
    description: 'Terminal radar vert phosphore, scanlines CRT subtiles, réticules vectoriels et bus orthogonaux.',
    enabled: true,
    builtin: true,
    palette: {
      background: ['#020904', '#0b3b1c', '#10b981', '#4ade80'],
      layers: {
        ui: '#4ade80',
        action: '#34d399',
        domain: '#10b981',
        database: '#a3e635',
        config: '#22c55e',
        utility: '#86efac',
        docs: '#6ee7b7',
      },
      severities: {
        CRITICAL: '#ff3b3b',
        HIGH: '#f59e0b',
        MEDIUM: '#facc15',
        LOW: '#22c55e',
      },
    },
    overlay: {
      membrane_style: 'hex_hull',
      edge_style: 'orthogonal_pcb',
      edge_pulse_speed: 1.8,
      membrane_breath_amp: 0.0,
    },
    uniforms: { grid_scale: 1.0, glow_sharpness: 1.3, star_density: 0.0, nebula_speed: 1.2 },
    backdrop_glsl: MATRIX_PHOSPHOR_BACKDROP,
    node_sdf_glsl: MATRIX_PHOSPHOR_NODE_SDF,
  },
];
