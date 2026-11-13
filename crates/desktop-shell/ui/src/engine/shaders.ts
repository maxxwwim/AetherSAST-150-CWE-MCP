// =========================================================================
// AETHERSCOPE V2 — WEBGL 2 SHADER PIPELINE (shaders.ts)
// 120 FPS Instanced SDF Celestial Renderer (Stars, Planets, Crystals, Pulsars)
// =========================================================================

export const vsSource = `#version 300 es
  in vec2 a_quad_pos;
  in vec2 a_node_pos;
  in float a_radius;
  in vec4 a_color;
  in float a_is_file;
  in float a_birth_time;

  uniform vec2 u_resolution;
  uniform vec2 u_camera_pos;
  uniform float u_zoom;
  uniform float u_time;

  out vec2 v_uv;
  out vec4 v_color;
  out float v_is_file;
  out float v_scale;
  out float v_spawn_progress;
  out float v_time;
  out float v_phase;

  void main() {
    v_uv = a_quad_pos;
    v_color = a_color;
    v_is_file = a_is_file;
    v_time = u_time;
    v_phase = fract(sin(dot(a_node_pos, vec2(12.9898, 78.233))) * 43758.5453) * 6.283185;

    float dt = u_time - a_birth_time;
    if (dt <= 0.0) {
      gl_Position = vec4(2.0, 2.0, 2.0, 1.0);
      v_scale = 0.0;
      v_spawn_progress = 0.0;
      return;
    }

    // 300ms organic breathing birth curve
    float spawn_dur = 300.0;
    float progress = clamp(dt / spawn_dur, 0.0, 1.0);
    v_spawn_progress = progress;

    float ease_out = 1.0 - pow(1.0 - progress, 3.0);
    float breath_overshoot = sin(progress * 3.14159) * 0.20 * (1.0 - progress);
    float scale = clamp(ease_out + breath_overshoot, 0.0, 1.30);
    v_scale = scale;

    float zoom_factor = clamp(1.0 / sqrt(clamp(u_zoom, 0.08, 3.5)), 0.85, 2.5);
    float breath = 1.0 + 0.045 * sin(u_time * 0.0014 + v_phase);
    float actual_r = a_radius * scale * breath * 2.85 * zoom_factor;

    // Gentle organic cytoplasmic suspension drift (phase-shifted per bubble)
    float buoy_x = sin(u_time * 0.00095 + v_phase + a_node_pos.y * 0.008) * 3.8
                 + cos(u_time * 0.00055 + v_phase * 1.7) * 1.6;
    float buoy_y = cos(u_time * 0.00082 + v_phase * 1.3 + a_node_pos.x * 0.008) * 4.2
                 + sin(u_time * 0.00048 + v_phase) * 1.6;
    vec2 dynamic_pos = a_node_pos + vec2(buoy_x, buoy_y);

    vec2 world_pos = dynamic_pos + a_quad_pos * actual_r;
    vec2 screen_pos = (world_pos - u_camera_pos) * u_zoom + u_resolution * 0.5;
    vec2 clip_pos = (screen_pos / u_resolution) * 2.0 - 1.0;
    clip_pos.y = -clip_pos.y;

    gl_Position = vec4(clip_pos, 0.0, 1.0);
  }
`;

export const fsSource = `#version 300 es
  precision highp float;
  in vec2 v_uv;
  in vec4 v_color;
  in float v_is_file;
  in float v_scale;
  in float v_spawn_progress;
  in float v_time;
  in float v_phase;

  out vec4 fragColor;

  void main() {
    if (v_spawn_progress <= 0.001) discard;
    float r = length(v_uv);
    if (r > 1.0) discard;

    float angle = atan(v_uv.y, v_uv.x);
    // Multi-harmonic living cell membrane contour ("bulle vivante")
    float wave = 0.044 * sin(angle * 3.0 + v_time * 0.0013 + v_phase)
               + 0.026 * cos(angle * 5.0 - v_time * 0.00095 + v_phase * 1.6);
    float r_org = r * (1.0 + wave);
    vec3 col = v_color.rgb;
    vec3 final_rgb = col;
    float alpha = 1.0;

    if (v_is_file < 0.5) {
      // SYMBOLE / FONCTION : Cellule synaptique bioluminescente vivante
      float twinkle = 0.93 + 0.07 * sin(v_time * 0.0020 + v_phase);
      float core = 1.0 - smoothstep(0.0, 0.34, r_org);
      float cytoplasm = (1.0 - smoothstep(0.18, 0.62, r_org)) * 0.55;
      float membrane = (1.0 - smoothstep(0.0, 0.09, abs(r_org - 0.44))) * 0.72 * twinkle;
      float halo = (1.0 - smoothstep(0.20, 0.98, r)) * 0.68 * twinkle;
      final_rgb = mix(col * 1.15, vec3(1.0, 0.99, 0.96), core * 0.78) + col * (cytoplasm + halo * 0.72) + mix(col, vec3(1.0), 0.5) * membrane;
      alpha = clamp(core * 0.96 + cytoplasm + membrane + halo * 0.62, 0.0, 1.0);
    } else if (v_is_file < 1.5) {
      // PLANÈTE / FICHIER : Bulle cellulaire organique à double membrane lipidique
      float z_sphere = sqrt(max(0.0, 1.0 - min(1.0, (r_org / 0.58) * (r_org / 0.58))));
      float cytoplasm = (1.0 - smoothstep(0.10, 0.58, r_org)) * (0.42 + 0.28 * (1.0 - z_sphere));
      float nucleus = 1.0 - smoothstep(0.0, 0.25, r_org);
      float inner_rim = 1.0 - smoothstep(0.0, 0.085, abs(r_org - 0.54));
      float outer_wave = 0.052 * cos(angle * 4.0 - v_time * 0.0015 + v_phase * 1.3);
      float exo_r = r * (1.0 + outer_wave);
      float outer_membrane = (1.0 - smoothstep(0.0, 0.065, abs(exo_r - 0.80))) * 0.82;
      float bio_aura = (1.0 - smoothstep(0.45, 0.98, r)) * 0.45;

      final_rgb = mix(col * 0.85, vec3(0.96, 0.99, 1.0), nucleus * 0.68 + inner_rim * 0.45);
      final_rgb += col * (cytoplasm * 0.85 + bio_aura * 0.90) + mix(col, vec3(0.88, 0.97, 1.0), 0.55) * (inner_rim * 0.85 + outer_membrane);
      alpha = clamp(nucleus * 0.85 + cytoplasm * 0.78 + inner_rim * 0.92 + outer_membrane * 0.85 + bio_aura * 0.55, 0.0, 1.0);
    } else if (v_is_file < 2.5) {
      // CLASSE / STRUCT : Organite hexagonal organique vivant
      float hex_wave = 0.038 * cos(angle * 6.0 + v_time * 0.0011 + v_phase);
      float r_hex = r_org * (1.0 + hex_wave);
      float body = (1.0 - smoothstep(0.20, 0.58, r_hex)) * 0.76;
      float rim = 1.0 - smoothstep(0.0, 0.075, abs(r_hex - 0.54));
      float inner_ring = (1.0 - smoothstep(0.0, 0.06, abs(r_hex - 0.31))) * 0.78;
      float core = 1.0 - smoothstep(0.0, 0.21, r_hex);
      float outer_glow = (1.0 - smoothstep(0.48, 0.96, r)) * 0.50;

      final_rgb = mix(col, vec3(1.0), core * 0.76) + vec3(0.95, 0.98, 1.0) * rim * 0.75 + col * (body * 0.65 + inner_ring * 0.85 + outer_glow * 0.88);
      alpha = clamp(body + rim * 0.92 + inner_ring * 0.70 + outer_glow * 0.52, 0.0, 1.0);
    } else {
      // FORM / ENDPOINT : Vésicule émettrice à respiration lente
      float pulse_r = mix(0.50, 0.90, fract(v_time * 0.00038 + v_phase * 0.159));
      float radar_wave = (1.0 - smoothstep(0.0, 0.07, abs(r_org - pulse_r))) * (1.0 - (pulse_r - 0.50) / 0.42) * 0.75;
      float body = (1.0 - smoothstep(0.22, 0.57, r_org)) * 0.75;
      float rim = 1.0 - smoothstep(0.0, 0.09, abs(r_org - 0.52));
      float core = 1.0 - smoothstep(0.0, 0.26, r_org);
      float outer_glow = (1.0 - smoothstep(0.48, 0.98, r)) * 0.56;

      final_rgb = mix(col, vec3(1.0, 0.97, 0.88), core * 0.72) + vec3(1.0) * (rim * 0.72 + radar_wave * 0.45) + col * (body * 0.6 + outer_glow * 0.88 + radar_wave * 0.75);
      alpha = clamp(body + rim * 0.90 + outer_glow * 0.68 + radar_wave * 0.72, 0.0, 1.0);
    }

    if (v_color.a < 0.2) {
      final_rgb *= (v_color.a * 2.5 + 0.08);
    }
    float spawn_alpha = clamp(v_spawn_progress * 1.6, 0.0, 1.0);
    fragColor = vec4(final_rgb, alpha * v_color.a * spawn_alpha);
  }
`;

export interface ShaderPipeline {
  program: WebGLProgram;
  vao: WebGLVertexArrayObject;
  quadVbo: WebGLBuffer;
  instanceVbo: WebGLBuffer;
  uniforms: {
    uRes: WebGLUniformLocation;
    uCam: WebGLUniformLocation;
    uZoom: WebGLUniformLocation;
    uTime: WebGLUniformLocation;
  };
}

export function initShaderPipeline(gl: WebGL2RenderingContext): ShaderPipeline {
  function compileShader(type: number, src: string): WebGLShader {
    const s = gl.createShader(type);
    if (!s) throw new Error('Failed to create shader');
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      const err = gl.getShaderInfoLog(s);
      gl.deleteShader(s);
      throw new Error(`Shader compile error: ${err}`);
    }
    return s;
  }

  const program = gl.createProgram();
  if (!program) throw new Error('Failed to create WebGL program');
  gl.attachShader(program, compileShader(gl.VERTEX_SHADER, vsSource));
  gl.attachShader(program, compileShader(gl.FRAGMENT_SHADER, fsSource));
  gl.linkProgram(program);

  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    const err = gl.getProgramInfoLog(program);
    throw new Error(`Program link error: ${err}`);
  }

  // Quad geometry (4 vertices)
  const quadVbo = gl.createBuffer();
  if (!quadVbo) throw new Error('Failed to create quadVbo');
  gl.bindBuffer(gl.ARRAY_BUFFER, quadVbo);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);

  // Instanced VBO
  const instanceVbo = gl.createBuffer();
  if (!instanceVbo) throw new Error('Failed to create instanceVbo');
  const vao = gl.createVertexArray();
  if (!vao) throw new Error('Failed to create VAO');
  gl.bindVertexArray(vao);

  gl.bindBuffer(gl.ARRAY_BUFFER, quadVbo);
  const aQuadPos = gl.getAttribLocation(program, 'a_quad_pos');
  gl.enableVertexAttribArray(aQuadPos);
  gl.vertexAttribPointer(aQuadPos, 2, gl.FLOAT, false, 0, 0);

  gl.bindBuffer(gl.ARRAY_BUFFER, instanceVbo);
  const stride = 9 * 4; // 9 floats per instance
  const aNodePos = gl.getAttribLocation(program, 'a_node_pos');
  gl.enableVertexAttribArray(aNodePos);
  gl.vertexAttribPointer(aNodePos, 2, gl.FLOAT, false, stride, 0);
  gl.vertexAttribDivisor(aNodePos, 1);

  const aRadius = gl.getAttribLocation(program, 'a_radius');
  gl.enableVertexAttribArray(aRadius);
  gl.vertexAttribPointer(aRadius, 1, gl.FLOAT, false, stride, 2 * 4);
  gl.vertexAttribDivisor(aRadius, 1);

  const aColor = gl.getAttribLocation(program, 'a_color');
  gl.enableVertexAttribArray(aColor);
  gl.vertexAttribPointer(aColor, 4, gl.FLOAT, false, stride, 3 * 4);
  gl.vertexAttribDivisor(aColor, 1);

  const aIsFile = gl.getAttribLocation(program, 'a_is_file');
  gl.enableVertexAttribArray(aIsFile);
  gl.vertexAttribPointer(aIsFile, 1, gl.FLOAT, false, stride, 7 * 4);
  gl.vertexAttribDivisor(aIsFile, 1);

  const aBirthTime = gl.getAttribLocation(program, 'a_birth_time');
  gl.enableVertexAttribArray(aBirthTime);
  gl.vertexAttribPointer(aBirthTime, 1, gl.FLOAT, false, stride, 8 * 4);
  gl.vertexAttribDivisor(aBirthTime, 1);

  gl.bindVertexArray(null);

  const uRes = gl.getUniformLocation(program, 'u_resolution')!;
  const uCam = gl.getUniformLocation(program, 'u_camera_pos')!;
  const uZoom = gl.getUniformLocation(program, 'u_zoom')!;
  const uTime = gl.getUniformLocation(program, 'u_time')!;

  return {
    program,
    vao,
    quadVbo,
    instanceVbo,
    uniforms: { uRes, uCam, uZoom, uTime },
  };
}

// =========================================================================
// COSMIC SPACE, ETHEREAL NEBULA & PARALLAX STELLAR STARFIELD BACKDROP
// =========================================================================

export const bgVsSource = `#version 300 es
  in vec2 a_pos;
  out vec2 v_uv;
  void main() {
    v_uv = a_pos * 0.5 + 0.5;
    gl_Position = vec4(a_pos, 0.0, 1.0);
  }
`;

export const bgFsSource = `#version 300 es
  precision highp float;
  in vec2 v_uv;
  uniform vec2 u_resolution;
  uniform vec2 u_camera_pos;
  uniform float u_zoom;
  uniform float u_time;
  out vec4 fragColor;

  float hash21(vec2 p) {
    p = fract(p * vec2(123.34, 456.21));
    p += dot(p, p + 45.32);
    return fract(p.x * p.y);
  }

  vec2 hash22(vec2 p) {
    vec3 p3 = fract(vec3(p.xyx) * vec3(0.1031, 0.1030, 0.0973));
    p3 += dot(p3, p3.yzx + 33.33);
    return fract((p3.xx + p3.yz) * p3.zy);
  }

  float noise2(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    float a = hash21(i);
    float b = hash21(i + vec2(1.0, 0.0));
    float c = hash21(i + vec2(0.0, 1.0));
    float d = hash21(i + vec2(1.0, 1.0));
    return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
  }

  float fbm(vec2 p) {
    float v = 0.0;
    float a = 0.5;
    mat2 rot = mat2(0.80, 0.60, -0.60, 0.80);
    for (int i = 0; i < 4; i++) {
      v += a * noise2(p);
      p = rot * p * 2.04 + vec2(11.3, 7.9);
      a *= 0.5;
    }
    return v;
  }

  // Delicate cosmic stardust & distant twinkling stars inside the nebula
  vec3 starLayer(vec2 uv, float scale, float density, float t, float flareThreshold) {
    vec2 gv = fract(uv * scale) - 0.5;
    vec2 id = floor(uv * scale);
    vec3 col = vec3(0.0);

    for (int y = -1; y <= 1; y++) {
      for (int x = -1; x <= 1; x++) {
        vec2 offs = vec2(float(x), float(y));
        vec2 cellId = id + offs;
        float h = hash21(cellId);
        if (h < density) continue;

        vec2 jitter = hash22(cellId) - 0.5;
        vec2 d = gv - offs - jitter * 0.82;
        float dist = length(d);

        float twinkle = 0.72 + 0.28 * sin(t * (0.7 + fract(h * 17.3) * 1.1) + h * 62.83);
        vec3 starTint = mix(
          vec3(0.75, 0.90, 1.0),
          mix(vec3(0.95, 0.82, 1.0), vec3(1.0, 0.92, 0.80), fract(h * 53.7)),
          fract(h * 29.1)
        );

        float mag = smoothstep(0.42, 0.015, dist * (3.2 + fract(h * 11.7) * 2.4));
        col += starTint * mag * mag * twinkle * 0.72;

        if (h > flareThreshold) {
          float rays = exp(-abs(d.x) * 38.0) * exp(-abs(d.y) * 6.5)
                     + exp(-abs(d.y) * 38.0) * exp(-abs(d.x) * 6.5);
          float coreGlow = exp(-dist * 12.0);
          col += starTint * (rays * 0.42 + coreGlow * 0.7) * twinkle;
        }
      }
    }
    return col;
  }

  void main() {
    float minDim = max(1.0, min(u_resolution.x, u_resolution.y));
    vec2 aspectUv = (gl_FragCoord.xy - 0.5 * u_resolution) / minDim;
    float t = u_time * 0.001;
    vec2 camShift = u_camera_pos * 0.00032;
    float zoomParallax = 1.0 + (u_zoom - 0.65) * 0.06;
    vec2 nebUv = aspectUv / clamp(zoomParallax, 0.78, 1.4) + camShift * 0.45;

    // Domain-warped cosmic nebula ("style nébuleuse")
    vec2 q = vec2(
      fbm(nebUv * 1.35 + vec2(t * 0.012, -t * 0.009)),
      fbm(nebUv * 1.35 + vec2(5.2 - t * 0.008, 1.3 + t * 0.011))
    );
    vec2 r = vec2(
      fbm(nebUv * 1.65 + 2.4 * q + vec2(1.7, 9.2) + t * 0.010),
      fbm(nebUv * 1.65 + 2.4 * q + vec2(8.3, 2.8) - t * 0.007)
    );
    float f = fbm(nebUv * 1.45 + 1.9 * r);
    float ridge = smoothstep(0.35, 0.85, fbm(nebUv * 2.5 - 1.4 * r + vec2(t * 0.006)));
    float dustLane = smoothstep(0.45, 0.82, fbm(nebUv * 3.1 + 1.1 * q));

    // Deep cosmic nebula palette (indigo -> teal/cyan -> violet/magenta wisps)
    vec3 cosmos = vec3(0.016, 0.020, 0.044);
    vec3 nebCyan = vec3(0.045, 0.19, 0.31);
    vec3 nebViolet = vec3(0.18, 0.065, 0.30);
    vec3 nebRose = vec3(0.24, 0.065, 0.19);

    cosmos += nebCyan * smoothstep(0.28, 0.82, f) * 0.58;
    cosmos += nebViolet * smoothstep(0.22, 0.86, length(q) * 0.72) * 0.52;
    cosmos += nebRose * pow(ridge, 1.8) * 0.42;
    cosmos *= (1.0 - dustLane * 0.38);

    // Soft distant stars veiled subtly behind/within the nebula clouds
    vec2 pUv = aspectUv / clamp(zoomParallax, 0.75, 1.5);
    vec3 stars = vec3(0.0);
    stars += starLayer(pUv + camShift * 0.30 + vec2(t * 0.0015, 0.0), 12.0, 0.76, t, 0.996) * 0.48;
    stars += starLayer(pUv + camShift * 0.65 + vec2(17.3, t * 0.001), 7.8, 0.83, t * 1.08, 0.988) * 0.72;

    fragColor = vec4(cosmos + stars, 1.0);
  }
`;

export interface BackdropPipeline {
  program: WebGLProgram;
  vao: WebGLVertexArrayObject;
  quadVbo: WebGLBuffer;
  uniforms: {
    uRes: WebGLUniformLocation;
    uCam: WebGLUniformLocation;
    uZoom: WebGLUniformLocation;
    uTime: WebGLUniformLocation;
  };
}

export function initBackdropPipeline(gl: WebGL2RenderingContext): BackdropPipeline {
  const compile = (type: number, src: string): WebGLShader => {
    const s = gl.createShader(type)!;
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      throw new Error(`Backdrop shader compile error: ${gl.getShaderInfoLog(s)}`);
    }
    return s;
  };
  const program = gl.createProgram()!;
  gl.attachShader(program, compile(gl.VERTEX_SHADER, bgVsSource));
  gl.attachShader(program, compile(gl.FRAGMENT_SHADER, bgFsSource));
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    throw new Error(`Backdrop program link error: ${gl.getProgramInfoLog(program)}`);
  }

  const quadVbo = gl.createBuffer()!;
  gl.bindBuffer(gl.ARRAY_BUFFER, quadVbo);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);

  const vao = gl.createVertexArray()!;
  gl.bindVertexArray(vao);
  const aPos = gl.getAttribLocation(program, 'a_pos');
  gl.enableVertexAttribArray(aPos);
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);
  gl.bindVertexArray(null);

  return {
    program,
    vao,
    quadVbo,
    uniforms: {
      uRes: gl.getUniformLocation(program, 'u_resolution')!,
      uCam: gl.getUniformLocation(program, 'u_camera_pos')!,
      uZoom: gl.getUniformLocation(program, 'u_zoom')!,
      uTime: gl.getUniformLocation(program, 'u_time')!,
    },
  };
}
