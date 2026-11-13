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
    float actual_r = a_radius * scale * 2.8 * zoom_factor;

    float buoy_x = sin(u_time * 0.0016 + a_node_pos.x * 0.012 + a_birth_time * 0.001) * 3.5;
    float buoy_y = cos(u_time * 0.0012 + a_node_pos.y * 0.012 + a_birth_time * 0.001) * 4.2;
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
    vec3 col = v_color.rgb;
    vec3 final_rgb = col;
    float alpha = 1.0;

    if (v_is_file < 0.5) {
      // MINI POINT POUR FONCTION : Étincelle stellaire avec croix de diffraction
      float twinkle = 0.90 + 0.10 * sin(v_time * 0.0045 + v_phase);
      float core = 1.0 - smoothstep(0.0, 0.30, r);
      float halo = (1.0 - smoothstep(0.15, 0.96, r)) * twinkle;
      float spike_x = exp(-abs(v_uv.y) * 18.0) * exp(-abs(v_uv.x) * 3.5);
      float spike_y = exp(-abs(v_uv.x) * 18.0) * exp(-abs(v_uv.y) * 3.5);
      float diffraction = (spike_x + spike_y) * 0.42 * twinkle;
      final_rgb = mix(col * 1.40, vec3(1.0, 1.0, 1.0), clamp(core + diffraction * 0.6, 0.0, 1.0)) + col * (halo * 0.60 + diffraction);
      alpha = clamp(core * 0.98 + halo * 0.85 + diffraction * 0.75, 0.0, 1.0);
    } else if (v_is_file < 1.5) {
      // PLANÈTE FICHIER : Orbe 3D Fresnel avec anneau orbital à onde de plasma
      float body = 1.0 - smoothstep(0.44, 0.56, r);
      float z_sphere = sqrt(max(0.0, 1.0 - min(1.0, (r / 0.54) * (r / 0.54))));
      float fresnel = pow(1.0 - z_sphere, 2.2) * body;
      float rim = 1.0 - smoothstep(0.0, 0.08, abs(r - 0.52));
      float core = 1.0 - smoothstep(0.0, 0.24, r);
      float outer_glow = (1.0 - smoothstep(0.50, 0.97, r)) * 0.48;
      float ring_wave = 0.78 + 0.22 * sin(angle * 4.0 - v_time * 0.0035 + v_phase);
      float ring = (1.0 - smoothstep(0.0, 0.055, abs(r - 0.78))) * 0.92 * ring_wave;

      final_rgb = mix(col * 0.95, vec3(1.0), core * 0.72 + fresnel * 0.35);
      final_rgb += vec3(1.0) * rim * 0.95 + col * (rim * 0.75 + fresnel * 0.55);
      final_rgb += col * outer_glow * 0.88;
      final_rgb += mix(col, vec3(0.92, 0.97, 1.0), 0.70) * ring;
      alpha = clamp(body * 0.96 + rim * 0.92 + outer_glow * 0.62 + ring, 0.0, 1.0);
    } else if (v_is_file < 2.5) {
      // CLASSE : Cristal céleste hexagonal rotatif
      float hex_facet = 0.82 + 0.18 * cos(angle * 6.0 + v_time * 0.0022 + v_phase);
      float body = 1.0 - smoothstep(0.48, 0.58, r);
      float rim = (1.0 - smoothstep(0.0, 0.07, abs(r - 0.52))) * hex_facet;
      float inner_halo = 1.0 - smoothstep(0.0, 0.06, abs(r - 0.32));
      float core = 1.0 - smoothstep(0.0, 0.19, r);
      float outer_glow = (1.0 - smoothstep(0.52, 0.96, r)) * 0.52 * hex_facet;

      final_rgb = mix(col, vec3(1.0), core * 0.82);
      final_rgb += vec3(1.0) * rim * 0.95 + col * inner_halo * 0.85;
      final_rgb += col * outer_glow * 0.85;
      alpha = clamp(body * 0.95 + rim + inner_halo * 0.75 + outer_glow * 0.55, 0.0, 1.0);
    } else {
      // FORM / ENDPOINT : Pulsar énergétique avec onde de choc radar
      float pulse_r = mix(0.50, 0.94, fract(v_time * 0.00075 + v_phase * 0.159));
      float radar_wave = (1.0 - smoothstep(0.0, 0.06, abs(r - pulse_r))) * (1.0 - (pulse_r - 0.50) / 0.44);
      float body = 1.0 - smoothstep(0.46, 0.56, r);
      float rim = 1.0 - smoothstep(0.0, 0.09, abs(r - 0.50));
      float core = 1.0 - smoothstep(0.0, 0.26, r);
      float outer_glow = (1.0 - smoothstep(0.50, 0.98, r)) * 0.62;

      final_rgb = mix(col, vec3(1.0, 0.96, 0.84), core * 0.78);
      final_rgb += vec3(1.0) * (rim * 0.95 + radar_wave * 0.65) + col * (outer_glow * 0.92 + radar_wave * 0.85);
      alpha = clamp(body * 0.96 + rim * 0.92 + outer_glow * 0.72 + radar_wave * 0.80, 0.0, 1.0);
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
    uniforms: { uRes, uCam, uZoom, uTime }
  };
}
