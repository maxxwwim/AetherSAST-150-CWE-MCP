/**
 * AetherCraft — Visualisation voxel interactive (île céleste qui se décompose)
 *
 *  - rendu 2D canvas, projection orthographique, faces texturées (textures pixel-art procédurales)
 *  - rotation pilotée par la souris + rotation lente automatique
 *  - la souris repousse les blocs proches (décomposition locale) et survole = nom du bloc
 *  - le scroll décompose l'île bloc par bloc ; bouton « Décomposer / Assembler »
 */
(function () {
  "use strict";

  const canvas = document.getElementById("voxel-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const hero = canvas.parentElement;
  const hudBlock = document.getElementById("voxel-hud-block");
  const hudPct = document.getElementById("voxel-hud-pct");
  const hudCount = document.getElementById("voxel-hud-count");
  const toggleBtn = document.getElementById("voxel-toggle");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- RNG déterministe ---------- */
  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const rng = mulberry32(20240621);

  /* ---------- Textures pixel-art procédurales (16x16) ---------- */
  const T = 16;
  const tiles = {};
  function tile(name, painter) {
    const c = document.createElement("canvas");
    c.width = c.height = T;
    const g = c.getContext("2d");
    const r = mulberry32(name.length * 7919 + name.charCodeAt(0) * 31);
    painter(g, r);
    tiles[name] = c;
  }
  function px(g, x, y, col) { g.fillStyle = col; g.fillRect(x, y, 1, 1); }
  function noise(g, r, base, v) {
    for (let y = 0; y < T; y++) for (let x = 0; x < T; x++) {
      const d = (r() - 0.5) * 2 * v;
      px(g, x, y, `rgb(${clamp(base[0] + d)},${clamp(base[1] + d)},${clamp(base[2] + d)})`);
    }
  }
  function clamp(n) { return Math.max(0, Math.min(255, n | 0)); }

  tile("grass_top", (g, r) => {
    noise(g, r, [92, 165, 52], 24);
    for (let i = 0; i < 22; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(140,205,80)");
    for (let i = 0; i < 10; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(52,110,36)");
  });
  tile("dirt", (g, r) => {
    noise(g, r, [134, 96, 67], 16);
    for (let i = 0; i < 16; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(96,66,44)");
    for (let i = 0; i < 6; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(168,128,96)");
  });
  tile("grass_side", (g, r) => {
    noise(g, r, [134, 96, 67], 16);
    for (let i = 0; i < 12; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(96,66,44)");
    for (let x = 0; x < T; x++) {
      const h = 3 + ((r() * 3) | 0);
      for (let y = 0; y < h; y++) {
        const d = (r() - 0.5) * 36;
        px(g, x, y, `rgb(${clamp(92 + d)},${clamp(165 + d)},${clamp(52 + d)})`);
      }
    }
  });
  tile("stone", (g, r) => {
    noise(g, r, [126, 126, 134], 18);
    for (let i = 0; i < 5; i++) {
      let x = (r() * T) | 0, y = (r() * T) | 0;
      for (let k = 0; k < 4; k++) { px(g, x, y, "rgb(82,82,92)"); x = (x + (r() > 0.5 ? 1 : 0)) % T; y = (y + (r() > 0.5 ? 1 : 0)) % T; }
    }
    for (let i = 0; i < 8; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(160,160,168)");
  });
  tile("amethyst", (g, r) => {
    noise(g, r, [128, 70, 196], 34);
    for (let i = 0; i < 14; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(224,190,255)");
    for (let i = 0; i < 8; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(78,36,130)");
  });
  tile("crystal", (g, r) => {
    noise(g, r, [36, 190, 214], 30);
    for (let i = 0; i < 18; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(210,255,255)");
    for (let i = 0; i < 6; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(16,110,150)");
  });
  tile("obsidian", (g, r) => {
    noise(g, r, [28, 18, 48], 10);
    for (let i = 0; i < 14; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(70,40,120)");
    for (let i = 0; i < 4; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(120,80,200)");
  });
  tile("rune", (g, r) => {
    noise(g, r, [34, 28, 62], 8);
    g.fillStyle = "rgb(60,230,240)";
    const glyph = [[5, 3, 1, 10], [5, 3, 5, 1], [10, 3, 1, 5], [5, 8, 6, 1], [8, 9, 1, 4]];
    glyph.forEach((s) => g.fillRect(s[0], s[1], s[2], s[3]));
    px(g, 3, 13, "rgb(150,255,255)"); px(g, 12, 2, "rgb(150,255,255)");
  });
  tile("log_side", (g, r) => {
    for (let x = 0; x < T; x++) {
      const stripe = (x % 4 === 0 ? -18 : 0) + (r() - 0.5) * 14;
      for (let y = 0; y < T; y++) px(g, x, y, `rgb(${clamp(104 + stripe)},${clamp(74 + stripe)},${clamp(42 + stripe)})`);
    }
  });
  tile("log_top", (g, r) => {
    noise(g, r, [176, 140, 84], 10);
    g.strokeStyle = "rgb(112,80,44)"; g.lineWidth = 1;
    g.strokeRect(2.5, 2.5, 11, 11); g.strokeRect(5.5, 5.5, 5, 5);
  });
  tile("leaves", (g, r) => {
    noise(g, r, [48, 124, 44], 36);
    for (let i = 0; i < 18; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(24,70,28)");
    for (let i = 0; i < 12; i++) px(g, (r() * T) | 0, (r() * T) | 0, "rgb(110,190,70)");
  });

  /* ---------- Définition des blocs ---------- */
  const TYPES = {
    grass: { name: "Bloc d'herbe", top: "grass_top", bottom: "dirt", side: "grass_side", glow: 0 },
    dirt: { name: "Terre", all: "dirt", glow: 0 },
    stone: { name: "Pierre céleste", all: "stone", glow: 0 },
    amethyst: { name: "Améthyste", all: "amethyst", glow: 0.45 },
    crystal: { name: "Cristal d'Aether", all: "crystal", glow: 0.8 },
    obsidian: { name: "Obsidienne runique", all: "obsidian", glow: 0 },
    rune: { name: "Pierre de rune", all: "rune", glow: 0.7 },
    log: { name: "Tronc de chêne", top: "log_top", bottom: "log_top", side: "log_side", glow: 0 },
    leaves: { name: "Feuillage", all: "leaves", glow: 0 },
    portal: { name: "Portail d'Aether", portal: true, glow: 1 },
  };

  const world = new Map();
  const key = (x, y, z) => x + "," + y + "," + z;
  const put = (x, y, z, type, extra) => world.set(key(x, y, z), Object.assign({ x, y, z, type }, extra || {}));

  // Île flottante en cône inversé
  const R = 6.3;
  for (let x = -7; x <= 7; x++) for (let z = -7; z <= 7; z++) {
    const d = Math.hypot(x, z);
    if (d > R) continue;
    if (d > 5 && rng() < 0.28) continue; // bord irrégulier
    const depth = Math.floor((R - d) * 0.95) + 1 + (rng() < 0.3 ? 1 : 0);
    for (let y = 0; y > -depth; y--) {
      let type = "stone";
      if (y === 0) type = "grass";
      else if (y >= -2) type = "dirt";
      else {
        const q = rng();
        if (q < 0.05) type = "amethyst";
        else if (q < 0.085) type = "crystal";
      }
      put(x, y, z, type);
    }
  }
  // Arbres
  function tree(tx, tz, h, r) {
    for (let y = 1; y <= h; y++) put(tx, y, tz, "log");
    for (let dx = -r; dx <= r; dx++) for (let dy = -1; dy <= r; dy++) for (let dz = -r; dz <= r; dz++) {
      if (Math.hypot(dx, dy * 1.2, dz) > r + 0.3) continue;
      const k = key(tx + dx, h + dy, tz + dz);
      if (!world.has(k) && rng() > 0.1) put(tx + dx, h + dy, tz + dz, "leaves");
    }
  }
  tree(-3, -2, 4, 2);
  tree(3, 3, 3, 1);
  // Cristaux sur l'île
  [[4, 1, -1, "amethyst"], [4, 2, -1, "amethyst"], [3, 1, -2, "amethyst"], [2, 1, 4, "crystal"], [-4, 1, 3, "crystal"], [-5, 1, 0, "amethyst"]]
    .forEach((c) => { if (world.has(key(c[0], 0, c[2]))) put(c[0], c[1], c[2], c[3]); });
  // Portail
  for (let y = 1; y <= 4; y++) {
    put(-1, y, 0, y === 2 || y === 3 ? "rune" : "obsidian");
    put(1, y, 0, y === 2 || y === 3 ? "rune" : "obsidian");
  }
  put(0, 4, 0, "obsidian");
  for (let y = 1; y <= 3; y++) put(0, y, 0, "portal");

  // Blocs orbitaux (runes)
  const blocks = [];
  world.forEach((b) => blocks.push(b));
  for (let i = 0; i < 7; i++) {
    blocks.push({ x: 0, y: 0, z: 0, type: "rune", scale: 0.5, orbit: { a: (i / 7) * Math.PI * 2, r: 4.6 + (i % 2) * 0.8, h: 2.5 + (i % 3) * 0.9, s: 0.5 + (i % 3) * 0.08 } });
  }

  // Pré-calculs : visibilité des faces, direction d'éjection, aléas
  const DIRS = [[0, 1, 0], [0, -1, 0], [1, 0, 0], [-1, 0, 0], [0, 0, 1], [0, 0, -1]];
  const CY = -0.5; // centre vertical de l'île
  blocks.forEach((b) => {
    b.scale = b.scale || 1;
    b.rnd = rng();
    b.rnd2 = rng();
    b.hv = 0;
    b.exposed = DIRS.map((d) => {
      if (b.orbit) return true;
      const n = world.get(key(b.x + d[0], b.y + d[1], b.z + d[2]));
      return !n || n.type === "portal" || (b.type === "portal" && n.type !== "portal");
    });
    let dx = b.x, dy = b.y - 1.5, dz = b.z;
    const l = Math.hypot(dx, dy, dz) || 1;
    b.dir = [dx / l, dy / l, dz / l];
  });
  if (hudCount) hudCount.textContent = blocks.length.toString();

  /* ---------- Géométrie des faces (origine, u, v) ---------- */
  const FACES = [
    { o: [-0.5, 0.5, -0.5], u: [1, 0, 0], v: [0, 0, 1], n: [0, 1, 0], kind: "top" },
    { o: [-0.5, -0.5, -0.5], u: [1, 0, 0], v: [0, 0, 1], n: [0, -1, 0], kind: "bottom" },
    { o: [0.5, 0.5, -0.5], u: [0, 0, 1], v: [0, -1, 0], n: [1, 0, 0], kind: "side" },
    { o: [-0.5, 0.5, 0.5], u: [0, 0, -1], v: [0, -1, 0], n: [-1, 0, 0], kind: "side" },
    { o: [0.5, 0.5, 0.5], u: [-1, 0, 0], v: [0, -1, 0], n: [0, 0, 1], kind: "side" },
    { o: [-0.5, 0.5, -0.5], u: [1, 0, 0], v: [0, -1, 0], n: [0, 0, -1], kind: "side" },
  ];
  const EPS = 0.012;

  /* ---------- État ---------- */
  let W = 0, H = 0, S = 20, dpr = 1;
  let yaw = 0.6, pitch = 0.5, targetYaw = 0.6, targetPitch = 0.5;
  let mouse = { x: -9999, y: -9999, active: false, nx: 0.5, ny: 0.5 };
  let explode = 0, held = false, visible = true, hovered = null;
  const LIGHT = (() => { const l = [-0.35, 0.85, 0.55]; const m = Math.hypot(l[0], l[1], l[2]); return [l[0] / m, l[1] / m, l[2] / m]; })();

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = canvas.getBoundingClientRect();
    W = r.width; H = r.height;
    canvas.width = Math.max(1, Math.round(W * dpr));
    canvas.height = Math.max(1, Math.round(H * dpr));
    S = Math.min(W / 17, H / 15);
  }
  window.addEventListener("resize", resize);
  resize();

  window.addEventListener("mousemove", (e) => {
    const r = canvas.getBoundingClientRect();
    mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top;
    mouse.active = mouse.x > 0 && mouse.x < r.width && mouse.y > 0 && mouse.y < r.height;
    mouse.nx = e.clientX / window.innerWidth; mouse.ny = e.clientY / window.innerHeight;
  });
  window.addEventListener("mouseleave", () => { mouse.active = false; });
  window.addEventListener("touchmove", (e) => {
    const t = e.touches[0]; if (!t) return;
    const r = canvas.getBoundingClientRect();
    mouse.x = t.clientX - r.left; mouse.y = t.clientY - r.top; mouse.active = true;
    mouse.nx = t.clientX / window.innerWidth; mouse.ny = t.clientY / window.innerHeight;
  }, { passive: true });
  window.addEventListener("touchend", () => { mouse.active = false; });

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      held = !held;
      toggleBtn.querySelector("span:last-child").textContent = held ? "ASSEMBLER" : "DÉCOMPOSER";
      if (window.AudioSys && AudioSys.playClick) AudioSys.playClick();
    });
  }
  if ("IntersectionObserver" in window) {
    new IntersectionObserver((en) => { const was = visible; visible = en[0].isIntersecting; if (visible && !was) { last = performance.now(); requestAnimationFrame(frame); } }, { threshold: 0 }).observe(hero);
  }

  /* ---------- Rendu ---------- */
  var last = performance.now();

  function frame(now) {
    if (!visible) return;
    const dt = Math.min(0.05, (now - last) / 1000); last = now;
    const t = now / 1000;

    // Cibles de rotation
    const auto = reduceMotion ? 0 : t * 0.18;
    targetYaw = 0.6 + auto + (mouse.nx - 0.5) * 1.1;
    targetPitch = 0.5 + (mouse.ny - 0.5) * 0.28;
    yaw += (targetYaw - yaw) * Math.min(1, dt * 3);
    pitch += (targetPitch - pitch) * Math.min(1, dt * 3);

    // Décomposition (scroll + bouton)
    const sy = window.scrollY || 0;
    const scrollE = Math.min(1, Math.max(0, sy / (hero.offsetHeight * 0.85)));
    const target = Math.max(scrollE, held ? 1 : 0);
    explode += (target - explode) * Math.min(1, dt * 3.2);
    if (hudPct) hudPct.textContent = Math.round(explode * 100) + "%";

    const cyaw = Math.cos(yaw), syaw = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
    const cx = W * 0.5, cy = H * 0.52;
    const bob = reduceMotion ? 0 : Math.sin(t * 0.9) * 0.22;

    // Projection d'un point monde → vue
    function view(x, y, z) {
      y = y - CY + bob;
      const x1 = x * cyaw + z * syaw, z1 = -x * syaw + z * cyaw;
      const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
      return [cx + x1 * S, cy - y2 * S, z2];
    }
    function viewN(n) {
      const x1 = n[0] * cyaw + n[2] * syaw, z1 = -n[0] * syaw + n[2] * cyaw;
      return [x1, n[1] * cp - z1 * sp, n[1] * sp + z1 * cp];
    }

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    // Halo derrière l'île
    const halo = ctx.createRadialGradient(cx, cy, 0, cx, cy, S * 9);
    halo.addColorStop(0, `rgba(34,211,238,${0.2 + explode * 0.12})`);
    halo.addColorStop(0.5, "rgba(139,92,246,0.10)");
    halo.addColorStop(1, "rgba(6,7,11,0)");
    ctx.fillStyle = halo; ctx.fillRect(0, 0, W, H);

    const faces = [];
    let best = null, bestScore = -1e9;
    const hoverR = S * 2.6;

    for (let i = 0; i < blocks.length; i++) {
      const b = blocks[i];
      let bx = b.x, by = b.y, bz = b.z;
      if (b.orbit) {
        const o = b.orbit, a = o.a + t * o.s;
        bx = Math.cos(a) * o.r; bz = Math.sin(a) * o.r; by = o.h + Math.sin(t * 1.3 + o.a) * 0.4;
      }
      // projection de base (pour l'interaction souris)
      const p0 = view(bx, by, bz);
      let target = 0;
      if (mouse.active) {
        const d = Math.hypot(p0[0] - mouse.x, p0[1] - mouse.y);
        if (d < hoverR) target = Math.pow(1 - d / hoverR, 1.6);
        if (d < S * 0.75 && p0[2] > bestScore) { bestScore = p0[2]; best = b; }
      }
      b.hv += (target - b.hv) * Math.min(1, dt * 8);

      const push = explode * (2 + b.rnd * 5.5) + b.hv * 1.8;
      const wob = explode > 0.02 && !reduceMotion ? Math.sin(t * 1.4 + b.rnd * 20) * 0.18 * explode : 0;
      const ex = bx + b.dir[0] * push, ey = by + b.dir[1] * push - explode * explode * b.rnd2 * 1.6 + wob, ez = bz + b.dir[2] * push;
      const spin = (b.rnd2 - 0.5) * 5 * explode + b.hv * (b.rnd - 0.5) * 2;
      const cs = Math.cos(spin), ss = Math.sin(spin);
      const sc = b.scale * (1 - explode * 0.12);
      const tp = TYPES[b.type];

      for (let f = 0; f < 6; f++) {
        if (explode < 0.015 && b.hv < 0.02 && !b.exposed[f]) continue;
        const F = FACES[f];
        // normale (rotation locale Y puis vue)
        const nl = [F.n[0] * cs + F.n[2] * ss, F.n[1], -F.n[0] * ss + F.n[2] * cs];
        const nv = viewN(nl);
        if (nv[2] <= 0.001) continue;

        const corner = (a, c) => {
          const lx = (F.o[0] + F.u[0] * a + F.v[0] * c) * sc, ly = (F.o[1] + F.u[1] * a + F.v[1] * c) * sc, lz = (F.o[2] + F.u[2] * a + F.v[2] * c) * sc;
          return view(ex + lx * cs + lz * ss, ey + ly, ez - lx * ss + lz * cs);
        };
        const P0 = corner(-EPS, -EPS), P1 = corner(1 + EPS, -EPS), P2 = corner(-EPS, 1 + EPS), P3 = corner(1 + EPS, 1 + EPS);
        const depth = (P0[2] + P3[2]) * 0.5;

        let tex = null;
        if (!tp.portal) tex = tp.all || (F.kind === "top" ? tp.top : F.kind === "bottom" ? tp.bottom : tp.side);
        const lit = Math.max(0, nv[0] * LIGHT[0] + nv[1] * LIGHT[1] + nv[2] * LIGHT[2]);
        faces.push({ tex, P0, P1, P2, P3, depth, lit, glow: tp.glow, portal: !!tp.portal, hv: b.hv, b });
      }
    }

    faces.sort((a, b) => a.depth - b.depth);

    for (let i = 0; i < faces.length; i++) {
      const f = faces[i];
      const [P0, P1, P2, P3] = [f.P0, f.P1, f.P2, f.P3];
      if (f.portal) {
        const hue = 180 + Math.sin(t * 1.6 + f.depth) * 40;
        const g = ctx.createLinearGradient(P0[0], P0[1], P3[0], P3[1]);
        g.addColorStop(0, `hsla(${hue},95%,60%,0.85)`);
        g.addColorStop(1, `hsla(${hue + 90},90%,55%,0.85)`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.moveTo(P0[0], P0[1]); ctx.lineTo(P1[0], P1[1]); ctx.lineTo(P3[0], P3[1]); ctx.lineTo(P2[0], P2[1]); ctx.closePath(); ctx.fill();
        continue;
      }
      ctx.setTransform(((P1[0] - P0[0]) / T) * dpr, ((P1[1] - P0[1]) / T) * dpr, ((P2[0] - P0[0]) / T) * dpr, ((P2[1] - P0[1]) / T) * dpr, P0[0] * dpr, P0[1] * dpr);
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(tiles[f.tex], 0, 0);
      const dark = (1 - (0.5 + 0.5 * f.lit)) * (1 - f.glow * 0.65);
      if (dark > 0.01) { ctx.fillStyle = `rgba(4,3,18,${dark.toFixed(3)})`; ctx.fillRect(0, 0, T, T); }
      if (f.hv > 0.05) { ctx.fillStyle = `rgba(190,255,255,${(f.hv * 0.16).toFixed(3)})`; ctx.fillRect(0, 0, T, T); }
      if (f.b === best) { ctx.strokeStyle = "rgba(255,255,255,0.9)"; ctx.lineWidth = 0.7; ctx.strokeRect(0.35, 0.35, T - 0.7, T - 0.7); }
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // Étincelles flottantes lors de la décomposition
    if (explode > 0.05 && !reduceMotion) {
      ctx.globalCompositeOperation = "lighter";
      for (let i = 0; i < 26; i++) {
        const a = i * 2.399 + t * 0.4, rr = S * (3 + (i % 7) * 1.1) * (0.4 + explode);
        const x = cx + Math.cos(a) * rr, y = cy + Math.sin(a * 1.3) * rr * 0.6 - ((t * 20 + i * 13) % 60);
        ctx.fillStyle = i % 2 ? `rgba(34,211,238,${0.5 * explode})` : `rgba(168,85,247,${0.5 * explode})`;
        ctx.fillRect(x, y, 2, 2);
      }
      ctx.globalCompositeOperation = "source-over";
    }

    hovered = best;
    if (hudBlock) {
      hudBlock.textContent = hovered ? TYPES[hovered.type].name + (hovered.orbit ? "" : "  [" + hovered.x + ", " + hovered.y + ", " + hovered.z + "]") : "Survolez un bloc";
    }

    // Fondu quand on quitte le hero
    canvas.style.opacity = String(Math.max(0, 1 - Math.max(0, sy - hero.offsetHeight * 0.45) / (hero.offsetHeight * 0.5)));
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
