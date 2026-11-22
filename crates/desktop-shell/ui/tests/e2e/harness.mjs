import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Canonical path resolution avoids Windows drive-letter ESM cache splits
export const UI_ROOT = path.resolve(__dirname, '../..');
export const REPO_ROOT = path.resolve(UI_ROOT, '../../..');

const requireFromUi = createRequire(path.join(UI_ROOT, 'package.json'));
const svelteCompiler = requireFromUi('svelte/compiler');

export class MockLocalStorage {
  constructor() {
    this.store = new Map();
  }
  getItem(key) {
    return this.store.has(key) ? this.store.get(key) : null;
  }
  setItem(key, value) {
    this.store.set(key, String(value));
  }
  removeItem(key) {
    this.store.delete(key);
  }
  clear() {
    this.store.clear();
  }
}

let stubsInstalled = false;
let rafCounter = 1;
export const pendingRafCallbacks = new Map();

export function installBrowserStubs() {
  if (stubsInstalled) return;
  stubsInstalled = true;

  const mockStorage = new MockLocalStorage();
  Object.defineProperty(globalThis, 'localStorage', {
    value: mockStorage,
    configurable: true,
    writable: true,
  });

  if (typeof globalThis.window === 'undefined') {
    Object.defineProperty(globalThis, 'window', {
      value: {
        innerWidth: 1440,
        innerHeight: 900,
        devicePixelRatio: 1,
        location: { href: 'http://127.0.0.1/' },
        addEventListener: () => {},
        removeEventListener: () => {},
        matchMedia: () => ({
          matches: false,
          addEventListener: () => {},
          removeEventListener: () => {},
        }),
      },
      configurable: true,
      writable: true,
    });
  }

  if (typeof globalThis.requestAnimationFrame === 'undefined') {
    Object.defineProperty(globalThis, 'requestAnimationFrame', {
      value: (cb) => {
        const id = rafCounter++;
        pendingRafCallbacks.set(id, cb);
        return id;
      },
      configurable: true,
      writable: true,
    });
  }

  if (typeof globalThis.cancelAnimationFrame === 'undefined') {
    Object.defineProperty(globalThis, 'cancelAnimationFrame', {
      value: (id) => {
        pendingRafCallbacks.delete(id);
      },
      configurable: true,
      writable: true,
    });
  }

  if (typeof globalThis.ResizeObserver === 'undefined') {
    Object.defineProperty(globalThis, 'ResizeObserver', {
      value: class MockResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
      configurable: true,
      writable: true,
    });
  }
}

export function flushNextRaf(now = performance.now()) {
  const first = pendingRafCallbacks.entries().next();
  if (first.done) return false;
  const [id, cb] = first.value;
  pendingRafCallbacks.delete(id);
  cb(now);
  return true;
}

export function setMockClipboard(impl) {
  const prevDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const baseNav = globalThis.navigator && typeof globalThis.navigator === 'object' ? globalThis.navigator : {};
  const wrappedNav = Object.create(baseNav);
  Object.defineProperty(wrappedNav, 'clipboard', {
    value: impl,
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, 'navigator', {
    value: wrappedNav,
    configurable: true,
    writable: true,
  });
  return () => {
    if (prevDescriptor) {
      Object.defineProperty(globalThis, 'navigator', prevDescriptor);
    }
  };
}

function createLucideStubPlugin(uiRoot) {
  const virtualId = '\0virtual:lucide-stub';
  let stubModuleCode = null;

  function buildStubCode() {
    if (stubModuleCode) return stubModuleCode;
    const distDir = path.join(uiRoot, 'node_modules/@lucide/svelte/dist');
    const files = [
      path.join(distDir, 'icons/index.js'),
      path.join(distDir, 'aliases/aliases.js'),
      path.join(distDir, 'aliases/prefixed.js'),
      path.join(distDir, 'aliases/suffixed.js'),
    ];
    const exportNames = new Set(['Icon', 'createLucideIcon', 'defaultAttributes']);
    const exportRegex = /export\s*\{([^}]+)\}/g;

    for (const file of files) {
      if (!fs.existsSync(file)) continue;
      const raw = fs
        .readFileSync(file, 'utf-8')
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/\/\/[^\n]*/g, ' ');
      let m;
      while ((m = exportRegex.exec(raw)) !== null) {
        const items = m[1].split(',');
        for (const item of items) {
          const asMatch = item.trim().match(/^(?:[A-Za-z_$][A-Za-z0-9_$]*\s+as\s+)?([A-Za-z_$][A-Za-z0-9_$]*)$/);
          if (asMatch) {
            const exported = asMatch[1];
            if (exported && exported !== 'default') {
              exportNames.add(exported);
            }
          }
        }
      }
    }

    const lines = [
      'const StubIcon = () => {};',
      'export default StubIcon;',
      'export const icons = new Proxy({}, { get: () => StubIcon });',
    ];
    for (const name of exportNames) {
      if (name !== 'icons' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) {
        lines.push(`export const ${name} = StubIcon;`);
      }
    }
    stubModuleCode = lines.join('\n');
    return stubModuleCode;
  }

  return {
    name: 'stub-lucide',
    enforce: 'pre',
    resolveId(source) {
      if (source === '@lucide/svelte' || source.startsWith('@lucide/svelte/')) {
        return virtualId;
      }
      return null;
    },
    load(id) {
      if (id === virtualId) {
        return buildStubCode();
      }
      return null;
    },
  };
}

let sharedServerPromise = null;
let sharedRenderFn = null;

export async function getViteServer() {
  installBrowserStubs();
  if (!sharedServerPromise) {
    sharedServerPromise = (async () => {
      const { createServer } = await import('vite');
      const { svelte } = await import('@sveltejs/vite-plugin-svelte');
      const server = await createServer({
        root: UI_ROOT,
        configFile: false,
        appType: 'custom',
        logLevel: 'silent',
        server: {
          middlewareMode: true,
          hmr: false,
          ws: false,
          watch: null,
        },
        optimizeDeps: {
          noDiscovery: true,
        },
        ssr: {
          external: ['svelte', 'svelte/internal/server'],
        },
        plugins: [
          createLucideStubPlugin(UI_ROOT),
          svelte({
            prebundleSvelteLibraries: false,
            compilerOptions: { dev: false },
          }),
        ],
      });
      return server;
    })();
  }
  return sharedServerPromise;
}

export async function closeViteServer() {
  if (!sharedServerPromise) return;
  const server = await sharedServerPromise;
  sharedServerPromise = null;
  sharedRenderFn = null;
  await server.close();
}

export async function ssrLoad(modulePath) {
  const server = await getViteServer();
  return server.ssrLoadModule(modulePath);
}

export async function getSvelteRender() {
  if (!sharedRenderFn) {
    const mod = await ssrLoad('svelte/server');
    sharedRenderFn = mod.render;
  }
  return sharedRenderFn;
}

export async function renderComponent(componentPath, props = {}) {
  const render = await getSvelteRender();
  const mod = await ssrLoad(componentPath);
  return render(mod.default, { props });
}

export async function getCockpitState() {
  const mod = await ssrLoad('/src/state/graphState.svelte.ts');
  return mod.cockpitState;
}

export async function getApiClient() {
  const mod = await ssrLoad('/src/lib/api.ts');
  return mod.api;
}

export function resetCockpitState(cockpitState) {
  if (typeof globalThis.localStorage !== 'undefined') {
    globalThis.localStorage.clear();
  }
  cockpitState.engine = null;
  cockpitState.viewMode = 'code';
  cockpitState.lastGraphMode = 'code';
  cockpitState.visionMode = 'standard';
  cockpitState.lodLevel = 1;
  cockpitState.activeLayout = 'Z-2';
  cockpitState.showRadar = true;
  cockpitState.isInspectorOpen = false;
  cockpitState.isDocPanelOpen = false;
  cockpitState.isPromptModalOpen = false;
  cockpitState.isCreateFileModalOpen = false;
  cockpitState.pendingImportFile = null;
  if ('pendingCreateFolder' in cockpitState) {
    cockpitState.pendingCreateFolder = null;
  }
  cockpitState.ideActiveFile = null;
  cockpitState.ideOpenFiles = [];
  cockpitState.ideTargetLine = null;
  cockpitState.ideCursorPosition = null;
  cockpitState.ideTargetTick = 0;
  cockpitState.ideZenMode = false;
  cockpitState.activeSymbol = null;
  cockpitState.hoveredSymbol = null;
  cockpitState.selectedFolder = null;
  cockpitState.activeAgents = [];
  cockpitState.agentTrails = {};
  cockpitState.gitStatus = null;
  cockpitState.folderEdits = {};
  cockpitState.disabledLayers = {};
  cockpitState.disabledRelations = {};
  cockpitState.disabledModules = {};
  cockpitState.searchQuery = '';
  cockpitState.focusTargetId = null;
  cockpitState.settings.ignoredCwes = [];
  cockpitState.settings.showAlerts = true;
  cockpitState.settings.showCweBubbles = true;
  cockpitState.settings.editorAutoSave = false;
  cockpitState.setGraph({ project_path: '/workspace', nodes: [], edges: [], clusters: {} }, false);
}

/**
 * Starts an ephemeral 127.0.0.1:0 HTTP server and temporarily rewrites
 * relative `/api/...` fetch calls to route over real TCP loopback.
 */
export async function withMockHttpServer(handler, fn) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks).toString('utf-8');
    let jsonBody = null;
    if (rawBody) {
      try {
        jsonBody = JSON.parse(rawBody);
      } catch {
        jsonBody = null;
      }
    }
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const rec = {
      method: req.method || 'GET',
      path: url.pathname,
      search: url.search,
      query: Object.fromEntries(url.searchParams.entries()),
      rawBody,
      jsonBody,
    };
    requests.push(rec);

    try {
      await handler(rec, res);
    } catch (err) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ status: 'error', message: String(err) }));
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  const origFetch = globalThis.fetch;

  globalThis.fetch = async (input, init) => {
    if (typeof input === 'string' && input.startsWith('/')) {
      return origFetch(`${baseUrl}${input}`, init);
    }
    if (input instanceof URL && input.pathname.startsWith('/')) {
      return origFetch(`${baseUrl}${input.pathname}${input.search}`, init);
    }
    return origFetch(input, init);
  };

  try {
    return await fn(baseUrl, requests);
  } finally {
    globalThis.fetch = origFetch;
    await new Promise((resolve) => server.close(resolve));
  }
}

/**
 * Creates lightweight WebGL2 + Canvas2D mocks for instantiating and exercising
 * AetherEngine and 2D Canvas overlay renderers in Node without jsdom.
 */
export function createCanvasMocks(options = {}) {
  const { failWebGL2 = false, fail2D = false, failShaderCompile = false } = options;
  const glCalls = [];
  const ctx2dCalls = [];

  const gl = failWebGL2
    ? null
    : {
        drawingBufferWidth: 1280,
        drawingBufferHeight: 720,
        VERTEX_SHADER: 35633,
        FRAGMENT_SHADER: 35632,
        COMPILE_STATUS: 35713,
        LINK_STATUS: 35714,
        ARRAY_BUFFER: 34962,
        STATIC_DRAW: 35044,
        DYNAMIC_DRAW: 35048,
        FLOAT: 5126,
        TRIANGLES: 4,
        TRIANGLE_STRIP: 5,
        COLOR_BUFFER_BIT: 16384,
        BLEND: 3042,
        SRC_ALPHA: 770,
        ONE_MINUS_SRC_ALPHA: 771,
        ONE: 1,
        createShader: (type) => ({ type }),
        shaderSource: () => {},
        compileShader: () => {},
        getShaderParameter: () => !failShaderCompile,
        getShaderInfoLog: () => (failShaderCompile ? 'mock compile error' : ''),
        deleteShader: () => {},
        createProgram: () => ({ id: Math.random() }),
        attachShader: () => {},
        linkProgram: () => {},
        getProgramParameter: () => !failShaderCompile,
        getProgramInfoLog: () => (failShaderCompile ? 'mock link error' : ''),
        deleteProgram: () => {},
        getUniformLocation: (_p, name) => ({ name }),
        getAttribLocation: () => 0,
        createBuffer: () => ({}),
        bindBuffer: () => {},
        bufferData: () => {},
        deleteBuffer: () => {},
        createVertexArray: () => ({}),
        bindVertexArray: () => {},
        deleteVertexArray: () => {},
        enableVertexAttribArray: () => {},
        vertexAttribPointer: () => {},
        vertexAttribDivisor: () => {},
        clearColor: (...args) => glCalls.push(['clearColor', ...args]),
        clear: (mask) => glCalls.push(['clear', mask]),
        disable: () => {},
        enable: () => {},
        blendFunc: () => {},
        useProgram: (p) => glCalls.push(['useProgram', Boolean(p)]),
        uniform1f: () => {},
        uniform2f: () => {},
        uniform3fv: () => {},
        uniform4f: () => {},
        uniform4fv: () => {},
        drawArrays: (...args) => glCalls.push(['drawArrays', ...args]),
        drawArraysInstanced: (...args) => glCalls.push(['drawArraysInstanced', ...args]),
        viewport: () => {},
        getExtension: () => null,
      };

  const ctx2d = fail2D
    ? null
    : {
        font: '',
        fillStyle: '',
        strokeStyle: '',
        lineWidth: 1,
        globalAlpha: 1,
        textAlign: 'left',
        textBaseline: 'alphabetic',
        shadowBlur: 0,
        shadowColor: '',
        save: () => ctx2dCalls.push(['save']),
        restore: () => ctx2dCalls.push(['restore']),
        setTransform: () => {},
        clearRect: (...a) => ctx2dCalls.push(['clearRect', ...a]),
        fillRect: (...a) => ctx2dCalls.push(['fillRect', ...a]),
        strokeRect: (...a) => ctx2dCalls.push(['strokeRect', ...a]),
        beginPath: () => ctx2dCalls.push(['beginPath']),
        closePath: () => ctx2dCalls.push(['closePath']),
        moveTo: (...a) => ctx2dCalls.push(['moveTo', ...a]),
        lineTo: (...a) => ctx2dCalls.push(['lineTo', ...a]),
        bezierCurveTo: (...a) => ctx2dCalls.push(['bezierCurveTo', ...a]),
        quadraticCurveTo: (...a) => ctx2dCalls.push(['quadraticCurveTo', ...a]),
        arc: (...a) => ctx2dCalls.push(['arc', ...a]),
        roundRect: (...a) => ctx2dCalls.push(['roundRect', ...a]),
        fill: () => ctx2dCalls.push(['fill']),
        stroke: () => ctx2dCalls.push(['stroke']),
        fillText: (text, ...rest) => ctx2dCalls.push(['fillText', text, ...rest]),
        strokeText: (text, ...rest) => ctx2dCalls.push(['strokeText', text, ...rest]),
        measureText: (text) => ({ width: String(text || '').length * 6.5 }),
        setLineDash: () => {},
        createRadialGradient: () => ({ addColorStop: () => {} }),
        createLinearGradient: () => ({ addColorStop: () => {} }),
      };

  const makeCanvas = (kind) => ({
    width: 1280,
    height: 720,
    clientWidth: 1280,
    clientHeight: 720,
    style: { cursor: 'default', width: '1280px', height: '720px' },
    parentElement: { clientWidth: 1280, clientHeight: 720 },
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 1280, height: 720, right: 1280, bottom: 720 }),
    getContext: (type) => (type === kind ? (kind === 'webgl2' ? gl : ctx2d) : null),
    addEventListener: () => {},
    removeEventListener: () => {},
    setPointerCapture: () => {},
    releasePointerCapture: () => {},
    toDataURL: () => 'data:image/png;base64,',
  });

  return {
    glCanvas: makeCanvas('webgl2'),
    lineCanvas: makeCanvas('2d'),
    gl,
    ctx2d,
    glCalls,
    ctx2dCalls,
  };
}

export function readUiSource(relPath) {
  return fs.readFileSync(path.join(UI_ROOT, relPath), 'utf-8');
}

export function parseSvelte(relPath) {
  const src = readUiSource(relPath);
  return svelteCompiler.parse(src, { modern: true, filename: relPath });
}

export function compileSvelteClient(relPath) {
  const src = readUiSource(relPath);
  return svelteCompiler.compile(src, {
    generate: 'client',
    filename: path.join(UI_ROOT, relPath),
  });
}

/**
 * Reads a Svelte component source along with any relative `./...` .ts/.js helper
 * modules it imports so tests stay agnostic to internal helper extraction.
 */
export function collectComponentBundleSource(relPath) {
  const fullPath = path.join(UI_ROOT, relPath);
  const src = fs.readFileSync(fullPath, 'utf-8');
  const dir = path.dirname(fullPath);
  const extraParts = [src];
  const importRe = /from\s+['"](\.[^'"]+)['"]/g;
  let m;
  while ((m = importRe.exec(src)) !== null) {
    const spec = m[1];
    if (spec.endsWith('.svelte')) continue;
    for (const candidate of [spec, `${spec}.ts`, `${spec}.js`, `${spec}/index.ts`, `${spec}/index.js`]) {
      const resolved = path.resolve(dir, candidate);
      if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
        extraParts.push(fs.readFileSync(resolved, 'utf-8'));
        break;
      }
    }
  }
  return {
    componentSource: src,
    combinedSource: extraParts.join('\n\n'),
  };
}
