import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { describe, it } from 'node:test';
import {
  ssrLoad,
  renderComponent,
  getCockpitState,
  getApiClient,
  resetCockpitState,
  withMockHttpServer,
  createCanvasMocks,
  flushNextRaf,
  pendingRafCallbacks,
  readUiSource,
  compileSvelteClient,
  collectComponentBundleSource,
} from './harness.mjs';

function makeNode(overrides = {}) {
  return {
    id: 'sym::default',
    name: 'default_fn',
    kind: 'Function',
    file_path: 'src/main.rs',
    line_number: 1,
    x: 0,
    y: 0,
    z: 0,
    radius: 12,
    layer: 'domain',
    folder: 'src',
    cluster_id: 'src',
    loc: 20,
    in_degree: 0,
    out_degree: 0,
    anomalies: [],
    metadata: {},
    ...overrides,
  };
}

describe('Tier 2 — UI & IDE Boundary, Invalid Input & Adversarial Cases (F8–F15)', () => {
  // ===========================================================================
  // F8 Boundaries
  // ===========================================================================
  describe('F8 Boundaries: AetherEngine & Canvas Overlays', () => {
    it('tier2_f8_engine_throws_without_webgl2_or_2d', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');

      const noGl = createCanvasMocks({ failWebGL2: true });
      assert.throws(() => new AetherEngine(noGl.glCanvas, noGl.lineCanvas, cs), /WebGL 2 not supported/);

      const no2d = createCanvasMocks({ fail2D: true });
      assert.throws(() => new AetherEngine(no2d.glCanvas, no2d.lineCanvas, cs), /2D overlay context/);
    });

    it('tier2_f8_empty_and_nan_coordinate_graph_sync', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        cs.setGraph({ project_path: '/workspace', nodes: [], edges: [], clusters: {} }, false);
        eng.syncGraphToEngine(true);
        assert.ok(Number.isFinite(eng.camera.x) && Number.isFinite(eng.camera.y));

        const weirdNodes = [
          makeNode({ id: 'n1', x: Number.NaN, y: Number.POSITIVE_INFINITY }),
          makeNode({ id: 'n2', x: 100, y: -100 }),
        ];
        cs.setGraph({ project_path: '/workspace', nodes: weirdNodes, edges: [], clusters: {} }, false);
        eng.syncGraphToEngine(true);
        eng.fitCameraToGraph(true);
        assert.ok(Number.isFinite(eng.camera.zoom) && eng.camera.zoom > 0);
      } finally {
        eng.destroy();
      }
    });

    it('tier2_f8_zoom_clamping_min_max', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        for (let i = 0; i < 60; i++) eng.zoomIn();
        assert.ok(eng.camera.targetZoom <= 12.0, `targetZoom ${eng.camera.targetZoom} must clamp <= 12.0`);
        for (let i = 0; i < 120; i++) eng.zoomOut();
        assert.ok(eng.camera.targetZoom >= 0.0001, `targetZoom ${eng.camera.targetZoom} must clamp >= 0.0001`);

        eng.zoomAtScreenPoint(-5, 640, 360);
        assert.ok(eng.camera.targetZoom >= 0.0001 && Number.isFinite(eng.camera.targetZoom));
      } finally {
        eng.destroy();
      }
    });

    it('tier2_f8_overlay_expired_and_empty_agents_safe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AgentOverlayRenderer } = await ssrLoad('/src/engine/agentOverlay.ts');
      const { renderGitDiffBadges, renderSecurityBeacons } = await ssrLoad('/src/engine/beaconsOverlay.ts');

      const mocks = createCanvasMocks();
      const overlayCtx = {
        state: cs,
        nodeMap: new Map(),
        zoom: 1.0,
        logicalWidth: 1280,
        logicalHeight: 720,
        hoveredNodeId: null,
        folderPillBounds: [],
        labelBounds: [],
        anomalyNodeIndices: [],
        isAnomalyIgnored: () => false,
        getEffectiveAnomalies: () => [],
        worldToScreen: (wx, wy) => ({ x: wx, y: wy }),
        classifyNode: () => ({ baseRadius: 12 }),
        getNodeScreenRadius: () => 12,
      };

      // Empty graph + empty agents
      renderGitDiffBadges(mocks.ctx2d, 1000, overlayCtx);
      renderSecurityBeacons(mocks.ctx2d, 1000, overlayCtx);
      const renderer = new AgentOverlayRenderer();
      renderer.render(mocks.ctx2d, 1000, 16, overlayCtx);
      assert.equal(mocks.ctx2dCalls.length, 0, 'Empty graph/agents must emit zero draw calls');

      // Expired agent (> 5 min)
      const n1 = makeNode({ id: 'sym::x', x: 10, y: 10 });
      cs.setGraph({ project_path: '/workspace', nodes: [n1], edges: [], clusters: {} }, false);
      cs.activeAgents = [
        {
          agentId: 'stale-1',
          agentName: 'ExpiredAgent',
          target: 'sym::x',
          nodeId: 'sym::x',
          timestamp: Date.now() - 10 * 60 * 1000,
        },
      ];
      overlayCtx.nodeMap.set(n1.id, n1);
      renderer.render(mocks.ctx2d, 1000, 16, overlayCtx);
      const texts = mocks.ctx2dCalls.filter((c) => c[0] === 'fillText').map((c) => String(c[1]));
      assert.equal(texts.some((t) => t.includes('ExpiredAgent')), false, 'Expired agents (>5 min) must not render');
    });

    it('tier2_f8_apply_visual_plugin_invalid_glsl_safe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        // Flip GL shader compilation to fail for custom hot-swap
        mocks.gl.getShaderParameter = () => false;
        mocks.gl.getProgramParameter = () => false;
        const res = eng.applyVisualPlugin({
          id: 'broken-pack',
          name: 'Broken',
          description: 'Invalid',
          backdrop_glsl: 'void main() { BROKEN SYNTAX',
          node_sdf_glsl: 'void main() {}',
          palette: {},
          uniforms: {},
          overlay: {},
        });
        assert.equal(res.ok, false, 'Invalid custom GLSL must fail gracefully with ok: false');
        assert.ok(typeof res.error === 'string' && res.error.length > 0);
      } finally {
        eng.destroy();
      }
    });

    it('tier2_f8_destroy_idempotent_and_stops_raf', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      eng.start();
      eng.destroy();
      eng.destroy();
      const before = pendingRafCallbacks.size;
      flushNextRaf(performance.now() + 16);
      assert.ok(pendingRafCallbacks.size <= before, 'Destroyed engine must not schedule new rAF callbacks');
    });
  });

  // ===========================================================================
  // F9 Boundaries
  // ===========================================================================
  describe('F9 Boundaries: ReDoS, Prototype Pollution, HTTP Errors & Prefill', () => {
    it('tier2_f9_redos_multi_star_bounty_pattern', async () => {
      const { matchesWildcardPattern } = await ssrLoad('/src/components/bounty/bountyEngine.ts');
      const longPath = 'a/'.repeat(120) + 'target.txt';
      const adversarialPat = '*/*/*/*/*/*/*/*/*/*/*/*/*.rs';
      const t0 = performance.now();
      const hit = matchesWildcardPattern(longPath, adversarialPat);
      const dt = performance.now() - t0;
      assert.equal(hit, false);
      assert.ok(dt < 50, `matchesWildcardPattern took ${dt.toFixed(2)}ms (< 50ms ReDoS bound)`);
      assert.equal(matchesWildcardPattern('src/a.rs', '*'.repeat(300)), false, 'Overly long patterns (>256) must be rejected');
    });

    it('tier2_f9_redos_plugin_nested_quantifier_rejected', async () => {
      const { isSafePluginRegexPattern, compileSafePluginRegExp, evaluatePluginRulesInBrowser } = await ssrLoad('/src/lib/demoPlugins.ts');
      for (const evil of ['(a+)+$', '(a|a?)+', '([a-zA-Z]+)*$', '(a)\\1+', 'a{1,500}', 'a'.repeat(300)]) {
        assert.equal(isSafePluginRegexPattern(evil), false, `Evil regex ${evil.slice(0, 24)} must be rejected`);
        assert.equal(compileSafePluginRegExp(evil), null);
      }

      const t0 = performance.now();
      const res = evaluatePluginRulesInBrowser('src/a.rs', 'a'.repeat(5000) + '!', [
        {
          id: 'EVIL-1',
          cwe_id: 'CWE-1333',
          name: 'Evil',
          category: 'test',
          severity: 'HIGH',
          description: '',
          remediation: '',
          file_extensions: ['rs'],
          match_mode: 'line_by_line',
          check_literals: false,
          must_contain: [],
          must_not_contain: [],
          regex_patterns: ['(a+)+$'],
          forbidden_tokens: [],
          in_path_matching: [],
          not_in_path_matching: [],
          test_cases_count: 0,
        },
      ]);
      const dt = performance.now() - t0;
      assert.deepEqual(res, []);
      assert.ok(dt < 50, `Plugin evaluation with rejected ReDoS took ${dt.toFixed(2)}ms (< 50ms)`);
    });

    it('tier2_f9_prototype_pollution_cwe_1321_safe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { evaluatePluginRulesInBrowser } = await ssrLoad('/src/lib/demoPlugins.ts');

      const pollutedPayload = JSON.parse(
        '{"project_path":"/workspace","nodes":[{"id":"__proto__","name":"constructor","kind":"Function","file_path":"src/prototype.rs","line_number":1,"x":0,"y":0,"z":0,"radius":10,"layer":"domain","anomalies":[],"metadata":{"__proto__":{"polluted":true}}}],"edges":[],"clusters":{"__proto__":{"polluted":true}}}'
      );
      cs.setGraph(pollutedPayload, false);
      evaluatePluginRulesInBrowser('src/__proto__.rs', 'const __proto__ = "x";', []);
      assert.equal(({}).polluted, undefined, 'Object.prototype must never be polluted');
    });

    it('tier2_f9_api_http_4xx_5xx_error_handling', async () => {
      const api = await getApiClient();
      await withMockHttpServer(async (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.path === '/api/git/status') {
          res.statusCode = 500;
          res.end(JSON.stringify({ status: 'error', message: 'git failure' }));
          return;
        }
        if (req.path === '/api/ai/create_file') {
          res.statusCode = 403;
          res.end(JSON.stringify({ status: 'error', message: 'Path confinement denied' }));
          return;
        }
        res.statusCode = 404;
        res.end(JSON.stringify({ status: 'error', message: 'Not found' }));
      }, async () => {
        await assert.rejects(() => api.getGitStatus(), /HTTP 500/);
        await assert.rejects(() => api.createFile({ project_path: '.', file_path: '../etc/passwd', content: 'x' }), /Path confinement denied/);
        const readErr = await api.getFileContent('missing.rs');
        assert.equal(readErr.status, 'error');
      });
    });

    it('tier2_f9_pending_create_folder_normalization_boundaries', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const modalSrc = readUiSource('src/components/CreateFileModal.svelte');

      // Verify normalization strips Windows backslashes, leading ./, trailing slashes, and ignores '.' / 'root' / ''
      assert.ok(/replace\(\/\\\\\/g,\s*['"]\/['"]\)/.test(modalSrc), 'Must normalize backslashes to POSIX slashes');
      assert.ok(/['"]root['"]/.test(modalSrc) && /['"]\.['"]/.test(modalSrc), 'Must ignore root and . placeholders');
      assert.ok(/Escape[\s\S]{0,60}closeModal|closeModal[\s\S]{0,120}pendingCreateFolder\s*=\s*null/.test(modalSrc), 'Escape / closeModal must clear pendingCreateFolder');

      cs.pendingCreateFolder = 'crates\\core///';
      cs.isCreateFileModalOpen = true;
      const rendered = await renderComponent('/src/components/CreateFileModal.svelte');
      assert.ok(rendered.body.includes('role="dialog"'));
    });

    it('tier2_f9_bounty_tokenize_50k_adversarial_line', async () => {
      const { tokenizeLine } = await ssrLoad('/src/components/bounty/bountyEngine.ts');
      const unclosed = 'let s = "' + 'a'.repeat(50000);
      const escapes = 'let e = "' + '\\\\'.repeat(25000);

      const t0 = performance.now();
      const out1 = tokenizeLine(unclosed).map((t) => t.text).join('');
      const out2 = tokenizeLine(escapes).map((t) => t.text).join('');
      const dt = performance.now() - t0;

      assert.equal(out1, unclosed);
      assert.equal(out2, escapes);
      assert.ok(dt < 100, `tokenizeLine on 50k adversarial inputs took ${dt.toFixed(2)}ms (< 100ms)`);
    });
  });

  // ===========================================================================
  // F10 Boundaries
  // ===========================================================================
  describe('F10 Boundaries: Unified Editor, Tokenizer, Replace & Undo/Redo', () => {
    it('tier2_f10_tokenizer_redos_50k_unclosed_and_escaped', async () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/tokenizeCodeLine/.test(combinedSource), 'IdeEditor must define or import tokenizeCodeLine');
      // Verify tokenizer regex has no nested quantifiers causing ReDoS
      assert.equal(/\(\.\*\)\+|\(\.\+\)\+/.test(combinedSource), false, 'Tokenizer regex must not use nested quantifiers');

      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.openFileInIde('src/big.rs', 1);
      const t0 = performance.now();
      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      const dt = performance.now() - t0;
      assert.ok(rendered.body.length > 0 && dt < 150, `IdeEditor SSR render took ${dt.toFixed(2)}ms`);
    });

    it('tier2_f10_tokenizer_xss_and_unicode_safe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const evilName = 'src/<script>alert(1)</script>_🚀.rs';
      cs.openFileInIde(evilName, 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.equal(rendered.body.includes('<script>alert(1)</script>'), false, 'XSS payload in file path/tab must be escaped in HTML');
      assert.ok(/(?:&lt;|&#60;|&#x3c;)script(?:&gt;|&#62;|&#x3e;|>)/i.test(rendered.body), 'Escaped script text must preserve path safely');
      assert.ok(rendered.body.includes('🚀'), 'Multi-byte emoji/Unicode must be preserved');
    });

    it('tier2_f10_replace_all_overlapping_replacement', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      // Must implement Find & Replace (Ctrl+H) without recursive while(indexOf) that loops when replacement contains search needle
      const hasReplace = /replaceAll|Tout remplacer/i.test(combinedSource);
      assert.ok(hasReplace, 'IdeEditor must implement Replace All for Ctrl+H');
      assert.equal(/while\s*\([^)]*indexOf\([^)]*\)\s*!==\s*-1\)\s*\{[^}]*\.replace\(/.test(combinedSource), false, 'Replace All must not loop infinitely when replacement contains search query');
    });

    it('tier2_f10_undo_redo_empty_stack_and_tab_isolation', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/undoStack/.test(combinedSource) && /redoStack/.test(combinedSource), 'Per-buffer undoStack/redoStack required');
      assert.ok(/buffers\[/.test(combinedSource), 'Undo/Redo history must be stored per-tab in buffers');
    });

    it('tier2_f10_ctrl_f_regex_metacharacters_literal', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      // Search match enumeration must not construct unescaped new RegExp(searchQuery)
      assert.equal(/new\s+RegExp\(\s*searchQuery/.test(combinedSource), false, 'Ctrl+F search must match literally without throwing on regex metacharacters');
      assert.ok(/indexOf/.test(combinedSource), 'Ctrl+F search must use literal substring matching');
    });

    it('tier2_f10_empty_and_null_active_file_ssr', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const emptyStateHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(emptyStateHtml.includes('Aucun fichier ouvert'), 'Null active file must render empty placeholder cleanly');

      cs.openFileInIde('src/empty.rs', 1);
      const activeEmptyHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(activeEmptyHtml.includes('<textarea'), 'Empty buffer must still render editor textarea cleanly');
    });
  });

  // ===========================================================================
  // F11 Boundaries
  // ===========================================================================
  describe('F11 Boundaries: Error Lens, Normalization & XSS Escaping', () => {
    it('tier2_f11_multiple_anomalies_same_line', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::multi',
              file_path: 'src/multi.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [
                { rule_id: 'CWE-89', severity: 'CRITICAL', line_number: 1, message: 'SQLi', file_path: 'src/multi.rs' },
                { rule_id: 'CWE-78', severity: 'HIGH', line_number: 1, message: 'CMDi', file_path: 'src/multi.rs' },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/multi.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('CWE-89') && rendered.body.includes('CWE-78'), 'Multiple anomalies on same line must both be surfaced');
    });

    it('tier2_f11_metadata_cve_anomalies_and_violations_string_fallback', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::meta',
              file_path: 'src/meta.rs',
              line_number: 1,
              metadata: {
                violations: ['[SAST] (CWE-79 | HIGH) L1: Reflected XSS sink'],
              },
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/meta.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('CWE-79'), 'Normalized metadata.violations CWE-79 must render in Error Lens');
    });

    it('tier2_f11_rule_max_lines_excluded_from_cwe_error_lens', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'file::big',
              kind: 'File',
              is_file: true,
              file_path: 'src/big.rs',
              line_number: 1,
              loc: 350,
              has_security_violation: true,
              anomalies: [
                {
                  rule_id: 'RULE_MAX_LINES',
                  cve_id: 'ARCH-BUDGET-EXCEEDED',
                  severity: 'MEDIUM',
                  line_number: 1,
                  message: '350 / 300 lines exceeded',
                  file_path: 'src/big.rs',
                },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/big.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(/\b0\s*CWE\b/.test(rendered.body), 'RULE_MAX_LINES must NOT be counted or flagged as a CWE security violation');
      assert.equal(rendered.body.includes('ARCH-BUDGET-EXCEEDED'), false, 'RULE_MAX_LINES must not render as a CWE Error Lens alert');
    });

    it('tier2_f11_out_of_bounds_line_number_clamped', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::oob',
              file_path: 'src/oob.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [
                { rule_id: 'CWE-89', severity: 'HIGH', line_number: 0, message: 'Line zero', file_path: 'src/oob.rs' },
                { rule_id: 'CWE-78', severity: 'HIGH', line_number: -5, message: 'Negative line', file_path: 'src/oob.rs' },
                { rule_id: 'CWE-79', severity: 'HIGH', line_number: 99999, message: 'Far line', file_path: 'src/oob.rs' },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/oob.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('<textarea'), 'Out-of-bounds line numbers must render cleanly without crashing');
    });

    it('tier2_f11_xss_in_anomaly_remediation_escaped', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::xss',
              file_path: 'src/xss.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [
                {
                  rule_id: 'CWE-79',
                  severity: 'CRITICAL',
                  line_number: 1,
                  message: '<script>alert(1)</script>',
                  remediation: '<img src=x onerror=alert(2)>',
                  file_path: 'src/xss.rs',
                },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/xss.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.equal(rendered.body.includes('<script>alert(1)</script>'), false, 'Raw <script> in anomaly message must be escaped');
      assert.equal(rendered.body.includes('<img src=x onerror=alert(2)>'), false, 'Raw <img> tag in remediation must be escaped');
      assert.ok(/(?:&lt;|&#60;|&#x3c;)script(?:&gt;|&#62;|&#x3e;|>)alert\(1\)/i.test(rendered.body), 'Escaped message must render safely');
    });

    it('tier2_f11_other_file_anomalies_isolated', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::other',
              file_path: 'src/other.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [{ rule_id: 'CWE-89', severity: 'CRITICAL', line_number: 1, message: 'Other file bug', file_path: 'src/other.rs' }],
            }),
            makeNode({ id: 'sym::clean', file_path: 'src/clean.rs', line_number: 1, anomalies: [] }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/clean.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.equal(rendered.body.includes('Other file bug'), false, 'CWE from other file must never leak into active file Error Lens');
      assert.ok(/\b0\s*CWE\b/.test(rendered.body));
    });
  });

  // ===========================================================================
  // F12 Boundaries
  // ===========================================================================
  describe('F12 Boundaries: Breadcrumbs & Call-Graph Edge Cases', () => {
    it('tier2_f12_cursor_before_first_symbol', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'sym::late', name: 'late_fn', file_path: 'src/net.rs', line_number: 15 })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/net.rs', 1);
      cs.ideCursorPosition = { line: 1, ch: 1 };

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('net.rs'), 'Cursor before first symbol must still show file breadcrumb');
      assert.equal(rendered.body.includes('late_fn'), false, 'Cursor at L1 must not claim symbol at L15 as enclosing');
    });

    it('tier2_f12_zero_ast_symbols_file', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.openFileInIde('docs/NOTES.md', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('NOTES.md'));
      assert.ok(rendered.body.includes('Cibler en 3D') || rendered.body.includes('Appelants'));
    });

    it('tier2_f12_self_recursive_edge', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'sym::rec', name: 'factorial', file_path: 'src/math.rs', line_number: 5 })],
          edges: [{ source: 'sym::rec', target: 'sym::rec', relation: 'calls' }],
          clusters: {},
        },
        false
      );
      assert.equal(cs.incidentEdges('sym::rec').length, 1, 'Self-edge must not duplicate in incidentEdges');
      cs.openFileInIde('src/math.rs', 6);
      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('factorial'));
    });

    it('tier2_f12_dangling_edge_target_missing', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'sym::a', name: 'alpha', file_path: 'src/a.rs', line_number: 2 })],
          edges: [{ source: 'sym::a', target: 'sym::nonexistent', relation: 'calls' }],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/a.rs', 3);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('alpha'));
      assert.equal(rendered.body.includes('undefined'), false, 'Dangling edge must not leak "undefined" into UI');
    });

    it('tier2_f12_file_container_node_does_not_shadow_function', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({ id: 'file::req', name: 'req_file_container', kind: 'File', is_file: true, file_path: 'src/req.rs', line_number: 1 }),
            makeNode({ id: 'sym::fn', name: 'parse_req', kind: 'Function', file_path: 'src/req.rs', line_number: 10 }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/req.rs', 12);
      cs.ideCursorPosition = { line: 12, ch: 1 };

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('parse_req'), 'Function symbol at L10 must not be shadowed by file container at L1');
    });

    it('tier2_f12_high_degree_50_callers_50_callees', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const hub = makeNode({ id: 'sym::hub', name: 'central_router', file_path: 'src/hub.rs', line_number: 5 });
      const nodes = [hub];
      const edges = [];
      for (let i = 0; i < 50; i++) {
        nodes.push(makeNode({ id: `sym::in_${i}`, name: `caller_${i}`, file_path: `src/in_${i}.rs`, line_number: 1 }));
        edges.push({ source: `sym::in_${i}`, target: 'sym::hub', relation: 'calls' });
        nodes.push(makeNode({ id: `sym::out_${i}`, name: `callee_${i}`, file_path: `src/out_${i}.rs`, line_number: 1 }));
        edges.push({ source: 'sym::hub', target: `sym::out_${i}`, relation: 'calls' });
      }
      cs.setGraph({ project_path: '/workspace', nodes, edges, clusters: {} }, false);
      cs.openFileInIde('src/hub.rs', 8);

      const t0 = performance.now();
      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      const dt = performance.now() - t0;

      assert.ok(dt < 50, `High-degree 100-edge breadcrumb render took ${dt.toFixed(2)}ms (< 50ms)`);
      assert.ok(/Appelants[\s\S]{0,120}\b50\b/.test(rendered.body), 'Must show 50 callers');
      assert.ok(/Appelés[\s\S]{0,120}\b50\b/.test(rendered.body), 'Must show 50 callees');
    });
  });

  // ===========================================================================
  // F13 Boundaries
  // ===========================================================================
  describe('F13 Boundaries: EARS & BLAKE3 Firewall Status Bar', () => {
    it('tier2_f13_line_budget_exceeded_keeps_0_cwe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'file::over',
              kind: 'File',
              is_file: true,
              file_path: 'src/over.rs',
              loc: 350,
              has_security_violation: true,
              metadata: { max_lines_limit: 300 },
              anomalies: [
                {
                  rule_id: 'RULE_MAX_LINES',
                  cve_id: 'ARCH-BUDGET-EXCEEDED',
                  severity: 'MEDIUM',
                  line_number: 1,
                  message: '350 / 300',
                  file_path: 'src/over.rs',
                },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/over.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(/\/\s*300\s*L\b/.test(rendered.body), 'Budget gauge must show / 300 L');
      assert.ok(/\b0\s*CWE\b/.test(rendered.body), 'RULE_MAX_LINES alone must keep 0 CWE in status bar');
    });

    it('tier2_f13_missing_max_lines_defaults_300', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'file::nolim', kind: 'File', is_file: true, file_path: 'src/nolim.rs', metadata: {} })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/nolim.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(/\/\s*300\s*L\b/.test(rendered.body), 'Missing max_lines_limit must default to / 300 L');
    });

    it('tier2_f13_stale_or_other_file_agent_excluded', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({ id: 'file::a', kind: 'File', is_file: true, file_path: 'src/a.rs' }),
            makeNode({ id: 'file::b', kind: 'File', is_file: true, file_path: 'src/b.rs' }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.activeAgents = [
        { agentId: 'stale', agentName: 'StaleAgent', target: 'src/a.rs', nodeId: 'file::a', timestamp: Date.now() - 360_000 },
        { agentId: 'other', agentName: 'OtherFileAgent', target: 'src/b.rs', nodeId: 'file::b', timestamp: Date.now() },
      ];
      cs.openFileInIde('src/a.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.equal(rendered.body.includes('StaleAgent'), false, 'Agent > 5 min old must be excluded from status bar');
      assert.equal(rendered.body.includes('OtherFileAgent'), false, 'Agent targeting other file must be excluded from active file status bar');
    });

    it('tier2_f13_ignored_cwes_excluded_from_counter', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::two',
              file_path: 'src/two.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [
                { rule_id: 'CWE-89', severity: 'CRITICAL', line_number: 1, message: 'sqli', file_path: 'src/two.rs' },
                { rule_id: 'CWE-78', severity: 'HIGH', line_number: 1, message: 'cmdi', file_path: 'src/two.rs' },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/two.rs', 1);

      cs.ignoreCweRule('CWE-89');
      const oneHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(/\b1\s*CWE\b/.test(oneHtml), 'Ignoring 1 of 2 CWEs must show 1 CWE');

      cs.ignoreCweRule('CWE-78');
      const zeroHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(/\b0\s*CWE\b/.test(zeroHtml), 'Ignoring both CWEs must show 0 CWE');
    });

    it('tier2_f13_seal_http_500_graceful_error', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const api = await getApiClient();
      const origNode = makeNode({ id: 'file::fw', kind: 'File', is_file: true, file_path: 'src/fw.rs', metadata: { max_lines_limit: 200 } });
      cs.setGraph({ project_path: '/workspace', nodes: [origNode], edges: [], clusters: {} }, false);

      await withMockHttpServer(async (_req, res) => {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ status: 'error', message: 'BLAKE3 lock failed' }));
      }, async () => {
        const res = await api.signContracts({ project_path: '/workspace' });
        assert.equal(res.status, 'error');
        assert.equal(cs.graph.nodes.length, 1);
        assert.equal(cs.getNodeById('file::fw').metadata.max_lines_limit, 200);
      });
    });

    it('tier2_f13_null_active_file_status_bar_safe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('UTF-8'), 'Status bar must render safely even when ideActiveFile is null');
    });
  });

  // ===========================================================================
  // F14 Boundaries
  // ===========================================================================
  describe('F14 Boundaries: Git Normalization, Missing Clipboard & Filters', () => {
    it('tier2_f14_null_git_or_non_git_repo', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.openFileInIde('src/clean.rs');

      const nullEd = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      const nullFt = (await renderComponent('/src/components/ide/IdeFileTree.svelte')).body;
      assert.ok(nullEd.includes('clean.rs') && nullFt.includes('Fichiers'));

      cs.gitStatus = {
        is_git_repo: false,
        branch: null,
        clean: true,
        files: [],
        modified_count: 0,
        untracked_count: 0,
        staged_count: 0,
        deleted_count: 0,
        security_alert_count: 0,
      };
      const nonGitEd = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      const nonGitFt = (await renderComponent('/src/components/ide/IdeFileTree.svelte')).body;
      assert.ok(nonGitEd.includes('clean.rs') && nonGitFt.includes('Fichiers'));
    });

    it('tier2_f14_path_normalization_no_collision', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.gitStatus = {
        is_git_repo: true,
        branch: 'main',
        clean: false,
        files: [{ path: '.\\crates\\a\\lib.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false }],
        modified_count: 1,
        untracked_count: 0,
        staged_count: 0,
        deleted_count: 0,
        security_alert_count: 0,
      };
      cs.openFileInIde('crates/a/lib.rs');
      cs.openFileInIde('crates/b/lib.rs');

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      const tabA = rendered.body.match(/title="crates\/a\/lib\.rs[^"]*"[\s\S]{0,600}?<\/button>/);
      const tabB = rendered.body.match(/title="crates\/b\/lib\.rs[^"]*"[\s\S]{0,600}?<\/button>/);
      assert.ok(tabA && /\bM\b/.test(tabA[0]), 'Normalized Git path .\\crates\\a\\lib.rs must badge crates/a/lib.rs');
      assert.ok(tabB && !/>\s*M\s*</.test(tabB[0]), 'crates/b/lib.rs must NOT collide on basename lib.rs');
    });

    it('tier2_f14_deleted_renamed_conflict_unknown_status', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.gitStatus = {
        is_git_repo: true,
        branch: 'main',
        clean: false,
        files: [
          { path: 'src/del.rs', status: 'deleted', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/ren.rs', status: 'renamed', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/conf.rs', status: 'conflict', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/unk.rs', status: 'unknown_xyz', has_security_violation: false, cwe_count: 0, ears_violation: false },
        ],
        modified_count: 0,
        untracked_count: 0,
        staged_count: 0,
        deleted_count: 1,
        security_alert_count: 0,
      };
      cs.openFileInIde('src/del.rs');
      cs.openFileInIde('src/ren.rs');
      cs.openFileInIde('src/conf.rs');
      cs.openFileInIde('src/unk.rs');

      const edHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      const ftHtml = (await renderComponent('/src/components/ide/IdeFileTree.svelte')).body;
      assert.equal(edHtml.includes('undefined'), false, 'Unknown/special Git status must not render undefined');
      assert.ok(ftHtml.includes('Fichiers'));
    });

    it('tier2_f14_git_filter_plus_adversarial_search', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte');
      assert.equal(/new\s+RegExp\(\s*(?:searchFilter|filter|q)/.test(combinedSource), false, 'File tree search filter must not construct raw RegExp from user input');
      assert.ok(/toLowerCase\(\)\.includes/.test(combinedSource), 'File tree search must use literal substring matching');
    });

    it('tier2_f14_clipboard_rejected_or_missing', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte');
      assert.ok(/clipboard/.test(combinedSource), 'IdeFileTree must guard clipboard access');
      // Must handle missing clipboard or async rejection safely (try/catch or .catch)
      const safeClipboard =
        /navigator\?\.clipboard\?\.writeText/.test(combinedSource) ||
        /typeof\s+navigator\s*!==\s*['"]undefined['"][\s\S]{0,120}clipboard[\s\S]{0,120}(?:try|catch)/.test(combinedSource);
      assert.ok(safeClipboard, 'Clipboard copy must degrade gracefully if navigator.clipboard is missing or rejected');
    });

    it('tier2_f14_editor_tab_git_badge_windows_path', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.gitStatus = {
        is_git_repo: true,
        branch: 'main',
        clean: false,
        files: [{ path: 'crates/core/main.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false }],
        modified_count: 1,
        untracked_count: 0,
        staged_count: 0,
        deleted_count: 0,
        security_alert_count: 0,
      };
      cs.openFileInIde('crates\\core\\main.rs');

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/gitStatus/.test(combinedSource), 'IdeEditor tabs must check gitStatus with path normalization');
      assert.ok(/\bM\b/.test(rendered.body), 'Windows-path tab must match normalized Git status M');
    });
  });

  // ===========================================================================
  // F15 Boundaries
  // ===========================================================================
  describe('F15 Boundaries: Mini-Hub Radar / Local Constellation PiP', () => {
    it('tier2_f15_empty_graph_and_no_selection', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.viewMode = 'ide';

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      const ideHtml = (await renderComponent('/src/components/ide/IdeView.svelte')).body;
      assert.equal(radarHtml.includes('NaN'), false, 'Empty graph RadarMinimap must not produce NaN');
      assert.equal(ideHtml.includes('NaN'), false, 'Empty graph IdeView must not produce NaN');
    });

    it('tier2_f15_orphan_symbol_zero_edges', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const orphan = makeNode({ id: 'sym::orphan', name: 'isolated_helper', file_path: 'src/iso.rs', line_number: 10, in_degree: 0, out_degree: 0 });
      cs.setGraph({ project_path: '/workspace', nodes: [orphan], edges: [], clusters: {} }, false);
      cs.activeSymbol = orphan;

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      assert.ok(radarHtml.includes('isolated_helper'), 'Orphan symbol in local mode must display center node');
      assert.ok(/0\s*(?:appelant|caller|voisin|appelé|callee)/i.test(radarHtml), 'Orphan symbol must render clean 0-neighbor state');
    });

    it('tier2_f15_high_degree_hub_bounded', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const hub = makeNode({ id: 'sym::hub', name: 'mega_hub', file_path: 'src/hub.rs', line_number: 1 });
      const nodes = [hub];
      const edges = [];
      for (let i = 0; i < 120; i++) {
        nodes.push(makeNode({ id: `sym::n${i}`, name: `neighbor_${i}`, file_path: `src/n${i}.rs`, line_number: i + 1 }));
        edges.push(i % 2 === 0 ? { source: `sym::n${i}`, target: 'sym::hub', relation: 'calls' } : { source: 'sym::hub', target: `sym::n${i}`, relation: 'calls' });
      }
      cs.setGraph({ project_path: '/workspace', nodes, edges, clusters: {} }, false);
      cs.activeSymbol = hub;

      const t0 = performance.now();
      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      const dt = performance.now() - t0;

      assert.ok(dt < 50, `120-edge local constellation render took ${dt.toFixed(2)}ms (< 50ms)`);
      assert.ok(radarHtml.includes('mega_hub'));
    });

    it('tier2_f15_expired_and_dangling_agents', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const sym = makeNode({ id: 'sym::center', name: 'center_fn', file_path: 'src/c.rs', line_number: 5 });
      cs.setGraph({ project_path: '/workspace', nodes: [sym], edges: [], clusters: {} }, false);
      cs.activeSymbol = sym;
      cs.activeAgents = [
        { agentId: 'old', agentName: 'OldBot', target: 'sym::center', nodeId: 'sym::center', timestamp: Date.now() - 600_000 },
        { agentId: 'ghost', agentName: 'GhostTargetBot', target: 'missing::sym', nodeId: 'missing::sym', timestamp: Date.now() },
      ];

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      assert.equal(radarHtml.includes('OldBot'), false, 'Expired agent (>5 min) must be excluded from PiP');
      assert.equal(radarHtml.includes('undefined'), false, 'Unresolvable target must not render undefined');
    });

    it('tier2_f15_neighbor_missing_file_or_line_zero', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.openFileInIde('src/valid.rs', 25);

      cs.openFileInIde('', 0);
      assert.equal(cs.ideActiveFile, 'src/valid.rs', 'Empty file path must not overwrite ideActiveFile');
      assert.equal(cs.ideTargetLine, 25, 'Line 0 must not overwrite ideTargetLine');

      cs.openFileInIde('src/next.rs', 0);
      assert.equal(cs.ideActiveFile, 'src/next.rs');
      assert.equal(cs.ideTargetLine, 25, 'targetLine <= 0 must not reset ideTargetLine to 0');
    });

    it('tier2_f15_self_loop_and_dangling_edge_ids', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const sym = makeNode({ id: 'sym::1', name: 'self_fn', file_path: 'src/s.rs', line_number: 10 });
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [sym],
          edges: [
            { source: 'sym::1', target: 'sym::1', relation: 'calls' },
            { source: 'sym::1', target: 'ghost::999', relation: 'calls' },
          ],
          clusters: {},
        },
        false
      );
      cs.activeSymbol = sym;

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      assert.ok(radarHtml.includes('self_fn'));
      assert.equal(radarHtml.includes('undefined'), false);
    });
  });
});
