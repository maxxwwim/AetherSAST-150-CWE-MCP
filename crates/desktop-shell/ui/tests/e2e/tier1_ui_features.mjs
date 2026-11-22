import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  UI_ROOT,
  ssrLoad,
  renderComponent,
  getCockpitState,
  getApiClient,
  resetCockpitState,
  withMockHttpServer,
  createCanvasMocks,
  flushNextRaf,
  readUiSource,
  parseSvelte,
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

describe('Tier 1 — UI & IDE Feature Coverage (F8–F15)', () => {
  // ===========================================================================
  // F8 — UI Engine Modularization & 2D Canvas Overlays
  // ===========================================================================
  describe('F8: AetherEngine Modularization & Canvas Overlays', () => {
    it('tier1_f8_engine_line_budget_and_modular_overlays', () => {
      const engineSrc = readUiSource('src/engine/engine.ts');
      const lineCount = engineSrc.split(/\r?\n/).length;
      assert.ok(lineCount < 3000, `engine.ts (${lineCount} lines) must be below 3000-line EARS budget`);
      assert.ok(lineCount < 2500, `engine.ts (${lineCount} lines) must be modularized below 2500 lines`);

      const engineFiles = fs.readdirSync(path.join(UI_ROOT, 'src/engine'));
      assert.ok(engineFiles.includes('agentOverlay.ts'), 'agentOverlay.ts module must exist under src/engine/');
      assert.ok(engineFiles.includes('beaconsOverlay.ts'), 'beaconsOverlay.ts module must exist under src/engine/');
    });

    it('tier1_f8_overlay_modules_render_2d_canvas_calls', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);

      const { AgentOverlayRenderer } = await ssrLoad('/src/engine/agentOverlay.ts');
      const { renderGitDiffBadges, renderSecurityBeacons } = await ssrLoad('/src/engine/beaconsOverlay.ts');

      const vulnFile = makeNode({
        id: 'file::auth',
        name: 'auth.rs',
        kind: 'File',
        is_file: true,
        file_path: 'src/auth.rs',
        git_status: 'modified',
        edit_kind: 'modif',
        has_security_violation: true,
        anomalies: [
          {
            rule_id: 'CWE-89',
            cve_id: 'CWE-89',
            severity: 'CRITICAL',
            line_number: 12,
            message: 'SQL injection sink',
            remediation: 'Use parameterized query',
            file_path: 'src/auth.rs',
          },
        ],
      });
      cs.setGraph({ project_path: '/workspace', nodes: [vulnFile], edges: [], clusters: {} }, false);
      cs.gitStatus = {
        is_git_repo: true,
        branch: 'main',
        clean: false,
        files: [{ path: 'src/auth.rs', status: 'modified', has_security_violation: true, cwe_count: 1, ears_violation: false }],
        modified_count: 1,
        untracked_count: 0,
        staged_count: 0,
        deleted_count: 0,
        security_alert_count: 1,
      };
      cs.activeAgents = [
        {
          agentId: 'ag-1',
          agentName: 'AuditBot',
          target: 'src/auth.rs',
          nodeId: 'file::auth',
          color: '#38bdf8',
          timestamp: Date.now(),
          action: 'scanning',
        },
      ];

      const mocks = createCanvasMocks();
      const nodeMap = new Map([[vulnFile.id, vulnFile]]);

      renderGitDiffBadges(mocks.ctx2d, performance.now(), {
        state: cs,
        zoom: 1.0,
        logicalWidth: 1280,
        logicalHeight: 720,
        hoveredNodeId: null,
        folderPillBounds: [],
        labelBounds: [],
        anomalyNodeIndices: [0],
        isAnomalyIgnored: (r, c) => cs.isCweIgnored(r, c),
        getEffectiveAnomalies: (n) => n.anomalies || [],
        worldToScreen: (wx, wy) => ({ x: 640 + wx, y: 360 + wy }),
        getNodeScreenRadius: () => 18,
      });

      renderSecurityBeacons(mocks.ctx2d, performance.now(), {
        state: cs,
        zoom: 1.0,
        logicalWidth: 1280,
        logicalHeight: 720,
        hoveredNodeId: null,
        folderPillBounds: [],
        labelBounds: [],
        anomalyNodeIndices: [0],
        isAnomalyIgnored: (r, c) => cs.isCweIgnored(r, c),
        getEffectiveAnomalies: (n) => n.anomalies || [],
        worldToScreen: (wx, wy) => ({ x: 640 + wx, y: 360 + wy }),
        getNodeScreenRadius: () => 18,
      });

      const agentOverlay = new AgentOverlayRenderer();
      agentOverlay.render(mocks.ctx2d, performance.now(), 16.6, {
        state: cs,
        nodeMap,
        zoom: 1.0,
        logicalWidth: 1280,
        logicalHeight: 720,
        worldToScreen: (wx, wy) => ({ x: 640 + wx, y: 360 + wy }),
        classifyNode: () => ({ baseRadius: 14 }),
        getNodeScreenRadius: () => 18,
      });

      const textCalls = mocks.ctx2dCalls.filter((c) => c[0] === 'fillText').map((c) => String(c[1]));
      const arcCalls = mocks.ctx2dCalls.filter((c) => c[0] === 'arc');
      assert.ok(arcCalls.length > 0, '2D overlays should draw arcs/rings for beacons and active agents');
      assert.ok(textCalls.some((t) => t.includes('CWE-89')), 'Security beacons should draw CWE-89 pill text');
      assert.ok(textCalls.some((t) => t.includes('AuditBot')), 'Agent overlay should draw active agent label');
    });

    it('tier1_f8_aether_engine_instantiation_and_sync', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        assert.equal(cs.engine, eng, 'AetherEngine constructor must register itself on cockpitState.engine');
        const n1 = makeNode({ id: 'a', name: 'alpha', x: -100, y: 50 });
        const n2 = makeNode({ id: 'b', name: 'beta', x: 200, y: -50 });
        cs.setGraph(
          {
            project_path: '/workspace',
            nodes: [n1, n2],
            edges: [{ source: 'a', target: 'b', relation: 'calls' }],
            clusters: {},
          },
          false
        );
        eng.syncGraphToEngine(true);
        assert.ok(Number.isFinite(eng.camera.x) && Number.isFinite(eng.camera.y), 'camera coordinates must stay finite');
      } finally {
        eng.destroy();
      }
    });

    it('tier1_f8_camera_zoom_and_coordinate_transforms', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        const n1 = makeNode({ id: 'sym::1', name: 'target_fn', x: 180, y: -90 });
        cs.setGraph({ project_path: '/workspace', nodes: [n1], edges: [], clusters: {} }, false);
        eng.syncGraphToEngine(true);

        const screen = eng.worldToScreen(120, -80);
        const world = eng.screenToWorld(screen.x, screen.y);
        assert.ok(Math.abs(world.x - 120) < 1e-6, 'screenToWorld(worldToScreen(x)) must round-trip X');
        assert.ok(Math.abs(world.y - -80) < 1e-6, 'screenToWorld(worldToScreen(y)) must round-trip Y');

        const z0 = eng.camera.targetZoom;
        eng.zoomIn();
        assert.ok(eng.camera.targetZoom > z0, 'zoomIn() must increase targetZoom');
        eng.zoomOut();
        eng.zoomOut();
        assert.ok(eng.camera.targetZoom < z0, 'zoomOut() must decrease targetZoom');
        eng.resetZoom();
        assert.equal(eng.camera.targetZoom, 0.65, 'resetZoom() must restore default zoom');

        eng.focusSymbol('sym::1');
        assert.equal(eng.camera.targetX, 180, 'focusSymbol() must aim camera targetX at node');
        assert.equal(eng.camera.targetY, -90, 'focusSymbol() must aim camera targetY at node');
      } finally {
        eng.destroy();
      }
    });

    it('tier1_f8_update_git_and_edit_highlights_in_place', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        const n1 = makeNode({ id: 'file::1', is_file: true, file_path: 'src/lib.rs', x: 50, y: 60 });
        cs.setGraph({ project_path: '/workspace', nodes: [n1], edges: [], clusters: {} }, false);
        eng.syncGraphToEngine(true);

        eng.camera.x = 333;
        eng.camera.y = -222;
        eng.camera.zoom = 1.4;
        n1.git_status = 'modified';
        n1.edit_kind = 'modif';
        eng.updateGitAndEditHighlights();

        assert.equal(eng.camera.x, 333, 'updateGitAndEditHighlights must preserve camera.x');
        assert.equal(eng.camera.y, -222, 'updateGitAndEditHighlights must preserve camera.y');
        assert.equal(eng.camera.zoom, 1.4, 'updateGitAndEditHighlights must preserve camera.zoom');
      } finally {
        eng.destroy();
      }
    });

    it('tier1_f8_engine_start_render_frame_invokes_overlays_and_destroy', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
      const mocks = createCanvasMocks();
      const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
      try {
        const n1 = makeNode({
          id: 'file::sec',
          is_file: true,
          file_path: 'src/sec.rs',
          x: 0,
          y: 0,
          has_security_violation: true,
          anomalies: [{ rule_id: 'CWE-78', severity: 'HIGH', line_number: 5, message: 'cmd inj', file_path: 'src/sec.rs' }],
        });
        cs.setGraph({ project_path: '/workspace', nodes: [n1], edges: [], clusters: {} }, false);
        cs.activeAgents = [{ agentId: 'a1', agentName: 'SecAgent', target: 'src/sec.rs', nodeId: 'file::sec', timestamp: Date.now() }];
        eng.syncGraphToEngine(true);

        eng.start();
        const stepped = flushNextRaf(performance.now() + 32);
        assert.equal(stepped, true, 'start() must schedule a requestAnimationFrame render tick');
        assert.ok(mocks.glCalls.some((c) => c[0] === 'clear'), 'render frame must invoke WebGL clear');
        assert.ok(mocks.glCalls.some((c) => c[0] === 'drawArraysInstanced'), 'render frame must invoke instanced node draw');
        assert.ok(mocks.ctx2dCalls.some((c) => c[0] === 'clearRect'), 'render frame must clear 2D overlay canvas');
        assert.ok(mocks.ctx2dCalls.some((c) => c[0] === 'arc'), 'render frame must draw 2D overlays');
      } finally {
        eng.destroy();
      }
    });
  });

  // ===========================================================================
  // F9 — UI/JS SAST Hygiene, Typed api.ts & CreateFileModal Prefill
  // ===========================================================================
  describe('F9: UI/JS SAST Hygiene, api.ts Contracts & Modal Prefill', () => {
    it('tier1_f9_api_zero_any_and_typed_contracts', async () => {
      const apiSrc = readUiSource('src/lib/api.ts');
      assert.equal(/:\s*any\b/.test(apiSrc), false, 'api.ts must contain zero `: any` type annotations');
      assert.equal(/\bas\s+any\b/.test(apiSrc), false, 'api.ts must contain zero `as any` casts');

      const api = await getApiClient();
      for (const method of ['getGitStatus', 'signContracts', 'updateContract', 'getFileContent', 'saveFile', 'createFile']) {
        assert.equal(typeof api[method], 'function', `api.${method} must be a function`);
      }
    });

    it('tier1_f9_api_get_git_status_and_contracts_http', async () => {
      const api = await getApiClient();
      const mockGraph = { project_path: '/tmp/proj', nodes: [], edges: [], clusters: {} };

      await withMockHttpServer(async (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.method === 'GET' && req.path === '/api/git/status') {
          res.end(
            JSON.stringify({
              is_git_repo: true,
              branch: 'main',
              clean: false,
              files: [{ path: 'src/lib.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false }],
              modified_count: 1,
              untracked_count: 0,
              staged_count: 0,
              deleted_count: 0,
              security_alert_count: 0,
            })
          );
          return;
        }
        if (req.method === 'POST' && req.path === '/api/contracts/sign') {
          res.end(JSON.stringify({ status: 'ok', message: 'Signed', signed_count: 2, blake3_hash: 'abc123', graph: mockGraph }));
          return;
        }
        if (req.method === 'POST' && req.path === '/api/contracts/update') {
          res.end(
            JSON.stringify({
              status: 'ok',
              message: 'Updated',
              contract_path: 'crates/core/README.md',
              blake3_hash: 'def456',
              file_blake3_hash: 'fed789',
              effective_max_lines: 300,
              graph: mockGraph,
            })
          );
          return;
        }
        res.statusCode = 404;
        res.end(JSON.stringify({ status: 'error' }));
      }, async (_baseUrl, requests) => {
        const git = await api.getGitStatus();
        assert.equal(git.is_git_repo, true);
        assert.equal(git.branch, 'main');
        assert.equal(git.files[0].status, 'modified');

        const signRes = await api.signContracts({ project_path: '/tmp/proj' });
        assert.equal(signRes.status, 'ok');
        assert.equal(signRes.signed_count, 2);
        assert.equal(signRes.blake3_hash, 'abc123');
        assert.deepEqual(signRes.graph, mockGraph);

        const updRes = await api.updateContract({ project_path: '/tmp/proj', folder: 'crates/core' });
        assert.equal(updRes.status, 'ok');
        assert.equal(updRes.contract_path, 'crates/core/README.md');
        assert.equal(updRes.file_blake3_hash, 'fed789');
        assert.equal(updRes.effective_max_lines, 300);
        assert.equal(requests.length, 3);
      });
    });

    it('tier1_f9_api_file_crud_http_roundtrip', async () => {
      const api = await getApiClient();
      const mockGraph = { project_path: '/tmp/proj', nodes: [], edges: [], clusters: {} };

      await withMockHttpServer(async (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.method === 'GET' && req.path === '/api/file_content') {
          res.end(JSON.stringify({ status: 'ok', path: req.query.path, content: 'pub fn hello() {}' }));
          return;
        }
        if (req.method === 'POST' && req.path === '/api/save_file') {
          res.end(JSON.stringify({ status: 'ok', file_path: req.jsonBody.file_path, bytes_written: req.jsonBody.content.length }));
          return;
        }
        if (req.method === 'POST' && req.path === '/api/ai/create_file') {
          res.end(JSON.stringify({ status: 'ok', file_path: req.jsonBody.file_path, created_symbol: 'sym::new', graph: mockGraph }));
          return;
        }
        res.statusCode = 404;
        res.end('{}');
      }, async () => {
        const readRes = await api.getFileContent('src/lib.rs', true);
        assert.equal(readRes.status, 'ok');
        assert.equal(readRes.content, 'pub fn hello() {}');

        const saveRes = await api.saveFile('src/lib.rs', 'pub fn hello() { 1 }');
        assert.equal(saveRes.status, 'ok');
        assert.equal(saveRes.bytes_written, 20);

        const createRes = await api.createFile({ project_path: '/tmp/proj', file_path: 'src/new.rs', content: 'pub fn x() {}' });
        assert.equal(createRes.status, 'ok');
        assert.equal(createRes.created_symbol, 'sym::new');
      });
    });

    it('tier1_f9_mjs_test_scripts_relocated_to_ui_tests', () => {
      const rootMjs = fs.readdirSync(UI_ROOT).filter((f) => f.endsWith('.mjs'));
      assert.deepEqual(rootMjs, [], `No .mjs test scripts should remain at ui/ root: found ${rootMjs.join(', ')}`);

      const testsDir = path.join(UI_ROOT, 'tests');
      for (const expected of ['verify_header_bindings.mjs', 'empirical_stress_test.mjs', 'adversarial_challenge_m4.mjs']) {
        assert.ok(fs.existsSync(path.join(testsDir, expected)), `Expected ${expected} under ui/tests/`);
      }
    });

    it('tier1_f9_redos_safe_bounty_and_plugin_matchers', async () => {
      const { matchesWildcardPattern, tokenizeLine, escapeRegExp } = await ssrLoad('/src/components/bounty/bountyEngine.ts');
      const { compileSafePluginRegExp, evaluatePluginRulesInBrowser } = await ssrLoad('/src/lib/demoPlugins.ts');

      assert.equal(matchesWildcardPattern('crates/core/src/lib.rs', 'crates/*/src/*.rs'), true);
      assert.equal(matchesWildcardPattern('crates/core/tests/lib.rs', 'crates/*/src/*.rs'), false);
      assert.equal(escapeRegExp('a.b+c(d)?'), 'a\\.b\\+c\\(d\\)\\?');

      const sample = 'pub fn auth(token: "abc") -> bool { true }';
      assert.equal(tokenizeLine(sample).map((t) => t.text).join(''), sample);

      const safeRe = compileSafePluginRegExp('unsafe\\s*\\{');
      assert.ok(safeRe instanceof RegExp);

      const hits = evaluatePluginRulesInBrowser(
        'src/danger.rs',
        'fn raw() { unsafe { ptr::read(p) } }',
        [
          {
            id: 'TEST-UNSAFE',
            cwe_id: 'CWE-242',
            name: 'Unsafe Block',
            category: 'memory',
            severity: 'HIGH',
            description: 'Unsafe block',
            remediation: 'Avoid unsafe',
            file_extensions: ['rs'],
            match_mode: 'line_by_line',
            check_literals: false,
            must_contain: [],
            must_not_contain: [],
            regex_patterns: ['unsafe\\s*\\{'],
            forbidden_tokens: [],
            in_path_matching: [],
            not_in_path_matching: [],
            test_cases_count: 0,
          },
        ]
      );
      assert.equal(hits.length, 1);
      assert.equal(hits[0].cwe_id, 'CWE-242');
    });

    it('tier1_f9_pending_create_folder_prefill_contract', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);

      assert.ok('pendingCreateFolder' in cs, 'cockpitState must define pendingCreateFolder');
      assert.equal(cs.pendingCreateFolder, null);

      cs.pendingCreateFolder = 'crates/core/src';
      cs.isCreateFileModalOpen = true;
      const compiled = compileSvelteClient('src/components/CreateFileModal.svelte');
      assert.ok(compiled.js.code.length > 0, 'CreateFileModal.svelte must compile cleanly');

      const modalSrc = readUiSource('src/components/CreateFileModal.svelte');
      assert.ok(modalSrc.includes('pendingCreateFolder'), 'CreateFileModal must integrate cockpitState.pendingCreateFolder');
      assert.ok(/cockpitState\.pendingCreateFolder\s*=\s*null/.test(modalSrc), 'CreateFileModal must clear pendingCreateFolder on close/submit');

      const rendered = await renderComponent('/src/components/CreateFileModal.svelte');
      assert.ok(rendered.body.includes('role="dialog"'), 'CreateFileModal SSR must render dialog when open');
      assert.ok(rendered.body.includes('cf-rel-path'), 'CreateFileModal SSR must render relative path input');
    });
  });

  // ===========================================================================
  // F10 — IDE #1: Unified Editor + Syntax Overlay + Ctrl+F + Ctrl+H + Undo/Redo
  // ===========================================================================
  describe('F10: Unified Editor, Syntax Overlay, Ctrl+F, Ctrl+H & Undo/Redo', () => {
    it('tier1_f10_unified_syntax_overlay_rendered', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.openFileInIde('src/main.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('<textarea'), 'IdeEditor must render editable <textarea>');
      assert.ok(rendered.body.includes('text-transparent'), 'Unified editor <textarea> must use text-transparent over syntax backdrop');
      assert.ok(/caret-/.test(rendered.body), 'Unified editor <textarea> must preserve visible caret color class');
      assert.ok(rendered.body.includes('aria-hidden="true"') || /pointer-events-none/.test(rendered.body), 'Unified editor must render synchronized non-interactive syntax overlay backdrop in edit mode');
    });

    it('tier1_f10_line_height_whitespace_alignment', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.openFileInIde('src/main.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      const textareaMatch = rendered.body.match(/<textarea\b[^>]*>/);
      assert.ok(textareaMatch, 'Expected <textarea> element in IdeEditor SSR output');
      assert.ok(textareaMatch[0].includes('leading-[21px]'), '<textarea> must enforce exact leading-[21px] line height');
      assert.ok(textareaMatch[0].includes('whitespace-pre'), '<textarea> must enforce whitespace-pre');
      assert.equal(textareaMatch[0].includes('leading-relaxed'), false, '<textarea> must not use leading-relaxed');

      const leading21Count = (rendered.body.match(/leading-\[21px\]/g) || []).length;
      const whitespacePreCount = (rendered.body.match(/whitespace-pre/g) || []).length;
      assert.ok(leading21Count >= 2, 'Both <textarea> and syntax backdrop (and/or gutter) must share leading-[21px]');
      assert.ok(whitespacePreCount >= 2, 'Both <textarea> and syntax backdrop must share whitespace-pre');
    });

    it('tier1_f10_dual_scroll_sync_wired', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      const compiled = compileSvelteClient('src/components/ide/IdeEditor.svelte');
      assert.ok(compiled.js.code.length > 0);
      assert.ok(/\.scrollTop\s*=\s*target\.scrollTop|\.scrollTop\s*=/.test(combinedSource), 'Scroll handler must sync scrollTop');
      assert.ok(/\.scrollLeft\s*=\s*target\.scrollLeft|\.scrollLeft\s*=/.test(combinedSource), 'Scroll handler must sync scrollLeft across backdrop');
    });

    it('tier1_f10_ctrl_f_inline_highlights_contract', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      const ast = parseSvelte('src/components/ide/IdeEditor.svelte');
      assert.ok(ast.fragment, 'IdeEditor.svelte must parse cleanly');
      assert.ok(/searchMatches/.test(combinedSource), 'IdeEditor must compute searchMatches for Ctrl+F');
      // Verify inline match rendering in edit overlay (not just scrollToLine jump)
      const hasInlineMatchOverlay =
        /currentMatchIndex/.test(combinedSource) &&
        (/(mark|bg-amber|bg-yellow|bg-sky)/.test(combinedSource) && /(match|highlight|search)/i.test(combinedSource)) &&
        (/splitWithSearch|renderHighlightedLine|searchRanges|lineMatches|highlightSearch/i.test(combinedSource) ||
          /searchMatches[\s\S]{0,600}charIndex/.test(combinedSource));
      assert.ok(hasInlineMatchOverlay, 'Ctrl+F must highlight matched substrings inline inside the unified editor backdrop');
    });

    it('tier1_f10_ctrl_h_find_and_replace_contract', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      const hasCtrlH = /key\.toLowerCase\(\)\s*===\s*['"]h['"]|=== ['"]h['"]|=== ['"]H['"]/.test(combinedSource);
      assert.ok(hasCtrlH, 'IdeEditor must bind Ctrl+H / Cmd+H for Find & Replace');
      const hasReplaceLogic =
        /replaceQuery|replaceText|replaceValue/i.test(combinedSource) &&
        /replaceCurrent|replaceOne|replaceAll|Tout remplacer|Remplacer/i.test(combinedSource);
      assert.ok(hasReplaceLogic, 'IdeEditor must provide Find & Replace state and single/all replace actions');
    });

    it('tier1_f10_per_buffer_undo_redo_stacks', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/undoStack/.test(combinedSource), 'Buffer model must track per-buffer undoStack');
      assert.ok(/redoStack/.test(combinedSource), 'Buffer model must track per-buffer redoStack');
      const hasUndoRedoKeys =
        /key\.toLowerCase\(\)\s*===\s*['"]z['"]/.test(combinedSource) &&
        (/key\.toLowerCase\(\)\s*===\s*['"]y['"]/.test(combinedSource) || /shiftKey/.test(combinedSource));
      assert.ok(hasUndoRedoKeys, 'IdeEditor must bind Ctrl+Z and Ctrl+Shift+Z / Ctrl+Y for Undo/Redo');
    });
  });

  // ===========================================================================
  // F11 — IDE #2: Inline SAST/CWE Gutter & Error Lens + Quick Remediation
  // ===========================================================================
  describe('F11: Inline SAST/CWE Gutter & Error Lens + Quick Remediation', () => {
    it('tier1_f11_gutter_marks_exact_cwe_line', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const node = makeNode({
        id: 'sym::auth',
        name: 'verify_sql',
        file_path: 'src/auth.rs',
        line_number: 1,
        has_security_violation: true,
        anomalies: [
          {
            rule_id: 'CWE-89',
            cve_id: 'CWE-89',
            severity: 'CRITICAL',
            line_number: 1,
            message: 'Unsanitized SQL query',
            remediation: 'Use bind parameters',
            file_path: 'src/auth.rs',
          },
        ],
      });
      cs.setGraph({ project_path: '/workspace', nodes: [node], edges: [], clusters: {} }, false);
      cs.openFileInIde('src/auth.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('CWE-89'), 'IdeEditor SSR must mark CWE-89 on line 1');
      assert.ok(/gutter|data-cwe|CWE-89/.test(rendered.body) && /rose-|red-/.test(rendered.body), 'Gutter/line 1 must render severity marker styling');
    });

    it('tier1_f11_error_lens_inline_badge_rendered', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const node = makeNode({
        id: 'sym::sql',
        file_path: 'src/db.rs',
        line_number: 1,
        has_security_violation: true,
        anomalies: [
          {
            rule_id: 'CWE-89',
            cve_id: 'CWE-89',
            severity: 'HIGH',
            line_number: 1,
            message: 'SQL injection sink detected',
            remediation: 'Use prepared statements',
            file_path: 'src/db.rs',
          },
        ],
      });
      cs.setGraph({ project_path: '/workspace', nodes: [node], edges: [], clusters: {} }, false);
      cs.openFileInIde('src/db.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('CWE-89'), 'Error Lens must render CWE-89 ID inline');
      assert.ok(rendered.body.includes('SQL injection sink detected'), 'Error Lens must render diagnostic message inline');
    });

    it('tier1_f11_windows_posix_path_matching', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const node = makeNode({
        id: 'sym::win',
        file_path: 'crates\\api\\src\\db.rs',
        line_number: 1,
        has_security_violation: true,
        anomalies: [
          {
            rule_id: 'CWE-78',
            cve_id: 'CWE-78',
            severity: 'CRITICAL',
            line_number: 1,
            message: 'OS command injection',
            file_path: 'crates\\api\\src\\db.rs',
          },
        ],
      });
      cs.setGraph({ project_path: '/workspace', nodes: [node], edges: [], clusters: {} }, false);
      cs.openFileInIde('crates/api/src/db.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('CWE-78'), 'Windows backslash path must match POSIX ideActiveFile');
    });

    it('tier1_f11_ignored_cwe_suppressed', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const node = makeNode({
        id: 'sym::ign',
        file_path: 'src/auth.rs',
        line_number: 1,
        has_security_violation: true,
        anomalies: [
          {
            rule_id: 'CWE-89',
            cve_id: 'CWE-89',
            severity: 'CRITICAL',
            line_number: 1,
            message: 'SQL injection sink',
            file_path: 'src/auth.rs',
          },
        ],
      });
      cs.setGraph({ project_path: '/workspace', nodes: [node], edges: [], clusters: {} }, false);
      cs.openFileInIde('src/auth.rs', 1);

      const before = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(before.body.includes('CWE-89'), 'CWE-89 must appear before ignoring');

      cs.ignoreCweRule('CWE-89');
      const after = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.equal(after.body.includes('SQL injection sink'), false, 'Ignored CWE-89 diagnostic must be suppressed');
    });

    it('tier1_f11_quick_remediation_actions_present', async () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/ignoreCweRule/.test(combinedSource), 'Error Lens quick remediation must wire ignoreCweRule');
      assert.ok(
        /openPromptModal|createTask|sendChatMessage|isChatOpen/.test(combinedSource),
        'Error Lens quick remediation must wire AI fix action'
      );
      assert.ok(
        /isInspectorOpen\s*=\s*true|selectSymbol/.test(combinedSource),
        'Error Lens quick remediation must wire Inspector jump action'
      );
    });

    it('tier1_f11_severity_styling_critical_vs_medium', async () => {
      const cs = await getCockpitState();

      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::crit',
              file_path: 'src/crit.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [{ rule_id: 'CWE-89', severity: 'CRITICAL', line_number: 1, message: 'Critical bug', file_path: 'src/crit.rs' }],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/crit.rs', 1);
      const critHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(critHtml.includes('CWE-89') && /rose-|red-/.test(critHtml), 'CRITICAL anomaly must render rose/red severity styling');

      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::med',
              file_path: 'src/med.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [{ rule_id: 'CWE-327', severity: 'MEDIUM', line_number: 1, message: 'Weak crypto', file_path: 'src/med.rs' }],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/med.rs', 1);
      const medHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(medHtml.includes('CWE-327') && /amber-|yellow-/.test(medHtml), 'MEDIUM anomaly must render amber/yellow severity styling');
    });
  });

  // ===========================================================================
  // F12 — IDE #3: AST Breadcrumbs & 1-Click Call-Graph
  // ===========================================================================
  describe('F12: AST Breadcrumbs & 1-Click Call-Graph', () => {
    it('tier1_f12_breadcrumb_detects_enclosing_symbol', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({ id: 'file::net', name: 'net.rs', kind: 'File', is_file: true, file_path: 'src/net.rs', line_number: 1 }),
            makeNode({ id: 'sym::alpha', name: 'alpha', kind: 'Function', file_path: 'src/net.rs', line_number: 10 }),
            makeNode({ id: 'sym::beta', name: 'beta', kind: 'Function', file_path: 'src/net.rs', line_number: 40 }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/net.rs', 22);
      cs.ideCursorPosition = { line: 22, ch: 1 };

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('net.rs'), 'Breadcrumb must include file path segment');
      assert.ok(rendered.body.includes('alpha'), 'Breadcrumb at line 22 must detect enclosing symbol alpha (L10)');
      assert.equal(rendered.body.includes('beta'), false, 'Breadcrumb at line 22 must not select later symbol beta (L40)');
    });

    it('tier1_f12_breadcrumb_tracks_cursor_movement', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({ id: 'sym::alpha', name: 'alpha', kind: 'Function', file_path: 'src/net.rs', line_number: 10 }),
            makeNode({ id: 'sym::beta', name: 'beta', kind: 'Function', file_path: 'src/net.rs', line_number: 40 }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/net.rs', 45);
      cs.ideCursorPosition = { line: 45, ch: 4 };

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('beta'), 'Moving cursor to line 45 must update breadcrumb to beta');
    });

    it('tier1_f12_callers_callees_counts_via_incident_edges', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({ id: 'sym::caller1', name: 'caller_one', file_path: 'src/entry.rs', line_number: 5 }),
            makeNode({ id: 'sym::alpha', name: 'alpha', file_path: 'src/net.rs', line_number: 10 }),
            makeNode({ id: 'sym::callee1', name: 'callee_one', file_path: 'src/db.rs', line_number: 12 }),
            makeNode({ id: 'sym::callee2', name: 'callee_two', file_path: 'src/log.rs', line_number: 3 }),
          ],
          edges: [
            { source: 'sym::caller1', target: 'sym::alpha', relation: 'calls' },
            { source: 'sym::alpha', target: 'sym::callee1', relation: 'calls' },
            { source: 'sym::alpha', target: 'sym::callee2', relation: 'calls' },
          ],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/net.rs', 15);
      cs.ideCursorPosition = { line: 15, ch: 1 };

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('Appelants'), 'Breadcrumb bar must show Appelants control');
      assert.ok(rendered.body.includes('Appelés'), 'Breadcrumb bar must show Appelés control');
      assert.ok(/Appelants[\s\S]{0,120}\b1\b/.test(rendered.body), 'Appelants count must equal 1');
      assert.ok(/Appelés[\s\S]{0,120}\b2\b/.test(rendered.body), 'Appelés count must equal 2');
    });

    it('tier1_f12_caller_callee_1_click_jump_wired', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/incidentEdges/.test(combinedSource), 'Call-graph breadcrumb must resolve callers/callees via cockpitState.incidentEdges');
      assert.ok(/openFileInIde/.test(combinedSource), '1-click caller/callee jump must invoke cockpitState.openFileInIde');
    });

    it('tier1_f12_cibler_en_3d_button_rendered_and_wired', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'sym::alpha', name: 'alpha', file_path: 'src/net.rs', line_number: 10 })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/net.rs', 12);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('Cibler en 3D'), 'Breadcrumb strip must render Cibler en 3D button');

      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/requestFocusSymbol/.test(combinedSource), 'Cibler en 3D must invoke cockpitState.requestFocusSymbol');
    });

    it('tier1_f12_nested_method_breadcrumb', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::repo',
              name: 'UserRepo',
              kind: 'ClassOrStruct',
              is_class: true,
              file_path: 'src/repo.rs',
              line_number: 5,
              methods: [
                { name: 'validate', line: 12 },
                { name: 'save', line: 30 },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/repo.rs', 18);
      cs.ideCursorPosition = { line: 18, ch: 1 };

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('UserRepo'), 'Nested breadcrumb must include parent struct/class UserRepo');
      assert.ok(rendered.body.includes('validate'), 'Nested breadcrumb at line 18 must include enclosing method validate');
      assert.equal(rendered.body.includes('save'), false, 'Nested breadcrumb at line 18 must not select save (L30)');
    });
  });

  // ===========================================================================
  // F13 — IDE #6: EARS & BLAKE3 Firewall Status Bar
  // ===========================================================================
  describe('F13: EARS & BLAKE3 Firewall Status Bar', () => {
    it('tier1_f13_ears_line_budget_gauge_rendered', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'file::fw',
              name: 'firewall.rs',
              kind: 'File',
              is_file: true,
              file_path: 'src/firewall.rs',
              loc: 42,
              metadata: { max_lines_limit: 250 },
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/firewall.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(/\/\s*250\s*L\b/.test(rendered.body), 'Status bar must render EARS line budget gauge `/ 250 L`');
    });

    it('tier1_f13_clean_file_shows_0_cwe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'file::clean', kind: 'File', is_file: true, file_path: 'src/clean.rs', anomalies: [] })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/clean.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(/\b0\s*CWE\b/.test(rendered.body), 'Clean file status bar must render `0 CWE`');
    });

    it('tier1_f13_vulnerable_file_shows_n_cwe', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({
              id: 'sym::v',
              file_path: 'src/vuln.rs',
              line_number: 1,
              has_security_violation: true,
              anomalies: [
                { rule_id: 'CWE-89', severity: 'CRITICAL', line_number: 1, message: 'sqli', file_path: 'src/vuln.rs' },
                { rule_id: 'CWE-78', severity: 'HIGH', line_number: 1, message: 'cmdi', file_path: 'src/vuln.rs' },
                { rule_id: 'CWE-79', severity: 'MEDIUM', line_number: 1, message: 'xss', file_path: 'src/vuln.rs' },
              ],
            }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/vuln.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(/\b3\s*CWE\b/.test(rendered.body), 'Status bar must render real-time active-file counter `3 CWE`');
    });

    it('tier1_f13_active_ai_agents_shown_for_file', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'file::fw', name: 'firewall.rs', kind: 'File', is_file: true, file_path: 'src/firewall.rs' })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.activeAgents = [
        {
          agentId: 'ag-claude',
          agentName: 'ClaudeGuard',
          target: 'src/firewall.rs',
          nodeId: 'file::fw',
          color: '#38bdf8',
          timestamp: Date.now(),
          action: 'editing',
        },
      ];
      cs.openFileInIde('src/firewall.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('ClaudeGuard'), 'Status bar must show active AI agent targeting the active file');
    });

    it('tier1_f13_sceller_blake3_button_rendered', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'file::fw', kind: 'File', is_file: true, file_path: 'src/firewall.rs' })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.openFileInIde('src/firewall.rs', 1);

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('Sceller BLAKE3'), 'Status bar must render `Sceller BLAKE3` action button');
    });

    it('tier1_f13_seal_contract_api_roundtrip_updates_graph', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const api = await getApiClient();

      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/signContracts|updateContract/.test(combinedSource), 'Sceller BLAKE3 must invoke contract seal API');

      const initialNode = makeNode({
        id: 'file::fw',
        kind: 'File',
        is_file: true,
        file_path: 'src/firewall.rs',
        metadata: { max_lines_limit: 250, lock_verified: false, blake3_hash: 'old' },
      });
      cs.setGraph({ project_path: '/workspace', nodes: [initialNode], edges: [], clusters: {} }, false);

      const sealedGraph = {
        project_path: '/workspace',
        nodes: [
          makeNode({
            id: 'file::fw',
            kind: 'File',
            is_file: true,
            file_path: 'src/firewall.rs',
            metadata: { max_lines_limit: 250, lock_verified: true, blake3_hash: 'sealed999' },
          }),
        ],
        edges: [],
        clusters: {},
      };

      await withMockHttpServer(async (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.method === 'POST' && req.path === '/api/contracts/sign') {
          res.end(JSON.stringify({ status: 'ok', message: 'Sealed', signed_count: 1, blake3_hash: 'sealed999', graph: sealedGraph }));
          return;
        }
        res.statusCode = 404;
        res.end('{}');
      }, async () => {
        const res = await api.signContracts({ project_path: '/workspace' });
        assert.equal(res.status, 'ok');
        cs.setGraph(res.graph, true);
        const updated = cs.getNodeById('file::fw');
        assert.equal(updated.metadata.lock_verified, true);
        assert.equal(updated.metadata.blake3_hash, 'sealed999');
        assert.equal(updated.metadata.max_lines_limit, 250, 'Sealing BLAKE3 must preserve existing max_lines_limit');
      });
    });
  });

  // ===========================================================================
  // F14 — IDE #5: Live Git Integration & Quick File Actions
  // ===========================================================================
  describe('F14: Live Git Integration & Quick File Actions', () => {
    it('tier1_f14_tree_git_badges', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [
            makeNode({ id: 'f1', is_file: true, kind: 'File', file_path: 'src/mod.rs' }),
            makeNode({ id: 'f2', is_file: true, kind: 'File', file_path: 'src/add.rs' }),
            makeNode({ id: 'f3', is_file: true, kind: 'File', file_path: 'src/new.rs' }),
          ],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.gitStatus = {
        is_git_repo: true,
        branch: 'main',
        clean: false,
        files: [
          { path: 'src/mod.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/add.rs', status: 'staged', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/new.rs', status: 'untracked', has_security_violation: false, cwe_count: 0, ears_violation: false },
        ],
        modified_count: 1,
        untracked_count: 1,
        staged_count: 1,
        deleted_count: 0,
        security_alert_count: 0,
      };

      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte');
      assert.ok(/gitStatus/.test(combinedSource), 'IdeFileTree must consume cockpitState.gitStatus');
      assert.ok(/['"]M['"]/.test(combinedSource) && /['"]A['"]/.test(combinedSource) && /['"]\?['"]/.test(combinedSource), 'IdeFileTree must map Git statuses to M, A, ? badges');

      const compiled = compileSvelteClient('src/components/ide/IdeFileTree.svelte');
      assert.ok(compiled.js.code.length > 0);
    });

    it('tier1_f14_directory_git_rollup', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte');
      assert.ok(/gitStatus/.test(combinedSource), 'IdeFileTree must compute Git state from cockpitState.gitStatus');
      const hasRollup =
        /hasGitChanges|gitChanged|gitBadge|gitStatusByDir|gitCount|gitRollup|dirGit/i.test(combinedSource) ||
        /children[\s\S]{0,400}git/i.test(combinedSource);
      assert.ok(hasRollup, 'IdeFileTree must roll up Git status indicators to parent directory nodes');
    });

    it('tier1_f14_editor_tab_git_badges', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.gitStatus = {
        is_git_repo: true,
        branch: 'main',
        clean: false,
        files: [
          { path: 'src/mod.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/add.rs', status: 'staged', has_security_violation: false, cwe_count: 0, ears_violation: false },
          { path: 'src/new.rs', status: 'untracked', has_security_violation: false, cwe_count: 0, ears_violation: false },
        ],
        modified_count: 1,
        untracked_count: 1,
        staged_count: 1,
        deleted_count: 0,
        security_alert_count: 0,
      };
      cs.openFileInIde('src/mod.rs');
      cs.openFileInIde('src/add.rs');
      cs.openFileInIde('src/new.rs');
      cs.openFileInIde('src/clean.rs');

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/gitStatus/.test(combinedSource), 'IdeEditor tabs must read cockpitState.gitStatus');

      // Extract open tab blocks and verify M, A, ? badges render on the matching tabs
      const modTab = rendered.body.match(/title="src\/mod\.rs[^"]*"[\s\S]{0,600}?<\/button>/);
      const addTab = rendered.body.match(/title="src\/add\.rs[^"]*"[\s\S]{0,600}?<\/button>/);
      const newTab = rendered.body.match(/title="src\/new\.rs[^"]*"[\s\S]{0,600}?<\/button>/);
      assert.ok(modTab && /\bM\b/.test(modTab[0]), 'Modified tab src/mod.rs must display M Git badge');
      assert.ok(addTab && /\bA\b/.test(addTab[0]), 'Staged/added tab src/add.rs must display A Git badge');
      assert.ok(newTab && />\s*\?\s*</.test(newTab[0]), 'Untracked tab src/new.rs must display ? Git badge');
    });

    it('tier1_f14_git_modified_only_filter', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const rendered = await renderComponent('/src/components/ide/IdeFileTree.svelte');
      assert.ok(
        /Fichiers modifiés Git uniquement/i.test(rendered.body),
        'IdeFileTree must render "Fichiers modifiés Git uniquement" filter toggle'
      );
    });

    it('tier1_f14_plus_new_file_in_folder', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte');
      assert.ok(/pendingCreateFolder/.test(combinedSource), 'IdeFileTree `+` folder action must set cockpitState.pendingCreateFolder');
      assert.ok(/isCreateFileModalOpen\s*=\s*true/.test(combinedSource), 'IdeFileTree `+` folder action must open CreateFileModal');
    });

    it('tier1_f14_copy_relative_path', () => {
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte');
      assert.ok(/clipboard\.writeText/.test(combinedSource), 'IdeFileTree must provide Copy relative path via navigator.clipboard.writeText');
    });
  });

  // ===========================================================================
  // F15 — IDE #4: Mini-Hub Radar / Local Constellation PiP
  // ===========================================================================
  describe('F15: Mini-Hub Radar / Local Constellation PiP', () => {
    it('tier1_f15_pip_toggle_in_ide', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.viewMode = 'ide';
      cs.engine = null;

      const rendered = await renderComponent('/src/components/ide/IdeView.svelte');
      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeView.svelte');
      const hasPip = /Radar|Constellation|PiP|showRadar|showConstellation/i.test(rendered.body) &&
        /RadarMinimap|Constellation|Pip/i.test(combinedSource);
      assert.ok(hasPip, 'IdeView must host a toggleable Mini-Hub Radar / Local Constellation PiP without requiring WebGL engine');
    });

    it('tier1_f15_local_mode_centers_active_symbol', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const symMid = makeNode({ id: 'sym::mid', name: 'process_order', file_path: 'src/order.rs', line_number: 25 });
      cs.setGraph({ project_path: '/workspace', nodes: [symMid], edges: [], clusters: {} }, false);
      cs.activeSymbol = symMid;
      cs.viewMode = 'ide';
      cs.openFileInIde('src/order.rs', 25);

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      const ideHtml = (await renderComponent('/src/components/ide/IdeView.svelte')).body;
      assert.ok(
        radarHtml.includes('process_order') || ideHtml.includes('process_order'),
        'Local constellation PiP must center on and display active symbol name even when engine is null'
      );
    });

    it('tier1_f15_callers_and_callees_constellation', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const callerA = makeNode({ id: 'sym::callerA', name: 'caller_http', file_path: 'src/http.rs', line_number: 8 });
      const symMid = makeNode({ id: 'sym::mid', name: 'core_handler', file_path: 'src/core.rs', line_number: 20 });
      const calleeB = makeNode({ id: 'sym::calleeB', name: 'db_write', file_path: 'src/db.rs', line_number: 42 });
      const calleeC = makeNode({ id: 'sym::calleeC', name: 'emit_audit', file_path: 'src/audit.rs', line_number: 15 });
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [callerA, symMid, calleeB, calleeC],
          edges: [
            { source: 'sym::callerA', target: 'sym::mid', relation: 'calls' },
            { source: 'sym::mid', target: 'sym::calleeB', relation: 'calls' },
            { source: 'sym::mid', target: 'sym::calleeC', relation: 'calls' },
          ],
          clusters: {},
        },
        false
      );
      cs.activeSymbol = symMid;
      cs.viewMode = 'ide';
      cs.openFileInIde('src/core.rs', 20);

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      const ideHtml = (await renderComponent('/src/components/ide/IdeView.svelte')).body;
      const combined = radarHtml + '\n' + ideHtml;
      assert.ok(combined.includes('caller_http'), 'Local constellation must display incoming caller');
      assert.ok(combined.includes('db_write') && combined.includes('emit_audit'), 'Local constellation must display outgoing callees');
    });

    it('tier1_f15_active_ai_agents_overlay', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      const symMid = makeNode({ id: 'sym::mid', name: 'core_handler', file_path: 'src/core.rs', line_number: 20 });
      const calleeB = makeNode({ id: 'sym::calleeB', name: 'db_write', file_path: 'src/db.rs', line_number: 42 });
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [symMid, calleeB],
          edges: [{ source: 'sym::mid', target: 'sym::calleeB', relation: 'calls' }],
          clusters: {},
        },
        false
      );
      cs.activeSymbol = symMid;
      cs.activeAgents = [
        {
          agentId: 'ag-nova',
          agentName: 'AgentNova',
          target: 'sym::calleeB',
          nodeId: 'sym::calleeB',
          color: '#38bdf8',
          timestamp: Date.now(),
          action: 'analyzing',
        },
      ];
      cs.viewMode = 'ide';

      const radarHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      const ideHtml = (await renderComponent('/src/components/ide/IdeView.svelte')).body;
      assert.ok(
        radarHtml.includes('AgentNova') || ideHtml.includes('AgentNova'),
        'Local constellation PiP must surface active AI agents targeting local symbols'
      );
    });

    it('tier1_f15_one_click_jump_to_neighbor', () => {
      const radarBundle = collectComponentBundleSource('src/components/RadarMinimap.svelte').combinedSource;
      const ideViewBundle = collectComponentBundleSource('src/components/ide/IdeView.svelte').combinedSource;
      const combined = radarBundle + '\n' + ideViewBundle;
      assert.ok(
        /openFileInIde|selectSymbol|openInIde/.test(combined),
        'PiP constellation must wire 1-click neighbor jump via openFileInIde / selectSymbol'
      );
    });

    it('tier1_f15_global_vs_local_mode_switch', async () => {
      const cs = await getCockpitState();
      resetCockpitState(cs);
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [makeNode({ id: 'sym::mid', name: 'core_handler', file_path: 'src/core.rs', line_number: 20 })],
          edges: [],
          clusters: {},
        },
        false
      );
      cs.activeSymbol = cs.graph.nodes[0];

      const localHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      const globalHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'global' })).body;
      assert.ok(localHtml.length > 0 && globalHtml.length > 0, 'Both local and global modes must render cleanly when engine is null');

      const radarSrc = collectComponentBundleSource('src/components/RadarMinimap.svelte').combinedSource;
      const ideViewSrc = collectComponentBundleSource('src/components/ide/IdeView.svelte').combinedSource;
      const hasModeSwitch = /['"]local['"][\s\S]*['"]global['"]|['"]global['"][\s\S]*['"]local['"]/.test(radarSrc + '\n' + ideViewSrc);
      assert.ok(hasModeSwitch, 'PiP Radar / RadarMinimap must support switching between local and global modes');
    });
  });
});
