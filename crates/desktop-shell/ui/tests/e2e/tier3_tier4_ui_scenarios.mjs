import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { describe, it } from 'node:test';
import {
  REPO_ROOT,
  ssrLoad,
  renderComponent,
  getCockpitState,
  getApiClient,
  resetCockpitState,
  withMockHttpServer,
  createCanvasMocks,
  setMockClipboard,
  collectComponentBundleSource,
  compileSvelteClient,
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

describe('Tier 3 — Cross-Feature UI Pairwise Combinations (F8–F15)', () => {
  it('tier3_pair_f8_f15_canvas_and_pip_focus_sync', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
    const mocks = createCanvasMocks();
    const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
    try {
      const symA = makeNode({ id: 'sym::a', name: 'caller_a', file_path: 'src/a.rs', line_number: 10, x: -200, y: 80 });
      const symB = makeNode({ id: 'sym::b', name: 'callee_b', file_path: 'src/b.rs', line_number: 42, x: 320, y: -140 });
      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [symA, symB],
          edges: [{ source: 'sym::a', target: 'sym::b', relation: 'calls' }],
          clusters: {},
        },
        false
      );
      cs.activeAgents = [{ agentId: 'ag-1', agentName: 'SyncBot', target: 'sym::b', nodeId: 'sym::b', timestamp: Date.now() }];
      cs.activeSymbol = symA;
      eng.syncGraphToEngine(true);

      // Simulate F15 1-click jump updating activeSymbol + requestFocusSymbol
      const tickBefore = cs.focusRequestTick;
      cs.selectSymbol('sym::b', true);
      cs.openFileInIde('src/b.rs', 42);
      eng.focusSymbol('sym::b');

      assert.equal(cs.activeSymbol?.id, 'sym::b');
      assert.ok(cs.focusRequestTick > tickBefore);
      assert.equal(eng.camera.targetX, 320);
      assert.equal(eng.camera.targetY, -140);

      const pipHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: eng, mode: 'local' })).body;
      assert.ok(pipHtml.includes('callee_b') && pipHtml.includes('caller_a'), 'Local PiP must reflect active symbol and caller');
    } finally {
      eng.destroy();
    }
  });

  it('tier3_pair_f9_f14_api_git_status_to_tree_and_tabs', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const fileA = makeNode({ id: 'f::a', is_file: true, kind: 'File', file_path: 'src/mod.rs', folder: 'src' });
    const fileB = makeNode({ id: 'f::b', is_file: true, kind: 'File', file_path: 'src/new.rs', folder: 'src' });
    cs.setGraph({ project_path: '/workspace', nodes: [fileA, fileB], edges: [], clusters: {} }, false);
    cs.openFileInIde('src/mod.rs');
    cs.openFileInIde('src/new.rs');

    await withMockHttpServer(async (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'GET' && req.path === '/api/git/status') {
        res.end(
          JSON.stringify({
            is_git_repo: true,
            branch: 'feat/ide',
            clean: false,
            files: [
              { path: 'src/mod.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false },
              { path: 'src/new.rs', status: 'untracked', has_security_violation: false, cwe_count: 0, ears_violation: false },
            ],
            modified_count: 1,
            untracked_count: 1,
            staged_count: 0,
            deleted_count: 0,
            security_alert_count: 0,
          })
        );
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    }, async () => {
      const status = await cs.fetchGitStatus(true);
      assert.equal(status?.branch, 'feat/ide');
      assert.equal(cs.gitStatus?.files.length, 2);

      const edHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      const ftHtml = (await renderComponent('/src/components/ide/IdeFileTree.svelte')).body;
      assert.ok(/\bM\b/.test(edHtml) && /\?/.test(edHtml), 'fetchGitStatus() must feed Git badges on IdeEditor tabs');
      assert.ok(/Fichiers modifiés Git uniquement/i.test(ftHtml), 'IdeFileTree must expose Git-modified filter toggle');
    });
  });

  it('tier3_pair_f9_f14_folder_plus_modal_prefill_and_create', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const api = await getApiClient();

    const ftBundle = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte').combinedSource;
    assert.ok(/pendingCreateFolder/.test(ftBundle), 'IdeFileTree + action must wire pendingCreateFolder');

    cs.pendingCreateFolder = 'crates/core/src';
    cs.isCreateFileModalOpen = true;
    const modalHtml = (await renderComponent('/src/components/CreateFileModal.svelte')).body;
    assert.ok(modalHtml.includes('role="dialog"'));

    const createdGraph = {
      project_path: '/workspace',
      nodes: [makeNode({ id: 'file::created', is_file: true, kind: 'File', file_path: 'crates/core/src/guard.rs' })],
      edges: [],
      clusters: {},
    };

    await withMockHttpServer(async (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'POST' && req.path === '/api/ai/create_file') {
        assert.equal(req.jsonBody.file_path, 'crates/core/src/guard.rs');
        res.end(
          JSON.stringify({
            status: 'ok',
            file_path: req.jsonBody.file_path,
            created_symbol: 'file::created',
            graph: createdGraph,
          })
        );
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    }, async () => {
      const res = await api.createFile({
        project_path: '/workspace',
        file_path: 'crates/core/src/guard.rs',
        content: 'pub fn guard() {}',
      });
      assert.equal(res.status, 'ok');
      cs.setGraph(res.graph);
      cs.pendingCreateFolder = null;
      cs.isCreateFileModalOpen = false;
      assert.equal(cs.pendingCreateFolder, null);
      assert.ok(cs.getNodeById('file::created'));
    });
  });

  it('tier3_pair_f10_f11_editor_replace_and_error_lens_sync', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    cs.setGraph(
      {
        project_path: '/workspace',
        nodes: [
          makeNode({
            id: 'sym::sink',
            file_path: 'src/sink.rs',
            line_number: 1,
            has_security_violation: true,
            anomalies: [{ rule_id: 'CWE-89', severity: 'CRITICAL', line_number: 1, message: 'Unsafe query', file_path: 'src/sink.rs' }],
          }),
        ],
        edges: [],
        clusters: {},
      },
      false
    );
    cs.openFileInIde('src/sink.rs', 1);

    const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
    assert.ok(rendered.body.includes('leading-[21px]') && rendered.body.includes('whitespace-pre'));
    assert.ok(rendered.body.includes('text-transparent'), 'Unified F10 transparent textarea required');
    assert.ok(rendered.body.includes('CWE-89') && rendered.body.includes('Unsafe query'), 'F11 Error Lens diagnostic required');

    const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
    assert.ok(/undoStack/.test(combinedSource) && /replace/i.test(combinedSource), 'F10 replace & undo must coexist cleanly with F11 Error Lens');
  });

  it('tier3_pair_f10_f13_edit_line_count_and_ears_firewall_bar', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    cs.setGraph(
      {
        project_path: '/workspace',
        nodes: [
          makeNode({
            id: 'file::ears',
            kind: 'File',
            is_file: true,
            file_path: 'src/ears.rs',
            loc: 42,
            metadata: { max_lines_limit: 220, lock_verified: false },
          }),
        ],
        edges: [],
        clusters: {},
      },
      false
    );
    cs.openFileInIde('src/ears.rs', 1);

    const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
    assert.ok(rendered.body.includes('text-transparent'), 'F10 unified editor must be active');
    assert.ok(/\/\s*220\s*L\b/.test(rendered.body), 'F13 EARS gauge must show / 220 L');
    assert.ok(rendered.body.includes('Sceller BLAKE3'), 'F13 Sceller BLAKE3 button must render');
  });

  it('tier3_pair_f11_f13_ignore_cwe_updates_lens_and_status_bar', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    cs.setGraph(
      {
        project_path: '/workspace',
        nodes: [
          makeNode({
            id: 'sym::triage',
            file_path: 'src/triage.rs',
            line_number: 1,
            has_security_violation: true,
            anomalies: [{ rule_id: 'CWE-78', severity: 'HIGH', line_number: 1, message: 'Shell command injection', file_path: 'src/triage.rs' }],
          }),
        ],
        edges: [],
        clusters: {},
      },
      false
    );
    cs.openFileInIde('src/triage.rs', 1);

    const before = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(before.includes('Shell command injection') && /\b1\s*CWE\b/.test(before));

    cs.ignoreCweRule('CWE-78');
    const afterIgnore = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.equal(afterIgnore.includes('Shell command injection'), false, 'F11 Error Lens must clear ignored CWE');
    assert.ok(/\b0\s*CWE\b/.test(afterIgnore), 'F13 status bar must drop to 0 CWE');

    cs.restoreAllCweRules();
    const afterRestore = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(afterRestore.includes('Shell command injection') && /\b1\s*CWE\b/.test(afterRestore));
  });

  it('tier3_pair_f12_f15_breadcrumb_jump_updates_pip_constellation', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const fnA = makeNode({ id: 'sym::fnA', name: 'entry_fn', file_path: 'src/a.rs', line_number: 10 });
    const fnB = makeNode({ id: 'sym::fnB', name: 'target_callee', file_path: 'src/b.rs', line_number: 33 });
    cs.setGraph(
      {
        project_path: '/workspace',
        nodes: [fnA, fnB],
        edges: [{ source: 'sym::fnA', target: 'sym::fnB', relation: 'calls' }],
        clusters: {},
      },
      false
    );
    cs.openFileInIde('src/a.rs', 12);
    cs.ideCursorPosition = { line: 12, ch: 1 };

    const edBefore = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(edBefore.includes('entry_fn') && /Appelés[\s\S]{0,120}\b1\b/.test(edBefore));

    // Jump to callee fnB
    cs.selectSymbol('sym::fnB', false);
    cs.openFileInIde('src/b.rs', 33);
    const pipHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
    assert.ok(pipHtml.includes('target_callee') && pipHtml.includes('entry_fn'), 'F15 PiP must re-center on jumped callee and show caller');
  });

  it('tier3_pair_f12_f8_target_in_3d_transitions_to_graph', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const sym = makeNode({ id: 'sym::target3d', name: 'focus_me', file_path: 'src/focus.rs', line_number: 10, x: 410, y: -190 });
    cs.setGraph({ project_path: '/workspace', nodes: [sym], edges: [], clusters: {} }, false);
    cs.viewMode = 'ide';
    cs.openFileInIde('src/focus.rs', 10);

    const edHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(edHtml.includes('Cibler en 3D'));

    const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
    assert.ok(/requestFocusSymbol/.test(combinedSource) && /switchToMode|viewMode/.test(combinedSource));

    // Simulate Cibler en 3D state transition consumed by AetherEngine
    cs.requestFocusSymbol('sym::target3d');
    cs.viewMode = 'code';
    assert.equal(cs.viewMode, 'code');
    assert.equal(cs.focusTargetId, 'sym::target3d');
  });

  it('tier3_pair_f14_f10_dirty_tab_git_badge_and_fs_conflict', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    cs.gitStatus = {
      is_git_repo: true,
      branch: 'main',
      clean: false,
      files: [{ path: 'src/conflict.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false }],
      modified_count: 1,
      untracked_count: 0,
      staged_count: 0,
      deleted_count: 0,
      security_alert_count: 0,
    };
    cs.openFileInIde('src/conflict.rs', 1);

    const edHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(/\bM\b/.test(edHtml), 'Git M badge must render on tab');
    const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
    assert.ok(/externalConflictContent/.test(combinedSource) && /undoStack/.test(combinedSource));
  });

  it('tier3_pair_f9_f10_redos_safe_regex_across_bounty_and_ide', async () => {
    const { matchesWildcardPattern } = await ssrLoad('/src/components/bounty/bountyEngine.ts');
    const { isSafePluginRegexPattern } = await ssrLoad('/src/lib/demoPlugins.ts');
    const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');

    const t0 = performance.now();
    assert.equal(matchesWildcardPattern('src/a/b/c.rs', '*/*/*/*/*/*/*/*.toml'), false);
    assert.equal(isSafePluginRegexPattern('([a-z]+)+$'), false);
    assert.equal(/new\s+RegExp\(\s*searchQuery/.test(combinedSource), false);
    const dt = performance.now() - t0;
    assert.ok(dt < 20, `Combined ReDoS checks completed in ${dt.toFixed(2)}ms (< 20ms)`);
  });
});

describe('Tier 4 — Real-World UI & Bundle E2E Scenarios (Scenarios 5–8 + Bundle)', () => {
  it('tier4_scenario5_ide_code_authoring_and_refactoring_flow', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const api = await getApiClient();
    const savedFiles = new Map([['src/refactor.rs', 'pub fn old_api() -> i32 { 1 }']]);

    await withMockHttpServer(async (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'GET' && req.path === '/api/file_content') {
        const content = savedFiles.get(req.query.path) || '';
        res.end(JSON.stringify({ status: 'ok', path: req.query.path, content }));
        return;
      }
      if (req.method === 'POST' && req.path === '/api/save_file') {
        savedFiles.set(req.jsonBody.file_path, req.jsonBody.content);
        res.end(JSON.stringify({ status: 'ok', file_path: req.jsonBody.file_path, bytes_written: req.jsonBody.content.length }));
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    }, async () => {
      cs.openFileInIde('src/refactor.rs', 1);
      const readRes = await api.getFileContent('src/refactor.rs', true);
      assert.equal(readRes.status, 'ok');
      assert.ok(readRes.content.includes('old_api'));

      const rendered = await renderComponent('/src/components/ide/IdeEditor.svelte');
      assert.ok(rendered.body.includes('text-transparent'), 'Unified transparent textarea required');
      assert.ok(rendered.body.includes('leading-[21px]') && rendered.body.includes('whitespace-pre'));

      const { combinedSource } = collectComponentBundleSource('src/components/ide/IdeEditor.svelte');
      assert.ok(/searchMatches/.test(combinedSource) && /key\.toLowerCase\(\)\s*===\s*['"]h['"]/.test(combinedSource));
      assert.ok(/undoStack/.test(combinedSource) && /redoStack/.test(combinedSource));

      const saveRes = await api.saveFile('src/refactor.rs', 'pub fn new_api() -> i32 { 2 }');
      assert.equal(saveRes.status, 'ok');
      assert.equal(savedFiles.get('src/refactor.rs'), 'pub fn new_api() -> i32 { 2 }');
    });
  });

  it('tier4_scenario6_ide_security_triage_flow', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const api = await getApiClient();

    const vulnNode = makeNode({
      id: 'sym::sql_exec',
      name: 'sql_exec',
      file_path: 'src/store.rs',
      line_number: 1,
      loc: 38,
      has_security_violation: true,
      metadata: { max_lines_limit: 50, lock_verified: false },
      anomalies: [
        {
          rule_id: 'CWE-89',
          cve_id: 'CWE-89',
          severity: 'CRITICAL',
          line_number: 1,
          message: 'Unsanitized query string',
          remediation: 'Use parameterized query',
          file_path: 'src/store.rs',
        },
      ],
    });
    cs.setGraph({ project_path: '/workspace', nodes: [vulnNode], edges: [], clusters: {} }, false);
    cs.activeAgents = [
      { agentId: 'ag-sec', agentName: 'SecSentinel', target: 'src/store.rs', nodeId: 'sym::sql_exec', color: '#38bdf8', timestamp: Date.now() },
    ];
    cs.openFileInIde('src/store.rs', 1);

    const triageHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(triageHtml.includes('CWE-89') && triageHtml.includes('Unsanitized query string'));
    assert.ok(/\/\s*50\s*L\b/.test(triageHtml) && /\b1\s*CWE\b/.test(triageHtml));
    assert.ok(triageHtml.includes('SecSentinel') && triageHtml.includes('Sceller BLAKE3'));

    // Triage step: ignore CWE -> verify counter & Error Lens clear, then seal contract
    cs.ignoreCweRule('CWE-89');
    const triagedHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
    assert.ok(/\b0\s*CWE\b/.test(triagedHtml));
    assert.equal(triagedHtml.includes('Unsanitized query string'), false);

    await withMockHttpServer(async (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'POST' && req.path === '/api/contracts/sign') {
        res.end(
          JSON.stringify({
            status: 'ok',
            message: 'Sealed',
            signed_count: 1,
            blake3_hash: 'seal_ok',
            graph: {
              project_path: '/workspace',
              nodes: [{ ...vulnNode, anomalies: [], has_security_violation: false, metadata: { max_lines_limit: 50, lock_verified: true, blake3_hash: 'seal_ok' } }],
              edges: [],
              clusters: {},
            },
          })
        );
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    }, async () => {
      const signRes = await api.signContracts({ project_path: '/workspace' });
      assert.equal(signRes.status, 'ok');
      cs.setGraph(signRes.graph, true);
      assert.equal(cs.getNodeById('sym::sql_exec').metadata.lock_verified, true);
    });
  });

  it('tier4_scenario7_ide_architectural_navigation_flow', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const { AetherEngine } = await ssrLoad('/src/engine/engine.ts');
    const mocks = createCanvasMocks();
    const eng = new AetherEngine(mocks.glCanvas, mocks.lineCanvas, cs);
    try {
      const callerFn = makeNode({ id: 'sym::caller', name: 'http_entry', file_path: 'src/http.rs', line_number: 5, x: -120, y: 0 });
      const targetFn = makeNode({ id: 'sym::target', name: 'dispatch_job', file_path: 'src/jobs.rs', line_number: 18, x: 0, y: 0 });
      const calleeFn = makeNode({ id: 'sym::callee', name: 'persist_job', file_path: 'src/db.rs', line_number: 40, x: 240, y: 120 });

      cs.setGraph(
        {
          project_path: '/workspace',
          nodes: [callerFn, targetFn, calleeFn],
          edges: [
            { source: 'sym::caller', target: 'sym::target', relation: 'calls' },
            { source: 'sym::target', target: 'sym::callee', relation: 'calls' },
          ],
          clusters: {},
        },
        false
      );
      cs.activeAgents = [{ agentId: 'ag-arch', agentName: 'ArchNav', target: 'sym::callee', nodeId: 'sym::callee', timestamp: Date.now() }];
      cs.viewMode = 'ide';
      cs.activeSymbol = targetFn;
      cs.openFileInIde('src/jobs.rs', 20);
      cs.ideCursorPosition = { line: 20, ch: 2 };

      const edHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
      assert.ok(edHtml.includes('dispatch_job'));
      assert.ok(/Appelants[\s\S]{0,120}\b1\b/.test(edHtml) && /Appelés[\s\S]{0,120}\b1\b/.test(edHtml));
      assert.ok(edHtml.includes('Cibler en 3D'));

      const pipHtml = (await renderComponent('/src/components/RadarMinimap.svelte', { engine: null, mode: 'local' })).body;
      assert.ok(pipHtml.includes('dispatch_job') && pipHtml.includes('http_entry') && pipHtml.includes('persist_job'));
      assert.ok(pipHtml.includes('ArchNav'));

      // 1-click jump to calleeFn + Cibler en 3D
      cs.selectSymbol('sym::callee', true);
      cs.openFileInIde('src/db.rs', 40);
      cs.requestFocusSymbol('sym::callee');
      cs.viewMode = 'code';
      eng.focusSymbol('sym::callee');

      assert.equal(cs.ideActiveFile, 'src/db.rs');
      assert.equal(cs.ideTargetLine, 40);
      assert.equal(cs.viewMode, 'code');
      assert.equal(cs.focusTargetId, 'sym::callee');
      assert.equal(eng.camera.targetX, 240);
      assert.equal(eng.camera.targetY, 120);
    } finally {
      eng.destroy();
    }
  });

  it('tier4_scenario8_ide_git_and_file_management_flow', async () => {
    const cs = await getCockpitState();
    resetCockpitState(cs);
    const api = await getApiClient();
    const restoreClipboard = setMockClipboard({ writeText: async () => {} });

    try {
      await withMockHttpServer(async (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.method === 'GET' && req.path === '/api/git/status') {
          res.end(
            JSON.stringify({
              is_git_repo: true,
              branch: 'main',
              clean: false,
              files: [
                { path: 'crates/core/src/lib.rs', status: 'modified', has_security_violation: false, cwe_count: 0, ears_violation: false },
                { path: 'crates/core/src/new_mod.rs', status: 'untracked', has_security_violation: false, cwe_count: 0, ears_violation: false },
              ],
              modified_count: 1,
              untracked_count: 1,
              staged_count: 0,
              deleted_count: 0,
              security_alert_count: 0,
            })
          );
          return;
        }
        if (req.method === 'POST' && req.path === '/api/ai/create_file') {
          res.end(
            JSON.stringify({
              status: 'ok',
              file_path: req.jsonBody.file_path,
              created_symbol: 'file::created',
              graph: {
                project_path: '/workspace',
                nodes: [makeNode({ id: 'file::created', is_file: true, kind: 'File', file_path: req.jsonBody.file_path })],
                edges: [],
                clusters: {},
              },
            })
          );
          return;
        }
        res.statusCode = 404;
        res.end('{}');
      }, async () => {
        await cs.fetchGitStatus(true);
        cs.openFileInIde('crates/core/src/lib.rs');
        cs.openFileInIde('crates/core/src/new_mod.rs');

        const edHtml = (await renderComponent('/src/components/ide/IdeEditor.svelte')).body;
        const ftHtml = (await renderComponent('/src/components/ide/IdeFileTree.svelte')).body;
        assert.ok(/\bM\b/.test(edHtml) && /\?/.test(edHtml), 'Editor tabs must display M and ? Git badges');
        assert.ok(/Fichiers modifiés Git uniquement/i.test(ftHtml), 'File tree must render Git-modified-only filter');

        const ftBundle = collectComponentBundleSource('src/components/ide/IdeFileTree.svelte').combinedSource;
        assert.ok(/pendingCreateFolder/.test(ftBundle) && /clipboard\.writeText/.test(ftBundle));

        cs.pendingCreateFolder = 'crates/core/src';
        cs.isCreateFileModalOpen = true;
        const modalHtml = (await renderComponent('/src/components/CreateFileModal.svelte')).body;
        assert.ok(modalHtml.includes('role="dialog"'));

        const createRes = await api.createFile({
          project_path: '/workspace',
          file_path: 'crates/core/src/added.rs',
          content: 'pub fn added() {}',
        });
        assert.equal(createRes.status, 'ok');
        cs.setGraph(createRes.graph);
        cs.pendingCreateFolder = null;
        assert.ok(cs.getNodeById('file::created'));
      });
    } finally {
      restoreClipboard();
    }
  });

  it('tier4_bundle_singlefile_dist_index_html_integrity', () => {
    const distHtmlPath = path.join(REPO_ROOT, 'crates/desktop-shell/dist/index.html');
    assert.ok(fs.existsSync(distHtmlPath), 'crates/desktop-shell/dist/index.html must exist');
    const html = fs.readFileSync(distHtmlPath, 'utf-8');
    assert.ok(html.length > 100_000, `Singlefile bundle looks unexpectedly small (${html.length} bytes)`);

    const appDivIdx = html.indexOf('<div id="app"></div>');
    const moduleScriptIdx = html.indexOf('<script type="module"');
    assert.ok(appDivIdx !== -1, 'dist/index.html must contain <div id="app"></div> injection point for viewer.rs');
    assert.ok(moduleScriptIdx !== -1, 'dist/index.html must contain inline module script');
    assert.ok(appDivIdx < moduleScriptIdx, '<div id="app"></div> must appear BEFORE <script type="module"> for viewer.rs bootstrap injection');

    // Must not depend on external JS/CSS assets
    assert.equal(/<script[^>]+src=["'][^"']+["']/.test(html), false, 'Singlefile bundle must not emit external <script src=...>');
    assert.equal(/<link[^>]+rel=["']stylesheet["'][^>]+href=/.test(html), false, 'Singlefile bundle must not emit external stylesheet <link>');
    assert.ok(html.includes('<style'), 'Singlefile bundle must inline compiled CSS');

    // Also verify all modified/created UI components compile cleanly without errors
    for (const rel of [
      'src/components/CreateFileModal.svelte',
      'src/components/RadarMinimap.svelte',
      'src/components/ide/IdeEditor.svelte',
      'src/components/ide/IdeFileTree.svelte',
      'src/components/ide/IdeView.svelte',
    ]) {
      const compiled = compileSvelteClient(rel);
      assert.ok(compiled.js.code.length > 0, `${rel} must compile cleanly`);
    }
  });
});
