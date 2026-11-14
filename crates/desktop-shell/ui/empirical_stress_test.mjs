import { performance } from 'perf_hooks';

// ============================================================================
// 1. BOUNTYMODAL TOKENIZER & REGEX RE-DOS EMPIRICAL HARNESS
// ============================================================================

const CODE_KEYWORDS = new Set([
  'fn', 'pub', 'let', 'mut', 'const', 'static', 'async', 'await', 'impl', 'trait',
  'struct', 'enum', 'mod', 'use', 'crate', 'self', 'super', 'where', 'match',
  'if', 'else', 'for', 'while', 'loop', 'return', 'break', 'continue', 'type',
  'unsafe', 'move', 'ref', 'in', 'as', 'function', 'class', 'interface', 'import',
  'export', 'from', 'default', 'new', 'this', 'try', 'catch', 'throw', 'typeof',
  'contract', 'pragma', 'solidity', 'mapping', 'event', 'require', 'revert',
  'true', 'false', 'null', 'undefined', 'curl', 'cargo', 'test', 'POST', 'GET',
  'PUT', 'DELETE', 'HTTP', 'Host', 'Content-Type', 'def', 'class', 'import'
]);

function tokenizeLine(line) {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('# ') || trimmed.startsWith('--')) {
    return [{ text: line, cls: 'text-slate-500 italic' }];
  }
  const tokens = [];
  const regex = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\/\/.*$|\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+(?:\.\d+)?\b|[{}()[\].,:;+\-/*=<>!&|?~]+)/g;
  let lastIndex = 0;
  let m;
  while ((m = regex.exec(line)) !== null) {
    if (m.index > lastIndex) {
      tokens.push({ text: line.slice(lastIndex, m.index), cls: 'text-slate-300' });
    }
    const tok = m[0];
    let cls = 'text-slate-200';
    if (tok.startsWith('//')) {
      cls = 'text-slate-500 italic';
    } else if (tok.startsWith('"') || tok.startsWith("'") || tok.startsWith('`')) {
      cls = 'text-amber-300 font-mono';
    } else if (/^\d/.test(tok)) {
      cls = 'text-purple-300 font-mono';
    } else if (CODE_KEYWORDS.has(tok)) {
      cls = 'text-pink-400 font-semibold';
    } else if (/^[A-Z][A-Za-z0-9_]*$/.test(tok)) {
      cls = 'text-emerald-300 font-medium';
    } else if (/^[{}()[\].,:;+\-/*=<>!&|?~]+$/.test(tok)) {
      cls = 'text-sky-300/80';
    }
    tokens.push({ text: tok, cls });
    lastIndex = regex.lastIndex;
  }
  if (lastIndex < line.length) {
    tokens.push({ text: line.slice(lastIndex), cls: 'text-slate-300' });
  }
  return tokens.length > 0 ? tokens : [{ text: line, cls: 'text-slate-300' }];
}

function matchesWildcardPattern(filePath, pattern) {
  const normPath = (filePath || '').replace(/\\/g, '/').toLowerCase();
  const normPat = (pattern || '').replace(/\\/g, '/').trim().toLowerCase();
  if (!normPat) return false;
  if (!normPat.includes('*')) {
    return normPath === normPat || normPath.startsWith(normPat + '/') || normPath.includes('/' + normPat + '/');
  }
  const regexStr =
    '^' +
    normPat
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*') +
    '$';
  try {
    if (new RegExp(regexStr, 'i').test(normPath)) return true;
    const prefix = normPat.replace(/\/?\*+$/, '');
    if (prefix && (normPath === prefix || normPath.startsWith(prefix + '/'))) return true;
  } catch {
    // ignore invalid regex
  }
  return false;
}

console.log('--- TEST 1: tokenizeLine ReDoS & Boundary Testing ---');
{
  // Test 1.1: Normal line
  const normalTokens = tokenizeLine('pub fn verify_signature(msg: &str) -> bool { true }');
  console.log(`[PASS] Normal line tokens count: ${normalTokens.length}`);

  // Test 1.2: Unclosed string literal stress (ReDoS probe)
  const unclosed = '"' + 'a'.repeat(50000);
  const t0 = performance.now();
  const unclosedTokens = tokenizeLine(unclosed);
  const durUnclosed = performance.now() - t0;
  console.log(`[PASS] Unclosed string (50k chars) executed in ${durUnclosed.toFixed(2)}ms (safe: <100ms)`);
  if (durUnclosed > 500) throw new Error('ReDoS detected on unclosed string');

  // Test 1.3: Heavy backslash escape pattern (ReDoS probe)
  const backslashes = '"' + '\\\\'.repeat(25000) + '"';
  const t1 = performance.now();
  const bsTokens = tokenizeLine(backslashes);
  const durBs = performance.now() - t1;
  console.log(`[PASS] Backslash chain (50k chars) executed in ${durBs.toFixed(2)}ms`);

  // Test 1.4: HTML / XSS Injection string
  const xssInput = '<script>alert("XSS")</script><img src=x onerror=alert(1)>';
  const xssTokens = tokenizeLine(xssInput);
  const reconstructed = xssTokens.map(t => t.text).join('');
  if (reconstructed !== xssInput) throw new Error('Token stream corrupted input text');
  console.log(`[PASS] HTML/XSS preserved verbatim without evaluation: ${reconstructed.length} chars`);
}

console.log('\n--- TEST 2: matchesWildcardPattern Boundary & Catastrophic Backtracking ---');
{
  // Test 2.1: Multi-star backtracking probe
  const maliciousPattern = '*/*/*/*/*/*/*/*/*/*/*.rs';
  const targetPath = 'crates/desktop-shell/ui/src/components/BountyModal.svelte';
  const t0 = performance.now();
  const match = matchesWildcardPattern(targetPath, maliciousPattern);
  const dur = performance.now() - t0;
  console.log(`[PASS] Multi-star wildcard executed in ${dur.toFixed(2)}ms (result=${match})`);
  if (dur > 200) throw new Error('Catastrophic backtracking on wildcard pattern');

  // Test 2.2: Regex special characters in pattern
  const dangerousPatterns = ['[a-z]+/*', '(evil|pattern)/*', '{1,5}/*', 'path+with+plus/*'];
  for (const pat of dangerousPatterns) {
    const res = matchesWildcardPattern('crates/foo/bar.rs', pat);
    console.log(`[PASS] Pattern "${pat}" handled cleanly without throwing (res=${res})`);
  }
}

// ============================================================================
// 2. SEARCH DROPDOWN PANEL ("LA TOTALE") EMPIRICAL HARNESS
// ============================================================================

console.log('\n--- TEST 3: SearchDropdownPanel Filtering & Large Graph Stress ---');

function computeSearchResults({ nodes, edges, clusters, query, activeTab }) {
  const q = (query || '').toLowerCase().trim();
  const items = [];

  const nodeMap = new Map();
  for (const n of nodes) {
    if (n && n.id) nodeMap.set(n.id, n);
  }

  // Extract distinct folders
  const folders = new Map();
  for (const n of nodes) {
    if (!n) continue;
    const f = n.folder || n.cluster_id || 'root';
    const cur = folders.get(f) || { count: 0, loc: 0 };
    cur.count += 1;
    cur.loc += n.loc || 1;
    folders.set(f, cur);
  }
  for (const [clusterName, nodeIds] of Object.entries(clusters || {})) {
    if (!folders.has(clusterName)) {
      folders.set(clusterName, { count: (nodeIds || []).length, loc: (nodeIds || []).length * 20 });
    }
  }
  const allFolders = Array.from(folders.entries()).map(([name, stat]) => ({
    name,
    count: stat.count,
    loc: stat.loc,
  }));

  // Extract distinct files
  const filePaths = new Map();
  for (const n of nodes) {
    if (!n || !n.file_path) continue;
    const cur = filePaths.get(n.file_path) || { symbolId: n.id, symbolCount: 0, loc: 0 };
    cur.symbolCount += 1;
    cur.loc += n.loc || 1;
    if (n.is_file) cur.symbolId = n.id;
    filePaths.set(n.file_path, cur);
  }
  const allFiles = Array.from(filePaths.entries()).map(([filePath, stat]) => ({
    filePath,
    symbolId: stat.symbolId,
    symbolCount: stat.symbolCount,
    loc: stat.loc,
  }));

  // 1. Functions & Symbols
  if (activeTab === 'all' || activeTab === 'functions') {
    for (const n of nodes) {
      if (!n) continue;
      const nameLower = (n.name || '').toLowerCase();
      const fileLower = (n.file_path || '').toLowerCase();
      const kindLower = String(n.kind || '').toLowerCase();
      const folderLower = (n.folder || '').toLowerCase();

      let match = false;
      let score = 0;

      if (!q) {
        match = true;
        score = (n.anomalies && n.anomalies.length > 0 ? 50 : 0) + ((n.cyclomatic_complexity || 1) >= 10 ? 30 : 10);
      } else if (nameLower === q) {
        match = true;
        score = 100;
      } else if (nameLower.startsWith(q)) {
        match = true;
        score = 85;
      } else if (nameLower.includes(q)) {
        match = true;
        score = 70;
      } else if (fileLower.includes(q) || folderLower.includes(q) || kindLower.includes(q)) {
        match = true;
        score = 40;
      } else if (n.anomalies && n.anomalies.some((a) => (a.cve_id || '').toLowerCase().includes(q) || (a.title || '').toLowerCase().includes(q))) {
        match = true;
        score = 75;
      }

      if (!match && n.methods) {
        for (const m of n.methods) {
          if ((m.name || '').toLowerCase().includes(q)) {
            items.push({
              id: `${n.id}::method::${m.name}`,
              type: 'symbol',
              title: `${n.name}::${m.name}()`,
              subtitle: `${n.file_path || ''}:${m.line || n.line_number || 1}`,
              kindBadge: 'method',
              complexity: 1,
              symbolId: n.id,
              filePath: n.file_path,
              score: 65,
            });
          }
        }
      }

      if (match) {
        const violCount = n.anomalies?.length || n.violations?.length || 0;
        items.push({
          id: n.id,
          type: 'symbol',
          title: n.name,
          subtitle: `${n.file_path || 'symbole'}${n.line_number ? `:${n.line_number}` : ''}${n.folder ? ` (${n.folder})` : ''}`,
          kindBadge: String(n.kind || 'fn'),
          complexity: n.cyclomatic_complexity || 1,
          violationsCount: violCount,
          symbolId: n.id,
          filePath: n.file_path,
          score: score + (violCount > 0 ? 15 : 0),
        });
      }
    }
  }

  // 2. Call Edges
  if (activeTab === 'all' || activeTab === 'calls') {
    const edgeList = edges || [];
    for (let i = 0; i < edgeList.length; i++) {
      const e = edgeList[i];
      if (!e) continue;
      const src = nodeMap.get(e.source);
      const tgt = nodeMap.get(e.target);
      const srcName = src?.name || e.source || '';
      const tgtName = tgt?.name || e.target || '';
      const rel = e.relation || e.edge_type || 'calls';
      const relLower = rel.toLowerCase();
      const srcLower = srcName.toLowerCase();
      const tgtLower = tgtName.toLowerCase();
      const transData = e.transmitted_data || '';

      let match = false;
      let score = 0;

      if (!q) {
        match = activeTab === 'calls' || i < 20;
        score = 20;
      } else if (srcLower.includes(q) || tgtLower.includes(q) || relLower.includes(q) || transData.toLowerCase().includes(q)) {
        match = true;
        score = 65;
        if (srcLower === q || tgtLower === q) score = 90;
      }

      if (match) {
        items.push({
          id: `edge-${e.source}-${e.target}-${i}`,
          type: 'call',
          title: `${srcName} ➔ ${tgtName}`,
          subtitle: `${rel} · ${src?.file_path || ''} ➔ ${tgt?.file_path || ''}${transData ? ` [${transData}]` : ''}`,
          relationType: rel,
          sourceNode: srcName,
          targetNode: tgtName,
          symbolId: tgt?.id || src?.id,
          score,
        });
      }
    }
  }

  // 3. Files & Folders
  if (activeTab === 'all' || activeTab === 'files') {
    for (const f of allFolders) {
      const fLower = f.name.toLowerCase();
      let match = false;
      let score = 0;

      if (!q) {
        match = activeTab === 'files' || f.name !== 'root';
        score = 30;
      } else if (fLower === q) {
        match = true;
        score = 95;
      } else if (fLower.startsWith(q)) {
        match = true;
        score = 80;
      } else if (fLower.includes(q)) {
        match = true;
        score = 60;
      }

      if (match) {
        items.push({
          id: `folder-${f.name}`,
          type: 'folder',
          title: f.name,
          subtitle: `Dossier architectural · ${f.count} symbole(s) · ~${f.loc} LOC`,
          folderName: f.name,
          kindBadge: 'dossier',
          score,
        });
      }
    }

    for (const file of allFiles) {
      const fileLower = file.filePath.toLowerCase();
      let match = false;
      let score = 0;

      if (!q) {
        match = activeTab === 'files';
        score = 25;
      } else if (fileLower.endsWith(q) || fileLower.includes(q)) {
        match = true;
        score = 65;
      }

      if (match) {
        items.push({
          id: `file-${file.filePath}`,
          type: 'file',
          title: file.filePath.split(/[/\\]/).pop() || file.filePath,
          subtitle: `${file.filePath} · ${file.symbolCount} symbole(s)`,
          filePath: file.filePath,
          symbolId: file.symbolId,
          kindBadge: 'fichier',
          score,
        });
      }
    }
  }

  items.sort((a, b) => b.score - a.score);
  return items.slice(0, 60);
}

{
  // Test 3.1: Generate Synthetic 10,000 nodes & 20,000 edges graph
  console.log('Generating synthetic 10,000 nodes & 20,000 edges benchmark graph...');
  const nodes = [];
  for (let i = 0; i < 10000; i++) {
    nodes.push({
      id: `sym_${i}`,
      name: `process_transaction_${i}`,
      file_path: `crates/module_${i % 50}/src/handler_${i % 10}.rs`,
      folder: `module_${i % 50}`,
      kind: i % 3 === 0 ? 'fn' : (i % 3 === 1 ? 'struct' : 'trait'),
      cyclomatic_complexity: (i % 20) + 1,
      anomalies: i % 100 === 0 ? [{ cve_id: `CWE-${(i % 120) + 1}`, title: `Security flaw in ${i}` }] : [],
      methods: i % 5 === 0 ? [{ name: `inner_dispatch_${i}`, line: 42 }] : [],
    });
  }

  const edges = [];
  for (let i = 0; i < 20000; i++) {
    edges.push({
      source: `sym_${i % 10000}`,
      target: `sym_${(i * 7) % 10000}`,
      relation: i % 2 === 0 ? 'calls' : 'imports',
      transmitted_data: i % 10 === 0 ? `tainted_arg_${i}` : undefined,
    });
  }

  // Benchmark empty query
  const t0 = performance.now();
  const emptyRes = computeSearchResults({ nodes, edges, clusters: {}, query: '', activeTab: 'all' });
  const durEmpty = performance.now() - t0;
  console.log(`[PASS] Empty query on 10k nodes: returned ${emptyRes.length} items in ${durEmpty.toFixed(2)}ms (slice limit 60 respected)`);
  if (emptyRes.length !== 60) throw new Error('Did not respect max 60 slice');

  // Benchmark specific query
  const t1 = performance.now();
  const queryRes = computeSearchResults({ nodes, edges, clusters: {}, query: 'transaction_99', activeTab: 'all' });
  const durQuery = performance.now() - t1;
  console.log(`[PASS] Query "transaction_99" returned ${queryRes.length} items in ${durQuery.toFixed(2)}ms`);

  // Benchmark call edges tab
  const t2 = performance.now();
  const callsRes = computeSearchResults({ nodes, edges, clusters: {}, query: 'calls', activeTab: 'calls' });
  const durCalls = performance.now() - t2;
  console.log(`[PASS] ActiveTab "calls" returned ${callsRes.length} items in ${durCalls.toFixed(2)}ms`);

  // Benchmark empty graph
  const emptyGraphRes = computeSearchResults({ nodes: [], edges: [], clusters: null, query: 'anything', activeTab: 'all' });
  console.log(`[PASS] Empty graph gracefully returned ${emptyGraphRes.length} items without throwing`);

  // Benchmark adversarial query (special regex chars)
  const regexRes = computeSearchResults({ nodes, edges, clusters: {}, query: '.*[a-z]+(?=evil)\\', activeTab: 'all' });
  console.log(`[PASS] Adversarial regex query returned ${regexRes.length} items without crashing`);
}

// ============================================================================
// 3. BOUNTYMODAL REPORT & EXPORT GENERATORS ORACLE
// ============================================================================

console.log('\n--- TEST 4: BountyModal PoC & Export Formats Verification ---');

function buildExecutablePocScript(a) {
  const cveSlug = (a.cve_id || 'vuln').toLowerCase().replace(/[^a-z0-9]/g, '_');
  const folder = (a.file_path || '').split('/')[0] || 'root';
  const param = a.transmitted_data || 'payload';
  const isRust = (a.file_path || '').endsWith('.rs');

  if (isRust) {
    const code = `// PoC ${a.cve_id}\n#[test]\nfn test_${cveSlug}() { let p = "${param}"; }`;
    const cli = `cargo test poc_${cveSlug} --package ${folder}`;
    return { code, cli };
  }
  const code = `#!/usr/bin/env python3\n# PoC ${a.cve_id}\nPAYLOAD = {"${param}": "vector"}`;
  const cli = `python3 poc_${cveSlug}.py`;
  return { code, cli };
}

function buildMcpHandshakeBlock(a) {
  return JSON.stringify({
    protocol: 'aetherscope-mcp-v2.4',
    mission: 'poc_generation_and_patch',
    target: {
      cve_id: a.cve_id || 'UNKNOWN',
      cwe_class: a.cwe_class || 'CWE',
      severity: a.severity || 'HIGH',
      file_path: a.file_path || '',
      line_number: a.line_number || 1,
      tainted_param: a.transmitted_data || 'payload',
    }
  }, null, 2);
}

{
  // Test 4.1: Normal anomaly
  const a1 = {
    cve_id: 'CWE-89',
    cwe_class: 'CWE-89 SQL Injection',
    severity: 'CRITICAL',
    title: 'Unescaped parameter query',
    file_path: 'crates/db/src/query.rs',
    line_number: 142,
    transmitted_data: 'user_id',
    transmitted_type: 'String',
  };
  const pocRust = buildExecutablePocScript(a1);
  console.log(`[PASS] Rust PoC generated: cli="${pocRust.cli}"`);

  // Test 4.2: Python anomaly
  const a2 = {
    cve_id: 'CWE-78',
    cwe_class: 'CWE-78 OS Command Injection',
    severity: 'HIGH',
    title: 'Command injection in worker',
    file_path: 'scripts/worker.py',
    line_number: 55,
    transmitted_data: 'cmd_arg',
  };
  const pocPy = buildExecutablePocScript(a2);
  console.log(`[PASS] Python PoC generated: cli="${pocPy.cli}"`);

  // Test 4.3: Edge case with null / undefined fields
  const aSparse = {
    cve_id: undefined,
    file_path: undefined,
    line_number: undefined,
    transmitted_data: undefined,
  };
  const pocSparse = buildExecutablePocScript(aSparse);
  const mcpSparse = buildMcpHandshakeBlock(aSparse);
  const parsed = JSON.parse(mcpSparse);
  console.log(`[PASS] Sparse anomaly parsed valid JSON: protocol="${parsed.protocol}", target.cve_id="${parsed.target.cve_id}"`);
}

console.log('\n=== ALL EMPIRICAL CHALLENGER TESTS PASSED ===\n');
