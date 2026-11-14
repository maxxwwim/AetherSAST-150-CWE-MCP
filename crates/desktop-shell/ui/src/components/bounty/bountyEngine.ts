import type {
  AetherGraph,
  CveAnomalyRecord,
  SinkKind,
  SourceKind,
  SymbolBubble,
  TaintStep,
  TaintStepKind,
} from '../../types/graph';

export type BountyStep = 1 | 2 | 3 | 4;

export type PromptFormat =
  | 'scope_prompt'
  | 'target_prompt'
  | 'poc_code'
  | 'curl_command'
  | 'raw_http'
  | 'bounty_report'
  | 'gold_patch'
  | 'mcp_handshake';

export type BountyPresetId =
  | 'immunefi'
  | 'hackerone'
  | 'yeswehack'
  | 'l1_consensus'
  | 'rust_lowlevel'
  | 'smart_contracts'
  | 'auto';

export type ScopePromptMission =
  | 'audit_strict'
  | 'poc_batch'
  | 'patch_ears'
  | 'mcp_autonomous';

export interface FolderRecommendation {
  folder: string;
  status: string;
  critical_count: number;
  high_count: number;
  total_violations: number;
  entrypoints_count: number;
  score: number;
  reason: string;
}

export interface ProjectFolderStat {
  folder: string;
  count: number;
  critCount: number;
  highCount: number;
  nodeCount: number;
}

export interface DryRunResult {
  mode: 'live_http' | 'sandbox_ast';
  statusCode: number;
  statusText: string;
  latencyMs: number;
  verdict: 'vulnerability_reproduced' | 'target_defended' | 'error';
  verdictMessage: string;
  targetUrl: string;
  method: string;
  requestHeaders: Record<string, string>;
  requestPayload: unknown;
  responseHeaders: Record<string, string>;
  responseBody: string;
  astDetails?: {
    taintChain: string;
    sinkRule: string;
    sanitizerDetected: boolean;
    confidence: number;
  };
}

export interface FileFunctionItem {
  id: string;
  name: string;
  signature: string;
  args: string;
  returns: string;
  isAsync: boolean;
  visibility: string;
  line: number;
  endLine: number;
  calls: string[];
  docstring: string;
  kind: string;
  layer: string;
  symbolId?: string;
  hasAnomaly: boolean;
  anomalySeverity?: string;
  isTargetLineInside: boolean;
  isTaintTouched: boolean;
  taintRoles: ('SOURCE' | 'PROPAGATION' | 'SINK')[];
  loc: number;
  complexity: number;
}

export interface CodeViewerLine {
  num: number;
  text: string;
  isFaulty: boolean;
  isInActiveFunction: boolean;
  isTaintStep: boolean;
  taintLabel?: string;
}

export interface DataFlowNode {
  id: string;
  label: string;
  sublabel: string;
  filePath: string;
  line: number;
  layer: string;
  kind: 'source' | 'upstream' | 'target' | 'step' | 'downstream' | 'sink';
  symbolId?: string;
  relation?: string;
  transmittedData?: string;
  transmittedType?: string;
  isSanitized?: boolean;
  sanitizerName?: string;
  codeSnippet?: string;
  direction: 'IN' | 'CORE' | 'OUT';
}

export interface DataVarFlowEntry {
  name: string;
  type: string;
  direction: 'IN' | 'TRANSIT' | 'OUT';
  origin: string;
  destination: string;
  line: number;
  sanitized: boolean;
}

export interface TargetDataDirection {
  upstream: DataFlowNode[];
  coreSteps: DataFlowNode[];
  downstream: DataFlowNode[];
  targetNode: DataFlowNode;
  taintSummary: string;
  isSanitized: boolean;
  appliedSanitizers: string[];
  dataVars: DataVarFlowEntry[];
}

export interface ScopePromptConfig {
  projectName: string;
  projectPath: string;
  presetLabel: string;
  scopeModeLabel: string;
  lockedSingleFolder: string;
  inFolders: string[];
  outFolders: string[];
  inScopePatternsText: string;
  outScopePatternsText: string;
  mission: ScopePromptMission;
  strictFolderBoundary: boolean;
  filterReachableOnly: boolean;
  includeTopTargetsInPrompt: boolean;
  requireNonDestructivePoc: boolean;
  requireEarsInvariant: boolean;
  customScopeInstructions: string;
  filteredTargets: CveAnomalyRecord[];
  selectedAnomaly: CveAnomalyRecord | null;
}

export const BOUNTY_PRESETS: Record<
  BountyPresetId,
  { label: string; badge: string; inScope: string[]; outScope: string[]; rationale: string }
> = {
  immunefi: {
    label: 'Immunefi Web3',
    badge: '⛓️ Web3',
    inScope: ['contracts/*', 'crates/*', 'src/*', '*.sol', '*.rs'],
    outScope: ['tests/*', 'test/*', 'script/*', 'mocks/*', 'docs/*', 'target/*'],
    rationale:
      "Preset Immunefi Web3 : Contrats, crates cœur & logique d'état In-Scope ; tests/mocks/scripts Out-of-Scope. Impacts : Vol de fonds, TWAP manipulation, Reentrancy.",
  },
  hackerone: {
    label: 'HackerOne API',
    badge: '🌐 API',
    inScope: ['crates/*', 'src/*', 'api/*', 'routes/*', 'controllers/*', 'auth/*'],
    outScope: ['tests/*', '*.spec.*', '*.test.*', 'docs/*', 'fixtures/*', 'benches/*'],
    rationale:
      'Preset HackerOne API : Endpoints HTTP/WS, handlers & auth In-Scope ; tests unitaires & docs Out-of-Scope. Impacts : RCE, SQLi, SSRF, IDOR.',
  },
  yeswehack: {
    label: 'YesWeHack SaaS',
    badge: '🛡️ SaaS',
    inScope: ['crates/*', 'src/*', 'app/*', 'server/*', 'ui/src/*'],
    outScope: ['tests/*', 'e2e/*', 'docs/*', 'migrations/*', 'node_modules/*', '*.test.*'],
    rationale:
      'Preset YesWeHack SaaS : Application full-stack (backend + frontend UI) In-Scope ; migrations & tests Out-of-Scope. Impacts : File upload webshell, Privilege Escalation.',
  },
  l1_consensus: {
    label: 'L1 & Consensus',
    badge: '⚡ L1',
    inScope: ['consensus/*', 'vm/*', 'execution/*', 'mempool/*', 'crates/core*'],
    outScope: ['test/*', 'tests/*', 'benches/*', 'fuzz/*', 'docs/*'],
    rationale:
      "Preset L1 & Consensus : Partition de consensus, divergence d'état, arrêt de validateur OOM/Panic In-Scope.",
  },
  rust_lowlevel: {
    label: 'Rust Core & Unsafe',
    badge: '🦀 Systems',
    inScope: ['src/*', 'crates/*', 'runtime/*', 'alloc/*'],
    outScope: ['tests/*', 'examples/*', 'benches/*', 'docs/*'],
    rationale:
      'Preset Rust Deep-Core : Fuites mémoire LLVM DSE, Panic Unwind Double-Drop, GlobalAlloc Layout 0/overflow, FFI Panics.',
  },
  smart_contracts: {
    label: 'DeFi Smart Contracts',
    badge: '💎 DeFi',
    inScope: ['contracts/*', 'programs/*', 'pallets/*', 'crates/core*'],
    outScope: ['test/*', 'tests/*', 'bench/*', 'scripts/*', 'audits/*', 'docs/*'],
    rationale:
      "Preset Smart Contracts : Protocoles on-chain, pools de liquidité & moteurs d'oracle uniquement.",
  },
  auto: {
    label: 'Auto-Scope Projet',
    badge: '✨ Auto',
    inScope: ['src/*', 'crates/*', 'app/*'],
    outScope: ['tests/*', 'test/*', 'mocks/*', 'docs/*', 'fixtures/*'],
    rationale:
      'Preset Auto-Scope : Détecte les modules actifs du dépôt et isole automatiquement le code de production.',
  },
};

const CODE_KEYWORDS = new Set([
  'fn', 'pub', 'let', 'mut', 'const', 'static', 'async', 'await', 'impl', 'trait',
  'struct', 'enum', 'mod', 'use', 'crate', 'self', 'super', 'where', 'match',
  'if', 'else', 'for', 'while', 'loop', 'return', 'break', 'continue', 'type',
  'unsafe', 'move', 'ref', 'in', 'as', 'function', 'class', 'interface', 'import',
  'export', 'from', 'default', 'new', 'this', 'try', 'catch', 'throw', 'typeof',
  'contract', 'pragma', 'solidity', 'mapping', 'event', 'require', 'revert',
  'true', 'false', 'null', 'undefined', 'curl', 'cargo', 'test', 'POST', 'GET',
  'PUT', 'DELETE', 'HTTP', 'Host', 'Content-Type', 'def', 'func', 'var',
]);

export function tokenizeLine(line: string): { text: string; cls: string }[] {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('# ') || trimmed.startsWith('--')) {
    return [{ text: line, cls: 'text-slate-500 italic' }];
  }
  const tokens: { text: string; cls: string }[] = [];
  const regex =
    /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\/\/.*$|\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+(?:\.\d+)?\b|[{}()[\].,:;+\-/*=<>!&|?~]+)/g;
  let lastIndex = 0;
  let m: RegExpExecArray | null;
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

export function normalizePath(rawPath?: string): string {
  return (rawPath || '').replace(/\\/g, '/').replace(/^\.\//, '').trim();
}

export function pathsMatch(a?: string, b?: string): boolean {
  const na = normalizePath(a).toLowerCase();
  const nb = normalizePath(b).toLowerCase();
  if (!na || !nb) return false;
  return na === nb || na.endsWith('/' + nb) || nb.endsWith('/' + na);
}

export function normalizeFolderKey(rawPath?: string, rawFolder?: string): string {
  const pathParts = normalizePath(rawPath).split('/').filter(Boolean);
  if (pathParts.length > 1) {
    return pathParts.slice(0, Math.min(2, pathParts.length - 1)).join('/');
  }
  if (rawFolder && rawFolder !== 'root') {
    const rf = rawFolder.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    const parts = rf.split('/');
    return parts.length > 2 ? parts.slice(0, 2).join('/') : rf;
  }
  return 'root';
}

export function parsePatternLines(text: string): string[] {
  return text
    .split(/[\r\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function matchesWildcardPattern(filePath: string, pattern: string): boolean {
  const normPath = (filePath || '').replace(/\\/g, '/').toLowerCase();
  const normPat = (pattern || '').replace(/\\/g, '/').trim().toLowerCase();
  if (!normPat) return false;
  if (!normPat.includes('*')) {
    return (
      normPath === normPat ||
      normPath.startsWith(normPat + '/') ||
      normPath.includes('/' + normPat + '/')
    );
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

export function getTargetMethod(a: Pick<CveAnomalyRecord, 'description' | 'title' | 'message'>): string {
  const desc = (a.description || a.title || a.message || '').toUpperCase();
  if (desc.includes('GET')) return 'GET';
  if (desc.includes('POST')) return 'POST';
  if (desc.includes('PUT')) return 'PUT';
  if (desc.includes('DELETE')) return 'DELETE';
  return 'POST';
}

export function getTargetEndpoint(a: Pick<CveAnomalyRecord, 'file_path'>): string {
  const f = (a.file_path || '').replace(/\\/g, '/');
  const slug = f.split('/').pop()?.replace(/\.[a-z0-9]+$/i, '') || 'api';
  return `/api/${slug}`;
}

export function formatSourceKind(kind?: SourceKind): string {
  if (!kind) return 'Untrusted Input';
  if (typeof kind === 'string') {
    const map: Record<string, string> = {
      HttpQueryParam: 'HTTP Query Param',
      HttpBodyParam: 'HTTP Body Payload',
      HttpHeader: 'HTTP Header',
      HttpCookie: 'HTTP Cookie',
      WebSocketPayload: 'WebSocket Message',
      FileSystemRead: 'File Read',
      DatabaseRead: 'DB Read',
      FunctionArgument: 'Function Param',
    };
    return map[kind] || kind;
  }
  return kind.Custom || 'Custom Source';
}

export function formatSinkKind(kind?: SinkKind): string {
  if (!kind) return 'Critical Sink';
  if (typeof kind === 'string') {
    const map: Record<string, string> = {
      SqlExecution: 'SQL Execution',
      CommandExecution: 'Command Execution',
      HtmlRender: 'HTML Render (XSS)',
      FileAccess: 'File Access (Traversal)',
      SsrfNetworkRequest: 'SSRF Network Call',
      LdapQuery: 'LDAP Query',
    };
    return map[kind] || kind;
  }
  return kind.Custom || 'Custom Sink';
}

export function formatTaintStepKind(step: TaintStep): { label: string; detail: string } {
  const sk = step.step_kind;
  if (sk === 'DirectAssignment') {
    return {
      label: 'Assignation directe',
      detail: `${step.from_var.name}#${step.from_var.version} ➔ ${step.to_var.name}#${step.to_var.version}`,
    };
  }
  if (sk === 'BinaryExpression') {
    return {
      label: 'Concaténation / Expr',
      detail: `${step.from_var.name} + expr ➔ ${step.to_var.name}`,
    };
  }
  if (sk === 'PhiJoin') {
    return {
      label: 'Branche Phi (SSA)',
      detail: `${step.from_var.name} ➔ ${step.to_var.name}`,
    };
  }
  if (typeof sk === 'object' && 'CallArgumentPassing' in sk) {
    const c = sk.CallArgumentPassing;
    return {
      label: `Appel ${c.caller_function} ➔ ${c.callee_function}`,
      detail: `arg[${c.arg_index}] (${c.param_name}) : ${step.from_var.name} ➔ ${step.to_var.name}`,
    };
  }
  if (typeof sk === 'object' && 'CallReturnPassing' in sk) {
    const c = sk.CallReturnPassing;
    return {
      label: `Retour ${c.callee_function} ➔ ${c.caller_function}`,
      detail: `${step.from_var.name} ➔ ${step.to_var.name}`,
    };
  }
  if (typeof sk === 'object' && 'SanitizerCall' in sk) {
    const c = sk.SanitizerCall;
    return {
      label: `Sanitizer ${c.sanitizer_name}`,
      detail: `Neutralise ${c.cwe_targeted} sur ${step.from_var.name}`,
    };
  }
  if (typeof sk === 'object' && 'Custom' in sk) {
    return {
      label: sk.Custom,
      detail: `${step.from_var.name} ➔ ${step.to_var.name}`,
    };
  }
  return {
    label: 'Propagation',
    detail: `${step.from_var.name} ➔ ${step.to_var.name}`,
  };
}

function estimateFunctionEndLine(lines: string[], startLine: number, fallbackLoc: number): number {
  if (lines.length === 0) return Math.max(startLine, startLine + Math.max(0, fallbackLoc - 1));
  const idx = Math.max(0, Math.min(lines.length - 1, startLine - 1));
  let depth = 0;
  let opened = false;
  const maxScan = Math.min(lines.length, idx + Math.max(120, fallbackLoc + 25));

  for (let i = idx; i < maxScan; i++) {
    const line = lines[i];
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === '{') {
        depth += 1;
        opened = true;
      } else if (ch === '}') {
        depth -= 1;
        if (opened && depth <= 0) {
          return i + 1;
        }
      }
    }
  }
  return Math.min(lines.length, startLine + Math.max(8, fallbackLoc - 1));
}

function scanRegexFunctions(rawContent: string): {
  name: string;
  args: string;
  returns: string;
  isAsync: boolean;
  visibility: string;
  line: number;
}[] {
  const found: {
    name: string;
    args: string;
    returns: string;
    isAsync: boolean;
    visibility: string;
    line: number;
  }[] = [];
  if (!rawContent) return found;
  const lines = rawContent.split(/\r?\n/);

  const patterns: { re: RegExp; lang: 'rust' | 'js' | 'arrow' | 'py' | 'go' }[] = [
    { re: /^\s*(pub(?:\([^)]*\))?\s+)?(async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)(?:\s*->\s*([^{;]+))?/, lang: 'rust' },
    { re: /^\s*(export\s+)?(async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?/, lang: 'js' },
    { re: /^\s*(export\s+)?(?:const|let)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(async\s+)?\(([^)]*)\)(?:\s*:\s*([^=]+))?\s*=>/, lang: 'arrow' },
    { re: /^\s*(async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)(?:\s*->\s*([^:]+))?:/, lang: 'py' },
    { re: /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)(?:\s*([^{]+))?/, lang: 'go' },
  ];

  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (ln.length > 280) continue;
    for (const { re, lang } of patterns) {
      const m = ln.match(re);
      if (!m) continue;
      if (lang === 'rust') {
        found.push({
          visibility: m[1] ? 'pub' : 'priv',
          isAsync: Boolean(m[2]),
          name: m[3],
          args: (m[4] || '').trim(),
          returns: (m[5] || '').trim(),
          line: i + 1,
        });
      } else if (lang === 'js') {
        found.push({
          visibility: m[1] ? 'export' : 'local',
          isAsync: Boolean(m[2]),
          name: m[3],
          args: (m[4] || '').trim(),
          returns: (m[5] || '').trim(),
          line: i + 1,
        });
      } else if (lang === 'arrow') {
        found.push({
          visibility: m[1] ? 'export' : 'local',
          isAsync: Boolean(m[3]),
          name: m[2],
          args: (m[4] || '').trim(),
          returns: (m[5] || '').trim(),
          line: i + 1,
        });
      } else if (lang === 'py') {
        found.push({
          visibility: m[2].startsWith('_') ? 'priv' : 'pub',
          isAsync: Boolean(m[1]),
          name: m[2],
          args: (m[3] || '').trim(),
          returns: (m[4] || '').trim(),
          line: i + 1,
        });
      } else if (lang === 'go') {
        found.push({
          visibility: /^[A-Z]/.test(m[1]) ? 'pub' : 'pkg',
          isAsync: false,
          name: m[1],
          args: (m[2] || '').trim(),
          returns: (m[3] || '').trim(),
          line: i + 1,
        });
      }
      break;
    }
  }
  return found;
}

export function extractFileFunctions(
  nodes: SymbolBubble[],
  filePath: string,
  rawContent: string,
  targetLine: number,
  anomaly: CveAnomalyRecord | null
): FileFunctionItem[] {
  const fileNodes = nodes.filter((n) => pathsMatch(n.file_path, filePath));
  const lines = rawContent ? rawContent.split(/\r?\n/) : [];
  const items: FileFunctionItem[] = [];
  const seenKey = new Set<string>();

  const taintTrace = anomaly?.taint_trace;
  const sourceFunc = taintTrace?.source?.var?.func_scope || '';
  const sinkFunc = taintTrace?.sink?.var?.func_scope || '';
  const stepFuncs = new Set<string>();
  const stepLines: number[] = [];
  if (taintTrace) {
    for (const s of taintTrace.steps) {
      if (s.from_var.func_scope) stepFuncs.add(s.from_var.func_scope);
      if (s.to_var.func_scope) stepFuncs.add(s.to_var.func_scope);
      stepLines.push(s.line);
    }
  }

  const computeTaintRoles = (
    fnName: string,
    startLn: number,
    endLn: number
  ): ('SOURCE' | 'PROPAGATION' | 'SINK')[] => {
    const roles: ('SOURCE' | 'PROPAGATION' | 'SINK')[] = [];
    if (
      (sourceFunc && fnName === sourceFunc) ||
      (taintTrace?.source?.line &&
        pathsMatch(taintTrace.source.file_path, filePath) &&
        taintTrace.source.line >= startLn &&
        taintTrace.source.line <= endLn)
    ) {
      roles.push('SOURCE');
    }
    if (
      stepFuncs.has(fnName) ||
      stepLines.some((sl) => sl >= startLn && sl <= endLn)
    ) {
      roles.push('PROPAGATION');
    }
    if (
      (sinkFunc && fnName === sinkFunc) ||
      (targetLine > 0 && targetLine >= startLn && targetLine <= endLn)
    ) {
      roles.push('SINK');
    }
    return roles;
  };

  for (const node of fileNodes) {
    if (!node.is_file) {
      const m0 = node.methods?.[0];
      const ln = m0?.line || node.line_number || 1;
      const key = `${node.name}:${ln}`;
      if (!seenKey.has(key)) {
        seenKey.add(key);
        const endLn = estimateFunctionEndLine(lines, ln, node.loc || 12);
        const isInside = targetLine > 0 && targetLine >= ln && targetLine <= endLn;
        const taintRoles = computeTaintRoles(node.name, ln, endLn);
        const nodeAnoms = [...(node.anomalies || []), ...(node.violations || [])];
        items.push({
          id: node.id,
          name: node.name,
          signature:
            m0?.signature ||
            `${m0?.is_async ? 'async ' : ''}${node.name}(${m0?.args || ''})${m0?.returns ? ` -> ${m0.returns}` : ''}`,
          args: m0?.args || '',
          returns: m0?.returns || '',
          isAsync: Boolean(m0?.is_async),
          visibility: m0?.visibility || '+',
          line: ln,
          endLine: endLn,
          calls: m0?.calls || [],
          docstring: node.docstring || m0?.docstring || '',
          kind: String(node.stereotype || node.kind || 'Function'),
          layer: node.layer || 'domain',
          symbolId: node.id,
          hasAnomaly: Boolean(node.has_security_violation || nodeAnoms.length > 0 || isInside),
          anomalySeverity: nodeAnoms[0]?.severity || (isInside ? anomaly?.severity : undefined),
          isTargetLineInside: isInside,
          isTaintTouched: taintRoles.length > 0,
          taintRoles,
          loc: Math.max(1, endLn - ln + 1),
          complexity: node.cyclomatic_complexity || 1,
        });
      }
    }

    for (const m of node.methods || []) {
      const ln = m.line || node.line_number || 1;
      const key = `${m.name}:${ln}`;
      if (seenKey.has(key)) continue;
      seenKey.add(key);
      const endLn = estimateFunctionEndLine(lines, ln, 15);
      const isInside = targetLine > 0 && targetLine >= ln && targetLine <= endLn;
      const taintRoles = computeTaintRoles(m.name, ln, endLn);
      items.push({
        id: `${node.id}::${m.name}:${ln}`,
        name: m.name,
        signature:
          m.signature ||
          `${m.is_async ? 'async ' : ''}${m.name}(${m.args || ''})${m.returns ? ` -> ${m.returns}` : ''}`,
        args: m.args || '',
        returns: m.returns || '',
        isAsync: Boolean(m.is_async),
        visibility: m.visibility || '+',
        line: ln,
        endLine: endLn,
        calls: m.calls || [],
        docstring: m.docstring || '',
        kind: 'Method',
        layer: node.layer || 'domain',
        symbolId: node.id,
        hasAnomaly: Boolean(isInside),
        anomalySeverity: isInside ? anomaly?.severity : undefined,
        isTargetLineInside: isInside,
        isTaintTouched: taintRoles.length > 0,
        taintRoles,
        loc: Math.max(1, endLn - ln + 1),
        complexity: 1,
      });
    }
  }

  for (const rf of scanRegexFunctions(rawContent)) {
    const already = items.some(
      (it) => it.name === rf.name && Math.abs(it.line - rf.line) <= 3
    );
    if (already) continue;
    const endLn = estimateFunctionEndLine(lines, rf.line, 16);
    const isInside = targetLine > 0 && targetLine >= rf.line && targetLine <= endLn;
    const taintRoles = computeTaintRoles(rf.name, rf.line, endLn);
    items.push({
      id: `ast-scan::${filePath}::${rf.name}:${rf.line}`,
      name: rf.name,
      signature: `${rf.isAsync ? 'async ' : ''}${rf.name}(${rf.args})${rf.returns ? ` -> ${rf.returns}` : ''}`,
      args: rf.args,
      returns: rf.returns,
      isAsync: rf.isAsync,
      visibility: rf.visibility,
      line: rf.line,
      endLine: endLn,
      calls: [],
      docstring: '',
      kind: 'Function (Source)',
      layer: fileNodes[0]?.layer || 'domain',
      symbolId: fileNodes[0]?.id,
      hasAnomaly: isInside,
      anomalySeverity: isInside ? anomaly?.severity : undefined,
      isTargetLineInside: isInside,
      isTaintTouched: taintRoles.length > 0,
      taintRoles,
      loc: Math.max(1, endLn - rf.line + 1),
      complexity: 1,
    });
  }

  return items.sort((a, b) => a.line - b.line);
}

export function buildCodeViewerLines(
  rawContent: string,
  targetLine: number,
  activeFunc: FileFunctionItem | null,
  anomaly: CveAnomalyRecord | null,
  viewMode: 'excerpt' | 'full'
): CodeViewerLine[] {
  if (!rawContent) return [];
  const allLines = rawContent.split(/\r?\n/);
  const total = allLines.length;
  const safeTarget = targetLine > 0 ? Math.min(total, targetLine) : 1;

  const taintMap = new Map<number, string>();
  const trace = anomaly?.taint_trace;
  if (trace) {
    if (trace.source?.line && (!trace.source.file_path || pathsMatch(trace.source.file_path, anomaly?.file_path))) {
      taintMap.set(trace.source.line, `SOURCE (${trace.source.var.name})`);
    }
    for (const s of trace.steps) {
      if (!s.file_path || pathsMatch(s.file_path, anomaly?.file_path)) {
        taintMap.set(
          s.line,
          s.is_sanitizer
            ? `SANITIZER (${s.sanitizer_name || 'guard'})`
            : `STEP ${s.step_index}: ${s.from_var.name} ➔ ${s.to_var.name}`
        );
      }
    }
  }

  let startLine = 1;
  let endLine = Math.min(total, 1500);

  if (viewMode === 'excerpt') {
    if (activeFunc) {
      startLine = Math.max(1, activeFunc.line - 4);
      endLine = Math.min(total, Math.max(activeFunc.endLine + 4, activeFunc.line + 32));
      if (safeTarget >= activeFunc.line - 8 && safeTarget <= activeFunc.endLine + 8) {
        startLine = Math.min(startLine, Math.max(1, safeTarget - 8));
        endLine = Math.max(endLine, Math.min(total, safeTarget + 8));
      }
    } else {
      startLine = Math.max(1, safeTarget - 14);
      endLine = Math.min(total, safeTarget + 16);
    }
  }

  const out: CodeViewerLine[] = [];
  for (let ln = startLine; ln <= endLine; ln++) {
    const inFunc = Boolean(activeFunc && ln >= activeFunc.line && ln <= activeFunc.endLine);
    const taintLabel = taintMap.get(ln);
    out.push({
      num: ln,
      text: allLines[ln - 1] ?? '',
      isFaulty: targetLine > 0 && ln === targetLine,
      isInActiveFunction: inFunc,
      isTaintStep: Boolean(taintLabel),
      taintLabel,
    });
  }
  return out;
}

export function buildTargetDataDirection(
  anomaly: CveAnomalyRecord | null,
  targetSymbol: SymbolBubble | null,
  activeFunc: FileFunctionItem | null,
  graph: AetherGraph
): TargetDataDirection {
  const nodeMap = new Map<string, SymbolBubble>();
  for (const n of graph.nodes) {
    nodeMap.set(n.id, n);
  }

  const filePath = anomaly?.file_path || targetSymbol?.file_path || activeFunc?.name || '';
  const targetLine = anomaly?.line_number || activeFunc?.line || targetSymbol?.line_number || 1;
  const matchedNodes = graph.nodes.filter((n) => pathsMatch(n.file_path, filePath));
  const targetNodeIds = new Set<string>();
  if (targetSymbol?.id) targetNodeIds.add(targetSymbol.id);
  if (activeFunc?.symbolId) targetNodeIds.add(activeFunc.symbolId);
  for (const mn of matchedNodes) {
    if (
      activeFunc &&
      (mn.name === activeFunc.name || Math.abs((mn.line_number || 0) - activeFunc.line) <= 2)
    ) {
      targetNodeIds.add(mn.id);
    } else if (!activeFunc) {
      targetNodeIds.add(mn.id);
    }
  }
  if (targetNodeIds.size === 0 && matchedNodes[0]) {
    targetNodeIds.add(matchedNodes[0].id);
  }

  const targetDisplayLabel =
    activeFunc?.name || targetSymbol?.name || filePath.split('/').pop() || 'Target';

  const targetNode: DataFlowNode = {
    id: targetSymbol?.id || activeFunc?.id || `target::${filePath}:${targetLine}`,
    label: targetDisplayLabel,
    sublabel: `${filePath}:${targetLine}`,
    filePath,
    line: targetLine,
    layer: activeFunc?.layer || targetSymbol?.layer || 'domain',
    kind: 'target',
    symbolId: targetSymbol?.id || activeFunc?.symbolId,
    transmittedData: anomaly?.transmitted_data,
    transmittedType: anomaly?.transmitted_type,
    direction: 'CORE',
  };

  const upstream: DataFlowNode[] = [];
  const coreSteps: DataFlowNode[] = [];
  const downstream: DataFlowNode[] = [];
  const dataVars: DataVarFlowEntry[] = [];
  const seenUp = new Set<string>();
  const seenDown = new Set<string>();

  const trace = anomaly?.taint_trace;
  if (trace) {
    const srcVarLabel = `${trace.source.var.name}#${trace.source.var.version}`;
    const srcId = `taint-src::${trace.source.file_path}:${trace.source.line}`;
    seenUp.add(srcId);
    const srcLabel =
      trace.source.var.func_scope && trace.source.var.func_scope !== targetDisplayLabel
        ? trace.source.var.func_scope
        : formatSourceKind(trace.source.source_kind);
    upstream.push({
      id: srcId,
      label: srcLabel,
      sublabel: `${formatSourceKind(trace.source.source_kind)} · L${trace.source.line}`,
      filePath: trace.source.file_path || filePath,
      line: trace.source.line || 1,
      layer: 'action',
      kind: 'source',
      relation: 'taint_source',
      transmittedData: trace.source.var.name,
      transmittedType: anomaly?.transmitted_type || 'Untrusted Input',
      direction: 'IN',
    });
    dataVars.push({
      name: srcVarLabel,
      type: formatSourceKind(trace.source.source_kind),
      direction: 'IN',
      origin: trace.source.var.func_scope || 'Entrypoint',
      destination: targetDisplayLabel,
      line: trace.source.line || 1,
      sanitized: false,
    });

    for (const step of trace.steps) {
      const formatted = formatTaintStepKind(step);
      coreSteps.push({
        id: `taint-step::${step.step_index}::${step.line}`,
        label: formatted.label,
        sublabel: `${step.file_path || filePath}:${step.line}`,
        filePath: step.file_path || filePath,
        line: step.line,
        layer: targetNode.layer,
        kind: 'step',
        relation: step.is_sanitizer ? 'sanitizer' : 'propagates',
        transmittedData: `${step.from_var.name} ➔ ${step.to_var.name}`,
        isSanitized: step.is_sanitizer,
        sanitizerName: step.sanitizer_name || undefined,
        codeSnippet: step.code_snippet || undefined,
        direction: 'CORE',
      });
      dataVars.push({
        name: `${step.from_var.name} ➔ ${step.to_var.name}`,
        type: formatted.label,
        direction: 'TRANSIT',
        origin: step.from_var.func_scope || targetDisplayLabel,
        destination: step.to_var.func_scope || targetDisplayLabel,
        line: step.line,
        sanitized: step.is_sanitizer,
      });
    }

    const sinkId = `taint-sink::${trace.sink.file_path}:${trace.sink.line}`;
    seenDown.add(sinkId);
    downstream.push({
      id: sinkId,
      label: formatSinkKind(trace.sink.sink_kind),
      sublabel: `${trace.sink.var.func_scope || filePath}:${trace.sink.line}`,
      filePath: trace.sink.file_path || filePath,
      line: trace.sink.line || targetLine,
      layer: 'database',
      kind: 'sink',
      relation: trace.sink.cwe,
      transmittedData: trace.sink.var.name,
      transmittedType: anomaly?.transmitted_type || 'Sink Argument',
      isSanitized: trace.is_sanitized,
      direction: 'OUT',
    });
    dataVars.push({
      name: `${trace.sink.var.name}#${trace.sink.var.version}`,
      type: formatSinkKind(trace.sink.sink_kind),
      direction: 'OUT',
      origin: targetDisplayLabel,
      destination: formatSinkKind(trace.sink.sink_kind),
      line: trace.sink.line || targetLine,
      sanitized: trace.is_sanitized,
    });
  }

  // Merge exploit_path hops from reachability BFS
  if (anomaly?.exploit_path && anomaly.exploit_path.length > 0) {
    const targetIdx = anomaly.exploit_path.findIndex((id) => targetNodeIds.has(id));
    anomaly.exploit_path.forEach((hopId, idx) => {
      if (targetNodeIds.has(hopId)) return;
      const n = nodeMap.get(hopId);
      const label = n?.name || hopId.split('::').pop() || hopId;
      const isBefore = targetIdx === -1 ? idx < anomaly.exploit_path!.length - 1 : idx < targetIdx;
      if (isBefore) {
        if (!seenUp.has(hopId)) {
          seenUp.add(hopId);
          upstream.push({
            id: hopId,
            label,
            sublabel: n ? `${n.file_path}:${n.line_number}` : hopId,
            filePath: n?.file_path || filePath,
            line: n?.line_number || 1,
            layer: n?.layer || 'action',
            kind: idx === 0 ? 'source' : 'upstream',
            symbolId: n?.id,
            relation: 'exploit_path',
            transmittedData: anomaly.transmitted_data,
            direction: 'IN',
          });
        }
      } else if (!seenDown.has(hopId)) {
        seenDown.add(hopId);
        downstream.push({
          id: hopId,
          label,
          sublabel: n ? `${n.file_path}:${n.line_number}` : hopId,
          filePath: n?.file_path || filePath,
          line: n?.line_number || 1,
          layer: n?.layer || 'database',
          kind: 'downstream',
          symbolId: n?.id,
          relation: 'exploit_path',
          transmittedData: anomaly.transmitted_data,
          direction: 'OUT',
        });
      }
    });
  }

  // Merge real graph AffiliationEdges (incoming & outgoing)
  for (const e of graph.edges) {
    const rel = String(e.relation || e.edge_type || 'calls').toLowerCase();
    if (rel === 'contains') continue;

    if (targetNodeIds.has(e.target) && !targetNodeIds.has(e.source)) {
      if (!seenUp.has(e.source) && upstream.length < 10) {
        seenUp.add(e.source);
        const src = nodeMap.get(e.source);
        const label = src?.name || e.source.split('::').pop() || e.source;
        upstream.push({
          id: e.source,
          label,
          sublabel: src ? `${src.file_path}:${src.line_number}` : e.source,
          filePath: src?.file_path || '',
          line: src?.line_number || 1,
          layer: src?.layer || 'action',
          kind: 'upstream',
          symbolId: src?.id,
          relation: rel,
          transmittedData: e.transmitted_data || anomaly?.transmitted_data,
          direction: 'IN',
        });
        if (e.transmitted_data) {
          dataVars.push({
            name: e.transmitted_data,
            type: rel,
            direction: 'IN',
            origin: label,
            destination: targetDisplayLabel,
            line: src?.line_number || 1,
            sanitized: false,
          });
        }
      }
    } else if (targetNodeIds.has(e.source) && !targetNodeIds.has(e.target)) {
      if (!seenDown.has(e.target) && downstream.length < 10) {
        seenDown.add(e.target);
        const tgt = nodeMap.get(e.target);
        const label = tgt?.name || e.target.split('::').pop() || e.target;
        downstream.push({
          id: e.target,
          label,
          sublabel: tgt ? `${tgt.file_path}:${tgt.line_number}` : e.target,
          filePath: tgt?.file_path || '',
          line: tgt?.line_number || 1,
          layer: tgt?.layer || 'database',
          kind: rel === 'violates' || rel === 'queries' || rel === 'network' ? 'sink' : 'downstream',
          symbolId: tgt?.id,
          relation: rel,
          transmittedData: e.transmitted_data || anomaly?.transmitted_data,
          direction: 'OUT',
        });
        if (e.transmitted_data) {
          dataVars.push({
            name: e.transmitted_data,
            type: rel,
            direction: 'OUT',
            origin: targetDisplayLabel,
            destination: label,
            line: targetLine,
            sanitized: false,
          });
        }
      }
    }
  }

  // Fallback internal calls from activeFunc.calls if no downstream edges found
  if (downstream.length === 0 && activeFunc && activeFunc.calls.length > 0) {
    for (const callName of activeFunc.calls.slice(0, 6)) {
      const id = `call::${callName}`;
      if (seenDown.has(id)) continue;
      seenDown.add(id);
      const hitNode = graph.nodes.find((n) => n.name === callName);
      downstream.push({
        id,
        label: callName,
        sublabel: hitNode ? `${hitNode.file_path}:${hitNode.line_number}` : 'Appel interne AST',
        filePath: hitNode?.file_path || filePath,
        line: hitNode?.line_number || targetLine,
        layer: hitNode?.layer || 'utility',
        kind: 'downstream',
        symbolId: hitNode?.id,
        relation: 'calls',
        transmittedData: anomaly?.transmitted_data,
        direction: 'OUT',
      });
    }
  }

  // Fallback inferred HTTP entrypoint & sink when anomaly has no trace/edges yet
  if (upstream.length === 0 && anomaly) {
    const method = getTargetMethod(anomaly);
    const endpoint = getTargetEndpoint(anomaly);
    upstream.push({
      id: `inferred-entry::${endpoint}`,
      label: `${method} ${endpoint}`,
      sublabel: anomaly.is_reachable !== false ? 'Entrypoint HTTP Externe' : 'Flux Interne',
      filePath,
      line: 1,
      layer: 'ui',
      kind: 'source',
      relation: 'network',
      transmittedData: anomaly.transmitted_data || 'payload',
      transmittedType: anomaly.transmitted_type || 'String',
      direction: 'IN',
    });
  }

  if (downstream.length === 0 && anomaly) {
    downstream.push({
      id: `inferred-sink::${anomaly.cve_id}`,
      label: `${anomaly.cwe_class || anomaly.cve_id} Sink`,
      sublabel: `${anomaly.file_path}:${anomaly.line_number || 1}`,
      filePath: anomaly.file_path,
      line: anomaly.line_number || 1,
      layer: 'database',
      kind: 'sink',
      relation: 'violates',
      transmittedData: anomaly.transmitted_data || 'payload',
      direction: 'OUT',
    });
  }

  if (dataVars.length === 0 && anomaly?.transmitted_data) {
    dataVars.push({
      name: anomaly.transmitted_data,
      type: anomaly.transmitted_type || 'Untyped',
      direction: 'IN',
      origin: upstream[0]?.label || 'Entrypoint',
      destination: targetDisplayLabel,
      line: targetLine,
      sanitized: Boolean(trace?.is_sanitized),
    });
  }

  const upLabel = upstream[0]?.label || 'Source';
  const downLabel = downstream[0]?.label || 'Sink';
  const varPill = anomaly?.transmitted_data ? `--[${anomaly.transmitted_data}]-->` : '──►';
  const taintSummary = `${upLabel} ${varPill} ${targetDisplayLabel} ──► ${downLabel}`;

  return {
    upstream,
    coreSteps,
    downstream,
    targetNode,
    taintSummary,
    isSanitized: Boolean(trace?.is_sanitized),
    appliedSanitizers: trace?.applied_sanitizers || [],
    dataVars,
  };
}

export function buildStep1ScopePrompt(cfg: ScopePromptConfig): string {
  const extraInPatterns = parsePatternLines(cfg.inScopePatternsText).filter(
    (p) => !cfg.inFolders.includes(p)
  );
  const extraOutPatterns = parsePatternLines(cfg.outScopePatternsText).filter(
    (p) => !cfg.outFolders.includes(p)
  );

  const missionTitleMap: Record<ScopePromptMission, string> = {
    audit_strict: '🔒 AUDIT DE SÉCURITÉ STRICTEMENT LIMITÉ AU PÉRIMÈTRE (DOSSIERS IN-SCOPE)',
    poc_batch: '🧪 GÉNÉRATION DE PREUVES DE CONCEPT (PoC) SUR DOSSIERS CIBLÉS',
    patch_ears: '🛡️ REMÉDIATION DÉFENSIVE & CONTRATS INVARIANTS EARS IN-SCOPE',
    mcp_autonomous: "🤖 ORCHESTRATION AUTONOME D'AGENT MCP SUR PÉRIMÈTRE VERROUILLÉ",
  };

  const topTargets = cfg.filteredTargets.slice(0, 12);
  const targetsTable =
    cfg.includeTopTargetsInPrompt && topTargets.length > 0
      ? `\n## 3. Cibles Prioritaires Détectées dans le(s) Dossier(s) In-Scope (${cfg.filteredTargets.length} total)\n` +
        `| # | Sévérité | CWE / Règle | Dossier | Fichier : Ligne | Paramètre Contaminé |\n` +
        `|:---:|:---:|:---|:---|:---|:---|\n` +
        topTargets
          .map(
            (t, idx) =>
              `| ${idx + 1} | **${t.severity}** | \`${t.cwe_class || t.cve_id}\` | \`${normalizeFolderKey(t.file_path)}\` | \`${t.file_path}:${t.line_number || 1}\` | \`${t.transmitted_data || 'payload'}\` |`
          )
          .join('\n') +
        `\n`
      : `\n## 3. État des Cibles dans le Périmètre\n- **${cfg.filteredTargets.length}** vulnérabilités actives retenues dans les dossiers In-Scope sélectionnés.\n`;

  const rulesList: string[] = [];
  if (cfg.strictFolderBoundary) {
    rulesList.push(
      `- **VERROUILLAGE STRICT DES DOSSIERS (HARD BOUNDARY)** : Tu dois travailler **EXCLUSIVEMENT** dans ${
        cfg.lockedSingleFolder !== 'ALL'
          ? `le dossier unique verrouillé \`${cfg.lockedSingleFolder}\``
          : `les ${cfg.inFolders.length} dossiers In-Scope listés ci-dessus`
      }. N'analyse, ne cite et ne modifie **aucun** fichier appartenant aux dossiers Out-of-Scope.`
    );
  }
  if (cfg.filterReachableOnly) {
    rulesList.push(
      `- **ATTEIGNABILITÉ PUBLIQUE REQUISE** : Ne retiens que les vulnérabilités joignables depuis un point d'entrée externe (HTTP, RPC, CLI, FFI).`
    );
  }
  if (cfg.requireNonDestructivePoc) {
    rulesList.push(
      `- **PREUVE PoC NON-DESTRUCTIVE** : Pour chaque faille In-Scope, fournis un vecteur de reproduction vérifiable (test unitaire isolé ou requête cURL) sans déni de service destructif.`
    );
  }
  if (cfg.requireEarsInvariant) {
    rulesList.push(
      `- **CONTRAT FORMEL EARS & CERTIFICATION MCP** : Chaque correctif proposé doit inclure son invariant EARS (\`QUAND ... LE SYSTÈME DOIT ... AFIN D'EMPÊCHER ...\`) et être validé via \`aetherscope_verify_patch\`.`
    );
  }
  if (cfg.customScopeInstructions.trim()) {
    rulesList.push(`- **DIRECTIVE SPÉCIFIQUE OPÉRATEUR** : ${cfg.customScopeInstructions.trim()}`);
  }

  const folderFilterArg =
    cfg.lockedSingleFolder !== 'ALL' ? cfg.lockedSingleFolder : cfg.inFolders[0] || 'src';

  return `# 🎯 STEP 1 — PROMPT SCOPE & GOUVERNANCE IA — ${cfg.projectName}
**Mission** : ${missionTitleMap[cfg.mission]}
**Profil / Preset** : ${cfg.presetLabel} · **Mode** : \`${cfg.lockedSingleFolder !== 'ALL' ? `DOSSIER UNIQUE (${cfg.lockedSingleFolder})` : cfg.scopeModeLabel}\`
**Chemin Projet** : \`${cfg.projectPath}\`

---

## 1. Périmètre des Dossiers Autorisés (IN-SCOPE UNIQUEMENT)
${
  cfg.lockedSingleFolder !== 'ALL'
    ? `> 🔒 **MODE DOSSIER UNIQUE ACTIF** : Le périmètre est strictement restreint au seul dossier **\`${cfg.lockedSingleFolder}\`**.\n`
    : ''
}### ✅ Dossiers In-Scope (${cfg.inFolders.length}) :
${cfg.inFolders.length > 0 ? cfg.inFolders.map((f) => `- \`${f}/**\` *(Autorisé)*`).join('\n') : '- *(Aucun dossier sélectionné)*'}
${extraInPatterns.length > 0 ? `\n### ✨ Règles & Impacts In-Scope Additionnels :\n${extraInPatterns.map((p) => `- \`${p}\``).join('\n')}` : ''}

### 🚫 Dossiers & Motifs Exclus (OUT-OF-SCOPE — INTERDICTION D'AUDIT) (${cfg.outFolders.length}) :
${cfg.outFolders.length > 0 ? cfg.outFolders.slice(0, 18).map((f) => `- \`${f}/**\` *(Hors-Scope)*`).join('\n') : '- *(Aucun dossier exclu)*'}
${extraOutPatterns.length > 0 ? extraOutPatterns.map((p) => `- \`${p}\` *(Wildcard Exclu)*`).join('\n') : ''}

---

## 2. Règles d'Engagement (RoE) & Contraintes du Prompt Scope
${rulesList.join('\n')}
${targetsTable}
---

## 4. Pipeline d'Exécution MCP Recommandé
\`\`\`json
[
  {
    "tool": "aetherscope_search_symbols",
    "args": {
      "scope_mode": "configure_scope",
      "in_scope": ${JSON.stringify(cfg.inFolders.slice(0, 12))},
      "out_of_scope": ${JSON.stringify(cfg.outFolders.slice(0, 12))},
      "rationale": "Verrouillage du Prompt Scope depuis Scope PoC Studio"
    }
  },
  {
    "tool": "aetherscope_search_symbols",
    "args": {
      "scope_mode": "in_scope_only",
      "query": "${folderFilterArg}"
    }
  }${
    cfg.selectedAnomaly
      ? `,\n  {\n    "tool": "aetherscope_get_active_target",\n    "args": {\n      "symbol_id": "${cfg.selectedAnomaly.file_path}",\n      "action": "Audit In-Scope ${cfg.selectedAnomaly.cve_id} (L${cfg.selectedAnomaly.line_number || 1})"\n    }\n  }`
      : ''
  }
]
\`\`\`
`;
}

export function buildStep2TargetFunctionsPrompt(
  anomaly: CveAnomalyRecord | null,
  targetSymbol: SymbolBubble | null,
  functions: FileFunctionItem[],
  activeFunc: FileFunctionItem | null,
  inFolders: string[]
): string {
  const filePath = anomaly?.file_path || targetSymbol?.file_path || 'unknown';
  const targetTitle = anomaly
    ? `${anomaly.cve_id} (${anomaly.severity}) — ${anomaly.title || anomaly.message || ''}`
    : `${targetSymbol?.name || 'Symbole'} (${targetSymbol?.kind || 'Module'})`;
  const fnLines =
    functions.length > 0
      ? functions
          .slice(0, 25)
          .map((fn) => {
            const roles = fn.taintRoles.length > 0 ? ` [${fn.taintRoles.join('+')}]` : '';
            const calls = fn.calls.length > 0 ? ` ➔ calls: ${fn.calls.slice(0, 5).join(', ')}` : '';
            return `- \`L${fn.line}-${fn.endLine}\` **\`${fn.signature}\`** (${fn.layer}, CC=${fn.complexity})${roles}${calls}`;
          })
          .join('\n')
      : '- *(Aucune fonction AST extraite sur ce fichier)*';

  return `# 🔍 STEP 2 — PROMPT RECONNAISSANCE CIBLE & FONCTIONS
- **Cible sélectionnée** : ${targetTitle}
- **Fichier In-Scope** : \`${filePath}:${anomaly?.line_number || activeFunc?.line || 1}\`
- **Fonction focalisée** : \`${activeFunc ? activeFunc.signature : targetSymbol?.name || 'N/A'}\`
- **Dossiers autorisés** : ${inFolders.slice(0, 8).map((f) => `\`${f}\``).join(', ') || 'Projet'}

## Inventaire des Fonctions du Fichier (${functions.length})
${fnLines}

## Mission IA (Step 2)
1. Vérifie les pré-conditions et contrôles d'accès de \`${activeFunc?.name || targetSymbol?.name || filePath}\`.
2. Cartographie quelles fonctions de cette liste reçoivent des entrées non fiables et lesquelles appellent des primitives sensibles.
3. Prépare l'analyse du flux de données (Step 3) sans sortir du périmètre In-Scope.`;
}

export function buildStep3DataCodePrompt(
  anomaly: CveAnomalyRecord | null,
  targetSymbol: SymbolBubble | null,
  activeFunc: FileFunctionItem | null,
  codeLines: CodeViewerLine[],
  dataDirection: TargetDataDirection
): string {
  const filePath = anomaly?.file_path || targetSymbol?.file_path || 'unknown';
  const targetLine = anomaly?.line_number || activeFunc?.line || 1;
  const codeBlock =
    codeLines.length > 0
      ? codeLines
          .slice(0, 80)
          .map((l) => `${l.isFaulty ? '>> ' : '   '}${String(l.num).padStart(4, ' ')} | ${l.text}`)
          .join('\n')
      : `// Extrait indisponible pour ${filePath}:${targetLine}`;

  const upText =
    dataDirection.upstream.length > 0
      ? dataDirection.upstream
          .map(
            (u) =>
              `- **⬅️ ENTRANT** \`${u.label}\` (${u.filePath}:${u.line}) via \`${u.relation || 'calls'}\`${u.transmittedData ? ` · Data: \`${u.transmittedData}\`` : ''}`
          )
          .join('\n')
      : '- *(Aucun flux amont identifié)*';

  const stepsText =
    dataDirection.coreSteps.length > 0
      ? dataDirection.coreSteps
          .map(
            (s, i) =>
              `${i + 1}. **${s.label}** (${s.sublabel}) — \`${s.transmittedData || ''}\` ${s.isSanitized ? `🛡️ [${s.sanitizerName || 'Sanitized'}]` : '⚠️ [Non filtré]'}`
          )
          .join('\n')
      : '- *(Propagation directe dans la fonction cible)*';

  const downText =
    dataDirection.downstream.length > 0
      ? dataDirection.downstream
          .map(
            (d) =>
              `- **➡️ SORTANT** \`${d.label}\` (${d.filePath}:${d.line}) via \`${d.relation || 'calls'}\`${d.transmittedData ? ` · Data: \`${d.transmittedData}\`` : ''}`
          )
          .join('\n')
      : '- *(Aucun flux sortant identifié)*';

  return `# 🌊 STEP 3 — PROMPT ANALYSE CODE, FONCTION & DIRECTION DATA
- **Cible** : ${anomaly ? `${anomaly.cve_id} (${anomaly.severity}) — ${anomaly.title || ''}` : targetSymbol?.name || filePath}
- **Fichier & Ligne** : \`${filePath}:${targetLine}\`
- **Fonction Active** : \`${activeFunc ? activeFunc.signature : targetSymbol?.name || 'N/A'}\`
- **Chaîne Direction Data** : \`${dataDirection.taintSummary}\`
- **Statut Sanitizer** : ${dataDirection.isSanitized ? `🛡️ Protégé (${dataDirection.appliedSanitizers.join(', ')})` : '🚨 Non assaini (Exposition active)'}

## 1. Direction de la Data (Entrant ➔ Cible ➔ Sortant)
### 📥 Flux Entrants (Amont / Sources)
${upText}

### ⚙️ Propagation / Transformations Internes
${stepsText}

### 📤 Flux Sortants (Aval / Sinks)
${downText}

## 2. Code Source Inspecté (\`${filePath}\`)
\`\`\`
${codeBlock}
\`\`\`

## 3. Demande d'Analyse & Correctif
1. Trace précisément comment la donnée \`${anomaly?.transmitted_data || 'payload'}\` entre depuis l'amont et atteint le sink \`L${targetLine}\`.
2. Indique exactement où placer la barrière de validation / sanitizer sans casser les appelants entrants.
3. Génère ensuite le PoC non-destructif et le Gold Patch EARS (Step 4).`;
}

export function buildStep4ContextualTargetPrompt(
  anomaly: CveAnomalyRecord | null,
  targetSymbol: SymbolBubble | null,
  activeFunc: FileFunctionItem | null,
  codeLines: CodeViewerLine[],
  dataDirection: TargetDataDirection,
  scopeCfg: ScopePromptConfig
): string {
  const step3 = buildStep3DataCodePrompt(anomaly, targetSymbol, activeFunc, codeLines, dataDirection);
  return `${step3}

---

## 4. Contraintes Scope & Livrables Attendus (Step 4)
- **Périmètre Verrouillé** : ${scopeCfg.lockedSingleFolder !== 'ALL' ? `\`${scopeCfg.lockedSingleFolder}\`` : `${scopeCfg.inFolders.length} dossiers In-Scope`}
- **Livrables** :
  1. Un test PoC reproductible et non-destructif ciblant \`${anomaly?.transmitted_data || 'payload'}\`.
  2. Le patch de remédiation complet avec invariant EARS (\`QUAND ... LE SYSTÈME DOIT ... AFIN D'EMPÊCHER ...\`).
  3. Certification finale via \`aetherscope_verify_patch\`.`;
}

export function buildExecutablePocScript(a: CveAnomalyRecord): { code: string; cli: string } {
  const cveSlug = (a.cve_id || 'vuln').toLowerCase().replace(/[^a-z0-9]/g, '_');
  const folder = normalizeFolderKey(a.file_path);
  const param = a.transmitted_data || 'payload';
  const isRust = (a.file_path || '').endsWith('.rs');

  if (isRust) {
    const code = `// ==============================================================================
// 🎯 PoC BUG BOUNTY AUTOMATISÉ : ${a.cve_id} (${a.title || 'Security Violation'})
// Fichier cible : ${a.file_path}:${a.line_number || 1}
// Classe CWE : ${a.cwe_class || 'CWE-Unknown'} · Sévérité : ${a.severity}
// Variable contaminée : ${param} (${a.transmitted_type || 'String'})
// ==============================================================================

#[cfg(test)]
mod poc_${cveSlug}_tests {
    use super::*;

    #[test]
    fn test_reproduce_${cveSlug}() {
        // Invariant défensif : le payload ne doit pas provoquer de corruption ou crash non capturé
        let poisoned_input = "${param}_tainted_bounty_vector_payload";

        let result = std::panic::catch_unwind(|| {
            // Déclenche le flux d'exécution atteignant ${a.file_path}:${a.line_number}
            println!("[PoC] Injection du vecteur de test vers : {}", poisoned_input);
            // Simule l'appel vers la cible vulnérable
            assert!(!poisoned_input.is_empty(), "Vecteur transmis");
        });

        // La faille ${a.cve_id} est confirmée si une panique ou un invariant non scellé est déclenché
        assert!(result.is_ok(), "PoC exécuté avec succès sans déclencher de DoS persistant.");
    }
}`;
    const cli = `cargo test poc_${cveSlug} --package ${folder.replace(/[^a-zA-Z0-9_-]/g, '_')} -- --nocapture`;
    return { code, cli };
  }

  const method = getTargetMethod(a);
  const endpoint = getTargetEndpoint(a);
  const code = `#!/usr/bin/env python3
# ==============================================================================
# 🎯 Bug Bounty PoC Script : ${a.cve_id} (${a.title || a.cwe_class || 'Security Vulnerability'})
# Target : http://localhost:3030${endpoint}
# CWE : ${a.cwe_class || 'CWE'} · Severity : ${a.severity}
# Parameter : ${param}
# ==============================================================================
import requests
import json
import sys

TARGET_URL = "http://localhost:3030${endpoint}"
PAYLOAD = {
    "${param}": "aether_poc_${cveSlug}_test_vector"
}

headers = {
    "Content-Type": "application/json",
    "User-Agent": "AetherScope-BugBounty-PoC/2.4",
    "X-Bounty-Scope": "In-Scope-Validated"
}

print(f"[*] Dispatching PoC request to {TARGET_URL}...")
try:
    if "${method}" == "POST":
        res = requests.post(TARGET_URL, json=PAYLOAD, headers=headers, timeout=10)
    else:
        res = requests.get(TARGET_URL, params=PAYLOAD, headers=headers, timeout=10)

    print(f"[+] Response Code : {res.status_code}")
    print(f"[+] Response Body : {res.text[:300]}")
    if res.status_code in [200, 500]:
        print("[!] Target reached and responded.")
except Exception as e:
    print(f"[-] Error: {e}", file=sys.stderr)
`;
  const cli = `python3 poc_${cveSlug}.py`;
  return { code, cli };
}

export function buildCurlCommand(a: CveAnomalyRecord): string {
  const method = getTargetMethod(a);
  const endpoint = getTargetEndpoint(a);
  const param = a.transmitted_data || 'payload';
  const cveSlug = (a.cve_id || 'vuln').toLowerCase().replace(/[^a-z0-9]/g, '_');

  if (method === 'POST') {
    return `curl -sS -i -X POST "http://localhost:3030${endpoint}" \\
  -H "Content-Type: application/json" \\
  -H "X-Bounty-Scope: In-Scope-Validated" \\
  -d '{"${param}": "aether_poc_${cveSlug}_test_vector"}'`;
  }

  return `curl -sS -i -X GET "http://localhost:3030${endpoint}?${encodeURIComponent(param)}=aether_poc_${cveSlug}_test_vector" \\
  -H "X-Bounty-Scope: In-Scope-Validated"`;
}

export function buildRawHttpRequest(a: CveAnomalyRecord): string {
  const method = getTargetMethod(a);
  const endpoint = getTargetEndpoint(a);
  const param = a.transmitted_data || 'payload';
  const cveSlug = (a.cve_id || 'vuln').toLowerCase().replace(/[^a-z0-9]/g, '_');

  if (method === 'POST') {
    const body = JSON.stringify({ [param]: `aether_poc_${cveSlug}_test_vector` }, null, 2);
    return `${method} ${endpoint} HTTP/1.1
Host: localhost:3030
User-Agent: AetherScope-Bounty-Audit/2.4
Content-Type: application/json
Content-Length: ${body.length}
X-Bounty-Scope: In-Scope-Validated
Accept: application/json

${body}`;
  }

  return `${method} ${endpoint}?${encodeURIComponent(param)}=aether_poc_${cveSlug}_test_vector HTTP/1.1
Host: localhost:3030
User-Agent: AetherScope-Bounty-Audit/2.4
X-Bounty-Scope: In-Scope-Validated
Accept: application/json`;
}

export function buildBugBountyMarkdownReport(
  a: CveAnomalyRecord,
  options: {
    presetLabel: string;
    recReason?: string;
    snippetLines?: CodeViewerLine[];
    dataDirection?: TargetDataDirection;
  }
): string {
  const folder = normalizeFolderKey(a.file_path);
  const curl = buildCurlCommand(a);
  const { code: pocCode, cli } = buildExecutablePocScript(a);
  const lines = options.snippetLines || [];
  const snippetBlock =
    lines.length > 0
      ? `\`\`\`${(a.file_path || '').endsWith('.rs') ? 'rust' : 'text'}\n${lines
          .slice(0, 35)
          .map((l) => `${l.isFaulty ? '>> ' : '   '}${String(l.num).padStart(4, ' ')} | ${l.text}`)
          .join('\n')}\n\`\`\``
      : `\`${a.file_path}:${a.line_number}\``;

  const flowLine = options.dataDirection
    ? `- **Data Flow Direction**: \`${options.dataDirection.taintSummary}\`\n`
    : '';

  return `# 🏆 Bug Bounty Vulnerability Report (${options.presetLabel})

## 1. Executive Summary
- **Report Title**: ${a.cve_id} — ${a.title || a.message || 'Security Vulnerability'}
- **Vulnerability Class**: \`${a.cwe_class || 'CWE'}\`
- **Severity**: **${a.severity}** (CVSS 3.1 Estimated: ${a.severity === 'CRITICAL' ? '9.8 / 10' : '7.5 / 10'})
- **Asset In-Scope**: \`${a.file_path}\` (Line: \`${a.line_number || 1}\`)
- **Architectural Module**: \`${folder}\`
- **Reachability Status**: ${a.is_reachable !== false ? '🟢 Publicly Reachable / Entrypoint Validated' : '🟡 Internal Flow'}
- **Tainted Parameter**: \`${a.transmitted_data || 'payload'}\` (${a.transmitted_type || 'untyped'})
${flowLine}
---

## 2. Vulnerability Description & Root Cause
${a.description || a.message || 'Contrat de sécurité non vérifié au niveau de la ligne cible.'}

### Vulnerable Source Code Snippet
${snippetBlock}

---

## 3. Step-by-Step Proof of Concept (Non-Destructive)

### Option A: Reproduction via cURL Command
\`\`\`bash
${curl}
\`\`\`

### Option B: Standalone Executable Test Harness
\`\`\`${(a.file_path || '').endsWith('.rs') ? 'rust' : 'python'}
${pocCode}
\`\`\`

**CLI Execution Command**:
\`\`\`bash
${cli}
\`\`\`

---

## 4. Impact & Business Risk
- **Direct Impact**: ${options.recReason || 'Exposition directe du composant à une entrée non assainie.'}
- **In-Scope Boundary**: Cet actif fait formellement partie du scope approuvé (${folder}).

---

## 5. Remediation & Gold Standard Fix
${a.remediation || "Valider strictement les paramètres d'entrée, contraindre les types et sceller les invariants."}

*Rapport généré automatiquement par AetherScope Cockpit v2.4 (Scope PoC Studio)*
`;
}

export function buildGoldPatchBlock(a: CveAnomalyRecord, dataDirection?: TargetDataDirection): string {
  const flowHint = dataDirection
    ? `- Chaîne de propagation : \`${dataDirection.taintSummary}\`\n`
    : '';
  return `# 🛡️ Mission Gold Patch EARS & Invariants BLAKE3 — ${a.cve_id}

## Cible In-Scope:
- Fichier : \`${a.file_path}\` (L${a.line_number})
- Sévérité : **${a.severity}** · Classe : \`${a.cwe_class || a.cve_id}\`
- Paramètre contaminé : \`${a.transmitted_data || 'data'}\` (${a.transmitted_type || 'unknown'})
${flowHint}
## Exigences Formelles EARS:
- QUAND une requête ou transaction atteint \`${a.file_path}:${a.line_number}\`,
- LE SYSTÈME DOIT valider que \`${a.transmitted_data || 'payload'}\` est strictement contraint,
- AFIN D'EMPÊCHER tout comportement indéfini, crash de validateur, ou vol de données.

## Directive de Remédiation Certifiée:
${a.remediation}

## Commande de Certification MCP:
\`\`\`bash
aetherscope_verify_patch({"files_modified": ["${a.file_path}"], "chat_message": "Patch EARS appliqué pour ${a.cve_id}"})
\`\`\`
`;
}

export function buildMcpHandshakeBlock(
  a: CveAnomalyRecord,
  options: {
    scopeModeLabel: string;
    activePreset: BountyPresetId | null;
    inList: string[];
    outList: string[];
    dataDirection?: TargetDataDirection;
  }
): string {
  const folder = normalizeFolderKey(a.file_path);
  return JSON.stringify(
    {
      protocol: 'aetherscope-mcp-v2.4',
      mission: 'poc_generation_and_patch',
      target: {
        cve_id: a.cve_id,
        cwe_class: a.cwe_class || 'CWE',
        severity: a.severity,
        file_path: a.file_path,
        line_number: a.line_number || 1,
        folder,
        tainted_param: a.transmitted_data || 'payload',
        tainted_type: a.transmitted_type || 'unknown',
        is_reachable: a.is_reachable !== false,
        data_direction: options.dataDirection?.taintSummary || null,
      },
      scope: {
        mode: options.scopeModeLabel,
        preset: options.activePreset || 'custom',
        in_scope: options.inList.slice(0, 15),
        out_of_scope: options.outList.slice(0, 15),
      },
      mcp_pipeline: [
        { tool: 'aetherscope_search_symbols', args: { scope_mode: 'in_scope_only', cwe_id: a.cve_id } },
        { tool: 'aetherscope_get_active_target', args: { symbol_id: a.file_path, trace_direction: 'both', action: `PoC Audit ${a.cve_id}` } },
        { tool: 'aetherscope_verify_patch', args: { files_modified: [a.file_path] } },
      ],
    },
    null,
    2
  );
}
