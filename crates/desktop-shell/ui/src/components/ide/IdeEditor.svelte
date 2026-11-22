<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { cockpitState, isLinesExceededAnomaly, formatCweShortId } from '../../state/graphState.svelte';
  import { api } from '../../lib/api';
  import type { SymbolBubble, CveAnomalyRecord } from '../../types/graph';
  import {
    Save,
    Search,
    X,
    ChevronDown,
    ChevronUp,
    ChevronRight,
    RefreshCw,
    Check,
    AlertCircle,
    Code2,
    Eye,
    Edit3,
    XCircle,
    BookOpen,
    SlidersHorizontal,
    Maximize2,
    Minimize2,
    ShieldAlert,
    ShieldCheck,
    Lock,
    Orbit,
    ArrowDownLeft,
    ArrowUpRight,
    Bot,
    Sparkles,
    EyeOff
  } from '@lucide/svelte';

  interface HistorySnapshot {
    content: string;
    cursorLine: number;
    cursorCol: number;
  }

  interface FileBuffer {
    content: string;
    savedContent: string;
    cursorLine: number;
    cursorCol: number;
    undoStack: HistorySnapshot[];
    redoStack: HistorySnapshot[];
  }

  interface LineDiagnostic {
    id: string;
    ruleId: string;
    cveId: string;
    displayId: string;
    severity: string;
    line: number;
    message: string;
    remediation: string;
    nodeId?: string;
  }

  // Multi-tab in-memory buffers preserving uncommitted edits and undo/redo stacks across tab switches
  let buffers = $state<Record<string, FileBuffer>>({});

  let content = $state('');
  let savedContent = $state('');
  let loadedFile = $state<string | null>(null);
  let isLoading = $state(false);
  let isSaving = $state(false);
  let isSealingBlake3 = $state(false);
  let errorMessage = $state<string | null>(null);
  let successNotice = $state<string | null>(null);
  let externalConflictContent = $state<string | null>(null);
  let lastHandledFsVersion = 0;

  // Target line highlight flash (active for ~2.5s on jump)
  let highlightedLine = $state<number | null>(null);
  let highlightTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingAutoSave = false;

  // Go-to-line (Ctrl+G) overlay state
  let isGotoLineOpen = $state(false);
  let gotoLineInput = $state('');
  let gotoInputEl = $state<HTMLInputElement | null>(null);

  // Editor View Mode: 'edit' (unified transparent textarea + syntax overlay) or 'preview'
  let editorViewMode = $state<'edit' | 'preview'>('edit');

  // Tab Sizing Mode: 'compact' | 'auto' | 'expanded'
  let tabSizeMode = $state<'auto' | 'compact' | 'expanded'>('auto');

  // Search & Replace overlay state (Ctrl+F / Ctrl+H)
  let isSearchOpen = $state(false);
  let isReplaceOpen = $state(false);
  let searchQuery = $state('');
  let replaceQuery = $state('');
  let searchInputEl = $state<HTMLInputElement | null>(null);
  let textareaEl = $state<HTMLTextAreaElement | null>(null);
  let gutterEl = $state<HTMLDivElement | null>(null);
  let backdropEl = $state<HTMLDivElement | null>(null);
  let previewContainerEl = $state<HTMLDivElement | null>(null);

  // Call-graph dropdown state in AST Breadcrumb bar
  let openCallMenu = $state<'callers' | 'callees' | null>(null);
  let activeDiagnosticPopoverLine = $state<number | null>(null);

  let cursorLine = $state(1);
  let cursorCol = $state(1);

  function normalizeRelPath(p?: string | null): string {
    return String(p || '')
      .replace(/\\/g, '/')
      .replace(/^\.\//, '')
      .replace(/^\/+/, '')
      .trim();
  }

  function normalizeLowerPath(p?: string | null): string {
    return normalizeRelPath(p).toLowerCase();
  }

  // Effective cursor line (reacts to cockpitState.ideCursorPosition and ideTargetLine in SSR & live)
  let effectiveCursorLine = $derived(
    cockpitState.ideCursorPosition?.line || cockpitState.ideTargetLine || cursorLine || 1
  );

  // Is buffer dirty (unsaved changes)
  let isDirty = $derived(content !== savedContent);

  function isTabDirty(filePath: string): boolean {
    if (filePath === loadedFile) return isDirty;
    const b = buffers[filePath];
    return Boolean(b && b.content !== b.savedContent);
  }

  // Split lines
  let lines = $derived(content.split('\n'));
  let lineCount = $derived(Math.max(1, lines.length));

  // Git Status lookup per normalized relative path (F14)
  function mapGitBadge(status?: string | null): { badge: string; cls: string; label: string } | null {
    const s = String(status || '').toLowerCase().trim();
    if (s === 'modified' || s === 'm') {
      return { badge: 'M', cls: 'bg-amber-500/20 text-amber-300 border-amber-500/40', label: 'Modifié (Git)' };
    }
    if (s === 'staged' || s === 'added' || s === 'a') {
      return { badge: 'A', cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40', label: 'Indexé / Ajouté (Git)' };
    }
    if (s === 'untracked' || s === '?') {
      return { badge: '?', cls: 'bg-sky-500/20 text-sky-300 border-sky-500/40', label: 'Non suivi (Git)' };
    }
    if (s === 'deleted' || s === 'd') {
      return { badge: 'D', cls: 'bg-rose-500/20 text-rose-300 border-rose-500/40', label: 'Supprimé (Git)' };
    }
    if (s === 'renamed' || s === 'r') {
      return { badge: 'R', cls: 'bg-purple-500/20 text-purple-300 border-purple-500/40', label: 'Renommé (Git)' };
    }
    if (s === 'conflict' || s === '!') {
      return { badge: '!', cls: 'bg-red-500/25 text-red-200 border-red-500/50', label: 'Conflit (Git)' };
    }
    return null;
  }

  let gitStatusByPath = $derived.by(() => {
    const map = new Map<string, { badge: string; cls: string; label: string }>();
    const gs = cockpitState.gitStatus;
    if (!gs || !gs.is_git_repo || !Array.isArray(gs.files)) return map;
    for (const f of gs.files) {
      if (!f || !f.path) continue;
      const norm = normalizeLowerPath(f.path);
      const info = mapGitBadge(f.status);
      if (norm && info) {
        map.set(norm, info);
      }
    }
    return map;
  });

  function getTabGitBadge(tabPath: string): { badge: string; cls: string; label: string } | null {
    const norm = normalizeLowerPath(tabPath);
    return gitStatusByPath.get(norm) || null;
  }

  // Syntax language detection based on extension
  let syntaxLanguage = $derived.by(() => {
    if (!cockpitState.ideActiveFile) return 'text';
    const ext = cockpitState.ideActiveFile.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'rs':
        return 'rust';
      case 'ts':
      case 'tsx':
        return 'typescript';
      case 'js':
      case 'jsx':
      case 'mjs':
        return 'javascript';
      case 'py':
        return 'python';
      case 'json':
        return 'json';
      case 'toml':
        return 'toml';
      case 'md':
        return 'markdown';
      case 'svelte':
        return 'svelte';
      default:
        return 'text';
    }
  });

  let targetLine = $derived(cockpitState.ideTargetLine);
  let activeFileNorm = $derived(normalizeLowerPath(cockpitState.ideActiveFile));

  // All graph nodes belonging to the active file
  let activeFileNodes = $derived.by<SymbolBubble[]>(() => {
    if (!activeFileNorm) return [];
    return (cockpitState.graph.nodes || []).filter(
      (n) => n.file_path && normalizeLowerPath(n.file_path) === activeFileNorm
    );
  });

  // File container node (or primary node) for active file metadata/contracts
  let activeFilePrimaryNode = $derived.by<SymbolBubble | null>(() => {
    if (activeFileNodes.length === 0) return null;
    return (
      activeFileNodes.find(
        (n) => n.is_file || String(n.kind).toLowerCase() === 'file' || String(n.kind) === '1' || n.id.startsWith('file::')
      ) || activeFileNodes[0]
    );
  });

  // F11: Per-file SAST/CWE diagnostics extracted from cockpitState.graph.nodes
  let fileDiagnostics = $derived.by<LineDiagnostic[]>(() => {
    const _filterVer = cockpitState.filterVersion;
    const _ignored = cockpitState.settings.ignoredCwes;
    if (!activeFileNorm || activeFileNodes.length === 0) return [];

    const list: LineDiagnostic[] = [];
    const seen = new Set<string>();
    const maxL = Math.max(1, lineCount);

    for (const n of activeFileNodes) {
      const rawAnoms: Partial<CveAnomalyRecord>[] = [
        ...(n.anomalies || []),
        ...(n.violations || []),
        ...(n.metadata?.cve_anomalies || [])
      ];

      if (rawAnoms.length > 0) {
        for (const a of rawAnoms) {
          if (!a || isLinesExceededAnomaly(a)) continue;
          const ruleId = String(a.rule_id || a.cve_id || 'CWE-SAST').trim();
          const cveId = String(a.cve_id || a.cwe_class || ruleId).trim();
          if (cockpitState.isCweIgnored(ruleId, cveId)) continue;

          const rawLine = Number(a.line_number ?? n.line_number ?? 1);
          const clampedLine = Math.max(1, Math.min(maxL, Number.isFinite(rawLine) && rawLine > 0 ? Math.floor(rawLine) : 1));
          const displayId = formatCweShortId(cveId, ruleId);
          const msg = String(a.message || a.description || a.title || ruleId).trim();
          const remediation = String(a.remediation || 'Inspecter et sécuriser le flux de données.').trim();
          const sev = String(a.severity || 'HIGH').toUpperCase();
          const key = `${clampedLine}::${ruleId}::${cveId}::${msg}`;
          if (seen.has(key)) continue;
          seen.add(key);

          list.push({
            id: key,
            ruleId,
            cveId,
            displayId,
            severity: sev,
            line: clampedLine,
            message: msg,
            remediation,
            nodeId: n.id
          });
        }
      } else if (Array.isArray(n.metadata?.violations)) {
        for (const rawStr of n.metadata.violations) {
          const s = String(rawStr || '').trim();
          if (!s) continue;
          const cweMatch = s.match(/\b(CWE-\d+|AETHER-[A-Z]+-\d+)\b/i);
          const sevMatch = s.match(/\b(CRITICAL|HIGH|MEDIUM|LOW|WARNING)\b/i);
          const lineMatch = s.match(/\bL(\d+)\b/i);
          const ruleId = cweMatch ? cweMatch[1].toUpperCase() : 'CWE-SAST';
          const sev = sevMatch ? sevMatch[1].toUpperCase() : 'HIGH';
          if (isLinesExceededAnomaly({ rule_id: ruleId, cve_id: ruleId, severity: sev, message: s })) continue;
          if (cockpitState.isCweIgnored(ruleId, ruleId)) continue;

          const parsedLine = lineMatch ? parseInt(lineMatch[1], 10) : (n.line_number || 1);
          const clampedLine = Math.max(1, Math.min(maxL, Number.isFinite(parsedLine) && parsedLine > 0 ? parsedLine : 1));
          const displayId = formatCweShortId(ruleId, ruleId);
          const key = `${clampedLine}::${ruleId}::${s}`;
          if (seen.has(key)) continue;
          seen.add(key);

          list.push({
            id: key,
            ruleId,
            cveId: ruleId,
            displayId,
            severity: sev,
            line: clampedLine,
            message: s,
            remediation: 'Corriger la violation signalée par le contrat / linter SAST.',
            nodeId: n.id
          });
        }
      }
    }

    return list;
  });

  let diagnosticsByLine = $derived.by(() => {
    const map = new Map<number, LineDiagnostic[]>();
    for (const d of fileDiagnostics) {
      const arr = map.get(d.line);
      if (arr) {
        arr.push(d);
      } else {
        map.set(d.line, [d]);
      }
    }
    return map;
  });

  function isHighOrCritical(sev: string): boolean {
    const s = sev.toUpperCase();
    return s === 'CRITICAL' || s === 'HIGH';
  }

  // F12: AST Breadcrumb & Enclosing Symbol / Method Detection
  let enclosingAstContext = $derived.by(() => {
    const curL = effectiveCursorLine;
    const nonFileSymbols = activeFileNodes
      .filter((n) => !n.is_file && String(n.kind).toLowerCase() !== 'file' && String(n.kind) !== '1' && !n.id.startsWith('file::'))
      .sort((a, b) => (a.line_number || 1) - (b.line_number || 1));

    let enclosingSymbol: SymbolBubble | null = null;
    for (const sym of nonFileSymbols) {
      const symLine = sym.line_number || 1;
      if (symLine <= curL) {
        enclosingSymbol = sym;
      } else {
        break;
      }
    }

    let enclosingMethod: { name: string; line: number } | null = null;
    if (enclosingSymbol && Array.isArray(enclosingSymbol.methods) && enclosingSymbol.methods.length > 0) {
      const sortedMethods = [...enclosingSymbol.methods].sort((a, b) => (a.line || 0) - (b.line || 0));
      for (const m of sortedMethods) {
        const mLine = m.line || enclosingSymbol.line_number || 1;
        if (mLine <= curL) {
          enclosingMethod = { name: m.name, line: mLine };
        }
      }
    }

    return {
      symbol: enclosingSymbol,
      method: enclosingMethod,
      targetNode: enclosingSymbol || activeFilePrimaryNode
    };
  });

  // F12: Callers (Appelants) & Callees (Appelés) via cockpitState.incidentEdges
  let callGraphContext = $derived.by(() => {
    const target = enclosingAstContext.targetNode;
    if (!target) {
      return { callers: [] as SymbolBubble[], callees: [] as SymbolBubble[] };
    }

    const edges = cockpitState.incidentEdges(target.id);
    const callersMap = new Map<string, SymbolBubble>();
    const calleesMap = new Map<string, SymbolBubble>();

    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      if (!e || e.source === e.target) continue;
      if (e.target === target.id) {
        const src = cockpitState.getNodeById(e.source);
        if (src && src.name && !callersMap.has(src.id)) {
          callersMap.set(src.id, src);
        }
      } else if (e.source === target.id) {
        const tgt = cockpitState.getNodeById(e.target);
        if (tgt && tgt.name && !calleesMap.has(tgt.id)) {
          calleesMap.set(tgt.id, tgt);
        }
      }
    }

    return {
      callers: Array.from(callersMap.values()),
      callees: Array.from(calleesMap.values())
    };
  });

  function jumpToCallGraphSymbol(sym: SymbolBubble) {
    if (!sym) return;
    openCallMenu = null;
    cockpitState.selectSymbol(sym.id, false);
    if (sym.file_path) {
      cockpitState.openFileInIde(sym.file_path, sym.line_number && sym.line_number > 0 ? sym.line_number : 1);
    }
    cockpitState.requestFocusSymbol(sym.id);
  }

  function targetCurrentIn3D() {
    const target = enclosingAstContext.targetNode;
    if (target) {
      cockpitState.activeSymbol = target;
      cockpitState.requestFocusSymbol(target.id);
    }
    void cockpitState.switchToMode('code');
  }

  // F13: EARS Line Budget, Active-File CWE Counter, Active AI Agents & BLAKE3 Seal
  let effectiveMaxLinesLimit = $derived.by(() => {
    for (const n of activeFileNodes) {
      if (n.metadata?.max_lines_limit && n.metadata.max_lines_limit > 0) {
        return n.metadata.max_lines_limit;
      }
    }
    return 300;
  });

  let effectiveFileLoc = $derived.by(() => {
    if (content.length > 0) return lineCount;
    return activeFilePrimaryNode?.loc || lineCount || 1;
  });

  let activeFileCweCount = $derived(fileDiagnostics.length);

  let activeFileAgents = $derived.by(() => {
    if (!activeFileNorm) return [];
    const nodeIds = new Set(activeFileNodes.map((n) => n.id));
    const result: { agentId: string; agentName: string; color: string; action?: string }[] = [];
    for (const ag of cockpitState.activeAgents || []) {
      if (!ag || cockpitState.isAgentInactive(ag)) continue;
      const name = String(ag.agentName || '').trim();
      if (!name || name === 'undefined') continue;

      const agTargetNorm = normalizeLowerPath(ag.target);
      const resolved = ag.nodeId ? cockpitState.getNodeById(ag.nodeId) : cockpitState.resolveTargetNode(ag.target);
      const resolvedFileNorm = normalizeLowerPath(resolved?.file_path);

      const matchesFile =
        agTargetNorm === activeFileNorm ||
        agTargetNorm.endsWith('/' + activeFileNorm) ||
        (ag.nodeId && nodeIds.has(ag.nodeId)) ||
        resolvedFileNorm === activeFileNorm;

      if (matchesFile) {
        result.push({
          agentId: ag.agentId,
          agentName: name,
          color: ag.color || '#38bdf8',
          action: ag.action
        });
      }
    }
    return result;
  });

  async function sealCurrentContractBlake3() {
    if (isSealingBlake3) return;
    isSealingBlake3 = true;
    errorMessage = null;
    try {
      const norm = normalizeRelPath(cockpitState.ideActiveFile);
      const parts = norm.split('/').filter(Boolean);
      const folder = parts.length > 1 ? parts.slice(0, parts.length - 1).join('/') : undefined;
      const res = await api.signContracts({
        project_path: cockpitState.graph.project_path || '.',
        folder
      });
      if (res && res.status === 'ok') {
        if (res.graph) {
          cockpitState.setGraph(res.graph, true);
        }
        const hashShort = res.blake3_hash ? ` (${res.blake3_hash.slice(0, 8)})` : '';
        successNotice = `Contrat BLAKE3 scellé${hashShort}`;
        setTimeout(() => {
          if (successNotice?.startsWith('Contrat BLAKE3 scellé')) successNotice = null;
        }, 2500);
      } else {
        errorMessage = res?.message || 'Échec du scellement BLAKE3';
      }
    } catch (e: any) {
      errorMessage = e?.message || 'Impossible de sceller le contrat BLAKE3';
    } finally {
      isSealingBlake3 = false;
    }
  }

  // F11 Quick Remediation actions
  function inspectDiagnosticInDrawer(diag: LineDiagnostic) {
    if (diag.nodeId) {
      cockpitState.selectSymbol(diag.nodeId, true);
    }
    cockpitState.activeTab = 'cve';
    cockpitState.isInspectorOpen = true;
  }

  function askAiToFixDiagnostic(diag: LineDiagnostic) {
    if (diag.nodeId) {
      cockpitState.selectSymbol(diag.nodeId, false);
    }
    cockpitState.isChatOpen = true;
    void api
      .sendChatMessage(
        `🔧 Peux-tu corriger la violation **[${diag.displayId}]** ligne ${diag.line} dans \`${cockpitState.ideActiveFile}\` ?\n- Diagnostic : ${diag.message}\n- Remédiation : ${diag.remediation}`,
        undefined,
        cockpitState.ideActiveFile || undefined
      )
      .catch(() => {});
  }

  // Search match structure (literal substring matching, ReDoS safe)
  interface SearchMatch {
    lineIndex: number;
    charIndex: number;
    length: number;
  }

  let searchMatches = $derived.by(() => {
    if (!searchQuery || !searchQuery.trim() || !content) return [];
    const q = searchQuery.toLowerCase();
    const matches: SearchMatch[] = [];

    lines.forEach((lineText, lIdx) => {
      const lower = lineText.toLowerCase();
      let pos = 0;
      while ((pos = lower.indexOf(q, pos)) !== -1) {
        matches.push({
          lineIndex: lIdx,
          charIndex: pos,
          length: q.length
        });
        pos += Math.max(1, q.length);
      }
    });

    return matches;
  });

  let currentMatchIndex = $state(0);

  $effect(() => {
    if (searchMatches.length === 0) {
      currentMatchIndex = 0;
    } else if (currentMatchIndex >= searchMatches.length) {
      currentMatchIndex = 0;
    }
  });

  // Undo / Redo per-buffer stack helpers (F10)
  function ensureBuffer(filePath: string): FileBuffer {
    if (!buffers[filePath]) {
      buffers[filePath] = {
        content,
        savedContent,
        cursorLine,
        cursorCol,
        undoStack: [],
        redoStack: []
      };
    }
    return buffers[filePath];
  }

  function pushUndoSnapshot(prevContent: string, prevLine = cursorLine, prevCol = cursorCol) {
    if (!loadedFile) return;
    const buf = ensureBuffer(loadedFile);
    const last = buf.undoStack[buf.undoStack.length - 1];
    if (last && last.content === prevContent) return;
    buf.undoStack.push({
      content: prevContent,
      cursorLine: prevLine,
      cursorCol: prevCol
    });
    if (buf.undoStack.length > 100) {
      buf.undoStack.shift();
    }
    buf.redoStack = [];
  }

  function performUndo() {
    if (!loadedFile) return;
    const buf = ensureBuffer(loadedFile);
    if (buf.undoStack.length === 0) return;
    const snapshot = buf.undoStack.pop()!;
    buf.redoStack.push({
      content,
      cursorLine,
      cursorCol
    });
    content = snapshot.content;
    cursorLine = snapshot.cursorLine;
    cursorCol = snapshot.cursorCol;
    cockpitState.ideCursorPosition = { line: cursorLine, ch: cursorCol };
    buf.content = content;
    buf.cursorLine = cursorLine;
    buf.cursorCol = cursorCol;
  }

  function performRedo() {
    if (!loadedFile) return;
    const buf = ensureBuffer(loadedFile);
    if (buf.redoStack.length === 0) return;
    const snapshot = buf.redoStack.pop()!;
    buf.undoStack.push({
      content,
      cursorLine,
      cursorCol
    });
    content = snapshot.content;
    cursorLine = snapshot.cursorLine;
    cursorCol = snapshot.cursorCol;
    cockpitState.ideCursorPosition = { line: cursorLine, ch: cursorCol };
    buf.content = content;
    buf.cursorLine = cursorLine;
    buf.cursorCol = cursorCol;
  }

  // Ctrl+H Replace Single & Replace All (non-looping on overlapping replacement)
  function replaceCurrentMatch() {
    if (searchMatches.length === 0 || !searchQuery) return;
    const match = searchMatches[currentMatchIndex] || searchMatches[0];
    if (!match) return;
    const targetLineText = lines[match.lineIndex];
    if (typeof targetLineText !== 'string') return;

    pushUndoSnapshot(content, cursorLine, cursorCol);
    const nextLines = [...lines];
    nextLines[match.lineIndex] =
      targetLineText.slice(0, match.charIndex) +
      replaceQuery +
      targetLineText.slice(match.charIndex + match.length);
    content = nextLines.join('\n');
    syncBufferAfterEdit();
  }

  function replaceAllMatches() {
    if (searchMatches.length === 0 || !searchQuery) return;
    const qLower = searchQuery.toLowerCase();
    const qLen = searchQuery.length;
    if (qLen === 0) return;

    pushUndoSnapshot(content, cursorLine, cursorCol);
    const nextLines = lines.map((lineText) => {
      const lower = lineText.toLowerCase();
      let pos = 0;
      let found = lower.indexOf(qLower, pos);
      if (found === -1) return lineText;
      let out = '';
      while (found !== -1) {
        out += lineText.slice(pos, found) + replaceQuery;
        pos = found + qLen;
        found = lower.indexOf(qLower, pos);
      }
      out += lineText.slice(pos);
      return out;
    });
    content = nextLines.join('\n');
    syncBufferAfterEdit();
  }

  // Watch for active file changes in graphState and switch / load tab
  $effect(() => {
    const activeFile = cockpitState.ideActiveFile;
    if (activeFile && activeFile !== loadedFile) {
      void loadFile(activeFile);
    } else if (!activeFile && loadedFile) {
      loadedFile = null;
      content = '';
      savedContent = '';
    }
  });

  async function loadFile(activeFile: string) {
    await switchToFile(activeFile);
  }

  $effect(() => {
    const _tick = cockpitState.ideTargetTick;
    const line = cockpitState.ideTargetLine;
    if (line && line > 0) {
      tick().then(() => {
        scrollToLine(line);
      });
    }
  });

  function syncBufferAfterEdit() {
    if (loadedFile) {
      const prev = buffers[loadedFile];
      buffers[loadedFile] = {
        content,
        savedContent,
        cursorLine,
        cursorCol,
        undoStack: prev?.undoStack || [],
        redoStack: prev?.redoStack || []
      };
      if (cockpitState.settings.editorAutoSave && content !== savedContent) {
        if (isSaving) {
          pendingAutoSave = true;
        } else {
          void saveCurrentFile(true);
        }
      }
    }
  }

  function handleContentInput() {
    if (loadedFile && buffers[loadedFile] && buffers[loadedFile].content !== content) {
      pushUndoSnapshot(buffers[loadedFile].content, buffers[loadedFile].cursorLine, buffers[loadedFile].cursorCol);
    }
    syncBufferAfterEdit();
  }

  async function switchToFile(filePath: string) {
    pendingAutoSave = false;
    if (cockpitState.settings.editorAutoSave && loadedFile && isDirty) {
      await saveCurrentFile(true);
    }
    if (loadedFile) {
      const prev = buffers[loadedFile];
      buffers[loadedFile] = {
        content,
        savedContent,
        cursorLine,
        cursorCol,
        undoStack: prev?.undoStack || [],
        redoStack: prev?.redoStack || []
      };
    }

    if (buffers[filePath]) {
      const b = buffers[filePath];
      loadedFile = filePath;
      content = b.content;
      savedContent = b.savedContent;
      externalConflictContent = null;
      cursorLine = b.cursorLine || 1;
      cursorCol = b.cursorCol || 1;
      cockpitState.ideCursorPosition = { line: cursorLine, ch: cursorCol };

      await tick();
      if (cockpitState.ideTargetLine && cockpitState.ideTargetLine > 0) {
        scrollToLine(cockpitState.ideTargetLine);
      }
      return;
    }

    await loadFileFromDisk(filePath);
  }

  function isPathAffectedByExternalChanges(filePath: string, changedList: string[]): boolean {
    if (!changedList || changedList.length === 0) return true;
    const normTarget = normalizeLowerPath(filePath);
    for (const raw of changedList) {
      const c = normalizeLowerPath(raw);
      if (!c) continue;
      if (
        normTarget === c ||
        normTarget.endsWith('/' + c) ||
        c.endsWith('/' + normTarget) ||
        normTarget.startsWith(c + '/')
      ) {
        return true;
      }
    }
    return false;
  }

  async function syncActiveFileFromExternalDisk(filePath: string) {
    if (!filePath || isSaving || isLoading) return;
    try {
      const res = await api.getFileContent(filePath, true);
      if (loadedFile !== filePath) return;
      if (res && res.status === 'ok' && typeof res.content === 'string') {
        const diskContent = res.content;
        if (diskContent === content) {
          savedContent = diskContent;
          externalConflictContent = null;
          if (buffers[filePath]) {
            buffers[filePath].savedContent = diskContent;
          }
          return;
        }
        if (!isDirty) {
          const prevScrollTop = textareaEl?.scrollTop ?? previewContainerEl?.scrollTop ?? 0;
          content = diskContent;
          savedContent = diskContent;
          externalConflictContent = null;
          const newTotalLines = Math.max(1, diskContent.split('\n').length);
          cursorLine = Math.min(cursorLine, newTotalLines);
          const prev = buffers[filePath];
          buffers[filePath] = {
            content: diskContent,
            savedContent: diskContent,
            cursorLine,
            cursorCol,
            undoStack: prev?.undoStack || [],
            redoStack: prev?.redoStack || []
          };
          await tick();
          if (textareaEl) textareaEl.scrollTop = prevScrollTop;
          if (backdropEl) backdropEl.scrollTop = prevScrollTop;
          if (previewContainerEl) previewContainerEl.scrollTop = prevScrollTop;
          successNotice = 'Synchronisé automatiquement (modification externe)';
          setTimeout(() => {
            if (successNotice === 'Synchronisé automatiquement (modification externe)') {
              successNotice = null;
            }
          }, 2600);
        } else if (diskContent !== savedContent) {
          externalConflictContent = diskContent;
        }
      }
    } catch {
      // ignore transient read error during external write
    }
  }

  function acceptExternalDiskVersion() {
    if (externalConflictContent === null || !loadedFile) return;
    const prevScrollTop = textareaEl?.scrollTop ?? previewContainerEl?.scrollTop ?? 0;
    pushUndoSnapshot(content, cursorLine, cursorCol);
    content = externalConflictContent;
    savedContent = externalConflictContent;
    externalConflictContent = null;
    const prev = buffers[loadedFile];
    buffers[loadedFile] = {
      content,
      savedContent,
      cursorLine,
      cursorCol,
      undoStack: prev?.undoStack || [],
      redoStack: prev?.redoStack || []
    };
    tick().then(() => {
      if (textareaEl) textareaEl.scrollTop = prevScrollTop;
      if (backdropEl) backdropEl.scrollTop = prevScrollTop;
      if (previewContainerEl) previewContainerEl.scrollTop = prevScrollTop;
    });
    successNotice = 'Version disque rechargée';
    setTimeout(() => {
      if (successNotice === 'Version disque rechargée') {
        successNotice = null;
      }
    }, 2500);
  }

  function keepLocalEditsOverExternal() {
    if (externalConflictContent === null || !loadedFile) return;
    savedContent = externalConflictContent;
    if (buffers[loadedFile]) {
      buffers[loadedFile].savedContent = externalConflictContent;
    }
    externalConflictContent = null;
  }

  $effect(() => {
    const fsVer = cockpitState.fsVersion;
    if (fsVer <= 0 || fsVer === lastHandledFsVersion) return;
    lastHandledFsVersion = fsVer;

    const changedList = cockpitState.lastChangedFiles || [];

    for (const tabPath of Object.keys(buffers)) {
      if (tabPath !== loadedFile && isPathAffectedByExternalChanges(tabPath, changedList)) {
        if (!isTabDirty(tabPath)) {
          delete buffers[tabPath];
        }
      }
    }

    if (loadedFile && isPathAffectedByExternalChanges(loadedFile, changedList)) {
      void syncActiveFileFromExternalDisk(loadedFile);
    }
  });

  async function loadFileFromDisk(filePath: string) {
    isLoading = true;
    errorMessage = null;
    successNotice = null;
    externalConflictContent = null;
    try {
      const res = await api.getFileContent(filePath, true);
      if (res && res.status === 'ok') {
        content = res.content ?? '';
        savedContent = content;
        loadedFile = filePath;
        const initLine = cockpitState.ideTargetLine && cockpitState.ideTargetLine > 0 ? cockpitState.ideTargetLine : 1;
        cursorLine = initLine;
        cursorCol = 1;
        cockpitState.ideCursorPosition = { line: initLine, ch: 1 };

        buffers[filePath] = {
          content,
          savedContent,
          cursorLine: initLine,
          cursorCol: 1,
          undoStack: [],
          redoStack: []
        };

        await tick();
        if (cockpitState.ideTargetLine && cockpitState.ideTargetLine > 0) {
          scrollToLine(cockpitState.ideTargetLine);
        }
      } else {
        errorMessage = res?.error || 'Erreur lors du chargement du fichier';
      }
    } catch (e: any) {
      errorMessage = e?.message || 'Impossible de joindre le serveur';
    } finally {
      isLoading = false;
    }
  }

  async function saveCurrentFile(isAuto = false) {
    if (!cockpitState.ideActiveFile) return;
    if (isSaving) {
      if (isAuto) pendingAutoSave = true;
      return;
    }
    if (isAuto && !isDirty) return;
    const targetFile = cockpitState.ideActiveFile;
    const contentToSave = content;
    isSaving = true;
    pendingAutoSave = false;
    errorMessage = null;
    if (!isAuto) successNotice = null;
    try {
      const res = await api.saveFile(targetFile, contentToSave);
      if (res && res.status === 'ok') {
        if (loadedFile === targetFile) {
          savedContent = contentToSave;
          externalConflictContent = null;
        }
        if (buffers[targetFile]) {
          buffers[targetFile].savedContent = contentToSave;
        }
        const msg = isAuto ? "Auto-enregistré à l'édit" : 'Enregistré sur disque (Ctrl+S)';
        successNotice = msg;
        setTimeout(() => {
          if (successNotice === msg) {
            successNotice = null;
          }
        }, 2000);
      } else {
        errorMessage = res?.error || "Erreur lors de l'enregistrement";
      }
    } catch (e: any) {
      errorMessage = e?.message || "Erreur d'écriture sur disque";
    } finally {
      isSaving = false;
      if (pendingAutoSave && cockpitState.settings.editorAutoSave && isDirty) {
        pendingAutoSave = false;
        void saveCurrentFile(true);
      }
    }
  }

  function scrollToLine(lineNum: number) {
    const safeLine = Math.max(1, Math.min(lineNum, lineCount));
    cursorLine = safeLine;
    cursorCol = 1;
    cockpitState.ideCursorPosition = { line: safeLine, ch: 1 };

    highlightedLine = safeLine;
    if (highlightTimer) clearTimeout(highlightTimer);
    highlightTimer = setTimeout(() => {
      highlightedLine = null;
    }, 2500);

    if (textareaEl) {
      const lineHeight = 21;
      const targetScroll = Math.max(0, (safeLine - 5) * lineHeight);
      textareaEl.scrollTo({ top: targetScroll, behavior: 'smooth' });
      if (backdropEl) {
        backdropEl.scrollTop = targetScroll;
      }
      if (gutterEl) {
        gutterEl.scrollTop = targetScroll;
      }
    }

    if (previewContainerEl) {
      const el = previewContainerEl.querySelector(`[data-line="${safeLine}"]`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }

  function handleEditorScroll(e: Event) {
    const target = e.target as HTMLElement;
    if (!target) return;
    if (gutterEl) {
      gutterEl.scrollTop = target.scrollTop;
    }
    if (backdropEl) {
      backdropEl.scrollTop = target.scrollTop;
      backdropEl.scrollLeft = target.scrollLeft;
    }
  }

  function updateCursorPosition() {
    if (!textareaEl) return;
    const pos = textareaEl.selectionStart;
    const textUpToCursor = content.substring(0, pos);
    const lineSplits = textUpToCursor.split('\n');
    cursorLine = lineSplits.length;
    cursorCol = lineSplits[lineSplits.length - 1].length + 1;
    cockpitState.ideCursorPosition = { line: cursorLine, ch: cursorCol };
    if (loadedFile && buffers[loadedFile]) {
      buffers[loadedFile].cursorLine = cursorLine;
      buffers[loadedFile].cursorCol = cursorCol;
    }
  }

  async function openExternalEditor(editor: 'vscode' | 'notepad') {
    if (!cockpitState.ideActiveFile) return;
    const rel = cockpitState.ideActiveFile.replace(/\\/g, '/').replace(/^\//, '');
    const lineCol = `${cursorLine}:${cursorCol}`;
    try {
      await api.launchCli(editor, lineCol, rel);
      const label = editor === 'vscode' ? `VS Code (L${cursorLine})` : 'Notepad';
      successNotice = `Ouvert dans ${label}`;
      setTimeout(() => {
        if (successNotice === `Ouvert dans ${label}`) successNotice = null;
      }, 2200);
    } catch {
      if (editor === 'vscode') {
        const root = (cockpitState.graph.project_path || '').replace(/^\\\\\?\\/, '').replace(/\\/g, '/').replace(/\/$/, '');
        const fullPath = root ? `${root}/${rel}` : rel;
        window.open(`vscode://file/${fullPath}:${lineCol}`, '_blank');
      }
    }
  }

  function applyLineEdit(newLines: string[], newCursorLine: number, newCursorCol = 1) {
    pushUndoSnapshot(content, cursorLine, cursorCol);
    content = newLines.join('\n');
    syncBufferAfterEdit();
    tick().then(() => {
      if (!textareaEl) return;
      const safeL = Math.max(1, Math.min(newCursorLine, newLines.length));
      let offset = 0;
      for (let i = 0; i < safeL - 1; i++) {
        offset += newLines[i].length + 1;
      }
      const colOffset = Math.max(0, Math.min(newCursorCol - 1, newLines[safeL - 1]?.length || 0));
      textareaEl.selectionStart = textareaEl.selectionEnd = offset + colOffset;
      updateCursorPosition();
    });
  }

  function handleGlobalEditorKeydown(e: KeyboardEvent) {
    if (cockpitState.viewMode !== 'ide' || !cockpitState.ideActiveFile) return;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      void saveCurrentFile(false);
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'g') {
      e.preventDefault();
      isGotoLineOpen = true;
      gotoLineInput = String(cursorLine);
      tick().then(() => {
        gotoInputEl?.focus();
        gotoInputEl?.select();
      });
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'h') {
      e.preventDefault();
      isSearchOpen = true;
      isReplaceOpen = true;
      tick().then(() => searchInputEl?.focus());
    }
  }

  function handleTextareaKeydown(e: KeyboardEvent) {
    // Ctrl+S / Cmd+S: Save file
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      e.stopPropagation();
      void saveCurrentFile(false);
      return;
    }

    // Ctrl+Z / Ctrl+Shift+Z / Ctrl+Y: Per-buffer Undo / Redo (F10)
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z') {
      e.preventDefault();
      if (e.shiftKey) {
        performRedo();
      } else {
        performUndo();
      }
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'y') {
      e.preventDefault();
      performRedo();
      return;
    }

    // Ctrl+F / Cmd+F: Search overlay
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      isSearchOpen = true;
      tick().then(() => searchInputEl?.focus());
      return;
    }

    // Ctrl+H / Cmd+H: Find & Replace overlay (F10)
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'h') {
      e.preventDefault();
      e.stopPropagation();
      isSearchOpen = true;
      isReplaceOpen = true;
      tick().then(() => searchInputEl?.focus());
      return;
    }

    // Ctrl+G / Cmd+G: Go to line
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'g') {
      e.preventDefault();
      e.stopPropagation();
      isGotoLineOpen = true;
      gotoLineInput = String(cursorLine);
      tick().then(() => {
        gotoInputEl?.focus();
        gotoInputEl?.select();
      });
      return;
    }

    // Ctrl+/ or Ctrl+: : Toggle line comment
    if ((e.ctrlKey || e.metaKey) && (e.key === '/' || e.key === ':')) {
      e.preventDefault();
      const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
      const prefix = syntaxLanguage === 'python' || syntaxLanguage === 'toml' ? '# ' : '// ';
      const rawPrefix = prefix.trim();
      const cur = lines[idx] ?? '';
      const trimmed = cur.trimStart();
      const leadLen = cur.length - trimmed.length;
      const nextLines = [...lines];
      if (trimmed.startsWith(prefix)) {
        nextLines[idx] = cur.slice(0, leadLen) + trimmed.slice(prefix.length);
      } else if (trimmed.startsWith(rawPrefix)) {
        nextLines[idx] = cur.slice(0, leadLen) + trimmed.slice(rawPrefix.length);
      } else {
        nextLines[idx] = cur.slice(0, leadLen) + prefix + trimmed;
      }
      applyLineEdit(nextLines, cursorLine, cursorCol);
      return;
    }

    // Ctrl+D or Alt+Shift+ArrowDown / Alt+Shift+ArrowUp: Duplicate current line
    if (
      ((e.ctrlKey || e.metaKey) && !e.shiftKey && e.key.toLowerCase() === 'd') ||
      (e.altKey && e.shiftKey && (e.key === 'ArrowDown' || e.key === 'ArrowUp'))
    ) {
      e.preventDefault();
      const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
      const nextLines = [...lines];
      nextLines.splice(idx + 1, 0, lines[idx] ?? '');
      const nextLine = e.key === 'ArrowUp' ? cursorLine : cursorLine + 1;
      applyLineEdit(nextLines, nextLine, cursorCol);
      return;
    }

    // Alt+ArrowUp / Alt+ArrowDown: Move current line up / down
    if (e.altKey && !e.shiftKey && !e.ctrlKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
      e.preventDefault();
      const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
      const targetIdx = e.key === 'ArrowUp' ? idx - 1 : idx + 1;
      if (targetIdx >= 0 && targetIdx < lines.length) {
        const nextLines = [...lines];
        const tmp = nextLines[idx];
        nextLines[idx] = nextLines[targetIdx];
        nextLines[targetIdx] = tmp;
        applyLineEdit(nextLines, targetIdx + 1, cursorCol);
      }
      return;
    }

    // Ctrl+Shift+K: Delete current line
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
      const nextLines = [...lines];
      if (nextLines.length <= 1) {
        nextLines[0] = '';
      } else {
        nextLines.splice(idx, 1);
      }
      applyLineEdit(nextLines, Math.min(cursorLine, nextLines.length), 1);
      return;
    }

    // Ctrl+L: Select current line
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      if (!textareaEl) return;
      const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
      let startOffset = 0;
      for (let i = 0; i < idx; i++) startOffset += lines[i].length + 1;
      const endOffset = Math.min(content.length, startOffset + lines[idx].length + 1);
      textareaEl.selectionStart = startOffset;
      textareaEl.selectionEnd = endOffset;
      return;
    }

    // Ctrl+Enter / Ctrl+Shift+Enter: Insert line below / above
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
      const indentMatch = (lines[idx] ?? '').match(/^\s*/);
      const indent = indentMatch ? indentMatch[0] : '';
      const nextLines = [...lines];
      const insertAt = e.shiftKey ? idx : idx + 1;
      nextLines.splice(insertAt, 0, indent);
      applyLineEdit(nextLines, insertAt + 1, indent.length + 1);
      return;
    }

    // Tab / Shift+Tab: Indent or Outdent 4 spaces
    if (e.key === 'Tab') {
      e.preventDefault();
      if (e.shiftKey) {
        const idx = Math.max(0, Math.min(cursorLine - 1, lines.length - 1));
        const cur = lines[idx] ?? '';
        const removed = cur.startsWith('    ') ? 4 : cur.match(/^ {1,3}/)?.[0].length ?? (cur.startsWith('\t') ? 1 : 0);
        if (removed > 0) {
          const nextLines = [...lines];
          nextLines[idx] = cur.slice(removed);
          applyLineEdit(nextLines, cursorLine, Math.max(1, cursorCol - removed));
        }
        return;
      }
      pushUndoSnapshot(content, cursorLine, cursorCol);
      const start = textareaEl?.selectionStart ?? 0;
      const end = textareaEl?.selectionEnd ?? 0;
      const spaces = '    ';
      content = content.substring(0, start) + spaces + content.substring(end);
      syncBufferAfterEdit();
      tick().then(() => {
        if (textareaEl) {
          textareaEl.selectionStart = textareaEl.selectionEnd = start + spaces.length;
          updateCursorPosition();
        }
      });
      return;
    }
  }

  function nextSearchMatch() {
    if (searchMatches.length === 0) return;
    currentMatchIndex = (currentMatchIndex + 1) % searchMatches.length;
    const match = searchMatches[currentMatchIndex];
    scrollToLine(match.lineIndex + 1);
  }

  function prevSearchMatch() {
    if (searchMatches.length === 0) return;
    currentMatchIndex = (currentMatchIndex - 1 + searchMatches.length) % searchMatches.length;
    const match = searchMatches[currentMatchIndex];
    scrollToLine(match.lineIndex + 1);
  }

  function handleSearchKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) {
        prevSearchMatch();
      } else {
        nextSearchMatch();
      }
    } else if (e.key === 'Escape') {
      isSearchOpen = false;
      isReplaceOpen = false;
      textareaEl?.focus();
    }
  }

  function closeTab(filePath: string) {
    delete buffers[filePath];
    cockpitState.closeIdeTab(filePath);
  }

  // Multi-language keyword sets for linear O(N) ReDoS-safe tokenization
  const KEYWORD_MAP: Record<string, Set<string>> = {
    rust: new Set([
      'fn', 'pub', 'let', 'mut', 'const', 'static', 'async', 'await', 'impl', 'trait',
      'struct', 'enum', 'mod', 'use', 'crate', 'self', 'super', 'where', 'match', 'if',
      'else', 'for', 'while', 'loop', 'return', 'break', 'continue', 'type', 'unsafe',
      'move', 'ref', 'in', 'as', 'true', 'false', 'Some', 'None', 'Ok', 'Err', 'Vec', 'String', 'Option', 'Result'
    ]),
    typescript: new Set([
      'function', 'class', 'interface', 'type', 'const', 'let', 'var', 'import', 'export',
      'from', 'default', 'new', 'this', 'try', 'catch', 'finally', 'throw', 'typeof',
      'instanceof', 'void', 'delete', 'async', 'await', 'return', 'if', 'else', 'for',
      'while', 'switch', 'case', 'break', 'continue', 'true', 'false', 'null', 'undefined'
    ]),
    python: new Set([
      'def', 'class', 'import', 'from', 'as', 'return', 'if', 'elif', 'else', 'for',
      'while', 'try', 'except', 'finally', 'raise', 'with', 'yield', 'lambda', 'pass',
      'break', 'continue', 'global', 'nonlocal', 'assert', 'True', 'False', 'None', 'async', 'await', 'self'
    ])
  };

  const GENERAL_KEYWORDS = new Set([
    ...Array.from(KEYWORD_MAP.rust),
    ...Array.from(KEYWORD_MAP.typescript),
    ...Array.from(KEYWORD_MAP.python)
  ]);

  function tokenizeCodeLine(line: string, lang: string): { text: string; cls: string }[] {
    if (!line) return [{ text: '', cls: 'text-slate-300' }];
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('# ') || trimmed.startsWith('--')) {
      return [{ text: line, cls: 'text-slate-500 italic' }];
    }
    // Cap tokenization scan on adversarial >4000-char lines while preserving full text faithfully
    if (line.length > 4000) {
      return [
        ...tokenizeCodeLine(line.slice(0, 2000), lang),
        { text: line.slice(2000), cls: 'text-slate-300' }
      ];
    }

    const keywords = KEYWORD_MAP[lang] || GENERAL_KEYWORDS;
    const tokens: { text: string; cls: string }[] = [];
    const len = line.length;
    let i = 0;

    while (i < len) {
      const ch = line[i];

      // Line comments // or #
      if ((ch === '/' && line[i + 1] === '/') || (ch === '#' && line[i + 1] !== '!')) {
        tokens.push({ text: line.slice(i), cls: 'text-slate-500 italic' });
        break;
      }

      // Quoted string literals (linear scan without backtracking)
      if (ch === '"' || ch === "'" || ch === '`') {
        const quote = ch;
        let j = i + 1;
        while (j < len) {
          if (line[j] === '\\') {
            j += 2;
          } else if (line[j] === quote) {
            j++;
            break;
          } else {
            j++;
          }
        }
        tokens.push({ text: line.slice(i, j), cls: 'text-amber-300 font-mono' });
        i = j;
        continue;
      }

      // Identifiers & keywords
      if (/[A-Za-z_]/.test(ch)) {
        let j = i + 1;
        while (j < len && /[A-Za-z0-9_]/.test(line[j])) j++;
        const tok = line.slice(i, j);
        let cls = 'text-slate-200';
        if (keywords.has(tok)) {
          cls = 'text-pink-400 font-semibold';
        } else if (tok[0] >= 'A' && tok[0] <= 'Z') {
          cls = 'text-emerald-300 font-medium';
        }
        tokens.push({ text: tok, cls });
        i = j;
        continue;
      }

      // Numbers
      if (ch >= '0' && ch <= '9') {
        let j = i + 1;
        while (j < len && /[0-9._xXa-fA-F]/.test(line[j])) j++;
        tokens.push({ text: line.slice(i, j), cls: 'text-purple-300 font-mono' });
        i = j;
        continue;
      }

      // Punctuation / operators
      if (/[{}()[\].,:;+\-/*=<>!&|?~]/.test(ch)) {
        let j = i + 1;
        while (j < len && /[{}()[\].,:;+\-/*=<>!&|?~]/.test(line[j])) j++;
        tokens.push({ text: line.slice(i, j), cls: 'text-sky-300/80' });
        i = j;
        continue;
      }

      // Whitespace or other characters
      let j = i + 1;
      while (
        j < len &&
        !/[A-Za-z0-9_"'`/#{}()[\].,:;+\-/*=<>!&|?~]/.test(line[j])
      ) {
        j++;
      }
      tokens.push({ text: line.slice(i, j), cls: 'text-slate-300' });
      i = j;
    }

    return tokens.length > 0 ? tokens : [{ text: line, cls: 'text-slate-300' }];
  }

  // F10: Split syntax tokens with inline Ctrl+F search match highlighting
  function splitWithSearch(
    lineText: string,
    lang: string,
    lineIdx: number
  ): { text: string; cls: string; isMatch: boolean; isCurrentMatch: boolean }[] {
    const baseTokens = tokenizeCodeLine(lineText, lang);
    if (!searchQuery || !searchQuery.trim() || searchMatches.length === 0) {
      return baseTokens.map((t) => ({ ...t, isMatch: false, isCurrentMatch: false }));
    }

    const lineMatches: { start: number; end: number; isCurrent: boolean }[] = [];
    for (let mIdx = 0; mIdx < searchMatches.length; mIdx++) {
      const m = searchMatches[mIdx];
      if (m.lineIndex === lineIdx) {
        lineMatches.push({
          start: m.charIndex,
          end: m.charIndex + m.length,
          isCurrent: mIdx === currentMatchIndex
        });
      }
    }

    if (lineMatches.length === 0) {
      return baseTokens.map((t) => ({ ...t, isMatch: false, isCurrentMatch: false }));
    }

    const result: { text: string; cls: string; isMatch: boolean; isCurrentMatch: boolean }[] = [];
    let offset = 0;

    for (const tok of baseTokens) {
      const tokStart = offset;
      const tokEnd = offset + tok.text.length;
      offset = tokEnd;

      let cursor = tokStart;
      for (const lm of lineMatches) {
        if (lm.end <= cursor || lm.start >= tokEnd) continue;
        if (lm.start > cursor) {
          result.push({
            text: lineText.slice(cursor, lm.start),
            cls: tok.cls,
            isMatch: false,
            isCurrentMatch: false
          });
        }
        const segStart = Math.max(cursor, lm.start);
        const segEnd = Math.min(tokEnd, lm.end);
        result.push({
          text: lineText.slice(segStart, segEnd),
          cls: lm.isCurrent
            ? 'bg-amber-400 text-slate-950 font-bold rounded-xs ring-1 ring-sky-300'
            : 'bg-amber-500/35 text-amber-100 rounded-xs',
          isMatch: true,
          isCurrentMatch: lm.isCurrent
        });
        cursor = segEnd;
      }
      if (cursor < tokEnd) {
        result.push({
          text: lineText.slice(cursor, tokEnd),
          cls: tok.cls,
          isMatch: false,
          isCurrentMatch: false
        });
      }
    }

    return result;
  }

  onMount(() => {
    if (cockpitState.ideActiveFile) {
      if (!cockpitState.ideOpenFiles.includes(cockpitState.ideActiveFile)) {
        cockpitState.ideOpenFiles.push(cockpitState.ideActiveFile);
      }
      void switchToFile(cockpitState.ideActiveFile);
    }
  });
</script>

<svelte:window onkeydown={handleGlobalEditorKeydown} />

<div class="w-full h-full flex flex-col bg-[#060810] text-slate-100 overflow-hidden relative">
  <!-- Multi-Tab Strip & Actions Bar -->
  <div class="h-9 bg-[#090d16] border-b border-white/10 flex items-stretch justify-between gap-1 shrink-0 select-none overflow-x-auto scrollbar-none">
    <!-- Open File Tabs -->
    <div class="flex items-stretch min-w-0 flex-1 overflow-x-auto scrollbar-none">
      {#if cockpitState.ideOpenFiles.length === 0}
        <div class="flex items-center px-3 text-xs font-mono text-slate-500 italic">
          Aucun fichier ouvert
        </div>
      {:else}
        {#each cockpitState.ideOpenFiles as tabPath (tabPath)}
          {@const isActive = tabPath === cockpitState.ideActiveFile}
          {@const isDirtyTab = isTabDirty(tabPath)}
          {@const tabName = tabPath.replace(/\\/g, '/').split('/').pop() || tabPath}
          {@const tabGit = getTabGitBadge(tabPath)}
          <div
            role="tab"
            tabindex="0"
            onclick={() => cockpitState.openFileInIde(tabPath)}
            onkeydown={(e) => { if (e.key === 'Enter') cockpitState.openFileInIde(tabPath); }}
            class="group relative flex items-center gap-1.5 border-r border-white/10 transition-all cursor-pointer min-w-0 shrink-0 select-none
              {tabSizeMode === 'compact' ? 'px-2 text-[11px] max-w-[140px]' : tabSizeMode === 'expanded' ? 'px-3.5 text-xs max-w-[320px]' : 'px-3 text-xs max-w-[230px]'}
              {isActive
                ? 'bg-[#060810] text-sky-200 border-t-2 border-t-sky-400 font-semibold shadow-xs'
                : 'bg-[#080b15]/70 hover:bg-[#0c111e] text-slate-400 hover:text-slate-200 border-t-2 border-t-transparent'}"
            title="{tabPath}{isDirtyTab ? ' (modifications non enregistrées)' : ''}"
          >
            <Code2 class="w-3.5 h-3.5 shrink-0 {isActive ? 'text-sky-400' : 'text-slate-500 group-hover:text-slate-400'}" />
            <span class="truncate flex-1">{tabName}</span>

            {#if tabGit}
              <span
                class="px-1 py-0.2 text-[9px] rounded font-mono font-bold border shrink-0 {tabGit.cls}"
                title={tabGit.label}
              >{tabGit.badge}</span>
            {/if}

            {#if isDirtyTab}
              <span class="w-2 h-2 rounded-full bg-amber-400 shrink-0 shadow-[0_0_6px_#f59e0b]" title="Non enregistré"></span>
            {/if}

            <button
              type="button"
              onclick={(e) => {
                e.stopPropagation();
                closeTab(tabPath);
              }}
              class="p-0.5 rounded text-slate-500 hover:text-rose-300 hover:bg-rose-500/20 shrink-0 opacity-60 group-hover:opacity-100 transition-opacity cursor-pointer"
              title="Fermer l'onglet ({tabName})"
            >
              <X class="w-3 h-3" />
            </button>
          </div>
        {/each}
      {/if}
    </div>

    <!-- Actions Bar -->
    <div class="flex items-center gap-1.5 px-2 shrink-0">
      {#if cockpitState.ideOpenFiles.length > 1}
        <button
          type="button"
          onclick={() => cockpitState.closeAllIdeTabs()}
          class="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-500 hover:text-rose-300 hover:bg-rose-500/15 transition-colors cursor-pointer"
          title="Fermer tous les onglets"
        >
          <XCircle class="w-3 h-3" />
          <span class="hidden xl:inline">Tout fermer</span>
        </button>
      {/if}

      <!-- Tab Sizing Mode Button -->
      <button
        type="button"
        onclick={() => {
          tabSizeMode = tabSizeMode === 'auto' ? 'compact' : tabSizeMode === 'compact' ? 'expanded' : 'auto';
        }}
        class="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10.5px] font-mono text-slate-400 hover:text-white hover:bg-white/5 border border-white/5 transition-colors cursor-pointer"
        title="Ajuster la taille des onglets : {tabSizeMode === 'compact' ? 'Compact' : tabSizeMode === 'expanded' ? 'Large' : 'Auto'}"
      >
        <SlidersHorizontal class="w-3 h-3 text-sky-400" />
        <span class="hidden 2xl:inline">{tabSizeMode === 'compact' ? 'Fin' : tabSizeMode === 'expanded' ? 'Large' : 'Auto'}</span>
      </button>

      <!-- Zen Mode -->
      <button
        type="button"
        onclick={() => cockpitState.toggleZenMode()}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer
          {cockpitState.ideZenMode ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-400/40 font-semibold shadow-xs' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
        title={cockpitState.ideZenMode ? 'Quitter le mode Plein Écran (restaurer les volets)' : 'Plein Écran Éditeur / Minimiser tous les volets (Mode Zen)'}
      >
        {#if cockpitState.ideZenMode}
          <Minimize2 class="w-3.5 h-3.5 text-indigo-400" />
          <span class="hidden md:inline">Restaurer</span>
        {:else}
          <Maximize2 class="w-3.5 h-3.5 text-slate-400" />
          <span class="hidden md:inline">Plein Écran</span>
        {/if}
      </button>

      <!-- Search & Replace Trigger Button (Ctrl+F / Ctrl+H) -->
      <button
        type="button"
        onclick={() => {
          isSearchOpen = !isSearchOpen;
          if (isSearchOpen) tick().then(() => searchInputEl?.focus());
        }}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer
          {isSearchOpen ? 'bg-sky-500/20 text-sky-300 border border-sky-400/30' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
        title="Rechercher / Remplacer dans le fichier (Ctrl+F / Ctrl+H)"
      >
        <Search class="w-3 h-3" />
        <span class="hidden md:inline">Ctrl+F</span>
      </button>

      <!-- Docs, EARS & Source Integrated Toggle Button -->
      <button
        type="button"
        onclick={() => cockpitState.toggleDocPanel()}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer
          {cockpitState.isDocPanelOpen ? 'bg-emerald-500/25 text-emerald-200 border border-emerald-400/40 font-semibold shadow-xs' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
        title="Afficher / Masquer le volet Doc, EARS & Source dans l'IDE (M)"
      >
        <BookOpen class="w-3.5 h-3.5 text-emerald-400" />
        <span class="hidden md:inline">Docs & EARS</span>
      </button>

      <!-- View Mode Switch: Edit / Preview -->
      <div class="flex items-center bg-white/[0.04] border border-white/10 rounded p-0.5 gap-0.5 text-[11px]">
        <button
          type="button"
          onclick={() => (editorViewMode = 'edit')}
          class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
            {editorViewMode === 'edit' ? 'bg-sky-500/25 text-sky-200 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Mode Édition unifié avec coloration syntaxique en direct"
        >
          <Edit3 class="w-3 h-3 text-sky-400" />
          <span class="hidden md:inline">Éditer</span>
        </button>
        <button
          type="button"
          onclick={() => (editorViewMode = 'preview')}
          class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
            {editorViewMode === 'preview' ? 'bg-emerald-500/25 text-emerald-200 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Mode Lecture colorée"
        >
          <Eye class="w-3 h-3 text-emerald-400" />
          <span class="hidden md:inline">Coloré</span>
        </button>
      </div>

      <!-- Open in VS Code / Notepad Quick Shortcuts -->
      {#if cockpitState.ideActiveFile}
        <button
          type="button"
          onclick={() => openExternalEditor('vscode')}
          class="flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-mono bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 transition-colors cursor-pointer"
          title="Ouvrir ce fichier à la ligne {cursorLine} dans VS Code"
        >
          <Code2 class="w-3 h-3 text-sky-400" />
          <span class="hidden lg:inline">VS Code</span>
        </button>
        <button
          type="button"
          onclick={() => openExternalEditor('notepad')}
          class="flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-mono bg-white/[0.04] hover:bg-white/10 text-slate-300 border border-white/10 transition-colors cursor-pointer"
          title="Ouvrir ce fichier dans Notepad (Bloc-notes)"
        >
          <Edit3 class="w-3 h-3 text-amber-400" />
          <span class="hidden xl:inline">Notepad</span>
        </button>
      {/if}

      <!-- Save Mode Quick Toggle -->
      <button
        type="button"
        onclick={() => {
          cockpitState.settings.editorAutoSave = !cockpitState.settings.editorAutoSave;
          cockpitState.saveLocalSettings();
          if (cockpitState.settings.editorAutoSave && isDirty) {
            void saveCurrentFile(true);
          }
        }}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-mono border transition-colors cursor-pointer
          {cockpitState.settings.editorAutoSave
            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-semibold'
            : 'bg-white/[0.04] text-slate-400 hover:text-white border-white/10'}"
        title={cockpitState.settings.editorAutoSave
          ? "Mode Save Auto actif (sauvegarde directe à l'édit) — Cliquez pour passer en Manuel (Ctrl+S)"
          : "Mode Manuel (Ctrl+S) — Cliquez pour activer Save Auto à l'édit"}
      >
        <span class="w-1.5 h-1.5 rounded-full {cockpitState.settings.editorAutoSave ? 'bg-emerald-400' : 'bg-slate-500'}"></span>
        <span>{cockpitState.settings.editorAutoSave ? 'Save Auto' : 'Ctrl+S'}</span>
      </button>

      <!-- Save Button -->
      <button
        type="button"
        onclick={() => saveCurrentFile(false)}
        disabled={isSaving || !cockpitState.ideActiveFile}
        class="flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold transition-all cursor-pointer shadow-sm
          {isDirty ? 'bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-[0_0_8px_rgba(245,158,11,0.4)] animate-pulse' : 'bg-white/10 hover:bg-white/15 text-slate-200'}"
        title="Enregistrer les modifications sur disque (Ctrl+S)"
      >
        {#if isSaving}
          <RefreshCw class="w-3 h-3 animate-spin" />
        {:else}
          <Save class="w-3 h-3" />
        {/if}
        <span>Enregistrer</span>
      </button>
    </div>
  </div>

  <!-- F12: AST Architectural Breadcrumb & 1-Click Call-Graph Bar -->
  {#if cockpitState.ideActiveFile}
    {@const normFile = normalizeRelPath(cockpitState.ideActiveFile)}
    {@const fileSegments = normFile.split('/').filter(Boolean)}
    {@const encSym = enclosingAstContext.symbol}
    {@const encMethod = enclosingAstContext.method}
    <div class="h-7 px-3 bg-[#080c16] border-b border-white/10 flex items-center justify-between gap-2 text-[11px] font-mono select-none shrink-0 z-20 relative">
      <!-- Left: Path & Enclosing Symbol / Method Breadcrumb -->
      <div class="flex items-center gap-1 min-w-0 overflow-x-auto scrollbar-none text-slate-400">
        {#each fileSegments as seg, sIdx}
          {#if sIdx > 0}
            <ChevronRight class="w-3 h-3 text-slate-600 shrink-0" />
          {/if}
          <span class="{sIdx === fileSegments.length - 1 ? 'text-slate-200 font-semibold' : 'text-slate-500'} truncate">
            {seg}
          </span>
        {/each}

        {#if encSym}
          <ChevronRight class="w-3 h-3 text-slate-600 shrink-0" />
          <button
            type="button"
            onclick={() => scrollToLine(encSym.line_number || 1)}
            class="px-1.5 py-0.2 rounded bg-purple-500/15 border border-purple-400/30 text-purple-200 font-semibold hover:bg-purple-500/25 cursor-pointer shrink-0 flex items-center gap-1"
            title="Symbole AST englobant (L{encSym.line_number || 1})"
          >
            <Code2 class="w-3 h-3 text-purple-400" />
            <span>{encSym.name}</span>
          </button>
        {/if}

        {#if encMethod}
          <ChevronRight class="w-3 h-3 text-slate-600 shrink-0" />
          <button
            type="button"
            onclick={() => scrollToLine(encMethod.line)}
            class="px-1.5 py-0.2 rounded bg-sky-500/15 border border-sky-400/30 text-sky-200 font-semibold hover:bg-sky-500/25 cursor-pointer shrink-0"
            title="Méthode englobante (L{encMethod.line})"
          >
            {encMethod.name}()
          </button>
        {/if}
      </div>

      <!-- Right: Callers (Appelants), Callees (Appelés) & Cibler en 3D -->
      <div class="flex items-center gap-1.5 shrink-0">
        <!-- Appelants Dropdown Button -->
        <div class="relative">
          <button
            type="button"
            onclick={() => (openCallMenu = openCallMenu === 'callers' ? null : 'callers')}
            class="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border transition-colors cursor-pointer
              {openCallMenu === 'callers'
                ? 'bg-amber-500/25 text-amber-200 border-amber-400/40 font-semibold'
                : 'bg-white/[0.04] hover:bg-white/10 text-slate-300 border-white/10'}"
            title="Afficher les fonctions appelantes (In-Degree)"
          >
            <ArrowDownLeft class="w-3 h-3 text-amber-400" />
            <span>Appelants</span>
            <span class="px-1 rounded bg-amber-500/20 text-amber-300 font-bold">{callGraphContext.callers.length}</span>
          </button>

          {#if openCallMenu === 'callers'}
            <div class="absolute right-0 top-full mt-1 w-64 max-h-56 overflow-y-auto rounded-lg bg-[#0b101e] border border-amber-500/40 shadow-2xl p-1.5 z-40 space-y-0.5">
              <div class="px-2 py-1 text-[9.5px] font-bold uppercase text-amber-300 border-b border-white/10">
                📥 Appelants ({callGraphContext.callers.length})
              </div>
              {#if callGraphContext.callers.length === 0}
                <div class="px-2 py-2 text-[10px] text-slate-500 italic">Aucun appelant détecté</div>
              {:else}
                {#each callGraphContext.callers as caller (caller.id)}
                  <button
                    type="button"
                    onclick={() => jumpToCallGraphSymbol(caller)}
                    class="w-full text-left px-2 py-1 rounded hover:bg-amber-500/20 text-slate-200 hover:text-amber-100 flex items-center justify-between gap-2 cursor-pointer transition-colors"
                  >
                    <span class="truncate font-semibold">{caller.name}</span>
                    <span class="text-[9px] text-slate-400 shrink-0">{caller.file_path?.split('/').pop() || ''}:L{caller.line_number || 1}</span>
                  </button>
                {/each}
              {/if}
            </div>
          {/if}
        </div>

        <!-- Appelés Dropdown Button -->
        <div class="relative">
          <button
            type="button"
            onclick={() => (openCallMenu = openCallMenu === 'callees' ? null : 'callees')}
            class="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border transition-colors cursor-pointer
              {openCallMenu === 'callees'
                ? 'bg-emerald-500/25 text-emerald-200 border-emerald-400/40 font-semibold'
                : 'bg-white/[0.04] hover:bg-white/10 text-slate-300 border-white/10'}"
            title="Afficher les fonctions appelées (Out-Degree)"
          >
            <ArrowUpRight class="w-3 h-3 text-emerald-400" />
            <span>Appelés</span>
            <span class="px-1 rounded bg-emerald-500/20 text-emerald-300 font-bold">{callGraphContext.callees.length}</span>
          </button>

          {#if openCallMenu === 'callees'}
            <div class="absolute right-0 top-full mt-1 w-64 max-h-56 overflow-y-auto rounded-lg bg-[#0b101e] border border-emerald-500/40 shadow-2xl p-1.5 z-40 space-y-0.5">
              <div class="px-2 py-1 text-[9.5px] font-bold uppercase text-emerald-300 border-b border-white/10">
                📤 Appelés ({callGraphContext.callees.length})
              </div>
              {#if callGraphContext.callees.length === 0}
                <div class="px-2 py-2 text-[10px] text-slate-500 italic">Aucun appelé détecté</div>
              {:else}
                {#each callGraphContext.callees as callee (callee.id)}
                  <button
                    type="button"
                    onclick={() => jumpToCallGraphSymbol(callee)}
                    class="w-full text-left px-2 py-1 rounded hover:bg-emerald-500/20 text-slate-200 hover:text-emerald-100 flex items-center justify-between gap-2 cursor-pointer transition-colors"
                  >
                    <span class="truncate font-semibold">{callee.name}</span>
                    <span class="text-[9px] text-slate-400 shrink-0">{callee.file_path?.split('/').pop() || ''}:L{callee.line_number || 1}</span>
                  </button>
                {/each}
              {/if}
            </div>
          {/if}
        </div>

        <!-- Cibler en 3D Button -->
        <button
          type="button"
          onclick={targetCurrentIn3D}
          class="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-sky-500/15 hover:bg-sky-500/25 text-sky-200 border border-sky-400/35 font-semibold transition-colors cursor-pointer"
          title="Centrer la caméra 3D WebGL sur ce symbole"
        >
          <Orbit class="w-3 h-3 text-sky-400" />
          <span>Cibler en 3D</span>
        </button>
      </div>
    </div>
  {/if}

  <!-- Go-To-Line Overlay Banner (Ctrl+G) -->
  {#if isGotoLineOpen}
    <div class="px-3 py-1.5 bg-[#0d1322] border-b border-emerald-500/30 flex items-center justify-between gap-2 text-xs shadow-md shrink-0 z-20">
      <div class="flex items-center gap-2">
        <span class="text-[11px] font-mono text-emerald-300 font-semibold">Aller à la ligne (1–{lineCount}) :</span>
        <input
          bind:this={gotoInputEl}
          type="number"
          min="1"
          max={lineCount}
          bind:value={gotoLineInput}
          onkeydown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              const target = parseInt(String(gotoLineInput), 10);
              if (!isNaN(target)) scrollToLine(target);
              isGotoLineOpen = false;
              textareaEl?.focus();
            } else if (e.key === 'Escape') {
              isGotoLineOpen = false;
              textareaEl?.focus();
            }
          }}
          class="w-24 px-2 py-0.5 rounded bg-white/[0.06] border border-white/15 text-slate-100 text-[11px] font-mono focus:outline-none focus:border-emerald-400"
        />
      </div>
      <button
        type="button"
        onclick={() => (isGotoLineOpen = false)}
        class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
        title="Fermer (Échap)"
      >
        <X class="w-3.5 h-3.5" />
      </button>
    </div>
  {/if}

  <!-- In-File Search & Replace Overlay Banner (Ctrl+F / Ctrl+H) -->
  {#if isSearchOpen}
    <div class="px-3 py-1.5 bg-[#0d1322] border-b border-sky-500/30 flex flex-wrap items-center justify-between gap-2 text-xs shadow-md shrink-0 z-20">
      <div class="flex flex-wrap items-center gap-2 flex-1">
        <div class="relative w-56">
          <Search class="w-3.5 h-3.5 text-slate-400 absolute left-2 top-1.5 pointer-events-none" />
          <input
            bind:this={searchInputEl}
            type="text"
            bind:value={searchQuery}
            onkeydown={handleSearchKeydown}
            placeholder="Rechercher (Ctrl+F)..."
            class="w-full pl-7 pr-2 py-1 rounded bg-white/[0.06] border border-white/15 text-slate-100 placeholder-slate-500 text-[11px] font-mono focus:outline-none focus:border-sky-400"
          />
        </div>

        <div class="text-[10px] font-mono text-slate-400 shrink-0 min-w-[65px] text-center">
          {#if searchMatches.length > 0}
            <span class="text-sky-300 font-bold">{currentMatchIndex + 1}</span> / {searchMatches.length}
          {:else if searchQuery}
            <span class="text-rose-400">0 résultat</span>
          {:else}
            0 / 0
          {/if}
        </div>

        <button
          type="button"
          onclick={prevSearchMatch}
          disabled={searchMatches.length === 0}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 disabled:opacity-30 cursor-pointer"
          title="Résultat précédent (Shift+Enter)"
        >
          <ChevronUp class="w-3.5 h-3.5" />
        </button>

        <button
          type="button"
          onclick={nextSearchMatch}
          disabled={searchMatches.length === 0}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 disabled:opacity-30 cursor-pointer"
          title="Résultat suivant (Enter)"
        >
          <ChevronDown class="w-3.5 h-3.5" />
        </button>

        <button
          type="button"
          onclick={() => (isReplaceOpen = !isReplaceOpen)}
          class="px-2 py-0.5 rounded text-[10.5px] font-mono border cursor-pointer transition-colors
            {isReplaceOpen ? 'bg-purple-500/20 text-purple-200 border-purple-400/40' : 'bg-white/[0.04] text-slate-400 border-white/10 hover:text-white'}"
          title="Afficher / Masquer Remplacer (Ctrl+H)"
        >
          Ctrl+H
        </button>

        {#if isReplaceOpen}
          <input
            type="text"
            bind:value={replaceQuery}
            placeholder="Remplacer par..."
            class="w-48 px-2 py-1 rounded bg-white/[0.06] border border-white/15 text-slate-100 placeholder-slate-500 text-[11px] font-mono focus:outline-none focus:border-purple-400"
          />
          <button
            type="button"
            onclick={replaceCurrentMatch}
            disabled={searchMatches.length === 0}
            class="px-2 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/40 text-purple-200 text-[10.5px] font-mono disabled:opacity-40 cursor-pointer"
          >
            Remplacer
          </button>
          <button
            type="button"
            onclick={replaceAllMatches}
            disabled={searchMatches.length === 0}
            class="px-2 py-0.5 rounded bg-purple-500/25 hover:bg-purple-500/40 border border-purple-400/50 text-purple-100 text-[10.5px] font-mono font-semibold disabled:opacity-40 cursor-pointer"
          >
            Tout remplacer
          </button>
        {/if}
      </div>

      <button
        type="button"
        onclick={() => {
          isSearchOpen = false;
          isReplaceOpen = false;
        }}
        class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
        title="Fermer la recherche (Échap)"
      >
        <X class="w-3.5 h-3.5" />
      </button>
    </div>
  {/if}

  <!-- Error, External Conflict, or Success Alert Notices -->
  {#if externalConflictContent !== null}
    <div class="px-3 py-1.5 bg-amber-500/20 border-b border-amber-500/40 text-amber-200 text-[11px] font-mono flex items-center justify-between gap-2 shrink-0">
      <div class="flex items-center gap-1.5 min-w-0">
        <AlertCircle class="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span class="truncate">Ce fichier a été modifié à l'extérieur sur le disque alors que vous avez des modifications non enregistrées.</span>
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        <button
          type="button"
          onclick={acceptExternalDiskVersion}
          class="px-2 py-0.5 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold cursor-pointer transition-colors"
        >
          Charger version disque
        </button>
        <button
          type="button"
          onclick={keepLocalEditsOverExternal}
          class="px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-amber-100 border border-amber-400/30 cursor-pointer transition-colors"
        >
          Garder mes modifications
        </button>
      </div>
    </div>
  {/if}
  {#if errorMessage}
    <div class="px-3 py-1 bg-rose-500/20 border-b border-rose-500/30 text-rose-300 text-[11px] font-mono flex items-center justify-between gap-2 shrink-0">
      <div class="flex items-center gap-1.5">
        <AlertCircle class="w-3.5 h-3.5 text-rose-400 shrink-0" />
        <span>{errorMessage}</span>
      </div>
      <button onclick={() => (errorMessage = null)} class="p-0.5 text-rose-400 hover:text-white cursor-pointer">
        <X class="w-3 h-3" />
      </button>
    </div>
  {:else if successNotice}
    <div class="px-3 py-1 bg-emerald-500/20 border-b border-emerald-500/30 text-emerald-300 text-[11px] font-mono flex items-center justify-between gap-2 shrink-0">
      <div class="flex items-center gap-1.5">
        <Check class="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span>{successNotice}</span>
      </div>
    </div>
  {/if}

  <!-- Main Unified Editor / Preview Workspace -->
  <div class="flex-1 flex overflow-hidden relative">
    {#if isLoading}
      <div class="absolute inset-0 z-30 bg-[#060810]/80 backdrop-blur-xs flex flex-col items-center justify-center gap-2">
        <RefreshCw class="w-5 h-5 text-sky-400 animate-spin" />
        <span class="text-xs font-mono text-slate-400">Chargement du code source...</span>
      </div>
    {/if}

    {#if !cockpitState.ideActiveFile || cockpitState.ideOpenFiles.length === 0}
      <div class="w-full h-full flex flex-col items-center justify-center text-slate-500 text-xs font-mono gap-3 p-6 text-center">
        <div class="w-14 h-14 rounded-2xl bg-white/[0.03] border border-white/10 flex items-center justify-center text-sky-400 shadow-inner">
          <Code2 class="w-7 h-7 text-sky-400/80" />
        </div>
        <div class="space-y-1">
          <span class="text-slate-200 text-sm font-semibold block">Aucun fichier ouvert dans l'IDE</span>
          <span class="text-slate-500 text-xs block max-w-sm">
            Cliquez sur un fichier dans l'arborescence à gauche ou sélectionnez une bulle dans le graphe 3D (<kbd class="px-1.5 py-0.5 bg-white/5 rounded border border-white/10 text-slate-300">Alt+1</kbd>).
          </span>
        </div>
      </div>
    {:else if editorViewMode === 'edit'}
      <!-- Line Numbers & CWE Severity Gutter (F10 + F11) -->
      <div
        bind:this={gutterEl}
        class="w-14 py-3 bg-[#080b14] border-r border-white/5 select-none font-mono text-[11.5px] leading-[21px] text-right pr-2 text-slate-600 overflow-hidden shrink-0"
      >
        {#each lines as _, idx}
          {@const lineNum = idx + 1}
          {@const isHighlighted = highlightedLine === lineNum}
          {@const isTarget = targetLine === lineNum}
          {@const isCurrent = effectiveCursorLine === lineNum}
          {@const lineAnoms = diagnosticsByLine.get(lineNum) || []}
          {@const hasCrit = lineAnoms.some((a) => isHighOrCritical(a.severity))}
          <div
            data-gutter-line={lineNum}
            data-cwe={lineAnoms.length > 0 ? lineAnoms.map((a) => a.displayId).join(',') : undefined}
            class="h-[21px] flex items-center justify-end gap-1 px-1 transition-colors
              {lineAnoms.length > 0
                ? hasCrit
                  ? 'bg-rose-500/25 text-rose-300 font-bold border-l-2 border-rose-500'
                  : 'bg-amber-500/25 text-amber-300 font-bold border-l-2 border-amber-400'
                : isHighlighted
                  ? 'text-sky-200 font-bold bg-sky-500/40 rounded-l animate-pulse'
                  : isTarget
                    ? 'text-sky-300 font-bold bg-sky-500/20 rounded-l'
                    : isCurrent
                      ? 'text-slate-300 font-semibold'
                      : ''}"
            title={lineAnoms.length > 0 ? lineAnoms.map((a) => `[${a.displayId}] ${a.message}`).join('\n') : undefined}
          >
            {#if lineAnoms.length > 0}
              <span class="w-1.5 h-1.5 rounded-full shrink-0 {hasCrit ? 'bg-rose-400' : 'bg-amber-400'}"></span>
            {/if}
            <span>{lineNum}</span>
          </div>
        {/each}
      </div>

      <!-- Unified Editor Container: Synchronized Syntax + Error Lens Backdrop under Transparent Textarea (F10 + F11) -->
      <div class="flex-1 h-full relative overflow-hidden bg-[#060810]">
        <!-- Non-interactive Syntax & Error Lens Overlay Backdrop -->
        <div
          bind:this={backdropEl}
          aria-hidden="true"
          class="absolute inset-0 py-3 px-3.5 font-mono text-[11.5px] leading-[21px] whitespace-pre overflow-hidden pointer-events-none select-none z-10"
        >
          {#each lines as lineText, idx}
            {@const lineNum = idx + 1}
            {@const isHighlighted = highlightedLine === lineNum}
            {@const isTarget = targetLine === lineNum}
            {@const lineAnoms = diagnosticsByLine.get(lineNum) || []}
            {@const hasCrit = lineAnoms.some((a) => isHighOrCritical(a.severity))}
            <div
              data-line={lineNum}
              class="h-[21px] leading-[21px] whitespace-pre flex items-center
                {lineAnoms.length > 0
                  ? hasCrit
                    ? 'bg-rose-500/10'
                    : 'bg-amber-500/10'
                  : isHighlighted
                    ? 'bg-sky-500/25'
                    : isTarget
                      ? 'bg-sky-500/15'
                      : ''}"
            >
              <span class="whitespace-pre">
                {#each splitWithSearch(lineText, syntaxLanguage, idx) as seg}
                  <span class={seg.cls}>{seg.text}</span>
                {/each}
              </span>

              <!-- F11: Non-line-shifting Inline Error Lens Diagnostic Pill(s) -->
              {#if lineAnoms.length > 0}
                <span class="ml-4 inline-flex items-center gap-1.5 pointer-events-auto">
                  {#each lineAnoms as diag (diag.id)}
                    {@const crit = isHighOrCritical(diag.severity)}
                    <span
                      class="inline-flex items-center gap-1 px-1.5 py-0 rounded text-[10px] font-mono border shadow-xs
                        {crit
                          ? 'bg-rose-950/90 text-rose-200 border-rose-500/50'
                          : 'bg-amber-950/90 text-amber-200 border-amber-500/50'}"
                      title="Remédiation : {diag.remediation}"
                    >
                      <ShieldAlert class="w-2.5 h-2.5 shrink-0 {crit ? 'text-rose-400' : 'text-amber-400'}" />
                      <strong class={crit ? 'text-rose-300' : 'text-amber-300'}>[{diag.displayId}]</strong>
                      <span class="truncate max-w-[360px]">{diag.message}</span>
                      <button
                        type="button"
                        onclick={() => askAiToFixDiagnostic(diag)}
                        class="ml-1 px-1 rounded bg-sky-500/20 hover:bg-sky-500/40 text-sky-200 text-[9px] cursor-pointer"
                        title="Envoyer au Chat IA pour correction"
                      >
                        IA
                      </button>
                      <button
                        type="button"
                        onclick={() => inspectDiagnosticInDrawer(diag)}
                        class="px-1 rounded bg-white/10 hover:bg-white/20 text-slate-200 text-[9px] cursor-pointer"
                        title="Ouvrir dans l'Inspecteur CWE"
                      >
                        Détails
                      </button>
                      <button
                        type="button"
                        onclick={() => cockpitState.ignoreCweRule(diag.ruleId || diag.cveId)}
                        class="px-1 rounded bg-white/5 hover:bg-rose-500/30 text-slate-400 hover:text-rose-200 text-[9px] cursor-pointer"
                        title="Ignorer la règle {diag.displayId}"
                      >
                        Ignorer
                      </button>
                    </span>
                  {/each}
                </span>
              {/if}
            </div>
          {/each}
        </div>

        <!-- Transparent Editable Textarea with Visible Caret -->
        <textarea
          bind:this={textareaEl}
          bind:value={content}
          oninput={handleContentInput}
          onscroll={handleEditorScroll}
          onkeydown={handleTextareaKeydown}
          onkeyup={updateCursorPosition}
          onclick={updateCursorPosition}
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          class="relative z-0 w-full h-full py-3 px-3.5 bg-transparent text-transparent caret-sky-400 selection:bg-sky-500/30 font-mono text-[11.5px] leading-[21px] resize-none focus:outline-none whitespace-pre overflow-auto scrollbar-thin select-text"
          placeholder="// Saisissez votre code source ici..."
        ></textarea>
      </div>
    {:else}
      <!-- Syntax Highlighted Tokenized Preview -->
      <div
        bind:this={previewContainerEl}
        class="flex-1 h-full overflow-auto py-3 px-2 bg-[#060810] font-mono text-[11.5px] leading-[21px] select-text scrollbar-thin"
      >
        {#each lines as lineText, idx}
          {@const lineNum = idx + 1}
          {@const isHighlighted = highlightedLine === lineNum}
          {@const isTarget = targetLine === lineNum}
          {@const lineAnoms = diagnosticsByLine.get(lineNum) || []}
          {@const hasCrit = lineAnoms.some((a) => isHighOrCritical(a.severity))}
          <div
            data-line={lineNum}
            class="flex items-baseline hover:bg-white/[0.03] px-1 rounded transition-colors h-[21px] leading-[21px]
              {isHighlighted ? 'bg-sky-500/35 border-l-4 border-sky-400 font-semibold shadow-md ring-1 ring-sky-400/40' : isTarget ? 'bg-sky-500/25 border-l-2 border-sky-400 font-semibold shadow-sm' : ''}"
          >
            <span class="w-10 shrink-0 select-none text-right pr-3 text-[10px] {isHighlighted ? 'text-sky-200 font-bold' : isTarget ? 'text-sky-300 font-bold' : 'text-slate-600'}">
              {lineNum}
            </span>
            <span class="whitespace-pre flex-1 truncate">
              {#each splitWithSearch(lineText, syntaxLanguage, idx) as tok}
                <span class={tok.cls}>{tok.text}</span>
              {/each}
              {#if lineAnoms.length > 0}
                {#each lineAnoms as diag (diag.id)}
                  <span class="ml-3 px-1.5 py-0.2 rounded text-[10px] {hasCrit ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'}">
                    [{diag.displayId}] {diag.message}
                  </span>
                {/each}
              {/if}
            </span>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- F13: Bottom Status Bar with Real-Time EARS Budget Gauge, SAST CWE Counter, Active AI Agents & 1-Click BLAKE3 Seal -->
  <div class="h-7 px-3 bg-[#090d16] border-t border-white/10 flex items-center justify-between gap-2 text-[10.5px] font-mono text-slate-400 select-none shrink-0 overflow-x-auto scrollbar-none">
    <div class="flex items-center gap-2.5 shrink-0">
      <span class="flex items-center gap-1">
        {#if isDirty}
          <span class="w-1.5 h-1.5 rounded-full bg-amber-400 shadow-[0_0_6px_#f59e0b]"></span>
          <span class="text-amber-300 font-semibold">● Modifications non enregistrées</span>
        {:else if isSaving}
          <RefreshCw class="w-2.5 h-2.5 text-sky-400 animate-spin" />
          <span class="text-sky-300">Enregistrement...</span>
        {:else}
          <Check class="w-2.5 h-2.5 text-emerald-400" />
          <span class="text-slate-400">Enregistré</span>
        {/if}
      </span>

      <span class="text-slate-700">|</span>

      <!-- EARS Line Budget Gauge -->
      <span
        class="px-1.5 py-0.2 rounded border text-[10px] font-semibold
          {effectiveFileLoc > effectiveMaxLinesLimit
            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
            : 'bg-white/[0.03] text-slate-300 border-white/10'}"
        title="Budget architectural de lignes du contrat EARS"
      >
        📏 {effectiveFileLoc} / {effectiveMaxLinesLimit} L
      </span>

      <!-- Real-Time Active-File SAST CWE Counter -->
      <span
        class="px-1.5 py-0.2 rounded border text-[10px] font-semibold flex items-center gap-1
          {activeFileCweCount > 0
            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'}"
        title="Compteur de violations SAST / CWE actives sur ce fichier"
      >
        {#if activeFileCweCount > 0}
          <ShieldAlert class="w-3 h-3 text-rose-400" />
          <span>{activeFileCweCount} CWE</span>
        {:else}
          <ShieldCheck class="w-3 h-3 text-emerald-400" />
          <span>0 CWE</span>
        {/if}
      </span>

      <!-- Active AI Agents targeting this file (< 5 min) -->
      {#if activeFileAgents.length > 0}
        <div class="flex items-center gap-1">
          {#each activeFileAgents as ag (ag.agentId)}
            <span
              class="inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[9.5px] bg-sky-500/15 border border-sky-400/35 text-sky-200"
              style="border-color: {ag.color}66;"
              title="Agent IA actif sur ce fichier ({ag.action || 'Analyse'})"
            >
              <Bot class="w-2.5 h-2.5" style="color: {ag.color};" />
              <span>{ag.agentName}</span>
            </span>
          {/each}
        </div>
      {/if}
    </div>

    <div class="flex items-center gap-2.5 shrink-0">
      <!-- 1-Click BLAKE3 Seal Action -->
      {#if cockpitState.ideActiveFile}
        <button
          type="button"
          onclick={sealCurrentContractBlake3}
          disabled={isSealingBlake3}
          class="flex items-center gap-1 px-2 py-0.2 rounded text-[10px] font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-200 border border-emerald-500/35 transition-colors cursor-pointer disabled:opacity-50"
          title="Sceller l'empreinte cryptographique BLAKE3 du contrat dans aether.lock.toml"
        >
          <Lock class="w-2.5 h-2.5 text-emerald-400" />
          <span>Sceller BLAKE3</span>
        </button>
      {/if}

      <span>Ln {cursorLine}, Col {cursorCol}</span>

      <span class="uppercase tracking-wider text-[9.5px] px-1.5 py-0.2 rounded bg-white/5 border border-white/10 text-sky-300">
        {syntaxLanguage}
      </span>
      <span class="text-slate-500 hidden md:inline">UTF-8</span>
    </div>
  </div>
</div>
