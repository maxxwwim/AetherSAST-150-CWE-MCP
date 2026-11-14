<script lang="ts">
  import { cockpitState, getNodeAlertKind } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import {
    BookOpen,
    Copy,
    Check,
    X,
    FileText,
    FolderOpen,
    RefreshCw,
    Library,
    ListTree,
    Maximize2,
    Minimize2,
    Lock,
    Search,
    ChevronRight,
    ChevronDown,
    ChevronUp,
    Pencil,
    Save,
    ShieldCheck,
    ShieldAlert,
    FileCode2,
    Sparkles,
    Layers,
    ArrowUpRight,
    ArrowDownLeft
  } from '@lucide/svelte';

  // State
  let loadedDocContent = $state('');
  let loadedDocPath = $state('');
  let loadedCodeContent = $state('');
  let loadedCodePath = $state('');
  let loadError = $state('');
  let loadingDoc = $state(false);
  let loadingCode = $state(false);
  let systemPromptText = $state('');

  // UI toggles
  let wideMode = $state(false);
  let showToc = $state(false);
  let showDocPicker = $state(false);
  let editMode = $state(false);
  let draftDocContent = $state('');
  let fullCodeView = $state(false);

  // Search & Copy feedback
  let docFilter = $state('');
  let contentSearch = $state('');
  let copiedDoc = $state(false);
  let copiedSnippet = $state(false);
  let copiedHash = $state(false);
  let saveDocStatus = $state('');
  let autoSaveEnabled = $state(true);
  let autoSaveTimer: ReturnType<typeof setTimeout> | null = null;
  let mermaidRawMap = $state<Record<number, boolean>>({});

  // Section collapsible states
  let openBlake3Section = $state(true);
  let openCodeSection = $state(true);
  let openDocSection = $state(true);
  let openRelationsSection = $state(true);

  // BLAKE3 Customization State
  let contractMaxLinesInput = $state(300);
  let contractSaveStatus = $state('');
  let contractSaving = $state(false);

  // Active Context resolution
  const symbol = $derived(cockpitState.activeSymbol);
  const selectedFolder = $derived(cockpitState.selectedFolder);

  // Find all Markdown docs across the repository
  const docLibraryFiles = $derived.by(() => {
    const seen = new Set<string>();
    const list: { name: string; path: string; folder: string; blake3?: boolean; lockVerified?: boolean; hasSec?: boolean }[] = [];
    const q = docFilter.trim().toLowerCase();

    for (const n of cockpitState.graph.nodes) {
      const p = n.file_path || '';
      const lower = p.toLowerCase();
      if (!(lower.endsWith('.md') || lower.endsWith('.mdx') || n.layer === 'docs')) continue;
      if (!p || seen.has(p)) continue;
      seen.add(p);

      const folder = n.folder || n.cluster_id || 'root';
      const name = p.split('/').pop() || n.name;
      if (q && !p.toLowerCase().includes(q) && !name.toLowerCase().includes(q) && !folder.toLowerCase().includes(q)) {
        continue;
      }
      list.push({
        name,
        path: p,
        folder,
        blake3: Boolean(n.metadata?.blake3_hash),
        lockVerified: Boolean(n.metadata?.lock_verified),
        hasSec: Boolean(n.has_security_violation),
      });
    }
    return list.sort((a, b) => {
      const aReadme = a.name.toLowerCase().includes('readme') ? -1 : 0;
      const bReadme = b.name.toLowerCase().includes('readme') ? -1 : 0;
      if (aReadme !== bReadme) return aReadme - bReadme;
      return a.path.localeCompare(b.path);
    });
  });

  // Best folder doc node
  const folderDocNode = $derived.by(() => {
    const startFolder = selectedFolder || symbol?.folder;
    if (startFolder) {
      let cur = startFolder.replace(/\\/g, '/');
      while (true) {
        const inFolder = docLibraryFiles.filter((d) => d.folder === cur);
        if (inFolder.length > 0) {
          return inFolder.find((d) => d.name.toLowerCase().includes('readme')) || inFolder[0];
        }
        if (!cur || cur === 'root' || cur === '.') break;
        const idx = cur.lastIndexOf('/');
        cur = idx >= 0 ? cur.slice(0, idx) : 'root';
      }
    }
    return docLibraryFiles.find((d) => d.path.toLowerCase() === 'readme.md') || docLibraryFiles[0] || null;
  });

  // Target node for contract metadata
  const activeTargetNode = $derived.by(() => {
    if (symbol) return symbol;
    if (selectedFolder) {
      const fn = cockpitState.graph.nodes.find(
        (n) => (n.folder || n.cluster_id) === selectedFolder && (n.metadata?.max_lines_limit || n.metadata?.blake3_hash)
      );
      if (fn) return fn;
    }
    return cockpitState.graph.nodes[0] || null;
  });

  const effectiveContractMaxLines = $derived(
    activeTargetNode?.metadata?.max_lines_limit || 300
  );

  const hasLinesAlert = $derived.by(() => {
    if (!activeTargetNode) return false;
    const loc = activeTargetNode.loc || 0;
    return loc > effectiveContractMaxLines || getNodeAlertKind(activeTargetNode) === 'lines_exceeded';
  });

  $effect(() => {
    contractMaxLinesInput = effectiveContractMaxLines;
  });

  // Load Source Code file
  async function loadCodeFile(path: string) {
    if (!path || path.endsWith('.md') || path.endsWith('.mdx')) {
      loadedCodeContent = '';
      loadedCodePath = '';
      return;
    }
    if (loadedCodePath === path && loadedCodeContent) return;
    loadingCode = true;
    try {
      const res = await api.getFileContent(path);
      if (res?.status === 'ok' && typeof res.content === 'string') {
        loadedCodeContent = res.content;
        loadedCodePath = res.path || path;
      } else {
        loadedCodeContent = '';
      }
    } catch {
      loadedCodeContent = '';
    } finally {
      loadingCode = false;
    }
  }

  // Load Markdown Doc file
  async function loadDocFile(path: string) {
    if (!path) return;
    if (loadedDocPath === path && loadedDocContent) return;
    loadingDoc = true;
    loadError = '';
    try {
      const res = await api.getFileContent(path);
      if (res?.status === 'ok' && typeof res.content === 'string') {
        loadedDocContent = res.content;
        loadedDocPath = res.path || path;
      } else {
        loadedDocContent = '';
        loadError = res?.message || `Impossible de charger ${path}`;
      }
    } catch (e: any) {
      loadedDocContent = '';
      loadError = String(e?.message || e || 'Erreur réseau');
    } finally {
      loadingDoc = false;
    }
  }

  // Reactively synchronize files whenever panel opens or target symbol/folder changes
  $effect(() => {
    if (!cockpitState.isDocPanelOpen) return;

    // 1. Code file sync
    const targetCodePath = symbol?.file_path || (cockpitState.docSelectedPath && !cockpitState.docSelectedPath.endsWith('.md') ? cockpitState.docSelectedPath : '');
    if (targetCodePath) {
      loadCodeFile(targetCodePath);
    } else {
      loadedCodeContent = '';
      loadedCodePath = '';
    }

    // 2. Doc file sync
    if (cockpitState.docMode === 'system') {
      if (cockpitState.graph.system_prompt) {
        systemPromptText = cockpitState.graph.system_prompt;
      } else {
        api.getSystemPrompt().then((res) => {
          systemPromptText = res?.system_prompt || '';
        }).catch(() => {});
      }
    } else {
      let targetDocPath = '';
      if (cockpitState.docSelectedPath && (cockpitState.docSelectedPath.endsWith('.md') || cockpitState.docSelectedPath.endsWith('.mdx'))) {
        targetDocPath = cockpitState.docSelectedPath;
      } else if (folderDocNode?.path) {
        targetDocPath = folderDocNode.path;
      } else {
        targetDocPath = selectedFolder && selectedFolder !== 'root' ? `${selectedFolder}/README.md` : 'README.md';
      }
      if (targetDocPath) {
        loadDocFile(targetDocPath);
      }
    }
  });

  // Extract AST comments preceding symbol definition
  function extractAstComments(content: string, lineNumber?: number): string {
    if (!content || !lineNumber || lineNumber <= 1) return '';
    const lines = content.split('\n');
    const idx = Math.min(lines.length - 1, lineNumber - 1);
    const out: string[] = [];
    for (let i = idx - 1; i >= 0 && i >= idx - 30; i--) {
      const t = lines[i].trim();
      if (!t) {
        if (out.length > 0) break;
        continue;
      }
      if (t.startsWith('#[') || t.startsWith('#![')) continue;
      if (t.startsWith('///') || t.startsWith('//!')) out.push(t.slice(3).trim());
      else if (t.startsWith('//')) out.push(t.slice(2).trim());
      else if (t.startsWith('*') || t.startsWith('/**') || t.startsWith('*/')) {
        const cleaned = t.replace(/^\/?\*+\/?/, '').trim();
        if (cleaned) out.push(cleaned);
      } else if (t.startsWith('#')) out.push(t.slice(1).trim());
      else break;
    }
    return out.reverse().join('\n');
  }

  const activeAstComments = $derived.by(() => {
    if (symbol?.docstring) return symbol.docstring;
    return extractAstComments(loadedCodeContent, symbol?.line_number);
  });

  // Code lines for syntax highlighting with target line indicator
  const displayedCodeLines = $derived.by(() => {
    const raw = loadedCodeContent || (symbol?.metadata as any)?.raw_content || '';
    if (!raw) return [];
    const allLines = raw.split('\n');
    const targetLine = symbol?.line_number || 1;

    if (fullCodeView || allLines.length <= 110) {
      return allLines.map((text: string, idx: number) => ({
        lineNum: idx + 1,
        text,
        isTarget: idx + 1 === targetLine,
      }));
    }

    const start = Math.max(0, targetLine - 25);
    const end = Math.min(allLines.length, targetLine + 75);
    return allLines.slice(start, end).map((text: string, idx: number) => ({
      lineNum: start + idx + 1,
      text,
      isTarget: start + idx + 1 === targetLine,
    }));
  });

  function copyCodeSnippet() {
    const code = displayedCodeLines.map((l: { text: string }) => l.text).join('\n');
    navigator.clipboard?.writeText(code);
    copiedSnippet = true;
    setTimeout(() => (copiedSnippet = false), 1500);
  }

  // Syntax highlighting tokenizer
  const CODE_KEYWORDS = new Set([
    'fn', 'pub', 'let', 'mut', 'const', 'static', 'async', 'await', 'impl', 'trait', 'struct', 'enum', 'mod', 'use', 'crate', 'self', 'super', 'where', 'match', 'if', 'else', 'for', 'while', 'loop', 'return', 'break', 'continue', 'type', 'unsafe', 'move', 'ref', 'in', 'as',
    'function', 'class', 'interface', 'extends', 'implements', 'import', 'export', 'from', 'default', 'new', 'this', 'try', 'catch', 'finally', 'throw', 'typeof', 'instanceof', 'void', 'delete',
    'def', 'elif', 'except', 'lambda', 'pass', 'raise', 'with', 'yield', 'global', 'nonlocal', 'assert', 'None', 'True', 'False',
    'contract', 'pragma', 'solidity', 'mapping', 'event', 'emit', 'modifier', 'require', 'revert', 'payable', 'view', 'pure', 'external', 'internal', 'public', 'private', 'memory', 'storage', 'calldata',
    'true', 'false', 'null', 'undefined',
  ]);

  function tokenizeCodeLine(line: string): { text: string; cls: string }[] {
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('# ') || trimmed.startsWith('--')) {
      return [{ text: line, cls: 'text-slate-500 italic' }];
    }
    const tokens: { text: string; cls: string }[] = [];
    const regex = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\/\/.*$|\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+(?:\.\d+)?\b|[{}()[\].,:;+-/*=<>!&|?~]+)/g;
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
        cls = 'text-amber-300';
      } else if (/^\d/.test(tok)) {
        cls = 'text-purple-300';
      } else if (CODE_KEYWORDS.has(tok)) {
        cls = 'text-pink-400 font-semibold';
      } else if (/^[A-Z][A-Za-z0-9_]*$/.test(tok)) {
        cls = 'text-emerald-300';
      } else if (/^[{}()[\].,:;+-/*=<>!&|?~]+$/.test(tok)) {
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

  // BLAKE3 Contract Customization API action
  async function saveContractBudget(mode: 'file' | 'folder' | 'clear_file') {
    const target = activeTargetNode;
    const folder = target?.metadata?.contract_folder || target?.folder || target?.cluster_id || selectedFolder || 'root';
    const filePath = target?.file_path || (loadedCodePath && !loadedCodePath.endsWith('.md') ? loadedCodePath : undefined);
    const limit = Math.max(10, Number(contractMaxLinesInput) || 300);

    contractSaving = true;
    contractSaveStatus = 'Scellement BLAKE3...';
    try {
      const payload: Parameters<typeof api.updateContract>[0] = {
        project_path: cockpitState.graph.project_path || '.',
        folder,
      };
      if (mode === 'file' && filePath) {
        payload.file_path = filePath;
        payload.file_max_lines = limit;
      } else if (mode === 'clear_file' && filePath) {
        payload.file_path = filePath;
        payload.clear_file_override = true;
      } else {
        payload.max_lines_per_file = limit;
      }
      const res = await api.updateContract(payload);
      if (res.status === 'ok') {
        if (res.graph) {
          cockpitState.setGraph(res.graph, true);
        }
        contractSaveStatus = `✓ Scellé BLAKE3 (${res.blake3_hash ? res.blake3_hash.slice(0, 8) : 'OK'})`;
      } else {
        contractSaveStatus = `Erreur: ${res.message}`;
      }
    } catch (e: any) {
      contractSaveStatus = String(e?.message || e || 'Erreur réseau');
    } finally {
      contractSaving = false;
      setTimeout(() => {
        contractSaveStatus = '';
      }, 4000);
    }
  }

  function copyBlake3Hash(hash: string) {
    navigator.clipboard?.writeText(hash);
    copiedHash = true;
    setTimeout(() => (copiedHash = false), 1400);
  }

  // Save Markdown document on disk with auto-save support
  async function saveCurrentDoc(isAuto = false) {
    const p = loadedDocPath || (symbol?.file_path?.endsWith('.md') ? symbol.file_path : 'README.md');
    const parts = p.split('/');
    const fileName = parts.pop() || 'README.md';
    const folder = parts.join('/') || '.';
    saveDocStatus = isAuto ? 'Auto-sauvegarde...' : 'Sauvegarde...';
    try {
      const res = await api.saveDoc({
        project_path: cockpitState.graph.project_path || '.',
        folder,
        file_name: fileName,
        content: draftDocContent,
      });
      loadedDocContent = draftDocContent;
      if (res.graph) cockpitState.setGraph(res.graph, true);
      saveDocStatus = res.blake3_hash
        ? `${isAuto ? '✓ Auto-save' : 'Enregistré'} (${res.blake3_hash.slice(0, 8)})`
        : isAuto
          ? '✓ Auto-sauvegardé'
          : 'Enregistré';
      setTimeout(() => (saveDocStatus = ''), 3000);
    } catch (e: any) {
      saveDocStatus = e?.message || 'Erreur sauvegarde';
    }
  }

  function triggerDocAutoSave() {
    if (!autoSaveEnabled || !editMode) return;
    if (autoSaveTimer) clearTimeout(autoSaveTimer);
    saveDocStatus = '⏳ Auto-save (1.5s)...';
    autoSaveTimer = setTimeout(() => {
      saveCurrentDoc(true);
    }, 1500);
  }

  async function signAllContracts() {
    const p = loadedDocPath || selectedFolder || '';
    const folder = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : p || undefined;
    saveDocStatus = 'Signature globale BLAKE3...';
    try {
      const res = await api.signContracts({
        project_path: cockpitState.graph.project_path || '.',
        folder,
      });
      if (res.graph) cockpitState.setGraph(res.graph, true);
      saveDocStatus = `Signé (${res.signed_count})`;
      setTimeout(() => (saveDocStatus = ''), 3000);
    } catch (e: any) {
      saveDocStatus = e?.message || 'Erreur signature';
    }
  }

  function enterEditMode() {
    if (!editMode) {
      draftDocContent = loadedDocContent;
      editMode = true;
    } else {
      if (autoSaveTimer) clearTimeout(autoSaveTimer);
      editMode = false;
    }
  }

  // Markdown parsing for rendered blocks
  type DocBlock =
    | { type: 'h1' | 'h2' | 'h3'; text: string; anchor: string }
    | { type: 'code'; text: string; lang?: string }
    | { type: 'table'; headers: string[]; rows: string[][] }
    | { type: 'image'; alt: string; src: string }
    | { type: 'list' | 'quote' | 'p'; text: string };

  function resolveImageSrc(rawSrc: string): string {
    const clean = rawSrc.trim().replace(/^["']|["']$/g, '').replace(/\\/g, '/');
    if (/^(https?:|data:|blob:)/i.test(clean)) return clean;
    const baseDir = loadedDocPath.includes('/') ? loadedDocPath.slice(0, loadedDocPath.lastIndexOf('/')) : '';
    const joined = clean.startsWith('/') ? clean.slice(1) : baseDir ? `${baseDir}/${clean}` : clean;
    const stack: string[] = [];
    for (const part of joined.split('/')) {
      if (!part || part === '.') continue;
      if (part === '..') stack.pop();
      else stack.push(part);
    }
    return api.getRawFileUrl(stack.join('/'));
  }

  const rawDocMarkdown = $derived.by(() => {
    if (cockpitState.docMode === 'system') {
      return systemPromptText || cockpitState.graph.system_prompt || `# ${cockpitState.graph.project_name || 'Aether Engine'}\n\nSpécification globale du projet.`;
    }
    if (loadedDocContent) return loadedDocContent;
    if (loadError) return `# Documentation\n\n> ⚠️ ${loadError}`;
    return `# Documentation & Contrats\n\nAucun fichier Markdown direct trouvé pour cette cible. Consultez les contrats EARS et le code source ci-dessus.`;
  });

  const parsedBlocks = $derived.by(() => {
    const lines = rawDocMarkdown.split('\n');
    const blocks: DocBlock[] = [];
    let inCode = false;
    let codeLang = '';
    let codeBuf: string[] = [];
    let tableBuf: string[] = [];

    const flushTable = () => {
      if (tableBuf.length >= 2) {
        const parseRow = (r: string) =>
          r
            .trim()
            .replace(/^\|/, '')
            .replace(/\|$/, '')
            .split('|')
            .map((c) => c.trim());
        const headers = parseRow(tableBuf[0]);
        const dataRows = tableBuf
          .slice(1)
          .filter((r) => !/^\|?[\s:-]+\|/.test(r.trim()))
          .map(parseRow);
        blocks.push({ type: 'table', headers, rows: dataRows });
      }
      tableBuf = [];
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith('```')) {
        flushTable();
        if (!inCode) {
          inCode = true;
          codeLang = line.trim().slice(3).trim();
          codeBuf = [];
        } else {
          blocks.push({ type: 'code', text: codeBuf.join('\n'), lang: codeLang });
          inCode = false;
          codeBuf = [];
        }
        continue;
      }
      if (inCode) {
        codeBuf.push(line);
        continue;
      }
      if (line.trim().startsWith('|') && line.includes('|')) {
        tableBuf.push(line);
        continue;
      }
      flushTable();

      const trimmed = line.trim();
      const htmlImgMatch = trimmed.match(/<img\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/i);
      if (htmlImgMatch) {
        const altMatch = trimmed.match(/\balt=["']([^"']*)["']/i);
        blocks.push({ type: 'image', alt: altMatch?.[1] || 'Image', src: resolveImageSrc(htmlImgMatch[1]) });
        continue;
      }
      if (/^<\/?(div|p|center|section|header|footer|details|summary|br)\b[^>]*>$/i.test(trimmed)) {
        continue;
      }

      const cleanLine = trimmed
        .replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, '$2 ($1)')
        .replace(/<\/?(b|strong|i|em|u|kbd|code|span|sub|sup)\b[^>]*>/gi, '')
        .trim();

      const imgMatch = cleanLine.match(/^!\[([^\]]*)\]\(([^)]+)\)/);
      if (imgMatch) {
        blocks.push({ type: 'image', alt: imgMatch[1] || 'Image', src: resolveImageSrc(imgMatch[2]) });
      } else if (cleanLine.startsWith('### ')) {
        blocks.push({ type: 'h3', text: cleanLine.slice(4), anchor: `doc-toc-${i}` });
      } else if (cleanLine.startsWith('## ')) {
        blocks.push({ type: 'h2', text: cleanLine.slice(3), anchor: `doc-toc-${i}` });
      } else if (cleanLine.startsWith('# ')) {
        blocks.push({ type: 'h1', text: cleanLine.slice(2), anchor: `doc-toc-${i}` });
      } else if (cleanLine.startsWith('> ')) {
        blocks.push({ type: 'quote', text: cleanLine.slice(2) });
      } else if (cleanLine.startsWith('- ') || cleanLine.startsWith('* ')) {
        blocks.push({ type: 'list', text: cleanLine.slice(2) });
      } else if (cleanLine.length > 0 && cleanLine !== '---') {
        blocks.push({ type: 'p', text: cleanLine });
      }
    }
    flushTable();
    if (inCode && codeBuf.length > 0) {
      blocks.push({ type: 'code', text: codeBuf.join('\n'), lang: codeLang });
    }
    return blocks;
  });

  const tocHeadings = $derived(
    parsedBlocks.filter((b): b is Extract<DocBlock, { type: 'h1' | 'h2' | 'h3' }> => b.type === 'h1' || b.type === 'h2' || b.type === 'h3')
  );

  const readingMetrics = $derived.by(() => {
    const words = rawDocMarkdown.trim() ? rawDocMarkdown.trim().split(/\s+/).length : 0;
    const minutes = Math.max(1, Math.ceil(words / 200));
    const codeBlocks = parsedBlocks.filter((b) => b.type === 'code').length;
    return { words, minutes, headings: tocHeadings.length, codeBlocks };
  });

  const filteredBlocks = $derived.by(() => {
    const q = contentSearch.trim().toLowerCase();
    if (!q) return parsedBlocks;
    return parsedBlocks.filter((b) => {
      if (b.type === 'table') {
        return b.headers.some((h) => h.toLowerCase().includes(q)) || b.rows.some((r) => r.some((c) => c.toLowerCase().includes(q)));
      }
      if (b.type === 'image') return b.alt.toLowerCase().includes(q);
      return b.text.toLowerCase().includes(q);
    });
  });

  // Mermaid parse
  function parseMermaidEdges(code: string): { nodes: string[]; edges: { from: string; to: string; label: string }[] } {
    const nodesSet = new Set<string>();
    const edges: { from: string; to: string; label: string }[] = [];
    for (const rawLine of code.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('%%') || /^(graph|flowchart|sequenceDiagram|classDiagram|subgraph|end)\b/i.test(line)) {
        continue;
      }
      const m = line.match(/([A-Za-z0-9_-]+)(?:\[[^\]]*\]|\([^)]*\))?\s*(?:-->|-.->|==>|->|-->>)\s*(?:\|([^|]+)\|)?\s*([A-Za-z0-9_-]+)/);
      if (m) {
        nodesSet.add(m[1]);
        nodesSet.add(m[3]);
        edges.push({ from: m[1], to: m[3], label: (m[2] || '').trim() });
      }
    }
    return { nodes: Array.from(nodesSet).slice(0, 12), edges: edges.slice(0, 16) };
  }

  // Relations Links at the bottom
  const docRelations = $derived.by(() => {
    const nodes = cockpitState.graph.nodes || [];
    const edges = cockpitState.graph.edges || [];
    if (nodes.length === 0) return { incoming: [], outgoing: [], scopeLabel: '' };

    const nodeById = new Map(nodes.map((n) => [n.id, n]));
    const targetIds = new Set<string>();
    let scopeLabel = '';

    if (symbol) {
      targetIds.add(symbol.id);
      scopeLabel = symbol.name;
    } else {
      const refPath = (loadedCodePath || loadedDocPath || selectedFolder || '').replace(/\\/g, '/');
      const folderPrefix = refPath.endsWith('.md')
        ? refPath.includes('/')
          ? refPath.slice(0, refPath.lastIndexOf('/'))
          : ''
        : refPath;
      scopeLabel = folderPrefix || 'Racine Projet';
      for (const n of nodes) {
        const nf = (n.file_path || '').replace(/\\/g, '/');
        if (!folderPrefix ? !nf.includes('/') : nf === folderPrefix || nf.startsWith(folderPrefix + '/')) {
          targetIds.add(n.id);
        }
      }
      if (targetIds.size === 0 && cockpitState.activeSymbol) {
        targetIds.add(cockpitState.activeSymbol.id);
        scopeLabel = cockpitState.activeSymbol.name;
      }
    }

    const incoming: { id: string; name: string; file: string; relation: string }[] = [];
    const outgoing: { id: string; name: string; file: string; relation: string }[] = [];
    const seenIn = new Set<string>();
    const seenOut = new Set<string>();

    for (const e of edges) {
      const fromId = e.source || (e as any).from;
      const toId = e.target || (e as any).to;
      const rel = String(e.relation || 'calls').toUpperCase();
      if (targetIds.has(toId) && !targetIds.has(fromId) && !seenIn.has(fromId)) {
        const src = nodeById.get(fromId);
        if (src) {
          seenIn.add(fromId);
          incoming.push({ id: src.id, name: src.name, file: src.file_path || '', relation: rel });
        }
      }
      if (targetIds.has(fromId) && !targetIds.has(toId) && !seenOut.has(toId)) {
        const dst = nodeById.get(toId);
        if (dst) {
          seenOut.add(toId);
          outgoing.push({ id: dst.id, name: dst.name, file: dst.file_path || '', relation: rel });
        }
      }
    }

    return {
      incoming: incoming.slice(0, 10),
      outgoing: outgoing.slice(0, 10),
      scopeLabel,
    };
  });

  function jumpToRelationNode(nodeId: string) {
    const target = cockpitState.graph.nodes.find((n) => n.id === nodeId);
    if (target) {
      cockpitState.selectSymbol(target.id);
      cockpitState.requestFocusSymbol(target.id);
    }
  }

  function selectDocFromPicker(path: string) {
    cockpitState.docSelectedPath = path;
    cockpitState.docMode = 'library';
    showDocPicker = false;
    loadDocFile(path);
  }

  function copyAllMarkdown() {
    navigator.clipboard?.writeText(rawDocMarkdown);
    copiedDoc = true;
    setTimeout(() => (copiedDoc = false), 1500);
  }
</script>

<!-- Left Edge Docked Pill when collapsed -->
{#if !cockpitState.isDocPanelOpen}
  <button
    type="button"
    onclick={() => cockpitState.openDoc('library')}
    class="fixed left-3 top-[80px] z-30 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0b0f19]/92 hover:bg-emerald-500/20 backdrop-blur-md border border-emerald-500/35 text-[11px] font-semibold text-emerald-200 shadow-xl cursor-pointer transition-all"
    title="Ouvrir le panneau Docs, EARS & Source à gauche"
  >
    <BookOpen class="w-3.5 h-3.5 text-emerald-400" />
    <span>Docs, EARS & Source</span>
    <span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px]">
      {docLibraryFiles.length}
    </span>
    <ChevronRight class="w-3 h-3" />
  </button>
{/if}

{#if cockpitState.isDocPanelOpen}
  <aside
    class="fixed left-0 sm:left-3 top-[76px] bottom-0 sm:bottom-6 w-full {wideMode ? 'sm:w-[740px]' : 'sm:w-[520px]'} max-w-full sm:max-w-[95vw] bg-[#070b14]/96 backdrop-blur-2xl border border-emerald-500/35 rounded-none sm:rounded-2xl shadow-[0_24px_70px_rgba(0,0,0,0.92)] z-40 flex flex-col overflow-hidden transition-all duration-200"
  >
    <!-- Top Header Bar -->
    <div class="px-3.5 py-2.5 bg-gradient-to-r from-[#0c1426] via-[#09101d] to-[#0b1322] border-b border-white/10 flex items-center justify-between gap-2 shrink-0">
      <div class="flex items-center gap-2 min-w-0">
        <div class="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-400/40 flex items-center justify-center shrink-0 shadow-[0_0_12px_rgba(16,185,129,0.25)]">
          <BookOpen class="w-4 h-4 text-emerald-400" />
        </div>
        <div class="min-w-0">
          <div class="text-xs font-extrabold text-white tracking-wide truncate flex items-center gap-1.5">
            <span>Lecteur Docs, EARS & Source</span>
            <span class="px-1.5 py-0.2 rounded bg-sky-500/20 border border-sky-500/40 text-sky-300 font-mono text-[9px]">
              v2.4
            </span>
          </div>
          <div class="text-[10px] font-mono text-slate-400 truncate">
            {#if symbol}
              <span class="text-sky-300 font-bold">{symbol.name}</span> · <span class="text-slate-400">{symbol.file_path}</span>
            {:else if selectedFolder}
              <span class="text-emerald-300 font-bold">📁 {selectedFolder}</span>
            {:else}
              <span class="text-slate-400">Racine du Projet</span>
            {/if}
          </div>
        </div>
      </div>

      <!-- Action buttons -->
      <div class="flex items-center gap-1 shrink-0">
        {#if loadingDoc || loadingCode}
          <RefreshCw class="w-3.5 h-3.5 text-sky-400 animate-spin mr-1" />
        {/if}
        <button
          type="button"
          onclick={() => (showToc = !showToc)}
          title="Sommaire Markdown"
          class="flex items-center gap-1 px-2 py-1 rounded text-[10px] border cursor-pointer {showToc ? 'bg-sky-500/20 border-sky-500/40 text-sky-300' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
        >
          <ListTree class="w-3 h-3" />
          <span class="hidden sm:inline">Sommaire ({tocHeadings.length})</span>
        </button>
        <button
          type="button"
          onclick={() => (wideMode = !wideMode)}
          title={wideMode ? 'Réduire la largeur' : 'Agrandir la largeur'}
          class="p-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 cursor-pointer"
        >
          {#if wideMode}<Minimize2 class="w-3 h-3" />{:else}<Maximize2 class="w-3 h-3" />{/if}
        </button>
        <button
          type="button"
          onclick={enterEditMode}
          title="Éditer le document Markdown"
          class="flex items-center gap-1 px-2 py-1 rounded text-[10px] border cursor-pointer {editMode ? 'bg-amber-500/20 border-amber-500/40 text-amber-300' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
        >
          <Pencil class="w-3 h-3" />
          <span class="hidden sm:inline">{editMode ? 'Aperçu' : 'Éditer'}</span>
        </button>
        <button
          type="button"
          onclick={signAllContracts}
          title="Signer l'empreinte BLAKE3 dans aether.lock.toml"
          class="flex items-center gap-1 px-2 py-1 rounded text-[10px] bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 cursor-pointer"
        >
          <ShieldCheck class="w-3 h-3" />
          <span class="hidden sm:inline">Signer</span>
        </button>
        <button
          type="button"
          onclick={copyAllMarkdown}
          class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] text-slate-300 cursor-pointer"
        >
          {#if copiedDoc}<Check class="w-3 h-3 text-emerald-400" /><span>Copié</span>{:else}<Copy class="w-3 h-3" /><span>Copier</span>{/if}
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.isDocPanelOpen = false)}
          aria-label="Fermer le panneau"
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>
    </div>

    <!-- Target Context Switcher & Doc Picker Strip -->
    <div class="px-3 py-1.5 bg-[#050811] border-b border-white/10 flex items-center justify-between gap-2 text-[10px] font-mono shrink-0">
      <div class="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-0.5">
        {#if symbol}
          <span class="px-2 py-0.5 rounded-md bg-sky-500/20 border border-sky-500/40 text-sky-200 font-bold shrink-0 flex items-center gap-1">
            <span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
            {symbol.name} ({symbol.stereotype || symbol.kind})
          </span>
        {/if}
        {#if selectedFolder || activeTargetNode?.folder}
          <button
            type="button"
            onclick={() => {
              cockpitState.docMode = 'folder';
              if (folderDocNode?.path) loadDocFile(folderDocNode.path);
            }}
            class="px-2 py-0.5 rounded-md bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 shrink-0 cursor-pointer flex items-center gap-1"
          >
            <FolderOpen class="w-2.5 h-2.5" />
            {selectedFolder || activeTargetNode?.folder || 'root'}
          </button>
        {/if}
        <button
          type="button"
          onclick={() => (showDocPicker = !showDocPicker)}
          class="px-2 py-0.5 rounded-md border shrink-0 cursor-pointer flex items-center gap-1 {showDocPicker ? 'bg-amber-500/20 border-amber-500/40 text-amber-200' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
        >
          <Library class="w-2.5 h-2.5 text-amber-400" />
          <span>Docs ({docLibraryFiles.length})</span>
          <ChevronDown class="w-2.5 h-2.5" />
        </button>
        <button
          type="button"
          onclick={() => {
            cockpitState.docMode = 'system';
            if (cockpitState.graph.system_prompt) systemPromptText = cockpitState.graph.system_prompt;
          }}
          class="px-2 py-0.5 rounded-md border shrink-0 cursor-pointer {cockpitState.docMode === 'system' ? 'bg-purple-500/20 border-purple-500/40 text-purple-200' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-400 hover:text-white'}"
        >
          📜 Projet
        </button>
      </div>

      {#if saveDocStatus}
        <span class="text-emerald-300 font-bold shrink-0">{saveDocStatus}</span>
      {/if}
    </div>

    <!-- Collapsible Quick Doc Picker Dropdown -->
    {#if showDocPicker}
      <div class="px-3 py-2 bg-[#060913] border-b border-amber-500/30 space-y-1.5 shrink-0">
        <div class="relative">
          <Search class="w-3 h-3 text-slate-500 absolute left-2 top-2" />
          <input
            type="text"
            bind:value={docFilter}
            placeholder="Rechercher un document Markdown / spécification..."
            class="w-full pl-6 pr-2 py-1 rounded bg-black/50 border border-white/15 text-[10.5px] text-slate-200 focus:outline-none focus:border-amber-400"
          />
        </div>
        <div class="max-h-36 overflow-y-auto space-y-1 pr-1 font-mono text-[10px]">
          {#each docLibraryFiles as doc}
            <button
              type="button"
              onclick={() => selectDocFromPicker(doc.path)}
              class="w-full flex items-center justify-between gap-2 px-2 py-1 rounded text-left cursor-pointer border transition-colors {loadedDocPath === doc.path ? 'bg-amber-500/20 border-amber-500/50 text-amber-200 font-bold' : 'bg-white/[0.03] border-white/5 text-slate-300 hover:bg-white/[0.08]'}"
            >
              <span class="truncate">📄 {doc.path}</span>
              <span class="flex items-center gap-1.5 shrink-0">
                {#if doc.blake3}
                  <Lock class="w-2.5 h-2.5 {doc.lockVerified ? 'text-emerald-400' : 'text-amber-400'}" />
                {/if}
                <span class="text-[9px] text-slate-500">{doc.folder}</span>
              </span>
            </button>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Optional Collapsible TOC -->
    {#if showToc && tocHeadings.length > 0}
      <div class="px-3 py-2 border-b border-white/10 bg-sky-950/20 max-h-32 overflow-y-auto space-y-1 shrink-0">
        <div class="text-[9.5px] font-mono uppercase text-sky-400 font-bold">Sommaire des sections</div>
        {#each tocHeadings as h}
          <button
            type="button"
            onclick={() => {
              document.getElementById(h.anchor)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }}
            class="block w-full text-left text-[10.5px] hover:text-sky-300 truncate cursor-pointer {h.type === 'h1' ? 'font-bold text-white' : h.type === 'h2' ? 'pl-2 text-emerald-300' : 'pl-4 text-slate-400'}"
          >
            {h.text}
          </button>
        {/each}
      </div>
    {/if}

    <!-- SINGLE UNIFIED TAB CONTENT (Everything in the same tab!) -->
    <div class="flex-1 overflow-y-auto p-3.5 space-y-3.5 select-text">

      <!-- ======================================================== -->
      <!-- 1. STYLE DE LA PERSONNALISATION DU BLAKE3 (CONTRAT CYBER) -->
      <!-- ======================================================== -->
      <section class="rounded-xl border {hasLinesAlert ? 'border-orange-500/60 shadow-[0_0_24px_rgba(249,115,22,0.2)]' : 'border-emerald-500/35 shadow-[0_8px_24px_rgba(0,0,0,0.6)]'} bg-gradient-to-br from-[#0c1426] via-[#080d19] to-[#04060c] overflow-hidden transition-all">
        <!-- Section Header Bar -->
        <div class="px-3.5 py-2.5 bg-black/40 border-b border-white/10 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-6 h-6 rounded-md {hasLinesAlert ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'} flex items-center justify-center shrink-0 shadow-sm">
              <Lock class="w-3.5 h-3.5" />
            </div>
            <div class="min-w-0">
              <div class="text-[11px] font-extrabold tracking-wide uppercase {hasLinesAlert ? 'text-orange-200' : 'text-emerald-200'} flex items-center gap-1.5">
                <span>CONTRAT CRYPTOGRAPHIQUE BLAKE3</span>
                {#if activeTargetNode?.metadata?.contract_folder}
                  <span class="text-[9.5px] font-mono text-slate-400 lowercase font-normal">
                    ({activeTargetNode.metadata.contract_folder})
                  </span>
                {/if}
              </div>
              <div class="text-[9.5px] font-mono text-slate-400">
                Gouvernance d’architecture & intégrité scellée dans <code class="text-emerald-300">aether.lock.toml</code>
              </div>
            </div>
          </div>
          <button
            type="button"
            onclick={() => (openBlake3Section = !openBlake3Section)}
            class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
            title="Replier / Déplier la section BLAKE3"
          >
            {#if openBlake3Section}<ChevronUp class="w-3.5 h-3.5" />{:else}<ChevronDown class="w-3.5 h-3.5" />{/if}
          </button>
        </div>

        {#if openBlake3Section}
          <div class="p-3.5 space-y-2.5">
            <!-- Cryptographic Badges -->
            <div class="flex flex-wrap gap-1.5 items-center text-[10px] font-mono">
              {#if activeTargetNode?.metadata?.blake3_hash}
                <span class="px-2 py-0.5 rounded-full flex items-center gap-1 {activeTargetNode.metadata.lock_verified ? 'bg-emerald-500/20 border border-emerald-500/50 text-emerald-300' : 'bg-amber-500/20 border border-amber-500/50 text-amber-300'}">
                  <ShieldCheck class="w-3 h-3" />
                  BLAKE3 {activeTargetNode.metadata.lock_verified ? 'Scellé' : 'Modifié'}
                  ({activeTargetNode.metadata.ears_count || 0} Invariants EARS)
                </span>
                <button
                  type="button"
                  onclick={() => copyBlake3Hash(activeTargetNode?.metadata?.blake3_hash || '')}
                  class="px-2 py-0.5 rounded-full bg-white/5 hover:bg-white/10 border border-white/15 text-slate-300 hover:text-white cursor-pointer transition-colors"
                  title="Copier l'empreinte BLAKE3"
                >
                  {#if copiedHash}✓ Copié{:else}#{activeTargetNode.metadata.blake3_hash.slice(0, 10)}...{/if}
                </button>
              {/if}

              {#if activeTargetNode?.metadata?.file_blake3_hash}
                <span class="px-2 py-0.5 rounded-full bg-sky-500/15 border border-sky-500/35 text-sky-300" title="Empreinte BLAKE3 du fichier source">
                  Fichier: #{activeTargetNode.metadata.file_blake3_hash.slice(0, 8)}
                </span>
              {/if}

              {#if activeTargetNode?.metadata?.file_max_lines_override}
                <span class="px-2 py-0.5 rounded-full bg-orange-500/20 border border-orange-500/50 text-orange-200 font-bold">
                  ⚡ Override Fichier ({activeTargetNode.metadata.file_max_lines_override} L)
                </span>
              {/if}
            </div>

            <!-- Orange Alert Banner if Lines Exceeded -->
            {#if hasLinesAlert}
              <div class="p-2.5 rounded-xl bg-orange-950/40 border border-orange-500/60 flex flex-col gap-1 shadow-inner">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[11px] font-extrabold text-orange-200 flex items-center gap-1.5">
                    <ShieldAlert class="w-4 h-4 text-orange-400 shrink-0" />
                    ⚠️ BUDGET LIGNES DÉPASSÉ ({activeTargetNode?.loc || 0} / {effectiveContractMaxLines} L)
                  </span>
                  <span class="px-1.5 py-0.5 rounded bg-orange-500/30 text-orange-200 font-mono text-[9px] font-bold">
                    RULE_MAX_LINES
                  </span>
                </div>
                <p class="text-[10.5px] text-orange-100/90 leading-relaxed">
                  Ce fichier dépasse la limite contractuelle BLAKE3 ({effectiveContractMaxLines} lignes). Vous pouvez augmenter la limite ou sceller un override ci-dessous.
                </p>
              </div>
            {/if}

            <!-- Interactive Customization Panel (Inputs + Presets + Sealing Buttons) -->
            <div class="p-3 rounded-xl bg-black/60 border border-white/10 space-y-2.5">
              <div class="flex items-center justify-between gap-2 flex-wrap">
                <div class="flex items-center gap-2">
                  <label for="blake3-max-lines-input" class="text-[10.5px] font-mono text-slate-300 font-bold shrink-0">
                    Budget Max Lignes :
                  </label>
                  <input
                    id="blake3-max-lines-input"
                    type="number"
                    min="10"
                    max="50000"
                    step="50"
                    bind:value={contractMaxLinesInput}
                    class="w-24 px-2.5 py-1 rounded-lg bg-[#060a14] border border-white/20 text-white font-mono text-xs font-bold focus:border-emerald-400 focus:outline-none focus:ring-1 focus:ring-emerald-400/50 shadow-inner"
                  />
                </div>

                <!-- Presets buttons -->
                <div class="flex items-center gap-1 flex-wrap">
                  {#each [200, 300, 500, 800, 1500, 3000] as preset}
                    <button
                      type="button"
                      onclick={() => (contractMaxLinesInput = preset)}
                      class="px-2 py-0.5 rounded text-[9.5px] font-mono border cursor-pointer transition-all {contractMaxLinesInput === preset ? 'bg-emerald-500/30 border-emerald-500/60 text-emerald-200 font-bold shadow-[0_0_8px_rgba(16,185,129,0.3)]' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
                    >
                      {preset}
                    </button>
                  {/each}
                </div>
              </div>

              <!-- Action Sealing Buttons -->
              <div class="flex flex-wrap gap-2 pt-1">
                <button
                  type="button"
                  disabled={contractSaving}
                  onclick={() => saveContractBudget('file')}
                  class="flex-1 py-1.5 px-3 rounded-lg bg-gradient-to-r from-orange-500/25 to-amber-500/25 hover:from-orange-500/35 hover:to-amber-500/35 border border-orange-500/50 text-orange-200 font-mono text-[10.5px] font-bold flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50 transition-all shadow-sm"
                  title="Appliquer cette limite uniquement à ce fichier et sceller le hash BLAKE3"
                >
                  <FileCode2 class="w-3.5 h-3.5 text-orange-400" />
                  <span>📄 Sceller Fichier</span>
                </button>

                <button
                  type="button"
                  disabled={contractSaving}
                  onclick={() => saveContractBudget('folder')}
                  class="flex-1 py-1.5 px-3 rounded-lg bg-gradient-to-r from-emerald-500/25 to-teal-500/25 hover:from-emerald-500/35 hover:to-teal-500/35 border border-emerald-500/50 text-emerald-200 font-mono text-[10.5px] font-bold flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50 transition-all shadow-sm"
                  title="Appliquer cette limite par défaut à tout le dossier et sceller le hash BLAKE3"
                >
                  <FolderOpen class="w-3.5 h-3.5 text-emerald-400" />
                  <span>📁 Sceller Dossier</span>
                </button>

                {#if activeTargetNode?.metadata?.file_max_lines_override}
                  <button
                    type="button"
                    disabled={contractSaving}
                    onclick={() => saveContractBudget('clear_file')}
                    class="py-1.5 px-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-slate-300 font-mono text-[10.5px] flex items-center gap-1 cursor-pointer disabled:opacity-50 transition-colors"
                    title="Supprimer l'override spécifique du fichier pour hériter du dossier"
                  >
                    <RefreshCw class="w-3 h-3 text-slate-400" />
                    <span>↺ Hériter</span>
                  </button>
                {/if}
              </div>

              {#if contractSaveStatus}
                <div class="text-[10px] font-mono text-center font-bold text-emerald-300 pt-0.5 animate-pulse">
                  {contractSaveStatus}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      </section>

      <!-- ======================================================== -->
      <!-- 2. EXTRAIT DE CODE SOURCE ("+ extrait de code")         -->
      <!-- ======================================================== -->
      <section class="rounded-xl border border-sky-500/30 bg-[#060913] overflow-hidden shadow-lg transition-all">
        <!-- Section Header -->
        <div class="px-3.5 py-2 bg-gradient-to-r from-sky-950/30 via-slate-900/40 to-[#060913] border-b border-white/10 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-6 h-6 rounded-md bg-sky-500/20 text-sky-400 border border-sky-500/40 flex items-center justify-center shrink-0">
              <FileCode2 class="w-3.5 h-3.5" />
            </div>
            <div class="min-w-0">
              <div class="text-[11px] font-extrabold text-sky-200 tracking-wide uppercase flex items-center gap-1.5">
                <span>EXTRAIT DE CODE SOURCE</span>
                {#if symbol}
                  <span class="px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 text-[9px] font-mono lowercase">
                    {symbol.name}:{symbol.line_number || 1}
                  </span>
                {/if}
              </div>
              <div class="text-[9.5px] font-mono text-slate-400 truncate">
                {loadedCodePath || symbol?.file_path || 'Aucun fichier source actif'}
              </div>
            </div>
          </div>

          <div class="flex items-center gap-1.5 shrink-0">
            {#if displayedCodeLines.length > 0}
              <button
                type="button"
                onclick={() => (fullCodeView = !fullCodeView)}
                class="px-2 py-0.5 rounded text-[9.5px] font-mono border cursor-pointer {fullCodeView ? 'bg-sky-500/25 border-sky-500/50 text-sky-200 font-bold' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
                title="Basculer entre extrait ciblé et fichier complet"
              >
                {fullCodeView ? 'Vue Ciblée' : 'Fichier Complet'}
              </button>
              <button
                type="button"
                onclick={copyCodeSnippet}
                class="flex items-center gap-1 px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[9.5px] font-mono text-slate-300 cursor-pointer"
                title="Copier cet extrait de code"
              >
                {#if copiedSnippet}<Check class="w-2.5 h-2.5 text-emerald-400" /><span>Copié</span>{:else}<Copy class="w-2.5 h-2.5" /><span>Copier</span>{/if}
              </button>
            {/if}
            <button
              type="button"
              onclick={() => (openCodeSection = !openCodeSection)}
              class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
            >
              {#if openCodeSection}<ChevronUp class="w-3.5 h-3.5" />{:else}<ChevronDown class="w-3.5 h-3.5" />{/if}
            </button>
          </div>
        </div>

        {#if openCodeSection}
          {#if loadingCode}
            <div class="p-6 text-center text-slate-400 text-xs font-mono flex items-center justify-center gap-2">
              <RefreshCw class="w-4 h-4 text-sky-400 animate-spin" />
              <span>Chargement du code source...</span>
            </div>
          {:else if displayedCodeLines.length > 0}
            <div class="max-h-72 overflow-x-auto overflow-y-auto p-2.5 font-mono text-[10.5px] bg-[#04060d] leading-snug">
              {#each displayedCodeLines as line}
                <div class="flex items-baseline hover:bg-white/[0.03] px-1 rounded transition-colors {line.isTarget ? 'bg-sky-500/20 border-l-2 border-sky-400 font-semibold shadow-sm' : ''}">
                  <span class="w-8 shrink-0 select-none text-right pr-3 text-[9px] {line.isTarget ? 'text-sky-300 font-bold' : 'text-slate-600'}">
                    {line.lineNum}
                  </span>
                  <span class="whitespace-pre flex-1">
                    {#each tokenizeCodeLine(line.text) as tok}
                      <span class={tok.cls}>{tok.text}</span>
                    {/each}
                  </span>
                </div>
              {/each}
            </div>
          {:else}
            <div class="p-4 text-center text-slate-500 text-xs font-mono">
              Sélectionnez un symbole ou un fichier source dans le graphe pour afficher son extrait de code.
            </div>
          {/if}
        {/if}
      </section>

      <!-- ======================================================== -->
      <!-- 3. SPÉCIFICATIONS, DOCUMENTATION & CONTRATS EARS        -->
      <!-- ======================================================== -->
      <section class="rounded-xl border border-white/10 bg-[#070a14] overflow-hidden shadow-lg transition-all">
        <!-- Section Header -->
        <div class="px-3.5 py-2.5 bg-gradient-to-r from-emerald-950/25 via-slate-900/40 to-[#070a14] border-b border-white/10 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-6 h-6 rounded-md bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center shrink-0">
              <BookOpen class="w-3.5 h-3.5" />
            </div>
            <div class="min-w-0">
              <div class="text-[11px] font-extrabold text-emerald-200 tracking-wide uppercase flex items-center gap-1.5">
                <span>DOCS, README & CONTRATS EARS</span>
                {#if loadedDocPath}
                  <span class="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[9px] lowercase">
                    {loadedDocPath.split('/').pop()}
                  </span>
                {/if}
              </div>
              <div class="text-[9.5px] font-mono text-slate-400 truncate">
                {loadedDocPath || 'README.md'}
              </div>
            </div>
          </div>

          <div class="flex items-center gap-2 shrink-0">
            <span class="text-[9.5px] font-mono text-slate-400 hidden sm:inline">
              📖 {readingMetrics.words} mots · ⏱ ~{readingMetrics.minutes} min
            </span>
            <button
              type="button"
              onclick={() => (openDocSection = !openDocSection)}
              class="p-1 rounded text-slate-400 hover:text-white cursor-pointer"
            >
              {#if openDocSection}<ChevronUp class="w-3.5 h-3.5" />{:else}<ChevronDown class="w-3.5 h-3.5" />{/if}
            </button>
          </div>
        </div>

        {#if openDocSection}
          <!-- Search & Metrics Strip -->
          <div class="px-3 py-1.5 bg-black/40 border-b border-white/10 flex items-center gap-2 text-[10px]">
            <div class="relative flex-1">
              <Search class="w-3 h-3 text-slate-500 absolute left-2 top-1.5" />
              <input
                type="text"
                bind:value={contentSearch}
                placeholder="Rechercher dans cette documentation..."
                class="w-full pl-6 pr-2 py-1 rounded bg-white/[0.04] border border-white/10 text-[10px] text-slate-200 focus:outline-none focus:border-emerald-400"
              />
            </div>
            <div class="flex items-center gap-2 font-mono text-[9.5px] text-slate-400 shrink-0">
              <span>📑 {readingMetrics.headings} sections</span>
              <span>💻 {readingMetrics.codeBlocks} blocs</span>
            </div>
          </div>

          <!-- Highlighted EARS AST Comments if available for active symbol -->
          {#if activeAstComments}
            <div class="m-3 p-3 rounded-xl bg-gradient-to-r from-emerald-950/30 to-sky-950/30 border border-emerald-500/30 space-y-1.5 shadow-sm">
              <div class="text-[10.5px] font-extrabold text-emerald-300 font-mono uppercase flex items-center gap-1.5">
                <Sparkles class="w-3.5 h-3.5 text-emerald-400" />
                <span>Spécification AST & Contrat EARS ({symbol?.name})</span>
              </div>
              <pre class="text-[10.5px] font-mono text-slate-200 whitespace-pre-wrap leading-relaxed bg-black/40 p-2 rounded-lg border border-white/5">{activeAstComments}</pre>
            </div>
          {/if}

          <!-- Live Markdown Editor or Rendered Document View -->
          {#if editMode}
            <div class="p-3 space-y-2">
              <textarea
                bind:value={draftDocContent}
                oninput={triggerDocAutoSave}
                class="w-full h-80 p-3 rounded-xl bg-[#04060d] border border-amber-500/40 font-mono text-[11px] text-slate-100 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none leading-relaxed shadow-inner"
              ></textarea>
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-3 text-[10px] font-mono text-slate-400">
                  <span>{draftDocContent.split('\n').length} lignes</span>
                  <label class="flex items-center gap-1 cursor-pointer text-emerald-300">
                    <input type="checkbox" bind:checked={autoSaveEnabled} class="accent-emerald-400" />
                    Auto-Save (1.5s)
                  </label>
                </div>
                <button
                  type="button"
                  onclick={() => saveCurrentDoc(false)}
                  class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-bold text-slate-950 cursor-pointer shadow-md transition-all"
                >
                  <Save class="w-3.5 h-3.5" /> Enregistrer sur Disque
                </button>
              </div>
            </div>
          {:else}
            <!-- Rendered Markdown Blocks -->
            <div class="p-4 space-y-2.5 text-xs text-slate-200 leading-relaxed">
              {#each filteredBlocks as block, bIdx}
                {#if block.type === 'h1'}
                  <h1 id={block.anchor} class="text-sm font-extrabold text-white border-b border-white/10 pb-1.5 pt-2">{block.text}</h1>
                {:else if block.type === 'h2'}
                  <h2 id={block.anchor} class="text-xs font-bold text-emerald-300 uppercase tracking-wider pt-2.5">{block.text}</h2>
                {:else if block.type === 'h3'}
                  <h3 id={block.anchor} class="text-xs font-semibold text-sky-300 pt-1.5">{block.text}</h3>
                {:else if block.type === 'quote'}
                  <blockquote class="border-l-2 border-amber-400/60 pl-3 text-[11px] text-amber-200/90 italic bg-amber-500/5 py-1 rounded-r">{block.text}</blockquote>
                {:else if block.type === 'list'}
                  <div class="flex gap-2 pl-2 text-[11px] text-slate-300">
                    <span class="text-emerald-400 font-bold">•</span>
                    <span>{block.text}</span>
                  </div>
                {:else if block.type === 'table'}
                  <div class="overflow-x-auto rounded-lg border border-white/10 my-2 shadow-sm">
                    <table class="w-full text-[10.5px] text-left border-collapse">
                      <thead class="bg-white/[0.06] text-sky-300 font-mono">
                        <tr>
                          {#each block.headers as h}
                            <th class="px-2.5 py-1.5 border-b border-white/10 font-bold">{h}</th>
                          {/each}
                        </tr>
                      </thead>
                      <tbody>
                        {#each block.rows as row}
                          <tr class="border-b border-white/5 hover:bg-white/[0.03]">
                            {#each row as cell}
                              <td class="px-2.5 py-1 text-slate-300 font-mono">{cell}</td>
                            {/each}
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {:else if block.type === 'image'}
                  <div class="p-2 rounded-lg bg-black/40 border border-white/10 my-1">
                    <img src={block.src} alt={block.alt} class="max-w-full rounded shadow" />
                  </div>
                {:else if block.type === 'code'}
                  {#if block.lang?.toLowerCase() === 'mermaid' && !mermaidRawMap[bIdx]}
                    {@const mData = parseMermaidEdges(block.text)}
                    <div class="rounded-xl border border-indigo-500/35 bg-[#070b16] p-3 space-y-2 my-2 shadow-md">
                      <div class="flex items-center justify-between text-[10px] font-mono text-indigo-300">
                        <span>Flux Mermaid ({mData.nodes.length} nœuds · {mData.edges.length} arêtes)</span>
                        <button
                          type="button"
                          onclick={() => (mermaidRawMap = { ...mermaidRawMap, [bIdx]: true })}
                          class="px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer text-[9.5px]"
                        >
                          Code brut
                        </button>
                      </div>
                      {#if mData.nodes.length > 0}
                        <svg viewBox="0 0 420 {Math.max(120, mData.nodes.length * 34 + 16)}" class="w-full font-mono text-[9px]">
                          {#each mData.nodes as nodeName, ni}
                            {@const y = 14 + ni * 34}
                            <rect x="16" y={y} width="130" height="24" rx="5" fill="#0f172a" stroke="#6366f1" stroke-width="1.2" />
                            <text x="81" y={y + 15} fill="#e2e8f0" text-anchor="middle">{nodeName.slice(0, 18)}</text>
                          {/each}
                          {#each mData.edges as edge, ei}
                            {@const fromI = mData.nodes.indexOf(edge.from)}
                            {@const toI = mData.nodes.indexOf(edge.to)}
                            {#if fromI >= 0 && toI >= 0}
                              {@const y1 = 26 + fromI * 34}
                              {@const y2 = 26 + toI * 34}
                              <path d="M 146 {y1} C {210 + (ei % 4) * 26} {y1}, {210 + (ei % 4) * 26} {y2}, 146 {y2}" fill="none" stroke="#38bdf8" stroke-width="1.3" opacity="0.8" />
                              {#if edge.label}
                                <text x={220 + (ei % 4) * 22} y={(y1 + y2) / 2} fill="#7dd3fc" font-size="8">{edge.label.slice(0, 20)}</text>
                              {/if}
                            {/if}
                          {/each}
                        </svg>
                      {:else}
                        <pre class="text-[10px] font-mono text-sky-100 whitespace-pre overflow-x-auto">{block.text}</pre>
                      {/if}
                    </div>
                  {:else}
                    {@const codeLines = block.text.split('\n')}
                    <div class="rounded-xl bg-[#04060e] border border-white/10 overflow-hidden my-2 shadow-inner">
                      <div class="flex items-center justify-between px-2.5 py-1 bg-white/[0.04] border-b border-white/5 text-[9.5px] font-mono text-slate-400">
                        <span class="px-1.5 py-0.2 rounded bg-sky-500/15 text-sky-300 uppercase font-bold">{block.lang || 'code'}</span>
                        <div class="flex items-center gap-2">
                          <span>{codeLines.length} L</span>
                          {#if block.lang?.toLowerCase() === 'mermaid'}
                            <button
                              type="button"
                              onclick={() => (mermaidRawMap = { ...mermaidRawMap, [bIdx]: false })}
                              class="text-indigo-300 hover:underline cursor-pointer"
                            >
                              Vue Visuelle
                            </button>
                          {/if}
                        </div>
                      </div>
                      <div class="p-2.5 font-mono text-[10.5px] overflow-x-auto leading-snug">
                        {#each codeLines as cLine, li}
                          <div class="flex items-baseline hover:bg-white/[0.02] px-1 rounded">
                            <span class="w-7 shrink-0 select-none text-right pr-2.5 text-[9px] text-slate-600">{li + 1}</span>
                            <span class="whitespace-pre">
                              {#each tokenizeCodeLine(cLine) as tok}
                                <span class={tok.cls}>{tok.text}</span>
                              {/each}
                            </span>
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}
                {:else}
                  <p class="text-[11.5px] text-slate-300">{block.text}</p>
                {/if}
              {/each}
            </div>
          {/if}
        {/if}
      </section>

      <!-- ======================================================== -->
      <!-- 4. LIAISONS ARCHITECTURALES (ENTRANTS & SORTANTS)       -->
      <!-- ======================================================== -->
      {#if docRelations.incoming.length > 0 || docRelations.outgoing.length > 0}
        <section class="rounded-xl border border-white/10 bg-[#060913] p-3.5 space-y-2.5 shadow-md">
          <div class="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-emerald-300 font-bold">
            <span class="flex items-center gap-1.5">
              <Layers class="w-3.5 h-3.5 text-emerald-400" />
              <span>Liaisons Architecturales ({docRelations.scopeLabel})</span>
            </span>
            <span class="text-slate-500 font-normal">Cliquer pour téléporter</span>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <!-- Incoming Callers -->
            <div class="p-2.5 rounded-lg bg-sky-950/25 border border-sky-500/25 space-y-1.5">
              <div class="text-[10px] font-mono font-bold text-sky-300 flex items-center gap-1">
                <ArrowDownLeft class="w-3 h-3 text-sky-400" />
                <span>Entrants / Appelants ({docRelations.incoming.length})</span>
              </div>
              {#if docRelations.incoming.length === 0}
                <div class="text-[9.5px] font-mono text-slate-500">Aucun appelant direct</div>
              {:else}
                <div class="space-y-1 max-h-32 overflow-y-auto pr-0.5">
                  {#each docRelations.incoming as item}
                    <button
                      type="button"
                      onclick={() => jumpToRelationNode(item.id)}
                      class="w-full text-left px-2 py-1 rounded bg-white/[0.03] hover:bg-sky-500/20 border border-white/5 hover:border-sky-400/40 flex items-center justify-between gap-1.5 cursor-pointer transition-colors"
                    >
                      <span class="text-[10px] font-mono text-slate-200 truncate">{item.name}</span>
                      <span class="text-[8.5px] font-mono px-1 py-0.2 rounded bg-sky-500/20 text-sky-300 shrink-0">{item.relation}</span>
                    </button>
                  {/each}
                </div>
              {/if}
            </div>

            <!-- Outgoing Calls -->
            <div class="p-2.5 rounded-lg bg-amber-950/25 border border-amber-500/25 space-y-1.5">
              <div class="text-[10px] font-mono font-bold text-amber-300 flex items-center gap-1">
                <ArrowUpRight class="w-3 h-3 text-amber-400" />
                <span>Sortants / Dépendances ({docRelations.outgoing.length})</span>
              </div>
              {#if docRelations.outgoing.length === 0}
                <div class="text-[9.5px] font-mono text-slate-500">Aucune dépendance directe</div>
              {:else}
                <div class="space-y-1 max-h-32 overflow-y-auto pr-0.5">
                  {#each docRelations.outgoing as item}
                    <button
                      type="button"
                      onclick={() => jumpToRelationNode(item.id)}
                      class="w-full text-left px-2 py-1 rounded bg-white/[0.03] hover:bg-amber-500/20 border border-white/5 hover:border-amber-400/40 flex items-center justify-between gap-1.5 cursor-pointer transition-colors"
                    >
                      <span class="text-[10px] font-mono text-slate-200 truncate">{item.name}</span>
                      <span class="text-[8.5px] font-mono px-1 py-0.2 rounded bg-amber-500/20 text-amber-300 shrink-0">{item.relation}</span>
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        </section>
      {/if}

    </div>
  </aside>
{/if}
