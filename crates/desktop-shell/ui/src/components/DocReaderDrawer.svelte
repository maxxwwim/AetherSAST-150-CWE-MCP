<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
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
    Pencil,
    Save,
    ShieldCheck
  } from '@lucide/svelte';

  let loadedContent = $state('');
  let loadedPath = $state('');
  let loadError = $state('');
  let loading = $state(false);
  let systemPromptText = $state('');
  let copied = $state(false);
  let showToc = $state(false);
  let wideMode = $state(false);
  let docFilter = $state('');
  let contentSearch = $state('');
  let editMode = $state(false);
  let draftContent = $state('');
  let saveStatus = $state('');
  let mermaidRawMap = $state<Record<number, boolean>>({});
  let copiedBlockIdx = $state<number | null>(null);

  // Collect unique Markdown documentation nodes / files across the whole repo
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

  // Best Markdown doc node for the currently selected folder or active symbol's folder (with parent hierarchy fallback)
  const folderDocNode = $derived.by(() => {
    const startFolder = cockpitState.selectedFolder || cockpitState.activeSymbol?.folder;
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

  async function loadPathContent(path: string) {
    if (!path) return;
    loading = true;
    loadError = '';
    try {
      const res = await api.getFileContent(path);
      if (res?.status === 'ok' && typeof res.content === 'string') {
        loadedContent = res.content;
        loadedPath = res.path || path;
      } else {
        loadedContent = '';
        loadError = res?.message || `Impossible de charger ${path}`;
      }
    } catch (e: any) {
      loadedContent = '';
      loadError = String(e?.message || e || 'Erreur réseau');
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (!cockpitState.isDocPanelOpen) return;
    const mode = cockpitState.docMode;
    const sym = cockpitState.activeSymbol;
    const folder = cockpitState.selectedFolder;

    if (mode === 'library') {
      const targetPath = cockpitState.docSelectedPath || folderDocNode?.path || docLibraryFiles[0]?.path || 'README.md';
      if (targetPath && loadedPath !== targetPath) {
        loadPathContent(targetPath);
      }
    } else if (mode === 'symbol' && sym?.file_path) {
      loadPathContent(sym.file_path);
    } else if (mode === 'folder') {
      const targetPath = folderDocNode?.path || (folder && folder !== 'root' ? `${folder}/README.md` : 'README.md');
      loadPathContent(targetPath);
    } else if (mode === 'system') {
      if (cockpitState.graph.system_prompt) {
        systemPromptText = cockpitState.graph.system_prompt;
      } else {
        api
          .getSystemPrompt()
          .then((res) => {
            systemPromptText = res?.system_prompt || '';
          })
          .catch(() => {});
      }
    }
  });

  function extractAstComments(content: string, lineNumber: number): string {
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

  function extractCodeSnippet(content: string, lineNumber: number): string {
    if (!content) return '';
    const lines = content.split('\n');
    if (!lineNumber || lines.length <= 160) return content.slice(0, 14000);
    const start = Math.max(0, lineNumber - 18);
    const end = Math.min(lines.length, lineNumber + 85);
    return lines
      .slice(start, end)
      .map((l, i) => `${String(start + i + 1).padStart(4, ' ')} | ${l}`)
      .join('\n');
  }

  const rawMarkdown = $derived.by(() => {
    const mode = cockpitState.docMode;
    const sym = cockpitState.activeSymbol;

    if (mode === 'library') {
      if (loadedContent) return loadedContent;
      if (loadError) return `# Documentation\n\n> ${loadError}`;
      return `# Bibliothèque Markdown\n\nSélectionnez un fichier Markdown ci-dessus pour l'afficher.`;
    }

    if (mode === 'symbol' && sym) {
      const body = loadedContent || sym.metadata?.raw_content || sym.docstring || '';
      const header = `# ${sym.name} (${sym.stereotype || sym.kind})\n\n- **Fichier :** \`${sym.file_path}:${sym.line_number || 1}\`\n- **Couche :** \`${sym.layer}\` | **LOC :** ${sym.loc || 1} | **Complexité :** ${sym.cyclomatic_complexity || 1}\n\n`;
      if (sym.file_path.toLowerCase().endsWith('.md')) {
        return body || header;
      }
      const comments = sym.docstring || extractAstComments(body, sym.line_number);
      const docSec = comments ? `## Commentaires AST & Contrat\n${comments}\n\n` : '';
      const snippet = extractCodeSnippet(body, sym.line_number);
      return snippet ? `${header}${docSec}## Code Source\n\`\`\`\n${snippet}\n\`\`\`` : `${header}${docSec}${loadError || 'Aucun contenu brut disponible.'}`;
    }

    if (mode === 'folder') {
      if (loadedContent) return loadedContent;
      const folder = cockpitState.selectedFolder || sym?.folder || 'root';
      const inFolder = cockpitState.graph.nodes.filter((n) => (n.folder || n.cluster_id || 'root') === folder);
      return `# 📁 Module \`${folder}\`\n\n${loadError ? `> ${loadError}\n\n` : ''}Aucun \`README.md\` direct trouvé pour ce dossier.\n\n## Entités détectées (${inFolder.length})\n${inFolder
        .slice(0, 35)
        .map((n) => `- \`${n.name}\` (${n.stereotype || n.kind}) — \`${n.file_path}\``)
        .join('\n')}`;
    }

    return (
      systemPromptText ||
      cockpitState.graph.system_prompt ||
      `# ${cockpitState.graph.project_name || 'AetherScope'}\n\nSélectionnez une bulle ou un document à gauche.`
    );
  });

  type DocBlock =
    | { type: 'h1' | 'h2' | 'h3'; text: string; anchor: string }
    | { type: 'code'; text: string; lang?: string }
    | { type: 'table'; headers: string[]; rows: string[][] }
    | { type: 'image'; alt: string; src: string }
    | { type: 'list' | 'quote' | 'p'; text: string };

  function resolveImageSrc(rawSrc: string): string {
    const clean = rawSrc.trim().replace(/^["']|["']$/g, '').replace(/\\/g, '/');
    if (/^(https?:|data:|blob:)/i.test(clean)) return clean;
    const baseDir = loadedPath.includes('/') ? loadedPath.slice(0, loadedPath.lastIndexOf('/')) : '';
    const joined = clean.startsWith('/') ? clean.slice(1) : baseDir ? `${baseDir}/${clean}` : clean;
    const stack: string[] = [];
    for (const part of joined.split('/')) {
      if (!part || part === '.') continue;
      if (part === '..') stack.pop();
      else stack.push(part);
    }
    return api.getRawFileUrl(stack.join('/'));
  }

  const parsedBlocks = $derived.by(() => {
    const lines = rawMarkdown.split('\n');
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
        blocks.push({ type: 'h3', text: cleanLine.slice(4), anchor: `toc-${i}` });
      } else if (cleanLine.startsWith('## ')) {
        blocks.push({ type: 'h2', text: cleanLine.slice(3), anchor: `toc-${i}` });
      } else if (cleanLine.startsWith('# ')) {
        blocks.push({ type: 'h1', text: cleanLine.slice(2), anchor: `toc-${i}` });
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
    const trimmed = rawMarkdown.trim();
    const words = trimmed ? trimmed.split(/\s+/).length : 0;
    const minutes = Math.max(1, Math.ceil(words / 200));
    const codeBlocks = parsedBlocks.filter((b) => b.type === 'code').length;
    return {
      words,
      minutes,
      headings: tocHeadings.length,
      codeBlocks,
    };
  });

  // Syntax highlighter tokenizer (multi-language GitHub Dark style, safe spans)
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

  // Incoming & Outgoing symbol/folder relations for bottom cards
  const docRelations = $derived.by(() => {
    const nodes = cockpitState.graph.nodes || [];
    const edges = cockpitState.graph.edges || [];
    if (nodes.length === 0) return { incoming: [], outgoing: [], scopeLabel: '' };

    const nodeById = new Map(nodes.map((n) => [n.id, n]));
    const targetIds = new Set<string>();
    let scopeLabel = '';

    if (cockpitState.docMode === 'symbol' && cockpitState.activeSymbol) {
      targetIds.add(cockpitState.activeSymbol.id);
      scopeLabel = cockpitState.activeSymbol.name;
    } else {
      const refPath = (loadedPath || cockpitState.selectedFolder || '').replace(/\\/g, '/');
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
      if (cockpitState.docMode === 'symbol') {
        loadPathContent(target.file_path);
      }
    }
  }

  let autoSaveEnabled = $state(true);
  let autoSaveTimer: ReturnType<typeof setTimeout> | null = null;

  function triggerDocAutoSave() {
    if (!autoSaveEnabled || !editMode) return;
    if (autoSaveTimer) clearTimeout(autoSaveTimer);
    saveStatus = '⏳ Auto-save (1.5s)...';
    autoSaveTimer = setTimeout(() => {
      saveCurrentDoc(true);
    }, 1500);
  }

  function selectLibraryDoc(path: string) {
    cockpitState.docSelectedPath = path;
    cockpitState.docMode = 'library';
    loadPathContent(path);
  }

  function scrollToAnchor(anchor: string) {
    document.getElementById(anchor)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function copyDoc() {
    navigator.clipboard?.writeText(rawMarkdown);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  function enterEditMode() {
    if (!editMode) {
      draftContent = loadedContent || rawMarkdown;
      editMode = true;
      saveStatus = '';
    } else {
      if (autoSaveTimer) clearTimeout(autoSaveTimer);
      editMode = false;
    }
  }

  async function saveCurrentDoc(isAuto = false) {
    const p = loadedPath || cockpitState.activeSymbol?.file_path || 'README.md';
    const parts = p.split('/');
    const fileName = parts.pop() || 'README.md';
    const folder = parts.join('/') || '.';
    saveStatus = isAuto ? 'Auto-sauvegarde...' : 'Sauvegarde...';
    try {
      const res = await api.saveDoc({
        project_path: cockpitState.graph.project_path || '.',
        folder,
        file_name: fileName,
        content: draftContent,
      });
      loadedContent = draftContent;
      if (res.graph) {
        cockpitState.setGraph(res.graph, true);
      }
      saveStatus = res.blake3_hash
        ? `${isAuto ? '✓ Auto-save' : 'Enregistré'} (${res.blake3_hash.slice(0, 8)})`
        : isAuto
          ? '✓ Auto-sauvegardé'
          : 'Enregistré';
      setTimeout(() => (saveStatus = ''), 3000);
    } catch (e: any) {
      saveStatus = e?.message || 'Erreur sauvegarde';
    }
  }

  async function signCurrentContract() {
    const p = loadedPath || cockpitState.selectedFolder || '';
    const folder = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : p || undefined;
    saveStatus = 'Signature BLAKE3...';
    try {
      const res = await api.signContracts({
        project_path: cockpitState.graph.project_path || '.',
        folder,
      });
      if (res.graph) cockpitState.setGraph(res.graph, true);
      saveStatus = `Signé (${res.signed_count})`;
      setTimeout(() => (saveStatus = ''), 3000);
    } catch (e: any) {
      saveStatus = e?.message || 'Erreur signature';
    }
  }

  function copyCodeSnippet(idx: number, text: string) {
    navigator.clipboard?.writeText(text);
    copiedBlockIdx = idx;
    setTimeout(() => {
      if (copiedBlockIdx === idx) copiedBlockIdx = null;
    }, 1400);
  }

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
        const from = m[1];
        const label = (m[2] || '').trim();
        const to = m[3];
        nodesSet.add(from);
        nodesSet.add(to);
        edges.push({ from, to, label });
      }
    }
    return { nodes: Array.from(nodesSet).slice(0, 12), edges: edges.slice(0, 16) };
  }

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
</script>

<!-- Left Edge Docked Pill when panel is collapsed (Restores Legacy #btn-expand-doc-dock) -->
{#if !cockpitState.isDocPanelOpen}
  <button
    type="button"
    onclick={() => cockpitState.openDoc('library')}
    class="fixed left-3 top-[80px] z-30 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0b0f19]/92 hover:bg-emerald-500/20 backdrop-blur-md border border-emerald-500/35 text-[11px] font-semibold text-emerald-200 shadow-xl cursor-pointer transition-all"
    title="Ouvrir le panneau Docs, README & Contrats EARS à gauche"
  >
    <BookOpen class="w-3.5 h-3.5 text-emerald-400" />
    <span>Docs & Contrats</span>
    <span class="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px]">
      {docLibraryFiles.length}
    </span>
    <ChevronRight class="w-3 h-3" />
  </button>
{/if}

{#if cockpitState.isDocPanelOpen}
  <aside
    class="fixed left-3 top-[80px] bottom-10 {wideMode ? 'w-[680px]' : 'w-[470px]'} max-w-[94vw] bg-[#0b0e17]/96 backdrop-blur-xl border border-emerald-500/35 rounded-xl shadow-[0_20px_60px_rgba(0,0,0,0.85)] z-40 flex flex-col overflow-hidden transition-all"
  >
    <!-- Header -->
    <div class="px-3.5 py-2.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between gap-2">
      <div class="flex items-center gap-2 min-w-0">
        <BookOpen class="w-4 h-4 text-emerald-400 shrink-0" />
        <div class="min-w-0">
          <div class="text-xs font-bold text-white truncate">Lecteur Docs, EARS & Source</div>
          {#if loadedPath && cockpitState.docMode !== 'system'}
            <div class="text-[10px] font-mono text-emerald-300/85 truncate">{loadedPath}</div>
          {/if}
        </div>
      </div>
      <div class="flex items-center gap-1 shrink-0">
        {#if loading}
          <RefreshCw class="w-3.5 h-3.5 text-sky-400 animate-spin mr-1" />
        {/if}
        <button
          type="button"
          onclick={() => (showToc = !showToc)}
          title="Afficher / Masquer le Sommaire"
          class="flex items-center gap-1 px-2 py-1 rounded text-[10px] border cursor-pointer {showToc ? 'bg-sky-500/20 border-sky-500/40 text-sky-300' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
        >
          <ListTree class="w-3 h-3" />
          <span class="hidden sm:inline">Sommaire ({tocHeadings.length})</span>
        </button>
        <button
          type="button"
          onclick={() => (wideMode = !wideMode)}
          title="Agrandir / Réduire le panneau"
          class="p-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 cursor-pointer"
        >
          {#if wideMode}<Minimize2 class="w-3 h-3" />{:else}<Maximize2 class="w-3 h-3" />{/if}
        </button>
        <button
          type="button"
          onclick={enterEditMode}
          title="Éditer le document Markdown sur disque"
          class="flex items-center gap-1 px-2 py-1 rounded text-[10px] border cursor-pointer {editMode ? 'bg-amber-500/20 border-amber-500/40 text-amber-300' : 'bg-white/5 hover:bg-white/10 border-white/10 text-slate-300'}"
        >
          <Pencil class="w-3 h-3" />
          <span class="hidden sm:inline">{editMode ? 'Aperçu' : 'Éditer'}</span>
        </button>
        {#if loadedPath}
          <button
            type="button"
            onclick={signCurrentContract}
            title="Signer ce contrat README avec BLAKE3 dans aether.lock.toml"
            class="flex items-center gap-1 px-2 py-1 rounded text-[10px] bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-300 cursor-pointer"
          >
            <ShieldCheck class="w-3 h-3" />
            <span class="hidden sm:inline">Signer</span>
          </button>
        {/if}
        <button
          type="button"
          onclick={copyDoc}
          class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] text-slate-300 cursor-pointer"
        >
          {#if copied}<Check class="w-3 h-3 text-emerald-400" /><span>Copié</span>{:else}<Copy class="w-3 h-3" /><span>Copier</span>{/if}
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.isDocPanelOpen = false)}
          aria-label="Fermer le panneau documentation"
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>
    </div>

    <!-- 4 Navigation Tabs -->
    <div class="px-2.5 py-2 border-b border-white/10 grid grid-cols-4 gap-1 bg-black/25 text-[10.5px]">
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'library')}
        class="py-1.5 px-1.5 rounded font-semibold cursor-pointer flex items-center justify-center gap-1 {cockpitState.docMode === 'library' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-white'}"
      >
        <Library class="w-3 h-3" /> Docs ({docLibraryFiles.length})
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'folder')}
        class="py-1.5 px-1.5 rounded font-semibold cursor-pointer flex items-center justify-center gap-1 {cockpitState.docMode === 'folder' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-slate-400 hover:text-white'}"
      >
        <FolderOpen class="w-3 h-3" /> README
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'symbol')}
        class="py-1.5 px-1.5 rounded font-semibold cursor-pointer flex items-center justify-center gap-1 {cockpitState.docMode === 'symbol' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'text-slate-400 hover:text-white'}"
      >
        <FileText class="w-3 h-3" /> Symbole
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'system')}
        class="py-1.5 px-1.5 rounded font-semibold cursor-pointer {cockpitState.docMode === 'system' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'text-slate-400 hover:text-white'}"
      >
        📜 Projet
      </button>
    </div>

    <!-- Doc Library File Selector (shown in 'library' mode) -->
    {#if cockpitState.docMode === 'library'}
      <div class="px-3 py-2 border-b border-white/10 bg-[#070a12] space-y-1.5">
        <div class="relative">
          <Search class="w-3 h-3 text-slate-500 absolute left-2 top-2" />
          <input
            type="text"
            bind:value={docFilter}
            placeholder="Filtrer un document Markdown / README..."
            class="w-full pl-6 pr-2 py-1 rounded bg-white/[0.04] border border-white/10 text-[10.5px] text-slate-200 focus:outline-none focus:border-emerald-500/40"
          />
        </div>
        <div class="max-h-32 overflow-y-auto space-y-1 pr-0.5">
          {#each docLibraryFiles as doc}
            <button
              type="button"
              onclick={() => selectLibraryDoc(doc.path)}
              class="w-full flex items-center justify-between gap-2 px-2 py-1 rounded text-[10.5px] font-mono text-left cursor-pointer border transition-colors {loadedPath === doc.path ? 'bg-emerald-500/15 border-emerald-500/45 text-emerald-200' : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.06]'}"
            >
              <span class="truncate">📄 {doc.path}</span>
              <span class="flex items-center gap-1 shrink-0">
                {#if doc.blake3}
                  <Lock class="w-2.5 h-2.5 {doc.lockVerified ? 'text-emerald-400' : 'text-amber-400'}" />
                {/if}
                <span class="text-[9px] text-slate-500">{doc.folder.split('/').pop()}</span>
              </span>
            </button>
          {/each}
        </div>
      </div>
    {/if}

    <!-- In-Doc Search + Reading Metrics + Save Status Strip -->
    {#if cockpitState.docMode !== 'library' || loadedPath}
      <div class="px-3 py-1.5 border-b border-white/10 bg-black/30 flex flex-col gap-1">
        <div class="flex items-center gap-2">
          <div class="relative flex-1">
            <Search class="w-3 h-3 text-slate-500 absolute left-2 top-1.5" />
            <input
              type="text"
              bind:value={contentSearch}
              placeholder="Rechercher dans le document..."
              class="w-full pl-6 pr-2 py-1 rounded bg-white/[0.04] border border-white/10 text-[10px] text-slate-200 focus:outline-none focus:border-sky-400"
            />
          </div>
          {#if saveStatus}
            <span class="text-[10px] font-mono text-emerald-300 shrink-0">{saveStatus}</span>
          {/if}
        </div>
        <div class="flex items-center justify-between text-[9.5px] font-mono text-slate-400">
          <div class="flex items-center gap-2.5">
            <span>📖 {readingMetrics.words} mots</span>
            <span>⏱ ~{readingMetrics.minutes} min</span>
            <span>📑 {readingMetrics.headings} titres</span>
            <span>💻 {readingMetrics.codeBlocks} blocs</span>
          </div>
          {#if docRelations.incoming.length > 0 || docRelations.outgoing.length > 0}
            <span class="text-sky-300/90">
              ⬅ {docRelations.incoming.length} · ➔ {docRelations.outgoing.length} liens
            </span>
          {/if}
        </div>
      </div>
    {/if}

    <!-- Optional Collapsible TOC -->
    {#if showToc && tocHeadings.length > 0}
      <div class="px-3 py-2 border-b border-white/10 bg-sky-950/20 max-h-36 overflow-y-auto space-y-1">
        <div class="text-[10px] font-mono uppercase text-sky-400 mb-1">Sommaire des sections</div>
        {#each tocHeadings as h}
          <button
            type="button"
            onclick={() => scrollToAnchor(h.anchor)}
            class="block w-full text-left text-[11px] hover:text-sky-300 truncate cursor-pointer {h.type === 'h1' ? 'font-bold text-white' : h.type === 'h2' ? 'pl-2 text-emerald-300' : 'pl-4 text-slate-400'}"
          >
            {h.text}
          </button>
        {/each}
      </div>
    {/if}

    <!-- Live Editor or Rendered Content -->
    {#if editMode}
      <div class="flex-1 flex flex-col p-3 gap-2 overflow-hidden">
        <textarea
          bind:value={draftContent}
          oninput={triggerDocAutoSave}
          class="flex-1 w-full p-3 rounded-lg bg-[#05070e] border border-amber-500/35 font-mono text-[11px] text-slate-100 focus:outline-none resize-none leading-relaxed"
        ></textarea>
        <div class="flex items-center justify-between gap-2">
          <div class="flex items-center gap-3 text-[10px] font-mono text-slate-400">
            <span>{draftContent.split('\n').length} lignes</span>
            <label class="flex items-center gap-1 cursor-pointer text-emerald-300">
              <input type="checkbox" bind:checked={autoSaveEnabled} class="accent-emerald-400" />
              Auto-Save (1.5s)
            </label>
          </div>
          <button
            type="button"
            onclick={() => saveCurrentDoc(false)}
            class="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-bold text-slate-950 cursor-pointer"
          >
            <Save class="w-3.5 h-3.5" /> Enregistrer sur Disque
          </button>
        </div>
      </div>
    {:else}
      <div class="flex-1 overflow-auto p-4 space-y-2.5 text-xs text-slate-200 leading-relaxed select-text">
        {#each filteredBlocks as block, bIdx}
          {#if block.type === 'h1'}
            <h1 id={block.anchor} class="text-sm font-bold text-white border-b border-white/10 pb-1.5 pt-1">{block.text}</h1>
          {:else if block.type === 'h2'}
            <h2 id={block.anchor} class="text-xs font-bold text-emerald-300 uppercase tracking-wider pt-2">{block.text}</h2>
          {:else if block.type === 'h3'}
            <h3 id={block.anchor} class="text-xs font-semibold text-sky-300 pt-1">{block.text}</h3>
          {:else if block.type === 'quote'}
            <blockquote class="border-l-2 border-amber-400/60 pl-3 text-[11px] text-amber-200/90 italic">{block.text}</blockquote>
          {:else if block.type === 'list'}
            <div class="flex gap-2 pl-2 text-[11px] text-slate-300">
              <span class="text-emerald-400">•</span>
              <span>{block.text}</span>
            </div>
          {:else if block.type === 'table'}
            <div class="overflow-x-auto rounded-lg border border-white/10 my-2">
              <table class="w-full text-[10.5px] text-left border-collapse">
                <thead class="bg-white/[0.06] text-sky-300 font-mono">
                  <tr>
                    {#each block.headers as h}
                      <th class="px-2 py-1.5 border-b border-white/10">{h}</th>
                    {/each}
                  </tr>
                </thead>
                <tbody>
                  {#each block.rows as row}
                    <tr class="border-b border-white/5 hover:bg-white/[0.03]">
                      {#each row as cell}
                        <td class="px-2 py-1 text-slate-300">{cell}</td>
                      {/each}
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else if block.type === 'image'}
            <div class="p-2 rounded-lg bg-black/30 border border-white/10">
              <img src={block.src} alt={block.alt} class="max-w-full rounded" />
            </div>
          {:else if block.type === 'code'}
            {#if block.lang?.toLowerCase() === 'mermaid' && !mermaidRawMap[bIdx]}
              {@const mData = parseMermaidEdges(block.text)}
              <div class="rounded-lg border border-indigo-500/35 bg-[#070b16] p-2.5 space-y-2">
                <div class="flex items-center justify-between text-[10px] font-mono text-indigo-300">
                  <span>Diagramme Mermaid ({mData.nodes.length} nœuds · {mData.edges.length} flux)</span>
                  <button
                    type="button"
                    onclick={() => (mermaidRawMap = { ...mermaidRawMap, [bIdx]: true })}
                    class="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
                  >
                    Code Source
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
              <div class="rounded-lg bg-[#06080f] border border-white/10 overflow-hidden">
                <div class="flex items-center justify-between px-2.5 py-1 bg-white/[0.04] border-b border-white/5 text-[9.5px] font-mono text-slate-400">
                  <span class="px-1.5 py-0.2 rounded bg-sky-500/15 text-sky-300 uppercase font-bold">{block.lang || 'code'}</span>
                  <div class="flex items-center gap-2">
                    <span class="text-slate-500">{codeLines.length} L</span>
                    {#if block.lang?.toLowerCase() === 'mermaid'}
                      <button
                        type="button"
                        onclick={() => (mermaidRawMap = { ...mermaidRawMap, [bIdx]: false })}
                        class="text-indigo-300 hover:underline cursor-pointer"
                      >
                        Vue SVG
                      </button>
                    {/if}
                    <button
                      type="button"
                      onclick={() => copyCodeSnippet(bIdx, block.text)}
                      class="hover:text-white cursor-pointer"
                    >
                      {copiedBlockIdx === bIdx ? '✓ Copié' : 'Copier'}
                    </button>
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

        <!-- Bottom Incoming & Outgoing Architectural Links Cards -->
        {#if docRelations.incoming.length > 0 || docRelations.outgoing.length > 0}
          <div class="mt-4 pt-3 border-t border-white/10 space-y-2.5">
            <div class="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-emerald-300">
              <span>🔗 Liaisons Architecturales ({docRelations.scopeLabel})</span>
              <span class="text-slate-500">Cliquer pour téléporter</span>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <!-- Incoming Callers / References -->
              <div class="p-2.5 rounded-lg bg-sky-950/20 border border-sky-500/25 space-y-1.5">
                <div class="text-[10px] font-mono font-bold text-sky-300">
                  ⬅ Entrants / Appelants ({docRelations.incoming.length})
                </div>
                {#if docRelations.incoming.length === 0}
                  <div class="text-[10px] font-mono text-slate-500">Aucun appelant externe</div>
                {:else}
                  <div class="space-y-1 max-h-36 overflow-y-auto pr-0.5">
                    {#each docRelations.incoming as item}
                      <button
                        type="button"
                        onclick={() => jumpToRelationNode(item.id)}
                        class="w-full text-left px-2 py-1 rounded bg-white/[0.03] hover:bg-sky-500/20 border border-white/5 hover:border-sky-400/40 flex items-center justify-between gap-1.5 cursor-pointer transition-colors"
                      >
                        <span class="text-[10.5px] font-mono text-slate-200 truncate">{item.name}</span>
                        <span class="text-[8.5px] font-mono px-1 py-0.2 rounded bg-sky-500/20 text-sky-300 shrink-0">{item.relation}</span>
                      </button>
                    {/each}
                  </div>
                {/if}
              </div>

              <!-- Outgoing Calls / Dependencies -->
              <div class="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/25 space-y-1.5">
                <div class="text-[10px] font-mono font-bold text-amber-300">
                  ➔ Sortants / Dépendances ({docRelations.outgoing.length})
                </div>
                {#if docRelations.outgoing.length === 0}
                  <div class="text-[10px] font-mono text-slate-500">Aucune dépendance sortante</div>
                {:else}
                  <div class="space-y-1 max-h-36 overflow-y-auto pr-0.5">
                    {#each docRelations.outgoing as item}
                      <button
                        type="button"
                        onclick={() => jumpToRelationNode(item.id)}
                        class="w-full text-left px-2 py-1 rounded bg-white/[0.03] hover:bg-amber-500/20 border border-white/5 hover:border-amber-400/40 flex items-center justify-between gap-1.5 cursor-pointer transition-colors"
                      >
                        <span class="text-[10.5px] font-mono text-slate-200 truncate">{item.name}</span>
                        <span class="text-[8.5px] font-mono px-1 py-0.2 rounded bg-amber-500/20 text-amber-300 shrink-0">{item.relation}</span>
                      </button>
                    {/each}
                  </div>
                {/if}
              </div>
            </div>
          </div>
        {/if}
      </div>
    {/if}
  </aside>
{/if}
