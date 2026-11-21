<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { cockpitState } from '../../state/graphState.svelte';
  import { api } from '../../lib/api';
  import {
    Save,
    Search,
    X,
    ChevronDown,
    ChevronUp,
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
    Minimize2
  } from '@lucide/svelte';

  interface FileBuffer {
    content: string;
    savedContent: string;
    cursorLine: number;
    cursorCol: number;
  }

  // Multi-tab in-memory buffers preserving uncommitted edits across tab switches
  let buffers = $state<Record<string, FileBuffer>>({});

  let content = $state('');
  let savedContent = $state('');
  let loadedFile = $state<string | null>(null);
  let isLoading = $state(false);
  let isSaving = $state(false);
  let errorMessage = $state<string | null>(null);
  let successNotice = $state<string | null>(null);
  let externalConflictContent = $state<string | null>(null);
  let lastHandledFsVersion = 0;

  // Target line highlight flash (active for ~2.5s on jump)
  let highlightedLine = $state<number | null>(null);
  let highlightTimer: any = null;
  let pendingAutoSave = false;

  // Go-to-line (Ctrl+G) overlay state
  let isGotoLineOpen = $state(false);
  let gotoLineInput = $state('');
  let gotoInputEl = $state<HTMLInputElement | null>(null);

  // Editor View Mode: 'edit' (interactive textarea) or 'preview' (syntax highlighted lines)
  let editorViewMode = $state<'edit' | 'preview'>('edit');

  // Tab Sizing Mode: 'compact' | 'auto' | 'expanded'
  let tabSizeMode = $state<'auto' | 'compact' | 'expanded'>('auto');

  // Search overlay state
  let isSearchOpen = $state(false);
  let searchQuery = $state('');
  let searchInputEl = $state<HTMLInputElement | null>(null);
  let textareaEl = $state<HTMLTextAreaElement | null>(null);
  let gutterEl = $state<HTMLDivElement | null>(null);
  let previewContainerEl = $state<HTMLDivElement | null>(null);

  let cursorLine = $state(1);
  let cursorCol = $state(1);

  // Is buffer dirty (unsaved changes)
  let isDirty = $derived(content !== savedContent);

  // Check if a specific tab buffer is dirty
  function isTabDirty(filePath: string): boolean {
    if (filePath === loadedFile) return isDirty;
    const b = buffers[filePath];
    return Boolean(b && b.content !== b.savedContent);
  }

  // Split lines
  let lines = $derived(content.split('\n'));
  let lineCount = $derived(lines.length);

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

  // Target line for AST symbol jump
  let targetLine = $derived(cockpitState.ideTargetLine);

  // Search match structure
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

  // Clamp current match index when matches change
  $effect(() => {
    if (searchMatches.length === 0) {
      currentMatchIndex = 0;
    } else if (currentMatchIndex >= searchMatches.length) {
      currentMatchIndex = 0;
    }
  });

  // Watch for active file changes in graphState and switch / load tab
  $effect(() => {
    const activeFile = cockpitState.ideActiveFile;
    if (activeFile && activeFile !== loadedFile) {
      loadFile(activeFile);
    } else if (!activeFile && loadedFile) {
      loadedFile = null;
      content = '';
      savedContent = '';
    }
  });

  async function loadFile(activeFile: string) {
    await switchToFile(activeFile);
  }

  // Watch for target line and jump tick changes and jump to it
  $effect(() => {
    const _tick = cockpitState.ideTargetTick;
    const line = cockpitState.ideTargetLine;
    if (line && line > 0) {
      tick().then(() => {
        scrollToLine(line);
      });
    }
  });

  // Keep active buffer content in sync with textarea and save immediately on edit when Save Auto is enabled
  function handleContentInput() {
    if (loadedFile) {
      buffers[loadedFile] = {
        content,
        savedContent,
        cursorLine,
        cursorCol
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

  async function switchToFile(filePath: string) {
    pendingAutoSave = false;
    if (cockpitState.settings.editorAutoSave && loadedFile && isDirty) {
      await saveCurrentFile(true);
    }
    // 1. Stash current buffer if modified or open
    if (loadedFile) {
      buffers[loadedFile] = {
        content,
        savedContent,
        cursorLine,
        cursorCol
      };
    }

    // 2. Check if new file buffer already cached in memory
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

    // 3. Otherwise fetch from backend API
    await loadFileFromDisk(filePath);
  }

  function isPathAffectedByExternalChanges(filePath: string, changedList: string[]): boolean {
    if (!changedList || changedList.length === 0) return true;
    const normTarget = filePath.replace(/\\/g, '/').toLowerCase().trim();
    for (const raw of changedList) {
      const c = raw.replace(/\\/g, '/').toLowerCase().trim();
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
          buffers[filePath] = {
            content: diskContent,
            savedContent: diskContent,
            cursorLine,
            cursorCol
          };
          await tick();
          if (textareaEl) textareaEl.scrollTop = prevScrollTop;
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
    content = externalConflictContent;
    savedContent = externalConflictContent;
    externalConflictContent = null;
    buffers[loadedFile] = {
      content,
      savedContent,
      cursorLine,
      cursorCol
    };
    tick().then(() => {
      if (textareaEl) textareaEl.scrollTop = prevScrollTop;
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

  // React to live external file/folder modifications from SSE watcher
  $effect(() => {
    const fsVer = cockpitState.fsVersion;
    if (fsVer <= 0 || fsVer === lastHandledFsVersion) return;
    lastHandledFsVersion = fsVer;

    const changedList = cockpitState.lastChangedFiles || [];

    // 1. Invalidate non-dirty cached buffers for background tabs that changed on disk
    for (const tabPath of Object.keys(buffers)) {
      if (tabPath !== loadedFile && isPathAffectedByExternalChanges(tabPath, changedList)) {
        if (!isTabDirty(tabPath)) {
          delete buffers[tabPath];
        }
      }
    }

    // 2. Auto-reload or prompt conflict for currently active file if affected
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
        cursorLine = 1;
        cursorCol = 1;
        cockpitState.ideCursorPosition = { line: 1, ch: 1 };

        // Cache in buffers
        buffers[filePath] = {
          content,
          savedContent,
          cursorLine: 1,
          cursorCol: 1
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

    // Trigger glowing visual flash on the function line
    highlightedLine = safeLine;
    if (highlightTimer) clearTimeout(highlightTimer);
    highlightTimer = setTimeout(() => {
      highlightedLine = null;
    }, 2500);

    // 1. Textarea scrolling
    if (textareaEl) {
      const lineHeight = 21; // approx px per line
      const targetScroll = Math.max(0, (safeLine - 5) * lineHeight);
      textareaEl.scrollTo({ top: targetScroll, behavior: 'smooth' });
    }

    // 2. Preview scrolling
    if (previewContainerEl) {
      const el = previewContainerEl.querySelector(`[data-line="${safeLine}"]`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }

  function handleEditorScroll(e: Event) {
    const target = e.target as HTMLElement;
    if (gutterEl && target) {
      gutterEl.scrollTop = target.scrollTop;
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
    content = newLines.join('\n');
    handleContentInput();
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
    if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
      e.preventDefault();
      void saveCurrentFile(false);
    } else if ((e.ctrlKey || e.metaKey) && (e.key === 'g' || e.key === 'G')) {
      e.preventDefault();
      isGotoLineOpen = true;
      gotoLineInput = String(cursorLine);
      tick().then(() => {
        gotoInputEl?.focus();
        gotoInputEl?.select();
      });
    }
  }

  function handleTextareaKeydown(e: KeyboardEvent) {
    // Ctrl+S / Cmd+S: Save file
    if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
      e.preventDefault();
      e.stopPropagation();
      void saveCurrentFile(false);
      return;
    }

    // Ctrl+F / Cmd+F: Search overlay
    if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
      e.preventDefault();
      isSearchOpen = true;
      tick().then(() => searchInputEl?.focus());
      return;
    }

    // Ctrl+G / Cmd+G: Go to line (Notepad / VS Code)
    if ((e.ctrlKey || e.metaKey) && (e.key === 'g' || e.key === 'G')) {
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

    // Ctrl+/ or Ctrl+: : Toggle line comment (VS Code)
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

    // Ctrl+D or Alt+Shift+ArrowDown / Alt+Shift+ArrowUp: Duplicate current line (VS Code / Notepad++)
    if (
      ((e.ctrlKey || e.metaKey) && !e.shiftKey && (e.key === 'd' || e.key === 'D')) ||
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

    // Alt+ArrowUp / Alt+ArrowDown: Move current line up / down (VS Code)
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

    // Ctrl+Shift+K: Delete current line (VS Code)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'k' || e.key === 'K')) {
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

    // Ctrl+L: Select current line (VS Code)
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && (e.key === 'l' || e.key === 'L')) {
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

    // Ctrl+Enter / Ctrl+Shift+Enter: Insert line below / above (VS Code)
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
      const start = textareaEl?.selectionStart ?? 0;
      const end = textareaEl?.selectionEnd ?? 0;
      const spaces = '    ';
      content = content.substring(0, start) + spaces + content.substring(end);
      handleContentInput();
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
      textareaEl?.focus();
    }
  }

  function closeTab(filePath: string) {
    delete buffers[filePath];
    cockpitState.closeIdeTab(filePath);
  }

  // Multi-language keyword sets for tokenization
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
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('# ') || trimmed.startsWith('--')) {
      return [{ text: line, cls: 'text-slate-500 italic' }];
    }

    const keywords = KEYWORD_MAP[lang] || GENERAL_KEYWORDS;
    const tokens: { text: string; cls: string }[] = [];
    const regex = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\/\/.*$|#[^!].*$|\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+(?:\.\d+)?\b|[{}()[\].,:;+\-/*=<>!&|?~]+)/g;
    let lastIndex = 0;
    let m: RegExpExecArray | null;

    while ((m = regex.exec(line)) !== null) {
      if (m.index > lastIndex) {
        tokens.push({ text: line.slice(lastIndex, m.index), cls: 'text-slate-300' });
      }
      const tok = m[0];
      let cls = 'text-slate-200';

      if (tok.startsWith('//') || tok.startsWith('#')) {
        cls = 'text-slate-500 italic';
      } else if (tok.startsWith('"') || tok.startsWith("'") || tok.startsWith('`')) {
        cls = 'text-amber-300 font-mono';
      } else if (/^\d/.test(tok)) {
        cls = 'text-purple-300 font-mono';
      } else if (keywords.has(tok)) {
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

  onMount(() => {
    if (cockpitState.ideActiveFile) {
      if (!cockpitState.ideOpenFiles.includes(cockpitState.ideActiveFile)) {
        cockpitState.ideOpenFiles.push(cockpitState.ideActiveFile);
      }
      switchToFile(cockpitState.ideActiveFile);
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
          {@const tabName = tabPath.split('/').pop() || tabPath}
          <div
            role="tab"
            tabindex="0"
            onclick={() => cockpitState.openFileInIde(tabPath)}
            onkeydown={(e) => { if (e.key === 'Enter') cockpitState.openFileInIde(tabPath); }}
            class="group relative flex items-center gap-1.5 border-r border-white/10 transition-all cursor-pointer min-w-0 shrink-0 select-none
              {tabSizeMode === 'compact' ? 'px-2 text-[11px] max-w-[130px]' : tabSizeMode === 'expanded' ? 'px-3.5 text-xs max-w-[320px]' : 'px-3 text-xs max-w-[210px]'}
              {isActive
                ? 'bg-[#060810] text-sky-200 border-t-2 border-t-sky-400 font-semibold shadow-xs'
                : 'bg-[#080b15]/70 hover:bg-[#0c111e] text-slate-400 hover:text-slate-200 border-t-2 border-t-transparent'}"
            title="{tabPath}{isDirtyTab ? ' (modifications non enregistrées)' : ''}"
          >
            <Code2 class="w-3.5 h-3.5 shrink-0 {isActive ? 'text-sky-400' : 'text-slate-500 group-hover:text-slate-400'}" />
            <span class="truncate flex-1">{tabName}</span>

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

      <!-- Tab Sizing Mode Button (Compact / Auto / Large) -->
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

      <!-- Zen Mode / Maximize Editor (Minimiser tous les volets latéraux) -->
      <button
        type="button"
        onclick={() => cockpitState.toggleZenMode()}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer
          {cockpitState.ideZenMode ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-400/40 font-semibold shadow-xs' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}"
        title={cockpitState.ideZenMode ? "Quitter le mode Plein Écran (restaurer les volets)" : "Plein Écran Éditeur / Minimiser tous les volets (Mode Zen)"}
      >
        {#if cockpitState.ideZenMode}
          <Minimize2 class="w-3.5 h-3.5 text-indigo-400" />
          <span class="hidden md:inline">Restaurer</span>
        {:else}
          <Maximize2 class="w-3.5 h-3.5 text-slate-400" />
          <span class="hidden md:inline">Plein Écran</span>
        {/if}
      </button>

      <!-- Search Overlay Trigger Button -->
      <button
        type="button"
        onclick={() => {
          isSearchOpen = !isSearchOpen;
          if (isSearchOpen) tick().then(() => searchInputEl?.focus());
        }}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer
          {isSearchOpen ? 'bg-sky-500/20 text-sky-300 border border-sky-400/30' : 'text-slate-400 hover:text-white hover:bg-white/5'}"
        title="Rechercher dans le fichier (Ctrl+F)"
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
          title="Mode Édition interactive"
        >
          <Edit3 class="w-3 h-3 text-sky-400" />
          <span class="hidden md:inline">Éditer</span>
        </button>
        <button
          type="button"
          onclick={() => (editorViewMode = 'preview')}
          class="flex items-center gap-1 px-2 py-0.5 rounded transition-colors cursor-pointer
            {editorViewMode === 'preview' ? 'bg-emerald-500/25 text-emerald-200 font-semibold' : 'text-slate-400 hover:text-white'}"
          title="Mode Rendu coloré syntaxique"
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

      <!-- Save Mode Quick Toggle (Auto-Save à l'édit vs Ctrl+S) -->
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

  <!-- In-File Search Overlay Banner (Ctrl+F) -->
  {#if isSearchOpen}
    <div class="px-3 py-1.5 bg-[#0d1322] border-b border-sky-500/30 flex items-center justify-between gap-2 text-xs shadow-md shrink-0 z-20">
      <div class="flex items-center gap-2 flex-1 max-w-md">
        <div class="relative flex-1">
          <Search class="w-3.5 h-3.5 text-slate-400 absolute left-2 top-1.5 pointer-events-none" />
          <input
            bind:this={searchInputEl}
            type="text"
            bind:value={searchQuery}
            onkeydown={handleSearchKeydown}
            placeholder="Rechercher dans ce fichier..."
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
      </div>

      <button
        type="button"
        onclick={() => (isSearchOpen = false)}
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

  <!-- Main Editor / Preview Workspace -->
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
      <!-- Line Numbers Gutter -->
      <div
        bind:this={gutterEl}
        class="w-12 py-3 bg-[#080b14] border-r border-white/5 select-none font-mono text-[11.5px] leading-relaxed text-right pr-2 text-slate-600 overflow-hidden shrink-0"
      >
        {#each lines as _, idx}
          {@const lineNum = idx + 1}
          {@const isHighlighted = highlightedLine === lineNum}
          {@const isTarget = targetLine === lineNum}
          {@const isCurrent = cursorLine === lineNum}
          <div
            class="h-[21px] transition-colors
              {isHighlighted ? 'text-sky-200 font-bold bg-sky-500/40 rounded-l animate-pulse' : isTarget ? 'text-sky-300 font-bold bg-sky-500/20 rounded-l' : ''}
              {isCurrent && !isTarget && !isHighlighted ? 'text-slate-400 font-semibold' : ''}"
          >
            {lineNum}
          </div>
        {/each}
      </div>

      <!-- Textarea Code Buffer -->
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
        class="flex-1 h-full py-3 px-3.5 bg-transparent text-slate-100 font-mono text-[11.5px] leading-relaxed resize-none focus:outline-none whitespace-pre overflow-auto scrollbar-thin select-text"
        placeholder="// Saisissez votre code source ici..."
      ></textarea>

    {:else}
      <!-- Syntax Highlighted Tokenized Preview -->
      <div
        bind:this={previewContainerEl}
        class="flex-1 h-full overflow-auto py-3 px-2 bg-[#060810] font-mono text-[11.5px] leading-relaxed select-text scrollbar-thin"
      >
        {#each lines as lineText, idx}
          {@const lineNum = idx + 1}
          {@const isHighlighted = highlightedLine === lineNum}
          {@const isTarget = targetLine === lineNum}
          <div
            data-line={lineNum}
            class="flex items-baseline hover:bg-white/[0.03] px-1 rounded transition-colors h-[21px]
              {isHighlighted ? 'bg-sky-500/35 border-l-4 border-sky-400 font-semibold shadow-md ring-1 ring-sky-400/40' : isTarget ? 'bg-sky-500/25 border-l-2 border-sky-400 font-semibold shadow-sm' : ''}"
          >
            <span class="w-10 shrink-0 select-none text-right pr-3 text-[10px] {isHighlighted ? 'text-sky-200 font-bold' : isTarget ? 'text-sky-300 font-bold' : 'text-slate-600'}">
              {lineNum}
            </span>
            <span class="whitespace-pre flex-1 truncate">
              {#each tokenizeCodeLine(lineText, syntaxLanguage) as tok}
                <span class={tok.cls}>{tok.text}</span>
              {/each}
            </span>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Bottom Status Bar -->
  <div class="h-6 px-3 bg-[#090d16] border-t border-white/10 flex items-center justify-between text-[10.5px] font-mono text-slate-400 select-none shrink-0">
    <div class="flex items-center gap-3">
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

      <span class="text-slate-600">|</span>

      <span>{lineCount} {lineCount > 1 ? 'lignes' : 'ligne'}</span>

      <span class="text-slate-600">|</span>

      <span>Ln {cursorLine}, Col {cursorCol}</span>
    </div>

    <div class="flex items-center gap-3">
      <span class="uppercase tracking-wider text-[9.5px] px-1.5 py-0.2 rounded bg-white/5 border border-white/10 text-sky-300">
        {syntaxLanguage}
      </span>
      <span class="text-slate-500 hidden md:inline">UTF-8</span>
    </div>
  </div>
</div>
