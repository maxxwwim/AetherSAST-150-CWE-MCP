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
    FileCode,
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

  // Target line highlight flash (active for ~2.5s on jump)
  let highlightedLine = $state<number | null>(null);
  let highlightTimer: any = null;

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

  // Keep active buffer content in sync with textarea
  function handleContentInput() {
    if (loadedFile) {
      buffers[loadedFile] = {
        content,
        savedContent,
        cursorLine,
        cursorCol
      };
    }
  }

  async function switchToFile(filePath: string) {
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

  async function loadFileFromDisk(filePath: string) {
    isLoading = true;
    errorMessage = null;
    successNotice = null;
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

  export async function saveCurrentFile() {
    if (!cockpitState.ideActiveFile || isSaving) return;
    isSaving = true;
    errorMessage = null;
    successNotice = null;
    try {
      const res = await api.saveFile(cockpitState.ideActiveFile, content);
      if (res && res.status === 'ok') {
        savedContent = content;
        if (loadedFile && buffers[loadedFile]) {
          buffers[loadedFile].savedContent = content;
        }
        successNotice = 'Enregistré sur disque';
        setTimeout(() => {
          if (successNotice === 'Enregistré sur disque') {
            successNotice = null;
          }
        }, 3000);
      } else {
        errorMessage = res?.error || "Erreur lors de l'enregistrement";
      }
    } catch (e: any) {
      errorMessage = e?.message || "Erreur d'écriture sur disque";
    } finally {
      isSaving = false;
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

  function handleTextareaKeydown(e: KeyboardEvent) {
    // Ctrl+S / Cmd+S: Save file
    if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
      e.preventDefault();
      saveCurrentFile();
      return;
    }

    // Ctrl+F / Cmd+F: Search overlay
    if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
      e.preventDefault();
      isSearchOpen = true;
      tick().then(() => searchInputEl?.focus());
      return;
    }

    // Tab key: Insert 4 spaces
    if (e.key === 'Tab') {
      e.preventDefault();
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

      <!-- Save Button -->
      <button
        type="button"
        onclick={saveCurrentFile}
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

  <!-- Error or Success Alert Notices -->
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
