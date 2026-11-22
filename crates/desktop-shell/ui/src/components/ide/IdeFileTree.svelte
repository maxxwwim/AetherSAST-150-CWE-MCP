<script lang="ts">
  import { onMount } from 'svelte';
  import { cockpitState } from '../../state/graphState.svelte';
  import { api } from '../../lib/api';
  import { getFolderColor, getLayerRgba, type RgbaColor } from '../../engine/palette';
  import {
    Folder,
    FolderOpen,
    FileText,
    FileCode,
    Code2,
    RefreshCw,
    Search,
    X,
    ChevronDown,
    ChevronRight,
    ShieldAlert,
    Plus,
    Copy,
    Check,
    GitBranch
  } from '@lucide/svelte';

  interface FileEntry {
    name: string;
    path: string;
    is_dir: boolean;
    size?: number;
    extension?: string;
  }

  interface TreeNode {
    name: string;
    path: string;
    is_dir: boolean;
    size?: number;
    extension?: string;
    children: TreeNode[];
    anomalyCount: number;
    gitBadge: string | null;
    hasGitChanges: boolean;
    gitCount: number;
  }

  interface FileBubbleInfo {
    color: string;
    layer?: string;
    hasAnomaly: boolean;
  }

  let rawFiles = $state<FileEntry[]>([]);
  let isLoading = $state(false);
  let loadError = $state<string | null>(null);
  let searchFilter = $state('');
  let gitModifiedOnly = $state(false);
  let copiedPath = $state<string | null>(null);
  let expandedPaths = $state<Set<string>>(new Set(['crates', 'src', 'crates/desktop-shell', 'crates/desktop-shell/ui']));

  function rgbaToHex(c: RgbaColor): string {
    const r = Math.round(c.r * 255).toString(16).padStart(2, '0');
    const g = Math.round(c.g * 255).toString(16).padStart(2, '0');
    const b = Math.round(c.b * 255).toString(16).padStart(2, '0');
    return `#${r}${g}${b}`;
  }

  function normalizeRelPath(p?: string | null): string {
    return String(p || '')
      .replace(/\\/g, '/')
      .replace(/^\.\//, '')
      .replace(/^\/+/, '')
      .trim();
  }

  function mapGitStatusBadge(status?: string | null): { badge: string; cls: string; label: string } | null {
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

  let gitStatusByFile = $derived.by(() => {
    const map = new Map<string, { badge: string; cls: string; label: string }>();
    const gs = cockpitState.gitStatus;
    if (!gs || !gs.is_git_repo || !Array.isArray(gs.files)) return map;
    for (const f of gs.files) {
      if (!f || !f.path) continue;
      const norm = normalizeRelPath(f.path);
      const info = mapGitStatusBadge(f.status);
      if (norm && info) {
        map.set(norm, info);
      }
    }
    return map;
  });

  // Pre-calculate file security anomalies and bubble colors from cockpitState.graph.nodes
  let anomaliesByFile = $derived.by(() => {
    const map = new Map<string, number>();
    for (const node of cockpitState.graph.nodes) {
      if (!node.file_path) continue;
      const norm = normalizeRelPath(node.file_path);
      const hasAnomaly =
        node.has_security_violation ||
        (node.anomalies && node.anomalies.length > 0) ||
        (node.metadata?.cve_anomalies && node.metadata.cve_anomalies.length > 0);
      if (hasAnomaly) {
        map.set(norm, (map.get(norm) || 0) + 1);
      }
    }
    return map;
  });

  // Pre-calculate bubble color and layer per file from AST graph nodes
  let bubbleInfoByFile = $derived.by(() => {
    const map = new Map<string, FileBubbleInfo>();
    for (const node of cockpitState.graph.nodes) {
      if (!node.file_path) continue;
      const norm = normalizeRelPath(node.file_path);
      const isFileNode = node.is_file || (node.kind as any) === 1 || node.kind === 'File' || node.id.startsWith('file::');
      const hasAnomaly = !!(
        node.has_security_violation ||
        (node.anomalies && node.anomalies.length > 0) ||
        (node.metadata?.cve_anomalies && node.metadata.cve_anomalies.length > 0)
      );

      const existing = map.get(norm);
      if (!existing || isFileNode || (hasAnomaly && !existing.hasAnomaly)) {
        let color: string;
        if (hasAnomaly) {
          color = '#ef4444';
        } else if (node.layer) {
          const rgba = getLayerRgba(node.layer);
          color = rgbaToHex(rgba);
        } else {
          const rgba = getFolderColor(node.folder || norm);
          color = rgbaToHex(rgba);
        }

        map.set(norm, {
          color,
          layer: node.layer || undefined,
          hasAnomaly
        });
      }
    }
    return map;
  });

  function getFileBubbleColor(filePath: string): FileBubbleInfo {
    const norm = normalizeRelPath(filePath);
    const exact = bubbleInfoByFile.get(norm);
    if (exact) return exact;

    for (const [key, val] of bubbleInfoByFile.entries()) {
      if (key.endsWith('/' + norm) || norm.endsWith('/' + key)) {
        return val;
      }
    }

    const parts = norm.split('/');
    const folder = parts.length > 1 ? parts.slice(0, parts.length - 1).join('/') : 'root';
    const folderCol = rgbaToHex(getFolderColor(folder));
    return {
      color: folderCol,
      layer: undefined,
      hasAnomaly: false
    };
  }

  function getFolderBubbleColor(folderPath: string): string {
    const norm = normalizeRelPath(folderPath);
    return rgbaToHex(getFolderColor(norm));
  }

  async function fetchFileList() {
    isLoading = true;
    loadError = null;
    try {
      const res = await api.getFiles();
      if (res && res.status === 'ok' && Array.isArray(res.files) && res.files.length > 0) {
        rawFiles = res.files;
      } else {
        fallbackFromGraph();
      }
    } catch {
      fallbackFromGraph();
    } finally {
      isLoading = false;
    }
  }

  function fallbackFromGraph() {
    const fileSet = new Set<string>();
    const entries: FileEntry[] = [];

    for (const node of cockpitState.graph.nodes) {
      if (node.file_path && !fileSet.has(node.file_path)) {
        fileSet.add(node.file_path);
        const norm = normalizeRelPath(node.file_path);
        const parts = norm.split('/');
        const name = parts[parts.length - 1];
        const ext = name.includes('.') ? name.split('.').pop() || '' : '';
        entries.push({
          name,
          path: norm,
          is_dir: false,
          size: node.loc ? node.loc * 35 : 1024,
          extension: ext
        });

        let currentDir = '';
        for (let i = 0; i < parts.length - 1; i++) {
          currentDir = currentDir ? `${currentDir}/${parts[i]}` : parts[i];
          if (!fileSet.has(currentDir)) {
            fileSet.add(currentDir);
            entries.push({
              name: parts[i],
              path: currentDir,
              is_dir: true,
              size: 0,
              extension: ''
            });
          }
        }
      }
    }

    // Also include Git status files if graph is empty
    const gs = cockpitState.gitStatus;
    if (gs?.is_git_repo && Array.isArray(gs.files)) {
      for (const gf of gs.files) {
        const norm = normalizeRelPath(gf.path);
        if (norm && !fileSet.has(norm)) {
          fileSet.add(norm);
          const parts = norm.split('/');
          const name = parts[parts.length - 1];
          const ext = name.includes('.') ? name.split('.').pop() || '' : '';
          entries.push({ name, path: norm, is_dir: false, size: 512, extension: ext });
        }
      }
    }

    if (entries.length > 0) {
      rawFiles = entries;
    } else {
      loadError = 'Aucun fichier répertorié';
    }
  }

  function buildTree(files: FileEntry[], filter: string, onlyGitModified: boolean): TreeNode[] {
    const rootMap = new Map<string, TreeNode>();
    const q = filter.trim().toLowerCase();

    for (const file of files) {
      const normPath = normalizeRelPath(file.path);
      if (!normPath) continue;
      const parts = normPath.split('/');
      let currentLevel = rootMap;
      let accumulatedPath = '';

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        accumulatedPath = accumulatedPath ? `${accumulatedPath}/${part}` : part;
        const isLeaf = i === parts.length - 1;
        const isDir = isLeaf ? file.is_dir : true;

        if (!currentLevel.has(part)) {
          const gitInfo = !isDir ? gitStatusByFile.get(accumulatedPath) : undefined;
          const badge = gitInfo?.badge || null;
          const node: TreeNode = {
            name: part,
            path: accumulatedPath,
            is_dir: isDir,
            size: isLeaf ? file.size : 0,
            extension: isLeaf ? (file.extension || (part.includes('.') ? part.split('.').pop() : '')) : '',
            children: [],
            anomalyCount: anomaliesByFile.get(accumulatedPath) || 0,
            gitBadge: badge,
            hasGitChanges: Boolean(badge),
            gitCount: badge ? 1 : 0
          };
          currentLevel.set(part, node);
        }

        const currentNode = currentLevel.get(part)!;
        if (!isLeaf) {
          let childMap = (currentNode as any)._childMap as Map<string, TreeNode>;
          if (!childMap) {
            childMap = new Map<string, TreeNode>();
            (currentNode as any)._childMap = childMap;
          }
          currentLevel = childMap;
        }
      }
    }

    function convertMapToArray(map: Map<string, TreeNode>): TreeNode[] {
      const list: TreeNode[] = [];
      for (const node of map.values()) {
        const childMap = (node as any)._childMap as Map<string, TreeNode> | undefined;
        if (childMap) {
          node.children = convertMapToArray(childMap);
          for (const ch of node.children) {
            node.anomalyCount += ch.anomalyCount;
            node.gitCount += ch.gitCount;
            if (ch.hasGitChanges) {
              node.hasGitChanges = true;
            }
          }
        }
        list.push(node);
      }

      list.sort((a, b) => {
        if (a.is_dir !== b.is_dir) {
          return a.is_dir ? -1 : 1;
        }
        return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
      });

      return list;
    }

    const fullTree = convertMapToArray(rootMap);

    if (!q && !onlyGitModified) {
      return fullTree;
    }

    function filterNode(node: TreeNode): TreeNode | null {
      const matchesQuery = !q || node.name.toLowerCase().includes(q) || node.path.toLowerCase().includes(q);
      const matchesGit = !onlyGitModified || (!node.is_dir && node.hasGitChanges);
      const filteredChildren: TreeNode[] = [];

      for (const child of node.children) {
        const filteredChild = filterNode(child);
        if (filteredChild) {
          filteredChildren.push(filteredChild);
        }
      }

      if ((matchesQuery && matchesGit && !node.is_dir) || (matchesQuery && !onlyGitModified && node.is_dir) || filteredChildren.length > 0) {
        if (node.is_dir) {
          expandedPaths.add(node.path);
        }
        return {
          ...node,
          children: filteredChildren
        };
      }
      return null;
    }

    const filtered: TreeNode[] = [];
    for (const rootNode of fullTree) {
      const res = filterNode(rootNode);
      if (res) filtered.push(res);
    }
    return filtered;
  }

  let treeData = $derived(buildTree(rawFiles, searchFilter, gitModifiedOnly));

  function toggleFolder(path: string, e: MouseEvent) {
    e.stopPropagation();
    if (expandedPaths.has(path)) {
      expandedPaths.delete(path);
    } else {
      expandedPaths.add(path);
    }
    expandedPaths = new Set(expandedPaths);
  }

  function createNewFileInFolder(folderPath: string, e: MouseEvent) {
    e.stopPropagation();
    cockpitState.pendingCreateFolder = folderPath;
    cockpitState.isCreateFileModalOpen = true;
  }

  async function copyRelativePath(relPath: string, e: MouseEvent) {
    e.stopPropagation();
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(relPath);
      } else {
        await navigator?.clipboard?.writeText(relPath);
      }
      copiedPath = relPath;
      setTimeout(() => {
        if (copiedPath === relPath) copiedPath = null;
      }, 1500);
    } catch {
      // degrade gracefully if clipboard is unavailable
    }
  }

  function handleFileClick(node: TreeNode) {
    if (node.is_dir) {
      if (expandedPaths.has(node.path)) {
        expandedPaths.delete(node.path);
      } else {
        expandedPaths.add(node.path);
      }
      expandedPaths = new Set(expandedPaths);
      return;
    }

    cockpitState.ideActiveFile = node.path;
    cockpitState.openFileInIde(node.path);

    const matchedNode =
      cockpitState.graph.nodes.find(
        (n) =>
          normalizeRelPath(n.file_path) === node.path &&
          (n.is_file || (n.kind as any) === 1 || n.kind === 'file' || n.kind === 'File' || n.id.startsWith('file::'))
      ) || cockpitState.graph.nodes.find((n) => normalizeRelPath(n.file_path) === node.path);

    if (matchedNode) {
      cockpitState.activeSymbol = matchedNode;
    }
  }

  function getFileIcon(ext?: string) {
    const lower = (ext || '').toLowerCase();
    switch (lower) {
      case 'rs':
        return Code2;
      case 'ts':
      case 'js':
      case 'svelte':
      case 'tsx':
      case 'jsx':
        return FileCode;
      case 'toml':
      case 'json':
      case 'yaml':
      case 'yml':
      case 'md':
      case 'txt':
        return FileText;
      default:
        return FileText;
    }
  }

  let lastSyncedFsVer = 0;
  let lastSyncedGraphVer = 0;
  let lastSyncedProjPath = '';

  onMount(() => {
    lastSyncedFsVer = cockpitState.fsVersion;
    lastSyncedGraphVer = cockpitState.graphVersion;
    lastSyncedProjPath = cockpitState.graph.project_path || '';
    fetchFileList();
  });

  $effect(() => {
    const fsVer = cockpitState.fsVersion;
    const gVer = cockpitState.graphVersion;
    const pPath = cockpitState.graph.project_path || '';
    if (
      (fsVer > 0 && fsVer !== lastSyncedFsVer) ||
      (gVer > 0 && gVer !== lastSyncedGraphVer) ||
      (pPath && pPath !== lastSyncedProjPath)
    ) {
      lastSyncedFsVer = fsVer;
      lastSyncedGraphVer = gVer;
      lastSyncedProjPath = pPath;
      void fetchFileList();
    }
  });
</script>

<div class="w-full h-full flex flex-col bg-[#070a14] border-r border-white/10 select-none text-xs">
  <!-- Header Bar -->
  <div class="h-9 px-3 border-b border-white/10 flex items-center justify-between bg-black/30 shrink-0">
    <div class="flex items-center gap-2">
      <span class="font-bold uppercase tracking-wider text-[10px] text-slate-300 font-mono">Fichiers</span>
      <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/5 text-slate-400 border border-white/5">
        {rawFiles.length}
      </span>
    </div>
    <div class="flex items-center gap-1">
      <!-- Filter: Fichiers modifiés Git uniquement (F14) -->
      <button
        type="button"
        onclick={() => (gitModifiedOnly = !gitModifiedOnly)}
        class="px-1.5 py-0.5 rounded text-[9.5px] font-mono border flex items-center gap-1 transition-colors cursor-pointer
          {gitModifiedOnly
            ? 'bg-amber-500/20 text-amber-200 border-amber-400/40 font-semibold'
            : 'bg-white/[0.03] text-slate-400 hover:text-white border-white/10'}"
        title="Fichiers modifiés Git uniquement"
        aria-label="Fichiers modifiés Git uniquement"
      >
        <GitBranch class="w-3 h-3 {gitModifiedOnly ? 'text-amber-300' : 'text-slate-400'}" />
        <span>Git</span>
      </button>

      <!-- Create File at Root Button -->
      <button
        type="button"
        onclick={(e) => createNewFileInFolder('', e)}
        class="p-1 rounded text-slate-400 hover:text-emerald-300 hover:bg-emerald-500/10 transition-colors cursor-pointer"
        title="Nouveau fichier dans le projet"
        aria-label="Nouveau fichier"
      >
        <Plus class="w-3.5 h-3.5" />
      </button>

      <button
        type="button"
        onclick={fetchFileList}
        class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
        title="Rafraîchir l'arborescence des fichiers"
        aria-label="Rafraîchir"
      >
        <RefreshCw class="w-3.5 h-3.5 {isLoading ? 'animate-spin text-sky-400' : ''}" />
      </button>
    </div>
  </div>

  <!-- Search Filter Input -->
  <div class="p-2 border-b border-white/5 shrink-0 bg-black/20 space-y-1">
    <div class="relative flex items-center">
      <Search class="w-3.5 h-3.5 text-slate-500 absolute left-2 pointer-events-none" />
      <input
        type="text"
        bind:value={searchFilter}
        placeholder="Filtrer les fichiers..."
        class="w-full pl-7 pr-6 py-1 rounded bg-white/[0.04] border border-white/10 text-slate-200 placeholder-slate-500 text-[11px] font-mono focus:outline-none focus:border-sky-500/50 transition-colors"
      />
      {#if searchFilter}
        <button
          type="button"
          onclick={() => (searchFilter = '')}
          class="absolute right-1.5 p-0.5 rounded text-slate-400 hover:text-white cursor-pointer"
          title="Effacer le filtre"
        >
          <X class="w-3 h-3" />
        </button>
      {/if}
    </div>
    {#if gitModifiedOnly}
      <div class="flex items-center justify-between px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/25 text-[9.5px] font-mono text-amber-200">
        <span>Fichiers modifiés Git uniquement</span>
        <button
          type="button"
          onclick={() => (gitModifiedOnly = false)}
          class="text-amber-300 hover:text-white cursor-pointer"
          title="Désactiver le filtre Git"
        >
          <X class="w-2.5 h-2.5" />
        </button>
      </div>
    {/if}
  </div>

  <!-- Directory Tree Container -->
  <div class="flex-1 overflow-y-auto overflow-x-hidden p-1.5 space-y-0.5 font-mono text-[11.5px] scrollbar-thin">
    {#if isLoading && rawFiles.length === 0}
      <div class="py-8 text-center text-slate-500 flex flex-col items-center gap-2">
        <RefreshCw class="w-4 h-4 animate-spin text-sky-400" />
        <span>Chargement du projet...</span>
      </div>
    {:else if treeData.length === 0}
      <div class="py-8 text-center text-slate-500 text-[11px]">
        {#if gitModifiedOnly}
          Aucun fichier modifié Git détecté
        {:else if searchFilter}
          Aucun fichier correspondant à "{searchFilter}"
        {:else}
          Aucun fichier détecté dans le répertoire de travail
        {/if}
      </div>
    {:else}
      {#snippet renderNode(node: TreeNode, depth: number)}
        {@const isExpanded = expandedPaths.has(node.path)}
        {@const isSelected = normalizeRelPath(cockpitState.ideActiveFile) === node.path}
        {@const IconComp = node.is_dir ? (isExpanded ? FolderOpen : Folder) : getFileIcon(node.extension)}
        {@const folderColor = node.is_dir ? getFolderBubbleColor(node.path) : null}
        {@const fileMeta = node.is_dir ? null : getFileBubbleColor(node.path)}
        {@const itemColor = node.is_dir ? folderColor : fileMeta?.color}
        {@const gitInfo = !node.is_dir ? gitStatusByFile.get(node.path) : null}

        <div
          role="button"
          tabindex="0"
          onclick={() => handleFileClick(node)}
          onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') handleFileClick(node); }}
          class="w-full flex items-center justify-between py-1 px-1.5 rounded transition-colors group cursor-pointer text-left
            {isSelected ? 'bg-sky-500/20 text-sky-200 border-l-2 border-sky-400 font-semibold' : 'text-slate-300 hover:bg-white/[0.04] hover:text-white'}"
          style="padding-left: {Math.max(6, depth * 14 + 6)}px"
          title={node.path}
        >
          <div class="flex items-center gap-1.5 min-w-0 flex-1">
            {#if node.is_dir}
              <button
                type="button"
                onclick={(e) => toggleFolder(node.path, e)}
                class="w-4 h-4 flex items-center justify-center text-slate-500 hover:text-slate-300 shrink-0"
              >
                {#if isExpanded}
                  <ChevronDown class="w-3 h-3 text-slate-400" />
                {:else}
                  <ChevronRight class="w-3 h-3 text-slate-400" />
                {/if}
              </button>
            {:else}
              <span class="w-4 h-4 shrink-0"></span>
            {/if}

            <IconComp
              class="w-3.5 h-3.5 shrink-0 transition-colors"
              style="color: {itemColor}; stroke: {itemColor};"
            />

            {#if !node.is_dir && fileMeta}
              <span
                class="w-2 h-2 rounded-full shrink-0 transition-transform group-hover:scale-125"
                style="background-color: {fileMeta.color}; box-shadow: 0 0 6px {fileMeta.color}aa;"
                title="Bulle AST: {fileMeta.layer ? `Couche ${fileMeta.layer.toUpperCase()}` : 'Fichier'} ({fileMeta.color})"
              ></span>
            {/if}

            <span class="truncate {fileMeta?.hasAnomaly ? 'text-rose-200' : node.hasGitChanges ? 'text-amber-100' : ''}">{node.name}</span>

            {#if !node.is_dir && fileMeta?.layer}
              <span
                class="text-[8.5px] font-mono uppercase px-1 py-0.2 rounded border shrink-0 opacity-70 group-hover:opacity-100 transition-opacity ml-auto mr-1"
                style="color: {fileMeta.color}; border-color: {fileMeta.color}40; background-color: {fileMeta.color}15;"
              >
                {fileMeta.layer}
              </span>
            {/if}
          </div>

          <div class="flex items-center gap-1 shrink-0">
            <!-- Quick File Actions on Hover: + New File in Folder / Copy Relative Path (F14) -->
            {#if node.is_dir}
              <button
                type="button"
                onclick={(e) => createNewFileInFolder(node.path, e)}
                class="opacity-0 group-hover:opacity-100 p-0.5 rounded text-slate-400 hover:text-emerald-300 hover:bg-emerald-500/15 transition-opacity cursor-pointer"
                title="Nouveau fichier dans {node.path}"
              >
                <Plus class="w-3 h-3" />
              </button>
            {/if}
            <button
              type="button"
              onclick={(e) => copyRelativePath(node.path, e)}
              class="opacity-0 group-hover:opacity-100 p-0.5 rounded text-slate-400 hover:text-sky-300 hover:bg-sky-500/15 transition-opacity cursor-pointer"
              title="Copier le chemin relatif ({node.path})"
            >
              {#if copiedPath === node.path}
                <Check class="w-2.5 h-2.5 text-emerald-400" />
              {:else}
                <Copy class="w-2.5 h-2.5" />
              {/if}
            </button>

            <!-- Git Status Badge for Files or Directory Rollup Dot -->
            {#if !node.is_dir && gitInfo}
              <span
                class="px-1 py-0.2 text-[9px] rounded font-mono font-bold border {gitInfo.cls}"
                title={gitInfo.label}
              >
                {gitInfo.badge}
              </span>
            {:else if node.is_dir && node.hasGitChanges}
              <span
                class="px-1 py-0.2 text-[8.5px] rounded font-mono bg-amber-500/15 border border-amber-500/30 text-amber-300"
                title="{node.gitCount} fichier(s) modifié(s) Git dans ce dossier"
              >
                ● {node.gitCount}
              </span>
            {/if}

            {#if node.anomalyCount > 0}
              <span
                class="shrink-0 flex items-center gap-0.5 px-1 py-0.2 text-[9px] rounded font-mono bg-rose-500/20 border border-rose-500/30 text-rose-300"
                title="{node.anomalyCount} anomalie(s) de sécurité détectée(s)"
              >
                <ShieldAlert class="w-2.5 h-2.5 text-rose-400" />
                {node.anomalyCount}
              </span>
            {/if}
          </div>
        </div>

        {#if node.is_dir && isExpanded && node.children.length > 0}
          <div class="space-y-0.5">
            {#each node.children as child (child.path)}
              {@render renderNode(child, depth + 1)}
            {/each}
          </div>
        {:else if node.is_dir && isExpanded && node.children.length === 0}
          <div
            class="text-[10px] text-slate-600 italic py-0.5"
            style="padding-left: {(depth + 1) * 14 + 10}px"
          >
            (dossier vide)
          </div>
        {/if}
      {/snippet}

      {#each treeData as rootNode (rootNode.path)}
        {@render renderNode(rootNode, 0)}
      {/each}
    {/if}
  </div>
</div>
