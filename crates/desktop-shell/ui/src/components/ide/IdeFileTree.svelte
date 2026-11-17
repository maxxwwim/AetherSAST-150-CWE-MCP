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
    ShieldAlert
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
  let expandedPaths = $state<Set<string>>(new Set(['crates', 'src', 'crates/desktop-shell', 'crates/desktop-shell/ui']));

  function rgbaToHex(c: RgbaColor): string {
    const r = Math.round(c.r * 255).toString(16).padStart(2, '0');
    const g = Math.round(c.g * 255).toString(16).padStart(2, '0');
    const b = Math.round(c.b * 255).toString(16).padStart(2, '0');
    return `#${r}${g}${b}`;
  }

  // Pre-calculate file security anomalies and bubble colors from cockpitState.graph.nodes
  let anomaliesByFile = $derived.by(() => {
    const map = new Map<string, number>();
    for (const node of cockpitState.graph.nodes) {
      if (!node.file_path) continue;
      const norm = node.file_path.replace(/\\/g, '/');
      const hasAnomaly = node.has_security_violation ||
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
      const norm = node.file_path.replace(/\\/g, '/');
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
          color = '#ef4444'; // Security violation alert bubble red
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
    const norm = filePath.replace(/\\/g, '/');
    const exact = bubbleInfoByFile.get(norm);
    if (exact) return exact;

    // Check if any node in bubbleInfoByFile ends with filePath or vice versa
    for (const [key, val] of bubbleInfoByFile.entries()) {
      if (key.endsWith(norm) || norm.endsWith(key)) {
        return val;
      }
    }

    // Fallback: derive cosmic folder color from the file's parent folder
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
    const norm = folderPath.replace(/\\/g, '/');
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

    // Extract unique file paths from graph nodes
    for (const node of cockpitState.graph.nodes) {
      if (node.file_path && !fileSet.has(node.file_path)) {
        fileSet.add(node.file_path);
        const norm = node.file_path.replace(/\\/g, '/');
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

        // Add parent directory entries
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

    if (entries.length > 0) {
      rawFiles = entries;
    } else {
      loadError = 'Aucun fichier répertorié';
    }
  }

  function buildTree(files: FileEntry[], filter: string): TreeNode[] {
    const rootMap = new Map<string, TreeNode>();
    const q = filter.trim().toLowerCase();

    // 1. Group items into tree hierarchy
    for (const file of files) {
      const normPath = file.path.replace(/\\/g, '/');
      const parts = normPath.split('/');
      let currentLevel = rootMap;
      let accumulatedPath = '';

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        accumulatedPath = accumulatedPath ? `${accumulatedPath}/${part}` : part;
        const isLeaf = i === parts.length - 1;
        const isDir = isLeaf ? file.is_dir : true;

        if (!currentLevel.has(part)) {
          const node: TreeNode = {
            name: part,
            path: accumulatedPath,
            is_dir: isDir,
            size: isLeaf ? file.size : 0,
            extension: isLeaf ? (file.extension || (part.includes('.') ? part.split('.').pop() : '')) : '',
            children: [],
            anomalyCount: anomaliesByFile.get(accumulatedPath) || 0
          };
          currentLevel.set(part, node);
        }

        const currentNode = currentLevel.get(part)!;
        if (!isLeaf) {
          // ensure children map lookup
          let childMap = (currentNode as any)._childMap as Map<string, TreeNode>;
          if (!childMap) {
            childMap = new Map<string, TreeNode>();
            (currentNode as any)._childMap = childMap;
          }
          currentLevel = childMap;
        }
      }
    }

    // 2. Convert map hierarchy to sorted TreeNode arrays
    function convertMapToArray(map: Map<string, TreeNode>): TreeNode[] {
      const list: TreeNode[] = [];
      for (const node of map.values()) {
        const childMap = (node as any)._childMap as Map<string, TreeNode> | undefined;
        if (childMap) {
          node.children = convertMapToArray(childMap);
          // Aggregate anomaly counts up tree
          for (const ch of node.children) {
            node.anomalyCount += ch.anomalyCount;
          }
        }
        list.push(node);
      }

      // Sort: directories first, then alphabetical
      list.sort((a, b) => {
        if (a.is_dir !== b.is_dir) {
          return a.is_dir ? -1 : 1;
        }
        return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
      });

      return list;
    }

    const fullTree = convertMapToArray(rootMap);

    // 3. Filter tree if query provided
    if (!q) {
      return fullTree;
    }

    function filterNode(node: TreeNode): TreeNode | null {
      const matchesSelf = node.name.toLowerCase().includes(q) || node.path.toLowerCase().includes(q);
      const filteredChildren: TreeNode[] = [];

      for (const child of node.children) {
        const filteredChild = filterNode(child);
        if (filteredChild) {
          filteredChildren.push(filteredChild);
        }
      }

      if (matchesSelf || filteredChildren.length > 0) {
        // Auto-expand folder when query matches child
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

  let treeData = $derived(buildTree(rawFiles, searchFilter));

  function toggleFolder(path: string, e: MouseEvent) {
    e.stopPropagation();
    if (expandedPaths.has(path)) {
      expandedPaths.delete(path);
    } else {
      expandedPaths.add(path);
    }
    expandedPaths = new Set(expandedPaths);
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

    // Check if there is an exact or related node in cockpitState.graph.nodes
    const matchedNode = cockpitState.graph.nodes.find(
      (n) => n.file_path === node.path && (n.is_file || (n.kind as any) === 1 || n.kind === 'file' || n.kind === 'File' || n.id.startsWith('file::'))
    ) || cockpitState.graph.nodes.find((n) => n.file_path === node.path);

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

  function getFileColor(ext?: string): string {
    const lower = (ext || '').toLowerCase();
    switch (lower) {
      case 'rs':
        return 'text-amber-400';
      case 'ts':
        return 'text-sky-400';
      case 'js':
        return 'text-yellow-300';
      case 'svelte':
        return 'text-orange-400';
      case 'json':
        return 'text-emerald-400';
      case 'toml':
        return 'text-purple-400';
      case 'md':
        return 'text-blue-300';
      default:
        return 'text-slate-400';
    }
  }

  onMount(() => {
    fetchFileList();
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
    <button
      onclick={fetchFileList}
      class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
      title="Rafraîchir l'arborescence des fichiers"
      aria-label="Rafraîchir"
    >
      <RefreshCw class="w-3.5 h-3.5 {isLoading ? 'animate-spin text-sky-400' : ''}" />
    </button>
  </div>

  <!-- Search Filter Input -->
  <div class="p-2 border-b border-white/5 shrink-0 bg-black/20">
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
          onclick={() => (searchFilter = '')}
          class="absolute right-1.5 p-0.5 rounded text-slate-400 hover:text-white cursor-pointer"
          title="Effacer le filtre"
        >
          <X class="w-3 h-3" />
        </button>
      {/if}
    </div>
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
        {#if searchFilter}
          Aucun fichier correspondant à "{searchFilter}"
        {:else}
          Aucun fichier détecté dans le répertoire de travail
        {/if}
      </div>
    {:else}
      {#snippet renderNode(node: TreeNode, depth: number)}
        {@const isExpanded = expandedPaths.has(node.path)}
        {@const isSelected = cockpitState.ideActiveFile === node.path}
        {@const IconComp = node.is_dir ? (isExpanded ? FolderOpen : Folder) : getFileIcon(node.extension)}
        {@const folderColor = node.is_dir ? getFolderBubbleColor(node.path) : null}
        {@const fileMeta = node.is_dir ? null : getFileBubbleColor(node.path)}
        {@const itemColor = node.is_dir ? folderColor : fileMeta?.color}

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

            <span class="truncate {fileMeta?.hasAnomaly ? 'text-rose-200' : ''}">{node.name}</span>

            {#if !node.is_dir && fileMeta?.layer}
              <span
                class="text-[8.5px] font-mono uppercase px-1 py-0.2 rounded border shrink-0 opacity-70 group-hover:opacity-100 transition-opacity ml-auto mr-1"
                style="color: {fileMeta.color}; border-color: {fileMeta.color}40; background-color: {fileMeta.color}15;"
              >
                {fileMeta.layer}
              </span>
            {/if}
          </div>

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
