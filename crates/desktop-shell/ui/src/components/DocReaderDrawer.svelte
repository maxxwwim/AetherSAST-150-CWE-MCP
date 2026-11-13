<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { BookOpen, Copy, Check, X, FileText, FolderOpen, RefreshCw } from '@lucide/svelte';

  let loadedContent = $state('');
  let loadedPath = $state('');
  let loadError = $state('');
  let loading = $state(false);
  let systemPromptText = $state('');
  let copied = $state(false);

  // Locate best Markdown doc file in the active folder (or project README fallback)
  const folderDocNode = $derived.by(() => {
    const nodes = cockpitState.graph.nodes;
    const folder = cockpitState.activeSymbol?.folder || cockpitState.selectedFolder;
    const mdNodes = nodes.filter((n) => {
      const p = (n.file_path || n.name || '').toLowerCase();
      return p.endsWith('.md') || p.endsWith('.mdx');
    });
    if (folder) {
      const inFolder = mdNodes.filter((n) => (n.folder || n.cluster_id || 'root') === folder);
      if (inFolder.length > 0) {
        return inFolder.find((n) => n.name.toLowerCase().includes('readme')) || inFolder[0];
      }
    }
    return mdNodes.find((n) => n.name.toLowerCase() === 'readme.md') || mdNodes[0] || null;
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

    if (mode === 'symbol' && sym?.file_path) {
      loadPathContent(sym.file_path);
    } else if (mode === 'folder') {
      const targetPath = folderDocNode?.file_path || (folder && folder !== 'root' ? `${folder}/README.md` : 'README.md');
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

  const rawMarkdown = $derived.by(() => {
    const mode = cockpitState.docMode;
    const sym = cockpitState.activeSymbol;

    if (mode === 'symbol' && sym) {
      const body = loadedContent || sym.metadata?.raw_content || sym.docstring || '';
      const header = `# ${sym.name} (${sym.stereotype || sym.kind})\n\n- **Fichier :** \`${sym.file_path}:${sym.line_number || 1}\`\n- **Couche :** \`${sym.layer}\` | **LOC :** ${sym.loc || 1} | **Complexité :** ${sym.cyclomatic_complexity || 1}\n\n`;
      if (sym.docstring && !body.includes(sym.docstring)) {
        return `${header}## Documentation / Contrat\n${sym.docstring}\n\n## Code Source\n\`\`\`\n${body.slice(0, 12000)}\n\`\`\``;
      }
      if (sym.file_path.toLowerCase().endsWith('.md')) {
        return body || header;
      }
      return body ? `${header}## Code Source\n\`\`\`\n${body.slice(0, 12000)}\n\`\`\`` : `${header}${loadError || 'Aucun contenu brut disponible.'}`;
    }

    if (mode === 'folder') {
      if (loadedContent) return loadedContent;
      const folder = cockpitState.selectedFolder || 'root';
      const inFolder = cockpitState.graph.nodes.filter((n) => (n.folder || n.cluster_id || 'root') === folder);
      return `# 📁 Module \`${folder}\`\n\n${loadError ? `> ${loadError}\n\n` : ''}Aucun \`README.md\` direct trouvé pour ce dossier.\n\n## Entités détectées (${inFolder.length})\n${inFolder
        .slice(0, 30)
        .map((n) => `- \`${n.name}\` (${n.stereotype || n.kind}) — \`${n.file_path}\``)
        .join('\n')}`;
    }

    return (
      systemPromptText ||
      cockpitState.graph.system_prompt ||
      `# ${cockpitState.graph.project_name || 'AetherScope'}\n\nSélectionnez une bulle ou un dossier pour afficher sa documentation, ses contrats EARS ou son code source.`
    );
  });

  interface DocBlock {
    type: 'h1' | 'h2' | 'h3' | 'code' | 'list' | 'quote' | 'p';
    text: string;
    lang?: string;
  }

  const parsedBlocks = $derived.by(() => {
    const lines = rawMarkdown.split('\n');
    const blocks: DocBlock[] = [];
    let inCode = false;
    let codeLang = '';
    let codeBuf: string[] = [];

    for (const line of lines) {
      if (line.trim().startsWith('```')) {
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
      if (line.startsWith('### ')) {
        blocks.push({ type: 'h3', text: line.slice(4) });
      } else if (line.startsWith('## ')) {
        blocks.push({ type: 'h2', text: line.slice(3) });
      } else if (line.startsWith('# ')) {
        blocks.push({ type: 'h1', text: line.slice(2) });
      } else if (line.startsWith('> ')) {
        blocks.push({ type: 'quote', text: line.slice(2) });
      } else if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
        blocks.push({ type: 'list', text: line.trim().slice(2) });
      } else if (line.trim().length > 0) {
        blocks.push({ type: 'p', text: line });
      }
    }
    if (inCode && codeBuf.length > 0) {
      blocks.push({ type: 'code', text: codeBuf.join('\n'), lang: codeLang });
    }
    return blocks;
  });

  function copyDoc() {
    navigator.clipboard?.writeText(rawMarkdown);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
</script>

{#if cockpitState.isDocPanelOpen}
  <aside class="fixed left-4 top-14 bottom-12 w-[450px] max-w-[92vw] bg-[#0b0e17]/95 backdrop-blur-xl border border-emerald-500/35 rounded-xl shadow-[0_20px_60px_rgba(0,0,0,0.85)] z-40 flex flex-col overflow-hidden">
    <div class="px-4 py-2.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between gap-2">
      <div class="flex items-center gap-2 min-w-0">
        <BookOpen class="w-4 h-4 text-emerald-400 shrink-0" />
        <div class="min-w-0">
          <div class="text-xs font-bold text-white truncate">Lecteur Docs, EARS & Source</div>
          {#if loadedPath && cockpitState.docMode !== 'system'}
            <div class="text-[10px] font-mono text-emerald-300/80 truncate">{loadedPath}</div>
          {/if}
        </div>
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        {#if loading}
          <RefreshCw class="w-3.5 h-3.5 text-sky-400 animate-spin" />
        {/if}
        <button
          type="button"
          onclick={copyDoc}
          class="flex items-center gap-1 px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] text-slate-300 cursor-pointer"
        >
          {#if copied}
            <Check class="w-3 h-3 text-emerald-400" />
            <span>Copié</span>
          {:else}
            <Copy class="w-3 h-3" />
            <span>Copier</span>
          {/if}
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

    <!-- Mode Switcher -->
    <div class="px-3 py-2 border-b border-white/10 flex gap-1.5 bg-black/25 text-[11px]">
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'system')}
        class="flex-1 py-1.5 px-2 rounded font-semibold cursor-pointer transition-colors {cockpitState.docMode === 'system' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-white'}"
      >
        📜 Projet
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'folder')}
        class="flex-1 py-1.5 px-2 rounded font-semibold cursor-pointer transition-colors flex items-center justify-center gap-1 {cockpitState.docMode === 'folder' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-slate-400 hover:text-white'}"
      >
        <FolderOpen class="w-3 h-3" />
        README
      </button>
      <button
        type="button"
        onclick={() => (cockpitState.docMode = 'symbol')}
        class="flex-1 py-1.5 px-2 rounded font-semibold cursor-pointer transition-colors flex items-center justify-center gap-1 {cockpitState.docMode === 'symbol' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'text-slate-400 hover:text-white'}"
      >
        <FileText class="w-3 h-3" />
        Symbole
      </button>
    </div>

    <!-- Formatted Markdown / Code Content -->
    <div class="flex-1 overflow-auto p-4 space-y-2.5 text-xs text-slate-200 leading-relaxed select-text">
      {#each parsedBlocks as block}
        {#if block.type === 'h1'}
          <h1 class="text-sm font-bold text-white border-b border-white/10 pb-1.5 pt-1">{block.text}</h1>
        {:else if block.type === 'h2'}
          <h2 class="text-xs font-bold text-emerald-300 uppercase tracking-wider pt-2">{block.text}</h2>
        {:else if block.type === 'h3'}
          <h3 class="text-xs font-semibold text-sky-300 pt-1">{block.text}</h3>
        {:else if block.type === 'quote'}
          <blockquote class="border-l-2 border-amber-400/60 pl-3 text-[11px] text-amber-200/90 italic">{block.text}</blockquote>
        {:else if block.type === 'list'}
          <div class="flex gap-2 pl-2 text-[11px] text-slate-300">
            <span class="text-emerald-400">•</span>
            <span>{block.text}</span>
          </div>
        {:else if block.type === 'code'}
          <pre class="p-3 rounded-lg bg-[#06080f] border border-white/10 font-mono text-[10.5px] text-sky-100 overflow-x-auto whitespace-pre leading-snug">{block.text}</pre>
        {:else}
          <p class="text-[11.5px] text-slate-300">{block.text}</p>
        {/if}
      {/each}
    </div>
  </aside>
{/if}
