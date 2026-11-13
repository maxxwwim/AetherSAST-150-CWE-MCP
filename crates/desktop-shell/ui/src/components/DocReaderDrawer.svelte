<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { BookOpen, Copy, Check, X, FileText } from 'lucide-svelte';

  let docSource = $state<'system' | 'symbol'>('system');
  let fileCode = $state('');
  let copied = $state(false);

  $effect(() => {
    const sym = cockpitState.activeSymbol;
    if (cockpitState.isDocPanelOpen && docSource === 'symbol' && sym?.file_path) {
      api
        .getFileContent(sym.file_path)
        .then((res) => {
          fileCode = res?.content || res?.code || '';
        })
        .catch(() => {
          fileCode = sym.docstring || '';
        });
    }
  });

  const displayedDoc = $derived.by(() => {
    if (docSource === 'symbol' && cockpitState.activeSymbol) {
      const sym = cockpitState.activeSymbol;
      return `# ${sym.name} (${sym.kind})\n\n- **Fichier :** \`${sym.file_path}:${sym.line_number}\`\n- **Couche :** \`${sym.layer}\`\n- **Complexité Cyclomatique :** ${sym.cyclomatic_complexity} | **LOC :** ${sym.loc}\n\n${sym.docstring ? `## Spécification & Docstring\n${sym.docstring}\n\n` : ''}${fileCode ? `## Code Source\n\`\`\`\n${fileCode.slice(0, 6000)}\n\`\`\`` : ''}`;
    }
    return (
      cockpitState.graph.system_prompt ||
      `# ${cockpitState.graph.project_name}\n\nOuvrez le Générateur de Prompts ou lancez un rescan pour afficher le contrat système complet.`
    );
  });

  function copyDoc() {
    navigator.clipboard?.writeText(displayedDoc);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
</script>

{#if cockpitState.isDocPanelOpen}
  <aside class="fixed left-4 top-14 bottom-12 w-[420px] max-w-[92vw] bg-[#0b0e17]/95 backdrop-blur-xl border border-emerald-500/30 rounded-xl shadow-[0_20px_60px_rgba(0,0,0,0.85)] z-40 flex flex-col overflow-hidden">
    <div class="px-4 py-3 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <BookOpen class="w-4 h-4 text-emerald-400" />
        <span class="text-xs font-bold text-white">Lecteur EARS & Contrats</span>
      </div>
      <div class="flex items-center gap-1.5">
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

    <div class="px-3 py-2 border-b border-white/10 flex gap-2 bg-black/20">
      <button
        type="button"
        onclick={() => (docSource = 'system')}
        class="flex-1 py-1.5 rounded text-[11px] font-semibold cursor-pointer {docSource === 'system' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-white'}"
      >
        📜 Contrat Projet
      </button>
      <button
        type="button"
        onclick={() => (docSource = 'symbol')}
        class="flex-1 py-1.5 rounded text-[11px] font-semibold cursor-pointer {docSource === 'symbol' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'text-slate-400 hover:text-white'}"
      >
        <FileText class="w-3 h-3 inline mr-1" />
        Symbole / Code
      </button>
    </div>

    <pre class="flex-1 overflow-auto p-4 text-[11px] font-mono text-slate-200 whitespace-pre-wrap leading-relaxed select-text">{displayedDoc}</pre>
  </aside>
{/if}
