<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { FilePlus2, X, Sparkles, Folder, Upload } from '@lucide/svelte';

  let projectPath = $state('');
  let relPath = $state('src/services/new_service.rs');
  let codeContent = $state(`// Généré depuis AetherScope Cockpit\npub fn execute_task() {\n    // TODO: Implémenter la logique métier\n}\n`);
  let isCreating = $state(false);
  let feedback = $state<string | null>(null);
  let localFileInputEl = $state<HTMLInputElement | null>(null);

  function stripWinPrefix(p: string): string {
    return p.replace(/^\\\\\?\\/, '');
  }

  function normalizeFolderPrefix(raw: string | null | undefined): string {
    if (!raw) return '';
    const cleaned = raw
      .trim()
      .replace(/\\/g, '/')
      .replace(/^(?:\.\/)+/, '')
      .replace(/^\/+|\/+$/g, '');
    if (!cleaned || cleaned === '.' || cleaned === 'root') return '';
    return cleaned;
  }

  $effect(() => {
    if (cockpitState.isCreateFileModalOpen) {
      projectPath = stripWinPrefix(cockpitState.graph.project_path || '.');
      feedback = null;
      const pending = cockpitState.pendingImportFile;
      const folderPrefix = normalizeFolderPrefix(cockpitState.pendingCreateFolder);
      if (pending) {
        const cleanName = pending.fileName.replace(/\\/g, '/').replace(/^\/+/, '');
        relPath = cleanName.includes('/')
          ? cleanName
          : folderPrefix
            ? `${folderPrefix}/${cleanName}`
            : `imported/${cleanName}`;
        codeContent = pending.content;
        cockpitState.pendingImportFile = null;
      } else if (cockpitState.pendingCreateFolder !== null) {
        relPath = folderPrefix ? `${folderPrefix}/` : '';
      }
    } else if (cockpitState.pendingCreateFolder !== null) {
      cockpitState.pendingCreateFolder = null;
    }
  });

  async function handleLocalFileSelected(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const cleanName = file.name.replace(/\\/g, '/').replace(/^\/+/, '');
      relPath = cleanName.includes('/') ? cleanName : `imported/${cleanName}`;
      codeContent = text;
      feedback = null;
    } catch (err: any) {
      feedback = err?.message || 'Impossible de lire le fichier sélectionné.';
    } finally {
      input.value = '';
    }
  }

  function applySuggestion(prefix: string, defaultFile: string, snippet: string) {
    relPath = `${prefix}${defaultFile}`;
    codeContent = snippet;
  }

  async function handleCreateFile() {
    if (!relPath.trim()) return;
    isCreating = true;
    feedback = null;
    try {
      const res = await api.createFile({
        project_path: projectPath.trim() || '.',
        file_path: relPath.trim(),
        content: codeContent,
      });
      if (res?.status !== 'ok') {
        feedback = res?.message || 'Erreur lors de la création / import du fichier.';
        return;
      }
      if (res.graph) {
        cockpitState.setGraph(res.graph);
        cockpitState.filterVersion += 1;
        cockpitState.requestCameraFit();
      }
      if (res.created_symbol || res.file_path) {
        const hit = cockpitState.resolveTargetNode(res.file_path || res.created_symbol || '');
        if (hit) cockpitState.selectSymbol(hit.id, true);
      }
      cockpitState.pendingCreateFolder = null;
      cockpitState.isCreateFileModalOpen = false;
    } catch (e: any) {
      feedback = e?.message || 'Erreur lors de la création du fichier.';
    } finally {
      isCreating = false;
    }
  }

  function closeModal() {
    cockpitState.pendingCreateFolder = null;
    cockpitState.isCreateFileModalOpen = false;
  }
</script>

{#if cockpitState.isCreateFileModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-2xl bg-[#090d16] border border-emerald-500/40 rounded-xl shadow-[0_24px_80px_rgba(16,185,129,0.22)] flex flex-col overflow-hidden text-slate-100">
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <FilePlus2 class="w-5 h-5 text-emerald-400" />
          <div>
            <h2 class="text-sm font-bold text-white">Importer ou Créer un Fichier & Mettre à Jour le Graphe</h2>
            <p class="text-[11px] text-slate-400">Importe un fichier local ou crée un fichier sur disque et re-scanne instantanément l'AST</p>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <input
            bind:this={localFileInputEl}
            type="file"
            class="hidden"
            onchange={handleLocalFileSelected}
          />
          <button
            type="button"
            onclick={() => localFileInputEl?.click()}
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-400/40 text-[11px] font-semibold text-sky-200 cursor-pointer"
          >
            <Upload class="w-3.5 h-3.5" />
            <span>Importer depuis le PC…</span>
          </button>
          <button
            type="button"
            onclick={closeModal}
            aria-label="Fermer création de fichier"
            class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </div>

      <div class="p-5 space-y-3.5 text-xs">
        <div>
          <label for="cf-project-path" class="block text-[10px] font-mono text-slate-400 uppercase mb-1">Racine Projet</label>
          <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 border border-white/10 font-mono text-slate-300">
            <Folder class="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <input id="cf-project-path" type="text" bind:value={projectPath} class="flex-1 bg-transparent outline-none" />
          </div>
        </div>

        <div>
          <label for="cf-rel-path" class="block text-[10px] font-mono text-slate-400 uppercase mb-1">Chemin Relatif du Nouveau Fichier</label>
          <input
            id="cf-rel-path"
            type="text"
            bind:value={relPath}
            placeholder="Ex: src/services/auth_guard.rs"
            class="w-full px-3 py-2 rounded-lg bg-black/50 border border-white/15 font-mono text-white focus:outline-none focus:border-emerald-400"
          />
          <div class="flex flex-wrap gap-1.5 mt-2">
            <button
              type="button"
              onclick={() => applySuggestion('src/ui/', 'panel_widget.ts', 'export function mountWidget() {\n  return "ready";\n}\n')}
              class="px-2 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/35 text-[10px] font-mono text-sky-300 cursor-pointer"
            >
              + UI
            </button>
            <button
              type="button"
              onclick={() => applySuggestion('src/domain/', 'model_entity.rs', 'pub struct DomainEntity {\n    pub id: String,\n}\n')}
              class="px-2 py-0.5 rounded bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/35 text-[10px] font-mono text-purple-300 cursor-pointer"
            >
              + Domain
            </button>
            <button
              type="button"
              onclick={() => applySuggestion('src/services/', 'service_handler.rs', 'pub async fn handle_service() -> bool {\n    true\n}\n')}
              class="px-2 py-0.5 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-[10px] font-mono text-emerald-300 cursor-pointer"
            >
              + Service
            </button>
            <button
              type="button"
              onclick={() => applySuggestion('docs/', 'SPECIFICATION.md', '# Spécification Module\n\n- Objectif :\n- Contrats EARS :\n')}
              class="px-2 py-0.5 rounded bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/35 text-[10px] font-mono text-amber-300 cursor-pointer"
            >
              + Doc
            </button>
          </div>
        </div>

        <div>
          <label for="cf-content" class="block text-[10px] font-mono text-slate-400 uppercase mb-1">Contenu Initial</label>
          <textarea
            id="cf-content"
            rows="8"
            bind:value={codeContent}
            class="w-full px-3 py-2 rounded-lg bg-black/55 border border-white/15 font-mono text-slate-200 focus:outline-none focus:border-emerald-400"
          ></textarea>
        </div>

        {#if feedback}
          <div class="p-2.5 rounded-lg bg-rose-500/15 border border-rose-500/35 text-rose-200 font-mono">{feedback}</div>
        {/if}

        <div class="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onclick={closeModal}
            class="px-3.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
          >
            Annuler
          </button>
          <button
            type="button"
            disabled={isCreating || !relPath.trim()}
            onclick={handleCreateFile}
            class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 font-bold text-slate-950 cursor-pointer"
          >
            <Sparkles class="w-3.5 h-3.5" />
            <span>{isCreating ? 'Création & Scan...' : 'Créer & Analyser'}</span>
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
