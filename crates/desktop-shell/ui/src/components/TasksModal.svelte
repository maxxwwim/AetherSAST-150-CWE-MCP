<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import {
    CheckSquare,
    X,
    Plus,
    Trash2,
    Navigation,
    RefreshCw,
    Save,
    Clock,
  } from '@lucide/svelte';
  import type { TaskItem } from '../types/graph';

  let filterStatus = $state<'all' | 'pending' | 'in_progress' | 'blocked' | 'done' | 'cancelled'>('all');
  let selectedTask = $state<TaskItem | null>(null);
  let showCreateForm = $state(false);
  let loading = $state(false);
  let statusMsg = $state<string | null>(null);

  // Create form fields
  let newTitle = $state('');
  let newKind = $state<TaskItem['kind']>('security_fix');
  let newPriority = $state<TaskItem['priority']>('high');
  let newSymbol = $state('');
  let newFile = $state('');
  let newReadme = $state('');

  // Editable selected task fields
  let editStatus = $state<TaskItem['status']>('pending');
  let editProgress = $state(0);
  let editReadme = $state('');

  const filteredTasks = $derived(
    filterStatus === 'all'
      ? cockpitState.tasks
      : cockpitState.tasks.filter((t) => t.status === filterStatus)
  );

  $effect(() => {
    if (cockpitState.isTasksModalOpen) {
      refreshTasks();
      if (cockpitState.activeSymbol && !newSymbol) {
        newSymbol = cockpitState.activeSymbol.id;
        newFile = cockpitState.activeSymbol.file_path || '';
      }
    }
  });

  async function refreshTasks() {
    loading = true;
    try {
      const list = await api.getTasks();
      cockpitState.tasks = list;
      if (selectedTask) {
        const updated = cockpitState.tasks.find((t) => t.id === selectedTask?.id) || null;
        if (updated) selectTask(updated);
      } else if (cockpitState.tasks.length > 0) {
        selectTask(cockpitState.tasks[0]);
      }
    } catch (e: any) {
      statusMsg = e?.message || 'Erreur chargement tâches';
    } finally {
      loading = false;
    }
  }

  function selectTask(t: TaskItem) {
    selectedTask = t;
    editStatus = t.status;
    editProgress = t.progress || 0;
    editReadme = t.full_readme || t.readme || t.readme_summary || '';
    statusMsg = null;
  }

  async function handleCreateTask() {
    if (!newTitle.trim()) return;
    loading = true;
    try {
      const res = await api.createTask({
        title: newTitle.trim(),
        kind: newKind,
        priority: newPriority,
        target_symbol: newSymbol.trim() || undefined,
        target_file: newFile.trim() || undefined,
        initial_readme: newReadme.trim() || undefined,
        author: 'Cockpit',
      });
      if (res.task) {
        cockpitState.tasks = [res.task, ...cockpitState.tasks];
        selectTask(res.task);
      } else {
        await refreshTasks();
      }
      newTitle = '';
      newReadme = '';
      showCreateForm = false;
      statusMsg = 'Tâche créée.';
    } catch (e: any) {
      statusMsg = e?.message || 'Impossible de créer la tâche.';
    } finally {
      loading = false;
    }
  }

  async function saveSelectedTask() {
    if (!selectedTask) return;
    loading = true;
    try {
      await api.updateTask(
        selectedTask.id,
        editStatus,
        Number(editProgress),
        `MAJ depuis Tableau Tâches (${editStatus}, ${editProgress}%)`,
        editReadme
      );
      await refreshTasks();
      statusMsg = 'Modifications enregistrées.';
    } catch (e: any) {
      statusMsg = e?.message || 'Erreur sauvegarde tâche.';
    } finally {
      loading = false;
    }
  }

  async function deleteSelectedTask() {
    if (!selectedTask) return;
    loading = true;
    try {
      await api.deleteTask(selectedTask.id);
      const deletedId = selectedTask.id;
      cockpitState.tasks = cockpitState.tasks.filter((t) => t.id !== deletedId);
      selectedTask = cockpitState.tasks[0] || null;
      if (selectedTask) selectTask(selectedTask);
      statusMsg = 'Tâche supprimée.';
    } catch (e: any) {
      statusMsg = e?.message || 'Erreur suppression tâche.';
    } finally {
      loading = false;
    }
  }

  function teleportToTaskTarget() {
    if (!selectedTask) return;
    const target = selectedTask.target_symbol || selectedTask.target_file || '';
    const hit = cockpitState.resolveTargetNode(target);
    if (hit) {
      cockpitState.selectSymbol(hit.id, true);
      cockpitState.isTasksModalOpen = false;
    } else if (selectedTask.target_symbol && selectedTask.target_file) {
      const hitFile = cockpitState.resolveTargetNode(selectedTask.target_file);
      if (hitFile) {
        cockpitState.selectSymbol(hitFile.id, true);
        cockpitState.isTasksModalOpen = false;
      }
    }
  }

  function closeModal() {
    cockpitState.isTasksModalOpen = false;
  }

  function formatKindIcon(kind: string) {
    switch (kind) {
      case 'security_fix':
      case 'security':
        return '🛡️';
      case 'arch_refactor':
      case 'refactor':
        return '⚙️';
      case 'function':
        return '⚡';
      case 'research':
      case 'audit':
        return '🔍';
      case 'documentation':
        return '📖';
      case 'test':
        return '🧪';
      default:
        return '📌';
    }
  }

  async function toggleTaskComplete(t: TaskItem, e?: Event) {
    if (e) e.stopPropagation();
    loading = true;
    try {
      const isDone = t.status === 'done';
      const newSt = isDone ? 'pending' : 'done';
      const newProg = isDone ? 0 : 100;
      await api.updateTask(
        t.id,
        newSt,
        newProg,
        isDone ? 'Réouverture de la tâche' : 'Tâche marquée complétée à 100%'
      );
      t.status = newSt as any;
      t.progress = newProg;
      if (selectedTask?.id === t.id) {
        editStatus = newSt as any;
        editProgress = newProg;
      }
      await refreshTasks();
      statusMsg = isDone ? 'Tâche réouverte.' : 'Tâche complétée avec succès !';
    } catch (err: any) {
      statusMsg = err?.message || 'Erreur mise à jour tâche.';
    } finally {
      loading = false;
    }
  }
</script>

{#if cockpitState.isTasksModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-5xl max-h-[86vh] bg-[#090d16] border border-indigo-500/40 rounded-xl shadow-[0_24px_80px_rgba(99,102,241,0.25)] flex flex-col overflow-hidden text-slate-100">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <CheckSquare class="w-5 h-5 text-indigo-400" />
          <h2 class="text-sm font-bold text-white">Tableau des Tâches & Remédiation</h2>
          <span class="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/35 text-[10px] font-mono font-bold">
            {cockpitState.tasks.length} tâches
          </span>
        </div>
        <div class="flex items-center gap-2">
          <button
            type="button"
            onclick={() => (showCreateForm = !showCreateForm)}
            class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-[11px] font-bold text-white cursor-pointer"
          >
            <Plus class="w-3.5 h-3.5" /> Nouvelle Tâche
          </button>
          <button
            type="button"
            onclick={refreshTasks}
            class="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 cursor-pointer"
            title="Actualiser"
          >
            <RefreshCw class="w-4 h-4 {loading ? 'animate-spin' : ''}" />
          </button>
          <button
            type="button"
            onclick={closeModal}
            aria-label="Fermer les tâches"
            class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- Optional New Task Drawer -->
      {#if showCreateForm}
        <div class="p-4 border-b border-white/10 bg-indigo-950/20 space-y-2.5">
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <input
              type="text"
              bind:value={newTitle}
              placeholder="Titre de la tâche (ex: Patcher PATH_JOIN_PREFIX_WIPE)"
              class="sm:col-span-2 px-3 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs text-white focus:outline-none focus:border-indigo-400"
            />
            <div class="flex gap-2">
              <select bind:value={newKind} class="flex-1 px-2 py-1.5 rounded-lg bg-slate-900 border border-white/15 text-xs text-slate-200">
                <option value="security_fix">Security Fix</option>
                <option value="arch_refactor">Arch Refactor</option>
                <option value="function">Function</option>
                <option value="research">Research</option>
                <option value="documentation">Documentation</option>
                <option value="test">Test</option>
                <option value="other">Autre</option>
              </select>
              <select bind:value={newPriority} class="flex-1 px-2 py-1.5 rounded-lg bg-slate-900 border border-white/15 text-xs text-slate-200">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input
              type="text"
              bind:value={newSymbol}
              placeholder="Symbole cible (optionnel)"
              class="px-3 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-200"
            />
            <input
              type="text"
              bind:value={newFile}
              placeholder="Fichier cible (optionnel)"
              class="px-3 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-200"
            />
          </div>
          <textarea
            rows="2"
            bind:value={newReadme}
            placeholder="Spécifications EARS / Détails Markdown..."
            class="w-full px-3 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-200"
          ></textarea>
          <div class="flex justify-end gap-2">
            <button
              type="button"
              onclick={() => (showCreateForm = false)}
              class="px-3 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-xs text-slate-300 cursor-pointer"
            >
              Annuler
            </button>
            <button
              type="button"
              onclick={handleCreateTask}
              disabled={!newTitle.trim() || loading}
              class="px-4 py-1 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
            >
              Créer la Tâche
            </button>
          </div>
        </div>
      {/if}

      <!-- Split View -->
      <div class="flex-1 flex flex-col md:flex-row overflow-hidden min-h-[380px]">
        <!-- Left List -->
        <div class="w-full md:w-80 border-b md:border-b-0 md:border-r border-white/10 flex flex-col bg-black/25 shrink-0 max-h-56 md:max-h-none">
          <div class="flex flex-wrap p-2 gap-1 border-b border-white/10 text-[10px] font-mono">
            {#each (['all', 'pending', 'in_progress', 'blocked', 'done', 'cancelled'] as const) as st}
              <button
                type="button"
                onclick={() => (filterStatus = st)}
                class="px-2 py-1 rounded cursor-pointer {filterStatus === st ? 'bg-indigo-500/25 text-indigo-200 font-bold' : 'text-slate-400 hover:text-white'}"
              >
                {st === 'all' ? 'Toutes' : st === 'pending' ? 'Attente' : st === 'in_progress' ? 'En cours' : st === 'blocked' ? 'Bloquée' : st === 'done' ? 'Fait' : 'Annulée'}
              </button>
            {/each}
          </div>
          <div class="flex-1 overflow-y-auto p-2 space-y-1.5">
            {#if filteredTasks.length === 0}
              <div class="py-12 text-center text-xs text-slate-500 font-mono">
                <Clock class="w-7 h-7 mx-auto mb-2 opacity-50" />
                Aucune tâche dans ce filtre
              </div>
            {:else}
              {#each filteredTasks as t}
                <div
                  role="button"
                  tabindex="0"
                  onclick={() => selectTask(t)}
                  onkeydown={(e) => e.key === 'Enter' && selectTask(t)}
                  class="w-full text-left p-2.5 rounded-lg border transition-colors cursor-pointer {selectedTask?.id === t.id ? 'bg-indigo-500/15 border-indigo-400/50 text-white' : 'bg-white/[0.02] border-white/5 text-slate-300 hover:bg-white/[0.05]'}"
                >
                  <div class="flex items-center justify-between text-[9.5px] font-mono gap-1">
                    <div class="flex items-center gap-1.5 truncate">
                      <button
                        type="button"
                        onclick={(e) => toggleTaskComplete(t, e)}
                        class="p-0.5 rounded hover:bg-white/20 transition-colors shrink-0 {t.status === 'done' ? 'text-emerald-400' : 'text-slate-500 hover:text-emerald-300'}"
                        title={t.status === 'done' ? 'Marquer comme non terminée' : 'Marquer comme terminée (100%)'}
                      >
                        <CheckSquare class="w-3.5 h-3.5 {t.status === 'done' ? 'text-emerald-400' : 'opacity-40'}" />
                      </button>
                      <span class="px-1.5 py-0.5 rounded bg-white/10 uppercase">
                        {formatKindIcon(t.kind)} {t.priority}
                      </span>
                      {#if t.agent_name || t.agent_id}
                        <span
                          class="px-1.5 py-0.5 rounded text-[9px] font-semibold truncate"
                          style="background-color: {t.color || '#38bdf8'}22; color: {t.color || '#38bdf8'}; border: 1px solid {t.color || '#38bdf8'}44;"
                        >
                          🤖 {t.agent_name || t.agent_id}
                        </span>
                      {/if}
                    </div>
                    <span class="shrink-0 font-mono {t.status === 'done' ? 'text-emerald-400 font-bold' : 'text-sky-300'}">{t.progress || 0}%</span>
                  </div>
                  <div class="text-xs font-semibold mt-1 truncate {t.status === 'done' ? 'line-through text-slate-400' : ''}">{t.title}</div>
                  {#if t.readme_summary}
                    <div class="text-[10px] text-slate-400 italic truncate mt-0.5">
                      {t.readme_summary}
                    </div>
                  {/if}
                  {#if t.target_symbol || t.target_file}
                    <div class="text-[10px] font-mono text-slate-500 truncate mt-0.5">
                      🎯 {t.target_symbol || t.target_file}
                    </div>
                  {/if}
                </div>
              {/each}
            {/if}
          </div>
        </div>

        <!-- Right Detail Editor -->
        <div class="flex-1 p-5 overflow-y-auto bg-[#070a12]">
          {#if selectedTask}
            <div class="space-y-4">
              <div class="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <div class="flex items-center gap-1.5 flex-wrap">
                    <span class="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-indigo-500/20 border border-indigo-500/40 text-indigo-300">
                      {selectedTask.kind} • {selectedTask.priority}
                    </span>
                    {#if selectedTask.agent_name || selectedTask.agent_id}
                      <span
                        class="px-2 py-0.5 rounded text-[10px] font-semibold"
                        style="background-color: {selectedTask.color || '#38bdf8'}22; color: {selectedTask.color || '#38bdf8'}; border: 1px solid {selectedTask.color || '#38bdf8'}55;"
                      >
                        🤖 {selectedTask.agent_name || selectedTask.agent_id}
                      </span>
                    {/if}
                  </div>
                  <h3 class="text-base font-bold text-white mt-1.5">{selectedTask.title}</h3>
                  {#if selectedTask.target_symbol || selectedTask.target_file}
                    <p class="text-[11px] font-mono text-sky-400 mt-0.5">
                      🎯 {selectedTask.target_symbol || ''} {selectedTask.target_file ? `(${selectedTask.target_file})` : ''}
                    </p>
                  {/if}
                </div>
                <div class="flex items-center gap-1.5">
                  <button
                    type="button"
                    onclick={() => selectedTask && toggleTaskComplete(selectedTask)}
                    class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-bold cursor-pointer transition-colors {selectedTask.status === 'done' ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40' : 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40'}"
                    title={selectedTask.status === 'done' ? 'Réouvrir la tâche' : 'Marquer comme terminée à 100%'}
                  >
                    <CheckSquare class="w-3.5 h-3.5" />
                    {selectedTask.status === 'done' ? 'Réouvrir (0%)' : '✅ Marquer Terminée (100%)'}
                  </button>
                  {#if selectedTask.target_symbol || selectedTask.target_file}
                    <button
                      type="button"
                      onclick={teleportToTaskTarget}
                      class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/40 text-xs text-sky-200 cursor-pointer"
                    >
                      <Navigation class="w-3.5 h-3.5" /> Téléporter
                    </button>
                  {/if}
                  <button
                    type="button"
                    onclick={deleteSelectedTask}
                    class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/30 border border-rose-500/35 text-xs text-rose-300 cursor-pointer"
                  >
                    <Trash2 class="w-3.5 h-3.5" /> Supprimer
                  </button>
                </div>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/10">
                <div>
                  <label for="task-edit-status" class="block text-[10px] font-mono text-slate-400 mb-1">STATUT</label>
                  <select
                    id="task-edit-status"
                    bind:value={editStatus}
                    class="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-white/15 text-xs text-white"
                  >
                    <option value="pending">pending</option>
                    <option value="in_progress">in_progress</option>
                    <option value="blocked">blocked</option>
                    <option value="done">done</option>
                    <option value="cancelled">cancelled</option>
                  </select>
                </div>
                <div>
                  <label for="task-edit-progress" class="flex justify-between text-[10px] font-mono text-slate-400 mb-1">
                    <span>PROGRESSION</span>
                    <span class="text-emerald-300 font-bold">{editProgress}%</span>
                  </label>
                  <input
                    id="task-edit-progress"
                    type="range"
                    min="0"
                    max="100"
                    step="5"
                    bind:value={editProgress}
                    class="w-full accent-emerald-400 cursor-pointer"
                  />
                </div>
              </div>

              <div>
                <label for="task-edit-readme" class="block text-[10px] font-mono text-slate-400 mb-1">README / NOTES DE REMÉDIATION</label>
                <textarea
                  id="task-edit-readme"
                  rows="8"
                  bind:value={editReadme}
                  class="w-full px-3 py-2 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-400"
                ></textarea>
              </div>

              <div class="flex items-center justify-between">
                <span class="text-[11px] font-mono text-emerald-300">{statusMsg || ''}</span>
                <button
                  type="button"
                  onclick={saveSelectedTask}
                  disabled={loading}
                  class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-bold text-slate-950 cursor-pointer"
                >
                  <Save class="w-3.5 h-3.5" /> Enregistrer Tâche
                </button>
              </div>
            </div>
          {:else}
            <div class="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Sélectionnez une tâche ou cliquez sur « Nouvelle Tâche ».
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
{/if}
