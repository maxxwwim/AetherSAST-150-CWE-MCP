<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { onMount } from 'svelte';
  import {
    FolderGit2,
    RefreshCw,
    Download,
    X,
    Layers,
    Sparkles,
    FolderOpen,
    Hammer,
    CheckCircle2
  } from '@lucide/svelte';

  interface ArchTemplateDef {
    id: 'rust' | 'python' | 'ts' | 'mvc' | 'hybrid' | 'roblox' | 'minecraft';
    icon: string;
    title: string;
    badge: string;
    profile: string;
    recommended: string;
    decoupling: string;
    folders: string[];
    accent: string;
  }

  const ARCHITECTURES: ArchTemplateDef[] = [
    {
      id: 'rust',
      icon: '🦀',
      title: 'Pure Rust',
      badge: 'Zero-Runtime • Critique',
      profile: 'Haute performance, sûreté mémoire absolue, zéro runtime, tolérance aux pannes.',
      recommended: 'Cargo Workspace Hexagonal (contracts/, client/, server/domain, data-nodes/).',
      decoupling: 'Trait RepositoryPort : bascule SQLite local <-> Postgres distant par config.',
      folders: ['contracts/src/lib.rs', 'client/', 'server/domain/src/lib.rs', 'data-nodes/', 'aether.lock.toml'],
      accent: 'border-orange-500/50 bg-orange-950/25',
    },
    {
      id: 'python',
      icon: '🐍',
      title: 'Pure Python (uv)',
      badge: 'FastAPI • Pydantic v2 • IA/ML',
      profile: 'IA, Data Science, APIs rapides, microservices asynchrones & workers ML.',
      recommended: 'Modular Clean Monorepo (uv workspace) avec FastAPI, Pydantic v2 & SQLAlchemy.',
      decoupling: 'Schémas Pydantic v2 dans contracts/ validant les flux client, API et workers.',
      folders: ['contracts/', 'client/', 'server/application/', 'data-nodes/cache-worker', 'aether.lock.toml'],
      accent: 'border-sky-500/50 bg-sky-950/25',
    },
    {
      id: 'ts',
      icon: '🟢',
      title: 'Node.js TypeScript',
      badge: 'pnpm • tRPC/Hono • Zod',
      profile: 'Fullstack temps réel, SaaS web moderne, écosystème riche, vélocité UI maximale.',
      recommended: 'pnpm Workspace orienté Contrats (tRPC / Hono / Zod / Drizzle ou Prisma).',
      decoupling: 'Validation Zod bout-en-bout : data-nodes/db-primary isolable en microservice.',
      folders: ['contracts/', 'client/ui/', 'server/api/', 'data-nodes/db-primary', 'aether.lock.toml'],
      accent: 'border-emerald-500/50 bg-emerald-950/25',
    },
    {
      id: 'mvc',
      icon: '🏛️',
      title: 'Architecture MVC Propre',
      badge: 'Modèle • Vue • Contrôleur',
      profile: 'Applications métier classiques structurées avec frontières strictes MVC + Services.',
      recommended: 'Couches dédiées models/, views/, controllers/, services/ et data-nodes/.',
      decoupling: 'Contrôleurs minces sans logique SQL directe ; persistance isolée dans data-nodes/.',
      folders: ['contracts/', 'client/ui/', 'server/api/', 'server/domain/', 'data-nodes/'],
      accent: 'border-indigo-500/50 bg-indigo-950/25',
    },
    {
      id: 'hybrid',
      icon: '⚡',
      title: 'Hybride Web3 & MMO',
      badge: 'PixiJS/Svelte + Rust WS + EVM',
      profile: 'Mondes virtuels temps réel haute cadence, WebSockets & Smart Contracts EVM.',
      recommended: 'Client Svelte/PixiJS + Serveur Rust Tokio WebSocket + Indexeurs on-chain.',
      decoupling: 'Paquets binaires WS + sync distante (Dissociated Mode) sur nœuds distribués.',
      folders: ['contracts/', 'client/', 'server/', 'data-nodes/', 'AETHER_AI_RULES.md'],
      accent: 'border-purple-500/50 bg-purple-950/25',
    },
    {
      id: 'roblox',
      icon: '🟥',
      title: 'Roblox Game Server',
      badge: 'Luau --!strict • Rojo 7 • Zero-Trust',
      profile: 'Serveurs de jeu Roblox haute cadence, anti-exploit, architecture authoritative.',
      recommended: 'Rojo 7 Monorepo (contracts/, server/, client/, data-nodes/) + ProfileService.',
      decoupling: 'RemoteEvents typés validés serveur uniquement ; Session Locking anti-duplication.',
      folders: ['contracts/', 'server/', 'client/', 'data-nodes/', 'aether.lock.toml'],
      accent: 'border-rose-500/50 bg-rose-950/25',
    },
    {
      id: 'minecraft',
      icon: '⛏️',
      title: 'Aether Minecraft Server',
      badge: 'Paper/Purpur • Runner Tokio + Control-Plane',
      profile: 'Serveurs Minecraft Paper/Purpur, tuning JVM Aikar et contrôleurs automatisés.',
      recommended: 'Runner Tokio + Control-Plane + Contrats Manifest & Plugins.',
      decoupling: 'Spécification Manifest universelle, stockage mondes/joueurs SQLite/MySQL isolé.',
      folders: ['contracts/', 'server/', 'client/', 'data-nodes/', 'aether.lock.toml'],
      accent: 'border-lime-500/50 bg-lime-950/25',
    },
  ];

  let hubTab = $state<'create' | 'manage'>('create');
  let selectedArch = $state<ArchTemplateDef['id']>('rust');
  let topologyMode = $state<'local' | 'dissociated'>('local');
  let parentDir = $state('C:\\Users\\1234\\Desktop\\Projets');
  let newProjName = $state('MonSuperProjet');
  let projectPath = $state(cockpitState.graph.project_path || '.');
  let knownProjects = $state<string[]>([]);
  let isBusy = $state(false);
  let feedback = $state<{ ok: boolean; text: string; dirs?: string[] } | null>(null);

  const selectedTemplate = $derived(
    ARCHITECTURES.find((a) => a.id === selectedArch) || ARCHITECTURES[0]
  );

  const computedNewPath = $derived.by(() => {
    const cleanParent = parentDir.trim().replace(/[\\/]+$/, '') || '.';
    const sep = cleanParent.includes('\\') || /^[A-Za-z]:/.test(cleanParent) ? '\\' : '/';
    const name = newProjName.trim() || 'MonSuperProjet';
    return `${cleanParent}${sep}${name}`;
  });

  onMount(async () => {
    try {
      const res = await api.getProjects();
      if (Array.isArray(res?.projects)) knownProjects = res.projects;
      if (res?.default_project) projectPath = res.default_project;
    } catch {
      // ignore if offline
    }
  });

  $effect(() => {
    if (cockpitState.isHubModalOpen && cockpitState.graph.project_path) {
      projectPath = cockpitState.graph.project_path;
      const cur = cockpitState.graph.project_path;
      const parts = cur.split(/[\\/]/).filter(Boolean);
      if (parts.length > 1) {
        parts.pop();
        const sep = cur.includes('\\') ? '\\' : '/';
        const prefix = cur.startsWith('/') ? '/' : '';
        parentDir = prefix + parts.join(sep);
      }
    }
  });

  async function browseWorkspaceDir() {
    try {
      const res = await api.pickWorkspace();
      if (res?.status === 'ok' && res.workspace) {
        parentDir = res.workspace;
      }
    } catch {
      feedback = { ok: false, text: 'Sélecteur natif indisponible en mode headless — saisissez le chemin.' };
    }
  }

  async function browseAndOpenProject() {
    isBusy = true;
    feedback = null;
    try {
      const res = await api.pickProject();
      if (res?.status === 'ok' && res.graph) {
        cockpitState.setGraph(res.graph);
        cockpitState.requestCameraFit();
        if (res.project_path) projectPath = res.project_path;
        feedback = { ok: true, text: `✅ Projet chargé : ${res.project_path} (${res.graph.nodes.length} nœuds)` };
      }
    } catch {
      feedback = { ok: false, text: 'Sélecteur natif indisponible.' };
    } finally {
      isBusy = false;
    }
  }

  async function forgeNewProject() {
    if (!newProjName.trim()) {
      feedback = { ok: false, text: '⚠️ Veuillez saisir un nom de projet.' };
      return;
    }
    isBusy = true;
    feedback = null;
    const targetPath = computedNewPath;
    try {
      const initRes = await api.initProject(targetPath, selectedArch, topologyMode);
      if (initRes?.status !== 'ok') {
        feedback = { ok: false, text: `❌ Échec scaffolding : ${initRes?.message || 'Erreur'}` };
        return;
      }
      const g = await api.analyzeProject(targetPath, cockpitState.settings.exclusions);
      cockpitState.setGraph(g);
      cockpitState.requestCameraFit();
      projectPath = targetPath;
      feedback = {
        ok: true,
        text: `✨ ${initRes.message} — Analysé (${g.nodes.length} nœuds, ${g.edges.length} flux) !`,
        dirs: initRes.created_dirs,
      };
    } catch (e: any) {
      feedback = { ok: false, text: `❌ Erreur serveur lors du forgeage : ${e?.message || e}` };
    } finally {
      isBusy = false;
    }
  }

  async function rescanProject(overridePath?: string) {
    const target = (overridePath ?? projectPath).trim() || '.';
    projectPath = target;
    isBusy = true;
    feedback = null;
    try {
      const g = await api.analyzeProject(target, cockpitState.settings.exclusions);
      cockpitState.setGraph(g);
      cockpitState.requestCameraFit();
      feedback = { ok: true, text: `✅ Rescan terminé : ${g.nodes.length} nœuds · ${g.edges.length} flux` };
    } catch {
      feedback = { ok: false, text: '❌ Impossible de contacter POST /api/analyze.' };
    } finally {
      isBusy = false;
    }
  }

  async function exportStandalone() {
    isBusy = true;
    feedback = null;
    try {
      const res = await api.exportHtml(projectPath.trim() || undefined);
      feedback = { ok: true, text: `💾 Exporté vers ${res.viewer_path}` };
    } catch {
      feedback = { ok: false, text: '❌ Échec de export HTML (/api/export).' };
    } finally {
      isBusy = false;
    }
  }

  async function switchMode(mode: 'code' | 'vault') {
    cockpitState.viewMode = mode;
    try {
      await api.switchViewMode(mode);
      const g = await api.getGraph();
      cockpitState.setGraph(g);
      cockpitState.requestCameraFit();
      feedback = { ok: true, text: `🔄 Mode ${mode === 'code' ? 'Code Source' : 'Obsidian Vault'} activé` };
    } catch {
      feedback = { ok: false, text: `⚠️ Bascule locale en mode ${mode}` };
    }
  }
</script>

{#if cockpitState.isHubModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && (cockpitState.isHubModalOpen = false)}
    onkeydown={(e) => e.key === 'Escape' && (cockpitState.isHubModalOpen = false)}
  >
    <div class="w-full max-w-4xl max-h-[90vh] bg-[#090d16] border border-sky-500/35 rounded-2xl shadow-[0_24px_80px_rgba(0,0,0,0.85)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <FolderGit2 class="w-5 h-5 text-sky-400" />
          <div>
            <h2 class="text-sm font-bold text-white">
              Hub Multi-Architectures & Création de Projets
            </h2>
            <p class="text-[11px] text-slate-400">
              Forgez une architecture contract-driven parmi 7 stacks définis (Contrats EARS + BLAKE3) ou analysez un workspace existant.
            </p>
          </div>
        </div>
        <button
          onclick={() => (cockpitState.isHubModalOpen = false)}
          aria-label="Fermer le hub projet"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Mode Switcher Tabs -->
      <div class="flex border-b border-white/10 bg-[#0b101b] px-4 gap-2 text-xs font-semibold shrink-0">
        <button
          type="button"
          onclick={() => (hubTab = 'create')}
          class="py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 cursor-pointer {hubTab === 'create' ? 'border-sky-400 text-sky-300' : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <Sparkles class="w-3.5 h-3.5" />
          Forger un Nouveau Projet ({ARCHITECTURES.length} Architectures)
        </button>
        <button
          type="button"
          onclick={() => (hubTab = 'manage')}
          class="py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 cursor-pointer {hubTab === 'manage' ? 'border-emerald-400 text-emerald-300' : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <FolderOpen class="w-3.5 h-3.5" />
          Ouvrir / Scanner / Export HTML
        </button>
      </div>

      <!-- Body -->
      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        {#if hubTab === 'create'}
          <!-- 7 Defined Architectures Grid -->
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {#each ARCHITECTURES as arch}
              {@const active = selectedArch === arch.id}
              <button
                type="button"
                onclick={() => (selectedArch = arch.id)}
                class="text-left p-3 rounded-xl border transition-all cursor-pointer flex flex-col justify-between gap-2 {active
                  ? `${arch.accent} ring-2 ring-sky-400/70`
                  : 'bg-white/[0.025] border-white/10 hover:border-white/25 hover:bg-white/[0.05]'}"
              >
                <div class="space-y-1.5">
                  <div class="flex items-center justify-between gap-1.5">
                    <span class="font-bold text-xs text-white flex items-center gap-1.5">
                      <span class="text-base">{arch.icon}</span>
                      {arch.title}
                    </span>
                    {#if active}
                      <CheckCircle2 class="w-4 h-4 text-sky-400 shrink-0" />
                    {/if}
                  </div>
                  <div class="inline-block px-1.5 py-0.5 rounded bg-black/45 border border-white/10 font-mono text-[9.5px] text-sky-300">
                    {arch.badge}
                  </div>
                  <p class="text-[11px] text-slate-300 leading-snug">{arch.profile}</p>
                </div>
                <div class="text-[10px] text-slate-400 border-t border-white/10 pt-1.5 leading-snug">
                  <strong class="text-slate-200">Structure :</strong> {arch.recommended}
                </div>
              </button>
            {/each}
          </div>

          <!-- Selected Architecture Decoupling & Generated Files Preview -->
          <div class="p-3 rounded-xl bg-sky-950/20 border border-sky-500/25 space-y-2 text-xs">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span class="font-bold text-sky-200">
                {selectedTemplate.icon} Découplage & Modules Forgés ({selectedTemplate.title})
              </span>
              <div class="flex items-center gap-1.5 text-[10.5px]">
                <span class="text-slate-400">Topologie :</span>
                <button
                  type="button"
                  onclick={() => (topologyMode = 'local')}
                  class="px-2 py-0.5 rounded border cursor-pointer {topologyMode === 'local' ? 'bg-sky-500/25 border-sky-400 text-sky-200' : 'bg-black/30 border-white/10 text-slate-400'}"
                >
                  Monorepo Local
                </button>
                <button
                  type="button"
                  onclick={() => (topologyMode = 'dissociated')}
                  class="px-2 py-0.5 rounded border cursor-pointer {topologyMode === 'dissociated' ? 'bg-purple-500/25 border-purple-400 text-purple-200' : 'bg-black/30 border-white/10 text-slate-400'}"
                >
                  Distribué / Dissocié
                </button>
              </div>
            </div>
            <div class="text-[11px] text-slate-300">🔒 {selectedTemplate.decoupling}</div>
            <div class="flex flex-wrap gap-1.5 pt-0.5">
              {#each selectedTemplate.folders as f}
                <span class="px-2 py-0.5 rounded bg-black/50 border border-white/10 font-mono text-[10px] text-emerald-300">
                  {f}
                </span>
              {/each}
            </div>
          </div>

          <!-- Destination Form -->
          <div class="p-4 rounded-xl bg-white/[0.03] border border-white/10 space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="space-y-1">
                <label for="forge-parent-dir" class="text-[11px] font-semibold text-slate-300">
                  📁 Dossier Racine de Destination
                </label>
                <div class="flex gap-1.5">
                  <input
                    id="forge-parent-dir"
                    type="text"
                    bind:value={parentDir}
                    class="flex-1 px-2.5 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-white focus:outline-none focus:border-sky-400"
                  />
                  <button
                    type="button"
                    onclick={browseWorkspaceDir}
                    class="px-2.5 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 border border-white/15 text-[11px] font-semibold text-slate-200 cursor-pointer shrink-0"
                  >
                    Parcourir
                  </button>
                </div>
              </div>
              <div class="space-y-1">
                <label for="forge-proj-name" class="text-[11px] font-semibold text-slate-300">
                  🏷️ Nom du Nouveau Projet
                </label>
                <input
                  id="forge-proj-name"
                  type="text"
                  bind:value={newProjName}
                  placeholder="Ex: NeoHotel, CryptoRaptor, FastApiApp"
                  class="w-full px-2.5 py-1.5 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-white focus:outline-none focus:border-sky-400"
                />
              </div>
            </div>

            <div class="flex flex-wrap items-center justify-between gap-3 pt-1">
              <div class="text-[10.5px] font-mono text-slate-400 truncate max-w-md">
                Cible : <span class="text-sky-300">{computedNewPath}</span>
              </div>
              <button
                type="button"
                disabled={isBusy}
                onclick={forgeNewProject}
                class="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-purple-600 hover:from-sky-400 hover:to-purple-500 disabled:opacity-50 text-xs font-extrabold text-white shadow-lg cursor-pointer"
              >
                <Hammer class="w-4 h-4 {isBusy ? 'animate-spin' : ''}" />
                <span>Forger l'Architecture & Entrer dans le Cockpit</span>
              </button>
            </div>
          </div>
        {:else}
          <!-- Existing Workspace Scanner / Picker / Dual-Vision / Export -->
          <div class="space-y-4">
            <div class="space-y-1.5">
              <div class="flex items-center justify-between">
                <label for="hub-project-path" class="text-xs font-semibold text-slate-300">Chemin du Projet / Workspace</label>
                <button
                  type="button"
                  disabled={isBusy}
                  onclick={browseAndOpenProject}
                  class="text-[11px] text-sky-300 hover:text-sky-200 font-semibold cursor-pointer flex items-center gap-1"
                >
                  <FolderOpen class="w-3.5 h-3.5" /> Choisir via explorateur
                </button>
              </div>
              <div class="flex gap-2">
                <input
                  id="hub-project-path"
                  type="text"
                  bind:value={projectPath}
                  class="flex-1 px-3 py-2 rounded-lg bg-black/45 border border-white/15 text-xs font-mono text-white focus:outline-none focus:border-sky-400"
                />
                <button
                  type="button"
                  disabled={isBusy}
                  onclick={() => rescanProject()}
                  class="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
                >
                  <RefreshCw class="w-3.5 h-3.5 {isBusy ? 'animate-spin' : ''}" />
                  <span>Analyser</span>
                </button>
              </div>
            </div>

            {#if knownProjects.length > 0}
              <div class="space-y-1.5">
                <div class="text-[11px] font-semibold text-slate-400">Workspaces Détectés ({knownProjects.length})</div>
                <div class="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                  {#each knownProjects as p}
                    <button
                      type="button"
                      onclick={() => rescanProject(p)}
                      class="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-sky-500/20 border border-white/10 hover:border-sky-400/50 font-mono text-[10.5px] text-slate-200 cursor-pointer"
                    >
                      📂 {p}
                    </button>
                  {/each}
                </div>
              </div>
            {/if}

            <div class="p-3.5 rounded-xl bg-white/[0.025] border border-white/10 space-y-2">
              <div class="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Layers class="w-3.5 h-3.5 text-sky-400" />
                <span>Mode de Graphe Dual-Vision</span>
              </div>
              <div class="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onclick={() => switchMode('code')}
                  class="py-2 rounded-lg border text-xs font-semibold cursor-pointer {cockpitState.viewMode === 'code' ? 'bg-sky-500/20 border-sky-400 text-sky-200' : 'bg-black/30 border-white/10 text-slate-400 hover:text-white'}"
                >
                  💻 Code Source & AST
                </button>
                <button
                  type="button"
                  onclick={() => switchMode('vault')}
                  class="py-2 rounded-lg border text-xs font-semibold cursor-pointer {cockpitState.viewMode === 'vault' ? 'bg-emerald-500/20 border-emerald-400 text-emerald-200' : 'bg-black/30 border-white/10 text-slate-400 hover:text-white'}"
                >
                  🧠 Obsidian Vault & Notes
                </button>
              </div>
            </div>

            <button
              type="button"
              disabled={isBusy}
              onclick={exportStandalone}
              class="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-semibold text-slate-200 cursor-pointer"
            >
              <Download class="w-4 h-4 text-amber-400" />
              <span>Exporter aetherscope_viewer.html Autonome</span>
            </button>
          </div>
        {/if}

        {#if feedback}
          <div
            class="px-3.5 py-2.5 rounded-xl border text-xs font-mono space-y-1 {feedback.ok
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/40 border-rose-500/40 text-rose-200'}"
          >
            <div>{feedback.text}</div>
            {#if feedback.dirs && feedback.dirs.length > 0}
              <div class="text-[10px] text-emerald-300/80">
                Dossiers créés : {feedback.dirs.join(', ')}
              </div>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}
