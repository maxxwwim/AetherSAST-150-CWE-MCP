<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { Sparkles, Copy, Check, X, Terminal, FileCode2, PlugZap } from 'lucide-svelte';

  let taskMode = $state<'refactor' | 'security' | 'tests' | 'docs' | 'audit'>('refactor');
  let targetKind = $state<'symbol' | 'folder'>('symbol');
  let blueprintModel = $state<'claude' | 'gemini' | 'openai'>('claude');
  let mcpClient = $state<'antigravity' | 'claude' | 'cursor'>('antigravity');
  let serverSystemPrompt = $state('');
  let copied = $state(false);

  $effect(() => {
    if (cockpitState.isPromptModalOpen && !serverSystemPrompt) {
      if (cockpitState.graph.system_prompt) {
        serverSystemPrompt = cockpitState.graph.system_prompt;
      } else {
        api
          .getSystemPrompt()
          .then((res) => {
            if (res?.system_prompt) serverSystemPrompt = res.system_prompt;
          })
          .catch(() => {});
      }
    }
  });

  const targetNode = $derived(cockpitState.activeSymbol || cockpitState.graph.nodes[0] || null);
  const targetFolder = $derived(cockpitState.selectedFolder || targetNode?.folder || targetNode?.cluster_id || 'root');

  const contextualPrompt = $derived.by(() => {
    const project = cockpitState.graph.project_name || 'AetherScope';
    const custom = cockpitState.settings.aiCustomPrompt.trim();
    const customSection = custom ? `\n## Directives Utilisateur\n${custom}\n` : '';

    const taskGoals: Record<typeof taskMode, string> = {
      refactor: 'Refactoriser proprement pour éliminer le couplage excessif, réduire la complexité cyclomatique et préserver tous les invariants.',
      security: 'Auditer et corriger toutes les vulnérabilités SAST/CWE (taint flow, injections, contrôles d’accès) sans régression.',
      tests: 'Générer une suite complète de tests unitaires et d’intégration couvrant les cas limites et les chemins critiques.',
      docs: 'Rédiger la spécification EARS (Ubiquitous / Event-Driven / Unwanted Behavior) et documenter les contrats publics.',
      audit: 'Réaliser une revue complète : goulots de performance, code mort, dettes d’architecture et couverture de tests.',
    };

    if (targetKind === 'folder') {
      const folderNodes = cockpitState.graph.nodes.filter(
        (n) => (n.folder || n.cluster_id || 'root') === targetFolder
      );
      const vulns = folderNodes.flatMap((n) => [...(n.anomalies || []), ...(n.violations || [])]);
      return `<context>
  <project name="${project}" />
  <target_folder name="${targetFolder}" total_symbols="${folderNodes.length}" violations="${vulns.length}" />
</context>

# Mission : ${taskGoals[taskMode]}

## Fichiers & Symboles principaux du module
${folderNodes
  .slice(0, 20)
  .map((n) => `- ${n.name} (${n.kind}, layer=${n.layer}, loc=${n.loc}, CC=${n.cyclomatic_complexity}) — ${n.file_path}:${n.line_number}`)
  .join('\n')}
${vulns.length > 0 ? `\n## Alertes SAST détectées\n${vulns.slice(0, 10).map((v) => `- [${v.severity}] ${v.cve_id || v.cwe_class} — ${v.title || v.description}`).join('\n')}` : ''}
${customSection}
Propose un plan concis puis applique directement les modifications vérifiables.`;
    }

    if (!targetNode) {
      return `Sélectionnez un symbole ou un dossier dans le graphe pour générer un prompt contextuel ciblé.`;
    }

    const inbound = cockpitState.graph.edges
      .filter((e) => e.target === targetNode.id)
      .slice(0, 12)
      .map((e) => e.source);
    const outbound = cockpitState.graph.edges
      .filter((e) => e.source === targetNode.id)
      .slice(0, 12)
      .map((e) => e.target);
    const vulns = [...(targetNode.anomalies || []), ...(targetNode.violations || [])];

    return `<context>
  <project name="${project}" />
  <symbol id="${targetNode.id}" name="${targetNode.name}" kind="${targetNode.kind}" layer="${targetNode.layer}" />
  <location file="${targetNode.file_path}" line="${targetNode.line_number}" loc="${targetNode.loc}" complexity="${targetNode.cyclomatic_complexity}" />
</context>

# Mission : ${taskGoals[taskMode]}

## Topologie des Dépendances
- **Appelants (In-Degree ${targetNode.in_degree})** : ${inbound.join(', ') || 'Aucun'}
- **Dépendances (Out-Degree ${targetNode.out_degree})** : ${outbound.join(', ') || 'Aucune'}
${vulns.length > 0 ? `\n## Failles CWE sur ce symbole\n${vulns.map((v) => `- [${v.severity}] ${v.cve_id}: ${v.title || v.description}`).join('\n')}` : ''}
${customSection}
Inspecte d'abord \`${targetNode.file_path}\` autour de la ligne ${targetNode.line_number}, valide les impacts sur les appelants ci-dessus, puis implémente et teste.`;
  });

  const masterBlueprintPrompt = $derived.by(() => {
    const project = cockpitState.graph.project_name || 'AetherScope';
    const modelLabel =
      blueprintModel === 'claude'
        ? 'Claude Sonnet / Opus'
        : blueprintModel === 'gemini'
          ? 'Google Gemini Pro / Flash'
          : 'OpenAI GPT-4o / o1';

    return `# 🚀 MASTER BLUEPRINT ARCHITECTURE — ${project}
# Modèle cible : ${modelLabel}
# Cartographie temps réel : AetherScope V2 (${cockpitState.graph.nodes.length} nœuds · ${cockpitState.graph.edges.length} flux)

Tu es l'Architecte Logiciel Principal sur **${project}**.
Applique strictement une approche **Spec-Driven Modulaire** :

1. **Frontières de Couches (Clean / Hexagonal)** : aucune dépendance I/O directe dans \`domain/\`.
2. **Spécification EARS avant modification** : pour chaque changement non trivial, vérifier les invariants et pré-conditions.
3. **Zero-Trust & SAST Clean** : zéro secret en dur (CWE-798), aucune requête SQL/Shell non paramétrée, validation stricte aux frontières.
4. **Budget & Lisibilité** : privilégier des fonctions courtes, cohésives, sans duplication ni effet de bord caché.
${cockpitState.settings.aiCustomPrompt.trim() ? `\n### Directives Additionnelles Projet\n${cockpitState.settings.aiCustomPrompt.trim()}\n` : ''}
Commence par analyser les zones à plus forte complexité et les éventuelles violations via MCP AetherScope avant d'éditer.`;
  });

  const mcpSnippet = $derived.by(() => {
    const port = typeof window !== 'undefined' && window.location.port ? window.location.port : '3030';
    return JSON.stringify(
      {
        mcpServers: {
          aetherscope: {
            command: cockpitState.settings.mcpBinaryPath || 'aetherscope-mcp.exe',
            args: ['--port', port],
          },
        },
      },
      null,
      2
    );
  });

  const mcpFileTarget = $derived(
    mcpClient === 'antigravity'
      ? '~/.gemini/config/mcp_config.json (Antigravity MCP Settings)'
      : mcpClient === 'claude'
        ? '%APPDATA%\\Claude\\claude_desktop_config.json'
        : '.cursor/mcp.json (Paramètres Cursor > MCP)'
  );

  const activeText = $derived.by(() => {
    if (cockpitState.promptModalTab === 'context') return contextualPrompt;
    if (cockpitState.promptModalTab === 'master') return masterBlueprintPrompt;
    if (cockpitState.promptModalTab === 'sysprompt') {
      return serverSystemPrompt || cockpitState.graph.system_prompt || masterBlueprintPrompt;
    }
    return mcpSnippet;
  });

  function copyActive() {
    navigator.clipboard?.writeText(activeText);
    copied = true;
    setTimeout(() => (copied = false), 1800);
  }

  function closeModal() {
    cockpitState.isPromptModalOpen = false;
  }
</script>

{#if cockpitState.isPromptModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-4xl max-h-[88vh] bg-[#090d16] border border-purple-500/40 rounded-xl shadow-[0_24px_80px_rgba(168,85,247,0.22)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <Sparkles class="w-5 h-5 text-purple-400" />
          <div>
            <h2 class="text-sm font-bold text-white">Studio Prompts IA & Pont MCP Zero-Shell</h2>
            <p class="text-[11px] text-slate-400">Génération contextuelle AST, Master Blueprint Architecture & Configuration MCP</p>
          </div>
        </div>
        <button
          onclick={closeModal}
          aria-label="Fermer le générateur de prompts"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Tabs -->
      <div class="px-5 pt-3 flex items-center gap-2 border-b border-white/10 bg-black/20 flex-wrap">
        <button
          type="button"
          onclick={() => (cockpitState.promptModalTab = 'context')}
          class="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold border-b-2 transition-colors cursor-pointer {cockpitState.promptModalTab === 'context' ? 'border-purple-400 text-purple-300' : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <FileCode2 class="w-3.5 h-3.5" />
          <span>Prompt Contextuel</span>
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.promptModalTab = 'master')}
          class="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold border-b-2 transition-colors cursor-pointer {cockpitState.promptModalTab === 'master' ? 'border-sky-400 text-sky-300' : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <Sparkles class="w-3.5 h-3.5" />
          <span>Master Blueprint</span>
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.promptModalTab = 'sysprompt')}
          class="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold border-b-2 transition-colors cursor-pointer {cockpitState.promptModalTab === 'sysprompt' ? 'border-emerald-400 text-emerald-300' : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <Terminal class="w-3.5 h-3.5" />
          <span>Directives Système</span>
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.promptModalTab = 'mcp')}
          class="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold border-b-2 transition-colors cursor-pointer {cockpitState.promptModalTab === 'mcp' ? 'border-amber-400 text-amber-300' : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <PlugZap class="w-3.5 h-3.5" />
          <span>Config MCP</span>
        </button>
      </div>

      <!-- Controls bar per tab -->
      <div class="px-5 py-2.5 bg-white/[0.02] border-b border-white/10 flex items-center justify-between flex-wrap gap-2">
        {#if cockpitState.promptModalTab === 'context'}
          <div class="flex items-center gap-2 flex-wrap">
            <div class="flex rounded-lg bg-black/40 border border-white/10 p-0.5 text-[11px]">
              <button
                type="button"
                onclick={() => (targetKind = 'symbol')}
                class="px-2.5 py-1 rounded cursor-pointer {targetKind === 'symbol' ? 'bg-purple-500/25 text-purple-200 font-semibold' : 'text-slate-400'}"
              >
                Symbole ({targetNode?.name || '—'})
              </button>
              <button
                type="button"
                onclick={() => (targetKind = 'folder')}
                class="px-2.5 py-1 rounded cursor-pointer {targetKind === 'folder' ? 'bg-purple-500/25 text-purple-200 font-semibold' : 'text-slate-400'}"
              >
                Dossier ({targetFolder})
              </button>
            </div>

            <div class="flex gap-1">
              {#each [
                { k: 'refactor', label: 'Refactor' },
                { k: 'security', label: 'Sécurité CWE' },
                { k: 'tests', label: 'Tests' },
                { k: 'docs', label: 'Doc EARS' },
                { k: 'audit', label: 'Audit' }
              ] as t}
                <button
                  type="button"
                  onclick={() => (taskMode = t.k as typeof taskMode)}
                  class="px-2.5 py-1 rounded-md text-[11px] border cursor-pointer {taskMode === t.k ? 'bg-sky-500/20 border-sky-400/50 text-sky-200 font-semibold' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
                >
                  {t.label}
                </button>
              {/each}
            </div>
          </div>
        {:else if cockpitState.promptModalTab === 'master'}
          <div class="flex items-center gap-2 text-xs">
            <span class="text-slate-400">Optimisé pour :</span>
            {#each ['claude', 'gemini', 'openai'] as m}
              <button
                type="button"
                onclick={() => (blueprintModel = m as typeof blueprintModel)}
                class="px-2.5 py-1 rounded border text-[11px] uppercase font-mono cursor-pointer {blueprintModel === m ? 'bg-sky-500/20 border-sky-400 text-sky-300 font-bold' : 'bg-white/5 border-white/10 text-slate-400'}"
              >
                {m}
              </button>
            {/each}
          </div>
        {:else if cockpitState.promptModalTab === 'mcp'}
          <div class="flex items-center justify-between w-full flex-wrap gap-2">
            <div class="flex gap-1.5">
              {#each ['antigravity', 'claude', 'cursor'] as client}
                <button
                  type="button"
                  onclick={() => (mcpClient = client as typeof mcpClient)}
                  class="px-2.5 py-1 rounded border text-[11px] capitalize cursor-pointer {mcpClient === client ? 'bg-amber-500/20 border-amber-400 text-amber-200 font-semibold' : 'bg-white/5 border-white/10 text-slate-400'}"
                >
                  {client}
                </button>
              {/each}
            </div>
            <span class="text-[11px] font-mono text-amber-300">{mcpFileTarget}</span>
          </div>
        {:else}
          <span class="text-[11px] font-mono text-emerald-300">Directives système générées par l'analyseur Rust du projet</span>
        {/if}

        <button
          type="button"
          onclick={copyActive}
          class="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-purple-500 hover:bg-purple-400 text-xs font-bold text-slate-950 transition-colors cursor-pointer"
        >
          {#if copied}
            <Check class="w-3.5 h-3.5" />
            <span>Copié !</span>
          {:else}
            <Copy class="w-3.5 h-3.5" />
            <span>Copier</span>
          {/if}
        </button>
      </div>

      <!-- Preview textarea -->
      <div class="flex-1 p-5 overflow-hidden flex flex-col">
        <textarea
          readonly
          value={activeText}
          class="w-full flex-1 min-h-[340px] rounded-xl bg-black/50 border border-white/10 p-4 text-xs font-mono text-slate-200 leading-relaxed focus:outline-none resize-none"
        ></textarea>
      </div>
    </div>
  </div>
{/if}
