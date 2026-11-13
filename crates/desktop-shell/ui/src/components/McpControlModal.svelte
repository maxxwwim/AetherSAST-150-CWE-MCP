<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import {
    Plug,
    X,
    Copy,
    Check,
    Play,
    Terminal,
    Activity,
    Cpu,
    ShieldCheck
  } from '@lucide/svelte';

  let clientTab = $state<'antigravity' | 'claude' | 'cursor' | 'http'>('antigravity');
  let copied = $state(false);
  let testOutput = $state('');
  let testingTool = $state('');

  const serverPort = $derived(
    typeof window !== 'undefined' && window.location.port ? window.location.port : '3333'
  );

  const clientPathHint = $derived(
    clientTab === 'antigravity'
      ? '~/.gemini/config/mcp_config.json (Google Antigravity MCP)'
      : clientTab === 'claude'
        ? '%APPDATA%\\Claude\\claude_desktop_config.json (Claude Desktop)'
        : clientTab === 'cursor'
          ? '.cursor/mcp.json (Cursor / Windsurf IDE)'
          : `http://127.0.0.1:${serverPort}/api/* (Pont REST Local Sans-Shell)`
  );

  const configSnippet = $derived.by(() => {
    const bin = cockpitState.settings.mcpBinaryPath || 'aetherscope-mcp.exe';
    if (clientTab === 'http') {
      return `# Test rapide Pont Télémétrie & Caméra 3D :\ncurl -X POST http://127.0.0.1:${serverPort}/api/ai/telemetry \\\n  -H "Content-Type: application/json" \\\n  -d '{"target":"${cockpitState.activeSymbol?.name || 'main'}","action":"Inspect","details":"Vérification pont MCP"}'\n\n# Envoyer un message au Chat IA :\ncurl -X POST http://127.0.0.1:${serverPort}/api/ai/chat \\\n  -H "Content-Type: application/json" \\\n  -d '{"sender":"ai","text":"Audit prêt","target_symbol":"${cockpitState.activeSymbol?.name || 'main'}"}'`;
    }
    return JSON.stringify(
      {
        mcpServers: {
          aetherscope: {
            command: bin,
            args: ['--port', serverPort, '--path', cockpitState.graph.project_path || '.'],
          },
        },
      },
      null,
      2
    );
  });

  const MCP_TOOLS = [
    { name: 'aetherscope_get_graph_summary', desc: 'Cartographie AST globale + Tâches + Alertes SAST (4-en-1)' },
    { name: 'aetherscope_get_active_target', desc: 'Caméra 3D + Contrat EARS + Trace MVC entrante/sortante' },
    { name: 'aetherscope_search_symbols', desc: 'Recherche sémantique AST + filtre CWE/couche' },
    { name: 'aetherscope_manage_tasks', desc: 'Créer, suivre et clôturer les tâches avec Mini-README' },
    { name: 'aetherscope_verify_patch', desc: 'Pare-Feu architectural <50ms + Tâche + Chat (4-en-1)' },
    { name: 'aetherscope_chat', desc: 'Lire/écrire dans le Chat Copilot & diriger la caméra' },
    { name: 'aetherscope_manage_plugins', desc: 'Lister, tester et déployer des règles SAST YAML custom' },
    { name: 'aetherscope_teleport_camera', desc: 'Téléporter la caméra 3D et le faisceau agent sur un nœud' },
    { name: 'aetherscope_scan_project', desc: 'Re-scanner le workspace à chaud' },
    { name: 'aetherscope_switch_view_mode', desc: 'Basculer entre Galaxie Code Source et Vault Obsidian' },
  ];

  function copySnippet() {
    navigator.clipboard?.writeText(configSnippet);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  async function testTelemetryBridge() {
    testingTool = 'teleport';
    const targetNode = cockpitState.activeSymbol || cockpitState.graph.nodes[0];
    const targetName = targetNode?.name || 'AetherScope';
    try {
      const res = await api.teleportCamera(
        targetName,
        'Antigravity MCP',
        `Synchronisation live depuis le Module MCP sur ${targetName}`,
        { agent_id: 'antigravity-mcp', agent_name: 'Antigravity MCP', color: '#38bdf8' }
      );
      if (res?.status === 'ok') {
        const tRes = await api.getTelemetry();
        if (tRes?.agents?.length || tRes?.telemetry) {
          cockpitState.recordAiTelemetry(tRes.telemetry as any, tRes.agents);
        }
        testOutput = `✅ Signal MCP envoyé et capté pour "${targetName}". Caméra + trajectoire mises à jour !`;
      } else {
        testOutput = '⚠️ Réponse inattendue du serveur.';
      }
    } catch (e: any) {
      testOutput = `❌ Erreur pont MCP : ${e?.message || e}`;
    } finally {
      testingTool = '';
    }
  }

  async function testChatBridge() {
    testingTool = 'chat';
    const targetName = cockpitState.activeSymbol?.name || cockpitState.graph.project_name || 'AetherScope';
    try {
      await api.sendChatMessage(
        `[Bridge MCP] Agent prêt sur **${targetName}** (${cockpitState.graph.nodes.length} nœuds, ${cockpitState.allViolations.length} alertes CWE).`,
        'ai',
        targetName
      );
      const chatRes = await api.getChatHistory();
      if (chatRes?.messages) cockpitState.aiChatMessages = chatRes.messages;
      cockpitState.isChatOpen = true;
      testOutput = `✅ Message agent injecté dans le Chat IA (${cockpitState.aiChatMessages.length} msg).`;
    } catch (e: any) {
      testOutput = `❌ Erreur chat MCP : ${e?.message || e}`;
    } finally {
      testingTool = '';
    }
  }
</script>

{#if cockpitState.isMcpModalOpen}
  <div
    class="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    aria-label="Module MCP IA & Bridge Agents"
  >
    <div class="w-full max-w-3xl max-h-[88vh] bg-[#0b0e18] border border-sky-500/35 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-xs">
      <!-- Header -->
      <div class="px-4 py-3 border-b border-white/10 bg-[#0e1424] flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <div class="p-1.5 rounded-lg bg-sky-500/15 border border-sky-500/35 text-sky-300">
            <Plug class="w-4 h-4" />
          </div>
          <div>
            <h2 class="text-sm font-bold text-white flex items-center gap-2">
              Module MCP IA & Orchestration Agents
              <span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 border border-emerald-500/40 text-emerald-300">
                ● Port :{serverPort} Actif
              </span>
            </h2>
            <p class="text-[11px] text-slate-400">
              Connectez Antigravity, Claude Desktop ou Cursor au graphe AST via Model Context Protocol (stdio + REST).
            </p>
          </div>
        </div>
        <button
          type="button"
          onclick={() => (cockpitState.isMcpModalOpen = false)}
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Body -->
      <div class="flex-1 overflow-y-auto p-4 space-y-4">
        <!-- Quick Bridge Diagnostics & Binary Config -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10 space-y-1">
            <div class="text-[10px] font-mono text-slate-400 flex items-center gap-1">
              <Cpu class="w-3 h-3 text-sky-400" /> BINAIRE MCP
            </div>
            <input
              type="text"
              bind:value={cockpitState.settings.mcpBinaryPath}
              onchange={() => cockpitState.saveLocalSettings()}
              class="w-full bg-black/50 border border-white/15 rounded px-2 py-1 text-[11px] font-mono text-sky-200 focus:outline-none focus:border-sky-400"
            />
          </div>
          <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10 flex flex-col justify-between gap-2">
            <div class="text-[10px] font-mono text-slate-400 flex items-center gap-1">
              <Activity class="w-3 h-3 text-purple-400" /> TEST TÉLÉMÉTRIE & CHAT
            </div>
            <div class="flex gap-1.5">
              <button
                type="button"
                onclick={testTelemetryBridge}
                disabled={testingTool !== ''}
                class="flex-1 py-1 px-2 rounded bg-purple-500/20 hover:bg-purple-500/35 border border-purple-500/40 text-purple-200 text-[10.5px] font-semibold flex items-center justify-center gap-1 cursor-pointer"
              >
                <Play class="w-3 h-3" /> Téléporter Agent
              </button>
              <button
                type="button"
                onclick={testChatBridge}
                disabled={testingTool !== ''}
                class="flex-1 py-1 px-2 rounded bg-sky-500/20 hover:bg-sky-500/35 border border-sky-500/40 text-sky-200 text-[10.5px] font-semibold flex items-center justify-center gap-1 cursor-pointer"
              >
                <Terminal class="w-3 h-3" /> Ping Chat
              </button>
            </div>
          </div>
          <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10 space-y-1">
            <div class="text-[10px] font-mono text-slate-400 flex items-center gap-1">
              <ShieldCheck class="w-3 h-3 text-emerald-400" /> PARE-FEU ARCHITECTURAL
            </div>
            <div class="text-[11px] text-slate-200">
              <span class="font-bold text-emerald-300">{cockpitState.graph.nodes.length}</span> symboles ·{' '}
              <span class="font-bold text-rose-300">{cockpitState.allViolations.length}</span> CWE indexés
            </div>
          </div>
        </div>

        {#if testOutput}
          <div class="px-3 py-2 rounded-lg bg-emerald-950/45 border border-emerald-500/40 text-emerald-200 font-mono text-[11px]">
            {testOutput}
          </div>
        {/if}

        <!-- Client Tabs & JSON Config -->
        <div class="space-y-2">
          <div class="flex flex-wrap gap-1.5">
            <button
              type="button"
              onclick={() => (clientTab = 'antigravity')}
              class="px-2.5 py-1 rounded-lg border text-[11px] font-semibold cursor-pointer {clientTab === 'antigravity' ? 'bg-sky-500/20 border-sky-400 text-sky-200' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
            >
              🪐 Antigravity
            </button>
            <button
              type="button"
              onclick={() => (clientTab = 'claude')}
              class="px-2.5 py-1 rounded-lg border text-[11px] font-semibold cursor-pointer {clientTab === 'claude' ? 'bg-purple-500/20 border-purple-400 text-purple-200' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
            >
              🤖 Claude Desktop
            </button>
            <button
              type="button"
              onclick={() => (clientTab = 'cursor')}
              class="px-2.5 py-1 rounded-lg border text-[11px] font-semibold cursor-pointer {clientTab === 'cursor' ? 'bg-amber-500/20 border-amber-400 text-amber-200' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
            >
              ⚡ Cursor / Windsurf
            </button>
            <button
              type="button"
              onclick={() => (clientTab = 'http')}
              class="px-2.5 py-1 rounded-lg border text-[11px] font-semibold cursor-pointer {clientTab === 'http' ? 'bg-emerald-500/20 border-emerald-400 text-emerald-200' : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'}"
            >
              🌐 REST API Sans-Shell
            </button>
          </div>

          <div class="flex items-center justify-between text-[10.5px] font-mono text-slate-400">
            <span>Fichier cible : <strong class="text-slate-200">{clientPathHint}</strong></span>
            <button
              type="button"
              onclick={copySnippet}
              class="px-2.5 py-1 rounded bg-sky-500/20 hover:bg-sky-500/35 border border-sky-500/40 text-sky-200 font-semibold flex items-center gap-1 cursor-pointer"
            >
              {#if copied}
                <Check class="w-3.5 h-3.5 text-emerald-300" /> Copié !
              {:else}
                <Copy class="w-3.5 h-3.5" /> Copier Config
              {/if}
            </button>
          </div>

          <pre class="p-3 rounded-xl bg-black/75 border border-white/10 text-[11px] font-mono text-sky-100 overflow-x-auto leading-relaxed select-text">{configSnippet}</pre>
        </div>

        <!-- 10 Unified MCP Tools Directory -->
        <div class="space-y-2">
          <div class="text-[11px] font-bold uppercase tracking-wider text-slate-300">
            Protocole Unifié — 10 Outils MCP AetherScope V2
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-1.5">
            {#each MCP_TOOLS as tool}
              <div class="p-2 rounded-lg bg-white/[0.02] border border-white/10">
                <div class="font-mono font-bold text-[10.5px] text-sky-300">{tool.name}</div>
                <div class="text-[10.5px] text-slate-400">{tool.desc}</div>
              </div>
            {/each}
          </div>
        </div>
      </div>
    </div>
  </div>
{/if}
