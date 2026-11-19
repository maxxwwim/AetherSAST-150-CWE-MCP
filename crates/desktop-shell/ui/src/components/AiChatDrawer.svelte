<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { onMount } from 'svelte';
  import {
    Bot,
    MessageSquare,
    Send,
    Plug,
    Trash2,
    X,
    Minimize2,
    Maximize2,
    StopCircle,
    Sparkles,
    Compass,
    Terminal,
    Copy,
    Check,
    RotateCcw,
    ChevronDown,
    Activity
  } from '@lucide/svelte';

  let subTab = $state<'chat' | 'agents'>('chat');
  let inputText = $state('');
  let sending = $state(false);
  let minimized = $state(false);
  let agentsHudOpen = $state(false);
  let agentsHudEl = $state<HTMLDivElement | null>(null);
  let collapsedThoughts = $state<Record<string, boolean>>({});
  let copiedMsgId = $state<string | null>(null);
  let cliFeedback = $state('');
  let chatBodyEl = $state<HTMLDivElement | null>(null);

  function handleAgentsHudOutsidePointer(e: PointerEvent) {
    if (!agentsHudOpen) return;
    if (agentsHudEl && !agentsHudEl.contains(e.target as Node)) {
      agentsHudOpen = false;
    }
  }

  function handleAgentsHudKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && agentsHudOpen) {
      agentsHudOpen = false;
    }
  }

  // Draggable window offset (relative to default bottom-4 right-4 anchor)
  let dragOffset = $state<{ x: number; y: number }>({ x: 0, y: 0 });
  let isDraggingWindow = $state(false);
  let dragStartPointer = { x: 0, y: 0 };
  let dragStartOffset = { x: 0, y: 0 };

  function onHeaderPointerDown(e: PointerEvent) {
    if ((e.target as HTMLElement)?.closest('button')) return;
    isDraggingWindow = true;
    dragStartPointer = { x: e.clientX, y: e.clientY };
    dragStartOffset = { ...dragOffset };
    window.addEventListener('pointermove', onWindowPointerMove);
    window.addEventListener('pointerup', onWindowPointerUp);
  }

  function onWindowPointerMove(e: PointerEvent) {
    if (!isDraggingWindow) return;
    const dx = e.clientX - dragStartPointer.x;
    const dy = e.clientY - dragStartPointer.y;
    dragOffset = {
      x: Math.max(-window.innerWidth + 140, Math.min(80, dragStartOffset.x + dx)),
      y: Math.max(-window.innerHeight + 100, Math.min(80, dragStartOffset.y + dy)),
    };
  }

  function onWindowPointerUp() {
    isDraggingWindow = false;
    window.removeEventListener('pointermove', onWindowPointerMove);
    window.removeEventListener('pointerup', onWindowPointerUp);
  }

  function resetWindowPosition() {
    dragOffset = { x: 0, y: 0 };
  }

  function scrollToBottom() {
    if (chatBodyEl) {
      requestAnimationFrame(() => {
        if (chatBodyEl) chatBodyEl.scrollTop = chatBodyEl.scrollHeight;
      });
    }
  }

  async function pollAiState() {
    try {
      const [telemRes, chatRes] = await Promise.all([
        api.getTelemetry().catch(() => null),
        api.getChatHistory().catch(() => null),
      ]);
      if (telemRes) {
        cockpitState.recordAiTelemetry(telemRes.telemetry as any, telemRes.agents ?? [], telemRes.history);
      } else {
        cockpitState.pruneInactiveAgents();
      }
      if (chatRes && Array.isArray(chatRes.messages)) {
        const prevLen = cockpitState.aiChatMessages.length;
        cockpitState.aiChatMessages = chatRes.messages;
        cockpitState.aiAgentStatus = (chatRes.agent_status as 'ready' | 'thinking' | 'idle') || 'ready';
        if (chatRes.messages.length > prevLen && subTab === 'chat') {
          scrollToBottom();
        }
      }
      cockpitState.mcpConnected = true;
    } catch {
      cockpitState.mcpConnected = false;
    }
  }

  onMount(() => {
    pollAiState();
    const timer = setInterval(pollAiState, 1500);
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (e.key.toLowerCase() === 'c' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        cockpitState.isChatOpen = !cockpitState.isChatOpen;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      clearInterval(timer);
      window.removeEventListener('keydown', onKey);
    };
  });

  function formatTime(ts?: number): string {
    if (!ts) return '';
    const ms = ts < 10_000_000_000 ? ts * 1000 : ts;
    return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function parseMessageBody(raw: string): { thought: string; body: string } {
    const match = raw.match(/<(?:thought|thinking)>([\s\S]*?)<\/(?:thought|thinking)>/i);
    if (!match) return { thought: '', body: raw };
    return {
      thought: match[1].trim(),
      body: raw.replace(/<(?:thought|thinking)>[\s\S]*?<\/(?:thought|thinking)>/i, '').trim(),
    };
  }

  async function sendMessage(overrideText?: string) {
    const text = (overrideText ?? inputText).trim();
    if (!text || sending) return;
    if (!overrideText) inputText = '';
    sending = true;
    const targetSym = cockpitState.activeSymbol?.name || cockpitState.selectedFolder || undefined;
    try {
      const res = await api.sendChatMessage(text, 'user', targetSym);
      if (res?.status === 'ok') {
        cockpitState.aiAgentStatus = 'thinking';
        await pollAiState();
        scrollToBottom();
      }
    } finally {
      sending = false;
    }
  }

  async function clearChat() {
    await api.clearChatHistory().catch(() => {});
    cockpitState.aiChatMessages = [];
    cockpitState.aiAgentStatus = 'ready';
  }

  async function cancelAi() {
    await api.cancelAi().catch(() => {});
    await pollAiState();
  }

  async function newSession() {
    await api.newAiSession().catch(() => {});
    cockpitState.aiChatMessages = [];
    cockpitState.clearAiTrail();
    cockpitState.aiAgentStatus = 'ready';
  }

  async function launchAgentCli(tool: 'gemini' | 'claude' | 'codex') {
    const target = cockpitState.activeSymbol?.name || cockpitState.selectedFolder || 'Codebase';
    const projPath = cockpitState.graph.project_path || '.';
    const res = await api
      .launchCli(
        tool,
        projPath,
        `Analyse ${target} dans AetherScope (${projPath}) via MCP aetherscope_get_active_target.`
      )
      .catch(() => null);
    cliFeedback = res?.message || `Session agent ${tool} initialisée pour ${target}`;
    await api
      .teleportCamera(target, `Agent ${tool.toUpperCase()}`, `Session CLI lancée sur ${target}`)
      .catch(() => {});
    await pollAiState();
    setTimeout(() => (cliFeedback = ''), 3500);
  }

  function focusSymbolByName(name?: string | null) {
    if (!name) return;
    const lower = name.toLowerCase();
    const hit = cockpitState.graph.nodes.find(
      (n) =>
        n.name.toLowerCase() === lower ||
        n.id.toLowerCase() === lower ||
        (n.file_path && n.file_path.toLowerCase().includes(lower))
    );
    if (hit) {
      cockpitState.selectSymbol(hit.id, true);
    }
  }

  async function simulateSwarmAgents() {
    const nodes = cockpitState.graph.nodes;
    const targets = [
      nodes.find((n) => n.has_security_violation)?.name || nodes[0]?.name || 'installer.rs',
      nodes.find((n) => n.layer === 'ui')?.name || nodes[1]?.name || 'HeaderDeck.svelte',
      nodes.find((n) => n.layer === 'domain')?.name || nodes[2]?.name || 'main.rs',
    ];
    await Promise.all([
      api.teleportCamera(targets[0], 'Audit CWE', 'Vérification taint SAST en parallèle', {
        agent_id: 'agent-sec',
        agent_name: 'Claude-Sec',
        color: '#f472b6',
      }),
      api.teleportCamera(targets[1], 'UI Organique', 'Inspection composants réactifs', {
        agent_id: 'agent-ui',
        agent_name: 'Gemini-UI',
        color: '#38bdf8',
      }),
      api.teleportCamera(targets[2], 'Flux Domaine', 'Validation contrats EARS & AST', {
        agent_id: 'agent-arch',
        agent_name: 'Cursor-Arch',
        color: '#34d399',
      }),
    ]).catch(() => {});
    await pollAiState();
  }

  async function clearAllAgentsTelemetry() {
    await api.clearTelemetry().catch(() => {});
    cockpitState.clearAiTrail();
  }

  function copyForMcpAgent(id: string, text: string, target?: string | null) {
    const sym = target || cockpitState.activeSymbol?.name || 'Codebase';
    const payload = `Dans AetherScope (${cockpitState.graph.project_path || '.'}) [Cible: ${sym}]:\n${text}\n\nOutils MCP : aetherscope_get_active_target({"symbol_id": "${sym}"}) -> aetherscope_verify_patch(...)`;
    navigator.clipboard?.writeText(payload);
    copiedMsgId = id;
    setTimeout(() => (copiedMsgId = null), 1500);
  }
</script>

<svelte:window onpointerdown={handleAgentsHudOutsidePointer} onkeydown={handleAgentsHudKeydown} />

<!-- Left-Edge Compact Collapsible Multi-Agent IA Dock (Sous Docs/EARS, zéro encombrement au centre) -->
{#if cockpitState.activeAgents.length > 0 && !cockpitState.isDocPanelOpen && cockpitState.viewMode !== 'ide'}
  <div
    bind:this={agentsHudEl}
    class="fixed left-3 top-[94px] z-30 flex flex-col items-start gap-1.5 select-none pointer-events-auto"
  >
    <!-- Compact Toggle Pill -->
    <div class="flex items-center rounded-lg bg-[#0b0f19]/92 backdrop-blur-md border border-purple-500/35 shadow-xl overflow-hidden">
      <button
        type="button"
        onclick={() => (agentsHudOpen = !agentsHudOpen)}
        aria-expanded={agentsHudOpen}
        title={agentsHudOpen
          ? 'Replier la liste des agents IA'
          : `Agents IA actifs (${cockpitState.activeAgents.length}) : ${cockpitState.activeAgents.map((a) => a.agentName + (a.target ? ' → ' + a.target : '')).join(' • ')}`}
        class="flex items-center gap-1.5 px-2.5 py-1.5 hover:bg-purple-500/15 text-[11px] font-semibold text-purple-100 transition-colors cursor-pointer"
      >
        <span class="relative flex h-2 w-2 shrink-0">
          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
          <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
        </span>
        <Bot class="w-3.5 h-3.5 text-purple-300 shrink-0" />
        <span class="font-mono font-bold text-[10.5px]">{cockpitState.activeAgents.length} IA</span>
        <span class="flex items-center -space-x-0.5 ml-0.5">
          {#each cockpitState.activeAgents.slice(0, 4) as ag (ag.agentId)}
            <span
              class="w-2 h-2 rounded-full ring-1 ring-[#0b0f19]"
              style="background-color: {ag.color}"
              title="{ag.agentName}{ag.target ? ` → ${ag.target}` : ''}"
            ></span>
          {/each}
        </span>
        <ChevronDown class="w-3 h-3 text-slate-400 transition-transform duration-150 {agentsHudOpen ? 'rotate-180' : ''}" />
      </button>

      <div class="w-px h-4 bg-white/10"></div>

      <button
        type="button"
        onclick={() => {
          subTab = 'agents';
          cockpitState.isChatOpen = true;
          agentsHudOpen = false;
        }}
        title="Ouvrir le suivi Copilot IA & Agents (Touche C)"
        class="px-2 py-1.5 text-purple-300 hover:text-white hover:bg-purple-500/20 transition-colors cursor-pointer"
      >
        <MessageSquare class="w-3 h-3" />
      </button>
    </div>

    <!-- Expanded Compact Left-Aligned Agents Popover -->
    {#if agentsHudOpen}
      <div class="w-[268px] max-w-[calc(100vw-24px)] rounded-xl bg-[#0b0e18]/96 backdrop-blur-xl border border-purple-500/35 shadow-[0_14px_38px_rgba(0,0,0,0.65)] overflow-hidden text-[11px]">
        <div class="px-2.5 py-1.5 bg-[#130d24]/90 border-b border-white/10 flex items-center justify-between gap-2">
          <span class="flex items-center gap-1.5 text-[10px] font-bold text-purple-200 uppercase tracking-wider">
            <Activity class="w-3 h-3 text-emerald-400" />
            Agents IA ({cockpitState.activeAgents.length})
          </span>
          <div class="flex items-center gap-1">
            <button
              type="button"
              onclick={() => {
                subTab = 'chat';
                cockpitState.isChatOpen = true;
                agentsHudOpen = false;
              }}
              class="px-1.5 py-0.5 rounded bg-purple-600/30 hover:bg-purple-600/50 border border-purple-400/30 text-purple-100 text-[9.5px] font-semibold cursor-pointer transition-colors"
              title="Ouvrir le Chat IA"
            >
              Chat
            </button>
            <button
              type="button"
              onclick={async () => {
                agentsHudOpen = false;
                await clearAllAgentsTelemetry();
              }}
              class="p-1 rounded text-slate-400 hover:text-rose-300 hover:bg-rose-500/10 cursor-pointer transition-colors"
              title="Réinitialiser télémétrie agents"
            >
              <Trash2 class="w-3 h-3" />
            </button>
          </div>
        </div>

        <div class="p-1.5 space-y-1 max-h-64 overflow-y-auto">
          {#each cockpitState.activeAgents as ag (ag.agentId)}
            <button
              type="button"
              onclick={() => {
                focusSymbolByName(ag.target);
                agentsHudOpen = false;
              }}
              class="w-full text-left px-2 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.08] border border-white/[0.06] hover:border-purple-400/35 transition-colors cursor-pointer flex flex-col gap-0.5"
              title="{ag.agentName} • {ag.action}: {ag.details}"
            >
              <div class="flex items-center justify-between gap-1.5">
                <span class="flex items-center gap-1.5 min-w-0">
                  <span class="w-2 h-2 rounded-full shrink-0" style="background-color: {ag.color}"></span>
                  <span class="font-bold text-slate-100 truncate">{ag.agentName}</span>
                </span>
                {#if ag.target}
                  <span class="px-1.5 py-0.2 rounded bg-black/50 border border-white/10 font-mono text-[9.5px] text-sky-300 truncate max-w-[115px] shrink-0">
                    ➔ {ag.target}
                  </span>
                {/if}
              </div>
              {#if ag.action || ag.details}
                <div class="text-[9.5px] text-slate-400 truncate pl-3.5">
                  {ag.action}{ag.details ? ` — ${ag.details}` : ''}
                </div>
              {/if}
            </button>
          {/each}
        </div>
      </div>
    {/if}
  </div>
{/if}

<!-- Bouton Flottant Chat IA (dégagé au-dessus du Radar / Zoom, sans jamais chevaucher le footer ni le Radar) -->
{#if !cockpitState.isChatOpen && !cockpitState.isInspectorOpen && cockpitState.viewMode !== 'ide'}
  <button
    type="button"
    onclick={() => (cockpitState.isChatOpen = true)}
    class="fixed right-4 {cockpitState.showRadar ? 'bottom-[192px]' : 'bottom-[88px]'} z-30 flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#130d24]/92 hover:bg-purple-600/90 text-white font-semibold text-[11px] shadow-[0_8px_24px_rgba(147,51,234,0.38)] border border-purple-400/45 backdrop-blur-xl transition-all duration-200 hover:scale-105 active:scale-95 cursor-pointer group"
    title="Ouvrir le Chat IA & Copilot (Touche C)"
  >
    <div class="relative">
      <Bot class="w-4 h-4 text-purple-300 group-hover:rotate-12 transition-transform" />
      {#if cockpitState.activeAgents.length > 0}
        <span class="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
        <span class="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-emerald-400"></span>
      {/if}
    </div>
    <span class="tracking-wide">Chat IA</span>
    {#if cockpitState.activeAgents.length > 0}
      <span class="px-1.5 py-0.2 rounded-full bg-emerald-500/25 border border-emerald-400/40 text-emerald-300 font-mono text-[10px] font-bold">
        {cockpitState.activeAgents.length}
      </span>
    {:else if cockpitState.aiChatMessages.length > 0}
      <span class="px-1.5 py-0.2 rounded-full bg-purple-500/30 border border-purple-400/40 text-purple-200 font-mono text-[10px]">
        {cockpitState.aiChatMessages.length}
      </span>
    {/if}
  </button>
{/if}

<!-- Draggable / Floating AI Chat, Agents & MCP Hub -->
{#if cockpitState.isChatOpen}
  <aside
    aria-label="Copilot IA, Agents & MCP"
    style="transform: translate3d({dragOffset.x}px, {dragOffset.y}px, 0);"
    class="fixed bottom-4 right-4 z-40 w-[400px] max-w-[95vw] {minimized ? 'h-11' : 'h-[500px] max-h-[80vh]'} bg-[#0b0e18]/96 backdrop-blur-2xl border border-purple-500/35 rounded-2xl shadow-[0_20px_60px_rgba(88,28,135,0.45)] flex flex-col overflow-hidden {isDraggingWindow ? '' : 'transition-all'}"
  >
    <!-- Header (Draggable Handle) -->
    <div
      onpointerdown={onHeaderPointerDown}
      role="toolbar"
      tabindex="-1"
      title="Glisser pour déplacer la fenêtre Copilot IA"
      class="px-3 py-2 border-b border-white/10 bg-[#120d22] flex items-center justify-between gap-2 shrink-0 cursor-move select-none"
    >
      <div class="flex items-center gap-2 min-w-0">
        <Bot class="w-4 h-4 text-purple-400 shrink-0" />
        <span class="text-xs font-bold text-white truncate">Copilot IA & Agents</span>
        <span
          class="px-1.5 py-0.5 rounded-full text-[9.5px] font-mono border {cockpitState.aiAgentStatus === 'thinking'
            ? 'bg-amber-500/20 border-amber-400/40 text-amber-200'
            : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'}"
        >
          {cockpitState.aiAgentStatus === 'thinking' ? '⚡ Réflexion' : '🟢 Prêt'}
        </span>
      </div>

      <div class="flex items-center gap-1 shrink-0">
        {#if dragOffset.x !== 0 || dragOffset.y !== 0}
          <button
            type="button"
            onclick={resetWindowPosition}
            class="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[9px] font-mono text-slate-300 cursor-pointer"
            title="Réinitialiser la position de la fenêtre"
          >
            Ancrer
          </button>
        {/if}
        <button
          type="button"
          onclick={() => (cockpitState.isMcpModalOpen = true)}
          class="px-1.5 py-0.5 rounded bg-sky-500/15 hover:bg-sky-500/30 border border-sky-500/35 text-sky-300 text-[10px] font-mono cursor-pointer flex items-center gap-1"
          title="Configurer le serveur MCP (Antigravity, Claude, Cursor)"
        >
          <Plug class="w-3 h-3" /> MCP
        </button>
        <button
          type="button"
          onclick={newSession}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
          title="Nouvelle session IA"
        >
          <RotateCcw class="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onclick={clearChat}
          class="p-1 rounded text-slate-400 hover:text-rose-300 hover:bg-white/10 cursor-pointer"
          title="Vider le journal chat"
        >
          <Trash2 class="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onclick={() => (minimized = !minimized)}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
          title={minimized ? 'Agrandir' : 'Réduire'}
        >
          {#if minimized}
            <Maximize2 class="w-3.5 h-3.5" />
          {:else}
            <Minimize2 class="w-3.5 h-3.5" />
          {/if}
        </button>
        <button
          type="button"
          onclick={() => (cockpitState.isChatOpen = false)}
          class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
          title="Fermer (C)"
        >
          <X class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>

    {#if !minimized}
      <!-- Sub-tabs: Chat vs Agents & Trajectoire -->
      <div class="flex border-b border-white/10 bg-[#0d111a] text-[11px] font-medium px-2 gap-1 shrink-0">
        <button
          type="button"
          onclick={() => (subTab = 'chat')}
          class="flex-1 py-1.5 border-b-2 transition-colors cursor-pointer flex items-center justify-center gap-1.5 {subTab === 'chat' ? 'border-purple-400 text-purple-200' : 'border-transparent text-slate-400 hover:text-slate-200'}"
        >
          <MessageSquare class="w-3.5 h-3.5" />
          Chat IA ({cockpitState.aiChatMessages.length})
        </button>
        <button
          type="button"
          onclick={() => (subTab = 'agents')}
          class="flex-1 py-1.5 border-b-2 transition-colors cursor-pointer flex items-center justify-center gap-1.5 {subTab === 'agents' ? 'border-sky-400 text-sky-200' : 'border-transparent text-slate-400 hover:text-slate-200'}"
        >
          <Activity class="w-3.5 h-3.5" />
          Agents & MCP ({cockpitState.aiTrail.length})
        </button>
      </div>

      {#if subTab === 'chat'}
        <!-- Quick Contextual Chips -->
        <div class="px-2.5 py-1.5 border-b border-white/5 bg-white/[0.02] flex flex-wrap gap-1 shrink-0">
          <button
            type="button"
            onclick={() =>
              sendMessage(
                `Audit sécurité CWE & flux critiques sur ${cockpitState.activeSymbol?.name || cockpitState.selectedFolder || 'le projet'}`
              )}
            class="px-2 py-0.5 rounded-full bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-200 text-[10px] cursor-pointer"
          >
            🚨 Auditer CWE
          </button>
          <button
            type="button"
            onclick={() =>
              sendMessage(
                `Expliquer l'architecture et les appels de ${cockpitState.activeSymbol?.name || cockpitState.selectedFolder || 'ce module'}`
              )}
            class="px-2 py-0.5 rounded-full bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-200 text-[10px] cursor-pointer"
          >
            🗺️ Tracer Flux
          </button>
          <button
            type="button"
            onclick={() =>
              sendMessage(
                `Proposer un refactoring EARS propre pour ${cockpitState.activeSymbol?.name || 'la cible active'}`
              )}
            class="px-2 py-0.5 rounded-full bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-200 text-[10px] cursor-pointer"
          >
            ✨ Refactor EARS
          </button>
        </div>

        <!-- Messages -->
        <div bind:this={chatBodyEl} class="flex-1 overflow-y-auto p-3 space-y-2.5 text-xs select-text">
          {#if cockpitState.aiChatMessages.length === 0}
            <div class="text-center py-10 space-y-2 text-slate-400">
              <Sparkles class="w-6 h-6 text-purple-400 mx-auto opacity-75" />
              <div class="font-semibold text-slate-300">Journal Chat IA & Pont MCP Live</div>
              <p class="text-[11px] leading-relaxed max-w-xs mx-auto">
                Envoyez une question ci-dessous ou laissez votre agent Antigravity / Claude / Cursor poster via <code class="text-sky-300">aetherscope_chat</code>.
              </p>
            </div>
          {:else}
            {#each cockpitState.aiChatMessages as msg (msg.id)}
              {@const isUser = msg.sender === 'user'}
              {@const parsed = parseMessageBody(msg.text || '')}
              {@const badgeColor = msg.color || (isUser ? '#c084fc' : '#38bdf8')}
              {@const senderTitle = isUser ? '👤 Vous' : `🤖 ${msg.agent_name || msg.agent_id || (msg.sender && msg.sender !== 'ai' ? msg.sender : 'Copilot MCP')}`}
              <div
                class="p-2.5 rounded-xl border space-y-1.5 {isUser
                  ? 'bg-purple-950/35 border-purple-500/35 ml-5'
                  : 'bg-[#0f172a]/90 border-sky-500/30 mr-4'}"
                style={!isUser && msg.color ? `border-color: ${msg.color}55` : undefined}
              >
                <div class="flex items-center justify-between gap-2 text-[10px]">
                  <div class="flex items-center gap-1.5 min-w-0 flex-wrap">
                    <span class="font-bold flex items-center gap-1" style="color: {badgeColor}">
                      {#if !isUser}
                        <span class="w-1.5 h-1.5 rounded-full shrink-0" style="background-color: {badgeColor}"></span>
                      {/if}
                      {senderTitle}
                    </span>
                    {#if msg.recipient}
                      <span class="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-400/30 text-emerald-200 font-mono text-[9px]">
                        ➔ @{msg.recipient}
                      </span>
                    {/if}
                    {#if msg.target_symbol}
                      <button
                        type="button"
                        onclick={() => focusSymbolByName(msg.target_symbol)}
                        class="px-1.5 py-0.5 rounded bg-white/10 hover:bg-sky-500/25 text-slate-200 font-mono truncate max-w-[130px] cursor-pointer"
                      >
                        📍 {msg.target_symbol}
                      </button>
                    {/if}
                  </div>
                  <div class="flex items-center gap-1.5 shrink-0">
                    {#if isUser}
                      <button
                        type="button"
                        onclick={() => copyForMcpAgent(msg.id, parsed.body, msg.target_symbol)}
                        class="px-1.5 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/35 text-purple-200 font-mono text-[9.5px] cursor-pointer flex items-center gap-1"
                        title="Copier avec commandes MCP pour Antigravity"
                      >
                        {#if copiedMsgId === msg.id}
                          <Check class="w-2.5 h-2.5 text-emerald-300" />
                        {:else}
                          <Copy class="w-2.5 h-2.5" />
                        {/if}
                        MCP
                      </button>
                    {/if}
                    <span class="text-slate-500 font-mono">{formatTime(msg.timestamp)}</span>
                  </div>
                </div>

                {#if parsed.thought}
                  <div class="rounded-lg bg-black/40 border border-purple-500/25 overflow-hidden">
                    <button
                      type="button"
                      onclick={() => (collapsedThoughts[msg.id] = !collapsedThoughts[msg.id])}
                      class="w-full px-2 py-1 flex items-center justify-between text-[10px] text-purple-300 hover:bg-white/5 cursor-pointer"
                    >
                      <span>🧠 Réflexion interne agent</span>
                      <ChevronDown class="w-3 h-3 transition-transform {collapsedThoughts[msg.id] ? '-rotate-90' : ''}" />
                    </button>
                    {#if !collapsedThoughts[msg.id]}
                      <div class="px-2 pb-1.5 text-[10.5px] text-slate-400 font-mono whitespace-pre-wrap leading-snug">
                        {parsed.thought}
                      </div>
                    {/if}
                  </div>
                {/if}

                <div class="text-[11.5px] text-slate-100 whitespace-pre-wrap leading-relaxed">
                  {parsed.body}
                </div>
              </div>
            {/each}
          {/if}
        </div>

        <!-- Input Bar & Footer -->
        <div class="p-2.5 border-t border-white/10 bg-[#0d111a] space-y-1.5 shrink-0">
          <div class="flex gap-1.5">
            <input
              type="text"
              bind:value={inputText}
              onkeydown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  sendMessage();
                }
              }}
              placeholder="Demander une analyse, CWE, ou patch MCP..."
              class="flex-1 bg-black/45 border border-white/15 focus:border-purple-400/60 rounded-lg px-2.5 py-1.5 text-xs text-white placeholder:text-slate-500 focus:outline-none"
            />
            <button
              type="button"
              onclick={() => sendMessage()}
              disabled={sending || !inputText.trim()}
              class="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-45 text-white text-xs font-semibold flex items-center gap-1 cursor-pointer"
            >
              <Send class="w-3.5 h-3.5" />
            </button>
          </div>
          <div class="flex items-center justify-between text-[10px] text-slate-400">
            <button
              type="button"
              onclick={() => (cockpitState.settings.aiAutoCam = !cockpitState.settings.aiAutoCam)}
              class="flex items-center gap-1 cursor-pointer hover:text-slate-200"
            >
              <Compass class="w-3 h-3 {cockpitState.settings.aiAutoCam ? 'text-emerald-400' : 'text-slate-500'}" />
              Auto-Cam: {cockpitState.settings.aiAutoCam ? 'ON' : 'OFF'}
            </button>
            {#if cockpitState.aiAgentStatus === 'thinking'}
              <button
                type="button"
                onclick={cancelAi}
                class="flex items-center gap-1 text-rose-300 hover:text-rose-200 cursor-pointer"
              >
                <StopCircle class="w-3 h-3" /> Annuler
              </button>
            {:else}
              <span>Raccourci: <kbd class="px-1 rounded bg-white/10 font-mono">C</kbd></span>
            {/if}
          </div>
        </div>
      {:else}
        <!-- Agents, Multi-Agent Swarm, CLI Launcher & Live Trajectory -->
        <div class="flex-1 overflow-y-auto p-3 space-y-3 text-xs">
          <!-- Simultaneous Active Agents Registry -->
          <div class="p-2.5 rounded-xl bg-white/[0.03] border border-white/10 space-y-2">
            <div class="flex items-center justify-between gap-2">
              <span class="text-[11px] font-bold text-slate-200 uppercase tracking-wider">
                Agents Simultanés ({cockpitState.activeAgents.length})
              </span>
              <div class="flex items-center gap-1.5">
                <button
                  type="button"
                  onclick={simulateSwarmAgents}
                  class="px-2 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/35 border border-purple-400/40 text-purple-200 text-[10px] font-semibold cursor-pointer"
                  title="Tester 3 agents simultanés sur le graphe"
                >
                  🚀 Tester Essaim (3x)
                </button>
                <span class="px-1.5 py-0.5 rounded text-[9.5px] font-mono {cockpitState.mcpConnected ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}">
                  {cockpitState.mcpConnected ? '● MCP OK' : '○ Off'}
                </span>
              </div>
            </div>

            {#if cockpitState.activeAgents.length > 0}
              <div class="space-y-1.5">
                {#each cockpitState.activeAgents as ag (ag.agentId)}
                  <button
                    type="button"
                    onclick={() => focusSymbolByName(ag.target)}
                    class="w-full text-left p-2 rounded-lg bg-black/40 hover:bg-white/[0.06] border transition-colors cursor-pointer space-y-0.5"
                    style="border-color: {ag.color}55"
                  >
                    <div class="flex items-center justify-between gap-2">
                      <span class="flex items-center gap-1.5 font-bold text-[11px] text-white">
                        <span class="w-2.5 h-2.5 rounded-full shrink-0" style="background-color: {ag.color}"></span>
                        {ag.agentName}
                      </span>
                      <span class="text-[9.5px] font-mono px-1.5 py-0.5 rounded bg-white/10 text-sky-200">
                        {ag.action}
                      </span>
                    </div>
                    <div class="text-[10.5px] font-mono text-slate-300 truncate">
                      📍 {ag.target} {ag.details ? `— ${ag.details}` : ''}
                    </div>
                  </button>
                {/each}
              </div>
            {:else}
              <div class="p-3 rounded-lg bg-black/30 border border-white/5 text-center text-slate-400 text-[10.5px]">
                En attente d'activité MCP / CLI. Plusieurs agents peuvent se connecter simultanément avec des identités et couleurs distinctes.
              </div>
            {/if}

            <div class="grid grid-cols-2 gap-1.5 text-[10.5px]">
              <div class="p-2 rounded-lg bg-black/35 border border-sky-500/25">
                <div class="font-bold text-sky-300">🪐 Antigravity MCP</div>
                <div class="text-slate-400 text-[10px]">10 outils • multi-agent_id</div>
              </div>
              <div class="p-2 rounded-lg bg-black/35 border border-purple-500/25">
                <div class="font-bold text-purple-300">⚡ FileWatcher Live</div>
                <div class="text-slate-400 text-[10px]">{cockpitState.graph.nodes.length} nœuds sync</div>
              </div>
            </div>

            <!-- Launch CLI Agent Helper -->
            <div class="pt-1 space-y-1">
              <div class="text-[10px] text-slate-400 font-semibold">Initialiser un Agent CLI sur la cible :</div>
              <div class="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onclick={() => launchAgentCli('gemini')}
                  class="px-2 py-1 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/35 text-sky-200 text-[10.5px] font-medium flex items-center gap-1 cursor-pointer"
                >
                  <Terminal class="w-3 h-3" /> Gemini CLI
                </button>
                <button
                  type="button"
                  onclick={() => launchAgentCli('claude')}
                  class="px-2 py-1 rounded bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/35 text-purple-200 text-[10.5px] font-medium flex items-center gap-1 cursor-pointer"
                >
                  <Terminal class="w-3 h-3" /> Claude Code
                </button>
                <button
                  type="button"
                  onclick={() => (cockpitState.isMcpModalOpen = true)}
                  class="px-2 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/35 text-emerald-200 text-[10.5px] font-medium flex items-center gap-1 cursor-pointer"
                >
                  <Plug class="w-3 h-3" /> Config MCP
                </button>
              </div>
              {#if cliFeedback}
                <div class="text-[10px] text-emerald-300 font-mono">{cliFeedback}</div>
              {/if}
            </div>
          </div>

          <!-- Trajectory History -->
          <div class="space-y-1.5">
            <div class="flex items-center justify-between">
              <span class="text-[11px] font-bold text-slate-300 uppercase tracking-wider">
                Trajectoire Stellaire IA ({cockpitState.aiTrail.length})
              </span>
              {#if cockpitState.aiTrail.length > 0}
                <button
                  type="button"
                  onclick={() => cockpitState.clearAiTrail()}
                  class="text-[10px] text-slate-400 hover:text-rose-300 cursor-pointer"
                >
                  🧹 Effacer tracé
                </button>
              {/if}
            </div>

            {#if cockpitState.aiTrail.length === 0}
              <div class="p-4 rounded-xl bg-white/[0.02] border border-white/10 text-center text-[11px] text-slate-400">
                Aucun déplacement enregistré pour cette session. Appelez <code class="text-sky-300">aetherscope_teleport_camera</code> ou connectez un agent MCP.
              </div>
            {:else}
              <div class="space-y-1.5">
                {#each [...cockpitState.aiTrail].reverse() as step}
                  <button
                    type="button"
                    onclick={() => focusSymbolByName(step.target)}
                    class="w-full text-left p-2 rounded-lg bg-black/35 hover:bg-white/[0.05] border transition-colors cursor-pointer space-y-1"
                    style="border-color: {step.color ? step.color + '44' : 'rgba(255,255,255,0.1)'}"
                  >
                    <div class="flex items-center justify-between gap-1.5">
                      <div class="flex items-center gap-1.5 truncate">
                        <span class="w-2 h-2 rounded-full shrink-0" style="background-color: {step.color || '#a855f7'}"></span>
                        {#if step.agentName}
                          <span
                            class="px-1.5 py-0.2 rounded text-[9px] font-semibold truncate"
                            style="background-color: {step.color || '#a855f7'}22; color: {step.color || '#a855f7'}; border: 1px solid {step.color || '#a855f7'}44;"
                          >
                            🤖 {step.agentName}
                          </span>
                        {/if}
                        <span class="font-mono font-bold text-white text-[10.5px] truncate">📍 {step.target}</span>
                      </div>
                      <span class="text-[9px] font-mono text-sky-300 shrink-0">{step.action}</span>
                    </div>
                    {#if step.details}
                      <div class="text-[10px] text-slate-400 truncate pl-3.5">{step.details}</div>
                    {/if}
                  </button>
                {/each}
              </div>
            {/if}
          </div>
        </div>
      {/if}
    {/if}
  </aside>
{/if}
