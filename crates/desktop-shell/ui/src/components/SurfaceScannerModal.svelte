<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { Radar, Play, X, Globe, Server, ShieldAlert, FileWarning, BookmarkCheck, GitCompareArrows, Copy, Check } from '@lucide/svelte';

  let target = $state('127.0.0.1');
  let scanLevel = $state<1 | 2 | 3 | 4>(3);
  let customPorts = $state('');
  let checkDns = $state(true);
  let checkPorts = $state(true);
  let checkHeaders = $state(true);
  let checkEndpoints = $state(true);
  let checkWebForms = $state(true);
  let checkSensitiveFiles = $state(true);
  let isScanning = $state(false);
  let errorMsg = $state<string | null>(null);
  let report = $state<any>(null);
  let baseline = $state<{ target: string; score: number; openPorts: number; findings: number; savedAt: string } | null>(null);
  let surfacePromptTab = $state<'arch' | 'hardening' | 'weakness'>('arch');
  let promptCopied = $state(false);

  $effect(() => {
    if (cockpitState.isSurfaceScannerOpen && typeof localStorage !== 'undefined') {
      try {
        const raw = localStorage.getItem('aetherscope_surface_baseline');
        if (raw) baseline = JSON.parse(raw);
      } catch {
        // ignore invalid baseline JSON
      }
    }
  });

  function saveBaselineSnapshot() {
    if (!report) return;
    const snap = {
      target: target.trim(),
      score: Number(report.security_score ?? 0),
      openPorts: (report.open_ports || []).filter((p: any) => p.open).length,
      findings: (report.findings || []).length,
      savedAt: new Date().toLocaleTimeString(),
    };
    baseline = snap;
    try {
      localStorage.setItem('aetherscope_surface_baseline', JSON.stringify(snap));
    } catch {
      // ignore quota error
    }
  }

  const deltaStats = $derived.by(() => {
    if (!report || !baseline) return null;
    const score = Number(report.security_score ?? 0);
    const openPorts = (report.open_ports || []).filter((p: any) => p.open).length;
    const findings = (report.findings || []).length;
    return {
      scoreDiff: score - baseline.score,
      portsDiff: openPorts - baseline.openPorts,
      findingsDiff: findings - baseline.findings,
    };
  });

  const astCorrelations = $derived.by(() => {
    if (!report) return [];
    const endpointNodes = cockpitState.graph.nodes.filter(
      (n) =>
        n.is_form ||
        n.kind === 'Endpoint' ||
        n.name.includes('/api/') ||
        n.file_path.includes('route') ||
        n.file_path.includes('main.rs')
    );
    return endpointNodes.slice(0, 10);
  });

  const surfacePromptText = $derived.by(() => {
    if (!report) return '';
    const openPorts = (report.open_ports || []).filter((p: any) => p.open).map((p: any) => `${p.port}/${p.service}`).join(', ');
    if (surfacePromptTab === 'hardening') {
      return `# 🛡️ Surface Hardening Plan — ${target}\nScore: ${report.security_score ?? 0}/100 (${report.grade})\nPorts ouverts: ${openPorts || 'aucun'}\nExclusions Bounty: ${cockpitState.bountyOutOfScopePatterns.join(', ') || 'aucune'}\nFindings (${(report.findings || []).length}):\n${(report.findings || []).slice(0, 8).map((f: any) => `- [${f.severity || 'INFO'}] ${f.title || f.category}`).join('\n')}`;
    }
    if (surfacePromptTab === 'weakness') {
      return `# ⚡ Audit Dual Side 2 (Black-Box Weaknesses) — ${target}\nCorrelate remote exposure (${openPorts || 'HTTP'}) with local AST routes (${astCorrelations.length} local endpoints detected). Validate rate limiting, CSP/HSTS headers, and auth boundaries.`;
    }
    return `# 🗺️ Architecture & Surface Trust Swimlanes — ${target}\nHost: ${report.host || target} · IPs: ${(report.resolved_ips || []).join(', ')}\nPorts: ${openPorts || 'aucun'}\nLocal AST Endpoints correlated: ${astCorrelations.length}`;
  });

  function copySurfacePrompt() {
    if (!surfacePromptText) return;
    navigator.clipboard?.writeText(surfacePromptText);
    promptCopied = true;
    setTimeout(() => (promptCopied = false), 1500);
  }

  async function launchScan() {
    if (!target.trim()) return;
    isScanning = true;
    errorMsg = null;
    try {
      report = await api.surfaceScan({
        target: target.trim(),
        scan_level: scanLevel,
        check_dns: checkDns,
        check_ports: checkPorts,
        check_headers: checkHeaders,
        check_endpoints: checkEndpoints,
        check_web_forms: checkWebForms,
        check_sensitive_files: checkSensitiveFiles,
        custom_ports: customPorts.trim() || undefined,
      });
    } catch (e: any) {
      errorMsg = e?.message || 'Erreur lors du scan de surface (serveur local requis).';
    } finally {
      isScanning = false;
    }
  }

  function closeModal() {
    cockpitState.isSurfaceScannerOpen = false;
  }
</script>

{#if cockpitState.isSurfaceScannerOpen}
  <div
    class="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-4xl max-h-[88vh] bg-[#090d16] border border-emerald-500/40 rounded-xl shadow-[0_24px_80px_rgba(16,185,129,0.22)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <Radar class="w-5 h-5 text-emerald-400" />
          <div>
            <h2 class="text-sm font-bold text-white">Scanner Surface d'Attaque Domaine / IP</h2>
            <p class="text-[11px] text-slate-400">Audit actif DNS, Ports TCP, Headers HTTP, Formulaires Web & Expositions .env / .git</p>
          </div>
        </div>
        <button
          onclick={closeModal}
          aria-label="Fermer le scanner de surface"
          class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Scan Bar -->
      <div class="p-4 border-b border-white/10 bg-white/[0.02] space-y-3">
        <div class="flex flex-wrap gap-2">
          <input
            type="text"
            bind:value={target}
            placeholder="Ex: example.com ou 127.0.0.1:3333"
            class="flex-1 min-w-[200px] px-3 py-2 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-white focus:outline-none focus:border-emerald-400"
          />
          <input
            type="text"
            bind:value={customPorts}
            placeholder="Ports custom (ex: 3333,8080)"
            class="w-40 px-2.5 py-2 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-400"
          />
          <select
            bind:value={scanLevel}
            class="px-3 py-2 rounded-lg bg-slate-900 border border-white/15 text-xs text-emerald-300 font-mono"
          >
            <option value={1}>Niveau 1 — Passif</option>
            <option value={2}>Niveau 2 — Services</option>
            <option value={3}>Niveau 3 — Web & Forms</option>
            <option value={4}>Niveau 4 — Audit .env/.git</option>
          </select>
          <button
            type="button"
            disabled={isScanning}
            onclick={launchScan}
            class="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-xs font-bold text-slate-950 cursor-pointer"
          >
            <Play class="w-3.5 h-3.5" />
            <span>{isScanning ? 'Scan en cours...' : 'Lancer Scan'}</span>
          </button>
          {#if report}
            <button
              type="button"
              onclick={saveBaselineSnapshot}
              title="Sauvegarder comme Baseline Delta"
              class="flex items-center gap-1 px-2.5 py-2 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/35 text-xs text-sky-200 cursor-pointer"
            >
              <BookmarkCheck class="w-3.5 h-3.5" /> Baseline
            </button>
          {/if}
        </div>

        <div class="flex flex-wrap gap-3 text-[11px] text-slate-300">
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" bind:checked={checkDns} class="accent-emerald-400" /> DNS</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" bind:checked={checkPorts} class="accent-emerald-400" /> Ports TCP</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" bind:checked={checkHeaders} class="accent-emerald-400" /> Headers HTTP</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" bind:checked={checkEndpoints} class="accent-emerald-400" /> Endpoints</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" bind:checked={checkWebForms} class="accent-emerald-400" /> Web Forms</label>
          <label class="flex items-center gap-1.5 cursor-pointer"><input type="checkbox" bind:checked={checkSensitiveFiles} class="accent-emerald-400" /> Fichiers Sensibles (.env / .git)</label>
        </div>
      </div>

      <!-- Body / Report -->
      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        {#if errorMsg}
          <div class="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-xs text-rose-200 font-mono">
            {errorMsg}
          </div>
        {/if}

        {#if !report}
          <div class="text-center py-12 text-xs text-slate-500 font-mono">
            Saisissez un domaine ou une IP cible autorisée et cliquez sur « Lancer Scan ».
          </div>
        {:else}
          <!-- Baseline Delta Banner -->
          {#if deltaStats && baseline}
            <div class="p-2.5 rounded-lg bg-sky-950/30 border border-sky-500/35 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
              <span class="flex items-center gap-1.5 text-sky-200">
                <GitCompareArrows class="w-3.5 h-3.5 text-sky-400" />
                Delta vs Baseline ({baseline.savedAt})
              </span>
              <div class="flex items-center gap-3">
                <span class={deltaStats.scoreDiff >= 0 ? 'text-emerald-300' : 'text-rose-300'}>Score: {deltaStats.scoreDiff >= 0 ? `+${deltaStats.scoreDiff}` : deltaStats.scoreDiff}</span>
                <span class="text-slate-300">Ports: {deltaStats.portsDiff >= 0 ? `+${deltaStats.portsDiff}` : deltaStats.portsDiff}</span>
                <span class={deltaStats.findingsDiff <= 0 ? 'text-emerald-300' : 'text-amber-300'}>Findings: {deltaStats.findingsDiff >= 0 ? `+${deltaStats.findingsDiff}` : deltaStats.findingsDiff}</span>
              </div>
            </div>
          {/if}

          <!-- Summary Cards -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10">
              <div class="text-[10px] font-mono text-slate-400">NOTE SÉCURITÉ</div>
              <div class="text-xl font-black text-emerald-400 mt-0.5">{report.grade || '—'} · {report.security_score ?? 0}/100</div>
            </div>
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10">
              <div class="text-[10px] font-mono text-slate-400 flex items-center gap-1"><Globe class="w-3 h-3" /> IPs RÉSOLUES</div>
              <div class="text-sm font-mono text-white mt-1 truncate">{(report.resolved_ips || []).join(', ') || report.host}</div>
            </div>
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10">
              <div class="text-[10px] font-mono text-slate-400 flex items-center gap-1"><Server class="w-3 h-3" /> PORTS OUVERTS</div>
              <div class="text-xl font-bold text-sky-300 mt-0.5">
                {(report.open_ports || []).filter((p: any) => p.open).length}
              </div>
            </div>
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/10">
              <div class="text-[10px] font-mono text-slate-400 flex items-center gap-1"><ShieldAlert class="w-3 h-3" /> ALERTES</div>
              <div class="text-xl font-bold text-rose-400 mt-0.5">{(report.findings || []).length}</div>
            </div>
          </div>

          <!-- Open ports -->
          {#if report.open_ports && report.open_ports.filter((p: any) => p.open).length > 0}
            <div class="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-2">
              <div class="text-xs font-bold text-sky-300 font-mono">PORTS & SERVICES OUVERTS</div>
              <div class="flex flex-wrap gap-2">
                {#each report.open_ports.filter((p: any) => p.open) as p}
                  <div class="px-2.5 py-1 rounded-lg bg-black/40 border border-sky-500/30 text-[11px] font-mono text-slate-200">
                    <span class="text-sky-400 font-bold">{p.port}/{p.protocol}</span> {p.service}
                    {#if p.latency_ms !== undefined}<span class="text-slate-500"> ({p.latency_ms}ms)</span>{/if}
                  </div>
                {/each}
              </div>
            </div>
          {/if}

          <!-- Findings -->
          {#if report.findings && report.findings.length > 0}
            <div class="space-y-2">
              <div class="text-xs font-bold text-rose-300 font-mono flex items-center gap-1.5">
                <FileWarning class="w-3.5 h-3.5" />
                <span>OBSERVATIONS & VULNÉRABILITÉS ({report.findings.length})</span>
              </div>
              {#each report.findings as f}
                <div class="p-3 rounded-lg bg-black/35 border border-white/10 text-xs space-y-1">
                  <div class="flex items-center justify-between">
                    <span class="font-bold text-white">{f.title || f.category || 'Alerte Surface'}</span>
                    <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300">{f.severity || f.risk_level || 'INFO'}</span>
                  </div>
                  <p class="text-[11px] text-slate-400">{f.description || f.recommendation || JSON.stringify(f)}</p>
                </div>
              {/each}
            </div>
          {/if}

          <!-- Surface <-> Local AST Bridge + Trust Swimlanes -->
          {#if astCorrelations.length > 0}
            <div class="p-3.5 rounded-xl bg-purple-950/15 border border-purple-500/30 space-y-2">
              <div class="flex items-center justify-between text-xs font-bold text-purple-300 font-mono">
                <span>PONTS SURFACE ↔ AST LOCAL ({astCorrelations.length} routes/endpoints détectés)</span>
              </div>
              <div class="flex flex-wrap gap-1.5">
                {#each astCorrelations as n}
                  <button
                    type="button"
                    onclick={() => { cockpitState.selectSymbol(n.id, true); closeModal(); }}
                    class="px-2 py-1 rounded bg-black/40 hover:bg-purple-500/20 border border-purple-500/30 text-[10.5px] font-mono text-slate-200 cursor-pointer"
                  >
                    {n.name} <span class="text-slate-500">({n.file_path.split('/').pop()})</span>
                  </button>
                {/each}
              </div>
            </div>
          {/if}

          <!-- Prompt Dual Audit (Arch / Hardening / Side 2 Weaknesses) -->
          <div class="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-2">
            <div class="flex items-center justify-between gap-2">
              <div class="flex gap-1 text-[10px] font-mono">
                <button
                  type="button"
                  onclick={() => (surfacePromptTab = 'arch')}
                  class="px-2 py-1 rounded cursor-pointer {surfacePromptTab === 'arch' ? 'bg-emerald-500/20 text-emerald-300 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  Trust Swimlanes
                </button>
                <button
                  type="button"
                  onclick={() => (surfacePromptTab = 'hardening')}
                  class="px-2 py-1 rounded cursor-pointer {surfacePromptTab === 'hardening' ? 'bg-sky-500/20 text-sky-300 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  Hardening Plan
                </button>
                <button
                  type="button"
                  onclick={() => (surfacePromptTab = 'weakness')}
                  class="px-2 py-1 rounded cursor-pointer {surfacePromptTab === 'weakness' ? 'bg-amber-500/20 text-amber-300 font-bold' : 'text-slate-400 hover:text-white'}"
                >
                  Dual Audit Side 2
                </button>
              </div>
              <button
                type="button"
                onclick={copySurfacePrompt}
                class="flex items-center gap-1 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] text-slate-200 cursor-pointer"
              >
                {#if promptCopied}<Check class="w-3 h-3 text-emerald-400" /> Copié{:else}<Copy class="w-3 h-3" /> Copier Prompt{/if}
              </button>
            </div>
            <pre class="p-2.5 rounded-lg bg-black/50 border border-white/5 text-[10.5px] font-mono text-slate-300 whitespace-pre-wrap">{surfacePromptText}</pre>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}
