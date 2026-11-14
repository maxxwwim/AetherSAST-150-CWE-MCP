<script lang="ts">
  import { cockpitState, normalizeEdgeRelation, getNodeAlertKind, isLinesExceededAnomaly } from '../state/graphState.svelte';
  import { ShieldAlert, FileCode2, ArrowRight, ArrowLeft } from '@lucide/svelte';

  const node = $derived(cockpitState.hoveredSymbol);
  const pos = $derived(cockpitState.hoverScreenPos);

  const alertKind = $derived(getNodeAlertKind(node));
  const hasSec = $derived(alertKind === 'security');
  const hasLinesWarn = $derived(alertKind === 'lines_exceeded');
  const primaryAnomaly = $derived.by(() => {
    const list = node?.anomalies || [];
    if (list.length === 0) return null;
    if (hasSec) return list.find((a) => !isLinesExceededAnomaly(a)) || list[0];
    return list[0];
  });
  const anomaliesCount = $derived(node?.anomalies?.length || 0);

  const nodeById = $derived.by(() => {
    const map = new Map<string, string>();
    for (const n of cockpitState.graph.nodes) {
      map.set(n.id, n.name);
    }
    return map;
  });

  const hoverLinks = $derived.by(() => {
    if (!node) {
      return { incoming: [] as { name: string; rel: string }[], outgoing: [] as { name: string; rel: string }[], callsIn: 0, callsOut: 0, imports: 0, data: 0 };
    }
    const incoming: { name: string; rel: string }[] = [];
    const outgoing: { name: string; rel: string }[] = [];
    let callsIn = 0;
    let callsOut = 0;
    let imports = 0;
    let data = 0;
    const seenIn = new Set<string>();
    const seenOut = new Set<string>();

    for (const e of cockpitState.graph.edges) {
      if (e.source !== node.id && e.target !== node.id) continue;
      const rel = normalizeEdgeRelation(e.relation || e.edge_type);
      if (rel === 'imports' || rel === 'inherits' || rel === 'contains') imports++;
      else if (rel === 'queries' || rel === 'submits' || rel === 'network' || rel === 'realtime') data++;

      if (e.target === node.id && e.source !== node.id) {
        if (rel === 'calls') callsIn++;
        const srcName = nodeById.get(e.source) || e.source.split('::').pop() || e.source;
        const key = `${srcName}:${rel}`;
        if (!seenIn.has(key) && incoming.length < 4) {
          seenIn.add(key);
          incoming.push({ name: srcName, rel });
        }
      } else if (e.source === node.id && e.target !== node.id) {
        if (rel === 'calls') callsOut++;
        const dstName = nodeById.get(e.target) || e.target.split('::').pop() || e.target;
        const key = `${dstName}:${rel}`;
        if (!seenOut.has(key) && outgoing.length < 4) {
          seenOut.add(key);
          outgoing.push({ name: dstName, rel });
        }
      }
    }
    return { incoming, outgoing, callsIn, callsOut, imports, data };
  });

  const signaturePreview = $derived.by(() => {
    if (!node) return '';
    if (node.methods && node.methods.length > 0) {
      return node.methods[0].signature || `${node.methods[0].name}(${node.methods[0].args || ''})`;
    }
    return '';
  });

  const cleanSummary = $derived.by(() => {
    const raw = (node?.docstring || '').trim();
    if (!raw) return '';
    const cleaned = raw.replace(/^[\/\*#\s]+/gm, '').trim();
    return cleaned.split('\n')[0].slice(0, 140);
  });

  const stylePos = $derived.by(() => {
    const vw = typeof window !== 'undefined' ? window.innerWidth : 1280;
    const vh = typeof window !== 'undefined' ? window.innerHeight : 800;
    const w = 336;
    const h = 235;
    let x = pos.x + 24;
    if (x + w > vw - 16) x = pos.x - w - 24;
    x = Math.max(12, Math.min(vw - w - 12, x));

    let y = pos.y - 60;
    if (y + h > vh - 36) y = vh - h - 36;
    y = Math.max(52, y);
    return `left:${Math.round(x)}px; top:${Math.round(y)}px;`;
  });
</script>

{#if node}
  <div
    class="fixed z-50 w-[336px] pointer-events-none rounded-xl bg-[#090d16]/95 backdrop-blur-xl border shadow-[0_14px_40px_rgba(0,0,0,0.85)] p-3 space-y-2 text-xs transition-transform duration-75 {hasSec ? 'border-rose-500/70' : hasLinesWarn ? 'border-orange-500/70' : 'border-sky-500/40'}"
    style={stylePos}
  >
    <div class="flex items-start justify-between gap-2">
      <div class="min-w-0">
        <div class="flex items-center gap-1.5">
          <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-sky-500/15 text-sky-300 border border-sky-500/30">
            {node.stereotype || `«${node.kind}»`}
          </span>
          <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/5 text-slate-300 border border-white/10 uppercase">
            {node.layer}
          </span>
        </div>
        <div class="text-xs font-bold text-white truncate mt-1">{node.name}</div>
        <div class="text-[10px] font-mono text-slate-400 truncate flex items-center gap-1">
          <FileCode2 class="w-2.5 h-2.5 shrink-0" />
          <span>{node.file_path}{node.line_number ? `:${node.line_number}` : ''}</span>
        </div>
      </div>
      <div class="text-right font-mono text-[10px] text-slate-400 shrink-0">
        <div class={hasLinesWarn ? 'text-orange-400 font-bold' : ''}>
          {node.loc || 1}{node.metadata?.max_lines_limit ? ` / ${node.metadata.max_lines_limit}` : ''} LOC
        </div>
        <div class={(node.cyclomatic_complexity || 1) >= 10 ? 'text-amber-300 font-bold' : ''}>
          CC {node.cyclomatic_complexity || 1}
        </div>
      </div>
    </div>

    {#if signaturePreview}
      <pre class="px-2 py-1 rounded bg-black/50 border border-white/10 font-mono text-[10px] text-sky-300 truncate">{signaturePreview}</pre>
    {/if}

    {#if cleanSummary}
      <p class="text-[11px] text-slate-300 italic line-clamp-2 border-l-2 border-sky-400/50 pl-2">{cleanSummary}</p>
    {/if}

    {#if hoverLinks.incoming.length > 0 || hoverLinks.outgoing.length > 0}
      <div class="pt-1 border-t border-white/10 space-y-1">
        <div class="flex flex-wrap items-center gap-1.5 text-[9.5px] font-mono">
          <span class="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            ← {hoverLinks.callsIn} appelants
          </span>
          <span class="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
            ➔ {hoverLinks.callsOut} appels
          </span>
          {#if hoverLinks.imports > 0}
            <span class="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
              📦 {hoverLinks.imports} imports
            </span>
          {/if}
          {#if hoverLinks.data > 0}
            <span class="px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
              🗄️ {hoverLinks.data} flux
            </span>
          {/if}
        </div>
        {#if hoverLinks.incoming.length > 0}
          <div class="flex flex-wrap items-center gap-1 text-[9.5px] font-mono text-emerald-200/90">
            <ArrowLeft class="w-2.5 h-2.5 text-emerald-400 shrink-0" />
            {#each hoverLinks.incoming as item}
              <span class="px-1 py-0.2 rounded bg-emerald-950/60 border border-emerald-500/25 truncate max-w-[96px]">
                {item.name}
              </span>
            {/each}
          </div>
        {/if}
        {#if hoverLinks.outgoing.length > 0}
          <div class="flex flex-wrap items-center gap-1 text-[9.5px] font-mono text-sky-200/90">
            <ArrowRight class="w-2.5 h-2.5 text-sky-400 shrink-0" />
            {#each hoverLinks.outgoing as item}
              <span class="px-1 py-0.2 rounded bg-sky-950/60 border border-sky-500/25 truncate max-w-[96px]">
                {item.name}
              </span>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    {#if hasSec}
      <div class="p-2 rounded-lg bg-rose-950/75 border border-rose-500/60 space-y-1">
        <div class="flex items-center justify-between gap-1.5">
          <span class="flex items-center gap-1 text-[10px] font-bold text-rose-200">
            <ShieldAlert class="w-3.5 h-3.5 text-rose-400" />
            🚨 {primaryAnomaly ? (primaryAnomaly.severity || 'CRITICAL').toUpperCase() : 'SAST ALERT'}
          </span>
          <span class="px-1.5 py-0.5 rounded bg-rose-500/30 text-rose-200 font-mono text-[9.5px] font-bold">
            {primaryAnomaly ? (primaryAnomaly.cve_id || primaryAnomaly.rule_id) : 'CWE-SAST'}
            {#if anomaliesCount > 1}(+{anomaliesCount - 1}){/if}
          </span>
        </div>
        <p class="text-[10.5px] text-rose-100/95 leading-snug line-clamp-2">
          {primaryAnomaly?.description || primaryAnomaly?.message || 'Vulnérabilité détectée sur ce fichier — cliquez pour inspecter.'}
        </p>
      </div>
    {:else if hasLinesWarn}
      <div class="p-2 rounded-lg bg-orange-950/75 border border-orange-500/60 space-y-1">
        <div class="flex items-center justify-between gap-1.5">
          <span class="flex items-center gap-1 text-[10px] font-bold text-orange-200">
            <ShieldAlert class="w-3.5 h-3.5 text-orange-400" />
            ⚠️ BUDGET LIGNES DÉPASSÉ
          </span>
          <span class="px-1.5 py-0.5 rounded bg-orange-500/30 text-orange-200 font-mono text-[9.5px] font-bold">
            {node.loc || 0} / {node.metadata?.max_lines_limit || 300} L
          </span>
        </div>
        <p class="text-[10.5px] text-orange-100/95 leading-snug line-clamp-2">
          {primaryAnomaly?.description || primaryAnomaly?.message || 'Ce fichier dépasse la limite de lignes du contrat BLAKE3 — modifiable depuis l’Inspecteur.'}
        </p>
      </div>
    {/if}
  </div>
{/if}
