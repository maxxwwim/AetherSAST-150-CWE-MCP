<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { ShieldAlert, FileCode2 } from '@lucide/svelte';

  const node = $derived(cockpitState.hoveredSymbol);
  const pos = $derived(cockpitState.hoverScreenPos);

  const primaryAnomaly = $derived(node?.anomalies && node.anomalies.length > 0 ? node.anomalies[0] : null);
  const anomaliesCount = $derived(node?.anomalies?.length || 0);
  const hasSec = $derived(
    Boolean(node && (node.has_security_violation || anomaliesCount > 0 || (node.violations && node.violations.length > 0)))
  );

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
    const w = 320;
    const h = 190;
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
    class="fixed z-50 w-80 pointer-events-none rounded-xl bg-[#090d16]/95 backdrop-blur-xl border shadow-[0_14px_40px_rgba(0,0,0,0.85)] p-3 space-y-2 text-xs transition-transform duration-75 {hasSec ? 'border-rose-500/70' : 'border-sky-500/40'}"
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
        <div>{node.loc || 1} LOC</div>
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
    {/if}
  </div>
{/if}
