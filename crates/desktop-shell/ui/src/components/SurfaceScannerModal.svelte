<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import { playSpatialTone } from '../lib/sound';
  import {
    Radar,
    Play,
    X,
    Globe,
    Server,
    ShieldAlert,
    FileWarning,
    BookmarkCheck,
    GitCompareArrows,
    Copy,
    Check,
    FolderTree,
    FileCode,
    ArrowRight,
    Sparkles,
    Send,
    Lock,
    FlaskConical,
    Layers,
    Link2
  } from '@lucide/svelte';

  let target = $state('127.0.0.1:3030');
  let scanLevel = $state<1 | 2 | 3 | 4>(4);
  let customPorts = $state('');
  let checkDns = $state(true);
  let checkPorts = $state(true);
  let checkHeaders = $state(true);
  let checkEndpoints = $state(true);
  let checkWebForms = $state(true);
  let checkSensitiveFiles = $state(true);

  let isScanning = $state(false);
  let progressPct = $state(0);
  let progressStep = $state('');
  let errorMsg = $state<string | null>(null);
  let report = $state<any>(null);
  let baseline = $state<any>(null);

  let selectedFileFilter = $state<string>('ALL');
  let htmlSourceTab = $state<'ALL' | 'FORMS' | 'URLS' | 'ANCHORS' | 'PATHS'>('ALL');
  let archViewMode = $state<'ARC_DIAGRAM' | 'TIERED_ARCS'>('ARC_DIAGRAM');
  let archCallFilter = $state<'ALL' | 'FORM' | 'API' | 'ANCHOR' | 'AST'>('ALL');
  let selectedArchNodeId = $state<string | null>(null);
  let hoveredArcId = $state<string | null>(null);
  let sideTwoUnlocked = $state(false);
  let sideTwoTestFilter = $state<'ALL' | 'POSITIVE' | 'NEGATIVE'>('ALL');
  let surfacePromptTab = $state<'arch' | 'hardening' | 'tests' | 'weakness'>('arch');
  let promptCopied = $state(false);
  let jsonCopied = $state(false);
  let sendingToCopilot = $state(false);

  $effect(() => {
    if (cockpitState.isSurfaceScannerOpen && typeof localStorage !== 'undefined') {
      try {
        const raw = localStorage.getItem('aetherscope_surface_baseline_v2');
        if (raw) baseline = JSON.parse(raw);
      } catch {
        // ignore invalid baseline JSON
      }
    }
  });

  function selectScanLevel(lvl: 1 | 2 | 3 | 4) {
    scanLevel = lvl;
    if (lvl === 1) {
      checkDns = true;
      checkPorts = false;
      checkHeaders = true;
      checkEndpoints = false;
      checkWebForms = false;
      checkSensitiveFiles = false;
    } else if (lvl === 2) {
      checkDns = true;
      checkPorts = true;
      checkHeaders = true;
      checkEndpoints = true;
      checkWebForms = false;
      checkSensitiveFiles = false;
    } else if (lvl === 3) {
      checkDns = true;
      checkPorts = true;
      checkHeaders = true;
      checkEndpoints = true;
      checkWebForms = true;
      checkSensitiveFiles = false;
    } else {
      checkDns = true;
      checkPorts = true;
      checkHeaders = true;
      checkEndpoints = true;
      checkWebForms = true;
      checkSensitiveFiles = true;
    }
  }

  function applyPreset(presetTarget: string) {
    target = presetTarget;
    launchScan();
  }

  function saveBaselineSnapshot() {
    if (!report) return;
    const snap = JSON.parse(JSON.stringify(report));
    snap.savedAt = new Date().toLocaleTimeString();
    baseline = snap;
    try {
      localStorage.setItem('aetherscope_surface_baseline_v2', JSON.stringify(snap));
    } catch {
      // ignore storage quota error
    }
  }

  function clearBaselineSnapshot() {
    baseline = null;
    try {
      localStorage.removeItem('aetherscope_surface_baseline_v2');
    } catch {
      // ignore
    }
  }

  const deltaStats = $derived.by(() => {
    if (!report || !baseline) return null;
    const scoreDiff = Number(report.security_score ?? 0) - Number(baseline.security_score ?? 0);
    const baseIds = new Set(((baseline.findings || []) as any[]).map((f) => f.id));
    const curIds = new Set(((report.findings || []) as any[]).map((f) => f.id));
    let resolvedCount = 0;
    baseIds.forEach((id) => {
      if (!curIds.has(id)) resolvedCount++;
    });
    let newCount = 0;
    curIds.forEach((id) => {
      if (!baseIds.has(id)) newCount++;
    });
    const openNow = ((report.open_ports || []) as any[]).filter((p) => p.open).length;
    const openBase = ((baseline.open_ports || []) as any[]).filter((p) => p.open).length;
    return {
      scoreDiff,
      resolvedCount,
      newCount,
      portsDiff: openNow - openBase,
      baseScore: baseline.security_score ?? 0,
      baseGrade: baseline.grade || '—',
      baseTarget: `${baseline.host || baseline.target_raw || ''}:${baseline.primary_port || ''}`,
      savedAt: baseline.savedAt || ''
    };
  });

  const webFiles = $derived<any[]>(report?.web_discovery?.web_files || []);
  const directories = $derived<any[]>(report?.web_discovery?.directories || []);
  const forms = $derived<any[]>(report?.web_discovery?.forms || []);
  const routes = $derived<any[]>(report?.web_discovery?.routes || []);
  const htmlLinks = $derived<any[]>(report?.web_discovery?.html_links || []);
  const pathTree = $derived<any[]>(report?.web_discovery?.path_tree || []);
  const hashLinks = $derived<any[]>(htmlLinks.filter((l) => l.kind === '#LINK / ANCRE DOM'));
  const discoveredUrls = $derived<any[]>(htmlLinks.filter((l) => l.kind !== '#LINK / ANCRE DOM'));
  const externalScripts = $derived<string[]>(report?.web_discovery?.external_scripts || []);
  const robotsEntries = $derived<string[]>(report?.web_discovery?.robots_entries || []);
  const totalInputsCount = $derived<number>(
    forms.reduce((acc, f) => acc + ((f.inputs || []).length as number), 0)
  );

  const selectedWebFileObj = $derived.by(() => {
    if (selectedFileFilter === 'ALL') return null;
    return webFiles.find((w) => w.path === selectedFileFilter) || null;
  });

  const filteredDirectories = $derived.by(() => {
    if (!selectedWebFileObj) return directories;
    const wfPath = selectedWebFileObj.path;
    const fCalls: string[] = selectedWebFileObj.folder_calls || [];
    return directories.filter(
      (d) => (d.source_files || []).includes(wfPath) || fCalls.includes(d.folder_path)
    );
  });

  const filteredRoutes = $derived.by(() => {
    if (!selectedWebFileObj) return routes;
    const wfPath = selectedWebFileObj.path;
    const refs: string[] = selectedWebFileObj.api_and_asset_refs || [];
    return routes.filter(
      (r) => refs.includes(r.path) || (r.source || '').includes(wfPath)
    );
  });

  function childItemsForDirectory(folderPath: string): string[] {
    const items: string[] = [];
    if (folderPath === '/#anchors/') {
      for (const hl of hashLinks) {
        if (!items.includes(hl.target) && items.length < 12) items.push(hl.target);
      }
      return items;
    }
    for (const r of routes) {
      if (typeof r.path === 'string' && r.path.startsWith(folderPath)) {
        const entry = `[${r.method}] ${r.path}`;
        if (!items.includes(entry) && items.length < 10) items.push(entry);
      }
    }
    for (const wf of webFiles) {
      for (const ref of wf.api_and_asset_refs || []) {
        if (typeof ref === 'string' && ref.startsWith(folderPath)) {
          if (!items.some((i) => i.endsWith(ref)) && items.length < 10) {
            items.push(ref);
          }
        }
      }
    }
    return items;
  }

  const astBridgeItems = $derived.by(() => {
    if (!report) return [];
    const nodes = cockpitState.graph.nodes || [];
    const wd = report.web_discovery;
    if (!wd) return [];
    const results: Array<{
      externalRef: string;
      refType: string;
      isMapped: boolean;
      matchedNodeId: string | null;
      matchedLabel: string;
      matchedLayer: string;
    }> = [];
    const seen = new Set<string>();

    for (const wf of wd.web_files || []) {
      const cleanPath = String(wf.path || '').split('?')[0].split('#')[0];
      if (!cleanPath || seen.has(cleanPath)) continue;
      seen.add(cleanPath);
      const baseName = cleanPath.split('/').filter(Boolean).pop() || '';
      const stem = baseName.replace(/\.[a-z0-9]+$/i, '').toLowerCase();

      const matched = nodes.find((n) => {
        const lbl = `${n.name} ${n.file_path}`.toLowerCase();
        return (
          (baseName.length > 2 && lbl.includes(baseName.toLowerCase())) ||
          (stem.length > 3 && lbl.includes(stem))
        );
      });

      results.push({
        externalRef: wf.path,
        refType: `Source ${wf.file_type}`,
        isMapped: Boolean(matched),
        matchedNodeId: matched ? matched.id : null,
        matchedLabel: matched
          ? `${matched.name} (${matched.file_path.split('/').pop()})`
          : 'Asset / Bundle externe ou statique non indexé AST',
        matchedLayer: matched ? matched.layer || 'ui' : 'Externe'
      });
    }

    for (const r of wd.routes || []) {
      const cleanRoute = String(r.path || '').split('?')[0];
      if (!cleanRoute || seen.has(cleanRoute)) continue;
      seen.add(cleanRoute);
      const segments = cleanRoute
        .split('/')
        .filter((s) => s && s !== 'api' && s !== 'v1' && s !== 'v2' && s.length > 2);
      const lastSeg = (segments[segments.length - 1] || '')
        .replace(/[^a-z0-9_]/gi, '')
        .toLowerCase();

      const matched =
        lastSeg.length >= 3
          ? nodes.find((n) => {
              const lbl = `${n.name} ${n.file_path}`.toLowerCase();
              return lbl.includes(lastSeg) || lbl.includes(cleanRoute.toLowerCase());
            })
          : undefined;

      results.push({
        externalRef: `[${r.method}] ${cleanRoute}`,
        refType: r.source || 'Route / API',
        isMapped: Boolean(matched),
        matchedNodeId: matched ? matched.id : null,
        matchedLabel: matched
          ? `${matched.name} (${matched.file_path.split('/').pop()})`
          : 'Route non résolue dans l\'AST local (Vérifier contrôleur)',
        matchedLayer: matched ? matched.layer || 'action' : 'Shadow / Externe'
      });
    }

    return results;
  });

  const archedCallGraph = $derived.by(() => {
    if (!report?.web_discovery) {
      return { nodes: [] as any[], arcs: [] as any[], selectedDetail: null as any };
    }

    type ArchNode = {
      id: string;
      shortLabel: string;
      fullLabel: string;
      subLabel: string;
      tier: number;
      category: 'HTML' | 'JS' | 'FORM' | 'ANCHOR' | 'ENDPOINT' | 'AST';
      color: string;
      linearX: number;
      linearY: number;
      tieredX: number;
      tieredY: number;
    };

    type ArchEdge = {
      id: string;
      fromId: string;
      toId: string;
      fromLabel: string;
      toLabel: string;
      kind: 'FORM' | 'API' | 'ANCHOR' | 'AST';
      method: string;
      badge: string;
      detail: string;
      color: string;
      linearPath: string;
      linearMidX: number;
      linearMidY: number;
      tieredPath: string;
      tieredMidX: number;
      tieredMidY: number;
    };

    const rawNodes: Omit<ArchNode, 'linearX' | 'linearY' | 'tieredX' | 'tieredY'>[] = [];
    const pushNode = (n: Omit<ArchNode, 'linearX' | 'linearY' | 'tieredX' | 'tieredY'>) => {
      if (!rawNodes.some((x) => x.id === n.id)) rawNodes.push(n);
    };

    // Tier 0: Sources HTML
    const htmlSources = webFiles.filter((w) => w.file_type === 'HTML');
    if (htmlSources.length > 0) {
      for (const hs of htmlSources.slice(0, 2)) {
        pushNode({
          id: `html:${hs.path}`,
          shortLabel: hs.path.replace(' (Entrée)', ''),
          fullLabel: hs.path,
          subLabel: `${forms.length} Form(s) • ${hashLinks.length} #link`,
          tier: 0,
          category: 'HTML',
          color: '#38bdf8'
        });
      }
    } else {
      pushNode({
        id: 'html:/index.html',
        shortLabel: '/index.html',
        fullLabel: '/index.html (Entrée)',
        subLabel: `${forms.length} Form(s) • ${hashLinks.length} #link`,
        tier: 0,
        category: 'HTML',
        color: '#38bdf8'
      });
    }
    const primaryHtmlId = rawNodes[0].id;

    // Tier 1: Modules JS & Assets
    const jsSources = webFiles.filter((w) => w.file_type !== 'HTML').slice(0, 3);
    for (const jsf of jsSources) {
      pushNode({
        id: `js:${jsf.path}`,
        shortLabel: jsf.path.split('/').pop() || jsf.path,
        fullLabel: `[${jsf.file_type}] ${jsf.path}`,
        subLabel: `${(jsf.api_and_asset_refs || []).length} appels • ${(jsf.json_payload_keys || []).length} clés JSON`,
        tier: 1,
        category: 'JS',
        color: '#a855f7'
      });
    }

    // Tier 2: Formulaires «Form» & #Links
    for (const f of forms.slice(0, 6)) {
      const inpCount = (f.inputs || []).length;
      const cleanName = String(f.id_or_name || `Form #${f.index}`)
        .replace(/^Formulaire\s+/i, '')
        .replace(/\s*\(SPA\)$/i, '');
      pushNode({
        id: `form:${f.index}`,
        shortLabel: `Form #${f.index} (${inpCount} ch.)`,
        fullLabel: `Form #${f.index} «${cleanName}»`,
        subLabel: `${f.method} ➔ ${f.action}`,
        tier: 2,
        category: 'FORM',
        color: f.security_posture === 'PASS' ? '#10b981' : '#f59e0b'
      });
    }
    if (hashLinks.length > 0) {
      pushNode({
        id: 'anchor:#links',
        shortLabel: `#Links (${hashLinks.length})`,
        fullLabel: `Ancres DOM & #Links (${hashLinks.length})`,
        subLabel: hashLinks.slice(0, 3).map((h) => h.target).join(', '),
        tier: 2,
        category: 'ANCHOR',
        color: '#fbbf24'
      });
    }

    // Tier 3: Endpoints & Routes API (prioriser les actions des formulaires + routes API)
    const prioritizedRoutes: Array<{ path: string; method: string; source: string }> = [];
    for (const f of forms.slice(0, 6)) {
      if (f.action && !prioritizedRoutes.some((r) => r.path === f.action)) {
        prioritizedRoutes.push({
          path: f.action,
          method: f.method || 'POST',
          source: `Form #${f.index}`
        });
      }
    }
    for (const r of routes) {
      if (
        r.path &&
        !String(r.path).startsWith('#') &&
        !prioritizedRoutes.some((pr) => pr.path === r.path) &&
        prioritizedRoutes.length < 8
      ) {
        prioritizedRoutes.push({
          path: r.path,
          method: r.method || 'GET',
          source: r.source || 'HTML/JS'
        });
      }
    }
    for (const pr of prioritizedRoutes.slice(0, 7)) {
      const isPost = String(pr.method).toUpperCase().includes('POST');
      pushNode({
        id: `ep:${pr.path}`,
        shortLabel: pr.path.length > 20 ? `…${pr.path.slice(-19)}` : pr.path,
        fullLabel: `[${pr.method}] ${pr.path}`,
        subLabel: `Source: ${pr.source}`,
        tier: 3,
        category: 'ENDPOINT',
        color: isPost ? '#34d399' : '#60a5fa'
      });
    }

    // Tier 4: Dossiers & Cibles AST
    for (const d of directories.slice(0, 4)) {
      const astMatch = astBridgeItems.find(
        (b) => b.isMapped && String(b.externalRef).startsWith(d.folder_path)
      );
      pushNode({
        id: `dir:${d.folder_path}`,
        shortLabel: `📁 ${d.folder_path}`,
        fullLabel: astMatch
          ? `📁 ${d.folder_path} ➔ 🧬 ${astMatch.matchedLabel}`
          : `📁 ${d.folder_path} (${d.classification})`,
        subLabel: astMatch ? `Pont AST: ${astMatch.matchedLayer}` : `${d.call_count} appels`,
        tier: 4,
        category: 'AST',
        color: '#ec4899'
      });
    }

    // Positionnement 1 : Diagramme d'Arcs Linéaire (axe horizontal y = 210)
    const totalN = Math.max(rawNodes.length, 1);
    const tierBuckets: Record<number, number[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
    rawNodes.forEach((n, idx) => {
      if (!tierBuckets[n.tier]) tierBuckets[n.tier] = [];
      tierBuckets[n.tier].push(idx);
    });
    const tierXMap: Record<number, number> = { 0: 90, 1: 280, 2: 495, 3: 735, 4: 955 };

    const nodes: ArchNode[] = rawNodes.map((n, idx) => {
      const linearX =
        totalN === 1 ? 530 : Math.round(58 + (idx * (1060 - 116)) / Math.max(totalN - 1, 1));
      const linearY = 212;
      const bucket = tierBuckets[n.tier] || [idx];
      const posInTier = Math.max(bucket.indexOf(idx), 0);
      const countInTier = Math.max(bucket.length, 1);
      const topPad = 48;
      const botPad = 292;
      const tieredY =
        countInTier === 1
          ? 170
          : Math.round(topPad + (posInTier * (botPad - topPad)) / Math.max(countInTier - 1, 1));
      return {
        ...n,
        linearX,
        linearY,
        tieredX: tierXMap[n.tier] ?? 520,
        tieredY
      };
    });

    const nodeById = new Map<string, ArchNode>();
    nodes.forEach((n) => nodeById.set(n.id, n));

    const rawArcs: Array<{
      id: string;
      fromId: string;
      toId: string;
      kind: 'FORM' | 'API' | 'ANCHOR' | 'AST';
      method: string;
      badge: string;
      detail: string;
      color: string;
      preferBelow?: boolean;
    }> = [];

    const addArc = (
      fromId: string,
      toId: string,
      kind: 'FORM' | 'API' | 'ANCHOR' | 'AST',
      method: string,
      badge: string,
      detail: string,
      color: string,
      preferBelow = false
    ) => {
      if (!nodeById.has(fromId) || !nodeById.has(toId) || fromId === toId) return;
      const id = `${fromId}->${toId}`;
      if (!rawArcs.some((a) => a.id === id)) {
        rawArcs.push({ id, fromId, toId, kind, method, badge, detail, color, preferBelow });
      }
    };

    // 1. HTML ⁀➴ Modules JS
    for (const jsf of jsSources) {
      addArc(
        primaryHtmlId,
        `js:${jsf.path}`,
        'API',
        'IMPORT',
        'MODULE JS',
        `Source HTML charge le bundle ${jsf.path} (${(jsf.size_bytes / 1024).toFixed(1)} Ko)`,
        '#a855f7',
        true
      );
    }

    // 2. HTML & JS ⁀➴ Formulaires «Form» ⁀➴ Endpoints API
    for (const f of forms.slice(0, 6)) {
      const fNodeId = `form:${f.index}`;
      const inpNames = (f.inputs || [])
        .slice(0, 4)
        .map((i: any) => i.name)
        .join(', ');
      addArc(
        primaryHtmlId,
        fNodeId,
        'FORM',
        f.method || 'POST',
        `Form #${f.index}`,
        `Source HTML expose Form #${f.index} «${f.id_or_name}» (${(f.inputs || []).length} champ(s): ${inpNames || 'aucun'})`,
        '#10b981',
        false
      );
      if (jsSources.length > 0 && String(f.enctype || '').includes('json')) {
        addArc(
          `js:${jsSources[0].path}`,
          fNodeId,
          'FORM',
          'BIND/SPA',
          'SPA Bind',
          `Module ${jsSources[0].path} intercepte et sérialise Form #${f.index} en JSON`,
          '#14b8a6',
          true
        );
      }
      const epId = `ep:${f.action}`;
      if (nodeById.has(epId)) {
        addArc(
          fNodeId,
          epId,
          'FORM',
          f.method || 'POST',
          `${String(f.method || 'POST').split(' ')[0]} (${(f.inputs || []).length} ch.)`,
          `Form #${f.index} «${f.id_or_name}» soumet ${(f.inputs || []).length} champ(s) [${inpNames}] vers ${f.action}`,
          '#34d399',
          false
        );
      }
    }

    // 3. HTML ⁀➴ #Links ⁀➴ Dossier /#anchors/
    if (nodeById.has('anchor:#links')) {
      addArc(
        primaryHtmlId,
        'anchor:#links',
        'ANCHOR',
        '#LINK',
        `${hashLinks.length} #link`,
        `Code source HTML contient ${hashLinks.length} ancre(s) DOM / #link (${hashLinks.slice(0, 4).map((h) => h.target).join(', ')})`,
        '#fbbf24',
        true
      );
      if (nodeById.has('dir:/#anchors/')) {
        addArc(
          'anchor:#links',
          'dir:/#anchors/',
          'ANCHOR',
          'DOM-HASH',
          '/#anchors/',
          `Navigation interne par fragments #link vers le registre d'ancres DOM /#anchors/`,
          '#f59e0b',
          true
        );
      }
    }

    // 4. Modules JS ⁀➴ Endpoints API
    for (const pr of prioritizedRoutes.slice(0, 7)) {
      const epId = `ep:${pr.path}`;
      const callerJs =
        jsSources.find((j) => (j.api_and_asset_refs || []).includes(pr.path)) || jsSources[0];
      if (callerJs && nodeById.has(`js:${callerJs.path}`)) {
        addArc(
          `js:${callerJs.path}`,
          epId,
          'API',
          pr.method,
          `${String(pr.method).split(' ')[0]} ${pr.path}`,
          `Module ${callerJs.path} exécute un appel ${pr.method} vers ${pr.path}`,
          '#38bdf8',
          true
        );
      } else {
        addArc(
          primaryHtmlId,
          epId,
          'API',
          pr.method,
          `${String(pr.method).split(' ')[0]}`,
          `Appel direct depuis la source HTML vers ${pr.path}`,
          '#38bdf8',
          true
        );
      }

      // 5. Endpoints API ⁀➴ Dossiers & Cibles AST
      const matchingDir = directories
        .slice(0, 4)
        .find((d) => d.folder_path !== '/' && pr.path.startsWith(d.folder_path)) ||
        directories[0];
      if (matchingDir && nodeById.has(`dir:${matchingDir.folder_path}`)) {
        const astMatch = astBridgeItems.find(
          (b) => b.isMapped && b.externalRef === pr.path
        );
        addArc(
          epId,
          `dir:${matchingDir.folder_path}`,
          'AST',
          'HANDLER',
          astMatch ? '🧬 Pont AST' : matchingDir.folder_path,
          astMatch
            ? `Endpoint ${pr.path} atterrit dans le handler AST local ${astMatch.matchedLabel}`
            : `Endpoint ${pr.path} routé vers le dossier ${matchingDir.folder_path}`,
          '#ec4899',
          false
        );
      }
    }

    const arcs: ArchEdge[] = rawArcs.map((a, idx) => {
      const fromN = nodeById.get(a.fromId)!;
      const toN = nodeById.get(a.toId)!;

      // Calcul de l'arche sur le Diagramme d'Arcs Linéaire (au-dessus ou en-dessous de l'axe y=212)
      const dxLin = Math.abs(toN.linearX - fromN.linearX);
      const spanRatio = Math.min(dxLin / 920, 1);
      const archMag = Math.round(38 + spanRatio * 128 + (idx % 3) * 11);
      const goBelow = Boolean(a.preferBelow);
      const peakY = goBelow
        ? Math.min(314, fromN.linearY + archMag * 0.68)
        : Math.max(24, fromN.linearY - archMag);
      const midXLin = Math.round((fromN.linearX + toN.linearX) / 2);
      const ctrlY = goBelow
        ? Math.round(fromN.linearY + (peakY - fromN.linearY) * 1.32)
        : Math.round(fromN.linearY - (fromN.linearY - peakY) * 1.32);
      const linearPath = `M ${fromN.linearX} ${fromN.linearY} Q ${midXLin} ${ctrlY} ${toN.linearX} ${toN.linearY}`;
      const linearMidY = Math.round(0.25 * fromN.linearY + 0.5 * ctrlY + 0.25 * toN.linearY);

      // Calcul de l'arche sur la Vue Multi-Couches (courbe arquée vers le haut entre colonnes)
      const midXTier = Math.round((fromN.tieredX + toN.tieredX) / 2);
      const distTier = Math.hypot(toN.tieredX - fromN.tieredX, toN.tieredY - fromN.tieredY);
      const archLift = Math.round(Math.min(72, Math.max(26, distTier * 0.16)) + (idx % 2) * 10);
      const ctrlYTier = Math.max(
        20,
        Math.round((fromN.tieredY + toN.tieredY) / 2 - (goBelow ? -archLift * 0.65 : archLift))
      );
      const tieredPath = `M ${fromN.tieredX} ${fromN.tieredY} Q ${midXTier} ${ctrlYTier} ${toN.tieredX} ${toN.tieredY}`;
      const tieredMidY = Math.round(0.25 * fromN.tieredY + 0.5 * ctrlYTier + 0.25 * toN.tieredY);

      return {
        id: a.id,
        fromId: a.fromId,
        toId: a.toId,
        fromLabel: fromN.fullLabel,
        toLabel: toN.fullLabel,
        kind: a.kind,
        method: a.method,
        badge: a.badge,
        detail: a.detail,
        color: a.color,
        linearPath,
        linearMidX: midXLin,
        linearMidY,
        tieredPath,
        tieredMidX: midXTier,
        tieredMidY
      };
    });

    const filteredArcs = arcs.filter((a) => {
      if (archCallFilter !== 'ALL' && a.kind !== archCallFilter) return false;
      if (selectedArchNodeId && a.fromId !== selectedArchNodeId && a.toId !== selectedArchNodeId) {
        return false;
      }
      return true;
    });

    const activeArc =
      filteredArcs.find((a) => a.id === hoveredArcId) || filteredArcs[0] || null;

    return {
      nodes,
      arcs: filteredArcs,
      allArcsCount: arcs.length,
      activeArc
    };
  });

  const sideTwoWeaknessSuite = $derived.by(() => {
    if (!report) return [];
    const nodes = cockpitState.graph.nodes || [];
    const probes: any[] = report.boundary_weaknesses || [];
    return probes.map((p, idx) => {
      const tokens = `${p.side_one_vector || ''} ${p.side_two_ast_target || ''}`
        .toLowerCase()
        .split(/[^a-z0-9_]+/)
        .filter(
          (w) =>
            w.length >= 4 &&
            !['http', 'https', 'form', 'post', 'test', 'avec', 'dans', 'pour'].includes(w)
        );

      const matchedNode = nodes.find((n) => {
        const lbl = `${n.name} ${n.file_path}`.toLowerCase();
        return tokens.some((tk) => lbl.includes(tk));
      });

      const fnSlug = String(p.id || `weakness_${idx}`)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_|_$/g, '');

      return {
        id: p.id,
        cwe: p.cwe,
        status: p.status,
        sideOneVector: p.side_one_vector,
        astNodeId: matchedNode ? matchedNode.id : null,
        astNodeLabel: matchedNode
          ? `${matchedNode.name} [${matchedNode.layer || 'AST'}]`
          : p.side_two_ast_target,
        isAstMapped: Boolean(matchedNode),
        positiveTestFn: `test_accept_${fnSlug}_nominal()`,
        positiveTestSpec:
          p.positive_test_spec ||
          'Test Positif : Vérifier que le flux nominal légitime répond 200 OK avec le schéma attendu.',
        negativeTestFn: `test_reject_${fnSlug}_boundary()`,
        negativeTestSpec: p.negative_test_spec
      };
    });
  });

  function triggerSideTwoAudit() {
    if (!report) return;
    sideTwoUnlocked = true;
    surfacePromptTab = 'weakness';
    playSpatialTone(cockpitState.settings.soundEnabled, 'select');
  }

  function buildSurfaceMarkdownPrompt(rep: any, mode: 'arch' | 'hardening' | 'tests' | 'weakness'): string {
    if (!rep) return '';
    const im = rep.impact_matrix || {};
    const openPortsMd =
      ((rep.open_ports || []) as any[])
        .filter((p) => p.open)
        .map(
          (p) =>
            `- Port :${p.port}/${p.protocol || 'TCP'} (${p.service}) : OUVERT (${p.latency_ms || 0} ms)${p.detected_version ? ` | Version: ${p.detected_version}` : ''}${p.banner ? ` | Bannière: \`${p.banner}\`` : ''}`
        )
        .join('\n') || '- Aucun port ouvert détecté';

    const techMd =
      ((rep.tech_stack || []) as any[])
        .map(
          (t) =>
            `- **[${t.category}] ${t.name}**${t.version ? ` (Version : \`${t.version}\`)` : ''} — Source : ${t.source} (${t.confidence})`
        )
        .join('\n') || '- Aucune bannière logicielle exposée';

    const trustMd =
      ((rep.trust_zones || []) as any[])
        .map(
          (tz) =>
            `- **${tz.title}** (${tz.subtitle || ''}) : **[${tz.posture}]** — ${(tz.controls || []).join(', ')}`
        )
        .join('\n') || '- Non évalué';

    const filesMd =
      ((rep.web_discovery?.web_files || []) as any[])
        .map(
          (wf) =>
            `- **[${wf.file_type}] \`${wf.path}\`** (${(wf.size_bytes / 1024).toFixed(1)} Ko) — Dossiers appelés : ${(wf.folder_calls || []).join(', ') || 'aucun'} | Appels API/Assets : ${(wf.api_and_asset_refs || []).slice(0, 8).join(', ') || 'aucun'}${wf.json_payload_keys?.length ? ` | Clés JSON : \`${wf.json_payload_keys.join(', ')}\`` : ''}`
        )
        .join('\n') || '- Aucun fichier inspecté';

    const dirsMd =
      ((rep.web_discovery?.directories || []) as any[])
        .map(
          (d) =>
            `- **\`${d.folder_path}\`** (${d.classification}, ${d.call_count} appel(s)) — Lien d'arborescence par source : ${(d.source_files || []).join(', ')}`
        )
        .join('\n') || '- Aucun sous-dossier détecté';

    const routesMd =
      ((rep.web_discovery?.routes || []) as any[])
        .map((r) => `- **[${r.method}] \`${r.path}\`** — Source : ${r.source}`)
        .join('\n') || '- Aucune route détectée';

    const formsMd =
      ((rep.web_discovery?.forms || []) as any[])
        .map((f) => {
          const inps =
            ((f.inputs || []) as any[])
              .map((i) => `\`${i.name}\` (${i.input_type} • ${i.classification})`)
              .join(', ') || 'aucun champ';
          return `- **Form #${f.index} \`${f.id_or_name}\`** [${f.method} ➔ \`${f.action}\`] (CSRF: ${f.has_csrf_token ? 'OUI' : 'NON'}, Posture: ${f.security_posture})\n  - Champs reçus : ${inps}`;
        })
        .join('\n') || '- Aucun formulaire HTML détecté';

    const bridgeMd =
      astBridgeItems
        .map(
          (b) =>
            `- \`${b.externalRef}\` (${b.refType}) ➔ **${b.isMapped ? 'MAPPÉ AST' : 'NON RÉSOLU'}** : \`${b.matchedLabel}\` [${b.matchedLayer}]`
        )
        .join('\n') || '- Aucun pont AST calculé';

    const sensMd =
      ((rep.exposed_artifacts || []) as any[])
        .map(
          (a) =>
            `- \`${a.path}\` (${a.label}) : **${a.exposed ? 'EXPOSÉ' : 'PROTÉGÉ'}** — ${a.redacted_preview || a.http_status}`
        )
        .join('\n') || '- Non audité';

    const findingsMd =
      ((rep.findings || []) as any[])
        .map(
          (f) =>
            `- **[${f.severity}] ${f.id} (${f.cwe})** — ${f.title}\n  - Diagnostic : ${f.description}\n  - Remédiation : ${f.remediation}`
        )
        .join('\n') || '- Aucune vulnérabilité de surface détectée.';

    const verifMd =
      ((rep.verification_suite || []) as any[])
        .map(
          (v) =>
            `- **[${v.id}] (${v.category}) ${v.title}**\n  - Commande non-destructive : \`${v.assertion_cmd}\`\n  - Assertion attendue : ${v.expected_result}\n  - Correctif type : ${v.patch_hint}`
        )
        .join('\n') || '- Aucune vérification générée.';

    const sideOneMd =
      ((rep.boundary_weaknesses || []) as any[])
        .map(
          (p) =>
            `- **[${p.status}] ${p.id} (${p.cwe} • ${p.category})**\n  - Vecteur Externe (Côté 1) : \`${p.side_one_vector}\`\n  - Comportement observé : ${p.observed_behavior}`
        )
        .join('\n') || '- Aucune sonde de frontière exécutée.';

    const sideTwoMd =
      sideTwoWeaknessSuite
        .map(
          (s) =>
            `- **Couple de Tests AST (${s.cwe}) — Cible : \`${s.astNodeLabel}\` (${s.isAstMapped ? 'Mappé dans l\'AST local' : 'Cible fonctionnelle'})**\n  - Entrée Externe Côté 1 : \`${s.sideOneVector}\`\n  - ✅ **Test Positif Nominal \`${s.positiveTestFn}\`** : ${s.positiveTestSpec}\n  - 🚫 **Test Négatif Frontière \`${s.negativeTestFn}\`** : ${s.negativeTestSpec}`
        )
        .join('\n') || '- Aucun test Côté 2 généré.';

    const mcpFooter = `\n\n## 🛠️ Commandes MCP Combinées AetherScope à Exécuter
1. **Recherche AST + Violations CWE (2-en-1) :** \`aetherscope_search_symbols({"stereotype": "«Controller»", "has_violation": true})\`
2. **Inspection Cible + Caméra 3D + Trace MVC (3-en-1) :** \`aetherscope_get_active_target({"symbol_id": "<handler_cible>", "action": "Surface Audit", "trace_direction": "both"})\`
3. **Validation Pare-Feu < 50ms + Tâche + Chat (4-en-1) :** \`aetherscope_verify_patch({"files_modified": ["<fichier_modifié>"], "status": "done", "chat_message": "Durcissement de surface validé (Grade A+)"})\``;

    if (mode === 'weakness') {
      return `# ⚖️ PROMPT BINÔME IA — MODE 4 BOOSTED : SUITE DE TESTS DE FAIBLESSE BILATÉRALE (CÔTÉ 1 BLACK-BOX ↔ CÔTÉ 2 WHITE-BOX AST : TESTS POSITIFS & NÉGATIFS)
- **Cible auditée :** \`${rep.target_raw}\` (\`${rep.scheme}://${rep.host}:${rep.primary_port}\`)
- **Score de Posture :** **${rep.security_score}/100 (Grade ${rep.grade})**
- **Approche Miroir Bilatérale :**
  1. **Côté 1 (Externe / Black-Box Boosted)** : Sondes de perméabilité des frontières HTTP (CORS Origin Reflection, verbes HTTP OPTIONS, indexation des dossiers CWE-548, drapeaux de cookies CWE-1004, contrats des formulaires «Form» CWE-352 et clés JSON CWE-20/CWE-88, dotfiles CWE-538).
  2. **Côté 2 (Interne / Après Scan Black-Box ➔ Code Source & AST)** : Corrélation de chaque point d'entrée externe avec les handlers/sinks AST locaux et génération conjointe des **Tests Unitaires Positifs (\`test_accept_*_nominal()\`)** et des **Tests Unitaires Négatifs (\`test_reject_*_boundary()\`)**.

## 🌐 CÔTÉ 1 : Résultats des Sondes de Faiblesse de Frontière (Externe / Black-Box)
${sideOneMd}

## 🧬 CÔTÉ 2 : Matrice de Réceptivité AST & Suite de Tests Positifs + Négatifs (Après Scan Black-Box)
${sideTwoMd}

## 🔗 Pont Hybride Surface Externe ↔ Fichiers Sources AST Locaux
${bridgeMd}

## 🎯 Instructions pour le Binôme IA
1. **Suite Côté 1 (Tests de Frontière HTTP)** : Génère les tests automatisés non-destructifs vérifiant le comportement nominal (\`200 OK\`) ET le rejet des origines CORS non autorisées, des verbes HTTP inattendus (\`405\`), et du Directory Listing (\`403/404\`).
2. **Suite Côté 2 (Tests Unitaires Positifs & Négatifs AST)** : Écris conjointement les fonctions \`test_accept_*_nominal()\` (garantissant que les flux légitimes passent sans faux positif) ET \`test_reject_*_boundary()\` (prouvant que le validateur rejette les entrées malformées avant tout sink interne).${mcpFooter}`;
    }

    if (mode === 'hardening') {
      return `# 🛡️ PROMPT BINÔME IA — MODE 2 : PLAN DE DURCISSEMENT & CORRECTIFS CODE CIBLÉS
- **Cible auditée :** \`${rep.target_raw}\` (Hôte : \`${rep.host}:${rep.primary_port}\`, Score actuel : **${rep.security_score}/100 — Grade ${rep.grade}**)
- **Stack identifiée :** ${((rep.tech_stack || []) as any[]).map((t) => `${t.name}${t.version ? ' ' + t.version : ''}`).join(', ') || 'Serveur HTTP / TCP'}

## 1. Pont Hybride Surface Externe ↔ Fichiers Sources AST Locaux
${bridgeMd}

## 2. Diagnostics de Posture & Failles à Corriger Prioritairement
${findingsMd}

## 3. Formulaires («Form»), Types de Requêtes & Contrats de Données Détectés
${formsMd}
${routesMd}

## 4. Exposition des Fichiers Sensibles (CWE-538 — Valeurs Masquées)
${sensMd}

## 🎯 Instructions pour le Binôme IA (Génération des Correctifs)
1. **Middlewares & En-têtes HTTP** : Fournis le code exact pour injecter \`Content-Security-Policy\`, \`X-Frame-Options: DENY\`, \`X-Content-Type-Options: nosniff\` et \`Strict-Transport-Security\`.
2. **Protection des Formulaires & Routes API** : Ajoute la validation de schéma et anti-CSRF sur les routes et clés JSON extraites ci-dessus.
3. **Blocage CWE-538** : Interdis l'accès HTTP aux dotfiles (\`.env\`, \`.git/*\`, \`docker-compose.yml\`).${mcpFooter}`;
    }

    if (mode === 'tests') {
      return `# 🧪 PROMPT BINÔME IA — MODE 3 : SUITE DE TESTS DE CONFORMITÉ DÉFENSIFS & NON-RÉGRESSION CI
- **Cible auditée :** \`${rep.target_raw}\` (\`${rep.scheme}://${rep.host}:${rep.primary_port}\`)
- **Score actuel :** **${rep.security_score}/100 (Grade ${rep.grade})**
- **Contrainte stricte :** Tests 100% défensifs, non-destructifs (assertions d'en-têtes \`curl -sSI\`, codes HTTP 403/404 sur dotfiles, présence de jetons CSRF).

## 1. Assertions de Conformité Générées Automatiquement par AetherScope
${verifMd}

## 2. Cascade X-Ray : Fichiers (.html/.js), Routes & Clés JSON à Couvrir
${filesMd}
${routesMd}

## 3. Pont AST Local pour les Tests d'Intégration
${bridgeMd}

## 🎯 Instructions pour le Binôme IA
1. Génère un script de vérification défensif exécutable en CI qui valide chacune des assertions ci-dessus sans aucun payload offensif.
2. Ajoute un test d'intégration pour chaque route mappée dans l'AST local afin de garantir le maintien du **Grade A+ (100/100)**.${mcpFooter}`;
    }

    return `# 📐 PROMPT BINÔME IA — MODE 1 : REVUE D'ARCHITECTURE, CHEMINEMENT DE DATA, ARBORESCENCE HTML & PONT AST
- **Cible auditée :** \`${rep.target_raw}\` (Hôte : \`${rep.host}\`, Port primaire : \`${rep.primary_port}\`)
- **Module d'Impact & Visibilité :** ${im.level_name || 'Niveau 4'} (${im.visibility_footprint || ''})
- **Classification :** ${rep.target_classification} | **IP(s) :** ${(rep.resolved_ips || []).join(', ') || 'Non résolu'}
- **Score de Posture :** **${rep.security_score}/100 (Grade ${rep.grade})** | **Statut HTTP :** ${rep.http_status || 'N/A'}

## 1. Carte des 4 Frontières de Confiance (Swimlanes Architecturales)
${trustMd}

## 2. Pont Hybride « Surface Externe ↔ Graphe AST Local »
${bridgeMd}

## 3. Cascade X-Ray par Fichier Source (.html ➔ .js ➔ Appels API & Clés JSON)
${filesMd}

## 4. Lien d'Arborescence des Dossiers & Modules par Source HTML
${dirsMd}

## 5. Types de Requêtes, Routes API, #Links, URLs & Formulaires («Form» / Cheminement de Data)
${routesMd}
${formsMd}
${((rep.web_discovery?.html_links || []) as any[]).slice(0, 25).map((l: any) => `- [${l.kind}] \`${l.target}\` ➔ \`${l.resolved_path}\` (${l.tag_context})`).join('\n')}

## 6. Services, Versions, Ports TCP & Fichiers Sensibles (CWE-538 Masqué)
${techMd}
${openPortsMd}
${sensMd}

## 7. Diagnostics & Remédiations Architecturales
${findingsMd}

## 🎯 Instructions pour le Binôme IA
Analyse cette topologie complète (du fichier \`.html\`/\`.js\` externe jusqu'au contrôleur AST local), vérifie le cheminement des données et types de requêtes, identifie les routes fantômes non mappées dans l'AST, et propose une architecture de défense en profondeur pour atteindre **100/100 (Grade A+)**.${mcpFooter}`;
  }

  const surfacePromptText = $derived.by(() =>
    buildSurfaceMarkdownPrompt(report, surfacePromptTab)
  );

  function copySurfacePrompt() {
    if (!surfacePromptText) return;
    navigator.clipboard?.writeText(surfacePromptText);
    promptCopied = true;
    playSpatialTone(cockpitState.settings.soundEnabled, 'success');
    setTimeout(() => (promptCopied = false), 1600);
  }

  function copySurfaceJson() {
    if (!report) return;
    navigator.clipboard?.writeText(JSON.stringify(report, null, 2));
    jsonCopied = true;
    playSpatialTone(cockpitState.settings.soundEnabled, 'success');
    setTimeout(() => (jsonCopied = false), 1600);
  }

  async function sendReportToCopilot() {
    if (!report || !surfacePromptText) return;
    sendingToCopilot = true;
    try {
      await api.sendChatMessage(surfacePromptText, 'user');
      cockpitState.isSurfaceScannerOpen = false;
      cockpitState.isChatOpen = true;
    } catch {
      // ignore
    } finally {
      sendingToCopilot = false;
    }
  }

  async function launchScan() {
    if (!target.trim()) return;
    isScanning = true;
    errorMsg = null;
    sideTwoUnlocked = false;
    selectedFileFilter = 'ALL';
    progressPct = 12;
    progressStep = `Initialisation de l'audit Niveau ${scanLevel} sur ${target.trim()}...`;

    const steps = [
      { pct: 25, msg: `Résolution DNS & classification IP sur ${target.trim()}...` },
      { pct: 48, msg: 'Sonde TCP multi-ports, banner grabbing & détection des versions...' },
      {
        pct: 74,
        msg: 'Scan architectural par source (.html ➔ .js), arborescence dossiers, types de requêtes & «Form»...'
      },
      { pct: 90, msg: 'Contrôle CWE-538 (.env / .git masqués), sondes de frontière & score de posture...' }
    ];
    let idx = 0;
    const timer = setInterval(() => {
      if (idx < steps.length) {
        progressPct = steps[idx].pct;
        progressStep = steps[idx].msg;
        idx++;
      }
    }, 340);

    playSpatialTone(cockpitState.settings.soundEnabled, 'action');

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
        custom_ports: customPorts.trim() || undefined
      });
      clearInterval(timer);
      progressPct = 100;
      progressStep = `Audit complété en ${report.scan_duration_ms ?? 0} ms — Score ${report.security_score ?? 0}/100 (Grade ${report.grade || '—'})`;
    } catch (e: any) {
      clearInterval(timer);
      progressPct = 0;
      progressStep = '';
      errorMsg = e?.message || 'Erreur lors du scan de surface (serveur local requis).';
    } finally {
      isScanning = false;
    }
  }

  function closeModal() {
    cockpitState.isSurfaceScannerOpen = false;
  }

  function methodBadgeClass(method: string): string {
    const m = (method || '').toUpperCase();
    if (m.includes('POST')) return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    if (m.includes('DELETE')) return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
    if (m.includes('PUT') || m.includes('PATCH')) return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    if (m.includes('ANCHOR') || m.includes('#')) return 'bg-amber-500/20 text-amber-200 border-amber-400/45';
    if (m.includes('WS') || m.includes('EXTERNAL')) return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
    return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
  }

  function postureColor(posture: string): string {
    if (posture === 'PASS' || posture === 'ROBUSTE') return 'border-emerald-500/50 text-emerald-300';
    if (posture === 'WARN' || posture === 'FAIBLESSE') return 'border-amber-500/50 text-amber-300';
    return 'border-rose-500/60 text-rose-300';
  }
</script>

{#if cockpitState.isSurfaceScannerOpen}
  <div
    class="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-3 sm:p-5 select-text"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.target === e.currentTarget && closeModal()}
    onkeydown={(e) => e.key === 'Escape' && closeModal()}
  >
    <div class="w-full max-w-[1160px] max-h-[92vh] bg-[#0b1120] border border-slate-400/25 rounded-xl shadow-[0_24px_80px_rgba(2,6,23,0.92)] flex flex-col overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3.5 bg-[#0f172a] border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-400/30 flex items-center justify-center text-sky-400">
            <Radar class="w-4 h-4" />
          </div>
          <div>
            <h2 class="text-sm font-bold text-slate-100">
              Audit de Surface, Architecture Fichiers (.html / .js), Cheminement Data & Studio Binôme IA
            </h2>
            <p class="text-[11px] text-slate-400 font-mono">
              Adresse:Port • Type de Requête • Lien d'Arborescence par Source HTML • 4 Frontières de Confiance • Pont AST Local • Miroir Côté 1 ↔ Côté 2
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            onclick={saveBaselineSnapshot}
            disabled={!report}
            title="Figer le scan actuel comme référence pour comparer Avant / Après"
            class="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-sky-400/35 text-[11px] font-mono text-sky-300 cursor-pointer"
          >
            <BookmarkCheck class="w-3.5 h-3.5" />
            <span>{baseline ? `📸 Baseline (${baseline.security_score}/100)` : '📸 Figer Baseline'}</span>
          </button>

          <span
            class="px-2.5 py-1 rounded-md text-[11px] font-mono font-bold border {report
              ? report.security_score >= 85
                ? 'bg-emerald-950/60 border-emerald-400/50 text-emerald-300'
                : report.security_score >= 65
                  ? 'bg-amber-950/60 border-amber-400/50 text-amber-300'
                  : 'bg-rose-950/60 border-rose-400/50 text-rose-300'
              : 'bg-slate-800/90 border-slate-600/40 text-slate-200'}"
          >
            {isScanning
              ? 'Audit en cours...'
              : report
                ? `Grade ${report.grade} • ${report.security_score}/100`
                : 'Prêt'}
          </span>

          <button
            onclick={closeModal}
            aria-label="Fermer le scanner de surface"
            class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- Scrollable Body -->
      <div class="flex-1 overflow-y-auto p-4 space-y-3.5">
        <!-- 1. Barre de Cible + Progression + 4 Niveaux d'Impact + Presets -->
        <div class="p-3.5 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-2.5">
          <div class="flex flex-wrap items-center gap-2">
            <div class="flex-1 min-w-[260px] flex items-center gap-2 bg-[#090d16] border border-slate-400/25 rounded-lg px-3 py-1.5 focus-within:border-sky-400">
              <Globe class="w-4 h-4 text-slate-400 shrink-0" />
              <input
                type="text"
                bind:value={target}
                onkeydown={(e) => e.key === 'Enter' && launchScan()}
                placeholder="Domaine, IP:Port, Dossier ou Fichier (ex: 127.0.0.1:3030, example.com/index.html)"
                class="flex-1 bg-transparent border-none text-xs font-mono font-semibold text-slate-100 focus:outline-none"
              />
            </div>

            <input
              type="text"
              bind:value={customPorts}
              onkeydown={(e) => e.key === 'Enter' && launchScan()}
              placeholder="Ports + (ex: 9000,3333)"
              title="Ports TCP supplémentaires à sonder"
              class="w-44 px-2.5 py-1.5 rounded-lg bg-[#090d16] border border-slate-400/25 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-400"
            />

            <button
              type="button"
              disabled={isScanning}
              onclick={launchScan}
              class="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 border border-sky-400 text-xs font-bold text-white cursor-pointer"
            >
              <Play class="w-3.5 h-3.5" />
              <span>{isScanning ? `Audit Niv.${scanLevel}...` : "Lancer l'Audit"}</span>
            </button>
          </div>

          <!-- Progress Bar -->
          {#if isScanning || progressPct > 0}
            <div class="p-2 rounded-lg bg-[#090d16] border border-sky-400/25 space-y-1">
              <div class="flex items-center justify-between text-[10.5px] font-mono">
                <span class="text-slate-300">{progressStep}</span>
                <span class="text-sky-400 font-bold">{progressPct}%</span>
              </div>
              <div class="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  class="h-full bg-gradient-to-r from-sky-500 to-emerald-400 transition-all duration-200"
                  style="width: {progressPct}%"
                ></div>
              </div>
            </div>
          {/if}

          <!-- 4 Level Cards -->
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            <button
              type="button"
              onclick={() => selectScanLevel(1)}
              class="text-left p-2.5 rounded-lg border transition cursor-pointer {scanLevel === 1
                ? 'bg-slate-800/90 border-emerald-400'
                : 'bg-[#090d16] border-slate-400/15 hover:border-slate-400/35'}"
            >
              <div class="flex items-center justify-between font-mono">
                <span class="text-[11px] font-bold text-slate-100">NIVEAU 1 • FURTIF</span>
                <span class="text-[9.5px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300">Passif</span>
              </div>
              <p class="text-[10px] text-slate-400 mt-1 leading-snug">
                Visibilité minimale (~2 pqts) • DNS, IP & Sonde HTTP <code>HEAD</code>
              </p>
            </button>

            <button
              type="button"
              onclick={() => selectScanLevel(2)}
              class="text-left p-2.5 rounded-lg border transition cursor-pointer {scanLevel === 2
                ? 'bg-slate-800/90 border-amber-400'
                : 'bg-[#090d16] border-slate-400/15 hover:border-slate-400/35'}"
            >
              <div class="flex items-center justify-between font-mono">
                <span class="text-[11px] font-bold text-slate-100">NIVEAU 2 • SERVICES</span>
                <span class="text-[9.5px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300">Modéré</span>
              </div>
              <p class="text-[10px] text-slate-400 mt-1 leading-snug">
                Visibilité modérée (~15 pqts) • Ports TCP, Bannières & Versions
              </p>
            </button>

            <button
              type="button"
              onclick={() => selectScanLevel(3)}
              class="text-left p-2.5 rounded-lg border transition cursor-pointer {scanLevel === 3
                ? 'bg-slate-800/90 border-sky-400'
                : 'bg-[#090d16] border-slate-400/15 hover:border-slate-400/35'}"
            >
              <div class="flex items-center justify-between font-mono">
                <span class="text-[11px] font-bold text-slate-100">NIVEAU 3 • ARCHI WEB</span>
                <span class="text-[9.5px] px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300">Fichiers/Forms</span>
              </div>
              <p class="text-[10px] text-slate-400 mt-1 leading-snug">
                Arborescence par source (<code>.html</code>, <code>.js</code>), Dossiers, Requêtes & «Form»
              </p>
            </button>

            <button
              type="button"
              onclick={() => selectScanLevel(4)}
              class="text-left p-2.5 rounded-lg border transition cursor-pointer {scanLevel === 4
                ? 'bg-slate-800/90 border-purple-400'
                : 'bg-[#090d16] border-slate-400/15 hover:border-slate-400/35'}"
            >
              <div class="flex items-center justify-between font-mono">
                <span class="text-[11px] font-bold text-slate-100">NIVEAU 4 • COMPLET</span>
                <span class="text-[9.5px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">CWE-538</span>
              </div>
              <p class="text-[10px] text-slate-300 mt-1 leading-snug">
                Audit complet + <code>.env</code>, <code>.git</code> & Configs (Masqué)
              </p>
            </button>
          </div>

          <!-- Presets & Checkboxes -->
          <div class="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div class="flex flex-wrap items-center gap-1.5 font-mono text-[10.5px]">
              <span class="text-slate-500">Cibles rapides :</span>
              <button
                type="button"
                onclick={() => applyPreset('127.0.0.1:3030')}
                class="px-2 py-0.5 rounded bg-[#090d16] hover:bg-slate-800 border border-slate-400/25 text-slate-300 cursor-pointer"
              >
                Cockpit (:3030)
              </button>
              <button
                type="button"
                onclick={() => applyPreset('127.0.0.1:5000')}
                class="px-2 py-0.5 rounded bg-[#090d16] hover:bg-slate-800 border border-slate-400/25 text-slate-300 cursor-pointer"
              >
                Control-Plane (:5000)
              </button>
              <button
                type="button"
                onclick={() => applyPreset('localhost:8080')}
                class="px-2 py-0.5 rounded bg-[#090d16] hover:bg-slate-800 border border-slate-400/25 text-slate-300 cursor-pointer"
              >
                Proxy (:8080)
              </button>
              <button
                type="button"
                onclick={() => applyPreset('example.com')}
                class="px-2 py-0.5 rounded bg-[#090d16] hover:bg-slate-800 border border-slate-400/25 text-slate-300 cursor-pointer"
              >
                example.com
              </button>
            </div>

            <div class="flex flex-wrap items-center gap-3 text-[10.5px] font-mono text-slate-300">
              <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" bind:checked={checkDns} class="accent-sky-400" /> DNS/IP</label>
              <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" bind:checked={checkPorts} class="accent-sky-400" /> Ports/Bannières</label>
              <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" bind:checked={checkHeaders} class="accent-sky-400" /> Headers/Versions</label>
              <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" bind:checked={checkEndpoints} class="accent-sky-400" /> robots.txt</label>
              <label class="flex items-center gap-1 cursor-pointer text-white"><input type="checkbox" bind:checked={checkWebForms} class="accent-sky-400" /> Fichiers (.html/.js), Dossiers & «Form»</label>
              <label class="flex items-center gap-1 cursor-pointer text-white"><input type="checkbox" bind:checked={checkSensitiveFiles} class="accent-sky-400" /> .env/.git (Masqué)</label>
            </div>
          </div>
        </div>

        {#if errorMsg}
          <div class="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-xs text-rose-200 font-mono">
            {errorMsg}
          </div>
        {/if}

        <!-- 1b. Bandeau Différentiel Avant / Après (Snapshot Baseline) -->
        {#if deltaStats}
          <div class="p-2.5 rounded-lg bg-emerald-950/25 border border-emerald-500/35 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
            <div class="flex flex-wrap items-center gap-2.5">
              <GitCompareArrows class="w-4 h-4 text-emerald-400" />
              <strong class={deltaStats.scoreDiff >= 0 ? 'text-emerald-300' : 'text-rose-300'}>
                ⚖️ COMPARAISON AVANT / APRÈS : {deltaStats.baseScore}/100 ({deltaStats.baseGrade}) ➔ {report.security_score}/100 ({report.grade}) [{deltaStats.scoreDiff >= 0 ? `+${deltaStats.scoreDiff}` : deltaStats.scoreDiff} pts]
              </strong>
              <span class="text-slate-300">
                • ✅ {deltaStats.resolvedCount} alerte(s) corrigée(s) • ⚠️ {deltaStats.newCount} nouvelle(s) alerte(s) • Ports: {deltaStats.portsDiff >= 0 ? `+${deltaStats.portsDiff}` : deltaStats.portsDiff} • Cible Baseline: {deltaStats.baseTarget} ({deltaStats.savedAt})
              </span>
            </div>
            <button
              type="button"
              onclick={clearBaselineSnapshot}
              class="px-2 py-0.5 rounded bg-[#090d16] hover:bg-slate-800 border border-slate-400/30 text-[10px] text-slate-400 hover:text-white cursor-pointer"
            >
              ✕ Effacer Baseline
            </button>
          </div>
        {/if}

        <!-- 2. Bandeau 5 KPIs -->
        <div class="grid grid-cols-2 sm:grid-cols-5 gap-2">
          <div class="p-2.5 rounded-lg bg-[#0f172a] border border-slate-400/15 font-mono">
            <div class="text-[9.5px] text-slate-400">SCORE DE POSTURE</div>
            <div
              class="text-base font-extrabold mt-0.5 {report
                ? report.security_score >= 85
                  ? 'text-emerald-400'
                  : report.security_score >= 65
                    ? 'text-amber-400'
                    : 'text-rose-400'
                : 'text-slate-100'}"
            >
              {report ? `${report.security_score}/100 (${report.grade})` : '-- / 100'}
            </div>
          </div>

          <div
            class="p-2.5 rounded-lg bg-[#0f172a] border border-slate-400/15 font-mono"
            title={report?.impact_matrix ? `${report.impact_matrix.visibility_footprint} — ${report.impact_matrix.impact_rating}` : ''}
          >
            <div class="text-[9.5px] text-slate-400">NIVEAU & EMPREINTE</div>
            <div class="text-[11px] font-semibold text-slate-200 mt-1 truncate">
              {report?.impact_matrix
                ? `${report.impact_matrix.level_name} (${report.impact_matrix.packets_sent_estimate})`
                : `Niveau ${scanLevel} • Prêt`}
            </div>
          </div>

          <div class="p-2.5 rounded-lg bg-[#0f172a] border border-slate-400/15 font-mono">
            <div class="text-[9.5px] text-slate-400">RÉSOLUTION DNS & IP</div>
            <div class="text-[11px] font-semibold text-slate-200 mt-1 truncate">
              {report
                ? `${(report.resolved_ips || []).join(', ') || 'Non résolu'} (${report.dns_latency_ms || 0} ms) • ${report.target_classification || ''}`
                : 'En attente...'}
            </div>
          </div>

          <div class="p-2.5 rounded-lg bg-[#0f172a] border border-slate-400/15 font-mono">
            <div class="text-[9.5px] text-slate-400">SERVICES & VERSIONS</div>
            <div class="text-[11px] font-bold text-sky-300 mt-1 truncate">
              {report
                ? `${((report.open_ports || []) as any[]).filter((p) => p.open).length} service(s) actif(s) • ${report.impact_matrix?.detected_versions_count ?? 0} version(s)`
                : '0 service(s)'}
            </div>
          </div>

          <div class="p-2.5 rounded-lg bg-[#0f172a] border border-slate-400/15 font-mono">
            <div class="text-[9.5px] text-slate-400">HTTP, FICHIERS & FORMS</div>
            <div class="text-[11px] font-semibold text-slate-200 mt-1 truncate">
              {report
                ? `${report.http_status || 'Pas de HTTP'} • ${forms.length} Form(s) / ${totalInputsCount} Champ(s)`
                : '--'}
            </div>
          </div>
        </div>

        <!-- 3. Identification des Services, Versions, Bannières & Stack Technologique -->
        <div class="p-3 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-2">
          <div class="flex items-center justify-between font-mono">
            <span class="text-[11px] font-bold text-slate-200">
              SERVICES, VERSIONS, BANNIÈRES & STACK TECHNOLOGIQUE
            </span>
            <span class="text-[10px] text-slate-400">
              {report ? `${(report.tech_stack || []).length} composant(s) / version(s) identifié(s)` : 'En attente'}
            </span>
          </div>

          {#if !report}
            <div class="text-[11px] text-slate-500 font-mono">
              Lancez l'audit pour identifier les services TCP, bannières protocolaires, serveurs HTTP et versions logicielles.
            </div>
          {:else if (report.tech_stack || []).length === 0}
            <div class="text-[11px] text-slate-500 font-mono">
              Aucune bannière logicielle ou version exposée (posture furtive ou Niveau 1).
            </div>
          {:else}
            <div class="flex flex-wrap gap-1.5">
              {#each report.tech_stack as t}
                <div class="px-2.5 py-1 rounded-md bg-indigo-950/60 border border-purple-400/40 flex items-center gap-1.5 font-mono text-[10.5px]">
                  <span class="text-purple-300 font-extrabold uppercase text-[9.5px]">[{t.category}]</span>
                  <strong class="text-white">{t.name}</strong>
                  {#if t.version}
                    <span class="px-1.5 py-0.2 rounded bg-emerald-500/20 border border-emerald-400/40 text-emerald-300 font-bold text-[9.5px]">
                      v: {t.version}
                    </span>
                  {/if}
                  <span class="text-slate-400 text-[9.5px]">({t.source} • {t.confidence})</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>

        <!-- 4. Architecture Web : 4 Frontières de Confiance, Cheminement de Data, Cascade X-Ray (.html ➔ .js ➔ API), Arborescence Dossiers & Pont AST -->
        <div class="p-3.5 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2 font-mono">
            <span class="text-xs font-bold text-slate-100 flex items-center gap-1.5">
              <Layers class="w-4 h-4 text-sky-400" />
              <span>ARCHITECTURE WEB : 4 FRONTIÈRES DE CONFIANCE, CHEMINEMENT DE DATA, LIEN D'ARBORESCENCE PAR SOURCE HTML & PONT AST</span>
            </span>
            <span class="text-[10.5px] text-slate-400">
              {#if report?.web_discovery}
                {report.web_discovery.is_web_arch ? '🌐 Architecture Web Détectée' : '⚡ Service Réseau/API'} • {webFiles.length} Source(s) • {directories.length} Dossier(s) • {routes.length} Route(s) • {forms.length} Form(s) ({totalInputsCount} Champ(s))
              {:else}
                Prêt
              {/if}
            </span>
          </div>

          <!-- 4.1 4 Frontières de Confiance (Swimlanes) -->
          {#if report?.trust_zones && report.trust_zones.length > 0}
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {#each report.trust_zones as tz}
                <div class="p-2.5 rounded-lg bg-[#090d16] border border-slate-400/15 border-t-2 {postureColor(tz.posture)} font-mono space-y-1">
                  <div class="flex items-center justify-between gap-1 text-[10.5px]">
                    <strong class="text-slate-100 truncate">{tz.title}</strong>
                    <span class="font-extrabold text-[9.5px]">[{tz.posture}]</span>
                  </div>
                  <div class="text-[10px] text-slate-400">{tz.subtitle}</div>
                  {#if tz.controls && tz.controls.length > 0}
                    <div class="text-[9.5px] text-sky-300 truncate" title={tz.controls.join('\n')}>
                      {tz.controls.join(' • ')}
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <div class="p-2.5 rounded-lg bg-[#090d16] border border-slate-400/15 text-[11px] text-slate-500 font-mono text-center">
              Les 4 Frontières de Confiance (Client .html/.js ➔ Formulaires «Form» ➔ Dossiers & API ➔ Services TCP & Secrets) s'afficheront ici après le scan.
            </div>
          {/if}

          <!-- 4.2 Graphe Visuel du Cheminement de Data (4 Nœuds Connectés) -->
          {#if report?.web_discovery}
            <div class="p-3 rounded-lg bg-[#090d16] border border-slate-400/15">
              <div class="text-[10px] font-mono text-sky-400 font-bold mb-2">
                🔀 CHEMINEMENT DE DATA DEPUIS L'EXTÉRIEUR (ENTRÉE ADRESSE:PORT ➔ SOURCE HTML/JS ➔ REQUÊTES & FORMULAIRES ➔ BACKEND)
              </div>
              <div class="grid grid-cols-1 lg:grid-cols-[1fr_auto_1.15fr_auto_1.15fr_auto_1fr] gap-2 items-center font-mono">
                <div class="p-2.5 rounded-lg bg-slate-900/90 border border-sky-400/45 space-y-0.5">
                  <div class="text-[11px] font-extrabold text-white">🌐 1. ENTRÉE & SOURCES HTML</div>
                  <div class="text-[10.5px] text-sky-400 font-bold truncate">
                    {report.scheme?.toUpperCase()}://{report.host}:{report.primary_port}
                  </div>
                  <div class="text-[10px] text-slate-400">
                    {webFiles.length} Fichier(s) (.html/.js/.css) • {directories.length} Dossier(s)
                  </div>
                </div>

                <ArrowRight class="w-4 h-4 text-sky-400 hidden lg:block mx-auto" />

                <div class="p-2.5 rounded-lg bg-slate-900/90 border {forms.some((f) => f.security_posture !== 'PASS') ? 'border-amber-400/60' : 'border-emerald-400/45'} space-y-0.5">
                  <div class="text-[11px] font-extrabold text-white">📝 2. SURFACE «FORM» & INPUTS</div>
                  <div class="text-[10.5px] text-emerald-300 font-bold">
                    {forms.length} Formulaire(s) • {totalInputsCount} Champ(s) reçu(s)
                  </div>
                  <div class="text-[10px] text-slate-400 truncate">
                    {forms.length > 0
                      ? `Requêtes: ${[...new Set(forms.map((f) => f.method))].join(', ')}`
                      : 'Aucun <form> HTML direct'}
                  </div>
                </div>

                <ArrowRight class="w-4 h-4 text-sky-400 hidden lg:block mx-auto" />

                <div class="p-2.5 rounded-lg bg-slate-900/90 border border-purple-400/45 space-y-0.5">
                  <div class="text-[11px] font-extrabold text-white">🧭 3. ROUTES, REQUÊTES & JSON</div>
                  <div class="text-[10.5px] text-purple-300 font-bold">
                    {routes.length} Route(s) • {externalScripts.length} Script(s) JS
                  </div>
                  <div class="text-[10px] text-slate-400">
                    robots.txt: {robotsEntries.length} • security.txt: {report.web_discovery.security_txt_present ? 'OUI' : 'NON'}
                  </div>
                </div>

                <ArrowRight class="w-4 h-4 text-sky-400 hidden lg:block mx-auto" />

                <div class="p-2.5 rounded-lg bg-slate-900/90 border border-emerald-400/45 space-y-0.5">
                  <div class="text-[11px] font-extrabold text-white">🖥️ 4. SERVICES & BACKEND</div>
                  <div class="text-[10.5px] text-emerald-300 font-bold">
                    {((report.open_ports || []) as any[]).filter((p) => p.open).length} Port(s) TCP • {(report.tech_stack || []).length} Tech(s)
                  </div>
                  <div class="text-[10px] text-slate-400 truncate">
                    {((report.tech_stack || []) as any[]).slice(0, 2).map((t) => t.name).join(', ') || 'Serveur HTTP'}
                  </div>
                </div>
              </div>
            </div>

            <!-- 4.2b Architecture de Liens d'Appels en Arcs (Appels Arqués SVG : Source HTML ⁀➴ Forms & #Links ⁀➴ Modules .js ⁀➴ Endpoints API ⁀➴ AST) -->
            <div class="p-3 rounded-lg bg-[#090d16] border border-sky-400/30 space-y-2.5 font-mono">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div class="text-[10.5px] font-bold text-sky-300 flex items-center gap-1.5">
                    <span>🕸️ ARCHITECTURE DE LIENS D'APPELS EN ARCS (APPELS ARQUÉS : SOURCE HTML ⁀➴ «FORM» & #LINKS ⁀➴ MODULES .JS ⁀➴ ENDPOINTS API ⁀➴ AST)</span>
                  </div>
                  <div class="text-[9.5px] text-slate-400">
                    Cliquez sur un nœud ou survolez une arche de Bézier pour isoler sa chaîne d'appels • {archedCallGraph.arcs.length} / {archedCallGraph.allArcsCount || 0} appel(s) arqué(s) affiché(s)
                  </div>
                </div>

                <div class="flex flex-wrap items-center gap-1">
                  <button
                    type="button"
                    onclick={() => (archViewMode = 'ARC_DIAGRAM')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archViewMode === 'ARC_DIAGRAM'
                      ? 'bg-sky-600/45 border-sky-400 text-white font-bold'
                      : 'bg-[#0f172a] border-white/10 text-slate-300 hover:text-white'}"
                  >
                    🌈 Diagramme d'Arcs (Appels Arqués)
                  </button>
                  <button
                    type="button"
                    onclick={() => (archViewMode = 'TIERED_ARCS')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archViewMode === 'TIERED_ARCS'
                      ? 'bg-purple-600/45 border-purple-400 text-white font-bold'
                      : 'bg-[#0f172a] border-white/10 text-slate-300 hover:text-white'}"
                  >
                    🏛️ Architecture 5 Couches en Arcs
                  </button>
                </div>
              </div>

              <!-- Filtres par type d'appel arqué -->
              <div class="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                <div class="flex flex-wrap items-center gap-1">
                  <button
                    type="button"
                    onclick={() => {
                      archCallFilter = 'ALL';
                      selectedArchNodeId = null;
                    }}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archCallFilter === 'ALL' && !selectedArchNodeId
                      ? 'bg-slate-700 border-sky-400 text-white font-bold'
                      : 'bg-[#0f172a] border-white/10 text-slate-300'}"
                  >
                    Tous les Appels ({archedCallGraph.allArcsCount || 0})
                  </button>
                  <button
                    type="button"
                    onclick={() => (archCallFilter = archCallFilter === 'FORM' ? 'ALL' : 'FORM')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archCallFilter === 'FORM'
                      ? 'bg-emerald-600/35 border-emerald-400 text-emerald-100 font-bold'
                      : 'bg-[#0f172a] border-emerald-500/25 text-emerald-300'}"
                  >
                    📝 Appels Formulaires «Form» ({forms.length})
                  </button>
                  <button
                    type="button"
                    onclick={() => (archCallFilter = archCallFilter === 'API' ? 'ALL' : 'API')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archCallFilter === 'API'
                      ? 'bg-sky-600/35 border-sky-400 text-sky-100 font-bold'
                      : 'bg-[#0f172a] border-sky-500/25 text-sky-300'}"
                  >
                    ⚡ Appels JS / Fetch API
                  </button>
                  <button
                    type="button"
                    onclick={() => (archCallFilter = archCallFilter === 'ANCHOR' ? 'ALL' : 'ANCHOR')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archCallFilter === 'ANCHOR'
                      ? 'bg-amber-600/35 border-amber-400 text-amber-100 font-bold'
                      : 'bg-[#0f172a] border-amber-500/25 text-amber-300'}"
                  >
                    #️⃣ Liens #link & Ancres ({hashLinks.length})
                  </button>
                  <button
                    type="button"
                    onclick={() => (archCallFilter = archCallFilter === 'AST' ? 'ALL' : 'AST')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {archCallFilter === 'AST'
                      ? 'bg-pink-600/35 border-pink-400 text-pink-100 font-bold'
                      : 'bg-[#0f172a] border-pink-500/25 text-pink-300'}"
                  >
                    🧬 Pont AST & Dossiers
                  </button>
                  {#if selectedArchNodeId}
                    <button
                      type="button"
                      onclick={() => (selectedArchNodeId = null)}
                      class="px-2 py-0.5 rounded text-[9.5px] bg-rose-500/20 border border-rose-400/50 text-rose-200 cursor-pointer"
                    >
                      ✕ Réinitialiser focus nœud
                    </button>
                  {/if}
                </div>

                <div class="flex items-center gap-2 text-[9px] text-slate-400">
                  <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-sky-400 inline-block"></span>HTML</span>
                  <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-purple-400 inline-block"></span>Module .js</span>
                  <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-emerald-400 inline-block"></span>Form «Form»</span>
                  <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-amber-400 inline-block"></span>#Link</span>
                  <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-pink-400 inline-block"></span>Dossier / AST</span>
                </div>
              </div>

              <!-- Canevas SVG des Appels Arqués -->
              <div class="rounded-lg bg-[#050811] border border-slate-700/60 overflow-x-auto">
                <svg
                  viewBox="0 0 1060 335"
                  class="w-full min-w-[780px] h-[305px] select-none"
                  role="img"
                  aria-label="Architecture de liens d'appels en arcs"
                >
                  <defs>
                    <marker id="arch-arrow-emerald" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
                    </marker>
                    <marker id="arch-arrow-sky" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
                    </marker>
                    <marker id="arch-arrow-amber" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#fbbf24" />
                    </marker>
                    <marker id="arch-arrow-pink" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#ec4899" />
                    </marker>
                  </defs>

                  {#if archViewMode === 'ARC_DIAGRAM'}
                    <!-- Axe horizontal de l'architecture -->
                    <line x1="35" y1="212" x2="1025" y2="212" stroke="#1e293b" stroke-width="2" stroke-dasharray="4 4" />
                    <text x="42" y="22" fill="#34d399" font-size="9.5" font-family="monospace" font-weight="bold">
                      ▲ ARCHES SUPÉRIEURES : SOUMISSIONS «FORM» (HTML ⁀➴ FORM #1..N ⁀➴ [POST/GET] ENDPOINT ⁀➴ DOSSIER & AST)
                    </text>
                    <text x="42" y="324" fill="#38bdf8" font-size="9.5" font-family="monospace" font-weight="bold">
                      ▼ ARCHES INFÉRIEURES : BUNDLES .JS, REQUÊTES FETCH/XHR & ANCRES DOM (#LINKS)
                    </text>
                  {:else}
                    <!-- En-têtes des 5 couches architecturales -->
                    <text x="90" y="22" text-anchor="middle" fill="#38bdf8" font-size="9.5" font-family="monospace" font-weight="bold">1. SOURCE HTML</text>
                    <text x="280" y="22" text-anchor="middle" fill="#a855f7" font-size="9.5" font-family="monospace" font-weight="bold">2. MODULES .JS</text>
                    <text x="495" y="22" text-anchor="middle" fill="#10b981" font-size="9.5" font-family="monospace" font-weight="bold">3. «FORM» & #LINKS</text>
                    <text x="735" y="22" text-anchor="middle" fill="#60a5fa" font-size="9.5" font-family="monospace" font-weight="bold">4. ENDPOINTS API</text>
                    <text x="955" y="22" text-anchor="middle" fill="#ec4899" font-size="9.5" font-family="monospace" font-weight="bold">5. DOSSIERS & AST</text>
                  {/if}

                  <!-- Tracé des Appels Arqués (Courbes de Bézier) -->
                  {#each archedCallGraph.arcs as arc}
                    {@const isHovered = hoveredArcId === arc.id}
                    {@const dPath = archViewMode === 'ARC_DIAGRAM' ? arc.linearPath : arc.tieredPath}
                    {@const midX = archViewMode === 'ARC_DIAGRAM' ? arc.linearMidX : arc.tieredMidX}
                    {@const midY = archViewMode === 'ARC_DIAGRAM' ? arc.linearMidY : arc.tieredMidY}
                    {@const markerUrl =
                      arc.kind === 'FORM'
                        ? 'url(#arch-arrow-emerald)'
                        : arc.kind === 'ANCHOR'
                          ? 'url(#arch-arrow-amber)'
                          : arc.kind === 'AST'
                            ? 'url(#arch-arrow-pink)'
                            : 'url(#arch-arrow-sky)'}
                    <g
                      role="button"
                      tabindex="0"
                      class="cursor-pointer"
                      onmouseenter={() => (hoveredArcId = arc.id)}
                      onmouseleave={() => (hoveredArcId = null)}
                      onclick={() => (hoveredArcId = hoveredArcId === arc.id ? null : arc.id)}
                      onkeydown={(e) => e.key === 'Enter' && (hoveredArcId = hoveredArcId === arc.id ? null : arc.id)}
                    >
                      <!-- Halo d'arche au survol -->
                      {#if isHovered}
                        <path
                          d={dPath}
                          fill="none"
                          stroke={arc.color}
                          stroke-width="6"
                          stroke-opacity="0.28"
                        />
                      {/if}
                      <!-- Courbe de Bézier arquée principale -->
                      <path
                        d={dPath}
                        fill="none"
                        stroke={arc.color}
                        stroke-width={isHovered ? '2.8' : '1.75'}
                        stroke-opacity={hoveredArcId && !isHovered ? '0.32' : '0.88'}
                        stroke-dasharray={arc.kind === 'ANCHOR' ? '4 3' : undefined}
                        marker-end={markerUrl}
                      />
                      <!-- Badge au sommet de l'arche -->
                      {#if isHovered || archedCallGraph.arcs.length <= 16 || arc.kind === 'FORM'}
                        <rect
                          x={midX - 38}
                          y={midY - 8}
                          width="76"
                          height="15"
                          rx="4"
                          fill="#090d16"
                          fill-opacity="0.92"
                          stroke={arc.color}
                          stroke-width={isHovered ? '1.3' : '0.8'}
                        />
                        <text
                          x={midX}
                          y={midY + 2.5}
                          text-anchor="middle"
                          fill={arc.color}
                          font-size="8"
                          font-family="monospace"
                          font-weight="bold"
                        >
                          {arc.badge.length > 14 ? `${arc.badge.slice(0, 13)}…` : arc.badge}
                        </text>
                      {/if}
                    </g>
                  {/each}

                  <!-- Nœuds Architecturaux -->
                  {#each archedCallGraph.nodes as node}
                    {@const nx = archViewMode === 'ARC_DIAGRAM' ? node.linearX : node.tieredX}
                    {@const ny = archViewMode === 'ARC_DIAGRAM' ? node.linearY : node.tieredY}
                    {@const isNodeSel = selectedArchNodeId === node.id}
                    <g
                      role="button"
                      tabindex="0"
                      class="cursor-pointer"
                      onclick={() => (selectedArchNodeId = isNodeSel ? null : node.id)}
                      onkeydown={(e) => e.key === 'Enter' && (selectedArchNodeId = isNodeSel ? null : node.id)}
                    >
                      {#if archViewMode === 'ARC_DIAGRAM'}
                        <circle
                          cx={nx}
                          cy={ny}
                          r={isNodeSel ? '9' : '6.5'}
                          fill="#090d16"
                          stroke={node.color}
                          stroke-width={isNodeSel ? '3' : '2'}
                        />
                        <circle cx={nx} cy={ny} r="2.8" fill={node.color} />
                        <g transform={`translate(${nx}, ${ny + 14}) rotate(28)`}>
                          <rect
                            x="-4"
                            y="-9"
                            width={Math.min(126, Math.max(58, node.shortLabel.length * 5.7 + 10))}
                            height="14"
                            rx="3"
                            fill={isNodeSel ? '#1e293b' : '#0b1120'}
                            stroke={node.color}
                            stroke-width={isNodeSel ? '1.4' : '0.7'}
                          />
                          <text
                            x="2"
                            y="1"
                            fill="#f8fafc"
                            font-size="8.2"
                            font-family="monospace"
                            font-weight="bold"
                          >
                            {node.shortLabel.length > 20 ? `${node.shortLabel.slice(0, 19)}…` : node.shortLabel}
                          </text>
                        </g>
                      {:else}
                        <rect
                          x={nx - 76}
                          y={ny - 15}
                          width="152"
                          height="30"
                          rx="6"
                          fill={isNodeSel ? '#1e293b' : '#0b1120'}
                          stroke={node.color}
                          stroke-width={isNodeSel ? '2' : '1.2'}
                        />
                        <text
                          x={nx}
                          y={ny - 2}
                          text-anchor="middle"
                          fill="#f8fafc"
                          font-size="8.5"
                          font-family="monospace"
                          font-weight="bold"
                        >
                          {node.shortLabel.length > 22 ? `${node.shortLabel.slice(0, 21)}…` : node.shortLabel}
                        </text>
                        <text
                          x={nx}
                          y={ny + 9}
                          text-anchor="middle"
                          fill={node.color}
                          font-size="7.5"
                          font-family="monospace"
                        >
                          {node.subLabel.length > 25 ? `${node.subLabel.slice(0, 24)}…` : node.subLabel}
                        </text>
                      {/if}
                    </g>
                  {/each}
                </svg>
              </div>

              <!-- Inspecteur de l'Arche Active -->
              {#if archedCallGraph.activeArc}
                {@const act = archedCallGraph.activeArc}
                <div class="px-2.5 py-1.5 rounded bg-[#0f172a] border border-white/10 flex flex-wrap items-center justify-between gap-2 text-[10px]">
                  <div class="flex items-center gap-1.5 min-w-0">
                    <span class="px-1.5 py-0.5 rounded font-bold text-[9px] bg-black/50 border border-white/15" style={`color:${act.color}`}>
                      [{act.kind} • {act.method}]
                    </span>
                    <strong class="text-slate-100 truncate">{act.fromLabel}</strong>
                    <span class="text-sky-400 font-bold">⁀➴</span>
                    <strong class="text-emerald-300 truncate">{act.toLabel}</strong>
                  </div>
                  <div class="text-[9.5px] text-slate-300 truncate">
                    {act.detail}
                  </div>
                </div>
              {/if}
            </div>

            <!-- 4.3 Barre de Filtrage Interactive Cascade X-Ray par Fichier Source (.html / .js) -->
            <div class="p-2 rounded-lg bg-[#090d16] border border-sky-400/20 flex flex-wrap items-center gap-1.5 font-mono">
              <span class="text-[10.5px] font-bold text-sky-400">🧬 Cascade X-Ray par Source HTML / JS :</span>
              <button
                type="button"
                onclick={() => (selectedFileFilter = 'ALL')}
                class="px-2 py-0.5 rounded text-[10px] cursor-pointer border {selectedFileFilter === 'ALL'
                  ? 'bg-sky-600 border-sky-400 text-white font-bold'
                  : 'bg-[#0f172a] border-slate-400/25 text-slate-300 hover:text-white'}"
              >
                Tous ({webFiles.length})
              </button>
              {#each webFiles as wf}
                <button
                  type="button"
                  onclick={() => (selectedFileFilter = selectedFileFilter === wf.path ? 'ALL' : wf.path)}
                  class="px-2 py-0.5 rounded text-[10px] cursor-pointer border {selectedFileFilter === wf.path
                    ? 'bg-sky-600 border-sky-400 text-white font-bold'
                    : 'bg-[#0f172a] border-slate-400/25 text-slate-300 hover:text-white'}"
                >
                  [{wf.file_type}] {wf.path}
                </button>
              {/each}
            </div>

            <!-- 4.4 Scan par Fichier Source (.html, .js, .css) & Lien d'Arborescence des Dossiers / Modules -->
            <div class="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-2.5">
              <!-- Fichiers Sources & Clés JSON -->
              <div class="p-2.5 rounded-lg bg-[#090d16] border border-slate-400/15 space-y-2">
                <div class="text-[10.5px] font-bold text-slate-200 font-mono flex items-center gap-1.5">
                  <FileCode class="w-3.5 h-3.5 text-sky-400" />
                  <span>SCAN PAR SOURCE (.HTML, .JS, MODULE, .CSS) & CLÉS DE PAYLOAD JSON</span>
                </div>
                <div class="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {#if webFiles.length === 0}
                    <div class="text-[11px] text-slate-500 font-mono p-2">Aucun fichier .html/.js/.css inspecté.</div>
                  {:else}
                    {#each webFiles as wf}
                      {@const isSel = selectedFileFilter === wf.path}
                      <div
                        role="button"
                        tabindex="0"
                        onclick={() => (selectedFileFilter = isSel ? 'ALL' : wf.path)}
                        onkeydown={(e) => e.key === 'Enter' && (selectedFileFilter = isSel ? 'ALL' : wf.path)}
                        class="p-2 rounded-md border font-mono cursor-pointer transition space-y-1.5 {isSel
                          ? 'bg-slate-800/90 border-sky-400'
                          : 'bg-[#0f172a] border-slate-400/15 hover:border-slate-400/35'}"
                      >
                        <div class="flex items-center justify-between gap-2 text-[10.5px]">
                          <strong class={isSel ? 'text-sky-300' : 'text-slate-100'}>
                            [{wf.file_type}] {wf.path}
                          </strong>
                          <span class="text-[9.5px] text-slate-400 shrink-0">
                            {(wf.size_bytes / 1024).toFixed(1)} Ko • {wf.http_status} • {wf.file_type === 'HTML' ? `${forms.length} form(s) • ${hashLinks.length} #link • ` : ''}{(wf.folder_calls || []).length} dossier(s) • {(wf.api_and_asset_refs || []).length} lien(s){wf.has_sourcemap ? ' • ⚠️ SourceMap' : ''}
                          </span>
                        </div>

                        {#if wf.file_type === 'HTML' && (forms.length > 0 || hashLinks.length > 0)}
                          <div class="flex flex-wrap gap-1">
                            {#each forms.slice(0, 6) as fm}
                              <span class="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-400/40 text-emerald-200 text-[9.5px]">
                                📝 Form #{fm.index} «{fm.id_or_name}» ({(fm.inputs || []).length} ch.) ⁀➴ {fm.action}
                              </span>
                            {/each}
                            {#if hashLinks.length > 0}
                              <span class="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-400/40 text-amber-200 text-[9.5px]">
                                #️⃣ {hashLinks.length} #Links ({hashLinks.slice(0, 3).map((h) => h.target).join(', ')})
                              </span>
                            {/if}
                          </div>
                        {/if}

                        {#if (wf.folder_calls && wf.folder_calls.length > 0) || (wf.api_and_asset_refs && wf.api_and_asset_refs.length > 0) || (wf.json_payload_keys && wf.json_payload_keys.length > 0)}
                          <div class="flex flex-wrap gap-1">
                            {#each (wf.folder_calls || []).slice(0, 8) as fc}
                              <span class="px-1.5 py-0.5 rounded bg-sky-500/15 border border-sky-400/30 text-sky-300 text-[9.5px]">
                                📁 {fc}
                              </span>
                            {/each}
                            {#each (wf.api_and_asset_refs || []).slice(0, 10) as ar}
                              <span class="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-400/25 text-slate-200 text-[9.5px]">
                                ↳ {ar}
                              </span>
                            {/each}
                            {#each (wf.json_payload_keys || []).slice(0, 10) as jk}
                              <span class="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-400/35 text-emerald-300 text-[9.5px]">
                                🔑 JSON:{jk}
                              </span>
                            {/each}
                          </div>
                        {/if}
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>

              <!-- Lien d'Arborescence des Dossiers & Modules par Source HTML -->
              <div class="p-2.5 rounded-lg bg-[#090d16] border border-slate-400/15 space-y-2">
                <div class="text-[10.5px] font-bold text-slate-200 font-mono flex items-center gap-1.5">
                  <FolderTree class="w-3.5 h-3.5 text-sky-400" />
                  <span>LIEN D'ARBORESCENCE DES DOSSIERS & MODULES PAR SOURCE HTML</span>
                </div>
                <div class="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {#if filteredDirectories.length === 0}
                    <div class="text-[11px] text-slate-500 font-mono p-2">
                      {selectedWebFileObj
                        ? `Aucun sous-dossier appelé par ${selectedWebFileObj.path}.`
                        : 'Aucun appel de sous-dossier ou module détecté.'}
                    </div>
                  {:else}
                    {#each filteredDirectories as d}
                      {@const children = childItemsForDirectory(d.folder_path)}
                      <div class="p-2 rounded-md bg-[#0f172a] border border-slate-400/15 font-mono space-y-1">
                        <div class="flex items-center justify-between gap-2 text-[10.5px]">
                          <strong class="text-sky-300">📁 {d.folder_path}</strong>
                          <span class="text-[9.5px] text-slate-400">{d.classification} ({d.call_count}x)</span>
                        </div>
                        <div class="text-[9.5px] text-emerald-300/90 truncate" title={(d.source_files || []).join(', ')}>
                          🔗 Source HTML/JS : {(d.source_files || []).join(' ➔ ')}
                        </div>
                        {#if children.length > 0}
                          <div class="flex flex-wrap gap-1 pt-0.5">
                            {#each children as ch}
                              <span class="px-1.5 py-0.2 rounded bg-black/50 border border-white/10 text-[9px] text-slate-300">
                                ⊢ {ch}
                              </span>
                            {/each}
                          </div>
                        {/if}
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>
            </div>

            <!-- 4.5 Formulaires «Form» (Gauche) & Routes / Types de Requêtes / Endpoints (Droite) -->
            <div class="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-2.5">
              <!-- Formulaires «Form» & Champs d'Information Reçus -->
              <div class="p-2.5 rounded-lg bg-[#090d16] border border-slate-400/15 space-y-2">
                <div class="text-[10.5px] font-bold text-slate-200 font-mono">
                  📝 FORMULAIRES «FORM» & CHAMPS DE DATA REÇUS ({forms.length})
                </div>
                <div class="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {#if forms.length === 0}
                    <div class="text-[11px] text-slate-500 font-mono p-2">
                      Aucune balise &lt;form&gt; ou champ &lt;input&gt; détecté sur la page d'entrée.
                    </div>
                  {:else}
                    {#each forms as f}
                      <div class="p-2.5 rounded-md bg-[#0f172a] border border-l-4 {postureColor(f.security_posture)} font-mono space-y-1.5">
                        <div class="flex flex-wrap items-center justify-between gap-1 text-[10.5px]">
                          <strong class="text-white">
                            📝 Form #{f.index} «{f.id_or_name}» [{f.method}] ➔ {f.action}
                          </strong>
                          <span class="font-extrabold text-[9.5px]">
                            {f.has_csrf_token ? '🛡️ CSRF OK' : '⚠️ Sans CSRF'} • [{f.security_posture}]
                          </span>
                        </div>

                        <div class="flex flex-wrap gap-1">
                          {#if !f.inputs || f.inputs.length === 0}
                            <span class="text-[10px] text-slate-500">Aucun champ &lt;input&gt;/&lt;select&gt;/&lt;textarea&gt; interne.</span>
                          {:else}
                            {#each f.inputs as inp}
                              {@const isSens = String(inp.classification || '').includes('Secret') || String(inp.classification || '').includes('Upload')}
                              <span
                                class="px-1.5 py-0.5 rounded text-[9.5px] border {isSens
                                  ? 'bg-rose-500/20 border-rose-500/50 text-rose-200'
                                  : 'bg-slate-950 border-sky-500/35 text-slate-200'}"
                              >
                                {inp.classification} : {inp.name} ({inp.input_type}{inp.required ? '*' : ''})
                              </span>
                            {/each}
                          {/if}
                        </div>

                        {#if f.security_notes && f.security_notes.length > 0}
                          {#each f.security_notes as note}
                            <div class="text-[9.5px] text-amber-300">↳ {note}</div>
                          {/each}
                        {/if}
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>

              <!-- Routes, Types de Requêtes, API, Scripts & robots.txt -->
              <div class="p-2.5 rounded-lg bg-[#090d16] border border-slate-400/15 space-y-2">
                <div class="text-[10.5px] font-bold text-slate-200 font-mono">
                  🧭 TYPES DE REQUÊTES, ROUTES API, SCRIPTS & ROBOTS.TXT ({filteredRoutes.length})
                </div>
                <div class="space-y-1.5 max-h-60 overflow-y-auto pr-1 font-mono">
                  {#if filteredRoutes.length === 0 && externalScripts.length === 0}
                    <div class="text-[11px] text-slate-500 p-2">
                      {selectedWebFileObj
                        ? `Aucune route directe isolée pour ${selectedWebFileObj.path}.`
                        : 'Aucune route ou script externe référencé.'}
                    </div>
                  {:else}
                    {#each filteredRoutes as r}
                      <div class="px-2 py-1.5 rounded bg-[#0f172a] border border-sky-400/25 flex items-center justify-between gap-2 text-[10px]">
                        <div class="flex items-center gap-1.5 min-w-0">
                          <span class="px-1.5 py-0.2 rounded border text-[9px] font-extrabold shrink-0 {methodBadgeClass(r.method)}">
                            {r.method}
                          </span>
                          <span class="text-slate-100 font-semibold truncate" title={r.path}>{r.path}</span>
                        </div>
                        <span class="text-[9.5px] text-sky-300 shrink-0 truncate max-w-[45%]" title={r.source}>
                          {r.source}
                        </span>
                      </div>
                    {/each}
                    {#if !selectedWebFileObj}
                      {#each externalScripts as sc}
                        <div class="px-2 py-1 rounded bg-indigo-950/40 border border-purple-400/25 flex items-center justify-between gap-2 text-[10px]">
                          <span class="text-purple-200 truncate">📜 {sc}</span>
                          <span class="text-[9px] text-slate-400 shrink-0">GET (Script JS)</span>
                        </div>
                      {/each}
                    {/if}
                  {/if}
                </div>
              </div>
            </div>

            <!-- 4.5b Analyse Profonde du Code Source HTML : Formulaires, URLs, #Links & Explorateur de Paths -->
            <div class="p-2.5 rounded-lg bg-[#090d16] border border-emerald-400/25 space-y-2 font-mono">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="text-[10.5px] font-bold text-emerald-300 flex items-center gap-1.5">
                  <FileCode class="w-3.5 h-3.5 text-emerald-400" />
                  <span>🔍 ANALYSE DU CODE SOURCE HTML : FORMULAIRES, URLS, #LINKS & EXPLORATEUR DE PATHS</span>
                </div>
                <div class="flex flex-wrap items-center gap-1">
                  <button
                    type="button"
                    onclick={() => (htmlSourceTab = 'ALL')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {htmlSourceTab === 'ALL' ? 'bg-emerald-600/35 border-emerald-400 text-white font-bold' : 'bg-[#0f172a] border-white/10 text-slate-300'}"
                  >
                    Tous ({pathTree.length})
                  </button>
                  <button
                    type="button"
                    onclick={() => (htmlSourceTab = 'FORMS')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {htmlSourceTab === 'FORMS' ? 'bg-emerald-600/35 border-emerald-400 text-white font-bold' : 'bg-[#0f172a] border-white/10 text-slate-300'}"
                  >
                    📝 Forms & Inputs ({forms.length} / {totalInputsCount})
                  </button>
                  <button
                    type="button"
                    onclick={() => (htmlSourceTab = 'URLS')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {htmlSourceTab === 'URLS' ? 'bg-sky-600/35 border-sky-400 text-white font-bold' : 'bg-[#0f172a] border-white/10 text-slate-300'}"
                  >
                    🔗 URLs ({discoveredUrls.length})
                  </button>
                  <button
                    type="button"
                    onclick={() => (htmlSourceTab = 'ANCHORS')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {htmlSourceTab === 'ANCHORS' ? 'bg-amber-600/35 border-amber-400 text-white font-bold' : 'bg-[#0f172a] border-white/10 text-slate-300'}"
                  >
                    #️⃣ #Links & Ancres DOM ({hashLinks.length})
                  </button>
                  <button
                    type="button"
                    onclick={() => (htmlSourceTab = 'PATHS')}
                    class="px-2 py-0.5 rounded text-[9.5px] border cursor-pointer {htmlSourceTab === 'PATHS' ? 'bg-purple-600/35 border-purple-400 text-white font-bold' : 'bg-[#0f172a] border-white/10 text-slate-300'}"
                  >
                    🌳 Arborescence Paths ({pathTree.length})
                  </button>
                </div>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-1.5 max-h-60 overflow-y-auto pr-1">
                {#if htmlSourceTab === 'ANCHORS'}
                  {#if hashLinks.length === 0}
                    <div class="text-[10.5px] text-slate-500 p-2 col-span-full">Aucun #link ou ancre DOM id="..." détecté dans le code source HTML.</div>
                  {:else}
                    {#each hashLinks as hl}
                      <div class="p-2 rounded bg-[#0f172a] border border-amber-400/30 text-[10px] space-y-0.5">
                        <div class="flex items-center justify-between gap-1">
                          <strong class="text-amber-300 truncate">#️⃣ {hl.target}</strong>
                          <span class="px-1.5 py-0.2 rounded bg-amber-500/20 border border-amber-400/40 text-amber-200 text-[8.5px] shrink-0">{hl.tag_context}</span>
                        </div>
                        <div class="text-[9.5px] text-slate-400 truncate">Path résolu : {hl.resolved_path} • {hl.label}</div>
                      </div>
                    {/each}
                  {/if}
                {:else if htmlSourceTab === 'URLS'}
                  {#if discoveredUrls.length === 0}
                    <div class="text-[10.5px] text-slate-500 p-2 col-span-full">Aucune URL externe ou ressource href/src additionnelle détectée.</div>
                  {:else}
                    {#each discoveredUrls as ul}
                      <div class="p-2 rounded bg-[#0f172a] border border-sky-400/30 text-[10px] space-y-0.5">
                        <div class="flex items-center justify-between gap-1">
                          <strong class="text-sky-300 truncate" title={ul.target}>🔗 {ul.target}</strong>
                          <span class="px-1.5 py-0.2 rounded bg-sky-500/20 border border-sky-400/40 text-sky-200 text-[8.5px] shrink-0">{ul.kind}</span>
                        </div>
                        <div class="text-[9.5px] text-slate-400 truncate">Source : {ul.tag_context} ➔ {ul.resolved_path}</div>
                      </div>
                    {/each}
                  {/if}
                {:else if htmlSourceTab === 'FORMS'}
                  {#each forms as f}
                    <div class="p-2 rounded bg-[#0f172a] border border-emerald-400/30 text-[10px] space-y-1">
                      <div class="flex items-center justify-between gap-1">
                        <strong class="text-emerald-300 truncate">📝 {f.id_or_name}</strong>
                        <span class="px-1.5 py-0.2 rounded border text-[8.5px] shrink-0 {methodBadgeClass(f.method)}">{f.method}</span>
                      </div>
                      <div class="text-[9.5px] text-sky-300 truncate">Action Path : {f.action} ({(f.inputs || []).length} champ(s))</div>
                      <div class="text-[9px] text-slate-400 truncate" title={(f.inputs || []).map((i: any) => i.name).join(', ')}>
                        Champs : {(f.inputs || []).map((i: any) => i.name).slice(0, 5).join(', ') || 'Aucun'}
                      </div>
                    </div>
                  {/each}
                {:else}
                  {#each pathTree as pn}
                    <div class="p-2 rounded bg-[#0f172a] border border-slate-700/80 hover:border-purple-400/40 text-[10px] space-y-0.5">
                      <div class="flex items-center justify-between gap-1">
                        <strong class="text-slate-100 truncate" title={pn.path}>
                          {pn.node_type.includes('#LINK') ? '#️⃣' : pn.node_type.includes('FORM') ? '📝' : pn.node_type.includes('EXTERNAL') ? '🌐' : '🧭'} {pn.path}
                        </strong>
                        <span class="px-1.5 py-0.2 rounded border text-[8.5px] font-bold shrink-0 {methodBadgeClass(pn.method)}">{pn.method}</span>
                      </div>
                      <div class="flex items-center justify-between gap-1 text-[9px] text-slate-400">
                        <span class="text-purple-300 truncate">📁 {pn.parent_dir} [{pn.node_type}]</span>
                        <span class="truncate max-w-[48%]" title={pn.source_ref}>{pn.source_ref}</span>
                      </div>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>
          {/if}

          <!-- 4.6 Pont Hybride « Surface Externe ↔ Code Source AST Local » -->
          <div class="p-3 rounded-lg bg-[#090d16] border border-sky-400/25 space-y-2">
            <div class="flex flex-wrap items-center justify-between gap-2 font-mono">
              <span class="text-[11px] font-bold text-sky-400 flex items-center gap-1.5">
                <Link2 class="w-3.5 h-3.5" />
                <span>PONT HYBRIDE AUTOMATIQUE : SURFACE WEB EXTERNE ↔ GRAPHE AST LOCAL DU PROJET</span>
              </span>
              <span class="text-[10px] text-slate-400">
                {astBridgeItems.filter((b) => b.isMapped).length}/{astBridgeItems.length} élément(s) corrélé(s) avec le graphe AST local
              </span>
            </div>

            {#if astBridgeItems.length === 0}
              <div class="text-[11px] text-slate-500 font-mono">
                Associe automatiquement les fichiers <code>.html</code>/<code>.js</code> et routes <code>[METHOD] /api/*</code> découverts sur le domaine aux fichiers sources locaux du projet actif.
              </div>
            {:else}
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 max-h-48 overflow-y-auto pr-1">
                {#each astBridgeItems as item}
                  <div
                    class="p-2 rounded-md bg-[#0f172a] border font-mono text-[10px] space-y-1 {item.isMapped
                      ? 'border-emerald-500/40'
                      : 'border-amber-500/35'}"
                  >
                    <div class="flex items-center justify-between gap-2">
                      <strong class="text-slate-100 truncate">
                        {item.isMapped ? '🔗' : '👻'} {item.externalRef}
                      </strong>
                      <span class="text-[9px] font-bold shrink-0 {item.isMapped ? 'text-emerald-300' : 'text-amber-300'}">
                        {item.isMapped ? 'AST MAPPÉ' : 'NON RÉSOLU AST'}
                      </span>
                    </div>
                    <div class="flex items-center justify-between gap-2 text-[9.5px] text-slate-400">
                      <span class="truncate">➔ {item.matchedLabel} [{item.matchedLayer}]</span>
                      {#if item.matchedNodeId}
                        <button
                          type="button"
                          onclick={() => {
                            cockpitState.selectSymbol(item.matchedNodeId!, true);
                            closeModal();
                          }}
                          class="px-1.5 py-0.2 rounded bg-sky-500/20 hover:bg-sky-500/35 border border-sky-400/40 text-sky-300 text-[9px] shrink-0 cursor-pointer"
                        >
                          Caméra 3D ➔
                        </button>
                      {/if}
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
          </div>

          <!-- 4.7 Suite de Faiblesses Miroir : Côté 1 (Frontières Black-Box) ↔ Côté 2 (Réceptivité AST, Tests Positifs & Tests Négatifs) -->
          <div class="p-3 rounded-lg bg-[#090d16] border border-purple-500/35 space-y-2.5">
            <div class="flex flex-wrap items-center justify-between gap-2 font-mono">
              <div>
                <div class="text-[11px] font-bold text-purple-200">
                  ⚖️ SUITE DE FAIBLESSES MIROIR : CÔTÉ 1 (FRONTIÈRES BLACK-BOX) ↔ CÔTÉ 2 (APRÈS SCAN ➔ CODE AST, TESTS POSITIFS & TESTS NÉGATIFS)
                </div>
                <div class="text-[9.5px] text-slate-400">
                  {sideTwoUnlocked
                    ? `Miroir Bilatéral Actif : ${(report?.boundary_weaknesses || []).length} sonde(s) Côté 1 ➔ ${sideTwoWeaknessSuite.length} Test(s) Positif(s) + ${sideTwoWeaknessSuite.length} Test(s) Négatif(s) AST Côté 2`
                    : 'Étape 1 : Sondes de frontière HTTP (CORS, OPTIONS, Dossiers, Cookies, Contrats JSON/Form) • Étape 2 : Débloquée après le scan Black-Box'}
                </div>
              </div>

              <button
                type="button"
                disabled={!report}
                onclick={triggerSideTwoAudit}
                class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-900/70 hover:bg-purple-800 disabled:opacity-40 border border-purple-400/50 text-[10.5px] font-mono font-bold text-purple-100 cursor-pointer"
              >
                <FlaskConical class="w-3.5 h-3.5" />
                <span>🔬 Propulser Côté 2 (Après Scan ➔ Tests Positifs & Négatifs AST)</span>
              </button>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-2.5">
              <!-- Côté 1 -->
              <div class="p-2.5 rounded-lg bg-[#0f172a] border border-sky-400/25 space-y-2 font-mono">
                <div class="flex items-center justify-between text-[10px]">
                  <strong class="text-sky-400">🌐 CÔTÉ 1 • SONDES DE FRONTIÈRE EXTERNES (BLACK-BOX)</strong>
                  <span class="text-slate-400 text-[9.5px]">
                    {report
                      ? `${(report.boundary_weaknesses || []).length} sonde(s)`
                      : 'En attente du scan'}
                  </span>
                </div>
                <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                  {#if !report || (report.boundary_weaknesses || []).length === 0}
                    <div class="text-[10.5px] text-slate-500 p-2">
                      Lancez l'audit Black-Box pour exécuter les sondes de faiblesse de frontière (CORS Origin, OPTIONS HTTP, Directory Listing CWE-548, Cookies, Contrats Form/JSON).
                    </div>
                  {:else}
                    {#each report.boundary_weaknesses as p}
                      <div class="p-2 rounded bg-[#090d16] border border-l-4 {postureColor(p.status)} text-[10px] space-y-1">
                        <div class="flex items-center justify-between gap-1">
                          <strong class="text-white">[{p.cwe}] {p.category}</strong>
                          <span class="font-extrabold text-[9px]">[{p.status}]</span>
                        </div>
                        <div class="text-sky-300 text-[9.5px] truncate" title={p.side_one_vector}>
                          Vecteur : {p.side_one_vector}
                        </div>
                        <div class="text-slate-300 text-[9.5px] leading-snug">{p.observed_behavior}</div>
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>

              <!-- Côté 2 -->
              <div class="p-2.5 rounded-lg bg-[#0f172a] border border-purple-400/30 space-y-2 font-mono">
                <div class="flex flex-wrap items-center justify-between gap-1.5 text-[10px]">
                  <strong class="text-purple-300">🧬 CÔTÉ 2 • CODE AST : TESTS POSITIFS (✅) & NÉGATIFS (🚫)</strong>
                  <div class="flex items-center gap-1">
                    {#if sideTwoUnlocked}
                      <button
                        type="button"
                        onclick={() => (sideTwoTestFilter = 'ALL')}
                        class="px-1.5 py-0.5 rounded text-[9px] border cursor-pointer {sideTwoTestFilter === 'ALL' ? 'bg-purple-500/30 border-purple-400 text-white font-bold' : 'bg-[#090d16] border-white/10 text-slate-400'}"
                      >
                        Tous ({sideTwoWeaknessSuite.length * 2})
                      </button>
                      <button
                        type="button"
                        onclick={() => (sideTwoTestFilter = 'POSITIVE')}
                        class="px-1.5 py-0.5 rounded text-[9px] border cursor-pointer {sideTwoTestFilter === 'POSITIVE' ? 'bg-emerald-500/30 border-emerald-400 text-emerald-200 font-bold' : 'bg-[#090d16] border-white/10 text-slate-400'}"
                      >
                        ✅ Positifs ({sideTwoWeaknessSuite.length})
                      </button>
                      <button
                        type="button"
                        onclick={() => (sideTwoTestFilter = 'NEGATIVE')}
                        class="px-1.5 py-0.5 rounded text-[9px] border cursor-pointer {sideTwoTestFilter === 'NEGATIVE' ? 'bg-rose-500/30 border-rose-400 text-rose-200 font-bold' : 'bg-[#090d16] border-white/10 text-slate-400'}"
                      >
                        🚫 Négatifs ({sideTwoWeaknessSuite.length})
                      </button>
                    {:else}
                      <span class="text-[9.5px] text-slate-400">
                        {report ? '⚡ Prêt à propulser' : 'Verrouillé avant scan'}
                      </span>
                    {/if}
                  </div>
                </div>
                <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                  {#if !sideTwoUnlocked}
                    <div class="text-[10.5px] text-slate-500 p-2">
                      Dès que le scan Black-Box est terminé, cliquez sur <strong>🔬 Propulser Côté 2</strong> pour croiser chaque vecteur externe avec vos nœuds AST et générer les couples de <strong>Tests Positifs (Nominal / Happy Path)</strong> et <strong>Tests Négatifs (Rejet de Frontière)</strong>.
                    </div>
                  {:else}
                    {#each sideTwoWeaknessSuite as item}
                      <div class="p-2 rounded bg-[#090d16] border border-purple-400/35 text-[10px] space-y-1.5">
                        <div class="flex items-center justify-between gap-1 border-b border-white/5 pb-1">
                          <span class="text-sky-300 text-[9.5px] font-semibold truncate">
                            🎯 Cible AST : {item.astNodeLabel}
                          </span>
                          <span class="text-purple-300 font-extrabold text-[9px] shrink-0">
                            {item.cwe} • {item.isAstMapped ? '🔗 Mappé AST' : '🎯 Cible'}
                          </span>
                        </div>

                        {#if sideTwoTestFilter === 'ALL' || sideTwoTestFilter === 'POSITIVE'}
                          <div class="p-1.5 rounded bg-emerald-950/25 border-l-2 border-emerald-400 space-y-0.5">
                            <div class="flex items-center justify-between gap-1">
                              <strong class="text-emerald-300">✅ {item.positiveTestFn}</strong>
                              <span class="text-[8.5px] px-1 rounded bg-emerald-500/20 text-emerald-200 font-bold">POSITIF / NOMINAL</span>
                            </div>
                            <div class="text-slate-300 text-[9.5px] leading-snug">{item.positiveTestSpec}</div>
                          </div>
                        {/if}

                        {#if sideTwoTestFilter === 'ALL' || sideTwoTestFilter === 'NEGATIVE'}
                          <div class="p-1.5 rounded bg-rose-950/20 border-l-2 border-rose-400 space-y-0.5">
                            <div class="flex items-center justify-between gap-1">
                              <strong class="text-rose-300">🚫 {item.negativeTestFn}</strong>
                              <span class="text-[8.5px] px-1 rounded bg-rose-500/20 text-rose-200 font-bold">NÉGATIF / REJET</span>
                            </div>
                            <div class="text-slate-300 text-[9.5px] leading-snug">{item.negativeTestSpec}</div>
                          </div>
                        {/if}
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 4b. Module 4 : Contrôle d'Exposition des Fichiers Sensibles (.env, .git/HEAD, docker-compose.yml — CWE-538 Masqué) -->
        <div class="p-3 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-2 font-mono">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="text-[11px] font-bold text-slate-200 flex items-center gap-1.5">
              <Lock class="w-3.5 h-3.5 text-purple-400" />
              <span>MODULE 4 • CONTRÔLE D'EXPOSITION DES FICHIERS SENSIBLES (.env, .git/HEAD, docker-compose.yml, openapi.json — CWE-538 MASQUÉ)</span>
            </span>
            <span class="text-[10px] text-slate-400">
              {#if report?.exposed_artifacts && report.exposed_artifacts.length > 0}
                {@const expCnt = report.exposed_artifacts.filter((a: any) => a.exposed).length}
                {expCnt > 0
                  ? `🚨 ${expCnt} fichier(s) sensible(s) exposé(s) (Valeurs masquées [MASQUÉ])`
                  : `🛡️ 0 exposition sur ${report.exposed_artifacts.length} fichiers sensibles sondés`}
              {:else}
                Anti-Soft-404 & masquage strict des valeurs [MASQUÉ]
              {/if}
            </span>
          </div>

          {#if !report || !report.exposed_artifacts || report.exposed_artifacts.length === 0}
            <div class="text-[11px] text-slate-500 text-center py-2">
              Vérifie en Niveau 4 si des fichiers de configuration (.env, .git/HEAD, docker-compose.yml, openapi.json) sont publiquement accessibles sans exfiltrer leurs secrets.
            </div>
          {:else}
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {#each report.exposed_artifacts as a}
                <div
                  class="p-2 rounded-lg border text-[10px] space-y-1 {a.exposed
                    ? 'bg-rose-950/35 border-rose-500/60'
                    : 'bg-[#090d16] border-emerald-500/35'}"
                >
                  <div class="flex items-center justify-between gap-1">
                    <strong class={a.exposed ? 'text-rose-300' : 'text-slate-200'}>
                      {a.exposed ? '🚨' : '🛡️'} {a.path}
                    </strong>
                    <span class="font-extrabold text-[9px] {a.exposed ? 'text-rose-400' : 'text-emerald-400'}">
                      {a.exposed ? 'EXPOSÉ' : 'PROTÉGÉ'}
                    </span>
                  </div>
                  <div class="text-[9.5px] text-slate-400 truncate" title={a.redacted_preview || a.http_status}>
                    {a.redacted_preview ? a.redacted_preview : `${a.label} (${a.http_status})`}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>

        <!-- 5. Grille Ports/Headers à gauche, Diagnostics & Remédiations à droite -->
        <div class="grid grid-cols-1 lg:grid-cols-[1fr_1.25fr] gap-3">
          <!-- Gauche : Ports TCP + Matrice Headers HTTP -->
          <div class="space-y-3">
            <div class="p-3 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-2 font-mono">
              <div class="text-[11px] font-bold text-slate-200 flex items-center gap-1.5">
                <Server class="w-3.5 h-3.5 text-sky-400" />
                <span>PORTS, SERVICES, BANNIÈRES & VERSIONS TCP</span>
              </div>
              {#if !report || !report.open_ports || report.open_ports.length === 0}
                <div class="text-[11px] text-slate-500 text-center py-3">
                  Lancez l'audit (Niveau 2+) pour inspecter les ports TCP et lire les bannières.
                </div>
              {:else}
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 max-h-56 overflow-y-auto pr-1">
                  {#each report.open_ports as p}
                    <div
                      class="p-2 rounded-md border text-[10px] space-y-1 {p.open
                        ? p.risk_level === 'CRITICAL' || p.risk_level === 'HIGH'
                          ? 'bg-rose-950/25 border-rose-500/55'
                          : 'bg-emerald-950/25 border-emerald-500/50'
                        : 'bg-[#090d16] border-slate-700/45'}"
                    >
                      <div class="flex items-center justify-between gap-1">
                        <span class={p.open ? 'text-white font-bold' : 'text-slate-500'}>
                          {p.open ? '🟢' : '⚫'} :{p.port}/{p.protocol || 'TCP'} {p.service}
                        </span>
                        <span class={p.open ? 'text-emerald-300' : 'text-slate-600'}>
                          {p.open ? `${p.latency_ms ?? 0} ms` : 'FERMÉ'}
                        </span>
                      </div>
                      {#if p.open && (p.detected_version || p.banner)}
                        <div class="text-[9.5px] text-sky-300 truncate" title={p.banner || ''}>
                          🏷️ {p.detected_version ? `[${p.detected_version}] ` : ''}{p.banner || ''}
                        </div>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
            </div>

            <div class="p-3 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-2 font-mono">
              <div class="text-[11px] font-bold text-slate-200">
                CONTRÔLES D'EN-TÊTES HTTP (CSP, HSTS, CORS, XFO, NOSNIFF)
              </div>
              {#if !report || !report.headers_audit || report.headers_audit.length === 0}
                <div class="text-[11px] text-slate-500 text-center py-3">
                  Aucun en-tête HTTP audité.
                </div>
              {:else}
                <div class="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {#each report.headers_audit as h}
                    <div class="p-2 rounded-md bg-[#090d16] border border-slate-700/60 text-[10px] space-y-0.5">
                      <div class="flex items-center justify-between">
                        <strong class="text-slate-200">{h.header}</strong>
                        <span
                          class="font-extrabold {h.status === 'PASS'
                            ? 'text-emerald-400'
                            : h.status === 'WARN'
                              ? 'text-amber-400'
                              : 'text-rose-400'}"
                        >
                          [{h.status}]
                        </span>
                      </div>
                      <div class="text-[9.5px] text-slate-400">
                        {h.value ? `Valeur : ${h.value} — ${h.recommendation}` : h.recommendation}
                      </div>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          </div>

          <!-- Droite : Diagnostics de Sécurité & Remédiations -->
          <div class="p-3 rounded-xl bg-[#0f172a] border border-slate-400/15 space-y-2 font-mono flex flex-col">
            <div class="flex items-center justify-between">
              <span class="text-[11px] font-bold text-slate-200 flex items-center gap-1.5">
                <ShieldAlert class="w-3.5 h-3.5 text-rose-400" />
                <span>DIAGNOSTICS DE POSTURE & REMÉDIATIONS</span>
              </span>
              <span class="text-[10px] text-slate-400">{(report?.findings || []).length} alerte(s)</span>
            </div>

            <div class="space-y-2 max-h-[460px] overflow-y-auto pr-1 flex-1">
              {#if !report}
                <div class="text-[11px] text-slate-500 text-center py-12">
                  Saisissez un domaine, une adresse IP:Port ou un chemin HTML puis cliquez sur <strong>Lancer l'Audit</strong>.
                </div>
              {:else if (report.findings || []).length === 0}
                <div class="p-5 rounded-lg bg-emerald-950/30 border border-emerald-500/50 text-center text-emerald-300 text-xs font-bold">
                  🛡️ Aucune anomalie critique de surface, de formulaire ou d'en-tête détectée sur cette cible !
                </div>
              {:else}
                {#each report.findings as f}
                  {@const sevBorder =
                    f.severity === 'CRITICAL'
                      ? 'border-rose-500 text-rose-400'
                      : f.severity === 'HIGH'
                        ? 'border-orange-500 text-orange-400'
                        : f.severity === 'MEDIUM'
                          ? 'border-amber-400 text-amber-300'
                          : 'border-sky-400 text-sky-300'}
                  <div class="p-2.5 rounded-lg bg-[#090d16] border border-l-4 {sevBorder} space-y-1">
                    <div class="flex items-center justify-between gap-2 text-[10px]">
                      <span class="font-extrabold">[{f.severity}] {f.cwe}</span>
                      <span class="text-slate-400 text-[9.5px]">{f.category}</span>
                    </div>
                    <div class="text-[11.5px] font-bold text-white">{f.title}</div>
                    <p class="text-[10.5px] text-slate-300 leading-snug">{f.description}</p>
                    <div class="text-[10px] text-emerald-300 pt-0.5">💡 Remédiation : {f.remediation}</div>
                  </div>
                {/each}
              {/if}
            </div>
          </div>
        </div>

        <!-- 6. Studio de Prompting Binôme IA Multi-Modes (4 Onglets Boostés) & Rapport Copiable -->
        <div class="p-3 rounded-xl bg-[#0f172a] border border-slate-400/20 space-y-2.5 font-mono">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="text-[11px] font-bold text-slate-200 flex items-center gap-1.5">
              <Sparkles class="w-3.5 h-3.5 text-sky-400" />
              <span>STUDIO DE PROMPTING BINÔME IA & RAPPORT COPIABLE (4 MODES D'INGÉNIERIE BOOSTÉS)</span>
            </span>

            <div class="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                disabled={!report}
                onclick={copySurfacePrompt}
                class="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-emerald-400/40 text-[10px] text-emerald-300 cursor-pointer"
              >
                {#if promptCopied}<Check class="w-3 h-3" /> Prompt Copié !{:else}<Copy class="w-3 h-3" /> 📋 Copier Prompt Actif{/if}
              </button>
              <button
                type="button"
                disabled={!report}
                onclick={copySurfaceJson}
                class="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-purple-400/40 text-[10px] text-purple-300 cursor-pointer"
              >
                {#if jsonCopied}<Check class="w-3 h-3" /> JSON Copié !{:else}<Copy class="w-3 h-3" /> 📦 Copier JSON Brut{/if}
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-1.5">
            <button
              type="button"
              onclick={() => (surfacePromptTab = 'arch')}
              class="text-left p-2 rounded-lg border text-[10px] cursor-pointer {surfacePromptTab === 'arch'
                ? 'bg-slate-800 border-sky-400 text-white font-bold'
                : 'bg-[#090d16] border-slate-400/20 text-slate-300'}"
            >
              <div>📐 Mode 1 • Architecture & Pont AST</div>
              <div class="text-[9px] text-slate-400 font-normal mt-0.5">
                Cheminement Data (.html ➔ .js ➔ API) & AST
              </div>
            </button>

            <button
              type="button"
              onclick={() => (surfacePromptTab = 'hardening')}
              class="text-left p-2 rounded-lg border text-[10px] cursor-pointer {surfacePromptTab === 'hardening'
                ? 'bg-slate-800 border-sky-400 text-white font-bold'
                : 'bg-[#090d16] border-slate-400/20 text-slate-300'}"
            >
              <div>🛡️ Mode 2 • Durcissement & Code</div>
              <div class="text-[9px] text-slate-400 font-normal mt-0.5">
                Correctifs (Middlewares, Forms, CWE-538)
              </div>
            </button>

            <button
              type="button"
              onclick={() => (surfacePromptTab = 'tests')}
              class="text-left p-2 rounded-lg border text-[10px] cursor-pointer {surfacePromptTab === 'tests'
                ? 'bg-slate-800 border-sky-400 text-white font-bold'
                : 'bg-[#090d16] border-slate-400/20 text-slate-300'}"
            >
              <div>🧪 Mode 3 • Conformité Défensive</div>
              <div class="text-[9px] text-slate-400 font-normal mt-0.5">
                Assertions non-destructives (curl -sSI)
              </div>
            </button>

            <button
              type="button"
              onclick={() => {
                surfacePromptTab = 'weakness';
                if (report) sideTwoUnlocked = true;
              }}
              class="text-left p-2 rounded-lg border text-[10px] cursor-pointer {surfacePromptTab === 'weakness'
                ? 'bg-slate-800 border-purple-400 text-purple-100 font-bold'
                : 'bg-[#090d16] border-purple-400/30 text-purple-200'}"
            >
              <div>⚖️ Mode 4 • Suite Faiblesses Miroir</div>
              <div class="text-[9px] text-purple-300 font-normal mt-0.5">
                Côté 1 (Frontières) ↔ Côté 2 (Tests Négatifs AST)
              </div>
            </button>
          </div>

          <textarea
            readonly
            value={surfacePromptText}
            placeholder="Le prompt Binôme IA formaté (Architecture / Cheminement Data / Correctifs / Tests de conformité / Miroir Côté 1 ↔ Côté 2) apparaîtra automatiquement ici dès la fin du scan..."
            class="w-full h-36 p-2.5 rounded-lg bg-[#090d16] border border-slate-400/20 text-[10.5px] font-mono text-slate-300 leading-relaxed resize-y focus:outline-none"
          ></textarea>
        </div>
      </div>

      <!-- Footer -->
      <div class="px-5 py-3 bg-[#0f172a] border-t border-white/10 flex flex-wrap items-center justify-between gap-2 font-mono">
        <div class="text-[10.5px] text-slate-400">
          {report
            ? `${report.impact_matrix?.visibility_footprint || ''} • Cible : ${report.host}:${report.primary_port} • Durée : ${report.scan_duration_ms} ms`
            : 'Audit défensif sans payload offensif • Texte 100% sélectionnable et copiable'}
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            disabled={!report || sendingToCopilot}
            onclick={sendReportToCopilot}
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-xs font-bold text-white cursor-pointer"
          >
            <Send class="w-3.5 h-3.5" />
            <span>{sendingToCopilot ? 'Envoi...' : '⚡ Envoyer au Copilote IA'}</span>
          </button>

          <button
            type="button"
            disabled={!report}
            onclick={copySurfacePrompt}
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 border border-sky-400 text-xs font-bold text-white cursor-pointer"
          >
            <Copy class="w-3.5 h-3.5" />
            <span>📋 Copier Rapport Complet</span>
          </button>

          <button
            type="button"
            onclick={closeModal}
            class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-white/10 text-xs text-slate-200 cursor-pointer"
          >
            Fermer
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
