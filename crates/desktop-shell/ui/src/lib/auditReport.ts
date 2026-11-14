import type { CockpitState } from '../state/graphState.svelte';
import type { CveAnomalyRecord, SymbolBubble } from '../types/graph';

export interface AuditSummary {
  projectName: string;
  projectPath: string;
  timestamp: string;
  totalNodes: number;
  totalEdges: number;
  totalClusters: number;
  totalLoc: number;
  totalViolations: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  hotspotsCount: number;
  orphanCount: number;
  earsContractsCount: number;
  securityScore: number;
  securityGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  layerDistribution: Record<string, number>;
}

export function computeAuditSummary(cockpitState: CockpitState): AuditSummary {
  const nodes = cockpitState.graph.nodes || [];
  const edges = cockpitState.graph.edges || [];
  const clusters = Object.keys(cockpitState.graph.clusters || {}).length;
  const violations = cockpitState.allViolations || [];

  let totalLoc = 0;
  let earsContractsCount = 0;
  const layerDistribution: Record<string, number> = {
    ui: 0,
    action: 0,
    domain: 0,
    database: 0,
    config: 0,
    utility: 0,
    docs: 0,
    other: 0,
  };

  for (const n of nodes) {
    totalLoc += n.loc || 1;
    if (n.metadata?.ears_count) earsContractsCount += n.metadata.ears_count;
    const l = (n.layer || 'other').toLowerCase();
    if (l in layerDistribution) {
      layerDistribution[l] += 1;
    } else {
      layerDistribution.other += 1;
    }
  }

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const v of violations) {
    const sev = (v.severity || 'MEDIUM').toUpperCase();
    if (sev === 'CRITICAL') criticalCount++;
    else if (sev === 'HIGH') highCount++;
    else if (sev === 'MEDIUM') mediumCount++;
    else lowCount++;
  }

  const hotspotsCount = cockpitState.hotspotNodes.length;
  const orphanCount = cockpitState.orphanNodes.length;

  // Calculate Security Health Score (0 to 100)
  let score = 100;
  score -= Math.min(45, criticalCount * 15);
  score -= Math.min(30, highCount * 6);
  score -= Math.min(15, mediumCount * 2);
  score -= Math.min(10, Math.floor(hotspotsCount * 1.5));
  if (earsContractsCount > 0) score = Math.min(100, score + 5);
  score = Math.max(10, Math.min(100, score));

  let securityGrade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
  if (score >= 90) securityGrade = 'A';
  else if (score >= 80) securityGrade = 'B';
  else if (score >= 70) securityGrade = 'C';
  else if (score >= 50) securityGrade = 'D';
  else securityGrade = 'F';

  return {
    projectName: cockpitState.graph.project_name || 'AetherScope Target Project',
    projectPath: cockpitState.graph.project_path || '.',
    timestamp: new Date().toISOString(),
    totalNodes: nodes.length,
    totalEdges: edges.length,
    totalClusters: clusters,
    totalLoc,
    totalViolations: violations.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    hotspotsCount,
    orphanCount,
    earsContractsCount,
    securityScore: score,
    securityGrade,
    layerDistribution,
  };
}

/**
 * Generates a comprehensive GitHub-Flavored Markdown Security Audit Report
 */
export function generateAuditMarkdown(cockpitState: CockpitState): string {
  const summary = computeAuditSummary(cockpitState);
  const violations = cockpitState.allViolations || [];
  const hotspots = cockpitState.hotspotNodes || [];
  const orphans = cockpitState.orphanNodes || [];

  const gradeEmoji = {
    A: '🟢 (Grade A - Fortement Sécurisé)',
    B: '🔵 (Grade B - Bonne Posture Défensive)',
    C: '🟡 (Grade C - Risque Modéré / Remédiations Requises)',
    D: '🟠 (Grade D - Risque Élevé / Failles Prioritaires)',
    F: '🔴 (Grade F - Risque Critique / Exploitation Immédiate)',
  }[summary.securityGrade];

  let md = `# 🛡️ Rapport Global d'Audit de Sécurité & Topologie AST
**Projet** : \`${summary.projectName}\`  
**Chemin Cible** : \`${summary.projectPath}\`  
**Horodatage de Scan** : ${summary.timestamp}  
**Moteur d'Audit** : AetherScope AST Security Engine (v2.4)  
**Score de Sécurité Global** : **${summary.securityScore}/100** ${gradeEmoji}  

---

## 1. Résumé Exécutif & Métriques Clés

| Métrique | Valeur | Statut Invariant |
|:---|:---|:---|
| **Composants AST (Nœuds)** | ${summary.totalNodes} | Cartographie Complète |
| **Flux & Appels (Liens)** | ${summary.totalEdges} | Dépendances Résolues |
| **Modules / Clusters** | ${summary.totalClusters} | Architecture Modulaire |
| **Volume de Code Source (LOC)** | ~${summary.totalLoc} lignes | Analysé par AST Parser |
| **Failles SAST & CWE Totales** | **${summary.totalViolations}** | ${summary.totalViolations === 0 ? '✅ Aucune faille active' : '⚠️ Alertes détectées'} |
| **Violations CRITIQUES** | **${summary.criticalCount}** | ${summary.criticalCount === 0 ? '✅ 0 Critique' : '🚨 P0 - Patch Immédiat'} |
| **Violations ÉLEVÉES (HIGH)** | **${summary.highCount}** | ${summary.highCount === 0 ? '✅ 0 Élevée' : '⚠️ P1 - À corriger'} |
| **Points Chauds de Complexité** | ${summary.hotspotsCount} (Cyclomatique ≥ 10) | ${summary.hotspotsCount === 0 ? '✅ Code fluide' : 'Refactoring conseillé'} |
| **Code Mort / Symboles Orphelins** | ${summary.orphanCount} composants | Élagage possible |
| **Contrats Formels EARS** | ${summary.earsContractsCount} invariants scellés | BLAKE3 cryptoseal |

---

## 2. Matrice des Vulnérabilités CWE & Alertes de Sécurité (${violations.length})

`;

  if (violations.length === 0) {
    md += `*Aucune vulnérabilité active détectée dans le périmètre actuel.*\n\n`;
  } else {
    md += `| Sévérité | Règle / CWE | Fichier : Ligne | Description & Taint | Remédiation Conseillée |\n`;
    md += `|:---:|:---|:---|:---|:---|\n`;

    for (const v of violations) {
      const sevBadge = v.severity === 'CRITICAL' ? '🔴 CRITIQUE' : v.severity === 'HIGH' ? '🟠 ÉLEVÉE' : '🟡 MOYENNE';
      const fileTarget = `\`${v.file_path}:${v.line_number || 1}\``;
      const param = v.transmitted_data ? ` *(Param: \`${v.transmitted_data}\`)*` : '';
      const desc = (v.title || v.description || 'Violation de sécurité').replace(/\|/g, '\\|');
      const rem = (v.remediation || 'Sanitiser les entrées et appliquer un contrat défensif.').replace(/\|/g, '\\|');
      md += `| **${sevBadge}** | **${v.cve_id || v.rule_id}**<br>_${v.cwe_class || 'CWE'}_ | ${fileTarget}${param} | ${desc} | ${rem} |\n`;
    }
    md += `\n`;
  }

  md += `---

## 3. Distribution de la Topologie Architecturale

| Couche Logique | Rôle Système | Nombre de Symboles | Part de l'Écosystème |
|:---|:---|:---:|:---:|\n`;

  for (const [layer, count] of Object.entries(summary.layerDistribution)) {
    const pct = summary.totalNodes > 0 ? ((count / summary.totalNodes) * 100).toFixed(1) : '0.0';
    const roleMap: Record<string, string> = {
      ui: 'Présentation & Composants d\'interface graphique',
      action: 'Contrôleurs, Handlers & Commandes d\'action',
      domain: 'Logique Métier & Modèles du domaine',
      database: 'Persistance, Repositories & Schémas',
      config: 'Configuration, Environnement & Initialisation',
      utility: 'Fonctions Utilitaires & Aides partagées',
      docs: 'Spécifications & Documentation EARS',
      other: 'Modules transverses & non-classifiés',
    };
    md += `| **\`${layer.toUpperCase()}\`** | ${roleMap[layer] || 'Composant Système'} | ${count} | ${pct}% |\n`;
  }

  md += `\n---

## 4. Points Chauds de Complexité Cyclomatique (Top Hotspots ≥ 10)

`;

  if (hotspots.length === 0) {
    md += `*Aucun point chaud de complexité détecté (ensemble des fonctions < 10 CC).*\n\n`;
  } else {
    md += `| Symbole | Complexité (CC) | Lignes (LOC) | Fichier Cible | Risque de Régression |\n`;
    md += `|:---|:---:|:---:|:---|:---:|\n`;
    const sortedHotspots = [...hotspots].sort((a, b) => (b.cyclomatic_complexity || 0) - (a.cyclomatic_complexity || 0));
    for (const h of sortedHotspots.slice(0, 15)) {
      const risk = (h.cyclomatic_complexity || 10) >= 20 ? '🚨 Très Élevé' : '⚠️ Modéré';
      md += `| **\`${h.name}\`** (${h.kind}) | **${h.cyclomatic_complexity}** | ${h.loc || 1} | \`${h.file_path}\` | ${risk} |\n`;
    }
    md += `\n`;
  }

  md += `---

## 5. Détection de Code Mort & Symboles Orphelins (${orphans.length})

`;

  if (orphans.length === 0) {
    md += `*Aucun composant orphelin isolé détecté. Tous les symboles sont intégrés au graphe d'appels.*\n\n`;
  } else {
    md += `| Symbole Orphelin | Type | Fichier | Volume |\n`;
    md += `|:---|:---:|:---|:---:|\n`;
    for (const o of orphans.slice(0, 12)) {
      md += `| \`${o.name}\` | \`${o.kind}\` | \`${o.file_path}\` | ${o.loc || 1} LOC |\n`;
    }
    if (orphans.length > 12) {
      md += `| _... et ${orphans.length - 12} autres symboles orphelins_ | | | |\n`;
    }
    md += `\n`;
  }

  md += `---

## 6. Recommandations Stratégiques et Plan d'Action Priorisé

1. **P0 (Immédiat) — Remédiation des Failles Critiques** :
   ${summary.criticalCount > 0 ? `- Traiter en priorité les **${summary.criticalCount}** vulnérabilités critiques identifiées dans la section 2.` : '- Aucune faille critique active.'}
   - Remplacer les constructions de requêtes dynamiques ou d'accès fichiers sans contrôle par des interfaces typées et scellées.
2. **P1 (Court Terme) — Découplage des Hotspots de Complexité** :
   - Refactoriser les fonctions dont la complexité cyclomatique dépasse 15 en découpant la logique métier en sous-fonctions unitaires testables.
3. **P2 (Moyen Terme) — Scellement Formel EARS & Nettoyage** :
   - Élaguer le code mort orphelin identifié pour alléger la surface d'attaque et la dette technique.
   - Enchâsser les entrées et sorties critiques dans des contrats invariants BLAKE3 via le module MCP AetherScope.

---
*Rapport généré automatiquement par Aether Engine / AetherScope Cockpit — Export certifié conforme.*
`;

  return md;
}

/**
 * Generates a self-contained, beautifully styled Dark-Mode HTML Security Audit Report
 */
export function generateAuditHtml(cockpitState: CockpitState): string {
  const summary = computeAuditSummary(cockpitState);
  const violations = cockpitState.allViolations || [];
  const hotspots = cockpitState.hotspotNodes || [];
  const orphans = cockpitState.orphanNodes || [];

  const gradeColor = {
    A: '#10b981',
    B: '#38bdf8',
    C: '#eab308',
    D: '#f97316',
    F: '#ef4444',
  }[summary.securityGrade];

  const violationsRows = violations.map((v) => {
    const sevClass = v.severity === 'CRITICAL' ? 'badge-critical' : v.severity === 'HIGH' ? 'badge-high' : 'badge-med';
    const param = v.transmitted_data ? `<span class="param-tag">param: ${escapeHtml(v.transmitted_data)}</span>` : '';
    return `
      <tr>
        <td><span class="badge ${sevClass}">${escapeHtml(v.severity)}</span></td>
        <td><strong>${escapeHtml(v.cve_id || v.rule_id)}</strong><br><span class="muted">${escapeHtml(v.cwe_class || 'CWE')}</span></td>
        <td><code>${escapeHtml(v.file_path)}:${v.line_number || 1}</code>${param}</td>
        <td>${escapeHtml(v.title || v.description)}</td>
        <td class="remediation">${escapeHtml(v.remediation || 'Sanitiser les entrées et vérifier les bornes.')}</td>
      </tr>
    `;
  }).join('');

  const hotspotRows = hotspots.slice(0, 15).map((h) => `
    <tr>
      <td><code>${escapeHtml(h.name)}</code> <span class="muted">(${escapeHtml(h.kind)})</span></td>
      <td><strong style="color: ${h.cyclomatic_complexity >= 20 ? '#ef4444' : '#f59e0b'};">${h.cyclomatic_complexity}</strong></td>
      <td>${h.loc || 1} LOC</td>
      <td><code>${escapeHtml(h.file_path)}</code></td>
    </tr>
  `).join('');

  const layerRows = Object.entries(summary.layerDistribution).map(([layer, count]) => {
    const pct = summary.totalNodes > 0 ? ((count / summary.totalNodes) * 100).toFixed(1) : '0';
    return `
      <tr>
        <td><strong>${escapeHtml(layer.toUpperCase())}</strong></td>
        <td>${count} symboles</td>
        <td>
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" style="width: ${pct}%;"></div>
          </div>
        </td>
        <td style="text-align: right;">${pct}%</td>
      </tr>
    `;
  }).join('');

  const tHtml = 'html';
  const tHead = 'head';
  const tBody = 'body';
  const tStyle = 'style';

  return `<!DOCTYPE html>
<${tHtml} lang="fr">
<${tHead}>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AetherScope — Rapport d'Audit de Sécurité : ${escapeHtml(summary.projectName)}</title>
  <${tStyle}>
    :root {
      --bg: #090d16;
      --card-bg: #0f1526;
      --border: rgba(255, 255, 255, 0.08);
      --accent: #38bdf8;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --critical: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --safe: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 32px 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }
    .brand { font-size: 24px; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 8px; }
    .brand span { color: var(--accent); }
    .score-badge {
      display: flex;
      align-items: center;
      gap: 16px;
      background: var(--card-bg);
      padding: 12px 24px;
      border-radius: 16px;
      border: 1px solid var(--border);
    }
    .score-circle {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      border: 4px solid ${gradeColor};
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      font-weight: 900;
      color: ${gradeColor};
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 20px;
    }
    .stat-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 6px; font-weight: 600; }
    .stat-card .val { font-size: 26px; font-weight: 800; color: #fff; font-family: monospace; }
    h2 { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    section { margin-bottom: 40px; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid var(--border);
      font-size: 13px;
    }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: rgba(255, 255, 255, 0.03); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
    tr:last-child td { border-bottom: none; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: rgba(255, 255, 255, 0.06); padding: 2px 6px; border-radius: 4px; color: #7dd3fc; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      font-family: monospace;
      letter-spacing: 0.03em;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge-med { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.4); }
    .param-tag { display: inline-block; margin-left: 6px; font-size: 10px; font-family: monospace; padding: 1px 6px; border-radius: 4px; background: rgba(168, 85, 247, 0.25); color: #d8b4fe; }
    .muted { color: var(--muted); font-size: 11px; }
    .remediation { color: #a7f3d0; font-size: 12px; }
    .progress-bar-bg { width: 100%; height: 8px; background: rgba(255, 255, 255, 0.05); border-radius: 4px; overflow: hidden; }
    .progress-bar-fill { height: 100%; background: var(--accent); border-radius: 4px; }
    .recommendations-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
    }
    .rec-item { margin-bottom: 16px; display: flex; gap: 12px; align-items: flex-start; }
    .rec-item:last-child { margin-bottom: 0; }
    .rec-priority { padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 800; font-family: monospace; shrink: 0; }
    .p0 { background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .p1 { background: rgba(249, 115, 22, 0.25); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .p2 { background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.4); }
    footer { text-align: center; margin-top: 48px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); padding-top: 24px; }

    @media print {
      body { background: #fff !important; color: #000 !important; padding: 0 !important; }
      .container { max-width: 100% !important; }
      .stat-card, table, .recommendations-box, .score-badge { background: #fff !important; border: 1px solid #ccc !important; color: #000 !important; }
      th { background: #f3f4f6 !important; color: #333 !important; }
      th, td { border-bottom: 1px solid #eee !important; color: #111 !important; }
      .stat-card .val, h2, .brand { color: #000 !important; }
      code { background: #f3f4f6 !important; color: #000 !important; }
      .badge-critical { background: #fee2e2 !important; color: #b91c1c !important; }
      .badge-high { background: #ffedd5 !important; color: #c2410c !important; }
      .badge-med { background: #fef9c3 !important; color: #a16207 !important; }
      .remediation { color: #065f46 !important; }
    }
  </${tStyle}>
</${tHead}>
<${tBody}>
  <div class="container">
    <header>
      <div>
        <div class="brand"><span>🪐</span> AetherScope Security Audit</div>
        <p class="muted" style="margin-top: 4px;">Cible : <code>${escapeHtml(summary.projectPath)}</code> · Scan : ${escapeHtml(summary.timestamp)}</p>
      </div>
      <div class="score-badge">
        <div>
          <div style="font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 700;">Score Défensif</div>
          <div style="font-size: 20px; font-weight: 800; color: #fff;">${summary.securityScore} / 100</div>
        </div>
        <div class="score-circle">${summary.securityGrade}</div>
      </div>
    </header>

    <div class="grid">
      <div class="stat-card">
        <div class="label">Nœuds AST</div>
        <div class="val">${summary.totalNodes}</div>
        <div class="muted">Symboles & structures</div>
      </div>
      <div class="stat-card">
        <div class="label">Flux d'Appels</div>
        <div class="val">${summary.totalEdges}</div>
        <div class="muted">Relations cartographiées</div>
      </div>
      <div class="stat-card">
        <div class="label">Failles CWE SAST</div>
        <div class="val" style="color: ${summary.totalViolations > 0 ? 'var(--critical)' : 'var(--safe)'};">${summary.totalViolations}</div>
        <div class="muted">${summary.criticalCount} Critiques · ${summary.highCount} Élevées</div>
      </div>
      <div class="stat-card">
        <div class="label">Hotspots de Complexité</div>
        <div class="val" style="color: ${summary.hotspotsCount > 0 ? 'var(--high)' : 'var(--safe)'};">${summary.hotspotsCount}</div>
        <div class="muted">Cyclomatique ≥ 10</div>
      </div>
      <div class="stat-card">
        <div class="label">Code Mort / Orphelins</div>
        <div class="val">${summary.orphanCount}</div>
        <div class="muted">Éligibles à l'élagage</div>
      </div>
      <div class="stat-card">
        <div class="label">Contrats EARS</div>
        <div class="val" style="color: var(--accent);">${summary.earsContractsCount}</div>
        <div class="muted">Invariants scellés BLAKE3</div>
      </div>
    </div>

    <section>
      <h2>🛡️ Matrice des Vulnérabilités & Alertes CWE (${violations.length})</h2>
      ${violations.length === 0 ? '<p class="muted">Aucune vulnérabilité active détectée dans le périmètre actuel.</p>' : `
      <table>
        <thead>
          <tr>
            <th>Sévérité</th>
            <th>CWE / Règle</th>
            <th>Emplacement Source</th>
            <th>Description & Vecteur</th>
            <th>Remédiation Conseillée</th>
          </tr>
        </thead>
        <tbody>
          ${violationsRows}
        </tbody>
      </table>
      `}
    </section>

    <section>
      <h2>🏛️ Distribution des Couches d'Architecture</h2>
      <table>
        <thead>
          <tr>
            <th>Couche Logique</th>
            <th>Composants</th>
            <th>Répartition Graphique</th>
            <th style="text-align: right;">Pourcentage</th>
          </tr>
        </thead>
        <tbody>
          ${layerRows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>🔥 Points Chauds de Complexité Cyclomatique (Top Hotspots)</h2>
      ${hotspots.length === 0 ? '<p class="muted">Aucun hotspot détecté.</p>' : `
      <table>
        <thead>
          <tr>
            <th>Symbole Cible</th>
            <th>Complexité (CC)</th>
            <th>Volume</th>
            <th>Chemin Fichier</th>
          </tr>
        </thead>
        <tbody>
          ${hotspotRows}
        </tbody>
      </table>
      `}
    </section>

    <section>
      <h2>📋 Plan d'Action & Recommandations de Remédiation</h2>
      <div class="recommendations-box">
        <div class="rec-item">
          <span class="rec-priority p0">P0</span>
          <div>
            <strong>Neutralisation Immédiate des Failles Critiques :</strong>
            <p class="muted" style="margin-top: 4px;">
              ${summary.criticalCount > 0 ? `Corriger sans délai les ${summary.criticalCount} failles critiques identifiées dans la matrice SAST.` : 'Aucune faille critique active.'}
              Sceller les entrées/sorties utilisateur via des analyseurs lexicaux stricts et des gardes défensives.
            </p>
          </div>
        </div>
        <div class="rec-item">
          <span class="rec-priority p1">P1</span>
          <div>
            <strong>Refactorisation des Hotspots de Complexité :</strong>
            <p class="muted" style="margin-top: 4px;">
              Décomposer les ${summary.hotspotsCount} fonctions présentant un score cyclomatique ≥ 10 pour limiter les chemins d'exécution non testés et faciliter l'audit formel.
            </p>
          </div>
        </div>
        <div class="rec-item">
          <span class="rec-priority p2">P2</span>
          <div>
            <strong>Élagage du Code Mort et Intégration Continue EARS :</strong>
            <p class="muted" style="margin-top: 4px;">
              Supprimer les ${summary.orphanCount} symboles orphelins isolés et configurer les contrats invariants EARS vérifiés via BLAKE3 pour prévenir toute régression structurelle.
            </p>
          </div>
        </div>
      </div>
    </section>

    <footer>
      Rapport d'audit de sécurité généré le ${new Date().toLocaleDateString('fr-FR')} par AetherScope Engine · Tous droits réservés
    </footer>
  </div>
</${tBody}>
</${tHtml}>`;
}

/**
 * Triggers an instant in-memory Blob file download in browser environments
 */
export function downloadBlob(content: string, filename: string, mimeType: string): void {
  if (typeof window === 'undefined') return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function escapeHtml(str?: string): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
