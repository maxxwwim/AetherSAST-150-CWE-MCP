// =========================================================================
// AETHERSCOPE V2 — AI, MODALS, CHAT & COCKPIT CONTROLLER (ui_ai_modals.js)
// Search Omnibox, AI Context Packer, Copilot Chat, Telemetry, Project Hub,
// MCP Bridge, Settings, Shortcuts & Lifecycle Initialization
// =========================================================================

// --- Search Omnibox & Beacon Illumination System ---
const searchModal = document.getElementById('search-modal');
const omniInput = document.getElementById('omni-search-input');
const searchList = document.getElementById('search-results-list');
let searchSelectedIndex = 0;

// Topbar Search Cockpit Elements
const topbarSearchInput = document.getElementById('topbar-search-input');
const topbarSearchDropdown = document.getElementById('topbar-search-dropdown');
const topbarSearchResults = document.getElementById('topbar-search-results');
const topbarSearchCount = document.getElementById('topbar-search-count');
const topbarSearchClear = document.getElementById('btn-topbar-search-clear');
let topbarSelectedIndex = 0;

const safeEscape = (str) => {
  if (typeof escapeHtml === 'function') return escapeHtml(String(str || ''));
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
};

// Core query engine shared by Topbar and Modal (Full Deep Search across functions, methods, calls, fields, docs, violations)
function querySearchNodes(q, cat) {
  q = (q || '').toLowerCase().trim();
  cat = cat || 'all';
  const nodes = state.data?.nodes || [];
  let scoredResults = [];

  // 1. Folders search
  if (cat === 'all' || cat === 'folder') {
    const uniqueFolders = new Set();
    nodes.forEach(n => {
      if (n.folder && n.folder !== 'root') uniqueFolders.add(n.folder);
    });
    Array.from(uniqueFolders).sort().forEach(f => {
      const fLower = f.toLowerCase();
      if (q.length === 0 || fLower.includes(q)) {
        let score = 25;
        if (fLower === q) score = 100;
        else if (fLower.startsWith(q)) score = 80;
        scoredResults.push({
          score,
          item: {
            is_folder: true,
            name: f,
            file_path: '📁 Dossier Architectural',
            stereotype: '«Dossier»'
          }
        });
      }
    });
  }

  // 2. Nodes Deep Search
  if (cat !== 'folder') {
    nodes.forEach(n => {
      if (cat === 'form' && !(n.stereotype === '«Form»' || n.stereotype === '«Endpoint»' || n.is_form || (n.id && n.id.startsWith('api::')))) return;
      if (cat === 'class' && !n.is_class) return;
      if (cat === 'func' && n.symbol_type !== 'function') return;
      if (cat === 'ui' && n.layer !== 'ui') return;
      if (cat === 'doc' && n.layer !== 'docs' && !(n.file_path && n.file_path.endsWith('.md'))) return;
      if (cat === 'file' && !n.is_file) return;
      if (cat === 'violation' && !n.has_security_violation && !(n.metadata?.violations && n.metadata.violations.length > 0)) return;

      if (q.length === 0) {
        let defaultScore = 10;
        if (n.has_security_violation) defaultScore = 95;
        else if (n.is_class) defaultScore = 30;
        else if (n.is_file) defaultScore = 20;
        scoredResults.push({ score: defaultScore, item: n });
        return;
      }

      const nameLower = (n.name || '').toLowerCase();
      const pathLower = (n.file_path || '').toLowerCase();
      const folderLower = (n.folder || '').toLowerCase();
      const idLower = (n.id || '').toLowerCase();
      const stereoLower = (n.stereotype || '').toLowerCase();
      const docLower = (n.docstring || '').toLowerCase();
      const contentLower = (n.metadata?.raw_content || '').toLowerCase();

      // Check methods & method calls
      let methodMatchName = null;
      if (n.metadata?.methods) {
        for (const m of n.metadata.methods) {
          const mName = (m.name || '').toLowerCase();
          if (mName.includes(q)) {
            methodMatchName = m.name;
            break;
          }
          if (m.calls && m.calls.some(c => (c || '').toLowerCase().includes(q))) {
            methodMatchName = `${m.name} ➔ appel(${q})`;
            break;
          }
        }
      }

      // Check struct/class attributes
      let attrMatchName = null;
      if (!methodMatchName && n.metadata?.attributes) {
        for (const a of n.metadata.attributes) {
          if ((a.name || '').toLowerCase().includes(q)) {
            attrMatchName = a.name;
            break;
          }
        }
      }

      // Check security violations
      let violationMatch = false;
      if (n.metadata?.violations) {
        violationMatch = n.metadata.violations.some(v => (v || '').toLowerCase().includes(q));
      }

      let score = 0;
      if (nameLower === q) score = 100;
      else if (nameLower.startsWith(q)) score = 90;
      else if (nameLower.includes(q)) score = 75;
      else if (methodMatchName) score = 65;
      else if (attrMatchName) score = 60;
      else if (pathLower.includes(q)) score = 50;
      else if (idLower.includes(q)) score = 45;
      else if (folderLower.includes(q)) score = 40;
      else if (stereoLower.includes(q)) score = 35;
      else if (violationMatch || (n.has_security_violation && q.includes('violat'))) score = 70;
      else if (docLower.includes(q)) score = 25;
      else if (contentLower.includes(q)) score = 15;

      if (score > 0) {
        let displayItem = n;
        if (methodMatchName) {
          displayItem = Object.assign({}, n, {
            stereotype: `⚙️ ${methodMatchName}`
          });
        } else if (attrMatchName) {
          displayItem = Object.assign({}, n, {
            stereotype: `🏷️ Champ: ${attrMatchName}`
          });
        }
        scoredResults.push({ score, item: displayItem });
      }
    });
  }

  scoredResults.sort((a, b) => b.score - a.score);
  return scoredResults.slice(0, 60).map(s => s.item);
}
window.querySearchNodes = querySearchNodes;

// --- Topbar Search Dropdown Controls ---
function openTopbarSearchDropdown() {
  if (topbarSearchDropdown) {
    topbarSearchDropdown.classList.add('open');
    topbarSearchDropdown.style.display = 'flex';
  }
}
window.openTopbarSearchDropdown = openTopbarSearchDropdown;

function closeTopbarSearchDropdown() {
  if (topbarSearchDropdown) {
    topbarSearchDropdown.classList.remove('open');
    topbarSearchDropdown.style.display = 'none';
  }
}
window.closeTopbarSearchDropdown = closeTopbarSearchDropdown;

function focusTopbarSearch() {
  if (topbarSearchInput) {
    topbarSearchInput.focus();
    topbarSearchInput.select();
    openTopbarSearchDropdown();
    updateTopbarSearchResults();
  } else {
    openSearchModal();
  }
}
window.focusTopbarSearch = focusTopbarSearch;

function updateTopbarSearchResults() {
  if (!topbarSearchResults) return;
  const q = topbarSearchInput ? topbarSearchInput.value : '';
  const cat = state.searchCategory || 'all';
  const results = querySearchNodes(q, cat);

  if (topbarSearchCount) {
    topbarSearchCount.innerText = `${results.length} résultat${results.length > 1 ? 's' : ''}`;
  }

  topbarSearchResults.innerHTML = '';
  if (results.length === 0) {
    topbarSearchResults.innerHTML = '<div style="padding:16px;text-align:center;color:#64748b;font-style:italic;font-size:12px;">Aucun symbole, fonction, classe ou dossier correspondant.</div>';
    return;
  }

  results.forEach((itemData, idx) => {
    const item = document.createElement('div');
    item.className = `search-result-item ${idx === 0 ? 'selected' : ''}`;
    let icon = '⚡';
    if (itemData.is_folder) icon = '📁';
    else if (itemData.has_security_violation) icon = '🚨';
    else if (itemData.is_file) {
      const p = (itemData.file_path || itemData.name || '').toLowerCase();
      if (p.endsWith('.java')) icon = '☕';
      else icon = '📄';
    }
    else if (itemData.is_class) icon = '🏛️';
    else if (itemData.layer === 'docs') icon = '📖';
    else if (itemData.layer === 'ui') icon = '🎨';

    const pathText = itemData.file_path || (itemData.folder ? `📁 ${itemData.folder}` : '');
    const stereoText = itemData.has_security_violation ? '🚨 Alerte SAST' : (itemData.stereotype || (itemData.is_folder ? '«Dossier»' : (itemData.layer ? itemData.layer.toUpperCase() : '')));

    item.innerHTML = `
      <div class="search-res-info">
        <div class="search-res-name">${icon} ${safeEscape(itemData.name)}</div>
        <div class="search-res-path">${safeEscape(pathText)}${itemData.folder && !itemData.is_folder ? ' • 📁 ' + safeEscape(itemData.folder) : ''}</div>
      </div>
      <div class="search-res-tag" style="${itemData.has_security_violation ? 'color:#ef4444;font-weight:800;' : ''}">${safeEscape(stereoText)}</div>
    `;

    item.addEventListener('click', (e) => {
      e.stopPropagation();
      closeTopbarSearchDropdown();
      if (itemData.is_folder) {
        if (typeof selectFolder === 'function') selectFolder(itemData.name);
      } else {
        activateSearchTarget(itemData);
      }
    });

    topbarSearchResults.appendChild(item);
  });

  topbarSelectedIndex = 0;
}

topbarSearchInput?.addEventListener('input', () => {
  const hasVal = topbarSearchInput.value.trim().length > 0;
  if (topbarSearchClear) {
    topbarSearchClear.style.display = hasVal ? 'block' : 'none';
    topbarSearchClear.classList.toggle('visible', hasVal);
  }
  openTopbarSearchDropdown();
  updateTopbarSearchResults();
});

topbarSearchInput?.addEventListener('focus', () => {
  openTopbarSearchDropdown();
  updateTopbarSearchResults();
});

topbarSearchInput?.addEventListener('click', (e) => {
  e.stopPropagation();
  openTopbarSearchDropdown();
  updateTopbarSearchResults();
});

document.getElementById('btn-expand-search-modal')?.addEventListener('click', (e) => {
  e.stopPropagation();
  const currentVal = topbarSearchInput ? topbarSearchInput.value : '';
  closeTopbarSearchDropdown();
  openSearchModal();
  if (omniInput) {
    omniInput.value = currentVal;
    updateSearchResults();
  }
});

topbarSearchClear?.addEventListener('click', (e) => {
  e.stopPropagation();
  if (topbarSearchInput) {
    topbarSearchInput.value = '';
    topbarSearchClear.style.display = 'none';
    topbarSearchClear.classList.remove('visible');
    updateTopbarSearchResults();
    topbarSearchInput.focus();
  }
});

// Topbar Category Pills
document.querySelectorAll('#topbar-search-cats .search-cat-pill').forEach(btn => {
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    document.querySelectorAll('#topbar-search-cats .search-cat-pill').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.searchCategory = btn.getAttribute('data-cat') || 'all';

    // Synchronize modal category pills
    document.querySelectorAll('#search-modal .cat-pill').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-cat') === state.searchCategory);
    });

    openTopbarSearchDropdown();
    updateTopbarSearchResults();
    if (topbarSearchInput) topbarSearchInput.focus();
  });
});

topbarSearchInput?.addEventListener('keydown', (e) => {
  if (!topbarSearchResults) return;
  const items = topbarSearchResults.querySelectorAll('.search-result-item');
  if (items.length === 0) {
    if (e.key === 'Escape') {
      closeTopbarSearchDropdown();
      topbarSearchInput.blur();
    }
    return;
  }

  if (e.key === 'ArrowDown') {
    e.preventDefault();
    items[topbarSelectedIndex]?.classList.remove('selected');
    topbarSelectedIndex = (topbarSelectedIndex + 1) % items.length;
    items[topbarSelectedIndex]?.classList.add('selected');
    items[topbarSelectedIndex]?.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    items[topbarSelectedIndex]?.classList.remove('selected');
    topbarSelectedIndex = (topbarSelectedIndex - 1 + items.length) % items.length;
    items[topbarSelectedIndex]?.classList.add('selected');
    items[topbarSelectedIndex]?.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter') {
    e.preventDefault();
    const selectedEl = items[topbarSelectedIndex];
    if (selectedEl) selectedEl.click();
  } else if (e.key === 'Escape') {
    e.preventDefault();
    closeTopbarSearchDropdown();
    topbarSearchInput.blur();
  }
});

// Click outside topbar search cockpit closes dropdown
document.addEventListener('click', (e) => {
  const cockpit = document.getElementById('topbar-search-cockpit') || document.getElementById('topbar-search-box');
  if (cockpit && !cockpit.contains(e.target)) {
    closeTopbarSearchDropdown();
  }
});

// --- Modal Search Controls (Legacy & Secondary Access) ---
function openSearchModal() {
  if (searchModal) {
    searchModal.classList.add('open');
  }
  if (omniInput) {
    omniInput.value = '';
    omniInput.focus();
  }
  updateSearchResults();
}
window.openSearchModal = openSearchModal;

function closeSearchModal() {
  if (searchModal) {
    searchModal.classList.remove('open');
  }
}
window.closeSearchModal = closeSearchModal;

document.getElementById('btn-trigger-search')?.addEventListener('click', focusTopbarSearch);
document.getElementById('btn-close-search-modal')?.addEventListener('click', closeSearchModal);

document.querySelectorAll('#search-modal .cat-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#search-modal .cat-pill').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.searchCategory = btn.getAttribute('data-cat') || 'all';

    // Synchronize topbar category pills
    document.querySelectorAll('#topbar-search-cats .search-cat-pill').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-cat') === state.searchCategory);
    });

    updateSearchResults();
  });
});

omniInput?.addEventListener('input', updateSearchResults);

function updateSearchResults() {
  if (!omniInput || !searchList) return;
  const q = omniInput.value;
  const cat = state.searchCategory || 'all';
  const results = querySearchNodes(q, cat);

  const countPill = document.getElementById('search-count-pill');
  if (countPill) countPill.innerText = `${results.length} résultat${results.length > 1 ? 's' : ''}`;

  searchList.innerHTML = '';
  if (results.length === 0) {
    searchList.innerHTML = '<div style="padding:16px;text-align:center;color:#64748b;font-style:italic;">Aucun symbole ou dossier correspondant trouvé.</div>';
    return;
  }

  results.forEach((itemData, idx) => {
    const item = document.createElement('div');
    item.className = `search-result-item ${idx === 0 ? 'selected' : ''}`;
    item.innerHTML = `
      <div class="search-res-info">
        <div class="search-res-name">${itemData.is_folder ? '📁 ' + safeEscape(itemData.name) : safeEscape(itemData.name)}</div>
        <div class="search-res-path">${safeEscape(itemData.file_path)}${itemData.folder ? ' • 📁 ' + safeEscape(itemData.folder) : ''}</div>
      </div>
      <div class="search-res-tag">${safeEscape(itemData.stereotype || '')}</div>
    `;

    item.addEventListener('click', () => {
      if (itemData.is_folder) {
        closeSearchModal();
        if (typeof selectFolder === 'function') selectFolder(itemData.name);
      } else {
        activateSearchTarget(itemData);
      }
    });

    searchList.appendChild(item);
  });

  searchSelectedIndex = 0;
}

omniInput?.addEventListener('keydown', (e) => {
  if (!searchList) return;
  const items = searchList.querySelectorAll('.search-result-item');
  if (items.length === 0) return;

  if (e.key === 'ArrowDown') {
    e.preventDefault();
    items[searchSelectedIndex]?.classList.remove('selected');
    searchSelectedIndex = (searchSelectedIndex + 1) % items.length;
    items[searchSelectedIndex]?.classList.add('selected');
    items[searchSelectedIndex]?.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    items[searchSelectedIndex]?.classList.remove('selected');
    searchSelectedIndex = (searchSelectedIndex - 1 + items.length) % items.length;
    items[searchSelectedIndex]?.classList.add('selected');
    items[searchSelectedIndex]?.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter') {
    e.preventDefault();
    const selectedEl = items[searchSelectedIndex];
    if (selectedEl) selectedEl.click();
  }
});

// Illuminate Node with Shockwave Beacon & Fly-to Redirection
function activateSearchTarget(n) {
  closeSearchModal();
  closeTopbarSearchDropdown();
  if (topbarSearchInput) topbarSearchInput.blur();

  // 1. Set pulsating beacon
  state.beaconNode = n;
  state.beaconStart = performance.now();
  if (window.AudioSys?.beaconPulse) AudioSys.beaconPulse();

  // 2. Camera cinematic fly-to
  state.camera.targetX = n.x;
  state.camera.targetY = n.y;
  state.camera.targetZoom = 1.15;

  // 3. Select node
  if (typeof selectNode === 'function') selectNode(n);
  showToast(`🎯 Cible illuminée : ${n.name}`);
}
window.activateSearchTarget = activateSearchTarget;

// --- AI Context Packer & Prompt Generator ---
const TASK_TEMPLATES = {
  refactor: {
    title: "⚡ Refactorisation & Performance",
    prompt: "Analyser la structure ci-dessous, identifier les goulots d'étranglement, la dette technique et proposer une refactorisation modulaire à haute performance sans rompre les contrats d'interface existants."
  },
  security: {
    title: "🛡️ Audit de Sécurité & Robustesse",
    prompt: "Effectuer un audit de sécurité approfondi (injections, validation des entrées, gestion des erreurs, fuites de mémoire) sur ce composant et ses interactions avec ses dépendances."
  },
  tests: {
    title: "🧪 Génération de Tests Unitaires",
    prompt: "Générer une suite complète de tests unitaires et d'intégration (cas nominaux, cas limites, mocking des dépendances identifiées ci-dessous) avec couverture maximale."
  },
  feature: {
    title: "✨ Nouvelle Fonctionnalité / Extension",
    prompt: "Étendre ce composant pour lui ajouter une nouvelle fonctionnalité tout en respectant scrupuleusement les contrats d'interface, le typage strict et les conventions d'architecture."
  },
  doc: {
    title: "📖 Spécifications & Documentation Technique",
    prompt: "Rédiger la documentation technique complète de ce symbole : rôle architectural, flux de données entrants et sortants, entrées/sorties et guide d'intégration."
  }
};

function generateAiPrompt(n, taskKey) {
  const currentPort = window.location.port || '3030';
  const apiOrigin = window.location.origin || `http://127.0.0.1:${currentPort}`;

  if (state.selectedFolder && !state.selectedNode) {
    const folder = state.selectedFolder;
    const nodes = (state.data.nodes || []).filter(node => (node.folder || 'root') === folder);
    const files = nodes.filter(node => node.is_file);
    const classes = nodes.filter(node => node.is_class);
    const funcs = nodes.filter(node => node.symbol_type === 'function');
    const t = TASK_TEMPLATES[taskKey] || TASK_TEMPLATES.refactor;

    return `<context>
  <project name="${state.data.project_name || 'Project'}"/>
  <target_folder name="${folder}"/>
  <metrics total_files="${files.length}" total_classes="${classes.length}" total_functions="${funcs.length}"/>
  
  <contained_files>
${files.map(f => `    - ${f.name} (${f.file_path}) [${(f.metadata && f.metadata.lines) || 0} LOC]`).join('\n')}
  </contained_files>
</context>

<task objective="${t.title} sur le module ${folder}">
${t.prompt}
Analyser la cohésion interne du module, le couplage avec les autres parties du projet et proposer les axes d'amélioration.
</task>

<aetherscope_api_and_research>
[COMMANDES MCP COMBINÉES AETHERSCOPE V2 & TÉLÉMÉTRIE]
1. Inspection + Caméra 3D + Flux MVC (3-en-1) :
   Outil MCP : aetherscope_get_active_target({"symbol_id": "${folder}", "action": "${t.title}", "details": "Inspection du module ${folder}", "trace_direction": "both", "max_depth": 3})
2. Création / Suivi de Tâche + Caméra 3D (3-en-1) :
   Outil MCP : aetherscope_manage_tasks({"action": "create", "title": "${t.title} (${folder})", "kind": "arch_refactor", "target_symbol": "${folder}"})
3. Validation Pare-Feu < 50ms + Clôture Tâche + Chat Copilot (4-en-1 après modification) :
   Outil MCP : aetherscope_verify_patch({"files_modified": [${files.slice(0, 3).map(f => `"${f.file_path}"`).join(', ') || `"${folder}"`}], "status": "done", "progress": 100, "chat_message": "${t.title} terminé sur ${folder}"})
4. Fallback HTTP Local (si hors MCP) :
   POST ${apiOrigin}/api/ai/telemetry — Body JSON: {"target": "${folder}", "action": "${t.title}", "details": "Inspection / modification du module ${folder}"}
5. Documentation & Contrats Modulaires : Consulter AETHER_AI_RULES.md et aether.lock.toml à la racine, ainsi que le README.md du dossier (${folder}).
</aetherscope_api_and_research>

<response_format_rules>
[CONSIGNES DE RÉPONSE OPTIMISÉE - PETIT PROMPT UPDATE OPTI]
- Concision & Zéro Blabla : Réponse technique, dense et directe. Aucune politesse superflue.
- Diffs & Updates Chirurgicaux : Ne JAMAIS réécrire un fichier complet si seules quelques lignes changent. Fournir uniquement les extraits ciblés à remplacer ou diffs précis.
- Règle d'Atomicité (< 35 lignes) : Découper le code en fonctions atomiques pures de moins de 35 lignes (règle stricte utils/ et domain/).
- Respect Strict des Couches & Contrats : Préserver la séparation (domain/ = logique pure sans UI/DB, application/ = services, infrastructure/ = I/O & API, ui/ = rendu). Ne jamais casser les signatures existantes.
- Réflexion Structurée : Penser à haute voix de manière ordonnée (Diagnostic ➔ Impact ➔ Modification chirurgicale).
</response_format_rules>`;
  }

  if (!n) n = state.data.nodes && state.data.nodes[0] ? state.data.nodes[0] : { name: 'Codebase', file_path: '', layer: 'general', stereotype: '«System»' };
  const edges = state.data.edges || [];
  const incoming = edges.filter(e => e.target === n.id).map(e => e.source.split('::').pop().replace('file::', ''));
  const outgoing = edges.filter(e => e.source === n.id).map(e => `${e.target.split('::').pop().replace('file::', '')} (${e.relation})`);

  const t = TASK_TEMPLATES[taskKey] || TASK_TEMPLATES.refactor;
  const isFormNode = n.stereotype === '«Form»' || n.is_form;
  const formNetRoutes = outgoing.filter(e => e.includes('submits') || e.includes('network'));

  return `<context>
  <project name="${state.data.project_name || 'Project'}"/>
  <target_symbol name="${n.name}" type="${n.stereotype}" path="${n.file_path}"/>
  <architectural_layer name="${(n.layer || 'general').toUpperCase()}"/>
  <metrics lines="${(n.metadata && n.metadata.lines) || 1}" in_degree="${n.in_degree || 0}" out_degree="${n.out_degree || 0}"/>
${isFormNode ? `  <form_spec is_form="true">
    <network_targets>
${formNetRoutes.length > 0 ? formNetRoutes.map(s => `      - ${s}`).join('\n') : '      (Aucun appel réseau direct détecté)'}
    </network_targets>
  </form_spec>\n` : ''}  
  <incoming_callers>
${incoming.length > 0 ? incoming.map(s => `    - ${s}`).join('\n') : '    (Point d\'entrée / Aucun appelant interne direct)'}
  </incoming_callers>

  <outgoing_dependencies>
${outgoing.length > 0 ? outgoing.map(s => `    - ${s}`).join('\n') : '    (Feuille / Aucune dépendance externe directe)'}
  </outgoing_dependencies>
</context>

<task objective="${t.title}">
${t.prompt}
</task>

<aetherscope_api_and_research>
[COMMANDES MCP COMBINÉES AETHERSCOPE V2 & TÉLÉMÉTRIE]
1. Inspection + Caméra 3D + Trace MVC (3-en-1) :
   Outil MCP : aetherscope_get_active_target({"symbol_id": "${n.name}", "action": "${t.title}", "details": "Inspection de ${n.name} (${n.file_path})", "trace_direction": "both", "max_depth": 4})
2. Création / Suivi de Tâche + Caméra 3D (3-en-1) :
   Outil MCP : aetherscope_manage_tasks({"action": "create", "title": "${t.title} : ${n.name}", "kind": "function", "target_symbol": "${n.name}", "target_file": "${n.file_path}"})
3. Validation Pare-Feu < 50ms + Clôture Tâche + Chat Copilot (4-en-1 après modification) :
   Outil MCP : aetherscope_verify_patch({"files_modified": ["${n.file_path}"], "status": "done", "progress": 100, "chat_message": "${t.title} validé sur ${n.name}"})
4. Fallback HTTP Local (si hors MCP) :
   POST ${apiOrigin}/api/ai/telemetry — Body JSON: {"target": "${n.name}", "action": "${t.title}", "details": "Inspection / modification de ${n.name} (${n.file_path})"}
5. Documentation & Contrats Modulaires : Consulter AETHER_AI_RULES.md et aether.lock.toml à la racine, ainsi que le README.md du dossier de ce symbole (${n.file_path}).
</aetherscope_api_and_research>

<response_format_rules>
[CONSIGNES DE RÉPONSE OPTIMISÉE - PETIT PROMPT UPDATE OPTI]
- Concision & Zéro Blabla : Réponse technique, dense et directe. Aucune politesse superflue.
- Diffs & Updates Chirurgicaux : Ne JAMAIS réécrire un fichier complet si seules quelques lignes changent. Fournir uniquement les extraits ciblés à remplacer ou diffs précis.
- Règle d'Atomicité (< 35 lignes) : Découper le code en fonctions atomiques pures de moins de 35 lignes (règle stricte utils/ et domain/).
- Respect Strict des Couches & Contrats : Couche ${(n.layer || 'domain').toUpperCase()} respectée (domain/ = règles pures sans UI/DB, application/ = services, infrastructure/ = I/O & API, ui/ = rendu). Préserver strictement les signatures et contrats utilisés par les appelants.
- Réflexion Structurée : Penser à haute voix de manière ordonnée (Diagnostic ➔ Impact ➔ Modification chirurgicale).
</response_format_rules>`;
}
window.generateAiPrompt = generateAiPrompt;

function openAiModal() {
  if (state.selectedFolder && !state.selectedNode) {
    const targetEl = document.getElementById('ai-modal-target');
    if (targetEl) targetEl.innerText = '📁 ' + state.selectedFolder;
    updateModalPrompt();
    document.getElementById('ai-modal')?.classList.add('open');
    return;
  }
  const n = state.selectedNode || (state.data.nodes && state.data.nodes[0]);
  if (!n) {
    showToast('Sélectionnez un symbole ou un dossier pour générer son prompt.');
    return;
  }
  const targetEl = document.getElementById('ai-modal-target');
  if (targetEl) targetEl.innerText = n.name;
  updateModalPrompt();
  document.getElementById('ai-modal')?.classList.add('open');
}
window.openAiModal = openAiModal;

function updateModalPrompt() {
  const n = state.selectedNode || (state.data.nodes && state.data.nodes[0]);
  let p = generateAiPrompt(n, state.currentTask);
  const customInput = document.getElementById('ai-custom-input')?.value?.trim();
  if (customInput) {
    p += `\n\n<custom_user_instructions>\n${customInput}\n</custom_user_instructions>`;
  }
  const preview = document.getElementById('ai-prompt-preview');
  if (preview) preview.value = p;
  const tokens = Math.round(p.length / 3.8);
  const countEl = document.getElementById('ai-token-count');
  if (countEl) countEl.innerText = `~${tokens} tokens context pack`;
}

document.getElementById('ai-custom-input')?.addEventListener('input', updateModalPrompt);

document.querySelectorAll('.task-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.task-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.currentTask = btn.getAttribute('data-task') || 'refactor';
    updateModalPrompt();
  });
});

document.getElementById('btn-insp-ai')?.addEventListener('click', openAiModal);
document.getElementById('btn-ai-prompt')?.addEventListener('click', openAiModal);
document.getElementById('btn-close-ai-modal')?.addEventListener('click', () => document.getElementById('ai-modal')?.classList.remove('open'));
document.getElementById('btn-dismiss-ai-modal')?.addEventListener('click', () => document.getElementById('ai-modal')?.classList.remove('open'));

document.getElementById('btn-copy-ai-prompt')?.addEventListener('click', () => {
  const txt = document.getElementById('ai-prompt-preview')?.value || '';
  navigator.clipboard.writeText(txt).then(() => {
    showToast('📋 Prompt IA copié dans le presse-papier !');
    document.getElementById('ai-modal')?.classList.remove('open');
  });
});

// --- Master Blueprint IA Project Generator (Gemini / Claude / GPT) ---
let currentMasterLlm = 'claude';

function generateMasterBlueprintPrompt(llm = 'claude') {
  const projName = state.data.project_name || 'NouveauProjet';
  const isClaude = llm === 'claude';
  const isGemini = llm === 'gemini';

  return `# 🚀 MASTER BLUEPRINT : ARCHITECTURE & MÉTHODE DE DÉVELOPPEMENT OPTIMISÉE POUR IA
# Compatible : ${isClaude ? 'Claude 3.5 Sonnet (Recommandé)' : (isGemini ? 'Google Gemini 1.5 Pro / Flash' : 'OpenAI GPT-4o / o1')}
# Visualiseur & Cartographie : AetherScope V2 (Rust WebGL Engine)

Tu es l'Architecte Logiciel Principal et Expert Technique sur le projet "${projName}".
Nous développons ce projet selon la **MÉTHODE PAR SPÉCIFICATION MODULAIRE (Spec-Driven Architecture)**, conçue pour permettre aux LLMs de coder à pleine vitesse avec un contexte ciblé sans jamais avoir à analyser tout le projet à la fois.

---

### 🌟 1. PRINCIPE CARDINAL : DÉVELOPPEMENT PAR FICHIER .MD (ZÉRO CONTEXT LOSS)
- **Chaque dossier doit contenir son propre \`README.md\`** (ex: \`src/domain/README.md\`, \`src/ui/README.md\`).
- Ce \`README.md\` documente :
  1. Le rôle architectural précis du dossier
  2. Les entrées / sorties attendues et contrats d'interfaces
  3. La liste des fichiers et fonctions hébergés
  4. Les flux réseau ou dépendances autorisées
- **Sceau d'intégrité BLAKE3 :** Tout contrat est scellé dans \`aether.lock.toml\` pour garantir l'absence de régression.

---

### 📁 2. ARBORESCENCE & DÉCOUPAGE STRICT DES DOSSIERS
Organise systématiquement les fichiers selon la structure modulaire suivante :

\`\`\`text
${projName}/
├── aether.lock.toml          # 🔒 Verrou BLAKE3 de conformité architecturale
├── AETHER_AI_RULES.md        # 📖 Spécifications globales & directives
├── contracts/                # 📜 Schémas d'interface et spécifications formelles EARS
├── client/                   # 🎨 Interface utilisateur, composants & visualisations
├── server/                   # ⚡ Moteur backend, logique métier & API Axum/Actix
└── data-nodes/               # 💾 Persistance, modèles de données & connecteurs
\`\`\`

---

### ⚡ 3. RÈGLES SUR LES FICHIERS ET LES FONCTIONS (POUR UN GRAPH AETHERSCOPE OPTIMAL)
Dans notre visualiseur AetherScope, chaque fichier est une planète céleste et chaque fonction est un point lumineux :

1. **Fonctions Atomiques & Pures :**
   - Écris des fonctions courtes (10 à 35 lignes maximum), pures et réutilisables.
   - Une fonction = une seule responsabilité.
2. **Conventions de Préfixes :**
   - \`handle_*\` : Fonctions d'événements et gestionnaires d'actions.
   - \`fetch_*\` ou \`api_*\` : Appels réseau sortants (faisceaux lasers).
   - \`render_*\` : Logique de rendu UI ou d'affichage.
   - \`validate_*\` : Vérification des formulaires et payloads.
3. **5 Filtres d'Affiliation AetherScope V2 :**
   - Bit 1 (1) : Structure Physique (contains)
   - Bit 2 (2) : Réseau RPC (submits)
   - Bit 3 (4) : Canaux WS Temps Réel (RealtimeWS - lasers Cyan)
   - Bit 4 (8) : Sémantique (imports/calls)
   - Bit 5 (16) : Violations de Sécurité (SECURITY_VIOLATES - lasers Rouges clignotants)

---

### 🛠️ 4. PROTOCOLE MCP UNIFIÉ (8 COMMANDES COMBINÉES AETHERSCOPE)
1. \`aetherscope_get_graph_summary({"rescan": false, "include_tasks": true, "severity": "HIGH"})\` : Vue globale + Tâches + Alertes SAST (4-en-1).
2. \`aetherscope_get_active_target({"symbol_id": "<symbole>", "action": "Analyse", "trace_direction": "both"})\` : Caméra 3D + Contrat EARS + Trace MVC (3-en-1).
3. \`aetherscope_search_symbols({"query": "...", "layer": "...", "has_violation": true, "cwe_id": "CWE-89"})\` : Recherche AST + Filtre CWE (2-en-1).
4. \`aetherscope_manage_tasks({"action": "list|create|update", "title": "...", "target_symbol": "..."})\` : Tâches + Mini-README + Caméra 3D (3-en-1).
5. \`aetherscope_verify_patch({"files_modified": ["..."], "task_id": "...", "status": "done", "chat_message": "..."})\` : Pare-Feu < 50ms + Tâche + Chat (4-en-1).
6. \`aetherscope_chat({"action": "send|history", "text": "...", "target_symbol": "..."})\` : Chat Copilot + Caméra 3D (2-en-1).
7. \`aetherscope_manage_plugins({"action": "list|test|scan|upsert", ...})\` : Gestion des règles YAML SAST (4-en-1).
8. \`aetherscope_teleport_camera({"target": "<symbole>", "action": "Focus", "details": "..."})\` : Téléportation directe de la caméra 3D.
`;
}
window.generateMasterBlueprintPrompt = generateMasterBlueprintPrompt;

function openMasterPromptModal() {
  const modal = document.getElementById('master-prompt-modal');
  const input = document.getElementById('init-project-input');
  const currPath = state.data.project_path || document.getElementById('project-path-input')?.value.trim();
  if (input && !input.value) {
    input.value = currPath ? currPath + '_NouveauProjet' : 'C:\\Users\\1234\\Desktop\\Projets\\NouveauProjet';
  }
  updateMasterPrompt();
  modal?.classList.add('open');
}
window.openMasterPromptModal = openMasterPromptModal;

function updateMasterPrompt() {
  const area = document.getElementById('master-prompt-textarea');
  if (area) {
    area.value = generateMasterBlueprintPrompt(currentMasterLlm);
  }
}

document.getElementById('btn-master-prompt')?.addEventListener('click', openMasterPromptModal);
document.getElementById('btn-close-master-prompt-modal')?.addEventListener('click', () => {
  document.getElementById('master-prompt-modal')?.classList.remove('open');
});
document.getElementById('btn-dismiss-master-modal')?.addEventListener('click', () => {
  document.getElementById('master-prompt-modal')?.classList.remove('open');
});

document.querySelectorAll('#llm-target-selector .task-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#llm-target-selector .task-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentMasterLlm = btn.getAttribute('data-llm') || 'claude';
    updateMasterPrompt();
  });
});

document.getElementById('btn-copy-master-prompt')?.addEventListener('click', () => {
  const txt = document.getElementById('master-prompt-textarea')?.value || '';
  navigator.clipboard.writeText(txt).then(() => {
    showToast('📋 Master Blueprint Prompt copié !');
  });
});

document.getElementById('btn-download-master-prompt')?.addEventListener('click', () => {
  const txt = document.getElementById('master-prompt-textarea')?.value || '';
  const blob = new Blob([txt], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `AetherScope_Master_Blueprint_${currentMasterLlm}.md`;
  a.click();
  showToast(`💾 Fichier ${a.download} téléchargé !`);
});

document.getElementById('btn-init-skeleton')?.addEventListener('click', async () => {
  const p = document.getElementById('init-project-input')?.value.trim();
  if (!p) {
    showToast('Veuillez entrer un chemin de dossier.');
    return;
  }
  showToast(`🔨 Initialisation du projet dans ${p}...`);
  try {
    const d = await window.AetherAPI.initProject(p, 'modular');
    if (d.status === 'ok') {
      showToast(`✅ ${d.message} !`);
      const pInput = document.getElementById('project-path-input');
      if (pInput) pInput.value = p;
      setTimeout(() => {
        analyze(p);
        document.getElementById('master-prompt-modal')?.classList.remove('open');
      }, 600);
    } else {
      showToast(`❌ Erreur: ${d.message || 'initialisation projet'}`);
    }
  } catch (e) {
    showToast('❌ Erreur réseau / API');
  }
});

// --- Draggable AI Copilot Chat & History Engine ---
window.copyUserPromptForAntigravity = function(target, userText) {
  const projPath = state.data?.project_path || '';
  const sym = target || 'Codebase';
  const prompt = `Dans le visualiseur AetherScope (${projPath}) :
${target ? `[Cible: ${target}] ` : ''}${userText}

Commandes MCP combinées à exécuter :
1. \`aetherscope_chat({"action": "history"})\` + \`aetherscope_get_active_target({"symbol_id": "${sym}", "action": "Analyse", "trace_direction": "both"})\` (aligne la caméra 3D et extrait le contrat EARS + flux MVC).
2. Après modification, valide en 1 appel : \`aetherscope_verify_patch({"files_modified": ["<fichier_modifié>"], "chat_message": "Réponse et correctif appliqués sur ${sym}"})\`.`;

  navigator.clipboard.writeText(prompt).then(() => {
    if (window.AudioSys?.playTone) AudioSys.playTone(880, 'sine', 0.12, 0.04);
    showToast('⚡ Prêt ! Collez le message dans Antigravity (Ctrl+V)');
  }).catch(() => {
    showToast('⚠️ Impossible de copier dans le presse-papier');
  });
};

function safeEscapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(ts) {
  if (!ts) return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const ms = ts < 10000000000 ? ts * 1000 : ts;
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function addAiChatMessage(telem, node) {
  if (!telem || !telem.target) return;
  const msgObj = {
    sender: 'ai',
    target: telem.target,
    action: telem.action || 'Navigation',
    details: telem.details || 'Déplacement sur la bulle stellaire',
    timestamp: telem.timestamp || Date.now(),
    nodeId: node ? node.id : null,
    nodeX: node ? node.x : null,
    nodeY: node ? node.y : null
  };

  state.aiChatHistory.push(msgObj);
  if (state.aiChatHistory.length > 150) {
    state.aiChatHistory.shift();
  }

  renderAiChatMessageEl(msgObj, node);
}

function renderAiChatMessageEl(msgObj, node) {
  const body = document.getElementById('ai-chat-body');
  const countPill = document.getElementById('ai-chat-count-pill');
  if (countPill) countPill.innerText = `${state.aiChatHistory.length} msg`;

  if (body) {
    const placeholder = body.querySelector('.ai-chat-placeholder');
    if (placeholder) {
      placeholder.remove();
    }

    const isUser = msgObj.sender === 'user';
    const msgEl = document.createElement('div');
    msgEl.className = `ai-chat-msg ${isUser ? 'user' : 'ai'}`;
    const rawText = msgObj.details || msgObj.text || '';
    let thoughtContent = '';
    let cleanText = rawText;

    // Parse <thought>...</thought> or <thinking>...</thinking>
    const thoughtMatch = rawText.match(/<(?:thought|thinking)>([\s\S]*?)<\/(?:thought|thinking)>/i);
    if (thoughtMatch) {
      thoughtContent = thoughtMatch[1].trim();
      cleanText = rawText.replace(/<(?:thought|thinking)>[\s\S]*?<\/(?:thought|thinking)>/i, '').trim();
    }

    let thoughtHtml = '';
    if (thoughtContent) {
      thoughtHtml = `
        <div class="ai-chat-thought-box">
          <div class="ai-thought-header" onclick="this.parentElement.classList.toggle('collapsed')">
            <span class="ai-thought-title">🧠 Réflexion & Analyse interne <span class="ai-typing-pulse"></span></span>
            <span style="font-size:0.60rem; color:#c084fc;">Afficher/Masquer ▾</span>
          </div>
          <div class="ai-thought-body">${safeEscapeHtml(thoughtContent)}</div>
        </div>
      `;
    }

    msgEl.innerHTML = `
      <div class="ai-chat-msg-meta">
        <div style="display:flex; align-items:center; gap:5px;">
          <span class="ai-chat-msg-target">${isUser ? '👤 Vous' : `📍 ${safeEscapeHtml(msgObj.target || 'AI Copilot')}`}</span>
          <span class="ai-chat-msg-action">${isUser ? 'Message' : safeEscapeHtml(msgObj.action || 'Réponse')}</span>
        </div>
        <div style="display:flex; align-items:center; gap:6px;">
          ${isUser ? `<button class="ai-chat-push-btn" title="Copier la question avec le contexte pour Antigravity" onclick="event.stopPropagation(); copyUserPromptForAntigravity('${safeEscapeHtml(msgObj.target || '')}', '${safeEscapeHtml(cleanText).replace(/'/g, "\\'")}')">⚡ Antigravity</button>` : ''}
          <span class="ai-chat-msg-time">${formatTime(msgObj.timestamp)}</span>
        </div>
      </div>
      ${thoughtHtml}
      <div class="ai-chat-msg-content">${safeEscapeHtml(cleanText)}</div>
    `;

    if (!isUser) {
      msgEl.addEventListener('click', () => {
        if (msgObj.nodeX != null && msgObj.nodeY != null) {
          state.camera.targetX = msgObj.nodeX;
          state.camera.targetY = msgObj.nodeY;
          state.camera.targetZoom = 1.05;
          if (node && typeof selectNode === 'function') selectNode(node);
          if (window.AudioSys?.playTone) AudioSys.playTone(880, 'sine', 0.15, 0.05);
          showToast(`🎯 Caméra alignée sur : ${msgObj.target}`);
        } else if (msgObj.target) {
          const tLower = msgObj.target.toLowerCase();
          const n = (state.data.nodes || []).find(x => 
            x.name.toLowerCase() === tLower || 
            x.id.toLowerCase() === tLower || 
            (x.file_path && x.file_path.toLowerCase().includes(tLower))
          );
          if (n) {
            state.camera.targetX = n.x;
            state.camera.targetY = n.y;
            state.camera.targetZoom = 1.05;
            if (typeof selectNode === 'function') selectNode(n);
            if (window.AudioSys?.playTone) AudioSys.playTone(880, 'sine', 0.15, 0.05);
            showToast(`🎯 Caméra alignée sur : ${n.name}`);
          }
        }
      });
    }

    body.appendChild(msgEl);
    if (state.aiChatAutoScroll) {
      body.scrollTop = body.scrollHeight;
    }
  }
}

async function sendUserChatMessage() {
  const input = document.getElementById('ai-chat-user-input');
  if (!input) return;
  const text = input.value.trim();
  if (!text) return;

  input.value = '';
  const targetSymbol = state.selectedNode ? state.selectedNode.name : (state.selectedFolder || null);
  updateAiStatus('thinking');

  const now = Date.now();
  const optimisticMsg = {
    id: `temp_${now}`,
    sender: 'user',
    target: targetSymbol || 'Copilot',
    action: 'Question',
    details: text,
    timestamp: now
  };
  state.aiChatHistory.push(optimisticMsg);
  renderAiChatMessageEl(optimisticMsg, null);

  try {
    const d = await window.AetherAPI.sendChatMessage(text, 'user', targetSymbol);
    if (d && d.status === 'ok') {
      if (window.AudioSys?.playTone) AudioSys.playTone(740, 'sine', 0.12, 0.04);
      showToast('⚡ Message transmis au Copilot IA !');
      if (d.message && d.message.id) {
        optimisticMsg.id = d.message.id;
      }
      pollServerChatMessages();
    } else {
      showToast('⚠️ Erreur envoi au serveur');
    }
  } catch (err) {
    console.error('sendUserChatMessage error:', err);
    showToast('⚠️ Erreur transmission message (serveur déconnecté ?)');
  }
}
window.sendUserChatMessage = sendUserChatMessage;

function toggleAiChatPopup() {
  const popup = document.getElementById('ai-chat-popup');
  const btn = document.getElementById('btn-ai-chat-toggle');
  if (!popup) return;
  const isHidden = popup.classList.toggle('hidden');
  if (!isHidden) {
    popup.classList.remove('minimized');
    if (btn) {
      btn.style.boxShadow = '0 0 16px rgba(192, 132, 252, 0.8)';
      btn.style.background = 'rgba(192, 132, 252, 0.35)';
    }
    const input = document.getElementById('ai-chat-user-input');
    if (input) setTimeout(() => input.focus(), 60);
  } else {
    if (btn) {
      btn.style.boxShadow = '';
      btn.style.background = 'rgba(168, 85, 247, 0.25)';
    }
  }
}
window.toggleAiChatPopup = toggleAiChatPopup;

// Make AI Chat popup Draggable
(function initDraggableChat() {
  const popup = document.getElementById('ai-chat-popup');
  const header = document.getElementById('ai-chat-header');
  if (!popup || !header) return;

  let isDragging = false;
  let startX = 0, startY = 0;
  let initialLeft = 0, initialTop = 0;

  header.addEventListener('mousedown', (e) => {
    if (e.target.closest('.ai-chat-header-btn') || e.target.closest('button')) return;
    isDragging = true;
    const rect = popup.getBoundingClientRect();
    startX = e.clientX;
    startY = e.clientY;
    initialLeft = rect.left;
    initialTop = rect.top;
    popup.style.bottom = 'auto';
    popup.style.right = 'auto';
    popup.style.left = `${initialLeft}px`;
    popup.style.top = `${initialTop}px`;
    e.preventDefault();
  });

  window.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    const newLeft = Math.max(10, Math.min(window.innerWidth - popup.offsetWidth - 10, initialLeft + dx));
    const newTop = Math.max(10, Math.min(window.innerHeight - 50, initialTop + dy));
    popup.style.left = `${newLeft}px`;
    popup.style.top = `${newTop}px`;
  });

  window.addEventListener('mouseup', () => {
    isDragging = false;
  });
})();

// Wire up AI Chat UI Toggles and Input Handlers
document.getElementById('btn-menu-ai-chat')?.addEventListener('click', toggleAiChatPopup);
document.getElementById('btn-ai-chat-toggle')?.addEventListener('click', toggleAiChatPopup);
document.getElementById('btn-ai-hud-open-chat')?.addEventListener('click', () => {
  const popup = document.getElementById('ai-chat-popup');
  if (popup && popup.classList.contains('hidden')) {
    toggleAiChatPopup();
  }
});
document.getElementById('btn-ai-chat-close')?.addEventListener('click', () => {
  const popup = document.getElementById('ai-chat-popup');
  if (popup && !popup.classList.contains('hidden')) {
    toggleAiChatPopup();
  }
});
document.getElementById('btn-ai-chat-min')?.addEventListener('click', () => {
  document.getElementById('ai-chat-popup')?.classList.toggle('minimized');
});
document.getElementById('btn-ai-chat-send')?.addEventListener('click', sendUserChatMessage);
document.getElementById('ai-chat-user-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendUserChatMessage();
  }
});

// --- Mode AI Copilot Telemetry Engine ---
function applyAiTelemetry(telem) {
  if (!telem || !telem.target) return;
  state.aiTelemetry = telem;
  state.aiLastTimestamp = telem.timestamp;

  // Update HUD banner
  const hud = document.getElementById('ai-telemetry-hud');
  const btn = document.getElementById('btn-ai-telemetry');
  if (hud) {
    hud.classList.remove('hidden');
    if (btn) btn.classList.add('active');
    const targetEl = document.getElementById('ai-target-badge');
    if (targetEl) targetEl.innerText = telem.target;
    const actEl = document.getElementById('ai-action-badge');
    if (actEl) actEl.innerText = telem.action || 'Exploration';
    const detEl = document.getElementById('ai-details-text');
    if (detEl) detEl.innerText = telem.details || '';
  }

  // Find node
  const nodes = state.data.nodes || [];
  const tLower = telem.target.toLowerCase();
  const node = nodes.find(n => 
    n.name.toLowerCase() === tLower || 
    n.id.toLowerCase() === tLower || 
    (n.file_path && n.file_path.toLowerCase().includes(tLower))
  );
  state.aiTelemetryNode = node || null;
  state.instanceDataDirty = true;

  // Add to Draggable Chat Popup History
  addAiChatMessage(telem, node);

  if (node) {
    if (typeof addToAiTrail === 'function') addToAiTrail(node, telem.action);

    const isCreation = (telem.action && (
      telem.action.toLowerCase().includes('créat') ||
      telem.action.toLowerCase().includes('creat') ||
      telem.action.toLowerCase().includes('naiss')
    ));

    if (isCreation) {
      state.aiSupernova = {
        x: node.x,
        y: node.y,
        name: node.name,
        startTime: performance.now(),
        duration: 3800
      };
      if (window.AudioSys?.supernovaBirth) AudioSys.supernovaBirth();
    } else {
      if (window.AudioSys?.playTone) {
        AudioSys.playTone(980, 'triangle', 0.20, 0.05);
        setTimeout(() => AudioSys.playTone(1470, 'sine', 0.25, 0.04), 70);
      }
    }

    if (state.aiAutoCam) {
      if (typeof smoothFlyTo === 'function') {
        smoothFlyTo(node.x, node.y, 0.95);
      } else {
        state.camera.targetX = node.x;
        state.camera.targetY = node.y;
        if (state.camera.targetZoom < 0.75) state.camera.targetZoom = 0.95;
      }
    }

    showToast(`🤖 L'IA explore : ${node.name} (${telem.action || 'Analyse'})`);
  }
}
window.applyAiTelemetry = applyAiTelemetry;

async function pollAiTelemetry() {
  try {
    const data = await window.AetherAPI.getTelemetry();
    if (data && data.telemetry && data.telemetry.timestamp !== state.aiLastTimestamp) {
      applyAiTelemetry(data.telemetry);
    }
  } catch (e) {}
}
setInterval(pollAiTelemetry, 400);

// --- Live Auto-Sync with Rust FileWatcher Bridge ---
let lastGraphVersion = 0;
let syncFailures = 0;
async function pollGraphVersion() {
  try {
    const res = await fetch('/api/graph/version');
    if (!res.ok) return;
    const d = await res.json();
    const sseDot = document.getElementById('sse-dot');
    if (sseDot) {
      sseDot.style.background = '#10b981';
      sseDot.style.boxShadow = '0 0 10px #10b981';
      sseDot.title = 'FileWatcher actif : synchronisation du code en temps réel';
    }
    if (lastGraphVersion === 0) {
      lastGraphVersion = d.version;
      return;
    }
    if (d.version !== lastGraphVersion) {
      lastGraphVersion = d.version;
      const gRes = await fetch('/api/graph');
      if (gRes.ok) {
        const newGraph = await gRes.json();
        applyDataKeepView(newGraph);
        const toastMsg = state.active_view_mode === 'vault'
          ? '⚡ Vault Obsidian actualisé en direct (FileWatcher)'
          : '⚡ Codebase actualisée en direct (FileWatcher)';
        showToast(toastMsg);
      }
    }
    syncFailures = 0;
  } catch (e) {
    syncFailures++;
    if (syncFailures > 4) {
      const sseDot = document.getElementById('sse-dot');
      if (sseDot) {
        sseDot.style.background = '#f59e0b';
        sseDot.style.boxShadow = 'none';
        sseDot.title = 'FileWatcher en pause';
      }
    }
  }
}
setInterval(pollGraphVersion, 800);

document.getElementById('btn-ai-autocam')?.addEventListener('click', () => {
  state.aiAutoCam = !state.aiAutoCam;
  const b = document.getElementById('btn-ai-autocam');
  if (b) b.innerText = state.aiAutoCam ? '🎥 Auto-Cam: ON' : '🎥 Auto-Cam: OFF';
  showToast(state.aiAutoCam ? 'Centrage automatique sur l\'IA activé' : 'Centrage automatique sur l\'IA désactivé');
});

function resetAiTrail() {
  state.aiTrail = [];
  if (window.AudioSys?.playTone) AudioSys.playTone(520, 'sine', 0.12, 0.04);
  showToast('🧹 Chemin IA effacé du graphe');
}
window.resetAiTrail = resetAiTrail;

document.getElementById('btn-ai-reset-trail')?.addEventListener('click', resetAiTrail);
document.getElementById('btn-ai-popup-reset-trail')?.addEventListener('click', resetAiTrail);

// --- Live AI Agent State & Full-Auto Copilot Bridge ---
function updateAiStatus(status, convId) {
  const badge = document.getElementById('ai-chat-status-badge');
  const statusText = document.getElementById('ai-chat-status-text');
  const btnCancelTop = document.getElementById('btn-ai-cancel-top');
  const btnCancelFooter = document.getElementById('btn-ai-cancel-footer');
  const sendLabel = document.getElementById('ai-chat-send-label');
  const sendIcon = document.getElementById('ai-chat-send-icon');
  const convPill = document.getElementById('ai-conv-id-pill');
  const body = document.getElementById('ai-chat-body');

  const st = (status || 'idle').toLowerCase();

  if (convPill) {
    if (convId) {
      convPill.innerText = `id:${convId.slice(0, 8)}...`;
      convPill.title = `Session Antigravity active : ${convId}`;
      convPill.style.display = 'inline-block';
    } else {
      convPill.style.display = 'none';
    }
  }

  if (st === 'thinking') {
    if (badge) {
      badge.className = 'ai-status-badge thinking';
      badge.innerHTML = '🧠 Réflexion...';
    }
    if (statusText) statusText.innerHTML = '🧠 Gemini réfléchit...';
    if (btnCancelTop) btnCancelTop.style.display = 'inline-flex';
    if (btnCancelFooter) btnCancelFooter.style.display = 'inline-flex';
    if (sendLabel) sendLabel.innerText = 'Réflexion...';
    if (sendIcon) sendIcon.innerText = '🧠';

    if (body && !document.getElementById('ai-thinking-live-bubble')) {
      const bubble = document.createElement('div');
      bubble.id = 'ai-thinking-live-bubble';
      bubble.className = 'ai-chat-msg ai ai-thinking-card';
      bubble.innerHTML = `
        <div class="ai-chat-msg-meta">
          <div style="display:flex; align-items:center; gap:5px;">
            <span class="ai-chat-msg-target">🤖 Antigravity Copilot</span>
            <span class="ai-chat-msg-action" style="color:#c084fc; background:rgba(192,132,252,0.2); border-color:rgba(192,132,252,0.4);">Réflexion...</span>
          </div>
          <span class="ai-chat-msg-time">En cours</span>
        </div>
        <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; padding:4px 0;">
          <div style="display:flex; align-items:center; gap:9px;">
            <div class="ai-spinner-orbit"></div>
            <div>
              <div style="color:#f5d0fe; font-weight:700; font-size:0.75rem;">Gemini réfléchit...</div>
              <div style="color:#a5b4fc; font-size:0.65rem;">Analyse du code et élaboration de la réponse</div>
            </div>
          </div>
          <button class="ai-cancel-btn-pulse" onclick="cancelAiGeneration()" title="Interrompre la génération">🛑 Annuler</button>
        </div>
      `;
      body.appendChild(bubble);
      if (state.aiChatAutoScroll) body.scrollTop = body.scrollHeight;
    }
  } else {
    const bubble = document.getElementById('ai-thinking-live-bubble');
    if (bubble) bubble.remove();

    if (btnCancelTop) btnCancelTop.style.display = 'none';
    if (btnCancelFooter) btnCancelFooter.style.display = 'none';
    if (sendLabel) sendLabel.innerText = 'Envoyer';
    if (sendIcon) sendIcon.innerText = '⚡';

    if (st === 'completed') {
      if (badge) {
        badge.className = 'ai-status-badge completed';
        badge.innerHTML = '✅ Prêt';
      }
      if (statusText) statusText.innerHTML = '✅ Réponse reçue';
    } else if (st === 'cancelled') {
      if (badge) {
        badge.className = 'ai-status-badge cancelled';
        badge.innerHTML = '⚠️ Annulé';
      }
      if (statusText) statusText.innerHTML = '⚠️ Requête annulée';
    } else if (st === 'miss') {
      if (badge) {
        badge.className = 'ai-status-badge miss';
        badge.innerHTML = '❌ Échec';
      }
      if (statusText) statusText.innerHTML = '❌ Timeout / Erreur Antigravity';
    } else {
      if (badge) {
        badge.className = 'ai-status-badge idle';
        badge.innerHTML = '🟢 Prêt';
      }
      if (statusText) statusText.innerHTML = '🟢 En écoute active';
    }
  }
}
window.updateAiStatus = updateAiStatus;

window.cancelAiGeneration = async function() {
  try {
    updateAiStatus('cancelled');
    if (window.AudioSys?.playTone) AudioSys.playTone(440, 'triangle', 0.12, 0.04);
    showToast('🛑 Requête Antigravity annulée');
    await window.AetherAPI.cancelAi();
    pollServerChatMessages();
  } catch (e) {
    console.error(e);
  }
};

let lastChatSyncCount = 0;
async function pollServerChatMessages() {
  try {
    const d = await window.AetherAPI.fetchChatMessages();
    if (d) {
      if (d.agent_status !== undefined) {
        updateAiStatus(d.agent_status, d.conversation_id);
      }
      if (d.messages && Array.isArray(d.messages)) {
        d.messages.forEach(m => {
          const mTime = m.timestamp ? (m.timestamp < 10000000000 ? m.timestamp * 1000 : m.timestamp) : Date.now();
          const exists = state.aiChatHistory.some(x => {
            if (m.id && x.id === m.id) return true;
            const xTime = x.timestamp ? (x.timestamp < 10000000000 ? x.timestamp * 1000 : x.timestamp) : 0;
            return x.details === m.text && x.sender === m.sender && Math.abs(xTime - mTime) < 3000;
          });
          if (!exists) {
            const obj = {
              id: m.id,
              sender: m.sender || 'ai',
              target: m.target_symbol || 'Copilot',
              action: m.sender === 'user' ? 'Question' : 'Réponse IA',
              details: m.text,
              timestamp: mTime
            };
            state.aiChatHistory.push(obj);
            renderAiChatMessageEl(obj, null);
          }
        });
        lastChatSyncCount = d.messages.length;
      }
    }
  } catch (e) {}
}
setInterval(pollServerChatMessages, 500);

document.getElementById('btn-ai-cancel-top')?.addEventListener('click', cancelAiGeneration);
document.getElementById('btn-ai-cancel-footer')?.addEventListener('click', cancelAiGeneration);

document.getElementById('btn-ai-new-session')?.addEventListener('click', async () => {
  try {
    await window.AetherAPI.newAiSession();
    if (window.AudioSys?.playTone) AudioSys.playTone(660, 'sine', 0.15, 0.05);
    showToast('✨ Nouvelle session Antigravity démarrée !');
    state.aiChatHistory = [];
    const body = document.getElementById('ai-chat-body');
    if (body) {
      body.innerHTML = '<div class="ai-chat-placeholder" style="text-align:center; padding:24px 12px; color:#64748b; font-size:0.75rem; font-family:var(--font-mono);">Nouvelle session démarrée. En attente de messages...</div>';
    }
    const countPill = document.getElementById('ai-chat-count-pill');
    if (countPill) countPill.innerText = '0 msg';
    lastChatSyncCount = 0;
    updateAiStatus('idle', null);
    pollServerChatMessages();
  } catch (e) {
    showToast('⚠️ Erreur création nouvelle session');
  }
});

document.getElementById('btn-ai-chat-clear')?.addEventListener('click', async () => {
  state.aiChatHistory = [];
  const body = document.getElementById('ai-chat-body');
  if (body) {
    body.innerHTML = '<div class="ai-chat-placeholder" style="text-align:center; padding:24px 12px; color:#64748b; font-size:0.75rem; font-family:var(--font-mono);">Historique effacé. En attente de nouveaux messages...</div>';
  }
  const countPill = document.getElementById('ai-chat-count-pill');
  if (countPill) countPill.innerText = '0 msg';
  lastChatSyncCount = 0;
  updateAiStatus('idle', null);
  window.AetherAPI.clearChatMessages().catch(() => {});
  showToast('🗑️ Historique chat IA réinitialisé');
});

document.getElementById('btn-ai-chat-autoscroll')?.addEventListener('click', () => {
  state.aiChatAutoScroll = !state.aiChatAutoScroll;
  const b = document.getElementById('btn-ai-chat-autoscroll');
  if (b) b.innerText = state.aiChatAutoScroll ? 'Défilement Auto: OUI' : 'Défilement Auto: NON';
});

document.getElementById('btn-ai-flyto')?.addEventListener('click', () => {
  if (state.aiTelemetry && state.aiTelemetry.target) {
    const tLower = state.aiTelemetry.target.toLowerCase();
    const node = (state.data.nodes || []).find(n => 
      n.name.toLowerCase() === tLower || 
      n.id.toLowerCase() === tLower || 
      (n.file_path && n.file_path.toLowerCase().includes(tLower))
    );
    if (node) {
      state.camera.targetX = node.x;
      state.camera.targetY = node.y;
      state.camera.targetZoom = 1.05;
      showToast(`🎯 Caméra alignée sur l'IA : ${node.name}`);
    }
  }
});

document.getElementById('btn-close-ai-hud')?.addEventListener('click', () => {
  document.getElementById('ai-telemetry-hud')?.classList.add('hidden');
});

document.getElementById('btn-ai-telemetry')?.addEventListener('click', () => {
  const hud = document.getElementById('ai-telemetry-hud');
  if (hud) hud.classList.toggle('hidden');
});

// Multi-Layer Synthesis Pills Builder
function renderLayerPills() {
  const box = document.getElementById('synth-pills');
  if (!box) return;
  box.innerHTML = '';
  const layers = state.data.stats && state.data.stats.layers ? state.data.stats.layers : {};
  const layerHex = {
    ui: '#ec4899', action: '#38bdf8', domain: '#f59e0b',
    database: '#818cf8', config: '#94a3b8', utility: '#c084fc',
    docs: '#10b981'
  };

  Object.entries(layers).forEach(([layer, count]) => {
    const pill = document.createElement('div');
    const active = state.activeLayers.has(layer);
    const col = layerHex[layer] || '#38bdf8';
    pill.className = `synth-pill ${active ? '' : 'disabled'}`;
    pill.style.borderColor = col;
    pill.style.color = col;
    pill.style.background = active ? `${col}22` : 'transparent';
    pill.innerText = `${layer.toUpperCase()} (${count})`;

    pill.addEventListener('click', () => {
      if (state.activeLayers.has(layer)) {
        state.activeLayers.delete(layer);
        AudioSys.playTone(320, 'sine', 0.08, 0.02);
      } else {
        state.activeLayers.add(layer);
        AudioSys.playTone(550, 'sine', 0.08, 0.02);
      }
      state.instanceDataDirty = true;
      if (typeof invalidateEdgePathCache === 'function') invalidateEdgePathCache();
      wakePhysics(60);
      renderLayerPills();
    });
    box.appendChild(pill);
  });
}
window.renderLayerPills = renderLayerPills;

function setAllLayerFilters(enableAll) {
  const allLayers = ['ui', 'action', 'domain', 'database', 'config', 'utility', 'docs'];
  if (enableAll) {
    allLayers.forEach(l => state.activeLayers.add(l));
  } else {
    state.activeLayers.clear();
  }
  state.instanceDataDirty = true;
  if (typeof invalidateEdgePathCache === 'function') invalidateEdgePathCache();
  wakePhysics(60);
  renderLayerPills();
  AudioSys.playTone(enableAll ? 650 : 350, 'sine', 0.1, 0.03);
  showToast(enableAll ? '👁️ Toutes les couches affichées' : '🚫 Toutes les couches masquées');
}
window.setAllLayerFilters = setAllLayerFilters;

function getUniqueModules() {
  const nodes = state.data?.nodes || [];
  const map = new Map();
  nodes.forEach(n => {
    const f = n.folder || 'root';
    map.set(f, (map.get(f) || 0) + 1);
  });
  return map;
}
window.getUniqueModules = getUniqueModules;

function renderModulePills() {
  const box = document.getElementById('synth-module-pills');
  if (!box) return;
  box.innerHTML = '';
  if (!state.hiddenModules) state.hiddenModules = new Set();

  const moduleMap = getUniqueModules();
  if (moduleMap.size === 0) {
    box.innerHTML = '<span style="font-size:0.65rem; color:#64748b; padding:4px;">Aucun module détecté</span>';
    return;
  }

  const sorted = Array.from(moduleMap.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  const badge = document.getElementById('synth-badge-modules');
  if (badge) badge.innerText = sorted.length;

  sorted.forEach(([folder, count]) => {
    const isHidden = state.hiddenModules.has(folder);
    const colRgba = typeof getFolderColor === 'function' ? getFolderColor(folder) : [0.22, 0.74, 0.97, 1];
    const colHex = `rgb(${Math.round(colRgba[0]*255)}, ${Math.round(colRgba[1]*255)}, ${Math.round(colRgba[2]*255)})`;

    const pill = document.createElement('div');
    pill.className = `synth-module-pill ${isHidden ? 'disabled' : ''}`;
    pill.style.borderColor = isHidden ? 'rgba(100, 116, 139, 0.3)' : colHex;
    pill.style.color = isHidden ? '#64748b' : '#f8fafc';
    pill.style.background = isHidden ? 'rgba(15, 23, 42, 0.45)' : `rgba(${Math.round(colRgba[0]*255)}, ${Math.round(colRgba[1]*255)}, ${Math.round(colRgba[2]*255)}, 0.14)`;

    const shortName = typeof formatFolderLabel === 'function' ? formatFolderLabel(folder) : folder;

    pill.innerHTML = `
      <span class="module-eye-icon">${isHidden ? '🚫' : '👁️'}</span>
      <span class="module-color-dot" style="background:${colHex};"></span>
      <span class="module-name" title="${escapeHtml(folder)}">${escapeHtml(shortName)}</span>
      <span class="module-count">${count}</span>
      <button class="module-doc-btn" title="Consulter la documentation du module ${escapeHtml(shortName)}">📖</button>
    `;

    // Click pill -> Toggle visibility (NEVER open doc)
    pill.addEventListener('click', (e) => {
      if (e.target.closest('.module-doc-btn')) return;

      if (state.hiddenModules.has(folder)) {
        state.hiddenModules.delete(folder);
        AudioSys.playTone(550, 'sine', 0.08, 0.02);
      } else {
        state.hiddenModules.add(folder);
        AudioSys.playTone(320, 'sine', 0.08, 0.02);
      }
      state.instanceDataDirty = true;
      if (typeof invalidateEdgePathCache === 'function') invalidateEdgePathCache();
      wakePhysics(60);
      renderModulePills();
    });

    // Click doc button -> Explicitly open documentation only
    const docBtn = pill.querySelector('.module-doc-btn');
    if (docBtn) {
      docBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (typeof openFolderDocReader === 'function') {
          const mdList = (state.folderMdMap && state.folderMdMap.get(folder)) || [];
          if (mdList.length > 0) {
            openFolderDocReader(folder, mdList, 0, true);
          } else {
            const folderNodes = (state.data.nodes || []).filter(n => (n.folder || 'root') === folder);
            openEmptyFolderDoc(folder, folderNodes, true);
          }
        }
      });
    }

    box.appendChild(pill);
  });
}
window.renderModulePills = renderModulePills;

function setAllModuleFilters(enableAll) {
  if (!state.hiddenModules) state.hiddenModules = new Set();
  const moduleMap = getUniqueModules();
  if (enableAll) {
    state.hiddenModules.clear();
  } else {
    moduleMap.forEach((_, f) => state.hiddenModules.add(f));
  }
  state.instanceDataDirty = true;
  if (typeof invalidateEdgePathCache === 'function') invalidateEdgePathCache();
  wakePhysics(60);
  renderModulePills();
  AudioSys.playTone(enableAll ? 650 : 350, 'sine', 0.1, 0.03);
  showToast(enableAll ? '👁️ Tous les modules affichés' : '🚫 Tous les modules masqués');
}
window.setAllModuleFilters = setAllModuleFilters;

function toggleSynthAccordion(catId) {
  const item = document.getElementById(`synth-acc-${catId}`);
  if (!item) return;
  const isCollapsed = item.classList.toggle('collapsed');
  try {
    localStorage.setItem(`aether_synth_acc_${catId}`, isCollapsed ? 'collapsed' : 'open');
  } catch (e) {}
  AudioSys.playTone(isCollapsed ? 340 : 480, 'sine', 0.08, 0.02);
}
window.toggleSynthAccordion = toggleSynthAccordion;

function initSynthAccordions() {
  ['modules', 'layers', 'pipeline', 'links', 'cve'].forEach(catId => {
    try {
      const saved = localStorage.getItem(`aether_synth_acc_${catId}`);
      if (saved === 'collapsed') {
        document.getElementById(`synth-acc-${catId}`)?.classList.add('collapsed');
      }
    } catch (e) {}
  });
}
window.initSynthAccordions = initSynthAccordions;
setTimeout(initSynthAccordions, 100);

// Server API & HUD Controls
async function loadProjects() {
  try {
    const d = await window.AetherAPI.fetchProjects();
    const sel = document.getElementById('project-select');
    if (sel && d.projects) {
      sel.innerHTML = '<option value="">-- Choisir un projet (' + d.projects.length + ') --</option>';
      d.projects.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.path;
        opt.innerText = p.name;
        sel.appendChild(opt);
      });
      const projToLoad = d.default_project || (d.projects && d.projects[0] && d.projects[0].path);
      if (projToLoad) {
        sel.value = projToLoad;
        const inp = document.getElementById('project-path-input');
        if (inp) inp.value = projToLoad;
        if (!state.data || !state.data.nodes || state.data.nodes.length === 0) {
          analyze(projToLoad);
        }
      }
    }
  } catch (e) {
    console.warn('Erreur chargement projets', e);
  }
}
window.loadProjects = loadProjects;

let loadingTimer = null;
function showLoadingScreen(title, stepText, folderPath) {
  const hud = document.getElementById('hydro-loading-hud');
  const titleEl = document.getElementById('hydro-project-title');
  const stepEl = document.getElementById('hydro-step-text');
  if (titleEl && title) titleEl.innerText = title;
  if (stepEl && (folderPath || stepText)) {
    stepEl.innerText = folderPath ? `Émergence de ${folderPath}...` : stepText;
  }
  if (hud) hud.classList.remove('hidden');

  const steps = [
    'Émergence aquatique des clusters de code...',
    'Scan AST multithread & linter SAST...',
    'Vérification des sceaux BLAKE3 et contrats EARS...',
    'Simulation des forces quantiques d\'affiliation...',
    'Projection spatiale WebGL 2 (120 FPS instancié)...'
  ];
  let stepIdx = 0;
  if (loadingTimer) clearInterval(loadingTimer);
  loadingTimer = setInterval(() => {
    stepIdx = (stepIdx + 1) % steps.length;
    if (stepEl) stepEl.innerText = steps[stepIdx];
  }, 700);
}

function hideLoadingScreen() {
  if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
  const hud = document.getElementById('hydro-loading-hud');
  if (hud) {
    setTimeout(() => {
      hud.classList.add('hidden');
    }, 750);
  }
}

async function analyze(path) {
  if (!path) path = state.data?.project_path || '.';
  const projectName = path.split(/[\\/]/).filter(Boolean).pop() || path;
  showLoadingScreen(projectName, 'Démarrage du scan AST...', path);
  showToast('⚡ Analyse Rust V2 ultra-rapide...');
  try {
    const data = await window.AetherAPI.analyze(path);
    if (typeof syncProjectStatus === 'function') syncProjectStatus();
    applyData(data);
    hideLoadingScreen();
    showToast(`✨ ${data.nodes.length} nœuds, ${data.edges.length} liens analysés en ${data.stats.elapsed_ms}ms !`);
  } catch (e) {
    hideLoadingScreen();
    showToast('❌ Erreur analyse serveur');
  }
}
window.analyze = analyze;

function applyData(data) {
  state.data = data;
  state.project_path = data.project_path || '';
  state.nodeMap = null;
  state.cachedFolderStats = null;
  state.cachedEdgePaths = null;
  state.waterRipples = [];
  if (typeof precomputeDocMetadata === 'function') precomputeDocMetadata(data);
  if (typeof wakePhysics === 'function') wakePhysics(180);

  const now = performance.now();
  const folderMap = new Map();
  (data.nodes || []).forEach(n => {
    const f = n.folder || 'root';
    if (!folderMap.has(f)) folderMap.set(f, []);
    folderMap.get(f).push(n);
  });

  // Staged Rhythmic Emergence Sequence ("1 x 2 x 3..." wave sequence)
  const sortedFolders = Array.from(folderMap.keys()).sort((a, b) => {
    if (a === 'root' || a === 'src' || a === 'core' || a === 'contracts') return -1;
    if (b === 'root' || b === 'src' || b === 'core' || b === 'contracts') return 1;
    const countA = folderMap.get(a).length;
    const countB = folderMap.get(b).length;
    return countB - countA;
  });

  // Batch folders into at most 8 waves so large projects emerge in ~1.0s instead of 15s+
  const MAX_WAVES = 8;
  const foldersPerWave = Math.max(1, Math.ceil(sortedFolders.length / MAX_WAVES));
  const WAVES = [];
  for (let i = 0; i < sortedFolders.length; i += foldersPerWave) {
    WAVES.push(sortedFolders.slice(i, i + foldersPerWave));
  }
  const totalWaves = Math.max(1, WAVES.length);
  const waveIntervalMs = Math.min(180, Math.max(70, Math.floor(900 / totalWaves)));

  state.bubbleBirthMap = new Map();
  const baseTime = now + 30;
  let maxSpawnTime = baseTime;
  let globalFolderIdx = 0;

  WAVES.forEach((waveFolders, wIdx) => {
    const folderBirth = baseTime + (wIdx * waveIntervalMs);
    waveFolders.forEach(folder => {
      const fNodes = folderMap.get(folder) || [];
      state.bubbleBirthMap.set(folder, {
        birthTime: folderBirth,
        poppedSound: false,
        phase: (globalFolderIdx * 1.7),
        folderIndex: globalFolderIdx,
        totalFolders: sortedFolders.length,
        name: folder,
        count: fNodes.length,
        wave: wIdx + 1
      });
      globalFolderIdx++;

      const files = fNodes.filter(n => n.is_file);
      const classes = fNodes.filter(n => !n.is_file && n.is_class);
      const others = fNodes.filter(n => !n.is_file && !n.is_class);

      files.forEach(n => {
        n.birth_time = folderBirth;
      });

      classes.forEach((n, ci) => {
        n.birth_time = folderBirth + Math.min(ci * 5, 50);
        if (n.birth_time > maxSpawnTime) maxSpawnTime = n.birth_time;
      });

      others.forEach((n, oi) => {
        n.birth_time = folderBirth + 12 + Math.min(oi * 3, 80);
        if (n.birth_time > maxSpawnTime) maxSpawnTime = n.birth_time;
      });
    });
  });

  const isLargeProject = (data.nodes || []).length > 450;
  state.spawnAnimationEndTime = maxSpawnTime + (isLargeProject ? 260 : 380);
  state.physicsCooldown = isLargeProject ? 110 : Math.min(200, Math.max(140, totalWaves * 18 + 60));
  state.physicsSleeping = false;
  state.instanceDataDirty = true;

  if (window.AudioSys && typeof AudioSys.waterRipple === 'function') {
    AudioSys.waterRipple(0.35);
  }

  // Realtime Animated HUD Banner
  const hud = document.getElementById('hydro-loading-hud');
  const hudTitle = document.getElementById('hydro-project-title');
  const hudStep = document.getElementById('hydro-step-text');

  if (hud) {
    hud.classList.remove('hidden');
    if (hudTitle) hudTitle.innerText = `✨ Émergence Céleste : Vague 1 / ${totalWaves}`;
    if (hudStep) hudStep.innerText = `Déploiement rapide des amas stellaires (${data.nodes.length} symboles)...`;

    WAVES.forEach((waveFolders, wIdx) => {
      setTimeout(() => {
        const folder = waveFolders[0];
        const fNodes = folderMap.get(folder) || [];
        const label = typeof formatFolderLabel === 'function' ? formatFolderLabel(folder) : folder;
        const extra = waveFolders.length > 1 ? ` +${waveFolders.length - 1}` : '';
        if (hudTitle) hudTitle.innerText = `✨ Émergence Céleste : Vague ${wIdx + 1} / ${totalWaves}`;
        if (hudStep) hudStep.innerText = `Naissance de [${label}${extra}] (${fNodes.length} symboles)...`;
        if (window.AudioSys && typeof AudioSys.waterBubblePop === 'function') {
          AudioSys.waterBubblePop(wIdx + 1);
        }
      }, 30 + wIdx * waveIntervalMs);
    });

    setTimeout(() => {
      if (hudTitle) hudTitle.innerText = `✨ Émergence Complète !`;
      if (hudStep) hudStep.innerText = `${data.nodes.length} symboles vivants • ${data.edges.length} flux quantiques`;
      setTimeout(() => {
        hud.classList.add('hidden');
      }, 500);
    }, 30 + totalWaves * waveIntervalMs + 220);
  }

  state.data = data;
  state.project_path = data.project_path || '';
  const inpPath = document.getElementById('project-path-input');
  if (inpPath && data.project_path) inpPath.value = data.project_path;
  const topPill = document.getElementById('topbar-project-pill');
  if (topPill) topPill.innerText = data.project_name || 'Projet';
  const synthStats = document.getElementById('synth-stats');
  if (synthStats) synthStats.innerText = `${data.nodes.length} symboles • ${data.edges.length} flux`;
  const burgerBadge = document.getElementById('burger-count-badge');
  if (burgerBadge) burgerBadge.innerText = `${data.edges.length} flux`;
  renderLayerPills();
  if (typeof renderModulePills === 'function') renderModulePills();
  if (typeof renderAffiliationPills === 'function') renderAffiliationPills();
  if (typeof renderEdgeTypologyLegend === 'function') renderEdgeTypologyLegend();
  if (typeof renderCveAnomaliesPanel === 'function') renderCveAnomaliesPanel();
  if (typeof fitView === 'function') fitView();

  try {
    const projKey = (data.project_path || data.project_name || 'default').toLowerCase();
    const seenProjects = JSON.parse(localStorage.getItem('aetherscope_seen_projects') || '{}');
    if (!seenProjects[projKey]) {
      seenProjects[projKey] = Date.now();
      localStorage.setItem('aetherscope_seen_projects', JSON.stringify(seenProjects));
    }
  } catch (e) {
    console.warn('LocalStorage non disponible pour le suivi des projets', e);
  }
}
window.applyData = applyData;

function applyDataKeepView(data, focusSymbol) {
  state.data = data;
  state.project_path = data.project_path || '';
  state.nodeMap = null;
  state.cachedFolderStats = null;
  if (typeof precomputeDocMetadata === 'function') precomputeDocMetadata(data);
  if (typeof wakePhysics === 'function') wakePhysics(110);

  const now = performance.now();
  const folderMap = new Map();
  (data.nodes || []).forEach(n => {
    const f = n.folder || 'root';
    if (!folderMap.has(f)) folderMap.set(f, []);
    folderMap.get(f).push(n);
    if (!n.birth_time) n.birth_time = now;
  });

  const oldBirthMap = state.bubbleBirthMap || new Map();
  state.bubbleBirthMap = new Map();
  let newFolderIdx = 0;

  folderMap.forEach((fNodes, folder) => {
    let birthInfo = oldBirthMap.get(folder);
    if (!birthInfo) {
      birthInfo = {
        birthTime: now,
        poppedSound: true,
        phase: newFolderIdx * 1.37,
        folderIndex: newFolderIdx,
        totalFolders: folderMap.size,
        name: folder,
        count: fNodes.length
      };
      newFolderIdx++;
    } else {
      birthInfo.count = fNodes.length;
    }
    state.bubbleBirthMap.set(folder, birthInfo);
  });

  state.data = data;
  state.project_path = data.project_path || '';
  const inpPath = document.getElementById('project-path-input');
  if (inpPath && data.project_path) inpPath.value = data.project_path;
  const topPill = document.getElementById('topbar-project-pill');
  if (topPill) topPill.innerText = data.project_name || 'Projet';
  const synthStats2 = document.getElementById('synth-stats');
  if (synthStats2) synthStats2.innerText = `${data.nodes.length} symboles • ${data.edges.length} flux`;
  const burgerBadge2 = document.getElementById('burger-count-badge');
  if (burgerBadge2) burgerBadge2.innerText = `${data.edges.length} flux`;
  renderLayerPills();
  if (typeof renderModulePills === 'function') renderModulePills();
  if (typeof renderAffiliationPills === 'function') renderAffiliationPills();
  if (typeof renderEdgeTypologyLegend === 'function') renderEdgeTypologyLegend();

  if (focusSymbol) {
    const sLower = focusSymbol.toLowerCase();
    const node = (data.nodes || []).find(n =>
      n.name.toLowerCase() === sLower ||
      n.id.toLowerCase() === sLower ||
      (n.file_path && n.file_path.toLowerCase().includes(sLower))
    );
    if (node) {
      state.camera.targetX = node.x;
      state.camera.targetY = node.y;
      state.camera.targetZoom = 1.15;
      state.selectedNode = node;
      state.aiSupernova = {
        x: node.x,
        y: node.y,
        name: node.name,
        startTime: performance.now(),
        duration: 3800
      };
      if (typeof addToAiTrail === 'function') addToAiTrail(node, 'Création Fichier');
      if (window.AudioSys?.supernovaBirth) AudioSys.supernovaBirth();
      if (typeof selectNode === 'function') selectNode(node);
      return;
    }
  }
}
window.applyDataKeepView = applyDataKeepView;

// Native Windows Dialog Handlers for Workspace & Single Project
document.getElementById('btn-pick-workspace')?.addEventListener('click', async () => {
  showToast('📁 Boîte de dialogue : choisissez le dossier racine de tous vos projets...');
  try {
    const d = await window.AetherAPI.pickWorkspace();
    if (d.status === 'ok' && d.projects) {
      const sel = document.getElementById('project-select');
      if (sel) {
        sel.innerHTML = '<option value="">-- Projets détectés (' + d.projects.length + ') --</option>';
        d.projects.forEach(p => {
          const opt = document.createElement('option');
          opt.value = p.path;
          opt.innerText = p.name;
          sel.appendChild(opt);
        });
      }
      showToast(`✅ Espace de travail : ${d.projects.length} projet(s) découvert(s)`);
      if (d.projects.length > 0) {
        const first = d.projects[0];
        const inp = document.getElementById('project-path-input');
        if (inp) inp.value = first.path;
        analyze(first.path);
      }
    } else if (d.status === 'cancelled') {
      showToast('Sélection annulée');
    }
  } catch (err) {
    showToast('❌ Erreur dialogue workspace');
  }
});

document.getElementById('btn-pick-project')?.addEventListener('click', async () => {
  showToast('🎯 Boîte de dialogue : sélectionnez un projet unique...');
  try {
    const d = await window.AetherAPI.pickProject();
    if (d.status === 'ok' && d.project_path) {
      const inp = document.getElementById('project-path-input');
      if (inp) inp.value = d.project_path;
      if (d.graph) {
        applyData(d.graph);
        showToast(`✅ Projet chargé : ${d.project_path}`);
        if (typeof syncProjectStatus === 'function') syncProjectStatus();
      } else {
        analyze(d.project_path);
      }
    } else if (d.status === 'cancelled') {
      showToast('Sélection annulée');
    }
  } catch (err) {
    showToast('❌ Erreur dialogue projet');
  }
});

// --- Generic AI System Prompt Modal Handlers ---
let cachedSystemPrompt = '';

function generateFallbackSystemPrompt() {
  const projName = state.data?.project_name || window.__AETHERSCOPE_DATA__?.project_name || 'aether-engine';
  const projPath = state.data?.project_path || window.__AETHERSCOPE_DATA__?.project_path || 'C:\\Users\\1234\\Desktop\\Projets\\aether-engine';
  return `# 🪐 AETHERSCOPE V2 — DIRECTIVES SYSTÈME COPILOTE IA (ARCHITECTURE & PAIR-PROGRAMMING)

> **Projet :** \`${projName}\`  
> **Racine :** \`${projPath}\`  
> **Stack Détectée :** 🦀 Pure Rust (Cargo Workspace Hexagonal)  
> **Architecture Active :** Cargo Workspace : \`crates/domain\` (100% pur), \`crates/server-axum\`, \`crates/client-ui\`, \`crates/db-adapter\`  
> **Serveur Local AetherScope :** \`http://127.0.0.1:3030\`  

Tu opères en binôme direct avec le développeur et le moteur d'intelligence architecturale **AetherScope V2**.
Le graphe 3D WebGL 2 tourne en continu sur le port \`3030\` et audite chaque modification du codebase.

---

## 🚀 1. WORKFLOW MCP ULTRA-COMPACT EN 3 APPELS (COMMANDES COMBINÉES)
Les commandes MCP d'AetherScope sont **combinées** pour réduire de 70% les allers-retours d'outils :

1. **Diagnostic Initial (1 seul appel au lancement de session) :**
   - **Commande MCP :** \`aetherscope_get_graph_summary({"rescan": false, "include_tasks": true, "severity": "HIGH"})\`
   - *Effet combiné :* Retourne en 1 appel la santé globale du graphe, la liste des tâches actives et les violations CWE filtrées.
   - Annonce immédiatement en 2 lignes :
     \`🪐 [AETHER_STATUS : Nœuds=<N>, Flux=<F>, Sécurité=<OK | X violations>, Tâches=<T actives>, Serveur=Connecté]\`

2. **Inspection Chirurgicale + Caméra 3D + Trace MVC (1 seul appel avant de coder) :**
   - **Commande MCP :** \`aetherscope_get_active_target({"symbol_id": "<symbole_ou_fichier>", "action": "Analyse", "details": "Inspection des contrats EARS", "trace_direction": "both", "max_depth": 4})\`
   - *Effet combiné :* Téléporte la caméra 3D WebGL + extrait le Handshake XML, les contrats EARS et les tâches liées + trace la chaîne d'appels amont/aval.

3. **Validation Pare-Feu < 50ms + Clôture de Tâche + Debrief Chat (1 seul appel après modification) :**
   - **Commande MCP :** \`aetherscope_verify_patch({"files_modified": ["chemin/relatif/fichier.rs"], "task_id": "<id_optionnel>", "status": "done", "progress": 100, "progress_note": "Patch validé", "chat_message": "Correctif appliqué et vérifié sans régression."})\`
   - *Effet combiné :* Rescanne l'AST en < 50ms, vérifie l'absence de nouvelles violations CWE/EARS/BLAKE3, téléporte la caméra 3D, met à jour/clôture la tâche et publie le debrief dans le chat AetherScope.

---

## 🛠️ 2. RÉFÉRENTIEL DES 8 COMMANDES MCP COMBINÉES (AETHERSCOPE MCP ENGINE)
Spécifie toujours les paramètres exacts lors de tes appels MCP :

1. **\`aetherscope_get_graph_summary({path?, rescan?, include_tasks?, severity?})\`** *(4-en-1)* :
   - Vue globale du graphe + rescan AST optionnel (\`rescan: true\`) + liste des tâches (\`include_tasks: true\`) + violations CWE (\`severity: "CRITICAL" | "HIGH" | "MEDIUM"\`).
2. **\`aetherscope_get_active_target({symbol_id, action?, details?, trace_direction?, max_depth?, path?})\`** *(3-en-1)* :
   - Téléportation caméra 3D (\`action\`, \`details\`) + extraction du contexte chirurgical EARS/Handshake + traçage de flux MVC (\`trace_direction: "upstream" | "downstream" | "both"\`).
3. **\`aetherscope_search_symbols({query?, layer?, kind?, stereotype?, has_violation?, cwe_id?, severity?, file_pattern?, limit?})\`** *(2-en-1)* :
   - Recherche multi-critères de symboles AST (\`layer: "domain" | "application" | "infrastructure" | "ui"\`, \`stereotype: "«Form»" | "«Controller»" | "«Service»" | "«Repository»"\`) + recherche détaillée des failles CWE (\`cwe_id: "CWE-89"\`, \`severity: "CRITICAL"\`).
4. **\`aetherscope_manage_tasks({action, task_id?, title?, kind?, target_symbol?, target_file?, priority?, status?, progress?, progress_note?, initial_readme?, full_readme?, status_filter?})\`** *(3-en-1)* :
   - \`action: "list"\` (filtre \`status_filter\`), \`action: "create"\` (\`title\`, \`kind: "function" | "research" | "security_fix" | "arch_refactor"\`, \`target_symbol\`), ou \`action: "update"\` (\`task_id\`, \`status\`, \`progress\`, \`progress_note\`) + téléportation auto de la caméra 3D sur \`target_symbol\`.
5. **\`aetherscope_verify_patch({files_modified, task_id?, status?, progress?, progress_note?, chat_message?})\`** *(4-en-1)* :
   - Pare-feu temps réel (< 50ms) sur les fichiers modifiés + téléportation caméra 3D + mise à jour/clôture automatique de la tâche + envoi du résumé dans le chat Copilot.
6. **\`aetherscope_chat({action?, text?, thought?, target_symbol?})\`** *(2-en-1)* :
   - \`action: "send"\` (publie un message/debrief dans le cockpit et téléporte la caméra sur \`target_symbol\`) ou \`action: "history"\` (lit l'historique des échanges).
7. **\`aetherscope_manage_plugins({action, target_path?, plugins_dir?, id?, name?, severity?, cwe?, regex_pattern?, message?, remediation?})\`** *(4-en-1)* :
   - \`action: "list" | "test" | "scan" | "upsert"\` pour gérer, tester et exécuter les règles SAST YAML personnalisées (\`.aether/plugins/*.yaml\`).
8. **\`aetherscope_teleport_camera({target, action, details})\`** :
   - Déplacement direct de la caméra 3D WebGL et illumination de la balise quantique sans extraction de contexte.

*(Note : Les anciens noms d'outils unitaires restent supportés en alias rétrocompatibles, mais privilégie toujours les 8 commandes combinées ci-dessus).*

---

## 🔒 3. ZERO-SHELL PROTOCOLE DE GOUVERNANCE
1. **Avant d'écrire ou modifier du code :**
   - Appelle \`aetherscope_get_active_target\` (ou lis \`.aether/ACTIVE_TARGET.md\`).
   - Lis le \`README.md\` du dossier cible pour connaître les règles EARS et les invariants.
   - Ne modifie JAMAIS un \`README.md\` pour contourner une règle : le hash cryptographique BLAKE3 est scellé dans \`aether.lock.toml\`.
2. **Après chaque modification de fichier :**
   - Appelle systématiquement \`aetherscope_verify_patch({"files_modified": [...], "chat_message": "..."})\`.
   - Si le statut est \`REJECTED\`, corrige immédiatement la ligne signalée avant de continuer.

---

## 🏛️ 4. INVARIANTS PAR COUCHE & SÉPARATION STRICTE
- \`contracts/\` : Traits Rust (\`RepositoryPort\`), DTOs partagés Serde et schémas RPC stricts
- \`client/\` : Rendu graphique, formulaires («Form»), état réactif. Ne doit JAMAIS importer \`server/domain\` ni \`data-nodes\`.
- \`server/domain/\` : **100% pur, déterministe, zéro I/O**. Interdiction formelle de requêtes SQL brutes, d'accès réseau ou de variables d'environnement (\`process.env\` / \`std::env::var\`).
- \`server/application/\` : Orchestrations des cas d'usage reliant le domaine aux interfaces de persistance.
- \`server/api/\` : Contrôleurs d'entrée (REST / WebSocket) validant tout payload via \`contracts/\`.
- \`data-nodes/\` : Adaptateurs de persistance (PostgreSQL / SQLite / Redis) isolables en microservices.

---

## ⚡ 5. CONSIGNES DE RÉPONSE OPTIMISÉE
- **Concision & Densité :** Réponse technique, chirurgicale et directe. Zéro bavardage inutile.
- **Diffs Chirurgicaux :** Ne réécris jamais un fichier complet si seules quelques lignes changent. Fournis uniquement les extraits ciblés.
- **Règle d'Atomicité (< 35 lignes) :** Découpe le code en fonctions atomiques pures de moins de 35 lignes maximum (particulièrement dans \`domain/\`).
- **Preuve de Lecture [AETHER_ACK] :** Démarre tes propositions techniques par :
  \`[AETHER_ACK: cible=<symbole>, couche=<layer>, imports_interdits=<liste>]\`;
`;
}

async function openSystemPromptModal(isFirstOpen = false) {
  const modal = document.getElementById('ai-sysprompt-modal');
  const textarea = document.getElementById('ai-sysprompt-textarea');
  const pill = document.getElementById('ai-first-open-pill');
  if (!modal || !textarea) return;
  try {
    const d = await window.AetherAPI.fetchSystemPrompt();
    if (d && d.system_prompt) {
      cachedSystemPrompt = d.system_prompt;
    }
  } catch (e) {
    // offline handled below
  }

  if (!cachedSystemPrompt || cachedSystemPrompt.startsWith('//')) {
    cachedSystemPrompt = state.data?.system_prompt || window.__AETHERSCOPE_DATA__?.system_prompt || generateFallbackSystemPrompt();
  }

  let promptText = cachedSystemPrompt;
  const projPath = state.data?.project_path || window.__AETHERSCOPE_DATA__?.project_path || '';
  if (projPath) {
    promptText = promptText.replaceAll('C:\\\\Chemin\\\\Vers\\\\Le\\\\Projet', projPath)
                           .replaceAll('C:\\Chemin\\Vers\\Le\\Projet', projPath);
  }
  textarea.value = promptText;

  if (pill) {
    pill.style.display = isFirstOpen ? 'block' : 'none';
  }
  modal.classList.add('open');
}
window.openSystemPromptModal = openSystemPromptModal;


document.getElementById('btn-ai-prompt-system')?.addEventListener('click', () => openSystemPromptModal(false));
document.getElementById('btn-close-ai-sysprompt-modal')?.addEventListener('click', () => {
  document.getElementById('ai-sysprompt-modal')?.classList.remove('open');
});
document.getElementById('btn-dismiss-ai-sysprompt-modal')?.addEventListener('click', () => {
  document.getElementById('ai-sysprompt-modal')?.classList.remove('open');
});
document.getElementById('btn-copy-ai-sysprompt')?.addEventListener('click', () => {
  const txt = document.getElementById('ai-sysprompt-textarea')?.value || '';
  navigator.clipboard.writeText(txt).then(() => {
    showToast('📋 Prompt Système Universel copié dans le presse-papier !');
  });
});
document.getElementById('btn-download-ai-sysprompt')?.addEventListener('click', () => {
  const txt = document.getElementById('ai-sysprompt-textarea')?.value || '';
  const blob = new Blob([txt], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'aetherscope_system_prompt.md';
  a.click();
  showToast('💾 aetherscope_system_prompt.md téléchargé !');
});

// --- AI Instant File Creation & Supernova Birth Handlers ---
function openCreateFileModal() {
  const modal = document.getElementById('ai-create-file-modal');
  if (!modal) return;
  const projInput = document.getElementById('create-file-project-path');
  if (projInput) {
    const cur = document.getElementById('project-path-input')?.value.trim() || state.data.project_path || '';
    projInput.value = cur;
  }
  modal.classList.add('open');
}
window.openCreateFileModal = openCreateFileModal;

document.getElementById('btn-ai-newfile')?.addEventListener('click', openCreateFileModal);
document.getElementById('btn-close-create-file-modal')?.addEventListener('click', () => {
  document.getElementById('ai-create-file-modal')?.classList.remove('open');
});
document.getElementById('btn-dismiss-create-file-modal')?.addEventListener('click', () => {
  document.getElementById('ai-create-file-modal')?.classList.remove('open');
});

// Preset suggestion pills
document.getElementById('pill-suggest-ui')?.addEventListener('click', () => {
  const relInput = document.getElementById('create-file-rel-path');
  const codeInput = document.getElementById('create-file-code-content');
  if (relInput) relInput.value = 'src/ui/components/RoomHeroCard.jsx';
  if (codeInput) codeInput.value = `import React from 'react';\n\nexport function RoomHeroCard({ title, price, status }) {\n  return (\n    <div className="room-card">\n      <h3>{title}</h3>\n      <span className="price">{price} ETH</span>\n      <span className="badge">{status}</span>\n    </div>\n  );\n}\n`;
});

document.getElementById('pill-suggest-domain')?.addEventListener('click', () => {
  const relInput = document.getElementById('create-file-rel-path');
  const codeInput = document.getElementById('create-file-code-content');
  if (relInput) relInput.value = 'src/domain/models/RoomBooking.js';
  if (codeInput) codeInput.value = `export class RoomBooking {\n  constructor(bookingId, guestAddress, nights) {\n    this.bookingId = bookingId;\n    this.guestAddress = guestAddress;\n    this.nights = nights;\n  }\n\n  calculateTotal(ratePerNight) {\n    return this.nights * ratePerNight;\n  }\n}\n`;
});

document.getElementById('pill-suggest-service')?.addEventListener('click', () => {
  const relInput = document.getElementById('create-file-rel-path');
  const codeInput = document.getElementById('create-file-code-content');
  if (relInput) relInput.value = 'src/application/services/BookingEngine.js';
  if (codeInput) codeInput.value = `import { RoomBooking } from '../../domain/models/RoomBooking.js';\n\nexport class BookingEngine {\n  static processBooking(order) {\n    const booking = new RoomBooking(order.id, order.guest, order.nights);\n    return booking.calculateTotal(0.15);\n  }\n}\n`;
});

document.getElementById('pill-suggest-doc')?.addEventListener('click', () => {
  const relInput = document.getElementById('create-file-rel-path');
  const codeInput = document.getElementById('create-file-code-content');
  if (relInput) relInput.value = 'src/domain/README.md';
  if (codeInput) codeInput.value = `# Couche Domaine & Entités Métier\n\nCe dossier contient les entités pures, objets-valeurs et calculs fondamentaux.\n\n## Responsabilités\n- Calculs financiers et réservations hôtelières\n- Validation des règles immuables\n`;
});

// Submit File Creation
document.getElementById('btn-submit-create-file')?.addEventListener('click', async () => {
  const project_path = document.getElementById('create-file-project-path')?.value.trim();
  const file_path = document.getElementById('create-file-rel-path')?.value.trim();
  const content = document.getElementById('create-file-code-content')?.value;

  if (!project_path || !file_path) {
    showToast('⚠️ Veuillez renseigner le projet et le chemin du fichier !');
    return;
  }
  if (!content || !content.trim()) {
    showToast('⚠️ Le contenu du fichier ne peut pas être vide !');
    return;
  }

  showToast('🚀 Écriture & Naissance stellaire en cours...');
  try {
    const d = await window.AetherAPI.createFile(project_path, file_path, content);
    if (d.status === 'ok' && (d.data || d.graph)) {
      document.getElementById('ai-create-file-modal')?.classList.remove('open');
      applyDataKeepView(d.data || d.graph, d.created_symbol);
      showToast(`✨ Supernova ! Planète créée : ${d.created_symbol}`);
    } else {
      showToast(`❌ Erreur: ${d.message || 'Échec création'}`);
    }
  } catch (err) {
    showToast('❌ Erreur de communication serveur');
  }
});

document.getElementById('btn-analyze')?.addEventListener('click', () => {
  let p = document.getElementById('project-path-input')?.value.trim();
  if (!p) p = state.data?.project_path || '.';
  analyze(p);
});

document.getElementById('project-select')?.addEventListener('change', (e) => {
  if (e.target.value) {
    const inp = document.getElementById('project-path-input');
    if (inp) inp.value = e.target.value;
    analyze(e.target.value);
  }
});

document.getElementById('btn-export')?.addEventListener('click', async () => {
  const p = document.getElementById('project-path-input')?.value.trim() || state.data.project_path;
  if (!p) {
    showToast('Veuillez spécifier un projet.');
    return;
  }
  showToast('💾 Export du viewer autonome...');
  try {
    const d = await window.AetherAPI.exportHtml(p);
    if (d.status === 'ok') {
      showToast(`✅ Exporté dans ${d.viewer_path}`);
    }
  } catch (e) {
    showToast('❌ Erreur export');
  }
});

// --- Connect MCP Configuration Modal & CLI Bridge Handlers ---
const currentMcpPort = window.location.port || '3030';
// Chemin par défaut générique : remplacé par le chemin réel renvoyé par /api/settings (mcp_binary_path).
let mcpBinaryPath = "C:\\Chemin\\Vers\\AetherScope\\aetherscope-mcp.exe";

function buildMcpConfigs() {
  const json = JSON.stringify({
    mcpServers: {
      aetherscope: {
        command: mcpBinaryPath,
        args: ["--port", currentMcpPort]
      }
    }
  }, null, 2);
  return {
    antigravity: { label: "FICHIER : ~/.gemini/config/mcp_config.json (ou Antigravity MCP Settings)", json },
    claude: { label: "FICHIER : %APPDATA%\\Claude\\claude_desktop_config.json", json },
    cursor: { label: "FICHIER : .cursor/mcp.json ou Paramètres Cursor > Features > MCP", json }
  };
}

let mcpConfigs = buildMcpConfigs();

fetch('/api/settings')
  .then(res => (res.ok ? res.json() : null))
  .then(data => {
    if (data && data.mcp_binary_path) {
      mcpBinaryPath = data.mcp_binary_path;
      mcpConfigs = buildMcpConfigs();
      if (document.getElementById('ai-mcp-modal')?.classList.contains('open')) {
        updateMcpModalView(curMcpTab);
      }
    }
  })
  .catch(() => { /* chemin générique conservé */ });

let curMcpTab = 'antigravity';
function updateMcpModalView(tab) {
  curMcpTab = tab;
  const cfg = mcpConfigs[tab] || mcpConfigs.antigravity;
  const label = document.getElementById('mcp-config-label');
  const textarea = document.getElementById('mcp-config-textarea');
  if (label) label.innerText = cfg.label;
  if (textarea) textarea.value = cfg.json;

  document.querySelectorAll('#ai-mcp-modal .task-btn').forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById(`tab-mcp-${tab}`);
  if (activeBtn) activeBtn.classList.add('active');
}

function openMcpModal() {
  const modal = document.getElementById('ai-mcp-modal');
  if (modal) {
    updateMcpModalView(curMcpTab);
    modal.classList.add('open');
  }
}
window.openMcpModal = openMcpModal;

function closeMcpModal() {
  document.getElementById('ai-mcp-modal')?.classList.remove('open');
}
window.closeMcpModal = closeMcpModal;

document.getElementById('btn-menu-mcp')?.addEventListener('click', openMcpModal);
document.getElementById('btn-ai-mcp-config')?.addEventListener('click', openMcpModal);
document.getElementById('btn-close-ai-mcp-modal')?.addEventListener('click', closeMcpModal);
document.getElementById('btn-dismiss-ai-mcp-modal')?.addEventListener('click', closeMcpModal);
document.getElementById('ai-mcp-modal')?.addEventListener('click', (e) => {
  if (e.target.id === 'ai-mcp-modal') closeMcpModal();
});

document.getElementById('tab-mcp-antigravity')?.addEventListener('click', () => updateMcpModalView('antigravity'));
document.getElementById('tab-mcp-claude')?.addEventListener('click', () => updateMcpModalView('claude'));
document.getElementById('tab-mcp-cursor')?.addEventListener('click', () => updateMcpModalView('cursor'));

document.getElementById('btn-copy-mcp-config')?.addEventListener('click', () => {
  const txt = document.getElementById('mcp-config-textarea')?.value || '';
  navigator.clipboard.writeText(txt).then(() => {
    if (window.AudioSys?.promptCopied) AudioSys.promptCopied();
    showToast('📋 Configuration MCP copiée dans le presse-papier !');
  });
});

document.getElementById('btn-ai-launch-cli')?.addEventListener('click', async () => {
  showToast('💻 Lancement du terminal Gemini CLI AetherScope...');
  try {
    const curPath = state.data?.project_path || document.getElementById('project-path-input')?.value.trim() || '';
    const d = await window.AetherAPI.launchCli('gemini', curPath, '');
    if (d.status === 'ok') {
      if (window.AudioSys?.playTone) AudioSys.playTone(580, 'triangle', 0.15, 0.04);
      showToast(`⚡ ${d.message}`);
    } else {
      showToast(`⚠️ ${d.message || 'Erreur au lancement du terminal'}`);
    }
  } catch (err) {
    showToast('❌ Échec de la connexion avec le serveur');
  }
});

// ========================================================
// PROJECT HUB & MULTI-ARCHITECTURE ORCHESTRATOR LOGIC
// ========================================================
let selectedArchStack = 'rust';

function openHubModal() {
  const modal = document.getElementById('project-hub-modal');
  if (!modal) return;
  const curDir = document.getElementById('project-path-input')?.value.trim();
  const hubDirInput = document.getElementById('hub-project-dir');
  if (hubDirInput && !hubDirInput.value) {
    if (curDir) {
      const parts = curDir.split(/[\\/]/);
      parts.pop();
      hubDirInput.value = parts.join('\\') || curDir;
    } else {
      hubDirInput.value = 'C:\\Users\\1234\\Desktop\\Projets';
    }
  }
  modal.classList.add('open');
}
window.openHubModal = openHubModal;

function closeHubModal() {
  document.getElementById('project-hub-modal')?.classList.remove('open');
}
window.closeHubModal = closeHubModal;

document.getElementById('btn-close-hub-modal')?.addEventListener('click', closeHubModal);
document.getElementById('btn-open-hub')?.addEventListener('click', openHubModal);

document.querySelectorAll('#arch-selector-grid .arch-card').forEach(card => {
  card.addEventListener('click', () => {
    document.querySelectorAll('#arch-selector-grid .arch-card').forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
    selectedArchStack = card.getAttribute('data-stack') || 'rust';
    if (window.AudioSys?.nodeSelect) AudioSys.nodeSelect();
  });
});

document.getElementById('btn-hub-browse-dir')?.addEventListener('click', async () => {
  try {
    const d = await window.AetherAPI.pickWorkspace();
    if (d.status === 'ok' && d.workspace) {
      const inp = document.getElementById('hub-project-dir');
      if (inp) inp.value = d.workspace;
    }
  } catch (e) {
    showToast('❌ Erreur sélection dossier');
  }
});

document.getElementById('btn-hub-action-workspace')?.addEventListener('click', () => {
  closeHubModal();
  document.getElementById('btn-pick-workspace')?.click();
});

document.getElementById('btn-hub-action-project')?.addEventListener('click', () => {
  closeHubModal();
  document.getElementById('btn-pick-project')?.click();
});

document.getElementById('btn-hub-create-scaffold')?.addEventListener('click', async () => {
  const baseDir = document.getElementById('hub-project-dir')?.value.trim();
  const projName = document.getElementById('hub-project-name')?.value.trim();

  if (!baseDir || !projName) {
    showToast('⚠️ Veuillez renseigner le dossier parent et le nom du projet !');
    return;
  }

  const fullPath = baseDir.replace(/[\\/]+$/, '') + '\\' + projName;
  showToast(`🔨 Forgeage de l'architecture [${selectedArchStack.toUpperCase()}] dans ${projName}...`);
  try {
    const d = await window.AetherAPI.initProject(fullPath, selectedArchStack);
    if (d.status === 'ok') {
      showToast(`✨ ${d.message} !`);
      closeHubModal();
      const pInput = document.getElementById('project-path-input');
      if (pInput) pInput.value = fullPath;
      setTimeout(() => {
        analyze(fullPath);
      }, 400);
    } else {
      showToast(`❌ Erreur: ${d.message || 'Échec initialisation'}`);
    }
  } catch (err) {
    showToast('❌ Erreur de communication serveur');
  }
});

setTimeout(() => {
  const hasSeenHub = localStorage.getItem('aetherscope_hub_seen_v2');
  if (!hasSeenHub) {
    localStorage.setItem('aetherscope_hub_seen_v2', 'true');
    openHubModal();
  }
}, 600);

// ========================================================
// GAME SERVERS CREATION & ORCHESTRATION CONTROLLER
// ========================================================
let selectedGameServerStack = 'roblox';

function openGameServersModal() {
  const modal = document.getElementById('game-servers-modal');
  if (!modal) return;
  const curDir = document.getElementById('project-path-input')?.value.trim();
  const gameDirInput = document.getElementById('game-project-dir');
  if (gameDirInput && !gameDirInput.value) {
    if (curDir) {
      const parts = curDir.split(/[\\/]/);
      parts.pop();
      gameDirInput.value = parts.join('\\') || curDir;
    } else {
      gameDirInput.value = 'C:\\Users\\1234\\Desktop\\Projets';
    }
  }
  updateGameServerSelection(selectedGameServerStack);
  modal.classList.add('open');
}
window.openGameServersModal = openGameServersModal;

function closeGameServersModal() {
  document.getElementById('game-servers-modal')?.classList.remove('open');
}
window.closeGameServersModal = closeGameServersModal;

function selectGameServerType(type) {
  selectedGameServerStack = type;
  updateGameServerSelection(type);
  if (window.AudioSys?.nodeSelect) AudioSys.nodeSelect();
}
window.selectGameServerType = selectGameServerType;

function updateGameServerSelection(type) {
  const cardMc = document.getElementById('card-server-mc');
  const cardRoblox = document.getElementById('card-server-roblox');
  const btnSelectMc = document.getElementById('btn-select-mc');
  const btnSelectRoblox = document.getElementById('btn-select-roblox');
  const nameInput = document.getElementById('game-project-name');
  const specsBox = document.getElementById('game-server-specs-box');
  const preview = document.getElementById('game-structure-preview');

  if (type === 'roblox') {
    cardRoblox?.classList.add('selected');
    cardMc?.classList.remove('selected');
    if (btnSelectRoblox) {
      btnSelectRoblox.classList.add('primary');
      btnSelectRoblox.innerHTML = '<span>✓ Stack Sélectionnée</span>';
    }
    if (btnSelectMc) {
      btnSelectMc.classList.remove('primary');
      btnSelectMc.innerHTML = '<span>Choisir cette stack</span>';
    }
    if (nameInput && (!nameInput.value || nameInput.value === 'AetherMinecraftServer')) {
      nameInput.value = 'AetherRobloxServer';
    }
    if (specsBox) {
      specsBox.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
          <div style="font-weight:800; font-size:0.86rem; color:#f87171; display:flex; align-items:center; gap:8px;">
            <span>🟥</span> Architecture Serveur Roblox Optimisée Aether Code (Strict Luau + Rojo 7)
          </div>
          <span class="game-tag" style="color:#f87171; border-color:rgba(239,68,68,0.4); font-weight:700;">Zero-Trust Authoritative</span>
        </div>
        <div style="font-size:0.75rem; color:#cbd5e1; line-height:1.5;">
          • <strong>contracts/ :</strong> <code>NetworkContracts.luau</code> (RemoteEvents validés, anti-exploit, rate-limiting) + <code>Types.luau</code>.<br>
          • <strong>server/ :</strong> Boucle authoritative <code>ServerController.luau</code> & logique métier pure <code>domain/CombatService.luau</code> (zéro I/O).<br>
          • <strong>client/ :</strong> Contrôleurs locaux <code>ClientController.luau</code> avec prédiction et interpolation fluide sans autorité.<br>
          • <strong>data-nodes/ :</strong> Persistance <code>DataStoreServiceAdapter.luau</code> avec session-locking anti-dupe (Pattern ProfileService).<br>
          • <strong>Outillage & Linting :</strong> <code>default.project.json</code> (Rojo 7), <code>wally.toml</code>, <code>selene.toml</code>, <code>AETHER_AI_RULES.md</code> et manifeste <code>aether.lock.toml</code> scellé BLAKE3.
        </div>
      `;
    }
    if (preview) {
      preview.innerHTML = `Structure créée : <code>contracts/</code>, <code>server/</code>, <code>client/</code>, <code>data-nodes/</code>, <code>default.project.json</code>, <code>aether.lock.toml</code>.`;
    }
  } else {
    cardMc?.classList.add('selected');
    cardRoblox?.classList.remove('selected');
    if (btnSelectMc) {
      btnSelectMc.classList.add('primary');
      btnSelectMc.innerHTML = '<span>✓ Stack Sélectionnée</span>';
    }
    if (btnSelectRoblox) {
      btnSelectRoblox.classList.remove('primary');
      btnSelectRoblox.innerHTML = '<span>Choisir cette stack</span>';
    }
    if (nameInput && (!nameInput.value || nameInput.value === 'AetherRobloxServer')) {
      nameInput.value = 'AetherMinecraftServer';
    }
    if (specsBox) {
      specsBox.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
          <div style="font-weight:800; font-size:0.86rem; color:#38bdf8; display:flex; align-items:center; gap:8px;">
            <span>⛏️</span> Architecture Serveur Minecraft (Paper/Purpur + Control-Plane Flask)
          </div>
          <span class="game-tag" style="color:#38bdf8; border-color:rgba(14,165,233,0.4); font-weight:700;">Tokio + JVM Aikar</span>
        </div>
        <div style="font-size:0.75rem; color:#cbd5e1; line-height:1.5;">
          • <strong>contracts/ :</strong> Spécification universelle <code>AETHER_MC_MANIFEST_SPEC.md</code> & Invariants EARS.<br>
          • <strong>server/ :</strong> Fichiers <code>server.properties</code>, <code>paper-global.yml</code> et scripts de démarrage <code>start.bat</code> / <code>start.sh</code> avec drapeaux Aikar flags.<br>
          • <strong>plugins/ :</strong> Répertoire plugins et hooks (Chunky, LuckPerms, Vault).<br>
          • <strong>data-nodes/ :</strong> Sauvegardes de mondes, chunks et persistance joueurs SQLite / MySQL.<br>
          • <strong>Cockpit Web :</strong> Accessible en local sur <a href="http://127.0.0.1:5000" target="_blank" style="color:#38bdf8; text-decoration:underline; font-weight:700;">http://127.0.0.1:5000</a> (dashboard admin <code>/admin</code>, boutique & joueurs).
        </div>
      `;
    }
    if (preview) {
      preview.innerHTML = `Structure créée : <code>contracts/</code>, <code>server/</code>, <code>plugins/</code>, <code>data-nodes/</code>, <code>start.bat</code>, <code>aether.lock.toml</code>.`;
    }
  }
}

async function browseGameServerDir() {
  try {
    const d = await window.AetherAPI.pickWorkspace();
    if (d.status === 'ok' && d.workspace) {
      const inp = document.getElementById('game-project-dir');
      if (inp) inp.value = d.workspace;
    }
  } catch (e) {
    showToast('❌ Erreur sélection dossier');
  }
}
window.browseGameServerDir = browseGameServerDir;

async function createGameServerProject() {
  const baseDir = document.getElementById('game-project-dir')?.value.trim();
  const projName = document.getElementById('game-project-name')?.value.trim();

  if (!baseDir || !projName) {
    showToast('⚠️ Veuillez renseigner le dossier parent et le nom du serveur !');
    return;
  }

  const fullPath = baseDir.replace(/[\\/]+$/, '') + '\\' + projName;
  const stackName = selectedGameServerStack === 'roblox' ? 'roblox' : 'minecraft';
  showToast(`🎮 Forgeage du serveur de jeu [${stackName.toUpperCase()}] dans ${projName}...`);
  try {
    const d = await window.AetherAPI.initProject(fullPath, stackName);
    if (d.status === 'ok') {
      showToast(`✨ ${d.message || 'Serveur forgé avec succès'} !`);
      closeGameServersModal();
      const pInput = document.getElementById('project-path-input');
      if (pInput) pInput.value = fullPath;
      setTimeout(() => {
        analyze(fullPath);
      }, 400);
    } else {
      showToast(`❌ Erreur: ${d.message || 'Échec initialisation'}`);
    }
  } catch (err) {
    showToast('❌ Erreur de communication serveur');
  }
}
window.createGameServerProject = createGameServerProject;

// ========================================================
// COCKPIT SETTINGS & PREFERENCES CONTROLLER
// ========================================================
function openSettingsModal() {
  const modal = document.getElementById('settings-modal');
  if (!modal) return;
  const lenInput = document.getElementById('setting-label-len');
  const lenVal = document.getElementById('setting-label-len-val');
  const previewText = document.getElementById('setting-preview-result') || document.getElementById('setting-preview-text');
  const lazyInput = document.getElementById('setting-lazy-readmes');
  const fpsInput = document.getElementById('setting-fps-limit');
  const soundInput = document.getElementById('setting-sound-enabled') || document.getElementById('setting-sound-effects');

  const maxLen = state.settings?.maxLabelLength || 18;
  if (lenInput) lenInput.value = maxLen;
  if (lenVal) lenVal.innerText = `${maxLen} car.`;
  if (previewText) previewText.innerText = typeof truncateNodeName === 'function' ? truncateNodeName('BookingEngineServiceWorkerImpl', maxLen) : 'BookingEngine…';
  const bubbleToggle = document.getElementById('setting-hide-bubble-labels');
  const bubbleThresholdInput = document.getElementById('setting-bubble-threshold');
  if (bubbleToggle) bubbleToggle.checked = state.settings?.hideBubbleLabelsOver20 !== false;
  if (bubbleThresholdInput) bubbleThresholdInput.value = state.settings?.clusterLabelThreshold || 20;
  if (lazyInput) lazyInput.checked = state.settings?.lazyReadmes !== false;
  if (fpsInput) fpsInput.value = state.settings?.fpsLimit || '120';
  if (soundInput) soundInput.checked = state.settings?.sound !== false;

  const exclusionsInput = document.getElementById('setting-exclusions');
  if (exclusionsInput) {
    const currentExcl = state.settings?.exclusions || ['tests', '*.spec.*', '*.test.*'];
    exclusionsInput.value = Array.isArray(currentExcl) ? currentExcl.join('\n') : String(currentExcl || '');
  }

  const autocamToggle = document.getElementById('setting-ai-autocam');
  if (autocamToggle) autocamToggle.checked = state.aiAutoCam !== false;

  const trailToggle = document.getElementById('setting-ai-trail');
  if (trailToggle) trailToggle.checked = state.settings?.aiTrailEnabled !== false;

  const portInput = document.getElementById('setting-ai-port');
  if (portInput) portInput.value = state.settings?.mcpPort || window.location.port || 3030;

  const aiPromptInput = document.getElementById('setting-ai-custom-prompt');
  if (aiPromptInput) aiPromptInput.value = state.settings?.copilotPrompt || '';

  // 8. Load & Render CVE Rules
  renderCveRulesSettings();

  modal.classList.add('open');
}
window.openSettingsModal = openSettingsModal;

// CVE Rules in Settings State & Functions
let currentCveCatalogue = [];

async function renderCveRulesSettings() {
  const container = document.getElementById('settings-cve-rules-container');
  if (!container) return;

  try {
    if (!currentCveCatalogue || currentCveCatalogue.length === 0) {
      const res = await fetch('/api/settings');
      if (res.ok) {
        const data = await res.json();
        if (data.cve_catalogue) {
          currentCveCatalogue = data.cve_catalogue;
          window.currentCveCatalogue = data.cve_catalogue;
        }
        if (data.active_cve_rules && !state.settings?.activeCveRules) {
          if (!state.settings) state.settings = {};
          state.settings.activeCveRules = data.active_cve_rules;
        }
        if (data.ignored_cwes && (!state.settings?.ignoredCwes || state.settings.ignoredCwes.length === 0)) {
          if (!state.settings) state.settings = {};
          state.settings.ignoredCwes = data.ignored_cwes;
        }
      }
    }
  } catch (e) {
    console.warn('Failed to fetch CVE rules from server:', e);
  }

  if (!currentCveCatalogue || currentCveCatalogue.length === 0) {
    container.innerHTML = '<div style="font-size:0.75rem; color:#64748b; padding:10px;">Catalogue 90+ Zero-Day Patterns & CWE Rules indisponible.</div>';
    return;
  }

  const activeRules = new Set(state.settings?.activeCveRules || currentCveCatalogue.map(r => r.rule_id));
  const searchInput = document.getElementById('setting-cve-search');
  const query = (searchInput?.value || '').toLowerCase().trim();

  const filtered = currentCveCatalogue.filter(r => {
    if (!query) return true;
    return r.rule_id.toLowerCase().includes(query) ||
           r.name.toLowerCase().includes(query) ||
           r.category.toLowerCase().includes(query) ||
           r.description.toLowerCase().includes(query) ||
           (r.cve_id && r.cve_id.toLowerCase().includes(query));
  });

  const counter = document.getElementById('cve-rules-counter');
  if (counter) {
    counter.innerText = `${activeRules.size}/${currentCveCatalogue.length} actives`;
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div style="font-size:0.75rem; color:#64748b; padding:10px; text-align:center;">Aucune règle ne correspond à ce filtre.</div>';
    return;
  }

  let html = '';
  const getFileTypesBadge = (r) => {
    const rid = (r.rule_id || '').toUpperCase();
    const cat = (r.category || '').toLowerCase();
    if (rid.includes('-PHP-') || cat.includes('php')) return '<span class="cve-rule-cat" style="color:#c084fc; border-color:rgba(192,132,252,0.3); background:rgba(192,132,252,0.1);">📁 .php, .phtml</span>';
    if (rid.includes('-ZIG-') || cat.includes('zig')) return '<span class="cve-rule-cat" style="color:#f59e0b; border-color:rgba(245,158,11,0.3); background:rgba(245,158,11,0.1);">📁 .zig</span>';
    if (rid.includes('-CS-') || cat.includes('c#')) return '<span class="cve-rule-cat" style="color:#60a5fa; border-color:rgba(96,165,250,0.3); background:rgba(96,165,250,0.1);">📁 .cs</span>';
    if (rid.includes('-RUST-') || cat.includes('rust')) return '<span class="cve-rule-cat" style="color:#f97316; border-color:rgba(249,115,22,0.3); background:rgba(249,115,22,0.1);">📁 .rs</span>';
    if (rid.includes('-PY-') || cat.includes('python')) return '<span class="cve-rule-cat" style="color:#eab308; border-color:rgba(234,179,8,0.3); background:rgba(234,179,8,0.1);">📁 .py</span>';
    if (rid.includes('-CPP-') || cat.includes('c / c++')) return '<span class="cve-rule-cat" style="color:#38bdf8; border-color:rgba(56,189,248,0.3); background:rgba(56,189,248,0.1);">📁 .cpp, .c, .h</span>';
    if (rid.includes('-JS-') || cat.includes('node') || cat.includes('front-end')) return '<span class="cve-rule-cat" style="color:#4ade80; border-color:rgba(74,222,128,0.3); background:rgba(74,222,128,0.1);">📁 .ts, .js</span>';
    if (rid.includes('SOL') || cat.includes('defi') || cat.includes('crypto')) return '<span class="cve-rule-cat" style="color:#818cf8; border-color:rgba(129,140,248,0.3); background:rgba(129,140,248,0.1);">📁 .sol</span>';
    return '<span class="cve-rule-cat">📁 Tout fichier</span>';
  };

  filtered.forEach(rule => {
    const isChecked = activeRules.has(rule.rule_id);
    const sevClass = rule.severity.toLowerCase() === 'critical' ? 'critical' : (rule.severity.toLowerCase() === 'high' ? 'high' : 'warning');
    const sevBadge = rule.severity.toUpperCase();

    html += `
      <div class="cve-rule-row ${isChecked ? '' : 'disabled'}" data-rule-id="${rule.rule_id}">
        <label class="aether-toggle" style="margin-top:2px;">
          <input type="checkbox" class="cve-rule-checkbox" data-rule-id="${rule.rule_id}" ${isChecked ? 'checked' : ''} onchange="onCveRuleToggle('${rule.rule_id}', this.checked)" />
          <span class="toggle-slider"></span>
        </label>
        <div class="cve-rule-info">
          <div class="cve-rule-header">
            <span class="cve-rule-id">${rule.rule_id}</span>
            <span class="cve-badge ${sevClass}" style="font-size:0.60rem; padding:1px 5px;">${sevBadge}</span>
            <span class="cve-rule-cat">${rule.category}</span>
            ${getFileTypesBadge(rule)}
            ${rule.cve_id ? `<span style="font-size:0.62rem; font-family:var(--font-mono); color:#a855f7;">${rule.cve_id}</span>` : ''}
          </div>
          <div style="font-size:0.74rem; font-weight:700; color:#e2e8f0; margin-top:1px;">${rule.name}</div>
          <div class="cve-rule-desc">${rule.description}</div>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}
window.renderCveRulesSettings = renderCveRulesSettings;

window.filterCveRulesList = function(val) {
  renderCveRulesSettings();
};

window.onCveRuleToggle = function(ruleId, isChecked) {
  if (!state.settings) state.settings = {};
  let active = new Set(state.settings.activeCveRules || currentCveCatalogue.map(r => r.rule_id));
  if (isChecked) {
    active.add(ruleId);
    if (Array.isArray(state.settings.ignoredCwes)) {
      state.settings.ignoredCwes = state.settings.ignoredCwes.filter(id => id !== ruleId && !ruleId.includes(id));
    }
  } else {
    active.delete(ruleId);
  }
  state.settings.activeCveRules = Array.from(active);
  const row = document.querySelector(`.cve-rule-row[data-rule-id="${ruleId}"]`);
  if (row) {
    if (isChecked) row.classList.remove('disabled');
    else row.classList.add('disabled');
  }
  const counter = document.getElementById('cve-rules-counter');
  if (counter) {
    counter.innerText = `${active.size}/${currentCveCatalogue.length} actives`;
  }
};

window.toggleAllCveRules = function(enableAll) {
  if (!state.settings) state.settings = {};
  if (enableAll) {
    state.settings.activeCveRules = currentCveCatalogue.map(r => r.rule_id);
    state.settings.ignoredCwes = [];
  } else {
    state.settings.activeCveRules = [];
  }
  renderCveRulesSettings();
};

window.addExclusionPill = function(pill) {
  const input = document.getElementById('setting-exclusions');
  if (!input) return;
  const current = input.value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!current.includes(pill)) {
    current.push(pill);
    input.value = current.join('\n');
    if (window.AudioSys?.nodeSelect) AudioSys.nodeSelect();
  }
};

function closeSettingsModal() {
  document.getElementById('settings-modal')?.classList.remove('open');
}
window.closeSettingsModal = closeSettingsModal;

function toggleSettingsModal() {
  const modal = document.getElementById('settings-modal');
  if (modal && modal.classList.contains('open')) {
    closeSettingsModal();
  } else {
    openSettingsModal();
  }
}
window.toggleSettingsModal = toggleSettingsModal;

function syncSettingsToMenuShortcuts() {
  const lenBadge = document.getElementById('menu-current-label-len');
  if (lenBadge) lenBadge.innerText = `${state.settings?.maxLabelLength || 18} car.`;
  const bubbleBadge = document.getElementById('menu-current-bubble');
  if (bubbleBadge) {
    bubbleBadge.innerText = state.settings?.hideBubbleLabelsOver20 !== false ? `> ${state.settings?.clusterLabelThreshold || 20}` : 'Inactif';
  }
  const lazyBadge = document.getElementById('menu-current-lazy');
  if (lazyBadge) lazyBadge.innerText = state.settings?.lazyReadmes !== false ? 'Actif' : 'Inactif';
}

// Settings Slider Live Preview
document.getElementById('setting-label-len')?.addEventListener('input', (e) => {
  const val = parseInt(e.target.value, 10);
  if (!state.settings) state.settings = {};
  state.settings.maxLabelLength = val;
  const lenVal = document.getElementById('setting-label-len-val');
  if (lenVal) lenVal.innerText = `${val} car.`;
  const previewText = document.getElementById('setting-preview-result') || document.getElementById('setting-preview-text');
  if (previewText) previewText.innerText = typeof truncateNodeName === 'function' ? truncateNodeName('BookingEngineServiceWorkerImpl', val) : 'BookingEngine…';
  syncSettingsToMenuShortcuts();
});

document.getElementById('setting-hide-bubble-labels')?.addEventListener('change', (e) => {
  if (!state.settings) state.settings = {};
  state.settings.hideBubbleLabelsOver20 = e.target.checked;
  syncSettingsToMenuShortcuts();
});

document.getElementById('setting-bubble-threshold')?.addEventListener('input', (e) => {
  const val = parseInt(e.target.value, 10) || 20;
  if (!state.settings) state.settings = {};
  state.settings.clusterLabelThreshold = val;
  syncSettingsToMenuShortcuts();
});

document.getElementById('setting-lazy-readmes')?.addEventListener('change', (e) => {
  if (!state.settings) state.settings = {};
  state.settings.lazyReadmes = e.target.checked;
  syncSettingsToMenuShortcuts();
});

document.getElementById('setting-fps-limit')?.addEventListener('change', (e) => {
  if (!state.settings) state.settings = {};
  state.settings.fpsLimit = e.target.value;
});

const soundCheckbox = document.getElementById('setting-sound-enabled') || document.getElementById('setting-sound-effects');
soundCheckbox?.addEventListener('change', (e) => {
  if (!state.settings) state.settings = {};
  state.settings.sound = e.target.checked;
  if (window.AudioSys) {
    window.AudioSys.enabled = e.target.checked;
  }
});

// Save Settings Button
document.getElementById('btn-save-settings')?.addEventListener('click', async () => {
  try {
    if (!state.settings) state.settings = {};

    // 1. Label Length
    const lenInput = document.getElementById('setting-label-len');
    if (lenInput) state.settings.maxLabelLength = parseInt(lenInput.value, 10) || 18;

    // 2. Hide bubble labels
    const bubbleToggle = document.getElementById('setting-hide-bubble-labels');
    if (bubbleToggle) state.settings.hideBubbleLabelsOver20 = bubbleToggle.checked;

    // 2b. Threshold
    const bubbleThresh = document.getElementById('setting-bubble-threshold');
    if (bubbleThresh) state.settings.clusterLabelThreshold = parseInt(bubbleThresh.value, 10) || 20;

    // 3. Lazy Readmes
    const lazyInput = document.getElementById('setting-lazy-readmes');
    if (lazyInput) state.settings.lazyReadmes = lazyInput.checked;

    // 4. FPS Limit
    const fpsInput = document.getElementById('setting-fps-limit');
    if (fpsInput) state.settings.fpsLimit = fpsInput.value;

    // 5. Sound
    const soundInput = document.getElementById('setting-sound-enabled') || document.getElementById('setting-sound-effects');
    if (soundInput) {
      state.settings.sound = soundInput.checked;
      if (window.AudioSys) window.AudioSys.enabled = soundInput.checked;
    }

    // 6. Exclusions
    const exclusionsInput = document.getElementById('setting-exclusions');
    let lines = [];
    if (exclusionsInput) {
      lines = exclusionsInput.value.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
      state.settings.exclusions = lines;
    }

    // 7. Copilot Preferences
    const autocamToggle = document.getElementById('setting-ai-autocam');
    if (autocamToggle) {
      state.aiAutoCam = autocamToggle.checked;
      state.settings.aiAutoCam = autocamToggle.checked;
      const btnAutocam = document.getElementById('btn-ai-autocam');
      if (btnAutocam) {
        btnAutocam.innerText = state.aiAutoCam ? '🎥 Auto-Cam: ON' : '🎥 Auto-Cam: OFF';
      }
    }

    const trailToggle = document.getElementById('setting-ai-trail');
    if (trailToggle) state.settings.aiTrailEnabled = trailToggle.checked;

    const portInput = document.getElementById('setting-ai-port');
    if (portInput) state.settings.mcpPort = parseInt(portInput.value, 10) || 3030;

    const aiPromptInput = document.getElementById('setting-ai-custom-prompt');
    if (aiPromptInput) state.settings.copilotPrompt = aiPromptInput.value.trim();

    // 8. CVE Active Rules & Ignored CWEs
    const activeCve = state.settings.activeCveRules || (currentCveCatalogue ? currentCveCatalogue.map(r => r.rule_id) : []);
    const ignoredCwes = state.settings.ignoredCwes || [];

    // Persist to LocalStorage
    localStorage.setItem('aetherscope_settings', JSON.stringify(state.settings));

    // Send exclusions, active CVE rules & ignored CWEs to Server API
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          exclusions: lines,
          active_cve_rules: activeCve,
          ignored_cwes: ignoredCwes
        })
      });
    } catch (_) {}

    syncSettingsToMenuShortcuts();
    if (typeof renderCveAnomaliesPanel === 'function') renderCveAnomaliesPanel();
    showToast('⚙️ Préférences du Copilote & Cockpit sauvegardées !');
    if (window.AudioSys?.nodeSelect) AudioSys.nodeSelect();
  } catch (err) {
    console.error('Save settings error:', err);
    showToast('❌ Erreur sauvegarde paramètres');
  }
  closeSettingsModal();
});

// Reset Settings Button (Support both IDs)
const resetSettingsHandler = () => {
  state.settings = {
    maxLabelLength: 18,
    lazyReadmes: true,
    fpsLimit: '120',
    sound: true,
    hideBubbleLabelsOver20: true,
    clusterLabelThreshold: 20,
    exclusions: ['tests', '*.spec.*', '*.test.*'],
    aiAutoCam: true,
    aiTrailEnabled: true,
    mcpPort: 3030,
    copilotPrompt: ''
  };
  state.aiAutoCam = true;
  if (window.AudioSys) {
    window.AudioSys.enabled = true;
  }
  try {
    localStorage.setItem('aetherscope_settings', JSON.stringify(state.settings));
  } catch (_) {}
  openSettingsModal();
  syncSettingsToMenuShortcuts();
  showToast('🔄 Paramètres réinitialisés aux valeurs optimales');
};
document.getElementById('btn-reset-default-settings')?.addEventListener('click', resetSettingsHandler);
document.getElementById('btn-reset-settings')?.addEventListener('click', resetSettingsHandler);

document.getElementById('btn-close-settings-modal')?.addEventListener('click', closeSettingsModal);
document.getElementById('btn-cancel-settings')?.addEventListener('click', closeSettingsModal);
document.getElementById('settings-modal')?.addEventListener('click', (e) => {
  if (e.target.id === 'settings-modal') closeSettingsModal();
});
document.getElementById('btn-settings-open-mcp')?.addEventListener('click', () => {
  closeSettingsModal();
  openMcpModal();
});
document.getElementById('btn-settings-open-sysprompt')?.addEventListener('click', () => {
  closeSettingsModal();
  openSystemPromptModal(false);
});
document.getElementById('btn-menu-ai-settings')?.addEventListener('click', openSettingsModal);
document.getElementById('btn-quick-settings')?.addEventListener('click', openSettingsModal);
document.getElementById('btn-menu-open-settings')?.addEventListener('click', openSettingsModal);
document.getElementById('btn-menu-open-settings-len')?.addEventListener('click', openSettingsModal);
document.getElementById('btn-menu-open-settings-bubble')?.addEventListener('click', openSettingsModal);
document.getElementById('btn-menu-open-settings-lazy')?.addEventListener('click', openSettingsModal);
document.getElementById('btn-menu-reset-view')?.addEventListener('click', () => { if (typeof fitView === 'function') fitView(); });
document.getElementById('btn-menu-clear-cache')?.addEventListener('click', () => {
  if (state.docCache) state.docCache.clear();
  state.settings = {
    maxLabelLength: 18,
    lazyReadmes: true,
    fpsLimit: '120',
    sound: true,
    hideBubbleLabelsOver20: true,
    clusterLabelThreshold: 20
  };
  if (window.AudioSys) {
    window.AudioSys.enabled = true;
  }
  try { localStorage.removeItem('aetherscope_settings'); } catch (_) {}
  syncSettingsToMenuShortcuts();
  showToast('🗑️ Cache de documentation & préférences réinitialisés');
});

// Keyboard Shortcuts Router
window.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
  if (e.key === 'x' || e.key === 'X') { if (typeof toggleXrayMode === 'function') toggleXrayMode(); }
  else if (e.key === 'd' || e.key === 'D') { if (typeof toggleDeadCodeMode === 'function') toggleDeadCodeMode(); }
  else if (e.key === 'h' || e.key === 'H') { if (typeof toggleHeatmapMode === 'function') toggleHeatmapMode(); }
  else if (e.key === 'v' || e.key === 'V') { if (typeof toggleSecurityVisionMode === 'function') toggleSecurityVisionMode(); }
  else if (e.key === 'p' || e.key === 'P') toggleSettingsModal();
  else if (e.key === 'n' || e.key === 'N') { if (typeof openSurfaceScannerModal === 'function') openSurfaceScannerModal(); }
  else if (e.key === 's' || e.key === 'S') { if (typeof takeSnapshot === 'function') takeSnapshot(); }
  else if (e.key === 'a' || e.key === 'A') document.getElementById('btn-ai-telemetry')?.click();
  else if (e.key === 'c' || e.key === 'C') toggleAiChatPopup();
  else if (e.key === '1') { if (typeof switchDepth === 'function') switchDepth(1); }
  else if (e.key === '2') { if (typeof switchDepth === 'function') switchDepth(2); }
  else if (e.key === '3') { if (typeof switchDepth === 'function') switchDepth(3); }
  else if (e.key === '4') { if (typeof switchDepth === 'function') switchDepth(4); }
  else if (e.key === 'f' || e.key === 'F') { if (typeof fitView === 'function') fitView(); }
  else if (e.key === 'g' || e.key === 'G') document.getElementById('btn-gravity')?.click();
  else if (e.key === 'b' || e.key === 'B') { if (typeof toggleSynthesisMenu === 'function') toggleSynthesisMenu(); }
  else if (e.key === 'm' || e.key === 'M') { if (typeof toggleDocReader === 'function') toggleDocReader(); }
  else if (e.key === 'i' || e.key === 'I') { if (typeof toggleInspector === 'function') toggleInspector(); }
  else if (e.key === 'Escape') {
    if (state.securityVisionMode) {
      if (typeof toggleSecurityVisionMode === 'function') toggleSecurityVisionMode();
      return;
    }
    if (document.getElementById('topbar-search-dropdown')?.classList.contains('open')) {
      closeTopbarSearchDropdown();
      document.getElementById('topbar-search-input')?.blur();
      return;
    }
    if (document.getElementById('settings-modal')?.classList.contains('open')) {
      closeSettingsModal();
      return;
    }
    if (document.getElementById('project-hub-modal')?.classList.contains('open')) {
      closeHubModal();
      return;
    }
    if (state.xrayMode && typeof toggleXrayMode === 'function') {
      toggleXrayMode();
      return;
    }
    if (state.deadCodeMode && typeof toggleDeadCodeMode === 'function') {
      toggleDeadCodeMode();
      return;
    }
    if (state.heatmapMode && typeof toggleHeatmapMode === 'function') {
      toggleHeatmapMode();
      return;
    }
    state.selectedNode = null;
    state.beaconNode = null;
    if (typeof toggleInspector === 'function') toggleInspector(false);
    else document.getElementById('inspector')?.classList.add('hidden');
    if (typeof toggleDocReader === 'function') toggleDocReader(false);
    else document.getElementById('doc-reader-panel')?.classList.add('hidden');
    if (typeof closeSynthesisMenu === 'function') closeSynthesisMenu();
    document.getElementById('search-modal')?.classList.remove('open');
    closeTopbarSearchDropdown();
    document.getElementById('ai-modal')?.classList.remove('open');
    document.getElementById('ai-tasks-modal')?.classList.remove('open');
    document.getElementById('master-prompt-modal')?.classList.remove('open');
    document.getElementById('bounty-scope-modal')?.classList.remove('open');
    document.getElementById('ai-sysprompt-modal')?.classList.remove('open');
    document.getElementById('ai-create-file-modal')?.classList.remove('open');
    document.getElementById('ai-mcp-modal')?.classList.remove('open');
    document.getElementById('surface-scanner-modal')?.classList.remove('open');
    document.getElementById('ai-telemetry-hud')?.classList.add('hidden');
  } else if (e.key === 'k' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    focusTopbarSearch();
  } else if (e.key === '/') {
    e.preventDefault();
    focusTopbarSearch();
  } else if ((e.key === 't' || e.key === 'T') && !['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName)) {
    e.preventDefault();
    openTasksModal();
  }
});

// =========================================================================
// TASKS & QUESTS CONTROLLER (Model & User Hybrid Task Engine)
// =========================================================================
let currentTasksCache = [];
let currentTaskFilter = 'active';
let activeSelectedTaskId = null;

async function openTasksModal(prefillSymbol = null, prefillFile = null) {
  const modal = document.getElementById('ai-tasks-modal');
  if (!modal) return;
  modal.classList.add('open');

  if (prefillSymbol || prefillFile) {
    const formPanel = document.getElementById('new-task-form-panel');
    if (formPanel) formPanel.style.display = 'flex';
    const symInput = document.getElementById('task-input-symbol');
    const fileInput = document.getElementById('task-input-file');
    const titleInput = document.getElementById('task-input-title');
    if (symInput && prefillSymbol) symInput.value = prefillSymbol;
    if (fileInput && prefillFile) fileInput.value = prefillFile;
    if (titleInput) {
      titleInput.value = prefillSymbol ? `Travailler sur ${prefillSymbol}` : '';
      titleInput.focus();
    }
  }

  await refreshTasksList();
}
window.openTasksModal = openTasksModal;

function closeTasksModal() {
  document.getElementById('ai-tasks-modal')?.classList.remove('open');
  const readmePanel = document.getElementById('task-readme-panel');
  if (readmePanel) readmePanel.style.display = 'none';
  activeSelectedTaskId = null;
}
window.closeTasksModal = closeTasksModal;

async function refreshTasksList() {
  const container = document.getElementById('tasks-list-container');
  if (!container) return;
  container.innerHTML = '<div style="color:#64748b; font-size:0.75rem; padding:12px; text-align:center;">Chargement des tâches...</div>';

  const res = await AetherAPI.fetchTasks();
  if (res && res.tasks) {
    currentTasksCache = res.tasks;
    renderTasksList(currentTasksCache);
  } else {
    container.innerHTML = '<div style="color:#ef4444; font-size:0.75rem; padding:12px; text-align:center;">Impossible de charger les tâches.</div>';
  }
}

function renderTasksList(tasks) {
  const container = document.getElementById('tasks-list-container');
  const countPill = document.getElementById('tasks-count-pill');
  if (!container) return;

  const filtered = (tasks || []).filter(t => {
    if (currentTaskFilter === 'done') return t.status === 'done';
    if (currentTaskFilter === 'active') return t.status !== 'done' && t.status !== 'cancelled';
    return true;
  });

  if (countPill) countPill.innerText = `${tasks.length} tâche(s)`;

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="background:rgba(15, 23, 42, 0.6); border:1px dashed rgba(56, 189, 248, 0.2); border-radius:8px; padding:24px; text-align:center; color:#94a3b8; font-size:0.75rem;">
        Aucune tâche dans cette vue.<br>
        <span style="font-size:0.70rem; color:#64748b;">Cliquez sur <strong>➕ Nouvelle Tâche</strong> ou demandez à l'IA via MCP !</span>
      </div>
    `;
    return;
  }

  const kindIcons = {
    function: '⚙️',
    research: '🔍',
    security_fix: '🛡️',
    arch_refactor: '🏛️',
    documentation: '📖',
    test: '🧪',
    other: '📌'
  };

  const statusBadges = {
    pending: '<span style="background:rgba(148,163,184,0.15); color:#94a3b8; border:1px solid rgba(148,163,184,0.3); padding:2px 6px; border-radius:4px; font-size:0.65rem; font-weight:700;">⏳ EN ATTENTE</span>',
    in_progress: '<span style="background:rgba(56,189,248,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.3); padding:2px 6px; border-radius:4px; font-size:0.65rem; font-weight:700;">⚡ EN COURS</span>',
    blocked: '<span style="background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); padding:2px 6px; border-radius:4px; font-size:0.65rem; font-weight:700;">⛔ BLOQUÉ</span>',
    done: '<span style="background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); padding:2px 6px; border-radius:4px; font-size:0.65rem; font-weight:700;">✅ TERMINÉ</span>',
    cancelled: '<span style="background:rgba(100,116,139,0.15); color:#64748b; border:1px solid rgba(100,116,139,0.3); padding:2px 6px; border-radius:4px; font-size:0.65rem; font-weight:700;">⚪ ANNULÉ</span>'
  };

  container.innerHTML = filtered.map(t => {
    const icon = kindIcons[t.kind] || '📌';
    const badge = statusBadges[t.status] || t.status;
    const target = t.target_symbol || t.target_file || '';
    const progress = t.progress || 0;

    return `
      <div class="task-card-item" data-id="${t.id}" style="background:rgba(15, 23, 42, 0.85); border:1px solid rgba(56, 189, 248, 0.22); border-radius:8px; padding:10px 14px; cursor:pointer; transition:all 0.18s; display:flex; flex-direction:column; gap:6px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:1.05rem;">${icon}</span>
            <span style="font-weight:700; color:#e2e8f0; font-size:0.80rem;">${t.title}</span>
            <span style="font-size:0.65rem; color:#64748b; font-family:var(--font-mono);">(${t.id})</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            ${badge}
            <span style="font-size:0.72rem; font-weight:700; color:#38bdf8;">${progress}%</span>
          </div>
        </div>

        <div style="width:100%; height:4px; background:rgba(30, 41, 59, 0.8); border-radius:2px; overflow:hidden;">
          <div style="width:${progress}%; height:100%; background:linear-gradient(90deg, #38bdf8, #818cf8); border-radius:2px;"></div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.70rem; color:#94a3b8;">
          <div style="display:flex; gap:10px; align-items:center;">
            ${target ? `<span style="color:#c084fc; font-weight:600;">🎯 ${target}</span>` : '<span style="color:#64748b;">Global</span>'}
            <span>Auteur : <strong>${t.author || 'user'}</strong></span>
          </div>
          <div style="display:flex; gap:6px;">
            ${t.status !== 'done' ? `<button class="aether-btn mark-done-btn" data-id="${t.id}" style="font-size:0.62rem; padding:2px 6px; border-color:#10b981; color:#34d399;">✓ Terminer</button>` : ''}
            <button class="aether-btn open-readme-btn" data-id="${t.id}" style="font-size:0.62rem; padding:2px 6px;">📖 Ouvrir README</button>
          </div>
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.task-card-item').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      const tid = card.getAttribute('data-id');
      const t = currentTasksCache.find(x => x.id === tid);
      if (t) selectTaskDetail(t);
    });
  });

  container.querySelectorAll('.open-readme-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const tid = btn.getAttribute('data-id');
      const t = currentTasksCache.find(x => x.id === tid);
      if (t) selectTaskDetail(t);
    });
  });

  container.querySelectorAll('.mark-done-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const tid = btn.getAttribute('data-id');
      await AetherAPI.updateTask(tid, 'done', 100, 'Tâche marquée comme terminée par l\'utilisateur');
      showToast(`✅ Tâche ${tid} terminée !`);
      await refreshTasksList();
    });
  });
}

function selectTaskDetail(task) {
  activeSelectedTaskId = task.id;
  const panel = document.getElementById('task-readme-panel');
  if (!panel) return;

  panel.style.display = 'flex';
  const titleEl = document.getElementById('task-detail-title');
  if (titleEl) titleEl.innerText = `📖 MINI-README : ${task.title} (${task.id})`;

  const statusSel = document.getElementById('task-detail-status');
  if (statusSel) statusSel.value = task.status;

  const range = document.getElementById('task-detail-progress-range');
  const label = document.getElementById('task-detail-progress-label');
  if (range) range.value = task.progress || 0;
  if (label) label.innerText = `${task.progress || 0}%`;

  const textarea = document.getElementById('task-detail-readme-textarea');
  if (textarea) textarea.value = task.full_readme || task.readme_summary || '';

  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Global button bindings for Tasks
document.getElementById('btn-menu-tasks')?.addEventListener('click', () => openTasksModal());
document.getElementById('btn-close-tasks-modal')?.addEventListener('click', closeTasksModal);
document.getElementById('btn-dismiss-tasks-modal')?.addEventListener('click', closeTasksModal);
document.getElementById('btn-refresh-tasks')?.addEventListener('click', refreshTasksList);

document.getElementById('btn-insp-task')?.addEventListener('click', () => {
  const node = state.selectedNode;
  const sym = node ? node.name : null;
  const file = node ? node.file_path : null;
  openTasksModal(sym, file);
});

document.getElementById('btn-toggle-new-task-form')?.addEventListener('click', () => {
  const panel = document.getElementById('new-task-form-panel');
  if (!panel) return;
  const isHidden = panel.style.display === 'none' || !panel.style.display;
  panel.style.display = isHidden ? 'flex' : 'none';
  if (isHidden) {
    document.getElementById('task-input-title')?.focus();
  }
});

document.getElementById('btn-cancel-new-task')?.addEventListener('click', () => {
  const panel = document.getElementById('new-task-form-panel');
  if (panel) panel.style.display = 'none';
});

document.getElementById('btn-submit-new-task')?.addEventListener('click', async () => {
  const title = document.getElementById('task-input-title')?.value?.trim();
  if (!title) {
    showToast('⚠️ Veuillez saisir un titre pour la tâche.');
    return;
  }
  const kind = document.getElementById('task-select-kind')?.value || 'function';
  const prio = document.getElementById('task-select-priority')?.value || 'medium';
  const sym = document.getElementById('task-input-symbol')?.value?.trim() || null;
  const file = document.getElementById('task-input-file')?.value?.trim() || null;
  const readme = document.getElementById('task-input-readme')?.value?.trim() || null;

  const res = await AetherAPI.createTask(title, kind, sym, file, prio, readme);
  if (res && res.status === 'ok') {
    showToast(`✅ Tâche créée avec succès !`);
    const titleInput = document.getElementById('task-input-title');
    if (titleInput) titleInput.value = '';
    const readmeInput = document.getElementById('task-input-readme');
    if (readmeInput) readmeInput.value = '';
    const panel = document.getElementById('new-task-form-panel');
    if (panel) panel.style.display = 'none';
    await refreshTasksList();
  } else {
    showToast(`⚠️ Erreur : ${(res && res.message) || 'Échec création'}`);
  }
});

document.getElementById('btn-close-task-detail')?.addEventListener('click', () => {
  const panel = document.getElementById('task-readme-panel');
  if (panel) panel.style.display = 'none';
  activeSelectedTaskId = null;
});

document.getElementById('task-detail-progress-range')?.addEventListener('input', (e) => {
  const val = e.target.value;
  const label = document.getElementById('task-detail-progress-label');
  if (label) label.innerText = `${val}%`;
});

document.getElementById('btn-save-task-detail')?.addEventListener('click', async () => {
  if (!activeSelectedTaskId) return;
  const status = document.getElementById('task-detail-status')?.value;
  const progress = parseInt(document.getElementById('task-detail-progress-range')?.value || '0', 10);
  const readme = document.getElementById('task-detail-readme-textarea')?.value;

  const res = await AetherAPI.updateTask(activeSelectedTaskId, status, progress, null, readme);
  if (res && res.status === 'ok') {
    showToast(`💾 Avancement de la tâche sauvegardé !`);
    await refreshTasksList();
  } else {
    showToast('⚠️ Erreur lors de la sauvegarde.');
  }
});

document.getElementById('btn-delete-task')?.addEventListener('click', async () => {
  if (!activeSelectedTaskId) return;
  if (!confirm(`Supprimer définitivement la tâche ${activeSelectedTaskId} ?`)) return;
  const res = await AetherAPI.deleteTask(activeSelectedTaskId);
  if (res && res.status === 'ok') {
    showToast('🗑️ Tâche supprimée.');
    const panel = document.getElementById('task-readme-panel');
    if (panel) panel.style.display = 'none';
    activeSelectedTaskId = null;
    await refreshTasksList();
  }
});

document.getElementById('btn-teleport-task-target')?.addEventListener('click', () => {
  if (!activeSelectedTaskId) return;
  const t = currentTasksCache.find(x => x.id === activeSelectedTaskId);
  if (!t) return;
  const target = t.target_symbol || t.target_file;
  if (!target) {
    showToast('Aucune cible spatiale associée à cette tâche.');
    return;
  }
  const nodes = (state.data && state.data.nodes) || [];
  const found = nodes.find(n => n.name === target || n.file_path === target || n.id === target);
  if (found) {
    closeTasksModal();
    if (typeof selectNode === 'function') selectNode(found);
    showToast(`🎯 Caméra alignée sur : ${target}`);
  } else {
    showToast(`Cible introuvable dans le graphe : ${target}`);
  }
});

document.querySelectorAll('#tasks-filter-tabs .task-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#tasks-filter-tabs .task-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentTaskFilter = btn.getAttribute('data-filter') || 'active';
    renderTasksList(currentTasksCache);
  });
});


// =========================================================================
// SURFACE & DOMAIN / IP POSTURE SCANNER CONTROLLER (Options -> Scanner)
// =========================================================================
let lastSurfaceScanReport = null;
let baselineSurfaceSnapshot = null;
let currentSurfaceScanLevel = 4;
let currentSurfacePromptMode = 'arch';
let selectedSurfaceFileFilter = 'ALL';
let surfaceProgressTimer = null;

function saveSurfaceBaselineSnapshot() {
  if (!lastSurfaceScanReport) {
    showToast('⚠️ Lancez d\'abord un audit pour figer une Baseline.');
    return;
  }
  baselineSurfaceSnapshot = JSON.parse(JSON.stringify(lastSurfaceScanReport));
  const btn = document.getElementById('btn-surface-snapshot');
  if (btn) {
    btn.innerText = `📸 Baseline (${baselineSurfaceSnapshot.security_score}/100)`;
    btn.style.borderColor = '#34d399';
    btn.style.color = '#34d399';
  }
  renderSurfaceDeltaBanner(lastSurfaceScanReport);
  showToast(`📸 Baseline figée à ${baselineSurfaceSnapshot.security_score}/100 (Grade ${baselineSurfaceSnapshot.grade}). Relancez un scan après vos correctifs pour voir le différentiel !`);
}
window.saveSurfaceBaselineSnapshot = saveSurfaceBaselineSnapshot;

function renderSurfaceDeltaBanner(rep) {
  const banner = document.getElementById('surface-delta-banner');
  if (!banner) return;
  banner.replaceChildren();
  if (!baselineSurfaceSnapshot || !rep) {
    banner.style.display = 'none';
    return;
  }
  banner.style.display = 'flex';
  const scoreDiff = (rep.security_score || 0) - (baselineSurfaceSnapshot.security_score || 0);
  const baseIds = new Set((baselineSurfaceSnapshot.findings || []).map(f => f.id));
  const curIds = new Set((rep.findings || []).map(f => f.id));
  let resolvedCount = 0;
  baseIds.forEach(id => { if (!curIds.has(id)) resolvedCount++; });
  let newCount = 0;
  curIds.forEach(id => { if (!baseIds.has(id)) newCount++; });

  const left = document.createElement('div');
  left.style.cssText = 'display:flex; align-items:center; gap:10px; flex-wrap:wrap; font-family:var(--font-mono); font-size:0.66rem;';

  const title = document.createElement('strong');
  title.style.color = scoreDiff >= 0 ? '#34d399' : '#f87171';
  const sign = scoreDiff > 0 ? `+${scoreDiff}` : `${scoreDiff}`;
  title.innerText = `⚖️ COMPARAISON AVANT / APRÈS : ${baselineSurfaceSnapshot.security_score}/100 (${baselineSurfaceSnapshot.grade}) ➔ ${rep.security_score}/100 (${rep.grade}) [${sign} pts]`;

  const meta = document.createElement('span');
  meta.style.color = '#cbd5e1';
  meta.innerText = `• ✅ ${resolvedCount} alerte(s) corrigée(s) • ⚠️ ${newCount} nouvelle(s) alerte(s) • Cible Baseline : ${baselineSurfaceSnapshot.host}:${baselineSurfaceSnapshot.primary_port}`;

  left.appendChild(title);
  left.appendChild(meta);

  const clearBtn = document.createElement('button');
  clearBtn.className = 'cat-pill';
  clearBtn.style.cssText = 'font-size:0.59rem; padding:2px 8px; background:#090d16; border-color:rgba(148,163,184,0.3); color:#94a3b8; cursor:pointer;';
  clearBtn.innerText = '✕ Effacer Baseline';
  clearBtn.onclick = () => {
    baselineSurfaceSnapshot = null;
    banner.style.display = 'none';
    const snapBtn = document.getElementById('btn-surface-snapshot');
    if (snapBtn) {
      snapBtn.innerText = '📸 Figer Baseline';
      snapBtn.style.borderColor = 'rgba(56, 189, 248, 0.35)';
      snapBtn.style.color = '#38bdf8';
    }
  };

  banner.appendChild(left);
  banner.appendChild(clearBtn);
}

function correlateSurfaceWithLocalAst(rep) {
  const nodes = (window.state && window.state.data && Array.isArray(window.state.data.nodes))
    ? window.state.data.nodes
    : [];
  const results = [];
  const wd = rep?.web_discovery;
  if (!wd) return results;

  const seenRefs = new Set();

  (wd.web_files || []).forEach(wf => {
    const cleanPath = (wf.path || '').split('?')[0];
    if (!cleanPath || seenRefs.has(cleanPath)) return;
    seenRefs.add(cleanPath);
    const baseName = cleanPath.split('/').filter(Boolean).pop() || '';
    const stem = baseName.replace(/\.[a-z0-9]+$/i, '').toLowerCase();

    const matched = nodes.find(n => {
      const lbl = (n.label || n.id || '').toLowerCase();
      return (baseName.length > 2 && lbl.includes(baseName.toLowerCase())) ||
             (stem.length > 3 && lbl.includes(stem));
    });

    results.push({
      externalRef: cleanPath,
      refType: `Fichier ${wf.file_type}`,
      isMapped: Boolean(matched),
      matchedLabel: matched ? (matched.label || matched.id) : 'Asset externe / statique non indexé dans l\'AST',
      matchedLayer: matched ? (matched.layer || 'Code Local') : 'Externe'
    });
  });

  (wd.routes || []).forEach(r => {
    const cleanRoute = (r.path || '').split('?')[0];
    if (!cleanRoute || seenRefs.has(cleanRoute)) return;
    seenRefs.add(cleanRoute);
    const segments = cleanRoute.split('/').filter(s => s && s !== 'api' && s !== 'v1' && s.length > 2);
    const lastSeg = (segments[segments.length - 1] || '').replace(/[^a-z0-9_]/gi, '').toLowerCase();

    const matched = lastSeg.length >= 3 ? nodes.find(n => {
      const lbl = (n.label || n.id || '').toLowerCase();
      const sum = (n.summary || '').toLowerCase();
      return lbl.includes(lastSeg) || sum.includes(lastSeg) || sum.includes(cleanRoute.toLowerCase());
    }) : null;

    results.push({
      externalRef: `[${r.method}] ${cleanRoute}`,
      refType: r.source || 'Route / API',
      isMapped: Boolean(matched),
      matchedLabel: matched ? (matched.label || matched.id) : 'Route non résolue dans l\'AST local (Vérifier contrôleur)',
      matchedLayer: matched ? (matched.layer || 'Backend AST') : 'Shadow / Externe'
    });
  });

  return results;
}

function setSurfaceFileFilter(filePath) {
  selectedSurfaceFileFilter = filePath || 'ALL';
  if (lastSurfaceScanReport) {
    renderSurfaceScanResults(lastSurfaceScanReport);
  }
}
window.setSurfaceFileFilter = setSurfaceFileFilter;

function buildSideTwoWeaknessSuite(rep) {
  if (!rep) return [];
  const nodes = (window.state && window.state.data && Array.isArray(window.state.data.nodes))
    ? window.state.data.nodes
    : [];
  const probes = rep.boundary_weaknesses || [];
  return probes.map((p, idx) => {
    const tokens = `${p.side_one_vector} ${p.side_two_ast_target}`
      .toLowerCase()
      .split(/[^a-z0-9_]+/)
      .filter(w => w.length >= 4 && !['http', 'https', 'form', 'post', 'test', 'avec', 'dans', 'pour'].includes(w));

    const matchedNode = nodes.find(n => {
      const lbl = (n.label || n.id || '').toLowerCase();
      const sum = (n.summary || '').toLowerCase();
      return tokens.some(tk => lbl.includes(tk) || sum.includes(tk));
    });

    const fnSlug = (p.id || `weakness_${idx}`)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_|_$/g, '');

    return {
      id: p.id,
      cwe: p.cwe,
      status: p.status,
      sideOneVector: p.side_one_vector,
      astNodeLabel: matchedNode ? `${matchedNode.label || matchedNode.id} [${matchedNode.layer || 'AST'}]` : p.side_two_ast_target,
      isAstMapped: Boolean(matchedNode),
      negativeTestFn: `test_reject_${fnSlug}_boundary()`,
      negativeTestSpec: p.negative_test_spec
    };
  });
}

function runPostBlackBoxSideTwoAudit() {
  if (!lastSurfaceScanReport) {
    showToast('⚠️ Lancez d\'abord le Scan Black-Box (Côté 1) avant de propulser le Côté 2.');
    return;
  }
  const sideTwoList = document.getElementById('surface-side-two-weakness-list');
  const sideTwoBadge = document.getElementById('surface-side-two-badge');
  const sumEl = document.getElementById('surface-dual-weakness-summary');
  const suite = buildSideTwoWeaknessSuite(lastSurfaceScanReport);

  if (sideTwoBadge) {
    sideTwoBadge.style.color = '#34d399';
    sideTwoBadge.innerText = `✅ ${suite.length} Test(s) Négatif(s) AST généré(s)`;
  }
  if (sumEl) {
    const mappedCount = suite.filter(s => s.isAstMapped).length;
    sumEl.innerText = `Miroir Bilatéral Actif : ${suite.length} sonde(s) Côté 1 croisée(s) avec ${mappedCount} nœud(s) AST Côté 2 • Mode 4 prêt à copier`;
  }

  if (sideTwoList) {
    sideTwoList.replaceChildren();
    if (suite.length === 0) {
      const empty = document.createElement('div');
      empty.style.cssText = 'font-size:0.63rem; color:#64748b; padding:6px;';
      empty.innerText = 'Aucune sonde de frontière disponible à corréler.';
      sideTwoList.appendChild(empty);
    } else {
      suite.forEach(item => {
        const col = item.status === 'ROBUSTE' ? '#c084fc' : (item.status === 'FAIBLESSE' ? '#fbbf24' : '#f87171');
        const card = document.createElement('div');
        card.style.cssText = `background:#090d16; border:1px solid ${col}; border-left:3px solid ${col}; border-radius:6px; padding:6px 8px; display:flex; flex-direction:column; gap:3px; font-family:var(--font-mono); font-size:0.60rem;`;

        const top = document.createElement('div');
        top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:4px;';
        const fnEl = document.createElement('strong');
        fnEl.style.color = '#f8fafc';
        fnEl.innerText = `🧪 ${item.negativeTestFn}`;
        const cweEl = document.createElement('span');
        cweEl.style.cssText = `color:${col}; font-weight:800; font-size:0.56rem;`;
        cweEl.innerText = `${item.cwe} • ${item.isAstMapped ? '🔗 AST' : '🎯 Cible'}`;
        top.appendChild(fnEl);
        top.appendChild(cweEl);
        card.appendChild(top);

        const targetEl = document.createElement('div');
        targetEl.style.cssText = 'color:#7dd3fc; font-size:0.57rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        targetEl.innerText = `Cible Code/AST : ${item.astNodeLabel}`;
        card.appendChild(targetEl);

        const specEl = document.createElement('div');
        specEl.style.cssText = 'color:#cbd5e1; font-size:0.57rem; line-height:1.3;';
        specEl.innerText = item.negativeTestSpec;
        card.appendChild(specEl);

        sideTwoList.appendChild(card);
      });
    }
  }

  setSurfacePromptMode('weakness');
  if (window.AudioSys?.nodeSelect) AudioSys.nodeSelect();
  showToast(`🔬 Côté 2 propulsé : ${suite.length} tests négatifs AST corrélés et chargés dans le Mode 4 !`);
}
window.runPostBlackBoxSideTwoAudit = runPostBlackBoxSideTwoAudit;

function setSurfacePromptMode(mode) {
  currentSurfacePromptMode = ['arch', 'hardening', 'tests', 'weakness'].includes(mode) ? mode : 'arch';
  const tabs = {
    arch: document.getElementById('surface-prompt-tab-arch'),
    hardening: document.getElementById('surface-prompt-tab-hardening'),
    tests: document.getElementById('surface-prompt-tab-tests'),
    weakness: document.getElementById('surface-prompt-tab-weakness')
  };
  Object.entries(tabs).forEach(([k, btn]) => {
    if (!btn) return;
    if (k === currentSurfacePromptMode) {
      btn.style.background = '#1e293b';
      btn.style.border = k === 'weakness' ? '1px solid #c084fc' : '1px solid #38bdf8';
      btn.style.color = '#f8fafc';
    } else {
      btn.style.background = '#090d16';
      btn.style.border = '1px solid rgba(148,163,184,0.2)';
      btn.style.color = '#cbd5e1';
    }
  });
  const rawArea = document.getElementById('surface-report-raw-textarea');
  if (rawArea && lastSurfaceScanReport) {
    rawArea.value = buildSurfaceScanMarkdownPrompt(lastSurfaceScanReport, currentSurfacePromptMode);
  }
}
window.setSurfacePromptMode = setSurfacePromptMode;

function updateSurfaceProgress(pct, stepText) {
  const wrap = document.getElementById('surface-scan-progress-wrap');
  const fill = document.getElementById('surface-scan-progress-fill');
  const step = document.getElementById('surface-scan-progress-step');
  const pctEl = document.getElementById('surface-scan-progress-pct');
  if (wrap) wrap.style.display = 'flex';
  if (fill) fill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  if (step) step.innerText = stepText;
  if (pctEl) pctEl.innerText = `${Math.round(pct)}%`;
}

function setSurfaceScanLevel(lvl) {
  currentSurfaceScanLevel = [1, 2, 3, 4].includes(Number(lvl)) ? Number(lvl) : 4;
  const configs = {
    1: { border: '#10b981', dns: true, ports: false, headers: true, endpoints: false, forms: false, sensitive: false },
    2: { border: '#f59e0b', dns: true, ports: true, headers: true, endpoints: true, forms: false, sensitive: false },
    3: { border: '#38bdf8', dns: true, ports: true, headers: true, endpoints: true, forms: true, sensitive: false },
    4: { border: '#38bdf8', dns: true, ports: true, headers: true, endpoints: true, forms: true, sensitive: true }
  };
  [1, 2, 3, 4].forEach(n => {
    const card = document.getElementById(`surface-lvl-card-${n}`);
    if (!card) return;
    if (n === currentSurfaceScanLevel) {
      card.style.background = '#1e293b';
      card.style.border = `1px solid ${configs[n].border}`;
      card.style.boxShadow = 'none';
    } else {
      card.style.background = '#090d16';
      card.style.border = '1px solid rgba(148, 163, 184, 0.16)';
      card.style.boxShadow = 'none';
    }
  });

  const c = configs[currentSurfaceScanLevel];
  const chkDns = document.getElementById('surface-chk-dns');
  const chkPorts = document.getElementById('surface-chk-ports');
  const chkHeaders = document.getElementById('surface-chk-headers');
  const chkEndpoints = document.getElementById('surface-chk-endpoints');
  const chkForms = document.getElementById('surface-chk-web-forms');
  const chkSens = document.getElementById('surface-chk-sensitive');
  if (chkDns) chkDns.checked = c.dns;
  if (chkPorts) chkPorts.checked = c.ports;
  if (chkHeaders) chkHeaders.checked = c.headers;
  if (chkEndpoints) chkEndpoints.checked = c.endpoints;
  if (chkForms) chkForms.checked = c.forms;
  if (chkSens) chkSens.checked = c.sensitive;

  const kpiImpact = document.getElementById('surface-kpi-impact');
  if (kpiImpact) {
    const labels = {
      1: 'Niveau 1 • Furtif (~2 pqts)',
      2: 'Niveau 2 • Services/Versions',
      3: 'Niveau 3 • Fichiers/Dossiers/Forms',
      4: 'Niveau 4 • Complet + CWE-538'
    };
    kpiImpact.innerText = labels[currentSurfaceScanLevel];
  }
}
window.setSurfaceScanLevel = setSurfaceScanLevel;

function openSurfaceScannerModal(prefillTarget = null) {
  const modal = document.getElementById('surface-scanner-modal');
  if (!modal) return;
  document.querySelectorAll('.aether-dropdown.open').forEach(d => d.classList.remove('open'));
  if (prefillTarget) {
    const inp = document.getElementById('surface-scan-target-input');
    if (inp) inp.value = prefillTarget;
  }
  modal.classList.add('open');
  if (window.AudioSys?.nodeSelect) AudioSys.nodeSelect();
  const inp = document.getElementById('surface-scan-target-input');
  if (inp) setTimeout(() => inp.focus(), 60);
}
window.openSurfaceScannerModal = openSurfaceScannerModal;

function closeSurfaceScannerModal() {
  document.getElementById('surface-scanner-modal')?.classList.remove('open');
}
window.closeSurfaceScannerModal = closeSurfaceScannerModal;

function setSurfacePreset(targetStr) {
  const inp = document.getElementById('surface-scan-target-input');
  if (inp) {
    inp.value = targetStr;
    runSurfaceScanner();
  }
}
window.setSurfacePreset = setSurfacePreset;

async function runSurfaceScanner() {
  const targetInput = document.getElementById('surface-scan-target-input');
  const target = targetInput ? targetInput.value.trim() : '';
  if (!target) {
    showToast('⚠️ Veuillez saisir un domaine, une adresse IP ou une URL.');
    return;
  }

  const checkDns = document.getElementById('surface-chk-dns')?.checked !== false;
  const checkPorts = document.getElementById('surface-chk-ports')?.checked !== false;
  const checkHeaders = document.getElementById('surface-chk-headers')?.checked !== false;
  const checkEndpoints = document.getElementById('surface-chk-endpoints')?.checked !== false;
  const checkWebForms = document.getElementById('surface-chk-web-forms')?.checked !== false;
  const checkSensitive = document.getElementById('surface-chk-sensitive')?.checked !== false;
  const customPorts = document.getElementById('surface-custom-ports-input')?.value?.trim() || null;

  const btn = document.getElementById('btn-run-surface-scan');
  if (btn) {
    btn.disabled = true;
    btn.innerText = `Audit Niv.${currentSurfaceScanLevel}...`;
  }
  const gradeBadge = document.getElementById('surface-scan-grade-badge');
  if (gradeBadge) gradeBadge.innerText = 'Audit en cours...';

  if (surfaceProgressTimer) clearInterval(surfaceProgressTimer);
  const progressSteps = [
    { pct: 18, msg: `Résolution DNS & classification IP sur ${target}...` },
    { pct: 42, msg: 'Sonde TCP multi-ports & lecture des bannières de services...' },
    { pct: 68, msg: 'Scan architectural par fichier (.html, .js, .css), dossiers & formulaires «Form»...' },
    { pct: 88, msg: 'Contrôle CWE-538 (.env / .git masqués) & calcul du score de posture...' }
  ];
  let stepIdx = 0;
  updateSurfaceProgress(10, `Initialisation de l'audit Niveau ${currentSurfaceScanLevel} sur ${target}...`);
  surfaceProgressTimer = setInterval(() => {
    if (stepIdx < progressSteps.length) {
      updateSurfaceProgress(progressSteps[stepIdx].pct, progressSteps[stepIdx].msg);
      stepIdx++;
    }
  }, 380);

  if (window.AudioSys?.xraySweep) AudioSys.xraySweep();

  try {
    const rep = await window.AetherAPI.surfaceScan({
      target,
      scan_level: currentSurfaceScanLevel,
      check_dns: checkDns,
      check_ports: checkPorts,
      check_headers: checkHeaders,
      check_endpoints: checkEndpoints,
      check_web_forms: checkWebForms,
      check_sensitive_files: checkSensitive,
      custom_ports: customPorts
    });
    if (surfaceProgressTimer) clearInterval(surfaceProgressTimer);
    updateSurfaceProgress(100, `Audit complété en ${rep.scan_duration_ms} ms — Score ${rep.security_score}/100 (Grade ${rep.grade})`);
    lastSurfaceScanReport = rep;
    renderSurfaceScanResults(rep);
    showToast(`✅ Audit terminé : ${rep.security_score}/100 (Grade ${rep.grade}) en ${rep.scan_duration_ms} ms`);
  } catch (err) {
    if (surfaceProgressTimer) clearInterval(surfaceProgressTimer);
    updateSurfaceProgress(0, 'Erreur de connexion au moteur local.');
    console.error('Surface scan error:', err);
    showToast('❌ Erreur lors du scan de surface (vérifiez le serveur local).');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = 'Lancer l\'Audit';
    }
  }
}
window.runSurfaceScanner = runSurfaceScanner;

function renderSurfaceScanResults(rep) {
  if (!rep) return;

  renderSurfaceDeltaBanner(rep);

  const scoreColor = rep.security_score >= 85 ? '#34d399' : (rep.security_score >= 65 ? '#fbbf24' : '#f87171');
  const kpiScore = document.getElementById('surface-kpi-score');
  if (kpiScore) {
    kpiScore.style.color = scoreColor;
    kpiScore.innerText = `${rep.security_score}/100 (${rep.grade})`;
  }

  const gradeBadge = document.getElementById('surface-scan-grade-badge');
  if (gradeBadge) {
    gradeBadge.innerText = `Grade ${rep.grade} • ${rep.security_score}/100`;
    gradeBadge.style.color = scoreColor;
    gradeBadge.style.borderColor = scoreColor;
  }

  const im = rep.impact_matrix || {};
  const kpiImpact = document.getElementById('surface-kpi-impact');
  if (kpiImpact) {
    kpiImpact.innerText = `${im.level_name || `Niveau ${currentSurfaceScanLevel}`} (${im.packets_sent_estimate || ''})`;
    kpiImpact.title = `${im.visibility_footprint || ''} — ${im.impact_rating || ''}`;
  }

  const kpiDns = document.getElementById('surface-kpi-dns');
  if (kpiDns) {
    const ipList = (rep.resolved_ips && rep.resolved_ips.length > 0) ? rep.resolved_ips.join(', ') : 'Non résolu';
    kpiDns.innerText = `${ipList} (${rep.dns_latency_ms || 0} ms) • ${rep.target_classification || ''}`;
  }

  const openList = (rep.open_ports || []).filter(p => p.open);
  const kpiPorts = document.getElementById('surface-kpi-ports');
  if (kpiPorts) {
    const verCnt = im.detected_versions_count ?? 0;
    kpiPorts.innerText = `${openList.length} service(s) actif(s) • ${verCnt} version(s)`;
  }

  const kpiHttp = document.getElementById('surface-kpi-http');
  if (kpiHttp) {
    const fCnt = im.detected_forms_count ?? 0;
    const iCnt = im.detected_inputs_count ?? 0;
    kpiHttp.innerText = `${rep.http_status || 'Pas de HTTP'} • ${fCnt} Form(s) / ${iCnt} Champ(s)`;
  }

  const footerMeta = document.getElementById('surface-scan-footer-meta');
  if (footerMeta) {
    footerMeta.innerText = `${im.visibility_footprint || ''} • Cible : ${rep.host}:${rep.primary_port} • Durée : ${rep.scan_duration_ms} ms`;
  }

  // 1. Render Tech Stack, Services & Versions
  const techList = document.getElementById('surface-tech-stack-list');
  const techCount = document.getElementById('surface-tech-count');
  const stack = rep.tech_stack || [];
  if (techCount) {
    techCount.innerText = `${stack.length} composant(s) / version(s) identifié(s)`;
  }
  if (techList) {
    techList.replaceChildren();
    if (stack.length === 0) {
      const empty = document.createElement('div');
      empty.style.cssText = 'font-size:0.68rem; color:#64748b;';
      empty.innerText = 'Aucune bannière logicielle ou version exposée (posture furtive ou Niveau 1).';
      techList.appendChild(empty);
    } else {
      stack.forEach(t => {
        const pill = document.createElement('div');
        pill.style.cssText = 'background:rgba(30, 27, 75, 0.65); border:1px solid rgba(192, 132, 252, 0.45); border-radius:6px; padding:5px 9px; display:flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:0.66rem;';
        const catSpan = document.createElement('span');
        catSpan.style.cssText = 'color:#c084fc; font-weight:800; font-size:0.60rem; text-transform:uppercase;';
        catSpan.innerText = `[${t.category}]`;

        const nameSpan = document.createElement('strong');
        nameSpan.style.color = '#f8fafc';
        nameSpan.innerText = t.name;

        pill.appendChild(catSpan);
        pill.appendChild(nameSpan);

        if (t.version) {
          const verSpan = document.createElement('span');
          verSpan.style.cssText = 'background:rgba(16, 185, 129, 0.2); border:1px solid rgba(16, 185, 129, 0.45); color:#6ee7b7; padding:1px 5px; border-radius:4px; font-size:0.60rem; font-weight:700;';
          verSpan.innerText = `v: ${t.version}`;
          pill.appendChild(verSpan);
        }

        const srcSpan = document.createElement('span');
        srcSpan.style.cssText = 'color:#94a3b8; font-size:0.58rem;';
        srcSpan.innerText = `(${t.source} • ${t.confidence})`;
        pill.appendChild(srcSpan);

        techList.appendChild(pill);
      });
    }
  }

  // 1b. Render 4 Trust Boundary Swimlanes (#surface-trust-swimlanes)
  const swimlanesEl = document.getElementById('surface-trust-swimlanes');
  const trustZones = rep.trust_zones || [];
  if (swimlanesEl) {
    swimlanesEl.replaceChildren();
    if (trustZones.length > 0) {
      trustZones.forEach(tz => {
        const col = tz.posture === 'PASS' ? '#34d399' : (tz.posture === 'WARN' ? '#fbbf24' : '#ef4444');
        const box = document.createElement('div');
        box.style.cssText = `background:#090d16; border:1px solid rgba(148,163,184,0.18); border-top:3px solid ${col}; border-radius:7px; padding:7px 9px; display:flex; flex-direction:column; gap:3px; font-family:var(--font-mono);`;

        const head = document.createElement('div');
        head.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:4px; font-size:0.61rem;';
        const title = document.createElement('strong');
        title.style.color = '#f8fafc';
        title.innerText = tz.title || tz.zone_name || `Zone ${tz.zone_id || ''}`;
        const badge = document.createElement('span');
        badge.style.cssText = `color:${col}; font-weight:800; font-size:0.56rem;`;
        badge.innerText = `[${tz.posture}]`;
        head.appendChild(title);
        head.appendChild(badge);
        box.appendChild(head);

        const sub = document.createElement('div');
        sub.style.cssText = 'font-size:0.57rem; color:#94a3b8;';
        sub.innerText = tz.subtitle || '';
        box.appendChild(sub);

        const ctrls = tz.controls || tz.key_items || [];
        if (ctrls.length > 0) {
          const itemsEl = document.createElement('div');
          itemsEl.style.cssText = 'font-size:0.56rem; color:#7dd3fc; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; margin-top:2px;';
          itemsEl.innerText = ctrls.join(' • ');
          itemsEl.title = ctrls.join('\n');
          box.appendChild(itemsEl);
        }
        swimlanesEl.appendChild(box);
      });
    }
  }

  // 2. Render Visual Web Architecture & Forms («Form» / Infos Reçues)
  const webMap = document.getElementById('surface-web-visual-map');
  const formsList = document.getElementById('surface-forms-list');
  const routesList = document.getElementById('surface-routes-list');
  const webSummary = document.getElementById('surface-web-arch-summary');
  const wd = rep.web_discovery;

  if (webMap && formsList && routesList) {
    webMap.replaceChildren();
    formsList.replaceChildren();
    routesList.replaceChildren();

    if (!wd) {
      if (webSummary) webSummary.innerText = 'Découverte Web désactivée (Activez le Niveau 3 ou la case Archi Web & «Form»)';
      const msg = document.createElement('div');
      msg.style.cssText = 'font-size:0.70rem; color:#64748b; text-align:center; padding:8px;';
      msg.innerText = 'Passez en Niveau 3 (Black-Box Complet) pour activer la découverte visuelle de l\'architecture Web et des formulaires «Form».';
      webMap.appendChild(msg);
    } else {
      const forms = wd.forms || [];
      const routes = wd.routes || [];
      const scripts = wd.external_scripts || [];
      const robots = wd.robots_entries || [];
      const webFiles = wd.web_files || [];
      const dirs = wd.directories || [];
      const totalInputs = forms.reduce((acc, f) => acc + ((f.inputs || []).length), 0);

      if (selectedSurfaceFileFilter !== 'ALL' && !webFiles.some(w => w.path === selectedSurfaceFileFilter)) {
        selectedSurfaceFileFilter = 'ALL';
      }

      if (webSummary) {
        webSummary.innerText = `${wd.is_web_arch ? '🌐 Architecture Web Détectée' : '⚡ Service Réseau/API'} • ${webFiles.length} Fichier(s) • ${dirs.length} Dossier(s) • ${forms.length} Form(s) (${totalInputs} Champ(s))`;
      }

      // 2.0 Interactive File Filter Bar (#surface-file-filter-bar)
      const filterBar = document.getElementById('surface-file-filter-bar');
      if (filterBar) {
        filterBar.replaceChildren();
        const lbl = document.createElement('span');
        lbl.style.cssText = 'font-size:0.61rem; font-weight:700; color:#38bdf8; font-family:var(--font-mono);';
        lbl.innerText = '🧬 Cascade X-Ray par Fichier :';
        filterBar.appendChild(lbl);

        const makeFilterBtn = (label, val) => {
          const b = document.createElement('button');
          const active = selectedSurfaceFileFilter === val;
          b.className = 'cat-pill';
          b.style.cssText = `font-size:0.59rem; padding:2px 8px; cursor:pointer; font-family:var(--font-mono); background:${active ? '#0284c7' : '#0f172a'}; border:1px solid ${active ? '#38bdf8' : 'rgba(148,163,184,0.25)'}; color:${active ? '#f8fafc' : '#cbd5e1'};`;
          b.innerText = label;
          b.onclick = () => setSurfaceFileFilter(val);
          return b;
        };

        filterBar.appendChild(makeFilterBtn(`Tous (${webFiles.length})`, 'ALL'));
        webFiles.forEach(wf => {
          filterBar.appendChild(makeFilterBtn(`${wf.file_type}: ${wf.path}`, wf.path));
        });
      }

      // 2a. Graphe Visuel de Topologie Web (4 Nœuds Connectés)
      const flowRow = document.createElement('div');
      flowRow.style.cssText = 'display:grid; grid-template-columns: 1fr auto 1.15fr auto 1.15fr auto 1fr; gap:6px; align-items:center;';

      const makeArchNode = (icon, title, subtitle, detail, borderCol) => {
        const box = document.createElement('div');
        box.style.cssText = `background:rgba(15, 23, 42, 0.92); border:1px solid ${borderCol}; border-radius:7px; padding:8px; display:flex; flex-direction:column; gap:3px; font-family:var(--font-mono);`;
        const h = document.createElement('div');
        h.style.cssText = 'font-size:0.68rem; font-weight:800; color:#f8fafc;';
        h.innerText = `${icon} ${title}`;
        const s = document.createElement('div');
        s.style.cssText = 'font-size:0.62rem; color:#38bdf8; font-weight:700;';
        s.innerText = subtitle;
        const d = document.createElement('div');
        d.style.cssText = 'font-size:0.59rem; color:#94a3b8;';
        d.innerText = detail;
        box.appendChild(h);
        box.appendChild(s);
        box.appendChild(d);
        return box;
      };

      const makeArrow = () => {
        const arr = document.createElement('div');
        arr.style.cssText = 'color:#38bdf8; font-weight:900; font-size:0.95rem; padding:0 2px;';
        arr.innerText = '➔';
        return arr;
      };

      flowRow.appendChild(makeArchNode(
        '🌐',
        'POINT D\'ENTRÉE & FICHIERS',
        `${rep.scheme.toUpperCase()}://${rep.host}:${rep.primary_port}`,
        `${webFiles.length} Fichier(s) (.html/.js/.css) • ${dirs.length} Dossier(s)`,
        'rgba(56, 189, 248, 0.5)'
      ));
      flowRow.appendChild(makeArrow());
      flowRow.appendChild(makeArchNode(
        '📝',
        'SURFACE «FORM» & ENTRÉES',
        `${forms.length} Formulaire(s) • ${totalInputs} Champ(s) reçu(s)`,
        forms.length > 0 ? `Méthodes: ${[...new Set(forms.map(f => f.method))].join(', ')}` : 'Aucun <form> HTML direct',
        forms.some(f => f.security_posture !== 'PASS') ? 'rgba(245, 158, 11, 0.65)' : 'rgba(16, 185, 129, 0.5)'
      ));
      flowRow.appendChild(makeArrow());
      flowRow.appendChild(makeArchNode(
        '🧭',
        'CARTOGRAPHIE ROUTES & API',
        `${routes.length} Route(s) • ${scripts.length} Script(s) JS`,
        `robots.txt: ${robots.length} entrée(s) • sec.txt: ${wd.security_txt_present ? 'OUI' : 'NON'}`,
        'rgba(192, 132, 252, 0.5)'
      ));
      flowRow.appendChild(makeArrow());
      flowRow.appendChild(makeArchNode(
        '🖥️',
        'SERVICES & STACK BACKEND',
        `${openList.length} Port(s) TCP • ${stack.length} Tech(s)`,
        stack.slice(0, 2).map(t => t.name).join(', ') || 'Serveur HTTP',
        'rgba(16, 185, 129, 0.5)'
      ));

      webMap.appendChild(flowRow);

      // 2a-bis. Scan Architectural par Fichier (.html, .js, .css, .json) & Arborescence des Dossiers Appelés
      const webFilesList = document.getElementById('surface-web-files-list');
      const dirsList = document.getElementById('surface-directories-list');
      const selectedWfObj = selectedSurfaceFileFilter === 'ALL'
        ? null
        : webFiles.find(w => w.path === selectedSurfaceFileFilter);

      if (webFilesList) {
        webFilesList.replaceChildren();
        if (webFiles.length === 0) {
          const emptyWF = document.createElement('div');
          emptyWF.style.cssText = 'font-size:0.65rem; color:#64748b; padding:6px;';
          emptyWF.innerText = 'Aucun fichier .html/.js/.css inspecté.';
          webFilesList.appendChild(emptyWF);
        } else {
          webFiles.forEach(wf => {
            const isSelected = selectedSurfaceFileFilter === wf.path;
            const wfCard = document.createElement('div');
            wfCard.style.cssText = `cursor:pointer; background:${isSelected ? '#1e293b' : '#0f172a'}; border:1px solid ${isSelected ? '#38bdf8' : 'rgba(148, 163, 184, 0.16)'}; border-radius:6px; padding:6px 8px; display:flex; flex-direction:column; gap:4px; font-family:var(--font-mono);`;
            wfCard.onclick = () => setSurfaceFileFilter(isSelected ? 'ALL' : wf.path);

            const wfHead = document.createElement('div');
            wfHead.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:6px; font-size:0.64rem;';
            const wfName = document.createElement('strong');
            wfName.style.color = isSelected ? '#38bdf8' : '#f8fafc';
            wfName.innerText = `[${wf.file_type}] ${wf.path}`;
            const wfMeta = document.createElement('span');
            wfMeta.style.cssText = 'color:#94a3b8; font-size:0.58rem;';
            const kb = (wf.size_bytes / 1024).toFixed(1);
            wfMeta.innerText = `${kb} Ko • ${(wf.folder_calls || []).length} dossier(s) • ${(wf.api_and_asset_refs || []).length} appel(s)${wf.has_sourcemap ? ' • SourceMap' : ''}`;
            wfHead.appendChild(wfName);
            wfHead.appendChild(wfMeta);
            wfCard.appendChild(wfHead);

            if ((wf.folder_calls && wf.folder_calls.length > 0) || (wf.api_and_asset_refs && wf.api_and_asset_refs.length > 0) || (wf.json_payload_keys && wf.json_payload_keys.length > 0)) {
              const callsRow = document.createElement('div');
              callsRow.style.cssText = 'display:flex; flex-wrap:wrap; gap:4px;';
              (wf.folder_calls || []).slice(0, 6).forEach(fc => {
                const badge = document.createElement('span');
                badge.style.cssText = 'background:rgba(56, 189, 248, 0.12); border:1px solid rgba(56, 189, 248, 0.3); color:#7dd3fc; border-radius:4px; padding:1px 5px; font-size:0.57rem;';
                badge.innerText = `📁 ${fc}`;
                callsRow.appendChild(badge);
              });
              (wf.api_and_asset_refs || []).slice(0, 6).forEach(ar => {
                const badge = document.createElement('span');
                badge.style.cssText = 'background:rgba(30, 41, 59, 0.9); border:1px solid rgba(148, 163, 184, 0.22); color:#cbd5e1; border-radius:4px; padding:1px 5px; font-size:0.57rem;';
                badge.innerText = `↳ ${ar}`;
                callsRow.appendChild(badge);
              });
              (wf.json_payload_keys || []).slice(0, 8).forEach(jk => {
                const badge = document.createElement('span');
                badge.style.cssText = 'background:rgba(16, 185, 129, 0.14); border:1px solid rgba(16, 185, 129, 0.35); color:#6ee7b7; border-radius:4px; padding:1px 5px; font-size:0.57rem;';
                badge.innerText = `🔑 JSON:${jk}`;
                callsRow.appendChild(badge);
              });
              wfCard.appendChild(callsRow);
            }

            webFilesList.appendChild(wfCard);
          });
        }
      }

      if (dirsList) {
        dirsList.replaceChildren();
        const filteredDirs = selectedWfObj
          ? dirs.filter(d => (d.source_files || []).includes(selectedWfObj.path) || (selectedWfObj.folder_calls || []).includes(d.folder_path))
          : dirs;
        if (filteredDirs.length === 0) {
          const emptyD = document.createElement('div');
          emptyD.style.cssText = 'font-size:0.65rem; color:#64748b; padding:6px;';
          emptyD.innerText = selectedWfObj ? `Aucun sous-dossier appelé par ${selectedWfObj.path}.` : 'Aucun appel de sous-dossier détecté.';
          dirsList.appendChild(emptyD);
        } else {
          filteredDirs.forEach(d => {
            const dRow = document.createElement('div');
            dRow.style.cssText = 'background:#0f172a; border:1px solid rgba(148, 163, 184, 0.16); border-radius:6px; padding:5px 8px; display:flex; flex-direction:column; gap:2px; font-family:var(--font-mono);';
            const top = document.createElement('div');
            top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; font-size:0.63rem;';
            const pSpan = document.createElement('strong');
            pSpan.style.color = '#7dd3fc';
            pSpan.innerText = `📁 ${d.folder_path}`;
            const cSpan = document.createElement('span');
            cSpan.style.cssText = 'color:#94a3b8; font-size:0.57rem;';
            cSpan.innerText = `${d.classification} (${d.call_count}x)`;
            top.appendChild(pSpan);
            top.appendChild(cSpan);
            dRow.appendChild(top);

            const srcEl = document.createElement('div');
            srcEl.style.cssText = 'font-size:0.56rem; color:#64748b; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
            srcEl.innerText = `Appelé depuis : ${(d.source_files || []).join(', ')}`;
            dRow.appendChild(srcEl);
            dirsList.appendChild(dRow);
          });
        }
      }

      // 2b. Cartes détaillées des Formulaires «Form» et des informations reçues
      if (forms.length === 0) {
        const emptyF = document.createElement('div');
        emptyF.style.cssText = 'font-size:0.68rem; color:#94a3b8; padding:10px;';
        emptyF.innerText = 'Aucune balise <form> ou champ <input> détecté sur la page d\'entrée.';
        formsList.appendChild(emptyF);
      } else {
        forms.forEach(f => {
          const fCard = document.createElement('div');
          const pCol = f.security_posture === 'PASS' ? '#34d399' : (f.security_posture === 'WARN' ? '#fbbf24' : '#f87171');
          fCard.style.cssText = `background:rgba(15, 23, 42, 0.9); border:1px solid ${pCol}; border-left:4px solid ${pCol}; border-radius:6px; padding:8px; display:flex; flex-direction:column; gap:6px; font-family:var(--font-mono);`;

          const fHead = document.createElement('div');
          fHead.style.cssText = 'display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:4px; font-size:0.67rem;';
          const fTitle = document.createElement('strong');
          fTitle.style.color = '#f8fafc';
          fTitle.innerText = `📝 Form #${f.index} «${f.id_or_name}» [${f.method}] ➔ ${f.action}`;

          const fMeta = document.createElement('span');
          fMeta.style.cssText = `color:${pCol}; font-weight:800; font-size:0.61rem;`;
          fMeta.innerText = `${f.has_csrf_token ? '🛡️ CSRF OK' : '⚠️ Sans CSRF'} • [${f.security_posture}]`;
          fHead.appendChild(fTitle);
          fHead.appendChild(fMeta);
          fCard.appendChild(fHead);

          // Liste des champs d'information reçus par ce formulaire
          const inputsWrap = document.createElement('div');
          inputsWrap.style.cssText = 'display:flex; flex-wrap:wrap; gap:4px;';
          const fInputs = f.inputs || [];
          if (fInputs.length === 0) {
            const noInp = document.createElement('span');
            noInp.style.cssText = 'font-size:0.61rem; color:#64748b;';
            noInp.innerText = 'Aucun champ <input>/<select>/<textarea> interne.';
            inputsWrap.appendChild(noInp);
          } else {
            fInputs.forEach(inp => {
              const chip = document.createElement('span');
              const isSens = inp.classification.includes('Secret') || inp.classification.includes('Upload');
              chip.style.cssText = `background:${isSens ? 'rgba(239, 68, 68, 0.18)' : 'rgba(2, 6, 23, 0.85)'}; border:1px solid ${isSens ? 'rgba(239, 68, 68, 0.5)' : 'rgba(56, 189, 248, 0.35)'}; border-radius:4px; padding:2px 6px; font-size:0.60rem; color:#e2e8f0;`;
              chip.innerText = `${inp.classification} : ${inp.name} (${inp.input_type}${inp.required ? '*' : ''})`;
              inputsWrap.appendChild(chip);
            });
          }
          fCard.appendChild(inputsWrap);

          if (f.security_notes && f.security_notes.length > 0) {
            f.security_notes.forEach(note => {
              const nEl = document.createElement('div');
              nEl.style.cssText = `font-size:0.60rem; color:${pCol};`;
              nEl.innerText = `↳ ${note}`;
              fCard.appendChild(nEl);
            });
          }

          formsList.appendChild(fCard);
        });
      }

      // 2c. Liste des Routes, API & Scripts découverts (filtrable par fichier X-Ray)
      const filteredRoutes = selectedWfObj
        ? routes.filter(r => (selectedWfObj.api_and_asset_refs || []).includes(r.path) || (r.source || '').includes(selectedWfObj.path))
        : routes;

      if (filteredRoutes.length === 0 && scripts.length === 0) {
        const emptyR = document.createElement('div');
        emptyR.style.cssText = 'font-size:0.68rem; color:#94a3b8; padding:10px;';
        emptyR.innerText = selectedWfObj ? `Aucune route directe isolée pour ${selectedWfObj.path}.` : 'Aucune route ou script externe référencé.';
        routesList.appendChild(emptyR);
      } else {
        filteredRoutes.forEach(r => {
          const rRow = document.createElement('div');
          rRow.style.cssText = 'background:rgba(15, 23, 42, 0.82); border:1px solid rgba(56, 189, 248, 0.25); border-radius:5px; padding:4px 7px; display:flex; justify-content:space-between; align-items:center; font-family:var(--font-mono); font-size:0.62rem;';
          const left = document.createElement('span');
          left.style.color = '#e2e8f0';
          left.innerText = `[${r.method}] ${r.path}`;
          const right = document.createElement('span');
          right.style.color = '#7dd3fc';
          right.style.fontSize = '0.58rem';
          right.innerText = r.source;
          rRow.appendChild(left);
          rRow.appendChild(right);
          routesList.appendChild(rRow);
        });
        if (!selectedWfObj) {
          scripts.forEach(sc => {
            const sRow = document.createElement('div');
            sRow.style.cssText = 'background:rgba(30, 27, 75, 0.45); border:1px solid rgba(192, 132, 252, 0.25); border-radius:5px; padding:4px 7px; display:flex; justify-content:space-between; align-items:center; font-family:var(--font-mono); font-size:0.61rem;';
            const left = document.createElement('span');
            left.style.color = '#d8b4fe';
            left.innerText = `📜 ${sc}`;
            const right = document.createElement('span');
            right.style.color = '#94a3b8';
            right.style.fontSize = '0.57rem';
            right.innerText = 'Script JS';
            sRow.appendChild(left);
            sRow.appendChild(right);
            routesList.appendChild(sRow);
          });
        }
      }

      // 2c-bis. Pont Hybride « Surface Externe ↔ Code Source AST Local » (#surface-ast-bridge-list)
      const bridgeListEl = document.getElementById('surface-ast-bridge-list');
      const bridgeSumEl = document.getElementById('surface-ast-bridge-summary');
      const bridgeItems = correlateSurfaceWithLocalAst(rep);
      if (bridgeListEl) {
        bridgeListEl.replaceChildren();
        const mappedCnt = bridgeItems.filter(b => b.isMapped).length;
        if (bridgeSumEl) {
          bridgeSumEl.innerText = `${mappedCnt}/${bridgeItems.length} élément(s) corrélé(s) avec le graphe AST local`;
        }
        if (bridgeItems.length === 0) {
          const emptyB = document.createElement('div');
          emptyB.style.cssText = 'font-size:0.64rem; color:#64748b; grid-column:span 2; padding:4px;';
          emptyB.innerText = 'Aucun fichier ou route à corréler avec l\'AST local.';
          bridgeListEl.appendChild(emptyB);
        } else {
          bridgeItems.slice(0, 18).forEach(item => {
            const card = document.createElement('div');
            const bCol = item.isMapped ? 'rgba(16, 185, 129, 0.38)' : 'rgba(245, 158, 11, 0.35)';
            card.style.cssText = `background:#0f172a; border:1px solid ${bCol}; border-radius:6px; padding:5px 8px; display:flex; flex-direction:column; gap:2px; font-family:var(--font-mono); font-size:0.61rem;`;

            const top = document.createElement('div');
            top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:4px;';
            const extSpan = document.createElement('strong');
            extSpan.style.color = '#f8fafc';
            extSpan.innerText = `${item.isMapped ? '🔗' : '👻'} ${item.externalRef}`;
            const statusSpan = document.createElement('span');
            statusSpan.style.cssText = `font-size:0.55rem; color:${item.isMapped ? '#34d399' : '#fbbf24'}; font-weight:700;`;
            statusSpan.innerText = item.isMapped ? 'AST MAPPÉ' : 'NON RÉSOLU AST';
            top.appendChild(extSpan);
            top.appendChild(statusSpan);
            card.appendChild(top);

            const bot = document.createElement('div');
            bot.style.cssText = 'font-size:0.56rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
            bot.innerText = `➔ ${item.matchedLabel} [${item.matchedLayer}]`;
            bot.title = `${item.matchedLabel} (${item.matchedLayer})`;
            card.appendChild(bot);

            bridgeListEl.appendChild(card);
          });
        }
      }
    }
  }

  // 2c-ter. Render Côté 1 (Sondes de Faiblesse de Frontière Black-Box Boosted) & Unlock Côté 2 (Post-Black-Box AST)
  const sideOneList = document.getElementById('surface-side-one-weakness-list');
  const sideOneBadge = document.getElementById('surface-side-one-badge');
  const sideTwoBadge = document.getElementById('surface-side-two-badge');
  const btnSideTwo = document.getElementById('btn-run-side-two-weakness');
  const bProbes = rep.boundary_weaknesses || [];

  if (btnSideTwo) {
    btnSideTwo.disabled = false;
    btnSideTwo.style.background = '#4c1d95';
    btnSideTwo.style.borderColor = '#c084fc';
    btnSideTwo.style.color = '#f8fafc';
  }
  if (sideTwoBadge) {
    sideTwoBadge.style.color = '#c084fc';
    sideTwoBadge.innerText = '⚡ Scan Black-Box acquis • Prêt à propulser';
  }

  if (sideOneList) {
    sideOneList.replaceChildren();
    const weakCnt = bProbes.filter(p => p.status !== 'ROBUSTE').length;
    if (sideOneBadge) {
      sideOneBadge.style.color = weakCnt > 0 ? '#fbbf24' : '#34d399';
      sideOneBadge.innerText = `${bProbes.length} sonde(s) • ${weakCnt} point(s) d'attention`;
    }
    if (bProbes.length === 0) {
      const emptyP = document.createElement('div');
      emptyP.style.cssText = 'font-size:0.63rem; color:#64748b; padding:6px;';
      emptyP.innerText = 'Aucune sonde de frontière exécutée.';
      sideOneList.appendChild(emptyP);
    } else {
      bProbes.forEach(p => {
        const col = p.status === 'ROBUSTE' ? '#34d399' : (p.status === 'FAIBLESSE' ? '#fbbf24' : '#ef4444');
        const card = document.createElement('div');
        card.style.cssText = `background:#090d16; border:1px solid ${col}; border-left:3px solid ${col}; border-radius:6px; padding:6px 8px; display:flex; flex-direction:column; gap:3px; font-family:var(--font-mono); font-size:0.60rem;`;

        const top = document.createElement('div');
        top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:4px;';
        const catEl = document.createElement('strong');
        catEl.style.color = '#f8fafc';
        catEl.innerText = `[${p.cwe}] ${p.category}`;
        const stEl = document.createElement('span');
        stEl.style.cssText = `color:${col}; font-weight:800; font-size:0.56rem;`;
        stEl.innerText = `[${p.status}]`;
        top.appendChild(catEl);
        top.appendChild(stEl);
        card.appendChild(top);

        const vecEl = document.createElement('div');
        vecEl.style.cssText = 'color:#38bdf8; font-size:0.57rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        vecEl.innerText = `Vecteur : ${p.side_one_vector}`;
        card.appendChild(vecEl);

        const obsEl = document.createElement('div');
        obsEl.style.cssText = 'color:#cbd5e1; font-size:0.57rem; line-height:1.3;';
        obsEl.innerText = p.observed_behavior;
        card.appendChild(obsEl);

        sideOneList.appendChild(card);
      });
    }
  }

  if (currentSurfacePromptMode === 'weakness') {
    runPostBlackBoxSideTwoAudit();
  }

  // 2d. Render Module 4 : Exposed Sensitive Files (.env, .git, Configs — Redacted CWE-538)
  const sensList = document.getElementById('surface-sensitive-list');
  const sensSummary = document.getElementById('surface-sensitive-summary');
  const artifacts = rep.exposed_artifacts || [];
  if (sensList) {
    sensList.replaceChildren();
    if (artifacts.length === 0) {
      if (sensSummary) sensSummary.innerText = 'Module 4 désactivé (Activez le Niveau 4 ou la case .env / .git)';
      const emptyS = document.createElement('div');
      emptyS.style.cssText = 'font-size:0.68rem; color:#64748b; grid-column:span 4; text-align:center; padding:8px;';
      emptyS.innerText = 'Passez en Niveau 4 pour contrôler l\'exposition des fichiers .env, .git/HEAD et manifestes (avec masquage automatique des valeurs).';
      sensList.appendChild(emptyS);
    } else {
      const exposedCount = artifacts.filter(a => a.exposed).length;
      if (sensSummary) {
        sensSummary.innerText = exposedCount > 0
          ? `🚨 ${exposedCount} fichier(s) sensible(s) exposé(s) sur ${artifacts.length} sondés (Valeurs masquées [MASQUÉ])`
          : `🛡️ 0 exposition sur ${artifacts.length} fichiers sensibles sondés (Tous protégés / 404 / Soft-404 filtrés)`;
      }
      artifacts.forEach(a => {
        const card = document.createElement('div');
        const borderCol = a.exposed ? '#ef4444' : 'rgba(16, 185, 129, 0.38)';
        const bgCol = a.exposed ? 'rgba(127, 29, 29, 0.32)' : 'rgba(2, 6, 23, 0.72)';
        card.style.cssText = `background:${bgCol}; border:1px solid ${borderCol}; border-radius:6px; padding:6px 8px; display:flex; flex-direction:column; gap:3px; font-family:var(--font-mono); font-size:0.63rem;`;

        const top = document.createElement('div');
        top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:4px;';
        const pEl = document.createElement('strong');
        pEl.style.color = a.exposed ? '#fca5a5' : '#e2e8f0';
        pEl.innerText = `${a.exposed ? '🚨' : '🛡️'} ${a.path}`;
        const stEl = document.createElement('span');
        stEl.style.cssText = `font-size:0.57rem; font-weight:800; color:${a.exposed ? '#f87171' : '#34d399'};`;
        stEl.innerText = a.exposed ? 'EXPOSÉ' : 'PROTÉGÉ';
        top.appendChild(pEl);
        top.appendChild(stEl);
        card.appendChild(top);

        const sub = document.createElement('div');
        sub.style.cssText = 'font-size:0.58rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        sub.innerText = a.redacted_preview ? a.redacted_preview : `${a.label} (${a.http_status})`;
        sub.title = a.redacted_preview || a.http_status;
        card.appendChild(sub);

        sensList.appendChild(card);
      });
    }
  }

  // 3. Render Ports Grid (with Protocol, Banner & Detected Version)
  const portsGrid = document.getElementById('surface-ports-grid');
  if (portsGrid) {
    portsGrid.replaceChildren();
    const ports = rep.open_ports || [];
    if (ports.length === 0) {
      const empty = document.createElement('div');
      empty.style.cssText = 'font-size:0.70rem; color:#64748b; grid-column:span 2; text-align:center; padding:10px;';
      empty.innerText = 'Scan des ports désactivé en Niveau 1 (Furtif).';
      portsGrid.appendChild(empty);
    } else {
      ports.forEach(p => {
        const card = document.createElement('div');
        const borderCol = p.open
          ? (p.risk_level === 'CRITICAL' || p.risk_level === 'HIGH' ? 'rgba(239,68,68,0.6)' : 'rgba(16,185,129,0.55)')
          : 'rgba(51,65,85,0.45)';
        const bgCol = p.open ? 'rgba(6, 78, 59, 0.25)' : 'rgba(2, 6, 23, 0.55)';
        card.style.cssText = `background:${bgCol}; border:1px solid ${borderCol}; border-radius:6px; padding:6px 8px; display:flex; flex-direction:column; gap:2px; font-family:var(--font-mono); font-size:0.65rem;`;

        const top = document.createElement('div');
        top.style.cssText = 'display:flex; justify-content:space-between; align-items:center;';
        const left = document.createElement('span');
        left.style.color = p.open ? '#f8fafc' : '#64748b';
        left.style.fontWeight = p.open ? '700' : '400';
        left.innerText = `${p.open ? '🟢' : '⚫'} :${p.port}/${p.protocol || 'TCP'} ${p.service}`;
        const right = document.createElement('span');
        right.style.color = p.open ? '#34d399' : '#475569';
        right.innerText = p.open ? `${p.latency_ms ?? 0} ms` : 'FERMÉ';
        top.appendChild(left);
        top.appendChild(right);
        card.appendChild(top);

        if (p.open && (p.detected_version || p.banner)) {
          const bEl = document.createElement('div');
          bEl.style.cssText = 'font-size:0.59rem; color:#7dd3fc; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
          bEl.innerText = `🏷️ ${p.detected_version ? `[${p.detected_version}] ` : ''}${p.banner || ''}`;
          bEl.title = p.banner || '';
          card.appendChild(bEl);
        }
        portsGrid.appendChild(card);
      });
    }
  }

  // 4. Render Headers Audit
  const headersList = document.getElementById('surface-headers-list');
  if (headersList) {
    headersList.replaceChildren();
    const hdrs = rep.headers_audit || [];
    if (hdrs.length === 0) {
      const empty = document.createElement('div');
      empty.style.cssText = 'font-size:0.70rem; color:#64748b; text-align:center; padding:10px;';
      empty.innerText = 'Aucun service HTTP détecté sur les ports sondés.';
      headersList.appendChild(empty);
    } else {
      hdrs.forEach(h => {
        const row = document.createElement('div');
        const col = h.status === 'PASS' ? '#34d399' : (h.status === 'WARN' ? '#fbbf24' : '#f87171');
        row.style.cssText = 'background:rgba(2, 6, 23, 0.72); border:1px solid rgba(51, 65, 85, 0.6); border-radius:6px; padding:6px 9px; display:flex; flex-direction:column; gap:3px;';
        const top = document.createElement('div');
        top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; font-family:var(--font-mono); font-size:0.68rem;';
        const nameEl = document.createElement('strong');
        nameEl.style.color = '#e2e8f0';
        nameEl.innerText = h.header;
        const badgeEl = document.createElement('span');
        badgeEl.style.cssText = `color:${col}; font-weight:800; font-size:0.62rem;`;
        badgeEl.innerText = `[${h.status}]`;
        top.appendChild(nameEl);
        top.appendChild(badgeEl);

        const recEl = document.createElement('div');
        recEl.style.cssText = 'font-size:0.64rem; color:#94a3b8;';
        recEl.innerText = h.value ? `Valeur : ${h.value} — ${h.recommendation}` : h.recommendation;
        row.appendChild(top);
        row.appendChild(recEl);
        headersList.appendChild(row);
      });
    }
  }

  // 5. Render Findings
  const findingsList = document.getElementById('surface-findings-list');
  const findingsCount = document.getElementById('surface-findings-count');
  const findings = rep.findings || [];
  if (findingsCount) findingsCount.innerText = `${findings.length} alerte(s)`;

  if (findingsList) {
    findingsList.replaceChildren();
    if (findings.length === 0) {
      const okBox = document.createElement('div');
      okBox.style.cssText = 'background:rgba(6, 78, 59, 0.25); border:1px solid rgba(16, 185, 129, 0.5); border-radius:8px; padding:18px; text-align:center; color:#6ee7b7; font-size:0.76rem; font-weight:700;';
      okBox.innerText = '🛡️ Aucune anomalie critique de surface, de formulaire ou d\'en-tête détectée sur cette cible !';
      findingsList.appendChild(okBox);
    } else {
      findings.forEach(f => {
        const sevCol = f.severity === 'CRITICAL' ? '#ef4444' : (f.severity === 'HIGH' ? '#f97316' : (f.severity === 'MEDIUM' ? '#fbbf24' : '#38bdf8'));
        const card = document.createElement('div');
        card.style.cssText = `background:rgba(2, 6, 23, 0.85); border:1px solid ${sevCol}; border-left:4px solid ${sevCol}; border-radius:6px; padding:8px 10px; display:flex; flex-direction:column; gap:4px;`;

        const head = document.createElement('div');
        head.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:6px; font-family:var(--font-mono); font-size:0.65rem;';
        const cweSpan = document.createElement('span');
        cweSpan.style.cssText = `color:${sevCol}; font-weight:800;`;
        cweSpan.innerText = `[${f.severity}] ${f.cwe}`;
        const catSpan = document.createElement('span');
        catSpan.style.cssText = 'color:#94a3b8; font-size:0.60rem;';
        catSpan.innerText = f.category;
        head.appendChild(cweSpan);
        head.appendChild(catSpan);

        const titleEl = document.createElement('div');
        titleEl.style.cssText = 'font-size:0.74rem; font-weight:700; color:#f8fafc;';
        titleEl.innerText = f.title;

        const descEl = document.createElement('div');
        descEl.style.cssText = 'font-size:0.67rem; color:#cbd5e1; line-height:1.35;';
        descEl.innerText = f.description;

        const remEl = document.createElement('div');
        remEl.style.cssText = 'font-size:0.65rem; color:#34d399; font-family:var(--font-mono); margin-top:2px;';
        remEl.innerText = `💡 Remédiation : ${f.remediation}`;

        card.appendChild(head);
        card.appendChild(titleEl);
        card.appendChild(descEl);
        card.appendChild(remEl);
        findingsList.appendChild(card);
      });
    }
  }

  // 6. Populate the Copyable Raw Report Textarea automatically with active Prompt Mode
  const rawArea = document.getElementById('surface-report-raw-textarea');
  if (rawArea) {
    rawArea.value = buildSurfaceScanMarkdownPrompt(rep, currentSurfacePromptMode);
  }
}

function buildSurfaceScanMarkdownPrompt(rep, mode = currentSurfacePromptMode) {
  if (!rep) return '';
  const im = rep.impact_matrix || {};
  const openPorts = (rep.open_ports || []).filter(p => p.open).map(p => `- Port :${p.port}/${p.protocol || 'TCP'} (${p.service}) : OUVERT (${p.latency_ms || 0} ms)${p.detected_version ? ` | Version: ${p.detected_version}` : ''}${p.banner ? ` | Bannière: \`${p.banner}\`` : ''}`).join('\n') || '- Aucun port ouvert détecté';
  const techMd = (rep.tech_stack || []).map(t => `- **[${t.category}] ${t.name}**${t.version ? ` (Version : \`${t.version}\`)` : ''} — Source : ${t.source} (${t.confidence})`).join('\n') || '- Aucune bannière logicielle exposée';
  const trustMd = (rep.trust_zones || []).map(tz => `- **${tz.title || tz.zone_name}** (${tz.subtitle || ''}) : **[${tz.posture}]** — ${(tz.controls || tz.key_items || []).join(', ')}`).join('\n') || '- Non évalué';
  const filesMd = (rep.web_discovery?.web_files || []).map(wf => `- **[${wf.file_type}] \`${wf.path}\`** (${(wf.size_bytes / 1024).toFixed(1)} Ko) — Dossiers : ${(wf.folder_calls || []).join(', ') || 'aucun'} | Appels : ${(wf.api_and_asset_refs || []).slice(0, 6).join(', ') || 'aucun'}${(wf.json_payload_keys && wf.json_payload_keys.length > 0) ? ` | Clés JSON : \`${wf.json_payload_keys.join(', ')}\`` : ''}`).join('\n') || '- Aucun fichier inspecté';
  const dirsMd = (rep.web_discovery?.directories || []).map(d => `- **\`${d.folder_path}\`** (${d.classification}, ${d.call_count} appel(s)) — Sources : ${(d.source_files || []).join(', ')}`).join('\n') || '- Aucun sous-dossier détecté';
  const formsMd = (rep.web_discovery?.forms || []).map(f => {
    const inps = (f.inputs || []).map(i => `\`${i.name}\` (${i.input_type} • ${i.classification})`).join(', ') || 'aucun champ';
    return `- **Form #${f.index} \`${f.id_or_name}\`** [${f.method} ➔ \`${f.action}\`] (CSRF: ${f.has_csrf_token ? 'OUI' : 'NON'}, Posture: ${f.security_posture})\n  - Champs reçus : ${inps}`;
  }).join('\n') || '- Aucun formulaire HTML détecté';
  const bridgeItems = correlateSurfaceWithLocalAst(rep);
  const bridgeMd = bridgeItems.map(b => `- \`${b.externalRef}\` (${b.refType}) ➔ **${b.isMapped ? 'MAPPÉ AST' : 'NON RÉSOLU'}** : \`${b.matchedLabel}\` [${b.matchedLayer}]`).join('\n') || '- Aucun pont AST calculé';
  const sensMd = (rep.exposed_artifacts || []).map(a => `- \`${a.path}\` (${a.label}) : **${a.exposed ? 'EXPOSÉ' : 'PROTÉGÉ'}** — ${a.redacted_preview || a.http_status}`).join('\n') || '- Non audité';
  const findingsMd = (rep.findings || []).map(f => `- **[${f.severity}] ${f.id} (${f.cwe})** — ${f.title}\n  - Diagnostic : ${f.description}\n  - Remédiation : ${f.remediation}`).join('\n') || '- Aucune vulnérabilité de surface détectée.';
  const verifMd = (rep.verification_suite || []).map(v => `- **[${v.id || v.check_id}] (${v.category || ''}) ${v.title}**\n  - Commande non-destructive : \`${v.assertion_cmd || v.non_destructive_cmd}\`\n  - Assertion attendue : ${v.expected_result || v.expected_assertion}\n  - Correctif type : ${v.patch_hint || ''}`).join('\n') || '- Aucune vérification générée.';
  const sideOneMd = (rep.boundary_weaknesses || []).map(p => `- **[${p.status}] ${p.id} (${p.cwe} • ${p.category})**\n  - Vecteur Externe (Côté 1) : \`${p.side_one_vector}\`\n  - Comportement observé : ${p.observed_behavior}`).join('\n') || '- Aucune sonde de frontière exécutée.';
  const sideTwoSuite = buildSideTwoWeaknessSuite(rep);
  const sideTwoMd = sideTwoSuite.map(s => `- **Test Unitaire Négatif \`${s.negativeTestFn}\` (${s.cwe})**\n  - Entrée Externe Côté 1 : \`${s.sideOneVector}\`\n  - Cible Interne Code/AST Côté 2 : \`${s.astNodeLabel}\` (${s.isAstMapped ? 'Mappé dans l\'AST local' : 'Cible fonctionnelle'})\n  - Spécification du Test Négatif : ${s.negativeTestSpec}`).join('\n') || '- Aucun test Côté 2 généré.';

  const mcpFooter = `\n\n## 🛠️ Commandes MCP Combinées AetherScope à Exécuter
1. **Recherche AST + Violations CWE (2-en-1) :** \`aetherscope_search_symbols({"stereotype": "«Controller»", "has_violation": true})\`
2. **Inspection Cible + Caméra 3D + Trace MVC (3-en-1) :** \`aetherscope_get_active_target({"symbol_id": "<handler_cible>", "action": "Surface Audit", "trace_direction": "both"})\`
3. **Validation Pare-Feu < 50ms + Tâche + Chat (4-en-1) :** \`aetherscope_verify_patch({"files_modified": ["<fichier_modifié>"], "status": "done", "chat_message": "Durcissement de surface validé (Grade A+)"})\``;

  if (mode === 'weakness') {
    return `# ⚖️ PROMPT BINÔME IA — MODE 4 BOOSTED : SUITE DE TESTS DE FAIBLESSE BILATÉRALE (CÔTÉ 1 BLACK-BOX ↔ CÔTÉ 2 WHITE-BOX AST)
- **Cible auditée :** \`${rep.target_raw}\` (\`${rep.scheme}://${rep.host}:${rep.primary_port}\`)
- **Score de Posture :** **${rep.security_score}/100 (Grade ${rep.grade})**
- **Approche Miroir Bilatérale :**
  1. **Côté 1 (Externe / Black-Box Boosted)** : Sondes de perméabilité des frontières HTTP (CORS Origin Reflection, verbes HTTP OPTIONS, indexation des dossiers CWE-548, drapeaux de cookies CWE-1004, contrats des formulaires «Form» CWE-352 et clés JSON CWE-20/CWE-88, dotfiles CWE-538).
  2. **Côté 2 (Interne / Après Scan Black-Box ➔ Code Source & AST)** : Corrélation de chaque point d'entrée externe avec les handlers/sinks AST locaux et génération des **Tests Unitaires Négatifs (Negative Boundary Tests)** pour prouver que les garde-fous internes rejettent toute entrée malformée.

## 🌐 CÔTÉ 1 : Résultats des Sondes de Faiblesse de Frontière (Externe / Black-Box)
${sideOneMd}

## 🧬 CÔTÉ 2 : Matrice de Réceptivité AST & Suite de Tests Unitaires Négatifs (Après Scan Black-Box)
${sideTwoMd}

## 🔗 Pont Hybride Surface Externe ↔ Fichiers Sources AST Locaux
${bridgeMd}

## 🎯 Instructions pour le Binôme IA (Génération des Suites de Tests des Deux Côtés)
1. **Suite Côté 1 (Tests de Frontière HTTP / Intégration Externe)** : Génère les tests automatisés non-destructifs qui vérifient le rejet des origines CORS non autorisées (\`Origin: https://untrusted.invalid\`), le rejet des verbes HTTP inattendus (\`405 Method Not Allowed\`), l'absence de Directory Listing (\`403/404\`) et le rejet des soumissions sans jeton CSRF ou avec un \`Content-Type\` invalide (\`415/422\`).
2. **Suite Côté 2 (Tests Unitaires Négatifs Côté Code / AST Interne)** : Écris le code complet des fonctions de test \`test_reject_*_boundary()\` ci-dessus (en Rust \`#[test]\` / TypeScript \`vitest\` selon les fichiers AST mappés) en passant des valeurs limites inoffensives (types invalides, chaînes vides, arguments préfixés par \`--\`, chemins relatifs simulés) et en vérifiant que le validateur retourne systématiquement \`Err(...)\` ou \`StatusCode::BAD_REQUEST / UNPROCESSABLE_ENTITY\` **avant** d'atteindre le sink interne.${mcpFooter}`;
  }

  if (mode === 'hardening') {
    return `# 🛡️ PROMPT BINÔME IA — MODE 2 : PLAN DE DURCISSEMENT & CORRECTIFS CODE CIBLÉS
- **Cible auditée :** \`${rep.target_raw}\` (Hôte : \`${rep.host}:${rep.primary_port}\`, Score actuel : **${rep.security_score}/100 — Grade ${rep.grade}**)
- **Stack identifiée :** ${(rep.tech_stack || []).map(t => `${t.name}${t.version ? ' ' + t.version : ''}`).join(', ') || 'Serveur HTTP / TCP'}

## 1. Pont Hybride Surface Externe ↔ Fichiers Sources AST Locaux
${bridgeMd}

## 2. Diagnostics de Posture & Failles à Corriger Prioritairement
${findingsMd}

## 3. Formulaires («Form») & Contrats de Données Détectés
${formsMd}

## 4. Exposition des Fichiers Sensibles (CWE-538 — Valeurs Masquées)
${sensMd}

## 🎯 Instructions pour le Binôme IA (Génération des Correctifs)
1. **Middlewares & En-têtes HTTP** : Fournis le code exact (Rust/Axum/Tower, Node/Express ou Nginx selon la stack détectée) pour injecter \`Content-Security-Policy\`, \`X-Frame-Options: DENY\`, \`X-Content-Type-Options: nosniff\` et \`Referrer-Policy\`.
2. **Protection des Formulaires & Routes API** : Si des formulaires ou routes API manquent de jeton anti-CSRF ou de validation de schéma sur les clés JSON extraites, écris le validateur côté serveur correspondant aux fichiers AST mappés ci-dessus.
3. **Blocage CWE-538** : Ajoute une règle explicite interdisant l'accès HTTP aux dotfiles (\`.env\`, \`.git/*\`, \`docker-compose.yml\`).${mcpFooter}`;
  }

  if (mode === 'tests') {
    return `# 🧪 PROMPT BINÔME IA — MODE 3 : SUITE DE TESTS DE CONFORMITÉ DÉFENSIFS & NON-RÉGRESSION CI
- **Cible auditée :** \`${rep.target_raw}\` (\`${rep.scheme}://${rep.host}:${rep.primary_port}\`)
- **Score actuel :** **${rep.security_score}/100 (Grade ${rep.grade})**
- **Contrainte stricte :** Tests 100% défensifs, non-destructifs (assertions d'en-têtes \`curl -sSI\`, codes HTTP 403/404 sur dotfiles, présence de jetons CSRF).

## 1. Assertions de Conformité Générées Automatiquement par AetherScope
${verifMd}

## 2. Routes, Fichiers (.html/.js) & Clés JSON à Couvrir
${filesMd}

## 3. Pont AST Local pour les Tests d'Intégration
${bridgeMd}

## 🎯 Instructions pour le Binôme IA (Génération des Tests Automatisés)
1. Génère un script de vérification défensif exécutable en CI (PowerShell / Bash \`curl -sSI\` ou test d'intégration Rust/Playwright) qui valide chacune des assertions ci-dessus sans aucun payload offensif.
2. Ajoute un test unitaire/intégration pour chaque route mappée dans l'AST local afin de garantir le maintien du **Grade A+ (100/100)**.${mcpFooter}`;
  }

  return `# 📐 PROMPT BINÔME IA — MODE 1 : REVUE D'ARCHITECTURE, 4 FRONTIÈRES DE CONFIANCE & PONT AST
- **Cible auditée :** \`${rep.target_raw}\` (Hôte : \`${rep.host}\`, Port primaire : \`${rep.primary_port}\`)
- **Module d'Impact & Visibilité :** ${im.level_name || 'Niveau 4'} (${im.visibility_footprint || ''})
- **Classification :** ${rep.target_classification} | **IP(s) :** ${(rep.resolved_ips || []).join(', ') || 'Non résolu'}
- **Score de Posture :** **${rep.security_score}/100 (Grade ${rep.grade})** | **Statut HTTP :** ${rep.http_status || 'N/A'}

## 1. Carte des 4 Frontières de Confiance (Swimlanes Architecturales)
${trustMd}

## 2. Pont Hybride « Surface Externe ↔ Graphe AST Local »
${bridgeMd}

## 3. Cascade X-Ray par Fichier (.html ➔ .js ➔ Appels API & Clés JSON)
${filesMd}

## 4. Arborescence des Dossiers & Répertoires Appelés
${dirsMd}

## 5. Formulaires («Form» / Informations Reçues)
${formsMd}

## 6. Services, Versions, Ports TCP & Fichiers Sensibles (CWE-538 Masqué)
${techMd}
${openPorts}
${sensMd}

## 7. Diagnostics & Remédiations Architecturales
${findingsMd}

## 🎯 Instructions pour le Binôme IA
Analyse cette topologie complète (du fichier \`.html\`/\`.js\` externe jusqu'au contrôleur AST local), identifie les routes fantômes non mappées dans l'AST, et propose une architecture de défense en profondeur pour atteindre **100/100 (Grade A+)**.${mcpFooter}`;
}

function copyTextWithFallback(text, successMsg) {
  const rawArea = document.getElementById('surface-report-raw-textarea');
  if (rawArea) {
    rawArea.value = text;
  }
  const fallbackCopy = () => {
    try {
      const targetEl = rawArea || document.createElement('textarea');
      if (!rawArea) {
        targetEl.value = text;
        targetEl.style.cssText = 'position:fixed;left:-9999px;top:0;';
        document.body.appendChild(targetEl);
      }
      targetEl.focus();
      targetEl.select();
      document.execCommand('copy');
      if (!rawArea) document.body.removeChild(targetEl);
      if (window.AudioSys?.promptCopied) AudioSys.promptCopied();
      showToast(successMsg);
    } catch (e) {
      console.error('Clipboard fallback error:', e);
      showToast('⚠️ Texte sélectionné dans la zone de rapport : appuyez sur Ctrl+C.');
    }
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      if (window.AudioSys?.promptCopied) AudioSys.promptCopied();
      showToast(successMsg);
    }).catch(() => fallbackCopy());
  } else {
    fallbackCopy();
  }
}

function selectAllSurfaceReportText() {
  const rawArea = document.getElementById('surface-report-raw-textarea');
  if (!rawArea) return;
  if (!rawArea.value && lastSurfaceScanReport) {
    rawArea.value = buildSurfaceScanMarkdownPrompt(lastSurfaceScanReport);
  }
  rawArea.focus();
  rawArea.select();
  try {
    document.execCommand('copy');
    showToast('📋 Tout le rapport a été sélectionné et copié (Ctrl+C) !');
  } catch (_) {
    showToast('🔍 Rapport sélectionné : appuyez sur Ctrl+C.');
  }
}
window.selectAllSurfaceReportText = selectAllSurfaceReportText;

function copySurfaceScanPrompt() {
  if (!lastSurfaceScanReport) {
    showToast('⚠️ Lancez d\'abord un audit avant de copier le rapport.');
    return;
  }
  const md = buildSurfaceScanMarkdownPrompt(lastSurfaceScanReport);
  copyTextWithFallback(md, '📋 Rapport Markdown complet copié dans le presse-papier !');
}
window.copySurfaceScanPrompt = copySurfaceScanPrompt;

function copySurfaceScanJson() {
  if (!lastSurfaceScanReport) {
    showToast('⚠️ Lancez d\'abord un audit avant de copier le JSON.');
    return;
  }
  const jsonStr = JSON.stringify(lastSurfaceScanReport, null, 2);
  copyTextWithFallback(jsonStr, '📦 Rapport JSON brut copié dans le presse-papier !');
}
window.copySurfaceScanJson = copySurfaceScanJson;

async function sendSurfaceReportToCopilot() {
  if (!lastSurfaceScanReport) {
    showToast('⚠️ Lancez d\'abord un scan de surface.');
    return;
  }
  const md = buildSurfaceScanMarkdownPrompt(lastSurfaceScanReport);
  closeSurfaceScannerModal();
  const popup = document.getElementById('ai-chat-popup');
  if (popup && popup.classList.contains('hidden')) {
    toggleAiChatPopup();
  }
  const input = document.getElementById('ai-chat-user-input');
  if (input) {
    input.value = md;
    await sendUserChatMessage();
  }
}
window.sendSurfaceReportToCopilot = sendSurfaceReportToCopilot;

document.getElementById('surface-scan-target-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    runSurfaceScanner();
  }
});

// Initial sync & Render Loop Bootstrap
syncSettingsToMenuShortcuts();
if (state.settings && window.AudioSys) {
  window.AudioSys.enabled = state.settings.sound !== false;
}
loadProjects();
if (typeof syncProjectStatus === 'function') syncProjectStatus();
if (state.data && state.data.nodes && state.data.nodes.length > 0) {
  applyData(state.data);
}
if (typeof renderEdgeTypologyLegend === 'function') {
  renderEdgeTypologyLegend();
}
if (typeof render === 'function') {
  requestAnimationFrame(render);
}
