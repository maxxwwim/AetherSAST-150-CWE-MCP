<script lang="ts">
  import { cockpitState } from '../state/graphState.svelte';
  import { api } from '../lib/api';
  import SearchDropdownPanel from './SearchDropdownPanel.svelte';
  import { generateAuditMarkdown, generateAuditHtml, downloadBlob } from '../lib/auditReport';
  import {
    Search,
    Layers,
    ShieldAlert,
    Target,
    Sparkles,
    Radar,
    Settings,
    Eye,
    Flame,
    Ghost,
    Maximize2,
    FileText,
    FolderGit2,
    FolderOpen,
    FolderTree,
    RefreshCw,
    Bot,
    Plug,
    CheckSquare,
    FilePlus2,
    Camera,
    Pause,
    Play,
    Code,
    Code2,
    BookOpen,
    Tag,
    Activity,
    Zap,
    X,
    Volume2,
    VolumeX,
    Download,
    Upload,
    Orbit,
    Globe,
    Workflow,
    Sun,
    Grid,
    ShieldOff,
    Compass
  } from '@lucide/svelte';

  // ---------------------------------------------------------------------------
  // État local
  // ---------------------------------------------------------------------------
  let folderInput = $state('');
  let isAnalyzingBar = $state(false);
  let fileActionError = $state<string | null>(null);
  let fileImportInputEl = $state<HTMLInputElement | null>(null);

  // Omnibox
  let searchQuery = $state('');
  let isSearchDropdownOpen = $state(false);
  let searchInputEl = $state<HTMLInputElement | null>(null);

  // Barre de menus déroulants (style application de bureau)
  let openMenu = $state<string | null>(null);
  let lastHoverSwitchTs = 0;
  let menubarEl = $state<HTMLElement | null>(null);

  const activeTaskCount = $derived(
    cockpitState.tasks.filter((t) => t.status !== 'done' && t.status !== 'cancelled').length
  );

  function stripWinPrefix(p: string): string {
    return p.replace(/^\\\\\?\\/, '');
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------
  function exportAuditMarkdown() {
    const md = generateAuditMarkdown(cockpitState);
    const proj = (cockpitState.graph.project_name || 'project').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    downloadBlob(md, `audit-report-${proj}-${Date.now()}.md`, 'text/markdown;charset=utf-8');
  }

  function exportAuditHtml() {
    const html = generateAuditHtml(cockpitState);
    const proj = (cockpitState.graph.project_name || 'project').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    downloadBlob(html, `audit-report-${proj}-${Date.now()}.html`, 'text/html;charset=utf-8');
  }

  $effect(() => {
    const p = cockpitState.graph.project_path;
    if (p) folderInput = stripWinPrefix(p);
  });

  function triggerImportLocalFile() {
    fileActionError = null;
    fileImportInputEl?.click();
  }

  async function handleImportLocalFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const content = await file.text();
      // If user imported a standalone AetherGraph JSON export, load it directly into the graph!
      if (file.name.toLowerCase().endsWith('.json')) {
        try {
          const parsed = JSON.parse(content);
          if (parsed && Array.isArray(parsed.nodes) && (Array.isArray(parsed.edges) || parsed.edges_compact)) {
            cockpitState.setGraph(parsed);
            cockpitState.requestCameraFit();
            openMenu = null;
            return;
          }
        } catch {
          // Regular JSON source file — import into workspace via modal
        }
      }
      cockpitState.pendingImportFile = { fileName: file.name, content };
      cockpitState.isCreateFileModalOpen = true;
      openMenu = null;
    } catch (err: any) {
      fileActionError = err?.message || 'Impossible de lire le fichier sélectionné.';
    } finally {
      input.value = '';
    }
  }

  async function analyzeFolderFromBar(e?: Event) {
    e?.preventDefault();
    fileActionError = null;
    const target = folderInput.trim() || cockpitState.graph.project_path || '.';
    if (
      /^https?:\/\//i.test(target) ||
      /^localhost(:\d+)?(\/.*)?$/i.test(target) ||
      /^\d{1,3}(\.\d{1,3}){3}(:\d+)?(\/.*)?$/.test(target)
    ) {
      cockpitState.isSurfaceScannerOpen = true;
      openMenu = null;
      return;
    }
    if (isAnalyzingBar) return;
    isAnalyzingBar = true;
    openMenu = null;
    cockpitState.isScanningProject = true;
    cockpitState.scanningTargetPath = target;
    try {
      const g = await api.analyzeProject(target, cockpitState.settings.exclusions);
      if (g && Array.isArray(g.nodes)) {
        cockpitState.setGraph(g);
        cockpitState.requestCameraFit();
      }
    } catch (err: any) {
      fileActionError = err?.message || 'Échec de l’analyse du chemin.';
      openMenu = 'file';
    } finally {
      isAnalyzingBar = false;
      cockpitState.isScanningProject = false;
    }
  }

  async function browseFolderFromBar() {
    if (isAnalyzingBar) return;
    fileActionError = null;
    isAnalyzingBar = true;
    try {
      const res = await api.pickProject();
      if (res?.status === 'cancelled') return;
      if (res?.project_path) folderInput = stripWinPrefix(res.project_path);
      if (res?.graph && Array.isArray(res.graph.nodes)) {
        cockpitState.setGraph(res.graph);
        cockpitState.requestCameraFit();
      } else if (res?.status && res.status !== 'ok') {
        fileActionError = res.message || 'Impossible d’ouvrir le projet sélectionné.';
        openMenu = 'file';
      }
    } catch {
      cockpitState.isHubModalOpen = true;
    } finally {
      isAnalyzingBar = false;
    }
  }

  function browseWorkspaceFromBar() {
    fileActionError = null;
    openMenu = null;
    cockpitState.openProjectHub('manage');
  }

  async function switchViewMode(mode: 'code' | 'vault' | 'ide') {
    const normalized = mode === 'vault' ? 'vault-notes' : mode;
    cockpitState.viewMode = normalized;
    try {
      const g = await api.switchViewMode(normalized);
      if (normalized !== 'ide' && g && Array.isArray(g.nodes)) {
        cockpitState.setGraph(g);
        cockpitState.requestCameraFit();
      }
    } catch (e) {
      console.warn('Erreur bascule viewMode:', e);
    }
  }

  function setVision(mode: 'standard' | 'xray' | 'heatmap' | 'deadcode') {
    cockpitState.visionMode = mode === 'standard' || cockpitState.visionMode !== mode ? mode : 'standard';
  }

  function setLayoutLevel(level: 1 | 2 | 3 | 4) {
    cockpitState.lodLevel = level === 1 ? 1 : level === 2 ? 2 : 3;
    cockpitState.activeLayout = `Z-${level}` as 'Z-1' | 'Z-2' | 'Z-3' | 'Z-4';
  }

  function openSearch() {
    isSearchDropdownOpen = true;
    openMenu = null;
  }

  function closeSearch() {
    isSearchDropdownOpen = false;
  }

  function handleWindowKeyDown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      openMenu = null;
      searchInputEl?.focus();
      isSearchDropdownOpen = true;
      return;
    }
    if (e.key === 'Escape' && openMenu) {
      openMenu = null;
    }
  }

  function handleWindowPointerDown(e: PointerEvent) {
    if (openMenu && menubarEl && !menubarEl.contains(e.target as Node)) {
      openMenu = null;
    }
  }

  function toggleMenu(id: string) {
    // Si on vient tout juste de basculer vers ce menu par survol (<300ms), le clic le laisse ouvert
    if (openMenu === id && performance.now() - lastHoverSwitchTs < 300) {
      return;
    }
    openMenu = openMenu === id ? null : id;
  }

  function hoverMenu(id: string) {
    // Comme une vraie barre de menus : une fois un menu ouvert, le survol bascule de menu en menu
    if (openMenu && openMenu !== id) {
      openMenu = id;
      lastHoverSwitchTs = performance.now();
    }
  }

  // ---------------------------------------------------------------------------
  // Définition des menus (aucune fonction de la v2.5 n'est retirée)
  // ---------------------------------------------------------------------------
  type MenuItem = {
    kind: 'item';
    icon?: any;
    emoji?: string;
    iconClass?: string;
    label: string;
    desc?: string;
    shortcut?: string;
    /** 'toggle' = pastille ON/OFF, 'radio' = sélection exclusive, sinon action simple */
    mode?: 'toggle' | 'radio';
    active?: () => boolean;
    badge?: () => string | number | null;
    /** Garde le menu ouvert après le clic (pratique pour enchaîner les bascules) */
    keepOpen?: boolean;
    run: () => void;
  };
  function focusAgentTarget(targetName: string) {
    if (!targetName) return;
    const hit = cockpitState.resolveTargetNode(targetName);
    if (hit) {
      cockpitState.selectSymbol(hit);
      cockpitState.focusTargetNode = hit;
    }
    openMenu = null;
  }

  async function clearAgentsFromMenu() {
    await api.clearTelemetry().catch(() => {});
    cockpitState.clearAiTrail();
    openMenu = null;
  }

  type MenuEntry =
    | MenuItem
    | { kind: 'header'; label: string }
    | { kind: 'sep' }
    | { kind: 'path' }
    | { kind: 'agents' };
  type Menu = { id: string; label: string; width?: string; entries: MenuEntry[] };

  const menus: Menu[] = [
    {
      id: 'file',
      label: 'Fichier',
      width: 'w-[22rem]',
      entries: [
        { kind: 'header', label: 'Projet & workspace' },
        { kind: 'path' },
        {
          kind: 'item', icon: FolderGit2, iconClass: 'text-sky-400',
          label: 'Hub Multi-Architectures',
          desc: 'Créer un projet (7 stacks), changer de dépôt, export HTML',
          run: () => cockpitState.openProjectHub('create')
        },
        {
          kind: 'item', icon: FolderOpen, iconClass: 'text-sky-300',
          label: 'Parcourir un projet…', desc: 'Ouvrir et analyser un projet unique',
          run: browseFolderFromBar
        },
        {
          kind: 'item', icon: FolderTree, iconClass: 'text-emerald-300',
          label: 'Parcourir un workspace…', desc: 'Explorer les dossiers & projets d’un workspace',
          run: browseWorkspaceFromBar
        },
        { kind: 'sep' },
        {
          kind: 'item', icon: Upload, iconClass: 'text-cyan-400',
          label: 'Importer un fichier…', desc: 'Importer un fichier source ou un graphe JSON depuis le PC',
          run: triggerImportLocalFile
        },
        {
          kind: 'item', icon: FilePlus2, iconClass: 'text-emerald-400',
          label: 'Nouveau fichier IA', desc: 'Créer un fichier et ré-indexer le graphe', shortcut: 'N',
          active: () => cockpitState.isCreateFileModalOpen,
          run: () => (cockpitState.isCreateFileModalOpen = true)
        },
        {
          kind: 'item', icon: Camera, iconClass: 'text-emerald-300',
          label: 'Snapshot PNG', desc: 'Capture haute résolution du graphe WebGL',
          run: () => cockpitState.requestSnapshot()
        },
        { kind: 'header', label: "Exporter le rapport d'audit" },
        {
          kind: 'item', icon: Download, iconClass: 'text-sky-400',
          label: 'Format Markdown (.md)', desc: 'Rapport global de sécurité',
          run: exportAuditMarkdown
        },
        {
          kind: 'item', icon: Download, iconClass: 'text-emerald-400',
          label: 'Format HTML Dark (.html)', desc: 'Rapport autonome, thème sombre',
          run: exportAuditHtml
        }
      ]
    },
    {
      id: 'view',
      label: 'Vue',
      width: 'w-[21rem]',
      entries: [
        { kind: 'header', label: 'Espace de travail (Tri-Vision)' },
        {
          kind: 'item', icon: Code2, iconClass: 'text-sky-400', mode: 'radio',
          label: 'Code AST', desc: 'Architecture & AST du code', shortcut: 'Alt+1',
          active: () => (cockpitState.viewMode as string) === 'code',
          run: () => switchViewMode('code')
        },
        {
          kind: 'item', icon: BookOpen, iconClass: 'text-emerald-400', mode: 'radio',
          label: 'Vault Notes', desc: 'Graphe de notes & wikilinks Obsidian', shortcut: 'Alt+2',
          active: () => ['vault', 'vault-notes'].includes(cockpitState.viewMode as string),
          run: () => switchViewMode('vault')
        },
        {
          kind: 'item', icon: Code, iconClass: 'text-indigo-400', mode: 'radio',
          label: 'IDE', desc: 'Environnement IDE & éditeur de code', shortcut: 'Alt+3',
          active: () => (cockpitState.viewMode as string) === 'ide',
          run: () => switchViewMode('ide')
        },
        { kind: 'header', label: 'Continuum spatial (niveau de détail)' },
        {
          kind: 'item', icon: Orbit, iconClass: 'text-sky-300', mode: 'radio', keepOpen: true,
          label: 'Z-1 Galaxie Fichiers', desc: 'Vue d\'ensemble des fichiers', shortcut: '1',
          active: () => cockpitState.activeLayout === 'Z-1',
          run: () => setLayoutLevel(1)
        },
        {
          kind: 'item', icon: Globe, iconClass: 'text-indigo-300', mode: 'radio', keepOpen: true,
          label: 'Z-2 Architecture Modules', desc: 'Regroupement par modules', shortcut: '2',
          active: () => cockpitState.activeLayout === 'Z-2',
          run: () => setLayoutLevel(2)
        },
        {
          kind: 'item', icon: Workflow, iconClass: 'text-purple-300', mode: 'radio', keepOpen: true,
          label: "Z-3 Flux DAG d'Exécution", desc: 'Graphe orienté des appels', shortcut: '3',
          active: () => cockpitState.activeLayout === 'Z-3',
          run: () => setLayoutLevel(3)
        },
        {
          kind: 'item', icon: Grid, iconClass: 'text-cyan-300', mode: 'radio', keepOpen: true,
          label: 'Z-4 Matrice UML & Classes', desc: 'Relations structurelles détaillées', shortcut: '4',
          active: () => cockpitState.activeLayout === 'Z-4',
          run: () => setLayoutLevel(4)
        },
        { kind: 'header', label: 'Modes de vision analytique' },
        {
          kind: 'item', icon: Sun, iconClass: 'text-sky-400', mode: 'radio', keepOpen: true,
          label: 'Standard', desc: 'Rendu normal du graphe', shortcut: 'V',
          active: () => cockpitState.visionMode === 'standard',
          run: () => setVision('standard')
        },
        {
          kind: 'item', icon: Eye, iconClass: 'text-indigo-400', mode: 'radio', keepOpen: true,
          label: 'X-Ray Focus', desc: 'Isoler la sélection et ses liens', shortcut: 'X',
          active: () => cockpitState.visionMode === 'xray',
          run: () => setVision('xray')
        },
        {
          kind: 'item', icon: Flame, iconClass: 'text-amber-400', mode: 'radio', keepOpen: true,
          label: 'Heatmap complexité', desc: 'Complexité cyclomatique en couleur', shortcut: 'H',
          active: () => cockpitState.visionMode === 'heatmap',
          run: () => setVision('heatmap')
        },
        {
          kind: 'item', icon: Ghost, iconClass: 'text-rose-400', mode: 'radio', keepOpen: true,
          label: 'Code mort & orphelins', desc: 'Repérer le code jamais appelé', shortcut: 'D',
          active: () => cockpitState.visionMode === 'deadcode',
          run: () => setVision('deadcode')
        },
        { kind: 'header', label: 'Caméra & moteur' },
        {
          kind: 'item', icon: Maximize2, iconClass: 'text-sky-300',
          label: 'Recadrer la caméra', desc: 'Centrer la vue sur tout le graphe', shortcut: 'F',
          run: () => cockpitState.requestCameraFit()
        },
        {
          kind: 'item', icon: Pause, iconClass: 'text-amber-300', mode: 'toggle', keepOpen: true,
          label: 'Pause physique', desc: 'Figer la gravité / simulation', shortcut: 'P',
          active: () => cockpitState.physicsPaused,
          run: () => cockpitState.togglePhysicsPaused()
        }
      ]
    },
    {
      id: 'display',
      label: 'Affichage',
      width: 'w-[21rem]',
      entries: [
        { kind: 'header', label: 'Graphe' },
        {
          kind: 'item', icon: FolderTree, iconClass: 'text-sky-400', mode: 'toggle', keepOpen: true,
          label: 'Titres dossiers', desc: 'Étiquettes de dossiers sur le graphe',
          active: () => cockpitState.settings.showFolderTitles,
          run: () => cockpitState.toggleFolderTitles()
        },
        {
          kind: 'item', icon: FolderTree, iconClass: 'text-indigo-400', mode: 'toggle', keepOpen: true,
          label: 'Membranes cellulaires', desc: 'Enveloppes des modules (allège si OFF)',
          active: () => cockpitState.settings.showFolderMembranes,
          run: () => cockpitState.toggleFolderMembranes()
        },
        {
          kind: 'item', icon: FileText, iconClass: 'text-sky-300', mode: 'toggle', keepOpen: true,
          label: 'Titres fichiers', desc: 'Nom des fichiers sur les bulles',
          active: () => cockpitState.settings.showFileTitles,
          run: () => cockpitState.toggleFileTitles()
        },
        { kind: 'header', label: 'Sécurité' },
        {
          kind: 'item', icon: ShieldAlert, iconClass: 'text-rose-400', mode: 'toggle', keepOpen: true,
          label: 'Alertes de sécurité', desc: 'Signaux des vulnérabilités détectées',
          active: () => cockpitState.settings.showAlerts,
          run: () => cockpitState.toggleAlerts()
        },
        {
          kind: 'item', icon: Target, iconClass: 'text-amber-400', mode: 'toggle', keepOpen: true,
          label: 'Bulles CWE', desc: 'Bulles de vulnérabilité sur les nœuds',
          active: () => cockpitState.settings.showCweBubbles,
          run: () => cockpitState.toggleCweBubbles()
        },
        {
          kind: 'item', icon: Tag, iconClass: 'text-purple-400', mode: 'toggle', keepOpen: true,
          label: 'Titres / Tags CWE', desc: 'Identifiants CWE affichés en clair',
          active: () => cockpitState.settings.showCweTitles,
          run: () => cockpitState.toggleCweTitles()
        },
        { kind: 'header', label: 'Copilote & IA' },
        {
          kind: 'item', icon: Activity, iconClass: 'text-cyan-400', mode: 'toggle', keepOpen: true,
          label: 'Lignes / Lasers IA', desc: "Trajectoires, faisceaux et orbites d'IA",
          active: () => cockpitState.settings.showAiLines,
          run: () => cockpitState.toggleAiLines()
        },
        {
          kind: 'item', icon: Bot, iconClass: 'text-purple-400', mode: 'toggle', keepOpen: true,
          label: 'Noms des agents IA', desc: "Badges des agents (masqués après 5 min d'inactivité)",
          active: () => cockpitState.settings.showAiNames,
          run: () => cockpitState.toggleAiNames()
        },
        { kind: 'header', label: 'Performance, radar & audio' },
        {
          kind: 'item', icon: Compass, iconClass: 'text-cyan-400', mode: 'toggle', keepOpen: true,
          label: 'Radar Minimap', desc: 'Carte de navigation en bas à droite', shortcut: 'R',
          active: () => cockpitState.showRadar,
          run: () => cockpitState.toggleRadar()
        },
        {
          kind: 'item', icon: Zap, iconClass: 'text-emerald-400', mode: 'toggle', keepOpen: true,
          label: 'Mode Éco / Petite config', desc: 'Réduit la RAM et la charge GPU',
          active: () => cockpitState.isLowMemoryMode,
          run: () => cockpitState.toggleLowMemoryMode()
        },
        {
          kind: 'item', icon: Volume2, iconClass: 'text-sky-400', mode: 'toggle', keepOpen: true,
          label: 'Son WebAudio', desc: 'Effets sonores de l\'interface',
          active: () => cockpitState.settings.soundEnabled,
          run: () => cockpitState.toggleSound()
        },
        { kind: 'sep' },
        {
          kind: 'item', icon: Settings, iconClass: 'text-sky-400',
          label: 'Configuration complète…', desc: 'Labels, exclusions AST, IA/MCP & 220 règles CWE', shortcut: 'S',
          run: () => (cockpitState.isSettingsModalOpen = true)
        }
      ]
    },
    {
      id: 'security',
      label: 'Sécurité',
      width: 'w-[21rem]',
      entries: [
        {
          kind: 'item', icon: Target, iconClass: 'text-amber-400',
          label: 'Scope & PoC Bug Bounty', desc: 'Générateur de scope / PoC Zero-Day', shortcut: 'B',
          run: () => (cockpitState.isBountyModalOpen = true)
        },
        {
          kind: 'item', icon: ShieldAlert, iconClass: 'text-rose-400',
          label: 'Audit SAST & failles CWE', desc: 'Liste des violations dans l\'inspecteur',
          badge: () => cockpitState.allViolations.length,
          run: () => {
            cockpitState.activeTab = 'cve';
            cockpitState.isInspectorOpen = true;
          }
        },
        {
          kind: 'item', icon: ShieldOff, iconClass: 'text-amber-300',
          label: 'Règles & CWE ignorées', desc: 'Gérer ou restaurer les règles masquées',
          badge: () => cockpitState.settings.ignoredCwes.length || null,
          run: () => (cockpitState.isIgnoredCweModalOpen = true)
        },
        {
          kind: 'item', icon: Radar, iconClass: 'text-cyan-400',
          label: 'Scanner de surface', desc: 'Domaine / IP : ports, requêtes HTTP, arbo HTML, flux', shortcut: 'U',
          run: () => (cockpitState.isSurfaceScannerOpen = true)
        },
        { kind: 'header', label: "Rapport d'audit global" },
        {
          kind: 'item', icon: Download, iconClass: 'text-sky-400',
          label: 'Exporter en Markdown (.md)',
          run: exportAuditMarkdown
        },
        {
          kind: 'item', icon: Download, iconClass: 'text-emerald-400',
          label: 'Exporter en HTML Dark (.html)',
          run: exportAuditHtml
        }
      ]
    },
    {
      id: 'ai',
      label: 'IA',
      width: 'w-[22rem]',
      entries: [
        { kind: 'agents' },
        {
          kind: 'item', icon: Bot, iconClass: 'text-purple-300',
          label: 'Chat IA multi-agents', desc: 'Journal Copilot, déplacements & chat', shortcut: 'C',
          active: () => cockpitState.isChatOpen,
          badge: () => cockpitState.activeAgents.length || cockpitState.aiChatMessages.length || null,
          run: () => (cockpitState.isChatOpen = !cockpitState.isChatOpen)
        },
        {
          kind: 'item', icon: Plug, iconClass: 'text-sky-400',
          label: 'Module MCP IA', desc: '10 outils & config Claude / Cursor / Antigravity',
          run: () => (cockpitState.isMcpModalOpen = true)
        },
        {
          kind: 'item', icon: Sparkles, iconClass: 'text-indigo-400',
          label: 'Générateur de prompts', desc: 'Prompt IA contextuel & master blueprint',
          run: () => cockpitState.openPromptModal('context')
        }
      ]
    },
    {
      id: 'tools',
      label: 'Outils',
      width: 'w-[21rem]',
      entries: [
        {
          kind: 'item', icon: CheckSquare, iconClass: 'text-indigo-400',
          label: 'Tableau des tâches & quêtes', desc: 'Suivi des tâches du projet',
          active: () => cockpitState.isTasksModalOpen,
          badge: () => activeTaskCount || (cockpitState.tasks.length ? `${cockpitState.tasks.length}` : null),
          run: () => (cockpitState.isTasksModalOpen = true)
        },
        {
          kind: 'item', icon: FilePlus2, iconClass: 'text-emerald-400',
          label: 'Nouveau fichier IA', desc: 'Créer un fichier et ré-indexer', shortcut: 'N',
          run: () => (cockpitState.isCreateFileModalOpen = true)
        },
        {
          kind: 'item', icon: FileText, iconClass: 'text-emerald-300',
          label: 'Documentation', desc: 'EARS & contrats BLAKE3', shortcut: 'M',
          active: () => cockpitState.isDocPanelOpen,
          run: () => cockpitState.toggleDocPanel()
        },
        {
          kind: 'item', icon: Activity, iconClass: 'text-sky-300',
          label: 'Panneau de synthèse', desc: 'Synthèse & flux de l\'écosystème',
          active: () => cockpitState.isSynthesisOpen,
          run: () => (cockpitState.isSynthesisOpen = !cockpitState.isSynthesisOpen)
        },
        {
          kind: 'item', icon: Layers, iconClass: 'text-sky-400',
          label: 'Inspecteur latéral', desc: 'Détails du nœud sélectionné', shortcut: 'I',
          active: () => cockpitState.isInspectorOpen,
          run: () => cockpitState.toggleInspector()
        },
        { kind: 'sep' },
        {
          kind: 'item', icon: Settings, iconClass: 'text-sky-400',
          label: 'Préférences', desc: 'Affichage, exclusions, 120+ règles CWE', shortcut: 'S',
          run: () => (cockpitState.isSettingsModalOpen = true)
        }
      ]
    }
  ];

  function runItem(item: MenuItem) {
    item.run();
    if (!item.keepOpen) openMenu = null;
  }

  const viewTabs = [
    { mode: 'code' as const, label: 'Code AST', icon: Code2, on: 'bg-sky-500/25 border-sky-400/40 text-sky-200', ic: 'text-sky-400', title: 'Vision 1 : Architecture & AST Code (Alt+1)' },
    { mode: 'vault' as const, label: 'Vault', icon: BookOpen, on: 'bg-emerald-500/25 border-emerald-400/40 text-emerald-200', ic: 'text-emerald-400', title: 'Vision 2 : Graphe de Notes & Wikilinks Obsidian (Alt+2)' },
    { mode: 'ide' as const, label: 'IDE', icon: Code, on: 'bg-indigo-500/25 border-indigo-400/40 text-indigo-200', ic: 'text-indigo-400', title: 'Vision 3 : Environnement IDE & Éditeur de Code (Alt+3)' }
  ];

  function isViewActive(mode: 'code' | 'vault' | 'ide') {
    const v = cockpitState.viewMode as string;
    return mode === 'vault' ? v === 'vault' || v === 'vault-notes' : v === mode;
  }
</script>

<svelte:window onkeydown={handleWindowKeyDown} onpointerdown={handleWindowPointerDown} />

<!-- Sélecteur de fichier natif (100% fiable en WebView2 & navigateur) -->
<input
  bind:this={fileImportInputEl}
  type="file"
  class="hidden"
  onchange={handleImportLocalFile}
/>

<!-- Backdrop overlay and detached portal search dropdown -->
{#if isSearchDropdownOpen}
  <div class="fixed inset-0 z-[65] bg-black/20" onclick={closeSearch} role="presentation"></div>
  <SearchDropdownPanel
    bind:query={searchQuery}
    isOpen={isSearchDropdownOpen}
    anchorEl={searchInputEl}
    onClose={closeSearch}
  />
{/if}

<!-- ========================================================================= -->
<!-- HEADER UNIQUE (1 ligne, h-11 / 44px) : Brand · Menus · Omnibox · Accès rapides -->
<!-- ========================================================================= -->
<header class="relative h-11 px-3 flex items-center gap-2 border-b border-white/10 bg-[#090b10]/95 backdrop-blur-md select-none z-50 shrink-0 shadow-lg flex-nowrap">
  <!-- Zone A : Brand & Projet actif -->
  <div class="flex items-center gap-2 shrink-0">
    <div class="flex items-center gap-1.5 font-bold text-xs tracking-tight text-white shrink-0">
      <span class="text-sky-400 text-sm">🪐</span>
      <span class="hidden md:inline bg-gradient-to-r from-sky-400 via-indigo-300 to-purple-300 bg-clip-text text-transparent font-extrabold tracking-wide whitespace-nowrap">
        AetherScope
      </span>
    </div>

    <button
      onclick={() => (cockpitState.isHubModalOpen = true)}
      title="Hub Multi-Architectures : Créer Projet (7 Stacks), Changer de Dépôt, Export HTML{cockpitState.graph.project_path ? `\n${cockpitState.graph.project_path}` : ''}"
      class="flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md font-mono bg-sky-950/60 hover:bg-sky-900/80 border border-sky-500/35 text-sky-300 max-w-[110px] lg:max-w-[170px] truncate cursor-pointer transition-colors shadow-xs"
    >
      <FolderGit2 class="w-3.5 h-3.5 shrink-0 text-sky-400" />
      <span class="truncate font-semibold">{cockpitState.graph.project_name || 'Projet'}</span>
      <span
        class="w-1.5 h-1.5 rounded-full shrink-0 {cockpitState.liveConnected ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]' : cockpitState.isDemoMode ? 'bg-cyan-400 shadow-[0_0_6px_#06b6d4]' : 'bg-slate-500'}"
        title={cockpitState.liveConnected ? `Watch Temps Réel Actif (v${cockpitState.graphVersion})` : cockpitState.isDemoMode ? 'Mode Démo Standalone WebGL (GitHub Pages)' : 'Mode Hors-Ligne / Statique'}
      ></span>
    </button>

    {#if cockpitState.isDemoMode}
      <span class="hidden 2xl:inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full font-mono font-bold tracking-wider uppercase bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_8px_rgba(6,182,212,0.25)]">
        <span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
        DÉMO LIVE
      </span>
    {/if}
  </div>

  <!-- Zone B : Barre de menus déroulants -->
  <nav bind:this={menubarEl} class="flex items-center gap-0.5 shrink-0" aria-label="Menu principal">
    {#each menus as menu (menu.id)}
      <div class="relative">
        <button
          type="button"
          onclick={() => toggleMenu(menu.id)}
          onmouseenter={() => hoverMenu(menu.id)}
          aria-haspopup="menu"
          aria-expanded={openMenu === menu.id}
          class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[12px] font-medium transition-colors cursor-pointer {openMenu === menu.id ? 'bg-white/12 text-white' : 'text-slate-300 hover:bg-white/[0.07] hover:text-white'}"
        >
          <span>{menu.label}</span>
          {#if menu.id === 'ai' && cockpitState.activeAgents.length > 0}
            <span
              class="inline-flex items-center gap-1 px-1.5 py-0.2 rounded-full bg-emerald-500/20 border border-emerald-400/45 text-emerald-300 font-mono text-[9.5px] font-bold"
              title="{cockpitState.activeAgents.length} agent(s) IA actif(s)"
            >
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              {cockpitState.activeAgents.length}
            </span>
          {/if}
        </button>

        {#if openMenu === menu.id}
          <div
            role="menu"
            class="absolute top-full left-0 mt-1 {menu.width ?? 'w-80'} max-h-[calc(100vh-64px)] overflow-y-auto bg-[#0b0f19]/98 backdrop-blur-xl border border-white/15 rounded-lg shadow-2xl p-1.5 z-[70] flex flex-col gap-0.5 text-xs"
          >
            {#each menu.entries as entry, i (i)}
              {#if entry.kind === 'header'}
                <div class="px-2 pt-2 pb-1 text-[10px] text-slate-500 font-semibold uppercase tracking-wider {i > 0 ? 'border-t border-white/[0.06] mt-1' : ''}">
                  {entry.label}
                </div>
              {:else if entry.kind === 'sep'}
                <div class="h-px bg-white/[0.08] my-1 mx-1"></div>
              {:else if entry.kind === 'agents'}
                {#if cockpitState.activeAgents.length > 0}
                  <div class="px-2 pt-1.5 pb-1 flex items-center justify-between text-[10px] text-purple-300 font-semibold uppercase tracking-wider">
                    <span class="flex items-center gap-1.5">
                      <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                      Agents IA actifs ({cockpitState.activeAgents.length})
                    </span>
                    <button
                      type="button"
                      onclick={clearAgentsFromMenu}
                      class="text-[9.5px] font-normal normal-case text-slate-400 hover:text-rose-300 px-1.5 py-0.5 rounded hover:bg-rose-500/10 cursor-pointer transition-colors"
                      title="Effacer la télémétrie agents"
                    >
                      Effacer
                    </button>
                  </div>
                  <div class="flex flex-col gap-0.5 mb-1 max-h-48 overflow-y-auto">
                    {#each cockpitState.activeAgents as ag (ag.agentId)}
                      <button
                        type="button"
                        role="menuitem"
                        onclick={() => focusAgentTarget(ag.target)}
                        class="w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-left hover:bg-white/[0.07] transition-colors cursor-pointer"
                        title="{ag.agentName} • {ag.action}: {ag.details}"
                      >
                        <span class="flex items-center gap-2 min-w-0">
                          <span class="w-2 h-2 rounded-full shrink-0" style="background-color: {ag.color}"></span>
                          <span class="min-w-0">
                            <span class="block text-[11.5px] font-semibold text-slate-100 truncate">{ag.agentName}</span>
                            {#if ag.action}
                              <span class="block text-[9.5px] text-slate-400 truncate">{ag.action}</span>
                            {/if}
                          </span>
                        </span>
                        {#if ag.target}
                          <span class="px-1.5 py-0.5 rounded bg-black/50 border border-white/10 font-mono text-[9.5px] text-sky-300 truncate max-w-[115px] shrink-0">
                            ➔ {ag.target}
                          </span>
                        {/if}
                      </button>
                    {/each}
                  </div>
                  <div class="h-px bg-white/[0.08] my-1 mx-1"></div>
                {/if}
              {:else if entry.kind === 'path'}
                <form
                  onsubmit={analyzeFolderFromBar}
                  class="flex items-center rounded-md bg-white/[0.04] border border-white/10 focus-within:border-sky-400/60 px-1 py-0.5 gap-1 mx-0.5 mb-1"
                  title="Chemin du dossier ou workspace actif (une URL ouvre le Scanner de surface)"
                >
                  <input
                    type="text"
                    bind:value={folderInput}
                    placeholder="Chemin absolu ou URL..."
                    class="flex-1 min-w-0 bg-transparent border-none outline-none text-[11px] font-mono text-slate-200 placeholder:text-slate-500 px-1 py-1"
                  />
                  <button
                    type="submit"
                    disabled={isAnalyzingBar}
                    title="Lancer l'analyse AST du dossier"
                    class="flex items-center gap-1 px-2 py-1 rounded bg-sky-500/20 hover:bg-sky-500/35 border border-sky-400/40 text-sky-200 text-[10.5px] font-semibold transition-colors cursor-pointer shrink-0 disabled:opacity-50"
                  >
                    <RefreshCw class="w-3 h-3 {isAnalyzingBar ? 'animate-spin' : ''}" />
                    {isAnalyzingBar ? '...' : 'Analyser'}
                  </button>
                </form>
                {#if fileActionError}
                  <div class="mx-1 mb-1 px-2 py-1 rounded bg-rose-500/15 border border-rose-500/35 text-[10.5px] font-mono text-rose-200">
                    {fileActionError}
                  </div>
                {/if}
              {:else}
                {@const Icon = entry.icon}
                {@const isOn = entry.active ? entry.active() : false}
                {@const badge = entry.badge ? entry.badge() : null}
                <button
                  type="button"
                  role={entry.mode === 'toggle' ? 'menuitemcheckbox' : entry.mode === 'radio' ? 'menuitemradio' : 'menuitem'}
                  aria-checked={entry.mode ? isOn : undefined}
                  onclick={() => runItem(entry)}
                  class="group flex items-center gap-2.5 px-2 py-1.5 rounded-md text-left transition-colors cursor-pointer {isOn && entry.mode !== 'toggle' ? 'bg-white/[0.07] text-white' : 'text-slate-200 hover:bg-white/10 hover:text-white'}"
                >
                  <span class="w-4 flex justify-center shrink-0">
                    {#if Icon}<Icon class="w-3.5 h-3.5 {entry.iconClass ?? 'text-slate-400'}" />{:else if entry.emoji}{entry.emoji}{/if}
                  </span>
                  <span class="flex-1 min-w-0 flex flex-col">
                    <span class="text-[12px] leading-tight">{entry.label}</span>
                    {#if entry.desc}
                      <span class="text-[10.5px] leading-tight text-slate-500 group-hover:text-slate-400 truncate">{entry.desc}</span>
                    {/if}
                  </span>
                  {#if badge !== null && badge !== undefined && badge !== 0}
                    <span class="px-1.5 rounded-full bg-indigo-500/30 border border-indigo-400/40 text-indigo-100 font-mono text-[10px] font-bold shrink-0">{badge}</span>
                  {/if}
                  {#if entry.shortcut}
                    <kbd class="shrink-0 px-1 py-0.5 text-[9.5px] font-mono rounded bg-white/[0.06] text-slate-400 border border-white/10">{entry.shortcut}</kbd>
                  {/if}
                  {#if entry.mode === 'toggle'}
                    <span class="shrink-0 w-8 text-center text-[9.5px] font-bold py-0.5 rounded {isOn ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-white/5 text-slate-500 border border-transparent'}">
                      {isOn ? 'ON' : 'OFF'}
                    </span>
                  {:else if entry.mode === 'radio'}
                    <span class="shrink-0 w-3 h-3 rounded-full border flex items-center justify-center {isOn ? 'border-sky-400' : 'border-white/20'}">
                      {#if isOn}<span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span>{/if}
                    </span>
                  {/if}
                </button>
              {/if}
            {/each}
          </div>
        {/if}
      </div>
    {/each}
  </nav>

  <!-- Zone C : Omnibox Recherche Globale -->
  <div class="relative flex items-center justify-center flex-1 min-w-[140px] max-w-lg mx-1 z-50">
    <div class="w-full flex items-center justify-between gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] hover:bg-white/[0.07] focus-within:bg-white/[0.08] border border-white/10 focus-within:border-sky-400/60 transition-all shadow-xs group">
      <Search class="w-3.5 h-3.5 shrink-0 text-slate-400 group-focus-within:text-sky-400 transition-colors" />
      <input
        bind:this={searchInputEl}
        type="text"
        bind:value={searchQuery}
        onfocus={openSearch}
        onclick={openSearch}
        placeholder="Rechercher fonctions, appels, fichiers, CWE..."
        class="flex-1 min-w-0 bg-transparent border-none outline-none text-xs text-white placeholder-slate-500 font-mono"
      />
      {#if searchQuery}
        <button
          type="button"
          onclick={() => { searchQuery = ''; searchInputEl?.focus(); }}
          class="text-slate-400 hover:text-white text-xs px-1 cursor-pointer"
          title="Effacer"
        >
          <X class="w-3.5 h-3.5" />
        </button>
      {/if}
      <kbd class="hidden sm:inline-block shrink-0 px-1.5 py-0.5 text-[9.5px] font-mono rounded bg-white/10 text-slate-300 border border-white/10">⌘K</kbd>
    </div>
  </div>

  <!-- Zone D : Accès rapides (les plus utilisés, aussi présents dans les menus) -->
  <div class="flex items-center gap-1.5 shrink-0">
    <!-- Tri-Vision : Code AST / Vault / IDE -->
    <div class="flex items-center bg-white/[0.04] border border-white/10 rounded-md p-0.5 gap-0.5">
      {#each viewTabs as tab (tab.mode)}
        <button
          onclick={() => switchViewMode(tab.mode)}
          title={tab.title}
          class="flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-semibold border transition-colors cursor-pointer {isViewActive(tab.mode) ? tab.on : 'border-transparent text-slate-400 hover:text-white'}"
        >
          <tab.icon class="w-3 h-3 {tab.ic}" />
          <span class="hidden xl:inline">{tab.label}</span>
        </button>
      {/each}
    </div>

    <!-- Métriques graphe -->
    <div
      class="hidden 2xl:flex items-center gap-2 px-2 py-1 rounded-md bg-white/[0.03] border border-white/10 font-mono text-[11px] text-slate-300"
      title="Nombre de symboles et dépendances dans le graphe"
    >
      <span class="flex items-center gap-1">
        <span class="w-2 h-2 rounded-full bg-sky-400"></span>
        <span>{cockpitState.graph.nodes.length} nœuds</span>
      </span>
      <span class="text-white/20">|</span>
      <span class="text-slate-400">{cockpitState.graph.edges.length} liens</span>
    </div>

    <!-- Moteur : recadrer / pause -->
    <div class="hidden lg:flex items-center p-0.5 bg-white/[0.03] border border-white/10 rounded-md gap-0.5">
      <button
        onclick={() => cockpitState.requestCameraFit()}
        title="Recadrer la vue caméra sur le graphe (F)"
        class="p-1 rounded text-slate-400 hover:text-sky-300 hover:bg-white/10 transition-colors cursor-pointer"
      >
        <Maximize2 class="w-3.5 h-3.5" />
      </button>
      <button
        onclick={() => cockpitState.togglePhysicsPaused()}
        title={cockpitState.physicsPaused ? 'Reprendre la simulation physique (P)' : 'Mettre en pause la gravité/physique (P)'}
        class="p-1 rounded transition-colors cursor-pointer {cockpitState.physicsPaused ? 'bg-amber-500/25 text-amber-300' : 'text-slate-400 hover:text-white hover:bg-white/10'}"
      >
        {#if cockpitState.physicsPaused}<Play class="w-3.5 h-3.5" />{:else}<Pause class="w-3.5 h-3.5" />{/if}
      </button>
    </div>

    <!-- Failles CWE -->
    <button
      onclick={() => { cockpitState.activeTab = 'cve'; cockpitState.isInspectorOpen = true; }}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold bg-rose-500/12 hover:bg-rose-500/24 border border-rose-500/35 text-rose-300 transition-colors shadow-xs cursor-pointer"
      title="Audit SAST & Failles CWE ({cockpitState.allViolations.length} violations détectées)"
    >
      <ShieldAlert class="w-3.5 h-3.5 text-rose-400" />
      <span class="font-mono text-[11px] font-bold">{cockpitState.allViolations.length}</span>
    </button>

    <!-- Chat IA -->
    <button
      onclick={() => (cockpitState.isChatOpen = !cockpitState.isChatOpen)}
      class="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-semibold border transition-all shadow-xs cursor-pointer {cockpitState.isChatOpen ? 'bg-purple-600/40 border-purple-400 text-purple-100 shadow-[0_0_12px_rgba(168,85,247,0.35)]' : 'bg-purple-500/20 hover:bg-purple-500/30 border-purple-400/45 text-purple-200'}"
      title="Journal Copilot IA, Déplacements & Chat Multi-Agents (Touche C)"
    >
      <Bot class="w-3.5 h-3.5 text-purple-300" />
      <span class="hidden lg:inline">Chat IA</span>
      {#if cockpitState.activeAgents.length > 0}
        <span class="px-1.5 rounded-full bg-emerald-500/30 border border-emerald-400/50 text-emerald-200 font-mono text-[10px] font-bold" title="Agents simultanés">
          {cockpitState.activeAgents.length}
        </span>
      {:else if cockpitState.aiChatMessages.length > 0}
        <span class="px-1.5 rounded-full bg-purple-400/30 text-purple-100 font-mono text-[10px]">
          {cockpitState.aiChatMessages.length}
        </span>
      {/if}
    </button>

    <!-- Inspecteur -->
    <button
      onclick={() => cockpitState.toggleInspector()}
      class="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold transition-colors shadow-xs cursor-pointer {cockpitState.isInspectorOpen ? 'bg-sky-500/25 border border-sky-400 text-sky-200 shadow-[0_0_10px_rgba(56,189,248,0.3)]' : 'bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-300'}"
      title="Inspecteur Latéral (I)"
    >
      <Layers class="w-3.5 h-3.5" />
      <span class="hidden xl:inline">Inspecteur</span>
    </button>

    <!-- Son -->
    <button
      type="button"
      onclick={() => cockpitState.toggleSound()}
      class="p-1.5 rounded-md transition-colors cursor-pointer border {cockpitState.settings.soundEnabled ? 'bg-sky-500/15 hover:bg-sky-500/25 border-sky-500/35 text-sky-300' : 'bg-white/[0.03] hover:bg-white/[0.07] border-white/10 text-slate-500'}"
      title={cockpitState.settings.soundEnabled ? "Couper l'audio WebAudio (Mute 1-Clic)" : "Activer l'audio WebAudio (Unmute 1-Clic)"}
    >
      {#if cockpitState.settings.soundEnabled}<Volume2 class="w-3.5 h-3.5" />{:else}<VolumeX class="w-3.5 h-3.5" />{/if}
    </button>

    <!-- Préférences -->
    <button
      onclick={() => (cockpitState.isSettingsModalOpen = true)}
      class="p-1.5 rounded-md bg-white/[0.04] hover:bg-white/10 border border-white/10 text-slate-200 transition-colors cursor-pointer shadow-xs"
      title="Préférences Cockpit (Affichage, Exclusions, 120+ Règles CWE) (S)"
    >
      <Settings class="w-3.5 h-3.5 text-sky-400" />
    </button>
  </div>
</header>
