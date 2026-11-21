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
    Compass,
    Palette,
    Menu as MenuIcon,
    ChevronDown
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

  // Menu responsive (écrans compacts / tablettes / fenêtres réduites)
  let isResponsiveMenuOpen = $state(false);
  let responsiveActiveMenuId = $state<string>('file');
  let responsiveMenuEl = $state<HTMLElement | null>(null);

  function closeAllMenus() {
    openMenu = null;
    isResponsiveMenuOpen = false;
  }

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
        await cockpitState.syncProjectStatus().catch(() => {});
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
        await cockpitState.syncProjectStatus().catch(() => {});
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

  async function switchViewMode(mode: 'graph' | 'code' | 'vault' | 'ide') {
    const res = await cockpitState.switchToMode(mode);
    if (!res.ok && res.message) {
      console.warn('Bascule viewMode:', res.message);
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
    closeAllMenus();
  }

  function closeSearch() {
    isSearchDropdownOpen = false;
  }

  function handleWindowKeyDown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      closeAllMenus();
      searchInputEl?.focus();
      isSearchDropdownOpen = true;
      return;
    }
    if (e.key === 'Escape') {
      if (openMenu || isResponsiveMenuOpen) {
        closeAllMenus();
      }
    }
  }

  function handleWindowPointerDown(e: PointerEvent) {
    if (openMenu && menubarEl && !menubarEl.contains(e.target as Node)) {
      openMenu = null;
    }
    if (isResponsiveMenuOpen && responsiveMenuEl && !responsiveMenuEl.contains(e.target as Node)) {
      isResponsiveMenuOpen = false;
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
    /** Affiche l'entrée uniquement si la condition retourne true */
    when?: () => boolean;
    run: () => void;
  };
  function focusAgentTarget(targetName: string) {
    if (!targetName) return;
    const hit = cockpitState.resolveTargetNode(targetName);
    if (hit) {
      cockpitState.selectSymbol(hit.id, true);
    }
    closeAllMenus();
  }

  async function clearAgentsFromMenu() {
    await api.clearTelemetry().catch(() => {});
    cockpitState.clearAiTrail();
    closeAllMenus();
  }

  type MenuEntry =
    | MenuItem
    | { kind: 'header'; label: string; when?: () => boolean }
    | { kind: 'sep' }
    | { kind: 'path' }
    | { kind: 'agents' }
    | { kind: 'visuals' };
  type Menu = {
    id: string;
    label: string;
    icon?: any;
    iconClass?: string;
    width?: string;
    entries: MenuEntry[];
  };

  const menus: Menu[] = [
    {
      id: 'file',
      label: 'Fichier',
      icon: FolderGit2,
      iconClass: 'text-sky-400',
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
      icon: Orbit,
      iconClass: 'text-indigo-400',
      width: 'w-[21rem]',
      entries: [
        { kind: 'header', label: 'Espace de travail (Graph | IDE)' },
        {
          kind: 'item', icon: Orbit, iconClass: 'text-sky-400', mode: 'radio',
          label: 'Graph', desc: 'Architecture AST & Obsidian Vault adaptatif', shortcut: 'Alt+1',
          active: () => cockpitState.isGraphView,
          run: () => switchViewMode('graph')
        },
        {
          kind: 'item', icon: Code, iconClass: 'text-indigo-400', mode: 'radio',
          label: 'IDE', desc: 'Environnement IDE & éditeur de code', shortcut: 'Alt+2',
          active: () => cockpitState.viewMode === 'ide',
          run: () => switchViewMode('ide')
        },
        {
          kind: 'header', label: 'Source du graphe (projet mixte)',
          when: () => cockpitState.isMixedProject
        },
        {
          kind: 'item', icon: Code2, iconClass: 'text-sky-400', mode: 'radio',
          label: 'Code AST', desc: 'Architecture & AST du code', shortcut: 'Alt+V',
          when: () => cockpitState.isMixedProject,
          active: () => cockpitState.viewMode === 'code',
          run: () => switchViewMode('code')
        },
        {
          kind: 'item', icon: BookOpen, iconClass: 'text-emerald-400', mode: 'radio',
          label: 'Vault Notes', desc: 'Graphe de notes & wikilinks Obsidian', shortcut: 'Alt+V',
          when: () => cockpitState.isMixedProject,
          active: () => cockpitState.viewMode === 'vault-notes',
          run: () => switchViewMode('vault')
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
      icon: Layers,
      iconClass: 'text-cyan-400',
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
        { kind: 'header', label: 'Thème WebGL (Plugins Visuels)' },
        { kind: 'visuals' },
        {
          kind: 'item', icon: Palette, iconClass: 'text-cyan-400',
          label: 'Studio Visuels & Shaders GLSL…', desc: 'Créer, éditer et tester des shaders WebGL en direct',
          run: () => cockpitState.openPluginsModal('visuals')
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
      icon: ShieldAlert,
      iconClass: 'text-rose-400',
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
          kind: 'item', icon: Plug, iconClass: 'text-purple-400',
          label: 'Centre Plugins SAST, Taint & WebGL', desc: 'Catalogue YAML, DSL v2, Taint SSA, Playground & Shaders', shortcut: 'G',
          run: () => cockpitState.openPluginsModal('plugins')
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
      id: 'plugins',
      label: 'Plugins',
      icon: Plug,
      iconClass: 'text-purple-400',
      width: 'w-[22rem]',
      entries: [
        { kind: 'header', label: 'Centre Plugins SAST & Taint YAML' },
        {
          kind: 'item', icon: Plug, iconClass: 'text-purple-400',
          label: 'Catalogue Plugins SAST & OWASP', desc: 'Activer/désactiver, éditer, exporter YAML & bundle 24 règles', shortcut: 'G',
          run: () => cockpitState.openPluginsModal('plugins')
        },
        {
          kind: 'item', icon: FilePlus2, iconClass: 'text-emerald-400',
          label: 'Éditeur Règle DSL v2', desc: 'Créer ou éditer une règle (ast_scope, fenêtre N lignes, tests)',
          run: () => cockpitState.openPluginsModal('create')
        },
        {
          kind: 'item', icon: Workflow, iconClass: 'text-cyan-400',
          label: 'Taint Dataflow SSA', desc: 'Sources, Sinks & Sanitizers inter-procéduraux par plugin',
          run: () => cockpitState.openPluginsModal('taint')
        },
        {
          kind: 'item', icon: Zap, iconClass: 'text-amber-400',
          label: 'Bac à Sable (Playground Live)', desc: 'Tester vos règles SAST en temps réel sur un snippet de code',
          run: () => cockpitState.openPluginsModal('playground')
        },
        {
          kind: 'item', icon: Upload, iconClass: 'text-sky-400',
          label: 'Importateur Semgrep (.yaml)', desc: 'Convertir un fichier ou snippet Semgrep OSS en plugin AetherScope',
          run: () => cockpitState.openPluginsModal('semgrep')
        },
        { kind: 'header', label: 'Thèmes & Shaders WebGL 2 (Hot-Swap)' },
        { kind: 'visuals' },
        {
          kind: 'item', icon: Palette, iconClass: 'text-cyan-400',
          label: 'Studio Visuels & Shaders GLSL…', desc: 'Éditeur de palettes 7 couches, membranes & GLSL ES 3.00',
          run: () => cockpitState.openPluginsModal('visuals')
        }
      ]
    },
    {
      id: 'ai',
      label: 'IA',
      icon: Bot,
      iconClass: 'text-emerald-400',
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
      icon: CheckSquare,
      iconClass: 'text-amber-400',
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
    if (!item.keepOpen) closeAllMenus();
  }

  const activeResponsiveMenu = $derived(
    menus.find((m) => m.id === responsiveActiveMenuId) || menus[0]
  );

  const isVaultGraphActive = $derived(
    cockpitState.hasVaultView &&
      (cockpitState.viewMode === 'vault-notes' ||
        (cockpitState.viewMode === 'ide' && cockpitState.lastGraphMode === 'vault-notes') ||
        cockpitState.projectType === 'PureObsidianVault')
  );

  const graphTabTitle = $derived(
    cockpitState.projectType === 'PureObsidianVault'
      ? 'Graph : Obsidian Vault & Notes (Alt+1)'
      : cockpitState.isMixedProject
        ? `Graph : ${isVaultGraphActive ? 'Obsidian Vault' : 'Code AST'} — projet mixte (Alt+1 · Alt+V pour basculer)`
        : 'Graph : Architecture & AST Code (Alt+1)'
  );
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

<!-- Backdrop overlay for responsive dropdown -->
{#if isResponsiveMenuOpen}
  <div class="fixed inset-0 z-[68] bg-black/40 backdrop-blur-[1px]" onclick={() => (isResponsiveMenuOpen = false)} role="presentation"></div>
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

  <!-- Snippet de rendu unifié des entrées de menu (Desktop & Responsive) -->
  {#snippet renderMenuEntries(entries: MenuEntry[])}
    {#each entries as entry, i (i)}
      {#if entry.kind === 'header'}
        {#if !entry.when || entry.when()}
          <div class="px-2 pt-2 pb-1 text-[10px] text-slate-500 font-semibold uppercase tracking-wider {i > 0 ? 'border-t border-white/[0.06] mt-1' : ''}">
            {entry.label}
          </div>
        {/if}
      {:else if entry.kind === 'sep'}
        <div class="h-px bg-white/[0.08] my-1 mx-1"></div>
      {:else if entry.kind === 'visuals'}
        <div class="flex flex-col gap-0.5 px-1 pb-1">
          {#each cockpitState.allVisualPlugins as vp (vp.id)}
            {@const isActiveVp = cockpitState.activeVisualPluginId === vp.id}
            <button
              type="button"
              role="menuitemradio"
              aria-checked={isActiveVp}
              onclick={() => cockpitState.selectVisualPlugin(vp.id, true)}
              class="w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-left transition-colors cursor-pointer {isActiveVp ? 'bg-cyan-500/15 text-white border border-cyan-400/35' : 'text-slate-200 hover:bg-white/10 border border-transparent'}"
            >
              <span class="flex items-center gap-2 min-w-0">
                <span class="flex items-center -space-x-1 shrink-0">
                  {#each (vp.palette?.background || ['#04050b', '#0ea5e9', '#a855f7']).slice(0, 3) as sw}
                    <span class="w-2.5 h-2.5 rounded-full border border-black/60" style="background-color: {sw}"></span>
                  {/each}
                </span>
                <span class="min-w-0">
                  <span class="block text-[11.5px] font-medium truncate">{vp.name}</span>
                  <span class="block text-[9.5px] text-slate-400 truncate">
                    {vp.overlay?.membrane_style || 'organic'} · {vp.overlay?.edge_style || 'bezier'}{vp.builtin ? '' : ' · custom'}
                  </span>
                </span>
              </span>
              <span class="shrink-0 w-3 h-3 rounded-full border flex items-center justify-center {isActiveVp ? 'border-cyan-400' : 'border-white/20'}">
                {#if isActiveVp}<span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>{/if}
              </span>
            </button>
          {/each}
        </div>
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
      {:else if !entry.when || entry.when()}
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
  {/snippet}

  <!-- Zone B - Responsive : Menu déroulant compact pour écrans < xl (tablettes, laptops, fenêtres réduites) -->
  <div class="relative xl:hidden shrink-0" bind:this={responsiveMenuEl}>
    <button
      type="button"
      onclick={() => { isResponsiveMenuOpen = !isResponsiveMenuOpen; openMenu = null; }}
      aria-haspopup="menu"
      aria-expanded={isResponsiveMenuOpen}
      class="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[12px] font-semibold transition-all cursor-pointer border {isResponsiveMenuOpen ? 'bg-sky-500/25 border-sky-400/50 text-white shadow-[0_0_10px_rgba(56,189,248,0.3)]' : 'bg-white/[0.06] hover:bg-white/10 border-white/10 text-slate-200'}"
      title="Menu principal & outils"
    >
      <MenuIcon class="w-3.5 h-3.5 text-sky-400 shrink-0" />
      <span class="hidden sm:inline">Menu</span>
      {#if cockpitState.activeAgents.length > 0}
        <span
          class="inline-flex items-center gap-1 px-1.5 py-0.2 rounded-full bg-emerald-500/20 border border-emerald-400/45 text-emerald-300 font-mono text-[9px] font-bold"
          title="{cockpitState.activeAgents.length} agent(s) IA actif(s)"
        >
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          {cockpitState.activeAgents.length}
        </span>
      {/if}
      <ChevronDown class="w-3 h-3 text-slate-400 transition-transform duration-200 {isResponsiveMenuOpen ? 'rotate-180 text-sky-400' : ''}" />
    </button>

    {#if isResponsiveMenuOpen}
      <div
        role="menu"
        class="absolute top-full left-0 mt-1.5 w-[92vw] sm:w-[500px] md:w-[560px] max-w-[560px] max-h-[calc(100vh-64px)] overflow-hidden bg-[#090d16]/98 backdrop-blur-2xl border border-white/15 rounded-xl shadow-2xl z-[75] flex flex-col text-xs"
      >
        <!-- En-tête du menu responsive -->
        <div class="px-3 py-2 border-b border-white/10 flex items-center justify-between bg-white/[0.03]">
          <div class="flex items-center gap-2">
            <span class="text-sky-400 text-sm">🪐</span>
            <span class="font-bold text-white tracking-wide text-[12px]">Menu & Outils</span>
            {#if cockpitState.isDemoMode}
              <span class="text-[9.5px] px-1.5 py-0.2 rounded font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-400/30">
                DÉMO
              </span>
            {/if}
          </div>
          <button
            type="button"
            onclick={() => (isResponsiveMenuOpen = false)}
            class="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
            title="Fermer (Échap)"
          >
            <X class="w-4 h-4" />
          </button>
        </div>

        <!-- Barre d'onglets catégories avec défilement horizontal fluide -->
        <div class="flex items-center gap-1 px-2 py-1.5 border-b border-white/10 overflow-x-auto no-scrollbar bg-black/40 shrink-0">
          {#each menus as menu (menu.id)}
            {@const Icon = menu.icon}
            {@const isActive = responsiveActiveMenuId === menu.id}
            {@const badge = menu.id === 'security' && cockpitState.allViolations.length > 0
              ? cockpitState.allViolations.length
              : menu.id === 'ai' && cockpitState.activeAgents.length > 0
                ? cockpitState.activeAgents.length
                : menu.id === 'tools' && activeTaskCount > 0
                  ? activeTaskCount
                  : null}
            <button
              type="button"
              onclick={() => (responsiveActiveMenuId = menu.id)}
              class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium shrink-0 transition-all cursor-pointer {isActive ? 'bg-sky-500/20 text-white border border-sky-400/40 shadow-xs' : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent'}"
            >
              {#if Icon}<Icon class="w-3.5 h-3.5 {menu.iconClass}" />{/if}
              <span>{menu.label}</span>
              {#if badge !== null}
                <span class="px-1.5 py-0.2 rounded-full text-[9px] font-mono font-bold {menu.id === 'security' ? 'bg-rose-500/30 text-rose-200 border border-rose-400/40' : menu.id === 'ai' ? 'bg-emerald-500/30 text-emerald-200 border border-emerald-400/40' : 'bg-indigo-500/30 text-indigo-200 border border-indigo-400/40'}">
                  {badge}
                </span>
              {/if}
            </button>
          {/each}
        </div>

        <!-- Contenu de la catégorie active -->
        <div class="p-2 max-h-[52vh] overflow-y-auto flex flex-col gap-0.5">
          {#if activeResponsiveMenu}
            {@render renderMenuEntries(activeResponsiveMenu.entries)}
          {/if}
        </div>

        <!-- Barre basse : Accès rapides compacts intégrés -->
        <div class="px-3 py-2 border-t border-white/10 bg-black/50 flex items-center justify-between text-[11px] text-slate-400 shrink-0">
          <!-- Switch Graph / IDE -->
          <div class="flex items-center bg-white/[0.04] p-0.5 rounded-md border border-white/10">
            <button
              type="button"
              onclick={() => { switchViewMode('graph'); closeAllMenus(); }}
              class="flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-semibold transition-colors {cockpitState.isGraphView ? 'bg-sky-500/25 text-sky-200 border border-sky-400/40' : 'text-slate-400 hover:text-white border border-transparent'}"
            >
              <Orbit class="w-3 h-3 text-sky-400" />
              <span>Graph</span>
            </button>
            <button
              type="button"
              onclick={() => { switchViewMode('ide'); closeAllMenus(); }}
              class="flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-semibold transition-colors {cockpitState.viewMode === 'ide' ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-400/40' : 'text-slate-400 hover:text-white border border-transparent'}"
            >
              <Code class="w-3 h-3 text-indigo-400" />
              <span>IDE</span>
            </button>
          </div>

          <!-- Outils rapides caméra, pause, son, préférences -->
          <div class="flex items-center gap-1">
            <button
              type="button"
              onclick={() => cockpitState.requestCameraFit()}
              class="p-1.5 rounded-md hover:bg-white/10 text-slate-300 hover:text-sky-300 transition-colors cursor-pointer"
              title="Recadrer la caméra (F)"
            >
              <Maximize2 class="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onclick={() => cockpitState.togglePhysicsPaused()}
              class="p-1.5 rounded-md transition-colors cursor-pointer {cockpitState.physicsPaused ? 'bg-amber-500/25 text-amber-300' : 'hover:bg-white/10 text-slate-300 hover:text-white'}"
              title="Pause physique (P)"
            >
              {#if cockpitState.physicsPaused}<Play class="w-3.5 h-3.5" />{:else}<Pause class="w-3.5 h-3.5" />{/if}
            </button>
            <button
              type="button"
              onclick={() => cockpitState.toggleSound()}
              class="p-1.5 rounded-md transition-colors cursor-pointer {cockpitState.settings.soundEnabled ? 'text-sky-300 bg-sky-500/15' : 'text-slate-500 hover:bg-white/10'}"
              title="Son WebAudio"
            >
              {#if cockpitState.settings.soundEnabled}<Volume2 class="w-3.5 h-3.5" />{:else}<VolumeX class="w-3.5 h-3.5" />{/if}
            </button>
            <button
              type="button"
              onclick={() => { cockpitState.isSettingsModalOpen = true; closeAllMenus(); }}
              class="p-1.5 rounded-md hover:bg-white/10 text-slate-300 hover:text-sky-300 transition-colors cursor-pointer"
              title="Préférences (S)"
            >
              <Settings class="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    {/if}
  </div>

  <!-- Zone B - Desktop : Barre de menus classique (≥ xl) -->
  <nav bind:this={menubarEl} class="hidden xl:flex items-center gap-0.5 shrink-0" aria-label="Menu principal">
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
            {@render renderMenuEntries(menu.entries)}
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
    <!-- Bi-Vision : Graph (AST / Vault adaptatif) | IDE -->
    <div class="flex items-center bg-white/[0.04] border border-white/10 rounded-md p-0.5 gap-0.5">
      <button
        type="button"
        onclick={() => switchViewMode('graph')}
        title={graphTabTitle}
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border transition-colors cursor-pointer {cockpitState.isGraphView ? (isVaultGraphActive ? 'bg-emerald-500/25 border-emerald-400/40 text-emerald-200' : 'bg-sky-500/25 border-sky-400/40 text-sky-200') : 'border-transparent text-slate-400 hover:text-white'}"
      >
        {#if isVaultGraphActive}
          <BookOpen class="w-3 h-3 text-emerald-400" />
        {:else}
          <Orbit class="w-3 h-3 text-sky-400" />
        {/if}
        <span class="hidden md:inline">Graph</span>
      </button>

      {#if cockpitState.isMixedProject && cockpitState.isGraphView}
        <button
          type="button"
          onclick={() => switchViewMode(isVaultGraphActive ? 'code' : 'vault')}
          title={isVaultGraphActive ? 'Projet mixte : passer au graphe Code AST (Alt+V)' : 'Projet mixte : passer au graphe Obsidian Vault (Alt+V)'}
          class="flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border transition-colors cursor-pointer {isVaultGraphActive ? 'bg-emerald-500/15 border-emerald-400/35 text-emerald-300 hover:bg-emerald-500/25' : 'bg-sky-500/15 border-sky-400/35 text-sky-300 hover:bg-sky-500/25'}"
        >
          {isVaultGraphActive ? 'Vault' : 'AST'}
        </button>
      {/if}

      <button
        type="button"
        onclick={() => switchViewMode('ide')}
        title="Environnement IDE & Éditeur de Code (Alt+2)"
        class="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border transition-colors cursor-pointer {cockpitState.viewMode === 'ide' ? 'bg-indigo-500/25 border-indigo-400/40 text-indigo-200' : 'border-transparent text-slate-400 hover:text-white'}"
      >
        <Code class="w-3 h-3 text-indigo-400" />
        <span class="hidden md:inline">IDE</span>
      </button>
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

    <!-- Centre Plugins SAST, Taint & Studio WebGL -->
    <button
      onclick={() => cockpitState.openPluginsModal('plugins')}
      class="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-semibold border transition-all shadow-xs cursor-pointer {cockpitState.isPluginsModalOpen ? 'bg-cyan-500/30 border-cyan-400 text-cyan-100 shadow-[0_0_12px_rgba(6,182,212,0.35)]' : 'bg-cyan-500/12 hover:bg-cyan-500/22 border-cyan-500/35 text-cyan-200'}"
      title="Centre Plugins SAST, Taint SSA, Playground DSL v2 & Studio Shaders WebGL (Touche G)"
    >
      <Plug class="w-3.5 h-3.5 text-cyan-400" />
      <span class="hidden xl:inline">Plugins</span>
      <span
        class="w-2 h-2 rounded-full border border-black/50 shrink-0"
        style="background-color: {cockpitState.activeVisualPluginPack.palette?.background?.[1] || '#0ea5e9'}"
        title="Thème WebGL actif : {cockpitState.activeVisualPluginPack.name}"
      ></span>
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
      class="hidden md:flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold transition-colors shadow-xs cursor-pointer {cockpitState.isInspectorOpen ? 'bg-sky-500/25 border border-sky-400 text-sky-200 shadow-[0_0_10px_rgba(56,189,248,0.3)]' : 'bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-300'}"
      title="Inspecteur Latéral (I)"
    >
      <Layers class="w-3.5 h-3.5" />
      <span class="hidden xl:inline">Inspecteur</span>
    </button>

    <!-- Son -->
    <button
      type="button"
      onclick={() => cockpitState.toggleSound()}
      class="hidden sm:flex p-1.5 rounded-md transition-colors cursor-pointer border {cockpitState.settings.soundEnabled ? 'bg-sky-500/15 hover:bg-sky-500/25 border-sky-500/35 text-sky-300' : 'bg-white/[0.03] hover:bg-white/[0.07] border-white/10 text-slate-500'}"
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
