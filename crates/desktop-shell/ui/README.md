---
id: desktop-shell-ui
layer: ui
max_lines_per_file: 3000
allowed_imports: ["svelte::*", "@lucide/svelte::*", "../state::*", "../lib::*", "../engine::*", "../types::*"]
forbidden_imports: ["fs::*", "child_process::*"]
security_rules:
  no_raw_sql: true
  no_env_access: true
---
# 🎨 desktop-shell-ui — Cockpit Spatial Svelte 5 Runes & WebGL 2 (v2.4.0)

Interface utilisateur réactive du cockpit **AetherScope v2.4.0**, construite avec **Svelte 5 Runes (`$state`, `$derived`, `$effect`)**, **TypeScript**, **Tailwind CSS v4** et **Vite 8 (`vite-plugin-singlefile`)**. Compilée en un bundle HTML autonome unique (`../dist/index.html`) embarqué dans `aether-engine.exe`.

## 📦 Contenu

| Dossier / Fichier | Rôle |
| :--- | :--- |
| `src/App.svelte` | Orchestrateur racine, raccourcis clavier globaux et montage des tiroirs/modales |
| `src/state/graphState.svelte.ts` | Store réactif Svelte 5 Runes (`CockpitState`), filtres, télémétrie Git et contrats BLAKE3 |
| `src/engine/engine.ts` | Moteur de rendu hybride WebGL 2 instancié 120 FPS + Canvas 2D vectoriel (bulles, halos oranges/rouges, lasers) |
| `src/engine/physics.worker.ts` | Simulation physique off-thread (répulsion de Coulomb, ressorts de Hooke, membranes à 12 lobes) |
| `src/lib/api.ts` | Client REST typé (`AetherAPI`) incluant `/api/contracts/update`, `/api/contracts/sign` et `/api/git/status` |
| `src/components/InspectorDrawer.svelte` | Inspecteur 4 onglets + Éditeur de contrat BLAKE3 en direct (fichier `file_max_lines` & dossier `max_lines_per_file`) |
| `src/components/DocReaderDrawer.svelte` | Lecteur/Éditeur Markdown GitHub-grade, diagrammes Mermaid, coloration syntaxique et sceau BLAKE3 |
| `src/components/SynthesisHud.svelte` | Tiroir de synthèse architecturale (filtres de couches, alertes SAST rouges et budgets de lignes oranges) |
| `src/components/CanvasTooltip.svelte` | Infobulle spatiale temps réel avec statut de contrat BLAKE3 et budgets de lignes |
| `src/components/GitDiffModal.svelte` | Visualiseur Git Diff côte-à-côte et unifié |

## 🛡️ Règles EARS

- WHEN the graph is rendered THE SYSTEM SHALL display `RULE_MAX_LINES` budget warnings in orange (`#f97316`) and security/CWE violations in red (`#ef4444`).
- WHEN the user updates a file or folder line budget in the Inspector THE SYSTEM SHALL call `POST /api/contracts/update` to seal the new contract with BLAKE3 and refresh the graph.
- IF a file of this folder exceeds `max_lines_per_file` (or its `file_max_lines` override) THEN THE SYSTEM SHALL report a `RULE_MAX_LINES` warning.
