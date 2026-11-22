# Introduction

Découvrez comment `aether-engine` réunit visualisation spatiale du code, audit statique de sécurité et garde-fous IA dans un seul moteur local.

## Qu'est-ce que `aether-engine` ?

`aether-engine` (nommé **AetherScope** dans l'interface Cockpit et **AetherSAST** dans les workflows de sécurité) analyse vos fichiers sources localement sans jamais transmettre votre code propriétaire vers des serveurs externes. Il construit en mémoire un graphe de dépendances et d'appels (`AetherGraph`), superpose les diagnostics de sécurité et d'architecture sur les symboles, puis expose le tout via une fenêtre WebGL 2, une API HTTP locale, un CLI CI/CD et un serveur MCP natif pour agents IA.

Que vous souhaitiez auditer un dépôt pour détecter des failles CWE, encadrer un assistant IA sur des modules critiques ou explorer un projet polyglotte inconnu ou un coffre Obsidian, `aether-engine` offre aux humains comme aux agents une cartographie partagée et déterministe.

## Vue d'ensemble des sous-systèmes

* **Scanner AST et graphe d'appels polyglotte (`ast-scanner`, `core-graph`)** : Parcourt les fichiers en parallèle avec Rayon, extrait les symboles (`SymbolBubble`) et les appels (`AffiliationEdge`), calcule 4 dispositions spatiales déterministes (`Z-1` à `Z-4`) et met en cache les analyses incrémentales dans `.aether/cache/ast/`.
* **SAST, Taint et SCA atteignable (`security-linter`)** : Évalue **247 règles** (`223` règles natives réparties en 52 catégories plus `24` règles Semgrep OWASP/CWE embarquées, incluant `28` détecteurs inédits `AETHER-*`). Le masquage lexical double passe (`AuditContext`) ignore les commentaires et littéraux sur les règles non littérales pour réduire les faux positifs, tandis que l'analyse SSA (`DataflowGraph`) et le SCA OSV.dev (`--sca`) distinguent les risques atteignables du code mort.
* **Gouvernance BLAKE3 et EARS (`contract.rs`, `aether.lock.toml`)** : Lit le frontmatter YAML et les clauses EARS (`WHEN ... THE SYSTEM SHALL ...`) dans les fichiers `README.md` des dossiers, scelle leurs empreintes BLAKE3 dans `aether.lock.toml` et signale toute altération (`BLAKE3_TAMPERED`) ou violation de contrat (`RULE_MAX_LINES`, `RULE_FORBIDDEN_IMPORT`).
* **Pont IA et pare-feu `<50ms` (`ai-file-bridge`, `aetherscope-mcp`)** : Conditionne le contexte chirurgical d'une cible dans un bloc XML `<aether_handshake version="2.1">`, suit les tâches dans `.aether/tasks/` et vérifie les patchs des agents en moins de 50 ms grâce à `PatchVerifier`.
* **Confinement de sécurité (`LocalGuard`, `PathGuard`, `SecretGuard`, `SecretMasker`)** : Restreint l'API HTTP aux hôtes loopback, bloque la traversée de répertoires (CWE-22), interdit l'accès aux fichiers `.env`/clés SSH/certificats et masque 12 familles de secrets.
* **Extensibilité et IDE Cockpit (`desktop-shell`, `plugins`)** : Prend en charge le rechargement à chaud de plugins SAST/Taint DSL v2 en YAML, des shaders WebGL 2 personnalisés, un IDE multi-onglets plein écran, l'export HTML autonome (`viewer.rs`), le générateur multi-stack (`arch-templates`) et la plateforme Minecraft externe AetherCraft (`apps/aethercraft/`).

## Langages supportés par le scanner (11 langages)

Le scanner polyglotte (`crates/ast-scanner/src/scanner.rs`) analyse les 11 langages suivants :

| # | Langage | Extensions reconnues | Comportement et nuances du scanner |
|---|---|---|---|
| 1 | **Rust** | `.rs` | Ignore `*_test.rs`, `*_tests.rs`, `*_check.rs` et `build.rs` ; `AuditContext` tronque les blocs `#[cfg(test)]` en ligne pour le SAST. |
| 2 | **JavaScript / TypeScript** | `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs` | Ignore les fichiers `.min.js`, `.bundle.js` et `.d.ts`. |
| 3 | **Python** | `.py` | Ignoré automatiquement lors de l'analyse d'un projet centré Rust (`Cargo.toml` / `crates/`). |
| 4 | **C / C++** | `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx`, `.inl` | Ignoré automatiquement lors de l'analyse d'un projet centré Rust (`Cargo.toml` / `crates/`). |
| 5 | **Solidity / Yul** | `.sol`, `.yul` | Le budget de lignes par défaut passe à `600` lignes sauf surcharge dans `README.md`. |
| 6 | **PHP** | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps` | Inclut des règles de sécurité PHP dédiées (`php_rules.rs`). |
| 7 | **Java** | `.java` | Extrait les routes Spring `@GetMapping`..`@RequestMapping` et les événements Minecraft `@EventHandler` ; budget par défaut de `10 000` lignes. |
| 8 | **Lua / Luau** | `.lua`, `.luau` | Prend en charge les conventions de projets Roblox/Luau. |
| 9 | **Zig** | `.zig` | Inclut des règles dédiées à la sûreté mémoire Zig (`zig_rules.rs`). |
| 10 | **C#** | `.cs` | Extrait les endpoints ASP.NET `[HttpGet]`..`[Route]` et Minimal API `MapGet`..`MapPatch` (`csharp_rules.rs`). |
| 11 | **Markdown (Contrats)** | `README.md` uniquement | Le scanner de code ignore tout `.md` autre que `README.md` et n'exécute pas de SAST sur `.md`. L'indexation complète des coffres `.md` est assurée par `obsidian-vault`. |

{% hint style="info" %}
`ast-scanner` ignore les fichiers `.md` autres que `README.md` afin que votre documentation ne pollue jamais les graphes d'appels de code et ne génère pas de faux positifs SAST.
{% endhint %}

## Classification automatique des projets (Dual-Vision)

Avant le scan, `obsidian_vault::detect_project_type` recherche les dossiers `.obsidian/` (profondeur maximale 2), compte les fichiers source face aux fichiers Markdown et échantillonne jusqu'à 10 fichiers Markdown (64 Ko maximum chacun) pour détecter la syntaxe Obsidian (liens wiki, transclusions de notes/médias, étiquettes imbriquées `#tag/subtag` et frontmatter). Trois modes en découlent :

* **`PureCode`** : Dépôt logiciel classique analysé par `ProjectScanner`.
* **`PureObsidianVault`** : Base de connaissances analysée par `scan_obsidian_vault` en bulles `«Note»`, `«Attachment»` et `«GhostNote»`.
* **`Mixed`** : Dépôt contenant à la fois du code et un coffre Obsidian. Les deux graphes sont générés et vous basculez instantanément dans le Cockpit avec `Alt+V`.

## Quatre modes d'exécution

1. **GUI Desktop (par défaut)** : Ouvre une fenêtre native `tao`/`wry` WebView2 adossée au serveur Axum local (`127.0.0.1:3030`) et à `FileWatcherBridge`.
2. **Serveur HTTP headless (`--no-gui`)** : Démarre exactement la même API REST Axum, le flux SSE temps réel et l'interface WebGL 2 embarquée pour un navigateur externe, sans fenêtre native.
3. **Audit CLI et CI/CD (`--audit-only`, `--format sarif`, `--sca`, `--benchmark`)** : Exécute une passe SAST, SCA OSV.dev, export SARIF v2.1.0, porte qualité `--fail-on` ou benchmark de performance, puis rend la main.
4. **Serveur MCP natif (`--mcp` ou `aetherscope-mcp`)** : Parle JSON-RPC 2.0 (`2024-11-05`) sur `stdin`/`stdout` pour Claude Desktop, Cursor et les agents Gemini/Antigravity.

## Étapes suivantes

{% content-ref url="architecture-overview.md" %}
[Vue d'ensemble de l'architecture](architecture-overview.md)
{% endcontent-ref %}

{% content-ref url="getting-started/installation.md" %}
[Installation](getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="getting-started/quickstart.md" %}
[Démarrage rapide](getting-started/quickstart.md)
{% endcontent-ref %}
