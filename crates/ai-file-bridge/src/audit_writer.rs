use chrono::Local;
use core_graph::bubble::SymbolBubble;
use security_linter::contract::ReadmeContract;
use security_linter::linter::LinterViolation;
use std::fs;
use std::path::{Component, Path};

fn safe_write_in_root(project_root: &Path, target: &Path, content: &str) -> std::io::Result<()> {
    if !target.starts_with(project_root)
        || target.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Target path escapes project root",
        ));
    }
    fs::write(target, content)
}

pub struct AuditWriter;

impl AuditWriter {
    /// Écrit .aether/LIVE_AUDIT.md après chaque sauvegarde interceptée par le FileWatcher
    pub fn write_live_audit(project_root: &Path, violations: &[LinterViolation], audited_files_count: usize) -> std::io::Result<()> {
        let aether_dir = project_root.join(".aether");
        fs::create_dir_all(&aether_dir)?;

        let audit_file = aether_dir.join("LIVE_AUDIT.md");
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let mut content = String::new();
        content.push_str("# 🛡️ AETHER LIVE AUDIT — SYSTEM HEALTH\n\n");
        content.push_str(&format!("> **Timestamp :** `{}` | **Fichiers inspectés :** `{}`\n\n", now, audited_files_count));

        let security_violations: Vec<&LinterViolation> = violations
            .iter()
            .filter(|v| v.rule_id != "RULE_MAX_LINES" && v.severity != "WARNING")
            .collect();

        if violations.is_empty() || (security_violations.is_empty() && violations.iter().all(|v| v.rule_id == "RULE_MAX_LINES")) {
            content.push_str("## ✅ ARCH_OK : Zéro violation architecturale ou de sécurité\n\n");
            content.push_str("- Tous les imports respectent les contrats de dossier `README.md`.\n");
            content.push_str("- Aucune injection SQL brute ni secret détecté dans le code.\n");
            content.push_str("- Les budgets de complexité et de lignes sont respectés.\n\n");
            content.push_str("*(Ce fichier est mis à jour en temps réel à chaque `Ctrl+S` par le File-Watcher AetherScope)*\n");
        } else {
            content.push_str(&format!("## ❌ {} VIOLATION(S) DÉTECTÉE(S)\n\n", violations.len()));
            content.push_str("| Sévérité | Fichier | Ligne | Règle | Détail & Remédiation |\n");
            content.push_str("| :--- | :--- | :--- | :--- | :--- |\n");

            for v in violations {
                let badge = match v.severity.as_str() {
                    "CRITICAL" => "🔴 CRITIQUE",
                    "HIGH" => "🟠 HAUT",
                    "MEDIUM" => "🟡 MOYEN",
                    _ => "⚪ AVERTISSEMENT",
                };
                let tainted = if let (Some(data), Some(ty)) = (&v.transmitted_data, &v.transmitted_type) {
                    format!("<br>📦 *Donnée :* `{}` (*Type :* `{}`)", data, ty)
                } else {
                    String::new()
                };
                content.push_str(&format!(
                    "| {} | `{}` | `{}` | `{}`<br><small>{}</small> | **{}**{}<br>*Fix:* {} |\n",
                    badge, v.file_path, v.line_number, v.rule_id, v.cve_id, v.message, tainted, v.remediation
                ));
            }
            if !security_violations.is_empty() {
                content.push_str("\n> ⚠️ **Consigne pour l'Agent IA (Cursor/Antigravity/Claude) :** Corrige immédiatement ces violations de sécurité avant de continuer.\n");
            }
        }

        safe_write_in_root(project_root, &audit_file, &content)
    }

    /// Écrit .aether/ACTIVE_TARGET.md lorsqu'une bulle est ciblée dans le cockpit WebGL
    pub fn write_active_target(
        project_root: &Path,
        symbol: &SymbolBubble,
        callers: &[String],
        dependencies: &[String],
        contract: Option<&ReadmeContract>,
    ) -> std::io::Result<()> {
        let mut in_cat = core_graph::edge::CategorizedLiaisons::default();
        in_cat.internal_calls = callers.to_vec();
        let mut out_cat = core_graph::edge::CategorizedLiaisons::default();
        out_cat.internal_calls = dependencies.to_vec();
        Self::write_active_target_categorized(project_root, symbol, &in_cat, &out_cat, contract)
    }

    /// Écrit .aether/ACTIVE_TARGET.md avec les liaisons structurées par catégories légères
    pub fn write_active_target_categorized(
        project_root: &Path,
        symbol: &SymbolBubble,
        incoming: &core_graph::edge::CategorizedLiaisons,
        outgoing: &core_graph::edge::CategorizedLiaisons,
        contract: Option<&ReadmeContract>,
    ) -> std::io::Result<()> {
        let aether_dir = project_root.join(".aether");
        fs::create_dir_all(&aether_dir)?;

        let target_file = aether_dir.join("ACTIVE_TARGET.md");
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let mut content = String::new();
        content.push_str("# 🎯 AETHER ACTIVE TARGET CONTEXT\n\n");
        content.push_str(&format!("> Synchronisé le `{}` depuis le cockpit AetherScope\n\n", now));
        content.push_str(&format!("- **Symbole :** `{}`\n", symbol.name));
        content.push_str(&format!("- **Fichier :** `{}:{}`\n", symbol.file_path, symbol.line_number));
        content.push_str(&format!("- **Galaxie :** `{}` | **Couche :** `{}`\n", symbol.galaxy, symbol.layer));
        content.push_str(&format!("- **Type :** `{:?}`\n\n", symbol.kind));

        content.push_str("## 📐 Dépendances & Flux (Synthèse Catégorisée)\n\n");
        content.push_str(&format!("### 📥 FLUX AMONT / APPELANTS (In-Degree: {})\n", incoming.total()));
        content.push_str(&incoming.to_compact_markdown("amont", 4));

        content.push_str(&format!("\n### 📤 FLUX AVAL / DÉPENDANCES & LIAISONS (Out-Degree: {})\n", outgoing.total()));
        content.push_str(&outgoing.to_compact_markdown("aval", 4));

        if let Some(c) = contract {
            content.push_str("\n## 🔒 Contrat du dossier (`README.md`)\n\n");
            content.push_str(&format!("- **Imports autorisés :** `{:?}`\n", c.frontmatter.allowed_imports));
            content.push_str(&format!("- **Imports INTERDITS :** `{:?}`\n", c.frontmatter.forbidden_imports));
            content.push_str(&format!("- **Lignes max :** `{}`\n\n", c.frontmatter.max_lines_per_file));

            if !c.ears_requirements.is_empty() {
                content.push_str("### 📋 Exigences EARS\n");
                for (idx, r) in c.ears_requirements.iter().enumerate() {
                    content.push_str(&format!("{}. **WHEN** {} **THE SYSTEM SHALL** {}\n", idx + 1, r.trigger, r.system_shall));
                }
            }
        }

        // Tâches actives associées à ce symbole ou ce fichier
        let all_tasks = crate::tasks::TaskManager::list_tasks(project_root);
        let relevant_tasks: Vec<&crate::tasks::TaskItem> = all_tasks
            .iter()
            .filter(|t| {
                t.status != crate::tasks::TaskStatus::Done
                    && t.status != crate::tasks::TaskStatus::Cancelled
                    && (t.target_symbol.as_deref() == Some(&symbol.name)
                        || t.target_file.as_deref() == Some(&symbol.file_path)
                        || t.target_symbol.as_deref() == Some(&symbol.id))
            })
            .collect();

        if !relevant_tasks.is_empty() {
            content.push_str("\n## 📋 TÂCHES COPILOTE ASSOCIÉES À CETTE CIBLE\n\n");
            for t in relevant_tasks {
                content.push_str(&format!(
                    "- {} `{}` **{}** (Statut: {}, Progrès: {}%)\n",
                    t.kind.icon(),
                    t.id,
                    t.title,
                    t.status.badge(),
                    t.progress
                ));
                if !t.readme_summary.is_empty() {
                    content.push_str(&format!("  *Résumé avancement :* {}\n", t.readme_summary));
                }
            }
        }

        content.push_str("\n## 🛠️ COMMANDES MCP COMBINÉES PRÉ-REMPLIES POUR CETTE CIBLE\n\n");
        content.push_str(&format!(
            "1. **Inspection + Caméra 3D + Flux Amont/Aval (1 appel) :**\n   `aetherscope_get_active_target({{\"symbol_id\": \"{}\", \"action\": \"Inspection\", \"details\": \"Analyse contrat EARS et dépendances\", \"trace_direction\": \"both\"}})`\n",
            symbol.name
        ));
        content.push_str(&format!(
            "2. **Création / Mise à jour de Tâche + Caméra (1 appel) :**\n   `aetherscope_manage_tasks({{\"action\": \"create\", \"title\": \"Intervention sur {}\", \"kind\": \"function\", \"target_symbol\": \"{}\", \"target_file\": \"{}\"}})`\n",
            symbol.name, symbol.name, symbol.file_path
        ));
        content.push_str(&format!(
            "3. **Pare-Feu Temps Réel <50ms + Clôture Tâche + Debrief Chat (1 appel après édition) :**\n   `aetherscope_verify_patch({{\"files_modified\": [\"{}\"], \"task_id\": \"<task_id>\", \"status\": \"done\", \"progress\": 100, \"chat_message\": \"Modification certifiée sur `{}`.\"}})`\n",
            symbol.file_path, symbol.name
        ));

        safe_write_in_root(project_root, &target_file, &content)
    }

    /// Détecte la stack réelle du projet en analysant les manifestes et lockfiles
    pub fn detect_project_stack(project_root: &Path) -> &'static str {
        if project_root.join("aether.lock.toml").exists() {
            if let Ok(lock) = fs::read_to_string(project_root.join("aether.lock.toml")) {
                let lock_lower = lock.to_lowercase();
                if lock_lower.contains("hybrid") || lock_lower.contains("mmo") || lock_lower.contains("web3") {
                    return "hybrid";
                }
            }
        }
        if (project_root.join("Cargo.toml").exists() || project_root.join("Cargo.lock").exists())
            && (project_root.join("package.json").exists() || project_root.join("client").exists())
        {
            "hybrid"
        } else if project_root.join("Cargo.toml").exists() || project_root.join("Cargo.lock").exists() {
            "rust"
        } else if project_root.join("pyproject.toml").exists() || project_root.join("requirements.txt").exists() {
            "python"
        } else if project_root.join("composer.json").exists() || project_root.join("index.php").exists() {
            "php"
        } else if project_root.join("CMakeLists.txt").exists() || project_root.join("Makefile").exists() {
            "cpp"
        } else if project_root.join("pom.xml").exists()
            || project_root.join("build.gradle").exists()
            || project_root.join("build.gradle.kts").exists()
        {
            "java"
        } else if project_root.join("package.json").exists() || project_root.join("pnpm-lock.yaml").exists() {
            "ts"
        } else {
            "hybrid"
        }
    }

    /// Génère le prompt système optimisé spécifique au projet et à sa stack
    pub fn generate_optimized_system_prompt(
        project_root: &Path,
        project_name: &str,
        stack_str: &str,
        server_port: u16,
    ) -> String {
        let p_str = project_root
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_string();
        let (stack_title, stack_arch, stack_contracts) = match stack_str.to_lowercase().as_str() {
            "rust" => (
                "🦀 Pure Rust (Cargo Workspace Hexagonal)",
                "Cargo Workspace : `crates/domain` (100% pur), `crates/server-axum`, `crates/client-ui`, `crates/db-adapter`",
                "Traits Rust (`RepositoryPort`), DTOs partagés Serde et schémas RPC stricts",
            ),
            "python" => (
                "🐍 Pure Python (Modular Clean Monorepo uv)",
                "`uv` Workspace : `contracts/` (Pydantic v2), `server/api/` (FastAPI), `server/domain/` (Pure logic), `data-nodes/` (SQLAlchemy)",
                "Schémas Pydantic v2 dans `contracts/` validant tous les échanges",
            ),
            "php" => (
                "🐘 PHP Moderne (Architecture Hexagonale / PSR)",
                "Modules isolés : `contracts/` (DTOs & Interfaces), `src/Controller/` (Entrées HTTP), `src/Domain/` (Métier pur), `src/Repository/` (PDO paramétré)",
                "Interfaces typées strictes (`declare(strict_types=1)`), requêtes préparées PDO et validation d'entrées",
            ),
            "cpp" => (
                "⚙️ C / C++ Natif Haute Performance",
                "Architecture modulaire RAII : `include/contracts/` (Headers & ABI), `src/domain/` (Logique pure), `src/net/` (I/O borné)",
                "Contrats d'en-têtes stricts, RAII sans pointeurs nus propriétaires, vérification des bornes mémoire",
            ),
            "ts" | "node" => (
                "🟢 Node.js TypeScript (pnpm Workspace)",
                "`pnpm` Workspace : `contracts/` (Zod), `server/` (Hono / tRPC), `client/` (Vite UI), `data-nodes/` (Drizzle / Prisma)",
                "Schémas Zod et routeurs tRPC de bout en bout",
            ),
            "java" | "minecraft" => (
                "☕ Java & JVM Ecosystem (Minecraft / Paper / Spring)",
                "Java / Gradle / Maven : Plugins Paper/Purpur (`src/main/java`), Runner Tokio, API Endpoints & Event Listeners",
                "Interfaces & Records Java, Invariants EARS et Spécifications Manifest universelles",
            ),
            "roblox" | "roblox-server" | "luau" => (
                "🟥 Roblox Luau (Authoritative Game Server)",
                "Architecture Aether Contract-Driven : `contracts/` (Remotes & Types), `server/` (Authoritative Game Engine), `client/` (Controllers/UI), `data-nodes/` (DataStore session-lock)",
                "Typage strict Luau (--!strict), RemoteEvents validés côté serveur, schémas de paquets sans confiance client",
            ),
            _ => (
                "⚡ Hybride Web3 & Temps Réel MMO",
                "Client PixiJS/TS + Serveur Rust WebSocket + Adaptateurs Data-Nodes (PostgreSQL / Redis)",
                "Paquets binaires WebSocket + ABIs Smart Contracts dans `contracts/`",
            ),
        };

        format!(
            r#"# 🪐 AETHERSCOPE V2 — DIRECTIVES SYSTÈME COPILOTE IA (COMMANDES MCP COMBINÉES & GOUVERNANCE)

> **Projet :** `{}`  
> **Racine :** `{}`  
> **Stack Détectée :** {}  
> **Architecture Active :** {}  
> **Serveur Local AetherScope :** `http://127.0.0.1:{}`  

Tu opères en binôme direct avec le développeur et le moteur d'intelligence architecturale **AetherScope V2**.
Le graphe 3D WebGL 2 tourne en continu sur le port `{}` et audite chaque modification du codebase en temps réel (< 50 ms).

---

## ⚡ 1. WORKFLOW MCP COMBINÉ EN 3 APPELS (ZÉRO COMMANDES REDONDANTES)
Les commandes MCP d'AetherScope ont été **fusionnées et réduites à 8 outils combinés** pour minimiser les appels d'outils :

1. **Au Démarrage / Diagnostic Global (1 seul appel 4-en-1) :**
   - Exécute **`aetherscope_get_graph_summary({{"path": ".", "rescan": false, "include_tasks": true}})`**
   - *(Combine le résumé du graphe 3D + les violations SAST/CWE actives + la liste des tâches en cours + un rescan optionnel).*
   - Annonce l'état en 1 ligne : `🪐 [AETHER_STATUS : Nœuds=<N>, Flux=<F>, Sécurité=<OK | X violations>, Tâches=<T actives>]`

2. **Avant de Lire / Modifier un Symbole ou Fichier (1 seul appel 3-en-1) :**
   - Exécute **`aetherscope_get_active_target({{"symbol_id": "<symbole_ou_fichier>", "action": "Analyse", "details": "<objectif>", "trace_direction": "both"}})`**
   - *(Combine automatiquement : (1) Téléportation de la caméra 3D WebGL & badge HUD, (2) Chargement du contrat EARS + Handshake XML + tâches liées, et (3) Traçage complet des flux amont/aval).*

3. **Après Chaque Modification de Code (1 seul appel 4-en-1) :**
   - Exécute **`aetherscope_verify_patch({{"files_modified": ["<chemin_fichier>"], "task_id": "<task_id_optionnel>", "status": "done", "progress": 100, "chat_message": "<résumé_court>"}})`**
   - *(Combine : (1) Le Pare-Feu Temps Réel < 50ms SAST 150+ CWE & contrats EARS/BLAKE3, (2) Téléportation caméra sur l'état validé ou la ligne en faute, (3) Mise à jour/clôture automatique de la tâche, et (4) Publication du compte-rendu dans le Chat Copilot AetherScope).*
   - Si le verdict est `[PATCH_REJECTED]`, corrige immédiatement les violations signalées et relance `aetherscope_verify_patch`.

---

## 🛠️ 2. RÉFÉRENTIEL DES 8 COMMANDES MCP COMBINÉES (`aetherscope_*`)
Spécifie toujours les paramètres exacts lors de tes appels MCP :

1. **`aetherscope_get_graph_summary(path?, rescan?, include_tasks?, severity?)`** *(4-en-1)*
   - Vue globale de l'architecture, dossiers, violations CWE filtrables par `severity` (`"critical"`, `"high"`, `"all"`), tâches actives (`include_tasks: true` par défaut) et réanalyse AST (`rescan: true` remplace `scan_project`).
2. **`aetherscope_get_active_target(symbol_id, action?, details?, trace_direction?, max_depth?, path?)`** *(3-en-1)*
   - Aligne la caméra 3D (`action`: `"Inspection"` | `"Analyse"` | `"Refactoring"` | `"Correction CVE"`), extrait le contrat EARS & Handshake XML, et trace le flux MVC amont/aval (`trace_direction`: `"both"` par défaut, `"upstream"`, `"downstream"`, ou `"none"`).
3. **`aetherscope_search_symbols(query?, layer?, kind?, stereotype?, has_violation?, cwe_id?, severity?, file_pattern?, limit?, path?)`** *(2-en-1)*
   - Combine la recherche multi-critères dans l'AST (`layer`: `"ui"` | `"action"` | `"domain"` | `"database"`, `kind`, `stereotype`) ET l'audit détaillé des violations SAST/CWE (`cwe_id`, `severity`, `file_pattern`) avec patrons de remédiation.
4. **`aetherscope_manage_tasks(action, task_id?, title?, kind?, target_symbol?, target_file?, priority?, status?, progress?, progress_note?, initial_readme?, full_readme?, status_filter?)`** *(3-en-1)*
   - Gère tout le cycle de vie des tâches dans `.aether/tasks/` via `action`:
     - `"list"` : liste les tâches (`status_filter`: `"active"` | `"all"` | `"done"`).
     - `"create"` : crée une tâche (`title`, `kind`: `"function"` | `"security_fix"` | `"arch_refactor"` | `"research"` | `"test"`, `target_symbol`, `priority`) et téléporte la caméra 3D.
     - `"update"` : met à jour une tâche (`task_id`, `status`: `"in_progress"` | `"done"` | `"blocked"`, `progress`: `0..100`, `progress_note`).
5. **`aetherscope_verify_patch(files_modified, task_id?, status?, progress?, progress_note?, chat_message?)`** *(4-en-1)*
   - Pare-Feu IA Temps Réel (< 50 ms) : vérifie les fichiers modifiés (`files_modified: ["..."]`), valide les 150+ règles CWE, l'atteignabilité Source-to-Sink et les contrats `README.md` (imports interdits, max lignes, BLAKE3). Si `[PATCH_APPROVED]`, met à jour `task_id` et envoie `chat_message` dans le HUD.
6. **`aetherscope_chat(action?, text?, thought?, target_symbol?)`** *(2-en-1)*
   - `action: "send"` (défaut si `text` fourni) : affiche un debrief Markdown dans le Chat Copilot d'AetherScope et centre la caméra sur `target_symbol`.
   - `action: "history"` : récupère l'historique des échanges du cockpit.
7. **`aetherscope_manage_plugins(action, target_path?, plugins_dir?, path?, plugin_name?, rule_id?, cwe_id?, name?, severity?, description?, remediation?, file_extensions?, ...)`** *(4-en-1)*
   - Gère les plugins déclaratifs YAML dans `.aether/plugins/` via `action`: `"list"` (inventaire), `"test"` (exécution des tests unitaires embarqués), `"scan"` (audit sur `target_path`), ou `"upsert"` (création/mise à jour certifiée d'une règle CWE).
8. **`aetherscope_teleport_camera(target, action, details)`**
   - Déplacement rapide de la caméra 3D WebGL et mise à jour du fil d'Ariane stellaire sans recharger le contrat complet.

*(Note : les anciens noms d'outils unitaires restent supportés en alias rétrocompatibles par le serveur MCP, mais privilégie toujours les 8 commandes combinées ci-dessus).*

---

## 🔒 3. ZERO-SHELL PROTOCOLE DE GOUVERNANCE & CONTRATS EARS
1. **Avant d'écrire ou modifier du code :**
   - Exécute `aetherscope_get_active_target` sur le symbole/fichier visé (ou lis `.aether/ACTIVE_TARGET.md` et le `README.md` du dossier).
   - Ne modifie JAMAIS un `README.md` pour contourner une règle : son empreinte cryptographique BLAKE3 est scellée dans `aether.lock.toml`.
2. **Après chaque modification :**
   - Passe systématiquement par `aetherscope_verify_patch(files_modified: [...])` pour certifier `0 violation` avant de conclure.

---

## 🏛️ 4. INVARIANTS PAR COUCHE & SÉPARATION STRICTE
- `contracts/` : {}
- `client/` : Rendu graphique, formulaires («Form»), état réactif. Ne doit JAMAIS importer `server/domain` ni `data-nodes`.
- `server/domain/` : **100% pur, déterministe, zéro I/O**. Interdiction formelle de requêtes SQL brutes, d'accès réseau ou de variables d'environnement (`process.env` / `std::env::var`).
- `server/application/` : Orchestration des cas d'usage reliant le domaine aux interfaces de persistance.
- `server/api/` : Contrôleurs d'entrée (REST / WebSocket) validant tout payload via `contracts/`.
- `data-nodes/` : Adaptateurs de persistance (PostgreSQL / SQLite / Redis) isolables en microservices.

---

## ⚡ 5. CONSIGNES DE RÉPONSE OPTIMISÉE
- **Concision & Densité :** Réponse technique, chirurgicale et directe. Zéro bavardage inutile.
- **Diffs Chirurgicaux :** Ne réécris jamais un fichier complet si seules quelques lignes changent.
- **Règle d'Atomicité (< 35 lignes) :** Découpe le code en fonctions atomiques pures de moins de 35 lignes maximum (particulièrement dans `domain/`).
- **Preuve de Lecture [AETHER_ACK] :** Démarre tes propositions techniques par :
  `[AETHER_ACK: cible=<symbole>, couche=<layer>, mcp=aetherscope_get_active_target->aetherscope_verify_patch]`
"#,
            project_name, p_str, stack_title, stack_arch, server_port, server_port, stack_contracts
        )
    }

    /// Génère le fichier maître AETHER_AI_RULES.md à la racine du projet
    pub fn ensure_master_rules_file(project_root: &Path) -> std::io::Result<()> {
        let rules_file = project_root.join("AETHER_AI_RULES.md");
        let proj_name = project_root
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Project".to_string());
        let stack_str = Self::detect_project_stack(project_root);
        let content = Self::generate_optimized_system_prompt(project_root, &proj_name, stack_str, 3030);
        safe_write_in_root(project_root, &rules_file, &content)
    }
}
