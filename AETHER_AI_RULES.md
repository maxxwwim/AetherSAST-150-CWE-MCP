# 🪐 AETHERSCOPE V2 — DIRECTIVES SYSTÈME COPILOTE IA (COMMANDES MCP COMBINÉES & GOUVERNANCE)

> **Projet :** `aether-engine`  
> **Racine :** `.` (workspace Cargo racine)  
> **Stack Détectée :** 🦀 Pure Rust (Cargo Workspace Hexagonal — 7 Crates) + Cockpit UI Svelte 5 / WebGL 2  
> **Architecture Active :** `crates/core-graph`, `crates/security-linter`, `crates/arch-templates`, `crates/ast-scanner`, `crates/obsidian-vault`, `crates/ai-file-bridge`, `crates/desktop-shell` (+ `ui/` Svelte 5)  
> **Serveur Local AetherScope :** `http://127.0.0.1:3030`  

Tu opères en binôme direct avec le développeur et le moteur d'intelligence architecturale **AetherScope V2**.
Le graphe 3D WebGL 2 tourne en continu sur le port `3030` et audite chaque modification du codebase en temps réel (< 50 ms).

---

## ⚡ 1. WORKFLOW MCP COMBINÉ EN 3 APPELS (ZÉRO COMMANDES REDONDANTES)
Les commandes MCP d'AetherScope sont **consolidées en 10 outils combinés** pour minimiser les appels d'outils :

1. **Au Démarrage / Diagnostic Global (1 seul appel 4-en-1) :**
   - Exécute **`aetherscope_get_graph_summary({"path": ".", "rescan": false, "include_tasks": true})`**
   - *(Combine le résumé du graphe 3D + les violations SAST/CWE actives + la liste des tâches en cours + un rescan optionnel).*
   - Annonce l'état en 1 ligne : `🪐 [AETHER_STATUS : Nœuds=<N>, Flux=<F>, Sécurité=<OK | X violations>, Tâches=<T actives>]`

2. **Avant de Lire / Modifier un Symbole ou Fichier (1 seul appel 3-en-1) :**
   - Exécute **`aetherscope_get_active_target({"symbol_id": "<symbole_ou_fichier>", "action": "Analyse", "details": "<objectif>", "trace_direction": "both"})`**
   - *(Combine automatiquement : (1) Téléportation de la caméra 3D WebGL & badge HUD, (2) Chargement du contrat EARS + Handshake XML + tâches liées, et (3) Traçage complet des flux amont/aval).*

3. **Après Chaque Modification de Code (1 seul appel 4-en-1) :**
   - Exécute **`aetherscope_verify_patch({"files_modified": ["<chemin_fichier>"], "task_id": "<task_id_optionnel>", "status": "done", "progress": 100, "chat_message": "<résumé_court>"})`**
   - *(Combine : (1) Le Pare-Feu Temps Réel < 50ms SAST 222+ règles CWE/AETHER-* & contrats EARS/BLAKE3 + `SecretGuard`, (2) Téléportation caméra sur l'état validé ou la ligne en faute, (3) Mise à jour/clôture automatique de la tâche, et (4) Publication du compte-rendu dans le Chat Copilot AetherScope).*
   - Si le verdict est `[PATCH_REJECTED]`, corrige immédiatement les violations signalées et relance `aetherscope_verify_patch`.

---

## 🛠️ 2. RÉFÉRENTIEL DES 10 COMMANDES MCP COMBINÉES (`aetherscope_*`)
Spécifie toujours les paramètres exacts lors de tes appels MCP :

1. **`aetherscope_get_graph_summary(path?, rescan?, include_tasks?, severity?)`** *(4-en-1)*
   - Vue globale de l'architecture, dossiers, classification Obsidian Vault, violations CWE filtrables par `severity` (`"critical"`, `"high"`, `"all"`), tâches actives (`include_tasks: true` par défaut) et réanalyse AST (`rescan: true`).
2. **`aetherscope_get_active_target(symbol_id, action?, details?, trace_direction?, max_depth?, path?)`** *(3-en-1)*
   - Aligne la caméra 3D (`action`: `"Inspection"` | `"Analyse"` | `"Refactoring"` | `"Correction CVE"`), extrait le contrat EARS & Handshake XML, et trace le flux amont/aval (`trace_direction`: `"both"` par défaut, `"upstream"`, `"downstream"`, ou `"none"`).
3. **`aetherscope_search_symbols(query?, layer?, kind?, stereotype?, has_violation?, cwe_id?, severity?, file_pattern?, limit?, path?)`** *(2-en-1)*
   - Combine la recherche multi-critères dans l'AST (`layer`: `"ui"` | `"action"` | `"domain"` | `"database"`, `kind`, `stereotype`) ET l'audit détaillé des violations SAST/CWE (`cwe_id`, `severity`, `file_pattern`) avec patrons de remédiation.
4. **`aetherscope_switch_view_mode(mode, path?)`**
   - Permute instantanément la visualisation 3D entre `"code"` (topologie AST) et `"vault"` (graphe de connaissances Obsidian).
5. **`aetherscope_manage_tasks(action, task_id?, title?, kind?, target_symbol?, target_file?, priority?, status?, progress?, progress_note?, initial_readme?, full_readme?, status_filter?)`** *(4-en-1)*
   - Gère tout le cycle de vie des tâches dans `.aether/tasks/` via `action`: `"list"`, `"create"`, `"update"` ou `"delete"`.
6. **`aetherscope_verify_patch(files_modified, task_id?, status?, progress?, progress_note?, chat_message?)`** *(4-en-1)*
   - Pare-Feu IA Temps Réel (< 50 ms) : vérifie les fichiers modifiés (`files_modified: ["..."]`), valide les 222+ règles CWE/AETHER-*, la protection `SecretGuard`, l'atteignabilité Source-to-Sink et les contrats `README.md` (imports interdits, max lignes, BLAKE3). Si `[PATCH_APPROVED]`, met à jour `task_id` et envoie `chat_message` dans le HUD.
7. **`aetherscope_chat(action?, text?, thought?, target_symbol?)`** *(2-en-1)*
   - `action: "send"` (défaut si `text` fourni) : affiche un debrief Markdown dans le Chat Copilot d'AetherScope et centre la caméra sur `target_symbol`.
   - `action: "history"` : récupère l'historique des échanges du cockpit.
8. **`aetherscope_manage_plugins(action, target_path?, plugins_dir?, path?, plugin_name?, enabled?, profile?, tags?, rule_id?, cwe_id?, name?, severity?, description?, remediation?, file_extensions?, not_preceded_within_lines?, in_path_matching?, not_in_path_matching?, ast_scope?, taint_sources?, taint_sinks?, sanitizers?, ...)`** *(6-en-1)*
   - Gère les plugins déclaratifs YAML (DSL v2 & Taint SSA) dans `.aether/plugins/` via `action`: `"list"` (inventaire), `"test"` (exécution des tests unitaires embarqués), `"scan"` (audit confiné `PathGuard` sur `target_path`), `"upsert"` (création/mise à jour certifiée d'une règle DSL v2/taint), `"toggle"` (activer/désactiver un plugin), ou `"init_bundle"` (déployer les 24 règles communautaires OWASP/CWE).
9. **`aetherscope_teleport_camera(target, action, details)`**
   - Déplacement rapide de la caméra 3D WebGL et mise à jour du fil d'Ariane stellaire sans recharger le contrat complet.
10. **`aetherscope_scan_project(path?)`**
    - Déclenche un rescan AST/SAST parallèle complet du projet cible et rafraîchit le graphe.

*(Note : les anciens noms d'outils unitaires restent supportés en alias rétrocompatibles par le serveur MCP, mais privilégie toujours les 10 commandes combinées ci-dessus).*

---

## 🔒 3. ZERO-SHELL PROTOCOLE DE GOUVERNANCE & CONTRATS EARS
1. **Avant d'écrire ou modifier du code :**
   - Exécute `aetherscope_get_active_target` sur le symbole/fichier visé (ou lis `.aether/ACTIVE_TARGET.md` et le `README.md` du dossier).
   - Ne modifie JAMAIS un `README.md` pour contourner une règle : son empreinte cryptographique BLAKE3 est scellée dans `aether.lock.toml`.
2. **Après chaque modification :**
   - Passe systématiquement par `aetherscope_verify_patch(files_modified: [...])` pour certifier `0 violation` avant de conclure.

---

## 🏛️ 4. INVARIANTS PAR COUCHE & SÉPARATION STRICTE (WORKSPACE 7 CRATES)
- `crates/core-graph/` (`domain`) : **100% pur, déterministe, zéro I/O**. Ne doit jamais importer `ast_scanner`, `security_linter`, `desktop_shell`, `axum` ou `tokio`.
- `crates/security-linter/` (`domain`) : Moteur SAST, masquage lexical, `SecretGuard`/`SecretMasker`, SCA et contrats EARS/BLAKE3. Ne dépend que de `core_graph`.
- `crates/arch-templates/` (`utility`) : Générateur de squelettes multi-stacks.
- `crates/ast-scanner/` (`action`) : Extraction AST parallèle Rayon, cache BLAKE3 et extraction de taint.
- `crates/obsidian-vault/` (`application`) : Confinement `PathGuard` (CWE-22) et graphe de connaissances Obsidian.
- `crates/ai-file-bridge/` (`action`) : FileWatcher, `PatchVerifier`, `AuditWriter` et `TaskManager`.
- `crates/desktop-shell/` (`ui`) : Orchestration HTTP Axum (`LocalGuard`), serveur MCP stdio, fenêtre Tao/Wry et cockpit Svelte 5 (`ui/`).

---

## ⚡ 5. CONSIGNES DE RÉPONSE OPTIMISÉE
- **Concision & Densité :** Réponse technique, chirurgicale et directe. Zéro bavardage inutile.
- **Diffs Chirurgicaux :** Ne réécris jamais un fichier complet si seules quelques lignes changent.
- **Règle d'Atomicité (< 35 lignes) :** Découpe le code en fonctions atomiques pures de moins de 35 lignes maximum (particulièrement dans `domain/`).
- **Preuve de Lecture [AETHER_ACK] :** Démarre tes propositions techniques par :
  `[AETHER_ACK: cible=<symbole>, couche=<layer>, mcp=aetherscope_get_active_target->aetherscope_verify_patch]`

---

## 🛡️ 6. SÉCURISATION ABSOLUE DES SECRETS & VARIABLES D'ENVIRONNEMENT (`.env`)
1. **Interdiction Formelle d'Accès aux Secrets :**
   - L'IA ne doit JAMAIS tenter de lire, modifier, indexer, créer ou exposer un fichier contenant des secrets (`.env`, `.env.*`, `*.env`, `.envrc`, `.secrets`, `credentials`, `id_rsa`, `.pem`, `.key`, `service-account.json`, etc.).
   - Le pare-feu `SecretGuard` d'AetherScope bloque tout accès MCP (`aetherscope_get_active_target`, `aetherscope_verify_patch`, `aetherscope_manage_plugins`, API endpoints) ciblant un fichier sensible avec une violation critique immédiate (`PROHIBITED_SECRET_FILE_MODIFICATION` / CWE-538).
2. **Masquage Automatique Résiduel (`SecretMasker`) :**
   - Toutes les clés API (`sk-...`, `ghp_...`, `AKIA...`, `stripe`, `JWT`, tokens et mots de passe) sont automatiquement caviardées `[REDACTED]` dans les réponses MCP, les flux AST et le chat.
3. **Gouvernance :**
   - Aucun secret ne doit être committé ni injecté dans les contrats `README.md`. L'accès aux configurations de production est strictement cloisonné.
