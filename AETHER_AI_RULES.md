# 🪐 AETHERSCOPE V2 — DIRECTIVES SYSTÈME COPILOTE IA (COMMANDES MCP COMBINÉES & GOUVERNANCE)

> **Projet :** `aether-engine`  
> **Racine :** `C:\Users\1234\Desktop\Projets\aether-engine`  
> **Stack Détectée :** 🦀 Pure Rust (Cargo Workspace Hexagonal)  
> **Architecture Active :** Cargo Workspace : `crates/domain` (100% pur), `crates/server-axum`, `crates/client-ui`, `crates/db-adapter`  
> **Serveur Local AetherScope :** `http://127.0.0.1:3030`  

Tu opères en binôme direct avec le développeur et le moteur d'intelligence architecturale **AetherScope V2**.
Le graphe 3D WebGL 2 tourne en continu sur le port `3030` et audite chaque modification du codebase en temps réel (< 50 ms).

---

## ⚡ 1. WORKFLOW MCP COMBINÉ EN 3 APPELS (ZÉRO COMMANDES REDONDANTES)
Les commandes MCP d'AetherScope ont été **fusionnées et réduites à 8 outils combinés** pour minimiser les appels d'outils :

1. **Au Démarrage / Diagnostic Global (1 seul appel 4-en-1) :**
   - Exécute **`aetherscope_get_graph_summary({"path": ".", "rescan": false, "include_tasks": true})`**
   - *(Combine le résumé du graphe 3D + les violations SAST/CWE actives + la liste des tâches en cours + un rescan optionnel).*
   - Annonce l'état en 1 ligne : `🪐 [AETHER_STATUS : Nœuds=<N>, Flux=<F>, Sécurité=<OK | X violations>, Tâches=<T actives>]`

2. **Avant de Lire / Modifier un Symbole ou Fichier (1 seul appel 3-en-1) :**
   - Exécute **`aetherscope_get_active_target({"symbol_id": "<symbole_ou_fichier>", "action": "Analyse", "details": "<objectif>", "trace_direction": "both"})`**
   - *(Combine automatiquement : (1) Téléportation de la caméra 3D WebGL & badge HUD, (2) Chargement du contrat EARS + Handshake XML + tâches liées, et (3) Traçage complet des flux amont/aval).*

3. **Après Chaque Modification de Code (1 seul appel 4-en-1) :**
   - Exécute **`aetherscope_verify_patch({"files_modified": ["<chemin_fichier>"], "task_id": "<task_id_optionnel>", "status": "done", "progress": 100, "chat_message": "<résumé_court>"})`**
   - *(Combine : (1) Le Pare-Feu Temps Réel < 50ms SAST 150+ CWE & contrats EARS/BLAKE3, (2) Téléportation caméra sur l'état validé ou la ligne en faute, (3) Mise à jour/clôture automatique de la tâche, et (4) Publication du compte-rendu dans le Chat Copilot AetherScope).*
   - Si le verdict est `[PATCH_REJECTED]`, corrige immédiatement les violations signalées et relance `aetherscope_verify_patch`.

---

## 🛠️ 2. RÉFÉRENTIEL COMPLET DES 21 MODULES & COMMANDES MCP (`aetherscope_*`)
AetherScope expose une suite modulaire complète de **21 outils MCP** (18 modules chirurgicaux dédiés + 3 commandes combinées pour workflows rapides) :

### 🌟 Modules Chirurgicaux Spécialisés (18 Outils Granulaires)
1. **`aetherscope_teleport_camera(target, action, details)`** : Déplacement direct de la caméra WebGL 3D, fil d'Ariane violet et réticule tactique.
2. **`aetherscope_get_graph_summary(path?, rescan?, include_tasks?, severity?)`** : Vue globale de l'architecture AST & notes Obsidian (nœuds, arêtes, violations, tâches).
3. **`aetherscope_get_active_target(symbol_id, action?, details?, trace_direction?, max_depth?, path?)`** : Contexte chirurgical, contrat EARS, métadonnées YAML/tags Obsidian et traçage direct de flux.
4. **`aetherscope_search_symbols(query?, layer?, kind?, stereotype?, has_violation?, cwe_id?, severity?, file_pattern?, limit?, path?)`** : Recherche multi-critères dans l'AST de code ou les notes Obsidian.
5. **`aetherscope_switch_view_mode(mode: 'code' | 'vault', path?)`** : Bascule dynamiquement la vision 3D entre graphe d'architecture logicielle (`'code'`) et graphe de connaissances Obsidian (`'vault'`).
6. **`aetherscope_trace_flow(symbol_id, direction: 'upstream' | 'downstream' | 'both', max_depth?, path?)`** : Traçage précis de dépendances, de flux MVC et de backlinks.
7. **`aetherscope_query_violations(severity?, cwe_id?, file_pattern?, path?)`** : Requête chirurgicale des violations SAST, motifs Zero-Day et failles CWE.
8. **`aetherscope_scan_project(path?)`** : Déclenche un rescan ultrarapide (< 50ms) de l'AST ou du vault.
9. **`aetherscope_verify_patch(files_modified, task_id?, status?, progress?, progress_note?, chat_message?)`** : Pare-feu IA Temps Réel (< 50ms) certifiant zéro violation SAST 150+ CWE et contrats EARS/BLAKE3.
10. **`aetherscope_create_task(title, kind, target_symbol?, target_file?, priority?, initial_readme?)`** : Crée une tâche avec son mini-README dans `.aether/tasks/`.
11. **`aetherscope_update_task(task_id, status?, progress?, progress_note?, full_readme?)`** : Met à jour l'avancement, le statut et l'historique d'une tâche.
12. **`aetherscope_list_tasks(status_filter: 'active' | 'all' | 'done')`** : Liste les tâches avec statut et progression.
13. **`aetherscope_send_chat_message(text, thought?, target_symbol?)`** : Publie un debrief dans le Chat Copilot du cockpit.
14. **`aetherscope_get_chat_history()`** : Récupère l'historique des échanges du chat AetherScope.
15. **`aetherscope_list_plugins(plugins_dir?, path?)`** : Inventaire des plugins déclaratifs YAML dans `.aether/plugins/`.
16. **`aetherscope_test_plugins(plugins_dir?, path?)`** : Exécute instantanément la suite de tests unitaires embarqués des plugins.
17. **`aetherscope_scan_with_plugins(target_path, plugins_dir?, path?)`** : Audit SAST sur fichier ou dossier via les plugins de règles personnalisées.
18. **`aetherscope_upsert_plugin_rule(plugin_name, rule_id, name, severity, ...)`** : Crée ou met à jour une règle CWE déclarative certifiée sans recompilation.

### ⚡ Commandes Combinées Multi-Actions (3 Workflows Haute-Efficacité)
19. **`aetherscope_manage_tasks(action: 'list' | 'create' | 'update', ...)`** : Gestion 3-en-1 des tâches (list, create, update) avec téléportation caméra.
20. **`aetherscope_chat(action: 'send' | 'history', text?, ...)`** : Chat Copilot 2-en-1 (envoi de debrief ou lecture historique).
21. **`aetherscope_manage_plugins(action: 'list' | 'test' | 'scan' | 'upsert', ...)`** : Suite plugin 4-en-1 unifiée.

---

## 🔒 3. ZERO-SHELL PROTOCOLE DE GOUVERNANCE & CONTRATS EARS
1. **Avant d'écrire ou modifier du code :**
   - Exécute `aetherscope_get_active_target` sur le symbole/fichier visé (ou lis `.aether/ACTIVE_TARGET.md` et le `README.md` du dossier).
   - Ne modifie JAMAIS un `README.md` pour contourner une règle : son empreinte cryptographique BLAKE3 est scellée dans `aether.lock.toml`.
2. **Après chaque modification :**
   - Passe systématiquement par `aetherscope_verify_patch(files_modified: [...])` pour certifier `0 violation` avant de conclure.

---

## 🏛️ 4. INVARIANTS PAR COUCHE & SÉPARATION STRICTE
- `contracts/` : Traits Rust (`RepositoryPort`), DTOs partagés Serde et schémas RPC stricts
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
