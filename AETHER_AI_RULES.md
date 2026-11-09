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

## 🛠️ 2. RÉFÉRENTIEL DES 10 OUTILS D'ÉLITE MCP AETHERSCOPE (10 MAX — ANTI-FLOOD)
AetherScope concentre l'intelligence architecturale sur **10 outils MCP d'élite** hautement optimisés pour éviter tout flood de contexte tout en couvrant 100% des cas d'usage :

### 🪐 Les 10 Commandes Stratégiques
1. **`aetherscope_get_graph_summary(path?, rescan?, include_tasks?, severity?)`** *(Diagnostic Global 4-en-1)*
   - Résumé global de l'architecture (Code AST & Vault Obsidian), violations SAST/CWE actives, liste des tâches et option de rescan à chaud.
2. **`aetherscope_get_active_target(symbol_id, action?, details?, trace_direction?, max_depth?, path?)`** *(Inspection Cible 3-en-1)*
   - Téléporte la caméra 3D, extrait le contrat EARS / métadonnées YAML Obsidian, et trace automatiquement les flux amont/aval ou wikilinks.
3. **`aetherscope_search_symbols(query?, layer?, kind?, stereotype?, has_violation?, cwe_id?, severity?, file_pattern?, limit?, path?)`** *(Recherche Universelle 2-en-1)*
   - Recherche multi-critères dans le graphe (symboles de code, notes Markdown Obsidian, tags `#tag`) ET audit ciblé des failles CWE.
4. **`aetherscope_switch_view_mode(mode: 'code' | 'vault', path?)`** *(Bascule Vision 3D WebGL2)*
   - Permute instantanément la vue du cockpit 3D entre la topologie de code AST (`'code'`) et le réseau de connaissances Obsidian (`'vault'`).
5. **`aetherscope_verify_patch(files_modified, task_id?, status?, progress?, progress_note?, chat_message?)`** *(Pare-Feu IA Temps Réel 4-en-1)*
   - Analyse incrémentale < 50ms sur `files_modified` (150+ CWEs, Reachability Source-to-Sink, contrats EARS/BLAKE3). Clôture la tâche et notifie le HUD.
6. **`aetherscope_manage_tasks(action: 'list' | 'create' | 'update', task_id?, title?, kind?, target_symbol?, priority?, status?, progress?, progress_note?, initial_readme?, full_readme?, status_filter?)`** *(Gestionnaire Tâches 3-en-1)*
   - Cycle complet des tâches avec mini-READMEs dans `.aether/tasks/` et alignement automatique de la caméra 3D.
7. **`aetherscope_chat(action: 'send' | 'history', text?, thought?, target_symbol?)`** *(Console Chat Copilot 2-en-1)*
   - Envoi de debrief Markdown avec balise `<thought>` dans le HUD du cockpit ou lecture de l'historique conversationnel.
8. **`aetherscope_manage_plugins(action: 'list' | 'test' | 'scan' | 'upsert', target_path?, plugins_dir?, path?, ...)`** *(Moteur Plugins SAST 4-en-1)*
   - Gestion déclarative complète des règles de sécurité YAML : inventaire, exécution des tests unitaires, audit de fichiers et upsert certifié.
9. **`aetherscope_teleport_camera(target, action, details)`** *(Navigation Rapide 3D)*
   - Oriente directement la caméra WebGL vers un composant, active le fil d'Ariane violet et le badge de télémétrie sans recharger l'arbre.
10. **`aetherscope_scan_project(path?)`** *(Rescan Express)*
   - Force une réanalyse AST/Vault ultrarapide du projet pour synchroniser immédiatement l'état sur disque avec le visualiseur 3D.

*(Note : les alias et commandes unitaires spécialisées restent supportés par le serveur en arrière-plan sans encombrer la mémoire de l'IA).*

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
