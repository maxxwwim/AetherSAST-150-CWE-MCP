# Améliorations IA et pare-feu de patch

`aether-engine` orchestre les modifications assistées par IA via un pare-feu de patch en `<50ms` (`PatchVerifier`), un gestionnaire de tâches persistant (`TaskManager`), des handshakes XML (`HandshakePacker`), des journaux d'audit en direct (`AuditWriter`) et des studios interactifs dans le Cockpit.

## Vue d'ensemble

Chaque édition IA dans `aether-engine` suit un cycle de gouvernance fermé. Le Cockpit ou le serveur MCP exporte une enveloppe contextuelle `<aether_handshake version="2.1">`, suit l'avancement dans `.aether/tasks/` et soumet chaque fichier modifié à `PatchVerifier` avant de clôturer la tâche ou de mettre à jour le HUD 3D.

```text
Contexte Cockpit / MCP ──► <aether_handshake version="2.1"> ──► Éditions Agent IA
         ▲                                                             │
         │                                                             ▼
  Caméra 3D & HUD ◄── POST /api/ai/telemetry ◄── PatchVerifier (<50 ms)
   (Laser rouge)         (si rejeté)             ├── Approuvé ──► Tâche clôturée (100%)
                                                 └── Rejeté   ──► [🔥 EXPLOITABLE] + Correctifs
```

## Pare-feu IA temps réel (`PatchVerifier`)

`PatchVerifier` (`crates/ai-file-bridge/src/patch_verifier.rs`) valide les fichiers modifiés de façon incrémentale via `PatchVerifier::verify_patch` ou `PatchVerifier::verify_patch_with_graph` et retourne un `PatchVerificationResult` contenant `verdict` (`PatchVerdict::Approved` ou `PatchVerdict::Rejected`), `duration_ms`, `files_scanned`, `total_lines`, `violations`, `offending_target`, `exploit_paths` et `formatted_output`.

### Pipeline de vérification (`< 50 ms`)

Pour chaque chemin de `files_modified`, `PatchVerifier` exécute sept contrôles séquentiels :

1. **Chargement des empreintes verrouillées** : `parse_locked_hashes` lit les sections `[galaxies.*]` d'`aether.lock.toml` pour associer chaque dossier `path` (et clé de galaxie) à son digest `readme_blake3` scellé.
2. **Blocage des chemins secrets (`SecretGuard`)** : `SecretGuard::is_secret_path` rejette immédiatement les fichiers `.env`, clés privées ou identifiants avec `PROHIBITED_SECRET_FILE_MODIFICATION` (`CWE-538 / SENSITIVE-SECRETS-PROHIBITED`, `CRITICAL`) sans lire le contenu du fichier.
3. **Vérification de lecture** : `std::fs::read_to_string` vérifie que le fichier existe et reste lisible ; un fichier absent ou illisible émet `FILE_NOT_FOUND` (`CWE-706 / FILE-NOT-FOUND`, `HIGH`).
4. **Intégrité des contrats BLAKE3** : Si le nom du fichier se termine par `readme.md` (insensible à la casse), `ReadmeContract::parse` et `verify_lock` comparent son empreinte BLAKE3 à `aether.lock.toml` ; toute divergence émet `BLAKE3_TAMPERED` (`CWE-353 / BLAKE3-INTEGRITY`, `CRITICAL`).
5. **Budget de lignes du contrat (`RULE_MAX_LINES`)** : `find_parent_contract` remonte jusqu'au contrat `README.md` parent le plus proche et contrôle `effective_max_lines`. Les fichiers sans surcharge explicite `file_max_lines` se terminant par `_test.rs`, contenant `/tests/` ou se terminant par `.t.sol` sont exemptés ; sinon tout dépassement émet `RULE_MAX_LINES` (`CONTRACT / ARCH-BUDGET-EXCEEDED`, `WARNING`).
6. **Audit SAST incrémental** : `SecurityLinter::audit_file` applique les détecteurs natifs CWE/`AETHER-*` et les règles de contrat EARS (`RULE_FORBIDDEN_IMPORT`, `RULE_FORBIDDEN_FUNCTION`, `SAST_DIRECT_ENV_ACCESS`).
7. **Atteignabilité Source-to-Sink (`[🔥 EXPLOITABLE]`)** : À partir du graphe `AetherGraph` fourni ou d'un appel `GET /api/graph` en direct (`30 ms` connexion, `150 ms` lecture, `50 ms` écriture), `PatchVerifier` injecte les violations comme `CveAnomalyRecord` et exécute `compute_reachability`. Les chemins atteignables affichent le badge `[🔥 EXPLOITABLE]` ; sans graphe disponible, `detect_local_endpoint` repère `#[get(`, `#[post(`, `app.get(`, `app.post(`, `pub async fn handle_` ou `pub async fn endpoint_` et génère `"{ep} -> handler -> {rule_id} (L{line})"`.

### Prédicat de rejet et télémétrie laser rouge

Un patch retourne `PatchVerdict::Rejected` (`[PATCH_REJECTED]`) si **au moins une** violation vérifie l'une de ces conditions :

* `severity == "CRITICAL"` ou `severity == "HIGH"`
* `rule_id == "RULE_FORBIDDEN_IMPORT"`
* `rule_id == "BLAKE3_TAMPERED"`
* `rule_id == "FILE_NOT_FOUND"`

{% hint style="info" %}
`RULE_MAX_LINES` porte la sévérité `WARNING`. Un dépassement de budget de lignes seul apparaît dans le rapport sans bloquer l'approbation du patch.
{% endhint %}

En cas de rejet, `emit_telemetry` ouvre une connexion TCP brute vers `127.0.0.1:<port>` (`3030` par défaut, `40 ms` connexion, `100 ms` écriture) et envoie `POST /api/ai/telemetry` avec `agent_name: "Pare-Feu IA [REJETÉ]"` et `target: "{file}:{line}"`. Le Cockpit téléporte la caméra WebGL sur le nœud fautif et active le laser rouge et le bandeau d'alerte HUD.

{% tabs %}
{% tab title="Sortie Approuvée" %}
```text
================================================================================
✅ [PATCH_APPROVED] AETHERSCOPE AI FIREWALL — CONFORMITÉ VALIDÉE
================================================================================
Scan incrémental exécuté en 14.2 ms sur 1 fichier(s) modifié(s) (128 LOC).
Résultat : 0 régression SAST, 0 violation architecturale, 0 altération de contrat.
```
{% endtab %}

{% tab title="Sortie Rejetée" %}
```text
================================================================================
🚨 [PATCH_REJECTED] AETHERSCOPE AI FIREWALL — VIOLATIONS DÉTECTÉES
================================================================================
1. [CRITICAL] SQL_INJECTION (CWE-89) [🔥 EXPLOITABLE]
   Fichier     : src/api/orders.rs:42
   Exploit     : #[post("/orders")] -> handler -> SQL_INJECTION (L42)
   Remédiation : Use parameterized queries instead of string formatting.

📡 ACTION DU COCKPIT :
Caméra WebGL téléportée sur 'src/api/orders.rs:42' (Laser rouge & HUD alerte activés).
```
{% endtab %}
{% endtabs %}

## Gestionnaire de tâches persistant (`TaskManager`)

`TaskManager` (`crates/ai-file-bridge/src/tasks.rs`) enregistre les tâches de développement et de remédiation sur disque dans `.aether/tasks/` afin que développeurs, outils CLI et agents MCP partagent une source de vérité unique.

### Structure sur disque et journal récapitulatif

* **Dossier de tâche structuré** : Chaque tâche vit dans `.aether/tasks/<task_id>/task.json` et `.aether/tasks/<task_id>/README.md`.
* **Compatibilité ascendante** : `get_task` et `list_tasks` savent aussi relire les anciens fichiers plats `.aether/tasks/<task_id>.json`.
* **Synthèse auto-générée** : Chaque appel à `create_task_with_agent`, `update_task_with_meta` ou `delete_task` régénère `.aether/TASKS_SUMMARY.md` (`sync_tasks_summary_markdown`) avec le tableau des tâches actives, la liste des tâches terminées et jusqu'à 5 corps de `README.md` actifs.
* **Format d'identifiant** : `task_{timestamp_ms % 1_000_000}_{slug}`, où `slugify` assemble jusqu'à `4` mots alphanumériques minuscules séparés par `_`.

### Variantes `TaskKind` et `TaskStatus`

| `TaskKind` | Chaîne Serde | Icône | `TaskStatus` | Chaîne Serde | Badge |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Function` *(défaut)* | `"function"` | `⚙️` | `Pending` *(défaut)* | `"pending"` | `⏳ EN ATTENTE` |
| `Research` | `"research"` | `🔍` | `InProgress` | `"in_progress"` | `⚡ EN COURS` |
| `SecurityFix` | `"security_fix"` | `🛡️` | `Blocked` | `"blocked"` | `⛔ BLOQUÉ` |
| `ArchRefactor` | `"arch_refactor"` | `🏛️` | `Done` | `"done"` | `✅ TERMINÉ` |
| `Documentation` | `"documentation"` | `📖` | `Cancelled` | `"cancelled"` | `⚪ ANNULÉ` |
| `Test` | `"test"` | `🧪` | — | — | — |
| `Other` | `"other"` | `📌` | — | — | — |

### Auto-promotion et clôture automatique MCP

* **Synchronisation statut/progression** (`update_task_with_meta`) : Passer `status` à `Done` force `progress = 100` s'il est inférieur à `100`. Passer `progress == 100` sur une tâche `Pending` la promeut à `Done`, tandis que `progress > 0` sur `Pending` la passe à `InProgress`.
* **Vérification et clôture en 1 appel** (`crates/desktop-shell/src/mcp.rs`) : Lorsque `aetherscope_verify_patch` retourne `PatchVerdict::Approved` avec un `task_id` non vide, le serveur MCP applique par défaut `status = "done"`, `progress = 100` et `progress_note = "Patch validé par aetherscope_verify_patch"`, met à jour `.aether/tasks/<task_id>/`, notifie le Cockpit actif via `POST /api/tasks/update` et publie `chat_message` via `POST /api/ai/chat`.

## Handshake XML (`<aether_handshake>`) et `AuditWriter`

### `<aether_handshake version="2.1">` (`HandshakePacker`)

`HandshakePacker::build_categorized_prompt` (`crates/ai-file-bridge/src/handshake.rs`) encapsule le contexte architectural d'un symbole dans un bloc XML compact afin d'éviter la saturation de contexte des LLM :

* **`<action>` et `<target>`** : Type d'opération (`Refactor`, `Test`, `Audit`, `Doc`, `Target`) suivi de `<name>`, `<file>` (`path:line`), `<galaxy>` et `<layer>`.
* **`<context>` (`<in_degree>` / `<out_degree>`)** : Regroupe les liaisons selon les 7 catégories de `CategorizedLiaisons` (`form_submit`, `network_http`, `realtime_ws`, `database_query`, `caller`, `dependency`, `violation`). Chaque groupe affiche au maximum **4** éléments et ajoute `<more_hidden count="N" />` au-delà.
* **`<contract_rules>`** : Balises optionnelles `<max_lines>`, `<allowed_imports>`, `<forbidden_imports>`, `<forbidden_functions>`, `<allowed_extensions>`, `<forbidden_extensions>` et `<max_files_per_folder>`.
* **`<mcp_commands>` et `<instruction>`** : Pré-remplit `aetherscope_get_active_target`, `aetherscope_manage_tasks` et `aetherscope_verify_patch`, et impose à l'agent de répondre avec `[AETHER_ACK] ... [/AETHER_ACK]` avant d'éditer le code.

<details>
<summary>Exemple de payload XML &lt;aether_handshake version="2.1"&gt;</summary>

```xml
<aether_handshake version="2.1">
  <action>SecurityFix</action>
  <target>
    <name>handle_order</name>
    <file>crates/api/src/orders.rs:42</file>
    <galaxy>api</galaxy>
    <layer>action</layer>
  </target>
  <context>
    <in_degree total="6">
      <network_http_group count="1">
        <network_http>POST /api/orders</network_http>
      </network_http_group>
      <caller_group count="5">
        <caller>router::mount_routes</caller>
        <caller>tests::smoke_orders</caller>
        <caller>legacy::v1_orders</caller>
        <caller>admin::replay_order</caller>
        <more_hidden count="1" />
      </caller_group>
    </in_degree>
    <out_degree total="1">
      <database_query_group count="1">
        <database_query>sqlx::query</database_query>
      </database_query_group>
    </out_degree>
  </context>
  <instruction>
    Avant d'écrire le code, réponds obligatoirement avec ce bloc de confirmation :
    [AETHER_ACK]
    Cible : handle_order
    Imports interdits pris en compte : OUI
    Commandes MCP combinées : aetherscope_get_active_target -> aetherscope_manage_tasks -> aetherscope_verify_patch
    Audit live surveillé dans .aether/LIVE_AUDIT.md : OUI
    [/AETHER_ACK]
  </instruction>
</aether_handshake>
```

</details>

### Fichiers `AuditWriter` et détection de stack

Chaque écriture effectuée par `AuditWriter` (`crates/ai-file-bridge/src/audit_writer.rs`) transite par `safe_write_in_root`, qui rejette `..` (`Component::ParentDir`) et toute cible sortant de `project_root` :

| Fichier généré | Déclencheur / Méthode | Rôle |
| :--- | :--- | :--- |
| `.aether/LIVE_AUDIT.md` | `write_live_audit` (après sauvegarde surveillée) | Exclut les entrées `RULE_MAX_LINES` / `WARNING` pour afficher soit `## ✅ ARCH_OK`, soit un tableau par sévérité (`🔴 CRITIQUE`, `🟠 HAUT`, `🟡 MOYEN`, `⚪ AVERTISSEMENT`) avec `📦 Donnée` et `Fix:`. |
| `.aether/ACTIVE_TARGET.md` | `write_active_target_categorized` (à la sélection) | Consigne les métadonnées du symbole, les flux `CategorizedLiaisons` (`"amont"` / `"aval"`, plafonnés à 4 éléments par groupe), le contrat EARS du `README.md` parent, les tâches actives liées et 3 commandes MCP prêtes à l'emploi. |
| `AETHER_AI_RULES.md` | `ensure_master_rules_file` | Créé à la racine du projet sur le port `3030` uniquement s'il est absent ou vide, via `detect_project_stack` + `generate_optimized_system_prompt`. |

`AuditWriter::detect_project_stack` inspecte `aether.lock.toml` (détection de `"hybrid"`, `"mmo"` ou `"web3"`) et les manifestes du dépôt pour retourner `"hybrid"` (également si Cargo et `package.json`/`client/` coexistent), `"rust"`, `"python"`, `"php"`, `"cpp"`, `"java"` ou `"ts"` (repli `"hybrid"`). `generate_optimized_system_prompt` couvre en plus `"node"`, `"minecraft"`, `"roblox"`, `"roblox-server"` et `"luau"`, en injectant le workflow MCP en 3 appels, les 10 outils `aetherscope_*`, les invariants de couches, l'atomicité `< 35` lignes par fonction, `[AETHER_ACK]` et les garde-fous `SecretGuard`/`SecretMasker`.

## Studios d'amélioration dans l'interface

Les workflows interactifs d'IA et de remédiation résident dans `crates/desktop-shell/ui/src/` :

### `PromptGeneratorModal` (`components/PromptGeneratorModal.svelte`)

Propose un studio à 4 onglets (`activeTab` : `context` | `master` | `sysprompt` | `mcp`) :

* **Prompt Contextuel (`context`)** : Bascule entre cible `symbol` et `folder` sur 5 modes `taskMode` (`refactor`, `security`, `tests`, `docs`, `audit`), en injectant `settings.aiCustomPrompt`.
* **Master Blueprint (`master`)** : Formate les directives d'architecture Spec-Driven pour `claude`, `gemini` ou `openai`.
* **System Prompt (`sysprompt`)** : Affiche `graph.system_prompt` ou interroge `GET /api/ai/system_prompt`.
* **Configuration MCP (`mcp`)** : Génère les blocs JSON sur le port actif (`window.location.port || '3030'`) pour `antigravity` (`~/.gemini/config/mcp_config.json`), `claude` (`%APPDATA%\Claude\claude_desktop_config.json`) et `cursor` (`.cursor/mcp.json`).

### Studio Bug Bounty & Remédiation en 4 étapes (`BountyModal.svelte` & `components/bounty/bountyEngine.ts`)

1. **Étape 1 — Scope (`StepScopePanel.svelte`)** : Sélectionne parmi 7 `BOUNTY_PRESETS` (`immunefi`, `hackerone`, `yeswehack`, `l1_consensus`, `rust_lowlevel`, `smart_contracts`, `auto`), lance AI Auto-Scope (`GET` / `POST /api/bounty/scope`), verrouille un dossier unique (`lockedSingleFolder`), édite les motifs wildcard In-Scope/Out-of-Scope, isole le périmètre dans le graphe 3D et choisit parmi 4 modes de mission (`audit_strict`, `poc_batch`, `patch_ears`, `mcp_autonomous`).
2. **Étape 2 — Cibles & Fonctions (`StepTargetsFunctionsPanel.svelte`)** : Filtre les vulnérabilités (`ALL`/`CRITICAL`/`HIGH`, `reachableOnly`, recherche) ou les symboles AST, et inspecte `extractFileFunctions` qui classe chaque fonction en `SOURCE`, `PROPAGATION` ou `SINK` avec sa complexité cyclomatique.
3. **Étape 3 — Code & Dataflow (`StepCodeDataPanel.svelte`)** : Bascule entre les sous-vues `split` / `code` / `data`, affiche un extrait (`excerpt`) ou le fichier complet (`full`, jusqu'à `1500` lignes via `GET /api/file_content`), génère le graphe SVG directionnel (`buildDirectionalDiagram`), trace les étapes SSA (`buildSsaSteps`) et liste les paramètres (`IN`, `TRANSIT`, `OUT`).
4. **Étape 4 — Prompts & PoC (`StepPromptsPocPanel.svelte`)** : Fournit 8 onglets de sortie (`target_prompt`, `scope_prompt`, `poc_code` [test `#[test]` Rust pour `.rs`, sinon `requests` Python], `curl_command`, `raw_http`, `bounty_report` [aperçu formaté ou Markdown brut avec sauvegarde en 1 clic dans `.aether/bounty_reports/report_<slug>.md` via `POST /api/ai/create_file`], `gold_patch`, `mcp_handshake`). Intègre un **Live HTTP Dry-Run** (timeout `AbortController` de `5 s` vers `http://localhost:3030...`) avec repli automatique sur la simulation `sandbox_ast`.

### Score d'audit et export (`lib/auditReport.ts`)

`computeAuditSummary(cockpitState)` calcule un `securityScore` borné entre `10` et `100` et attribue les notes `A..F` :

```ts
let score = 100;
score -= Math.min(45, criticalCount * 15);
score -= Math.min(30, highCount * 6);
score -= Math.min(15, mediumCount * 2);
score -= Math.min(10, Math.floor(hotspotsCount * 1.5));
if (earsContractsCount > 0) score = Math.min(100, score + 5);
score = Math.max(10, Math.min(100, score));
```

| Note | Seuil de score | Signification à l'export (`generateAuditMarkdown` / `generateAuditHtml`) |
| :--- | :--- | :--- |
| **A** | `>= 90` | Fortement sécurisé |
| **B** | `>= 80` | Bonne posture défensive |
| **C** | `>= 70` | Risque modéré / remédiations requises |
| **D** | `>= 50` | Risque élevé / failles prioritaires |
| **F** | `< 50` | Risque critique / exposition immédiate |

`lowCount` ne retire `0` point. `generateAuditMarkdown` génère un rapport GFM complet (notez que sa bannière d'en-tête affiche encore la mention historique `AetherScope AST Security Engine (v2.4)`), tandis que `generateAuditHtml` produit un rapport HTML autonome embarquant le graphe interactif (`auditGraphHtml.ts`).

### `InspectorDrawer`, `DocReaderDrawer` et `AiChatDrawer`

* **Tiroir Inspecteur (`InspectorDrawer.svelte`)** : Panneau latéral redimensionnable (`280 px` à `70vw`, `396 px` par défaut, `600 px` étendu) doté de 5 onglets (`debrief`, `uml`, `relations`, `cve`, `tasks`). Son éditeur de contrat propose des boutons rapides `max_lines` (`200`, `300`, `500`, `800`, `1500`) ou une valeur libre envoyée à `POST /api/contracts/update` pour sceller le `README.md` avec BLAKE3.
* **Signature globale des contrats (`DocReaderDrawer.svelte`)** : Assure l'auto-sauvegarde en `1,5 s` des contrats `README.md` et déclenche la signature BLAKE3 par dossier (`signAllContracts()`) via `POST /api/contracts/sign`.
* **Chat IA et dock essaim (`AiChatDrawer.svelte` & `graphState.svelte.ts`)** : Interroge `/api/ai/telemetry` et `/api/ai/chat` toutes les `1500 ms`, bascule avec `C`, sépare les sous-onglets `chat` et `agents`, replie les blocs `<thought>` / `<thinking>` et expose les lanceurs CLI (`gemini`, `claude`, `codex` -> `POST /api/ai/launch_cli`). Les messages envoyés sur `POST /api/ai/chat` écrivent dans `.aether/CHAT_INBOX.md` (`PENDING_AI_RESPONSE` pour `"user"`, `ANSWERED` pour les agents). Les agents actifs expirent après `AI_AGENT_TTL_SECS = 300` (`AI_INACTIVITY_TIMEOUT_MS = 300_000` ms) et reçoivent une couleur déterministe issue de la palette backend à 12 couleurs hachée par FNV-1a (`AI_AGENT_PALETTE` / `MCP_AGENT_PALETTE`, base `14695981039346656037`), complétée par un repli frontend `resolveAgentColor` à 16 couleurs.

{% content-ref url="./blake3-governance.md" %}
[Gouvernance BLAKE3 et contrats EARS](./blake3-governance.md)
{% endcontent-ref %}

{% content-ref url="./security-confinement.md" %}
[Confinement de sécurité et garde-fous](./security-confinement.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/rest-api-ide-contracts-ai.md" %}
[API REST : IDE, contrats, IA et tâches](../api-mcp/rest-api-ide-contracts-ai.md)
{% endcontent-ref %}

{% content-ref url="../api-mcp/mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](../api-mcp/mcp-server.md)
{% endcontent-ref %}
