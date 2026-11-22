# Conseils en or

Bonnes pratiques terrain directement alignées sur le fonctionnement interne de `aether-engine` pour préserver vos contrats, sécuriser les éditions IA, fiabiliser vos scans SAST et garder des performances fluides sur les grands dépôts.

## 1. Hygiène des contrats EARS et du verrou BLAKE3

* **Respectez les budgets de lignes avant de découper artificiellement** : La limite par défaut `max_lines_per_file` vaut `300` lignes (`.java` : `10 000`, `.sol` : `600`). Lorsqu'un fichier cohérent nécessite plus de place, déclarez une exception ciblée dans `file_max_lines` du `README.md` du dossier plutôt que d'augmenter le plafond global. Notez que `RULE_MAX_LINES` émet un `WARNING` (il ne bloque pas `PatchVerifier`) et que les fichiers de test, mocks, interfaces et `.d.ts` sont exemptés sauf s'ils figurent explicitement dans `file_max_lines`.
* **Combinez `forbidden_imports` (bloquant) et `allowed_imports` (guide IA)** : `SecurityLinter` bloque activement les lignes `use`/`import`/`from` correspondant à `forbidden_imports` via `RULE_FORBIDDEN_IMPORT` (`CRITICAL`, rejetant les patchs dans `PatchVerifier`), tandis qu'`allowed_imports` alimente `<aether_handshake>` et `.aether/ACTIVE_TARGET.md` pour orienter l'IA.
* **Formulez des clauses EARS vérifiables** : Rédigez des règles `- WHEN <déclencheur> THE SYSTEM SHALL <comportement>` dans vos `README.md` afin de fournir des invariants clairs aux humains comme aux agents.
* **Ne modifiez jamais un `README.md` scellé sans le re-signer** : Toute modification manuelle d'un `README.md` verrouillé sans mise à jour de `aether.lock.toml` déclenche `BLAKE3_TAMPERED` (`CWE-353`, `CRITICAL`). Re-scellez toujours via `POST /api/contracts/update`, `POST /api/contracts/sign`, `POST /api/save_doc` sur `README.md`, ou le bouton de signature en 1 clic de l'Inspecteur Cockpit.

{% hint style="success" %}
**Astuce :** Envoyer `max_files_per_folder: 0` à `POST /api/contracts/update` supprime proprement une limite de nombre de fichiers par dossier tout en gardant `aether.lock.toml` scellé.
{% endhint %}

## 2. Workflow IA chirurgical et pare-feu `<50ms`

Suivez la boucle fermée décrite dans `AETHER_AI_RULES.md` :

1. **Lisez `AETHER_AI_RULES.md` en premier** : Maintenu automatiquement à la racine du projet au démarrage et ajouté à `GET /api/ai/system_prompt`.
2. **Commencez par `aetherscope_get_graph_summary`** : Obtenez en un seul appel MCP l'état du graphe, les violations actives et la file `.aether/tasks/`.
3. **Verrouillez la cible avec `aetherscope_get_active_target`** : Génère `.aether/ACTIVE_TARGET.md` et renvoie le paquet XML `<aether_handshake version="2.1">` (liaisons entrantes/sortantes catégorisées limitées à 4 par groupe, règles de contrat, tâches actives et jeton `[AETHER_ACK]`).
4. **Gardez des fonctions pures courtes et suivez vos tâches** : Visez `< 35` lignes pour les fonctions pures du domaine et tracez votre avancement avec `aetherscope_manage_tasks` (`.aether/tasks/` + `TASKS_SUMMARY.md`).
5. **Certifiez chaque modification avec `aetherscope_verify_patch`** : Exécute `PatchVerifier` en `< 50 ms` (vérification `SecretGuard`, `BLAKE3_TAMPERED`, `RULE_MAX_LINES`, SAST + `RULE_FORBIDDEN_IMPORT` et chemins d'exploitation par BFS inverse `compute_reachability`).

{% hint style="info" %}
`PatchVerifier` rejette (`[PATCH_REJECTED]`) tout patch présentant une violation `CRITICAL`, `HIGH`, `RULE_FORBIDDEN_IMPORT`, `BLAKE3_TAMPERED` ou `FILE_NOT_FOUND`. `RULE_MAX_LINES` (`WARNING`) est signalé sans bloquer la livraison.
{% endhint %}

## 3. Hygiène sécurité, SAST et SCA atteignable

* **Ne touchez jamais aux fichiers sensibles et n'embarquez aucun secret** : `SecretGuard` bloque `.env*`, `.git`, `.ssh`, `.aws`, `.kube`, `.docker`, `id_rsa*`, `.pem`/`.key`/`.p12`/`.pfx` dans le scanner, `PatchVerifier`, MCP et l'API REST. `SecretMasker` masque 12 familles de secrets en lecture et renvoie `403 FORBIDDEN` sur `/api/save_doc` ou `/api/ai/create_file` si un jeton est détecté.
* **Faites confiance au masquage lexical double passe (`AuditContext`)** : Les chaînes et commentaires sont masqués selon le langage avant l'évaluation des règles non littérales, les blocs Rust `#[cfg(test)]` / `mod tests` sont tronqués, et les plugins YAML utilisent `check_literals: false` par défaut. Inutile de désactiver une règle par crainte d'un mot-clé dans un commentaire.
* **Distinguez bien `ignored_cwes` et `--plugins`** :
  * Utilisez `ignored_cwes` dans `.aether/settings.json` pour le **filtrage post-scan dans l'UI/graphe** (correspondance insensible à la casse sur `rule_id` ou `cve_id`). `BLAKE3_TAMPERED` et `RULE_MAX_LINES` restent protégés contre une suppression involontaire par `active_cve_rules`.
  * Utilisez `--plugins <SPEC>` (`default`, `auto`, `all`, noms de packs ou `profile:<nom>`) pour la **sélection des règles au moment du scan** en CLI et en CI.
* **Conditionnez la CI au SCA atteignable et au taint non assaini** : Combinez `--sca` (ou `--offline-sca` avec `.aether/cache/osv/` en environnement isolé) et `--fail-on HIGH|CRITICAL`. Avec `--sca-only`, `--fail-on` n'évalue **que les vulnérabilités atteignables** (`is_reachable == true`), et avec `--audit-only`, `--fail-on` ignore automatiquement les flux de taint marqués `is_sanitized == true`.

## 4. Performances et hygiène des grands dépôts

* **Éliminez le bruit avec `exclusions`** : En plus des exclusions intégrées (`.git`, `node_modules`, `target`, `dist`, `vendor`, fichiers `> 1,5 Mo`, `.d.ts`, `*.min.js`), ajoutez vos dossiers générés ou jeux de tests volumineux dans `exclusions` de `.aether/settings.json`.
* **Conservez `.aether/cache/ast/`** : Chaque fichier est indexé par `BLAKE3(v1|<rel_path>|<file_hash>|<contract_sig>|<plugin_digest>)`, évitant toute ré-analyse des fichiers inchangés.
* **Maîtrisez les seuils des grands graphes** :
  * **Mode éco UI automatique (`> 2 500` nœuds)** : `graphState.svelte.ts` active automatiquement `lowMemoryMode` (`dpr = 1`, badges réduits, suppression du `shadowBlur` coûteux).
  * **Compaction backend (`> 3 000` nœuds ou `> 20 000` arêtes)** : `GET /api/graph` bascule vers `edges_compact` (tableaux indexés) et supprime `raw_content`. Ajoutez `?full=1` si vos scripts nécessitent le JSON complet non compacté.
* **Mémoire WebView2 sous Windows** : `aether-engine` transmet automatiquement `--js-flags=--max-old-space-size=4096` à WebView2 sous Windows afin de garder les graphes massifs fluides.

## Étapes suivantes

{% content-ref url="../core/improvements-and-workflows.md" %}
[Améliorations IA et pare-feu de patch](../core/improvements-and-workflows.md)
{% endcontent-ref %}

{% content-ref url="../extensions-dev/benchmark-and-performance.md" %}
[Benchmark et optimisation des performances](../extensions-dev/benchmark-and-performance.md)
{% endcontent-ref %}
